"""Web app (SPEC §4.1, §6, §7.6). Server-rendered, no inline script, strict CSP.

Areas and roles (from Entra security-group claims, re-evaluated every request
against the group IDs currently in settings):
  /me/*     users     (SpringSync-Users + pilot list)  - own status only
  /admin/*  admins    (SpringSync-Admins, Mark)        - settings + user actions
  /audit/*  auditors  (SpringSync-Auditors, Walter)    - GET only, read-only
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Protocol

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from odnas import cloud, service_mode
from odnas.google import ClaimsError, GoogleClient, check_claims
from odnas.notify import Alerter
from odnas import __version__
from odnas import autoupdate
from odnas import db as D
from odnas import settings_store
from odnas.config import Config
from odnas.crypto import Keyring
from odnas.db import pack, unpack
from odnas.entra import EntraClient
from odnas.nas import V_ERROR, friendly, local_name_from_upn
from odnas.runner import delete_count, delete_counts, delta_file
from odnas.scheduler import LOCAL_TZ  # noqa: F401  (kept for callers)
from odnas.timefmt import display_time, localize_text
from odnas.status import credential_expiry, disk_free_pct, worker_alive

log = logging.getLogger("odnas.web")
HERE = Path(__file__).resolve().parent
SESSION_HOURS = 8
ROLE_USER, ROLE_ADMIN, ROLE_AUDITOR = "user", "admin", "auditor"
# Every POST /admin/users/{uid}/{action}. IT-admin role only (SpringSync-Admins); auditors get 403.
ADMIN_USER_ACTIONS = ("pause", "resume", "approve-resync", "request-dryrun", "offboard",
                      "safety-restore", "safety-accept-deletes", "safety-refresh-delta",
                      "service-mode-on", "service-mode-off",
                      # v0.9 (SPEC §6.6, §4.4, §9.6, §9.7.2)
                      "set-direction", "set-gdocs-mode", "set-provider", "approve-mirror-baseline",
                      "recount-mirror-baseline", "safety-retry", "safety-switch-copy")

CSP = ("default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; "
       "base-uri 'none'")


class WorkerClient(Protocol):
    def verify_nas(self, username: str, password: str) -> str: ...


class HttpWorkerClient:
    def __init__(self, cfg: Config, kr: Keyring):
        self.cfg, self.kr = cfg, kr

    def verify_nas(self, username: str, password: str) -> str:
        import httpx
        try:
            r = httpx.post(f"{self.cfg.broker_base}/internal/nas-verify", timeout=90,
                           json={"username": username, "password": password},
                           headers={"x-internal-token": self.kr.internal_token()})
            return r.json().get("status", V_ERROR) if r.status_code == 200 else V_ERROR
        except Exception:
            return V_ERROR


def svc_test_status(db: D.DB) -> dict | None:
    """SPEC v0.7 §6.4: state of the svc-sync password test shown on Settings.
    - 'testing': a new nas_svc_password was saved while the global pause is set and the worker has not
      reported a final result for it yet (its next tick, <= 60 s; an unreachable NAS keeps it testing);
    - 'ok' / 'rejected': the result of the last test of the CURRENT password; None otherwise."""
    cur = db.setting_version("nas_svc_password")
    hb = db.heartbeat("nas_svc_test")
    last = json.loads(hb["detail"]) if hb and hb["detail"] else {}
    f = db.flag(D.NAS_GLOBAL_PAUSE)
    if f is not None and cur and cur not in (f.get("pw_version"), f.get("tested_pw_version")):
        return {"state": "testing", "retrying": last.get("pw_version") == cur and last.get("result") != "ok",
                "last_result": last.get("result") if last.get("pw_version") == cur else None}
    if last and last.get("pw_version") == cur:
        return {"state": "ok" if last["result"] == "ok" else "rejected" if last["result"] == "auth_failed"
                else last["result"], "at": last.get("at")}
    return None


def local_time(v: str | None) -> str:
    """v0.9.1: every time on a page is Central (America/Chicago) with its zone label."""
    return display_time(v)


def create_app(cfg: Config, db: D.DB, kr: Keyring, entra: EntraClient,
               worker: WorkerClient | None = None, google: GoogleClient | None = None) -> FastAPI:
    app = FastAPI(title=cfg.product_name, docs_url=None, redoc_url=None, openapi_url=None)
    templates = Jinja2Templates(directory=str(HERE / "templates"))
    templates.env.filters["local"] = local_time
    templates.env.filters["local_text"] = localize_text    # embedded UTC timestamps in free text
    templates.env.globals.update(product=cfg.product_name, version=__version__, labels=D.STATE_LABELS,
                                 state_label=D.state_label, provider_labels=cloud.PROVIDER_LABELS,
                                 direction_labels=cloud.DIRECTION_LABELS)
    if google is None:
        from odnas.google import HttpGoogleClient
        google = HttpGoogleClient(cfg)   # no network until a user actually connects Google Drive
    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")
    worker = worker or HttpWorkerClient(cfg, kr)
    cookie = f"{cfg.slug}_sid"
    flow_cookie = f"{cfg.slug}_flow"
    app.state.cfg, app.state.db = cfg, db

    def settings():
        return settings_store.load(db, cfg)  # no keyring: secrets never decrypted in the web views

    # ---- security headers ----------------------------------------------
    @app.middleware("http")
    async def headers(request: Request, call_next):
        resp: Response = await call_next(request)
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    # ---- sessions (server-side) -----------------------------------------
    def _sid_key(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def new_session(resp: Response, data: dict) -> None:
        token = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)
        db.q("DELETE FROM sessions WHERE expires_at < ?", (D.iso(now),))
        db.q("INSERT INTO sessions(id, data_json, csrf, created_at, expires_at) VALUES (?,?,?,?,?)",
             (_sid_key(token), json.dumps(data), secrets.token_urlsafe(32), D.iso(now),
              D.iso(now + timedelta(hours=SESSION_HOURS))))
        resp.set_cookie(cookie, token, max_age=SESSION_HOURS * 3600, secure=cfg.cookie_secure, httponly=True,
                        samesite="lax", path="/")

    def get_session(request: Request) -> dict | None:
        token = request.cookies.get(cookie)
        if not token:
            return None
        r = db.one("SELECT * FROM sessions WHERE id=? AND expires_at > ?", (_sid_key(token), D.iso(D.utcnow())))
        if not r:
            return None
        d = json.loads(r["data_json"])
        d["_csrf"], d["_sid"] = r["csrf"], r["id"]
        return d

    def roles_for(sess: dict) -> set[str]:
        """Roles come ONLY from the Microsoft Entra sign-in (SPEC v0.9 §4.4: app sign-in stays Microsoft for
        everyone; Google is a data connection, never a session)."""
        s = settings()
        groups = set(sess.get("groups", []))
        roles = set()
        if s.group_admins and s.group_admins in groups:
            roles.add(ROLE_ADMIN)
        if s.group_auditors and s.group_auditors in groups:
            roles.add(ROLE_AUDITOR)
        if sess.get("user_id") and s.group_users and s.group_users in groups:
            roles.add(ROLE_USER)
        return roles

    async def check_csrf(request: Request, sess: dict) -> dict:
        form = dict(await request.form())
        if not secrets.compare_digest(str(form.get("csrf", "")), sess["_csrf"]):
            raise HTTPException(403, "CSRF check failed")
        return form

    def require(*allowed: str) -> Callable:
        def dep(request: Request) -> dict:
            sess = get_session(request)
            if not sess:
                raise HTTPException(401, "sign in required")
            r = roles_for(sess)
            if not r & set(allowed):
                raise HTTPException(403, "not allowed for your role")
            sess["_roles"] = r
            return sess
        return dep

    def render(request: Request, name: str, sess: dict | None = None, **ctx: Any) -> HTMLResponse:
        ctx.update(request=request, sess=sess, roles=(sess or {}).get("_roles", set()),
                   csrf=(sess or {}).get("_csrf", ""))
        return templates.TemplateResponse(request, name, ctx)

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        if exc.status_code == 401 and request.method == "GET":
            return RedirectResponse("/", 303)
        return templates.TemplateResponse(request, "error.html", {"request": request, "sess": None, "roles": set(),
                                          "csrf": "", "code": exc.status_code, "message": exc.detail},
                                          status_code=exc.status_code)

    # ---- public -----------------------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        sess = get_session(request)
        if sess:
            r = roles_for(sess)
            target = "/me" if ROLE_USER in r else "/admin" if ROLE_ADMIN in r else "/audit" if ROLE_AUDITOR in r else None
            if target:
                return RedirectResponse(target, 303)
        return render(request, "index.html", sess)

    @app.get("/healthz")
    def healthz(request: Request):
        if request.client and request.client.host not in ("127.0.0.1", "::1", "testclient"):
            raise HTTPException(404)
        alive, ts = worker_alive(db)
        try:
            db.one("SELECT 1")
            dbok = True
        except Exception:
            dbok = False
        body = {"db": dbok, "worker_heartbeat": ts, "worker_alive": alive, "version": __version__}
        return JSONResponse(body, 200 if dbok else 503)

    @app.get("/login")
    def login(request: Request):
        ip = request.client.host if request.client else "?"
        if db.rate_limited(f"login:{ip}"):
            raise HTTPException(429, "Too many sign-in attempts. Try again in 15 minutes.")
        flow = entra.begin_auth(cfg.redirect_uri)
        sealed = kr.seal(json.dumps(flow), Keyring.aad("auth_flows", flow["state"], "flow"))
        db.q("DELETE FROM auth_flows WHERE created_at < ?", (D.iso(D.utcnow() - timedelta(minutes=10)),))
        db.q("INSERT INTO auth_flows(state, flow_ct, key_id, created_at) VALUES (?,?,?,?)",
             (flow["state"], pack(sealed), sealed.key_id, D.iso(D.utcnow())))
        resp = RedirectResponse(flow["auth_uri"], 303)
        resp.set_cookie(flow_cookie, flow["state"], max_age=600, secure=cfg.cookie_secure, httponly=True,
                        samesite="lax", path="/auth")
        return resp

    @app.get(cfg.redirect_path)
    def callback(request: Request):
        q = dict(request.query_params)
        state = q.get("state", "")
        if not state or not secrets.compare_digest(request.cookies.get(flow_cookie, ""), state):
            raise HTTPException(400, "Sign-in session mismatch. Please start again.")
        row = db.one("SELECT * FROM auth_flows WHERE state=? AND created_at > ?",
                     (state, D.iso(D.utcnow() - timedelta(minutes=10))))
        db.q("DELETE FROM auth_flows WHERE state=?", (state,))
        if not row:
            raise HTTPException(400, "Sign-in expired. Please start again.")
        flow = json.loads(kr.open(unpack(row["flow_ct"], row["key_id"]), Keyring.aad("auth_flows", state, "flow")))
        if flow.get("purpose") == "google_connect":
            raise HTTPException(400, "Sign-in session mismatch. Please start again.")
        res = entra.complete_auth(flow, q)
        if not res.ok:
            log.warning("sign-in failed: %s", res.error)
            raise HTTPException(403, "Microsoft sign-in did not complete. " + (
                "A sign-in policy blocked it; IT has been told." if res.classification == "blocked_by_ca" else
                "Please try again."))
        c = res.id_claims
        if c.get("tid", "").lower() != cfg.tenant_id.lower():
            raise HTTPException(403, "Wrong organisation.")
        upn = (c.get("preferred_username") or c.get("upn") or "").lower()
        if cfg.allowed_upn_domain and not upn.endswith("@" + cfg.allowed_upn_domain.lower()):
            raise HTTPException(403, "This account is not allowed.")
        if "_claim_names" in c and "groups" in c.get("_claim_names", {}):
            raise HTTPException(403, "Group overage: ask IT to restrict the groups claim to assigned groups.")
        s = settings()
        groups = [g.lower() for g in c.get("groups", [])]
        oid = c.get("oid", "")
        data = {"oid": oid, "upn": upn, "name": c.get("name", upn), "groups": groups, "user_id": None}
        is_user = bool(s.group_users) and s.group_users in groups
        allowed = is_user and (not s.pilot_only or upn in s.pilot_set())
        u = db.user_by_oid(oid) if allowed else None
        if allowed and (u is not None or res.refresh_token):
            new = u is None
            if u is None:
                # v0.9: the admin chooses the provider (Settings gdrive_users for new users, or the user page)
                prov = cloud.PROVIDER_GD if upn in s.gdrive_user_set() else cloud.PROVIDER_OD
                uid = db.create_user(oid, upn, data["name"], local_name_from_upn(upn), D.ONBOARDING, True,
                                     provider=prov, direction=s.default_direction, gdocs_mode=s.google_gdocs_default)
                db.audit(oid, "user_connected", uid, {"upn": upn, "provider": prov,
                                                      "direction": s.default_direction})
                u = db.user_full(uid)
            else:
                uid = u["id"]
                u = db.user_full(uid)
            onedrive = cloud.provider(u) == cloud.PROVIDER_OD
            if onedrive and cloud.PROVIDER_OD not in s.providers():
                db.audit(oid, "connect_denied_provider_disabled", uid, {"upn": upn, "provider": "onedrive"})
            elif onedrive and res.refresh_token:
                drive = entra.get_drive(res.access_token)
                if u["state"] == D.REMOVED:
                    db.set_state(uid, D.ONBOARDING)
                    db.update_profile(uid, enabled=1, needs_resync=1, dryrun_ok_at=None, preflight_at=None)
                elif u["state"] in (D.NEEDS_REAUTH, D.BLOCKED_BY_CA):
                    reconnect_state(uid)
                if not new:
                    db.audit(oid, "user_reconnected", uid, {"upn": upn})
                db.put_ms_credential(kr, uid, res.refresh_token, drive["id"], drive.get("driveType", "business"))
                if s.nas_option == "B" and not db.user(uid)["state"] == D.ACTIVE:
                    db.update_profile(uid, preflight_requested=1)
            elif not onedrive and u["state"] == D.REMOVED:
                db.set_state(uid, D.ONBOARDING)
                db.update_profile(uid, enabled=1, needs_resync=1, dryrun_ok_at=None, preflight_at=None)
            # Google users: the Microsoft refresh token is NOT stored (their cloud side is Google Drive);
            # the session is still the Microsoft one. They connect Google Drive from /me.
            data["user_id"] = uid
        elif is_user and not allowed:
            db.audit(oid, "connect_denied_not_on_pilot", "", {"upn": upn})
        db.audit(oid, "login", "", {"upn": upn})
        resp = RedirectResponse("/", 303)
        resp.delete_cookie(flow_cookie, path="/auth")
        new_session(resp, data)
        return resp

    def reconnect_state(uid: str) -> None:
        """needs_reauth / blocked_by_ca -> resumes on the next slot (SPEC §6.2). v0.9: a user who had not
        finished onboarding goes back to onboarding, never straight to active."""
        u = db.user_full(uid)
        db.set_state(uid, D.ACTIVE if u["onboarding_completed_at"] or u["last_success_at"] else D.ONBOARDING)
        db.close_issues(uid, "needs_reauth", "blocked_by_ca")

    # ---- Connect Google Drive (v0.9 §4.3, §4.4): a data connection for a signed-in user ---------------
    def _google_ready(u) -> bool:
        return (cfg.google_configured and cloud.provider(u) == cloud.PROVIDER_GD
                and cloud.PROVIDER_GD in settings().providers())

    def _google_expected(upn: str, s) -> set[str]:
        return {upn.lower()} | s.google_aliases().get(upn.lower(), set())

    @app.post("/me/google/connect")
    async def google_connect(request: Request, sess: dict = Depends(require(ROLE_USER))):
        await check_csrf(request, sess)
        u = db.user_full(sess["user_id"])
        if not _google_ready(u):
            raise HTTPException(409, "Google Drive is not your connected cloud drive (ask IT).")
        if u["state"] in (D.OFFBOARDING, D.REMOVED, D.PAUSED):
            raise HTTPException(409, "Your sync is stopped by IT; connecting is not possible right now.")
        if db.rate_limited(f"gconnect:{u['id']}"):
            raise HTTPException(429, "Too many attempts. Try again in 15 minutes.")
        s = settings()
        flow = google.begin_auth(cfg.google_redirect_uri, s.google_allowed_domain, login_hint=u["upn"])
        flow.update(purpose="google_connect", uid=u["id"], sid=sess["_sid"])
        sealed = kr.seal(json.dumps(flow), Keyring.aad("auth_flows", flow["state"], "flow"))
        db.q("DELETE FROM auth_flows WHERE created_at < ?", (D.iso(D.utcnow() - timedelta(minutes=10)),))
        db.q("INSERT INTO auth_flows(state, flow_ct, key_id, created_at) VALUES (?,?,?,?)",
             (flow["state"], pack(sealed), sealed.key_id, D.iso(D.utcnow())))
        db.audit(sess["oid"], "google_connect_started", u["id"], {"upn": u["upn"]})
        resp = RedirectResponse(flow["auth_uri"], 303)
        resp.set_cookie(flow_cookie, flow["state"], max_age=600, secure=cfg.cookie_secure, httponly=True,
                        samesite="lax", path="/auth")
        return resp

    @app.get(cfg.google_redirect_path)
    def google_callback(request: Request):
        sess = get_session(request)
        if not sess or ROLE_USER not in roles_for(sess):
            raise HTTPException(401, "Sign in with Microsoft first, then connect Google Drive.")
        q = dict(request.query_params)
        state = q.get("state", "")
        if not state or not secrets.compare_digest(request.cookies.get(flow_cookie, ""), state):
            raise HTTPException(400, "Connect session mismatch. Please start again.")
        row = db.one("SELECT * FROM auth_flows WHERE state=? AND created_at > ?",
                     (state, D.iso(D.utcnow() - timedelta(minutes=10))))
        db.q("DELETE FROM auth_flows WHERE state=?", (state,))
        if not row:
            raise HTTPException(400, "Connect session expired. Please start again.")
        flow = json.loads(kr.open(unpack(row["flow_ct"], row["key_id"]), Keyring.aad("auth_flows", state, "flow")))
        uid = sess["user_id"]
        if flow.get("purpose") != "google_connect" or flow.get("uid") != uid or flow.get("sid") != sess["_sid"]:
            raise HTTPException(400, "Connect session mismatch. Please start again.")
        u = db.user_full(uid)
        if not _google_ready(u):
            raise HTTPException(409, "Google Drive is not your connected cloud drive (ask IT).")
        res = google.complete_auth(flow, q)
        actor = sess["oid"]
        if not res.ok:
            log.warning("google connect failed: %s", res.error)
            db.audit(actor, "google_connect_failed", uid, {"error": res.error[:60],
                                                           "classification": res.classification})
            raise HTTPException(403, "Google Drive was not connected. " + (
                "A Google Workspace admin policy blocked it; IT has been told." if res.classification == "blocked_by_ca"
                else "Google Drive access must be allowed on the consent screen." if res.error ==
                "drive_scope_not_granted" else "Please try again."))
        s = settings()
        try:
            sub, email = check_claims(res.id_claims, s.google_allowed_domain, _google_expected(u["upn"], s))
        except ClaimsError as e:
            c = res.id_claims
            db.audit(actor, "google_connect_denied", uid,
                     {"reason": e.reason, "hd": str(c.get("hd", ""))[:100], "email": str(c.get("email", ""))[:200]})
            raise HTTPException(403, str(e)) from None
        if not res.refresh_token:
            raise HTTPException(403, "Google did not grant offline access. Please connect again.")
        other = db.google_credential_by_sub(sub)
        if other is not None and other["user_id"] != uid:
            db.audit(actor, "google_connect_denied", uid, {"reason": "google_account_linked_to_other_user"})
            raise HTTPException(409, "This Google account is already connected for another user. Ask IT.")
        drive = google.get_drive(res.access_token)
        if str(drive.get("email", "")).lower() != email:
            db.audit(actor, "google_connect_denied", uid, {"reason": "drive_account_mismatch"})
            raise HTTPException(403, "The Google Drive account does not match the Google sign-in.")
        reconnect = db.google_credential(uid) is not None
        db.put_google_credential(kr, uid, res.refresh_token, sub, email, res.scope or "")
        if u["state"] in (D.NEEDS_REAUTH, D.BLOCKED_BY_CA):
            reconnect_state(uid)
        if s.nas_option == "B" and not db.user(uid)["state"] == D.ACTIVE:
            db.update_profile(uid, preflight_requested=1)
        db.audit(actor, "google_reconnected" if reconnect else "google_connected", uid,
                 {"upn": u["upn"], "google_email": email, "alias": email != u["upn"].lower(),
                  "scope": res.scope or ""})
        resp = RedirectResponse("/me?msg=google_connected", 303)
        resp.delete_cookie(flow_cookie, path="/auth")
        return resp

    @app.post("/logout")
    async def logout(request: Request):
        sess = get_session(request)
        if sess:
            await check_csrf(request, sess)
            db.q("DELETE FROM sessions WHERE id=?", (sess["_sid"],))
        resp = RedirectResponse("/", 303)
        resp.delete_cookie(cookie, path="/")
        return resp

    # ---- user area ------------------------------------------------------
    me = APIRouter(prefix="/me")
    user_dep = require(ROLE_USER)

    @me.get("", response_class=HTMLResponse)
    def me_page(request: Request, sess: dict = Depends(user_dep)):
        uid = sess["user_id"]
        u = db.user_full(uid)
        s = settings()
        return render(request, "me.html", sess, u=u, runs=db.runs(uid, 10), issues=db.open_issues(uid),
                      nas=db.nas_credential_meta(uid), ms=db.cloud_credential(uid), nas_option=s.nas_option,
                      cv=cloud.view(u, s), google_ready=_google_ready(u), gcred=db.google_credential(uid),
                      has_preflight=(Path(cfg.p_state) / "preflight" / f"{uid}.json").exists(),
                      msg=request.query_params.get("msg", ""))

    @me.post("/nas")
    async def me_nas(request: Request, sess: dict = Depends(user_dep)):
        form = await check_csrf(request, sess)
        uid = sess["user_id"]
        if settings().nas_option != "A":
            raise HTTPException(400, "NAS logins are not used in the current NAS option.")
        if db.rate_limited(f"nasverify:{uid}"):
            raise HTTPException(429, "Too many attempts. Try again in 15 minutes.")
        user, pw = str(form.get("username", "")).strip(), str(form.get("password", ""))
        status = worker.verify_nas(user, pw)
        db.audit(sess["oid"], "nas_verify", uid, {"result": status})
        if status != "ok":
            return RedirectResponse("/me?msg=" + status, 303)
        db.put_nas_credential(kr, uid, "A", user, pw)
        u = db.user(uid)
        if u["state"] == D.NAS_AUTH_FAILED:
            db.set_state(uid, D.ACTIVE)  # resume by re-entering credentials (SPEC §4.2)
            db.close_issues(uid, "nas_auth_failed")
        elif u["state"] == D.ONBOARDING:
            db.update_profile(uid, preflight_requested=1)
        return RedirectResponse("/me?msg=ok", 303)

    @me.post("/preflight")
    async def me_preflight(request: Request, sess: dict = Depends(user_dep)):
        await check_csrf(request, sess)
        db.update_profile(sess["user_id"], preflight_requested=1)
        return RedirectResponse("/me?msg=preflight", 303)

    @me.get("/preflight.json")
    def me_preflight_report(sess: dict = Depends(user_dep)):
        p = Path(cfg.p_state) / "preflight" / f"{sess['user_id']}.json"
        if not p.exists():
            raise HTTPException(404, "No report yet.")
        return FileResponse(p, media_type="application/json", filename="preflight-report.json")

    app.include_router(me)
    app.state.templates_friendly = friendly

    # ---- admin area -----------------------------------------------------
    adm = APIRouter(prefix="/admin")
    admin_dep = require(ROLE_ADMIN)

    def overview() -> dict:
        s = settings()
        alive, hb = worker_alive(db)
        tls = db.heartbeat("tls_expiry")
        users = db.users(include_removed=True)
        return {"users": users, "cviews": {u["id"]: cloud.view(u, s) for u in users},
                "issues": db.open_issues(), "worker_alive": alive,
                "worker_hb": hb, "expiry": credential_expiry(cfg, s), "disk": disk_free_pct(cfg.p_state),
                "tls": tls["detail"] if tls else "", "chain": db.heartbeat("audit_chain"), "s": s,
                "nas_option": s.nas_option, "nas_pause": db.flag(D.NAS_GLOBAL_PAUSE), "sm": service_mode.view(db),
                "sm_limits": (service_mode.MIN_HOURS, service_mode.MAX_HOURS, service_mode.DEFAULT_HOURS),
                "sm_confirm": service_mode.CONFIRM_ALL,
                "google_app": db.flag("google_app_credential"),
                "disabled_providers": sorted({cloud.provider(u) for u in users if u["state"] != D.REMOVED
                                              and not cloud.provider_enabled(u, s)})}

    @adm.get("", response_class=HTMLResponse)
    def admin_home(request: Request, sess: dict = Depends(admin_dep)):
        return render(request, "admin.html", sess, **overview())

    def _backup_test_status() -> dict | None:
        hb = db.heartbeat("backup_test")
        try:
            return json.loads(hb["detail"]) if hb and hb["detail"] else None
        except ValueError:
            return None

    @adm.get("/settings", response_class=HTMLResponse)
    def admin_settings(request: Request, sess: dict = Depends(admin_dep)):
        s = settings_store.load(db, cfg)  # secrets not decrypted: shown as set/not set only
        set_flags = {k: bool(db.one("SELECT 1 FROM settings WHERE key=? AND is_secret=1", (k,)))
                     for k, sp in settings_store.SPECS.items() if sp.secret}
        return render(request, "admin_settings.html", sess, s=s, specs=settings_store.SPECS, set_flags=set_flags,
                      list_keys=settings_store.LIST_KEYS, bool_keys=settings_store.BOOL_KEYS,
                      google_configured=cfg.google_configured, backup_test=_backup_test_status(),
                      nas_pause=db.flag(D.NAS_GLOBAL_PAUSE), svc_test=svc_test_status(db),
                      auto_update=autoupdate.state(cfg, db),   # v0.11: read-only, the GUI never updates (§11.4.1)
                      msg=request.query_params.get("msg", ""), err=request.query_params.get("err", ""))

    @adm.post("/settings")
    async def admin_settings_save(request: Request, sess: dict = Depends(admin_dep)):
        form = await check_csrf(request, sess)
        form.pop("csrf", None)
        try:
            changed = settings_store.update(db, cfg, kr, form, sess["oid"])
        except ValueError as e:
            from urllib.parse import quote
            return RedirectResponse("/admin/settings?err=" + quote(str(e)[:400]), 303)
        return RedirectResponse(f"/admin/settings?msg=saved+{len(changed)}+change(s)", 303)

    @adm.post("/settings/backup-test")
    async def admin_backup_test(request: Request, sess: dict = Depends(admin_dep)):
        """v0.9 §6.4: the worker mounts the backup target and writes/removes a marker on its next tick."""
        await check_csrf(request, sess)
        db.set_flag("backup_test_requested", "admin test", by=sess["upn"])
        db.audit(sess["oid"], "backup_target_test_requested", "", {"target": settings().pull_backup_target})
        return RedirectResponse("/admin/settings?msg=Backup+target+test+requested+(result+within+a+minute)", 303)

    @adm.post("/settings/nas-test")
    async def admin_nas_test(request: Request, sess: dict = Depends(admin_dep)):
        form = await check_csrf(request, sess)
        if db.rate_limited(f"nasverify:admin:{sess['oid']}"):
            raise HTTPException(429, "Too many attempts. Try again in 15 minutes.")
        status = worker.verify_nas(str(form.get("username", "")), str(form.get("password", "")))  # never stored
        db.audit(sess["oid"], "nas_test", "", {"result": status})
        return RedirectResponse("/admin/settings?msg=NAS+test:+" + status, 303)

    @adm.get("/users/{uid}", response_class=HTMLResponse)
    def admin_user(uid: str, request: Request, sess: dict = Depends(admin_dep)):
        u = db.user_full(uid)
        if not u:
            raise HTTPException(404)
        return render(request, "user_detail.html", sess, u=u, runs=db.runs(uid, 30), issues=db.open_issues(uid),
                      nas=db.nas_credential_meta(uid), ms=db.cloud_credential(uid), admin=True,
                      safety=_safety_view(u, with_delta=True), cv=cloud.view(u, settings()),
                      providers=settings().providers(), **_sm_user(u))

    def _sm_user(u) -> dict:
        w = service_mode.user_window(u)
        return {"sm_user": w, "sm_global": service_mode.global_window(db),
                "sm_scope": service_mode.active_scope(db, u),
                "sm_eligible": bool(u["onboarding_completed_at"]) and u["state"] not in (D.REMOVED, D.OFFBOARDING),
                "sm_deletes": service_mode.deletes_during(db, w["started_at"] or "", service_mode.SCOPE_USER, u["id"])
                if w else [],
                "sm_limits": (service_mode.MIN_HOURS, service_mode.MAX_HOURS, service_mode.DEFAULT_HOURS)}

    @adm.post("/service-mode")
    async def admin_service_mode(request: Request, sess: dict = Depends(admin_dep)):
        """SPEC v0.8 §9.5: the All-users switch and the Selected-accounts picker. IT admins only."""
        form = await check_csrf(request, sess)
        raw = await request.form()
        scope, op = str(form.get("scope", "")), str(form.get("op", ""))
        alerter = Alerter(db)
        actor, upn = sess["oid"], sess["upn"]
        if scope not in ("all", "selected") or op not in ("on", "off"):
            raise HTTPException(400, "bad service-mode request")
        if op == "on":
            try:
                hours = service_mode.parse_hours(form.get("hours"))
                reason = service_mode.parse_reason(form.get("reason"))
            except ValueError as e:
                raise HTTPException(400, str(e)) from None
        if scope == "all":
            if op == "on":
                if str(form.get("confirm", "")).strip() != service_mode.CONFIRM_ALL:
                    raise HTTPException(400, f"Type {service_mode.CONFIRM_ALL} to confirm service mode for everyone.")
                service_mode.enable_all(db, alerter, actor, upn, hours, reason, settings())
            else:
                service_mode.disable_all(db, alerter, actor, upn, s=settings())
            return RedirectResponse("/admin", 303)
        ids = [str(x) for x in raw.getlist("user_id")]
        if not ids:
            raise HTTPException(400, "Select at least one account.")
        users = [db.user_full(i) for i in ids]
        if any(u is None for u in users):
            raise HTTPException(404)
        for u in users:
            if op == "on":
                if not u["onboarding_completed_at"] or u["state"] in (D.REMOVED, D.OFFBOARDING):
                    raise HTTPException(409, f"{u['upn']}: service mode doesn't apply (onboarding incomplete or "
                                             "leaving). Nothing was changed.")
        for u in users:
            if op == "on":
                service_mode.enable_user(db, alerter, u["id"], actor, upn, hours, reason, settings())
            else:
                service_mode.disable_user(db, alerter, u["id"], actor, upn, s=settings())
        return RedirectResponse("/admin", 303)

    def _delta_doc(uid: str) -> dict | None:
        f = delta_file(cfg, uid)
        return json.loads(f.read_text()) if f.exists() else None

    def _safety_view(u, with_delta: bool) -> dict | None:
        """Counts and decision state only (no file names) for admins and auditors alike. The file list
        has its own admin-only, audited page (SPEC v0.3 §14.13)."""
        if not u["safety_abort_at"]:
            return None
        at = D.parse_iso(u["safety_action_at"])
        v = {"abort": json.loads(u["safety_abort_json"] or "{}"), "at": u["safety_abort_at"],
             "delta_at": u["safety_delta_at"], "delta_summary": u["safety_delta_summary"],
             "delta_pending": bool(u["safety_delta_requested"]), "action": u["safety_action"],
             "action_by": u["safety_action_by"], "action_at": u["safety_action_at"],
             "restore_when": u["safety_restore_when"], "approved_deletes": u["safety_approved_deletes"],
             "approved_p1": u["safety_approved_del_p1"], "approved_p2": u["safety_approved_del_p2"],
             "requeued": bool(u["safety_restore_requeued"]),
             "abort_sides": json.loads(u["safety_abort_json"] or "{}").get("per_side", {}),
             "accept_state": (D.ACCEPT_PENDING if u["safety_action"] == D.SAFETY_ACCEPT else u["safety_accept_state"]),
             "accept_state_at": u["safety_accept_state_at"], "restore_timeouts": u["restore_timeouts"],
             "expires_at": D.iso(at + timedelta(hours=D.ACCEPT_TTL_HOURS))
             if at and u["safety_action"] == D.SAFETY_ACCEPT else None,
             "delete_count": None, "del_p1": None, "del_p2": None, "has_list": False,
             "onboarding": not u["onboarding_completed_at"],
             "no_delta": json.loads(u["safety_abort_json"] or "{}").get("during") == "dryrun",
             "tonight_held_at": u["tonight_held_at"],
             "one_way": cloud.is_pull(u),
             "cloud": cloud.CLOUD_SIDE[cloud.provider(u)]}
        if with_delta and u["safety_delta_at"]:
            d = _delta_doc(u["id"])
            if d is not None:
                v["del_p1"], v["del_p2"] = delete_counts(d)
                v["delete_count"], v["has_list"] = delete_count(d), True
        return v

    @adm.get("/users/{uid}/safety-delta", response_class=HTMLResponse)
    def admin_safety_delta(uid: str, request: Request, sess: dict = Depends(admin_dep)):
        """The safety-abort file list. IT admins only; every view is audited (SPEC v0.3 §14.13: until
        Walter signs off on admins seeing file names)."""
        u = db.user_full(uid)
        # v0.9: also the Mirror baseline list (what Mirror would move to the backup target), same rules
        if not u or not (u["safety_delta_at"] or u["mirror_baseline_counted_at"]):
            raise HTTPException(404)
        d = _delta_doc(uid)
        if d is None:
            raise HTTPException(404)
        entries = d.get("items", [])
        db.audit(sess["oid"], "safety_delta_viewed", uid,
                 {"viewer_upn": sess["upn"], "user_upn": u["upn"], "entries": len(entries),
                  "delta_at": u["safety_delta_at"] or u["mirror_baseline_counted_at"],
                  "list": "safety" if u["safety_delta_at"] else "mirror_baseline"})
        p1, p2 = delete_counts(d)
        summary = u["safety_delta_summary"] or (
            f"Mirror baseline: {u['mirror_baseline_count']} of {u['mirror_baseline_total']} NAS file(s) would be "
            "moved to the backup target")
        return render(request, "safety_delta.html", sess, u=u, entries=entries[:500],
                      truncated=bool(d.get("truncated")) or len(entries) > 500, summary=summary,
                      del_p1=p1, del_p2=p2)

    @adm.post("/users/{uid}/{action}")
    async def admin_user_action(uid: str, action: str, request: Request, sess: dict = Depends(admin_dep)):
        form = await check_csrf(request, sess)
        u = db.user_full(uid)
        if not u:
            raise HTTPException(404)
        actor = sess["oid"]
        if action not in ADMIN_USER_ACTIONS:
            raise HTTPException(404)
        details: dict = {"upn": u["upn"]}
        if action.startswith("safety-") and u["state"] != D.SAFETY_ABORT:
            raise HTTPException(409, "This user is not stopped by a safety abort.")
        if action in ("set-direction", "set-gdocs-mode", "set-provider", "approve-mirror-baseline",
                      "recount-mirror-baseline", "safety-retry", "safety-switch-copy"):
            return _cloud_action(uid, action, u, form, sess)
        if action == "safety-restore" and cloud.is_pull(u):
            raise HTTPException(409, "One-way users have no Restore (the cloud is never written). Use Accept "
                                     "deletes, Switch to Copy only, or Retry.")
        if action in ("service-mode-on", "service-mode-off"):
            alerter = Alerter(db)
            if action == "service-mode-off":
                service_mode.disable_user(db, alerter, uid, actor, sess["upn"], s=settings())
                return RedirectResponse(f"/admin/users/{uid}", 303)
            if not u["onboarding_completed_at"] or u["state"] in (D.REMOVED, D.OFFBOARDING):
                raise HTTPException(409, "Service mode doesn't apply to this user (onboarding incomplete or leaving).")
            try:
                hours = service_mode.parse_hours(form.get("hours"))
                reason = service_mode.parse_reason(form.get("reason"))
            except ValueError as e:
                raise HTTPException(400, str(e)) from None
            service_mode.enable_user(db, alerter, uid, actor, sess["upn"], hours, reason, settings())
            return RedirectResponse(f"/admin/users/{uid}", 303)  # audited inside (service_mode_*)
        if action == "pause":
            db.set_state(uid, D.PAUSED, f"paused by admin {sess['upn']}")
        elif action == "resume":
            if u["state"] not in (D.PAUSED,):
                raise HTTPException(409, "Only paused users can be resumed here.")
            db.set_state(uid, D.ACTIVE if u["last_success_at"] else D.ONBOARDING)
        elif action == "approve-resync":
            if u["state"] == D.SAFETY_ABORT:
                raise HTTPException(409, "Safety abort: use Restore or Accept deletes.")
            if not u["dryrun_ok_at"] and u["state"] == D.ONBOARDING:
                raise HTTPException(409, "Run and review the dry-run first.")
            if cloud.is_pull(u) and u["state"] not in (D.ONBOARDING, D.CRITICAL):
                raise HTTPException(409, "One-way users don't resync; switch to two-way for a new bisync baseline.")
            if not (u["needs_resync"] or u["state"] in (D.ONBOARDING, D.CRITICAL)):
                raise HTTPException(409, "This user does not need a resync.")
            prof = dict(resync_approved_by=actor, resync_approved_at=D.iso(D.utcnow()))
            if cloud.direction(u) == cloud.PULL_MIRROR and u["state"] == D.ONBOARDING:
                # SPEC v0.9 §6.1 step 9: the Mirror baseline count shown with the approval is approved with it
                try:
                    shown = int(str(form.get("baseline_count", "")))
                except ValueError:
                    raise HTTPException(400, "Missing the Mirror baseline count.") from None
                if u["mirror_baseline_count"] is None or shown != u["mirror_baseline_count"]:
                    raise HTTPException(409, "The Mirror baseline count changed; reload and review.")
                prof.update(mirror_baseline_approved_by=sess["upn"], mirror_baseline_approved_at=prof["resync_approved_at"],
                            mirror_baseline_approved_count=shown, mirror_baseline_state=cloud.BASELINE_PENDING)
                details.update(mirror_baseline_moves=shown, total=u["mirror_baseline_total"])
            db.update_profile(uid, **prof)
            db.close_issues(uid, "approval_needed")
        elif action == "request-dryrun":
            db.update_profile(uid, dryrun_ok_at=None, dryrun_summary=None, last_run_at=None)
            if u["state"] == D.CRITICAL:
                db.set_state(uid, D.ONBOARDING, "repair: dry-run requested")
        elif action == "offboard":
            if form.get("confirm") != u["upn"]:
                raise HTTPException(400, "Type the user's UPN to confirm offboarding.")
            db.update_profile(uid, final_sync_requested=1 if form.get("final_sync") == "on" else 0)
            db.set_state(uid, D.OFFBOARDING, f"offboarded by {sess['upn']}")
        elif action in ("safety-restore", "safety-accept-deletes"):
            # SPEC v0.2 §9.4: both need the dry-run delta list first; both are audited with the counts.
            # SPEC v0.5 §6.1 step 8: an abort on the onboarding dry-run has no listings, hence no delta list
            # and nothing to accept; only Restore (= re-run the onboarding --resync) is offered.
            abort = json.loads(u["safety_abort_json"] or "{}")
            onboarding = not u["onboarding_completed_at"]
            no_delta = abort.get("during") == "dryrun"
            if no_delta and action == "safety-accept-deletes":
                raise HTTPException(409, "Nothing to accept: the abort happened on the onboarding dry run.")
            if not no_delta and (not u["safety_delta_at"] or u["safety_delta_requested"]):
                raise HTTPException(409, "Wait for the dry-run delta list before choosing.")
            if u["safety_action"]:
                raise HTTPException(409, f"Already approved: {u['safety_action']}.")
            now = D.iso(D.utcnow())
            details.update(abort=json.loads(u["safety_abort_json"] or "{}"), delta=u["safety_delta_summary"])
            if action == "safety-restore":
                when = str(form.get("when") or D.RESTORE_NEXT_SLOT)
                if when not in (D.RESTORE_NEXT_SLOT, D.RESTORE_TONIGHT):
                    raise HTTPException(400, "Choose 'next slot' or 'tonight'.")
                if onboarding:
                    when = D.RESTORE_TONIGHT   # the onboarding --resync runs in resync_hours (no time limit)
                    details["onboarding_resync"] = True
                db.update_profile(uid, safety_action=D.SAFETY_RESTORE, safety_action_by=actor, safety_action_at=now,
                                  safety_restore_when=when, safety_restore_requeued=0, tonight_hold_nights=0,
                                  tonight_held_at=None, needs_resync=1,
                                  resync_approved_by=actor,
                                  resync_approved_at=now, safety_accept_state=None, safety_accept_state_at=None)
                details["when"] = when
                if onboarding and no_delta:
                    # SPEC v0.6 §6.1 step 8: straight to the real onboarding --resync (no fresh dry run); the
                    # Restore click IS the approval of the first sync, recorded as its own audit action.
                    db.audit(actor, "admin_first_sync_approved_via_restore", uid,
                             {"by_upn": sess.get("upn"), "abort_during": "dryrun", "dry_run_skipped": True})
            else:
                if form.get("confirm") != u["upn"]:
                    raise HTTPException(400, "Type the user's UPN to confirm Accept deletes.")
                d = _delta_doc(uid)
                if d is None:
                    raise HTTPException(409, "The dry-run delta list is missing; refresh it first.")
                p1, p2 = delete_counts(d)
                try:
                    shown = (int(str(form.get("approved_deletes_path1", ""))), int(str(form.get("approved_deletes_path2", ""))))
                except ValueError:
                    raise HTTPException(400, "Missing per-side delete counts.") from None
                if shown != (p1, p2):   # the page the admin looked at is stale
                    raise HTTPException(409, f"The delete counts changed (shown Path1={shown[0]} Path2={shown[1]}, "
                                             f"now Path1={p1} Path2={p2}). Reload and review.")
                n = p1 + p2
                db.update_profile(uid, safety_action=D.SAFETY_ACCEPT, safety_action_by=actor, safety_action_at=now,
                                  safety_approved_deletes=n, safety_approved_del_p1=p1, safety_approved_del_p2=p2,
                                  safety_accept_state=D.ACCEPT_PENDING, safety_accept_state_at=now)
                details.update(approved_deletes_path1=p1, approved_deletes_path2=p2, expires_at=D.iso(D.utcnow() + timedelta(hours=D.ACCEPT_TTL_HOURS)))
        elif action == "safety-refresh-delta":
            if u["safety_action"]:
                raise HTTPException(409, f"Already approved: {u['safety_action']}.")
            db.update_profile(uid, safety_delta_requested=1, safety_delta_at=None, safety_delta_summary=None,
                              next_run_at=None)
        db.audit(actor, f"admin_{action.replace('-', '_')}", uid, details)
        return RedirectResponse(f"/admin/users/{uid}", 303)

    def _job_running(uid: str) -> bool:
        return db.one("SELECT 1 FROM sync_runs WHERE user_id=? AND ended_at IS NULL AND started_at > ?",
                      (uid, D.iso(D.utcnow() - timedelta(hours=6)))) is not None

    def _cloud_action(uid: str, action: str, u, form: dict, sess: dict):
        """v0.9 direction / provider / Google-files / Mirror-baseline / one-way safety actions. Admin only;
        every change is audited inside cloud.* or here."""
        if u["state"] in (D.REMOVED, D.OFFBOARDING):
            raise HTTPException(409, "This user is leaving or removed.")
        actor, upn = sess["oid"], sess["upn"]
        s = settings()
        try:
            if action == "set-direction":
                to = str(form.get("direction", ""))
                mf = (form.get("mirror_first") == "on") if form.get("mf_shown") else None
                cloud.request_direction(db, uid, to, str(form.get("reason", "")), actor, upn, mirror_first=mf)
            elif action == "set-gdocs-mode":
                cloud.set_gdocs_mode(db, uid, str(form.get("gdocs_mode", "")), actor, upn)
            elif action == "approve-mirror-baseline":
                if form.get("confirm") != u["upn"]:
                    raise HTTPException(400, "Type the user's UPN to confirm the Mirror baseline.")
                try:
                    n = int(str(form.get("count", "")))
                except ValueError:
                    raise HTTPException(400, "Missing the count.") from None
                cloud.approve_baseline(db, uid, n, actor, upn)
                db.close_issues(uid, "mirror_baseline_approval")
            elif action == "recount-mirror-baseline":
                cloud.recount_baseline(db, uid, actor, upn)
            elif action in ("safety-retry", "safety-switch-copy"):
                if u["state"] != D.SAFETY_ABORT or not cloud.is_pull(u):
                    raise HTTPException(409, "Only for a one-way user stopped by a safety abort.")
                reason = str(form.get("reason", "")) or ("retry after review" if action == "safety-retry" else "")
                if action == "safety-switch-copy":
                    cloud.request_direction(db, uid, cloud.PULL_COPY, reason or "safety abort: switch to Copy only",
                                            actor, upn)
                else:
                    from odnas.runner import _SAFETY_CLEAR
                    if u["safety_action"]:
                        raise HTTPException(409, f"Already approved: {u['safety_action']}.")
                    db.update_profile(uid, **_SAFETY_CLEAR, next_run_at=None)
                    db.set_state(uid, D.ACTIVE)
                    db.close_issues(uid, "safety_abort")
                    db.audit(actor, "admin_safety_retry", uid, {"upn": u["upn"], "reason": reason,
                                                                "abort": json.loads(u["safety_abort_json"] or "{}")})
            else:   # set-provider
                to = str(form.get("provider", ""))
                if to not in cloud.PROVIDERS or to == cloud.provider(u):
                    raise HTTPException(400, "Choose the other provider.")
                if to not in s.providers():
                    raise HTTPException(409, "That provider is not enabled in Settings.")
                if form.get("confirm") != u["upn"]:
                    raise HTTPException(400, "Type the user's UPN to confirm the provider change.")
                if _job_running(uid):
                    raise HTTPException(409, "A sync is running for this user. Pause the user, wait for it to "
                                             "finish, then change the provider.")
                cloud.set_provider(db, cfg, Alerter(db), uid, to, str(form.get("reason", "")), actor, upn,
                                   rec=[x.strip() for x in (s.alert_recipients or "").split(",") if x.strip()])
        except ValueError as e:
            raise HTTPException(400, str(e)) from None
        return RedirectResponse(f"/admin/users/{uid}", 303)

    app.include_router(adm)

    # ---- auditor area: GET ONLY ---------------------------------------------
    aud = APIRouter(prefix="/audit")
    auditor_dep = require(ROLE_AUDITOR, ROLE_ADMIN)

    @aud.get("", response_class=HTMLResponse)
    def audit_home(request: Request, sess: dict = Depends(auditor_dep)):
        return render(request, "audit.html", sess, **overview())

    @aud.get("/users/{uid}", response_class=HTMLResponse)
    def audit_user(uid: str, request: Request, sess: dict = Depends(auditor_dep)):
        u = db.user_full(uid)
        if not u:
            raise HTTPException(404)
        return render(request, "user_detail.html", sess, u=u, runs=db.runs(uid, 30), issues=db.open_issues(uid),
                      nas=db.nas_credential_meta(uid), ms=db.cloud_credential(uid), admin=False,
                      safety=_safety_view(u, with_delta=False), cv=cloud.view(u, settings()),
                      providers=settings().providers(), **_sm_user(u))

    def _audit_filter(request: Request) -> list:
        qp = request.query_params
        return db.audit_rows(qp.get("actor", ""), qp.get("action", ""), qp.get("since", ""))

    @aud.get("/log", response_class=HTMLResponse)
    def audit_log(request: Request, sess: dict = Depends(auditor_dep)):
        ok, n, msg = db.verify_audit_chain()
        return render(request, "audit_log.html", sess, rows=_audit_filter(request), chain_ok=ok, chain_n=n,
                      chain_msg=msg, qp=request.query_params)

    @aud.get("/log.csv")
    def audit_csv(request: Request, sess: dict = Depends(auditor_dep)):
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["seq", "ts", "actor", "action", "target", "details_json", "prev_hash", "hash"])
        for r in _audit_filter(request):
            w.writerow([r["seq"], r["ts"], r["actor"], r["action"], r["target"], r["details_json"], r["prev_hash"],
                        r["hash"]])
        return PlainTextResponse(buf.getvalue(), media_type="text/csv",
                                 headers={"Content-Disposition": "attachment; filename=audit-log.csv"})

    app.include_router(aud)
    return app


def build_from_env() -> FastAPI:
    """Entry point for `odnas web` (uvicorn factory)."""
    from odnas.config import load_config
    from odnas.entra import MsalEntraClient
    cfg = load_config()
    db = D.DB(cfg.p_db)
    kr = Keyring.from_config(cfg)
    from odnas.google import HttpGoogleClient
    return create_app(cfg, db, kr, MsalEntraClient(cfg), google=HttpGoogleClient(cfg))


def iter_routes(app: FastAPI):
    """Flatten (path, methods) for every endpoint, including routes inside included routers
    (FastAPI >= 0.150 keeps included routers nested)."""
    from fastapi.routing import APIRoute

    def walk(routes, prefix=""):
        for r in routes:
            if isinstance(r, APIRoute):
                yield (r.path if r.path.startswith(prefix) else prefix + r.path), set(r.methods)
            elif hasattr(r, "original_router"):
                yield from walk(r.original_router.routes, "")
    yield from walk(app.routes)
