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

from odnas import __version__
from odnas import db as D
from odnas import settings_store
from odnas.config import Config
from odnas.crypto import Keyring
from odnas.db import pack, unpack
from odnas.entra import EntraClient
from odnas.nas import V_ERROR, friendly, local_name_from_upn
from odnas.runner import delete_count, delete_counts, delta_file
from odnas.scheduler import LOCAL_TZ
from odnas.status import credential_expiry, disk_free_pct, worker_alive

log = logging.getLogger("odnas.web")
HERE = Path(__file__).resolve().parent
SESSION_HOURS = 8
ROLE_USER, ROLE_ADMIN, ROLE_AUDITOR = "user", "admin", "auditor"
# Every POST /admin/users/{uid}/{action}. IT-admin role only (SpringSync-Admins); auditors get 403.
ADMIN_USER_ACTIONS = ("pause", "resume", "approve-resync", "request-dryrun", "offboard",
                      "safety-restore", "safety-accept-deletes", "safety-refresh-delta")

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


def local_time(v: str | None) -> str:
    if not v:
        return "never"
    return D.parse_iso(v).astimezone(LOCAL_TZ).strftime("%Y-%m-%d %H:%M %Z")


def create_app(cfg: Config, db: D.DB, kr: Keyring, entra: EntraClient,
               worker: WorkerClient | None = None) -> FastAPI:
    app = FastAPI(title=cfg.product_name, docs_url=None, redoc_url=None, openapi_url=None)
    templates = Jinja2Templates(directory=str(HERE / "templates"))
    templates.env.filters["local"] = local_time
    templates.env.globals.update(product=cfg.product_name, version=__version__, labels=D.STATE_LABELS)
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
        if allowed and res.refresh_token:
            u = db.user_by_oid(oid)
            drive = entra.get_drive(res.access_token)
            if u is None:
                uid = db.create_user(oid, upn, data["name"], local_name_from_upn(upn), D.ONBOARDING, True)
                db.audit(oid, "user_connected", uid, {"upn": upn})
            else:
                uid = u["id"]
                if u["state"] == D.REMOVED:
                    db.set_state(uid, D.ONBOARDING)
                    db.update_profile(uid, enabled=1, needs_resync=1, dryrun_ok_at=None, preflight_at=None)
                elif u["state"] in (D.NEEDS_REAUTH, D.BLOCKED_BY_CA):
                    db.set_state(uid, D.ACTIVE)  # resumes automatically on the next slot (SPEC §6.2)
                    db.close_issues(uid, "needs_reauth", "blocked_by_ca")
                db.audit(oid, "user_reconnected", uid, {"upn": upn})
            db.put_ms_credential(kr, uid, res.refresh_token, drive["id"], drive.get("driveType", "business"))
            if s.nas_option == "B" and not db.user(uid)["state"] == D.ACTIVE:
                db.update_profile(uid, preflight_requested=1)
            data["user_id"] = uid
        elif is_user and not allowed:
            db.audit(oid, "connect_denied_not_on_pilot", "", {"upn": upn})
        db.audit(oid, "login", "", {"upn": upn})
        resp = RedirectResponse("/", 303)
        resp.delete_cookie(flow_cookie, path="/auth")
        new_session(resp, data)
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
                      nas=db.nas_credential_meta(uid), ms=db.ms_credential(uid), nas_option=s.nas_option,
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
        return {"users": db.users(include_removed=True), "issues": db.open_issues(), "worker_alive": alive,
                "worker_hb": hb, "expiry": credential_expiry(cfg, s), "disk": disk_free_pct(cfg.p_state),
                "tls": tls["detail"] if tls else "", "chain": db.heartbeat("audit_chain"), "s": s,
                "nas_option": s.nas_option}

    @adm.get("", response_class=HTMLResponse)
    def admin_home(request: Request, sess: dict = Depends(admin_dep)):
        return render(request, "admin.html", sess, **overview())

    @adm.get("/settings", response_class=HTMLResponse)
    def admin_settings(request: Request, sess: dict = Depends(admin_dep)):
        s = settings_store.load(db, cfg)  # secrets not decrypted: shown as set/not set only
        set_flags = {k: bool(db.one("SELECT 1 FROM settings WHERE key=? AND is_secret=1", (k,)))
                     for k, sp in settings_store.SPECS.items() if sp.secret}
        return render(request, "admin_settings.html", sess, s=s, specs=settings_store.SPECS, set_flags=set_flags,
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
                      nas=db.nas_credential_meta(uid), ms=db.ms_credential(uid), admin=True,
                      safety=_safety_view(u, with_delta=True))

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
             "delete_count": None, "del_p1": None, "del_p2": None, "has_list": False}
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
        if not u or not u["safety_delta_at"]:
            raise HTTPException(404)
        d = _delta_doc(uid)
        if d is None:
            raise HTTPException(404)
        entries = d.get("items", [])
        db.audit(sess["oid"], "safety_delta_viewed", uid,
                 {"viewer_upn": sess["upn"], "user_upn": u["upn"], "entries": len(entries),
                  "delta_at": u["safety_delta_at"]})
        p1, p2 = delete_counts(d)
        return render(request, "safety_delta.html", sess, u=u, entries=entries[:500],
                      truncated=bool(d.get("truncated")) or len(entries) > 500, summary=u["safety_delta_summary"],
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
            if not (u["needs_resync"] or u["state"] in (D.ONBOARDING, D.CRITICAL)):
                raise HTTPException(409, "This user does not need a resync.")
            db.update_profile(uid, resync_approved_by=actor, resync_approved_at=D.iso(D.utcnow()))
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
            # SPEC v0.2 §9.4: both need the dry-run delta list first; both are audited with the counts
            if not u["safety_delta_at"] or u["safety_delta_requested"]:
                raise HTTPException(409, "Wait for the dry-run delta list before choosing.")
            if u["safety_action"]:
                raise HTTPException(409, f"Already approved: {u['safety_action']}.")
            now = D.iso(D.utcnow())
            details.update(abort=json.loads(u["safety_abort_json"] or "{}"), delta=u["safety_delta_summary"])
            if action == "safety-restore":
                when = str(form.get("when") or D.RESTORE_NEXT_SLOT)
                if when not in (D.RESTORE_NEXT_SLOT, D.RESTORE_TONIGHT):
                    raise HTTPException(400, "Choose 'next slot' or 'tonight'.")
                db.update_profile(uid, safety_action=D.SAFETY_RESTORE, safety_action_by=actor, safety_action_at=now,
                                  safety_restore_when=when, safety_restore_requeued=0, needs_resync=1,
                                  resync_approved_by=actor,
                                  resync_approved_at=now, safety_accept_state=None, safety_accept_state_at=None)
                details["when"] = when
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
                      nas=db.nas_credential_meta(uid), ms=db.ms_credential(uid), admin=False,
                      safety=_safety_view(u, with_delta=False))

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
    return create_app(cfg, db, kr, MsalEntraClient(cfg))


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
