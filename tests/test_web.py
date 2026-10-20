import re

import pytest
from starlette.testclient import TestClient

from odnas import db as D
from odnas import settings_store
from odnas.web.app import create_app, iter_routes
from tests.conftest import CANARY_PW, CANARY_RT, G_ADMINS, G_AUDIT, G_USERS, claims, seed_user


class FakeWorkerClient:
    def __init__(self, status="ok"):
        self.status, self.calls = status, []

    def verify_nas(self, username, password):
        self.calls.append((username, password))
        return self.status


@pytest.fixture
def wc():
    return FakeWorkerClient()


@pytest.fixture
def app(cfg, db, kr, entra, wc):
    settings_store.update(db, cfg, kr, {"pilot_list": "jsmith@hotsprings.org, mark@hotsprings.org"}, "test")
    return create_app(cfg, db, kr, entra, wc)


def login(app, entra, **kw):
    c = TestClient(app, follow_redirects=False)
    entra.claims = claims(**kw)
    r = c.get("/login")
    assert r.status_code == 303 and r.headers["location"].startswith("https://login.example.invalid")
    state = c.cookies.get("springsync_flow")
    r = c.get(f"/auth/callback?code=abc&state={state}")
    assert r.status_code == 303, r.text
    return c


def csrf(c, path):
    m = re.search(r'name="csrf" value="([^"]+)"', c.get(path).text)
    return m.group(1)


def test_user_onboarding_flow(app, entra, db, kr, wc):
    c = login(app, entra)
    u = db.users()[0]
    assert u["state"] == D.ONBOARDING and u["upn"] == "jsmith@hotsprings.org"
    assert db.refresh_token(kr, u["id"]) == CANARY_RT
    assert db.ms_credential(u["id"])["drive_id"] == "b!drive123"
    page = c.get("/me")
    assert page.status_code == 200 and "My sync status" in page.text and CANARY_RT not in page.text
    tok = csrf(c, "/me")
    r = c.post("/me/nas", data={"csrf": tok, "username": "jsmith", "password": CANARY_PW})
    assert r.headers["location"] == "/me?msg=ok"
    assert db.nas_credential(kr, u["id"]) == ("jsmith", CANARY_PW)
    assert db.user_full(u["id"])["preflight_requested"] == 1
    assert CANARY_PW not in c.get("/me").text


def test_wrong_nas_password_stores_nothing(app, entra, db, kr, wc):
    wc.status = "auth_failed"
    c = login(app, entra)
    r = c.post("/me/nas", data={"csrf": csrf(c, "/me"), "username": "jsmith", "password": "wrong"})
    assert r.headers["location"] == "/me?msg=auth_failed"
    assert db.nas_credential_meta(db.users()[0]["id"]) is None
    assert "did not accept" in c.get("/me?msg=auth_failed").text


def test_nas_reentry_resumes_paused_user(app, entra, db, kr, wc):
    c = login(app, entra)
    uid = db.users()[0]["id"]
    db.set_state(uid, D.NAS_AUTH_FAILED)
    c.post("/me/nas", data={"csrf": csrf(c, "/me"), "username": "jsmith", "password": "new"})
    assert db.user(uid)["state"] == D.ACTIVE


def test_nas_verify_rate_limited(app, entra, wc):
    wc.status = "auth_failed"
    c = login(app, entra)
    tok = csrf(c, "/me")
    codes = [c.post("/me/nas", data={"csrf": tok, "username": "u", "password": "p"}).status_code for _ in range(6)]
    assert codes[:5] == [303] * 5 and codes[5] == 429


def test_not_on_pilot_list_cannot_connect(app, entra, db):
    c = login(app, entra, oid="o2", upn="other@hotsprings.org")
    assert db.users() == []
    assert c.get("/me").status_code == 403


def test_wrong_tenant_rejected(app, entra):
    c = TestClient(app, follow_redirects=False)
    entra.claims = claims(tid="99999999-9999-9999-9999-999999999999")
    c.get("/login")
    r = c.get(f"/auth/callback?code=x&state={c.cookies.get('springsync_flow')}")
    assert r.status_code == 403


def test_callback_state_must_match_cookie(app, entra):
    c = TestClient(app, follow_redirects=False)
    entra.claims = claims()
    c.get("/login")
    assert c.get("/auth/callback?code=x&state=forged").status_code == 400


def test_reconnect_after_needs_reauth_resumes(app, entra, db, kr):
    login(app, entra)
    uid = db.users()[0]["id"]
    db.set_state(uid, D.NEEDS_REAUTH)
    login(app, entra)
    assert db.user(uid)["state"] == D.ACTIVE


def test_roles(app, entra):
    user = login(app, entra)
    assert user.get("/admin").status_code == 403 and user.get("/audit").status_code == 403
    walter = login(app, entra, oid="w", upn="walter@hotsprings.org", groups=(G_AUDIT,))
    assert walter.get("/audit").status_code == 200 and walter.get("/audit/log").status_code == 200
    assert walter.get("/admin").status_code == 403 and walter.get("/admin/settings").status_code == 403
    assert walter.get("/me").status_code == 403
    mark = login(app, entra, oid="m", upn="mark@hotsprings.org", groups=(G_ADMINS, G_USERS))
    assert mark.get("/admin").status_code == 200 and mark.get("/admin/settings").status_code == 200
    assert mark.get("/audit").status_code == 200 and mark.get("/me").status_code == 200


def test_auditor_area_is_get_only(app):
    routes = list(iter_routes(app))
    audit = [(p, m) for p, m in routes if p.startswith("/audit")]
    assert len(audit) >= 4  # guard against a vacuous pass
    for p, m in audit:
        assert m <= {"GET", "HEAD"}, p


def test_auditor_rejected_on_every_non_get_route(app, entra, db, kr):
    uid = seed_user(db, kr, upn="victim@hotsprings.org")
    walter = login(app, entra, oid="w", upn="walter@hotsprings.org", groups=(G_AUDIT,))
    tok = csrf(walter, "/audit")
    posts = [p for p, m in iter_routes(app) if m - {"GET", "HEAD"}]
    assert len(posts) >= 6
    for p in posts:
        path = p.replace("{uid}", uid).replace("{action}", "pause")
        if path == "/logout":
            continue  # ending your own session is allowed for everyone
        resp = walter.post(path, data={"csrf": tok, "confirm": "victim@hotsprings.org"})
        assert resp.status_code == 403, path
    assert db.user(uid)["state"] == D.ACTIVE
    assert settings_store.load(db, app.state.cfg).pilot_only is True


def test_csrf_enforced(app, entra, db, kr):
    mark = login(app, entra, oid="m", upn="mark@hotsprings.org", groups=(G_ADMINS,))
    uid = seed_user(db, kr)
    assert mark.post(f"/admin/users/{uid}/pause", data={}).status_code == 403
    assert mark.post(f"/admin/users/{uid}/pause", data={"csrf": "nope"}).status_code == 403
    assert db.user(uid)["state"] == D.ACTIVE
    assert mark.post(f"/admin/users/{uid}/pause", data={"csrf": csrf(mark, "/admin")}).status_code == 303
    assert db.user(uid)["state"] == D.PAUSED


def test_admin_settings_validate_audit_and_hide_secrets(app, entra, db, kr, cfg):
    mark = login(app, entra, oid="m", upn="mark@hotsprings.org", groups=(G_ADMINS,))
    tok = csrf(mark, "/admin/settings")
    r = mark.post("/admin/settings", data={"csrf": tok, "nas_host": "bad host/x", "max_concurrent": "2"})
    assert "err=" in r.headers["location"]
    r = mark.post("/admin/settings", data={"csrf": tok, "nas_host": "unas2.hotsprings.local", "max_concurrent": "1",
                                           "smtp_password": "CANARY-SMTP-PW", "alert_email": "x"})
    assert "saved" in r.headers["location"]
    s = settings_store.load(db, cfg, kr)
    assert s.nas_host == "unas2.hotsprings.local" and s.max_concurrent == 1 and s.secret("smtp_password") == "CANARY-SMTP-PW"
    page = mark.get("/admin/settings").text
    assert "CANARY-SMTP-PW" not in page and "*** set" in page
    log = [dict(r) for r in db.audit_rows(action="setting_changed")]
    assert any(r["target"] == "nas_host" and "unas2" in r["details_json"] for r in log)
    assert all("CANARY-SMTP-PW" not in r["details_json"] for r in log)
    walter = login(app, entra, oid="w", upn="walter@hotsprings.org", groups=(G_AUDIT,))
    assert "CANARY-SMTP-PW" not in walter.get("/audit/log").text


def test_approve_resync_requires_dryrun(app, entra, db, kr):
    mark = login(app, entra, oid="m", upn="mark@hotsprings.org", groups=(G_ADMINS,))
    uid = seed_user(db, kr, state=D.ONBOARDING)
    tok = csrf(mark, "/admin")
    assert mark.post(f"/admin/users/{uid}/approve-resync", data={"csrf": tok}).status_code == 409
    db.update_profile(uid, dryrun_ok_at=D.iso(D.utcnow()))
    assert mark.post(f"/admin/users/{uid}/approve-resync", data={"csrf": tok}).status_code == 303
    assert db.user_full(uid)["resync_approved_by"] == "m"


def test_offboard_requires_confirmation(app, entra, db, kr):
    mark = login(app, entra, oid="m", upn="mark@hotsprings.org", groups=(G_ADMINS,))
    uid = seed_user(db, kr)
    tok = csrf(mark, "/admin")
    assert mark.post(f"/admin/users/{uid}/offboard", data={"csrf": tok, "confirm": "nope"}).status_code == 400
    assert mark.post(f"/admin/users/{uid}/offboard", data={"csrf": tok, "confirm": "jsmith@hotsprings.org",
                                                           "final_sync": "on"}).status_code == 303
    u = db.user_full(uid)
    assert u["state"] == D.OFFBOARDING and u["final_sync_requested"] == 1


def test_no_secrets_on_any_admin_or_auditor_page(app, entra, db, kr):
    uid = seed_user(db, kr)
    pages = []
    for who, groups in (("m", (G_ADMINS,)), ("w", (G_AUDIT,))):
        c = login(app, entra, oid=who, upn=f"{who}@hotsprings.org", groups=groups)
        for p in ("/admin", f"/admin/users/{uid}", "/admin/settings", "/audit", f"/audit/users/{uid}", "/audit/log",
                  "/audit/log.csv"):
            r = c.get(p)
            if r.status_code == 200:
                pages.append(r.text)
    assert len(pages) >= 8
    for t in pages:
        assert CANARY_RT not in t and CANARY_PW not in t


def test_security_headers_and_healthz(app):
    c = TestClient(app)
    r = c.get("/")
    assert "script-src" not in r.headers["content-security-policy"]  # default-src 'none': no script at all
    assert r.headers["x-frame-options"] == "DENY"
    h = c.get("/healthz").json()
    assert h["db"] is True and h["worker_alive"] is False


def test_credential_expiry_shown(app, entra, db, kr, cfg):
    settings_store.update(db, cfg, kr, {"entra_credential_expires_on": "2026-11-01"}, "t")
    mark = login(app, entra, oid="m", upn="mark@hotsprings.org", groups=(G_ADMINS,))
    t = mark.get("/admin").text
    assert "expires 2026-11-01" in t and "critical" in t
