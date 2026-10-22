"""v0.12.1 (SPEC v0.10.2 §4.5.6): more step-up rules for Google sessions.

- A Restore needs a Microsoft session unless a safety delta list exists and records ONLY deletions
  (the Restore then only puts missing files back). Onboarding Restores (the first-sync approval), a missing,
  unreadable or empty list, or any new/changed/newer/older/renamed/size-changed entry need Microsoft.
- Changing the NAS login, connecting or reconnecting Google Drive and the admin set-provider action need a
  Microsoft session. The admin "Test NAS login" stays allowed (it stores nothing).
"""
import json
from dataclasses import replace

import pytest

from tests.conftest import CANARY_PW, G_ADMINS, G_USERS, seed_user
from tests.test_v09 import FakeGoogle
from tests.test_v12_signin import (  # noqa: F401  (g, scfg, sapp are fixtures)
    FakeGoogleSignin, client, csrf, g, gc, google_login, link_google, ms, sapp, scfg)
from tests.test_web import FakeWorkerClient, _safety_user
from odnas import db as D
from odnas import settings_store
from odnas.runner import delta_file
from odnas.tokens import write_private
from odnas.web.app import STEPUP_RESTORE_MSG, create_app

ADMIN_UPN = "it-admin@hotsprings.org"


def audit(db, action):
    return [json.loads(r["details_json"]) for r in db.audit_rows(action=action)]


def _google_admin(sapp, g, entra, db):
    """A Microsoft admin who linked Google, then a fresh Google session for the same admin (within 24 h)."""
    c = ms(client(sapp), entra, oid="oid-m", upn=ADMIN_UPN, groups=(G_USERS, G_ADMINS))
    link_google(c, g, gc(sub="g-sub-m", email=ADMIN_UPN))
    gs = client(sapp)
    assert google_login(gs, g, gc(sub="g-sub-m", email=ADMIN_UPN)).status_code == 303
    assert gs.get("/admin").status_code == 200
    return c, gs


def _set_delta(cfg, uid, counts, items=None, summary="delta"):
    db_items = items if items is not None else [
        {"side": s, "where": "x", "event": k, "name": f"f-{s}-{k}"} for s, c in counts.items() for k in c]
    write_private(delta_file(cfg, uid), json.dumps({"counts": counts, "items": db_items, "truncated": False}))


# ---- 1. Restore -----------------------------------------------------------------------------------------

@pytest.mark.smoke
def test_google_admin_may_restore_when_delta_is_deletions_only(sapp, g, entra, db, kr, scfg):
    _, gs = _google_admin(sapp, g, entra, db)
    uid = _safety_user(db, kr, scfg)                      # Path1 3 deleted, Path2 1 deleted, nothing else
    page = gs.get(f"/admin/users/{uid}").text
    assert "could overwrite existing files" not in page
    r = gs.post(f"/admin/users/{uid}/safety-restore", data={"csrf": csrf(gs, "/admin")})
    assert r.status_code == 303
    u = db.user_full(uid)
    assert u["safety_action"] == D.SAFETY_RESTORE and u["safety_action_by"].startswith("google:")
    assert not audit(db, "stepup_required")


@pytest.mark.smoke
@pytest.mark.parametrize("counts", [
    {"Path1": {"deleted": 3, "changed": 1}, "Path2": {}},          # newer/older/size/renamed -> "changed"
    {"Path1": {"deleted": 3}, "Path2": {"changed": 2}},
    {"Path1": {"deleted": 1}, "Path2": {"new": 1}},
])
def test_restore_that_could_overwrite_needs_microsoft(sapp, g, entra, db, kr, scfg, counts):
    mc, gs = _google_admin(sapp, g, entra, db)
    uid = _safety_user(db, kr, scfg)
    _set_delta(scfg, uid, counts)
    page = gs.get(f"/admin/users/{uid}").text
    assert "could overwrite existing files" in page and "/login?stepup=1" in page
    r = gs.post(f"/admin/users/{uid}/safety-restore", data={"csrf": csrf(gs, "/admin")})
    assert r.status_code == 403 and STEPUP_RESTORE_MSG in r.text and "/login?stepup=1" in r.text
    assert db.user_full(uid)["safety_action"] is None
    (det,) = audit(db, "stepup_required")
    assert det["action"] == "safety-restore" and det["reason"].startswith("would_overwrite:")
    assert db.audit_rows(action="stepup_required")[0]["target"] == uid
    # the same admin on a Microsoft session can
    assert "could overwrite" not in mc.get(f"/admin/users/{uid}").text
    assert mc.post(f"/admin/users/{uid}/safety-restore", data={"csrf": csrf(mc, "/admin")}).status_code == 303
    assert db.user_full(uid)["safety_action"] == D.SAFETY_RESTORE


def test_delta_items_alone_also_count(sapp, g, entra, db, kr, scfg):
    """Defence in depth: an item with a non-delete event counts even if the counts only say 'deleted'."""
    _, gs = _google_admin(sapp, g, entra, db)
    uid = _safety_user(db, kr, scfg)
    _set_delta(scfg, uid, {"Path1": {"deleted": 1}, "Path2": {}},
               items=[{"side": "Path1", "event": "changed", "name": "x"}])
    assert gs.post(f"/admin/users/{uid}/safety-restore", data={"csrf": csrf(gs, "/admin")}).status_code == 403


@pytest.mark.parametrize("case,why", [
    ("missing_file", "no_delta_list"), ("unreadable", "no_delta_list"), ("no_counts", "no_delta_list"),
    ("empty", "delta_list_empty"), ("onboarding", "onboarding_restore"),
    ("onboarding_dryrun", "onboarding_restore"),
])
def test_restore_without_a_deletions_only_list_needs_microsoft(sapp, g, entra, db, kr, scfg, case, why):
    mc, gs = _google_admin(sapp, g, entra, db)
    uid = _safety_user(db, kr, scfg)
    f = delta_file(scfg, uid)
    if case == "missing_file":
        f.unlink()
    elif case == "unreadable":
        f.write_text("{not json")
    elif case == "no_counts":
        f.write_text(json.dumps({"items": []}))
    elif case == "empty":
        _set_delta(scfg, uid, {"Path1": {}, "Path2": {}})
    elif case == "onboarding":
        db.update_profile(uid, onboarding_completed_at=None)
    else:   # abort on the onboarding dry run: no delta list at all; Restore = approve the first sync
        f.unlink()
        db.update_profile(uid, onboarding_completed_at=None, safety_delta_at=None, safety_delta_summary=None,
                          safety_abort_json=json.dumps({"check": "max_delete", "during": "dryrun"}))
    r = gs.post(f"/admin/users/{uid}/safety-restore", data={"csrf": csrf(gs, "/admin")})
    assert r.status_code == 403 and STEPUP_RESTORE_MSG in r.text
    assert audit(db, "stepup_required")[-1]["reason"] == why
    assert db.user_full(uid)["safety_action"] is None
    assert not db.audit_rows(action="admin_first_sync_approved_via_restore")
    if case in ("onboarding", "onboarding_dryrun", "empty", "no_counts"):   # Microsoft is fine (unless 409 rules)
        assert mc.post(f"/admin/users/{uid}/safety-restore", data={"csrf": csrf(mc, "/admin")}).status_code == 303


def test_other_restore_rules_still_apply_before_stepup(sapp, g, entra, db, kr, scfg):
    _, gs = _google_admin(sapp, g, entra, db)
    uid = _safety_user(db, kr, scfg, delta=False)        # delta list still pending: 409, not a step-up
    assert gs.post(f"/admin/users/{uid}/safety-restore", data={"csrf": csrf(gs, "/admin")}).status_code == 409
    assert not audit(db, "stepup_required")


# ---- 2. NAS login, Drive connect, set-provider ------------------------------------------------------

def _google_user(sapp, g, entra, db):
    c = ms(client(sapp), entra)                          # jsmith, OneDrive user
    link_google(c, g)
    gs = client(sapp)
    assert google_login(gs, g).status_code == 303
    return c, gs, db.users()[0]["id"]


@pytest.mark.smoke
def test_nas_login_change_needs_microsoft(sapp, g, entra, db, kr):
    mc, gs, uid = _google_user(sapp, g, entra, db)
    page = gs.get("/me").text
    assert 'action="/me/nas"' not in page and "Changing your NAS login needs a Microsoft sign-in" in page
    r = gs.post("/me/nas", data={"csrf": csrf(gs, "/me"), "username": "jsmith", "password": CANARY_PW})
    assert r.status_code == 403 and "needs a Microsoft sign-in" in r.text and "/login?stepup=1" in r.text
    assert db.nas_credential_meta(uid) is None
    assert audit(db, "stepup_required")[-1]["action"] == "nas_login_change"
    assert not db.audit_rows(action="nas_verify")
    # Microsoft session: works as before
    assert 'action="/me/nas"' in mc.get("/me").text
    r = mc.post("/me/nas", data={"csrf": csrf(mc, "/me"), "username": "jsmith", "password": CANARY_PW})
    assert r.headers["location"] == "/me?msg=ok" and db.nas_credential(kr, uid) == ("jsmith", CANARY_PW)


def test_onedrive_reconnect_link_steps_up_on_google_session(sapp, g, entra, db):
    mc, gs, _ = _google_user(sapp, g, entra, db)
    assert '<a href="/login?stepup=1">Reconnect</a>' in gs.get("/me").text
    assert '<a href="/login">Reconnect</a>' in mc.get("/me").text


class FakeGoogleBoth(FakeGoogle):
    """Drive connect (FakeGoogle) plus the sign-in half (FakeGoogleSignin)."""
    begin_signin = FakeGoogleSignin.begin_signin

    def complete_signin(self, flow, query):
        from odnas.google import GoogleTokenResult
        return GoogleTokenResult(access_token="signin", id_claims=dict(self.claims))


@pytest.fixture
def gdapp(scfg, db, kr, entra):
    settings_store.update(db, scfg, kr, {"pilot_list": f"jsmith@hotsprings.org\n{ADMIN_UPN}",
                                         "gdrive_users": "jsmith@hotsprings.org"}, "test")
    gb = FakeGoogleBoth()
    return create_app(scfg, db, kr, entra, FakeWorkerClient(), google=gb), gb


@pytest.mark.smoke
def test_google_drive_connect_needs_microsoft(gdapp, entra, db, kr):
    app, gb = gdapp
    mc = ms(client(app), entra)
    uid = db.users()[0]["id"]
    assert db.user_full(uid)["provider"] == "gdrive"
    link_google(mc, gb, gc())
    gs = client(app)
    assert google_login(gs, gb, gc()).status_code == 303
    page = gs.get("/me").text
    assert 'action="/me/google/connect"' not in page and "Sign in with Microsoft to connect Google Drive" in page
    r = gs.post("/me/google/connect", data={"csrf": csrf(gs, "/me")})
    assert r.status_code == 403 and "needs a Microsoft sign-in" in r.text
    assert not db.audit_rows(action="google_connect_started")
    assert audit(db, "stepup_required")[-1]["action"] == "google_connect"
    # a connect started on the Microsoft session can't be finished by a Google session either
    gb.claims = {"sub": "g-sub-1", "email": "jsmith@hotsprings.org", "hd": "hotsprings.org", "email_verified": True}
    r = mc.post("/me/google/connect", data={"csrf": csrf(mc, "/me")})
    assert r.status_code == 303
    st = mc.cookies.get("springsync_flow")
    gs.cookies.set("springsync_flow", st, path="/auth")
    assert gs.get(f"/auth/google/callback?code=x&state={st}").status_code == 403
    assert db.google_credential(uid) is None
    # the Microsoft session connects normally (a fresh flow; the stolen one wasn't consumed)
    r = mc.get(f"/auth/google/callback?code=x&state={st}")
    assert r.status_code == 303 and "google_connected" in r.headers["location"], r.text
    assert db.google_credential(uid) is not None
    # reconnect on a Google session: also refused, the link says "reconnect"
    assert "Sign in with Microsoft to reconnect Google Drive" in gs.get("/me").text
    assert gs.post("/me/google/connect", data={"csrf": csrf(gs, "/me")}).status_code == 403


def test_admin_set_provider_needs_microsoft_and_nas_test_does_not(sapp, g, entra, db, kr, scfg):
    mc, gs = _google_admin(sapp, g, entra, db)
    settings_store.update(db, scfg, kr, {"providers_enabled": "onedrive,gdrive"}, "test")
    target = seed_user(db, kr, upn="other@hotsprings.org", oid="oid-o")
    tok = csrf(gs, "/admin")
    form = {"csrf": tok, "provider": "gdrive", "confirm": "other@hotsprings.org", "reason": "move to Google"}
    r = gs.post(f"/admin/users/{target}/set-provider", data=form)
    assert r.status_code == 403 and "needs a Microsoft sign-in" in r.text
    assert db.user_full(target)["provider"] == "onedrive"
    # Test NAS login: allowed on the Google admin session, never stored
    r = gs.post("/admin/settings/nas-test", data={"csrf": tok, "username": "probe", "password": "pw-never-stored"})
    assert r.status_code == 303 and "NAS+test" in r.headers["location"]
    assert db.audit_rows(action="nas_test")
    # Microsoft admin: set-provider proceeds past the step-up
    r = mc.post(f"/admin/users/{target}/set-provider", data={**form, "csrf": csrf(mc, "/admin")})
    assert r.status_code == 303
    assert db.user_full(target)["provider"] == "gdrive"


def test_user_role_google_session_cannot_reach_admin_actions(sapp, g, entra, db, kr, scfg):
    """A plain user on a Google session gets 403 for the admin restore (role check), not a step-up prompt."""
    _, gs, _ = _google_user(sapp, g, entra, db)
    uid = _safety_user(db, kr, scfg)
    r = gs.post(f"/admin/users/{uid}/safety-restore", data={"csrf": csrf(gs, "/me")})
    assert r.status_code == 403 and STEPUP_RESTORE_MSG not in r.text
    assert db.user_full(uid)["safety_action"] is None
