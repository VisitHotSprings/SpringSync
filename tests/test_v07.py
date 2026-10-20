"""SPEC v0.7 (Reid's answers, 2026-10-20):
- the svc-sync password test runs on the worker's next tick (<= 60 s); Settings shows "Testing new password…"
  until the result is back, then the outcome;
- a dedicated health-check share (`nas_health_share`, default Sync-Health, svc-sync only) is used by both
  the test mount and the routine NAS health check; neither touches a user's Home share, so the pause can
  clear with zero users;
- the installer never creates the share; it only prints a reminder (needs Mark's OK);
- accepted as built: offboarding final sync waits for the pause; switching to A clears it (audited); an
  automatic re-queue keeps tonight_hold_nights."""
import json
from datetime import timedelta
from pathlib import Path

import pytest

from odnas import db as D
from odnas import settings_store
from tests.conftest import G_ADMINS, FakeProc, seed_user
from tests.test_runner_broker import make_worker
from tests.test_safety_v03 import actions
from tests.test_web import csrf, login, wc  # noqa: F401  (wc is a fixture)
from tests.test_v06 import _deferred, _tonight_user, ct

ROOT = Path(__file__).resolve().parents[1]
HEALTH_UNC = "//unas.hotsprings.local/Sync-Health"


def _option_b(db, cfg, kr, pw="old-pw", **extra):
    settings_store.update(db, cfg, kr, {"nas_option": "B", "nas_svc_password": pw, **extra}, "test")


def _paused(db, cfg, kr, entra, helper):
    _option_b(db, cfg, kr)
    w, hr = make_worker(cfg, db, kr, entra, FakeProc(), helper)
    db.set_flag(D.NAS_GLOBAL_PAUSE, "svc-sync NAS login rejected",
                pw_version=db.setting_version("nas_svc_password"))
    return w, hr


@pytest.fixture
def mark(cfg, db, kr, entra, wc):
    from odnas.web.app import create_app
    a = create_app(cfg, db, kr, entra, wc)
    return login(a, entra, oid="m", upn="mark@hotsprings.org", groups=(G_ADMINS,))


# ---- health share: test mount and health check ------------------------------------------------

def test_setting_default_and_validation(cfg, db, kr):
    assert settings_store.load(db, cfg).nas_health_share == "Sync-Health"
    with pytest.raises(ValueError):
        settings_store.update(db, cfg, kr, {"nas_health_share": "../etc"}, "test")


def test_test_mount_uses_health_share_and_clears_with_zero_users(cfg, db, kr, entra):
    w, hr = _paused(db, cfg, kr, entra, {"verify": 0})
    assert not db.users()                                       # zero users
    _option_b(db, cfg, kr, "new-pw")
    w.tick(wait=True)
    assert hr.uncs == [("verify", HEALTH_UNC)]                   # never a Home-<user> share
    assert db.flag(D.NAS_GLOBAL_PAUSE) is None
    det = json.loads(db.audit_rows(action="nas_global_pause_cleared")[0]["details_json"])
    assert det["test_share"] == "Sync-Health"


def test_custom_health_share_name(cfg, db, kr, entra):
    w, hr = _paused(db, cfg, kr, entra, {"verify": 0})
    _option_b(db, cfg, kr, "new-pw", nas_health_share="SS-Health")
    seed_user(db, kr, nas=False)
    w.tick(wait=True)
    assert ("verify", "//unas.hotsprings.local/SS-Health") in hr.uncs
    assert not any("Home-" in u for _, u in hr.uncs if _ == "verify")


def test_rejected_new_password_keeps_pause_alerts_high_no_retry(cfg, db, kr, entra):
    w, hr = _paused(db, cfg, kr, entra, {"verify": 13})
    _option_b(db, cfg, kr, "wrong-again")
    for i in range(3):
        w.tick(D.utcnow() + timedelta(minutes=10 * i), wait=True)
    assert len(hr.uncs) == 1 and db.flag(D.NAS_GLOBAL_PAUSE)
    assert any(i["type"] == "nas_global_pause_test_failed" and i["severity"] == "high" for i in db.open_issues())


def test_routine_health_check_option_b(cfg, db, kr, entra):
    _option_b(db, cfg, kr)
    w, hr = make_worker(cfg, db, kr, entra, FakeProc(), {"verify": 4})
    t0 = D.utcnow()
    w.tick(t0, wait=True)
    assert hr.uncs == [("verify", HEALTH_UNC)]
    assert any(i["type"] == "nas_health" and i["severity"] == "medium" for i in db.open_issues())
    w.tick(t0 + timedelta(minutes=5), wait=True)
    assert len(hr.uncs) == 1                                    # every 15 min, not every tick
    hr.codes["verify"] = 0
    w.tick(t0 + timedelta(minutes=16), wait=True)
    assert len(hr.uncs) == 2 and not any(i["type"] == "nas_health" for i in db.open_issues())
    assert json.loads(db.heartbeat("nas_health")["detail"])["result"] == "ok"
    assert db.flag(D.NAS_GLOBAL_PAUSE) is None


def test_health_check_rejected_login_sets_global_pause(cfg, db, kr, entra):
    _option_b(db, cfg, kr)
    w, hr = make_worker(cfg, db, kr, entra, FakeProc(), {"verify": 13})
    uid = seed_user(db, kr, nas=False)
    assert w.tick(wait=True) == []                              # the pause applies within the same tick
    f = db.flag(D.NAS_GLOBAL_PAUSE)
    assert f and f["source"] == "health_check"
    assert db.user(uid)["state"] == D.ACTIVE
    w.tick(D.utcnow() + timedelta(hours=1), wait=True)
    assert len(hr.uncs) == 1                                    # no retries of the rejected login


def test_no_health_check_under_option_a(cfg, db, kr, entra):
    w, hr = make_worker(cfg, db, kr, entra, FakeProc())
    w.tick(wait=True)
    assert hr.uncs == [] and db.heartbeat("nas_health") is None


# ---- Settings page: "Testing new password…" ----------------------------------------------------

def test_settings_shows_testing_then_result(cfg, db, kr, entra, mark):
    w, hr = _paused(db, cfg, kr, entra, {"verify": 4})
    assert "Testing new password" not in mark.get("/admin/settings").text
    tok = csrf(mark, "/admin/settings")
    assert mark.post("/admin/settings", data={"csrf": tok, "nas_svc_password": "new-pw"}).status_code == 303
    page = mark.get("/admin/settings").text
    assert "Testing new password…" in page and 'http-equiv="refresh"' in page
    w.tick(wait=True)                                           # NAS unreachable: still testing, retrying
    page = mark.get("/admin/settings").text
    assert "Testing new password…" in page and "retrying every 5 min" in page
    hr.codes["verify"] = 0
    w.tick(D.utcnow() + timedelta(minutes=6), wait=True)
    page = mark.get("/admin/settings").text
    assert "Testing new password" not in page and "test mount OK" in page and "has resumed" in page
    assert "All NAS syncs are paused" not in page


def test_settings_shows_rejected(cfg, db, kr, entra, mark):
    w, hr = _paused(db, cfg, kr, entra, {"verify": 13})
    tok = csrf(mark, "/admin/settings")
    mark.post("/admin/settings", data={"csrf": tok, "nas_svc_password": "nope"})
    w.tick(wait=True)
    page = mark.get("/admin/settings").text
    assert "rejected" in page and "Testing new password" not in page and "All NAS syncs are paused" in page
    assert "nope" not in page                                   # the secret is never echoed


# ---- accepted-as-built rules --------------------------------------------------------------------

def test_offboarding_final_sync_waits_for_pause(cfg, db, kr, entra):
    w, hr = _paused(db, cfg, kr, entra, {"verify": 0})
    uid = seed_user(db, kr, nas=False, state=D.OFFBOARDING, final_sync_requested=1)
    assert w.tick(wait=True) == [] and db.user(uid)["state"] == D.OFFBOARDING
    _option_b(db, cfg, kr, "fixed-pw")
    assert w.tick(wait=True) == [(uid, "offboard")]
    assert db.user(uid)["state"] == D.REMOVED


def test_offboarding_without_final_sync_proceeds_during_pause(cfg, db, kr, entra):
    w, hr = _paused(db, cfg, kr, entra, {"verify": 0})
    uid = seed_user(db, kr, nas=False, state=D.OFFBOARDING, final_sync_requested=0)
    assert w.tick(wait=True) == [(uid, "offboard")]


def test_switching_to_option_a_clears_pause_audited(cfg, db, kr, entra):
    w, hr = _paused(db, cfg, kr, entra, {"verify": 0})
    settings_store.update(db, cfg, kr, {"nas_option": "A"}, "test")
    w.tick(wait=True)
    assert db.flag(D.NAS_GLOBAL_PAUSE) is None
    det = json.loads(db.audit_rows(action="nas_global_pause_cleared")[0]["details_json"])
    assert det["reason"] == "nas_option_changed"


def test_requeue_keeps_hold_count(cfg, db, kr, entra, monkeypatch):
    w, uid = _tonight_user(cfg, db, kr, entra)
    db.update_profile(uid, safety_restore_when=D.RESTORE_NEXT_SLOT)
    w._tonight_holds(db.users(), w.settings(), ct(2026, 10, 22, 6, 45))   # not tonight: no hold
    db.update_profile(uid, safety_restore_when=D.RESTORE_TONIGHT, tonight_hold_nights=1)
    db.update_profile(uid, safety_restore_when=D.RESTORE_NEXT_SLOT)
    monkeypatch.setattr(D, "utcnow", lambda: ct(2026, 10, 22, 12, 0))
    w.runner.proc = FakeProc(timed_out=True, exit_codes=[-2])
    w.runner.run(uid, "resync")                                 # next-slot timeout -> auto re-queue
    u = db.user_full(uid)
    assert u["safety_restore_requeued"] == 1 and u["tonight_hold_nights"] == 1
    monkeypatch.undo()
    w._tonight_holds(db.users(), w.settings(), ct(2026, 10, 23, 6, 45))
    assert _deferred(db, uid) == ["medium"]                     # second hold of the same Restore


# ---- installer and docs -------------------------------------------------------------------------

def test_installer_only_reminds_never_creates_share():
    sh = (ROOT / "deploy/install.sh").read_text()
    assert "REMINDER (Option B only)" in sh and "needs Mark's OK" in sh and "does not create it" in sh
    low = sh.lower()
    for bad in ("smbclient", "net share", "net usershare", "unifi-os", "mount -t cifs"):
        assert bad not in low                                   # no NAS-side commands at all


def test_deploy_doc_flags_share_step():
    doc = (ROOT / "docs/DEPLOY.md").read_text()
    assert "Sync-Health" in doc and "needs Mark's OK" in doc.replace("**", "") and "svc-sync` only" in doc


def test_cli_nas_info(cfg, db, kr):
    from odnas.cli import nas_info
    assert nas_info(db, cfg) == "option=A health_share=Sync-Health health_share_configured=0"
    settings_store.update(db, cfg, kr, {"nas_option": "B", "nas_health_share": "SS-Health"}, "test")
    assert nas_info(db, cfg) == "option=B health_share=SS-Health health_share_configured=1"
