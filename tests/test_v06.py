"""SPEC v0.6 (Reid's answers, 2026-10-20):
- onboarding completes only on the first successful normal bisync (never on a Restore/resync);
- Restore after an onboarding dry-run abort goes straight to --resync; the click is audited as the
  first-sync approval;
- tonight-Restore hold alert: low on the first night, medium if the same Restore is held a second night,
  back to low for a new Restore;
- Option B svc-sync login rejected: one global NAS pause (worker_state 'nas_global_pause'), one high alert,
  no retries, no user set to nas_auth_failed, no new runs; auto-resume after a new nas_svc_password plus a
  successful test mount (a rejected test keeps it); audited."""
import json
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest

from odnas import db as D
from odnas import settings_store
from tests.conftest import G_ADMINS, G_AUDIT, FakeProc, seed_user
from tests.test_runner_broker import make_worker
from tests.test_safety_abort import DELTA, MAXDEL, _choose
from tests.test_safety_v03 import EVENING, actions, approve_restore
from tests.test_web import csrf, login, wc  # noqa: F401  (wc is a fixture)

CT = ZoneInfo("America/Chicago")


def ct(y, mo, d, h, mi=0):
    return datetime(y, mo, d, h, mi, tzinfo=CT).astimezone(timezone.utc)


def issues(db, uid=None):
    return [i for i in db.open_issues(uid)] if uid else [i for i in db.open_issues()]


@pytest.fixture
def web(cfg, db, kr, entra, wc):
    from odnas.web.app import create_app
    a = create_app(cfg, db, kr, entra, wc)
    mark = login(a, entra, oid="m", upn="mark@hotsprings.org", groups=(G_ADMINS,))
    walter = login(a, entra, oid="w", upn="walter@hotsprings.org", groups=(G_AUDIT,))
    return mark, csrf(mark, "/admin"), walter


# ---- 1/2. onboarding --------------------------------------------------------------------------

def test_dryrun_abort_restore_audited_as_first_sync_approval(cfg, db, kr, entra, web):
    mark, tok, _ = web
    w, _ = make_worker(cfg, db, kr, entra, FakeProc(exit_codes=[0, 1], log_lines=MAXDEL))
    uid = seed_user(db, kr, state=D.ONBOARDING, upn="victim@hotsprings.org", preflight_at=D.iso(D.utcnow()))
    w.runner.run(uid, "dryrun")
    assert mark.post(f"/admin/users/{uid}/safety-restore", data={"csrf": tok}).status_code == 303
    rows = db.audit_rows(action="admin_first_sync_approved_via_restore")
    assert len(rows) == 1 and rows[0]["actor"] == "m" and rows[0]["target"] == uid
    assert json.loads(rows[0]["details_json"])["dry_run_skipped"] is True
    w.runner.proc = proc = FakeProc(exit_codes=[0])
    assert _choose(w, db, uid, EVENING) == "resync"              # no fresh dry run first
    w.runner.run(uid, "resync")
    assert len(proc.calls) == 1 and "--dry-run" not in proc.calls[0][0] and "--resync" in proc.calls[0][0]
    assert db.user_full(uid)["onboarding_completed_at"] is None  # a Restore never completes onboarding
    # the first normal bisync trips -> still an onboarding abort
    w.runner.proc = FakeProc(exit_codes=[1], log_lines=MAXDEL)
    w.runner.run(uid, "bisync")
    u = db.user_full(uid)
    assert u["state"] == D.SAFETY_ABORT and json.loads(u["safety_abort_json"])["onboarding"] is True
    assert actions(db).count("onboarding_safety_abort") == 2


def test_first_bisync_abort_restore_is_not_a_first_sync_approval(cfg, db, kr, entra, web):
    from tests.test_web import _safety_user
    mark, tok, _ = web
    uid = _safety_user(db, kr, cfg)
    db.update_profile(uid, onboarding_completed_at=None)
    assert mark.post(f"/admin/users/{uid}/safety-restore", data={"csrf": tok}).status_code == 303
    assert not db.audit_rows(action="admin_first_sync_approved_via_restore")


# ---- 3. hold alert escalation --------------------------------------------------------------------

def _tonight_user(cfg, db, kr, entra):
    w, _ = make_worker(cfg, db, kr, entra, FakeProc(exit_codes=[1], log_lines=MAXDEL))
    uid = seed_user(db, kr)
    w.runner.run(uid, "bisync")
    w.runner.proc = FakeProc(exit_codes=[0], log_lines=DELTA)
    w.runner.run(uid, "delta")
    approve_restore(db, uid, D.RESTORE_TONIGHT)
    return w, uid


def _deferred(db, uid):
    return [(i["severity"]) for i in db.open_issues(uid) if i["type"] == "restore_deferred"]


def test_hold_alert_low_then_medium_on_second_night(cfg, db, kr, entra):
    w, uid = _tonight_user(cfg, db, kr, entra)
    w._tonight_holds(db.users(), w.settings(), ct(2026, 10, 22, 6, 45))
    assert _deferred(db, uid) == ["low"] and db.user_full(uid)["tonight_hold_nights"] == 1
    w._tonight_holds(db.users(), w.settings(), ct(2026, 10, 22, 6, 50))   # same night: nothing new
    assert _deferred(db, uid) == ["low"]
    w._tonight_holds(db.users(), w.settings(), ct(2026, 10, 23, 6, 45))   # the same Restore, 2nd night
    assert _deferred(db, uid) == ["medium"] and db.user_full(uid)["tonight_hold_nights"] == 2
    det = [json.loads(r["details_json"]) for r in db.audit_rows(action="safety_restore_tonight_deferred")]
    assert sorted((d["nights_held"], d["severity"]) for d in det) == [(1, "low"), (2, "medium")]


def test_new_restore_restarts_at_low(cfg, db, kr, entra, web):
    mark, tok, _ = web
    w, uid = _tonight_user(cfg, db, kr, entra)
    db.q("UPDATE users SET upn='victim@hotsprings.org' WHERE id=?", (uid,))
    w._tonight_holds(db.users(), w.settings(), ct(2026, 10, 22, 6, 45))
    w._tonight_holds(db.users(), w.settings(), ct(2026, 10, 23, 6, 45))
    # the restore runs and times out at 07:00 -> admin must choose a NEW Restore
    w.runner.proc = FakeProc(timed_out=True, exit_codes=[-2])
    w.runner.run(uid, "resync")
    assert not _deferred(db, uid)                                   # cleared when the Restore started
    assert mark.post(f"/admin/users/{uid}/safety-restore", data={"csrf": tok, "when": "tonight"}).status_code == 303
    assert db.user_full(uid)["tonight_hold_nights"] == 0
    w._tonight_holds(db.users(), w.settings(), ct(2026, 10, 24, 6, 45))
    assert _deferred(db, uid) == ["low"]


# ---- 4. Option B global NAS pause -----------------------------------------------------------------

def _option_b(db, cfg, kr, pw="old-pw"):
    settings_store.update(db, cfg, kr, {"nas_option": "B", "nas_svc_password": pw}, "test")


def test_option_b_rejected_svc_login_sets_one_global_pause(cfg, db, kr, entra):
    _option_b(db, cfg, kr)
    proc = FakeProc()
    w, hr = make_worker(cfg, db, kr, entra, proc, {"mount": 13})
    a = seed_user(db, kr, upn="a@hotsprings.org", nas=False)
    b = seed_user(db, kr, upn="b@hotsprings.org", nas=False)
    assert w.runner.run(a, "bisync").result == "nas_auth"
    assert w.runner.run(b, "bisync").result == "nas_auth"           # an in-flight run hitting it too
    for uid in (a, b):
        u = db.user_full(uid)
        assert u["state"] == D.ACTIVE and u["consecutive_mount_failures"] == 0   # no per-user state/failure
    assert db.flag(D.NAS_GLOBAL_PAUSE)["reason"] == "svc-sync NAS login rejected"
    glob = [i for i in db.open_issues() if i["type"] == "nas_global_pause"]
    assert len(glob) == 1 and glob[0]["severity"] == "high" and glob[0]["user_id"] is None
    assert not any(i["type"] == "nas_auth_failed" for i in db.open_issues())
    assert actions(db).count("nas_global_pause_set") == 1
    # no new runs for anyone, no retries
    n = len(hr.calls)
    for i in range(3):
        db.q("UPDATE sync_profiles SET next_run_at=NULL")
        assert w.tick(D.utcnow() + timedelta(minutes=31 * (i + 1)), wait=True) == []
    assert len(hr.calls) == n and proc.calls == []


def test_global_pause_resumes_only_after_new_password_and_ok_test_mount(cfg, db, kr, entra):
    _option_b(db, cfg, kr)
    w, hr = make_worker(cfg, db, kr, entra, FakeProc(), {"mount": 13, "verify": 13})
    uid = seed_user(db, kr, nas=False)
    w.runner.run(uid, "bisync")
    assert db.flag(D.NAS_GLOBAL_PAUSE)
    # the same password: no test, no retry
    w.tick(wait=True)
    assert not [c for c in hr.calls if c[0] == "verify"]
    # IT saves a new password that is ALSO wrong: tested once, stays paused, not retried
    _option_b(db, cfg, kr, "still-wrong")
    w.tick(wait=True); w.tick(wait=True)
    assert len([c for c in hr.calls if c[0] == "verify"]) == 1
    assert db.flag(D.NAS_GLOBAL_PAUSE)["tested_pw_version"]
    assert "nas_global_pause_test_failed" in actions(db)
    # the right password: test mount ok -> pause cleared, audited, alert closed, syncing continues
    hr.codes.update(mount=0, verify=0)
    _option_b(db, cfg, kr, "right-pw")
    db.q("UPDATE sync_profiles SET next_run_at=NULL")
    started = w.tick(wait=True)
    assert db.flag(D.NAS_GLOBAL_PAUSE) is None
    det = json.loads(db.audit_rows(action="nas_global_pause_cleared")[0]["details_json"])
    assert det["reason"] == "svc_sync_password_updated_and_test_mount_ok"
    assert not [i for i in db.open_issues() if i["type"] == "nas_global_pause"]
    assert started == [(uid, "bisync")]


def test_unreachable_test_mount_retries_after_5_min(cfg, db, kr, entra):
    _option_b(db, cfg, kr)
    w, hr = make_worker(cfg, db, kr, entra, FakeProc(), {"mount": 13, "verify": 4})
    uid = seed_user(db, kr, nas=False)
    w.runner.run(uid, "bisync")
    _option_b(db, cfg, kr, "new-pw")
    t0 = D.utcnow()
    w.tick(t0, wait=True); w.tick(t0 + timedelta(minutes=1), wait=True)
    assert len([c for c in hr.calls if c[0] == "verify"]) == 1
    hr.codes["verify"] = 0
    hr.codes["mount"] = 0   # the new password works for mounts too (else a slot boundary in the 6 min re-pauses)
    w.tick(t0 + timedelta(minutes=6), wait=True)
    assert db.flag(D.NAS_GLOBAL_PAUSE) is None


def test_option_a_nas_auth_unchanged(cfg, db, kr, entra):
    w, _ = make_worker(cfg, db, kr, entra, FakeProc(), {"mount": 13})
    uid = seed_user(db, kr)
    w.runner.run(uid, "bisync")
    assert db.user(uid)["state"] == D.NAS_AUTH_FAILED and db.flag(D.NAS_GLOBAL_PAUSE) is None


def test_global_pause_shown_on_admin_settings_and_auditor_pages(cfg, db, kr, entra, web):
    mark, _, walter = web
    db.set_flag(D.NAS_GLOBAL_PAUSE, "svc-sync NAS login rejected")
    assert "All NAS syncs are paused" in mark.get("/admin").text
    assert "All NAS syncs are paused" in mark.get("/admin/settings").text
    page = walter.get("/audit").text
    assert "All NAS syncs are paused" in page and "PAUSED (server-wide)" in page
    db.clear_flag(D.NAS_GLOBAL_PAUSE)
    assert "All NAS syncs are paused" not in mark.get("/admin").text


def test_migration_6_adds_hold_count_and_worker_state(db):
    assert db.schema_version() >= 6
    cols = {r["name"] for r in db.all("PRAGMA table_info(sync_profiles)")}
    assert "tonight_hold_nights" in cols
    assert db.one("SELECT name FROM sqlite_master WHERE type='table' AND name='worker_state'")
