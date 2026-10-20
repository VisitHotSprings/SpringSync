"""SPEC v0.5 (Reid's answers, 2026-10-20):
- nas_auth (wrong NAS password) neither counts nor resets the mount-failure counter; ONLY a successful mount
  resets it (an internal error after a good mount does; one before the mount does not);
- a tonight run starts only with >= 30 min left before 07:00 CT, else waits for the next night (audited once);
- a safety abort during onboarding (dry run or first bisync) is a normal safety abort, onboarding stays
  incomplete, and Restore re-runs the onboarding --resync."""
import json
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest

from odnas import db as D
from tests.conftest import G_ADMINS, FakeProc, seed_user
from tests.test_runner_broker import make_worker
from tests.test_safety_abort import DELTA, MAXDEL, _choose
from tests.test_safety_v03 import EVENING, NOON, actions, approve_restore
from tests.test_web import _safety_user, csrf, login, wc  # noqa: F401  (wc is a fixture)

CT = ZoneInfo("America/Chicago")


def ct(y, mo, d, h, mi=0):
    return datetime(y, mo, d, h, mi, tzinfo=CT).astimezone(timezone.utc)


def issues(db, uid):
    return {i["type"] for i in db.open_issues(uid)}


# ---- 1. NAS login failure vs. mount-failure counter ------------------------------------------

def test_nas_auth_neither_counts_nor_resets_mount_counter(cfg, db, kr, entra):
    proc = FakeProc()
    w, hr = make_worker(cfg, db, kr, entra, proc, {"mount": 4})
    uid = seed_user(db, kr)
    w.runner.run(uid, "bisync")                                   # mount failure #1
    assert db.user_full(uid)["consecutive_mount_failures"] == 1
    hr.codes["mount"] = 13                                        # wrong NAS password
    assert w.runner.run(uid, "bisync").result == "nas_auth"
    u = db.user_full(uid)
    assert u["consecutive_mount_failures"] == 1                   # unchanged
    assert u["state"] == D.NAS_AUTH_FAILED and "nas_auth_failed" in issues(db, uid)   # own alert, paused at once
    assert _choose(w, db, uid) is None and proc.calls == []      # no retries
    # the user re-enters the password; the next attempt is another mount failure -> 2 in a row -> alert
    db.set_state(uid, D.ACTIVE)
    hr.codes["mount"] = 4
    w.runner.run(uid, "bisync")
    assert db.user_full(uid)["consecutive_mount_failures"] == 2 and "nas_unreachable" in issues(db, uid)


def test_internal_error_after_successful_mount_resets_counter(cfg, db, kr, entra):
    w, hr = make_worker(cfg, db, kr, entra, FakeProc(), {"mount": 4})
    uid = seed_user(db, kr)
    w.runner.run(uid, "bisync")
    hr.codes["mount"] = 0

    def boom(*a, **k):
        raise RuntimeError("token strategy exploded")
    w.runner.strategy.prepare = boom
    assert w.runner.run(uid, "bisync").result == "error"
    assert db.user_full(uid)["consecutive_mount_failures"] == 0   # the mount itself succeeded


def test_internal_error_before_mount_does_not_reset_counter(cfg, db, kr, entra, monkeypatch):
    w, hr = make_worker(cfg, db, kr, entra, FakeProc(), {"mount": 4})
    uid = seed_user(db, kr)
    w.runner.run(uid, "bisync")

    def boom(*a, **k):
        raise RuntimeError("credential read failed")
    monkeypatch.setattr(w.runner.db, "nas_credential", boom)
    assert w.runner.run(uid, "bisync").result == "error"
    assert db.user_full(uid)["consecutive_mount_failures"] == 1
    assert [c[0] for c in hr.calls].count("mount") == 1           # the second run never mounted


# ---- 2. Tonight-run 30-minute start cutoff --------------------------------------------------

def _tonight_user(cfg, db, kr, entra):
    w, _ = make_worker(cfg, db, kr, entra, FakeProc(exit_codes=[1], log_lines=MAXDEL))
    uid = seed_user(db, kr)
    w.runner.run(uid, "bisync")
    w.runner.proc = FakeProc(exit_codes=[0], log_lines=DELTA)
    w.runner.run(uid, "delta")
    approve_restore(db, uid, D.RESTORE_TONIGHT)
    return w, uid


def test_tonight_run_needs_30_min_left(cfg, db, kr, entra):
    w, uid = _tonight_user(cfg, db, kr, entra)
    assert _choose(w, db, uid, ct(2026, 10, 22, 6, 31)) is None       # 29 min left
    assert _choose(w, db, uid, ct(2026, 10, 22, 6, 30)) == "resync"   # exactly 30 min left starts
    assert _choose(w, db, uid, ct(2026, 10, 21, 18, 0)) == "resync"


def test_tonight_hold_is_audited_once_and_runs_next_night(cfg, db, kr, entra):
    w, uid = _tonight_user(cfg, db, kr, entra)
    w.runner.proc = proc = FakeProc(exit_codes=[0])
    assert w.tick(ct(2026, 10, 22, 6, 40), wait=True) == []
    assert w.tick(ct(2026, 10, 22, 6, 41), wait=True) == []
    assert actions(db).count("safety_restore_tonight_deferred") == 1   # once per night, not per tick
    det = json.loads(db.audit_rows(action="safety_restore_tonight_deferred")[0]["details_json"])
    assert det["minutes_left"] == 20 and det["min_required"] == 30
    assert "restore_deferred" in issues(db, uid) and proc.calls == []
    u = db.user_full(uid)
    assert u["state"] == D.SAFETY_ABORT and u["safety_action"] == D.SAFETY_RESTORE   # approval kept
    assert w.tick(ct(2026, 10, 22, 12, 0), wait=True) == []           # daytime: still waiting
    assert w.tick(ct(2026, 10, 22, 18, 0), wait=True) == [(uid, "resync")]
    assert db.user(uid)["state"] == D.ACTIVE


def test_tonight_hold_audited_again_on_a_later_night(cfg, db, kr, entra):
    w, uid = _tonight_user(cfg, db, kr, entra)
    w._tonight_holds(db.users(), w.settings(), ct(2026, 10, 22, 6, 45))
    w._tonight_holds(db.users(), w.settings(), ct(2026, 10, 23, 6, 45))
    assert actions(db).count("safety_restore_tonight_deferred") == 2


def test_tonight_restore_not_bound_by_active_hours(cfg, db, kr, entra):
    from odnas import settings_store
    w, uid = _tonight_user(cfg, db, kr, entra)
    settings_store.update(db, cfg, kr, {"active_hours": "07:00-18:00"}, "test")
    assert _choose(w, db, uid, ct(2026, 10, 21, 20, 0)) == "resync"


# ---- 3. Safety abort during onboarding ------------------------------------------------------

@pytest.fixture
def admin(cfg, db, kr, entra, wc):
    from odnas.web.app import create_app
    a = create_app(cfg, db, kr, entra, wc)
    c = login(a, entra, oid="m", upn="mark@hotsprings.org", groups=(G_ADMINS,))
    return c, csrf(c, "/admin")


def test_abort_on_onboarding_dryrun_then_restore_reruns_onboarding_resync(cfg, db, kr, entra, admin):
    client, tok = admin
    w, _ = make_worker(cfg, db, kr, entra, FakeProc(exit_codes=[0, 1], log_lines=MAXDEL))
    uid = seed_user(db, kr, state=D.ONBOARDING, upn="victim@hotsprings.org", preflight_at=D.iso(D.utcnow()))
    assert w.runner.run(uid, "dryrun").result == "safety_abort"
    u = db.user_full(uid)
    assert u["state"] == D.SAFETY_ABORT and u["onboarding_completed_at"] is None
    assert u["safety_delta_requested"] == 0                      # no listings yet: no delta list possible
    assert json.loads(u["safety_abort_json"])["during"] == "dryrun"
    assert "safety_abort" in issues(db, uid) and "onboarding_safety_abort" in actions(db)
    assert _choose(w, db, uid, EVENING) is None                  # paused until the admin decides
    page = client.get(f"/admin/users/{uid}").text
    assert "Onboarding</th><td>incomplete" in page and "re-run the onboarding resync" in page
    assert "safety-accept-deletes" not in page.split("Restore re-runs")[1]
    assert client.post(f"/admin/users/{uid}/safety-accept-deletes",
                       data={"csrf": tok, "confirm": "victim@hotsprings.org"}).status_code == 409
    assert client.post(f"/admin/users/{uid}/safety-restore", data={"csrf": tok}).status_code == 303
    det = json.loads(db.audit_rows(action="admin_safety_restore")[0]["details_json"])
    assert det["onboarding_resync"] is True and det["when"] == "tonight"
    # it runs like the onboarding --resync: in resync_hours, no run-time limit, real (not dry) resync
    assert _choose(w, db, uid, NOON) is None
    assert _choose(w, db, uid, EVENING) == "resync"
    w.runner.proc = proc = FakeProc(exit_codes=[0])
    assert w.runner.run(uid, "resync").result == "ok"
    cmd, limit = proc.calls[-1]
    assert "--resync" in cmd and "--dry-run" not in cmd and limit is None
    u = db.user_full(uid)
    assert u["state"] == D.ACTIVE and u["onboarding_completed_at"] is None   # completes on the first bisync
    assert json.loads(db.audit_rows(action="safety_restore_completed")[0]["details_json"])["onboarding_resync"]
    w.runner.run(uid, "bisync")
    assert db.user_full(uid)["onboarding_completed_at"] and "onboarding_completed" in actions(db)


def test_abort_on_first_bisync_keeps_onboarding_incomplete(cfg, db, kr, entra):
    w, _ = make_worker(cfg, db, kr, entra, FakeProc(exit_codes=[1], log_lines=MAXDEL))
    uid = seed_user(db, kr, onboarding_completed_at=None)        # onboarding --resync done, no bisync yet
    assert w.runner.run(uid, "bisync").result == "safety_abort"
    u = db.user_full(uid)
    assert u["state"] == D.SAFETY_ABORT and u["onboarding_completed_at"] is None and u["safety_delta_requested"]
    assert json.loads(u["safety_abort_json"])["onboarding"] is True
    w.runner.proc = FakeProc(exit_codes=[0], log_lines=DELTA)
    assert w.runner.run(uid, "delta").result == "ok"             # the delta list works here (listings exist)
    approve_restore(db, uid)                                     # even "next slot" -> onboarding rules
    assert _choose(w, db, uid, NOON) is None and _choose(w, db, uid, EVENING) == "resync"
    w.runner.proc = proc = FakeProc(exit_codes=[0])
    w.runner.run(uid, "resync")
    assert proc.calls[-1][1] is None
    assert db.user(uid)["state"] == D.ACTIVE and db.user_full(uid)["onboarding_completed_at"] is None


def test_completed_user_abort_is_not_onboarding(cfg, db, kr, entra):
    w, _ = make_worker(cfg, db, kr, entra, FakeProc(exit_codes=[1], log_lines=MAXDEL))
    uid = seed_user(db, kr)
    w.runner.run(uid, "bisync")
    assert json.loads(db.user_full(uid)["safety_abort_json"])["onboarding"] is False
    assert "onboarding_safety_abort" not in actions(db)


def test_migration_5_backfills_onboarding_completed(tmp_path):
    import sqlite3
    p = tmp_path / "m.db"
    con = sqlite3.connect(p)
    con.executescript("CREATE TABLE sync_profiles (user_id TEXT, last_success_at TEXT);"
                      "CREATE TABLE sync_runs (user_id TEXT, kind TEXT, result TEXT);"
                      "INSERT INTO sync_profiles VALUES ('done', '2026-10-01T00:00:00+00:00'), ('new', NULL);"
                      "INSERT INTO sync_runs VALUES ('done', 'bisync', 'ok'), ('new', 'resync', 'ok');")
    con.executescript(D.MIGRATIONS[4])
    rows = dict(con.execute("SELECT user_id, onboarding_completed_at FROM sync_profiles"))
    assert rows == {"done": "2026-10-01T00:00:00+00:00", "new": None}
