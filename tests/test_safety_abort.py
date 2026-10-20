"""SPEC v0.2 §9.4: safety_abort (exit 1 + "Safety abort"), the two exit-7 variants, and the
admin-only Restore / Accept-deletes actions. No network; rclone is faked here (the real binary
is exercised in test_integration_rclone.py)."""
import json
from datetime import timedelta
from pathlib import Path

import pytest

from odnas import db as D
from odnas.runner import delta_file
from tests.conftest import FakeProc, seed_user
from tests.test_runner_broker import make_worker

MAXDEL = [{"level": "error", "msg": 'too many deletes (>10%, 4 of 21) on Path2 "/srv/springsync/mnt/x/". '
                                    'Run with --force if desired.', "object": "Safety abort", "objectType": "string"},
          {"level": "notice", "msg": "Bisync aborted. Please try again."},
          {"level": "notice", "msg": "Failed to bisync: too many deletes"}]
DELTA = [{"level": "notice", "msg": "- Path2             File was deleted                            - Budget/2026.xlsx"},
         {"level": "notice", "msg": "- Path2             File was deleted                            - Budget/2025.xlsx"},
         {"level": "notice", "msg": "- Path1             File is new                                 - notes.txt"}]
CRIT = {"level": "error", "msg": "Bisync critical error: check file check failed"}
RETRY = {"level": "error", "msg": "Bisync aborted. Error is retryable without --resync due to --resilient mode."}
LOCK = {"level": "error", "msg": "Bisync aborted. Must run --resync to recover."}


def _choose(w, db, uid, now=None):
    u = next(x for x in db.users() if x["id"] == uid)
    return w.choose_job(u, w.settings(), now or D.utcnow() + timedelta(days=1))


def _tripped(cfg, db, kr, entra):
    w, _ = make_worker(cfg, db, kr, entra, FakeProc(exit_codes=[1], log_lines=MAXDEL))
    uid = seed_user(db, kr)
    oc = w.runner.run(uid, "bisync")
    return w, uid, oc


def _with_delta(cfg, db, kr, entra):
    w, uid, _ = _tripped(cfg, db, kr, entra)
    w.runner.proc = FakeProc(exit_codes=[0], log_lines=DELTA)
    assert _choose(w, db, uid) == "delta"
    assert w.runner.run(uid, "delta").result == "ok"
    return w, uid


# ---- worker / runner ------------------------------------------------------------------

def test_safety_abort_pauses_user_and_queues_readonly_delta(cfg, db, kr, entra):
    w, uid, oc = _tripped(cfg, db, kr, entra)
    assert oc.result == "safety_abort"
    u = db.user_full(uid)
    assert u["state"] == D.SAFETY_ABORT and u["last_result"] == "safety_abort"
    assert json.loads(u["safety_abort_json"]) == {"check": "max_delete", "side": "Path2", "path": "/srv/springsync/mnt/x/",
                                                  "pct": 10, "deletes": 4, "total": 21,
                                                  "per_side": {"Path2": {"deletes": 4, "total": 21, "pct": 10}},
                                                  "during": "bisync", "onboarding": False}
    issue = next(i for i in db.open_issues(uid) if i["type"] == "safety_abort")
    assert issue["severity"] == "critical" and "4 of 21" in issue["summary"]
    assert db.runs(uid)[0]["result"] == "safety_abort"
    # paused: the next scheduled thing is only the read-only delta, never a plain bisync
    assert _choose(w, db, uid) == "delta"


def test_delta_run_is_dry_run_force_and_keeps_filenames_out_of_db(cfg, db, kr, entra):
    w, uid = _with_delta(cfg, db, kr, entra)
    cmd = w.runner.proc.calls[-1][0]
    assert "--dry-run" in cmd and "--force" in cmd and "--resync" not in cmd
    u = db.user_full(uid)
    assert u["state"] == D.SAFETY_ABORT and not u["safety_delta_requested"]
    assert u["safety_delta_summary"] == "OneDrive: 1 new; NAS: 2 deleted"
    f = delta_file(cfg, uid)
    assert oct(f.stat().st_mode & 0o777) == "0o600" and "Budget/2026.xlsx" in f.read_text()
    dump = "\n".join(str(tuple(r)) for t in ("sync_profiles", "sync_runs", "issues", "audit_log")
                     for r in db.all(f"SELECT * FROM {t}"))
    assert "Budget" not in dump and "xlsx" not in dump
    assert _choose(w, db, uid) is None          # waiting for the admin


def test_force_run_refused_without_approval(cfg, db, kr, entra):
    w, uid = _with_delta(cfg, db, kr, entra)
    with pytest.raises(RuntimeError):
        w.runner.run(uid, "force")
    active = seed_user(db, kr, upn="other@hotsprings.org")
    with pytest.raises(RuntimeError):
        w.runner.run(active, "force")


def test_exit7_retryable_counter_resets_on_success(cfg, db, kr, entra):
    w, _ = make_worker(cfg, db, kr, entra, FakeProc(exit_codes=[7], log_lines=[CRIT, RETRY]))
    uid = seed_user(db, kr)
    w.runner.run(uid, "bisync"); w.runner.run(uid, "bisync")
    w.runner.proc = FakeProc()
    w.runner.run(uid, "bisync")
    assert db.user_full(uid)["consecutive_crit_retry"] == 0


def test_exit7_must_resync_is_immediate_lockout(cfg, db, kr, entra):
    w, _ = make_worker(cfg, db, kr, entra, FakeProc(exit_codes=[7], log_lines=[CRIT, LOCK]))
    uid = seed_user(db, kr)
    assert w.runner.run(uid, "bisync").result == "critical"
    u = db.user_full(uid)
    assert u["state"] == D.CRITICAL and u["needs_resync"] and not u["resync_approved_by"]
    assert _choose(w, db, uid) is None           # never auto --resync


def test_usage_error_pauses(cfg, db, kr, entra):
    w, _ = make_worker(cfg, db, kr, entra, FakeProc(exit_codes=[2]))
    uid = seed_user(db, kr)
    assert w.runner.run(uid, "bisync").result == "usage"
    assert db.user_full(uid)["state"] == D.PAUSED
    assert any(i["type"] == "bug" and i["severity"] == "high" for i in db.open_issues(uid))


def test_offboard_removes_delta_file(cfg, db, kr, entra):
    w, uid = _with_delta(cfg, db, kr, entra)
    assert delta_file(cfg, uid).exists()
    db.set_state(uid, D.OFFBOARDING)
    w.offboard(uid)
    assert not delta_file(cfg, uid).exists()


def test_migration_2_is_expand_only(tmp_path):
    """A v0.1 (schema 1) DB upgrades in place and keeps its run history."""
    import sqlite3
    p = tmp_path / "old.db"
    c = sqlite3.connect(p, isolation_level=None)
    c.executescript("BEGIN;" + D.MIGRATIONS[0] + ";PRAGMA user_version=1;COMMIT;")
    c.execute("INSERT INTO users VALUES ('u','o','a@b','A','a','active',NULL,1,'t','t')")
    c.execute("INSERT INTO sync_runs(id,user_id,started_at,kind,result) VALUES (7,'u','t','bisync','ok')")
    c.close()
    db = D.DB(str(p))
    assert db.schema_version() == len(D.MIGRATIONS) == 5
    assert dict(db.one("SELECT id, kind, result FROM sync_runs")) == {"id": 7, "kind": "bisync", "result": "ok"}
    db.q("INSERT INTO sync_runs(user_id,started_at,kind) VALUES ('u','t','force')")
    with pytest.raises(Exception):
        db.q("INSERT INTO sync_runs(user_id,started_at,kind) VALUES ('u','t','bogus')")
