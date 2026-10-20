"""SPEC v0.3 §9.4 / §9.4.1 decisions:
- critical_retryable escalates on the same error twice in a row, immediately on a check-access failure,
  and on the 3rd in a row; the tool never starts --resync by itself;
- Restore runs at the next slot (within max_concurrent), or 'tonight' inside resync_hours; normal run limit;
- Accept deletes: normal run limit; 24 h expiry; pre-run dry-run recount cancels on mismatch; a timed-out
  --force run leaves the user paused and never re-runs; every step audited;
- the file list is IT-admin only and every view is audited (§14.13)."""
import json
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from odnas import db as D
from odnas.runner import ProcResult, delta_file
from tests.conftest import FakeProc, seed_user
from tests.test_runner_broker import make_worker
from tests.test_safety_abort import DELTA, _choose, _with_delta

CT = ZoneInfo("America/Chicago")
NOON = datetime(2026, 10, 21, 12, 0, tzinfo=CT).astimezone(timezone.utc)
EVENING = datetime(2026, 10, 21, 20, 0, tzinfo=CT).astimezone(timezone.utc)
RETRY = {"level": "error", "msg": "Bisync aborted. Error is retryable without --resync due to --resilient mode."}


def crit(err):
    return {"level": "error", "msg": f"Bisync critical error: {err}"}


class ScriptProc(FakeProc):
    """Per-call script: a list of (exit_code, log_lines, timed_out); the last entry repeats."""
    def __init__(self, script):
        super().__init__()
        self.script = list(script)

    def run(self, cmd, env, timeout_s, capture=False, stderr_path=None):
        code, lines, to = self.script.pop(0) if len(self.script) > 1 else self.script[0]
        self.exit_codes, self.log_lines, self.timed_out = [code], lines, to
        return super().run(cmd, env, timeout_s, capture, stderr_path)


def actions(db):
    return [r["action"] for r in db.all("SELECT action FROM audit_log ORDER BY seq")]


def approve_accept(db, uid, p1, p2, at=None):
    at = at or D.utcnow()
    db.update_profile(uid, safety_action=D.SAFETY_ACCEPT, safety_action_by="m", safety_action_at=D.iso(at),
                      safety_approved_deletes=p1 + p2, safety_approved_del_p1=p1, safety_approved_del_p2=p2,
                      safety_accept_state=D.ACCEPT_PENDING)


def approve_restore(db, uid, when=D.RESTORE_NEXT_SLOT):
    now = D.iso(D.utcnow())
    db.update_profile(uid, safety_action=D.SAFETY_RESTORE, safety_action_by="m", safety_action_at=now,
                      safety_restore_when=when, needs_resync=1, resync_approved_by="m", resync_approved_at=now)


# ---- 1. critical_retryable escalation ---------------------------------------------------

def test_same_retryable_error_twice_escalates_on_second_run(cfg, db, kr, entra):
    w, _ = make_worker(cfg, db, kr, entra, ScriptProc([(7, [crit("filters file has changed (hash 1234)"), RETRY], False),
                                                      (7, [crit("filters file has changed (hash 9876)"), RETRY], False)]))
    uid = seed_user(db, kr)
    assert w.runner.run(uid, "bisync").result == "critical_retryable"
    assert db.user(uid)["state"] == D.ACTIVE and _choose(w, db, uid) in ("bisync", "check")   # retried
    w.runner.run(uid, "bisync")                     # same error (digits normalised) on the 2nd consecutive run
    u = db.user_full(uid)
    assert u["state"] == D.CRITICAL and u["needs_resync"] and not u["resync_approved_by"]
    assert any(i["type"] == "critical" and i["severity"] == "critical" for i in db.open_issues(uid))
    assert "critical_retryable_escalated" in actions(db)
    assert _choose(w, db, uid) is None              # paused until an admin approves a resync


def test_check_access_failure_escalates_immediately(cfg, db, kr, entra):
    access = {"level": "error", "msg": "Access test failed: Path1 count 1, Path2 count 0 - .springsync-check"}
    w, _ = make_worker(cfg, db, kr, entra, FakeProc(exit_codes=[7], log_lines=[access, crit("check file check failed"),
                                                                              RETRY]))
    uid = seed_user(db, kr)
    w.runner.run(uid, "bisync")
    u = db.user_full(uid)
    assert u["state"] == D.CRITICAL and "check-access" in u["pause_reason"] and "mount" in u["pause_reason"]
    assert json.loads(db.audit_rows(action="critical_retryable_escalated")[0]["details_json"]) == {"reason": "access"}


def test_three_different_retryable_errors_escalate_on_third(cfg, db, kr, entra):
    w, _ = make_worker(cfg, db, kr, entra, ScriptProc([(7, [crit("error A"), RETRY], False),
                                                      (7, [crit("error B"), RETRY], False),
                                                      (7, [crit("error C"), RETRY], False)]))
    uid = seed_user(db, kr)
    w.runner.run(uid, "bisync"); w.runner.run(uid, "bisync")
    assert db.user(uid)["state"] == D.ACTIVE and db.user_full(uid)["consecutive_crit_retry"] == 2
    w.runner.run(uid, "bisync")
    assert db.user(uid)["state"] == D.CRITICAL


def test_other_result_breaks_the_consecutive_chain(cfg, db, kr, entra):
    w, _ = make_worker(cfg, db, kr, entra, ScriptProc([(7, [crit("error A"), RETRY], False), (5, [], False),
                                                      (7, [crit("error A"), RETRY], False)]))
    uid = seed_user(db, kr)
    for _ in range(3):
        w.runner.run(uid, "bisync")
    u = db.user_full(uid)
    assert u["state"] == D.ACTIVE and u["consecutive_crit_retry"] == 1 and u["last_crit_error"] == "error a"


def test_no_code_path_starts_resync_without_admin(cfg, db, kr, entra):
    proc = FakeProc(exit_codes=[7], log_lines=[crit("error A"), RETRY])
    w, _ = make_worker(cfg, db, kr, entra, proc)
    uid = seed_user(db, kr)
    now = EVENING                                    # inside resync_hours, so only approval can block it
    for i in range(6):
        db.update_profile(uid, next_run_at=None)
        w.tick(now + timedelta(minutes=31 * i), wait=True)
    assert db.user(uid)["state"] == D.CRITICAL
    assert not any("--resync" in c for c, _ in proc.calls)


# ---- 2. Restore timing -----------------------------------------------------------------

def test_restore_next_slot_runs_in_business_hours(cfg, db, kr, entra):
    w, uid = _with_delta(cfg, db, kr, entra)
    approve_restore(db, uid)
    assert _choose(w, db, uid, NOON) == "resync"


def test_restore_tonight_waits_for_resync_window(cfg, db, kr, entra):
    w, uid = _with_delta(cfg, db, kr, entra)
    approve_restore(db, uid, D.RESTORE_TONIGHT)
    assert _choose(w, db, uid, NOON) is None
    assert _choose(w, db, uid, EVENING) == "resync"


def test_next_slot_restores_obey_max_concurrent_only(cfg, db, kr, entra):
    w, _ = make_worker(cfg, db, kr, entra, FakeProc())
    uids = []
    for i in range(3):
        uid = seed_user(db, kr, upn=f"u{i}@hotsprings.org")
        db.set_state(uid, D.SAFETY_ABORT)
        db.update_profile(uid, safety_abort_at=D.iso(D.utcnow()), safety_delta_at=D.iso(D.utcnow()))
        approve_restore(db, uid)
        uids.append(uid)
    w.governor.max_concurrent = lambda now, cap: cap          # isolate from the throttle governor
    started = w.tick(NOON, wait=True)
    assert [k for _, k in started] == ["resync", "resync"]    # cap 2; not limited to one resync at a time


def test_tonight_restore_timeout_needs_new_click(cfg, db, kr, entra):
    w, uid = _with_delta(cfg, db, kr, entra)
    approve_restore(db, uid, D.RESTORE_TONIGHT)
    w.runner.proc = FakeProc(timed_out=True, exit_codes=[-2])
    assert w.runner.run(uid, "resync").result == "timeout"
    u = db.user_full(uid)
    assert u["state"] == D.SAFETY_ABORT and u["safety_action"] is None and not u["resync_approved_by"]
    assert u["restore_timeouts"] == 1 and not u["needs_resync"]
    assert _choose(w, db, uid, EVENING) is None
    assert any(i["type"] == "restore_failed" for i in db.open_issues(uid))
    a = actions(db)
    assert "safety_restore_started" in a and "safety_restore_window_closed" in a


def test_restore_success_audited(cfg, db, kr, entra):
    w, uid = _with_delta(cfg, db, kr, entra)
    approve_restore(db, uid)
    w.runner.proc = FakeProc()
    assert w.runner.run(uid, "resync").result == "ok"
    cmd = w.runner.proc.calls[-1][0]
    assert "--resync" in cmd and "--force" not in cmd
    u = db.user_full(uid)
    assert u["state"] == D.ACTIVE and not u["safety_abort_at"] and not u["needs_resync"]
    assert {"safety_restore_started", "safety_restore_completed"} <= set(actions(db))


# ---- 3. Accept deletes ------------------------------------------------------------------

def test_accept_deletes_prechecks_then_one_force_run(cfg, db, kr, entra):
    w, uid = _with_delta(cfg, db, kr, entra)                 # DELTA: 2 deletes on the NAS side
    approve_accept(db, uid, 0, 2, at=NOON - timedelta(hours=1))
    assert _choose(w, db, uid, NOON) == "force"
    approve_accept(db, uid, 0, 2)
    w.runner.proc = FakeProc(log_lines=DELTA)
    assert w.runner.run(uid, "force").result == "ok"
    (pre, pre_limit), (run, limit) = w.runner.proc.calls[-2:]
    assert "--dry-run" in pre and "--force" in pre and "--resync" not in pre
    assert "--force" in run and "--dry-run" not in run and "--resync" not in run
    assert limit == 25 * 60                                  # same run-time limit as a normal run
    two = db.runs(uid)[:2]                                   # newest first
    assert [r["kind"] for r in two] == ["force", "delta"] and two[1]["id"] < two[0]["id"]   # recount row first
    u = db.user_full(uid)
    assert u["state"] == D.ACTIVE and not u["safety_action"] and u["safety_approved_deletes"] is None
    a = actions(db)
    for step in ("accept_deletes_precheck", "accept_deletes_started", "accept_deletes_completed"):
        assert step in a
    pre_audit = json.loads(db.audit_rows(action="accept_deletes_precheck")[0]["details_json"])
    assert (pre_audit["deletes_path1"], pre_audit["deletes_path2"]) == (0, 2)
    assert (pre_audit["approved_deletes_path1"], pre_audit["approved_deletes_path2"]) == (0, 2)


def test_count_change_cancels_and_voids_approval(cfg, db, kr, entra):
    w, uid = _with_delta(cfg, db, kr, entra)
    approve_accept(db, uid, 0, 2)
    more = DELTA + [{"level": "notice", "msg": "- Path2             File was deleted                            - x.txt"}]
    w.runner.proc = FakeProc(log_lines=more)
    oc = w.runner.run(uid, "force")
    assert oc.result == "cancelled" and "approved Path1=0 Path2=2, now Path1=0 Path2=3" in oc.detail
    assert len(w.runner.proc.calls) == 1 and "--dry-run" in w.runner.proc.calls[0][0]   # --force never ran
    u = db.user_full(uid)
    assert u["state"] == D.SAFETY_ABORT and u["safety_action"] is None and u["safety_approved_deletes"] is None
    assert u["safety_accept_state"] == D.ACCEPT_CANCELLED
    assert "x.txt" in delta_file(cfg, uid).read_text()      # admin re-reviews the new list
    assert any(i["type"] == "accept_deletes_cancelled" for i in db.open_issues(uid))
    det = json.loads(db.audit_rows(action="accept_deletes_cancelled")[0]["details_json"])
    assert (det["approved_deletes_path2"], det["deletes_now_path2"]) == (2, 3)
    runs = db.runs(uid)
    assert runs[0]["kind"] == "delta" and runs[0]["result"] == "cancelled"
    assert not any(r["kind"] == "force" for r in runs)          # --force never ran, so no force row
    assert _choose(w, db, uid, NOON) is None


def test_approval_expires_after_24h(cfg, db, kr, entra):
    w, uid = _with_delta(cfg, db, kr, entra)
    approve_accept(db, uid, 0, 2, at=NOON - timedelta(hours=23, minutes=59))
    assert _choose(w, db, uid, NOON) == "force"
    approve_accept(db, uid, 0, 2, at=NOON - timedelta(hours=24))
    assert _choose(w, db, uid, NOON) is None
    w.tick(NOON)
    u = db.user_full(uid)
    assert u["safety_accept_state"] == D.ACCEPT_EXPIRED and u["safety_action"] is None
    assert "accept_deletes_expired" in actions(db)
    assert any(i["type"] == "accept_deletes_expired" for i in db.open_issues(uid))
    approve_accept(db, uid, 0, 2, at=D.utcnow() - timedelta(hours=25))
    import pytest
    with pytest.raises(RuntimeError):
        w.runner.run(uid, "force")


def test_force_timeout_stays_paused_and_never_reruns(cfg, db, kr, entra):
    w, uid = _with_delta(cfg, db, kr, entra)
    approve_accept(db, uid, 0, 2)
    w.runner.proc = ScriptProc([(0, DELTA, False), (-2, [], True)])   # pre-check ok, --force hits the limit
    assert w.runner.run(uid, "force").result == "timeout"
    u = db.user_full(uid)
    assert u["state"] == D.SAFETY_ABORT and u["safety_action"] is None
    assert u["safety_accept_state"] == D.ACCEPT_TIMEOUT
    assert "accept_deletes_timeout" in actions(db)
    assert any(i["type"] == "accept_deletes_failed" for i in db.open_issues(uid))
    calls_before = len(w.runner.proc.calls)
    for i in range(4):
        w.tick(NOON + timedelta(hours=i), wait=True)
    assert len(w.runner.proc.calls) == calls_before            # nothing re-ran automatically
    assert _choose(w, db, uid, NOON) is None


def test_force_failure_stays_paused(cfg, db, kr, entra):
    w, uid = _with_delta(cfg, db, kr, entra)
    approve_accept(db, uid, 0, 2)
    w.runner.proc = ScriptProc([(0, DELTA, False), (5, [], False)])
    assert w.runner.run(uid, "force").result == "retryable"
    u = db.user_full(uid)
    assert u["state"] == D.SAFETY_ABORT and u["safety_accept_state"] == D.ACCEPT_FAILED and u["safety_action"] is None
    assert "accept_deletes_failed" in actions(db)


def test_precheck_failure_cancels(cfg, db, kr, entra):
    w, uid = _with_delta(cfg, db, kr, entra)
    approve_accept(db, uid, 0, 2)
    w.runner.proc = FakeProc(exit_codes=[5])
    assert w.runner.run(uid, "force").result == "cancelled"
    assert len(w.runner.proc.calls) == 1
    assert db.user_full(uid)["safety_accept_state"] == D.ACCEPT_PRECHECK_FAILED
