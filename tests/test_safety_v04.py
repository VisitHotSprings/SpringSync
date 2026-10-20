"""SPEC v0.4 (Reid's answers, 2026-10-20):
- tonight Restores run until resync_hours closes (07:00 CT); a next-slot Restore that hits 25 min is
  re-queued once as a tonight run (no new approval, audited, admin notified); a tonight Restore still running
  at 07:00 is stopped, the user stays paused and the admin is alerted;
- delete counts are per side; Accept deletes approves both, and either side changing cancels --force;
- mount failures (rclone never started) are skipped by the same-error chain, counted separately, alert after
  2 in a row, no lockout;
- run history: the recount row comes before the force row;
- §5 value lists match the code exactly."""
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

from odnas import db as D
from odnas.classify import RESULTS, find_safety_abort, iter_log
from odnas.runner import KINDS
from tests.conftest import FakeProc, seed_user
from tests.test_runner_broker import make_worker
from tests.test_safety_abort import DELTA, MAXDEL, _choose, _with_delta
from tests.test_web import wc  # noqa: F401  (fixture)
from tests.test_safety_v03 import EVENING, NOON, RETRY, ScriptProc, actions, approve_accept, approve_restore, crit

CT = ZoneInfo("America/Chicago")
SPEC = Path(__file__).resolve().parents[2] / "SPEC.md"


def at(monkeypatch, when):
    monkeypatch.setattr(D, "utcnow", lambda: when)


def issues(db, uid):
    return {i["type"] for i in db.open_issues(uid)}


# ---- 1. Restore run-time limits and the automatic tonight re-queue -----------------------

def test_next_slot_restore_timeout_requeues_once_as_tonight(cfg, db, kr, entra, monkeypatch):
    w, uid = _with_delta(cfg, db, kr, entra)
    approve_restore(db, uid)                                   # next slot, approved by "m"
    at(monkeypatch, NOON)
    w.runner.proc = proc = FakeProc(timed_out=True, exit_codes=[-2])
    assert w.runner.run(uid, "resync").result == "timeout"
    assert proc.calls[-1][1] == 25 * 60                        # normal limit for a next-slot Restore
    u = db.user_full(uid)
    assert u["state"] == D.SAFETY_ABORT
    assert (u["safety_action"], u["safety_restore_when"], u["safety_restore_requeued"]) == \
        (D.SAFETY_RESTORE, D.RESTORE_TONIGHT, 1)
    assert u["needs_resync"] and u["resync_approved_by"] == "m"   # original approver; no new approval asked
    det = json.loads(db.audit_rows(action="safety_restore_requeued_tonight")[0]["details_json"])
    assert det["approved_by"] == "m"
    assert "restore_requeued" in issues(db, uid) and "restore_failed" not in issues(db, uid)
    assert db.runs(uid)[0]["result"] == "timeout"
    assert _choose(w, db, uid, NOON + timedelta(hours=1)) is None   # waits for the night window
    assert _choose(w, db, uid, EVENING) == "resync"


def test_requeued_tonight_restore_runs_until_0700_ct(cfg, db, kr, entra, monkeypatch):
    w, uid = _with_delta(cfg, db, kr, entra)
    approve_restore(db, uid)
    at(monkeypatch, NOON)
    w.runner.proc = FakeProc(timed_out=True, exit_codes=[-2])
    w.runner.run(uid, "resync")
    at(monkeypatch, EVENING)                                    # 20:00 CT
    w.runner.proc = proc = FakeProc(exit_codes=[0])
    assert w.runner.run(uid, "resync").result == "ok"
    assert proc.calls[-1][1] == 11 * 3600                       # until 07:00 CT, not 25 min
    u = db.user_full(uid)
    assert u["state"] == D.ACTIVE and not u["safety_restore_requeued"] and u["safety_action"] is None
    started = json.loads(db.audit_rows(action="safety_restore_started")[0]["details_json"])
    assert started["auto_requeued"] is True and started["limit_s"] == 11 * 3600


def test_tonight_restore_stopped_at_0700_stays_paused_and_alerts(cfg, db, kr, entra, monkeypatch):
    w, uid = _with_delta(cfg, db, kr, entra)
    approve_restore(db, uid)
    at(monkeypatch, NOON)
    w.runner.proc = FakeProc(timed_out=True, exit_codes=[-2])
    w.runner.run(uid, "resync")                                 # -> re-queued for tonight
    at(monkeypatch, datetime(2026, 10, 22, 6, 0, tzinfo=CT).astimezone(timezone.utc))
    w.runner.proc = proc = FakeProc(timed_out=True, exit_codes=[-2])
    assert w.runner.run(uid, "resync").result == "timeout"
    assert proc.calls[-1][1] == 3600                            # stopped at 07:00 CT
    u = db.user_full(uid)
    assert u["state"] == D.SAFETY_ABORT and u["safety_action"] is None and not u["resync_approved_by"]
    assert not u["needs_resync"]
    assert "restore_failed" in issues(db, uid)
    assert actions(db).count("safety_restore_requeued_tonight") == 1   # re-queued only once
    assert "safety_restore_window_closed" in actions(db)
    assert _choose(w, db, uid, EVENING + timedelta(days=1)) is None    # admin must click Restore again


def test_admin_tonight_restore_limit_is_window_not_25_min(cfg, db, kr, entra, monkeypatch):
    w, uid = _with_delta(cfg, db, kr, entra)
    approve_restore(db, uid, D.RESTORE_TONIGHT)
    at(monkeypatch, datetime(2026, 10, 21, 18, 0, tzinfo=CT).astimezone(timezone.utc))
    w.runner.proc = proc = FakeProc(exit_codes=[0])
    w.runner.run(uid, "resync")
    assert proc.calls[-1][1] == 13 * 3600


def test_tonight_limit_respects_dst_end(cfg, db, kr, entra, monkeypatch):
    # 2026-11-01 02:00 CDT -> 01:00 CST: the night of Oct 31 is 14 h long, 18:00 to 07:00 CST
    w, uid = _with_delta(cfg, db, kr, entra)
    approve_restore(db, uid, D.RESTORE_TONIGHT)
    at(monkeypatch, datetime(2026, 10, 31, 18, 0, tzinfo=CT).astimezone(timezone.utc))
    w.runner.proc = proc = FakeProc(exit_codes=[0])
    w.runner.run(uid, "resync")
    assert proc.calls[-1][1] == 14 * 3600


def test_restore_failure_is_not_requeued(cfg, db, kr, entra, monkeypatch):
    w, uid = _with_delta(cfg, db, kr, entra)
    approve_restore(db, uid)
    at(monkeypatch, NOON)
    w.runner.proc = FakeProc(exit_codes=[2])                    # a real error, not the time limit
    w.runner.run(uid, "resync")
    u = db.user_full(uid)
    assert u["safety_action"] is None and not u["safety_restore_requeued"]
    assert "safety_restore_requeued_tonight" not in actions(db)


def test_admin_reclick_resets_requeue(app_client_admin):
    client, db, uid, tok = app_client_admin
    db.update_profile(uid, safety_restore_requeued=1)
    assert client.post(f"/admin/users/{uid}/safety-restore", data={"csrf": tok, "when": "next_slot"}).status_code == 303
    assert db.user_full(uid)["safety_restore_requeued"] == 0


@pytest.fixture
def app_client_admin(cfg, db, kr, entra, wc):
    from tests.conftest import G_ADMINS
    from tests.test_web import _safety_user, csrf, login
    from odnas.web.app import create_app
    a = create_app(cfg, db, kr, entra, wc)
    c = login(a, entra, oid="m", upn="mark@hotsprings.org", groups=(G_ADMINS,))
    uid = _safety_user(db, kr, cfg)
    return c, db, uid, csrf(c, "/admin")


# ---- 2. Per-side delete counts --------------------------------------------------------

def _abort_line(n, side, path):
    return {"level": "error", "object": "Safety abort",
            "msg": f'too many deletes (>10%, {n} of 21) on {side} "{path}". Run with --force if desired.'}


def test_safety_abort_parses_each_sides_line():
    e = list(iter_log("\n".join(json.dumps(x) for x in [_abort_line(3, "Path1", "od:"), _abort_line(4, "Path2", "/m/")])))
    sa = find_safety_abort(e)
    assert sa.per_side == {"Path1": {"deletes": 3, "total": 21, "pct": 10}, "Path2": {"deletes": 4, "total": 21, "pct": 10}}
    assert "OneDrive 3 of 21" in sa.summary() and "NAS 4 of 21" in sa.summary()


P1_DEL = {"level": "notice", "msg": "- Path1             File was deleted                            - Old/x.docx"}


@pytest.mark.parametrize("approved,precheck", [
    ((0, 2), DELTA + [P1_DEL]),          # Path1 changed alone (Path2 still 2)
    ((0, 2), DELTA[1:]),                 # Path2 changed alone (Path1 still 0)
    ((1, 1), DELTA),                     # same total (2) but split differently
])
def test_either_side_alone_changing_cancels_force(cfg, db, kr, entra, approved, precheck):
    w, uid = _with_delta(cfg, db, kr, entra)
    approve_accept(db, uid, *approved, at=D.utcnow() - timedelta(hours=1))
    w.runner.proc = proc = FakeProc(exit_codes=[0], log_lines=precheck)
    assert w.runner.run(uid, "force").result == "cancelled"
    assert len(proc.calls) == 1 and "--dry-run" in proc.calls[0][0]      # --force never ran for real
    u = db.user_full(uid)
    assert u["safety_accept_state"] == D.ACCEPT_CANCELLED and u["safety_action"] is None
    assert u["safety_approved_del_p1"] is None and u["safety_approved_del_p2"] is None
    assert [r["kind"] for r in db.runs(uid)][:1] == ["delta"] and "force" not in [r["kind"] for r in db.runs(uid)]
    assert "accept_deletes_cancelled" in issues(db, uid)


def test_matching_per_side_counts_run_force_after_recount_row(cfg, db, kr, entra):
    w, uid = _with_delta(cfg, db, kr, entra)
    approve_accept(db, uid, 0, 2, at=D.utcnow() - timedelta(hours=1))
    w.runner.proc = FakeProc(exit_codes=[0], log_lines=DELTA)
    assert w.runner.run(uid, "force").result == "ok"
    rows = sorted(db.runs(uid), key=lambda r: r["id"])[-2:]
    assert [r["kind"] for r in rows] == ["delta", "force"]            # chronological: recount, then force
    assert rows[0]["ended_at"] <= rows[1]["started_at"]
    assert "Path1=0 Path2=2" in rows[0]["detail"]


# ---- 3. Mount failures ----------------------------------------------------------------

def test_mount_failure_neither_breaks_nor_extends_same_error_chain(cfg, db, kr, entra):
    proc = ScriptProc([(7, [crit("error A"), RETRY], False)])
    w, hr = make_worker(cfg, db, kr, entra, proc)
    uid = seed_user(db, kr)
    w.runner.run(uid, "bisync")                                  # crit A (1)
    hr.codes["mount"] = 4                                        # NAS unreachable: rclone never starts
    assert w.runner.run(uid, "bisync").result == "retryable"
    u = db.user_full(uid)
    assert (u["consecutive_crit_retry"], u["last_crit_error"]) == (1, "error a")   # untouched
    hr.codes["mount"] = 0
    w.runner.run(uid, "bisync")                                  # crit A again -> same error twice -> lockout
    assert db.user(uid)["state"] == D.CRITICAL


def test_mount_failure_does_not_count_as_a_retryable(cfg, db, kr, entra):
    proc = ScriptProc([(7, [crit("error A"), RETRY], False), (7, [crit("error B"), RETRY], False)])
    w, hr = make_worker(cfg, db, kr, entra, proc)
    uid = seed_user(db, kr)
    w.runner.run(uid, "bisync")
    hr.codes["mount"] = 3
    w.runner.run(uid, "bisync")
    hr.codes["mount"] = 0
    w.runner.run(uid, "bisync")                                  # error B: 2nd retryable, different error
    u = db.user_full(uid)
    assert u["state"] == D.ACTIVE and u["consecutive_crit_retry"] == 2


def test_two_mount_failures_alert_without_lockout_and_rclone_start_resets(cfg, db, kr, entra):
    proc = FakeProc()
    w, hr = make_worker(cfg, db, kr, entra, proc, {"mount": 4})
    uid = seed_user(db, kr)
    w.runner.run(uid, "bisync")
    assert db.user_full(uid)["consecutive_mount_failures"] == 1 and "nas_unreachable" not in issues(db, uid)
    w.runner.run(uid, "bisync")
    u = db.user_full(uid)
    assert u["consecutive_mount_failures"] == 2 and "nas_unreachable" in issues(db, uid)
    assert u["state"] == D.ACTIVE and u["consecutive_failures"] == 0      # no lockout, not a "retryable failure"
    assert proc.calls == []
    assert _choose(w, db, uid) is not None                               # keeps being scheduled
    hr.codes["mount"] = 0
    w.runner.run(uid, "bisync")
    assert db.user_full(uid)["consecutive_mount_failures"] == 0 and "nas_unreachable" not in issues(db, uid)
    hr.codes["mount"] = 4
    w.runner.run(uid, "bisync")
    assert "nas_unreachable" not in issues(db, uid)                      # counter restarted at 1


def test_rclone_start_with_failure_still_resets_mount_counter(cfg, db, kr, entra):
    w, hr = make_worker(cfg, db, kr, entra, FakeProc(exit_codes=[3]))
    uid = seed_user(db, kr)
    hr.codes["mount"] = 4
    w.runner.run(uid, "bisync")
    hr.codes["mount"] = 0
    w.runner.run(uid, "bisync")                                  # rclone started (and failed)
    assert db.user_full(uid)["consecutive_mount_failures"] == 0


def _with_delta_hr(cfg, db, kr, entra):
    w, hr = make_worker(cfg, db, kr, entra, FakeProc(exit_codes=[1], log_lines=MAXDEL))
    uid = seed_user(db, kr)
    w.runner.run(uid, "bisync")
    w.runner.proc = FakeProc(exit_codes=[0], log_lines=DELTA)
    w.runner.run(uid, "delta")
    return w, hr, uid


def test_mount_failure_keeps_one_shot_accept_approval(cfg, db, kr, entra):
    w, hr, uid = _with_delta_hr(cfg, db, kr, entra)
    approve_accept(db, uid, 0, 2, at=D.utcnow() - timedelta(hours=1))
    hr.codes["mount"] = 4
    w.runner.proc = proc = FakeProc(exit_codes=[0], log_lines=DELTA)
    assert w.runner.run(uid, "force").result == "retryable"
    assert proc.calls == []
    u = db.user_full(uid)
    assert (u["safety_action"], u["safety_approved_del_p1"], u["safety_approved_del_p2"], u["safety_accept_state"]) \
        == (D.SAFETY_ACCEPT, 0, 2, D.ACCEPT_PENDING)
    assert "accept_deletes_failed" not in actions(db)


def test_mount_failure_keeps_one_shot_restore_approval(cfg, db, kr, entra):
    w, hr, uid = _with_delta_hr(cfg, db, kr, entra)
    approve_restore(db, uid)
    hr.codes["mount"] = 4
    assert w.runner.run(uid, "resync").result == "retryable"
    u = db.user_full(uid)
    assert u["safety_action"] == D.SAFETY_RESTORE and u["resync_approved_by"] == "m" and u["needs_resync"]
    assert "safety_restore_failed" not in actions(db) and not u["safety_restore_requeued"]


# ---- 4. SPEC §5 names --------------------------------------------------------------------

def _spec_list(col):
    text = SPEC.read_text()
    m = re.search(r"`" + re.escape(col) + r"` \(`([^)]*)`\)", text)
    return tuple(m.group(1).replace("`", "").split("\\|"))


@pytest.mark.skipif(not SPEC.exists(), reason="SPEC.md not next to the repo")
def test_spec_section5_value_lists_match_code():
    assert set(_spec_list("state")) == set(D.STATES)
    assert set(_spec_list("result")) == set(RESULTS)
    assert set(_spec_list("kind")) == set(KINDS)


def test_value_lists_frozen():
    # the same lists, frozen here so the check also runs where SPEC.md is absent
    assert set(D.STATES) == {"invited", "onboarding", "active", "paused", "needs_reauth", "nas_auth_failed",
                             "blocked_by_ca", "critical", "safety_abort", "offboarding", "removed"}
    assert set(RESULTS) == {"ok", "retryable", "critical", "critical_retryable", "safety_abort", "usage", "timeout",
                            "cancelled", "auth", "nas_auth", "error"}
    assert KINDS == ("dryrun", "resync", "bisync", "check", "preflight", "delta", "force")
