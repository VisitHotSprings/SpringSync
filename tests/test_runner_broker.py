import json
import os
import signal
import sys
import textwrap
import time
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from odnas import db as D
from odnas.entra import TokenResult
from odnas.nas import MountHelperClient
from odnas.runner import ProcessRunner
from tests.conftest import CANARY_PW, CANARY_RT, FakeHelperRunner, FakeProc, seed_user


def make_worker(cfg, db, kr, entra, proc, helper_codes=None):
    from odnas.worker import Worker
    hr = FakeHelperRunner(helper_codes, mnt_root=cfg.p_mnt)
    w = Worker(cfg, db, kr, entra, proc=proc, helper=MountHelperClient(cfg, hr))
    return w, hr


def test_ok_run_updates_status_and_cleans_up(cfg, db, kr, entra):
    proc = FakeProc(log_lines=[{"level": "notice", "msg": "done", "stats": {"transfers": 4, "deletes": 1, "bytes": 10,
                                                                           "errors": 0}}])
    w, hr = make_worker(cfg, db, kr, entra, proc)
    uid = seed_user(db, kr)
    oc = w.runner.run(uid, "bisync")
    assert oc.result == "ok"
    u = db.user_full(uid)
    assert u["last_success_at"] and u["next_run_at"] and u["last_result"] == "ok"
    r = db.runs(uid)[0]
    assert (r["files_copied"], r["files_deleted"], r["exit_code"]) == (4, 1, 0)
    # mount used the user's own NAS login (option A), via helper, then unmounted
    assert [c[0] for c in hr.calls] == ["mount", "umount"]
    assert CANARY_PW in hr.calls[0][2]
    # incremental runs get the worker-enforced limit (25 min default)
    assert proc.calls[0][1] == 25 * 60
    # no per-run secrets left on tmpfs
    for sub in ("creds", "rclone"):
        d = Path(cfg.p_run) / sub
        assert not d.exists() or not any(d.iterdir())
    assert w.broker.active_handles() == 0


def test_wrong_nas_password_pauses_without_retry(cfg, db, kr, entra):
    proc = FakeProc()
    w, hr = make_worker(cfg, db, kr, entra, proc, {"mount": 13})
    uid = seed_user(db, kr)
    assert w.runner.run(uid, "bisync").result == "nas_auth"
    u = db.user_full(uid)
    assert u["state"] == D.NAS_AUTH_FAILED
    assert db.nas_credential_meta(uid)["failure_count"] == 1
    assert proc.calls == []  # rclone never started
    assert any(i["type"] == "nas_auth_failed" for i in db.open_issues(uid))
    # no further attempts: the scheduler never picks this user again
    from datetime import timedelta
    for k in range(5):
        assert w.choose_job(db.user_full(uid), w.settings(), D.utcnow() + timedelta(hours=k)) is None
    assert [c[0] for c in hr.calls].count("mount") == 1


def test_exit7_goes_critical_and_needs_approval(cfg, db, kr, entra):
    w, _ = make_worker(cfg, db, kr, entra, FakeProc(exit_codes=[7]))
    uid = seed_user(db, kr)
    assert w.runner.run(uid, "bisync").result == "critical"
    u = db.user_full(uid)
    assert u["state"] == D.CRITICAL and u["needs_resync"] == 1 and not u["resync_approved_by"]
    assert w.choose_job(u, w.settings(), D.utcnow()) is None


def test_three_retryable_failures_open_issue(cfg, db, kr, entra):
    w, _ = make_worker(cfg, db, kr, entra, FakeProc(exit_codes=[1]))
    uid = seed_user(db, kr)
    for _ in range(2):
        w.runner.run(uid, "bisync")
    assert not db.open_issues(uid)
    w.runner.run(uid, "bisync")
    assert [i["type"] for i in db.open_issues(uid)] == ["repeated_failures"]
    assert db.user(uid)["state"] == D.ACTIVE


def test_usage_error_pauses_user(cfg, db, kr, entra):
    w, _ = make_worker(cfg, db, kr, entra, FakeProc(exit_codes=[2]))
    uid = seed_user(db, kr)
    w.runner.run(uid, "bisync")
    assert db.user(uid)["state"] == D.PAUSED


def test_resync_completion_activates(cfg, db, kr, entra):
    w, _ = make_worker(cfg, db, kr, entra, FakeProc())
    uid = seed_user(db, kr, state=D.ONBOARDING, dryrun_ok_at="2026-10-20T00:00:00+00:00", resync_approved_by="mark")
    w.runner.run(uid, "resync")
    u = db.user_full(uid)
    assert u["state"] == D.ACTIVE and u["needs_resync"] == 0 and u["resync_approved_by"] is None


def test_dryrun_creates_check_files_and_uses_dry_run(cfg, db, kr, entra):
    proc = FakeProc()
    w, _ = make_worker(cfg, db, kr, entra, proc)
    uid = seed_user(db, kr, state=D.ONBOARDING)
    w.runner.run(uid, "dryrun")
    cmds = [c for c, _ in proc.calls]
    assert cmds[0][1] == "touch" and cmds[0][2] == f"od-{uid}:.springsync-check"
    assert "--dry-run" in cmds[1] and "--resync" in cmds[1]
    assert (Path(cfg.p_mnt) / uid / ".springsync-check").exists()
    assert db.user_full(uid)["dryrun_ok_at"]
    assert any(i["type"] == "approval_needed" for i in db.open_issues(uid))


def test_preflight_report_only_counts_in_db(cfg, db, kr, entra):
    listing = json.dumps([{"Path": "Docs/CON.txt", "Size": 1}, {"Path": "Docs/a.txt", "Size": 1},
                          {"Path": "Docs/A.txt", "Size": 1}])
    w, _ = make_worker(cfg, db, kr, entra, FakeProc(stdout=listing))
    uid = seed_user(db, kr, state=D.ONBOARDING, preflight_requested=1)
    w.runner.run(uid, "preflight")
    u = db.user_full(uid)
    assert "blocked_name: 2" in u["preflight_summary"] and "case_collision" in u["preflight_summary"]
    assert "CON.txt" not in u["preflight_summary"]  # filenames never in DB
    rep = Path(cfg.p_state) / "preflight" / f"{uid}.json"
    assert oct(rep.stat().st_mode & 0o777) == "0o600" and "CON.txt" in rep.read_text()


def test_preflight_quota_from_rclone_about(cfg, db, kr, entra):
    class QuotaProc(FakeProc):
        def run(self, cmd, env, timeout_s, capture=False, stderr_path=None):
            from odnas.runner import ProcResult
            self.calls.append((cmd, timeout_s))
            if "about" in cmd:
                return ProcResult(0, False, json.dumps({"total": 1000, "free": 10}))
            return ProcResult(0, False, json.dumps([{"Path": "big.bin", "Size": 500}]))
    proc = QuotaProc()
    w, _ = make_worker(cfg, db, kr, entra, proc)
    uid = seed_user(db, kr, state=D.ONBOARDING, preflight_requested=1)
    w.runner.run(uid, "preflight")
    assert any("about" in c for c, _ in proc.calls)
    assert "onedrive_quota" in db.user_full(uid)["preflight_summary"]


# ---- broker ------------------------------------------------------------

def test_broker_rotates_and_persists(cfg, db, kr, entra):
    from odnas.tokens import TokenBroker
    b = TokenBroker(db, kr, entra, cfg)
    uid = seed_user(db, kr)
    h = b.issue(uid, 1)
    code, body = b.token(uid, {"grant_type": "refresh_token", "refresh_token": h, "client_id": cfg.client_id})
    assert code == 200 and body["access_token"] == "at-1" and body["refresh_token"] == h
    assert entra.refresh_calls == [CANARY_RT]
    assert db.refresh_token(kr, uid) == "rt-rotated-1"  # rotation persisted, re-encrypted
    b.token(uid, {"grant_type": "refresh_token", "refresh_token": h})
    assert entra.refresh_calls[-1] == "rt-rotated-1"


def test_broker_rejects_wrong_user_or_handle(cfg, db, kr, entra):
    from odnas.tokens import TokenBroker
    b = TokenBroker(db, kr, entra, cfg)
    u1, u2 = seed_user(db, kr, upn="a@hotsprings.org"), seed_user(db, kr, upn="b@hotsprings.org")
    h = b.issue(u1, 1)
    assert b.token(u2, {"grant_type": "refresh_token", "refresh_token": h})[0] == 400
    assert b.token(u1, {"grant_type": "refresh_token", "refresh_token": "guess"})[0] == 400
    assert b.token(u1, {"grant_type": "client_credentials"})[0] == 400
    assert b.token(u1, {"grant_type": "refresh_token", "refresh_token": h, "client_id": "evil"})[0] == 401
    b.revoke(h)
    assert b.token(u1, {"grant_type": "refresh_token", "refresh_token": h})[0] == 400
    assert entra.refresh_calls == []


@pytest.mark.parametrize("codes,state", [([700082], D.NEEDS_REAUTH), ([53003], D.BLOCKED_BY_CA)])
def test_broker_error_maps_to_state(cfg, db, kr, entra, codes, state):
    entra.next_refresh = TokenResult(error="invalid_grant", error_description=f"AADSTS{codes[0]}: x",
                                     error_codes=codes)

    class RcloneCallsBroker(FakeProc):
        def run(self, cmd, env, timeout_s, capture=False, stderr_path=None):
            # emulate rclone hitting token_url with the handle from its config
            conf = Path(cmd[cmd.index("--config") + 1]).read_text()
            handle = json.loads(conf.split("token = ", 1)[1].splitlines()[0])["refresh_token"]
            uid = cmd[2].removeprefix("od-").rstrip(":")
            code, _ = w.broker.token(uid, {"grant_type": "refresh_token", "refresh_token": handle})
            assert code == 400
            return super().run(cmd, env, timeout_s, capture, stderr_path)

    proc = RcloneCallsBroker(exit_codes=[1])
    w, _ = make_worker(cfg, db, kr, entra, proc)
    uid = seed_user(db, kr)
    oc = w.runner.run(uid, "bisync")
    assert oc.result == "auth"
    assert db.user(uid)["state"] == state
    assert db.ms_credential(uid)["last_refresh_error"].startswith(state)
    assert db.refresh_token(kr, uid) == CANARY_RT  # untouched on failure


def test_broker_http_endpoint(cfg, db, kr, entra):
    from odnas.worker import build_internal_app
    w, _ = make_worker(cfg, db, kr, entra, FakeProc())
    uid = seed_user(db, kr)
    h = w.broker.issue(uid, 1)
    c = TestClient(build_internal_app(w))
    r = c.post(f"/broker/{uid}/token", data={"grant_type": "refresh_token", "refresh_token": h})
    assert r.status_code == 200 and r.json()["token_type"] == "Bearer" and r.headers["cache-control"] == "no-store"
    assert c.post("/internal/nas-verify", json={"username": "x", "password": "y"}).status_code == 403
    r = c.post("/internal/nas-verify", json={"username": "x", "password": "y"},
               headers={"x-internal-token": kr.internal_token()})
    assert r.json()["status"] == "ok"


# ---- real process: worker-enforced run time limit -------------------------

def test_time_limit_sends_sigint_then_kill(tmp_path):
    script = tmp_path / "fake_rclone.py"
    marker = tmp_path / "got_sigint"
    script.write_text(textwrap.dedent(f"""
        import signal, sys, time
        def h(*a):
            open({str(marker)!r}, "w").write("1")
            time.sleep(30)   # misbehave: ignore graceful-stop deadline
        signal.signal(signal.SIGINT, h)
        time.sleep(30)
    """))
    pr = ProcessRunner(grace_s=0.5)
    t = time.time()
    res = pr.run([sys.executable, str(script)], dict(os.environ), timeout_s=0.5)
    assert res.timed_out and marker.exists() and time.time() - t < 10
    assert res.exit_code == -signal.SIGKILL


def test_time_limit_graceful(tmp_path):
    script = tmp_path / "fake_rclone.py"
    script.write_text("import signal,sys,time\nsignal.signal(signal.SIGINT, lambda *a: sys.exit(1))\ntime.sleep(30)\n")
    res = ProcessRunner(grace_s=5).run([sys.executable, str(script)], dict(os.environ), timeout_s=0.5)
    assert res.timed_out and res.exit_code == 1
