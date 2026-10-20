"""One sync job end to end (SPEC §9.2): mount -> per-run rclone config -> rclone
with a worker-enforced wall-clock limit -> classify -> state update -> unmount and
shred, always in finally."""
from __future__ import annotations

import json
import logging
import os
import re
import signal
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from odnas import db as D
from odnas.bisync import (JobPaths, build_bisync, build_check, build_lsjson, build_touch_check_file, log_path)
from odnas.classify import (R_AUTH, R_CRITICAL, R_ERROR, R_NAS_AUTH, R_OK, R_RETRY, R_TIMEOUT, Outcome, Stats,
                            classify, parse_json_log)
from odnas.config import Config
from odnas.crypto import Keyring
from odnas.entra import AUTH_CA
from odnas.nas import V_AUTH_FAILED, V_OK, V_UNREACHABLE, NasAccessProvider
from odnas.notify import Alert, Alerter
from odnas.preflight import scan
from odnas.scheduler import ThrottleGovernor, next_backoff, next_slot
from odnas.tokens import TokenStrategy, write_private

log = logging.getLogger("odnas.runner")

KINDS = ("bisync", "dryrun", "resync", "check", "preflight")


@dataclass
class ProcResult:
    exit_code: int | None
    timed_out: bool
    stdout: str = ""


class ProcessRunner:
    """Runs rclone; on timeout sends SIGINT once (bisync graceful shutdown), waits `grace_s`, then SIGKILL."""

    def __init__(self, grace_s: float = 120.0):
        self.grace_s = grace_s

    def run(self, cmd: list[str], env: dict[str, str], timeout_s: float | None, capture: bool = False,
            stderr_path: str | None = None) -> ProcResult:
        err = open(stderr_path, "ab") if stderr_path else subprocess.DEVNULL
        try:
            p = subprocess.Popen(cmd, env=env, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE if capture else subprocess.DEVNULL, stderr=err,
                                 start_new_session=True)
            try:
                out, _ = p.communicate(timeout=timeout_s)
                return ProcResult(p.returncode, False, (out or b"").decode("utf-8", "replace"))
            except subprocess.TimeoutExpired:
                p.send_signal(signal.SIGINT)
                try:
                    out, _ = p.communicate(timeout=self.grace_s)
                except subprocess.TimeoutExpired:
                    os.killpg(p.pid, signal.SIGKILL)
                    out, _ = p.communicate()
                return ProcResult(p.returncode, True, (out or b"").decode("utf-8", "replace"))
        finally:
            if stderr_path:
                err.close()


def rclone_env() -> dict[str, str]:
    """Minimal env: no inherited secrets, no RCLONE_* surprises from the service environment."""
    return {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C.UTF-8",
            "RCLONE_CONFIG_PASS": "", "TZ": "UTC"}


class JobRunner:
    def __init__(self, cfg: Config, db: D.DB, kr: Keyring, strategy: TokenStrategy,
                 provider_factory: Callable[[], NasAccessProvider], settings_loader: Callable[[], object],
                 alerter: Alerter, proc: ProcessRunner | None = None, governor: ThrottleGovernor | None = None):
        self.cfg, self.db, self.kr, self.strategy = cfg, db, kr, strategy
        self.provider_factory, self.settings_loader = provider_factory, settings_loader
        self.alerter, self.proc = alerter, proc or ProcessRunner()
        self.governor = governor or ThrottleGovernor()

    # ------------------------------------------------------------------
    def run(self, uid: str, kind: str) -> Outcome:
        assert kind in KINDS
        s = self.settings_loader()
        u = self.db.user_full(uid)
        run_id = self.db.start_run(uid, kind, "")
        lp = log_path(self.cfg, uid, run_id)
        Path(lp).parent.mkdir(parents=True, exist_ok=True)
        self.db.q("UPDATE sync_runs SET log_path=? WHERE id=?", (lp, run_id))
        self.db.update_profile(uid, last_run_at=D.iso(D.utcnow()))
        provider = self.provider_factory()
        auth = None
        mounted = False
        stats = Stats()
        try:
            creds = self.db.nas_credential(self.kr, uid) if provider.per_user_credentials else None
            m = provider.mount(uid, u["local_name"], creds)
            if m.status == V_AUTH_FAILED:
                return self._finish(uid, kind, run_id, Outcome(R_NAS_AUTH, "NAS login failed (no retry)"), stats, s)
            if m.status == V_UNREACHABLE:
                return self._finish(uid, kind, run_id, Outcome(R_RETRY, "NAS unreachable"), stats, s, nas_down=True)
            if m.status != V_OK:
                return self._finish(uid, kind, run_id, Outcome(R_RETRY, "NAS mount error"), stats, s, nas_down=True)
            mounted = True
            auth = self.strategy.prepare(uid, run_id)
            jp = JobPaths(uid, run_id, str(auth.config_path), m.path, u["path2_subdir"])
            env = rclone_env()
            if kind == "preflight":
                return self._preflight(uid, run_id, jp, env, s)
            if kind == "dryrun":
                self._ensure_check_files(jp, env)
            max_del = u["max_delete_pct"] or s.default_max_delete_pct
            if kind == "check":
                cmd, limit = build_check(self.cfg, jp), None
            else:
                cmd = build_bisync(self.cfg, jp, max_delete_pct=max_del, resync=kind in ("resync", "dryrun"),
                                   dry_run=kind == "dryrun", bwlimit=s.resync_bwlimit)
                limit = s.run_time_limit_min * 60 if kind == "bisync" else None
            pr = self.proc.run(cmd, env, limit, stderr_path=lp + ".stderr")
            text = Path(lp).read_text(errors="replace") if Path(lp).exists() else ""
            stats = parse_json_log(text)
            broker_auth = self.strategy.finish(uid, auth)
            auth = None
            if kind == "check":
                oc = self._check_outcome(pr.exit_code, text)
            else:
                oc = classify(pr.exit_code, text, timed_out=pr.timed_out, broker_auth=broker_auth, stats=stats)
            return self._finish(uid, kind, run_id, oc, stats, s, exit_code=pr.exit_code)
        except Exception as e:  # never leave a run row open or secrets behind
            log.exception("job failed uid=%s kind=%s", uid, kind)
            return self._finish(uid, kind, run_id, Outcome(R_ERROR, f"internal error: {type(e).__name__}"), stats, s)
        finally:
            if auth is not None:
                try:
                    self.strategy.finish(uid, auth)
                except Exception:
                    log.exception("strategy cleanup failed")
            if mounted:
                try:
                    provider.unmount(uid)
                except Exception:
                    log.exception("unmount failed")

    # ------------------------------------------------------------------
    def _ensure_check_files(self, jp: JobPaths, env: dict[str, str]) -> None:
        local = Path(jp.path2()) / self.cfg.check_filename
        if not local.exists():
            local.write_text(f"{self.cfg.product_name} access check file. Do not delete.\n")
        self.proc.run(build_touch_check_file(self.cfg, f"od-{jp.uid}:", jp.config_path), env, 300)

    def _check_outcome(self, exit_code: int | None, text: str) -> Outcome:
        m = re.search(r"(\d+) differences found", text)
        n = int(m.group(1)) if m else (0 if exit_code == 0 else -1)
        if exit_code == 0:
            return Outcome(R_OK, "weekly check: 0 mismatches")
        if n > 0:
            return Outcome(R_ERROR, f"weekly check: {n} mismatches")
        return Outcome(R_RETRY, f"weekly check could not complete (exit {exit_code})")

    def _preflight(self, uid: str, run_id: int, jp: JobPaths, env: dict[str, str], s) -> Outcome:
        listings = {}
        for side, target in (("onedrive", f"od-{uid}:"), ("nas", jp.path2())):
            pr = self.proc.run(build_lsjson(self.cfg, target, jp.config_path), env, 3600, capture=True)
            if pr.exit_code != 0:
                return self._finish(uid, "preflight", run_id, Outcome(R_RETRY, f"listing {side} failed"), Stats(), s)
            listings[side] = json.loads(pr.stdout or "[]")
        rep = scan(listings)
        out = Path(self.cfg.p_state) / "preflight" / f"{uid}.json"
        write_private(out, json.dumps({"counts": rep.counts(), "total_bytes": rep.total_bytes,
                                       "findings": [f.__dict__ for f in rep.findings]}, indent=1))
        self.db.update_profile(uid, preflight_requested=0, preflight_at=D.iso(D.utcnow()),
                               preflight_summary=rep.summary())
        return self._finish(uid, "preflight", run_id, Outcome(R_OK, "preflight: " + rep.summary()), Stats(), s)

    # ------------------------------------------------------------------
    def _finish(self, uid: str, kind: str, run_id: int, oc: Outcome, st: Stats, s, exit_code: int | None = None,
                nas_down: bool = False) -> Outcome:
        apply_outcome(self.db, self.alerter, s, uid, kind, run_id, oc, st, exit_code, self.governor, nas_down)
        return oc


def _recipients(s) -> list[str]:
    return [x.strip() for x in (s.alert_recipients or "").split(",") if x.strip()]


def apply_outcome(db: D.DB, alerter: Alerter, s, uid: str, kind: str, run_id: int, oc: Outcome, st: Stats,
                  exit_code: int | None, governor: ThrottleGovernor, nas_down: bool = False) -> None:
    now = D.utcnow()
    db.finish_run(run_id, exit_code=exit_code, result=oc.result, detail=oc.detail[:500],
                  files_copied=st.files_copied, files_deleted=st.files_deleted, bytes=st.bytes,
                  conflicts=st.conflicts, errors_count=st.errors_count, throttled=int(st.throttled))
    u = db.user_full(uid)
    rec = _recipients(s)
    prof: dict = {"last_result": oc.result}
    upn = u["upn"]

    if st.throttled:
        governor.record(now)
    prof["backoff_factor"] = next_backoff(u["backoff_factor"], st.throttled)

    if oc.result == R_OK:
        prof.update(consecutive_failures=0, consecutive_timeouts=0)
        alerter.resolve(uid, "repeated_failures", "repeated_timeouts", "nas_unreachable", "stale")
        if kind in ("bisync", "resync"):
            prof["last_success_at"] = D.iso(now)
        if kind == "resync":
            prof.update(needs_resync=0, resync_approved_by=None, resync_approved_at=None)
            if u["state"] in (D.ONBOARDING, D.CRITICAL):
                db.set_state(uid, D.ACTIVE)
            alerter.resolve(uid, "critical")
            db.audit("system", "resync_completed", uid)
        if kind == "dryrun":
            prof.update(dryrun_ok_at=D.iso(now),
                        dryrun_summary=f"would copy {st.files_copied}, delete {st.files_deleted}, "
                                       f"{st.bytes} bytes, {st.conflicts} conflicts")
            alerter.raise_(Alert("approval_needed", "low", f"{upn}: dry-run ok, waiting for 'Approve initial sync'", uid),
                           rec)
        if kind == "check":
            prof["last_check_at"] = D.iso(now)
            alerter.resolve(uid, "check_mismatch")
    elif oc.result == R_RETRY:
        n = u["consecutive_failures"] + 1
        prof["consecutive_failures"] = n
        if nas_down:
            alerter.raise_(Alert("nas_unreachable", "medium", f"{upn}: NAS share could not be mounted", uid), rec)
        if n >= 3:
            alerter.raise_(Alert("repeated_failures", "medium", f"{upn}: {n} retryable failures in a row", uid), rec)
    elif oc.result == R_TIMEOUT:
        n = u["consecutive_timeouts"] + 1
        prof["consecutive_timeouts"] = n
        if n >= 3:
            alerter.raise_(Alert("repeated_timeouts", "medium", f"{upn}: hit run time limit {n} times in a row", uid),
                           rec)
    elif oc.result == R_CRITICAL:
        prof.update(needs_resync=1, resync_approved_by=None, resync_approved_at=None)
        if u["state"] != D.ONBOARDING:
            db.set_state(uid, D.CRITICAL, oc.detail[:200])
        alerter.raise_(Alert("critical", "critical", f"{upn}: {oc.detail}", uid), rec)
    elif oc.result == R_ERROR:
        if kind == "check":
            prof["last_check_at"] = D.iso(now)
            alerter.raise_(Alert("check_mismatch", "medium", f"{upn}: {oc.detail}", uid), rec)
        elif kind in ("dryrun", "preflight"):
            alerter.raise_(Alert(f"{kind}_failed", "medium", f"{upn}: {kind} failed: {oc.detail}", uid), rec)
        else:
            db.set_state(uid, D.PAUSED, oc.detail[:200])
            alerter.raise_(Alert("bug", "high", f"{upn}: {oc.detail}; user paused", uid), rec)
    elif oc.result == R_AUTH:
        if oc.auth == AUTH_CA:
            db.set_state(uid, D.BLOCKED_BY_CA, "Conditional Access blocked token refresh")
            alerter.raise_(Alert("blocked_by_ca", "high", f"{upn}: blocked by Conditional Access", uid), rec)
        else:
            db.set_state(uid, D.NEEDS_REAUTH, "Microsoft sign-in expired or revoked")
            alerter.raise_(Alert("needs_reauth", "medium", f"{upn}: needs to reconnect Microsoft", uid,
                                 notify_user=True), rec)
    elif oc.result == R_NAS_AUTH:
        db.set_state(uid, D.NAS_AUTH_FAILED, "NAS login failed; paused, no retries")
        db.q("UPDATE nas_credentials SET last_failure_at=?, failure_count=failure_count+1 WHERE user_id=?",
             (D.iso(now), uid))
        alerter.raise_(Alert("nas_auth_failed", "high", f"{upn}: NAS login failed; paused until re-entered", uid,
                             notify_user=True), rec)

    if st.unsyncable:
        prof["unsyncable_count"] = st.unsyncable
        alerter.raise_(Alert("unsyncable_files", "low", f"{upn}: {st.unsyncable} file(s) can't sync", uid), rec)
    interval = u["interval_min"] or s.default_interval_min
    prof["next_run_at"] = D.iso(next_slot(now, interval, u["slot_offset_min"], prof["backoff_factor"]))
    db.update_profile(uid, **prof)
    db.audit("system", f"run_{kind}", uid, {"run_id": run_id, "result": oc.result, "exit_code": exit_code})


def sweep_runtime(cfg: Config) -> int:
    """Delete stale per-run secrets at worker start (SPEC §7.5)."""
    from odnas.tokens import shred
    n = 0
    for sub in ("creds", "rclone"):
        d = Path(cfg.p_run) / sub
        if d.is_dir():
            for f in d.iterdir():
                if f.is_file():
                    shred(f)
                    n += 1
    return n
