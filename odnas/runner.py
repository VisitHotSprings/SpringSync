"""One sync job end to end (SPEC §9.2): mount -> per-run rclone config -> rclone
with a worker-enforced wall-clock limit -> classify -> state update -> unmount and
shred, always in finally."""
from __future__ import annotations

import json
from datetime import timedelta
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
from odnas.classify import (R_CRIT_RETRY, R_SAFETY, R_USAGE, delta_summary, parse_deltas)
from odnas.classify import (R_AUTH, R_CRITICAL, R_ERROR, R_NAS_AUTH, R_OK, R_RETRY, R_TIMEOUT, Outcome, Stats,
                            classify, parse_json_log)
from odnas.config import Config
from odnas.crypto import Keyring
from odnas.entra import AUTH_CA
from odnas.nas import V_AUTH_FAILED, V_OK, V_UNREACHABLE, NasAccessProvider
from odnas.notify import Alert, Alerter
from odnas.preflight import scan
from odnas import settings_store
from odnas.scheduler import ThrottleGovernor, next_backoff, next_slot, seconds_until_window_end
from odnas.tokens import TokenStrategy, write_private

log = logging.getLogger("odnas.runner")

KINDS = ("dryrun", "resync", "bisync", "check", "preflight", "delta", "force")   # SPEC v0.4 §5 order


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


def delete_counts(d: dict) -> tuple[int, int]:
    """(Path1, Path2) deletions detected in a delta list. rclone applies --max-delete per side, so the
    admin approves both numbers separately (SPEC v0.4)."""
    c = d.get("counts", {})
    return int(c.get("Path1", {}).get("deleted", 0)), int(c.get("Path2", {}).get("deleted", 0))


def delete_count(d: dict) -> int:
    return sum(delete_counts(d))


def accept_expired(u, now) -> bool:
    at = D.parse_iso(u["safety_action_at"])
    return u["safety_action"] == D.SAFETY_ACCEPT and at is not None and now - at >= timedelta(hours=D.ACCEPT_TTL_HOURS)


def expire_accept_approvals(db: D.DB, alerter: Alerter, s, now=None) -> list[str]:
    """SPEC v0.3 §9.4.1 step 2: an unused Accept-deletes approval expires after 24 h."""
    now = now or D.utcnow()
    out = []
    for u in db.users():
        if u["state"] == D.SAFETY_ABORT and accept_expired(u, now):
            by = u["safety_action_by"]
            db.update_profile(u["id"], safety_action=None, safety_action_by=None, safety_action_at=None,
                              safety_approved_deletes=None, safety_approved_del_p1=None, safety_approved_del_p2=None,
                              safety_accept_state=D.ACCEPT_EXPIRED,
                              safety_accept_state_at=D.iso(now))
            db.audit("system", "accept_deletes_expired", u["id"], {"approved_by": by, "ttl_hours": D.ACCEPT_TTL_HOURS})
            alerter.raise_(Alert("accept_deletes_expired", "medium",
                                 f"{u['upn']}: Accept-deletes approval expired unused; re-approval needed", u["id"]),
                           _recipients(s))
            out.append(u["id"])
    return out


def delta_file(cfg: Config, uid: str) -> Path:
    """Safety-abort delta list (contains filenames; 0600; admin page only)."""
    return Path(cfg.p_state) / "safety" / f"{uid}.json"


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
        restore = kind == "resync" and u["state"] == D.SAFETY_ABORT
        if kind == "force":
            if u["state"] != D.SAFETY_ABORT or u["safety_action"] != D.SAFETY_ACCEPT or not u["safety_action_by"] \
                    or u["safety_approved_del_p1"] is None or u["safety_approved_del_p2"] is None:
                raise RuntimeError("force run without a pending admin 'Accept deletes' approval")
            if accept_expired(u, D.utcnow()):
                raise RuntimeError("Accept-deletes approval has expired")
            approved = (u["safety_approved_del_p1"], u["safety_approved_del_p2"])
            approved_by = u["safety_action_by"]
        if restore and (u["safety_action"] != D.SAFETY_RESTORE or not u["resync_approved_by"]):
            raise RuntimeError("restore run without a pending admin 'Restore' approval")
        # For Accept deletes the first row is the pre-check dry-run (kind 'delta'); the 'force' row is only
        # created if the recount matches, so run history reads in order and a cancelled run has no force row.
        run_id = self.db.start_run(uid, "delta" if kind == "force" else kind, "")
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
                if getattr(provider, "option", "A") == "B":
                    # SPEC v0.6 §9.4: the shared svc-sync login was rejected -> server-wide pause, not a
                    # per-user failure (no user goes to nas_auth_failed), one high alert, no retries.
                    return self._finish(uid, kind, run_id,
                                        Outcome(R_NAS_AUTH, "svc-sync NAS login rejected: global NAS pause (no retry)"),
                                        stats, s, mounted=False, global_nas=True)
                return self._finish(uid, kind, run_id, Outcome(R_NAS_AUTH, "NAS login failed (no retry)"), stats, s,
                                    mounted=False)
            if m.status != V_OK:
                # SPEC v0.4: rclone never started. Approvals are NOT consumed (nothing ran) and the
                # consecutive-error chain is untouched; mount failures are counted separately.
                why = "NAS unreachable" if m.status == V_UNREACHABLE else "NAS mount error"
                return self._finish(uid, kind, run_id, Outcome(R_RETRY, why), stats, s, nas_down=True,
                                    mounted=False)
            mounted = True
            # Single-use approvals are consumed once the mount is up, right before rclone runs, so a
            # crash or timeout can never turn them into a repeated --force / --resync.
            if kind == "force":
                self.db.update_profile(uid, safety_action=None, safety_action_by=None, safety_action_at=None,
                                       safety_approved_deletes=None, safety_approved_del_p1=None,
                                       safety_approved_del_p2=None)
            if restore:
                self.db.update_profile(uid, safety_action=None, resync_approved_by=None, resync_approved_at=None)
            auth = self.strategy.prepare(uid, run_id)
            jp = JobPaths(uid, run_id, str(auth.config_path), m.path, u["path2_subdir"])
            env = rclone_env()
            if kind == "preflight":
                return self._preflight(uid, run_id, jp, env, s)
            if kind == "dryrun":
                self._ensure_check_files(jp, env)
            max_del = u["max_delete_pct"] or s.default_max_delete_pct
            if kind == "force":
                cancelled = self._accept_precheck(uid, run_id, jp, env, s, max_del, approved_by, approved)
                if cancelled is not None:
                    return cancelled
                run_id = self.db.start_run(uid, "force", "")
                lp = log_path(self.cfg, uid, run_id)
                self.db.q("UPDATE sync_runs SET log_path=? WHERE id=?", (lp, run_id))
                jp = JobPaths(uid, run_id, jp.config_path, jp.mount_path, jp.path2_subdir)
                self.db.audit("system", "accept_deletes_started", uid,
                              {"approved_by": approved_by, "approved_deletes_path1": approved[0],
                               "approved_deletes_path2": approved[1], "run_id": run_id})
            if kind == "check":
                cmd, limit = build_check(self.cfg, jp), None
            else:
                cmd = build_bisync(self.cfg, jp, max_delete_pct=max_del, resync=kind in ("resync", "dryrun"),
                                   dry_run=kind in ("dryrun", "delta"), bwlimit=s.resync_bwlimit,
                                   force=kind in ("delta", "force"))
                limit = self._limit(kind, u, s, restore)
                if restore:
                    self.db.audit("system", "safety_restore_started", uid,
                                  {"run_id": run_id, "when": u["safety_restore_when"], "limit_s": limit,
                                   "onboarding_resync": not u["onboarding_completed_at"],
                                   "approved_by": u["safety_action_by"],
                                   "auto_requeued": bool(u["safety_restore_requeued"])})
                    self.alerter.resolve(uid, "restore_deferred")   # no longer held
            pr = self.proc.run(cmd, env, limit, stderr_path=lp + ".stderr")
            text = Path(lp).read_text(errors="replace") if Path(lp).exists() else ""
            stats = parse_json_log(text)
            broker_auth = self.strategy.finish(uid, auth)
            auth = None
            if kind == "check":
                oc = self._check_outcome(pr.exit_code, text)
            else:
                oc = classify(pr.exit_code, text, timed_out=pr.timed_out, broker_auth=broker_auth, stats=stats)
                if oc.warning:
                    log.warning("classifier warning uid=%s run=%s exit=%s: %s", uid, run_id, pr.exit_code, oc.warning)
            if kind == "delta" and oc.result == R_OK:
                self._store_delta(uid, text)
            return self._finish(uid, kind, run_id, oc, stats, s, exit_code=pr.exit_code)
        except Exception as e:  # never leave a run row open or secrets behind
            log.exception("job failed uid=%s kind=%s", uid, kind)
            return self._finish(uid, kind, run_id, Outcome(R_ERROR, f"internal error: {type(e).__name__}"), stats, s,
                                mounted=mounted)
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

    def _limit(self, kind: str, u, s, restore: bool) -> int | None:
        """Worker wall-clock limit (seconds).
        - incremental, delta, Accept deletes (--force), next-slot Restore: run_time_limit_min (SPEC v0.3)
        - 'tonight' Restore (admin choice or the automatic re-queue): until resync_hours closes (SPEC v0.4)
        - initial / post-critical resync and the onboarding dry-run: unbounded"""
        normal = s.run_time_limit_min * 60
        if restore and not u["onboarding_completed_at"]:
            return None   # SPEC v0.5: Restore during onboarding = the onboarding --resync (no limit, §6.1)
        if restore and u["safety_restore_when"] == D.RESTORE_TONIGHT:
            left = seconds_until_window_end(D.utcnow(), settings_store.active_window_for(s.resync_hours))
            return left if left is not None else normal   # started outside the window: fail safe to normal
        if kind in ("bisync", "delta", "force") or restore:
            return normal
        return None

    # ------------------------------------------------------------------
    def _ensure_check_files(self, jp: JobPaths, env: dict[str, str]) -> None:
        local = Path(jp.path2()) / self.cfg.check_filename
        if not local.exists():
            local.write_text(f"{self.cfg.product_name} access check file. Do not delete.\n")
        self.proc.run(build_touch_check_file(self.cfg, f"od-{jp.uid}:", jp.config_path), env, 300)

    def delta_path(self, uid: str) -> Path:
        return delta_file(self.cfg, uid)

    def _store_delta(self, uid: str, text: str) -> dict:
        """Delta list (has filenames): 0600 file for the admin page; the DB keeps counts only."""
        d = parse_deltas(text)
        write_private(self.delta_path(uid), json.dumps(d, indent=1))
        self.db.update_profile(uid, safety_delta_requested=0, safety_delta_at=D.iso(D.utcnow()),
                               safety_delta_summary=delta_summary(d))
        return d

    def _accept_precheck(self, uid: str, run_id: int, jp: JobPaths, env: dict[str, str], s, max_del: int,
                         approved_by: str, approved: tuple[int, int]) -> Outcome | None:
        """SPEC v0.3/v0.4 §9.4.1 step 3: `--dry-run --force` with the same flags immediately before --force,
        recorded in the already-open `run_id` row (kind 'delta'). Both per-side delete counts must match the
        approved ones. Returns an Outcome if the run is cancelled, else None (go ahead)."""
        cmd = build_bisync(self.cfg, jp, max_delete_pct=max_del, dry_run=True, force=True)
        plp = log_path(self.cfg, uid, run_id)
        pr = self.proc.run(cmd, env, s.run_time_limit_min * 60, stderr_path=plp + ".stderr")
        text = Path(plp).read_text(errors="replace") if Path(plp).exists() else ""
        oc = classify(pr.exit_code, text, timed_out=pr.timed_out)
        now_counts = None
        if oc.result == R_OK:
            now_counts = delete_counts(self._store_delta(uid, text))
        ok = now_counts == tuple(approved)
        self.db.finish_run(run_id, exit_code=pr.exit_code, result=oc.result if ok else "cancelled",
                           detail=(f"accept-deletes pre-check: deletes Path1={now_counts[0]} Path2={now_counts[1]}"
                                   if now_counts else f"accept-deletes pre-check failed ({oc.result})")
                           + ("" if ok else "; --force not run"))
        self.db.audit("system", "accept_deletes_precheck", uid,
                      {"run_id": run_id, "result": oc.result,
                       "deletes_path1": now_counts[0] if now_counts else None,
                       "deletes_path2": now_counts[1] if now_counts else None,
                       "approved_deletes_path1": approved[0], "approved_deletes_path2": approved[1]})
        if ok:
            return None
        state = D.ACCEPT_CANCELLED if now_counts is not None else D.ACCEPT_PRECHECK_FAILED
        why = (f"delete counts changed (approved Path1={approved[0]} Path2={approved[1]}, "
               f"now Path1={now_counts[0]} Path2={now_counts[1]})" if now_counts is not None
               else f"pre-check dry-run failed ({oc.result})")
        self.db.update_profile(uid, safety_accept_state=state, safety_accept_state_at=D.iso(D.utcnow()))
        self.db.audit("system", "accept_deletes_cancelled", uid,
                      {"reason": state, "approved_deletes_path1": approved[0], "approved_deletes_path2": approved[1],
                       "deletes_now_path1": now_counts[0] if now_counts else None,
                       "deletes_now_path2": now_counts[1] if now_counts else None, "approved_by": approved_by})
        u = self.db.user_full(uid)
        self.alerter.raise_(Alert("accept_deletes_cancelled", "high",
                                  f"{u['upn']}: Accept deletes cancelled: {why}; re-approval needed", uid),
                            _recipients(s))
        return Outcome("cancelled", why)

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
        quota = None
        pa = self.proc.run([self.cfg.rclone_bin, "about", f"od-{uid}:", "--json", "--config", jp.config_path,
                            "--user-agent", self.cfg.user_agent], env, 300, capture=True)
        try:
            about = json.loads(pa.stdout or "{}")
            quota = int(about["free"]) if isinstance(about, dict) and "free" in about else None
        except (ValueError, TypeError):
            quota = None
        rep = scan(listings, quota_remaining=quota)
        out = Path(self.cfg.p_state) / "preflight" / f"{uid}.json"
        write_private(out, json.dumps({"counts": rep.counts(), "total_bytes": rep.total_bytes,
                                       "findings": [f.__dict__ for f in rep.findings]}, indent=1))
        self.db.update_profile(uid, preflight_requested=0, preflight_at=D.iso(D.utcnow()),
                               preflight_summary=rep.summary())
        return self._finish(uid, "preflight", run_id, Outcome(R_OK, "preflight: " + rep.summary()), Stats(), s)

    # ------------------------------------------------------------------
    def _finish(self, uid: str, kind: str, run_id: int, oc: Outcome, st: Stats, s, exit_code: int | None = None,
                nas_down: bool = False, mounted: bool = True, global_nas: bool = False) -> Outcome:
        apply_outcome(self.db, self.alerter, s, uid, kind, run_id, oc, st, exit_code, self.governor, nas_down,
                      mounted=mounted, global_nas=global_nas)
        return oc


def _recipients(s) -> list[str]:
    return [x.strip() for x in (s.alert_recipients or "").split(",") if x.strip()]


def apply_outcome(db: D.DB, alerter: Alerter, s, uid: str, kind: str, run_id: int, oc: Outcome, st: Stats,
                  exit_code: int | None, governor: ThrottleGovernor, nas_down: bool = False,
                  mounted: bool = True, global_nas: bool = False) -> None:
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

    restore = kind == "resync" and u["state"] == D.SAFETY_ABORT
    rclone_started = mounted and not nas_down and oc.result != R_NAS_AUTH
    # SPEC v0.4: a mount failure (rclone never started) is skipped by the same-error chain (neither counts
    # nor resets it) and is counted separately; any run where rclone starts resets that counter.
    if rclone_started and oc.result != R_CRIT_RETRY:   # any other rclone result breaks the chain
        prof.update(consecutive_crit_retry=0, last_crit_error=None)
    if mounted:
        # SPEC v0.5: ONLY a successful mount resets the mount-failure counter. nas_auth (wrong password)
        # neither counts nor resets it; an internal error after a good mount does reset it.
        prof["consecutive_mount_failures"] = 0
        alerter.resolve(uid, "nas_unreachable")
    if oc.result == R_OK:
        prof.update(consecutive_failures=0, consecutive_timeouts=0)
        alerter.resolve(uid, "repeated_failures", "repeated_timeouts", "nas_unreachable", "stale")
        if kind in ("bisync", "resync"):
            prof["last_success_at"] = D.iso(now)
        if kind == "bisync" and not u["onboarding_completed_at"]:
            prof["onboarding_completed_at"] = D.iso(now)       # SPEC v0.5 §6.1 step 8
            db.audit("system", "onboarding_completed", uid, {"run_id": run_id})
        if kind == "resync":
            prof.update(needs_resync=0, resync_approved_by=None, resync_approved_at=None)
            if u["state"] == D.SAFETY_ABORT:
                prof.update(**_SAFETY_CLEAR)
                db.audit("system", "safety_restore_completed", uid,
                         {"run_id": run_id, "result": oc.result, "copied": st.files_copied, "bytes": st.bytes,
                          "onboarding_resync": not u["onboarding_completed_at"]})
                alerter.resolve(uid, "safety_abort")
            if u["state"] in (D.ONBOARDING, D.CRITICAL, D.SAFETY_ABORT):
                db.set_state(uid, D.ACTIVE)
            alerter.resolve(uid, "critical")
            db.audit("system", "resync_completed", uid)
        if kind == "force":
            prof.update(**_SAFETY_CLEAR)
            if u["state"] == D.SAFETY_ABORT:
                db.set_state(uid, D.ACTIVE)
            alerter.resolve(uid, "safety_abort")
            db.audit("system", "accept_deletes_completed", uid,
                     {"run_id": run_id, "result": oc.result, "deleted": st.files_deleted, "copied": st.files_copied})
        if kind == "dryrun":
            prof.update(dryrun_ok_at=D.iso(now),
                        dryrun_summary=f"would copy {st.files_copied}, delete {st.files_deleted}, "
                                       f"{st.bytes} bytes, {st.conflicts} conflicts")
            alerter.raise_(Alert("approval_needed", "low", f"{upn}: dry-run ok, waiting for 'Approve initial sync'", uid),
                           rec)
        if kind == "check":
            prof["last_check_at"] = D.iso(now)
            alerter.resolve(uid, "check_mismatch")
    elif oc.result == R_RETRY and nas_down:
        n = u["consecutive_mount_failures"] + 1
        prof["consecutive_mount_failures"] = n
        if n >= 2:   # SPEC v0.4: alert after 2 in a row; no lockout, keeps trying at each slot
            alerter.raise_(Alert("nas_unreachable", "medium",
                                 f"{upn}: NAS share could not be mounted {n} times in a row (rclone not started)",
                                 uid), rec)
    elif oc.result == R_RETRY:
        n = u["consecutive_failures"] + 1
        prof["consecutive_failures"] = n
        if n >= 3:
            alerter.raise_(Alert("repeated_failures", "medium", f"{upn}: {n} retryable failures in a row", uid), rec)
    elif oc.result == R_TIMEOUT:
        n = u["consecutive_timeouts"] + 1
        prof["consecutive_timeouts"] = n
        if n >= 3:
            alerter.raise_(Alert("repeated_timeouts", "medium", f"{upn}: hit run time limit {n} times in a row", uid),
                           rec)
    elif oc.result == R_SAFETY:
        sa = oc.safety
        prof.update(**_SAFETY_CLEAR)
        onboarding = not u["onboarding_completed_at"]
        # SPEC v0.5 §6.1 step 8: same as any safety abort; onboarding stays incomplete. On the onboarding
        # dry-run there are no bisync listings yet, so no `--dry-run --force` delta list can be built and
        # nothing exists to "accept": the only action is Restore (= re-run the onboarding --resync).
        no_delta = kind == "dryrun"
        rec_ = dict(sa.as_dict() if sa else {}, during=kind, onboarding=onboarding)
        prof.update(safety_abort_at=D.iso(now), safety_abort_json=json.dumps(rec_),
                    safety_delta_requested=0 if no_delta else 1)
        if onboarding:
            db.audit("system", "onboarding_safety_abort", uid, {"run_id": run_id, "during": kind})
        db.set_state(uid, D.SAFETY_ABORT, oc.detail[:200])
        alerter.raise_(Alert("safety_abort", "critical",
                             f"{upn}: {sa.summary() if sa else 'safety abort'}; paused. Admin: Restore or Accept deletes",
                             uid), rec)
    elif oc.result == R_CRIT_RETRY:
        # SPEC v0.3 §9.4: retry, but lock out (pause + admin alert, never an automatic --resync)
        #   - immediately if the check-access test failed (likely a bad or empty mount),
        #   - when the same normalised error repeats on 2 consecutive runs,
        #   - on the 3rd retryable result in a row (upper bound).
        n = u["consecutive_crit_retry"] + 1
        same = n >= 2 and bool(oc.crit_error) and oc.crit_error == u["last_crit_error"]
        if oc.access_failed:
            _critical(db, alerter, rec, u, uid, prof,
                      f"check-access test failed (likely a bad or empty NAS mount): {oc.detail}", escalated="access")
        elif same:
            _critical(db, alerter, rec, u, uid, prof, f"same retryable error on 2 consecutive runs: {oc.detail}",
                      escalated="same_error")
        elif n >= 3:
            _critical(db, alerter, rec, u, uid, prof, f"{n} retryable critical aborts in a row: {oc.detail}",
                      escalated="three_in_a_row")
        else:
            prof.update(consecutive_crit_retry=n, last_crit_error=oc.crit_error or None)
    elif oc.result == R_CRITICAL:
        _critical(db, alerter, rec, u, uid, prof, oc.detail)
    elif oc.result == R_USAGE:
        db.set_state(uid, D.PAUSED, oc.detail[:200])
        alerter.raise_(Alert("bug", "high", f"{upn}: {oc.detail}", uid), rec)
    elif oc.result == R_ERROR:
        if kind == "check":
            prof["last_check_at"] = D.iso(now)
            alerter.raise_(Alert("check_mismatch", "medium", f"{upn}: {oc.detail}", uid), rec)
        elif kind in ("dryrun", "preflight", "delta"):
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
    elif oc.result == R_NAS_AUTH and global_nas:
        set_nas_global_pause(db, alerter, rec, uid, run_id)
    elif oc.result == R_NAS_AUTH:
        db.set_state(uid, D.NAS_AUTH_FAILED, "NAS login failed; paused, no retries")
        db.q("UPDATE nas_credentials SET last_failure_at=?, failure_count=failure_count+1 WHERE user_id=?",
             (D.iso(now), uid))
        alerter.raise_(Alert("nas_auth_failed", "high", f"{upn}: NAS login failed; paused until re-entered", uid,
                             notify_user=True), rec)

    if kind == "force" and oc.result != R_OK and rclone_started:
        # SPEC v0.3 §9.4.1 step 4/5: user stays paused for review; --force is never re-applied automatically
        state = D.ACCEPT_TIMEOUT if oc.result == R_TIMEOUT else D.ACCEPT_FAILED
        prof.update(safety_accept_state=state, safety_accept_state_at=D.iso(now))
        db.audit("system", "accept_deletes_timeout" if state == D.ACCEPT_TIMEOUT else "accept_deletes_failed", uid,
                 {"run_id": run_id, "result": oc.result, "exit_code": exit_code, "deleted": st.files_deleted})
        alerter.raise_(Alert("accept_deletes_failed", "high",
                             f"{upn}: Accept-deletes run {'hit the run-time limit' if state == D.ACCEPT_TIMEOUT else 'failed'}"
                             f" ({oc.result}); user stays paused, a new approval is needed", uid), rec)
    if restore and oc.result != R_OK and rclone_started:
        tonight = u["safety_restore_when"] == D.RESTORE_TONIGHT or not u["onboarding_completed_at"]
        prof["restore_timeouts"] = u["restore_timeouts"] + (oc.result == R_TIMEOUT)
        if oc.result == R_TIMEOUT and not tonight and not u["safety_restore_requeued"]:
            # SPEC v0.4 §9.4.1: a next-slot Restore that hits the 25-min limit is re-queued ONCE as a tonight
            # run without a new approval (--resync --resync-mode newer only copies, never deletes).
            prof.update(safety_action=D.SAFETY_RESTORE, safety_restore_when=D.RESTORE_TONIGHT,
                        safety_restore_requeued=1, needs_resync=1, resync_approved_by=u["safety_action_by"],
                        resync_approved_at=D.iso(now))
            db.audit("system", "safety_restore_requeued_tonight", uid,
                     {"run_id": run_id, "approved_by": u["safety_action_by"], "copied": st.files_copied,
                      "window": s.resync_hours})
            alerter.raise_(Alert("restore_requeued", "medium",
                                 f"{upn}: Restore hit the run-time limit; re-queued once for tonight ({s.resync_hours})",
                                 uid), rec)
        else:
            if prof.get("needs_resync") != 1:      # a lockout during the restore keeps needs_resync set
                prof["needs_resync"] = 0
            if oc.result == R_TIMEOUT and tonight:
                msg, action = "was still running when the night window closed and was stopped", "safety_restore_window_closed"
            elif oc.result == R_TIMEOUT:
                msg, action = "hit the run-time limit", "safety_restore_timeout"
            else:
                msg, action = "failed", "safety_restore_failed"
            db.audit("system", action, uid, {"run_id": run_id, "result": oc.result, "exit_code": exit_code,
                                             "copied": st.files_copied, "when": u["safety_restore_when"]})
            alerter.raise_(Alert("restore_failed", "high",
                                 f"{upn}: Restore {msg} ({oc.result}); user stays paused, click Restore again to continue",
                                 uid), rec)

    if st.unsyncable:
        prof["unsyncable_count"] = st.unsyncable
        alerter.raise_(Alert("unsyncable_files", "low", f"{upn}: {st.unsyncable} file(s) can't sync", uid), rec)
    interval = u["interval_min"] or s.default_interval_min
    prof["next_run_at"] = D.iso(next_slot(now, interval, u["slot_offset_min"], prof["backoff_factor"]))
    db.update_profile(uid, **prof)
    db.audit("system", f"run_{kind}", uid, {"run_id": run_id, "result": oc.result, "exit_code": exit_code})


def set_nas_global_pause(db: D.DB, alerter: Alerter, rec: list[str], uid: str | None, run_id: int | None) -> bool:
    """SPEC v0.6: one server-wide NAS pause for a rejected Option B svc-sync login. Idempotent: concurrent
    runs that hit the same rejection add no second alert or audit entry."""
    new = db.set_flag(D.NAS_GLOBAL_PAUSE, "svc-sync NAS login rejected",
                      pw_version=db.setting_version("nas_svc_password"), first_user=uid, run_id=run_id)
    if new:
        db.audit("system", "nas_global_pause_set", uid or "",
                 {"reason": "svc_sync_login_rejected", "run_id": run_id})
        alerter.raise_(Alert("nas_global_pause", "high",
                             "NAS svc-sync login rejected: all NAS syncs paused (no retries). "
                             "Update the svc-sync password in Settings; a test mount then resumes syncing.", None),
                       rec)
    return new


_SAFETY_CLEAR = dict(safety_abort_at=None, safety_abort_json=None, safety_delta_requested=0, safety_delta_at=None,
                     safety_delta_summary=None, safety_action=None, safety_action_by=None, safety_action_at=None,
                     safety_restore_when=None, safety_approved_deletes=None, safety_accept_state=None,
                     safety_accept_state_at=None, restore_timeouts=0, safety_approved_del_p1=None,
                     safety_approved_del_p2=None, safety_restore_requeued=0, tonight_hold_nights=0,
                     tonight_held_at=None)


def _critical(db: D.DB, alerter: Alerter, rec: list[str], u, uid: str, prof: dict, detail: str,
              escalated: str = "") -> None:
    prof.update(needs_resync=1, resync_approved_by=None, resync_approved_at=None, consecutive_crit_retry=0,
                last_crit_error=None)
    if u["state"] != D.ONBOARDING:
        db.set_state(uid, D.CRITICAL, detail[:200])
    if escalated:
        db.audit("system", "critical_retryable_escalated", uid, {"reason": escalated})
    alerter.raise_(Alert("critical", "critical", f"{u['upn']}: {detail}", uid), rec)


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
