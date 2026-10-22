"""One sync job end to end (SPEC §9.2): mount -> per-run rclone config -> rclone
with a worker-enforced wall-clock limit -> classify -> state update -> unmount and
shred, always in finally."""
from __future__ import annotations

import json
from datetime import timedelta
import logging
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from odnas import db as D
from odnas.bisync import (JobPaths, build_bisync, build_check, build_lsf_root, build_lsjson, build_touch_check_file,
                          log_path)
from odnas.classify import (R_CRIT_RETRY, R_SAFETY, R_USAGE, SafetyAbort, delta_summary, iter_log, parse_deltas)
from odnas.classify import (R_AUTH, R_CRITICAL, R_ERROR, R_NAS_AUTH, R_OK, R_RETRY, R_TIMEOUT, Outcome, Stats,
                            classify, parse_json_log)
from odnas.config import Config
from odnas.crypto import Keyring
from odnas.entra import AUTH_CA
from odnas.google import AUTH_APP
from odnas.nas import V_AUTH_FAILED, V_OK, V_UNREACHABLE, BackupTarget, NasAccessProvider
from odnas.notify import Alert, Alerter
from odnas.preflight import scan
from odnas import cloud, pull, service_mode, settings_store
from odnas.scheduler import ThrottleGovernor, next_backoff, next_slot, seconds_until_window_end
from odnas.tokens import TokenStrategy, shred, write_private

log = logging.getLogger("odnas.runner")

KINDS = ("dryrun", "resync", "bisync", "check", "preflight", "delta", "force")   # SPEC v0.4 §5 order


@dataclass
class ProcResult:
    exit_code: int | None
    timed_out: bool
    stdout: str = ""


class ProcessRunner:
    """Runs rclone with a worker-enforced wall-clock limit.
    Linux: own session; on timeout SIGINT once (bisync graceful shutdown), wait `grace_s`, then SIGKILL the group.
    Windows (v0.10, SPEC §11.5.6): own process group + Job Object (kill-on-close); on timeout CTRL_BREAK_EVENT
    once, wait `grace_s`, then TerminateJobObject (fallback taskkill /T /F). [T-W3: untested on real Windows.]
    `stop_all()` sends the polite stop to every running rclone (Windows service stop / pre-shutdown drain;
    on Linux systemd's KillMode=mixed does this)."""

    def __init__(self, grace_s: float = 120.0, host: str | None = None, _popen=subprocess.Popen, _job=None):
        from odnas.hostos import current_os
        self.grace_s, self.host = grace_s, host or current_os()
        self._popen, self._job_factory = _popen, _job
        import threading
        self._live: dict[int, object] = {}
        self._lk = threading.Lock()

    def _new_job(self):
        if self._job_factory is not None:
            return self._job_factory()
        from odnas.hostos import WinJob
        return WinJob()

    def stop_all(self) -> int:
        from odnas.hostos import graceful_stop
        with self._lk:
            procs = list(self._live.values())
        for p in procs:
            try:
                graceful_stop(p, self.host)
            except Exception:
                log.exception("graceful stop failed")
        return len(procs)

    def kill_all(self) -> int:
        from odnas.hostos import hard_kill
        with self._lk:
            procs = list(self._live.values())
        for p in procs:
            try:
                if p.poll() is None:
                    hard_kill(p, self.host, getattr(p, "_odnas_job", None))
            except Exception:
                log.exception("hard kill failed")
        return len(procs)

    def run(self, cmd: list[str], env: dict[str, str], timeout_s: float | None, capture: bool = False,
            stderr_path: str | None = None) -> ProcResult:
        from odnas.hostos import WINDOWS, graceful_stop, hard_kill, popen_kwargs
        err = open(stderr_path, "ab") if stderr_path else subprocess.DEVNULL
        job = None
        try:
            if self.host == WINDOWS:
                env = {**env, "SystemRoot": os.environ.get("SystemRoot", r"C:\Windows")}  # Go needs it on Windows
            p = self._popen(cmd, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE if capture else subprocess.DEVNULL, stderr=err,
                            **popen_kwargs(self.host))
            if self.host == WINDOWS:
                job = self._new_job()
                if not job.assign(p):
                    log.warning("rclone not in a job object; timeout kill falls back to taskkill /T")
                try:
                    p._odnas_job = job
                except AttributeError:
                    pass
            with self._lk:
                self._live[p.pid] = p
            try:
                out, _ = p.communicate(timeout=timeout_s)
                return ProcResult(p.returncode, False, (out or b"").decode("utf-8", "replace"))
            except subprocess.TimeoutExpired:
                graceful_stop(p, self.host)
                try:
                    out, _ = p.communicate(timeout=self.grace_s)
                except subprocess.TimeoutExpired:
                    hard_kill(p, self.host, job)
                    out, _ = p.communicate()
                return ProcResult(p.returncode, True, (out or b"").decode("utf-8", "replace"))
            finally:
                with self._lk:
                    self._live.pop(p.pid, None)
        finally:
            if job is not None:
                job.close()
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


def resync_preview(text: str) -> tuple[int, int]:
    """(uploads to the cloud, downloads to the NAS) from a `bisync --resync --dry-run` JSON log (v0.9 §6.6:
    the switch-back preview shows how many files will be UPLOADED). bisync logs "- Path2 ... Resync is
    copying files to ... - Path1" before the Path2 -> Path1 copies, then the Path1 -> Path2 marker."""
    up = down = 0
    cur = None
    for e in iter_log(text):
        m = e.msg
        if "Resync is copying" in m:
            cur = "up" if m.strip().startswith("- Path2") else "down"
        elif m.startswith("Skipped copy") and cur:
            if cur == "up":
                up += 1
            else:
                down += 1
    return up, down


GOOGLE_APP_FLAG = "google_app_credential"   # worker_state: invalid_client -> no Google runs until fixed


def rclone_env() -> dict[str, str]:
    """Minimal env: no inherited secrets, no RCLONE_* surprises from the service environment."""
    return {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C.UTF-8",
            "RCLONE_CONFIG_PASS": "", "TZ": "UTC"}


class JobRunner:
    def __init__(self, cfg: Config, db: D.DB, kr: Keyring, strategy: TokenStrategy,
                 provider_factory: Callable[[], NasAccessProvider], settings_loader: Callable[[], object],
                 alerter: Alerter, proc: ProcessRunner | None = None, governor: ThrottleGovernor | None = None,
                 backup: BackupTarget | None = None):
        self.cfg, self.db, self.kr, self.strategy = cfg, db, kr, strategy
        self.provider_factory, self.settings_loader = provider_factory, settings_loader
        self.alerter, self.proc = alerter, proc or ProcessRunner(host=cfg.host)
        self.governor = governor or ThrottleGovernor()
        self.backup = backup or BackupTarget(cfg)

    # ------------------------------------------------------------------
    def run(self, uid: str, kind: str) -> Outcome:
        assert kind in KINDS
        s = self.settings_loader()
        u = self.db.user_full(uid)
        restore = kind == "resync" and u["state"] == D.SAFETY_ABORT
        direction, prov = cloud.direction(u), cloud.provider(u)
        pull_run = cloud.is_pull(u)
        # v0.9 §6.6: the Mirror baseline uses the delta (count) and force (approved run) kinds while ACTIVE
        baseline = pull_run and u["state"] == D.ACTIVE and cloud.baseline_needed(u) and kind in ("delta", "force")
        approved, approved_by = (0, 0), ""
        if kind == "force" and baseline:
            if not cloud.baseline_approved(u, D.utcnow()):
                raise RuntimeError("Mirror baseline run without a valid admin approval")
            approved, approved_by = (0, int(u["mirror_baseline_approved_count"])), u["mirror_baseline_approved_by"]
        elif kind == "force":
            if u["state"] != D.SAFETY_ABORT or u["safety_action"] != D.SAFETY_ACCEPT or not u["safety_action_by"] \
                    or u["safety_approved_del_p1"] is None or u["safety_approved_del_p2"] is None:
                raise RuntimeError("force run without a pending admin 'Accept deletes' approval")
            if accept_expired(u, D.utcnow()):
                raise RuntimeError("Accept-deletes approval has expired")
            approved = (u["safety_approved_del_p1"], u["safety_approved_del_p2"])
            approved_by = u["safety_action_by"]
        if restore and (u["safety_action"] != D.SAFETY_RESTORE or not u["resync_approved_by"]):
            raise RuntimeError("restore run without a pending admin 'Restore' approval")
        if pull_run and restore:
            raise RuntimeError("one-way users have no Restore (the cloud is never written); see SPEC §9.7.2")
        # For Accept deletes the first row is the pre-check dry-run (kind 'delta'); the 'force' row is only
        # created if the recount matches, so run history reads in order and a cancelled run has no force row.
        run_id = self.db.start_run(uid, "delta" if kind == "force" else kind, "")
        lp = log_path(self.cfg, uid, run_id)
        Path(lp).parent.mkdir(parents=True, exist_ok=True)
        self.db.q("UPDATE sync_runs SET log_path=?, direction=?, provider=?, op=? WHERE id=?",
                  (lp, direction, prov, _op_name(kind, pull_run), run_id))
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
            auth = self.strategy.prepare(uid, run_id, export_formats=cloud.export_formats(u, s))
            jp = JobPaths(uid, run_id, str(auth.config_path), m.path, u["path2_subdir"], prov)
            env = rclone_env()
            if kind == "preflight":
                return self._preflight(uid, run_id, jp, env, s, u)
            if pull_run and kind != "check":
                a, auth = auth, None      # _pull finishes the token strategy itself (several rclone runs)
                return self._pull(uid, kind, run_id, u, jp, env, s, a, lp, baseline=baseline,
                                  approved=approved, approved_by=approved_by)
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
                jp = JobPaths(uid, run_id, jp.config_path, jp.mount_path, jp.path2_subdir, prov)
                self.db.q("UPDATE sync_runs SET direction=?, provider=?, op='bisync' WHERE id=?",
                          (direction, prov, run_id))
                self.db.audit("system", "accept_deletes_started", uid,
                              {"approved_by": approved_by, "approved_deletes_path1": approved[0],
                               "approved_deletes_path2": approved[1], "run_id": run_id})
            if kind == "check" and pull_run:
                cmd = pull.build_check_one_way(self.cfg, jp, lp, skip_gdocs_flag=cloud.export_formats(u, s) is not None)
                limit = None
            elif kind == "check":
                cmd, limit = build_check(self.cfg, jp), None
            else:
                # Service mode: incremental runs only, window re-checked here at run start
                sm = service_mode.active_scope(self.db, u) if kind == "bisync" else None
                if sm:
                    self.db.q("UPDATE sync_runs SET service_mode=? WHERE id=?", (sm, run_id))
                cmd = build_bisync(self.cfg, jp, max_delete_pct=max_del, resync=kind in ("resync", "dryrun"),
                                   dry_run=kind in ("dryrun", "delta"), bwlimit=s.resync_bwlimit,
                                   force=kind in ("delta", "force"), service_mode=bool(sm))
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
                oc = classify(pr.exit_code, text, timed_out=pr.timed_out, broker_auth=broker_auth, stats=stats,
                              provider=prov)
                if oc.warning:
                    log.warning("classifier warning uid=%s run=%s exit=%s: %s", uid, run_id, pr.exit_code, oc.warning)
                if prov == cloud.PROVIDER_GD and oc.result != R_OK and pull.upload_limit_hit(text):
                    # SPEC v0.9 §4.3: the 750 GB/day Workspace upload stop: retryable the next day, low alert
                    oc = Outcome(R_RETRY, "Google 750 GB/day upload limit reached; retried the next day")
                    self.alerter.raise_(Alert("google_upload_limit", "low",
                                              f"{u['upn']}: Google 750 GB/day upload limit reached", uid),
                                        _recipients(s))
            if kind == "delta" and oc.result == R_OK:
                self._store_delta(uid, text)
            if kind == "dryrun" and oc.result == R_OK:
                up, down = resync_preview(text)
                res = self._finish(uid, kind, run_id, oc, stats, s, exit_code=pr.exit_code)
                self.db.update_profile(uid, dryrun_summary=(
                    f"resync would upload {up} file(s) to {cloud.CLOUD_SIDE[prov]} and copy {down} to the NAS "
                    f"({stats.bytes} bytes); nothing is deleted")[:300])
                return res
            if kind == "bisync":
                # per-side deletions detected in this run (counts only), for the service-mode summary
                p1, p2 = delete_counts(parse_deltas(text))
                self.db.q("UPDATE sync_runs SET deletes_path1=?, deletes_path2=? WHERE id=?", (p1, p2, run_id))
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
        self.proc.run(build_touch_check_file(self.cfg, f"{jp.remote}:", jp.config_path), env, 300)

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
        return self._accept_result(uid, run_id, pr.exit_code, oc, now_counts, approved_by, approved, s)

    def _accept_result(self, uid: str, run_id: int, exit_code: int | None, oc: Outcome, now_counts,
                       approved_by: str, approved: tuple[int, int], s) -> Outcome | None:
        """Both modes: the recount must equal the approved per-side counts, else the run is cancelled."""
        pr = ProcResult(exit_code, False)
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

    def _preflight(self, uid: str, run_id: int, jp: JobPaths, env: dict[str, str], s, u) -> Outcome:
        listings = {}
        prov = cloud.provider(u)
        cloud_key = "google_drive" if prov == cloud.PROVIDER_GD else "onedrive"
        for side, target in ((cloud_key, f"{jp.remote}:"), ("nas", jp.path2())):
            cmd = build_lsjson(self.cfg, target, jp.config_path)
            if side == "google_drive":
                cmd += ["--drive-skip-gdocs=false"]   # Google-native files show with size -1 (counted only)
            pr = self.proc.run(cmd, env, 3600, capture=True)
            if pr.exit_code != 0:
                return self._finish(uid, "preflight", run_id, Outcome(R_RETRY, f"listing {side} failed"), Stats(), s)
            listings[side] = json.loads(pr.stdout or "[]")
        quota = None
        if prov == cloud.PROVIDER_OD:
            pa = self.proc.run([self.cfg.p_rclone, "about", f"{jp.remote}:", "--json", "--config", jp.config_path,
                                "--user-agent", self.cfg.user_agent], env, 300, capture=True)
            try:
                about = json.loads(pa.stdout or "{}")
                quota = int(about["free"]) if isinstance(about, dict) and "free" in about else None
            except (ValueError, TypeError):
                quota = None
        unc = "\\\\" + s.nas_host + "\\" + (s.nas_share if s.nas_option == "A" else
                                            s.nas_shared_template.replace("{user}", u["local_name"])) + "\\"
        if u["path2_subdir"]:
            unc += u["path2_subdir"].strip("/").replace("/", "\\") + "\\"
        rep = scan(listings, quota_remaining=quota, provider=prov, one_way=cloud.is_pull(u), unc_prefix=unc,
                   ignore=(self.cfg.check_filename, self.cfg.archive_dirname))
        out = Path(self.cfg.p_state) / "preflight" / f"{uid}.json"
        write_private(out, json.dumps({"counts": rep.counts(), "total_bytes": rep.total_bytes,
                                       "nas_only": rep.nas_only, "gdocs": rep.gdocs,
                                       "findings": [f.__dict__ for f in rep.findings]}, indent=1))
        self.db.update_profile(uid, preflight_requested=0, preflight_at=D.iso(D.utcnow()),
                               preflight_summary=rep.summary())
        return self._finish(uid, "preflight", run_id, Outcome(R_OK, "preflight: " + rep.summary()), Stats(), s)

    # ------------------------------------------------------------------
    def _pull(self, uid: str, kind: str, run_id: int, u, jp: JobPaths, env: dict[str, str], s, auth, lp: str,
              baseline: bool = False, approved: tuple[int, int] = (0, 0), approved_by: str = "") -> Outcome:
        """One-way pull run (SPEC v0.9 §9.7, odnas/pull.py). kinds keep their lifecycle meaning:
        dryrun  = onboarding pre-check: create the check files on BOTH roots, then the counting dry-run;
        resync  = the approved first pull (Copy; for a Mirror user in onboarding the approved Mirror baseline)
                  or the approved run after a critical stop (Copy);
        bisync  = the scheduled incremental run (Copy, or Mirror with the counting dry-run first);
        delta   = counting dry-run only (safety-abort delta list, or the Mirror baseline count);
        force   = one admin-approved Mirror run with an exact count (Accept deletes, or the Mirror baseline).
        Guards before every run except dryrun: check files on both roots (missing -> critical), then the
        backup target reachable and writable (else the run is skipped with a medium alert)."""
        d = cloud.direction(u)
        mirror = d == cloud.PULL_MIRROR
        prov = cloud.provider(u)
        label = cloud.CLOUD_SIDE[prov]
        done = {"auth": False}
        t0 = D.utcnow()
        stamp = t0.strftime(pull.STAMP_FMT)
        pct = u["max_delete_pct"] or s.default_max_delete_pct
        rec = _recipients(s)
        combined = Path(self.cfg.p_run) / "rclone" / f"{uid}.{run_id}.combined"   # tmpfs, has file names

        def fin() -> str:
            if done["auth"]:
                return AUTH_OK
            done["auth"] = True
            return self.strategy.finish(uid, auth)

        def finish(oc: Outcome, st: Stats | None = None, exit_code: int | None = None, **kw) -> Outcome:
            fin()
            return self._finish(uid, kind, run_id, oc, st or Stats(), s, exit_code=exit_code, **kw)

        def remaining(limit: int | None) -> int | None:
            if limit is None:
                return None
            return max(int(limit - (D.utcnow() - t0).total_seconds()), 60)

        limit = self._limit(kind, u, s, False)

        def count(backup: str) -> tuple[pull.Count | None, Outcome | None, int | None]:
            """The counting dry-run (op pull_count): the same sync + --dry-run --max-delete -1 --combined."""
            clog = lp + ".count.json"
            cmd = pull.build_pull(self.cfg, jp, op="sync", backup=backup, log_file=clog, dry_run=True,
                                  max_delete=-1, combined=str(combined))
            try:
                pr = self.proc.run(cmd, env, remaining(limit), stderr_path=clog + ".stderr")
                text = Path(clog).read_text(errors="replace") if Path(clog).exists() else ""
                oc = pull.classify_pull(pr.exit_code, text, timed_out=pr.timed_out, provider=prov, cloud=label)
                if oc.result != R_OK:
                    oc = pull.classify_pull(pr.exit_code, text, timed_out=pr.timed_out, broker_auth=fin(),
                                            provider=prov, cloud=label)
                    return None, oc, pr.exit_code
                c = pull.parse_combined(combined.read_text(errors="replace") if combined.exists() else "",
                                        self.cfg.check_filename)
                return c, None, pr.exit_code
            finally:
                shred(combined)

        def store_delta(c: pull.Count) -> dict:
            doc = pull.delta_doc(c)
            write_private(self.delta_path(uid), json.dumps(doc, indent=1))
            return doc

        try:
            nas_check = Path(jp.path2()) / self.cfg.check_filename
            if kind == "dryrun":
                # §6.1 step 9: the server creates the check files on both roots (the cloud one needs write
                # access once, §4.3/§14.19); everything after that is read-only on the cloud side.
                self._ensure_check_files(jp, env)
            # Guard 2: check files at the cloud root AND the NAS root (rclone lsf --max-depth 1)
            missing = []
            for side, target in ((label, f"{jp.remote}:"), ("NAS", jp.path2())):
                pr = self.proc.run(build_lsf_root(self.cfg, target, jp.config_path), env, 300, capture=True)
                if pr.exit_code != 0:
                    if side == label:
                        oc = pull.classify_pull(pr.exit_code, pr.stdout, provider=prov, cloud=label,
                                                broker_auth=fin())
                        if oc.result == R_AUTH:
                            return finish(oc, exit_code=pr.exit_code)
                    return finish(Outcome(R_RETRY, f"listing the {side} root failed (exit {pr.exit_code})"),
                                  exit_code=pr.exit_code)
                names = {ln.strip() for ln in (pr.stdout or "").splitlines()}
                if self.cfg.check_filename not in names and not (side == "NAS" and nas_check.exists()):
                    missing.append(side)
            if missing:
                return finish(Outcome(R_CRITICAL, f"Access test failed: {self.cfg.check_filename} missing at the "
                                                  f"{' and '.join(missing)} root (wrong or empty drive or mount?); "
                                                  "nothing was copied", access_failed=True))
            # Guard 3: backup target reachable and writable, else skip the run (medium alert, no state change)
            bt = self.backup.prepare(s, uid, jp.mount_path)
            if not bt.ok:
                return finish(Outcome(R_RETRY, f"run skipped: backup target unavailable ({bt.message})"),
                              skipped=bt.message or bt.status)
            self.alerter.resolve(uid, "backup_target_unavailable")
            backup = pull.backup_dir(bt.root, uid, stamp, per_user=bt.per_user)
            sm = service_mode.active_scope(self.db, u) if kind == "bisync" else None
            if sm:
                self.db.q("UPDATE sync_runs SET service_mode=? WHERE id=?", (sm, run_id))

            if kind == "dryrun":
                c, oc, code = count(backup)
                if oc is not None:
                    return finish(oc, exit_code=code)
                store_delta(c)
                summ = pull.summary(c, d)
                prof = {}
                if mirror:   # §6.1 step 9: the Mirror baseline count is shown with Approve initial sync
                    prof = dict(mirror_baseline_count=c.nas_only, mirror_baseline_total=c.dest_total,
                                mirror_baseline_counted_at=D.iso(D.utcnow()))
                res = finish(Outcome(R_OK, summ), Stats(files_copied=c.new + c.changed,
                                                        files_deleted=c.nas_only if mirror else 0), exit_code=0)
                self.db.update_profile(uid, dryrun_summary=summ[:300], **prof)
                return res

            onboarding_baseline = kind == "resync" and mirror and u["state"] == D.ONBOARDING
            if onboarding_baseline:
                approved = (0, int(u["mirror_baseline_approved_count"] or 0))
                approved_by = u["resync_approved_by"] or ""
            maxdel: int | None = None
            plan_total: int | None = None
            op = "copy"
            if kind == "delta":
                c, oc, code = count(backup)
                if oc is not None:
                    return finish(oc, exit_code=code)
                doc = store_delta(c)
                if baseline:
                    now = D.iso(D.utcnow())
                    prof = dict(mirror_baseline_count=c.nas_only, mirror_baseline_total=c.dest_total,
                                mirror_baseline_counted_at=now)
                    if c.source_empty and c.dest_total > 0:
                        prof["mirror_baseline_state"] = "empty_source"
                    elif c.nas_only == 0:
                        prof.update(mirror_baseline_ok_at=now, mirror_baseline_state=cloud.BASELINE_DONE)
                        self.db.audit("system", "mirror_baseline_ok", uid, {"run_id": run_id, "moves": 0,
                                                                            "total": c.dest_total})
                    self.db.update_profile(uid, **prof)
                    if c.nas_only or c.source_empty:
                        self.alerter.raise_(Alert(
                            "mirror_baseline_approval", "low",
                            f"{u['upn']}: Mirror baseline: {c.nas_only} of {c.dest_total} NAS file(s) would be moved "
                            "to the backup target; admin approval needed" + (
                                " (the cloud listing is EMPTY: check the account first)" if c.source_empty else ""),
                            uid), rec)
                    return finish(Outcome(R_OK, f"Mirror baseline count: {c.nas_only} of {c.dest_total}"),
                                  exit_code=0)
                self.db.update_profile(uid, safety_delta_requested=0, safety_delta_at=D.iso(D.utcnow()),
                                       safety_delta_summary=delta_summary(doc)[:300])
                return finish(Outcome(R_OK, "one-way delta list ready"), exit_code=0)

            if kind == "force" or onboarding_baseline:
                c, oc, code = count(backup)
                now_counts = (0, c.nas_only) if c else None
                if baseline or onboarding_baseline:
                    if c is None or now_counts != tuple(approved):
                        return self._baseline_cancelled(uid, kind, run_id, s, u, approved, c, oc, code, fin,
                                                        onboarding_baseline)
                    if c.source_empty and c.dest_total > 0:
                        return self._baseline_cancelled(uid, kind, run_id, s, u, approved, c, oc, code, fin,
                                                        onboarding_baseline, why="the cloud listing is empty")
                    self.db.finish_run(run_id, exit_code=code, result=R_OK,
                                       detail=f"Mirror baseline recount: {c.nas_only} (approved {approved[1]})")
                else:
                    if c is not None:
                        store_delta(c)
                    cancelled = self._accept_result(uid, run_id, code, oc or Outcome(R_OK, "ok"), now_counts,
                                                    approved_by, approved, s)
                    if cancelled is not None:
                        fin()
                        return cancelled
                run_id = self.db.start_run(uid, "force" if kind == "force" else "resync", "")
                lp = log_path(self.cfg, uid, run_id)
                self.db.q("UPDATE sync_runs SET log_path=?, direction=?, provider=?, op=? WHERE id=?",
                          (lp, d, prov, pull.OP_MIRROR, run_id))
                self.db.audit("system", "mirror_baseline_started" if (baseline or onboarding_baseline)
                              else "accept_deletes_started", uid,
                              {"approved_by": approved_by, "approved_moves": approved[1], "run_id": run_id,
                               "direction": d})
                op, maxdel, plan_total = "sync", approved[1], c.dest_total
            elif kind == "bisync" and mirror and not cloud.baseline_needed(u):
                c, oc, code = count(backup)
                if oc is not None:
                    return finish(oc, exit_code=code)
                # v0.9.1 (Reid): service mode does NOT loosen Mirror; the run is only tagged (sm) for the summary
                sa = pull.evaluate(c, pct=pct, path=f"{jp.remote}:")
                if sa is not None:
                    sa.cloud = label
                    doc = store_delta(c)
                    self.db.update_profile(uid, safety_delta_at=D.iso(D.utcnow()),
                                           safety_delta_summary=delta_summary(doc)[:300])
                    return finish(Outcome(R_SAFETY, f"safety abort: {sa.summary()}; nothing was moved; user paused. "
                                                    "Admin: Accept deletes, Switch to Copy only, or Retry",
                                          safety=sa), delta_ready=True)
                op = "sync"
                maxdel = pull.max_delete_allowed(c.dest_total, pct)   # always the backstop, service mode or not
                plan_total = c.dest_total
            # kind resync (not a Mirror onboarding baseline), or bisync for Copy only / a Mirror user still
            # waiting for the baseline: rclone copy (never deletes)
            self.db.q("UPDATE sync_runs SET op=? WHERE id=?", (pull.OP_MIRROR if op == "sync" else pull.OP_COPY,
                                                              run_id))
            cmd = pull.build_pull(self.cfg, jp, op=op, backup=backup, log_file=lp, max_delete=maxdel)
            pr = self.proc.run(cmd, env, remaining(limit), stderr_path=lp + ".stderr")
            text = Path(lp).read_text(errors="replace") if Path(lp).exists() else ""
            stats = parse_json_log(text)
            oc = pull.classify_pull(pr.exit_code, text, timed_out=pr.timed_out, broker_auth=fin(), provider=prov,
                                    cloud=label, max_delete=maxdel)
            moved = pull.moved_in_run(text) if op == "sync" else 0
            if oc.result == R_SAFETY:
                total = plan_total
                oc.safety = SafetyAbort("max_delete_backstop", "Path2", f"{jp.remote}:", pct, maxdel, total,
                                        {"Path2": {"deletes": maxdel, "total": total, "pct": pct}},
                                        mode=cloud.PULL_MIRROR, cloud=label)
            # SPEC v0.9 §5: deletes_path1 is always 0 for pull runs; deletes_path2 = NAS files moved away
            self.db.q("UPDATE sync_runs SET deletes_path1=0, deletes_path2=? WHERE id=?", (moved, run_id))
            stats.files_deleted = moved
            return self._finish(uid, "force" if kind == "force" else kind, run_id, oc, stats, s,
                                exit_code=pr.exit_code, baseline=baseline or onboarding_baseline)
        except Exception as e:
            log.exception("one-way pull failed uid=%s kind=%s", uid, kind)
            return self._finish(uid, kind, run_id, Outcome(R_ERROR, f"internal error: {type(e).__name__}"), Stats(), s)
        finally:
            shred(combined)
            if not done["auth"]:
                try:
                    fin()
                except Exception:
                    log.exception("strategy cleanup failed")

    def _baseline_cancelled(self, uid: str, kind: str, run_id: int, s, u, approved, c, oc, code, fin,
                            onboarding: bool, why: str = "") -> Outcome:
        """The recount right before an approved Mirror baseline differs (or failed): nothing runs; the new
        count waits for a new approval (SPEC §6.6 / §9.4.1 rules)."""
        fin()
        now = c.nas_only if c else None
        why = why or (f"count changed (approved {approved[1]}, now {now})" if c else
                      f"recount failed ({oc.result if oc else 'error'})")
        self.db.finish_run(run_id, exit_code=code, result="cancelled", detail=f"Mirror baseline cancelled: {why}")
        prof = dict(mirror_baseline_approved_by=None, mirror_baseline_approved_at=None,
                    mirror_baseline_approved_count=None, mirror_baseline_state=cloud.BASELINE_CANCELLED)
        if c is not None:
            prof.update(mirror_baseline_count=c.nas_only, mirror_baseline_total=c.dest_total,
                        mirror_baseline_counted_at=D.iso(D.utcnow()))
        if onboarding:
            prof.update(resync_approved_by=None, resync_approved_at=None)
        self.db.update_profile(uid, **prof)
        self.db.audit("system", "mirror_baseline_cancelled", uid,
                      {"run_id": run_id, "approved_moves": approved[1], "moves_now": now, "reason": why,
                       "onboarding": onboarding})
        self.alerter.raise_(Alert("mirror_baseline_cancelled", "high",
                                  f"{u['upn']}: Mirror baseline cancelled: {why}; re-approval needed", uid),
                            _recipients(s))
        return Outcome("cancelled", why)

    def _finish(self, uid: str, kind: str, run_id: int, oc: Outcome, st: Stats, s, exit_code: int | None = None,
                nas_down: bool = False, mounted: bool = True, global_nas: bool = False, skipped: str = "",
                baseline: bool = False, delta_ready: bool = False) -> Outcome:
        apply_outcome(self.db, self.alerter, s, uid, kind, run_id, oc, st, exit_code, self.governor, nas_down,
                      mounted=mounted, global_nas=global_nas, skipped=skipped, baseline=baseline,
                      delta_ready=delta_ready)
        return oc


def _op_name(kind: str, pull_run: bool) -> str:
    """sync_runs.op: the SPEC v0.9 run kinds pull_count / pull_copy / pull_mirror (recorded additively)."""
    if kind == "preflight":
        return "lsjson"
    if kind == "check":
        return "check --one-way" if pull_run else "check"
    if pull_run:
        return pull.OP_COUNT if kind in ("dryrun", "delta", "force") else pull.OP_COPY
    return "bisync"


def _recipients(s) -> list[str]:
    return [x.strip() for x in (s.alert_recipients or "").split(",") if x.strip()]


def apply_outcome(db: D.DB, alerter: Alerter, s, uid: str, kind: str, run_id: int, oc: Outcome, st: Stats,
                  exit_code: int | None, governor: ThrottleGovernor, nas_down: bool = False,
                  mounted: bool = True, global_nas: bool = False, skipped: str = "", baseline: bool = False,
                  delta_ready: bool = False) -> None:
    """skipped: a one-way run skipped by guard 3 (backup target): medium alert, no counters, no state change.
    baseline: an approved Mirror baseline run (kind force while active, or the onboarding resync).
    delta_ready: a Mirror safety abort whose delta list came from the counting dry-run itself."""
    now = D.utcnow()
    db.finish_run(run_id, exit_code=exit_code, result=oc.result, detail=oc.detail[:500],
                  files_copied=st.files_copied, files_deleted=st.files_deleted, bytes=st.bytes,
                  conflicts=st.conflicts, errors_count=st.errors_count, throttled=int(st.throttled))
    u = db.user_full(uid)
    rec = _recipients(s)
    prof: dict = {"last_result": oc.result}
    upn = u["upn"]
    pull_user = cloud.is_pull(u)
    if skipped:
        alerter.raise_(Alert("backup_target_unavailable", "medium",
                             f"{upn}: one-way run skipped: backup target unreachable or not writable ({skipped})"[:300],
                             uid), rec)
        interval = u["interval_min"] or s.default_interval_min
        db.update_profile(uid, last_result=oc.result, consecutive_mount_failures=0, next_run_at=D.iso(
            next_slot(now, interval, u["slot_offset_min"], u["backoff_factor"])))
        db.audit("system", f"run_{kind}", uid, {"run_id": run_id, "result": oc.result, "skipped": "backup_target"})
        return

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
        if kind in ("bisync", "resync") or (kind == "force" and pull_user):
            prof["last_success_at"] = D.iso(now)
        if not u["onboarding_completed_at"] and (kind == "bisync" or (
                pull_user and kind in ("resync", "force"))):
            # SPEC v0.5 §6.1 step 8 (two-way: first normal bisync); v0.9 step 9 (one-way: first successful pull)
            prof["onboarding_completed_at"] = D.iso(now)
            db.audit("system", "onboarding_completed", uid, {"run_id": run_id})
        if kind == "bisync" and not pull_user and not u["two_way_baseline_at"]:
            prof["two_way_baseline_at"] = D.iso(now)        # v0.9 §6.6: service mode applies again from here
            if u["direction_changed_at"]:
                db.audit("system", "two_way_baseline_completed", uid, {"run_id": run_id})
        if baseline:
            prof.update(mirror_baseline_ok_at=D.iso(now), mirror_baseline_state=cloud.BASELINE_DONE,
                        mirror_baseline_approved_by=None, mirror_baseline_approved_at=None,
                        mirror_baseline_approved_count=None)
            db.audit("system", "mirror_baseline_completed", uid, {"run_id": run_id, "moved": st.files_deleted,
                                                                   "copied": st.files_copied})
            alerter.resolve(uid, "mirror_baseline_approval", "mirror_baseline_cancelled")
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
        if kind == "force" and not baseline:
            prof.update(**_SAFETY_CLEAR)
            if u["state"] == D.SAFETY_ABORT:
                db.set_state(uid, D.ACTIVE)
            alerter.resolve(uid, "safety_abort")
            db.audit("system", "accept_deletes_completed", uid,
                     {"run_id": run_id, "result": oc.result, "deleted": st.files_deleted, "copied": st.files_copied})
        if kind == "dryrun" and pull_user:
            prof.update(dryrun_ok_at=D.iso(now))
            alerter.raise_(Alert("approval_needed", "low", f"{upn}: one-way dry-run ok, waiting for 'Approve initial "
                                                           "sync'", uid), rec)
        elif kind == "dryrun":
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
        no_delta = kind == "dryrun" or delta_ready
        rec_ = dict(sa.as_dict() if sa else {}, during=kind, onboarding=onboarding)
        prof.update(safety_abort_at=D.iso(now), safety_abort_json=json.dumps(rec_),
                    safety_delta_requested=0 if no_delta else 1)
        if delta_ready:   # the counting dry-run's list, stored by the runner just before
            prof.update(safety_delta_at=u["safety_delta_at"], safety_delta_summary=u["safety_delta_summary"])
        if onboarding:
            db.audit("system", "onboarding_safety_abort", uid, {"run_id": run_id, "during": kind})
        db.set_state(uid, D.SAFETY_ABORT, oc.detail[:200])
        actions = "Accept deletes, Switch to Copy only, or Retry" if pull_user else "Restore or Accept deletes"
        alerter.raise_(Alert("safety_abort", "critical",
                             f"{upn}: {sa.summary() if sa else 'safety abort'}; paused. Admin: {actions}",
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
    elif oc.result == R_AUTH and oc.auth == AUTH_APP:
        # v0.9 §4.3: invalid_client / unauthorized_client = the app's Google credential, not the user's:
        # one high alert (app-wide), no Google user runs until fixed; the user's state is unchanged.
        if db.set_flag(GOOGLE_APP_FLAG, "Google OAuth client rejected (invalid_client/unauthorized_client)",
                       first_user=uid, run_id=run_id):
            db.audit("system", "google_app_credential_failed", uid, {"run_id": run_id})
            alerter.raise_(Alert("google_app_credential", "high",
                                 "Google OAuth client rejected (invalid_client): all Google Drive syncs are paused. "
                                 "Check the client ID / secret (rotate it), then restart the worker.", None), rec)
    elif oc.result == R_AUTH:
        google = cloud.provider(u) == cloud.PROVIDER_GD
        if oc.auth == AUTH_CA:
            why = "blocked by Google admin policy" if google else "Conditional Access blocked token refresh"
            db.set_state(uid, D.BLOCKED_BY_CA, why)
            alerter.raise_(Alert("blocked_by_ca", "high", f"{upn}: {why}", uid), rec)
        else:
            db.set_state(uid, D.NEEDS_REAUTH, f"{'Google' if google else 'Microsoft'} sign-in expired or revoked")
            alerter.raise_(Alert("needs_reauth", "medium",
                                 f"{upn}: needs to reconnect {'Google Drive' if google else 'Microsoft'}", uid,
                                 notify_user=True), rec)
    elif oc.result == R_NAS_AUTH and global_nas:
        set_nas_global_pause(db, alerter, rec, uid, run_id)
    elif oc.result == R_NAS_AUTH:
        db.set_state(uid, D.NAS_AUTH_FAILED, "NAS login failed; paused, no retries")
        db.q("UPDATE nas_credentials SET last_failure_at=?, failure_count=failure_count+1 WHERE user_id=?",
             (D.iso(now), uid))
        alerter.raise_(Alert("nas_auth_failed", "high", f"{upn}: NAS login failed; paused until re-entered", uid,
                             notify_user=True), rec)

    if kind == "force" and baseline and oc.result != R_OK and rclone_started:
        prof.update(mirror_baseline_approved_by=None, mirror_baseline_approved_at=None,
                    mirror_baseline_approved_count=None, mirror_baseline_state=cloud.BASELINE_FAILED,
                    mirror_baseline_counted_at=None)
        db.audit("system", "mirror_baseline_failed", uid, {"run_id": run_id, "result": oc.result,
                                                            "moved": st.files_deleted})
        alerter.raise_(Alert("mirror_baseline_failed", "high",
                             f"{upn}: approved Mirror baseline run did not finish ({oc.result}); it will be "
                             "recounted and needs a new approval", uid), rec)
    elif kind == "force" and oc.result != R_OK and rclone_started:
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

    if oc.deletes_skipped:
        db.q("UPDATE sync_runs SET detail=detail || ' [deletes_skipped]' WHERE id=?", (run_id,))
    if st.unsyncable:
        prof["unsyncable_count"] = st.unsyncable
        alerter.raise_(Alert("unsyncable_files", "low", f"{upn}: {st.unsyncable} file(s) can't sync", uid), rec)
    interval = u["interval_min"] or s.default_interval_min
    prof["next_run_at"] = D.iso(next_slot(now, interval, u["slot_offset_min"], prof["backoff_factor"]))
    db.update_profile(uid, **prof)
    run = db.one("SELECT service_mode FROM sync_runs WHERE id=?", (run_id,))
    det = {"run_id": run_id, "result": oc.result, "exit_code": exit_code}
    if run is not None and run["service_mode"]:
        det.update(service_mode=run["service_mode"], deleted=st.files_deleted)
    db.audit("system", f"run_{kind}", uid, det)


def set_nas_global_pause(db: D.DB, alerter: Alerter, rec: list[str], uid: str | None, run_id: int | None,
                         source: str = "run") -> bool:
    """SPEC v0.6: one server-wide NAS pause for a rejected Option B svc-sync login. Idempotent: concurrent
    runs that hit the same rejection add no second alert or audit entry."""
    new = db.set_flag(D.NAS_GLOBAL_PAUSE, "svc-sync NAS login rejected",
                      pw_version=db.setting_version("nas_svc_password"), first_user=uid, run_id=run_id,
                      source=source)
    if new:
        db.audit("system", "nas_global_pause_set", uid or "",
                 {"reason": "svc_sync_login_rejected", "run_id": run_id, "source": source})
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
    if u["direction"] == "pull_mirror":
        prof.update(cloud.BASELINE_CLEAR)   # v0.9: after a critical stop Mirror re-baselines before deleting
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
