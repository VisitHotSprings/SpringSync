"""springsync worker (SPEC §3, §9.1): 60 s scheduler tick + token broker and an
internal API on 127.0.0.1:8081. The only process that launches rclone and the
mount helper."""
from __future__ import annotations

import hmac
import json
import logging
import shutil
import signal
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable

from odnas import db as D
from odnas import settings_store
from odnas.bisync import render_filters
from odnas.config import TOKEN_MODE_BROKER, Config
from odnas.crypto import Keyring
from odnas.entra import EntraClient
from odnas.nas import V_AUTH_FAILED, V_OK, MountHelperClient, NasAccessProvider, provider_from_settings
from odnas.notify import Alert, Alerter, Notifier
from odnas.runner import (JobRunner, ProcessRunner, _recipients, accept_expired, expire_accept_approvals,
                          set_nas_global_pause, sweep_runtime)
from odnas.scheduler import (ThrottleGovernor, assign_offsets, in_window, seconds_until_window_end,
                             weekly_check_due)
from odnas.tokens import BrokerTokenStrategy, TmpfsConfigStrategy, TokenBroker

NAS_HEALTH_INTERVAL_MIN = 15   # SPEC v0.7 health check (Option B)
log = logging.getLogger("odnas.worker")


class Worker:
    def __init__(self, cfg: Config, db: D.DB, kr: Keyring, entra: EntraClient, *,
                 notifier: Notifier | None = None, proc: ProcessRunner | None = None,
                 helper: MountHelperClient | None = None,
                 provider_factory: Callable[[], NasAccessProvider] | None = None):
        self.cfg, self.db, self.kr, self.entra = cfg, db, kr, entra
        self.alerter = Alerter(db, notifier)
        self.broker = TokenBroker(db, kr, entra, cfg)
        self.strategy = BrokerTokenStrategy(cfg, db, self.broker) if cfg.token_mode == TOKEN_MODE_BROKER \
            else TmpfsConfigStrategy(cfg, db, kr)
        self.helper = helper or MountHelperClient(cfg)
        self.governor = ThrottleGovernor()
        self.provider_factory = provider_factory or (lambda: provider_from_settings(cfg, self.settings(), self.helper))
        self.runner = JobRunner(cfg, db, kr, self.strategy, self.provider_factory, self.settings, self.alerter,
                                proc, self.governor)
        self._running: dict[str, tuple[str, Future]] = {}
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="job")
        self._stop = threading.Event()

    # ---- settings / flags ---------------------------------------------
    def settings(self):
        return settings_store.load(self.db, self.cfg, self.kr)

    @property
    def drain_flag(self) -> Path:
        return Path(self.cfg.p_state) / "drain"

    def draining(self) -> bool:
        return self.drain_flag.exists()

    def running(self) -> dict[str, str]:
        with self._lock:
            for uid in [u for u, (_, f) in self._running.items() if f.done()]:
                del self._running[uid]
            return {u: k for u, (k, _) in self._running.items()}

    # ---- startup ------------------------------------------------------
    def startup(self) -> None:
        n = sweep_runtime(self.cfg)
        if n:
            log.warning("swept %d stale per-run secret file(s)", n)
        self.drain_flag.unlink(missing_ok=True)
        self.check_filters()
        self.db.audit("system", "worker_started", "", {"token_mode": self.strategy.name})

    def check_filters(self) -> bool:
        """A release that changes the filters file sets needs_resync for all users (SPEC §9.3)."""
        _, md5 = render_filters(self.cfg)
        prev = self.db.heartbeat("filters_md5")
        self.db.beat("filters_md5", md5)
        if prev and prev["detail"] != md5:
            self.db.q("UPDATE sync_profiles SET needs_resync=1, resync_approved_by=NULL, resync_approved_at=NULL "
                      "WHERE user_id IN (SELECT id FROM users WHERE state IN ('active','critical'))")
            self.db.audit("system", "filters_changed", "", {"old": prev["detail"], "new": md5})
            self.alerter.raise_(Alert("filters_changed", "high",
                                      "bisync filters changed in this release: every user needs an approved resync"))
            return True
        return False

    # ---- scheduling ---------------------------------------------------
    def choose_job(self, u, s, now: datetime) -> str | None:
        """Decide what (if anything) to run for this user right now. Pure w.r.t. side effects."""
        st = u["state"]
        has_ms = self.db.ms_credential(u["id"]) is not None
        provider_needs_creds = s.nas_option == "A"
        has_nas = (not provider_needs_creds) or self.db.nas_credential_meta(u["id"]) is not None
        if st == D.OFFBOARDING:
            return "offboard"
        if not (has_ms and has_nas) or not u["enabled"]:
            return None
        if u["preflight_requested"]:
            return "preflight"
        approved = bool(u["resync_approved_by"])
        resync_ok = in_window(now, settings_store.active_window_for(s.resync_hours))
        if st == D.ONBOARDING:
            if approved and u["dryrun_ok_at"]:
                return "resync" if resync_ok else None
            if not u["dryrun_ok_at"] and u["preflight_at"]:
                last = D.parse_iso(u["last_run_at"])
                if last is None or now - last > timedelta(minutes=u["interval_min"] or s.default_interval_min):
                    return "dryrun"
            return None
        if st == D.CRITICAL:
            return "resync" if approved and resync_ok else None
        if st == D.SAFETY_ABORT:
            # SPEC v0.2 §9.4: paused (a plain bisync would re-trip every slot). Only three things run:
            # the read-only `--dry-run --force` delta list, an admin-approved Restore (--resync),
            # or one admin-approved Accept-deletes (--force) run.
            if u["safety_action"] == D.SAFETY_RESTORE and u["safety_action_by"] and approved \
                    and not u["safety_delta_requested"]:
                if not u["onboarding_completed_at"]:
                    # SPEC v0.5 §6.1 step 8: Restore = re-run the onboarding --resync, under the onboarding
                    # resync rules (resync_hours, one at a time, no run-time limit)
                    return "resync" if resync_ok else None
                if u["safety_restore_when"] == D.RESTORE_TONIGHT:
                    # tonight runs are bound by resync_hours (not active hours) and need >= 30 min left (v0.5)
                    return "resync" if tonight_start_ok(now, s) else None
                return "resync" if in_window(now, settings_store.active_window(s)) else None
            if not in_window(now, settings_store.active_window(s)):
                return None
            if u["safety_delta_requested"]:
                nxt = D.parse_iso(u["next_run_at"])
                return "delta" if nxt is None or nxt <= now else None
            if u["safety_action"] == D.SAFETY_ACCEPT and u["safety_action_by"] \
                    and u["safety_approved_deletes"] is not None and not accept_expired(u, now):
                return "force"
            return None
        if st != D.ACTIVE:
            return None  # paused, needs_reauth, nas_auth_failed, blocked_by_ca, removed: no attempts
        if u["needs_resync"]:
            return "resync" if approved and resync_ok else None
        if not in_window(now, settings_store.active_window(s)):
            return None
        if weekly_check_due(now, D.parse_iso(u["last_check_at"]), s.check_weekday, s.check_time):
            return "check"
        nxt = D.parse_iso(u["next_run_at"])
        return "bisync" if nxt is None or nxt <= now else None

    def _tonight_holds(self, users, s, now: datetime) -> None:
        """SPEC v0.5 §9.4.1: a tonight Restore inside resync_hours with < 30 min left is held for the next
        night. Audited (and a low alert) once per night: tonight_held_at dedupes the 60 s tick."""
        win = settings_store.active_window_for(s.resync_hours)
        for u in users:
            if not (u["state"] == D.SAFETY_ABORT and u["safety_action"] == D.SAFETY_RESTORE and u["safety_action_by"]
                    and u["resync_approved_by"] and u["onboarding_completed_at"]
                    and u["safety_restore_when"] == D.RESTORE_TONIGHT):
                continue
            left = seconds_until_window_end(now, win)
            if left is None or left >= D.TONIGHT_MIN_REMAINING_S:
                continue
            held = D.parse_iso(u["tonight_held_at"])
            if held is not None and now - held < timedelta(hours=12):
                continue
            nights = (u["tonight_hold_nights"] or 0) + 1
            # SPEC v0.6: first hold of this Restore -> low; the same Restore held again -> medium
            sev = "low" if nights == 1 else "medium"
            self.db.update_profile(u["id"], tonight_held_at=D.iso(now), tonight_hold_nights=nights)
            self.db.audit("system", "safety_restore_tonight_deferred", u["id"],
                          {"minutes_left": left // 60, "min_required": D.TONIGHT_MIN_REMAINING_S // 60,
                           "window": s.resync_hours, "auto_requeued": bool(u["safety_restore_requeued"]),
                           "nights_held": nights, "severity": sev})
            if nights > 1:
                self.alerter.resolve(u["id"], "restore_deferred")   # re-open at the higher severity
            self.alerter.raise_(Alert("restore_deferred", sev,
                                      f"{u['upn']}: tonight Restore held for the next night "
                                      f"(only {left // 60} min left before the window closes; "
                                      f"held {nights} night(s))", u["id"]),
                                _recipients(s))

    def _nas_global_pause(self, s, now: datetime) -> bool:
        """SPEC v0.6 §9.4 (Option B): while the global NAS pause is set, no NAS runs start. It clears only
        after IT saves a new nas_svc_password AND a test mount with it succeeds. A rejected test marks that
        password as tried (never retried: avoids locking out svc-sync); NAS-unreachable tests retry every
        5 min. Returns True while paused."""
        f = self.db.flag(D.NAS_GLOBAL_PAUSE)
        if f is None:
            return False
        rec = _recipients(s)
        if s.nas_option != "B":
            self.db.clear_flag(D.NAS_GLOBAL_PAUSE)
            self.db.audit("system", "nas_global_pause_cleared", "", {"reason": "nas_option_changed",
                                                                     "nas_option": s.nas_option})
            self.alerter.resolve(None, "nas_global_pause")
            return False
        pw_ver = self.db.setting_version("nas_svc_password")
        if pw_ver is None or pw_ver in (f.get("pw_version"), f.get("tested_pw_version")):
            return True   # no new password since the pause / since the last rejected test
        last = D.parse_iso(f.get("last_test_at"))
        if f.get("last_test_pw") == pw_ver and last is not None and now - last < timedelta(minutes=5):
            return True
        res = self.provider_factory().test_mount()     # SPEC v0.7: the health-check share, never a Home share
        self.db.update_flag(D.NAS_GLOBAL_PAUSE, last_test_at=D.iso(now), last_test_pw=pw_ver)
        self.db.beat("nas_svc_test", json.dumps({"result": res.status, "at": D.iso(now), "pw_version": pw_ver}))
        # the same mount is also this interval's health check (no second mount in the same tick)
        self.db.beat("nas_health", json.dumps({"result": res.status, "at": D.iso(now), "share": s.nas_health_share}))
        if res.status == V_OK:
            self.db.clear_flag(D.NAS_GLOBAL_PAUSE)
            self.db.audit("system", "nas_global_pause_cleared", "",
                          {"reason": "svc_sync_password_updated_and_test_mount_ok", "paused_since": f["set_at"],
                           "test_share": s.nas_health_share})
            self.alerter.resolve(None, "nas_global_pause")
            return False
        if res.status == V_AUTH_FAILED:
            self.db.update_flag(D.NAS_GLOBAL_PAUSE, tested_pw_version=pw_ver)
            self.db.audit("system", "nas_global_pause_test_failed", "", {"result": res.status})
            self.alerter.raise_(Alert("nas_global_pause_test_failed", "high",
                                      "The new svc-sync password was rejected by the NAS; syncing stays paused.",
                                      None), rec)
        else:
            self.db.audit("system", "nas_global_pause_test_failed", "", {"result": res.status, "retry": "5 min"})
        return True

    def _nas_health(self, s, now: datetime) -> None:
        """SPEC v0.7: periodic NAS health check (Option B) = read-only svc-sync test mount of the health-check
        share every NAS_HEALTH_INTERVAL_MIN. Not run while the global pause is set (its own test handles
        that, without retrying a rejected password). A rejected svc-sync login sets the global pause."""
        if s.nas_option != "B":
            return
        hb = self.db.heartbeat("nas_health")
        last = D.parse_iso(json.loads(hb["detail"]).get("at")) if hb and hb["detail"] else None
        if last is not None and now - last < timedelta(minutes=NAS_HEALTH_INTERVAL_MIN):
            return
        res = self.provider_factory().test_mount()
        self.db.beat("nas_health", json.dumps({"result": res.status, "at": D.iso(now), "share": s.nas_health_share}))
        rec = _recipients(s)
        if res.status == V_OK:
            self.alerter.resolve(None, "nas_health")
        elif res.status == V_AUTH_FAILED:
            set_nas_global_pause(self.db, self.alerter, rec, None, None, source="health_check")
        else:
            self.alerter.raise_(Alert("nas_health", "medium",
                                      f"NAS health check failed ({res.status}) on share {s.nas_health_share}", None),
                                rec)

    def tick(self, now: datetime | None = None, wait: bool = False) -> list[tuple[str, str]]:
        now = now or D.utcnow()
        s = self.settings()
        self.db.beat("worker", f"running={len(self.running())}")
        users = self.db.users()
        offsets = assign_offsets([u["id"] for u in users], s.default_interval_min)
        for u in users:
            if u["slot_offset_min"] != offsets[u["id"]]:
                self.db.update_profile(u["id"], slot_offset_min=offsets[u["id"]])
        self._staleness(users, s, now)
        expire_accept_approvals(self.db, self.alerter, s, now)
        self._tonight_holds(users, s, now)
        nas_paused = self._nas_global_pause(s, now)
        if not nas_paused:
            self._nas_health(s, now)
            nas_paused = self.db.flag(D.NAS_GLOBAL_PAUSE) is not None
        if self.draining():
            return []
        cap = self.governor.max_concurrent(now, s.max_concurrent)
        started: list[tuple[str, str]] = []
        running = self.running()
        for u in self.db.users():
            if len(running) + len(started) >= cap:
                break
            if u["id"] in running:
                continue  # one run per user (in-process lock; bisync has its own lock too)
            kind = self.choose_job(u, s, now)
            if not kind:
                continue
            if nas_paused and (kind != "offboard" or u["final_sync_requested"]):
                continue  # SPEC v0.6: global NAS pause -> no NAS runs for anyone (user states unchanged)
            next_slot_restore = (kind == "resync" and u["state"] == D.SAFETY_ABORT and u["onboarding_completed_at"]
                                 and u["safety_restore_when"] != D.RESTORE_TONIGHT)
            if kind == "resync" and not next_slot_restore and \
                    any(k == "resync" for k in list(running.values()) + [k for _, k in started]):
                continue  # initial/approved resync: one user at a time (SPEC §9.1); a next-slot Restore
                #           (SPEC v0.3 §9.4.1) only obeys max_concurrent
            started.append((u["id"], kind))
            self._submit(u["id"], kind)
        if wait:
            for _, (_, f) in list(self._running.items()):
                f.result()
        return started

    def _submit(self, uid: str, kind: str) -> None:
        fn = (lambda: self.offboard(uid)) if kind == "offboard" else (lambda: self.runner.run(uid, kind))
        with self._lock:
            self._running[uid] = (kind, self._pool.submit(fn))

    def _staleness(self, users, s, now: datetime) -> None:
        for u in users:
            if u["state"] != D.ACTIVE or not u["last_success_at"]:
                continue
            if now - D.parse_iso(u["last_success_at"]) > timedelta(hours=s.stale_hours):
                self.alerter.raise_(Alert("stale", "medium", f"{u['upn']}: no successful sync in {s.stale_hours} h",
                                          u["id"]))

    # ---- offboarding (SPEC §6.3) --------------------------------------
    def offboard(self, uid: str) -> None:
        u = self.db.user_full(uid)
        if u["final_sync_requested"] and self.db.ms_credential(uid):
            self.db.set_state(uid, D.ACTIVE)  # transient so the runner accepts it
            try:
                self.runner.run(uid, "bisync")
            finally:
                self.db.set_state(uid, D.OFFBOARDING)
        self.db.crypto_erase(uid)
        shutil.rmtree(Path(self.cfg.p_state) / "bisync" / uid, ignore_errors=True)
        (Path(self.cfg.p_state) / "preflight" / f"{uid}.json").unlink(missing_ok=True)
        (Path(self.cfg.p_state) / "safety" / f"{uid}.json").unlink(missing_ok=True)
        try:
            self.helper.call("umount", uid)
        except Exception:
            log.exception("umount during offboard failed")
        self.db.update_profile(uid, enabled=0, final_sync_requested=0, next_run_at=None)
        self.db.set_state(uid, D.REMOVED, "offboarded")
        self.alerter.resolve(uid, "needs_reauth", "nas_auth_failed", "critical", "stale", "repeated_failures",
                             "safety_abort")
        self.db.audit("system", "user_offboarded", uid, {"crypto_erase": True, "final_sync": bool(u["final_sync_requested"])})

    # ---- loop ---------------------------------------------------------
    def serve_forever(self) -> None:
        self.startup()
        signal.signal(signal.SIGTERM, lambda *_: self._stop.set())
        signal.signal(signal.SIGINT, lambda *_: self._stop.set())
        t = threading.Thread(target=self._serve_http, daemon=True)
        t.start()
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception:
                log.exception("tick failed")
            self._stop.wait(60)
        log.info("stopping: waiting for running jobs (rclone handles SIGTERM via systemd KillMode=mixed)")
        self._pool.shutdown(wait=True, cancel_futures=True)

    def _serve_http(self) -> None:
        import uvicorn
        uvicorn.run(build_internal_app(self), host=self.cfg.broker_host, port=self.cfg.broker_port,
                    log_level="warning", access_log=False)


def build_internal_app(w: Worker):
    """Broker + internal API. Loopback only (also enforced by the bind address)."""
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    def loopback(req: Request) -> bool:
        return req.client is not None and req.client.host in ("127.0.0.1", "::1", "testclient")

    def internal_ok(req: Request) -> bool:
        return loopback(req) and hmac.compare_digest(req.headers.get("x-internal-token", ""), w.kr.internal_token())

    async def token(req: Request):
        if not loopback(req):
            return JSONResponse({"error": "forbidden"}, 403)
        form = dict(await req.form())
        code, body = w.broker.token(req.path_params["uid"], {k: str(v) for k, v in form.items()})
        return JSONResponse(body, code, headers={"Cache-Control": "no-store"})

    async def nas_verify(req: Request):
        if not internal_ok(req):
            return JSONResponse({"error": "forbidden"}, 403)
        j = await req.json()
        res = w.provider_factory().verify(str(j.get("username", "")), str(j.get("password", "")))
        return JSONResponse({"status": res.status})

    async def health(req: Request):
        if not loopback(req):
            return JSONResponse({"error": "forbidden"}, 403)
        return JSONResponse({"ok": True, "running": len(w.running()), "draining": w.draining(),
                             "broker_handles": w.broker.active_handles()})

    return Starlette(routes=[Route("/broker/{uid}/token", token, methods=["POST"]),
                             Route("/internal/nas-verify", nas_verify, methods=["POST"]),
                             Route("/internal/health", health, methods=["GET"])])


def tonight_start_ok(now: datetime, s) -> bool:
    """Inside resync_hours with at least 30 minutes left before it closes (SPEC v0.5 §9.4.1)."""
    left = seconds_until_window_end(now, settings_store.active_window_for(s.resync_hours))
    return left is not None and left >= D.TONIGHT_MIN_REMAINING_S
