"""springsync worker (SPEC §3, §9.1): 60 s scheduler tick + token broker and an
internal API on 127.0.0.1:8081. The only process that launches rclone and the
mount helper."""
from __future__ import annotations

import hmac
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
from odnas.nas import MountHelperClient, NasAccessProvider, provider_from_settings
from odnas.notify import Alert, Alerter, Notifier
from odnas.runner import JobRunner, ProcessRunner, sweep_runtime
from odnas.scheduler import ThrottleGovernor, assign_offsets, in_window, weekly_check_due
from odnas.tokens import BrokerTokenStrategy, TmpfsConfigStrategy, TokenBroker

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
            if kind == "resync" and any(k == "resync" for k in list(running.values()) + [k for _, k in started]):
                continue  # initial/approved resync: one user at a time (SPEC §9.1)
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
        try:
            self.helper.call("umount", uid)
        except Exception:
            log.exception("umount during offboard failed")
        self.db.update_profile(uid, enabled=0, final_sync_requested=0, next_run_at=None)
        self.db.set_state(uid, D.REMOVED, "offboarded")
        self.alerter.resolve(uid, "needs_reauth", "nas_auth_failed", "critical", "stale", "repeated_failures")
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
