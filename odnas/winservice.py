r"""Windows services (SPEC v0.9 §11.5.5): springsync-web and springsync-worker run as svc-springsync,
hosted by the bundled python.exe through deploy\windows\svc.py with pywin32 (no NSSM/WinSW binary to trust).
caddy.exe registers as its own service (Caddy supports the Windows service manager natively).

    install.ps1 registers:  "<app>\current\python\python.exe" "<app>\current\deploy\windows\svc.py" worker
    restart on failure:     sc.exe failure ... reset= 86400 actions= restart/60000/restart/60000/restart/60000
    start:                  Automatic (Delayed Start), runs with nobody signed in

Stop / pre-shutdown (worker): stop starting jobs, CTRL_BREAK to running rclone, hard kill after 120 s, keep
reporting STOP_PENDING to the service manager meanwhile. The worker accepts SERVICE_CONTROL_PRESHUTDOWN so a
Windows Update restart drains first; install.ps1 sets PreshutdownTimeout=150 s for it.

The pywin32 glue is in `run_service()`; `ServiceBody` is plain Python so it is unit-tested on Linux.
"""
from __future__ import annotations

import logging
import logging.handlers
import os
import threading
import time
from pathlib import Path

SERVICES = {"web": "springsync-web", "worker": "springsync-worker"}
DISPLAY = {"web": "SpringSync web", "worker": "SpringSync worker"}
DESCRIPTION = {"web": "SpringSync web pages and admin (127.0.0.1:8080, behind Caddy)",
               "worker": "SpringSync scheduler, token broker (127.0.0.1:8081) and rclone runs"}
SERVICE_ACCEPT_PRESHUTDOWN = 0x00000100
SERVICE_CONTROL_PRESHUTDOWN = 0x0000000F
STOP_WAIT_S = 150


def setup_logging(cfg, role: str) -> Path:
    """Services have no console: JSON-ish lines to <logs>\\<role>.log, 10 x 10 MB."""
    p = Path(cfg.p_log) / f"{role}.log"
    p.parent.mkdir(parents=True, exist_ok=True)
    h = logging.handlers.RotatingFileHandler(p, maxBytes=10 * 1024 * 1024, backupCount=10, encoding="utf-8")
    h.setFormatter(logging.Formatter('{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s",'
                                     '"msg":"%(message)s"}'))
    root = logging.getLogger()
    root.handlers[:] = [h]
    root.setLevel(logging.INFO)
    return p


class ServiceBody:
    """What the service runs, independent of pywin32. start() returns at once; the body runs in a thread.
    stop() asks it to finish and waits (calling `pending()` every few seconds so the SCM keeps waiting)."""

    def __init__(self, role: str, cfg=None, factory=None):
        if role not in SERVICES:
            raise ValueError(role)
        self.role, self.cfg = role, cfg
        self._factory = factory          # tests: returns an object with run() and stop()
        self._impl = None
        self._thread: threading.Thread | None = None
        self.error: BaseException | None = None

    def _build(self):
        if self._factory:
            return self._factory(self.role)
        from odnas.cli import _host_startup
        from odnas.config import load_config
        cfg = self.cfg or load_config()
        self.cfg = cfg
        _host_startup(cfg)
        if self.role == "worker":
            self_check(cfg)
        return _WebImpl(cfg) if self.role == "web" else _WorkerImpl(cfg)

    def start(self) -> None:
        self._impl = self._build()

        def body():
            try:
                self._impl.run()
            except BaseException as e:   # noqa: BLE001 - reported to the SCM as a failure -> restart
                self.error = e
                logging.getLogger("odnas.winservice").exception("%s service body failed", self.role)
        self._thread = threading.Thread(target=body, name=f"{self.role}-main", daemon=True)
        self._thread.start()

    def alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def wait(self, timeout: float | None = None) -> bool:
        if self._thread:
            self._thread.join(timeout)
        return not self.alive()

    def stop(self, pending=lambda: None, max_wait_s: float = STOP_WAIT_S, step_s: float = 3.0) -> bool:
        if self._impl is not None:
            self._impl.stop()
        deadline = time.monotonic() + max_wait_s
        while self.alive() and time.monotonic() < deadline:
            pending()
            self.wait(step_s)
        return not self.alive()


def self_check(cfg) -> None:
    """Doctor as the service account (the only identity that can open the DPAPI secrets) at every worker
    start; install.ps1 / update.ps1 read <logs>\\doctor-service.json. Never fatal."""
    try:
        from odnas import doctor
        doctor.write_report(cfg, doctor.run_all(cfg, decrypt=True), "doctor-service.json")
    except Exception:
        logging.getLogger("odnas.winservice").exception("self-check failed")


class _WebImpl:
    def __init__(self, cfg):
        import uvicorn
        self.cfg = cfg
        conf = uvicorn.Config("odnas.web.app:build_from_env", factory=True, host=cfg.web_host, port=cfg.web_port,
                              proxy_headers=True, forwarded_allow_ips="127.0.0.1", access_log=False,
                              log_config=None)
        self.server = uvicorn.Server(conf)

    def run(self):
        self.server.run()

    def stop(self):
        self.server.should_exit = True


class _WorkerImpl:
    def __init__(self, cfg):
        from odnas import db as D
        from odnas.crypto import Keyring
        from odnas.entra import MsalEntraClient
        from odnas.worker import Worker
        self.worker = Worker(cfg, D.DB(cfg.p_db), Keyring.from_config(cfg), MsalEntraClient(cfg))

    def run(self):
        self.worker.serve_forever()

    def stop(self):
        self.worker.request_stop(drain=True)


def run_service(role: str) -> None:   # pragma: no cover - needs Windows + pywin32 (lab test T-W1)
    import servicemanager
    import win32service
    import win32serviceutil

    class _Svc(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICES[role]
        _svc_display_name_ = DISPLAY[role]
        _svc_description_ = DESCRIPTION[role]

        def __init__(self, args):
            super().__init__(args)
            self.body = ServiceBody(role)
            self._done = threading.Event()

        def GetAcceptedControls(self):
            c = super().GetAcceptedControls()
            return c | SERVICE_ACCEPT_PRESHUTDOWN if role == "worker" else c

        def _pending(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING, waitHint=10000)

        def _stop(self):
            self._pending()
            self.body.stop(self._pending)
            self._done.set()

        def SvcStop(self):
            self._stop()

        def SvcShutdown(self):
            self._stop()

        def SvcOtherEx(self, control, event_type, data):
            if control == SERVICE_CONTROL_PRESHUTDOWN:
                self._stop()

        def SvcDoRun(self):
            from odnas.config import load_config
            cfg = load_config()
            setup_logging(cfg, role)
            self.body.cfg = cfg
            servicemanager.LogInfoMsg(f"{self._svc_name_} starting")
            self.body.start()
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)
            while not self._done.is_set():
                if not self.body.alive():
                    # body ended on its own (crash or refused start): exit non-zero so recovery restarts us
                    # exit the process without reporting STOPPED: the SCM counts it as a failure and the
                    # recovery actions (restart x3) apply
                    servicemanager.LogErrorMsg(f"{self._svc_name_} stopped unexpectedly: {self.body.error!r}")
                    logging.shutdown()
                    os._exit(1)
                self._done.wait(5)

    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(_Svc)
    servicemanager.StartServiceCtrlDispatcher()
