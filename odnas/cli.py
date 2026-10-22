"""Command line: `odnas <command>` (installed as /usr/local/bin/<slug>)."""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time


def _host_startup(cfg) -> None:
    """Windows: protect any secrets waiting in keys\\incoming before anything reads them (SPEC §11.5.4)."""
    if cfg.is_windows:
        from odnas import dpapi
        for name in dpapi.ingest_incoming(cfg):
            logging.getLogger("odnas.cli").info("secret %s protected with DPAPI", name)


def _ctx():
    from odnas import db as D
    from odnas.config import load_config
    from odnas.crypto import Keyring
    cfg = load_config()
    _host_startup(cfg)
    return cfg, D.DB(cfg.p_db), Keyring.from_config(cfg)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="odnas")
    sub = ap.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("web"); w.add_argument("--bind", default="")
    wk = sub.add_parser("worker"); wk.add_argument("action", nargs="?", default="run", choices=["run", "drain", "undrain"])
    wk.add_argument("--timeout", type=int, default=1800)
    sub.add_parser("maint")
    b = sub.add_parser("backup"); b.add_argument("--tag", default="")
    sub.add_parser("db-upgrade")
    sub.add_parser("check-config")
    sub.add_parser("nas-info")
    sub.add_parser("verify-audit")
    n = sub.add_parser("notify"); n.add_argument("--unit", required=True)
    sub.add_parser("rekey")
    d = sub.add_parser("doctor", help="self-check of this host (v0.10)")
    d.add_argument("--as-service", action="store_true", help="also decrypt the secrets (run as the service account)")
    d.add_argument("--http", action="store_true", help="also check web /healthz and the worker on loopback")
    d.add_argument("--caddy-exe", default=""); d.add_argument("--caddyfile", default="")
    d.add_argument("--nas-host", default="", help="also check TCP 445 on this NAS host")
    d.add_argument("--json", action="store_true")
    ae = sub.add_parser("audit-event", help="append one system audit entry (deploy scripts; DB only, no keys)")
    ae.add_argument("action", choices=["deploy", "rollback", "install", "uninstall"])
    ae.add_argument("target"); ae.add_argument("--from", dest="from_", default="")
    sub.add_parser("keygen", help="create data.key and the Entra certificate if missing (Windows installer)")
    sc = sub.add_parser("secrets"); sc.add_argument("action", choices=["ingest", "status"])
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format='{"level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}')

    if a.cmd == "web":
        import uvicorn
        from odnas.config import load_config
        cfg = load_config()
        _host_startup(cfg)
        host, port = (a.bind.rsplit(":", 1) if a.bind else (cfg.web_host, str(cfg.web_port)))
        if host not in ("127.0.0.1", "::1"):
            print("refusing to bind web to a non-loopback address", file=sys.stderr)
            return 2
        uvicorn.run("odnas.web.app:build_from_env", factory=True, host=host, port=int(port), proxy_headers=True,
                    forwarded_allow_ips="127.0.0.1", access_log=False)
        return 0
    if a.cmd == "worker":
        from pathlib import Path
        from odnas.config import load_config
        cfg = load_config()      # drain/undrain need no keys (update.ps1 runs them as an Administrator)
        flag = Path(cfg.p_state) / "drain"
        if a.action == "drain":
            flag.touch()
            import httpx
            deadline = time.time() + a.timeout
            while time.time() < deadline:
                try:
                    if httpx.get(f"{cfg.broker_base}/internal/health", timeout=5).json().get("running", 0) == 0:
                        print("drained")
                        return 0
                except Exception:
                    print("worker not reachable; treating as drained")
                    return 0
                time.sleep(10)
            print("timed out waiting for running jobs", file=sys.stderr)
            return 1
        if a.action == "undrain":
            flag.unlink(missing_ok=True)
            return 0
        from odnas.entra import MsalEntraClient
        from odnas.worker import Worker
        cfg, db, kr = _ctx()
        Worker(cfg, db, kr, MsalEntraClient(cfg)).serve_forever()
        return 0
    if a.cmd == "maint":
        cfg, db, kr = _ctx()
        from odnas.maint import run_maint
        from odnas.notify import Alerter
        print(json.dumps(run_maint(cfg, db, Alerter(db)), default=str))
        return 0
    if a.cmd == "backup":
        from odnas import db as D
        from odnas.config import load_config
        from odnas.maint import run_backup
        cfg = load_config()
        for p in run_backup(cfg, D.DB(cfg.p_db), tag=a.tag):
            print(p)
        return 0
    if a.cmd == "db-upgrade":
        from odnas import db as D
        from odnas.config import load_config
        cfg = load_config()
        print("schema version", D.DB(cfg.p_db).migrate())
        return 0
    if a.cmd == "check-config":
        cfg, db, kr = _ctx()
        print(f"ok: {cfg.product_name} slug={cfg.slug} token_mode={cfg.token_mode} credential={cfg.credential_type} "
              f"key_id={kr.primary_id} schema={db.schema_version()}")
        return 0
    if a.cmd == "nas-info":
        print(nas_info(*_nas_ctx()))
        return 0
    if a.cmd == "verify-audit":
        _, db, _ = _ctx()
        ok, n, msg = db.verify_audit_chain()
        print(msg, n)
        return 0 if ok else 1
    if a.cmd == "notify":
        _, db, _ = _ctx()
        from odnas.notify import Alert, Alerter
        Alerter(db).raise_(Alert("unit_failed", "critical", f"systemd unit failed: {a.unit}"))
        return 0
    if a.cmd == "doctor":
        from odnas import doctor
        from odnas.config import load_config
        cfg = load_config()
        if a.as_service:
            _host_startup(cfg)
        checks = doctor.run_all(cfg, decrypt=a.as_service, http=a.http, caddy_exe=a.caddy_exe,
                                caddyfile=a.caddyfile, nas_host=a.nas_host)
        try:
            doctor.write_report(cfg, checks)
        except OSError:
            pass
        print(json.dumps([c.__dict__ for c in checks], indent=1) if a.json else doctor.render(checks))
        return doctor.exit_code(checks)
    if a.cmd == "audit-event":
        from odnas import db as D
        from odnas.config import load_config
        cfg = load_config()
        D.DB(cfg.p_db).audit("system", a.action, a.target, {"from": a.from_, "host": cfg.host})
        return 0
    if a.cmd == "keygen":
        from odnas.config import load_config
        from odnas.keygen import keygen
        for line in keygen(load_config()):
            print(line)
        return 0
    if a.cmd == "secrets":
        from odnas import dpapi
        from odnas.config import load_config
        cfg = load_config()
        if a.action == "ingest":
            print("ingested:", ", ".join(dpapi.ingest_incoming(cfg)) or "nothing")
        else:
            for k, v in dpapi.status(cfg).items():
                print(f"{k:24} {v}")
        return 0
    if a.cmd == "rekey":
        cfg, db, kr = _ctx()
        from odnas.rekey import rekey_all
        print(json.dumps(rekey_all(db, kr)))
        return 0
    return 2


def _nas_ctx():
    from odnas import db as D
    from odnas.config import load_config
    cfg = load_config()
    return D.DB(cfg.p_db), cfg


def nas_info(db, cfg) -> str:
    """Non-secret NAS settings for install.sh's reminder (SPEC v0.7 §11.2 step 13). Never decrypts."""
    from odnas import settings_store
    s = settings_store.load(db, cfg)
    saved = db.one("SELECT 1 FROM settings WHERE key='nas_health_share'") is not None
    return f"option={s.nas_option} health_share={s.nas_health_share} health_share_configured={int(saved)}"
