"""Command line: `odnas <command>` (installed as /usr/local/bin/<slug>)."""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time


def _ctx():
    from odnas import db as D
    from odnas.config import load_config
    from odnas.crypto import Keyring
    cfg = load_config()
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
    sub.add_parser("verify-audit")
    n = sub.add_parser("notify"); n.add_argument("--unit", required=True)
    sub.add_parser("rekey")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format='{"level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}')

    if a.cmd == "web":
        import uvicorn
        from odnas.config import load_config
        cfg = load_config()
        host, port = (a.bind.rsplit(":", 1) if a.bind else (cfg.web_host, str(cfg.web_port)))
        if host not in ("127.0.0.1", "::1"):
            print("refusing to bind web to a non-loopback address", file=sys.stderr)
            return 2
        uvicorn.run("odnas.web.app:build_from_env", factory=True, host=host, port=int(port), proxy_headers=True,
                    forwarded_allow_ips="127.0.0.1", access_log=False)
        return 0
    if a.cmd == "worker":
        cfg, db, kr = _ctx()
        from pathlib import Path
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
    if a.cmd == "rekey":
        cfg, db, kr = _ctx()
        from odnas.rekey import rekey_all
        print(json.dumps(rekey_all(db, kr)))
        return 0
    return 2
