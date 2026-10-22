"""`odnas doctor`: a self-check for either host (v0.10; SPEC §11.5 install step "smoke checks").

Local checks only by default. Network checks are opt-in flags and go only to this host (loopback /healthz,
the worker's internal health) or to the NAS on TCP 445 (--nas); nothing ever goes to Microsoft or Google.
Never prints a secret; secrets are reported as present / decryptable or not.

Result: a list of Check(name, status, detail) with status ok | warn | fail | skip; exit code 1 if any fail.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

from odnas import hostos

RCLONE_VERSION = "v1.75.2"   # SPEC §9.8 pin (deploy/install.sh, deploy/windows/pins.psd1)
OK, WARN, FAIL, SKIP = "ok", "warn", "fail", "skip"


@dataclass
class Check:
    name: str
    status: str
    detail: str = ""


def _writable(d: str) -> tuple[bool, str]:
    try:
        Path(d).mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=d, prefix=".doctor-", delete=True) as fh:
            fh.write(b"x")
        return True, d
    except OSError as e:
        return False, f"{d}: {type(e).__name__}"


def check_paths(cfg) -> list[Check]:
    out = []
    for name, d in (("state", cfg.p_state), ("logs", cfg.p_log), ("run", cfg.p_run),
                    ("db_dir", str(Path(cfg.p_db).parent))):
        ok, msg = _writable(d)
        out.append(Check(f"path_{name}", OK if ok else FAIL, msg))
    return out


def check_db(cfg) -> Check:
    from odnas import db as D
    if not Path(cfg.p_db).is_file():
        return Check("db_schema", FAIL, f"no database at {cfg.p_db} (run db-upgrade)")
    v = D.DB(cfg.p_db).schema_version()
    want = len(D.MIGRATIONS)
    return Check("db_schema", OK if v == want else FAIL, f"schema {v}, code expects {want}")


def check_secrets(cfg, decrypt: bool) -> list[Check]:
    out = []
    if cfg.is_windows:
        from odnas import dpapi
        st = dpapi.status(cfg)
        for name in ("data.key", "entra-app.key"):
            s = st[name]
            out.append(Check(f"secret_{name}", OK if s == "protected" else (WARN if s == "incoming" else FAIL), s))
        g = st["google-client.secret"]
        if cfg.google_configured:
            out.append(Check("secret_google-client.secret", OK if g == "protected" else WARN, g))
        esc = Path(cfg.p_etc) / "escrow"
        try:
            pending = esc.is_dir() and any(esc.iterdir())
        except PermissionError:   # escrow\ is Administrators-only; the service account cannot look
            pending = False
        if pending:
            out.append(Check("key_escrow", WARN, f"escrow copy still on this PC ({esc}): move it to the "
                                                 "password manager / safe, then delete it here"))
    if not decrypt:
        out.append(Check("secrets_decrypt", SKIP, "not run as the service account (use --as-service)"))
        return out
    try:
        from odnas.crypto import Keyring
        kr = Keyring.from_config(cfg)
        out.append(Check("secrets_decrypt", OK, f"data key id {kr.primary_id}"))
    except Exception as e:
        out.append(Check("secrets_decrypt", FAIL, str(e)[:300]))
    return out


def _run(cmd: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    kw = {"creationflags": hostos.CREATE_NO_WINDOW} if os.name == "nt" else {}
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False, **kw)


def check_rclone(cfg, run=_run) -> list[Check]:
    from odnas.bisync import ENC
    exe = cfg.p_rclone
    if not Path(exe).is_file():
        return [Check("rclone_version", FAIL, f"{exe} not found")]
    p = run([exe, "version"])
    first = (p.stdout or "").splitlines()[0] if p.stdout else ""
    out = [Check("rclone_version", OK if first.strip() == f"rclone {RCLONE_VERSION}" else FAIL, first or p.stderr[:200])]
    with tempfile.TemporaryDirectory(dir=cfg.p_run if Path(cfg.p_run).is_dir() else None) as td:
        Path(td, "probe.txt").write_text("x")
        p = run([exe, "lsf", td, *ENC, "--config", os.devnull if os.name != "nt" else "NUL"])
        out.append(Check("rclone_local_encoding", OK if p.returncode == 0 and "probe.txt" in p.stdout else FAIL,
                         "pinned --local-encoding accepted" if p.returncode == 0 else p.stderr[-300:]))
    return out


def check_http(cfg, get=None) -> list[Check]:
    import httpx
    get = get or (lambda url: httpx.get(url, timeout=5))
    out = []
    for name, url in (("web_healthz", f"http://{cfg.web_host}:{cfg.web_port}/healthz"),
                      ("worker_health", f"{cfg.broker_base}/internal/health")):
        try:
            r = get(url)
            out.append(Check(name, OK if r.status_code == 200 else FAIL, f"HTTP {r.status_code}"))
        except Exception as e:
            out.append(Check(name, FAIL, type(e).__name__))
    return out


def check_caddy(cfg, caddy_exe: str, caddyfile: str, run=_run) -> list[Check]:
    if not Path(caddy_exe).is_file():
        return [Check("caddy", FAIL, f"{caddy_exe} not found")]
    p = run([caddy_exe, "list-modules"])
    mods = p.stdout or ""
    out = [Check("caddy_dns_module", OK if "dns.providers.googleclouddns" in mods else FAIL,
                 "googleclouddns present" if "googleclouddns" in mods else "googleclouddns missing")]
    p = run([caddy_exe, "validate", "--config", caddyfile, "--adapter", "caddyfile"])
    out.append(Check("caddy_validate", OK if p.returncode == 0 else FAIL, (p.stderr or p.stdout)[-300:].strip()))
    return out


def check_nas(host: str, port: int = 445, connect=socket.create_connection) -> Check:
    if not host:
        return Check("nas_reachable", SKIP, "no NAS host")
    try:
        with connect((host, port), timeout=5):
            return Check("nas_reachable", OK, f"{host}:{port} answers")
    except OSError as e:
        return Check("nas_reachable", FAIL, f"{host}:{port}: {type(e).__name__}")


def check_windows_host(reg=None) -> list[Check]:
    """LongPathsEnabled (SPEC §11.5 install step) via winreg."""
    try:
        reg = reg or __import__("winreg")
    except ImportError:
        return [Check("long_paths", SKIP, "not Windows")]
    try:
        k = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\FileSystem")
        v, _ = reg.QueryValueEx(k, "LongPathsEnabled")
        return [Check("long_paths", OK if int(v) == 1 else FAIL, f"LongPathsEnabled={v}")]
    except OSError:
        return [Check("long_paths", FAIL, "LongPathsEnabled not set")]


def run_all(cfg, *, decrypt: bool = False, http: bool = False, caddy_exe: str = "", caddyfile: str = "",
            nas_host: str = "", run=_run) -> list[Check]:
    checks: list[Check] = [Check("config", OK, f"host={cfg.host} slug={cfg.slug} base_url={cfg.base_url}")]
    checks += check_paths(cfg)
    try:
        checks.append(check_db(cfg))
    except Exception as e:
        checks.append(Check("db_schema", FAIL, type(e).__name__))
    checks += check_secrets(cfg, decrypt)
    checks += check_rclone(cfg, run)
    if cfg.is_windows:
        checks += check_windows_host()
    if http:
        checks += check_http(cfg)
    if caddy_exe:
        checks += check_caddy(cfg, caddy_exe, caddyfile, run)
    if nas_host:
        checks.append(check_nas(nas_host))
    free = shutil.disk_usage(cfg.p_state).free // (1024 ** 3) if Path(cfg.p_state).is_dir() else None
    if free is not None:
        checks.append(Check("disk_free", OK if free >= 5 else WARN, f"{free} GiB free on the data drive"))
    return checks


def render(checks: list[Check]) -> str:
    w = max(len(c.name) for c in checks)
    return "\n".join(f"{c.status.upper():5} {c.name:<{w}}  {c.detail}" for c in checks)


def exit_code(checks: list[Check]) -> int:
    return 1 if any(c.status == FAIL for c in checks) else 0


def write_report(cfg, checks: list[Check], name: str = "doctor.json") -> Path:
    p = Path(cfg.p_log) / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps([asdict(c) for c in checks], indent=1), encoding="utf-8")
    return p
