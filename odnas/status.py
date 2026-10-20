"""Read-only status helpers shared by the admin and auditor views and maint."""
from __future__ import annotations

import shutil
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path

from odnas.config import CRED_CERT, Config
from odnas.db import DB, parse_iso, utcnow

REMINDER_DAYS = (60, 30, 14, 7, 1)


@dataclass
class Expiry:
    on: date | None
    days_left: int | None
    source: str

    @property
    def level(self) -> str:
        if self.days_left is None:
            return "unknown"
        if self.days_left < 0:
            return "expired"
        if self.days_left <= 14:
            return "critical"
        if self.days_left <= 60:
            return "warning"
        return "ok"


def credential_expiry(cfg: Config, s, today: date | None = None) -> Expiry:
    today = today or datetime.now(timezone.utc).date()
    if cfg.credential_type == CRED_CERT and cfg.cert_path and Path(cfg.cert_path).is_file():
        from odnas.entra import certificate_expiry
        d = certificate_expiry(Path(cfg.cert_path).read_bytes()).date()
        return Expiry(d, (d - today).days, "certificate")
    if s.entra_credential_expires_on:
        d = date.fromisoformat(s.entra_credential_expires_on)
        return Expiry(d, (d - today).days, "settings")
    return Expiry(None, None, "not set")


def disk_free_pct(path: str) -> float | None:
    try:
        u = shutil.disk_usage(path)
        return round(100.0 * u.free / u.total, 1)
    except OSError:
        return None


def worker_alive(db: DB, max_age_s: int = 180) -> tuple[bool, str | None]:
    hb = db.heartbeat("worker")
    if not hb:
        return False, None
    return (utcnow() - parse_iso(hb["ts"])).total_seconds() < max_age_s, hb["ts"]


def tls_cert_expiry_probe(host: str, port: int = 443, connect: str = "127.0.0.1") -> datetime | None:
    """Called only by maint (never in a web request). Reads the cert Caddy serves locally."""
    import socket
    import ssl
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((connect, port), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                na = ss.getpeercert()["notAfter"]
        return datetime.fromtimestamp(ssl.cert_time_to_seconds(na), timezone.utc)
    except (OSError, ssl.SSLError, KeyError):
        return None
