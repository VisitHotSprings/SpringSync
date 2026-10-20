"""Nightly maintenance (SPEC §11.3 springsync-maint) and daily backup (SPEC §10.3)."""
from __future__ import annotations

import logging
import logging.handlers
import os
import sqlite3
import tarfile
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from odnas import db as D
from odnas import settings_store
from odnas.config import Config
from odnas.notify import Alert, Alerter
from odnas.runner import sweep_runtime
from odnas.status import REMINDER_DAYS, credential_expiry, disk_free_pct, tls_cert_expiry_probe

log = logging.getLogger("odnas.maint")
REFRESH_TOKEN_MAX_AGE_DAYS = 80
RUN_LOG_RETENTION_DAYS = 30
BACKUP_KEEP = 14
# never include key material in backups (SPEC §10.3); deploy/ and creds/ also hold secrets
BACKUP_EXCLUDE_DIRS = {"keys", "creds", "deploy"}
BACKUP_EXCLUDE_FILES = {"gcp-acme-sa.json"}


def audit_to_journal(db: D.DB, since_seq: int, slug: str = "springsync") -> int:
    """Write audit entries to journald/syslog with identifier <slug>-audit (best effort)."""
    if not Path("/dev/log").exists():
        return since_seq
    h = logging.handlers.SysLogHandler(address="/dev/log")
    h.ident = f"{slug}-audit: "
    lg = logging.getLogger("odnas.audit.journal")
    lg.addHandler(h)
    last = since_seq
    for r in db.all("SELECT * FROM audit_log WHERE seq > ? ORDER BY seq", (since_seq,)):
        lg.warning("seq=%s ts=%s actor=%s action=%s target=%s hash=%s", r["seq"], r["ts"], r["actor"], r["action"],
                   r["target"], r["hash"])
        last = r["seq"]
    lg.removeHandler(h)
    return last


def prune_logs(cfg: Config, now: float | None = None) -> int:
    now = now or time.time()
    cutoff = now - RUN_LOG_RETENTION_DAYS * 86400
    n = 0
    root = Path(cfg.p_log) / "runs"
    if root.is_dir():
        for f in root.rglob("*"):
            if f.is_file() and f.stat().st_mtime < cutoff:
                f.unlink()
                n += 1
    return n


def expiry_reminders(cfg: Config, db: D.DB, alerter: Alerter, s, today: date | None = None) -> int | None:
    e = credential_expiry(cfg, s, today)
    if e.days_left is None:
        alerter.raise_(Alert("credential_expiry_unknown", "medium",
                             "Entra app credential expiry date is not set (Settings > Entra)"))
        return None
    alerter.resolve(None, "credential_expiry_unknown")
    if e.days_left < 0:
        alerter.raise_(Alert("credential_expired", "critical", f"Entra app credential EXPIRED on {e.on}"))
    else:
        for d in sorted(REMINDER_DAYS):  # smallest threshold that applies
            if e.days_left <= d:
                sev = "critical" if d <= 7 else "high" if d <= 14 else "medium"
                alerter.raise_(Alert(f"credential_expiry_{d}d", sev,
                                     f"Entra app credential expires {e.on} ({e.days_left} days left)"))
                break
    return e.days_left


def stale_refresh_tokens(db: D.DB, alerter: Alerter, now: datetime | None = None) -> int:
    """Safety net (SPEC §6.2): refresh token 80 days old with no successful refresh -> needs_reauth."""
    now = now or D.utcnow()
    n = 0
    for r in db.all("SELECT m.user_id, m.last_refresh_at, m.token_obtained_at, u.state, u.upn FROM ms_credentials m "
                    "JOIN users u ON u.id=m.user_id WHERE u.state='active'"):
        last = D.parse_iso(r["last_refresh_at"] or r["token_obtained_at"])
        if last and now - last > timedelta(days=REFRESH_TOKEN_MAX_AGE_DAYS):
            db.set_state(r["user_id"], D.NEEDS_REAUTH, "refresh token older than 80 days")
            alerter.raise_(Alert("needs_reauth", "medium", f"{r['upn']}: token not refreshed in 80 days",
                                 r["user_id"], notify_user=True))
            n += 1
    return n


def run_maint(cfg: Config, db: D.DB, alerter: Alerter, probe_tls: bool = True) -> dict:
    s = settings_store.load(db, cfg)
    out: dict = {}
    ok, n, msg = db.verify_audit_chain()
    db.beat("audit_chain", f"{'ok' if ok else 'FAILED'}: {msg} ({n} entries)")
    if not ok:
        alerter.raise_(Alert("audit_chain", "critical", f"audit hash chain verification failed: {msg}"))
    prev = db.heartbeat("audit_journal_seq")
    last = audit_to_journal(db, int(prev["detail"]) if prev else 0, cfg.slug)
    db.beat("audit_journal_seq", str(last))
    out["audit_chain"] = ok
    out["pruned_logs"] = prune_logs(cfg)
    out["swept_tmp"] = sweep_runtime(cfg)
    out["credential_days_left"] = expiry_reminders(cfg, db, alerter, s)
    out["stale_tokens"] = stale_refresh_tokens(db, alerter)
    free = disk_free_pct(cfg.p_state)
    if free is not None and free < 15:
        alerter.raise_(Alert("disk_low", "high", f"disk free {free}% on {cfg.p_state}"))
    if probe_tls:
        host = cfg.base_url.split("//", 1)[-1].split("/", 1)[0]
        exp = tls_cert_expiry_probe(host)
        if exp:
            days = (exp - datetime.now(timezone.utc)).days
            db.beat("tls_expiry", f"{exp.date()} ({days} days)")
            if days < 14:
                alerter.raise_(Alert("tls_expiry", "high", f"TLS certificate expires in {days} days"))
    # Entra group re-check for offboarding needs app-only User.Read.All: OPEN (SPEC §6.3), not implemented.
    db.audit("system", "maint_run", "", {k: v for k, v in out.items()})
    return out


def _tar_filter(ti: tarfile.TarInfo) -> tarfile.TarInfo | None:
    parts = Path(ti.name).parts
    if any(p in BACKUP_EXCLUDE_DIRS for p in parts) or Path(ti.name).name in BACKUP_EXCLUDE_FILES:
        return None
    if Path(ti.name).suffix in (".key", ".cred", ".pem") or Path(ti.name).name.startswith("id_"):
        return None
    return ti


def run_backup(cfg: Config, db: D.DB, out_dir: str | None = None, extra_dirs: tuple[str, ...] = ("/etc/caddy",),
               tag: str = "") -> list[Path]:
    """sqlite .backup + tar of config dirs excluding key material; keep 14 of each."""
    out = Path(out_dir or f"{cfg.p_state}/backups")
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    stamp = tag or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    dbfile = out / f"db-{stamp}.sqlite"
    src = sqlite3.connect(cfg.p_db)
    dst = sqlite3.connect(dbfile)
    with dst:
        src.backup(dst)
    dst.execute("PRAGMA journal_mode=DELETE")  # single self-contained file
    dst.close()
    src.close()
    os.chmod(dbfile, 0o600)
    tarpath = out / f"config-{stamp}.tar.gz"
    with tarfile.open(tarpath, "w:gz") as tf:
        for d in (cfg.p_etc, *extra_dirs):
            if Path(d).is_dir():
                tf.add(d, arcname=Path(d).name, filter=_tar_filter)
    os.chmod(tarpath, 0o600)
    for prefix in ("db-", "config-"):
        files = sorted((p for p in out.glob(prefix + "2*")),  # timestamped only; pre-<tag> backups are kept
                       key=lambda p: p.stat().st_mtime)
        for old in files[:-BACKUP_KEEP]:
            old.unlink()
    db.audit("system", "backup_written", "", {"files": [dbfile.name, tarpath.name]})
    # Copy to the IT-only NAS share (IT-Backups/<slug>) is NOT implemented in v0.1: needs a dedicated
    # backup credential and share decision (see OPEN-QUESTIONS.md).
    return [dbfile, tarpath]
