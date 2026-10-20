"""GUI-editable settings (SPEC §6.4). Stored in the `settings` table as JSON;
secret values are AES-GCM sealed (is_secret=1) and can only be replaced, never
read back through the UI. Every change is validated and audited (secrets as ***).
The worker reloads settings on every tick, so changes apply without a restart.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import date, time
from typing import Any, Callable

from odnas.config import Config, GUID_RE
from odnas.crypto import Keyring
from odnas.db import DB, iso, pack, unpack, utcnow

HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$")
SHARE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,79}$")
EMAIL_RE = re.compile(r"^[^@\s,;<>]+@[^@\s,;<>]+\.[A-Za-z]{2,}$")
HHMM_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


def _host(v: str) -> str:
    v = v.strip()
    if not HOST_RE.match(v):
        raise ValueError("must be a hostname or IPv4 address (no \\\\, slashes or spaces)")
    return v


def _share(v: str) -> str:
    v = v.strip()
    if not SHARE_RE.match(v):
        raise ValueError("share name: letters, digits, space, _ . - (max 80)")
    return v


def _template(v: str) -> str:
    v = v.strip()
    if v.count("{user}") != 1 or not SHARE_RE.match(v.replace("{user}", "x")):
        raise ValueError("must contain {user} exactly once, e.g. Home-{user}")
    return v


def _int(lo: int, hi: int) -> Callable[[str], int]:
    def f(v: str) -> int:
        n = int(str(v).strip())
        if not lo <= n <= hi:
            raise ValueError(f"must be between {lo} and {hi}")
        return n
    return f


def _bool(v: Any) -> bool:
    return v if isinstance(v, bool) else str(v).strip().lower() in ("1", "true", "on", "yes")


def _emails(v: str) -> str:
    items = [x.strip() for x in re.split(r"[,\s;]+", v or "") if x.strip()]
    for a in items:
        if not EMAIL_RE.match(a):
            raise ValueError(f"not an email address: {a}")
    return ", ".join(items)


def _upns(v: str) -> str:
    items = sorted({x.strip().lower() for x in re.split(r"[,\s;]+", v or "") if x.strip()})
    for a in items:
        if not EMAIL_RE.match(a):
            raise ValueError(f"not a UPN: {a}")
    return "\n".join(items)


def _guid_or_empty(v: str) -> str:
    v = (v or "").strip()
    if v and not GUID_RE.match(v):
        raise ValueError("must be a group object ID (GUID)")
    return v.lower()


def _date_or_empty(v: str) -> str:
    v = (v or "").strip()
    if v:
        date.fromisoformat(v)
    return v


def _hours(v: str) -> str:
    v = (v or "").strip()
    if not v:
        return ""
    m = re.match(r"^(\d\d:\d\d)-(\d\d:\d\d)$", v)
    if not m or not all(HHMM_RE.match(x) for x in m.groups()) or m.group(1) == m.group(2):
        raise ValueError("format HH:MM-HH:MM, e.g. 06:00-22:00 (empty = always)")
    return v


def _hhmm(v: str) -> str:
    v = v.strip()
    if not HHMM_RE.match(v):
        raise ValueError("format HH:MM")
    return v


def _option(v: str) -> str:
    v = v.strip().upper()
    if v not in ("A", "B"):
        raise ValueError("A (Personal-Drive, user's own login) or B (Home-<user> shared drive + svc-sync)")
    return v


def _bwlimit(v: str) -> str:
    v = (v or "").strip()
    if v and not re.match(r"^\d+(\.\d+)?[KMG]?$", v):
        raise ValueError("rclone --bwlimit value like 20M (empty = unlimited)")
    return v


def _free(v: str) -> str:
    v = (v or "").strip()
    if len(v) > 256 or any(c in v for c in "\r\n\x00"):
        raise ValueError("too long or contains control characters")
    return v


@dataclass(frozen=True)
class Spec:
    group: str
    label: str
    parse: Callable[[Any], Any]
    default: Any
    secret: bool = False
    help: str = ""


SPECS: dict[str, Spec] = {
    # NAS
    "nas_option": Spec("NAS", "NAS access option", _option, "A",
                       help="A = user's own Personal-Drive login (pilot). B = Home-<user> shared drive + svc-sync."),
    "nas_host": Spec("NAS", "NAS address", _host, "unas.hotsprings.local"),
    "nas_share": Spec("NAS", "Personal-Drive share name (option A)", _share, "Personal-Drive"),
    "nas_shared_template": Spec("NAS", "Shared-drive name template (option B)", _template, "Home-{user}"),
    "nas_svc_username": Spec("NAS", "svc-sync username (option B)", _free, "svc-sync"),
    "nas_svc_password": Spec("NAS", "svc-sync password (option B)", _free, "", secret=True),
    "nas_domain": Spec("NAS", "SMB domain (usually empty)", _free, ""),
    # Schedule
    "default_interval_min": Spec("Schedule", "Default interval (minutes)", _int(15, 1440), 30),
    "active_hours": Spec("Schedule", "Active hours (America/Chicago)", _hours, ""),
    "max_concurrent": Spec("Schedule", "Max concurrent jobs", _int(1, 4), 2),
    "run_time_limit_min": Spec("Schedule", "Run time limit, incremental (minutes)", _int(5, 240), 25),
    "resync_bwlimit": Spec("Schedule", "Initial resync --bwlimit", _bwlimit, ""),
    "resync_hours": Spec("Schedule", "Initial/approved resync window (outside business hours)", _hours, "18:00-07:00"),
    "stale_hours": Spec("Schedule", "Staleness alert after (hours)", _int(1, 720), 24),
    # Safety
    "default_max_delete_pct": Spec("Safety", "Default --max-delete (%)", _int(1, 50), 10),
    "check_weekday": Spec("Safety", "Weekly rclone check day (0=Mon .. 6=Sun)", _int(0, 6), 6),
    "check_time": Spec("Safety", "Weekly rclone check time", _hhmm, "03:00"),
    # Alerts (email delivery is a stub in v0.1: SPEC §14.5 open)
    "alert_recipients": Spec("Alerts", "Alert email recipients", _emails, ""),
    "smtp_host": Spec("Alerts", "SMTP host", lambda v: _host(v) if str(v).strip() else "", ""),
    "smtp_port": Spec("Alerts", "SMTP port", _int(1, 65535), 587),
    "smtp_starttls": Spec("Alerts", "SMTP STARTTLS", _bool, True),
    "smtp_username": Spec("Alerts", "SMTP username", _free, ""),
    "smtp_password": Spec("Alerts", "SMTP password", _free, "", secret=True),
    # Pilot
    "pilot_only": Spec("Pilot", "Pilot-only mode", _bool, True),
    "pilot_list": Spec("Pilot", "Pilot UPNs (one per line)", _upns, ""),
    # Entra
    "group_users": Spec("Entra", "Users group object ID", _guid_or_empty, ""),
    "group_admins": Spec("Entra", "Admins group object ID", _guid_or_empty, ""),
    "group_auditors": Spec("Entra", "Auditors group object ID", _guid_or_empty, ""),
    "entra_credential_expires_on": Spec("Entra", "App credential expiry (YYYY-MM-DD)", _date_or_empty, "",
                                        help="Auto-read from the certificate when one is configured."),
}
BOOL_KEYS = {k for k, s in SPECS.items() if s.parse is _bool}


class Settings:
    """Read-only snapshot. Secrets are exposed only via secret()."""

    def __init__(self, values: dict[str, Any], secrets: dict[str, str], meta: dict[str, dict]):
        self._v, self._s, self.meta = values, secrets, meta

    def __getattr__(self, k: str) -> Any:
        try:
            return self._v[k]
        except KeyError:
            raise AttributeError(k) from None

    def __getitem__(self, k: str) -> Any:
        return self._v[k]

    def secret(self, k: str) -> str:
        return self._s.get(k, "")

    def secret_is_set(self, k: str) -> bool:
        return bool(self._s.get(k))

    def pilot_set(self) -> set[str]:
        return {x for x in self._v["pilot_list"].split("\n") if x}

    def as_public_dict(self) -> dict[str, Any]:
        return {k: ("***" if SPECS[k].secret else v) for k, v in self._v.items()}


def _bootstrap_defaults(cfg: Config) -> dict[str, Any]:
    d = {k: s.default for k, s in SPECS.items()}
    d.update(nas_host=cfg.nas_host or d["nas_host"], nas_share=cfg.nas_share or d["nas_share"],
             group_users=cfg.group_users.lower(), group_admins=cfg.group_admins.lower(),
             group_auditors=cfg.group_auditors.lower())
    return d


def load(db: DB, cfg: Config, kr: Keyring | None = None) -> Settings:
    values = _bootstrap_defaults(cfg)
    secrets: dict[str, str] = {}
    meta: dict[str, dict] = {}
    for r in db.all("SELECT * FROM settings"):
        k = r["key"]
        if k not in SPECS:
            continue
        meta[k] = {"updated_by": r["updated_by"], "updated_at": r["updated_at"]}
        if r["is_secret"]:
            values[k] = ""
            if kr is not None:
                blob = bytes.fromhex(json.loads(r["value_json"]))
                secrets[k] = kr.open(unpack(blob, r["key_id"]), Keyring.aad("settings", k, "value"))
        else:
            try:
                values[k] = SPECS[k].parse(json.loads(r["value_json"]))
            except (ValueError, TypeError):
                pass
    for k, s in SPECS.items():
        if s.secret:
            values[k] = ""
    return Settings(values, secrets, meta)


def update(db: DB, cfg: Config, kr: Keyring, form: dict[str, Any], actor: str) -> list[str]:
    """Validate the whole form first; write and audit only changed keys. Empty secret = keep."""
    current = load(db, cfg, kr)
    parsed: dict[str, Any] = {}
    errors = []
    for k, spec in SPECS.items():
        if k in BOOL_KEYS and f"{k}__present" in form:
            raw = form.get(k, "off")
        elif k in form:
            raw = form[k]
        else:
            continue
        if spec.secret and not str(raw):
            continue
        try:
            parsed[k] = spec.parse(raw)
        except (ValueError, TypeError) as e:
            errors.append(f"{spec.label}: {e}")
    if errors:
        raise ValueError("; ".join(errors))
    changed = []
    now = iso(utcnow())
    for k, val in parsed.items():
        spec = SPECS[k]
        if spec.secret:
            if val == current.secret(k):
                continue
            s = kr.seal(val, Keyring.aad("settings", k, "value"))
            db.q("INSERT INTO settings(key, value_json, is_secret, key_id, updated_by, updated_at) VALUES (?,?,1,?,?,?) "
                 "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, is_secret=1, key_id=excluded.key_id,"
                 " updated_by=excluded.updated_by, updated_at=excluded.updated_at",
                 (k, json.dumps(pack(s).hex()), s.key_id, actor, now))
            db.audit(actor, "setting_changed", k, {"old": "***", "new": "***"})
        else:
            old = getattr(current, k)
            if val == old:
                continue
            db.q("INSERT INTO settings(key, value_json, is_secret, updated_by, updated_at) VALUES (?,?,0,?,?) "
                 "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_by=excluded.updated_by, "
                 "updated_at=excluded.updated_at", (k, json.dumps(val), actor, now))
            db.audit(actor, "setting_changed", k, {"old": old, "new": val})
        changed.append(k)
    return changed


def active_window(s: Settings) -> tuple[time, time] | None:
    if not s.active_hours:
        return None
    a, b = s.active_hours.split("-")
    return time.fromisoformat(a), time.fromisoformat(b)


def active_window_for(spec: str) -> tuple[time, time] | None:
    if not spec:
        return None
    a, b = spec.split("-")
    return time.fromisoformat(a), time.fromisoformat(b)
