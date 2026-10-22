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


PROVIDER_NAMES = ("onedrive", "gdrive")       # odnas.cloud.PROVIDERS (kept here to avoid an import cycle)
DIRECTION_NAMES = ("two_way", "pull_copy", "pull_mirror")   # odnas.cloud.DIRECTIONS
EXPORT_FORMATS = ("docx", "xlsx", "pptx", "svg", "odt", "ods", "odp", "pdf", "rtf", "txt", "csv", "html", "epub",
                  "jpg", "png", "zip", "tsv")   # rclone drive export extensions we allow (rclone.org/drive)


def _providers(v: str) -> str:
    items = {x.strip().lower() for x in re.split(r"[,\s;]+", str(v or "")) if x.strip()}
    bad = items - set(PROVIDER_NAMES)
    if bad:
        raise ValueError("unknown provider(s): " + ", ".join(sorted(bad)) + " (use onedrive, gdrive)")
    if not items:
        raise ValueError("enable at least one provider")
    return ",".join(p for p in PROVIDER_NAMES if p in items)


def _domain(v: str) -> str:
    d = str(v or "").strip().lower().lstrip("@")
    if not HOST_RE.match(d) or "." not in d:
        raise ValueError(f"not a domain name: {d}")
    return d


def _direction(v: str) -> str:
    v = str(v or "").strip().lower().replace("-", "_").replace(" ", "_")
    if v not in DIRECTION_NAMES:
        raise ValueError("two_way, pull_copy (one-way: Copy only) or pull_mirror (one-way: Mirror)")
    return v


def _gdocs(v: str) -> str:
    v = str(v or "").strip().lower()
    if v not in ("skip", "export"):
        raise ValueError("skip or export")
    return v


def _formats(v: str) -> str:
    items = [x.strip().lower().lstrip(".") for x in re.split(r"[,\s;]+", str(v or "")) if x.strip()]
    bad = [x for x in items if x not in EXPORT_FORMATS]
    if bad or not items:
        raise ValueError("comma-separated rclone export extensions, e.g. docx,xlsx,pptx,svg")
    return ",".join(dict.fromkeys(items))


def _aliases(v: str) -> str:
    """Approved Google email aliases (SPEC v0.9 §4.4, §14.24): one `upn = google-email` per line."""
    out = []
    for raw in str(v or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.count("=") != 1:
            raise ValueError(f"use 'upn = google-email' per line: {line}")
        a, b = (x.strip().lower() for x in line.split("="))
        if not EMAIL_RE.match(a) or not EMAIL_RE.match(b):
            raise ValueError(f"not an email address in: {line}")
        out.append(f"{a} = {b}")
    return "\n".join(sorted(set(out)))


def _backup_target(v: str) -> str:
    v = str(v or "").strip().lower()
    if v not in ("backup_nas", "same_share"):
        raise ValueError("backup_nas (UNAS #2 share) or same_share (.springsync-archive on the user's share)")
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
    "nas_health_share": Spec("NAS", "Health-check share (option B; svc-sync only)", _share, "Sync-Health",
                             help="Used for the svc-sync test mount after a password change and the periodic NAS "
                                  "health check. Only svc-sync may reach it; no user's Home share is touched."),
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
    # Cloud providers and sync direction (v0.9, SPEC §4.4, §6.6)
    "providers_enabled": Spec("Cloud", "Enabled cloud providers", _providers, "onedrive,gdrive",
                              help="onedrive, gdrive or both. Users of a disabled provider are paused (no runs, a "
                                   "banner on their page); nothing is deleted."),
    "default_direction": Spec("Cloud", "Default sync direction for new users", _direction, "two_way",
                              help="two_way (bisync), pull_copy (one-way, Copy only: never deletes on the NAS) or "
                                   "pull_mirror (one-way, Mirror: NAS files missing from the cloud are moved to the "
                                   "backup target). Existing users keep theirs; change them on the user's page."),
    "pull_backup_target": Spec("Cloud", "Backup target for one-way runs", _backup_target, "backup_nas",
                               help="backup_nas = the Sync-Archive share on the backup NAS (needs Mark's OK to "
                                    "create). same_share = .springsync-archive on the user's own share. One-way runs "
                                    "never run without a reachable, writable backup target."),
    "backup_nas_host": Spec("Cloud", "Backup NAS address", lambda v: _host(v) if str(v).strip() else "", ""),
    "backup_nas_share": Spec("Cloud", "Backup NAS share", _share, "Sync-Archive"),
    "backup_nas_username": Spec("Cloud", "Backup NAS service login", _free, ""),
    "backup_nas_password": Spec("Cloud", "Backup NAS service password", _free, "", secret=True),
    "gdrive_users": Spec("Cloud", "Users whose cloud drive is Google Drive (UPNs, one per line)", _upns, "",
                         help="Applied when the user first signs in (with Microsoft); afterwards change the provider "
                              "on the user's page. Everyone else connects OneDrive."),
    # Google (v0.9, SPEC §4.3). The client ID is in the bootstrap file, the secret is a credential file.
    "google_allowed_domain": Spec("Google", "Allowed Google Workspace domain", _domain, "hotsprings.org",
                                  help="Connect Google Drive needs hd == this domain, a verified email, and the email "
                                       "equal to the user's Microsoft UPN (or an approved alias below)."),
    "google_email_aliases": Spec("Google", "Approved Google email aliases (upn = google-email, one per line)",
                                 _aliases, ""),
    "google_gdocs_default": Spec("Google", "Google-native files for new users", _gdocs, "skip",
                                 help="skip (default). export only applies to one-way users; two-way never exports."),
    "google_export_formats": Spec("Google", "Export formats (one-way export only)", _formats, "docx,xlsx,pptx,svg"),
    "google_client_secret_expires_on": Spec("Google", "Google client secret: rotate by (YYYY-MM-DD)",
                                            _date_or_empty, ""),
    "google_signin_ms_max_age_days": Spec(
        "Google", "Sign in with Google: require a Microsoft sign-in every (days)", _int(1, 90), 7,
        help="A Google session gets no access until the person signs in with Microsoft again once this many days have "
             "passed since their last Microsoft sign-in (SPEC §14.38-§14.41, pending Mark). Admin and Auditor need a "
             "Microsoft sign-in within 24 h."),
    # Entra
    "group_users": Spec("Entra", "Users group object ID", _guid_or_empty, ""),
    "group_admins": Spec("Entra", "Admins group object ID", _guid_or_empty, ""),
    "group_auditors": Spec("Entra", "Auditors group object ID", _guid_or_empty, ""),
    "entra_credential_expires_on": Spec("Entra", "App credential expiry (YYYY-MM-DD)", _date_or_empty, "",
                                        help="Auto-read from the certificate when one is configured."),
}
BOOL_KEYS = {k for k, s in SPECS.items() if s.parse is _bool}
LIST_KEYS = {"pilot_list", "gdrive_users", "google_email_aliases"}   # shown as textareas


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

    def providers(self) -> set[str]:
        return {x for x in self._v["providers_enabled"].split(",") if x}

    def gdrive_user_set(self) -> set[str]:
        return {x for x in self._v["gdrive_users"].split("\n") if x}

    def google_aliases(self) -> dict[str, set[str]]:
        out: dict[str, set[str]] = {}
        for line in self._v["google_email_aliases"].split("\n"):
            if "=" in line:
                a, b = (x.strip() for x in line.split("="))
                out.setdefault(a, set()).add(b)
        return out

    def as_public_dict(self) -> dict[str, Any]:
        return {k: ("***" if SPECS[k].secret else v) for k, v in self._v.items()}


def _bootstrap_defaults(cfg: Config) -> dict[str, Any]:
    d = {k: s.default for k, s in SPECS.items()}
    d.update(nas_host=cfg.nas_host or d["nas_host"], nas_share=cfg.nas_share or d["nas_share"],
             group_users=cfg.group_users.lower(), group_admins=cfg.group_admins.lower(),
             group_auditors=cfg.group_auditors.lower(),
             google_allowed_domain=(getattr(cfg, "google_allowed_domain", "") or d["google_allowed_domain"]).lower())
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
