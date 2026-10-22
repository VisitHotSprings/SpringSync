r"""Bootstrap configuration (SPEC §8.2).

Source order: built-in defaults < /etc/<slug>/<slug>.toml (Windows:
%ProgramData%\SpringSync\<slug>.toml) < ODNAS_* env vars.
The bootstrap file holds NO secrets. Secrets are read from files delivered by
systemd LoadCredentialEncrypted= ($CREDENTIALS_DIRECTORY), on Windows from
DPAPI-protected files in the keys directory (SPEC §11.5.4, odnas/dpapi.py), or,
for local dev, from an explicit key directory. Everything operational lives in the DB settings
table and is edited in the admin GUI (odnas/settings_store.py).
"""
from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path

SLUG_RE = re.compile(r"^[a-z][a-z0-9-]{1,30}\Z")
GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")
DELEGATED_SCOPES = ("Files.ReadWrite", "User.Read")  # MSAL adds openid/profile/offline_access
RCLONE_ACCESS_SCOPES = "Files.ReadWrite offline_access"

REPO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}\Z")
GOOGLE_CLIENT_ID_RE = re.compile(r"^[0-9]{6,20}-[a-z0-9]{10,64}\.apps\.googleusercontent\.com\Z")
GOOGLE_SECRET_FILE = "google-client.secret"   # systemd credential google-client.secret.cred; never in the repo/DB

CRED_CERT = "certificate"
CRED_SECRET = "secret"
TOKEN_MODE_BROKER = "broker"        # SPEC §2/§9.2: rclone refreshes via local broker with a per-run handle [T-A3]
TOKEN_MODE_TMPFS = "tmpfs_config"   # fallback: real refresh token + client secret in a per-run tmpfs config


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Config:
    # [app]
    product_name: str = "SpringSync"
    slug: str = "springsync"
    org_name: str = "VisitHotSprings"
    base_url: str = "https://sync.hotsprings.org"
    web_host: str = "127.0.0.1"
    web_port: int = 8080
    broker_host: str = "127.0.0.1"
    broker_port: int = 8081
    cookie_secure: bool = True
    host_os: str = ""            # v0.10: "" = the OS we run on; "linux" | "windows" (forcing is for tests)
    internal_timers: str = ""    # v0.10: "" = on for Windows (no systemd timers, SPEC §11.5.5); "on" | "off"
    # [entra]
    tenant_id: str = ""
    client_id: str = ""
    redirect_path: str = "/auth/callback"
    credential_type: str = CRED_CERT
    cert_path: str = ""          # public cert (.crt, 0444); private key comes from credentials
    token_mode: str = TOKEN_MODE_BROKER
    allowed_upn_domain: str = ""
    group_users: str = ""        # bootstrap group object IDs; GUI settings override
    group_admins: str = ""
    group_auditors: str = ""
    # [google] (v0.9). The OAuth client SECRET is never config: it is the credential file google-client.secret.
    google_client_id: str = ""
    google_allowed_domain: str = ""   # bootstrap default for the google_allowed_domain setting (SPEC §8.2)
    google_redirect_path: str = "/auth/google/callback"
    # [paths] (empty = derived from slug)
    db_path: str = ""
    state_dir: str = ""
    log_dir: str = ""
    runtime_dir: str = ""
    mount_root: str = ""
    keys_dir: str = ""           # dev fallback when $CREDENTIALS_DIRECTORY is unset
    etc_dir: str = ""
    release_root: str = ""
    filters_template: str = ""
    rclone_bin: str = ""         # "" = /usr/local/bin/rclone (Linux) or <Program Files>\SpringSync\bin\rclone.exe
    mount_helper: str = ""
    # [nas] bootstrap defaults (GUI settings override)
    nas_host: str = "unas.hotsprings.local"
    nas_share: str = "Personal-Drive"
    # [auto_update] (v0.11, SPEC §11.4.1). Off by default; only the server's local config can turn it on.
    auto_update_enabled: bool = False
    auto_update_repo: str = "VisitHotSprings/SpringSync"   # public GitHub repo whose releases are checked
    auto_update_require_signed_tags: bool = False         # turn on once tag signing exists (§11.4 step 1)
    auto_update_allowed_signers: str = ""                 # ssh allowed-signers file for `git verify-tag`

    # ---- derived -------------------------------------------------------
    def _d(self, value: str, default: str) -> str:
        return value or default

    @property
    def host(self) -> str:
        from odnas.hostos import current_os
        return self.host_os or current_os()
    @property
    def is_windows(self) -> bool: return self.host == "windows"
    @property
    def timers_in_worker(self) -> bool:
        return self.internal_timers == "on" or (self.internal_timers == "" and self.is_windows)

    def _def(self, key: str) -> str:
        from odnas.hostos import default_paths
        return default_paths(self.host, self.slug)[key]

    @property
    def p_db(self) -> str: return self._d(self.db_path, self._def("db"))
    @property
    def p_state(self) -> str: return self._d(self.state_dir, self._def("state"))
    @property
    def p_log(self) -> str: return self._d(self.log_dir, self._def("log"))
    @property
    def p_run(self) -> str: return self._d(self.runtime_dir, self._def("run"))
    @property
    def p_mnt(self) -> str: return self._d(self.mount_root, self._def("mnt"))
    @property
    def p_etc(self) -> str: return self._d(self.etc_dir, self._def("etc"))
    @property
    def p_keys(self) -> str:
        from odnas.hostos import join
        return self.keys_dir or join(self, self.p_etc, "keys")
    @property
    def p_releases(self) -> str: return self._d(self.release_root, self._def("releases"))
    @property
    def p_rclone(self) -> str: return self._d(self.rclone_bin, self._def("rclone"))
    @property
    def p_mount_helper(self) -> str: return self._d(self.mount_helper, self._def("mount_helper"))
    @property
    def p_filters_template(self) -> str:
        return self._d(self.filters_template,
                       str(Path(__file__).resolve().parent.parent / "deploy/filters/bisync-filters.txt.tmpl"))

    @property
    def check_filename(self) -> str: return f".{self.slug}-check"
    @property
    def archive_dirname(self) -> str: return f".{self.slug}-archive"
    @property
    def user_agent(self) -> str:
        from odnas import __version__
        major_minor = ".".join(__version__.split(".")[:2])
        return f"NONISV|{self.org_name}|{self.product_name}/{major_minor}"
    @property
    def redirect_uri(self) -> str: return self.base_url.rstrip("/") + self.redirect_path
    @property
    def authority(self) -> str: return f"https://login.microsoftonline.com/{self.tenant_id}"
    @property
    def auth_url(self) -> str: return f"{self.authority}/oauth2/v2.0/authorize"
    @property
    def token_url(self) -> str: return f"{self.authority}/oauth2/v2.0/token"
    @property
    def google_redirect_uri(self) -> str: return self.base_url.rstrip("/") + self.google_redirect_path
    @property
    def google_configured(self) -> bool: return bool(self.google_client_id)
    @property
    def broker_base(self) -> str: return f"http://{self.broker_host}:{self.broker_port}"

    # ---- secrets (never logged, never in repr) --------------------------
    def read_secret(self, name: str) -> bytes:
        """Read a secret file delivered by systemd credentials (preferred) or the dev keys dir.
        Windows: <keys>\\<name>.dpapi unprotected with DPAPI in the service account's user scope (SPEC §11.5.4);
        a plain file is only accepted from $CREDENTIALS_DIRECTORY (dev/tests), never from the keys dir."""
        if self.is_windows:
            from odnas import dpapi
            return dpapi.read_secret(self, name)
        cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")
        for base in filter(None, (cred_dir, self.p_keys)):
            p = Path(base) / name
            if p.is_file():
                return p.read_bytes()
        raise ConfigError(f"secret '{name}' not found in $CREDENTIALS_DIRECTORY or {self.p_keys}")

    def validate(self) -> "Config":
        errs = []
        if not SLUG_RE.match(self.slug):
            errs.append("slug must match " + SLUG_RE.pattern)
        if not re.match(r"^[A-Za-z0-9]{2,40}$", self.org_name):
            errs.append("org_name must be alphanumeric (User-Agent NONISV|Company|App/Ver)")
        if self.tenant_id and not GUID_RE.match(self.tenant_id):
            errs.append("tenant_id must be the VHS tenant GUID (single-tenant; no common/organizations)")
        if self.client_id and not GUID_RE.match(self.client_id):
            errs.append("client_id must be a GUID")
        if self.google_client_id and not GOOGLE_CLIENT_ID_RE.match(self.google_client_id):
            errs.append("google_client_id must look like <digits>-<id>.apps.googleusercontent.com")
        if not self.google_redirect_path.startswith("/auth/") or self.google_redirect_path == self.redirect_path:
            errs.append("google_redirect_path must be under /auth/ and differ from the Microsoft redirect path")
        if self.credential_type not in (CRED_CERT, CRED_SECRET):
            errs.append("credential_type must be certificate|secret")
        if self.token_mode not in (TOKEN_MODE_BROKER, TOKEN_MODE_TMPFS):
            errs.append("token_mode must be broker|tmpfs_config")
        if self.token_mode == TOKEN_MODE_TMPFS and self.credential_type != CRED_SECRET:
            errs.append("token_mode=tmpfs_config needs credential_type=secret (rclone cannot use a certificate)")
        if self.web_host not in ("127.0.0.1", "::1") or self.broker_host not in ("127.0.0.1", "::1"):
            errs.append("web and broker must bind to loopback (SPEC §7.7)")
        for g in ("group_users", "group_admins", "group_auditors"):
            v = getattr(self, g)
            if v and not GUID_RE.match(v):
                errs.append(f"{g} must be a group object ID (GUID)")
        if self.host_os not in ("", "linux", "windows"):
            errs.append("host_os must be empty, linux or windows")
        if not REPO_RE.match(self.auto_update_repo):
            errs.append("auto_update repo must be <owner>/<repo>")
        if self.auto_update_allowed_signers and not self.auto_update_allowed_signers.startswith("/"):
            errs.append("auto_update allowed_signers must be an absolute path")
        if self.internal_timers not in ("", "on", "off"):
            errs.append("internal_timers must be empty, on or off")
        if errs:
            raise ConfigError("; ".join(errs))
        return self


_SECTIONS = ("app", "entra", "google", "paths", "nas", "auto_update")


def load_config(path: str | None = None, env: dict[str, str] | None = None) -> Config:
    e = dict(os.environ if env is None else env)
    values: dict[str, object] = {}
    path = path or e.get("ODNAS_CONFIG")
    if not path and os.name == "nt":   # services pass ODNAS_CONFIG too; this is the documented default
        from odnas.hostos import default_paths
        path = default_paths("windows", "springsync", e)["config_file"]
    if path and Path(path).is_file():
        data = tomllib.loads(Path(path).read_text(encoding="utf-8-sig"))   # Notepad may add a BOM
        for sec in _SECTIONS:
            if sec == "google":   # SPEC §8.2: [google] client_id / allowed_domain -> google_client_id / ...
                values.update({(k if k.startswith("google_") else "google_" + k): v
                               for k, v in data.get(sec, {}).items()})
            elif sec == "auto_update":   # SPEC §11.4.1: [auto_update] enabled = true -> auto_update_enabled
                values.update({"auto_update_" + k: v for k, v in data.get(sec, {}).items()})
            else:
                values.update(data.get(sec, {}))
    known = {f.name: f for f in fields(Config)}
    for k, v in e.items():
        if k.startswith("ODNAS_") and k != "ODNAS_CONFIG":
            name = k[6:].lower()
            if name in known:
                values[name] = v
    unknown = set(values) - set(known)
    if unknown:
        raise ConfigError("unknown config keys: " + ", ".join(sorted(unknown)))
    typed: dict[str, object] = {}
    for k, v in values.items():
        t = known[k].type
        if t in ("int", int):
            typed[k] = int(v)
        elif t in ("bool", bool):
            typed[k] = v if isinstance(v, bool) else str(v).lower() in ("1", "true", "yes", "on")
        else:
            typed[k] = str(v)
    return Config(**typed).validate()
