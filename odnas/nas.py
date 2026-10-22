"""NAS access (SPEC §4.2), hidden behind NasAccessProvider so Option A <-> B is a
settings change plus a per-user migration, not a rewrite.

Option A (pilot): each user's own UniFi file-service login, //<nas>/Personal-Drive.
Option B: //<nas>/Home-<user> per user, one svc-sync login, mounts kept persistent.

On Linux all mounting goes through the root-owned mount helper via `sudo -n` (one
command only, see deploy/sudoers). On Windows (v0.10) odnas/winshare.py opens a
per-run SMB session to the UNC path instead (same call/mount_path interface). The worker writes a 0600 credentials file and a .unc
file to tmpfs; the helper reads them, mounts, and the worker shreds them in finally.
"""
from __future__ import annotations

import os
import re
import subprocess
import threading
import uuid as uuidlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

from odnas.config import Config
from odnas.tokens import shred, write_private

# Mount helper exit codes (keep in sync with deploy/mount-helper)
H_OK, H_USAGE, H_OTHER, H_UNREACHABLE, H_AUTH = 0, 2, 3, 4, 13

V_OK, V_AUTH_FAILED, V_UNREACHABLE, V_ERROR = "ok", "auth_failed", "unreachable", "error"
UNC_RE = re.compile(r"^//[A-Za-z0-9.-]{1,253}/[A-Za-z0-9][A-Za-z0-9 _.-]{0,79}\Z")


@dataclass
class VerifyResult:
    status: str
    message: str

    @property
    def ok(self) -> bool:
        return self.status == V_OK


@dataclass
class MountResult:
    status: str        # V_* values
    path: str = ""
    message: str = ""

    @property
    def ok(self) -> bool:
        return self.status == V_OK


def friendly(status: str) -> str:
    return {V_OK: "NAS login verified.",
            V_AUTH_FAILED: "The NAS did not accept that username or password. Nothing was saved.",
            V_UNREACHABLE: "The NAS could not be reached right now. Nothing was saved; please try again later.",
            V_ERROR: "Something went wrong checking the NAS login. Nothing was saved; IT can see the details."}[status]


def _check_cred(username: str, password: str) -> None:
    for v in (username, password):
        if not v or any(c in v for c in "\r\n\x00"):
            raise ValueError("username/password must be non-empty and single-line")
    if len(username) > 128 or len(password) > 256:
        raise ValueError("username/password too long")


Runner = Callable[[list[str]], subprocess.CompletedProcess]


def _default_runner(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)


class MountHelperClient:
    def __init__(self, cfg: Config, runner: Runner | None = None):
        self.cfg, self.run = cfg, runner or _default_runner

    def creds_dir(self) -> Path:
        return Path(self.cfg.p_run) / "creds"

    def call(self, action: str, ident: str, unc: str = "", username: str = "", password: str = "",
             domain: str = "") -> tuple[int, str]:
        uuidlib.UUID(ident)  # helper validates too; fail early here
        cred_file, unc_file = self.creds_dir() / ident, self.creds_dir() / f"{ident}.unc"
        try:
            if action in ("mount", "verify"):
                _check_cred(username, password)
                if not UNC_RE.match(unc):
                    raise ValueError(f"invalid UNC {unc!r}")
                body = f"username={username}\npassword={password}\n" + (f"domain={domain}\n" if domain else "")
                write_private(cred_file, body)
                write_private(unc_file, unc + "\n")
            p = self.run(["sudo", "-n", self.cfg.p_mount_helper, action, ident])
            return p.returncode, (p.stderr or p.stdout or "").strip()[-500:]
        finally:
            shred(cred_file)
            shred(unc_file)

    def mount_path(self, ident: str) -> str:
        return str(Path(self.cfg.p_mnt) / ident)

    def is_connected(self, ident: str) -> bool:
        return os.path.ismount(self.mount_path(ident))


def default_share_client(cfg: Config):
    """Linux: the root mount helper via sudo. Windows (v0.10, SPEC §11.5.3): per-run SMB sessions to UNC
    paths with WNetAddConnection2 (odnas/winshare.py)."""
    if cfg.is_windows:
        from odnas.winshare import WindowsShareClient
        return WindowsShareClient(cfg)
    return MountHelperClient(cfg)


def _status(code: int) -> str:
    return {H_OK: V_OK, H_AUTH: V_AUTH_FAILED, H_UNREACHABLE: V_UNREACHABLE}.get(code, V_ERROR)


class NasAccessProvider(Protocol):
    option: str
    per_user_credentials: bool
    def verify(self, username: str, password: str) -> VerifyResult: ...
    def mount(self, uid: str, local_name: str, creds: tuple[str, str] | None) -> MountResult: ...
    def unmount(self, uid: str) -> None: ...
    def describe(self) -> dict: ...


class PersonalDriveProvider:
    """Option A."""
    option = "A"
    per_user_credentials = True

    def __init__(self, cfg: Config, helper: MountHelperClient, host: str, share: str, domain: str = ""):
        self.cfg, self.helper, self.host, self.share, self.domain = cfg, helper, host, share, domain

    @property
    def unc(self) -> str:
        return f"//{self.host}/{self.share}"

    def verify(self, username: str, password: str) -> VerifyResult:
        probe = str(uuidlib.uuid4())  # throwaway id: never reuses a user's mount point
        try:
            code, msg = self.helper.call("verify", probe, self.unc, username, password, self.domain)
        except ValueError as e:
            return VerifyResult(V_ERROR, str(e))
        return VerifyResult(_status(code), msg)

    def mount(self, uid: str, local_name: str, creds: tuple[str, str] | None) -> MountResult:
        if not creds:
            return MountResult(V_AUTH_FAILED, message="no NAS credential stored")
        code, msg = self.helper.call("mount", uid, self.unc, creds[0], creds[1], self.domain)
        return MountResult(_status(code), self.helper.mount_path(uid), msg)

    def unmount(self, uid: str) -> None:
        self.helper.call("umount", uid)

    def describe(self) -> dict:
        return {"option": "A", "label": "Personal-Drive with each user's own NAS login",
                "unc": self.unc, "per_user_credentials": True, "persistent_mounts": False}


class SharedHomeProvider:
    """Option B. The svc-sync credential is the only NAS secret; mounts stay up between runs."""
    option = "B"
    per_user_credentials = False

    def __init__(self, cfg: Config, helper: MountHelperClient, host: str, template: str,
                 svc_user: str, svc_password: str, domain: str = "", health_share: str = "Sync-Health"):
        self.cfg, self.helper, self.host, self.template = cfg, helper, host, template
        self.svc = (svc_user, svc_password)
        self.domain = domain
        self.health_share = health_share

    @property
    def health_unc(self) -> str:
        return f"//{self.host}/{self.health_share}"

    def test_mount(self) -> VerifyResult:
        """SPEC v0.7: read-only test mount of the dedicated health-check share with svc-sync (helper
        `verify`: ro mount, list root, unmount). Used after a svc-sync password change and by the periodic
        NAS health check; never touches a user's Home share."""
        try:
            code, msg = self.helper.call("verify", str(uuidlib.uuid4()), self.health_unc, *self.svc, self.domain)
        except ValueError as e:
            return VerifyResult(V_ERROR, str(e))
        return VerifyResult(_status(code), msg)

    def unc_for(self, local_name: str) -> str:
        return f"//{self.host}/{self.template.replace('{user}', local_name)}"

    def verify(self, username: str, password: str) -> VerifyResult:
        # verify the svc-sync login against the template with a probe user name is not possible
        # without a real share; admins test with a concrete share via the Test button.
        probe = str(uuidlib.uuid4())
        try:
            code, msg = self.helper.call("verify", probe, f"//{self.host}/{self.template.replace('{user}', username)}",
                                         *self.svc, self.domain)
        except ValueError as e:
            return VerifyResult(V_ERROR, str(e))
        return VerifyResult(_status(code), msg)

    def mount(self, uid: str, local_name: str, creds: tuple[str, str] | None) -> MountResult:
        code, msg = self.helper.call("mount", uid, self.unc_for(local_name), *self.svc, self.domain)
        return MountResult(_status(code), self.helper.mount_path(uid), msg)

    def unmount(self, uid: str) -> None:
        return None  # persistent (SPEC §4.2 B); offboarding calls helper.call("umount") directly

    def describe(self) -> dict:
        return {"option": "B", "label": "Home-<user> shared drive per person, one svc-sync login",
                "unc": self.unc_for("<user>"), "per_user_credentials": False, "persistent_mounts": True,
                "health_unc": self.health_unc}


def provider_from_settings(cfg: Config, s, helper: MountHelperClient | None = None) -> NasAccessProvider:
    helper = helper or default_share_client(cfg)
    if s.nas_option == "B":
        return SharedHomeProvider(cfg, helper, s.nas_host, s.nas_shared_template, s.nas_svc_username,
                                  s.secret("nas_svc_password"), s.nas_domain, s.nas_health_share)
    return PersonalDriveProvider(cfg, helper, s.nas_host, s.nas_share, s.nas_domain)


# ---- backup target for one-way runs (SPEC v0.9 §9.7.3) ----------------------------------------------
# The backup NAS share (suggested Sync-Archive on UNAS #2) is mounted through the SAME root helper and
# sudoers line as user shares, under a reserved mount id, so no new privileged code path is added. The
# SPEC's example path /srv/springsync/archive is therefore <mount_root>/<ARCHIVE_IDENT> (CHANGELOG).
ARCHIVE_IDENT = "00000000-0000-4000-8000-00000000a5c1"
TARGET_BACKUP_NAS, TARGET_SAME_SHARE = "backup_nas", "same_share"
WRITE_MARKER = ".springsync-write-test"


@dataclass
class BackupResult:
    status: str
    root: str = ""
    per_user: bool = True     # backup_nas: <root>/<user_id>/<stamp>; same_share: <root>/<stamp>
    message: str = ""

    @property
    def ok(self) -> bool:
        return self.status == V_OK


class BackupTarget:
    """Guard 3 of §9.7.2: the backup target must be reachable AND writable (a marker file is written and
    removed) before any one-way run. SpringSync never deletes anything from the backup target."""

    def __init__(self, cfg: Config, helper: MountHelperClient | None = None):
        self.cfg, self.helper = cfg, helper or default_share_client(cfg)
        self._lock = threading.Lock()

    def unc(self, s) -> str:
        return f"//{s.backup_nas_host}/{s.backup_nas_share}"

    def _mount(self, s) -> BackupResult:
        if not (s.backup_nas_host and s.backup_nas_share and s.backup_nas_username
                and s.secret_is_set("backup_nas_password")):
            return BackupResult(V_ERROR, message="backup NAS not configured (host, share, login)")
        with self._lock:
            if not self._connected():
                try:
                    code, msg = self.helper.call("mount", ARCHIVE_IDENT, self.unc(s), s.backup_nas_username,
                                                 s.secret("backup_nas_password"), s.nas_domain)
                except ValueError as e:
                    return BackupResult(V_ERROR, message=str(e))
                if code != H_OK:
                    return BackupResult(_status(code), message=f"backup NAS mount failed: {msg}"[:300])
            path = self.helper.mount_path(ARCHIVE_IDENT)   # Windows: known only once connected
        return BackupResult(V_OK, path, True)

    def _connected(self) -> bool:
        f = getattr(self.helper, "is_connected", None)
        if f is not None:
            return bool(f(ARCHIVE_IDENT))
        return os.path.ismount(self.helper.mount_path(ARCHIVE_IDENT))

    def prepare(self, s, uid: str, user_mount: str) -> BackupResult:
        if s.pull_backup_target == TARGET_SAME_SHARE:
            from odnas.hostos import subdir_join
            res = BackupResult(V_OK, subdir_join(self.cfg, user_mount, self.cfg.archive_dirname), False)
        else:
            res = self._mount(s)
            if not res.ok:
                return res
        return self._writable(res, uid)

    def test(self, s) -> BackupResult:
        """Admin Settings 'Test' button (backup_nas only): mount + write/remove a marker at the root."""
        if s.pull_backup_target == TARGET_SAME_SHARE:
            return BackupResult(V_OK, message="same_share: checked on each user's share before each run")
        res = self._mount(s)
        return self._writable(res, None) if res.ok else res

    @staticmethod
    def _writable(res: BackupResult, uid: str | None) -> BackupResult:
        d = Path(res.root) / uid if (uid and res.per_user) else Path(res.root)
        try:
            d.mkdir(parents=True, exist_ok=True)
            m = d / WRITE_MARKER
            m.write_text("springsync write test\n")
            m.unlink()
        except OSError as e:
            return BackupResult(V_ERROR, res.root, res.per_user, f"backup target not writable ({type(e).__name__})")
        return res


def local_name_from_upn(upn: str) -> str:
    """jsmith@hotsprings.org -> jsmith. Used only for Option B share names, never for paths."""
    base = upn.split("@", 1)[0].lower()
    base = re.sub(r"[^a-z0-9._-]", "-", base).strip(".-")
    return base[:60] or "user"
