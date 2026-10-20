"""NAS access (SPEC §4.2), hidden behind NasAccessProvider so Option A <-> B is a
settings change plus a per-user migration, not a rewrite.

Option A (pilot): each user's own UniFi file-service login, //<nas>/Personal-Drive.
Option B: //<nas>/Home-<user> per user, one svc-sync login, mounts kept persistent.

All mounting goes through the root-owned mount helper via `sudo -n` (one command
only, see deploy/sudoers). The worker writes a 0600 credentials file and a .unc
file to tmpfs; the helper reads them, mounts, and the worker shreds them in finally.
"""
from __future__ import annotations

import re
import subprocess
import uuid as uuidlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

from odnas.config import Config
from odnas.tokens import shred, write_private

# Mount helper exit codes (keep in sync with deploy/mount-helper)
H_OK, H_USAGE, H_OTHER, H_UNREACHABLE, H_AUTH = 0, 2, 3, 4, 13

V_OK, V_AUTH_FAILED, V_UNREACHABLE, V_ERROR = "ok", "auth_failed", "unreachable", "error"
UNC_RE = re.compile(r"^//[A-Za-z0-9.-]{1,253}/[A-Za-z0-9][A-Za-z0-9 _.-]{0,79}$")


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
                 svc_user: str, svc_password: str, domain: str = ""):
        self.cfg, self.helper, self.host, self.template = cfg, helper, host, template
        self.svc = (svc_user, svc_password)
        self.domain = domain

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
                "unc": self.unc_for("<user>"), "per_user_credentials": False, "persistent_mounts": True}


def provider_from_settings(cfg: Config, s, helper: MountHelperClient | None = None) -> NasAccessProvider:
    helper = helper or MountHelperClient(cfg)
    if s.nas_option == "B":
        return SharedHomeProvider(cfg, helper, s.nas_host, s.nas_shared_template, s.nas_svc_username,
                                  s.secret("nas_svc_password"), s.nas_domain)
    return PersonalDriveProvider(cfg, helper, s.nas_host, s.nas_share, s.nas_domain)


def local_name_from_upn(upn: str) -> str:
    """jsmith@hotsprings.org -> jsmith. Used only for Option B share names, never for paths."""
    base = upn.split("@", 1)[0].lower()
    base = re.sub(r"[^a-z0-9._-]", "-", base).strip(".-")
    return base[:60] or "user"
