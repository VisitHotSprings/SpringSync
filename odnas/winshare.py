r"""NAS access on the Windows host (SPEC v0.9 §11.5.3), same interface as nas.MountHelperClient.

There is no mount helper, no sudo and no mount point on Windows. rclone reads and writes the share through
its UNC path (\\host\share\...) with the `local` backend, exactly like the Linux mount point, so the pinned
--local-encoding, hashes, --backup-dir and the Windows name rules all stay identical (SPEC §9.8).
The SMB session is opened per run with WNetAddConnection2W:

  * deviceless (no drive letter) and CONNECT_TEMPORARY (never persisted, nothing in the user profile),
  * the password goes from the decrypted DB value straight into the API call in memory; it is never on a
    command line, in an environment variable, a file or a log (unlike `net use` or `cmdkey`),
  * WNetCancelConnection2W when the run ends (Option A) or at offboarding (Option B keeps it, like Linux).

Windows error 1219 (ERROR_SESSION_CREDENTIAL_CONFLICT): one logon session may hold only ONE credential per
server. The services run in one logon session (svc-springsync), so:
  * Option B (one svc-sync login for every Home-<user> share) never conflicts. Recommended on Windows.
  * Option A (each user's own login on the same server) is serialised per server: a run for another user
    waits until the server is free (`mount_wait_s`); a web "verify" waits only `verify_wait_s` and then
    says the NAS is busy. This is option (a) of §11.5.3; rclone's smb backend (option c) was not used
    because it has no hashes, cannot use --backup-dir across servers and breaks the §9.8 encoding parity.
  * the backup NAS (Sync-Archive) must be a different server name than the user NAS if its login differs;
    otherwise the backup mount fails fast with a clear message (waiting would deadlock the run).

ctypes only (no pywin32 needed here); tests inject a fake `api`. [UNTESTED on real Windows: lab test T-W2.]
"""
from __future__ import annotations

import logging
import os
import threading
import time
import uuid as uuidlib
from dataclasses import dataclass, field

from odnas import hostos
from odnas.nas import ARCHIVE_IDENT, H_AUTH, H_OK, H_OTHER, H_UNREACHABLE, H_USAGE, UNC_RE, _check_cred

log = logging.getLogger("odnas.winshare")

ERROR_SESSION_CREDENTIAL_CONFLICT = 1219
ERROR_BAD_NET_NAME = 67
ERROR_NOT_CONNECTED = 2250
AUTH_ERRORS = {5, 86, 1326, 1327, 1328, 1330, 1331, 1909, 2202}
UNREACHABLE_ERRORS = {53, 64, 121, 1203, 1222, 1231, 1232, 1311}
CONNECT_TEMPORARY = 0x00000004
RESOURCETYPE_DISK = 0x00000001


def map_error(err: int) -> int:
    if err == 0:
        return H_OK
    if err in AUTH_ERRORS:
        return H_AUTH
    if err in UNREACHABLE_ERRORS:
        return H_UNREACHABLE
    return H_OTHER


def describe_error(err: int) -> str:
    return {
        1219: "Windows allows only one NAS login per server per session (error 1219)",
        67: "share not found on the NAS (error 67)",
        53: "NAS not found on the network (error 53)",
        1326: "NAS rejected the user name or password (error 1326)",
        86: "NAS rejected the password (error 86)",
        5: "access denied by the NAS (error 5)",
        1909: "NAS account is locked (error 1909)",
        1331: "NAS account is disabled (error 1331)",
        1330: "NAS password has expired (error 1330)",
    }.get(err, f"Windows network error {err}")


class WNetApi:
    """The two calls we need, via ctypes (mpr.dll)."""

    def __init__(self):
        import ctypes
        from ctypes import wintypes

        class NETRESOURCEW(ctypes.Structure):
            _fields_ = [("dwScope", wintypes.DWORD), ("dwType", wintypes.DWORD),
                        ("dwDisplayType", wintypes.DWORD), ("dwUsage", wintypes.DWORD),
                        ("lpLocalName", wintypes.LPWSTR), ("lpRemoteName", wintypes.LPWSTR),
                        ("lpComment", wintypes.LPWSTR), ("lpProvider", wintypes.LPWSTR)]
        self._c, self._NR = ctypes, NETRESOURCEW
        self._mpr = ctypes.WinDLL("mpr", use_last_error=True)

    def add(self, remote: str, username: str, password: str) -> int:
        c = self._c
        nr = self._NR()
        nr.dwType = RESOURCETYPE_DISK
        nr.lpLocalName = None                    # deviceless: no drive letter
        nr.lpRemoteName = remote
        pw = c.create_unicode_buffer(password)
        try:
            return int(self._mpr.WNetAddConnection2W(c.byref(nr), pw, username, CONNECT_TEMPORARY))
        finally:
            c.memset(pw, 0, c.sizeof(pw))      # best effort: wipe our copy of the password

    def cancel(self, remote: str) -> int:
        return int(self._mpr.WNetCancelConnection2W(remote, 0, True))


@dataclass
class _Server:
    username: str = ""
    refs: dict[str, int] = field(default_factory=dict)    # UNC -> open count

    @property
    def busy(self) -> bool:
        return any(self.refs.values())


class WindowsShareClient:
    """Drop-in for MountHelperClient on Windows: call(action, ident, unc, username, password, domain)
    returns (helper-style code, message); mount_path(ident) returns the UNC path to give rclone."""

    def __init__(self, cfg, api=None, mount_wait_s: float = 4 * 3600, verify_wait_s: float = 15,
                 lister=None):
        self.cfg = cfg
        self._api = api
        self.mount_wait_s, self.verify_wait_s = mount_wait_s, verify_wait_s
        self._list = lister or (lambda p: next(iter(os.scandir(p)), None))
        self._cv = threading.Condition()
        self._servers: dict[str, _Server] = {}
        self._idents: dict[str, str] = {}          # ident -> native UNC

    @property
    def api(self):
        if self._api is None:
            self._api = WNetApi()
        return self._api

    @staticmethod
    def server_of(unc: str) -> str:
        return unc.lstrip("/\\").replace("\\", "/").split("/", 1)[0].lower()

    @staticmethod
    def login(username: str, domain: str) -> str:
        return f"{domain}\\{username}" if domain else username

    # -- connection bookkeeping (all under self._cv) --
    def _acquire(self, unc: str, login: str, password: str, wait_s: float) -> tuple[int, str]:
        srv_name = self.server_of(unc)
        deadline = time.monotonic() + wait_s
        with self._cv:
            while True:
                srv = self._servers.setdefault(srv_name, _Server())
                if not srv.busy or srv.username.lower() == login.lower():
                    break
                left = deadline - time.monotonic()
                if left <= 0:
                    return H_OTHER, (f"NAS busy: {srv_name} is connected with another login; "
                                     f"{describe_error(ERROR_SESSION_CREDENTIAL_CONFLICT)}")
                self._cv.wait(min(left, 30))
            if srv.refs.get(unc, 0) == 0:
                err = self.api.add(unc, login, password)
                if err == ERROR_SESSION_CREDENTIAL_CONFLICT:
                    # a stale session (e.g. after a crash) we no longer track: drop it once and retry
                    for other in list(srv.refs) or [unc]:
                        self.api.cancel(other)
                    err = self.api.add(unc, login, password)
                if err:
                    if not srv.busy:
                        srv.username = ""
                    return map_error(err), describe_error(err)
            srv.username = login
            srv.refs[unc] = srv.refs.get(unc, 0) + 1
            return H_OK, ""

    def _release(self, unc: str) -> None:
        srv_name = self.server_of(unc)
        with self._cv:
            srv = self._servers.get(srv_name)
            if not srv or srv.refs.get(unc, 0) == 0:
                return
            srv.refs[unc] -= 1
            if srv.refs[unc] == 0:
                err = self.api.cancel(unc)
                if err not in (0, ERROR_NOT_CONNECTED):
                    log.warning("disconnect %s: %s", unc, describe_error(err))
                del srv.refs[unc]
            if not srv.busy:
                srv.username = ""
            self._cv.notify_all()

    # -- MountHelperClient interface --
    def call(self, action: str, ident: str, unc: str = "", username: str = "", password: str = "",
             domain: str = "") -> tuple[int, str]:
        try:
            uuidlib.UUID(ident)
        except ValueError:
            return H_USAGE, "bad ident"
        if action == "umount":
            native = self._idents.pop(ident, "")
            if native:
                self._release(native)
            return H_OK, ""
        if action not in ("mount", "verify"):
            return H_USAGE, f"unknown action {action}"
        try:
            _check_cred(username, password)
        except ValueError as e:
            return H_USAGE, str(e)
        if not UNC_RE.match(unc):
            return H_USAGE, f"invalid UNC {unc!r}"
        native = hostos.to_unc(unc)
        login = self.login(username, domain)
        if action == "verify":
            code, msg = self._acquire(native, login, password, self.verify_wait_s)
            if code != H_OK:
                return code, msg
            try:
                self._list(native)
                return H_OK, ""
            except PermissionError:
                return H_AUTH, "logged in but the share cannot be listed (permissions)"
            except OSError as e:
                return H_OTHER, f"share cannot be listed ({type(e).__name__})"
            finally:
                self._release(native)
        # mount: idempotent per ident (Option B keeps it between runs)
        old = self._idents.get(ident)
        if old == native:
            return H_OK, ""
        if old:
            self._idents.pop(ident, None)
            self._release(old)
        wait = 0 if ident == ARCHIVE_IDENT else self.mount_wait_s
        code, msg = self._acquire(native, login, password, wait)
        if code == H_OK:
            self._idents[ident] = native
        elif ident == ARCHIVE_IDENT and "1219" in msg:
            msg += ("; the backup NAS uses a different login on the same server as the user NAS. Use a "
                    "different server name or IP for the backup NAS (SPEC §11.5.3)")
        return code, msg

    def mount_path(self, ident: str) -> str:
        return self._idents.get(ident, "")

    def is_connected(self, ident: str) -> bool:
        p = self._idents.get(ident, "")
        return bool(p) and os.path.isdir(p)

    def creds_dir(self):   # interface parity; nothing is ever written on Windows
        from pathlib import Path
        return Path(self.cfg.p_run) / "creds"
