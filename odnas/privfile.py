"""Private files: readable and writable only by the account that writes them (SPEC §5.3, §11.5.4).

Linux: mode 0600 (also forced on an existing file, whose old mode O_TRUNC would otherwise keep).
Windows: POSIX modes mean nothing there (`st_mode` always reports 0o666), so the file gets its own
*protected* DACL (inheritance off) allowing only SYSTEM, Administrators and the current account. The
content is written to a new temp file that is created with that DACL and no sharing, then renamed over
the target, so the secret never sits in a file with a looser ACL, not even for a moment. A rename on
the same volume keeps the file's security descriptor.

`is_private(path)` is the matching check, used by the tests (and the update.ps1 smoke subset on the
Windows host) so the same safety assertion holds on both hosts.
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path

SID_SYSTEM, SID_ADMINS = "S-1-5-18", "S-1-5-32-544"
_SE_DACL_PROTECTED = 0x1000
_ACCESS_ALLOWED_ACE_TYPE = 0


def write_private_bytes(path: Path, data: bytes) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "nt":
        _win_write(path, data)
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as f:
            fd = -1
            f.write(data)
    finally:
        if fd != -1:
            os.close(fd)


def is_private(path: Path) -> bool:
    """Linux: exactly mode 0600. Windows: a protected DACL whose allow entries are only SYSTEM,
    Administrators and the current account (a NULL DACL, i.e. everyone, is not private)."""
    if os.name != "nt":
        return (Path(path).stat().st_mode & 0o777) == 0o600
    import win32security
    sd = win32security.GetFileSecurity(str(path), win32security.DACL_SECURITY_INFORMATION)
    control, _rev = sd.GetSecurityDescriptorControl()
    if not control & _SE_DACL_PROTECTED:
        return False
    dacl = sd.GetSecurityDescriptorDacl()
    if dacl is None:
        return False
    allowed = {SID_SYSTEM, SID_ADMINS, current_user_sid()}
    for i in range(dacl.GetAceCount()):
        (ace_type, _flags), _mask, sid = dacl.GetAce(i)
        if ace_type == _ACCESS_ALLOWED_ACE_TYPE and win32security.ConvertSidToStringSid(sid) not in allowed:
            return False
    return True


def current_user_sid() -> str:
    import win32api
    import win32con
    import win32security
    tok = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    try:
        sid = win32security.GetTokenInformation(tok, win32security.TokenUser)[0]
    finally:
        tok.Close()
    return win32security.ConvertSidToStringSid(sid)


def private_sddl(user_sid: str) -> str:
    """D:P = protected DACL (no inherited entries); FA = full access."""
    return f"D:P(A;;FA;;;{SID_SYSTEM})(A;;FA;;;{SID_ADMINS})(A;;FA;;;{user_sid})"


def _win_write(path: Path, data: bytes) -> None:
    import win32con
    import win32file
    import win32security
    sa = win32security.SECURITY_ATTRIBUTES()
    sa.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        private_sddl(current_user_sid()), win32security.SDDL_REVISION_1)
    sa.bInheritHandle = False
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    h = win32file.CreateFile(str(tmp), win32con.GENERIC_WRITE, 0, sa, win32con.CREATE_NEW,
                             win32con.FILE_ATTRIBUTE_NORMAL, None)
    try:
        try:
            view = memoryview(data)
            while view:
                _rc, n = win32file.WriteFile(h, view.tobytes())
                view = view[n:]
            win32file.FlushFileBuffers(h)
        finally:
            h.Close()
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
