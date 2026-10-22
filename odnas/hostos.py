r"""Host layer (SPEC v0.9 §11.5): everything that differs between the Ubuntu test host and the Windows 11
host lives here or behind it, so the app, DB, settings, safety rules and web UI are one codebase.

    paths        Linux: /var/lib/<slug>, /etc/<slug>, /run/<slug> ...
                 Windows: %ProgramData%\SpringSync\... (data, config, keys, run, logs) and
                          %ProgramFiles%\SpringSync\... (code, bin\rclone.exe, bin\caddy.exe)
    join/local   path joining and "is this a local absolute path" for rclone arguments (UNC on Windows)
    FileLock     fcntl.flock (Linux) / msvcrt.locking (Windows); no POSIX-only calls on Windows
    processes    Linux: own session, SIGINT then SIGKILL of the group.
                 Windows: CREATE_NEW_PROCESS_GROUP (+ CREATE_NO_WINDOW), a Job Object with
                 KILL_ON_JOB_CLOSE, CTRL_BREAK_EVENT once, then TerminateJobObject / taskkill /T /F.

Which host applies is decided by `Config.host_os` ("" = the OS this process runs on), so the Windows
branch can be unit-tested on Linux with a forced "windows" config and mocks (tests/test_v10_windows.py).
Nothing in this module touches the network.
"""
from __future__ import annotations

import ntpath
import os
import posixpath
import re
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

LINUX, WINDOWS = "linux", "windows"
WIN_DATA_DIRNAME = "SpringSync"          # %ProgramData%\SpringSync and %ProgramFiles%\SpringSync (SPEC §11.5.2)
_UNC_RE = re.compile(r"^\\\\[A-Za-z0-9.-]{1,253}\\[A-Za-z0-9][A-Za-z0-9 _.$-]{0,79}(\\.*)?\Z")
_DRIVE_RE = re.compile(r"^[A-Za-z]:\\")

# Windows process constants (values from the Windows SDK; defined here so Linux can import them)
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_NO_WINDOW = 0x08000000
CTRL_BREAK_EVENT = 1


def current_os() -> str:
    return WINDOWS if os.name == "nt" else LINUX


def host_of(cfg) -> str:
    return getattr(cfg, "host_os", "") or current_os()


def is_windows(cfg) -> bool:
    return host_of(cfg) == WINDOWS


# ---- paths -----------------------------------------------------------------------------------------

def win_programdata(env: dict | None = None) -> str:
    return (env if env is not None else os.environ).get("ProgramData") or r"C:\ProgramData"


def win_programfiles(env: dict | None = None) -> str:
    return (env if env is not None else os.environ).get("ProgramFiles") or r"C:\Program Files"


def default_paths(host: str, slug: str, env: dict | None = None) -> dict[str, str]:
    """Defaults for the [paths] keys (SPEC §8.2 Linux, §11.5.2 Windows)."""
    if host == WINDOWS:
        data = ntpath.join(win_programdata(env), WIN_DATA_DIRNAME)
        app = ntpath.join(win_programfiles(env), WIN_DATA_DIRNAME)
        return {"state": data, "db": ntpath.join(data, "db", f"{slug}.db"), "log": ntpath.join(data, "logs"),
                "run": ntpath.join(data, "run"), "mnt": "", "etc": data, "keys": ntpath.join(data, "keys"),
                "releases": app, "rclone": ntpath.join(app, "bin", "rclone.exe"), "mount_helper": "",
                "config_file": ntpath.join(data, f"{slug}.toml")}
    return {"state": f"/var/lib/{slug}", "db": f"/var/lib/{slug}/db/{slug}.db", "log": f"/var/log/{slug}",
            "run": f"/run/{slug}", "mnt": f"/srv/{slug}/mnt", "etc": f"/etc/{slug}", "keys": f"/etc/{slug}/keys",
            "releases": f"/opt/{slug}", "rclone": "/usr/local/bin/rclone",
            "mount_helper": f"/usr/local/lib/{slug}/mount-helper", "config_file": f"/etc/{slug}/{slug}.toml"}


def pathmod(cfg):
    return ntpath if is_windows(cfg) else posixpath


def join(cfg, *parts: str) -> str:
    """Join with the host's separator (rclone and Windows accept '/', but logs and UNC read better native).
    A base that is already a POSIX absolute path keeps '/' (tests forcing host_os=windows on Linux)."""
    if parts and parts[0].startswith("/"):
        return posixpath.join(*parts)
    return pathmod(cfg).join(*parts)


def to_unc(unc: str) -> str:
    r"""'//host/share' (the UNC_RE form used in settings and the Linux helper) -> '\\host\share'."""
    return "\\\\" + unc.lstrip("/\\").replace("/", "\\")


def is_unc(path: str) -> bool:
    return bool(_UNC_RE.match(path or ""))


def is_local_abs(cfg, path: str) -> bool:
    r"""An absolute LOCAL path rclone treats as the `local` backend (never a remote `name:`).
    Linux: '/...'. Windows: a UNC path '\\host\share\...' or 'C:\...'."""
    if not path or any(c in path for c in "\r\n\x00"):
        return False
    if is_windows(cfg):
        return is_unc(path) or bool(_DRIVE_RE.match(path))
    return path.startswith("/") and ":" not in path


def is_windows_path(p: str) -> bool:
    return (p or "").startswith("\\\\") or bool(_DRIVE_RE.match(p or ""))


def under(root: str, *subs: str) -> str:
    """root + relative parts (written with '/' in settings), in the root's own style: '/' for a Linux mount
    point, '\\' for a UNC or drive path. Refuses '..'. Needs no config: the root decides."""
    parts = []
    for sub in subs:
        s = (sub or "").replace("\\", "/").strip("/")
        if ".." in s.split("/"):
            raise ValueError("sub-path must not contain ..")
        if s:
            parts.append(s)
    if not parts:
        return root
    if is_windows_path(root):
        return root.rstrip("\\") + "\\" + "\\".join(p.replace("/", "\\") for p in parts)
    return root.rstrip("/") + "/" + "/".join(parts)


def subdir_join(cfg, root: str, sub: str) -> str:   # kept for callers that have a cfg
    return under(root, sub)


def is_local_path(p: str) -> bool:
    """Host-independent: an absolute local path in either style (never an rclone `remote:`)."""
    if not p or any(c in p for c in "\r\n\x00"):
        return False
    if is_windows_path(p):
        return is_unc(p) or bool(_DRIVE_RE.match(p))
    return p.startswith("/") and ":" not in p


def norm_prefix(p: str) -> str:
    """For 'is A inside B' checks: one separator style, case-folded for Windows paths."""
    return p.replace("\\", "/").rstrip("/").lower() if is_windows_path(p) else p.rstrip("/")


# ---- file locking ----------------------------------------------------------------------------------

class LockBusy(RuntimeError):
    pass


class FileLock:
    """Exclusive, non-blocking lock on a file (single worker instance, key ingest). Released on close and
    by the OS if the process dies. Linux: fcntl.flock. Windows: msvcrt.locking on byte 0."""

    def __init__(self, path: str | os.PathLike, host: str | None = None, _mods: dict | None = None):
        self.path, self.host = Path(path), host or current_os()
        self._mods = _mods or {}
        self._fh = None

    def _mod(self, name: str):
        if name in self._mods:
            return self._mods[name]
        import importlib
        return importlib.import_module(name)

    def acquire(self) -> "FileLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fh = open(self.path, "a+b")
        try:
            if self.host == WINDOWS:
                msvcrt = self._mod("msvcrt")
                fh.seek(0)
                try:
                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError as e:
                    raise LockBusy(str(self.path)) from e
            else:
                fcntl = self._mod("fcntl")
                try:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as e:
                    raise LockBusy(str(self.path)) from e
        except BaseException:
            fh.close()
            raise
        self._fh = fh
        return self

    def release(self) -> None:
        fh, self._fh = self._fh, None
        if fh is None:
            return
        try:
            if self.host == WINDOWS:
                msvcrt = self._mod("msvcrt")
                fh.seek(0)
                try:
                    msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
            else:
                self._mod("fcntl").flock(fh.fileno(), self._mod("fcntl").LOCK_UN)
        finally:
            fh.close()

    def __enter__(self) -> "FileLock":
        return self.acquire()

    def __exit__(self, *exc) -> None:
        self.release()


@contextmanager
def locked(path, host: str | None = None):
    lk = FileLock(path, host).acquire()
    try:
        yield lk
    finally:
        lk.release()


# ---- processes -------------------------------------------------------------------------------------

def popen_kwargs(host: str) -> dict:
    """Linux: own session (SIGINT/SIGKILL go to the whole group). Windows: own process group so
    CTRL_BREAK_EVENT reaches only rclone (SPEC §11.5.6), and no console window."""
    if host == WINDOWS:
        return {"creationflags": CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW}
    return {"start_new_session": True}


class WinJob:
    """A Windows Job Object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: rclone (and anything it starts) dies with
    the worker even if the worker crashes, and TerminateJobObject kills the whole tree. ctypes only; any
    failure leaves `ok` False and the caller falls back to `taskkill /T /F`."""

    def __init__(self, kernel32=None):
        self.ok, self.handle = False, None
        try:
            import ctypes
            from ctypes import wintypes
            k = kernel32 or ctypes.WinDLL("kernel32", use_last_error=True)
            self._k = k
            h = k.CreateJobObjectW(None, None)
            if not h:
                return

            class _Basic(ctypes.Structure):
                _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                            ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                            ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                            ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                            ("SchedulingClass", wintypes.DWORD)]

            class _Io(ctypes.Structure):
                _fields_ = [(n, ctypes.c_uint64) for n in ("r", "w", "o", "rb", "wb", "ob")]

            class _Ext(ctypes.Structure):
                _fields_ = [("Basic", _Basic), ("Io", _Io), ("ProcessMemoryLimit", ctypes.c_size_t),
                            ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
                            ("PeakJobMemoryUsed", ctypes.c_size_t)]
            info = _Ext()
            info.Basic.LimitFlags = 0x00002000   # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not k.SetInformationJobObject(h, 9, ctypes.byref(info), ctypes.sizeof(info)):  # Extended info
                k.CloseHandle(h)
                return
            self.handle, self.ok = h, True
        except Exception:
            self.ok = False

    def assign(self, proc) -> bool:
        if not self.ok:
            return False
        try:
            return bool(self._k.AssignProcessToJobObject(self.handle, int(proc._handle)))
        except Exception:
            return False

    def terminate(self, code: int = 1) -> bool:
        return bool(self.ok and self._k.TerminateJobObject(self.handle, code))

    def close(self) -> None:
        if self.ok and self.handle:
            self._k.CloseHandle(self.handle)
        self.ok, self.handle = False, None


import threading  # noqa: E402

_CONSOLE_LOCK = threading.Lock()


def _win_break_via_console(pid: int, kernel32=None) -> bool:
    """A service has no console, and GenerateConsoleCtrlEvent only reaches processes on the caller's
    console. rclone was started with CREATE_NO_WINDOW, so it has its own hidden console: attach to it,
    ignore the event ourselves, send CTRL_BREAK to rclone's process group, detach. Process-wide, so
    serialised. Returns False if any step fails (the caller then tries send_signal)."""
    try:
        import ctypes
        k = kernel32 or ctypes.WinDLL("kernel32", use_last_error=True)
    except Exception:
        return False
    with _CONSOLE_LOCK:
        k.FreeConsole()
        if not k.AttachConsole(int(pid)):
            return False
        try:
            k.SetConsoleCtrlHandler(None, True)          # this process ignores the event
            return bool(k.GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, int(pid)))   # pid == process group id
        finally:
            k.FreeConsole()
            k.SetConsoleCtrlHandler(None, False)


def graceful_stop(proc, host: str, kernel32=None) -> str:
    """First, polite stop: SIGINT (Linux, bisync graceful shutdown) or CTRL_BREAK_EVENT (Windows; Go's
    atexit maps it to os.Interrupt, SPEC §11.5.6). Returns which method was used.
    [UNTESTED on real Windows: lab test T-W3.]"""
    import signal
    if host == WINDOWS:
        if _win_break_via_console(proc.pid, kernel32):
            return "console_ctrl_break"
        try:
            proc.send_signal(getattr(signal, "CTRL_BREAK_EVENT", CTRL_BREAK_EVENT))
            return "send_signal_ctrl_break"
        except (OSError, ValueError):
            return "none"
    proc.send_signal(signal.SIGINT)
    return "sigint"


def hard_kill(proc, host: str, job: WinJob | None = None, run=subprocess.run) -> None:
    """Kill the whole process tree."""
    if host == WINDOWS:
        if job is not None and job.terminate():
            return
        run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True, check=False, timeout=60)
        return
    import signal
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def python_exe() -> str:
    return sys.executable
