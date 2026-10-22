"""v0.10: Windows host layer, tested on Linux with a forced host_os="windows" config and fakes.
Nothing here calls a Windows API, the network, Microsoft, Google or a NAS. What these tests cannot prove
(real WNet/DPAPI/service/CTRL_BREAK behaviour) is lab tests T-W1..T-W4 (docs/INSTALL-WINDOWS.md)."""
import ntpath
import os
import subprocess
import sys
import threading
import time
import types
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from odnas import dpapi, hostos
from odnas.config import ConfigError, load_config
from odnas.nas import ARCHIVE_IDENT, H_AUTH, H_OK, H_OTHER, H_UNREACHABLE, H_USAGE
from tests.conftest import CANARY_PW, CLIENT, TENANT

UID1 = "11111111-1111-4111-8111-111111111111"
UID2 = "22222222-2222-4222-8222-222222222222"


def wincfg(**kw):
    env = {"ODNAS_TENANT_ID": TENANT, "ODNAS_CLIENT_ID": CLIENT, "ODNAS_HOST_OS": "windows"}
    env.update({f"ODNAS_{k.upper()}": v for k, v in kw.items()})
    return load_config(env=env)


# ---- config / paths -------------------------------------------------------------------------------

def test_windows_default_paths_follow_spec_11_5_2(monkeypatch):
    monkeypatch.delenv("ProgramData", raising=False)
    monkeypatch.delenv("ProgramFiles", raising=False)
    c = wincfg()
    assert c.is_windows and c.timers_in_worker
    assert c.p_db == r"C:\ProgramData\SpringSync\db\springsync.db"
    assert c.p_state == r"C:\ProgramData\SpringSync"
    assert c.p_log == r"C:\ProgramData\SpringSync\logs"
    assert c.p_run == r"C:\ProgramData\SpringSync\run"
    assert c.p_keys == r"C:\ProgramData\SpringSync\keys"
    assert c.p_rclone == r"C:\Program Files\SpringSync\bin\rclone.exe"
    assert c.p_releases == r"C:\Program Files\SpringSync"


def test_programdata_env_is_honoured(monkeypatch):
    monkeypatch.setenv("ProgramData", r"D:\PD")
    assert wincfg().p_db == r"D:\PD\SpringSync\db\springsync.db"


def test_linux_defaults_unchanged():
    c = load_config(env={"ODNAS_HOST_OS": "linux"})
    assert (c.p_db, c.p_state, c.p_log, c.p_run, c.p_mnt, c.p_keys, c.p_rclone, c.p_mount_helper) == (
        "/var/lib/springsync/db/springsync.db", "/var/lib/springsync", "/var/log/springsync",
        "/run/springsync", "/srv/springsync/mnt", "/etc/springsync/keys", "/usr/local/bin/rclone",
        "/usr/local/lib/springsync/mount-helper")
    assert not c.timers_in_worker
    assert load_config(env={"ODNAS_ETC_DIR": "/x"}).p_keys == "/x/keys"


def test_bad_host_os_rejected():
    with pytest.raises(ConfigError):
        load_config(env={"ODNAS_HOST_OS": "macos"})
    with pytest.raises(ConfigError):
        load_config(env={"ODNAS_INTERNAL_TIMERS": "maybe"})


def test_toml_with_bom_from_notepad(tmp_path):
    p = tmp_path / "s.toml"
    p.write_bytes(b"\xef\xbb\xbf[app]\nslug = \"springsync\"\nhost_os = \"windows\"\n")
    assert load_config(str(p), env={}).is_windows


def test_unc_and_local_path_rules():
    assert hostos.to_unc("//unas.hotsprings.local/Personal-Drive") == r"\\unas.hotsprings.local\Personal-Drive"
    assert hostos.is_unc(r"\\unas\Home-jsmith\Docs")
    assert not hostos.is_unc(r"\\unas")
    c = wincfg()
    assert hostos.is_local_abs(c, r"\\unas\share\x") and hostos.is_local_abs(c, r"C:\data")
    assert not hostos.is_local_abs(c, "od-abc:") and not hostos.is_local_abs(c, "relative\\x")
    assert hostos.is_local_path("/srv/x") and not hostos.is_local_path("od-1:/x")
    assert hostos.is_local_path(r"\\unas\s") and not hostos.is_local_path("\\\\unas\\s\nX")
    assert hostos.under(r"\\unas\share", "a/b", "c") == r"\\unas\share\a\b\c"
    assert hostos.under("/srv/m/u", "a/b") == "/srv/m/u/a/b"
    with pytest.raises(ValueError):
        hostos.under(r"\\unas\share", "../x")
    assert hostos.norm_prefix("\\\\UNAS\\Share\\") == "//unas/share"


# ---- command building -----------------------------------------------------------------------------

def _jp(mount=r"\\unas.hotsprings.local\Personal-Drive", sub=""):
    from odnas.bisync import JobPaths
    return JobPaths(UID1, 7, r"C:\ProgramData\SpringSync\run\rclone\x.conf", mount, sub)


def test_bisync_command_on_windows_uses_unc_and_programdata(tmp_path):
    from odnas.bisync import ENC, build_bisync
    c = wincfg(state_dir=str(tmp_path))   # filters file must be renderable on Linux
    cmd = build_bisync(c, _jp(sub="Docs/Work"), max_delete_pct=50)
    assert cmd[0] == r"C:\Program Files\SpringSync\bin\rclone.exe"
    assert cmd[3] == r"\\unas.hotsprings.local\Personal-Drive\Docs\Work"
    assert cmd[cmd.index("--backup-dir2") + 1] == r"\\unas.hotsprings.local\Personal-Drive\.springsync-archive"
    assert cmd[cmd.index("--log-file") + 1] == r"C:\ProgramData\SpringSync\logs\runs" + "\\" + UID1 + r"\7.json"
    assert cmd[cmd.index("--workdir") + 1].replace("\\", "/").endswith("bisync/" + UID1)
    assert ENC[1] in cmd   # identical pinned local encoding on both hosts (SPEC §9.8)


def test_path2_rejects_dotdot_on_unc():
    with pytest.raises(ValueError):
        _jp(sub="../other").path2()


def test_pull_on_windows_accepts_unc_and_keeps_guards(tmp_path):
    from odnas.pull import backup_dir, build_pull
    c = wincfg(state_dir=str(tmp_path))
    jp = _jp()
    bk = backup_dir(r"\\backup-nas\Sync-Archive", UID1, "20261022T080000Z")
    assert bk == r"\\backup-nas\Sync-Archive" + "\\" + UID1 + r"\20261022T080000Z"
    cmd = build_pull(c, jp, op="sync", backup=bk, log_file=r"C:\x.json", max_delete=25)
    assert cmd[2] == jp.remote + ":" and cmd[3] == jp.mount_path
    assert cmd[cmd.index("--max-delete") + 1] == "25"
    same = backup_dir(r"\\unas.hotsprings.local\Personal-Drive\.springsync-archive", UID1, "s", per_user=False)
    build_pull(c, jp, op="copy", backup=same, log_file="x")         # inside dst but under the archive: ok
    with pytest.raises(ValueError):
        build_pull(c, jp, op="copy", backup=r"\\UNAS.hotsprings.local\personal-drive\Docs\bk", log_file="x")
    with pytest.raises(ValueError):
        build_pull(c, replace(jp, mount_path="od-x:"), op="copy", backup=bk, log_file="x")
    with pytest.raises(ValueError):
        build_pull(c, jp, op="sync", backup=bk, log_file="x")         # Mirror without backstop
    with pytest.raises(ValueError):
        backup_dir("gd-1:Archive", UID1, "s")


def test_touch_check_file_on_unc():
    from odnas.bisync import build_touch_check_file
    cmd = build_touch_check_file(wincfg(), r"\\unas\share", "c.conf")
    assert cmd[2] == r"\\unas\share\.springsync-check"


# ---- file locking ---------------------------------------------------------------------------------

def test_filelock_real_os_is_exclusive(tmp_path):
    a = hostos.FileLock(tmp_path / "w.lock").acquire()
    with pytest.raises(hostos.LockBusy):
        hostos.FileLock(tmp_path / "w.lock").acquire()
    a.release()
    hostos.FileLock(tmp_path / "w.lock").acquire().release()


def test_filelock_windows_branch_uses_msvcrt(tmp_path):
    held = set()

    def locking(fd, mode, n):
        if mode == fake.LK_NBLCK:
            if "x" in held:
                raise OSError(36, "busy")
            held.add("x")
        else:
            held.discard("x")
    fake = types.SimpleNamespace(LK_NBLCK=2, LK_UNLCK=0, locking=locking)
    mods = {"msvcrt": fake}
    a = hostos.FileLock(tmp_path / "l", "windows", mods).acquire()
    with pytest.raises(hostos.LockBusy):
        hostos.FileLock(tmp_path / "l", "windows", mods).acquire()
    a.release()
    assert not held


def test_worker_single_instance(cfg, db, kr, entra):
    from tests.test_scheduler import _worker
    from tests.conftest import FakeProc
    w1, w2 = _worker(cfg, db, kr, entra, FakeProc()), _worker(cfg, db, kr, entra, FakeProc())
    w1._single_instance()
    with pytest.raises(SystemExit):
        w2._single_instance()
    w1._instance_lock.release()


# ---- processes ------------------------------------------------------------------------------------

def test_popen_kwargs_per_host():
    assert hostos.popen_kwargs("linux") == {"start_new_session": True}
    flags = hostos.popen_kwargs("windows")["creationflags"]
    assert flags & hostos.CREATE_NEW_PROCESS_GROUP and flags & hostos.CREATE_NO_WINDOW


class _FakeP:
    def __init__(self, cmd, **kw):
        self.cmd, self.kw, self.pid, self.returncode = cmd, kw, 4242, None
        self.signals, self.n = [], 0
        _FakeP.last = self

    def communicate(self, timeout=None):
        self.n += 1
        if self.n <= 2:   # ignores the timeout AND the polite stop
            raise subprocess.TimeoutExpired("rclone", timeout)
        self.returncode = 1
        return b"", b""

    def send_signal(self, s):
        self.signals.append(s)

    def poll(self):
        return self.returncode


class _FakeJob:
    def __init__(self):
        self.assigned, self.terminated, self.closed = [], False, False

    def assign(self, p):
        self.assigned.append(p.pid)
        return True

    def terminate(self, code=1):
        self.terminated = True
        return True

    def close(self):
        self.closed = True


def test_process_runner_windows_timeout_ctrl_break_then_job_kill():
    from odnas.runner import ProcessRunner
    jobs = []
    pr = ProcessRunner(grace_s=0.01, host="windows", _popen=_FakeP, _job=lambda: jobs.append(_FakeJob()) or jobs[-1])
    res = pr.run(["rclone.exe", "bisync"], {"PATH": "x"}, timeout_s=0.01)
    p = _FakeP.last
    assert res.timed_out
    assert p.kw["creationflags"] & hostos.CREATE_NEW_PROCESS_GROUP and "start_new_session" not in p.kw
    assert "SystemRoot" in p.kw["env"]
    assert p.signals == [hostos.CTRL_BREAK_EVENT]      # console attach unavailable on Linux -> send_signal
    assert jobs[0].assigned == [4242] and jobs[0].terminated and jobs[0].closed


def test_hard_kill_falls_back_to_taskkill():
    calls = []
    hostos.hard_kill(types.SimpleNamespace(pid=99), "windows", None, run=lambda c, **k: calls.append(c))
    assert calls == [["taskkill", "/PID", "99", "/T", "/F"]]


def test_ctrl_break_via_console_sequence():
    log = []

    class K:
        def __getattr__(self, n):
            return lambda *a: log.append((n, a)) or 1
    assert hostos._win_break_via_console(77, K())
    names = [n for n, _ in log]
    assert names == ["FreeConsole", "AttachConsole", "SetConsoleCtrlHandler", "GenerateConsoleCtrlEvent",
                     "FreeConsole", "SetConsoleCtrlHandler"]
    assert log[3][1] == (hostos.CTRL_BREAK_EVENT, 77)


@pytest.mark.skipif(os.name == "nt", reason="off-Windows behaviour")
def test_winjob_is_inert_off_windows():
    assert not hostos.WinJob().ok


def test_request_stop_on_windows_stops_rclone(cfg, db, kr, entra):
    from tests.test_scheduler import _worker
    from tests.conftest import FakeProc
    c = replace(cfg, host_os="windows")
    w = _worker(c, db, kr, entra, FakeProc())
    stopped = []
    w.runner.proc.stop_all = lambda: stopped.append(1) or 0
    w.request_stop()
    assert stopped and w._stop.is_set() and w.draining()


# ---- NAS on Windows (WNet) ------------------------------------------------------------------------

class FakeWNet:
    def __init__(self, add_codes=None):
        self.add_codes = list(add_codes or [])
        self.added, self.cancelled = [], []

    def add(self, remote, user, password):
        self.added.append((remote, user, password))
        return self.add_codes.pop(0) if self.add_codes else 0

    def cancel(self, remote):
        self.cancelled.append(remote)
        return 0


def _client(api, **kw):
    from odnas.winshare import WindowsShareClient
    return WindowsShareClient(wincfg(), api=api, lister=lambda p: None, **kw)


def test_wnet_mount_gives_unc_path_and_umount_disconnects():
    api = FakeWNet()
    c = _client(api)
    assert c.call("mount", UID1, "//unas/Personal-Drive", "jsmith", CANARY_PW) == (H_OK, "")
    assert c.mount_path(UID1) == r"\\unas\Personal-Drive"
    assert api.added == [(r"\\unas\Personal-Drive", "jsmith", CANARY_PW)]
    assert c.call("mount", UID1, "//unas/Personal-Drive", "jsmith", CANARY_PW)[0] == H_OK   # idempotent
    assert len(api.added) == 1
    c.call("umount", UID1)
    assert api.cancelled == [r"\\unas\Personal-Drive"] and c.mount_path(UID1) == ""


@pytest.mark.parametrize("err,code", [(1326, H_AUTH), (86, H_AUTH), (1909, H_AUTH), (53, H_UNREACHABLE),
                                      (1231, H_UNREACHABLE), (67, H_OTHER), (1, H_OTHER)])
def test_wnet_error_mapping(err, code):
    c = _client(FakeWNet([err]))
    got, msg = c.call("verify", UID1, "//unas/Personal-Drive", "jsmith", CANARY_PW)
    assert got == code and CANARY_PW not in msg


def test_verify_lists_then_disconnects():
    api = FakeWNet()
    c = _client(api)
    assert c.call("verify", UID1, "//unas/Personal-Drive", "u", "p")[0] == H_OK
    assert api.cancelled == [r"\\unas\Personal-Drive"]


def test_domain_login_and_input_validation():
    api = FakeWNet()
    c = _client(api)
    c.call("mount", UID1, "//unas/S", "u", "p", "HOTSPRINGS")
    assert api.added[0][1] == "HOTSPRINGS\\u"
    assert c.call("mount", UID2, "//unas/S;rm", "u", "p")[0] == H_USAGE
    assert c.call("mount", UID2, "//unas/S", "u\nx", "p")[0] == H_USAGE
    assert c.call("mount", "not-a-uuid", "//unas/S", "u", "p")[0] == H_USAGE


def test_option_a_error_1219_serialised_per_server():
    """Two users' own logins on the same server: the second waits until the first run ends."""
    api = FakeWNet()
    c = _client(api, mount_wait_s=5, verify_wait_s=0.05)
    assert c.call("mount", UID1, "//unas/Personal-Drive", "alice", "pa")[0] == H_OK
    code, msg = c.call("verify", "33333333-3333-4333-8333-333333333333", "//unas/Personal-Drive", "bob", "pb")
    assert code == H_OTHER and "1219" in msg and "pb" not in msg
    got = []
    t = threading.Thread(target=lambda: got.append(c.call("mount", UID2, "//unas/Personal-Drive", "bob", "pb")))
    t.start()
    time.sleep(0.2)
    assert not got                                   # waiting, not failing
    c.call("umount", UID1)
    t.join(3)
    assert got == [(H_OK, "")] and c.mount_path(UID2) == r"\\unas\Personal-Drive"
    assert [a[1] for a in api.added] == ["alice", "bob"]


def test_option_b_same_login_shares_the_server():
    api = FakeWNet()
    c = _client(api, mount_wait_s=0)
    assert c.call("mount", UID1, "//unas/Home-alice", "svc-sync", "s")[0] == H_OK
    assert c.call("mount", UID2, "//unas/Home-bob", "svc-sync", "s")[0] == H_OK
    c.call("umount", UID1)
    assert api.cancelled == [r"\\unas\Home-alice"]


def test_backup_nas_on_same_server_with_other_login_fails_fast():
    c = _client(FakeWNet(), mount_wait_s=60)
    c.call("mount", UID1, "//unas/Personal-Drive", "alice", "pa")
    t0 = time.monotonic()
    code, msg = c.call("mount", ARCHIVE_IDENT, "//unas/Sync-Archive", "backup", "pb")
    assert code == H_OTHER and "different server name" in msg and time.monotonic() - t0 < 2


def test_backup_nas_on_other_server_is_independent():
    c = _client(FakeWNet(), mount_wait_s=0)
    c.call("mount", UID1, "//unas/Personal-Drive", "alice", "pa")
    assert c.call("mount", ARCHIVE_IDENT, "//unas2/Sync-Archive", "backup", "pb")[0] == H_OK
    assert c.mount_path(ARCHIVE_IDENT) == r"\\unas2\Sync-Archive"


def test_stale_1219_session_is_dropped_and_retried_once():
    api = FakeWNet([1219, 0])
    c = _client(api)
    assert c.call("mount", UID1, "//unas/S", "u", "p")[0] == H_OK
    assert api.cancelled == [r"\\unas\S"] and len(api.added) == 2


def test_windows_never_writes_credential_files(tmp_path):
    from odnas.winshare import WindowsShareClient
    c = WindowsShareClient(wincfg(runtime_dir=str(tmp_path)), api=FakeWNet(), lister=lambda p: None)
    c.call("mount", UID1, "//unas/S", "u", CANARY_PW)
    assert not any(tmp_path.rglob("*"))


def test_default_share_client_per_host(cfg):
    from odnas.nas import MountHelperClient, default_share_client
    from odnas.winshare import WindowsShareClient
    assert isinstance(default_share_client(cfg), MountHelperClient)
    assert isinstance(default_share_client(replace(cfg, host_os="windows")), WindowsShareClient)


def test_backup_target_uses_is_connected(tmp_path):
    from odnas.nas import BackupTarget

    class H:
        def __init__(self):
            self.connected, self.calls = False, []

        def is_connected(self, ident):
            return self.connected

        def call(self, *a):
            self.calls.append(a[0])
            self.connected = True
            return 0, ""

        def mount_path(self, ident):
            return str(tmp_path) if self.connected else ""
    s = types.SimpleNamespace(backup_nas_host="unas2", backup_nas_share="Sync-Archive", backup_nas_username="b",
                              secret_is_set=lambda k: True, secret=lambda k: "pw", nas_domain="",
                              pull_backup_target="backup_nas")
    h = H()
    bt = BackupTarget(wincfg(), h)
    r = bt.prepare(s, UID1, r"\\unas\Personal-Drive")
    assert r.ok and r.root == str(tmp_path) and h.calls == ["mount"]
    bt.prepare(s, UID1, r"\\unas\Personal-Drive")
    assert h.calls == ["mount"]                                  # already connected: no second session


# ---- DPAPI secrets --------------------------------------------------------------------------------

class FakeDpapi:
    def protect(self, data, entropy):
        return b"DP1" + entropy + b"|" + bytes(b ^ 0x5A for b in data)

    def unprotect(self, blob, entropy):
        head = b"DP1" + entropy + b"|"
        if not blob.startswith(head):
            raise dpapi.DpapiError("bad entropy / other account")
        return bytes(b ^ 0x5A for b in blob[len(head):])


@pytest.fixture
def fake_dpapi(monkeypatch):
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    dpapi.set_backend(FakeDpapi())
    yield
    dpapi.set_backend(None)


def test_ingest_protects_and_shreds_plaintext(tmp_path, fake_dpapi):
    c = wincfg(keys_dir=str(tmp_path / "keys"))
    inc = tmp_path / "keys" / "incoming"
    inc.mkdir(parents=True)
    key = bytes(range(32))
    (inc / "data.key").write_bytes(key)
    (inc / "google-client.secret").write_text("not-a-real-google-secret")
    (inc / "unknown.txt").write_text("ignored")
    assert dpapi.status(c)["data.key"] == "incoming"
    with pytest.raises(ConfigError, match="waiting"):
        c.read_secret("data.key")
    assert sorted(dpapi.ingest_incoming(c)) == ["data.key", "google-client.secret"]
    assert not (inc / "data.key").exists() and (inc / "unknown.txt").exists()
    blob = (tmp_path / "keys" / "data.key.dpapi").read_bytes()
    assert key not in blob
    assert c.read_secret("data.key") == key                        # Config.read_secret -> DPAPI on Windows
    from odnas.crypto import Keyring
    assert Keyring.from_config(c).primary_id
    assert dpapi.status(c)["data.key"] == "protected"
    assert dpapi.ingest_incoming(c) == []


def test_renamed_dpapi_file_does_not_decrypt(tmp_path, fake_dpapi):
    c = wincfg(keys_dir=str(tmp_path))
    (tmp_path / "incoming").mkdir()
    (tmp_path / "incoming" / "entra-client-secret").write_text("x")
    dpapi.ingest_incoming(c)
    (tmp_path / "entra-client-secret.dpapi").rename(tmp_path / "google-client.secret.dpapi")
    with pytest.raises(ConfigError, match="DPAPI"):
        c.read_secret("google-client.secret")


def test_bad_data_key_length_refused(tmp_path, fake_dpapi):
    c = wincfg(keys_dir=str(tmp_path))
    (tmp_path / "incoming").mkdir()
    (tmp_path / "incoming" / "data.key").write_bytes(b"short")
    with pytest.raises(dpapi.DpapiError):
        dpapi.ingest_incoming(c)


@pytest.mark.skipif(os.name == "nt", reason="off-Windows behaviour")
def test_dpapi_unavailable_off_windows():
    dpapi.set_backend(None)
    with pytest.raises(dpapi.DpapiError):
        dpapi.backend()


def test_keygen_creates_keys_once_with_escrow(tmp_path, fake_dpapi):
    from cryptography import x509
    from odnas.keygen import keygen
    c = wincfg(etc_dir=str(tmp_path), keys_dir=str(tmp_path / "keys"))
    out = keygen(c)
    assert any("NEW data.key" in l for l in out)
    k = (tmp_path / "keys" / "incoming" / "data.key").read_bytes()
    assert len(k) == 32 and (tmp_path / "escrow" / "data.key").read_bytes() == k
    cert = x509.load_pem_x509_certificate((tmp_path / "keys" / "entra-app.crt").read_bytes())
    assert cert.subject.rfc4514_string() == "CN=springsync-entra-app"
    assert b"PRIVATE KEY" in (tmp_path / "keys" / "incoming" / "entra-app.key").read_bytes()
    assert b"PRIVATE" not in (tmp_path / "keys" / "entra-app.crt").read_bytes()
    dpapi.ingest_incoming(c)
    assert all("kept" in l for l in keygen(c))                    # never replaces existing keys
    assert c.read_secret("data.key") == k


# ---- doctor ---------------------------------------------------------------------------------------

def _run_ok(cmd, timeout=60):
    if cmd[1] == "version":
        return subprocess.CompletedProcess(cmd, 0, "rclone v1.75.2\n- os/version: x\n", "")
    if cmd[1] == "lsf":
        return subprocess.CompletedProcess(cmd, 0, "probe.txt\n", "")
    return subprocess.CompletedProcess(cmd, 0, "dns.providers.googleclouddns\n", "")


def test_doctor_all_ok_and_bad_rclone(cfg, db, tmp_path):
    from odnas import doctor
    exe = tmp_path / "rclone"
    exe.write_text("")
    c = replace(cfg, rclone_bin=str(exe))
    db.migrate()
    checks = doctor.run_all(c, decrypt=True, run=_run_ok)
    assert doctor.exit_code(checks) == 0, doctor.render(checks)
    bad = doctor.run_all(c, run=lambda cmd, timeout=60: subprocess.CompletedProcess(cmd, 0, "rclone v1.70.0\n", ""))
    assert doctor.exit_code(bad) == 1
    assert {x.name: x.status for x in bad}["rclone_version"] == "fail"
    assert "FAIL" in doctor.render(bad)
    assert doctor.write_report(c, checks).is_file()


def test_doctor_windows_secret_states_and_escrow_warning(tmp_path, fake_dpapi):
    from odnas import doctor
    c = wincfg(etc_dir=str(tmp_path), keys_dir=str(tmp_path / "keys"))
    from odnas.keygen import keygen
    keygen(c)
    got = {x.name: x.status for x in doctor.check_secrets(c, decrypt=False)}
    assert got["secret_data.key"] == "warn" and got["key_escrow"] == "warn"
    dpapi.ingest_incoming(c)
    for f in (tmp_path / "escrow").iterdir():
        f.unlink()
    got = {x.name: x.status for x in doctor.check_secrets(c, decrypt=True)}
    assert got["secret_data.key"] == "ok" and "key_escrow" not in got and got["secrets_decrypt"] == "ok"


def test_doctor_caddy_and_nas_checks(tmp_path):
    from odnas import doctor
    exe = tmp_path / "caddy.exe"
    exe.write_text("")
    st = {c.name: c.status for c in doctor.check_caddy(wincfg(), str(exe), "Caddyfile", run=_run_ok)}
    assert st == {"caddy_dns_module": "ok", "caddy_validate": "ok"}

    def refuse(addr, timeout):
        raise ConnectionRefusedError()
    assert doctor.check_nas("unas", connect=refuse).status == "fail"


def test_doctor_long_paths_registry():
    from odnas import doctor

    class R:
        HKEY_LOCAL_MACHINE = 0

        def OpenKey(self, *a):
            return 1

        def QueryValueEx(self, k, n):
            return (0, 4)
    assert doctor.check_windows_host(R())[0].status == "fail"


# ---- maint / timers / services -------------------------------------------------------------------

def test_audit_to_file_jsonl(cfg, db, tmp_path):
    import json
    from odnas.maint import audit_to_file
    db.audit("system", "x_happened", "", {"a": 1})
    last = audit_to_file(db, 0, str(tmp_path))
    lines = next((tmp_path / "audit").glob("audit-*.jsonl")).read_text().splitlines()
    assert last >= 1 and json.loads(lines[-1])["action"] == "x_happened"
    assert audit_to_file(db, last, str(tmp_path)) == last


def test_windows_backup_tars_only_config_files(cfg, db, tmp_path):
    import tarfile
    from odnas.maint import run_backup
    etc = Path(cfg.p_etc)
    (etc / "springsync.toml").write_text("[app]\n")
    (etc / "caddy").mkdir()
    (etc / "caddy" / "Caddyfile").write_text("x")
    (etc / "caddy" / "gcp-acme-sa.json").write_text("{}")
    (etc / "big.bin").write_text("no")
    db.migrate()
    files = run_backup(replace(cfg, host_os="windows"), db, out_dir=str(tmp_path / "bk"))
    names = tarfile.open(files[1]).getnames()
    assert sorted(names) == ["config/Caddyfile", "config/springsync.toml"]


def test_daily_jobs_in_worker_on_windows(cfg, db, kr, entra, monkeypatch):
    from tests.test_scheduler import _worker
    from tests.conftest import FakeProc
    import odnas.maint as M
    ran = []
    monkeypatch.setattr(M, "run_backup", lambda *a, **k: ran.append("backup"))
    monkeypatch.setattr(M, "run_maint", lambda *a, **k: ran.append("maint"))
    lin = _worker(cfg, db, kr, entra, FakeProc())
    assert lin.daily_jobs(datetime(2026, 10, 22, 9, 0, tzinfo=timezone.utc)) == []   # Linux: systemd timers
    w = _worker(replace(cfg, host_os="windows"), db, kr, entra, FakeProc())
    assert w.daily_jobs(datetime(2026, 10, 22, 7, 0, tzinfo=timezone.utc)) == []      # 02:00 CDT: too early
    assert w.daily_jobs(datetime(2026, 10, 22, 7, 31, tzinfo=timezone.utc)) == ["backup"]   # 02:31 CDT
    monkeypatch.setattr(w, "running", lambda: {"u": "bisync"})
    assert w.daily_jobs(datetime(2026, 10, 22, 8, 40, tzinfo=timezone.utc)) == []      # maint waits for idle
    monkeypatch.setattr(w, "running", lambda: {})
    assert w.daily_jobs(datetime(2026, 10, 22, 8, 41, tzinfo=timezone.utc)) == ["maint"]
    assert w.daily_jobs(datetime(2026, 10, 22, 20, 0, tzinfo=timezone.utc)) == []      # once per local day
    assert ran == ["backup", "maint"]


def test_service_body_start_stop_reports_pending():
    from odnas.winservice import ServiceBody

    class Impl:
        def __init__(self):
            self.ev = threading.Event()

        def run(self):
            self.ev.wait(5)
            time.sleep(0.2)          # drain takes a moment

        def stop(self):
            self.ev.set()
    b = ServiceBody("worker", factory=lambda role: Impl())
    b.start()
    assert b.alive()
    pend = []
    assert b.stop(lambda: pend.append(1), max_wait_s=3, step_s=0.05)
    assert pend and not b.alive()
    with pytest.raises(ValueError):
        ServiceBody("caddy")


def test_write_private_keeps_exact_newlines(tmp_path):
    from odnas.tokens import write_private
    write_private(tmp_path / "c.conf", "a\nb\n")
    assert (tmp_path / "c.conf").read_bytes() == b"a\nb\n"


# ---- real Windows only (GitHub windows runner / the host). Skipped on Linux. ---------------------------
# These are NOT the lab tests: no service context, no NAS. They prove the ctypes calls are right.
win_only = pytest.mark.skipif(os.name != "nt", reason="needs real Windows")


@win_only
def test_real_dpapi_round_trip_and_entropy_binding(tmp_path, monkeypatch):
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    dpapi.set_backend(None)
    b = dpapi.backend()
    blob = b.protect(b"secret-bytes", b"e1")
    assert b"secret-bytes" not in blob and b.unprotect(blob, b"e1") == b"secret-bytes"
    with pytest.raises(dpapi.DpapiError):
        b.unprotect(blob, b"e2")
    c = wincfg(keys_dir=str(tmp_path))
    (tmp_path / "incoming").mkdir()
    (tmp_path / "incoming" / "data.key").write_bytes(os.urandom(32))
    assert dpapi.ingest_incoming(c) == ["data.key"]
    assert len(c.read_secret("data.key")) == 32


@win_only
def test_real_job_object_kills_child_tree():
    p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], **hostos.popen_kwargs("windows"))
    job = hostos.WinJob()
    assert job.ok and job.assign(p)
    assert job.terminate()
    assert p.wait(10) is not None
    job.close()


@win_only
def test_real_process_runner_timeout_stops_child(tmp_path):
    """Console session (not a service): CTRL_BREAK should reach the child; otherwise the hard kill must."""
    from odnas.runner import ProcessRunner
    script = tmp_path / "c.py"
    script.write_text("import signal, sys, time\n"
                      "signal.signal(signal.SIGBREAK, lambda *a: (print('got-break', flush=True), sys.exit(9)))\n"
                      "time.sleep(60)\n")
    t0 = time.monotonic()
    res = ProcessRunner(grace_s=5, host="windows").run([sys.executable, str(script)], dict(os.environ),
                                                       timeout_s=2, capture=True)
    assert res.timed_out and time.monotonic() - t0 < 30
    print("graceful" if "got-break" in res.stdout else "hard-kill", res.exit_code)


@win_only
def test_real_filelock_msvcrt(tmp_path):
    a = hostos.FileLock(tmp_path / "l", "windows").acquire()
    with pytest.raises(hostos.LockBusy):
        hostos.FileLock(tmp_path / "l", "windows").acquire()
    a.release()


@win_only
def test_real_long_paths_registry_readable():
    from odnas import doctor
    assert doctor.check_windows_host()[0].status in ("ok", "fail")


# ---- private files on both hosts (v0.10.1: Windows uses a protected DACL, not POSIX modes) ------------
def test_private_sddl_is_protected_and_owner_only():
    from odnas.privfile import private_sddl
    s = private_sddl("S-1-5-21-1-2-3-1001")
    assert s.startswith("D:P(") and s.count("(A;;FA;;;") == 3
    assert "S-1-5-18" in s and "S-1-5-32-544" in s and "S-1-5-21-1-2-3-1001" in s
    assert "WD" not in s and "BU" not in s and "AU" not in s and "OICI" not in s


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode check; the Windows DACL is tested below")
def test_write_private_tightens_an_existing_loose_file(tmp_path):
    from odnas.privfile import is_private
    from odnas.tokens import write_private
    f = tmp_path / "creds"
    f.write_text("old")
    os.chmod(f, 0o644)
    assert not is_private(f)
    write_private(f, "new")
    assert is_private(f) and f.read_text() == "new"


@win_only
def test_real_write_private_sets_a_protected_owner_only_dacl(tmp_path):
    import win32security
    from odnas.privfile import SID_ADMINS, SID_SYSTEM, current_user_sid, is_private
    from odnas.tokens import write_private
    plain = tmp_path / "plain.txt"
    plain.write_text("x")
    assert not is_private(plain)              # an ordinary file inherits its folder's ACL
    f = tmp_path / "creds"
    f.write_text("old")                        # an existing, inherited-ACL file is replaced, not reused
    write_private(f, "username=u\npassword=p\n")
    assert f.read_bytes() == b"username=u\npassword=p\n" and is_private(f)
    assert not list(tmp_path.glob(".creds.*.tmp"))
    sd = win32security.GetFileSecurity(str(f), win32security.DACL_SECURITY_INFORMATION)
    dacl = sd.GetSecurityDescriptorDacl()
    sids = {win32security.ConvertSidToStringSid(dacl.GetAce(i)[2]) for i in range(dacl.GetAceCount())}
    assert sids == {SID_SYSTEM, SID_ADMINS, current_user_sid()}


@win_only
def test_real_linux_mount_helper_refuses_to_run_on_windows():
    from odnas.nas import _default_runner
    with pytest.raises(RuntimeError, match="Linux mount helper"):
        _default_runner(["sudo", "-n", "/usr/local/lib/springsync/mount-helper", "mount", "x"])
