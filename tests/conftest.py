import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from odnas import db as D  # noqa: E402
from odnas.config import load_config  # noqa: E402
from odnas.crypto import Keyring, new_data_key  # noqa: E402
from odnas.entra import TokenResult  # noqa: E402

TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "66666666-7777-8888-9999-000000000000"
G_USERS = "aaaaaaaa-0000-0000-0000-000000000001"
G_ADMINS = "aaaaaaaa-0000-0000-0000-000000000002"
G_AUDIT = "aaaaaaaa-0000-0000-0000-000000000003"
CANARY_RT = "CANARY-REFRESH-TOKEN-do-not-leak-7f3a"
CANARY_PW = "CANARY-NAS-PASSWORD-do-not-leak-91b2"


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    keys = tmp_path / "etc" / "keys"
    keys.mkdir(parents=True)
    (keys / "data.key").write_bytes(new_data_key())
    (keys / "entra-client-secret").write_text("placeholder-secret-for-tests")
    env = {
        "ODNAS_TENANT_ID": TENANT, "ODNAS_CLIENT_ID": CLIENT,
        "ODNAS_DB_PATH": str(tmp_path / "db" / "t.db"), "ODNAS_STATE_DIR": str(tmp_path / "state"),
        "ODNAS_LOG_DIR": str(tmp_path / "log"), "ODNAS_RUNTIME_DIR": str(tmp_path / "run"),
        "ODNAS_MOUNT_ROOT": str(tmp_path / "mnt"), "ODNAS_KEYS_DIR": str(keys), "ODNAS_ETC_DIR": str(tmp_path / "etc"),
        "ODNAS_COOKIE_SECURE": "false", "ODNAS_GROUP_USERS": G_USERS, "ODNAS_GROUP_ADMINS": G_ADMINS,
        "ODNAS_GROUP_AUDITORS": G_AUDIT, "ODNAS_RCLONE_BIN": "rclone",
    }
    return load_config(env=env)


@pytest.fixture
def db(cfg):
    return D.DB(cfg.p_db)


@pytest.fixture
def kr(cfg):
    return Keyring.from_config(cfg)


class FakeEntra:
    def __init__(self):
        self.refresh_calls = []
        self.next_refresh = None
        self.claims = {}
        self.rt_counter = 0

    def begin_auth(self, redirect_uri):
        return {"state": "st-" + os.urandom(4).hex(), "auth_uri": "https://login.example.invalid/authorize",
                "redirect_uri": redirect_uri}

    def complete_auth(self, flow, query):
        if query.get("error"):
            return TokenResult(error=query["error"], error_description=query.get("error_description", ""))
        return TokenResult(access_token="at-1", refresh_token=CANARY_RT, expires_in=3600, id_claims=dict(self.claims))

    def refresh(self, rt):
        self.refresh_calls.append(rt)
        if self.next_refresh is not None:
            return self.next_refresh
        self.rt_counter += 1
        return TokenResult(access_token=f"at-{self.rt_counter}", refresh_token=f"rt-rotated-{self.rt_counter}",
                           expires_in=3600)

    def get_drive(self, at):
        return {"id": "b!drive123", "driveType": "business"}


@pytest.fixture
def entra():
    return FakeEntra()


def claims(oid="oid-1", upn="jsmith@hotsprings.org", groups=(G_USERS,), tid=TENANT):
    return {"oid": oid, "preferred_username": upn, "name": upn.split("@")[0], "tid": tid, "groups": list(groups)}


@dataclass
class FakeProc:
    """Stands in for ProcessRunner: records commands, writes a JSON log, returns scripted exit codes."""
    exit_codes: list = field(default_factory=lambda: [0])
    log_lines: list = field(default_factory=list)
    timed_out: bool = False
    stdout: str = "[]"
    calls: list = field(default_factory=list)
    auto_success: bool = True     # like real rclone: a bisync that exits 0 logs "Bisync successful"

    def run(self, cmd, env, timeout_s, capture=False, stderr_path=None):
        from odnas.runner import ProcResult
        self.calls.append((cmd, timeout_s))
        code = self.exit_codes.pop(0) if len(self.exit_codes) > 1 else self.exit_codes[0]
        if "--log-file" in cmd:
            p = Path(cmd[cmd.index("--log-file") + 1])
            p.parent.mkdir(parents=True, exist_ok=True)
            lines = list(self.log_lines)
            if code == 0 and self.auto_success and cmd[1] == "bisync":
                lines.append({"level": "info", "msg": "Bisync successful"})
            p.write_text("\n".join(json.dumps(x) for x in lines) + "\n")
        return ProcResult(code, self.timed_out, self.stdout)


class FakeHelperRunner:
    """Replaces `sudo mount-helper`: returns a scripted exit code per action."""
    def __init__(self, codes=None, mnt_root=None):
        self.codes = codes or {}
        self.calls = []
        self.uncs = []          # (action, UNC) the helper would have mounted
        self.mnt_root = mnt_root

    def __call__(self, cmd):
        action, ident = cmd[-2], cmd[-1]
        # capture what the helper would have read, then confirm the files exist with 0600
        cred = None
        if action in ("mount", "verify"):
            d = Path(self.mnt_root).parent / "run" / "creds"
            f = d / ident
            assert oct(f.stat().st_mode & 0o777) == "0o600"
            cred = f.read_text()
            self.uncs.append((action, (d / f"{ident}.unc").read_text().strip()))
        self.calls.append((action, ident, cred))
        code = self.codes.get(action, 0)
        if action == "mount" and code == 0 and self.mnt_root:
            Path(self.mnt_root, ident).mkdir(parents=True, exist_ok=True)
        return subprocess.CompletedProcess(cmd, code, "", "mount error(13): Permission denied" if code == 13 else "")


def seed_user(db, kr, *, state=D.ACTIVE, upn="jsmith@hotsprings.org", oid=None, nas=True, ms=True, **prof):
    uid = db.create_user(oid or ("oid-" + upn), upn, upn, upn.split("@")[0], state)
    if ms:
        db.put_ms_credential(kr, uid, CANARY_RT, "b!drive123", "business")
    if nas:
        db.put_nas_credential(kr, uid, "A", "jsmith", CANARY_PW)
    # an "active" test user has finished onboarding (SPEC v0.5 §6.1 step 8) unless a test says otherwise
    defaults = ({"needs_resync": 0, "last_success_at": None, "onboarding_completed_at": "2026-10-01T00:00:00+00:00"}
                if state == D.ACTIVE else {})
    defaults.update(prof)
    if defaults:
        db.update_profile(uid, **defaults)
    return uid


def pytest_addoption(parser):
    parser.addoption("--smoke", action="store_true", help="run only tests marked smoke")


def pytest_collection_modifyitems(config, items):
    if config.getoption("--smoke"):
        keep = [i for i in items if i.get_closest_marker("smoke")]
        deselected = [i for i in items if not i.get_closest_marker("smoke")]
        config.hook.pytest_deselected(items=deselected)
        items[:] = keep
