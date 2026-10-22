import configparser
import json
import os
from pathlib import Path

import pytest

from odnas.bisync import FORBIDDEN_FLAGS, JobPaths, build_bisync, build_check, render_filters
from odnas.tokens import (BrokerTokenStrategy, TmpfsConfigStrategy, TokenBroker, remote_name, render_rclone_config)
from tests.conftest import CANARY_RT, seed_user

pytestmark = pytest.mark.smoke

UID = "0b6c3a52-6d43-4c55-9d2b-6a1c9e1f0a11"


def flag_value(cmd, flag):
    return cmd[cmd.index(flag) + 1]


def test_bisync_command_matches_spec(cfg):
    jp = JobPaths(UID, 42, "/run/springsync/rclone/x.conf", f"/srv/springsync/mnt/{UID}")
    cmd = build_bisync(cfg, jp, max_delete_pct=10)
    assert cmd[:4] == ["rclone", "bisync", f"od-{UID}:", f"/srv/springsync/mnt/{UID}"]
    assert flag_value(cmd, "--compare") == "size,modtime,checksum"
    for f in ("--slow-hash-sync-only", "--resilient", "--recover", "--check-access", "--create-empty-src-dirs",
              "--suffix-keep-extension", "--use-json-log", "--stats-one-line"):
        assert f in cmd
    assert flag_value(cmd, "--max-lock") == "2m"
    assert flag_value(cmd, "--color") == "NEVER"          # SPEC v0.2 §9.3
    assert "--force" not in cmd                            # never on a scheduled run
    assert flag_value(cmd, "--conflict-resolve") == "newer"
    assert flag_value(cmd, "--conflict-loser") == "num"
    assert flag_value(cmd, "--conflict-suffix") == "sync-conflict-{DateOnly}-"
    assert flag_value(cmd, "--max-delete") == "10"
    assert flag_value(cmd, "--check-filename") == ".springsync-check"
    assert flag_value(cmd, "--backup-dir1") == f"od-{UID}:.springsync-archive"
    assert flag_value(cmd, "--backup-dir2") == f"/srv/springsync/mnt/{UID}/.springsync-archive"
    assert flag_value(cmd, "--disable") == "ListR"
    assert flag_value(cmd, "--tpslimit") == "4"
    assert flag_value(cmd, "--retries") == "3" and flag_value(cmd, "--retries-sleep") == "30s"
    assert flag_value(cmd, "--low-level-retries") == "10"
    assert flag_value(cmd, "--transfers") == "4" and flag_value(cmd, "--checkers") == "8"
    assert flag_value(cmd, "--user-agent") == "NONISV|VisitHotSprings|SpringSync/0.9"
    assert flag_value(cmd, "--workdir").endswith(f"/bisync/{UID}")
    assert flag_value(cmd, "--log-file").endswith(f"/runs/{UID}/42.json")
    assert flag_value(cmd, "--filters-file").endswith("bisync-filters.txt")
    assert "--resync" not in cmd and "--dry-run" not in cmd
    assert not set(FORBIDDEN_FLAGS) & set(cmd)


def test_resync_and_dryrun_flags(cfg):
    jp = JobPaths(UID, 1, "c", "/m", "Documents")
    cmd = build_bisync(cfg, jp, max_delete_pct=5, resync=True, dry_run=True, bwlimit="20M")
    assert cmd[3] == "/m/Documents"
    assert flag_value(cmd, "--resync-mode") == "newer" and "--resync" in cmd and "--dry-run" in cmd
    assert flag_value(cmd, "--bwlimit") == "20M"
    assert flag_value(cmd, "--backup-dir2") == "/m/.springsync-archive"  # outside path2, same local fs


def test_bad_inputs_rejected(cfg):
    with pytest.raises(ValueError):
        build_bisync(cfg, JobPaths(UID, 1, "c", "/m"), max_delete_pct=80)
    with pytest.raises(ValueError):
        build_bisync(cfg, JobPaths(UID, 1, "c", "/m", "../etc"), max_delete_pct=10)


def test_check_command(cfg):
    cmd = build_check(cfg, JobPaths(UID, 7, "c", "/m"))
    assert cmd[1] == "check" and "--filter-from" in cmd and "--one-way" not in cmd


def test_filters_rendered_for_slug(cfg):
    p, md5 = render_filters(cfg)
    text = p.read_text()
    for rule in ("- .springsync-archive/**", "- ~$*", "- desktop.ini", "- Thumbs.db", "- /Personal Vault/**",
                 "- .springsync-check-*", "- #recycle/**", "- .snapshot/**", "- .~lock.*", "- *.tmp", "- .DS_Store"):
        assert rule in text
    rules = [line for line in text.splitlines() if line.startswith("-")]
    assert "- .springsync-check" not in rules  # the check file itself must NOT be excluded
    assert len(md5) == 32


def test_rclone_config_broker_mode(cfg, db, kr, entra):
    uid = seed_user(db, kr)
    broker = TokenBroker(db, kr, entra, cfg)
    strat = BrokerTokenStrategy(cfg, db, broker)
    auth = strat.prepare(uid, 5)
    text = auth.config_path.read_text()
    assert oct(os.stat(auth.config_path).st_mode & 0o777) == "0o600"
    cp = configparser.ConfigParser(interpolation=None)
    cp.read_string(text)
    sec = cp[remote_name(uid)]
    assert sec["type"] == "onedrive" and sec["drive_type"] == "business" and sec["drive_id"] == "b!drive123"
    assert sec["token_url"] == f"http://127.0.0.1:8081/broker/{uid}/token"
    assert sec["auth_url"] == f"https://login.microsoftonline.com/{cfg.tenant_id}/oauth2/v2.0/authorize"
    assert sec["access_scopes"] == "Files.ReadWrite offline_access"
    assert sec["disable_site_permission"] == "true"
    assert sec["client_secret"] == ""
    tok = json.loads(sec["token"])
    assert tok["refresh_token"] == auth.handle and tok["expiry"].startswith("2000-")
    assert CANARY_RT not in text  # real refresh token never on disk in broker mode
    strat.finish(uid, auth)
    assert not auth.config_path.exists()
    assert broker.active_handles() == 0


def test_rclone_config_tmpfs_fallback_reads_back_rotation(cfg, db, kr):
    uid = seed_user(db, kr)
    strat = TmpfsConfigStrategy(cfg, db, kr)
    auth = strat.prepare(uid, 5)
    text = auth.config_path.read_text()
    assert CANARY_RT in text and "placeholder-secret-for-tests" in text
    assert f"token_url = https://login.microsoftonline.com/{cfg.tenant_id}/oauth2/v2.0/token" in text
    # simulate rclone writing back a rotated token
    new = text.replace(CANARY_RT, "rt-rotated-by-rclone")
    auth.config_path.write_text(new)
    strat.finish(uid, auth)
    assert db.refresh_token(kr, uid) == "rt-rotated-by-rclone"
    assert not auth.config_path.exists()


def test_config_rejects_injection(cfg):
    with pytest.raises(ValueError):
        render_rclone_config(cfg, UID, "drive\n[evil]", "business", {}, "http://x")


def test_force_only_when_asked_and_never_with_resync(cfg):
    import pytest
    jp = JobPaths(UID, 1, "/run/x.conf", f"/srv/springsync/mnt/{UID}")
    assert "--force" in build_bisync(cfg, jp, max_delete_pct=10, force=True)
    d = build_bisync(cfg, jp, max_delete_pct=10, force=True, dry_run=True)
    assert "--force" in d and "--dry-run" in d and "--resync" not in d
    with pytest.raises(ValueError):
        build_bisync(cfg, jp, max_delete_pct=10, force=True, resync=True)
