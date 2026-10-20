"""Integration: the REAL rclone (v1.75.2) bisync between two local dirs with our exact
flag set (SPEC §12.1). Path1 stands in for OneDrive. Skipped if rclone is absent.
Set ODNAS_TEST_RCLONE=/path/to/rclone to point at a binary."""
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from odnas.bisync import JobPaths, build_bisync, render_filters
from odnas.classify import R_CRITICAL, R_OK, classify

CANDIDATES = [os.environ.get("ODNAS_TEST_RCLONE", ""),
              str(Path(__file__).resolve().parents[2] / "tools/rclone-v1.75.2-linux-amd64/rclone"),
              shutil.which("rclone") or ""]
RCLONE = next((c for c in CANDIDATES if c and Path(c).is_file()), None)
pytestmark = [pytest.mark.integration, pytest.mark.skipif(RCLONE is None, reason="rclone binary not available")]
UID = "0b6c3a52-6d43-4c55-9d2b-6a1c9e1f0a11"


@pytest.fixture
def env(cfg, tmp_path):
    from dataclasses import replace
    c = replace(cfg, rclone_bin=RCLONE)
    p1, mnt = tmp_path / "onedrive", tmp_path / "nas"
    p1.mkdir()
    (mnt / "Files").mkdir(parents=True)
    render_filters(c)
    return c, p1, mnt


def run(c, p1, mnt, run_id, **kw):
    jp = JobPaths(UID, run_id, "/dev/null", str(mnt), "Files")
    cmd = build_bisync(c, jp, max_delete_pct=10, **kw)
    cmd[2] = str(p1)                                    # local stand-in for od-<id>:
    i = cmd.index("--backup-dir1"); cmd[i + 1] = str(p1 / c.archive_dirname)
    i = cmd.index("--config"); del cmd[i:i + 2]
    i = cmd.index("--retries-sleep"); cmd[i + 1] = "1s"
    log = Path(cmd[cmd.index("--log-file") + 1])
    log.parent.mkdir(parents=True, exist_ok=True)
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    text = log.read_text() if log.exists() else ""
    return p.returncode, text, classify(p.returncode, text)


def seed(c, p1, mnt, n=20):
    for i in range(n):
        (p1 / f"f{i}.txt").write_text(f"file {i}\n")
    (p1 / "~$locked.docx").write_text("office lock")
    (p1 / "desktop.ini").write_text("x")
    for root in (p1, mnt / "Files"):
        (root / c.check_filename).write_text("check")


def test_onboarding_dryrun_then_resync_then_incremental(env):
    c, p1, mnt = env
    seed(c, p1, mnt)
    code, _, oc = run(c, p1, mnt, 1, resync=True, dry_run=True)
    assert code == 0 and oc.result == R_OK
    assert not (mnt / "Files" / "f0.txt").exists()      # dry run changed nothing
    code, _, oc = run(c, p1, mnt, 2, resync=True)
    assert code == 0 and oc.result == R_OK
    assert (mnt / "Files" / "f19.txt").read_text() == "file 19\n"
    assert not (mnt / "Files" / "~$locked.docx").exists() and not (mnt / "Files" / "desktop.ini").exists()  # filtered
    (mnt / "Files" / "new-on-nas.txt").write_text("hello")
    code, _, oc = run(c, p1, mnt, 3)
    assert code == 0 and (p1 / "new-on-nas.txt").exists()


def test_conflict_naming_and_backup_dir(env):
    c, p1, mnt = env
    seed(c, p1, mnt)
    assert run(c, p1, mnt, 1, resync=True)[0] == 0
    (p1 / "f1.txt").write_text("edited in onedrive\n")
    time.sleep(1.2)
    (mnt / "Files" / "f1.txt").write_text("edited on nas, later\n")
    (mnt / "Files" / "f2.txt").unlink()                 # 1 of 21: under max-delete
    code, text, oc = run(c, p1, mnt, 2)
    assert code == 0, text[-2000:]
    names = {p.name for p in (mnt / "Files").iterdir()} | {p.name for p in p1.iterdir()}
    assert any("sync-conflict-" in n for n in names), names   # loser kept under the conflict suffix
    assert (p1 / "f1.txt").read_text() == "edited on nas, later\n"  # newer wins
    assert not (p1 / "f2.txt").exists()
    archived = list((p1 / c.archive_dirname).rglob("*"))
    assert any(p.name.startswith("f2") for p in archived)  # deleted file kept in backup-dir1
    assert not (mnt / "Files" / c.archive_dirname).exists()  # archive dirs never synced across


def test_max_delete_abort_is_critical(env):
    c, p1, mnt = env
    seed(c, p1, mnt)
    assert run(c, p1, mnt, 1, resync=True)[0] == 0
    for i in range(3):
        (mnt / "Files" / f"f{i}.txt").unlink()           # 3 of 21 > 10%
    code, text, oc = run(c, p1, mnt, 2)
    assert code != 0 and "too many deletes" in text
    assert oc.result == R_CRITICAL                       # real rclone exits 1 here; classifier must still say critical
    assert (p1 / "f0.txt").exists()                      # nothing deleted on the other side


def test_check_access_failure_exit_7(env):
    c, p1, mnt = env
    seed(c, p1, mnt)
    assert run(c, p1, mnt, 1, resync=True)[0] == 0
    (mnt / "Files" / c.check_filename).unlink()          # e.g. wrong/empty share mounted
    code, _, oc = run(c, p1, mnt, 2)
    assert code == 7 and oc.result == R_CRITICAL


def test_rclone_version_pinned():
    out = subprocess.run([RCLONE, "version"], capture_output=True, text=True).stdout
    assert out.startswith("rclone v1.75.2")
