"""Integration (v0.9 §12): the REAL rclone (v1.75.2) one-way pull with our exact flag set between local
dirs. The source dir stands in for the cloud remote (od-/gd-<id>:). Skipped if rclone is absent."""
import json
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from odnas.bisync import ENC, JobPaths, LOCAL_ENCODING, build_lsf_root, render_filters
from odnas.classify import R_OK, R_SAFETY
from odnas.pull import (MSG_MAX_DELETE, backup_dir, build_pull, classify_pull, max_delete_allowed, moved_in_run,
                        parse_combined)
from odnas.tokens import render_drive_config
from tests.test_integration_rclone import RCLONE

pytestmark = [pytest.mark.integration, pytest.mark.skipif(RCLONE is None, reason="rclone binary not available")]
UID = "0b6c3a52-6d43-4c55-9d2b-6a1c9e1f0a11"


@pytest.fixture
def env(cfg, tmp_path):
    c = replace(cfg, rclone_bin=RCLONE)
    src, mnt, bk = tmp_path / "cloud", tmp_path / "nas", tmp_path / "backup"
    src.mkdir()
    (mnt / "Files").mkdir(parents=True)
    bk.mkdir()
    render_filters(c)
    return c, src, mnt, bk


def write(root: Path, files: dict):
    for k, v in files.items():
        p = root / k
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(v)


def tree(root: Path) -> dict:
    return {str(p.relative_to(root)): p.read_text() for p in sorted(root.rglob("*")) if p.is_file()}


def pull(c, src, mnt, op, backup, log, **kw):
    jp = JobPaths(UID, 1, "/dev/null", str(mnt), "Files")
    cmd = build_pull(c, jp, op=op, backup=backup, log_file=str(log), **kw)
    cmd[2] = str(src)                                  # local stand-in for the cloud remote
    i = cmd.index("--config"); del cmd[i:i + 2]
    i = cmd.index("--retries-sleep"); cmd[i + 1] = "0s"
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    return p.returncode, log.read_text() if log.exists() else "", cmd


def test_copy_never_deletes_and_backs_up_replaced(env, tmp_path):
    c, src, mnt, bk = env
    nas = mnt / "Files"
    write(src, {"a.txt": "cloud-a", "sub/b.txt": "cloud-b"})
    write(nas, {"a.txt": "nas-edit-of-a", "only-nas.txt": "keep me"})
    b1 = backup_dir(str(bk), UID, "2026-10-21_040000")
    code, log, cmd = pull(c, src, mnt, "copy", b1, tmp_path / "l1")
    assert code == 0, log
    assert "--max-delete" not in cmd and "--delete-after" not in cmd
    assert tree(nas) == {"a.txt": "cloud-a", "only-nas.txt": "keep me", "sub/b.txt": "cloud-b"}
    assert tree(Path(b1)) == {"a.txt": "nas-edit-of-a"}       # old NAS version kept, not lost
    assert classify_pull(code, log).result == R_OK


def test_mirror_counts_match_real_run_and_moves_to_dated_backup(env, tmp_path):
    c, src, mnt, bk = env
    nas = mnt / "Files"
    write(src, {"a.txt": "A", "c.txt": "C-new", "new.txt": "N"})
    write(nas, {"a.txt": "A", "c.txt": "C-old-longer", "gone1.txt": "1", "sub/gone2.txt": "2"})
    comb = tmp_path / "combined.txt"
    code, log, _ = pull(c, src, mnt, "sync", str(bk / "x"), tmp_path / "dry", dry_run=True, max_delete=-1,
                        combined=str(comb))
    assert code == 0, log
    cnt = parse_combined(comb.read_text())
    assert (cnt.same, cnt.changed, cnt.nas_only, cnt.new) == (1, 1, 2, 1)
    assert tree(nas)["gone1.txt"] == "1" and not (bk / "x").exists()       # dry run touched nothing
    b1 = backup_dir(str(bk), UID, "2026-10-21_040000")
    code, log, cmd = pull(c, src, mnt, "sync", b1, tmp_path / "real", max_delete=cnt.deletes)
    assert code == 0, log
    assert tree(nas) == {"a.txt": "A", "c.txt": "C-new", "new.txt": "N"}
    assert tree(Path(b1)) == {"c.txt": "C-old-longer", "gone1.txt": "1", "sub/gone2.txt": "2"}
    assert "--delete-after" in cmd
    assert moved_in_run(log) == 2       # only the removals (gone1, gone2), not the replaced c.txt
    # a second run with a new stamp never overwrites the first backup folder
    write(nas, {"late.txt": "L"})
    b2 = backup_dir(str(bk), UID, "2026-10-22_040000")
    code, log, _ = pull(c, src, mnt, "sync", b2, tmp_path / "real2", max_delete=1)
    assert code == 0, log
    assert tree(Path(b2)) == {"late.txt": "L"}
    assert tree(Path(b1)) == {"c.txt": "C-old-longer", "gone1.txt": "1", "sub/gone2.txt": "2"}


def test_backstop_exit_7_with_pinned_message(env, tmp_path):
    c, src, mnt, bk = env
    nas = mnt / "Files"
    write(src, {"a.txt": "A"})
    write(nas, {"a.txt": "A", **{f"g{i}.txt": str(i) for i in range(5)}})
    assert max_delete_allowed(6, 10) == 0
    code, log, _ = pull(c, src, mnt, "sync", str(bk / "s"), tmp_path / "l", max_delete=0)
    assert code == 7
    assert MSG_MAX_DELETE in log                     # the string classify_pull matches on (pinned)
    assert classify_pull(code, log, max_delete=0).result == R_SAFETY
    assert len([p for p in nas.iterdir() if p.name.startswith("g")]) == 5   # nothing removed


def test_local_encoding_is_accepted_by_rclone(env, tmp_path):
    c, src, mnt, bk = env
    write(src, {"ok.txt": "x"})
    cmd = [RCLONE, "lsf", str(src), *ENC]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    assert p.returncode == 0 and "ok.txt" in p.stdout, p.stderr
    assert "--local-encoding" in ENC and LOCAL_ENCODING in ENC
    lsf = build_lsf_root(c, str(src), "/dev/null")
    i = lsf.index("--config"); del lsf[i:i + 2]
    p = subprocess.run(lsf, capture_output=True, text=True, timeout=60)
    assert p.returncode == 0 and p.stdout.split() == ["ok.txt"], p.stderr


def test_drive_config_parses_with_real_rclone(cfg, tmp_path):
    tok = {"access_token": "x", "token_type": "Bearer", "expiry": "2000-01-01T00:00:00Z"}
    text = render_drive_config(cfg, UID, tok, "http://127.0.0.1:1/token", client_secret="placeholder")
    f = tmp_path / "r.conf"
    f.write_text(text)
    p = subprocess.run([RCLONE, "config", "dump", "--config", str(f)], capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    d = json.loads(p.stdout)[f"gd-{UID}"]
    assert d["type"] == "drive" and d["scope"] == "drive" and d["skip_gdocs"] == "true"
    assert d.get("root_folder_id", "") == "" and "shared_with_me" not in d and "use_trash" not in d
