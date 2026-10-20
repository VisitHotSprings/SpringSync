"""rclone command builders (SPEC §9.3). Pure functions: easy to test, no I/O
except render_filters()."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from odnas.config import Config
from odnas.tokens import remote_name

FORBIDDEN_FLAGS = ("--inplace", "--onedrive-hard-delete", "--force", "--track-renames")


@dataclass(frozen=True)
class JobPaths:
    uid: str
    run_id: int
    config_path: str
    mount_path: str
    path2_subdir: str = ""

    def path2(self) -> str:
        sub = self.path2_subdir.strip("/")
        if ".." in sub.split("/"):
            raise ValueError("path2_subdir must not contain ..")
        return f"{self.mount_path}/{sub}" if sub else self.mount_path


def filters_path(cfg: Config) -> Path:
    return Path(cfg.p_state) / "bisync-filters.txt"


def render_filters(cfg: Config) -> tuple[Path, str]:
    """Render the repo template for this slug; returns (path, md5)."""
    text = Path(cfg.p_filters_template).read_text().replace("@SLUG@", cfg.slug)
    p = filters_path(cfg)
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.exists() or p.read_text() != text:
        p.write_text(text)
    return p, hashlib.md5(text.encode()).hexdigest()  # noqa: S324 (same digest bisync uses to detect changes)


def log_path(cfg: Config, uid: str, run_id: int) -> str:
    return f"{cfg.p_log}/runs/{uid}/{run_id}.json"


def build_bisync(cfg: Config, jp: JobPaths, *, max_delete_pct: int, resync: bool = False, dry_run: bool = False,
                 bwlimit: str = "") -> list[str]:
    if not 1 <= max_delete_pct <= 50:
        raise ValueError("max_delete_pct out of range")
    remote = remote_name(jp.uid)
    path2 = jp.path2()
    cmd = [
        cfg.rclone_bin, "bisync", f"{remote}:", path2,
        "--config", jp.config_path,
        "--workdir", f"{cfg.p_state}/bisync/{jp.uid}",
        "--compare", "size,modtime,checksum", "--slow-hash-sync-only",
        "--resilient", "--recover", "--max-lock", "2m",
        "--conflict-resolve", "newer", "--conflict-loser", "num",
        "--conflict-suffix", "sync-conflict-{DateOnly}-", "--suffix-keep-extension",
        "--max-delete", str(max_delete_pct),
        "--check-access", "--check-filename", cfg.check_filename,
        "--backup-dir1", f"{remote}:{cfg.archive_dirname}",
        "--backup-dir2", f"{jp.mount_path}/{cfg.archive_dirname}",
        "--filters-file", str(filters_path(cfg)),
        "--create-empty-src-dirs",
        "--disable", "ListR",
        "--retries", "3", "--retries-sleep", "30s", "--low-level-retries", "10",
        "--tpslimit", "4", "--transfers", "4", "--checkers", "8",
        "--user-agent", cfg.user_agent,
        "--use-json-log", "--log-level", "INFO", "--stats", "1m", "--stats-one-line",
        "--log-file", log_path(cfg, jp.uid, jp.run_id),
    ]
    if resync:
        cmd += ["--resync", "--resync-mode", "newer"]
        if bwlimit:
            cmd += ["--bwlimit", bwlimit]
    if dry_run:
        cmd.append("--dry-run")
    assert not any(f in cmd for f in FORBIDDEN_FLAGS)
    return cmd


def build_check(cfg: Config, jp: JobPaths) -> list[str]:
    """Weekly verification (SPEC §9.3): size+hash, both directions; only the mismatch count is reported."""
    remote = remote_name(jp.uid)
    return [cfg.rclone_bin, "check", f"{remote}:", jp.path2(), "--config", jp.config_path,
            "--filter-from", str(filters_path(cfg)), "--exclude", f"/{cfg.check_filename}",
            "--disable", "ListR", "--tpslimit", "4", "--checkers", "8", "--user-agent", cfg.user_agent,
            "--use-json-log", "--log-level", "INFO", "--log-file", log_path(cfg, jp.uid, jp.run_id)]


def build_lsjson(cfg: Config, target: str, config_path: str) -> list[str]:
    """Preflight listing (names/sizes only, never contents)."""
    return [cfg.rclone_bin, "lsjson", target, "-R", "--files-only", "--no-mimetype", "--no-modtime",
            "--config", config_path, "--filter-from", str(filters_path(cfg)), "--disable", "ListR",
            "--tpslimit", "4", "--user-agent", cfg.user_agent]


def build_touch_check_file(cfg: Config, target_root: str, config_path: str) -> list[str]:
    return [cfg.rclone_bin, "touch", f"{target_root.rstrip('/')}/{cfg.check_filename}" if not target_root.endswith(":")
            else f"{target_root}{cfg.check_filename}", "--config", config_path, "--user-agent", cfg.user_agent]
