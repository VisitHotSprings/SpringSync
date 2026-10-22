"""One-way pull runs (SPEC v0.9 §9.7): cloud -> NAS only, `rclone copy` (Copy only) or `rclone sync`
(Mirror). Command builders, the Mirror counting dry-run parser, the guards' decisions and the §9.7.4
classifier. Pure functions (no I/O), like odnas/bisync.py; the runner does the I/O.

- build_pull refuses anything but cloud remote -> local NAS path, and never emits --inplace, --checksum,
  --track-renames, --delete-excluded, --ignore-errors or --resync: a one-way run can never write to the
  cloud and an interrupted run leaves at most a `.partial` file.
- Every replaced (Copy and Mirror) or removed (Mirror) NAS file is MOVED into the backup target with
  `--backup-dir <target>/<user_id>/<YYYY-MM-DD_HHMMSS>` (a fresh folder per run: rclone overwrites a file
  of the same path already in the backup dir). Nothing is ever deleted without a kept copy.
- Mirror only: before the real `sync`, a counting dry-run (op `pull_count`) = the same sync plus
  `--dry-run --max-delete -1 --combined <tmpfs file>`. `- path` lines are NAS files that would be moved
  away; the destination total is the `=`, `*` and `-` lines. (-1 is required: in v1.75.2 the delete is
  counted toward --max-delete before --dry-run is checked, so a limited dry-run stops early and
  undercounts.) Empty source -> safety_abort; deletes/total > pct -> safety_abort (not in service mode).
- The real sync gets `--max-delete N` (N = floor(total * pct / 100), or the approved count) as a backstop.
  When it trips, rclone has already moved up to N files (exit 7, "--max-delete threshold reached").
"""
from __future__ import annotations

from dataclasses import dataclass, field

from odnas.bisync import ENC, JobPaths, filters_path
from odnas.classify import (R_AUTH, R_CRIT_RETRY, R_ERROR, R_OK, R_RETRY, R_SAFETY, R_TIMEOUT, R_USAGE, Outcome,
                            SafetyAbort, iter_log, normalise_crit_error)
from odnas.config import Config
from odnas.entra import AUTH_CA, AUTH_OK, AUTH_REAUTH
from odnas.tokens import log_auth_classification

OPS = ("copy", "sync")
# sync_runs.op values (SPEC v0.9 §5 run kinds, recorded additively: see db.py migration 8)
OP_COUNT, OP_COPY, OP_MIRROR = "pull_count", "pull_copy", "pull_mirror"
FORBIDDEN_PULL_FLAGS = ("--force", "--inplace", "--track-renames", "--delete-excluded", "--ignore-errors",
                        "--checksum", "-c", "--onedrive-hard-delete", "--resync", "--update", "--fast-list",
                        "--drive-acknowledge-abuse", "--no-update-modtime")
MSG_MAX_DELETE = "--max-delete threshold reached"
MSG_IO_NO_DELETE = "not deleting files as there were IO errors"
RETRYABLE = {1, 3, 4, 5, 6, 8, 10}
STAMP_FMT = "%Y-%m-%d_%H%M%S"   # UTC; one backup folder per run


def backup_dir(root: str, uid: str, stamp: str, per_user: bool = True) -> str:
    """<backup NAS mount>/<user_id>/<stamp>, or (same_share) <user share>/.springsync-archive/<stamp>."""
    from odnas.hostos import is_local_path, under
    if not is_local_path(root) or ".." in root.replace("\\", "/").split("/"):
        raise ValueError("backup target must be an absolute local path")
    return under(root, uid, stamp) if per_user else under(root, stamp)


def build_pull(cfg: Config, jp: JobPaths, *, op: str, backup: str, log_file: str, dry_run: bool = False,
               max_delete: int | None = None, combined: str | None = None) -> list[str]:
    """op 'copy' (Copy only: never deletes) or 'sync' (Mirror). Source: the user's cloud remote.
    Destination: the local NAS mount path. max_delete: N >= 0 = the backstop (REQUIRED for a real Mirror run,
    v0.9.1: also in service mode), -1 = no limit (counting dry-run only)."""
    if op not in OPS:
        raise ValueError("one-way pull uses rclone copy or sync only")
    if op == "sync" and not dry_run and max_delete is None:
        raise ValueError("a real Mirror run always has the --max-delete backstop (service mode included)")
    if op == "copy" and (max_delete is not None or combined):
        raise ValueError("copy never deletes: no --max-delete, no counting")
    if max_delete is not None and max_delete < -1:
        raise ValueError("max_delete must be >= -1")
    if max_delete == -1 and not dry_run:
        raise ValueError("--max-delete -1 is only for the counting dry-run")
    if combined and not dry_run:
        raise ValueError("--combined counting is a dry-run")
    src, dst = f"{jp.remote}:", jp.path2()
    from odnas.hostos import is_local_path, norm_prefix, under
    if not is_local_path(dst):
        raise ValueError("one-way pull destination must be the local NAS mount")
    if not is_local_path(backup):
        raise ValueError("backup target must be a local path")
    inside = norm_prefix(backup).startswith(norm_prefix(dst) + "/")
    if inside and not norm_prefix(backup).startswith(norm_prefix(under(jp.mount_path, cfg.archive_dirname)) + "/"):
        # rclone: --backup-dir must not overlap the destination unless a filter excludes it
        raise ValueError("a backup dir inside the destination must be under the filtered archive folder")
    cmd = [
        cfg.p_rclone, op, src, dst,
        "--config", jp.config_path,
        "--backup-dir", backup,
        "--filter-from", str(filters_path(cfg)),
        "--exclude", f"/{cfg.check_filename}",
        "--create-empty-src-dirs",
        "--disable", "ListR",
        *ENC,
        "--retries", "3", "--retries-sleep", "30s", "--low-level-retries", "10",
        "--tpslimit", "4", "--transfers", "4", "--checkers", "8",
        "--user-agent", cfg.user_agent,
        "--use-json-log", "--log-level", "INFO", "--color", "NEVER", "--stats", "1m", "--stats-one-line",
        "--log-file", log_file,
    ]
    if op == "sync":
        cmd += ["--delete-after"]
        if max_delete is not None:
            cmd += ["--max-delete", str(max_delete)]
    if dry_run:
        cmd.append("--dry-run")
    if combined:
        cmd += ["--combined", combined]
    assert cmd[2] == src and cmd[3] == dst, "source must be the cloud, destination the NAS"
    assert not any(f in cmd for f in FORBIDDEN_PULL_FLAGS)
    return cmd


def build_check_one_way(cfg: Config, jp: JobPaths, log_file: str, skip_gdocs_flag: bool = False) -> list[str]:
    """Weekly verification for one-way users: every cloud file must be on the NAS and identical; NAS-only
    files are expected (`--one-way`)."""
    cmd = [cfg.p_rclone, "check", f"{jp.remote}:", jp.path2(), "--one-way", "--config", jp.config_path,
           "--filter-from", str(filters_path(cfg)), "--exclude", f"/{cfg.check_filename}",
           "--disable", "ListR", *ENC, "--tpslimit", "4", "--checkers", "8", "--user-agent", cfg.user_agent,
           "--use-json-log", "--log-level", "INFO", "--log-file", log_file]
    if skip_gdocs_flag:
        cmd.append("--drive-skip-gdocs")   # exported Google docs have no size/hash to compare
    return cmd


@dataclass
class Count:
    """Parsed `--combined` report of the counting dry-run. `items` has FILE NAMES (admin delta page only,
    0600 file); everything else is counts."""
    same: int = 0
    changed: int = 0
    nas_only: int = 0      # `-`: in the destination only -> Mirror moves it to the backup target
    new: int = 0           # `+`
    errors: int = 0        # `!`
    items: list[dict] = field(default_factory=list)

    @property
    def deletes(self) -> int:
        return self.nas_only

    @property
    def dest_total(self) -> int:
        return self.same + self.changed + self.nas_only

    @property
    def source_files(self) -> int:
        return self.same + self.changed + self.new

    @property
    def source_empty(self) -> bool:
        return self.source_files == 0


def parse_combined(text: str, check_filename: str = ".springsync-check", limit: int = 2000) -> Count:
    c = Count()
    ev = {"-": "deleted", "*": "changed", "+": "new"}
    for raw in text.splitlines():
        if len(raw) < 3 or raw[1] != " " or raw[0] not in "=-+*!":
            continue
        sym, name = raw[0], raw[2:]
        if name.rsplit("/", 1)[-1] == check_filename and "/" not in name:
            continue
        if sym == "=":
            c.same += 1
        elif sym == "*":
            c.changed += 1
        elif sym == "-":
            c.nas_only += 1
        elif sym == "+":
            c.new += 1
        else:
            c.errors += 1
        if sym in ev and len(c.items) < limit:
            # SPEC v0.9 §5: for pull runs the deletes are NAS-side (Path2); the cloud side is never written
            c.items.append({"side": "Path2", "where": "nas", "event": ev[sym], "name": name})
    return c


def delta_doc(c: Count) -> dict:
    """Same shape as classify.parse_deltas, so the admin delta page and Accept deletes work unchanged."""
    counts = {k: v for k, v in (("deleted", c.nas_only), ("changed", c.changed), ("new", c.new)) if v}
    items = sorted(c.items, key=lambda i: ({"deleted": 0, "changed": 1, "new": 2}[i["event"]], i["name"]))
    return {"counts": {"Path1": {}, "Path2": counts}, "items": items,
            "truncated": len(items) < c.nas_only + c.changed + c.new, "one_way": True,
            "dest_total": c.dest_total, "source_files": c.source_files}


def max_delete_allowed(dest_total: int, pct: int) -> int:
    """N for the --max-delete backstop: floor(total * pct / 100) (SPEC v0.9 §9.7.2 step 5)."""
    return (dest_total * pct) // 100


def evaluate(c: Count, *, pct: int, path: str) -> SafetyAbort | None:
    """Mirror guards on the counting dry-run (§9.7.2 step 4): empty source, then the user's percentage stop.
    v0.9.1 (Reid): service mode never loosens Mirror, so there is deliberately no service-mode argument."""
    side = {"Path2": {"deletes": c.nas_only, "total": c.dest_total, "pct": pct}}
    if c.source_empty and c.dest_total > 0:
        return SafetyAbort("empty_source", "Path2", path, None, c.nas_only, c.dest_total, side, mode="pull_mirror")
    if c.dest_total > 0 and c.nas_only * 100 > c.dest_total * pct:
        return SafetyAbort("max_delete", "Path2", path, pct, c.nas_only, c.dest_total, side, mode="pull_mirror")
    return None


def summary(c: Count, direction: str) -> str:
    s = f"one-way pull: {c.new} new, {c.changed} replaced (old NAS versions to the backup target)"
    if direction == "pull_mirror":
        return s + f"; Mirror would move {c.nas_only} NAS-only file(s) of {c.dest_total} to the backup target"
    return s + f"; {c.nas_only} NAS-only file(s) kept (Copy only never deletes)"


def classify_pull(exit_code: int | None, text: str, *, timed_out: bool = False, broker_auth: str = AUTH_OK,
                  provider: str = "onedrive", cloud: str = "cloud", max_delete: int | None = None) -> Outcome:
    """SPEC v0.9 §9.7.4. Precedence as in classify(): auth > time limit > exit code."""
    from odnas.google import AUTH_APP
    if broker_auth in (AUTH_REAUTH, AUTH_CA, AUTH_APP):
        return Outcome(R_AUTH, f"{cloud} token refresh failed ({broker_auth})", broker_auth)
    la = log_auth_classification(text, provider)
    if la != AUTH_OK and exit_code != 0:
        return Outcome(R_AUTH, f"{cloud} token refresh failed ({la})", la)
    if timed_out:
        return Outcome(R_TIMEOUT, "run time limit reached; stopped, lists again next slot")
    msgs = [e.msg for e in iter_log(text)] + [ln for ln in text.splitlines() if not ln.startswith("{")]
    if exit_code == 7 and any(MSG_MAX_DELETE in m for m in msgs):
        n = "N" if max_delete is None else str(max_delete)
        return Outcome(R_SAFETY, f"safety abort: the --max-delete backstop tripped; up to {n} NAS file(s) were "
                                 "already moved to the backup target; user paused")
    if exit_code == 0:
        return Outcome(R_OK, "ok")
    if exit_code == 2:
        return Outcome(R_USAGE, "rclone usage/syntax error (exit 2): treated as a bug; user paused")
    if exit_code in RETRYABLE:
        skipped = any(MSG_IO_NO_DELETE in m for m in msgs)
        oc = Outcome(R_RETRY, f"retryable or partial error (exit {exit_code}); retried next slot"
                              + ("; deletes_skipped (rclone did not delete because of IO errors)" if skipped else ""))
        oc.deletes_skipped = skipped
        return oc
    if exit_code is not None and exit_code < 0:
        return Outcome(R_RETRY, f"rclone killed by signal {-exit_code}")
    last = next((m for m in reversed(msgs) if m.strip()), f"exit {exit_code}")
    return Outcome(R_CRIT_RETRY, f"fatal error (exit {exit_code}); retried next slot, the same error twice pauses",
                   crit_error=normalise_crit_error(f"pull exit {exit_code}: {last}"))


def upload_limit_hit(text: str) -> bool:
    """Google's 750 GB/day per-user upload stop (two-way only; stop_on_upload_limit)."""
    return "uploadLimitExceeded" in text or "upload limit exceeded" in text.lower()


def moved_in_run(text: str) -> int:
    """NAS files moved into the backup target because they are gone from the cloud (real sync run)."""
    return sum(1 for e in iter_log(text) if e.msg == "Moved into backup dir")
