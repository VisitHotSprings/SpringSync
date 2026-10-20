"""Exit-code + log classification (SPEC §9.4), with one correction found by
running the real rclone v1.75.2: with --resilient, a tripped --max-delete
("Safety abort: too many deletes") exits 1, not 7. So safety aborts are detected
from the JSON log text and treated as critical regardless of exit code.
A failed --check-access does exit 7 (verified).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from odnas.entra import AUTH_CA, AUTH_OK, AUTH_REAUTH
from odnas.tokens import log_auth_classification

R_OK, R_RETRY, R_CRITICAL, R_AUTH, R_NAS_AUTH, R_ERROR, R_TIMEOUT = (
    "ok", "retryable", "critical", "auth", "nas_auth", "error", "timeout")

SAFETY_ABORT_RE = re.compile(r"too many deletes|Safety abort|all files were changed|check file check failed|"
                             r"Access test failed|Bisync critical error|Must run --resync", re.I)
THROTTLE_RE = re.compile(r"\b(429|503)\b|Too Many Requests|throttl|activityLimitReached", re.I)
CONFLICT_RE = re.compile(r"conflict", re.I)
FILE_ERROR_RE = re.compile(r"path too long|name.*(invalid|not allowed)|is a reserved name|exceeds the maximum|"
                           r"filename.*(blocked|restricted)|case.?(collision|insensitive)", re.I)


@dataclass
class Stats:
    files_copied: int = 0
    files_deleted: int = 0
    bytes: int = 0
    errors_count: int = 0
    conflicts: int = 0
    unsyncable: int = 0
    throttled: bool = False
    messages: list[str] = field(default_factory=list)


def parse_json_log(text: str) -> Stats:
    """rclone --use-json-log: one JSON object per line; the last 'stats' object holds totals."""
    st = Stats()
    last_stats: dict = {}
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            o = json.loads(line)
        except ValueError:
            continue
        msg = str(o.get("msg", ""))
        if isinstance(o.get("stats"), dict):
            last_stats = o["stats"]
        lvl = o.get("level", "")
        if lvl in ("error", "warning") or "conflict" in msg.lower():
            st.messages.append(msg[:500])
        if CONFLICT_RE.search(msg) and ("renam" in msg.lower() or "winner" in msg.lower() or "loser" in msg.lower()):
            st.conflicts += 1
        if lvl == "error" and FILE_ERROR_RE.search(msg):
            st.unsyncable += 1
        if THROTTLE_RE.search(msg):
            st.throttled = True
    if last_stats:
        st.files_copied = int(last_stats.get("transfers", 0) or 0)
        st.files_deleted = int(last_stats.get("deletes", 0) or 0)
        st.bytes = int(last_stats.get("bytes", 0) or 0)
        st.errors_count = int(last_stats.get("errors", 0) or 0)
    return st


@dataclass
class Outcome:
    result: str
    detail: str
    auth: str = AUTH_OK      # needs_reauth / blocked_by_ca when result == auth


def classify(exit_code: int | None, log_text: str, *, timed_out: bool = False, broker_auth: str = AUTH_OK,
             stats: Stats | None = None) -> Outcome:
    """Order matters: auth (broker, then log) > timeout > safety abort > exit code."""
    stats = stats or parse_json_log(log_text)
    if broker_auth in (AUTH_REAUTH, AUTH_CA):
        return Outcome(R_AUTH, f"Microsoft token refresh failed ({broker_auth})", broker_auth)
    log_auth = log_auth_classification(log_text)
    if log_auth != AUTH_OK and exit_code != 0:
        return Outcome(R_AUTH, f"Microsoft token refresh failed ({log_auth})", log_auth)
    if timed_out:
        return Outcome(R_TIMEOUT, "run time limit reached; graceful stop, continues next slot")
    m = SAFETY_ABORT_RE.search(log_text)
    if m and exit_code != 0:
        what = "max-delete safety abort" if "delete" in m.group(0).lower() else \
            "check-access failed" if "access" in m.group(0).lower() or "check file" in m.group(0).lower() else \
            "bisync safety/critical abort"
        return Outcome(R_CRITICAL, f"{what} (exit {exit_code}); admin must review and approve resync")
    if exit_code == 0:
        return Outcome(R_OK, "ok")
    if exit_code == 7:
        return Outcome(R_CRITICAL, "bisync critical error (exit 7); admin must approve resync")
    if exit_code == 2:
        return Outcome(R_ERROR, "rclone usage/syntax error (exit 2): treated as a bug")
    if exit_code in (1, 3, 4, 5, 6):
        return Outcome(R_RETRY, f"retryable or partial error (exit {exit_code})")
    return Outcome(R_ERROR, f"unexpected exit code {exit_code}")
