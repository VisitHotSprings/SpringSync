"""Exit-code + log classification, SPEC v0.2 §9.4 (sources: rclone v1.75.2
cmd/bisync/operations.go, deltas.go, cmd.go; cmd/cmd.go resolveExitCode).

Key facts, re-verified against the real v1.75.2 binary in tests/test_integration_rclone.py:
- --max-delete tripped / "all files were changed" -> exit 1, nothing synced, nothing
  locked out, re-trips every run until a human acts  -> ``safety_abort``.
- exit 7 + "Must run --resync to recover."                         -> ``critical`` (lockout).
- exit 7 + "Error is retryable without --resync due to --resilient mode." -> ``critical_retryable``.
- any other exit-7 / code-vs-text mismatch                          -> ``critical`` (fail safe, warning logged).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from odnas.entra import AUTH_CA, AUTH_OK, AUTH_REAUTH
from odnas.tokens import log_auth_classification

R_OK, R_RETRY, R_CRITICAL, R_AUTH, R_NAS_AUTH, R_ERROR, R_TIMEOUT = (
    "ok", "retryable", "critical", "auth", "nas_auth", "error", "timeout")
R_SAFETY, R_CRIT_RETRY, R_USAGE = "safety_abort", "critical_retryable", "usage"
RESULTS = (R_OK, R_RETRY, R_CRITICAL, R_AUTH, R_NAS_AUTH, R_ERROR, R_TIMEOUT, R_SAFETY, R_CRIT_RETRY, R_USAGE)

# --- exact v1.75.2 strings (SPEC §9.4 table) ---------------------------------
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
SAFETY_OBJECT = "Safety abort"
MAX_DELETE_RE = re.compile(r'^too many deletes \(>(\d+)%, (\d+) of (\d+)\) on (Path[12]) "(.*)"\. '
                           r"Run with --force if desired\.$")
ALL_CHANGED_RE = re.compile(r'^Safety abort: all files were changed on (Path[12]) "(.*)"\. Run with --force if desired\.$')
TEXT_SAFETY_PREFIX = "Safety abort: "          # text-mode output prefixes the object: "ERROR : Safety abort: too many..."
MSG_SUCCESS = "Bisync successful"
MSG_LOCKOUT = "Bisync aborted. Must run --resync to recover."
MSG_RETRYABLE = "Bisync aborted. Error is retryable without --resync due to --resilient mode."
MSG_CRITICAL_PREFIX = "Bisync critical error: "
MSG_ACCESS_PREFIX = "Access test failed:"
DELTA_RE = re.compile(r"^- (Path[12])\s+(File was deleted|File is new|File changed: .+?|File is newer|File is older|"
                      r"File size changed|File was renamed)\s+- (.+)$")
SIDE_LABEL = {"Path1": "OneDrive", "Path2": "NAS"}
RETRYABLE_EXITS = (1, 3, 4, 5, 6, 8, 10)
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
class SafetyAbort:
    """Parsed from the safety-abort message. Holds counts and the remote root only, never filenames."""
    check: str                 # "max_delete" | "all_files_changed"
    side: str                  # "Path1" (OneDrive) | "Path2" (NAS)
    path: str
    pct: int | None = None
    deletes: int | None = None
    total: int | None = None

    def summary(self) -> str:
        where = SIDE_LABEL.get(self.side, self.side)
        if self.check == "max_delete":
            return f"too many deletes on {where} ({self.deletes} of {self.total}, limit {self.pct}%)"
        return f"all files were changed on {where}"

    def as_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class Outcome:
    result: str
    detail: str
    auth: str = AUTH_OK      # needs_reauth / blocked_by_ca when result == auth
    safety: SafetyAbort | None = None
    warning: str = ""        # classifier warning (code/text mismatch), logged by the caller


@dataclass
class LogEntry:
    level: str
    msg: str
    obj: str = ""


def iter_log(text: str):
    """JSON-log lines -> LogEntry; also accepts text-mode lines ("ERROR : msg") as a fallback."""
    for raw in text.splitlines():
        line = ANSI_RE.sub("", raw).strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                o = json.loads(line)
            except ValueError:
                continue
            yield LogEntry(str(o.get("level", "")), ANSI_RE.sub("", str(o.get("msg", ""))).strip(),
                           str(o.get("object", "")) if o.get("objectType") in (None, "string") else "")
            continue
        m = re.match(r"^(?:\S+ \S+ )?(ERROR|NOTICE|INFO|DEBUG|WARNING)\s*: (.*)$", line)
        if m:
            yield LogEntry(m.group(1).lower(), m.group(2).strip())


def find_safety_abort(entries: list[LogEntry]) -> SafetyAbort | None:
    for e in entries:
        msg = e.msg
        if e.obj != SAFETY_OBJECT and msg.startswith(TEXT_SAFETY_PREFIX + "too many deletes"):
            msg = msg[len(TEXT_SAFETY_PREFIX):]          # text mode: object rendered as a prefix
            obj = SAFETY_OBJECT
        else:
            obj = e.obj
        m = MAX_DELETE_RE.match(msg)
        if m and obj == SAFETY_OBJECT:
            return SafetyAbort("max_delete", m.group(4), m.group(5), int(m.group(1)), int(m.group(2)), int(m.group(3)))
        m = ALL_CHANGED_RE.match(e.msg)
        if m:
            return SafetyAbort("all_files_changed", m.group(1), m.group(2))
    return None


def parse_deltas(text: str, limit: int = 2000) -> dict:
    """Delta list from a `bisync --dry-run --force` log (what the run would do). Contains FILENAMES:
    callers keep it in a 0600 file for the admin page only, never in the DB / issues / auditor view."""
    counts: dict[str, dict[str, int]] = {"Path1": {}, "Path2": {}}
    items: list[dict] = []
    for e in iter_log(text):
        m = DELTA_RE.match(e.msg)
        if not m:
            continue
        side, event, name = m.group(1), m.group(2), m.group(3).strip()
        key = "deleted" if event == "File was deleted" else "new" if event == "File is new" else "changed"
        counts[side][key] = counts[side].get(key, 0) + 1
        if len(items) < limit:
            items.append({"side": side, "where": SIDE_LABEL[side], "event": key, "name": name})
    return {"counts": counts, "items": items, "truncated": sum(sum(c.values()) for c in counts.values()) > len(items)}


def delta_summary(d: dict) -> str:
    parts = []
    for side in ("Path1", "Path2"):
        c = d["counts"].get(side, {})
        if c:
            parts.append(f"{SIDE_LABEL[side]}: " + ", ".join(f"{v} {k}" for k, v in sorted(c.items())))
    return "; ".join(parts) or "no changes detected"


def classify(exit_code: int | None, log_text: str, *, timed_out: bool = False, broker_auth: str = AUTH_OK,
             stats: Stats | None = None) -> Outcome:
    """Pre-checks (not in the §9.4 list, which assumes rclone ran to completion):
    broker auth > auth text in the log > worker time limit. Then SPEC §9.4 rules 1-6 in order."""
    if broker_auth in (AUTH_REAUTH, AUTH_CA):
        return Outcome(R_AUTH, f"Microsoft token refresh failed ({broker_auth})", broker_auth)
    log_auth = log_auth_classification(log_text)
    if log_auth != AUTH_OK and exit_code != 0:
        return Outcome(R_AUTH, f"Microsoft token refresh failed ({log_auth})", log_auth)
    if timed_out:
        return Outcome(R_TIMEOUT, "run time limit reached; graceful stop, continues next slot")

    entries = list(iter_log(log_text))
    msgs = [e.msg for e in entries]
    success = MSG_SUCCESS in msgs
    lockout = MSG_LOCKOUT in msgs
    retryable_text = MSG_RETRYABLE in msgs
    crit_err = next((m[len(MSG_CRITICAL_PREFIX):] for m in msgs if m.startswith(MSG_CRITICAL_PREFIX)), "")
    access = any(m.startswith(MSG_ACCESS_PREFIX) for m in msgs)
    why = f": {crit_err.splitlines()[0][:160]}" if crit_err else (": check-access failed" if access else "")

    # 1. ok
    if exit_code == 0 and success and not (lockout or retryable_text or crit_err):
        return Outcome(R_OK, "ok")
    # 2. safety abort, any exit code (expected: 1)
    sa = find_safety_abort(entries)
    if sa is not None:
        warn = "" if exit_code == 1 else f"safety abort with unexpected exit {exit_code}"
        return Outcome(R_SAFETY, f"safety abort: {sa.summary()}; user paused, admin must Restore or Accept deletes",
                       safety=sa, warning=warn)
    # 3. lockout
    if exit_code == 7 and lockout:
        return Outcome(R_CRITICAL, f"bisync critical error, listings locked out{why}; admin must approve resync")
    # 4. retryable critical (--resilient)
    if exit_code == 7 and retryable_text:
        return Outcome(R_CRIT_RETRY, f"bisync aborted, retryable under --resilient{why}; next run proceeds")
    # 6 (mismatches) before 5, so a code that looks harmless can't hide critical text
    if exit_code == 7:
        return Outcome(R_CRITICAL, f"exit 7 without a recognised abort message{why}; admin must approve resync",
                       warning="exit 7 with neither lockout nor retryable text")
    if exit_code is not None and exit_code >= 0 and (lockout or retryable_text or crit_err):
        return Outcome(R_CRITICAL, f"critical bisync text with exit {exit_code}{why}; admin must approve resync",
                       warning=f"critical text with exit {exit_code}")
    if exit_code == 0:
        return Outcome(R_CRITICAL, "exit 0 without 'Bisync successful' in the log; admin must review",
                       warning="exit 0 without success line")
    # 5. by exit code
    if exit_code == 2:
        return Outcome(R_USAGE, "rclone usage/syntax error (exit 2): treated as a bug; user paused")
    if exit_code in RETRYABLE_EXITS:
        return Outcome(R_RETRY, f"retryable or partial error (exit {exit_code})")
    if exit_code is not None and exit_code < 0:
        return Outcome(R_RETRY, f"rclone killed by signal {-exit_code}; --recover handles the next run")
    return Outcome(R_CRITICAL, f"unexpected exit code {exit_code}; admin must review",
                   warning=f"unexpected exit code {exit_code}")
