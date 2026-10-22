"""Opt-in nightly auto-update: the decision half (SPEC §11.4.1, v0.11).

`deploy/auto-update.sh` (root, run by the <slug>-autoupdate timer) asks this module, running as the
service account, which tag to install, then runs the normal `deploy/update.sh <tag>` and reports the
result back here. This module never installs anything itself and has no root-only code.

Rules (SPEC §11.4.1, each one has a test in tests/test_v11_autoupdate.py):
1. Off by default: `[auto_update] enabled = true` in the server's local config. A failed update writes
   `<etc>/auto-update.disabled` (by auto-update.sh); while it exists nothing runs until an admin re-enables.
2. Window 02:45 Central + up to 30 min (the timer). Never before the 02:30 backup has finished (auto-update.sh
   waits up to 15 min, then skips with `backup_running`), never while update.sh or maintenance holds the update
   lock, and never while a Mirror run, an approval or a safety hold is pending (blockers()).
3. Only normal published GitHub releases with a plain `vX.Y.Z` tag: no drafts, no pre-releases, no suffixes
   (`-rc1`, `-beta`), no branches. A tag without a published release is ignored too.
4. The release must be at least 24 h old.
5. Patch releases of the running minor only (v0.11.x). A newer minor/major is audited + alerted and waits
   for a manual `update.sh`.
6. Tag signatures are checked by auto-update.sh (git verify-tag) when `require_signed_tags` is on.
7. Install path = update.sh (drain, pre-<tag> backup, smoke tests, health check, automatic rollback).
8. Every check writes an audit entry (checked / skipped and why / installed / rolled back).
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from odnas import db as D
from odnas.config import Config
from odnas.notify import Alert, Alerter

log = logging.getLogger("odnas.autoupdate")

TAG_RE = re.compile(r"^v(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\Z")
MIN_AGE = timedelta(hours=24)
DISABLED_FILE = "auto-update.disabled"
HEARTBEAT = "auto_update"
API = "https://api.github.com/repos/{repo}/releases?per_page=100"
# alert/issue types (one open issue per type; a newer event updates nothing until the issue is closed)
ISSUE_MANUAL = "auto_update_manual_needed"
ISSUE_FAILED = "auto_update_failed"
ISSUE_INSTALLED = "auto_update_installed"
ISSUE_REFUSED = "auto_update_refused"

Version = tuple[int, int, int]


class FetchError(RuntimeError):
    pass


def parse_tag(tag: str) -> Version | None:
    """`vX.Y.Z` only (no leading zeros, no suffix, no branch names). Anything else -> None."""
    m = TAG_RE.match(tag or "")
    return (int(m[1]), int(m[2]), int(m[3])) if m else None


def is_newer(candidate: str, current: str) -> bool:
    """Strict semver comparison of two plain tags; False if either is not a valid `vX.Y.Z`."""
    a, b = parse_tag(candidate), parse_tag(current)
    return bool(a and b and a > b)


@dataclass(frozen=True)
class Release:
    tag: str
    draft: bool
    prerelease: bool
    published_at: datetime | None   # None for drafts (never published)
    created_at: datetime | None = None

    @property
    def visible_since(self) -> datetime | None:
        """When the release became public. The later of created/published, so a tag cut long ago but
        published just now still waits 24 h."""
        times = [t for t in (self.published_at, self.created_at) if t]
        return max(times) if self.published_at and times else None


def _ts(s) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def releases_from_api(payload) -> list[Release]:
    if not isinstance(payload, list):
        raise FetchError("unexpected GitHub API response")
    out = []
    for r in payload:
        if isinstance(r, dict) and isinstance(r.get("tag_name"), str):
            out.append(Release(r["tag_name"], bool(r.get("draft", True)), bool(r.get("prerelease", True)),
                               _ts(r.get("published_at")), _ts(r.get("created_at"))))
    return out


def fetch_releases(repo: str, user_agent: str, timeout: float = 20.0) -> list[Release]:
    """Anonymous GitHub REST call (public repo, no token). Raises FetchError on any failure."""
    import httpx
    try:
        r = httpx.get(API.format(repo=repo), timeout=timeout, follow_redirects=False,
                      headers={"Accept": "application/vnd.github+json", "User-Agent": user_agent,
                               "X-GitHub-Api-Version": "2022-11-28"})
        r.raise_for_status()
        return releases_from_api(r.json())
    except FetchError:
        raise
    except Exception as e:   # network, HTTP status, bad JSON: never fatal, the next night tries again
        raise FetchError(f"{type(e).__name__}: {str(e)[:200]}") from e


@dataclass(frozen=True)
class Decision:
    action: str                 # "install" | "none"
    reason: str                 # machine-readable reason (audited)
    tag: str = ""               # tag to install, or the tag the reason is about
    newer_minor: str = ""       # newest eligible release of a newer minor/major (needs a manual update)


def eligible(r: Release) -> bool:
    """A normal published release with a plain vX.Y.Z tag (SPEC §11.4.1 rule 3)."""
    return parse_tag(r.tag) is not None and not r.draft and not r.prerelease and r.published_at is not None


def choose(current: str, releases: list[Release], now: datetime) -> Decision:
    """Pure decision: what (if anything) to auto-install over `current`."""
    cur = parse_tag(current)
    if cur is None:
        return Decision("none", "current_version_unknown", current)
    newer = [r for r in releases if eligible(r) and parse_tag(r.tag) > cur]
    old_enough = [r for r in newer if r.visible_since and now - r.visible_since >= MIN_AGE]
    key = lambda r: parse_tag(r.tag)  # noqa: E731
    patches = [r for r in old_enough if parse_tag(r.tag)[:2] == cur[:2]]
    minors = [r for r in old_enough if parse_tag(r.tag)[:2] != cur[:2]]
    newer_minor = max(minors, key=key).tag if minors else ""
    if patches:
        return Decision("install", "newer_patch", max(patches, key=key).tag, newer_minor)
    young = [r for r in newer if r not in old_enough and parse_tag(r.tag)[:2] == cur[:2]]
    if young:
        return Decision("none", "waiting_period", max(young, key=key).tag, newer_minor)
    if newer_minor:
        return Decision("none", "newer_minor_needs_manual_update", newer_minor, newer_minor)
    return Decision("none", "up_to_date", current)


def blockers(db: D.DB) -> list[str]:
    """SPEC §11.4.1 rule 2: never while a Mirror run or an approval is pending."""
    out = []
    if db.one("SELECT 1 FROM sync_runs WHERE ended_at IS NULL AND (direction='pull_mirror' "
              "OR op IN ('pull_mirror','pull_count'))"):
        out.append("mirror_run_in_progress")
    if db.one("SELECT 1 FROM sync_profiles WHERE safety_accept_state=? OR mirror_baseline_state=? "
              "OR direction_req IS NOT NULL", (D.ACCEPT_PENDING, "pending")):
        out.append("approval_pending")
    # v0.11.0 / SPEC v0.10 rule 7: an open safety hold (percentage stop or Mirror --max-delete backstop; both
    # leave the user in state safety_abort until Restore / Accept deletes) also skips the night.
    if db.one("SELECT 1 FROM users WHERE state=?", (D.SAFETY_ABORT,)):
        out.append("safety_hold")
    return out


def disabled_flag(cfg: Config) -> Path:
    return Path(cfg.p_etc) / DISABLED_FILE


def state(cfg: Config, db: D.DB) -> dict:
    """Read-only view for the admin Settings page (SPEC §11.4.1 rule 1: shown, never changed by the GUI)."""
    hb = db.heartbeat(HEARTBEAT)
    try:
        last = json.loads(hb["detail"]) if hb and hb["detail"] else None
    except ValueError:
        last = None
    return {"enabled": cfg.auto_update_enabled, "self_disabled": disabled_flag(cfg).exists(),
            "signed_tags": cfg.auto_update_require_signed_tags, "repo": cfg.auto_update_repo, "last": last}


def _record(db: D.DB, event: str, detail: dict, now: datetime) -> None:
    db.audit("system", "auto_update_" + event, detail.get("tag", ""), detail)
    db.beat(HEARTBEAT, json.dumps({"at": D.iso(now), "result": event, **detail}, sort_keys=True))


def check(cfg: Config, db: D.DB, current: str,
          fetch: Callable[[], list[Release]] | None = None, now: datetime | None = None) -> Decision:
    """One nightly check. Audits the outcome (except when auto-update is simply off) and alerts when a
    newer minor/major waits for a manual update. Never raises for network problems."""
    now = now or D.utcnow()
    if not cfg.auto_update_enabled:
        return Decision("none", "disabled")
    if disabled_flag(cfg).exists():
        d = Decision("none", "disabled_after_failure")
        _record(db, "skipped", {"reason": d.reason, "current": current}, now)
        return d
    if parse_tag(current) is None:
        d = Decision("none", "current_version_unknown", current)
        _record(db, "skipped", {"reason": d.reason, "current": current}, now)
        return d
    block = blockers(db)
    if block:
        d = Decision("none", block[0])
        _record(db, "skipped", {"reason": ",".join(block), "current": current}, now)
        return d
    try:
        rels = (fetch or (lambda: fetch_releases(cfg.auto_update_repo, cfg.user_agent)))()
    except FetchError as e:
        log.warning("auto-update: could not read releases (%s); nothing changed, will retry next night", e)
        _record(db, "skipped", {"reason": "fetch_failed", "current": current, "error": str(e)[:200]}, now)
        return Decision("none", "fetch_failed")
    d = choose(current, rels, now)
    detail = {"reason": d.reason, "current": current, "tag": d.tag}
    if d.newer_minor:
        detail["newer_minor"] = d.newer_minor
        Alerter(db).raise_(Alert(ISSUE_MANUAL, "medium",
                                 f"{d.newer_minor} is available but is a new minor/major version: auto-update "
                                 f"only installs patch releases of {current}. Run update.sh {d.newer_minor} by hand."))
    _record(db, "checked" if d.action == "install" or d.reason == "up_to_date" else "skipped", detail, now)
    return d


def report(cfg: Config, db: D.DB, event: str, tag: str, from_: str, now: datetime | None = None) -> None:
    """auto-update.sh reports what it did: installed | failed | refused_unsigned | reenabled, or why it skipped
    the night before checking: backup_running (the 02:30 backup was still running after 15 min) | busy (a manual
    update.sh or the 03:30 maintenance job holds the update lock)."""
    now = now or D.utcnow()
    detail = {"tag": tag, "from": from_}
    al = Alerter(db)
    if event == "installed":
        _record(db, "installed", detail, now)
        al.resolve(None, ISSUE_INSTALLED)   # one alert per install: close the previous one first
        al.raise_(Alert(ISSUE_INSTALLED, "low", f"Auto-update installed {tag} (was {from_})."))
    elif event == "failed":
        _record(db, "rolled_back", detail, now)
        _record(db, "self_disabled", {**detail, "reason": "update_failed"}, now)
        al.raise_(Alert(ISSUE_FAILED, "high",
                        f"Auto-update to {tag} failed and was rolled back to {from_}. Auto-update is now OFF "
                        "until an admin re-enables it (auto-update.sh --reenable)."))
    elif event == "refused_unsigned":
        _record(db, "refused", {**detail, "reason": "tag_signature_invalid"}, now)
        al.raise_(Alert(ISSUE_REFUSED, "high", f"Auto-update refused {tag}: the tag is unsigned or not signed by "
                                               "an allowed key. Nothing changed."))
    elif event in ("backup_running", "busy"):   # auto-update.sh skipped tonight before the check
        reason = "backup_running" if event == "backup_running" else "update_or_maintenance_running"
        _record(db, "skipped", {"reason": reason, "current": tag}, now)
    elif event == "reenabled":
        _record(db, "reenabled", detail, now)
        al.resolve(None, ISSUE_FAILED, ISSUE_REFUSED)
    else:
        raise ValueError(f"unknown auto-update event {event!r}")
