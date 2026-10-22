"""Cloud provider and sync direction per user (SPEC v0.9 §4.4, §6.6).

Provider (`sync_profiles.provider`): `onedrive` (remote od-<id>) or `gdrive` (gd-<id>), one per user, set by
an admin. App sign-in stays Microsoft for everyone; a gdrive user connects Google Drive from their page.

Direction (`sync_profiles.direction`): `two_way` (bisync), `pull_copy` (one-way, Copy only: `rclone copy`,
never deletes on the NAS) or `pull_mirror` (one-way, Mirror: `rclone sync`, NAS files missing from the cloud
are MOVED to the backup target). New users get Settings `default_direction`.

Switching (admin only, a reason is required, audited, `low` alert). The web page only records the request
(`direction_req*`); the worker applies it between runs (apply_direction_changes runs at the top of each tick
and skips users whose job is running), so a switch never lands in the middle of a run:
- two_way -> pull_copy: listings set aside (`*.lst*` renamed `-old-<ts>`), needs_resync=1; next run copies.
- -> pull_mirror (from two_way or Copy only): the same set-aside from two_way, then the Mirror baseline:
  mirror_baseline_ok_at = NULL. The worker counts (kind delta / op pull_count); 0 -> proceeds; otherwise an
  admin approves the exact count (24 h expiry, recount right before the run, cancelled on a mismatch).
  Until then the user keeps getting Copy-only runs (they never delete).
- pull_mirror -> pull_copy: immediate.
- pull_* -> two_way: fresh bisync baseline: listings deleted, gdocs_mode forced to skip, filename preflight,
  check files on both roots, `bisync --resync --dry-run` whose summary shows the upload count, then an
  admin's Approve resync (the user is put back in the onboarding flow; onboarding_completed_at is kept).
  "Mirror first" (default when coming from Copy only): the user is switched to pull_mirror first
  (direction_then = two_way); once the approved Mirror baseline has run, the two-way switch is applied.
  Service mode waits for two_way_baseline_at (first successful normal bisync afterwards).
- In safety_abort or critical, a switch clears the pending Restore/Accept/Approve-resync choice (audited)
  and the new direction's baseline rules apply. Paused / needs_reauth / blocked / NAS-login-failed users
  get one-way switches at once (they stay stopped); a switch back to two-way waits until they are active.
"""
from __future__ import annotations

import shutil
from datetime import timedelta
from pathlib import Path

from odnas import db as D
from odnas.notify import Alert, Alerter

PROVIDER_OD, PROVIDER_GD = "onedrive", "gdrive"
PROVIDERS = (PROVIDER_OD, PROVIDER_GD)
PROVIDER_LABELS = {PROVIDER_OD: "Microsoft OneDrive", PROVIDER_GD: "Google Drive (My Drive)"}
CLOUD_SIDE = {PROVIDER_OD: "OneDrive", PROVIDER_GD: "Google Drive"}
TWO_WAY, PULL_COPY, PULL_MIRROR = "two_way", "pull_copy", "pull_mirror"
DIRECTIONS = (TWO_WAY, PULL_COPY, PULL_MIRROR)
DIRECTION_LABELS = {TWO_WAY: "Two-way", PULL_COPY: "One-way pull: Copy only", PULL_MIRROR: "One-way pull: Mirror"}
GDOCS_MODES = ("skip", "export")
MIRROR_WARNING = ("Mirror makes the NAS folder match the cloud: every NAS file that isn't in the cloud is moved "
                  "to the backup NAS, including files created only on the NAS, not just files deleted in the cloud.")
COPY_NOTE = ("Copy only never deletes on the NAS. A NAS file that differs from the cloud copy is replaced by the "
             "cloud version; the old NAS version is moved to the backup target first.")
BASELINE_PENDING, BASELINE_EXPIRED, BASELINE_CANCELLED = "pending", "expired", "cancelled_count_changed"
BASELINE_FAILED, BASELINE_DONE = "failed", "done"
# Cleared when a switch resolves a safety_abort / critical stop (the runner's _SAFETY_CLEAR plus approvals)
_APPROVALS_CLEAR = dict(resync_approved_by=None, resync_approved_at=None)
BASELINE_CLEAR = dict(mirror_baseline_ok_at=None, mirror_baseline_count=None, mirror_baseline_total=None,
                      mirror_baseline_counted_at=None, mirror_baseline_approved_by=None,
                      mirror_baseline_approved_at=None, mirror_baseline_approved_count=None,
                      mirror_baseline_state=None)
REQ_CLEAR = dict(direction_req=None, direction_req_by=None, direction_req_at=None, direction_req_reason=None,
                 direction_req_mirror_first=0)


def _get(u, k, default=None):
    try:
        v = u[k]
    except (KeyError, IndexError):
        return default
    return default if v is None else v


def provider(u) -> str:
    return _get(u, "provider", PROVIDER_OD)


def direction(u) -> str:
    return _get(u, "direction", TWO_WAY)


def is_pull(u) -> bool:
    return direction(u) in (PULL_COPY, PULL_MIRROR)


def provider_enabled(u, s) -> bool:
    return provider(u) in s.providers()


def export_formats(u, s) -> str | None:
    """rclone export_formats for this user's runs, or None (= skip_gdocs). Export only ever for a Google
    user in a one-way direction with gdocs_mode = export (SPEC v0.9 §9.6)."""
    if provider(u) == PROVIDER_GD and is_pull(u) and _get(u, "gdocs_mode", "skip") == "export":
        return s.google_export_formats
    return None


def baseline_needed(u) -> bool:
    return direction(u) == PULL_MIRROR and not _get(u, "mirror_baseline_ok_at")


def baseline_expired(u, now) -> bool:
    at = D.parse_iso(_get(u, "mirror_baseline_approved_at"))
    return at is not None and now - at >= timedelta(hours=D.ACCEPT_TTL_HOURS)


def baseline_approved(u, now) -> bool:
    return bool(_get(u, "mirror_baseline_approved_by")) and _get(u, "mirror_baseline_approved_count") is not None \
        and not baseline_expired(u, now)


def service_mode_effect(u) -> str:
    return {TWO_WAY: "--max-delete 100 on scheduled bisync runs",
            PULL_MIRROR: "no percentage stop and no --max-delete backstop (other guards stay on)",
            PULL_COPY: "no effect (Copy only)"}[direction(u)]


def view(u, s) -> dict:
    """What the user/admin/auditor pages show (no secrets, no file names)."""
    d = direction(u)
    return {"provider": provider(u), "provider_label": PROVIDER_LABELS[provider(u)],
            "cloud_side": CLOUD_SIDE[provider(u)], "provider_enabled": provider_enabled(u, s),
            "direction": d, "direction_label": DIRECTION_LABELS[d], "is_pull": d != TWO_WAY,
            "gdocs_mode": _get(u, "gdocs_mode", "skip"), "exporting": export_formats(u, s) is not None,
            "requested": _get(u, "direction_req"), "requested_label": DIRECTION_LABELS.get(_get(u, "direction_req")),
            "requested_mirror_first": bool(_get(u, "direction_req_mirror_first", 0)),
            "then": _get(u, "direction_then"),
            "changed_at": _get(u, "direction_changed_at"), "changed_by": _get(u, "direction_changed_by"),
            "reason": _get(u, "direction_reason"),
            "baseline_needed": baseline_needed(u), "baseline_count": _get(u, "mirror_baseline_count"),
            "baseline_total": _get(u, "mirror_baseline_total"),
            "baseline_counted_at": _get(u, "mirror_baseline_counted_at"),
            "baseline_approved_by": _get(u, "mirror_baseline_approved_by"),
            "baseline_approved_count": _get(u, "mirror_baseline_approved_count"),
            "baseline_state": _get(u, "mirror_baseline_state"),
            "two_way_baseline_pending": d == TWO_WAY and not _get(u, "two_way_baseline_at")
            and bool(_get(u, "direction_changed_at")),
            "service_mode_effect": service_mode_effect(u),
            "warning": MIRROR_WARNING if d == PULL_MIRROR else COPY_NOTE if d == PULL_COPY else ""}


def parse_reason(raw) -> str:
    r = " ".join(str(raw or "").split())
    if len(r) < 3:
        raise ValueError("a reason is required")
    return r[:300]


# ---- admin requests (web) --------------------------------------------------------------------------

def request_direction(db: D.DB, uid: str, to: str, reason: str, actor: str, actor_upn: str,
                      mirror_first: bool | None = None) -> dict:
    """Record an admin's switch; the worker applies it between runs. Returns the audit details."""
    if to not in DIRECTIONS:
        raise ValueError("unknown direction")
    reason = parse_reason(reason)
    u = db.user_full(uid)
    if u["state"] in (D.OFFBOARDING, D.REMOVED):
        raise ValueError("the user is being disconnected")
    frm = direction(u)
    if to == frm and not _get(u, "direction_then"):
        if _get(u, "direction_req"):   # withdraw a pending request
            db.update_profile(uid, **REQ_CLEAR)
            det = {"upn": u["upn"], "withdrawn": u["direction_req"], "reason": reason, "by_upn": actor_upn}
            db.audit(actor, "direction_request_withdrawn", uid, det)
            return det
        raise ValueError("the user already has this direction")
    if mirror_first is None:
        mirror_first = frm == PULL_COPY and to == TWO_WAY   # SPEC §6.6: the default when coming from Copy only
    mirror_first = bool(mirror_first) and to == TWO_WAY and frm == PULL_COPY   # Mirror is already mirroring
    db.update_profile(uid, direction_req=to, direction_req_by=actor_upn, direction_req_at=D.iso(D.utcnow()),
                      direction_req_reason=reason, direction_req_mirror_first=int(mirror_first),
                      **({"direction_then": None} if to != TWO_WAY else {}))
    det = {"upn": u["upn"], "from": frm, "to": to, "reason": reason, "mirror_first": mirror_first,
           "state": u["state"], "by_upn": actor_upn}
    db.audit(actor, "direction_switch_requested", uid, det)
    return det


def set_gdocs_mode(db: D.DB, uid: str, mode: str, actor: str, actor_upn: str) -> dict:
    """skip | export. Export is refused for two-way (an exported file must never be bisynced, §9.6).
    export -> skip while in Mirror needs a new Mirror baseline (the exported files would be moved away)."""
    if mode not in GDOCS_MODES:
        raise ValueError("skip or export")
    u = db.user_full(uid)
    if provider(u) != PROVIDER_GD:
        raise ValueError("Google-native files only apply to Google Drive users")
    if mode == "export" and not is_pull(u):
        raise ValueError("export is only allowed for one-way users (two-way never exports Google files)")
    if (u["direction_req"] or "") == TWO_WAY and mode == "export":
        raise ValueError("a switch to two-way is pending; export is refused")
    old = _get(u, "gdocs_mode", "skip")
    if old == mode:
        raise ValueError("no change")
    prof: dict = {"gdocs_mode": mode}
    rebase = old == "export" and mode == "skip" and direction(u) == PULL_MIRROR
    if rebase:
        prof.update(BASELINE_CLEAR)
    db.update_profile(uid, **prof)
    det = {"upn": u["upn"], "from": old, "to": mode, "mirror_baseline_required": rebase, "by_upn": actor_upn}
    db.audit(actor, "admin_set_gdocs_mode", uid, det)
    return det


def approve_baseline(db: D.DB, uid: str, count: int, actor: str, actor_upn: str) -> dict:
    """Admin approves the exact Mirror-baseline count shown (SPEC §6.6, §9.4.1 rules)."""
    u = db.user_full(uid)
    if not baseline_needed(u) or u["mirror_baseline_count"] is None:
        raise ValueError("no Mirror baseline count is waiting for approval")
    if int(count) != int(u["mirror_baseline_count"]):
        raise ValueError("the count changed; reload the page")
    db.update_profile(uid, mirror_baseline_approved_by=actor_upn, mirror_baseline_approved_at=D.iso(D.utcnow()),
                      mirror_baseline_approved_count=int(count), mirror_baseline_state=BASELINE_PENDING)
    det = {"upn": u["upn"], "approved_moves": int(count), "total": u["mirror_baseline_total"],
           "ttl_hours": D.ACCEPT_TTL_HOURS, "by_upn": actor_upn}
    db.audit(actor, "mirror_baseline_approved", uid, det)
    return det


def recount_baseline(db: D.DB, uid: str, actor: str, actor_upn: str) -> None:
    u = db.user_full(uid)
    if not baseline_needed(u):
        raise ValueError("no Mirror baseline is pending")
    db.update_profile(uid, **{**BASELINE_CLEAR, "mirror_baseline_ok_at": None})
    db.audit(actor, "mirror_baseline_recount", uid, {"upn": u["upn"], "by_upn": actor_upn})


def expire_baseline_approvals(db: D.DB, alerter: Alerter, rec: list[str], now=None) -> list[str]:
    now = now or D.utcnow()
    out = []
    for u in db.users():
        if baseline_needed(u) and u["mirror_baseline_approved_by"] and baseline_expired(u, now):
            db.update_profile(u["id"], mirror_baseline_approved_by=None, mirror_baseline_approved_at=None,
                              mirror_baseline_approved_count=None, mirror_baseline_counted_at=None,
                              mirror_baseline_state=BASELINE_EXPIRED)
            db.audit("system", "mirror_baseline_expired", u["id"],
                     {"approved_by": u["mirror_baseline_approved_by"], "ttl_hours": D.ACCEPT_TTL_HOURS})
            alerter.raise_(Alert("mirror_baseline_expired", "medium",
                                 f"{u['upn']}: Mirror baseline approval expired unused; it will be recounted", u["id"]),
                           rec)
            out.append(u["id"])
    return out


# ---- applying switches (worker, between runs) ------------------------------------------------------

def set_aside_listings(cfg, uid: str, now) -> int:
    """two_way -> one-way: rename the bisync listings `*.lst*` to `<name>-old-<ts>` (kept for forensics)."""
    wd = Path(cfg.p_state) / "bisync" / uid
    n = 0
    if wd.is_dir():
        ts = now.strftime("%Y%m%dT%H%M%SZ")
        for f in wd.iterdir():
            if f.is_file() and ".lst" in f.name and "-old-" not in f.name:
                f.rename(f.with_name(f"{f.name}-old-{ts}"))
                n += 1
    return n


def delete_listings(cfg, uid: str) -> None:
    shutil.rmtree(Path(cfg.p_state) / "bisync" / uid, ignore_errors=True)


_WAITING_STATES = (D.PAUSED, D.NEEDS_REAUTH, D.BLOCKED_BY_CA, D.NAS_AUTH_FAILED)


def apply_direction_changes(db: D.DB, alerter: Alerter, s, cfg, running, now=None,
                            recipients: list[str] | None = None) -> list[tuple[str, str, str]]:
    """Apply pending switches for users with no job running. Returns [(uid, from, to)]."""
    from odnas.runner import _SAFETY_CLEAR   # import here: runner imports this module
    now = now or D.utcnow()
    rec = recipients or []
    out = []
    for u in db.users():
        uid = u["id"]
        if uid in running or u["state"] in (D.OFFBOARDING, D.REMOVED, D.INVITED):
            continue
        to = u["direction_req"]
        by, reason, mirror_first = u["direction_req_by"], u["direction_req_reason"], bool(u["direction_req_mirror_first"])
        continuation = False
        if not to and u["direction_then"] == TWO_WAY and u["direction"] == PULL_MIRROR and u["mirror_baseline_ok_at"]:
            to, by, reason, mirror_first, continuation = TWO_WAY, u["direction_changed_by"], u["direction_reason"], \
                False, True
        if not to:
            continue
        frm, st = direction(u), u["state"]
        if to == TWO_WAY and st in _WAITING_STATES:
            continue   # a two-way baseline needs an active user; the request stays pending
        prof: dict = dict(REQ_CLEAR)
        det = {"from": frm, "to": to, "reason": reason, "by_upn": by, "state_before": st}
        if continuation:
            det["after_mirror_first"] = True
        if st in (D.SAFETY_ABORT, D.CRITICAL):
            cleared = {k: u[k] for k in ("safety_action", "safety_action_by", "resync_approved_by",
                                         "safety_approved_del_p1", "safety_approved_del_p2") if u[k]}
            prof.update(_SAFETY_CLEAR, **_APPROVALS_CLEAR)
            db.audit("system", "direction_switch_cleared_pending", uid, {"state": st, "cleared": cleared, "to": to})
            alerter.resolve(uid, "safety_abort", "critical", "accept_deletes_cancelled", "accept_deletes_failed",
                            "restore_failed")
            det["cleared_pending"] = sorted(cleared)
        if frm == TWO_WAY and to != TWO_WAY:
            det["listings_set_aside"] = set_aside_listings(cfg, uid, now)
            prof.update(needs_resync=1, **_APPROVALS_CLEAR)
        if to == TWO_WAY and mirror_first and not continuation:
            # "Mirror first": one approved Mirror baseline, then the two-way switch (direction_then)
            prof.update(direction=PULL_MIRROR, direction_then=TWO_WAY, **BASELINE_CLEAR)
            det.update(how="mirror_first_baseline_then_two_way", applied=PULL_MIRROR)
            new = PULL_MIRROR
        elif to == TWO_WAY:
            delete_listings(cfg, uid)
            prof.update(direction=TWO_WAY, direction_then=None, two_way_baseline_at=None, needs_resync=1,
                        dryrun_ok_at=None, dryrun_summary=None, preflight_requested=1, preflight_at=None,
                        preflight_summary=None, last_run_at=None, **_APPROVALS_CLEAR, **BASELINE_CLEAR)
            if u["gdocs_mode"] == "export":
                prof["gdocs_mode"] = "skip"
                det["gdocs_forced_skip"] = True
            det["how"] = "two_way_baseline: preflight, check files, resync dry-run (upload count), Approve resync"
            new = TWO_WAY
        elif to == PULL_MIRROR:
            prof.update(direction=PULL_MIRROR, direction_then=None, **BASELINE_CLEAR)
            det["how"] = "mirror_baseline_required"
            new = PULL_MIRROR
        else:   # pull_copy
            prof.update(direction=PULL_COPY, direction_then=None, **BASELINE_CLEAR)
            det["how"] = "copy_next_run"
            new = PULL_COPY
        prof.update(direction_changed_at=D.iso(now), direction_changed_by=by, direction_reason=reason)
        if st == D.ONBOARDING:
            # the dry run / approval was for the old plan: a fresh one is needed
            prof.update(dryrun_ok_at=None, dryrun_summary=None, last_run_at=None, **_APPROVALS_CLEAR)
            alerter.resolve(uid, "approval_needed")
        db.update_profile(uid, **prof)
        if new == TWO_WAY and st not in (D.ONBOARDING,):
            db.set_state(uid, D.ONBOARDING, "switched to two-way: preflight, resync dry-run and Approve resync")
        elif st in (D.SAFETY_ABORT, D.CRITICAL):
            db.set_state(uid, D.ACTIVE if u["onboarding_completed_at"] or u["last_success_at"] else D.ONBOARDING)
        db.audit("system", "direction_switched", uid, det)
        alerter.resolve(uid, "direction_changed")
        alerter.raise_(Alert("direction_changed", "low",
                             f"{u['upn']}: sync direction {DIRECTION_LABELS[frm]} -> {DIRECTION_LABELS[new]}"
                             + (" (Mirror first, then two-way)" if new != to else "") + f"; reason: {reason}", uid),
                       rec)
        out.append((uid, frm, new))
    return out


def set_provider(db: D.DB, cfg, alerter: Alerter, uid: str, to: str, reason: str, actor: str, actor_upn: str,
                 rec: list[str] | None = None) -> dict:
    """Admin: change the user's cloud provider (SPEC v0.9 §4.4). Crypto-erases the old cloud credential,
    deletes the bisync listings / delta / preflight files, resets the baselines for the direction, and puts
    the user in onboarding: they connect the new provider, then preflight, dry run and an admin approval.
    Nothing is copied between clouds and the NAS is not touched. Refused while a job runs (web checks the
    worker) and for offboarding users."""
    if to not in PROVIDERS:
        raise ValueError("unknown provider")
    reason = parse_reason(reason)
    u = db.user_full(uid)
    old = provider(u)
    if to == old:
        raise ValueError("the user already uses this provider")
    if u["state"] in (D.OFFBOARDING, D.REMOVED):
        raise ValueError("the user is being disconnected")
    from odnas.runner import _SAFETY_CLEAR
    db.erase_cloud_credentials(uid)
    delete_listings(cfg, uid)
    for f in (Path(cfg.p_state) / "preflight" / f"{uid}.json", Path(cfg.p_state) / "safety" / f"{uid}.json"):
        f.unlink(missing_ok=True)
    prof = dict(provider=to, path1=("gd-" if to == PROVIDER_GD else "od-") + uid + ":", gdocs_mode="skip",
                two_way_baseline_at=None, needs_resync=1, dryrun_ok_at=None, dryrun_summary=None,
                preflight_at=None, preflight_summary=None, preflight_requested=0, last_run_at=None,
                **_APPROVALS_CLEAR, **_SAFETY_CLEAR, **BASELINE_CLEAR)
    db.update_profile(uid, **prof)
    db.set_state(uid, D.ONBOARDING, f"cloud provider changed to {CLOUD_SIDE[to]}: connect it to continue")
    alerter.resolve(uid, "needs_reauth", "blocked_by_ca", "safety_abort", "critical", "approval_needed", "stale")
    det = {"upn": u["upn"], "from": old, "to": to, "reason": reason, "by_upn": actor_upn, "credential_erased": True,
           "listings_deleted": True, "previous_state": u["state"], "direction": direction(u)}
    db.audit(actor, "admin_set_provider", uid, det)
    alerter.raise_(Alert("provider_changed", "low",
                         f"{u['upn']}: cloud provider {CLOUD_SIDE[old]} -> {CLOUD_SIDE[to]}; reason: {reason}", uid),
                   rec or [])
    return det
