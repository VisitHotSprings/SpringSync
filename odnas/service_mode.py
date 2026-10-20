"""Service mode (SPEC v0.8 §9.5; Mark's request 2026-10-20).

For planned bulk work (cleanup, reorganisation, NAS move): during a bounded window, scheduled incremental
bisync runs of covered users pass `--max-delete 100` instead of the user's max_delete_pct, so large deletes
go through without a safety abort.

- Scope: ALL users (worker_state row `service_mode_global`) and/or SELECTED accounts
  (`sync_profiles.service_mode_until`). A user is covered if either window is open (`now < ends_at`).
- `--max-delete 100` never trips (rclone v1.75.2 aborts only if deleted/old > max-delete/100 and clamps
  the value to 0-100). Omitting the flag would fall back to rclone's 50% default, so it is never omitted.
- Never `--force`: the all-files-changed abort, --check-access (an empty/unmounted side has no check
  file), filters, the run-time limit and the retry/lockout rules all stay on. Deletes still go to
  .springsync-archive via --backup-dir1/2.
- Not applied to: onboarding-incomplete users, any run other than a scheduled `bisync` (Restore, Accept
  deletes, delta lists, resyncs, checks), users in safety_abort / critical / paused (they don't get bisync
  runs at all; an existing safety_abort is not cleared), or while nas_global_pause blocks runs.
- Each window has a required reason and an end time: default 4 h, max 24 h. Re-enabling an active window
  is an "extend" (new end time, audited). It ends on its own at ends_at (stored in the DB, so a restart
  neither extends nor re-enables it); a run that started inside the window keeps its flags.
- On / off / extend / expire are audited (who, scope, reason, end time). On raises a `low` alert; the end
  raises a summary alert with deletes per user per side during the window (counts only, no file names).
"""
from __future__ import annotations

from datetime import datetime, timedelta

from odnas import db as D
from odnas.notify import Alert, Alerter

MIN_HOURS, MAX_HOURS, DEFAULT_HOURS = 1, 24, 4
SERVICE_MAX_DELETE_PCT = 100
SCOPE_ALL, SCOPE_USER = "all", "user"
CONFIRM_ALL = "ALL USERS"     # typed confirmation for the all-users switch


def parse_hours(raw) -> int:
    try:
        h = int(str(raw if raw not in (None, "") else DEFAULT_HOURS))
    except ValueError:
        raise ValueError("duration must be a whole number of hours") from None
    if not MIN_HOURS <= h <= MAX_HOURS:
        raise ValueError(f"duration must be {MIN_HOURS}-{MAX_HOURS} hours")
    return h


def parse_reason(raw) -> str:
    r = " ".join(str(raw or "").split())
    if len(r) < 3:
        raise ValueError("a reason is required")
    return r[:200]


def global_window(db: D.DB, now: datetime | None = None) -> dict | None:
    f = db.flag(D.SERVICE_MODE_GLOBAL)
    if f is None:
        return None
    ends = D.parse_iso(f.get("ends_at"))
    return f if ends is not None and ends > (now or D.utcnow()) else None


def user_window(u, now: datetime | None = None) -> dict | None:
    ends = D.parse_iso(u["service_mode_until"])
    if ends is None or ends <= (now or D.utcnow()):
        return None
    return {"ends_at": u["service_mode_until"], "set_by": u["service_mode_by"], "started_at": u["service_mode_at"],
            "reason": u["service_mode_reason"]}


def active_scope(db: D.DB, u, now: datetime | None = None) -> str | None:
    """Scope this user's next scheduled bisync runs under, or None. Onboarding-incomplete users are never
    covered (SPEC v0.8 §9.5)."""
    if not u["onboarding_completed_at"]:
        return None
    if global_window(db, now):
        return SCOPE_ALL
    if user_window(u, now):
        return SCOPE_USER
    return None


def _recips(s) -> list[str]:
    return [x.strip() for x in (getattr(s, "alert_recipients", "") or "").split(",") if x.strip()]


# ---- delete summary (counts only) ---------------------------------------------------------------

def deletes_during(db: D.DB, since: str, scope: str, uid: str | None = None) -> list[dict]:
    """Deletes per user per side for runs tagged with `scope` since `since`."""
    sql = ("SELECT r.user_id, u.upn, COUNT(*) AS runs, COALESCE(SUM(r.deletes_path1),0) AS p1, "
           "COALESCE(SUM(r.deletes_path2),0) AS p2 FROM sync_runs r JOIN users u ON u.id=r.user_id "
           "WHERE r.service_mode=? AND r.started_at>=?")
    args: list = [scope, since]
    if uid:
        sql += " AND r.user_id=?"
        args.append(uid)
    rows = db.all(sql + " GROUP BY r.user_id, u.upn ORDER BY u.upn", tuple(args))
    return [{"user_id": r["user_id"], "upn": r["upn"], "runs": r["runs"], "deleted_onedrive": r["p1"],
             "deleted_nas": r["p2"]} for r in rows]


def summary_text(rows: list[dict]) -> str:
    if not rows:
        return "no service-mode runs"
    return "; ".join(f"{r['upn']}: OneDrive {r['deleted_onedrive']}, NAS {r['deleted_nas']} "
                     f"({r['runs']} run(s))" for r in rows)


def _end_summary(db: D.DB, alerter: Alerter, rec, scope: str, since: str, uid: str | None, label: str) -> list[dict]:
    rows = deletes_during(db, since, scope, uid)
    alerter.resolve(uid, "service_mode_summary")       # replace an older summary
    alerter.raise_(Alert("service_mode_summary", "low",
                         f"Service mode ended ({label}). Deletes during the window: {summary_text(rows)}", uid), rec)
    return rows


# ---- all users ------------------------------------------------------------------------------------

def enable_all(db: D.DB, alerter: Alerter, actor: str, actor_upn: str, hours: int, reason: str, s=None) -> str:
    now = D.utcnow()
    ends = D.iso(now + timedelta(hours=hours))
    cur = global_window(db, now)
    if cur:   # extend: keep the start (for the summary), set a new end time
        db.update_flag(D.SERVICE_MODE_GLOBAL, ends_at=ends, hours=hours, reason=reason, extended_by=actor_upn)
        db.audit(actor, "service_mode_extended", "", {"scope": SCOPE_ALL, "hours": hours, "ends_at": ends,
                                                      "reason": reason, "by_upn": actor_upn,
                                                      "previous_ends_at": cur["ends_at"]})
        return ends
    db.clear_flag(D.SERVICE_MODE_GLOBAL)    # a stale, already-expired row
    db.set_flag(D.SERVICE_MODE_GLOBAL, reason, ends_at=ends, started_at=D.iso(now), set_by=actor,
                set_by_upn=actor_upn, hours=hours)
    db.audit(actor, "service_mode_enabled", "", {"scope": SCOPE_ALL, "hours": hours, "ends_at": ends,
                                                 "reason": reason, "by_upn": actor_upn})
    alerter.raise_(Alert("service_mode", "low", f"Service mode ON for ALL users until {ends} by {actor_upn}: "
                                                f"{reason} (no max-delete stop)", None), _recips(s))
    return ends


def disable_all(db: D.DB, alerter: Alerter, actor: str, actor_upn: str, *, expired: bool = False,
                s=None) -> list[dict] | None:
    f = db.flag(D.SERVICE_MODE_GLOBAL)
    if f is None:
        return None
    db.clear_flag(D.SERVICE_MODE_GLOBAL)
    alerter.resolve(None, "service_mode")
    rows = _end_summary(db, alerter, _recips(s), SCOPE_ALL, f.get("started_at") or f["set_at"], None, "all users")
    db.audit(actor, "service_mode_expired" if expired else "service_mode_disabled", "",
             {"scope": SCOPE_ALL, "reason": f.get("reason") or f["reason"], "ends_at": f.get("ends_at"),
              "enabled_by": f.get("set_by_upn"), "deletes": rows, **({} if expired else {"by_upn": actor_upn})})
    return rows


# ---- selected accounts --------------------------------------------------------------------------

def enable_user(db: D.DB, alerter: Alerter, uid: str, actor: str, actor_upn: str, hours: int, reason: str,
                s=None) -> str:
    now = D.utcnow()
    ends = D.iso(now + timedelta(hours=hours))
    u = db.user_full(uid)
    cur = user_window(u, now)
    if cur:
        db.update_profile(uid, service_mode_until=ends, service_mode_reason=reason)
        db.audit(actor, "service_mode_extended", uid, {"scope": SCOPE_USER, "hours": hours, "ends_at": ends,
                                                       "reason": reason, "by_upn": actor_upn, "upn": u["upn"],
                                                       "previous_ends_at": cur["ends_at"]})
        return ends
    db.update_profile(uid, service_mode_until=ends, service_mode_by=actor_upn, service_mode_at=D.iso(now),
                      service_mode_reason=reason)
    db.audit(actor, "service_mode_enabled", uid, {"scope": SCOPE_USER, "hours": hours, "ends_at": ends,
                                                  "reason": reason, "by_upn": actor_upn, "upn": u["upn"]})
    alerter.raise_(Alert("service_mode", "low", f"{u['upn']}: service mode ON until {ends} by {actor_upn}: "
                                                f"{reason} (no max-delete stop)", uid), _recips(s))
    return ends


def disable_user(db: D.DB, alerter: Alerter, uid: str, actor: str, actor_upn: str, *, expired: bool = False,
                 s=None) -> list[dict] | None:
    u = db.user_full(uid)
    if not u or not u["service_mode_until"]:
        return None
    db.update_profile(uid, service_mode_until=None, service_mode_by=None, service_mode_at=None,
                      service_mode_reason=None)
    alerter.resolve(uid, "service_mode")
    rows = _end_summary(db, alerter, _recips(s), SCOPE_USER, u["service_mode_at"] or "", uid, u["upn"])
    db.audit(actor, "service_mode_expired" if expired else "service_mode_disabled", uid,
             {"scope": SCOPE_USER, "reason": u["service_mode_reason"], "ends_at": u["service_mode_until"],
              "enabled_by": u["service_mode_by"], "upn": u["upn"], "deletes": rows,
              **({} if expired else {"by_upn": actor_upn})})
    return rows


def expire(db: D.DB, alerter: Alerter, now: datetime, s=None) -> None:
    """Worker tick: end windows whose end time has passed (audited as service_mode_expired, actor
    'system'). Works the same after a restart because ends_at is in the DB."""
    f = db.flag(D.SERVICE_MODE_GLOBAL)
    if f is not None:
        ends = D.parse_iso(f.get("ends_at"))
        if ends is None or ends <= now:
            disable_all(db, alerter, "system", "system", expired=True, s=s)
    for u in db.users(include_removed=True):
        if not u["service_mode_until"]:
            continue
        ends = D.parse_iso(u["service_mode_until"])
        if ends is None or ends <= now or u["state"] == D.REMOVED:
            disable_user(db, alerter, u["id"], "system", "system", expired=True, s=s)


def view(db: D.DB, now: datetime | None = None) -> dict:
    """Banner data for admins and auditors (counts only)."""
    now = now or D.utcnow()
    g = global_window(db, now)
    users = [dict(upn=u["upn"], id=u["id"], **user_window(u, now)) for u in db.users() if user_window(u, now)]
    for x in users:
        x["deletes"] = deletes_during(db, x["started_at"] or "", SCOPE_USER, x["id"])
    return {"global": g, "global_deletes": deletes_during(db, g.get("started_at") or g["set_at"], SCOPE_ALL)
            if g else [], "users": users, "any": bool(g or users)}
