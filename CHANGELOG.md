# Changelog

## 0.8.0 (unreleased, lab build, 2026-10-20). Follows SPEC.md v0.8 (§9.5 Service mode; Mark's request)
### Added
- **Service mode** (`odnas/service_mode.py`):
  - **Scopes:** all users and/or selected accounts.
  - **Switches:** the all-users switch (typed `ALL USERS`) and the selected-accounts picker on the admin
    dashboard, plus a toggle on each user's admin page. IT admins only; auditors get 403 on every
    service-mode POST.
  - **Window:** each needs a reason (3-200 chars) and a duration of 1-24 h, default 4 h. Re-enabling an
    active window extends it (audited `service_mode_extended` with the previous end time). "Turn off now"
    is available.
  - **Effect:** scheduled `bisync` runs of covered users get `--max-delete 100` (`build_bisync(...,
    service_mode=True)`, refused for resync, dry-run and `--force` builds). Nothing else changes; never
    `--force`.
  - **Not applied to:** onboarding-incomplete users (the picker doesn't offer them; the server refuses them
    with 409), Restore, Accept deletes, delta lists, resyncs, checks, already-paused users (an existing
    `safety_abort` is kept), or runs blocked by `nas_global_pause`.
  - **Window checks:** the window is checked at the start of each run (an expired window is never applied,
    even before the tick), and a run keeps the flags it started with. The tick expires windows at their
    stored end time, also after a restart (audited `service_mode_expired`, actor `system`).
  - **Audit:** `service_mode_enabled` / `_extended` / `_disabled` / `_expired`, with who, scope, reason,
    hours, end time and the per-user delete counts at the end.
  - **Alerts:** `low` `service_mode` while on. At the end, a `low` `service_mode_summary` with deletes per
    user per side (counts only, no file names).
  - **Visibility:**
    - a banner on the admin dashboard and auditor view (scope, who, reason, end time, deletes so far);
    - a "Service mode" status row on the dashboard and on user pages;
    - a "service mode" badge in the user list and on each service-mode run.
- **Per-run delete counts per side** for every bisync run (`sync_runs.deletes_path1/2`, from the run's
  delta lines), so the service-mode summary can add them up.
- Migration 7 (expand-only):
  - `sync_profiles.service_mode_until / _by / _at / _reason`;
  - `sync_runs.service_mode` (`all`|`user`|NULL), `deletes_path1`, `deletes_path2`;
  - the `worker_state` key `service_mode_global` (ends_at, started_at, set_by, set_by_upn, hours, reason).
- **Real-rclone integration tests (v1.75.2):**
  - with `--max-delete 100`, deleting **100%** of one side goes through (exit 0) and every deleted file
    lands in `.springsync-archive`;
  - an all-files-changed side still aborts as `safety_abort`;
  - an empty NAS side (no check file) still fails `--check-access` (exit 7), with nothing deleted.
- Tests: 281 total (55 smoke, 12 integration).

### Changed
- **NAS health check (SPEC v0.8 §10.2):** the `medium` alert now comes after **2 consecutive failures**
  (the count is kept in the `nas_health` heartbeat and reset by any OK). A password rejection still goes
  straight to `nas_global_pause` and its `high` alert.
- Version 0.8.0 (User-Agent `…|SpringSync/0.8`).

## 0.7.0 (unreleased, lab build, 2026-10-20). Follows SPEC.md v0.7
### Added
- **Health-check share:** new setting `nas_health_share` (NAS group, default `Sync-Health`, share-name
  validated). It is a svc-sync-only NAS share. `SharedHomeProvider.test_mount()` does a read-only helper
  `verify` of `//<nas>/<nas_health_share>` with svc-sync.
- **Routine NAS health check (Option B):** every 15 min (`NAS_HEALTH_INTERVAL_MIN`), never while
  `nas_global_pause` is set.
  - OK → closes the `nas_health` alert.
  - Unreachable/error → `medium` `nas_health` alert.
  - Rejected login → sets `nas_global_pause` (`source: health_check`, audited, one `high` alert, no retry).
  - Result is in the `nas_health` heartbeat. Not run under Option A.
- **Settings "Testing new password…":** shown while the global pause is set and the newly saved
  `nas_svc_password` has no final result. The page refreshes every 10 s (meta refresh, no script; CSP
  unchanged). It then shows **"test mount OK … syncing has resumed"** or **"rejected … will not be
  retried"**. An unreachable NAS keeps it testing, with "retrying every 5 min". The result comes from the
  `nas_svc_test` heartbeat (result, time, opaque password version; never the secret).
- `odnas nas-info`: prints non-secret NAS settings (option, health share, whether it was configured).
- **install.sh step 13** prints a reminder when the health share isn't configured: Option B only, create it,
  NAS change, **needs Mark's OK**, the installer does not create it. It never runs NAS-side commands (a
  test checks this).
- **docs/DEPLOY.md:** new "NAS install steps (manual; NOT done by install.sh)" section, flagged **needs
  Mark's OK**: create `Sync-Health`, svc-sync-only, no user data.
- Tests: 259 total (55 smoke, 9 integration against real rclone v1.75.2). The test helper now records the
  UNC of each mount/verify.

### Changed
- The pause-clearing test mount uses the health share instead of the first user's `Home-<user>` share, so
  `nas_global_pause` can clear with **zero users**. The same mount also counts as that interval's health
  check (no second mount). Audit `nas_global_pause_cleared` records `test_share`.
- Accepted as built (SPEC v0.7), now with tests:
  - an offboarding final sync waits for the pause (offboarding without a final sync proceeds);
  - switching to Option A clears the pause (audited);
  - an automatic re-queue keeps `tonight_hold_nights`.
- No schema change (still migration 6). Version 0.7.0 (User-Agent `…|SpringSync/0.7`).

## 0.6.0 (unreleased, lab build, 2026-10-20). Follows SPEC.md v0.6
### Changed
- **Onboarding complete** stays "first successful normal bisync" (`onboarding_completed_at`); a Restore or
  resync never sets it. Tests cover an abort on that first bisync after a Restore (still an onboarding abort).
- **Restore after an onboarding dry-run abort** goes straight to the real `--resync` (no fresh dry run). The
  click is additionally audited as `admin_first_sync_approved_via_restore` (actor, UPN, `dry_run_skipped`).
- **Tonight-Restore hold alert:** `restore_deferred` is `low` on the first night the Restore is held and
  `medium` if the same Restore is held a second (or later) night. New per-Restore count
  `sync_profiles.tonight_hold_nights`; reset (with `tonight_held_at`) by a new Restore click and by the
  safety-abort clean-up. The automatic tonight re-queue is the same Restore and keeps the count. The alert
  closes when the Restore starts. The audit entry records `nights_held` and `severity`.
- **Option B: `svc-sync` login rejected = server-wide NAS pause:**
  - Server-wide flag: `worker_state` row with key `nas_global_pause` (reason, time, detail).
  - Set by the first run whose mount gets a logon failure under Option B; later runs that hit it add nothing.
  - One `high` alert `nas_global_pause` (no user), audit `nas_global_pause_set`.
  - No user is set to `nas_auth_failed`, and no per-user failure count or mount-failure count changes.
  - While set, the scheduler starts no NAS runs (offboarding without a final sync still proceeds); user
    states are unchanged; runs in flight finish normally.
  - **Auto-resume:** the worker notices a newly saved `nas_svc_password` (an opaque version hash of the
    stored ciphertext, never the secret) within one tick and runs one test mount (helper `verify`) against an
    existing user's `Home-<user>` share. OK → pause cleared, alert closed, audit `nas_global_pause_cleared`,
    users continue at their next slot. Rejected → audit `nas_global_pause_test_failed`, a `high`
    `nas_global_pause_test_failed` alert, and that password is **never retried**. NAS unreachable → retried
    every 5 min.
  - Switching `nas_option` away from B clears the pause (audited, reason `nas_option_changed`).
  - Banner on the admin dashboard, Settings page and auditor view; "NAS sync: PAUSED (server-wide)" row.
  - Option A behaviour unchanged.
- Version 0.6.0 (User-Agent `…|SpringSync/0.6`).

### Added
- Migration 6 (expand-only): `sync_profiles.tonight_hold_nights`, table `worker_state`.
- Tests: 243 total (55 smoke, 9 integration against real rclone v1.75.2).

## 0.5.0 (unreleased, lab build, 2026-10-20). Follows SPEC.md v0.5
### Changed
- **Mount-failure counter (§9.4):** only a **successful mount** resets `consecutive_mount_failures`.
  - `nas_auth` (wrong NAS password) neither counts nor resets it, and stays its own failure: under Option A
    it pauses at once (`nas_auth_failed`) with no retries and its own alert. Mount fail → `nas_auth` → mount
    fail still alerts.
  - An internal error after a good mount resets the counter. One before the mount (e.g. credential read)
    does not, and is outside the same-error chain.
- **Tonight-run start cutoff (§9.4.1):** a tonight Restore (admin's choice or the automatic re-queue)
  starts only if at least 30 minutes remain before 07:00 CT (`TONIGHT_MIN_REMAINING_S`); otherwise it waits
  for the next night. The deferral is audited (`safety_restore_tonight_deferred`, minutes left) and raises a
  low `restore_deferred` alert, once per night (`tonight_held_at` dedupes the 60 s tick). The approval is
  kept. Tonight Restores are now bound by `resync_hours` only, not by `active_hours`.
- **Safety abort during onboarding (§6.1 step 8):**
  - New `onboarding_completed_at`: set by the first successful normal bisync after the onboarding
    `--resync` (audit `onboarding_completed`).
  - An abort on the onboarding dry run or the first bisync is a normal safety abort (pause, alert), records
    `during` and `onboarding` in the abort record, audits `onboarding_safety_abort`, and leaves onboarding
    incomplete.
  - **Restore re-runs the onboarding `--resync`:** resync window, one at a time, no run-time limit (so no
    re-queue or cutoff). The admin page says so and offers no next-slot/tonight choice.
  - An abort on the onboarding **dry run** has no bisync listings, so no delta list is requested and Accept
    deletes is refused (409); Restore is allowed without a delta list.
- **Per-side counts (§9.4 wording):** counts come from the `kind=delta` dry run; the log only says which
  side tripped. This was already the case in 0.4.0; the docs now say so.
- Version 0.5.0 (User-Agent `…|SpringSync/0.5`).

### Added
- Migration 5 (expand-only): `onboarding_completed_at` (backfilled from existing successful bisyncs),
  `tonight_held_at`. Test users created as `active` count as onboarded unless a test says otherwise.
- Tests: 233 total (55 smoke, 9 integration against real rclone v1.75.2).

## 0.4.0 (unreleased, lab build, 2026-10-20). Follows SPEC.md v0.4 (Reid's answers to the v0.3 questions)
### Changed
- **Restore run-time limits:**
  - A **next-slot** Restore keeps the normal 25-minute limit. If it hits it (`timeout`), it is
    **re-queued once as a tonight run**: no new admin approval (resync only copies, never deletes), audit
    `safety_restore_requeued_tonight` (with the original approver), medium alert `restore_requeued`. The
    admin page flags it.
  - A **tonight** Restore (admin's choice or the re-queue) may run until `resync_hours` closes
    (07:00 CT, DST-aware; e.g. 11 h from 20:00, 14 h on the DST-end night). If it is still running then,
    the worker stops it, the user stays in `safety_abort`, the admin gets a `restore_failed` alert and
    audit `safety_restore_window_closed`; a new Restore click is needed. A re-click resets the one-time
    re-queue.
  - A Restore that fails for any other reason is not re-queued.
- **Per-side delete counts:** Path1 (OneDrive) and Path2 (NAS) are counted, shown, approved and checked
  separately.
  - The Safety-abort record keeps a `per_side` map of every side's `too many deletes` line.
  - The admin approves both numbers (`approved_deletes_path1/2`); a stale page on either side gets 409.
  - The pre-`--force` recount must match **each** side. A change on one side alone, or the same total split
    differently, cancels the run and voids the approval.
  - Audit details carry `approved_deletes_path1/2`, `deletes_path1/2`, `deletes_now_path1/2`.
- **Mount failures** (NAS unreachable or mount error, rclone never started):
  - skipped by the `critical_retryable` same-error chain (neither counted nor reset);
  - no longer counted as a "retryable failure in a row";
  - tracked in `consecutive_mount_failures`, `nas_unreachable` alert after 2 in a row, no lockout;
  - any run where rclone starts resets the counter and closes the alert;
  - one-shot Restore / Accept-deletes approvals are not used up, and no Restore/Accept failure is recorded.
- **Run history order:** the Accept-deletes recount (`delta`) row is created first; the `force` row is only
  created once the recount matches, so ids are chronological and a cancelled run has no `force` row.
- **SPEC v0.4 §5 names:** `RESULTS` gains the `cancelled` constant (`R_CANCELLED`); `KINDS` now in spec
  order. A test compares `users.state`, `sync_runs.result` and `sync_runs.kind` against the SPEC.md text,
  plus a frozen copy for when SPEC.md is absent.
- Version 0.4.0 (User-Agent `…|SpringSync/0.4`).

### Added
- Migration 4 (expand-only): `safety_approved_del_p1`, `safety_approved_del_p2`, `safety_restore_requeued`,
  `consecutive_mount_failures`. (`safety_approved_deletes` is kept as the total for older readers.)
- Integration finding (real rclone v1.75.2): when **both** sides exceed `--max-delete`, rclone logs the
  Safety abort for **Path1 only** (it stops at the first side). The per-side approval numbers come from the
  `--dry-run --force` delta list, which counts both. New integration test.
- Tests: 222 total (55 smoke, 9 integration against real rclone v1.75.2).

## 0.3.0 (unreleased, lab build, 2026-10-20). Follows SPEC.md v0.3 (§9.4, §9.4.1, §14.13)
### Changed
- **`critical_retryable` escalation:** the user is still retried at the next slot. The tool **escalates to
  `critical`** (lockout: pause, critical alert, audit `critical_retryable_escalated`) in three cases:
  - immediately, if the log has `Access test failed:` (likely a bad or empty mount);
  - when the same normalised `Bisync critical error: <err>` (digits, whitespace and case normalised) repeats
    on **2 consecutive runs**;
  - on the 3rd retryable result in a row (upper bound).

  Any other result breaks the chain. The worker never starts `--resync` by itself; a test runs repeated
  ticks inside `resync_hours` and asserts this.
- **Restore** (single use; normal run-time limit):
  - The admin chooses **Next slot** (default) or **Run tonight**, which holds it for `resync_hours`.
  - A next-slot Restore obeys `max_concurrent` but is not held by the "one initial resync at a time" rule.
  - The approval is used up when the run starts. If the run times out or fails, the user stays paused and
    gets a `restore_failed` alert; a new click is needed (progress is kept, because resync is additive).
- **Accept deletes**:
  - The admin approves the **exact delete count** shown. The server rejects a stale page (409).
  - An unused approval **expires after 24 h** (worker tick, plus a guard in the runner), with an alert and
    an audit entry.
  - Immediately before `--force`, a `--dry-run --force` with the same flags recounts the deletes. A
    mismatch, or a failed pre-check, **cancels** the run: `--force` never starts, the approval is void, the
    new list is stored for review, and the admin gets an alert.
  - The `--force` run has the **normal run-time limit**. On a timeout or failure the user stays in
    `safety_abort`, the approval state becomes `timeout`/`failed`, the admin gets an alert, and it is
    **never re-run automatically**.
  - Audited at each step: `admin_safety_accept_deletes`, `accept_deletes_expired`,
    `accept_deletes_precheck`, `accept_deletes_cancelled`, `accept_deletes_started`,
    `accept_deletes_timeout` / `accept_deletes_failed` / `accept_deletes_completed`.
  - Restore is audited as `admin_safety_restore` (with when), `safety_restore_started` and
    `safety_restore_completed` / `_timeout` / `_failed`.
- **File list (§14.13, pending Walter's sign-off):** the list has moved off the user page to its own page,
  `GET /admin/users/<id>/safety-delta`.
  - Only IT admins can open it; Auditors and Users get 403.
  - **Every view is audited** as `safety_delta_viewed`, recording the viewer oid and UPN, the time, which
    user's list, and the entry count. File names are never written to the log.
- Version 0.3.0, so the User-Agent is `…|SpringSync/0.3`.

### Added
- Migration 3 (expand-only): `last_crit_error`, `safety_restore_when`, `safety_approved_deletes`,
  `safety_accept_state(_at)`, `restore_timeouts`.
- Tests: 199 total (55 smoke, 8 integration against real rclone v1.75.2). The new tests cover every
  decision above. Two are the ones added at the parent's request: the `--force` timeout (no re-run), and the
  admin-only, audited list view.

## 0.2.0 (unreleased, lab build, 2026-10-20). Follows SPEC.md v0.2
### Changed
- **Classifier rewritten to SPEC v0.2 §9.4.** It uses the exit code **plus the exact v1.75.2 log text**:
  - the JSON `object`/`msg` fields are read, with a text-mode fallback, and ANSI codes are stripped;
  - the check order is ok → safety_abort → lockout → retryable → mismatch → exit code;
  - new results are `safety_abort`, `critical_retryable` and `usage`;
  - exits 8 and 10 are retryable;
  - exit 9 and other unknown codes are `critical`, with a warning;
  - exit 0 without `Bisync successful` is `critical` (fail safe);
  - a process killed by a signal is `retryable`.
- `critical_retryable` (exit 7 + "retryable … --resilient mode") proceeds at the next slot and escalates to
  `critical` after 3 in a row. `critical` (exit 7 + "Must run --resync") locks the user out until an admin
  approves a resync.
- Every bisync command now carries `--color NEVER` (§9.3).
- Version 0.2.0, so the User-Agent is `…|SpringSync/0.2`.

### Added
- **Safety-abort flow (§9.4, §6.4):**
  - a new user state, `safety_abort`, which pauses the user and opens a critical issue (counts only);
  - an automatic read-only `bisync --dry-run --force` that builds the delta list (0600 file, IT-admin page
    only);
  - IT-admin actions **Restore** (one approved `--resync --resync-mode newer`), **Accept deletes** (one
    `--force` run; UPN confirmation; the approval is consumed at run start, so it never repeats) and
    **Refresh delta**;
  - every decision is audited, the auditor view shows counts and decisions only, and all these POST
    routes return 403 for auditors.
- **Migration 2** (expand-only): new `sync_profiles` columns, and `sync_runs.kind` gains `delta` and `force`.
  It rebuilds the table, keeps its history, and v0.1 code still runs against it.
- **Pins:**
  - `install.sh` now builds Caddy with `caddy-dns/googleclouddns@v1.1.0`, the tag at
    `6fcdbd98a8565df50ff40ff53411dc6c8d97dcd9`.
  - It forces `GOPROXY=proxy.golang.org` and `GOSUMDB=sum.golang.org`.
  - It refuses a build unless `caddy build-info` shows `v1.1.0` with go.sum hash
    `h1:SDxKxFh7d5Jq2/JPnu9Jv8ErOIdfXmK+Oad0qVzQi80=`, and the same check runs before skipping a rebuild.
  - `GO_SHA256` is pinned to `65efbc80…379b40`, which removes the v0.1 refusal.
- **Tests:** 185 in total (55 smoke, 8 integration against real rclone v1.75.2). New coverage:
  - exit 1 safety abort, which also re-trips;
  - the delta list, Accept deletes and Restore end to end;
  - check-access exit 7 that is retryable and recovers;
  - a real exit-7 lockout;
  - the classifier rules 1–6, with exact strings;
  - the admin-only routes, including auditor and user 403s;
  - migration 2 on a v0.1 DB;
  - the Caddy plugin pin check.

### Resolved from 0.1 OPEN-QUESTIONS §D (accepted in SPEC v0.2)
These are now spec, not deviations:
- check files are created before the dry-run;
- `resync_hours`;
- a nonce per encrypted value;
- the mount-helper `verify` verb;
- stdlib sqlite3 with numbered migrations;
- Option B per-run idempotent mounts;
- backups to `IT-Backups` are deferred until before go-live;
- `requirements.lock` is regenerated on 24.04;
- the Caddy plugin pin;
- the Go checksum;
- exit codes.

## 0.1.0 (unreleased, lab build, 2026-10-20)
First working local version, built to `SPEC.md` v0.1 (source of truth) and `research.md`.

### Added
- Entra confidential-client sign-in (MSAL auth-code + PKCE). Roles come from group claims: Users (with the
  pilot list), Admins, Auditors.
- AES-256-GCM encryption at rest with key ids and rotation (`odnas rekey`). The data key lives outside the DB
  and outside backups, delivered by systemd credentials.
- SQLite store (WAL) with the SPEC §5 tables. The audit log is append-only and hash-chained.
- Token handling behind `TokenStrategy`:
  - `BrokerTokenStrategy` (SPEC design, pending T-A3);
  - `TmpfsConfigStrategy` (fallback).
- NAS access behind `NasAccessProvider`:
  - Option A `PersonalDriveProvider` (own login, pilot default);
  - Option B `SharedHomeProvider` (`Home-<user>` + svc-sync).
- Root mount helper (`mount|umount|verify <uuid>`) and its sudoers rule.
- The SPEC §9.3 bisync command builder, filter file template, preflight scan, onboarding dry-run, admin
  approval, and one-at-a-time resync.
- Worker:
  - 60 s tick, round-robin stagger, max 2 concurrent runs, one run per user;
  - active-hours and resync windows, weekly `rclone check`;
  - throttle back-off and governor;
  - SIGINT → 120 s → SIGKILL run time limit.
- Exit-code and log classification, plus issues/alerts. Alerts go to the admin page only; email is a stub.
- Admin settings GUI (validated, audited, secrets write-only), per-user actions, offboarding with
  crypto-erase.
- Read-only auditor view, audit-log viewer, and CSV export.
- Nightly maintenance (chain verify, log pruning, tmp sweep, credential-expiry reminders at 60/30/14/7/1
  days, 80-day token check, disk, TLS) and a daily backup that excludes keys.
- Deploy assets: `install.sh` (idempotent, `--dry-run`), `update.sh` (tags only, smoke tests, drain,
  pre-backup, migrate, health check, auto-rollback), `rollback.sh`, systemd units and timers, the Caddy
  DNS-01 template and unit, RESTORE.md, and a CI template with gitleaks.
- 148 pytest tests, including 5 integration tests against the real rclone v1.75.2.

### Deviations from SPEC.md v0.1 (with reasons; items 1–8 and 11 were accepted into SPEC v0.2)
1. **stdlib `sqlite3` + numbered migrations instead of SQLAlchemy + Alembic.** One small DB, fewer
   dependencies, and the same expand-only rule. `PRAGMA user_version` tracks the schema.
2. **Exit codes, safety aborts:** the real rclone v1.75.2 exits **1**, not 7, when `--max-delete` trips under
   `--resilient`. The classifier treats "too many deletes", "Safety abort", and "check file check failed" in
   the JSON log as **critical** whatever the exit code. Check-access failure does exit 7 (verified).
3. **Nonce storage:** SPEC §5 shows a single `nonce` column per row, but `nas_credentials` has two encrypted
   fields, and reusing a GCM nonce is unsafe. Each blob is stored as `nonce || ciphertext`, with `key_id` per
   row.
4. **Mount helper has a third verb, `verify`** (ro mount, list root, unmount on a throwaway uuid). SPEC §4.2
   asks for a verify step, while §7.4 lists only `mount|umount`.
5. **Mounts are per run for both options.** Option B's provider skips unmounting, so its mounts persist
   after the first run, but there is no separate boot-time mount step yet.
6. **Email:** SMTP settings are stored, but nothing is sent. Alerts are admin-page issues, per the room's
   instruction (outbound mail path through Gidget is open, SPEC §14.5). The `springsync-alert@` unit opens a
   critical issue.
7. **Backups:** besides `keys/` and `gcp-acme-sa.json`, `creds/`, `deploy/` (the deploy key), and any
   `*.key`, `*.cred`, `*.pem`, `id_*` are excluded too. The copy to the NAS `IT-Backups` share is not
   implemented yet.
8. **Initial resync timing:** "outside business hours" (SPEC §9.1) is implemented as a GUI setting,
   `resync_hours`, default `18:00-07:00` America/Chicago.
9. **Entra group re-check for offboarding** (SPEC §6.3) isn't implemented; it's open whether app-only
   `User.Read.All` is wanted.
10. **Web→worker NAS verify** goes over a loopback internal API, so the worker stays the only process that
    runs the mount helper, and nothing is stored when verification fails.
11. **Option naming follows SPEC** (A = Personal-Drive with the user's own login, B = `Home-<user>` +
    svc-sync), which is the reverse of research.md §2.3.
12. **User-Agent** is `NONISV|VisitHotSprings|SpringSync/0.1`, per SPEC §9.3 (research used `HomeSync/1.0`),
    and is built from the configurable product name.
13. **Preflight quota check:** compares the NAS-side total with `rclone about od-<id>: --json` "free". It is
    skipped if `about` returns nothing.
