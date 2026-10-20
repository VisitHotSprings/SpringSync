# Changelog

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
- **Tests:** 185 in total (54 smoke, 8 integration against real rclone v1.75.2). New coverage:
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
