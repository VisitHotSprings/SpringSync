# Changelog

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

### Deviations from SPEC.md (with reasons)
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
