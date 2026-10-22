# Changelog

## 0.11.0 (2026-10-22)
- **New: opt-in nightly auto-update for the Ubuntu host** (SPEC §11.4.1; approved by Mark on Oct 22, 2026).
  **Off by default** (`[auto_update] enabled = false`). When on, `<slug>-autoupdate.timer` (02:45 Central +
  up to 30 min) runs `deploy/auto-update.sh`, which installs the newest **patch** release of the running minor
  through the existing `update.sh` (drain, backup, smoke tests, health check, rollback). Only normal published
  GitHub releases with a plain `vX.Y.Z` tag count, 24 h after `published_at`. Drafts, pre-releases, suffixed tags and
  branches are ignored. A new minor/major is alerted and waits for a manual update. It waits for the 02:30
  backup to finish (up to 15 min, else skips with `backup_running`) and never runs while a Mirror run, an
  approval or a safety hold (percentage stop or `--max-delete` backstop) is pending. A failed update rolls back and turns auto-update off until
  `auto-update.sh --reenable`. Unsigned tags are refused once `require_signed_tags = true`. Every check is
  audited. A GitHub outage is a logged no-op.
- New `odnas auto-update check|report|status` (DB and config only, run as the service account).
- Admin Settings shows the auto-update state and the last check, **read-only**: the GUI never starts an update.
- `update.sh`: with `REQUIRE_SIGNED_TAGS`, the tag signature is now also checked when `releases/<tag>` is left
  over from an earlier attempt (before, a re-run skipped the check).
- **Update lock** `/run/lock/<slug>-update.lock` (created by `/etc/tmpfiles.d/<slug>.conf`): `update.sh` holds
  it exclusively (waits up to 15 min, else exits 75 with nothing changed), the 03:30 maintenance job holds it
  shared, so maintenance never runs during an update and vice versa.
- `install.sh` step 12 installs and enables the new timer and the tmpfiles entry.
- Built to SPEC v0.10 §11.4.1 (Reid); revised in place before the first push.
- Pilot note: all releases so far are GitHub pre-releases, so auto-update ignores them. Publish a normal
  release for it to act. See docs/DEPLOY.md "Automatic updates (opt-in)".
- No schema change.

## 0.10.3 (2026-10-22)
- **Fixed: `install.sh` lost the `--version` value on real Ubuntu.** It sourced `/etc/os-release`, whose
  `VERSION` variable ("24.04.5 LTS (Noble Numbat)") overwrote ours, so step 6 tried to clone a tag by that
  name. The OS file is now read in a subshell. Found on Mark's first Ubuntu dry run. Regression test added.
- **Fixed: `--dry-run` stopped at step 7** reading `/opt/<slug>/current`, which a dry run never creates; it
  now keeps reading from the checkout.

## 0.10.2 (2026-10-22)
- **Ubuntu install works from the public repo.** `install.sh` now defaults `REPO_URL` to
  `https://github.com/VisitHotSprings/SpringSync.git` and needs no deploy key for an HTTPS URL. An SSH URL
  still requires the read-only deploy key. `update.sh` uses the deploy key only if it exists.
- No app code change.

## 0.10.1 (unreleased, lab build, 2026-10-22). Windows CI fixes
The first run of the `windows` CI job on a real Windows runner found 7 test failures. Two of them were real
Windows bugs; the rest were tests that assumed Linux. Nothing live; no schema change.

### Fixed (real bugs)
- **Private files on Windows** (`odnas/privfile.py`; `tokens.write_private` uses it). On Windows the
  0600 mode was silently ignored (`st_mode` is always 0o666), so NAS login files, per-run rclone configs
  and delta files only had the inherited folder ACL. They now get their own **protected DACL** (no
  inheritance; SYSTEM, Administrators and the current account only). It's written to a new no-share
  temp file created with that DACL, then renamed over the target, so the secret is never in a file with a
  looser ACL. Linux: 0600 is now also forced on an existing file (`O_TRUNC` kept an older, looser mode).
- **`update.ps1` smoke tests would have failed on every Windows update.** Five of them (Copy only, Mirror
  safety stop, service-mode stop and backstop) ran into the 0600 check above. With the fix they pass on
  real Windows, using the same safety check (`is_private`).
- The Linux sudo mount helper now refuses to run on Windows, with a clear error, instead of failing on a
  missing `sudo`. The NAS provider selection was already correct (`WindowsShareClient` when the host is
  Windows); the failing tests had forced `host_os=linux`.
- `install.ps1`: the generated service-account password is built into a SecureString one character at a
  time, not with `ConvertTo-SecureString -AsPlainText` (a PSScriptAnalyzer error rule).
- `.gitattributes`: Linux-side scripts (`*.sh`, mount helper, sudoers, systemd, Caddy) keep LF line
  endings in a Windows checkout.

### Changed (tests that assumed Linux)
- `test_config_validation` checks both default layouts (`host_os=linux` and `windows`), and that the
  unforced default matches the OS the tests run on.
- Copy only backup-dir check is separator-agnostic (Windows temp paths are `C:\...`).
- `bash -n` of the build scripts is skipped on Windows (they run on the Linux build box; the Linux job
  checks them).
- New tests: real-Windows DACL check (protected, exactly SYSTEM / Administrators / current account),
  the mount-helper refusal, the SDDL, and the Linux "tighten an existing loose file" check.

### CI
- The PowerShell parse step runs `.github/scripts/ps-parse.ps1` in both `pwsh` and `powershell.exe` (no
  nested quoting). PSScriptAnalyzer installs from a trusted PSGallery. Result: 7 files parse with 0 errors
  in 5.1 and 7, and PSScriptAnalyzer reports 0 errors. The remaining warnings are unused-parameter false
  positives (the parameters are used inside script blocks), `Invoke-Change` relying on the script's
  ShouldProcess, and one empty catch block, which now logs at verbose level.

## 0.10.0 (unreleased, lab build, 2026-10-22). Windows 11 Pro host
SPEC §11.5 (Windows host) and §11.6 (Ubuntu → Windows). One codebase: the Ubuntu host is unchanged and
the full Linux suite still passes. Nothing live: no Microsoft, Google, NAS, Entra or DNS calls were made,
and nothing ran on a real Windows PC (see "Not verified" below). No schema change, so no migration.

### Added: host layer (`odnas/hostos.py`)
- `host_os` ("" = the OS it runs on; `linux` / `windows` can be forced for tests) and `internal_timers`
  ("" = on for Windows). Windows defaults: data in `%ProgramData%\SpringSync`, programs in
  `%ProgramFiles%\SpringSync`; every `p_*` path goes through one table, so Linux paths are byte-for-byte
  the same as 0.9.1.
- Path helpers that keep a user root inside its share (`under` refuses `..`), UNC helpers, case-insensitive
  prefix checks for UNC paths.
- `FileLock` (fcntl on Linux, msvcrt on Windows); the worker takes `state/worker.lock` so only one runs.
- rclone processes on Windows: new process group, no window, a Job Object (kill-on-close), graceful stop by
  CTRL_BREAK (AttachConsole method, then `send_signal`), hard stop after 120 s (`TerminateJobObject` /
  `taskkill /T /F`). `cfg.p_rclone` replaces `cfg.rclone_bin` in bisync/pull/runner.

### Added: NAS on Windows (`odnas/winshare.py`)
- UNC access through the WNet API (`WNetAddConnection2W`, deviceless, temporary). The password stays in
  memory for the call; it is never on a command line, in a log or in Credential Manager. Same refcounting
  and error codes as the Linux mount helper, so `nas.py` callers don't change. Also used for the backup NAS.
- Error 1219 (one login per server per session): users on the same server with different logins run one
  after another; a stale connection is cancelled and retried once; a backup NAS on the same server with a
  different login fails fast with a clear message (use Option B).

### Added: secrets with DPAPI (`odnas/dpapi.py`)
- Service secrets are DPAPI-protected (user scope, svc-springsync) in `ProgramData\SpringSync\keys\*.dpapi`.
  The installer writes plaintext to `keys\incoming`; the service ingests it at start (round-trip checked,
  plaintext overwritten and deleted). `odnas secrets ingest|status`.
- `odnas keygen` creates `data.key`, the Entra certificate (`entra-app.crt`/`.key`, RSA-2048, 730 days) and
  Administrators-only escrow copies. It never replaces existing keys.

### Added: Windows services (`odnas/winservice.py`, `deploy/windows/svc.py`)
- `springsync-web`, `springsync-worker` (pywin32 on the private Python) and `springsync-caddy` (Caddy's own
  service support), all under the low-privilege `svc-springsync` account: automatic start, restart on
  failure (3 times), run with nobody signed in. The worker accepts pre-shutdown (150 s) and drains.
- Timers run inside the worker on Windows: database backup 02:30 and maintenance 03:30 Central, once per
  day each. Maintenance also writes the monthly audit copy `logs\audit\audit-YYYY-MM.jsonl`.
- File logs (`logs\<role>.log`, rotated) and a self-check at start (`logs\doctor-service.json`).

### Added: `odnas doctor` (both hosts)
- Paths, database, secrets (warns while escrow copies are still on the PC), rclone version + an `lsf` with
  the pinned encoding, HTTP health, Caddy modules + Caddyfile, NAS TCP 445, Windows long paths.
  `--json` for scripts. Also `odnas audit-event` for install/update/rollback records.

### Added: Windows packaging (`deploy/windows/`)
- `install.ps1` (pre-flight: Windows 11 Pro, Administrator, BitLocker, TPM, sleep/hibernate with
  `-SetPowerSettings`, active hours with `-SetActiveHours`, long paths; account, folders + icacls, private
  Python, rclone, settings, keys, database, services, firewall rule for TCP 443 and 80 (redirect) to caddy.exe, doctor). Safe to re-run;
  `-WhatIf` shows the plan.
- `update.ps1` (side-by-side, smoke tests, drain, DB backup, switch, 60 s health check, automatic switch
  back; keeps 3 versions), `rollback.ps1` (`-RestoreDb`), `uninstall.ps1` (keeps data unless `-PurgeData`
  and a typed `PURGE`), `set-secret.ps1` (hidden prompt).
- Pinned and SHA-256-checked: Python 3.13.17 embeddable, pip 26.2.2, rclone v1.75.2, Caddy v2.11.7 with
  googleclouddns v1.1.0 (`pins.psd1`; same rclone/Caddy pins as `install.sh`). `requirements-windows.lock`
  = `requirements.lock` + pywin32, tzdata, colorama, all hashed.
- Antivirus-friendly: no PyInstaller/Nuitka/packed exe, plain readable PowerShell 5.1 (no
  `-EncodedCommand`, no `Invoke-Expression`, no hidden windows beyond the services), `Unblock-File` only on
  the package's own files, Defender/ThreatDown settings untouched. `SHA256SUMS.txt` inside the zip and next
  to it. Scripts are ready for Authenticode signing (not signed).
- `build-release.sh` (zip from `git archive` + verified vendor files), `build-caddy-windows.sh` (xcaddy;
  needs Go module access, not run here), `ps_static_check.py` (PowerShell rule check used in tests).
- Guide: `docs/INSTALL-WINDOWS.md` and `.pdf` (numbered copy-paste steps; Entra, DNS and NAS steps are
  marked "needs Mark's OK").
- CI: a `windows` job (windows-2025) runs the Windows tests on real Windows, parses the scripts in
  PowerShell 5.1 and 7, and runs PSScriptAnalyzer. Additions only to `ci.yml`.

### Changed
- TOML config is read as UTF-8 with or without a BOM (PowerShell 5.1 writes a BOM).
- Token files are written as UTF-8 with no newline translation.

### Deviations from the spec (OPEN-QUESTIONS.md §H)
Python 3.13 embeddable instead of the 3.12 installer; zip install instead of `git clone` with a deploy
key; WNet with database-stored NAS logins instead of Credential Manager; pywin32 instead of WinSW;
Caddy service named `springsync-caddy`; per-run rclone configs on disk (BitLocker required; no tmpfs).

### Not verified (no Windows PC, no Microsoft hosts)
The PowerShell scripts were never run (no PowerShell here; static checks only). The Windows code ran on
Linux against mocks. Lab tests T-W1 to T-W4 (NAS 1219, CTRL_BREAK stop, reboot during a run, Option A vs B)
are still to do. Caddy for Windows was not built.

## CI fix (2026-10-22, no app code change)
- GitHub CI: the secret scan now runs the free gitleaks CLI v8.30.1, pinned by SHA-256, instead of
  `gitleaks-action`, which needs a paid license for organization repos and failed the first run.
- Bumped `actions/checkout` to v5 and `actions/setup-python` to v6 (Node 20 deprecation).

## 0.9.1 (unreleased, lab build, 2026-10-21). Reid's review of 0.9.0
Reid approved the 0.9.0 deviations: the `sync_runs.op` column, the backup NAS mount path, Copy only with
guards 2 and 3 only, and UTC backup folder names. Nothing live; no schema change (no migration).

### Changed: service mode never loosens Mirror (Reid)
- **Mirror in service mode keeps BOTH the percentage stop and the `--max-delete` backstop.** 0.9.0 skipped
  both; that is reverted. The counting dry-run's limit check (`pull.evaluate`) no longer takes a
  service-mode argument at all, and the real run always gets `--max-delete floor(total × pct / 100)`.
- `pull.build_pull` refuses to build a real Mirror (`sync`) command without `--max-delete`, so no code path
  can drop the backstop.
- Mirror runs in a service-mode window are still **tagged** (`sync_runs.service_mode`) so they show in the
  end-of-window summary; nothing else changes for them. The service-mode picker says "no effect (Mirror
  keeps its percentage stop and --max-delete backstop)".
- Two-way service mode (`--max-delete 100`) and Copy only (no effect) are unchanged.
- Large planned Mirror deletes go through the safety stop's **Accept deletes** (exact count, typed UPN).
- Tests: per-user and all-users windows both stop at the percentage limit with nothing moved; the backstop
  is the same N as outside service mode; an exit-7 backstop trip in service mode is a safety abort; a real
  Mirror command can't be built without the backstop.
- Spec note for §9.5 / §9.7.2 in OPEN-QUESTIONS.md §G (SPEC.md itself is Reid's; not edited).

### Changed: every time shown to people is Central time (Reid)
- New `odnas/timefmt.py`: `display_time` (UTC ISO → `YYYY-MM-DD HH:MM CST/CDT`, America/Chicago, DST
  aware) and `localize_text` (rewrites UTC timestamps embedded in free text).
- **Pages** (user, admin, auditor, audit log): every time uses the `local` filter; free text that can carry
  a timestamp (issue/alert summaries, run details, dry-run/preflight/delta summaries, pause reasons, the
  backup-test message, audit `details_json`) goes through the new `local_text` filter.
- **Alerts:** `Alerter.raise_` converts timestamps in the summary before it is stored or handed to the
  notifier; service-mode "ON until …" alerts use Central time directly.
- **Unchanged, by design:** stored values, the audit hash chain, logs, CLI/JSON output and backup folder
  names (`<user_id>/<YYYY-MM-DD_HHMMSS>`) stay UTC.
- Tests: CDT/CST and the DST change-over; embedded timestamps; alert text; no UTC ISO timestamp on any user,
  admin, auditor or audit-log page; backup folder stamps are UTC.

### Docs
- OPEN-QUESTIONS.md: Reid's approvals recorded; **bulk approve is not built** (Mark hasn't decided);
  Reid's proposal recorded (bulk approve only users whose test run shows no deletes and no conflicts;
  everyone else one at a time). New §G spec notes for Reid.
- docs/DEPLOY.md: new **Ubuntu test-host checklist**; **T-G2 (Google token refresh through the broker) is
  required before any real Google user is connected**, with the six pass steps and the tmpfs fallback.
- Version 0.9.1 (User-Agent stays `…|SpringSync/0.9`).

## 0.9.0 (unreleased, lab build, 2026-10-21). Follows SPEC.md v0.9 (§4.3, §4.4, §6.6, §9.6–§9.8, §13.1)
Built in the §13.1 order: one-way pull first (works with OneDrive), then Google Drive. No Windows port (v0.10).
Nothing here touched Microsoft, Google, the NAS, Entra, Google Admin or DNS; all tests use fakes or local paths.

### Added: one-way pull (`odnas/pull.py`, `odnas/cloud.py`)
- **Per-user direction** `sync_profiles.direction`: `two_way` (default, unchanged bisync), `pull_copy`
  ("Copy only": `rclone copy`, never deletes on the NAS) and `pull_mirror` ("Mirror": `rclone sync
  --delete-after`). Global default: setting `default_direction` (applies to new users).
- **Mirror safety (§9.7.2):**
  1. Guard 2: `rclone lsf --max-depth 1` must see `.springsync-check` at the cloud root AND the NAS root,
     else `critical` (Access test failed). Applies to Copy only too.
  2. Guard 3: the backup target must be reachable and writable (marker written and removed), else the run
     is **skipped** with a `medium` `backup_target_unavailable` alert and no state change.
  3. Counting dry-run first: the same `sync` with `--dry-run --max-delete -1 --combined <tmpfs file>`
     (op `pull_count`). `-` lines = NAS files Mirror would move. The combined file has file names: it lives
     in `/run`, is shredded after parsing, and only the 0600 delta document (admin-only page) keeps names.
  4. Over the user's delete limit (same `max_delete_pct` as two-way) → `safety_abort`, nothing moved.
     An **empty cloud listing** with a non-empty NAS → `safety_abort` (`empty_source`), even in service mode.
  5. The real run gets `--max-delete floor(total × pct / 100)` as a backstop. Exit 7 + `--max-delete
     threshold reached` → `safety_abort` (the record says up to N files may already be moved).
- **Removed and replaced NAS files are moved, never deleted:** `--backup-dir` to a new folder per run,
  `<target>/<user_id>/<YYYY-MM-DD_HHMMSS>` (UTC stamp), so two runs never overwrite each other.
- **Backup target** (`odnas/nas.py` `BackupTarget`): `pull_backup_target` = `backup_nas` (default;
  `backup_nas_host`, `backup_nas_share` = `Sync-Archive`, `backup_nas_username`, `backup_nas_password`
  secret) or `same_share` (`.springsync-archive` in the user's share). Settings has a **Test backup target**
  button (worker flag `backup_test_requested`, result in heartbeat `backup_test`, audited).
  **The Sync-Archive share and its login need Mark's OK; nothing creates them.**
- **Mirror baseline (§6.6):** switching to Mirror (or onboarding as Mirror) counts what the first Mirror
  would move; an admin approves that exact count (typed UPN, 24 h TTL, expired approvals → `medium`
  alert); a recount that differs cancels the run. While waiting, the user gets **Copy only** runs.
  Onboarding Mirror users approve the count with **Approve initial sync**.
- **Classifier for pull runs** (§9.7.4) `pull.classify_pull`: auth > time limit > exit code; exit 7 with the
  pinned message → `safety_abort`; 1,3,4,5,6,8,10 retryable (`deletes_skipped` when rclone logs
  `not deleting files as there were IO errors`); 2 usage; others `critical_retryable`.
- **Safety-abort actions for one-way users:** Accept deletes (one Mirror run with the exact count),
  **Switch to Copy only**, **Retry**. **Restore is refused** (409; the cloud is never written).
- **Weekly check for one-way users:** `rclone check --one-way` (NAS-only files are expected).
- **Safe direction switching** (§6.6), applied by the worker between runs, never during one:
  - reason required, audited `direction_switch_requested` / `direction_switched`, `low` alert;
  - two-way → one-way: bisync listings set aside (`*.lst*` → `-old-<ts>`), next slot pulls;
  - one-way → two-way: listings deleted, back to **onboarding** (preflight, dry run, Approve initial
    sync), Google-native export forced back to skip, service mode waits for `two_way_baseline_at`;
  - Copy only → two-way defaults to **Mirror first** (`direction_then = two_way`) so NAS-only files go
    to the backup target instead of being uploaded; untick to upload them;
  - a switch for a paused / needs-reauth / blocked / NAS-auth-failed user waits; a switch out of
    `safety_abort` / `critical` clears the stop and its approvals (audited `direction_switch_cleared_pending`).
- **Service mode per direction** (*Mirror part reverted in 0.9.1: Mirror keeps both checks*): two-way unchanged (`--max-delete 100`); Mirror: no % stop and no
  `--max-delete` backstop (empty-source, check-file and backup guards stay); Copy only: no effect.
  The service-mode picker shows the effect per user.

### Added: Google Drive (My Drive) as a per-user connected drive (`odnas/google.py`, §4.3, §4.4, §9.6)
- **App sign-in stays Microsoft for everyone.** No "Sign in with Google". Google is a data connection:
  a signed-in user whose provider is Google clicks **Connect Google Drive** on /me
  (`POST /me/google/connect` → `GET /auth/google/callback`). The callback requires the same Microsoft
  session that started the flow (flow sealed with user id + session id).
- Checks: `hd` = `google_allowed_domain` (`hotsprings.org`), verified email, email = the user's UPN or an
  approved alias (`google_email_aliases`), the Google `sub` not linked to another user, the Drive
  account = the signed-in account, Drive scope actually granted. Denials audited with a reason code.
- **One provider per user** (`sync_profiles.provider` = `onedrive` | `gdrive`). New users get `gdrive` if
  their UPN is in the `gdrive_users` setting, else `onedrive`. Google users' Microsoft refresh token is not
  stored. Admin **Switch cloud provider** (reason + typed UPN, refused while a run is active) erases both
  cloud credentials (secure_delete + VACUUM) and listings, keeps NAS files and the NAS login, and sends the
  user back to onboarding (audited `admin_set_provider`).
- New table **`google_credentials`** (sealed refresh token, AAD `google_credentials/<uid>/refresh_token`,
  `google_sub` unique, `google_email`, `granted_scope`, refresh times/errors). Included in rekey and
  crypto-erase.
- **rclone `drive` remote `gd-<id>`** with exactly the §9.6 keys (`scope = drive`, `root_folder_id` empty,
  `skip_gdocs`, `skip_shortcuts`, `skip_dangling_shortcuts`, `stop_on_upload_limit`, `export_formats`
  only when exporting). Token via the same broker (`token_url` → `127.0.0.1:8081`), **T-G2 untested**.
- **Google-native files** skipped by default (`google_gdocs_default = skip`); `export` (formats
  `google_export_formats`, default `docx,xlsx,pptx,svg`) only for one-way users and refused for two-way.
- **Google error handling:** `invalid_grant`/`invalid_rapt` → needs_reauth; `admin_policy_enforced`/
  `org_internal` → blocked (label "Google admin policy"); `invalid_client`/`unauthorized_client` →
  **app-wide**: one `high` alert, flag `google_app_credential`, all Google users skipped until the worker is
  restarted with a fixed client secret (flag cleared at startup, audited). Two-way 750 GB/day upload stop
  → retryable next day + `low` alert.
- **Settings:** `providers_enabled` (`onedrive,gdrive`; a disabled provider's users show a banner and do
  not sync), `gdrive_users`, `google_allowed_domain`, `google_email_aliases`, `google_gdocs_default`,
  `google_export_formats`, `google_client_secret_expires_on` (maint reminders ≤30 days / overdue).
- **Bootstrap:** `[google] client_id`, `allowed_domain`, optional `redirect_path`; the client secret is the
  credential file `google-client.secret` (LoadCredentialEncrypted); placeholders only in the repo.

### Added: Windows file-name rules from day one (§9.8)
- Every rclone command (bisync, copy, sync, check, lsf, lsjson, touch) passes the pinned
  `--local-encoding "Slash,LtGt,DoubleQuote,Colon,Question,Asterisk,Pipe,BackSlash,Ctl,RightSpace,RightPeriod,InvalidUtf8,Dot"`.
- Preflight adds `win_reserved_name` (CON, PRN, AUX, NUL, COM1–9, LPT1–9 incl. ¹²³), `win_reserved_char`,
  `win_trailing_space_or_dot`, `win_path_too_long` (UNC > 259); Google rules `google_duplicate_name`,
  `google_slash_in_name`, plus counts of Google-native files and (one-way) NAS-only files.

### Changed
- `sync_runs` gains `direction`, `provider` and `op` (`bisync`, `pull_count`, `pull_copy`, `pull_mirror`, …).
  Pages show provider, direction, Mirror baseline state, the plain-language Mirror warning and the op of
  each run. The auditor view shows all of it read-only.
- Version 0.9.0 (User-Agent `…|SpringSync/0.9`).

### Deviations from SPEC v0.9 (flagged in OPEN-QUESTIONS.md §E)
- **No `sync_runs.kind` rebuild:** the additive-only rule forbids rebuilding the table for the CHECK
  constraint, so the new kinds are recorded in `sync_runs.op`; `kind` keeps the lifecycle meaning.
- **Backup NAS mount path:** mounted by the existing mount helper under a reserved id
  (`/srv/<slug>/mnt/00000000-0000-4000-8000-00000000a5c1`) instead of `/srv/springsync/archive`, so no
  helper change is needed. It stays mounted between runs.
- **One-time `filters_changed` on upgrade:** the local-encoding string is part of the baseline digest, so
  every two-way user needs one approved resync after the upgrade from 0.8 (Mirror users recount the
  baseline). This is intended: names may change once.
- **Copy only runs no pre-count**, and the all-files-changed check is not applied to pull runs (§9.7).
- Backup folder stamps are UTC.

### Migration
- Migration 8 (expand-only): `google_credentials`; new `sync_profiles` columns with defaults
  (`provider = onedrive`, `direction = two_way`, `gdocs_mode = skip`); existing users get
  `two_way_baseline_at = onboarding_completed_at`; existing runs get `direction = two_way`,
  `provider = onedrive`. v0.8 code still runs against the new schema.

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
