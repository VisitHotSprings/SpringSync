# Open questions and blockers (v0.1, updated through v0.9)

Nothing in this repo has touched production: no Entra, NAS, DNS, GitHub, or server, and no real sign-in.
Everything below has to be resolved, or tested in a lab, **before the 3–5 user pilot**.

## A. Lab tests that block production (research §7 → SPEC §12.2)
| ID | Research §7 | What must be shown | Code that depends on it |
|---|---|---|---|
| **T-N1** | 1 | A NAS admin or svc user **cannot** mount another user's Personal-Drive; the user's own login **can**. Personal drives work as a backup-task source. Confirm the share name and the lockout count after bad logins. | Option A (`PersonalDriveProvider`); the "no retries on wrong password" rule |
| **T-N3** | 2 | Creating and permissioning 77 `Home-<user>` shares: is there an API or CLI? Per-share quota and snapshots; H: mapping. | Option B (`SharedHomeProvider`) |
| **T-N2** | 8 | UNAS→UNAS backup keeps versions, with snapshots on the target. Restore a deleted file from UNAS #2 as of T-1 day. | The whole recovery story (RESTORE.md) |
| **T-S1** | 3 | SMB 3.1.1 modtime precision, whether modtimes set by rclone stick, and how much hashing over CIFS costs for a 20–50 GB user. | `--compare size,modtime,checksum --slow-hash-sync-only`; 25-min run limit |
| **T-S2** | 5 | `.springsync-archive` on the NAS survives, can't be deleted by users, and isn't synced. | `--backup-dir2`, filters |
| **T-B1..B4** | 4 | Office files edited in the browser (size/hash drift), conflict `newer` + backup-dir, folder rename vs `--max-delete` (`--track-renames` is deliberately off), trees >100k items, restricted-character round trip, `~$` and `desktop.ini` filtered. | bisync flags, filters, preflight |
| **T-T1..T3** | 6 | Refresh beyond 90 days, admin reset and "revoke sessions" → `needs_reauth`, CA policies (MFA, compliant device, location) with a sign-in-frequency exclusion for this app. **Needs Margaret.** | `entra.classify_auth_error`, re-sign-in flow |
| **T-P1** | 7 | Staggered jobs at pilot scale, then a simulated 77-user run. Watch 429/503 and RateLimit headers. Measure the 1.27 TB seed over the VHS WAN. | `tpslimit`, governor, `resync_bwlimit` |
| **T-X1** | 9 | UniFi Drive's native M365 backup for the pilot users | The "OneDrive on/off" decision |
| **T-A3** | spec | rclone refreshes through `token_url` → our broker with a per-run handle. The rotated token is saved, no real token is on disk, and it holds up over long runs. **Untested; code ready.** | `BrokerTokenStrategy` (default). If it fails, set `token_mode = "tmpfs_config"` + `credential_type = "secret"`. |
| **T-A4** | spec (research §6 #20) | rclone lists, uploads, and deletes with only `Files.ReadWrite offline_access` and `disable_site_permission = true` | `tokens.render_rclone_config` |
| **T-G1..G3** | v0.9 | Google Cloud project, Internal client, Trusted app (needs Mark's OK); broker refresh for rclone `drive` (T-G2, untested); Google specifics (Docs skipped/exported, shortcuts, duplicates, trash, 403/429) | `odnas/google.py`, `tokens.render_drive_config`, preflight Google rules |
| **T-M1** | v0.9 | Mirror / Copy only to UNAS #2 `Sync-Archive` (cross-NAS move = copy + delete), time per 1,000 files, retention | `BackupTarget`, `pull.build_pull` |
| **T-C1** | spec / §14.12 | The Caddy v2.11.7 + googleclouddns build issues a cert from LE staging, then production, through the CNAME to the ACME zone with the minimal SA, and writes to other RRsets are denied | `install.sh` step 5, Caddyfile |

Also not covered by local tests:
- `install.sh` on a fresh 24.04 VM, including a second run to prove it is idempotent;
- `update.sh` / `rollback.sh` end to end;
- `caddy validate` (no Caddy binary here);
- real CIFS mounts through the helper inside the worker's systemd mount namespace;
- MSAL against a real tenant.

## B. Entra app credential expiry (24-month maximum)
- Entra caps a client secret at **24 months**, and certificates are normally issued for 12–24 months. Each
  app credential **will** expire, and when it does every user's sync stops at the next token refresh.
- v0.1 supports **certificate credentials** (`credential_type = "certificate"`, which is the default and
  preferred) and keeps the client secret as a fallback.
- The expiry date is read from the certificate itself. For a secret, it comes from the
  `entra_credential_expires_on` setting.
- The countdown appears on the **admin** and **auditor** pages: amber at ≤60 days, red at ≤14 days, and a
  banner once it has expired or if it is unknown.
- `maint` opens reminder issues at 60/30/14/7/1 days.
- **Process to agree:**
  1. Create the new certificate or secret about 30 days early.
  2. Upload it beside the old one in Entra.
  3. Swap the files with `systemd-creds encrypt`, then restart the services.
  4. Confirm a sync works, then remove the old credential.
  5. Record the date in the IT calendar.

## C. Decisions and approvals needed from Mark (SPEC §14 + build)
1. **OneDrive on or off** (T-X1). If off, this becomes a one-way migration and bisync is dropped.
2. **Option A vs. B**, after T-N1/T-N2/T-N3. Option A stores about 77 NAS passwords and may not allow admin
   backup of personal drives. The code supports both through the `nas_option` setting; the default is A.
3. **Final product name** (SpringSync is the frontrunner). Only `product_name` / `slug` change.
4. **Offboarding:** final sync yes or no; data retention; app-only `User.Read.All` for detecting disabled
   accounts (Walter). The automatic group re-check is not implemented.
5. **Alert mail path:** the M365 relay or an internal relay, and whether the product may send system alerts
   directly under the "outbound to people via Gidget" rule. Until that is decided, alerts show **only on the
   admin page**.
6. **Sync root:** the whole drive vs. a subfolder such as `OneDrive/`.
7. **A record for `sync.hotsprings.org`:** public or internal-only. The name shows up in CT logs either way.
8. **SIEM/syslog forwarding** and how long to keep audit records.
9. **GitHub:** org/account, private repo, read-only deploy key, tag signing, and who holds repo admin
   (Walter reviews).
10. **Entra app registration:**
    - single-tenant, redirect `https://sync.hotsprings.org/auth/callback`;
    - delegated `Files.ReadWrite offline_access User.Read`;
    - certificate upload, `groups` claim (security groups);
    - 3 groups: Users / Admins / Auditors.
11. **Tenant user-consent settings.** If users can't consent themselves, admin consent is needed for those
    delegated scopes only (Walter and Margaret).
12. **CA policy test and sign-in-frequency exclusion** for the app, with Margaret (T-T3).
13. **ACME DNS:** GCP project, ACME-only zone, minimal SA, and the `_acme-challenge` CNAME in hotsprings.org.
14. **Hosting:** a VM vs. a mini-PC, and TPM availability for `systemd-creds`.
15. **Walter's review checklist** (SPEC §7.10): repo/deploy key, credential storage, app permissions, sudo
    helper, audit-log integrity.
16. **Key escrow:** where Mark keeps the offline copy of `data.key`.

## D. Spec ambiguities and build findings

### Resolved by SPEC v0.2 (closed)
- ~~Caddy plugin pin~~:
  - The tag `v1.1.0` is commit `6fcdbd98a8565df50ff40ff53411dc6c8d97dcd9` (checked on proxy.golang.org).
  - sum.golang.org gives `h1:SDxKxFh7d5Jq2/JPnu9Jv8ErOIdfXmK+Oad0qVzQi80=`, and its go.mod requires
    libdns/googleclouddns v1.2.0.
  - install.sh pins the tag and verifies the module version and hash in the built binary. The build itself
    is still T-C1.
- ~~Go toolchain checksum~~: pinned at `65efbc80…379b40`, which matches go.dev/dl JSON as of 2026-10-20.
  The refusal is removed.
- ~~Exit 7 vs. `--max-delete`~~: §9.4 is rewritten, implemented, and verified against the real binary.
- ~~Check files before the dry-run~~, ~~"outside business hours" (`resync_hours`)~~, ~~single nonce column~~,
  ~~mount-helper `verify` verb~~, ~~Option B per-run mounts~~ and ~~SQLAlchemy/Alembic → stdlib sqlite3~~
  are all accepted in SPEC v0.2.
- ~~requirements.lock on 3.13~~ is accepted as a pre-install step (regenerate on 24.04 / 3.12).
  **It is still to do before the first install.**
- ~~IT-Backups copy~~ is deferred by SPEC v0.2 to before go-live, not before the pilot. It is still not
  built.

### Resolved by SPEC v0.3 (closed)
- ~~"Retryable" text doesn't guarantee recovery~~: escalation now happens on the same error twice in a row,
  immediately on a check-access failure, or on the 3rd in a row. "cannot find prior listings" therefore
  locks out on its 2nd occurrence.
- ~~Restore timing~~: next slot by default, or **Run tonight**.
- ~~Restore / Accept-deletes semantics~~: Accept deletes has a 24 h expiry, a pre-run recount, the normal
  run-time limit, no automatic re-run, and full audit.

### Resolved by SPEC v0.4 (closed)
- ~~Restore and the run-time limit~~: next slot 25 min, then one automatic re-queue as tonight; tonight runs
  until 07:00 CT; still running then → stopped, paused, alert.
- ~~What a "delete count" is~~: per side (Path1 / Path2), from the dry-run's `File was deleted` deltas.
- ~~What breaks a "consecutive" chain~~: mount failures are skipped; counted separately (alert after 2).
- ~~Run ordering~~: fixed (recount row before force row).
- ~~SPEC §5 value lists~~: aligned, and checked by a test.

### Resolved by SPEC v0.5 (closed)
- ~~Per-side counts vs. real rclone~~: counts come from the delta dry run, never the log.
- ~~Which runs reset the mount-failure counter~~: only a successful mount; `nas_auth` neither counts nor resets.
- ~~Tonight run near 07:00~~: needs at least 30 min left, else waits for the next night (audited).
- ~~Safety abort during onboarding~~: normal safety abort; onboarding stays incomplete; Restore re-runs
  the onboarding `--resync`.

### Resolved by SPEC v0.6 (closed)
- ~~When onboarding counts as complete~~: first successful normal bisync only.
- ~~Restore after an onboarding dry-run abort~~: straight to `--resync`; click audited as the first-sync approval.
- ~~Hold alert severity~~: `low`, then `medium` if the same Restore is held a second night.
- ~~`nas_auth` under Option B~~: one global NAS pause, one high alert, no retries, auto-resume after a new
  password and a good test mount.

### Resolved by SPEC v0.7 (closed)
- ~~When the svc-sync test mount runs~~: the worker's next tick (≤60 s); Settings shows "Testing new password…".
- ~~What gets test-mounted~~: the svc-sync-only health-check share (`nas_health_share`, default `Sync-Health`).
- ~~Offboarding during the pause / switching to A / hold count across re-queue~~: accepted as built.

### Resolved by SPEC v0.8 (closed)
- ~~Health-check interval and alert rule~~: every 15 min; `medium` after 2 consecutive failures.
- ~~Service mode scope~~: all users plus selected accounts (§9.5).

### Still open or ambiguous (v0.8)
1. **§14.13: may IT admins see file names in the Accept-deletes list?** Walter has to sign off. **This
   stays OPEN and is going to Mark via Gidget.** Until then the list has its own IT-admin-only page,
   Auditors and Users get 403, every view is audited, and everything else carries counts only.
2. **Service mode is a real risk window. Flagged for Mark.** Integration-tested: under service mode, a
   deletion of **100%** of one side's files propagates.
   - What still protects us: the all-files-changed check, `--check-access` (catches an empty or wrong
     mount), `.springsync-archive` (every deleted file is kept), the OneDrive recycle bin and NAS snapshots.
   - What doesn't: a real mass deletion on one side, e.g. ransomware that deletes rather than encrypts, or
     a OneDrive-side mistake. It reaches the other side within one slot.
   - Options, not built:
     - a high ceiling (e.g. 90%) instead of 100;
     - an alert when one service-mode run deletes more than N files;
     - a delete-count cap per window.
3. **"End time" input.** The UI asks for a duration in whole hours (1-24, default 4), and the end time is
   shown and stored. There is no picker for a clock time. Confirm.
4. **Extend semantics.** Re-enabling sets the end to now + the new hours (still max 24 h from now), so
   repeated extends can keep it on for longer than 24 h in total. Each extend is audited. Should there be a
   hard total cap?
5. **Typed confirmation** is required only for the all-users switch (`ALL USERS`); selected accounts need a
   reason, not a typed confirmation.
6. **Both scopes at once.** A run is tagged `all` when the all-users window is open, else `user`. Each
   window's end summary counts only runs with its own tag, so an overlap is counted once, under all users.
7. **Per-side delete counts** come from the run log's `File was deleted` lines on each side (the deletion
   is then applied to the other side). `files_deleted` (rclone stats) stays as the total.
8. **The user's own status page** doesn't show service mode (not in §6.5's lists). Should employees see
   that it's on?
9. **Summary alert severity** is `low` (not stated in the spec).
10. **Creating `Sync-Health`** (and the Option B shares and svc-sync account) needs Mark's OK. Documented
    in docs/DEPLOY.md, not done.
11. **A missing health share vs. a rejected password**: the CIFS error codes need lab test T-N2.
12. **Shared tonight window**, onboarding Restore rules, and the 30-min cutoff only for tonight Restores:
    accepted for the pilot unless Mark objects.
13. **Lockout under `--resilient`** still isn't reproducible locally. The integration test drops
    `--resilient`. A T-B* lab test should capture a real one.
14. **`caddy build-info` format** (used by the plugin-pin check) is untested until T-C1.
15. **Worker hardening:** `NoNewPrivileges` is off because the worker needs sudo. A socket-activated helper
    would allow it.
16. **The internal web→worker token** is HMAC-derived from the data key, not a separate secret.
17. **Option B "mounted persistently"** is per-run idempotent mounts. A boot-time mount unit is not built.

## E. v0.9 build findings and deviations (Dex)
1. ~~**`sync_runs.kind` was not rebuilt.**~~ **Approved by Reid (v0.9.1).** SPEC v0.9 adds run kinds; changing the CHECK constraint means a
   table rebuild, which the additive-only rule forbids. The new kinds are in the new `sync_runs.op` column
   (`bisync`, `pull_count`, `pull_copy`, `pull_mirror`); `kind` keeps its lifecycle meaning (dryrun,
   resync, bisync, delta, force, check). OK, or should a later release do the rebuild?
2. ~~**Backup NAS mount point**~~ **Approved by Reid (v0.9.1).** is `/srv/<slug>/mnt/<reserved id>` through the existing helper, not
   `/srv/springsync/archive` as in the §9.7.3 example. It stays mounted between runs. OK?
3. **Upgrade from 0.8 trips `filters_changed` once** because the pinned local-encoding string is part of the
   baseline digest. Every two-way user needs one approved resync after the upgrade (Mirror users recount
   their baseline). Intended, but it's up to 77 one-at-a-time approvals. **Bulk approve is NOT built:
   Mark hasn't decided.** Reid's proposal, for Mark:
   - bulk approve only users whose test run (the dry run before the resync) shows **no deletes and no
     conflicts** on either side;
   - everyone else is approved one at a time, as now (review, then **Approve initial sync / resync**);
   - (Dex's notes for when it's built: the bulk action would re-check each user's counts at click time,
     list the users it approved and skipped, audit one entry per user, and stay IT-admin only.)
4. ~~**Copy only has no pre-count**~~ **Approved by Reid (v0.9.1):** Copy only keeps exactly guards 2
   and 3., and the all-files-changed check does not apply to pull runs (the SPEC's
   §9.7.2 guards are for Mirror). The brief said "keep the checks"; confirm Copy only is fine with guards 2
   and 3 only (its replacements always go to the backup target).
5. **Mirror backstop:** the real run's `--max-delete N` can move up to N files before it trips (exit 7);
   those files are already in the backup folder. Integration-tested on v1.75.2.
6. ~~**Mirror under service mode** has no % stop and no backstop~~ **Changed in v0.9.1 (Reid):** service
   mode does not loosen Mirror at all. Mirror keeps the percentage stop and the `--max-delete` backstop in
   service mode; its runs are only tagged for the end-of-window summary. A real Mirror command can't be
   built without the backstop. For a planned large Mirror cleanup, use **Accept deletes** on the safety
   stop (exact count, typed UPN, 24 h).
7. **Mirror while waiting for the baseline** runs Copy only (never deletes), so cloud changes keep arriving.
8. **Switching back to two-way without "Mirror first"** uploads every NAS-only file to the cloud on the
   onboarding resync. The default from Copy only is Mirror first; from Mirror it's not needed.
9. **Google duplicate names** are reported by preflight and then skipped by rclone (one of them is not
   synced). Folder shortcuts are skipped by rclone and not counted (rclone hides them in listings).
10. **Google users' Microsoft refresh token is not stored** (their session is still Microsoft). A
    provider switch to OneDrive therefore needs the user to sign in again.
11. **New users get their provider from `gdrive_users`** (a UPN list in Settings) at first sign-in;
    afterwards only the admin's Switch cloud provider changes it. OK, or should IT pick per user before
    first sign-in some other way?
12. **App-wide Google client failure** (`invalid_client`) stops all Google users until the worker restarts
    (one high alert, admin/auditor banner). There is no "clear" button on purpose (the secret is a file).
13. **T-G2 (broker refresh for rclone `drive`)** is untested; the tmpfs-config fallback is wired for Google.
14. ~~**Backup stamps are UTC**~~ **Approved by Reid (v0.9.1)**; every time *shown* (pages, admin,
    auditor, alerts) is Central (America/Chicago) with CST/CDT. Backup stamps are UTC (`YYYY-MM-DD_HHMMSS`), not Central time.

## F. SPEC v0.9 §14.19–§14.27 (open; defaults as built)
| SPEC | Question | Who | Built default |
|---|---|---|---|
| §14.19 | Cloud scope for one-way users: `drive` / `Files.ReadWrite` for everyone (check file + no reconnect on switch) vs. `drive.readonly` / `Files.Read` for one-way-only users | Walter | `drive` and `Files.ReadWrite` for everyone. Read-only scope would need a saved root-folder id instead of the cloud check file, and a reconnect to switch to two-way. |
| §14.20 | Backup target: share name, retention (suggest 90 days), who may read it; creating it **needs Mark's OK** | Mark, Walter | `backup_nas`, `Sync-Archive`; runs skipped until it's configured and tested. Fallback `same_share`. |
| §14.21 | Who sets direction and provider; default direction; users picking their own; a second provider later | Mark | Admins only, per user; `default_direction = two_way`; one provider per user. |
| §14.22 | Copy only and NAS edits: cloud replaces (old NAS copy to backup) vs. `--update` (keep newer NAS files) | Mark | Cloud replaces; old version to the backup target. `--update` not built. |
| §14.23 | Google-native files: export for one-way users (docx/xlsx/pptx or pdf)? | Mark | Skip for everyone (`google_gdocs_default = skip`); per-user export allowed for one-way only (`docx,xlsx,pptx,svg`). |
| §14.24 | Google email = UPN, or aliases? Test-only admin Google sign-in for the Ubuntu test (needs Walter's OK) | Mark, Walter | Aliases via `google_email_aliases`. **No test-only Google sign-in built** (app login stays Microsoft). |
| §14.25 | Windows NAS access Option A vs. B (error 1219); recommendation B; T-W4 | Mark | Not in scope (v0.10). |
| §14.26 | Windows host: machine with TPM 2.0 + UPS, Intune ring, restart window (Sun 03:00–05:00 CT), BitLocker key escrow, remote management | Mark, Margaret | Not in scope (v0.10). |
| §14.27 | Google data volume / API cost (1 TB/day egress threshold); Dec 2026 move to M365 may make Google short-term | Mark | No code limit; use `resync_bwlimit` and seed over several nights; Copy only is the final Google → NAS pull. |

## G. Notes for SPEC.md (for Reid; SPEC.md not edited by Dex)
- **§9.5 (service mode, per direction) and §9.7.2 step 4–5:** replace the v0.9 Mirror line with: "Mirror:
  no effect. Service mode never loosens Mirror: the counting dry-run's percentage stop and the real run's
  `--max-delete floor(total × pct / 100)` backstop both apply; Mirror runs are only tagged for the summary.
  Large planned Mirror deletes go through Accept deletes." (Built in v0.9.1.)
- **§6.5 / §10 (display):** "All times shown to people (pages for users, admins and auditors; alert and
  issue text; alert mail) are Central (America/Chicago) with the CST/CDT label. Stored times, the audit
  chain, logs and backup folder names (`YYYY-MM-DD_HHMMSS`) stay UTC." (Built in v0.9.1.)
- **§13 / §12.2:** T-G2 must pass on the Ubuntu test host before any real Google user is connected
  (docs/DEPLOY.md checklist).
- **§14 (new):** bulk approve for the post-upgrade resyncs (§E.3), Reid's proposal, Mark to decide.

## H. v0.10 Windows host: deviations and open questions (Dex)
Built from SPEC §11.5 / §11.6. Each item is how it's built now; Reid / Mark to confirm or change.

### H.1 Deviations from the spec
1. **Python 3.13.17 embeddable, not the 3.12 installer.** python.org no longer ships Windows binaries for
   3.12 security releases. The embeddable zip is the official python.org build, is checked by SHA-256 and
   avoids a system-wide install (and antivirus-unfriendly bundlers). The app's tests run on 3.13 in CI.
2. **Zip install, not `git clone` with a deploy key.** There is no org deploy key yet. The release zip is
   built from `git archive` of the tag plus verified vendor files, with `SHA256SUMS.txt` inside and next to
   it. `update.ps1 -Zip -Sha256` replaces "git fetch + checkout". A deploy-key pull can come later.
3. **No venv.** The private Python gets packages with `pip --target` from the hashed
   `requirements-windows.lock` (offline, `--require-hashes --only-binary=:all:`).
4. **NAS: WNet API with the database-stored NAS logins, not Credential Manager / `cmdkey`.** `cmdkey` puts
   the password on a command line, and svc-springsync is denied interactive logon, so it can't manage its
   own vault. Not the rclone `smb` backend either: no hashes, `--backup-dir` can't span servers, and it
   breaks the §9.8 behaviour match with Linux.
5. **Service wrapper: pywin32, not WinSW.** It runs on the private Python, needs no extra exe from GitHub,
   and handles pre-shutdown so a reboot drains running syncs.
6. **Caddy service is `springsync-caddy`** (Caddy's own Windows service support via `sc.exe`), so it can't
   clash with another Caddy on the PC. Logs go to `logs\caddy.log` (service stdout is discarded).
7. **Timers live in the worker** (backup 02:30, maintenance 03:30 Central) instead of systemd timers / Task
   Scheduler, so no scheduled task needs a stored password.
8. **Per-run rclone configs are written to `ProgramData\SpringSync\run`** (ACL-locked, deleted after the
   run). Windows has no tmpfs, so **BitLocker is required** (pre-flight warns without it).
9. **On Windows the config backup covers only `springsync.toml` and the Caddyfile**; keys are DPAPI-bound to
   the account and are recovered from escrow, not from the backup.

### H.2 Open questions
1. **§14.25 Option A vs B (error 1219).** Built: Option A works, but users on the same NAS server with
   different logins run one after another, and a backup NAS on the same server with another login fails
   fast. **Recommendation: Option B** (one service login on the UNAS Pro). T-W4 decides.
2. **Plain HTTP for the lab?** The spec is HTTPS-only, so none was built. If Mark wants a lab run before
   DNS-01 is ready, proposal: a lab-only `tls internal` Caddyfile plus a hosts-file entry, or use the site
   from the PC itself (`127.0.0.1`). Needs Reid's OK; not built.
3. **Windows Update window (§14.26).** Proposed only: Intune ring, active hours 06:00–22:00, restarts Sunday
   03:00–05:00 CT (after the 02:30 backup and clear of the 03:30 maintenance). Margaret owns Intune.
4. **Caddy for Windows** has to be built where Go modules can be downloaded
   (`deploy/windows/build-caddy-windows.sh`), then its SHA-256 recorded. Not built here.
5. **Code signing.** Scripts are ready for Authenticode (`Set-AuthenticodeSignature`). Does VHS want a
   certificate (and who holds it)? Until then the guide covers SmartScreen and SHA-256 checks.
6. **Ubuntu → Windows move (§11.6).** The guide covers a fresh Windows install. Moving the database from
   the Ubuntu host needs the escrowed `data.key` (and `entra-app.key`) put in with
   `set-secret.ps1 -FromFile` before the services start; steps are at the end of INSTALL-WINDOWS.md §15,
   untested.
7. **Not tested on real Windows:** T-W1 (1219), T-W2 (long paths / encoding), T-W3 (CTRL_BREAK stop),
   T-W4 (A vs B), reboot during a run, DPAPI after a password change. The `windows` CI job runs the
   Windows unit tests once the branch is pushed.

## I. v0.11 opt-in auto-update (Dex, 2026-10-22)
Built to SPEC §11.4.1. Reid settled items 1–7 in **SPEC v0.10** (§14 "Resolved in v0.10"); v0.11.0 follows
them as written:
1. ~~Which releases count~~: only normal published releases with a plain `vX.Y.Z` tag. No drafts, no
   pre-releases, no bare tags, no `git ls-remote` fallback (§11.4.1 rule 3). Built.
2. ~~24 h wait~~: counted from `published_at` (§11.4.1 rule 4). Built.
3. ~~"Approval pending"~~: Mirror run in progress, a pending Accept-deletes or Mirror-baseline approval, an open
   safety hold (`state=safety_abort`, from the percentage stop or the `--max-delete` backstop), or a pending
   direction change. "Approve initial sync" and two-way runs don't block (§11.4.1 rule 7). Built.
4. ~~Window vs. backup~~: 02:45 Central + up to 30 min. auto-update.sh checks `<slug>-backup.service`, waits up
   to 15 min and otherwise skips with `backup_running` (§11.4.1 rule 2). The 03:30 maintenance job waits for an
   update through the shared update lock (Dex's choice of lock: `/run/lock/<slug>-update.lock`). Built.
5. ~~Catch-up~~: none, `Persistent=false`. Built.
6. ~~Alert mail~~: admin-page issues now; email follows §14.5 (SPEC §14.36).
7. ~~Windows~~: Ubuntu only in v0.11.0; Windows later as a Scheduled Task (SPEC §14.37).
8. **Still open: tag signing** (SPEC §14.9). `require_signed_tags` and `allowed_signers` exist, but there's no
   signing key yet. Until there is one, the GitHub org must require 2FA for every owner and member.

## J. v0.12 Sign in with Microsoft / Google (Dex, 2026-10-22)
Built to SPEC v0.10.1 §4.5 (Mark's order, 4:38 PM CT). For Reid to confirm or move into SPEC:
1. **Redirect path:** `/auth/google/signin/callback` (config `[google] signin_redirect_path`), on the existing
   Internal client. Mark adds `https://sync.hotsprings.org/auth/google/signin/callback` in the Google console.
2. **Switch name:** `[signin] google = true` as in §4.5.9 (with `microsoft_work`, always true, and
   `personal_microsoft`, which must be false). The code default is **false** and the example file ships
   `google = false`; the DEPLOY step sets it to true for the pilot. No Gmail setting.
3. **Turning it back on after the GUI kill switch:** §4.5.9 says "needs the local config". Built as a server
   CLI command (`springsync signin enable-google`, audited) that clears the kill flag; it refuses if the
   config says `google = false`. A config edit alone doesn't clear the flag, so a kill isn't undone by an
   unrelated restart.
4. **Step-up list (§4.5.6):** Offboard, Accept deletes, Mirror baseline, set direction, set provider, Service
   mode on (per user and global), every Settings save (covers pilot list, NAS option/share, providers), admin
   unlink, and the kill switch. Pause/Resume, Approve initial sync, Retry and Restore stay allowed on a fresh
   Google admin session. Role changes have no GUI (they come from Entra). Confirm.
5. **N-day rule (§14.38–41, pending Mark):** setting `google_signin_ms_max_age_days` (1–90, default 7). Past it,
   a Google session has **no access** (it asks for a Microsoft sign-in); it doesn't end the session.
6. **Google session length 4 h** (Microsoft 8 h), because Google sign-in bypasses Entra Conditional Access
   (§4.5.8 item 3). Not stated for Workspace accounts in SPEC; Dex's choice.
7. **Skew:** 60 s as SPEC. Max token age 10 min after `iat` for both providers.
8. **Last method removed by an admin** = the user goes to `offboarding` (credentials erased by the existing
   offboarding job; files untouched), with the UPN typed to confirm. Users can't remove their last method.
9. **Unlinking a Microsoft identity** renames `users.entra_oid` to `unlinked:<oid>:<time>` so the old account
   can't re-attach by the legacy column; a later Microsoft sign-in with it is refused ("removed from
   SpringSync. Ask IT.") instead of creating a second user. Re-linking it is through Link Microsoft from a
   Google session (or an admin restore later).
10. **Not built in v0.12.0:** admin invites / one-time links and **Google-only users** created by an admin with
   a chosen NAS share (§4.5.5 b, §4.5.6). Until then every user starts with a Microsoft sign-in. No `invites`
   table yet.
11. **Microsoft sign-in still also connects OneDrive** (same scopes as before); only Link Microsoft discards
   its refresh token. Splitting sign-in from connect is not in this release.
12. **Google sessions** may change the NAS login and connect Google Drive like Microsoft sessions. Say if
   those should need a Microsoft session too.
13. `auth_time`: Google sends it only if enabled for the project; checked when present, otherwise the
   10-minute, session-bound link request is the control (T-I1 records which).

