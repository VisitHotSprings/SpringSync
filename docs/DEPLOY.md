# Deploy model

This page is the Ubuntu host. For the Windows 11 Pro host (v0.10, SPEC §11.5) see
[INSTALL-WINDOWS.md](INSTALL-WINDOWS.md); its scripts are in `deploy/windows/`.

## Pull model
- The code is in the **public** repo https://github.com/VisitHotSprings/SpringSync (public since
  2026-10-22). Never commit real hostnames, IPs, share names or staff emails; they go in the server's
  local config only.
- The server **pulls** over HTTPS: `install.sh` and `update.sh` run `git clone --depth 1 --branch vX.Y.Z`.
  No CI job or person pushes to the server, and the server holds no credential that can write to GitHub.
- If the repo ever goes private again, set `REPO_URL=git@github.com:...` and put a read-only deploy key at
  `/etc/<slug>/deploy/id_ed25519` (0400 root); both scripts then use it.
- Only `vX.Y.Z` tags are accepted; branch names are refused. Tag-signature verification can be switched on
  (`REQUIRE_SIGNED_TAGS=1`) once a signing key exists.
- Dependencies are installed with `pip --require-hashes` from `requirements.lock`.

## Layout
```
/opt/<slug>/releases/<tag>/   code + venv (root-owned, read-only to the service)
/opt/<slug>/current  -> releases/<tag>
/opt/<slug>/previous -> releases/<older tag>    (set by update.sh, used by rollback.sh)
```

## One-command update
```
sudo /opt/springsync/current/deploy/update.sh v0.1.1
```
1. Fetch the tag and build its venv.
2. Run the `--smoke` tests.
3. `worker drain` (waits for running jobs, up to 30 min).
4. DB backup `pre-<tag>`.
5. `db-upgrade` (expand-only).
6. Switch `current`, restart web and worker, then `/healthz` for 60 s.
7. If health fails, it **rolls back automatically**.
8. Audit entry, then prune to the last 3 releases.

Manual rollback: `sudo /opt/springsync/current/deploy/rollback.sh [--restore-db]`.

The GUI shows the running version but never triggers an update (SPEC §11.4).

## Services
| Unit | Starts at boot | Restart |
|---|---|---|
| `caddy` | yes | on-failure |
| `<slug>-web` | yes | on-failure, 5 s, burst 5/300 s, `OnFailure=` alert |
| `<slug>-worker` | yes | same; `KillMode=mixed`, 120 s stop timeout |
| `<slug>-backup.timer` | 02:30 America/Chicago | `Persistent=true` |
| `<slug>-maint.timer` | 03:30 America/Chicago | `Persistent=true` |

## Logs
- App and worker logs go to journald (`journalctl -u <slug>-worker`).
- Per-run rclone JSON logs are in `/var/log/<slug>/runs/<user_id>/<run_id>.json`, `0640 <slug>:adm`,
  pruned after 30 days.
- Members of `adm` (Walter, via `LOG_READERS`) can read both. Audit entries are also written to syslog as
  `<slug>-audit`.

## NAS install steps (manual; NOT done by install.sh)

> **Needs Mark's OK** (through Todd) before anyone does it: these are NAS changes. The installer only
> prints a reminder; no SpringSync code ever creates shares or changes NAS permissions.

1. **Option B only: create the health-check share** (SPEC v0.7 §11.1), **needs Mark's OK**.
   - On UNAS #1, create a small share, default name `Sync-Health`. It holds no user data (an empty share,
     or a single README, is enough).
   - Permissions: **`svc-sync` only** (read is enough; the test is a read-only mount that lists the root).
     No user or group access.
   - If you pick another name, enter it in **Settings → NAS → Health-check share** (`nas_health_share`).
   - It is used for (a) the test mount after a new `svc-sync` password is saved (this clears
     `nas_global_pause`, even with zero users) and (b) the routine NAS health check every 15 min. Neither
     ever touches a user's `Home-<user>` share.
2. Option B: the `Home-<user>` shares and the `svc-sync` account itself (SPEC §4.2), also NAS changes that
   need Mark's OK.

## CIFS mounts
- The worker never writes fstab. Each run calls the helper, which mounts:
  - Option A: `//<nas>/<share>` with the user's credentials;
  - Option B: `//<nas>/Home-<user>` with svc-sync.
- The mount point is `/srv/<slug>/mnt/<user_uuid>`, with fixed options. For a manual lab check, the
  equivalent of what the helper does is:
  ```
  mount -t cifs //unas.hotsprings.local/Personal-Drive /srv/springsync/mnt/<uuid> \
    -o vers=3.1.1,seal,uid=springsync,gid=springsync,file_mode=0600,dir_mode=0700,nosuid,nodev,noexec,noserverino,credentials=/run/springsync/creds/<uuid>
  ```

## v0.9: one-way backup target and Google Drive (manual; NOT done by install.sh)

> Everything in this section **needs Mark's OK** before anyone does it. These are NAS changes and Google
> Cloud / Google Workspace admin changes. No SpringSync code creates shares, Google projects, OAuth clients
> or Admin-console settings, and nothing here has been done.

### Sync-Archive share on the backup NAS (needs Mark's OK, through Todd) — SPEC §9.7.3, §14.20
Needed only when Settings → Cloud → `pull_backup_target` = `backup_nas` (the default) and any user is on
Copy only or Mirror. Until it exists, one-way runs are **skipped** (medium alert `backup_target_unavailable`);
nothing is replaced or removed without a backup.
1. On UNAS #2 create a share, suggested name `Sync-Archive` (`backup_nas_share`).
2. Create a dedicated service login for it (not `svc-sync`, not a person). Read/write on this share only.
3. Retention: a NAS-side rule (suggested 90 days, §14.20). SpringSync never deletes from it.
4. Readers: decide who may read it (§14.20): it holds every one-way user's moved and replaced files.
5. In Settings → Cloud enter `backup_nas_host`, `backup_nas_share`, `backup_nas_username` and
   `backup_nas_password` (secret; replace-only), save, then press **Test backup target**. The worker mounts
   it within 60 s and writes/removes `.springsync-write-test`; the result shows on the Settings page and in
   the audit log (`backup_target_tested`).
- The worker mounts it through the existing mount helper at
  `/srv/<slug>/mnt/00000000-0000-4000-8000-00000000a5c1` (reserved id) and leaves it mounted.
- Each run writes to `<user_id>/<YYYY-MM-DD_HHMMSS>` (UTC). Moving across NAS boxes is copy + delete, so
  each moved file crosses the network twice (lab test T-M1 measures it).
- Fallback without a new share: `pull_backup_target = same_share` (`.springsync-archive` in each user's
  share, copied by the UniFi backup task).

### Google Cloud project and OAuth client (needs Mark's OK; Mark's Google admin sign-in) — SPEC §4.3, T-G1
1. In the hotsprings.org Google Cloud organisation, create an **org-owned** project (e.g. `springsync`).
2. Enable the **Google Drive API** only.
3. OAuth consent screen: **Internal** user type; scopes `openid`, `email`,
   `https://www.googleapis.com/auth/drive` (Walter reviews the scope, §14.19).
4. Credentials → OAuth client ID → **Web application**; authorised redirect URI
   `https://sync.hotsprings.org/auth/google/callback`. No JavaScript origins.
5. Google Admin console → Security → API controls → App access control: mark the client as **Trusted**
   (so Drive access isn't blocked by the Workspace policy).
6. Put the client ID in `/etc/<slug>/springsync.toml` under `[google] client_id`, and
   `allowed_domain = "hotsprings.org"`.
7. Store the **client secret** as an encrypted credential, never in the repo or the DB:
   ```
   sudo systemd-creds encrypt --name=google-client.secret - /etc/<slug>/creds/google-client.secret.cred
   ```
   and add a drop-in for **both** `<slug>-web` and `<slug>-worker`:
   ```
   # /etc/systemd/system/<slug>-worker.service.d/google.conf (same for -web)
   [Service]
   LoadCredentialEncrypted=google-client.secret:/etc/<slug>/creds/google-client.secret.cred
   ```
   The drop-in is not shipped in the units by default (no Google until Mark's OK).
8. Record the rotate-by date in Settings → Google → `google_client_secret_expires_on`; maint raises a
   reminder from 30 days before it.
9. Restart web and worker. "Connect Google Drive" appears for users whose provider is Google (Settings →
   Cloud → `gdrive_users`, or the user's admin page).
   **Do not add any real Google user to `gdrive_users` (or switch anyone to Google) until T-G2 has passed
   on the Ubuntu test host** (checklist below). Until then only a test account connects.
- Rotating the secret: create the new secret in the console, re-encrypt the credential file, restart the
  worker (this also clears the app-wide `google_app_credential` stop), confirm a Google run, then delete
  the old secret in the console (T-G1 confirms the flow).
- Volume/cost: new projects have a 1 TB/day egress threshold (§14.27). Seed large My Drives over several
  nights with `resync_bwlimit`.

## Ubuntu test-host checklist (before real users)

The lab tests from SPEC §12.2 that run on the Ubuntu 24.04 test host (Mark's MDF desktop) and the
SpringSync step each one unblocks. Record date, tester and result for each in the pilot log. Every item
that changes the NAS, Entra, Google Admin or DNS needs Mark's OK first.

| # | Test | Required before | Pass when |
|---|---|---|---|
| 1 | T-N1, T-N2, T-N3 (NAS access, backup versions, Option B shares) | any real user | as SPEC §12.2 |
| 2 | T-S1, T-S2, T-B1..B4 (SMB modtimes, archive folder, bisync behaviour) | any real two-way user | as SPEC §12.2 |
| 3 | T-A3, T-A4 (OneDrive token refresh through the broker; minimal scopes) | any real OneDrive user | as SPEC §12.2 |
| 4 | T-M1 (Copy only / Mirror to UNAS #2 `Sync-Archive`) | any real one-way user | moved files restorable from UNAS #2 |
| 5 | T-G1 (Google Cloud project, Internal client, Trusted app; **needs Mark's OK**) | T-G2 | a hotsprings.org test account connects; an outside account is refused |
| 6 | **T-G2: Google token refresh through the broker** | **any real Google user is connected** | see below |
| 7 | T-G3 (Docs skipped/exported, shortcuts, duplicates, trash, 403/429 back-off) | the Google pilot user | documented behaviour, no data loss |

### T-G2 (required before ANY real Google user is connected)
Status: **not run** (no Google project exists yet; it depends on T-G1). The code is built and unit-tested
only with a fake Google client.

Goal (SPEC §4.3, §12.2): rclone's `drive` backend refreshes its access token through `token_url` →
the SpringSync broker (`http://127.0.0.1:8081/broker/<id>/token`) with a per-run handle, and no real Google
token is ever on disk.

Use one **test** Google account in hotsprings.org (not a staff member's), connected with Connect Google
Drive, on Copy only first, then two-way, against a test NAS folder.
1. **Refresh via the broker:** run a sync longer than one access-token lifetime (over 1 h; e.g. a large
   test folder with `resync_bwlimit` set low). Pass: the run log shows no auth errors, and the
   `google_credentials` row shows a new `last_refresh_at` after the run started.
2. **No real token on disk:** during the run, check the per-run rclone config in `/run/<slug>/rclone/`
   (0600, tmpfs). Pass: `token` holds only the per-run handle and an expired access token; no refresh token
   from Google, no client secret. Nothing under `/var/lib/<slug>` or `/var/log/<slug>` contains a
   Google token (`grep -r "1//0\|ya29\." ` finds nothing).
3. **Handle revoked:** after the run, a token request with the old handle gets `invalid_grant`.
4. **Rotation saved:** if Google returns a new refresh token, the sealed value in `google_credentials`
   changes and the next run still works.
5. **Scope:** with `scope = drive` the run lists, uploads (two-way) and deletes (two-way, goes to Drive
   trash) in My Drive only; nothing in Shared drives or shared-with-me.
6. **Failure paths:** revoke the app for the test account (myaccount.google.com → Security → Third-party
   apps). Pass: the next run ends `needs_reauth` for that user only. Then break the client secret on the
   test host only. Pass: one `high` app-wide alert, every Google user is skipped, other users keep syncing,
   and a worker restart with the right secret clears it.
- **If T-G2 fails:** switch to the tmpfs-config fallback (`token_mode = "tmpfs_config"`,
  `credential_type = "secret"`), re-run steps 1–6 against it, and record which mode passed. In that
  mode step 2 changes: the real refresh token and client secret are expected in the per-run tmpfs config
  only, and must be gone (shredded) once the run ends.
- **Pass = all six steps.** Only then add real users to `gdrive_users`.
