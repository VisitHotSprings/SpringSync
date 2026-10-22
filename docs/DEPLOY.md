# Deploy model

## Read-only deploy-key pull
- The code lives in a private GitHub repo. The org/account doesn't exist yet (OPEN).
- On the repo, add a **deploy key** with *Allow write access* **unchecked**. Its private half is
  `/etc/<slug>/deploy/id_ed25519` (0400 root) on the server and nowhere else.
- The server **pulls**. `install.sh` and `update.sh` run `git clone --depth 1 --branch vX.Y.Z` with
  `GIT_SSH_COMMAND="ssh -i /etc/<slug>/deploy/id_ed25519 -o IdentitiesOnly=yes"`. No CI job or person
  pushes to the server, and the server holds no credential that can write to GitHub.
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
- Rotating the secret: create the new secret in the console, re-encrypt the credential file, restart the
  worker (this also clears the app-wide `google_app_credential` stop), confirm a Google run, then delete
  the old secret in the console (T-G1 confirms the flow).
- Volume/cost: new projects have a 1 TB/day egress threshold (§14.27). Seed large My Drives over several
  nights with `resync_bwlimit`.
