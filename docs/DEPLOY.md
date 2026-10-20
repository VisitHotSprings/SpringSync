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
