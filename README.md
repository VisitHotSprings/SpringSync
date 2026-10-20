# SpringSync (working name), v0.1 lab build

SpringSync is a small service for the Visit Hot Springs LAN. It keeps each person's **OneDrive for Business**
and their **UniFi NAS home folder** in two-way sync, using one `rclone bisync` job per user.

- **Users** connect themselves on an internal page: they sign in with Microsoft, then enter their NAS login once.
  Each person has their own status page.
- **Admins** (Mark) change settings and run user actions in a GUI: NAS address, schedule, alerts, pilot list,
  Entra groups, pause/resume, approve resync, offboard.
- **Auditors** (Walter) get a strictly read-only status page and audit-log view.

> **Status: lab-only v0.1.** Nothing has been deployed. The build spec is `../SPEC.md` (source of truth) and the
> background research is `../research.md`. `OPEN-QUESTIONS.md` lists everything that blocks a pilot.

The product name is not final. The Python package is deliberately neutral (`odnas`). The display name and the
*slug* (which drives paths, unit names, and the check/archive file names) are config values:
`product_name` / `slug`, defaulting to `SpringSync` / `springsync`.

## Architecture

```mermaid
flowchart LR
  subgraph LAN["VHS LAN / VPN only"]
    B["Browser (user / Mark / Walter)"]
  end
  subgraph Server["Ubuntu 24.04 sync server"]
    C["Caddy v2.11.7 + googleclouddns<br/>TLS via DNS-01 (CNAME-delegated ACME zone)"]
    W["web (FastAPI) 127.0.0.1:8080<br/>/me /admin /audit"]
    K["worker 127.0.0.1:8081<br/>scheduler (60 s tick, max 2 jobs)<br/>token broker + internal API"]
    DB[("SQLite WAL<br/>AES-256-GCM secrets<br/>hash-chained audit log")]
    H["mount-helper (root, via sudo)<br/>mount|umount|verify &lt;uuid&gt;"]
    R["rclone v1.75.2 bisync<br/>per user, per-run tmpfs config"]
    KEY["/etc/springsync/keys/data.key<br/>(systemd LoadCredentialEncrypted)"]
  end
  MS["Microsoft Entra + Graph / OneDrive"]
  NAS1["UNAS #1<br/>Personal-Drive (Option A) or Home-&lt;user&gt; (Option B)<br/>snapshots"]
  NAS2["UNAS #2 (UniFi backup task + snapshots)"]
  GCP["GCP ACME-only DNS zone"]

  B -- HTTPS 443 --> C --> W
  W <--> DB
  K <--> DB
  KEY -.-> W
  KEY -.-> K
  W -- "NAS verify (loopback, internal token)" --> K
  K -- "sudo -n" --> H -- "CIFS vers=3.1.1,seal" --> NAS1
  K --> R
  R -- "token_url = broker/&lt;id&gt;/token<br/>(per-run handle)" --> K
  K -- "MSAL refresh (certificate)" --> MS
  R -- "Graph Files.ReadWrite" --> MS
  R <-- "local path /srv/springsync/mnt/&lt;id&gt;" --> NAS1
  NAS1 -- scheduled --> NAS2
  C -- "DNS-01 TXT" --> GCP
```

**How a sync run works** (SPEC §9.2, `odnas/runner.py`):
1. The scheduler picks the user (stagger slot, active hours, concurrency limit, one run per user).
2. The NAS share is mounted through the helper. With Option A this uses the user's own login, decrypted
   only for this run and written to a 0600 file on tmpfs.
3. A per-run rclone config is written to `/run/springsync/rclone/<id>.conf`. In **broker mode** it holds only
   a random per-run handle and `token_url` pointing at the local broker. The broker uses MSAL with the
   certificate to swap the real refresh token for a short-lived access token, and stores the rotated
   refresh token re-encrypted. This is pending lab test T-A3. The **tmpfs_config fallback** puts the real
   refresh token plus the client secret in the tmpfs config and reads the rotated token back afterwards.
4. `rclone bisync` runs with the SPEC §9.3 flag set (including `--color NEVER`) and a worker-enforced time
   limit (25 min for incremental runs). When the limit is hit the worker sends SIGINT once, waits 120 s, then SIGKILL.
5. The worker classifies the run from the exit code **plus the exact v1.75.2 log text** (SPEC v0.2 §9.4),
   updates state and issues, unmounts, and shreds the temp files. Steps 2–5 always clean up in `finally`.

**Classifier (SPEC v0.2 §9.4, `odnas/classify.py`)**, checked in this order:

| Check | Result |
|---|---|
| broker / log auth error | `auth` → `needs_reauth` or `blocked_by_ca` |
| worker time limit hit | `timeout` (continues at the next slot) |
| exit 0 + `Bisync successful` | `ok` |
| `object="Safety abort"` + `too many deletes (>N%, X of Y) on PathN …`, or `Safety abort: all files were changed …` (expected with exit 1) | **`safety_abort`** |
| exit 7 + `Bisync aborted. Must run --resync to recover.` | `critical` (lockout) |
| exit 7 + `Bisync aborted. Error is retryable without --resync due to --resilient mode.` | `critical_retryable`: the next run proceeds, but it escalates to `critical` (pause + alert) immediately on `Access test failed:`, on the same error twice in a row, or on the 3rd in a row (SPEC v0.3) |
| exit 7 with neither line, or exit code and log text disagree | `critical` (fail safe, warning logged) |
| exit 2 | `usage` (bug: user paused, high issue) |
| exit 1, 3, 4, 5, 6, 8, 10, or killed by a signal | `retryable` |

**User lifecycle:**
- **Onboarding:** `onboarding` → Microsoft connect → NAS login verified → preflight filename scan →
  `--resync --dry-run` → admin clicks **Approve initial sync** → real `--resync` (one user at a time, inside
  the resync window) → `active`.
- **Failure states:**
  - `needs_reauth` / `blocked_by_ca` (from the broker or the rclone log);
  - `nas_auth_failed` (paused, no retries);
  - `critical` (exit-7 lockout; needs **Approve resync**);
  - `safety_abort` (see below);
  - `paused` (admin action or rclone usage error).
- **Safety abort** (a tripped `--max-delete` or "all files changed"): nothing was synced, and a plain run
  would trip again every slot, so the user is paused.
  1. The worker runs a read-only `bisync --dry-run --force` to build a delta list. The list holds file names,
     so it is kept in a 0600 file and shown on the IT-admin page only.
  2. The admin then chooses one of two actions, both audited, single use, with the normal run-time limit
     (SPEC v0.3 §9.4.1):
     - **Restore:** one `--resync --resync-mode newer` at the next slot, or with **Run tonight** in
       `resync_hours`. It copies the deleted files back.
     - **Accept deletes:** the admin approves the exact delete count and types the UPN to confirm.
       - The approval expires after 24 h.
       - Just before the run, a dry-run recounts the deletes. A different count cancels the run, voids the
         approval and alerts the admin.
       - If the `--force` run times out or fails, the user stays paused, and it never re-runs on its own.
  3. Success sets the user back to `active`.
  4. Walter sees the counts and decision state, but not the list or the buttons. The list has its own
     IT-admin-only page, and every view of it is audited (§14.13, pending Walter's sign-off).
- **Offboarding:** admin clicks **Offboard** → optional final sync → crypto-erase (credential rows deleted with
  `secure_delete`, then `VACUUM`) → workdir removed → `removed`.

## Repository layout

```
odnas/                 the app (SPEC "app/"): web, worker, broker, models, migrations
  config.py            bootstrap config (TOML + ODNAS_* env), no secrets
  crypto.py            AES-256-GCM keyring, key_id rotation
  db.py                SQLite schema + expand-only migrations, audit hash chain
  settings_store.py    GUI-editable settings (validated, audited, secrets write-only)
  entra.py             MSAL wrapper behind EntraClient + AADSTS classifier
  tokens.py            TokenStrategy: BrokerTokenStrategy (default) / TmpfsConfigStrategy (fallback)
  nas.py               NasAccessProvider: PersonalDriveProvider (A) / SharedHomeProvider (B)
  bisync.py            exact rclone command builders
  classify.py          exit-code + JSON-log classification
  preflight.py         blocked names, 400-char paths, 250 GB, case collisions, >100k items
  scheduler.py         stagger, windows, weekly check, throttle governor
  runner.py            one job end to end
  worker.py            tick loop, offboarding, broker/internal HTTP app
  maint.py, rekey.py   nightly maintenance, backups, key rotation
  web/                 FastAPI app + Jinja templates (no JavaScript)
deploy/
  install.sh update.sh rollback.sh RESTORE.md
  systemd/  caddy/  sudoers/  mount-helper  filters/bisync-filters.txt.tmpl  config/springsync.toml.example
tests/                 pytest (unit, web/security, real-rclone integration)
requirements.in / requirements.lock (pip --require-hashes)
```

## Run the tests

```bash
python3 -m venv .venv && .venv/bin/pip install --require-hashes --no-deps -r requirements.lock
.venv/bin/python -m pytest -q            # everything
.venv/bin/python -m pytest -q --smoke    # the subset update.sh runs against a new release
ODNAS_TEST_RCLONE=/path/to/rclone-v1.75.2 .venv/bin/python -m pytest -q -m integration
```
MSAL, Graph, the NAS, and the mount helper are all faked in the tests. No test makes a network call.
The integration tests run the **real** rclone v1.75.2 between two local directories using our exact flags.
They are skipped if no rclone binary is found.

## Setup

### Lab / development
1. Copy `.env.example` to `.env`, then export its values. Put a 32-byte `data.key` (`head -c32 /dev/urandom`)
   in `ODNAS_KEYS_DIR`.
2. Run `python -m odnas db-upgrade`, then `python -m odnas check-config`.
3. Run `python -m odnas web` and `python -m odnas worker`. Real sign-in needs a lab Entra app registration
   (see OPEN-QUESTIONS).

### Server (Ubuntu 24.04), after the SPEC §11.1 prerequisites
```bash
sudo REPO_URL=git@github.com:<OWNER>/<REPO>.git TENANT_ID=... CLIENT_ID=... \
     GROUP_USERS=... GROUP_ADMINS=... GROUP_AUDITORS=... \
     SYNC_HOST=sync.hotsprings.org GCP_ACME_PROJECT=... ACME_ZONE=... \
     LAN_CIDRS="10.0.0.0/16" ADMIN_CIDR="10.0.10.0/24" LOG_READERS="walter" \
     ./deploy/install.sh --version v0.3.0           # add --dry-run to see the plan first
```
`install.sh` is idempotent: every step checks state first, and it never overwrites keys, the DB, or settings.
It handles:
- packages and unattended security upgrades;
- users and directories;
- the pinned, checksum-verified rclone;
- a Caddy custom build with xcaddy and the pinned plugin;
- the app release and venv;
- keys and `systemd-creds`;
- config;
- the DB;
- sudoers and the mount helper;
- ufw;
- systemd units that start at boot and restart on failure;
- a smoke test.

Updates: `sudo /opt/springsync/current/deploy/update.sh vX.Y.Z`. Rollback:
`sudo /opt/springsync/current/deploy/rollback.sh [--restore-db]`. See `docs/DEPLOY.md`.

## Configuration reference

### Bootstrap (`/etc/<slug>/<slug>.toml`, or `ODNAS_<KEY>` env vars; never secrets)
| Key | Default | Notes |
|---|---|---|
| `product_name` / `slug` / `org_name` | `SpringSync` / `springsync` / `VisitHotSprings` | slug drives paths, units, `.<slug>-check`, `.<slug>-archive`; User-Agent `NONISV|<org>|<product>/<major.minor>` (e.g. `SpringSync/0.2`) |
| `base_url` | `https://sync.hotsprings.org` | redirect URI = base_url + `/auth/callback` |
| `web_host:web_port`, `broker_host:broker_port` | `127.0.0.1:8080`, `127.0.0.1:8081` | non-loopback is refused |
| `tenant_id`, `client_id` | – | GUIDs; `common`/`organizations` refused |
| `credential_type` | `certificate` | or `secret` (fallback) |
| `cert_path` | – | public cert; its expiry drives the admin countdown |
| `token_mode` | `broker` | `tmpfs_config` fallback (requires `secret`) |
| `allowed_upn_domain` | – | e.g. `hotsprings.org` |
| `group_users` / `group_admins` / `group_auditors` | – | bootstrap only; the GUI overrides them |
| `db_path`, `state_dir`, `log_dir`, `runtime_dir`, `mount_root`, `keys_dir`, `etc_dir` | derived from slug | see SPEC §8.2 |
| `rclone_bin` | `/usr/local/bin/rclone` | |
| `nas_host`, `nas_share` | `unas.hotsprings.local`, `Personal-Drive` | bootstrap defaults for the GUI |

### Secrets (files only; `$CREDENTIALS_DIRECTORY` via `LoadCredentialEncrypted=`)
| Name | Purpose |
|---|---|
| `data.key` | 32-byte AES-256-GCM data key (`data.key.old` is optional during rotation) |
| `entra-app.key` | Entra app certificate private key |
| `entra-client-secret` | fallback client secret (secret mode / tmpfs_config only) |

### GUI settings (DB `settings` table; admin page; every change audited)
| Group | Key | Default | Secret |
|---|---|---|---|
| NAS | `nas_option` (A/B), `nas_host`, `nas_share`, `nas_shared_template`, `nas_svc_username`, `nas_domain` | `A`, `unas.hotsprings.local`, `Personal-Drive`, `Home-{user}`, `svc-sync`, – | |
| NAS | `nas_svc_password` (Option B) | – | yes |
| Schedule | `default_interval_min`, `active_hours`, `max_concurrent`, `run_time_limit_min`, `resync_bwlimit`, `resync_hours`, `stale_hours` | `30`, always, `2`, `25`, –, `18:00-07:00`, `24` | |
| Safety | `default_max_delete_pct`, `check_weekday`, `check_time` | `10`, `6` (Sun), `03:00` | |
| Alerts | `alert_recipients`, `smtp_host`, `smtp_port`, `smtp_starttls`, `smtp_username` | –, –, `587`, on, – | |
| Alerts | `smtp_password` | – | yes |
| Pilot | `pilot_only`, `pilot_list` | on, empty (nobody) | |
| Entra | `group_users`, `group_admins`, `group_auditors`, `entra_credential_expires_on` | –, –, –, – (auto-read from the certificate when set) | |

Secret fields can only be replaced, never viewed. **Email is not sent in v0.1:** alerts appear as issues on the
admin and auditor pages. `odnas.notify.Notifier` is the plug-in point once the mail path is decided.

## CLI
`odnas web | worker [drain|undrain] | maint | backup [--tag] | db-upgrade | check-config | verify-audit | rekey | notify --unit X`
