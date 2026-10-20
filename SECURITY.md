# Security notes (v0.1, for Walter's review)

## What is protected, and how

| Asset | Where it lives | Protection |
|---|---|---|
| Users' Microsoft refresh tokens | `ms_credentials.refresh_token_ct` | AES-256-GCM, random 96-bit nonce per value, AAD = `table:row:field` (a ciphertext can't be moved to another row). Never logged, never shown. |
| Users' NAS logins (Option A) | `nas_credentials.username_ct/password_ct` | Same scheme. Write-only from the user's page. Nobody can view them, admins included: there is no code path that decrypts them except the worker's mount step. |
| svc-sync and SMTP passwords | `settings` rows with `is_secret=1` | Same scheme. The GUI shows only "*** set" or "not set"; the field can be replaced, never read. |
| Data key | `/etc/<slug>/keys/data.key` (0400 root) → `systemd-creds encrypt` → `LoadCredentialEncrypted=` | Outside the DB and outside every backup. Escrow an offline copy (SPEC §7.3). Losing it only means users reconnect. |
| Entra app credential | certificate key in `/etc/<slug>/keys/entra-app.key` (same path to the services) | The certificate is preferred. A client secret is a fallback only. Both are capped at 24 months, and expiry is counted down on the admin and auditor pages. |
| GitHub deploy key | `/etc/<slug>/deploy/id_ed25519` (0400 root) | Read-only deploy key. The server pulls tagged releases and nothing pushes to it. |
| ACME DNS credential | `/etc/caddy/gcp-acme-sa.json` (0400 caddy) | Scoped to one TXT RRset in a separate ACME-only zone and GCP project (research §9.5), so the mail records in hotsprings.org can't be reached. |

## Token handling
- The app is a **confidential client**, single tenant, with delegated `Files.ReadWrite offline_access User.Read`
  only. It never requests `Files.ReadWrite.All`, `Sites.*`, or app-only permissions.
- **Broker mode (default; lab test T-A3 pending):** rclone never sees the real refresh token or the app
  credential.
  - Its per-run config holds a random handle that is valid only for that user and that run.
  - The handle is revoked as soon as the run ends.
  - The broker only accepts loopback callers, checks the handle against the user id, and serializes
    refreshes per user.
  - It stores the rotated refresh token re-encrypted, and returns only a short-lived access token.
- **Fallback mode (`tmpfs_config`):** the real refresh token and client secret sit in a 0600 file on tmpfs
  for the length of one run. The file is read back for rotation, then overwritten and unlinked in `finally`.
  Stale files are also swept when the worker starts and every night.
- A user changing their own password does **not** cut off a confidential-client token (research §3.1). An
  admin reset in the Entra or M365 admin center, or "Revoke sessions", does. Either way the next run shows
  `needs_reauth`.
- `invalid_grant`, `interaction_required`, and AADSTS700082 / 50173 / 50076 / 50078 → `needs_reauth`.
  AADSTS53000 / 53003 → `blocked_by_ca`. In both cases the user is paused and an issue is opened.

## NAS access
- All mounts go through `/usr/local/lib/<slug>/mount-helper` (root), which sudoers allows as the only root
  command.
  - It accepts only `mount|umount|verify <uuid>`.
  - It reads the UNC and credentials from 0600 files owned by the service user (`O_NOFOLLOW`, no symlinks).
  - It validates the UNC with a strict regex.
  - It mounts with a **fixed** option set: `vers=3.1.1,seal,nosuid,nodev,noexec,file_mode=0600,dir_mode=0700`.
- A wrong NAS password (mount error 13 / `STATUS_LOGON_FAILURE`) sets `nas_auth_failed` and pauses that user.
  There are **no retries**, to avoid NAS account lockout. The user resumes by re-entering the login.
- CIFS mounts are made inside the worker unit's private mount namespace and exist only while a run is active
  (Option A).

## Web
- Caddy terminates TLS with HSTS. The app binds to 127.0.0.1 only and trusts `X-Forwarded-*` only from
  127.0.0.1.
- Sessions are server-side (the cookie holds a random id; the DB stores its SHA-256), with `HttpOnly`,
  `Secure`, and `SameSite=Lax`. Sessions last at most 8 h.
- Roles come from Entra group claims and are re-checked against the group IDs in settings on **every**
  request. Group-overage tokens are refused.
- Every POST requires a CSRF token. Login and NAS-verify are limited to 5 per 15 min per IP / user.
- The CSP is `default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'`. There is no
  JavaScript at all.
- The sign-in flow uses MSAL's auth-code flow (PKCE, state, nonce). The flow state is encrypted in the DB
  for 10 min and bound to the browser with a short-lived cookie. The tenant id (`tid`) is checked.

## What Walter (Auditors group) can see
- **Shown:** each connected user and their state, last successful sync, last run result, and counts
  (copied, deleted, bytes, conflicts, errors). Also: open issues, worker heartbeat, Entra credential expiry
  countdown, TLS certificate expiry, disk free, the audit log (filters + CSV export), and the result of a
  live hash-chain verification.
- **Never shown:** file names, file contents, tokens, passwords, or rclone logs.
  - Preflight file lists are visible only to the user they belong to.
  - Issue summaries carry counts only.
- Every route under `/audit` is GET only. A test enforces this, and another test sends every non-GET route
  in the app with an auditor session and expects 403.
- **On the server:** run logs in `/var/log/<slug>/runs` are `0640 <slug>:adm` (setgid directory), so Walter
  can read them from a shell if his account is in `adm` (`LOG_READERS="walter"` at install). They contain
  file names, which is why they are not in the UI.

## Audit log
- The log is append-only: SQLite triggers abort UPDATE and DELETE.
- Each entry is hash-chained (SHA-256 over the previous hash plus the entry).
- The chain is verified nightly, and on every view of `/audit/log`. Entries are also written to syslog
  (`<slug>-audit`).
- Detail fields whose names look like secrets are redacted to `***` before they are hashed.

## Known gaps in v0.1 (also in OPEN-QUESTIONS.md)
- The worker can't use `NoNewPrivileges` because it needs sudo for the helper. A socket-activated root helper
  unit would allow it.
- The internal web→worker API token is derived from the data key with HMAC. It's fine on loopback, but it
  is not a separate secret.
- `requirements.lock` was compiled on Python 3.13 and should be regenerated on the 24.04 host (3.12).
- gitleaks runs only in the CI template, because the repo doesn't exist yet. Locally, a pattern-scan test
  stands in for it.
