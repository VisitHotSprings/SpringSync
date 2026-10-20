# Open questions and blockers (v0.1)

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
- **Caddy plugin pin:**
  - The SPEC table gives `caddy-dns/googleclouddns@6fcdbd98a856` "(v1.1.0 + libdns v1.2.0)".
  - §14.12 says "v1.1.0".
  - The research says the module was bumped to libdns v1.2.0 after v1.1.0.
  - `install.sh` pins the full commit `6fcdbd98a8565df50ff40ff53411dc6c8d97dcd9`. Confirm that is intended,
    or choose the v1.1.0 tag (T-C1).
- **Go toolchain checksum:** SPEC pins Go 1.27.3 for xcaddy but gives no SHA-256. `install.sh` has a
  `GO_SHA256` placeholder and **refuses to build Caddy** until it is filled in from go.dev/dl.
- **Exit 7 vs. `--max-delete`:** with rclone v1.75.2 a tripped `--max-delete` under `--resilient` exits 1,
  not 7. We treat it as critical by matching the log text. The integration test pins this behavior.
- **A missing check file blocks even the dry-run** (exit 7). Onboarding now touches `.springsync-check` on
  both sides before the dry-run.
- **"Outside business hours"** for the initial resync isn't defined. It is the `resync_hours` setting,
  default 18:00–07:00 CT.
- **Single `nonce` column** in the SPEC §5 tables would reuse a GCM nonce across username and password. Each
  value carries its own nonce instead.
- **Mount-helper verbs:** §7.4 lists `mount|umount`, while §4.2 needs a verify step, so a third verb,
  `verify`, was added.
- **Option B "mounted persistently":** implemented as per-run idempotent mounts that are left mounted. A
  boot-time mount unit may be preferable.
- **SQLAlchemy/Alembic** (SPEC §3) were replaced by stdlib sqlite3 with numbered migrations
  (`odnas db-upgrade` in place of `springsync db upgrade`).
- **Backups to the NAS `IT-Backups` share** (SPEC §10.4) are not implemented. Backups stay local in
  `/var/backups/<slug>`.
- **Worker hardening:** `NoNewPrivileges` is off because the worker needs sudo. A socket-activated helper
  would allow it.
- **requirements.lock** was compiled on Python 3.13 and must be regenerated on the 24.04 host (3.12).
