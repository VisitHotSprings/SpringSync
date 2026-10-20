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

### Still open or ambiguous (v0.2)
1. **The "retryable" text doesn't guarantee recovery.** Against the real v1.75.2:
   - After a genuine lockout (`*.lst-err`), the next `--resilient` run reports
     `cannot find prior Path1 or Path2 listings` with the *retryable* line, yet it can never succeed without
     `--resync`.
   - The same happens if the listings are lost or corrupted (`empty prior Path1 listing`).
   - The worker isn't exposed to this after a lockout, because the user stays `critical`. In other cases it
     wastes 2 runs before the escalate-after-3 rule fires.
   - **Proposal:** treat "cannot find prior … listings" and "empty prior … listing" as an immediate
     `critical`. This needs a spec decision; v0.2 follows §9.4 literally.
2. **Lockout under `--resilient` isn't reproducible locally.** The integration test gets the real
   `Must run --resync` text by dropping `--resilient`. Lab test T-B* should capture a real lockout with our
   exact flags.
3. **Restore timing:** §9.1 confines the *initial* resync to `resync_hours`. I treat a safety-abort Restore
   as not initial: it runs at the next slot inside active hours, still one resync at a time. Approved
   resyncs after a `critical` result keep the v0.1 behaviour and do wait for `resync_hours`. Confirm this is
   intended.
4. **Who sees the delta list?** §9.4 puts the list "on the admin page". The list contains file names, which
   §6.5 and research §1.4 otherwise keep from everyone but the user. v0.2 shows it to IT admins only, never
   to auditors. **Walter should confirm** that IT admins may see file names in this case.
5. **How Restore and Accept deletes work:**
   - Both require the delta list first.
   - Accept deletes requires typing the UPN.
   - The decision is one-shot. If the `--force` run fails or the NAS is down, the user stays in
     `safety_abort` and a new decision is needed.
   - The `--force` run has no time limit, because an interrupted run would need a second approval.
   - Confirm these are the wanted semantics.
6. **`users.state` and `sync_runs.result`** value lists in SPEC §5 don't yet include `safety_abort`,
   `critical_retryable` or `usage` (§9.4 introduces them). `sync_runs.kind` also gains `delta` and `force`.
   The spec table should be updated to match.
7. **`caddy build-info` output format** (tab-separated `dep <module> <version> <h1>`) is assumed, not tested.
   No Caddy binary here; part of T-C1. `go version -m` is printed alongside it as a cross-check.
8. **Worker hardening:** `NoNewPrivileges` stays off, because the worker needs sudo for the helper. A
   socket-activated helper would allow it.
9. **The internal web→worker token** is derived from the data key with HMAC. It's fine on loopback, but it
   is not a separate secret.
10. **Option B "mounted persistently"** is per-run idempotent mounts, as accepted in v0.2. A boot-time mount
    unit is an allowed refinement and not built.
