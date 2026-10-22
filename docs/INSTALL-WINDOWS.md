# SpringSync 0.10.0: test install on Windows 11 Pro

For: Mark. Version: 0.10.0 (lab build). Plan: SPEC.md §11.5 (Windows host) and §11.6 (moving from Ubuntu).

> **What this is.** This guide sets up a **test** install on one Windows 11 Pro desktop. The first test
> syncs only **your own** account, in **Copy only** mode (cloud to NAS; nothing on the NAS or in the cloud is
> ever deleted).
>
> **Not tested on real Windows yet.** All the Windows parts were built and tested on Linux with stand-ins.
> The services, DPAPI, NAS sessions, the graceful rclone stop and the PowerShell scripts have **not run on
> a real Windows PC**. Section 9 is the lab tests that prove them. Expect to report a problem or two.
>
> Steps marked **[needs Mark's OK]** change something outside this PC (Entra, Google, DNS, the NAS). Do
> them only when you've decided to. Everything else stays on this PC.

---

## Contents
1. Before you start
2. Copy the zip over and check it
3. Antivirus and code signing
4. Run the installer
5. HTTPS: Caddy and DNS **[needs Mark's OK]**
6. Entra app registration **[needs Mark's OK]**
7. First sign-in and first-time settings
8. NAS test share on the new UNAS Pro **[needs Mark's OK]**
9. Lab tests, in order
10. Your first sync: your own account, Copy only
11. Checking services and logs
12. Update, rollback, uninstall
13. Windows Update
14. Google Drive (later) **[needs Mark's OK]**
15. Troubleshooting
16. What was and wasn't tested

---

## 1. Before you start

You need:

1. **The PC.** Windows 11 **Pro**, 64-bit, on wired LAN with a fixed IP (or a DHCP reservation), with TPM 2.0
   and an SSD. A UPS is recommended. Nobody uses this PC day to day.
2. **An administrator login** on that PC.
3. **BitLocker** turned on for drive C: (Settings > Privacy & security > Device encryption, or Control
   Panel > BitLocker). The installer warns you if it's off. There's no RAM-only scratch disk on Windows,
   so short-lived sync files sit on the disk for the length of a run.
4. **BIOS/UEFI setting:** "Restore on AC power loss" (it may be called "After power loss") = **Power On**, so the
   PC comes back on its own after a power cut. The installer can't check this. Set it in the firmware setup.
5. **The release files** (from Dex):
   - `SpringSync-0.10.0-windows.zip`
   - its SHA-256 (in `SpringSync-0.10.0-windows.zip.sha256`, and in the report)
   - `SHA256SUMS.txt` (lists the SHA-256 of every file inside the zip)
6. **Later, for HTTPS (section 5):** a `caddy.exe` built by `build-caddy-windows.sh`, plus the DNS pieces.

What the installer puts on the PC:

| Where | What |
|---|---|
| `C:\Program Files\SpringSync\releases\0.10.0\` | the app and its own private Python (official python.org files) |
| `C:\Program Files\SpringSync\current` | a link to the release that's running |
| `C:\Program Files\SpringSync\bin\rclone.exe` | rclone v1.75.2, the official file, unchanged |
| `C:\ProgramData\SpringSync\` | settings, database, keys, logs, backups. Only Administrators and the service account can open it |
| Windows services | `springsync-worker`, `springsync-web`, later `springsync-caddy` |
| Local account | `svc-springsync`: runs the services, can't sign in at the keyboard or over RDP |

---

## 2. Copy the zip over and check it

1. Copy the zip and its `.sha256` file to the PC, for example into `C:\Install\`. A USB stick or a network
   share are both fine.
2. Open **PowerShell as administrator**: Start, type `PowerShell`, right-click **Windows PowerShell**, then
   **Run as administrator**.
3. Check the SHA-256. The value it prints must match the `.sha256` file exactly:
   ```powershell
   cd C:\Install
   (Get-FileHash .\SpringSync-0.10.0-windows.zip -Algorithm SHA256).Hash.ToLower()
   Get-Content .\SpringSync-0.10.0-windows.zip.sha256
   ```
   If they differ, **stop**. Ask for a fresh copy.
4. Unblock the zip (Windows marks downloaded files), then extract it:
   ```powershell
   Unblock-File .\SpringSync-0.10.0-windows.zip
   Expand-Archive .\SpringSync-0.10.0-windows.zip -DestinationPath C:\Install
   cd C:\Install\SpringSync-0.10.0-windows
   ```
   The installer checks every file against `SHA256SUMS.txt` again before it changes anything, and unblocks
   only the files in this folder.

---

## 3. Antivirus and code signing

How the package stays easy for antivirus to trust:

- **No packed or self-extracting programs.** The only programs in the zip are official ones, unchanged:
  - the python.org **embeddable Python 3.13.17** zip
  - **pip 26.2.2** and the Python packages, as wheels from PyPI
  - the rclone.org **rclone v1.75.2** zip

  Each one is checked by SHA-256 against the pins in `app\deploy\windows\pins.psd1` and
  `app\requirements-windows.lock`. No PyInstaller, no Nuitka.
- **The scripts are plain, readable PowerShell.**
  - They never run encoded commands, never call `Invoke-Expression`, and download nothing.
  - They never touch Microsoft Defender settings or exclusions.
  - The services have no window, because a Windows service never has one. rclone runs without a console
    window for the same reason.
- **Not code-signed yet**, because there's no code-signing certificate. The scripts are ready to be signed
  later with `Set-AuthenticodeSignature`.

What you'll see:

1. **The execution policy.** Windows 11 blocks scripts by default. Allow them **for this one PowerShell
   window only**; this changes nothing permanently:
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```
2. **SmartScreen** ("Windows protected your PC") may pop up if you double-click something from the zip.
   Click **More info**, check the file name, then **Run anyway**. You don't need to double-click anything:
   everything here runs from the PowerShell window.
3. **Checking the files yourself.** Section 2 step 3 checks the zip. After you extract it, this re-checks
   any one file against `SHA256SUMS.txt`:
   ```powershell
   Get-FileHash .\vendor\rclone-v1.75.2-windows-amd64.zip -Algorithm SHA256
   Select-String rclone-v1.75.2 .\SHA256SUMS.txt
   ```
4. **Optional antivirus exclusion: only if your antivirus blocks or slows SpringSync.** Exclude **only**
   the program folder `C:\Program Files\SpringSync\`. The scripts never do this for you. Don't exclude
   `C:\ProgramData\SpringSync\`, the NAS, or the whole drive.
   - **ThreatDown (Malwarebytes) console:** Settings > Exclusions > Add > Folder >
     `C:\Program Files\SpringSync\` (apply it to this one endpoint or its policy).
   - **Microsoft Defender:** Windows Security > Virus & threat protection > Manage settings > Exclusions >
     Add an exclusion > Folder. If Intune manages Defender, Margaret adds it in the Intune antivirus policy.

---

## 4. Run the installer

The installer is safe to run again. It never overwrites your settings, keys or database.

1. In the administrator PowerShell window, inside `C:\Install\SpringSync-0.10.0-windows`:
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```
2. **Dry run first.** This shows what it would do and changes nothing:
   ```powershell
   .\install.ps1 -WhatIf
   ```
3. **Real run.** The first time, leave out Caddy (section 5) and the Entra IDs (section 6); you can add them
   later.
   - `-SetPowerSettings` sets sleep to never and turns hibernate off (it asks nothing else).
   - `-SetActiveHours` sets Windows Update active hours to 06:00-22:00. Leave it off if Intune manages updates.
   ```powershell
   .\install.ps1 -SetPowerSettings
   ```
   If you already have the Entra IDs, add them now:
   ```powershell
   .\install.ps1 -SetPowerSettings -TenantId <tenant GUID> -ClientId <client GUID> `
       -GroupAdmins <SpringSync-Admins group object ID>
   ```
4. Read the output. Green **OK** lines are fine; yellow **WARN** lines tell you what to fix. The installer:
   - **Pre-flight:** checks Windows 11 Pro, Administrator, BitLocker, TPM, sleep, hibernate, active hours and
     long paths. It turns on **long paths**, which deep OneDrive folders need.
   - **Package:** checks every file, then unblocks only the package files.
   - **Account:** creates **svc-springsync** with a long random password. The password is saved in
     `C:\ProgramData\SpringSync\escrow\`.
   - **Folders:** creates the program folders and locks `C:\ProgramData\SpringSync` down to Administrators
     and the service account.
   - **Programs:** installs the private Python, the app and rclone.
   - **Settings and keys:** writes `springsync.toml`, creates the encryption key (`data.key`) and the Entra
     certificate, and creates the database.
   - **Services:** registers them (they start automatically, restart up to 3 times on failure, and run with
     nobody signed in), starts them, and runs the self-check.
5. **Escrow (do this now).** In `C:\ProgramData\SpringSync\escrow\` you'll find:
   - `data.key`: the master encryption key
   - `entra-app.key`: the Entra certificate's private key
   - `svc-springsync-password.txt`

   Put all three in the IT password manager or the safe. Then delete them from the PC:
   ```powershell
   Remove-Item C:\ProgramData\SpringSync\escrow\* -Confirm
   ```
   **Never reset the svc-springsync password** (resetting is different from changing it). A reset makes the
   stored keys unreadable. The escrow copies are how you recover (section 15, "Lost keys").

The installer only turns HTTPS on in section 5, so until then nothing is reachable from other PCs. The web
service (`127.0.0.1:8080`) and the worker (`127.0.0.1:8081`) only listen on the PC itself.

---

## 5. HTTPS: Caddy and DNS **[needs Mark's OK]**

The spec allows HTTPS only (SPEC §8.1), and Microsoft and Google sign-in need an `https://` return
address. So the web page can only be used after this section. There's no "plain HTTP on the LAN" option
in this build. The OPEN-QUESTIONS file has a proposal for a short lab-only shortcut, for Reid and Walter to
decide.

1. **Build `caddy.exe`** on any Linux machine with internet access. On this PC, WSL works:
   `wsl --install -d Ubuntu`.
   ```bash
   bash build-caddy-windows.sh ~/caddy-win
   ```
   The script is in the zip at `app\deploy\windows\`. It uses the same pins as the Ubuntu install:
   Caddy 2.11.7, the googleclouddns plugin v1.1.0 with its checksum, and Go 1.27.3 with its checksum. It
   prints the SHA-256 of `caddy.exe`.
2. **[needs Mark's OK] DNS and the certificate account** (SPEC §8.1; lab test T-C1):
   - **Public DNS:** add a CNAME `_acme-challenge.sync.hotsprings.org` → `sync.<ACME zone>`. It lets Caddy
     prove the name to Let's Encrypt.
   - **GCP:** a separate ACME-only zone and project, and a service account that may only write TXT records
     there. Download its JSON key file.
   - **Internal DNS:** `sync.hotsprings.org` → this PC's LAN IP. For a test from this PC only, add
     `127.0.0.1 sync.hotsprings.org` to `C:\Windows\System32\drivers\etc\hosts`.
3. **Install Caddy** (copy `caddy.exe` and the JSON key file to the PC first):
   ```powershell
   .\install.ps1 -CaddyExe C:\Install\caddy.exe -AcmeEmail it@hotsprings.org `
       -GcpAcmeProject <project id> -AcmeZone <acme zone domain> `
       -GcpAcmeKeyFile C:\Install\gcp-acme-sa.json
   ```
   The installer:
   - checks `caddy.exe`: version 2.11.7, the googleclouddns module, the pinned plugin hash;
   - writes `C:\ProgramData\SpringSync\caddy\Caddyfile`;
   - registers `springsync-caddy`;
   - opens the firewall for TCP 443 and 80 **from the local subnet only**, and only for `caddy.exe`.

   Use `-FirewallRemoteAddress 10.0.0.0/8,192.168.0.0/16` to list the LAN/VPN ranges yourself.
   Delete the JSON key from `C:\Install` afterwards.
4. **First certificate from the Let's Encrypt staging CA** (T-C1):
   - Open `C:\ProgramData\SpringSync\caddy\Caddyfile` in Notepad (as administrator) and remove the `#` in
     front of the `acme_ca ...staging...` line.
   - Restart Caddy: `Restart-Service springsync-caddy`. Watch `C:\ProgramData\SpringSync\logs\caddy.log`.
   - When it works, put the `#` back and restart Caddy again for the real certificate.

---

## 6. Entra app registration **[needs Mark's OK]**

The steps are in the Entra admin center (entra.microsoft.com) > App registrations > New registration.

1. **Name:** `SpringSync`. **Supported account types:** this organization only (single tenant).
2. **Redirect URI:** platform **Web**, `https://sync.hotsprings.org/auth/callback`
3. **Certificates & secrets > Certificates > Upload certificate:**
   `C:\ProgramData\SpringSync\keys\entra-app.crt`. This is the public half only, so it's safe to copy.
   Note the expiry date; it's 24 months.
4. **API permissions** (delegated, Microsoft Graph): `Files.ReadWrite`, `User.Read`, `offline_access`.
   Nothing with `.All` and no application permissions (SPEC §4.1).
5. **Token configuration > Add groups claim:** Security groups, in the ID token.
6. **Groups:** create `SpringSync-Users`, `SpringSync-Admins` (you) and `SpringSync-Auditors` (Walter). Note
   each group's **Object ID**.
7. Margaret: exclude the app from sign-in-frequency Conditional Access policies (SPEC §4.1).
8. Put the IDs into the settings file. Open `C:\ProgramData\SpringSync\springsync.toml` in Notepad as
   administrator and fill in:
   - under `[entra]`: `tenant_id`, `client_id`, `group_admins` (and `group_users`, `group_auditors`)

   Then restart:
   ```powershell
   Restart-Service springsync-worker, springsync-web
   ```

---

## 7. First sign-in and first-time settings

1. On a LAN PC (or on this PC with the hosts entry), open **https://sync.hotsprings.org**.
2. Sign in with your Microsoft account. You're an admin because you're in `SpringSync-Admins`.
3. Open **Admin > Settings**. For the first test:
   - **Pilot:** Pilot-only mode **on**; pilot list = **only your own UPN**.
   - **Cloud:**
     - Enabled providers = OneDrive only (leave Google off for now).
     - Default direction = **Copy only** (`pull_copy`).
     - Backup target = **same_share** (`.springsync-archive` on your own NAS share). No second NAS is needed
       for this test.
   - **NAS:**
     - Option **B** is recommended on Windows (one NAS login for everyone; see section 8).
     - Address = the UNAS Pro's name, for example `unas-pro.hotsprings.local`.
     - Shared-drive template = `Home-{user}`.
     - svc-sync username and password.
     - Health-check share = `Sync-Health`. Press **Test**.
   - **Schedule:** leave the defaults (every 60 min during active hours).
   - **Alerts:** your email, plus the SMTP server if you want email alerts.
4. **Save.** Every change is recorded in the audit log.

---

## 8. NAS test share on the new UNAS Pro **[needs Mark's OK]**

Use the **new** UNAS Pro, and keep this test away from real company shares.

**Option B (recommended on Windows).** In UniFi Drive on the UNAS Pro:

1. Create a local NAS user `svc-sync` with a long random password. Put it in the password manager.
2. Create the shared drive `Home-<your user name>`, for example `Home-mark`. Give `svc-sync` Read/Write and
   yourself Read/Write. Turn on snapshots/versioning for it.
3. Create the shared drive `Sync-Health` (empty). Give `svc-sync` Read only.
4. Enter these in Admin > Settings > NAS (section 7) and press **Test**.

**Why Option B on Windows:** Windows allows only one NAS login per server name at a time (error 1219). With
Option A (each person's own login on the same NAS), SpringSync has to sync those users one after another.
It does that by itself, but it's slower. With Option B, everyone uses the one `svc-sync` login, so there's
no conflict.

**Later, for Mirror only:** create the `Sync-Archive` share on the backup NAS (UNAS #2) with its own login,
and switch Backup target to `backup_nas`. It must have a **different server name** from the user NAS if
its login is different.

The NAS password never appears on a command line, in a file or in a log. SpringSync keeps it encrypted in
the database and opens a NAS session for each run, with no drive letter.

---

## 9. Lab tests, in order

Do them in this order and write down the results. Details: SPEC §12.2.

| # | Test | What to do | Pass when |
|---|---|---|---|
| 1 | **T-W1** services | Reboot with nobody signed in; then pull the power plug (BIOS power-on) | All three services come back by themselves; `/healthz` OK; no broken runs |
| 2 | **T-W2** file names | `& "C:\Program Files\SpringSync\bin\rclone.exe" help flags local-encoding` (look at the default shown) and `odnas doctor` | doctor says `rclone_local_encoding OK`; names with `: * ? " < > \|` round-trip |
| 3 | **T-W4** NAS paths | Test buttons in Settings; one folder deeper than 260 characters; (Option A only) two users at once | Listing works; long path syncs; Option A users run one after another, no 1219 failures |
| 4 | **T-C1** certificate | Section 5 step 4 (staging, then real) | Certificate issued; the GCP account can't write any other record |
| 5 | **T-A3 / T-A4** OneDrive token broker | Your own account, Copy only (section 10), for a few days | Runs keep working past the 1-hour access-token life; no real token in `C:\ProgramData\SpringSync\run` |
| 6 | **T-W3** graceful stop | During a long run: `Restart-Service springsync-worker` | `worker.log` shows the stop request; the next run is normal (`--recover` if needed) |
| 7 | **T-M1** Mirror | Only after Sync-Archive exists on UNAS #2 | Moved files can be restored from UNAS #2 |
| 8 | **T-G1** Google project | Section 14 | A hotsprings.org test account connects; an outside account is refused |
| 9 | **T-G2** Google token refresh | **Required before ANY real Google user is connected** | as T-A3, for Google |
| 10 | **T-G3** Google specifics | The Google pilot account | Docs skipped/exported as documented; no data loss |

---

## 10. Your first sync: your own account, Copy only

1. Sign in at https://sync.hotsprings.org with your Microsoft account. That sign-in also connects your
   OneDrive. **My page** shows OneDrive "connected".
2. Under **Option A**, enter your NAS login under "NAS login". Under Option B there's nothing to enter.
3. Check that the direction shows **Copy only**: cloud to NAS, never deletes.
4. The worker runs a dry run first. **Admin > Users > you** shows what it would copy.
5. Approve. The first copy runs in the resync window (outside business hours).
6. Afterwards, check the files on `\\<unas-pro>\Home-<you>\`. Files that change in OneDrive are copied
   again; anything already on the NAS that gets replaced goes to `.springsync-archive\` first.

---

## 11. Checking services and logs

```powershell
Get-Service springsync-*
Invoke-RestMethod http://127.0.0.1:8080/healthz          # on this PC only
Get-Content C:\ProgramData\SpringSync\logs\worker.log -Tail 50
Get-Content C:\ProgramData\SpringSync\logs\web.log -Tail 50
Get-Content C:\ProgramData\SpringSync\logs\caddy.log -Tail 50
# the self-check the worker writes at every start:
Get-Content C:\ProgramData\SpringSync\logs\doctor-service.json
```

- **Run logs:** `C:\ProgramData\SpringSync\logs\runs\<user id>\<run>.json` (kept 30 days).
- **Audit copy:** `C:\ProgramData\SpringSync\logs\audit\audit-YYYY-MM.jsonl`.
- **Start/stop failures:** Event Viewer > Windows Logs > System (Service Control Manager) and
  Application (source = the service name).
- **Self-check from this window** (as Administrator; it can't open the keys, and that's expected):
  ```powershell
  $env:ODNAS_CONFIG = 'C:\ProgramData\SpringSync\springsync.toml'
  & 'C:\Program Files\SpringSync\current\python\python.exe' -m odnas doctor --http `
      --nas-host <unas-pro name>
  ```
- **Daily jobs:** the database backup (02:30) and maintenance (03:30, Central time) run inside the worker.
  Backups go to `C:\ProgramData\SpringSync\backups\`.

---

## 12. Update, rollback, uninstall

**Update.** Copy the new zip over and check its SHA-256 (section 2), then:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
$s = 'C:\Program Files\SpringSync\current\app\deploy\windows'
& "$s\update.ps1" -Zip C:\Install\SpringSync-<new>-windows.zip -Sha256 <hash>
```
The update script:
1. checks the zip and builds the new version next to the old one;
2. runs the smoke tests;
3. lets running syncs finish (up to 30 minutes);
4. backs up the database;
5. switches over and checks health for 60 seconds.

If anything fails, it switches back by itself. It keeps the last 3 versions.

**Rollback** (go back one version by hand):
```powershell
$s = 'C:\Program Files\SpringSync\current\app\deploy\windows'
& "$s\rollback.ps1"
```
Add `-RestoreDb` only if Dex says a database change needs undoing. Database changes are add-only, so
normally it doesn't.

**Uninstall.** This removes the services, the firewall rule and the program files. It **keeps**
`C:\ProgramData\SpringSync` (database, keys, settings, logs), so a re-install continues where you left off.
```powershell
$s = 'C:\Program Files\SpringSync\current\app\deploy\windows'
Copy-Item "$s\uninstall.ps1", "$s\SpringSync.psm1" C:\Install\
& C:\Install\uninstall.ps1
```
- `-PurgeData` also deletes all data. It asks you to type `PURGE`.
- `-RemoveAccount` also deletes `svc-springsync`.
- Nothing on the NAS or in OneDrive/Google is touched, ever.

**Replace a secret** (for example after rotating the Google client secret). It asks for the value with a
hidden prompt:
```powershell
$s = 'C:\Program Files\SpringSync\current\app\deploy\windows'
& "$s\set-secret.ps1" -Name google-client.secret
```

---

## 13. Windows Update

This is a **proposal, not decided** (SPEC §11.5.1; Margaret owns Intune):

- Enroll the PC in Intune and give it its **own update ring**:
  - active hours cover the business day (for example 06:00-22:00);
  - quality updates get a short deferral and a deadline;
  - feature updates are approved by hand;
  - automatic restarts happen only in a weekly window, **Sunday 03:00-05:00 CT**. That's after the 02:30
    backup and the 03:30 maintenance.
- When Windows shuts down for a restart, SpringSync gets up to 150 seconds of warning:
  1. it stops starting new syncs;
  2. it asks rclone to stop cleanly;
  3. the next run repairs anything left half done (`--recover`).
- Without Intune, `install.ps1 -SetActiveHours` sets 06:00-22:00 locally. Intune settings override it.

---

## 14. Google Drive (later) **[needs Mark's OK]**

Leave Google off for the first test. When you're ready (T-G1, SPEC §4.3):

1. Create a Google Cloud project owned by the hotsprings.org organization, with an **Internal** consent
   screen. Turn on the Drive API.
2. Create an OAuth client of type **Web application** with the redirect URI
   `https://sync.hotsprings.org/auth/google/callback`.
3. In the Google Admin console > API controls, mark the app as **Trusted**.
4. Put the client ID in `springsync.toml` under `[google] client_id`, then hand over the secret:
   ```powershell
   $s = 'C:\Program Files\SpringSync\current\app\deploy\windows'
& "$s\set-secret.ps1" -Name google-client.secret
   ```
5. **Run T-G2 before any real Google user is connected.**

---

## 15. Troubleshooting

| Symptom | What to check |
|---|---|
| "running scripts is disabled on this system" | Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in this window first |
| "SHA-256 mismatch" | The copy is damaged or changed: get a fresh one. Don't edit files in the package |
| Antivirus blocks `rclone.exe` or `python.exe` | Check the hash (section 3). If it matches, add the folder exclusion in section 3 |
| A service won't start | Event Viewer > System; `worker.log` / `web.log`; `doctor-service.json` |
| "secret 'data.key' is waiting in keys\incoming" | The worker hasn't started yet as `svc-springsync`: `Start-Service springsync-worker` |
| **Lost keys:** "could not be decrypted with DPAPI" | The `svc-springsync` password was **reset**. Restore from escrow: `set-secret.ps1 -Name data.key -FromFile <escrow copy>` and `-Name entra-app.key -FromFile ...`. Users lose no data |
| NAS: "error 1219" | Option A with two logins on one server: they run one after another. If it persists, `Restart-Service springsync-worker`. Use Option B |
| NAS: "error 53" / unreachable | Name or IP of the NAS; firewall; `Test-NetConnection <nas> -Port 445` |
| NAS: "error 1326" | Wrong NAS user or password: re-enter it in Settings (Option B) or on My page (Option A) |
| Backup NAS: "different server name" | The backup NAS uses another login on the same server name as the user NAS. Give it its own name or IP |
| Page not reachable from another PC | Caddy installed (section 5)? Firewall rule `SpringSync-HTTPS`? Internal DNS name? |
| Sign-in loops / fails | `tenant_id`, `client_id` and redirect URI exactly `https://sync.hotsprings.org/auth/callback`; certificate uploaded |
| Update stopped at "drain timed out" | Syncs were still running after 30 minutes; nothing changed. Try again later or add `-DrainTimeout 3600` |

**Moving from an Ubuntu test host later (SPEC §11.6):** turn the Ubuntu services off **first**. Then copy the
database and `springsync.toml`, put the escrowed keys in with `set-secret.ps1 -FromFile`, and start the
services:
- two-way users each need one approved resync;
- Copy only users need nothing;
- Mirror users get a new baseline that should show 0 deletes.

Keep Ubuntu as a cold standby for 2 weeks.

---

## 16. What was and wasn't tested

**Tested (on Linux, by Dex):**
- All the app tests still pass on Linux.
- New tests cover the Windows parts using stand-ins:
  - paths and UNC handling; the command lines given to rclone; file locking;
  - the Windows process stop logic; the NAS session handling, including the error 1219 rules;
  - DPAPI secret storage and hand-over; keys and certificate creation; the self-check;
  - the daily jobs inside the worker; the service start/stop logic.
- The Python package list for Windows installs completely with hash checking (cross-checked on Linux for
  Windows).
- A text check of every PowerShell script: brackets, plain ASCII, none of the forbidden commands.
- The official Python, pip and rclone files: SHA-256 checked.

**Not tested (needs this PC or a Windows runner):**
- The PowerShell scripts have never run; PowerShell and PSScriptAnalyzer weren't available to Dex. A
  GitHub Windows CI job is included; it runs once the code is pushed.
- The Windows services; DPAPI on the real account; NAS sessions (WNet) against the UNAS Pro.
- rclone's graceful stop from a service (T-W3); the Caddy Windows build (T-C1).
- Everything with Microsoft, Google, DNS and the NAS.

Report anything odd to Dex, with `worker.log`, `web.log` and `doctor-service.json`.
