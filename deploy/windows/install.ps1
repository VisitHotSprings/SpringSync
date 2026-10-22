<#
.SYNOPSIS
    Installs SpringSync on a Windows 11 Pro PC (SPEC 11.5). Run as Administrator. Safe to run again.

.DESCRIPTION
    1. Pre-flight: Windows 11 Pro 64-bit, Administrator, BitLocker/TPM, sleep/hibernate, active hours,
       long paths. Reports problems; changes power settings / active hours only when asked to.
    2. Verifies every file of the package against SHA256SUMS.txt and the pins, then unblocks ONLY those files.
    3. Creates the low-privilege account svc-springsync (log on as a service; no interactive or RDP logon).
    4. Creates C:\Program Files\SpringSync and C:\ProgramData\SpringSync with locked-down ACLs.
    5. Builds the release from the official Python embeddable zip and hash-locked wheels; installs the
       official rclone.exe; optionally installs a verified caddy.exe.
    6. Writes springsync.toml and the Caddyfile once (never overwrites), creates keys, upgrades the DB.
    7. Registers the services springsync-worker, springsync-web, springsync-caddy (auto start, restart on
       failure x3, run with nobody signed in) and the firewall rule for 443/80 (Caddy only).
    8. Starts everything and runs the self-check (odnas doctor).
    Nothing here touches Microsoft Defender settings, downloads anything, or runs encoded commands.

.EXAMPLE
    .\install.ps1 -TenantId <guid> -ClientId <guid> -WhatIf
    .\install.ps1 -TenantId <guid> -ClientId <guid>
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$BaseUrl = 'https://sync.hotsprings.org',
    [string]$TenantId = '',
    [string]$ClientId = '',
    [string]$AllowedUpnDomain = 'hotsprings.org',
    [string]$GroupUsers = '',
    [string]$GroupAdmins = '',
    [string]$GroupAuditors = '',
    [string]$GoogleClientId = '',
    [string]$NasHost = 'unas.hotsprings.local',
    [string]$NasShare = 'Personal-Drive',
    # Caddy (HTTPS). Leave -CaddyExe empty on a first install if the DNS / GCP pieces are not ready yet:
    # then nothing listens on the network and the firewall rule is not created.
    [string]$CaddyExe = '',
    [string]$AcmeEmail = '',
    [string]$GcpAcmeProject = '',
    [string]$AcmeZone = '',
    [string]$GcpAcmeKeyFile = '',
    [string]$FirewallRemoteAddress = 'LocalSubnet',
    [securestring]$ServiceAccountPassword,
    [switch]$SetPowerSettings,
    [switch]$SetActiveHours,
    [switch]$AllowOtherEdition,
    [switch]$SkipServiceStart
)

$ErrorActionPreference = 'Stop'
$PackageRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $PackageRoot 'app\deploy\windows\SpringSync.psm1') -Force
$P = Get-SSPaths

function Invoke-Change {
    param([string]$What, [scriptblock]$Action)
    if ($PSCmdlet.ShouldProcess($What)) { & $Action } else { Write-Info "WHATIF: $What" }
}

# ---------------------------------------------------------------------------------------------------
Write-Step '1. Pre-flight checks'
Assert-Administrator
Write-Ok 'running as Administrator'
$os = Get-CimInstance Win32_OperatingSystem
if (-not [Environment]::Is64BitOperatingSystem) { throw 'Windows must be 64-bit.' }
if ($os.Caption -match 'Windows 11 Pro') { Write-Ok $os.Caption }
elseif ($AllowOtherEdition) { Write-Warn2 "$($os.Caption) (not Windows 11 Pro; continuing because of -AllowOtherEdition)" }
else { throw "This is '$($os.Caption)'. SPEC 11.5 targets Windows 11 Pro (use -AllowOtherEdition to override)." }
if ($PSVersionTable.PSVersion -lt [version]'5.1') { throw 'PowerShell 5.1 or newer is required.' }

try {
    $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    if ($bl.ProtectionStatus -eq 'On') { Write-Ok "BitLocker is on for $env:SystemDrive" }
    else { Write-Warn2 "BitLocker is OFF for $env:SystemDrive. The database holds encrypted tokens; turn BitLocker on (SPEC 11.5)." }
} catch { Write-Warn2 'Could not read the BitLocker status.' }
try {
    $tpm = Get-Tpm -ErrorAction Stop
    if ($tpm.TpmPresent -and $tpm.TpmReady) { Write-Ok 'TPM present and ready' } else { Write-Warn2 'TPM not ready.' }
} catch { Write-Warn2 'Could not read the TPM status.' }

# Sleep / hibernate: a server must not sleep. powercfg prints the AC index first, then DC.
$standby = (& powercfg.exe /query SCHEME_CURRENT SUB_SLEEP STANDBYIDLE) -join "`n"
$acStandby = [regex]::Matches($standby, '0x[0-9a-fA-F]{8}') | Select-Object -Last 2 | Select-Object -First 1
$hib = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name HibernateEnabled -ErrorAction SilentlyContinue).HibernateEnabled
$sleepOk = ($acStandby -and ([Convert]::ToInt32($acStandby.Value, 16) -eq 0))
if ($sleepOk) { Write-Ok 'sleep on AC power: never' } else { Write-Warn2 'this PC can go to sleep on AC power' }
if ($hib -eq 0) { Write-Ok 'hibernate: off' } else { Write-Warn2 'hibernate is on' }
if (-not ($sleepOk -and $hib -eq 0)) {
    if ($SetPowerSettings) {
        Invoke-Change 'set sleep and hibernate to never / off' {
            & powercfg.exe /change standby-timeout-ac 0
            & powercfg.exe /change hibernate-timeout-ac 0
            & powercfg.exe /hibernate off
        }
        Write-Ok 'power settings changed (sleep never, hibernate off)'
    } else {
        Write-Info 'Re-run with -SetPowerSettings to set: sleep never, hibernate off. Or run:'
        Write-Info '  powercfg /change standby-timeout-ac 0 ; powercfg /change hibernate-timeout-ac 0 ; powercfg /hibernate off'
    }
}
Write-Info 'REMINDER: in the PC firmware (BIOS/UEFI) set "Restore on AC power loss" = Power On. This script cannot check it.'

$pol = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update' -ErrorAction SilentlyContinue
$ux = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -ErrorAction SilentlyContinue
if ($pol -and ($pol.PSObject.Properties.Name -contains 'ActiveHoursStart')) {
    Write-Ok "active hours are managed by Intune: $($pol.ActiveHoursStart):00-$($pol.ActiveHoursEnd):00"
} elseif ($ux -and ($ux.PSObject.Properties.Name -contains 'ActiveHoursStart')) {
    Write-Info "active hours (local setting): $($ux.ActiveHoursStart):00-$($ux.ActiveHoursEnd):00"
} else { Write-Warn2 'active hours not set' }
if ($SetActiveHours) {
    Invoke-Change 'set Windows Update active hours 06:00-22:00 (Intune policy wins if present)' {
        $k = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
        New-Item -Path $k -Force | Out-Null
        Set-ItemProperty -Path $k -Name ActiveHoursStart -Value 6 -Type DWord
        Set-ItemProperty -Path $k -Name ActiveHoursEnd -Value 22 -Type DWord
        Set-ItemProperty -Path $k -Name SmartActiveHoursState -Value 0 -Type DWord
    }
} else { Write-Info 'Proposed (not decided): Intune update ring, active hours 06-22, restart window Sun 03:00-05:00 CT.' }

$lp = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name LongPathsEnabled -ErrorAction SilentlyContinue).LongPathsEnabled
if ($lp -eq 1) { Write-Ok 'long paths enabled' } else {
    Invoke-Change 'enable long paths (LongPathsEnabled=1, needed for deep OneDrive folders)' {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name LongPathsEnabled -Value 1 -Type DWord
    }
}

# ---------------------------------------------------------------------------------------------------
Write-Step '2. Verify the package'
Test-PackageSums -PackageRoot $PackageRoot
$Pins = Get-Pins -PackageRoot $PackageRoot
$Version = Get-PackageVersion -PackageRoot $PackageRoot
Write-Ok "SpringSync $Version"
Invoke-Change "unblock the files of this package ($PackageRoot)" { Unblock-PackageFiles -PackageRoot $PackageRoot }

# ---------------------------------------------------------------------------------------------------
Write-Step "3. Service account $ServiceAccount"
function New-RandomPassword {
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_=+.'.ToCharArray()
    $bytes = New-Object byte[] 28
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
}
function Grant-ServiceRights {
    # secedit: add the account to "Log on as a service" and to "Deny log on locally" / "Deny log on through RDP".
    param([string]$Sid)
    $tmp = Join-Path $env:TEMP ('springsync-secedit-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        & secedit.exe /export /cfg "$tmp\cur.inf" /areas USER_RIGHTS | Out-Null
        $cur = Get-Content "$tmp\cur.inf"
        $lines = @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1', '[Privilege Rights]')
        foreach ($right in 'SeServiceLogonRight', 'SeDenyInteractiveLogonRight', 'SeDenyRemoteInteractiveLogonRight') {
            $existing = ($cur | Where-Object { $_ -match "^$right\s*=" }) -replace "^$right\s*=\s*", ''
            $list = @()
            if ($existing) { $list = @($existing -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
            if ($list -notcontains "*$Sid") { $list += "*$Sid" }
            $lines += "$right = " + ($list -join ',')
        }
        Set-Content -Path "$tmp\new.inf" -Value $lines -Encoding Unicode
        & secedit.exe /configure /db "$tmp\new.sdb" /cfg "$tmp\new.inf" /areas USER_RIGHTS | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "secedit failed ($LASTEXITCODE)" }
    } finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}
$user = Get-LocalUser -Name $ServiceAccount -ErrorAction SilentlyContinue
$generated = $false
if (-not $user) {
    if (-not $ServiceAccountPassword) {
        $plain = New-RandomPassword
        # Build the SecureString character by character (no ConvertTo-SecureString -AsPlainText).
        $ServiceAccountPassword = New-Object System.Security.SecureString
        foreach ($c in $plain.ToCharArray()) { $ServiceAccountPassword.AppendChar($c) }
        $ServiceAccountPassword.MakeReadOnly()
        $generated = $true
    }
    Invoke-Change "create local account $ServiceAccount" {
        New-LocalUser -Name $ServiceAccount -Password $ServiceAccountPassword -PasswordNeverExpires `
            -UserMayNotChangePassword -AccountNeverExpires -FullName 'SpringSync service' `
            -Description 'Runs the SpringSync services. No interactive or RDP logon.' | Out-Null
    }
    $user = Get-LocalUser -Name $ServiceAccount -ErrorAction SilentlyContinue
} else { Write-Ok "$ServiceAccount exists (password unchanged)" }
if ($user) { Invoke-Change "grant service logon / deny interactive + RDP logon to $ServiceAccount" { Grant-ServiceRights -Sid $user.SID.Value } }

# ---------------------------------------------------------------------------------------------------
Write-Step '4. Folders and permissions'
Invoke-Change "create $($P.AppRoot) and $($P.DataRoot)" {
    foreach ($d in $P.Bin, $P.Releases) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
    foreach ($d in 'db', 'keys', 'keys\incoming', 'bisync', 'run', 'logs', 'logs\runs', 'backups', 'caddy',
                   'caddy\data', 'caddy\config', 'preflight', 'safety', 'escrow') {
        New-Item -ItemType Directory -Force -Path (Join-Path $P.DataRoot $d) | Out-Null
    }
    Set-DataAcl -Path $P.DataRoot
    Set-DataAcl -Path $P.Escrow -AdminsOnly
}
Write-Ok "$($P.DataRoot): inheritance off; SYSTEM, Administrators, $ServiceAccount only (escrow: Administrators only)"
if ($generated) {
    Invoke-Change 'save the generated service-account password to the escrow folder' {
        Set-Content -LiteralPath (Join-Path $P.Escrow 'svc-springsync-password.txt') -Value $plain -Encoding ASCII
    }
    Write-Warn2 "A password for $ServiceAccount was generated and saved in $($P.Escrow)\svc-springsync-password.txt."
    Write-Info  'Move it into the IT password manager, then delete that file. Never RESET this password'
    Write-Info  '(a reset makes the DPAPI-protected keys unreadable; SPEC 11.5.4).'
    Remove-Variable plain
}

# ---------------------------------------------------------------------------------------------------
Write-Step '5. Programs (official files, verified)'
$Release = Join-Path $P.Releases $Version
Invoke-Change "build release $Version in $Release" { $script:Release = Install-Release -PackageRoot $PackageRoot -Pins $Pins }
Invoke-Change "install rclone $($Pins.Rclone.Version)" { Install-Rclone -PackageRoot $PackageRoot -Pins $Pins }
$haveCaddy = Test-Path -LiteralPath $P.CaddyExe
if ($CaddyExe) {
    Test-CaddyBuild -Exe $CaddyExe -Pins $Pins
    Invoke-Change "install caddy.exe to $($P.CaddyExe)" {
        Copy-Item -LiteralPath $CaddyExe -Destination $P.CaddyExe -Force
        Set-Content -LiteralPath (Join-Path $P.CaddyDir 'caddy.exe.sha256') -Value (Get-FileSha256 $P.CaddyExe) -Encoding ASCII
    }
    $haveCaddy = $true
} elseif ($haveCaddy) {
    Test-CaddyBuild -Exe $P.CaddyExe -Pins $Pins
} else {
    Write-Warn2 'No caddy.exe given: HTTPS is not set up yet. The web page will not be reachable from other PCs.'
    Write-Info  'Build it with app\deploy\windows\build-caddy-windows.sh, then re-run with -CaddyExe <path>.'
}

$cur = Get-JunctionTarget -Path $P.Current
if (-not $cur) { Invoke-Change "point $($P.Current) at $Release" { Set-CurrentJunction -Target $Release } }
elseif ($cur -ne $Release) { Write-Warn2 "current is $cur; use update.ps1 to switch releases (install.ps1 never switches)." }
else { Write-Ok "current = $Release" }
$CurrentRelease = $P.Current

# ---------------------------------------------------------------------------------------------------
Write-Step '6. Settings, keys, database'
function Expand-Template {
    param([string]$Src, [string]$Dst, [hashtable]$Map)
    $t = Get-Content -LiteralPath $Src -Raw
    foreach ($k in $Map.Keys) { $t = $t.Replace("@$k@", $Map[$k]) }
    if ($t -match '@[A-Z_]+@') { throw "unfilled placeholder in $Dst ($($Matches[0]))" }
    [IO.File]::WriteAllText($Dst, $t, (New-Object Text.UTF8Encoding($false)))
}
$tmplDir = Join-Path $PackageRoot 'app\deploy\windows'
if (-not (Test-Path -LiteralPath $P.Config)) {
    Invoke-Change "write $($P.Config)" {
        Expand-Template -Src (Join-Path $tmplDir 'springsync.toml.tmpl') -Dst $P.Config -Map @{
            DATA = $P.DataRoot; BASE_URL = $BaseUrl; TENANT_ID = $TenantId; CLIENT_ID = $ClientId
            UPN_DOMAIN = $AllowedUpnDomain; GOOGLE_CLIENT_ID = $GoogleClientId; NAS_HOST = $NasHost; NAS_SHARE = $NasShare
            GROUP_USERS = $GroupUsers; GROUP_ADMINS = $GroupAdmins; GROUP_AUDITORS = $GroupAuditors }
    }
} else { Write-Ok "$($P.Config) exists (kept)" }
if ($haveCaddy -and -not (Test-Path -LiteralPath $P.Caddyfile)) {
    if (-not ($AcmeEmail -and $GcpAcmeProject -and $AcmeZone)) { throw 'Caddy needs -AcmeEmail, -GcpAcmeProject and -AcmeZone.' }
    $syncHost = ([uri]$BaseUrl).Host
    Invoke-Change "write $($P.Caddyfile)" {
        Expand-Template -Src (Join-Path $tmplDir 'Caddyfile.tmpl') -Dst $P.Caddyfile -Map @{
            DATA = ($P.DataRoot -replace '\\', '/'); SYNC_HOST = $syncHost; ACME_EMAIL = $AcmeEmail }
    }
}
if ($GcpAcmeKeyFile) {
    Invoke-Change 'copy the GCP ACME service-account key' {
        Copy-Item -LiteralPath $GcpAcmeKeyFile -Destination (Join-Path $P.CaddyDir 'gcp-acme-sa.json') -Force
    }
    Write-Info "You can now delete $GcpAcmeKeyFile (a copy is in $($P.CaddyDir), readable by the service only)."
}
Invoke-Change 'create data.key and the Entra certificate if missing (odnas keygen)' {
    if ((Invoke-Odnas -Release $CurrentRelease keygen) -ne 0) { throw 'keygen failed' }
}
Invoke-Change 'create / upgrade the database (expand-only)' {
    if ((Invoke-Odnas -Release $CurrentRelease db-upgrade) -ne 0) { throw 'db-upgrade failed' }
}

# ---------------------------------------------------------------------------------------------------
Write-Step '7. Services and firewall'
$py  = Join-Path $P.Current 'python\python.exe'
$svc = Join-Path $P.Current 'app\deploy\windows\svc.py'
$defs = @(
    @{ Name = $WorkerService; Display = 'SpringSync worker'; Bin = "`"$py`" `"$svc`" worker"
       Desc = 'SpringSync scheduler, token broker (127.0.0.1:8081) and rclone runs' },
    @{ Name = $WebService; Display = 'SpringSync web'; Bin = "`"$py`" `"$svc`" web"
       Desc = 'SpringSync web pages (127.0.0.1:8080, behind Caddy)' }
)
if ($haveCaddy) {
    $defs += @{ Name = $CaddyService; Display = 'SpringSync Caddy (HTTPS)'
                Bin = "`"$($P.CaddyExe)`" run --config `"$($P.Caddyfile)`" --adapter caddyfile"
                Desc = 'HTTPS for SpringSync (Caddy 2.11.7, DNS-01)' }
}
$missing = @($defs | Where-Object { -not (Get-Service -Name $_.Name -ErrorAction SilentlyContinue) })
if ($missing.Count -gt 0 -and -not $ServiceAccountPassword) {
    $ServiceAccountPassword = Read-Host -AsSecureString "Password of $ServiceAccount (from the password manager)"
}
foreach ($d in $defs) {
    if (-not (Get-Service -Name $d.Name -ErrorAction SilentlyContinue)) {
        Invoke-Change "register service $($d.Name) as .\$ServiceAccount" {
            $cred = New-Object Management.Automation.PSCredential(".\$ServiceAccount", $ServiceAccountPassword)
            New-Service -Name $d.Name -DisplayName $d.Display -Description $d.Desc -BinaryPathName $d.Bin `
                -StartupType Automatic -Credential $cred | Out-Null
        }
    } else { Write-Ok "service $($d.Name) exists" }
    Invoke-Change "restart-on-failure x3 and delayed auto start for $($d.Name)" { Set-ServiceRecovery -Name $d.Name }
}
Invoke-Change 'service environment (config path; Caddy DNS settings)' {
    Set-ServiceEnvironment -Name $WorkerService -Pairs @("ODNAS_CONFIG=$($P.Config)")
    Set-ServiceEnvironment -Name $WebService -Pairs @("ODNAS_CONFIG=$($P.Config)")
    # Windows Update restarts: let the worker drain first (CTRL_BREAK to rclone, 120 s, then stop).
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$WorkerService" -Name PreshutdownTimeout `
        -PropertyType DWord -Value 150000 -Force | Out-Null
    if ($haveCaddy) {
        $envPairs = @("XDG_DATA_HOME=$($P.CaddyDir)\data", "XDG_CONFIG_HOME=$($P.CaddyDir)\config")
        if ($GcpAcmeProject) { $envPairs += "GCP_ACME_PROJECT=$GcpAcmeProject" }
        if ($AcmeZone) { $envPairs += "ACME_ZONE=$AcmeZone" }
        Set-ServiceEnvironment -Name $CaddyService -Pairs $envPairs
    }
}
if ($haveCaddy) {
    Invoke-Change "firewall: allow TCP 443 and 80 to caddy.exe from $FirewallRemoteAddress" {
        $rule = Get-NetFirewallRule -Name $FirewallRule -ErrorAction SilentlyContinue
        if ($rule) { Remove-NetFirewallRule -Name $FirewallRule }
        New-NetFirewallRule -Name $FirewallRule -DisplayName 'SpringSync HTTPS (Caddy)' -Direction Inbound -Action Allow `
            -Protocol TCP -LocalPort 443, 80 -Program $P.CaddyExe -RemoteAddress $FirewallRemoteAddress `
            -Profile Domain, Private | Out-Null
    }
    Write-Info 'Port 8080 (web) and 8081 (worker) listen on 127.0.0.1 only and get no firewall rule.'
}

# ---------------------------------------------------------------------------------------------------
Write-Step '8. Start and self-check'
if ($SkipServiceStart -or $WhatIfPreference) { Write-Info 'services not started (-SkipServiceStart / -WhatIf)' }
else {
    $report = Join-Path $P.Logs 'doctor-service.json'
    if (Test-Path -LiteralPath $report) { Remove-Item -LiteralPath $report -Force }
    Start-SSServices
    if (Wait-Healthy -Seconds 90) { Write-Ok 'web /healthz answers and the worker is alive' }
    else { Write-Warn2 "web or worker not healthy yet; see $($P.Logs)\web.log and worker.log" }
    $deadline = (Get-Date).AddSeconds(60)
    while (-not (Test-Path -LiteralPath $report) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 3 }
    if (Test-Path -LiteralPath $report) {
        $checks = Get-Content -LiteralPath $report -Raw | ConvertFrom-Json
        foreach ($c in $checks) {
            if ($c.status -eq 'fail') { Write-Warn2 "service self-check FAIL: $($c.name) $($c.detail)" }
        }
        Write-Ok "service self-check written to $report"
    }
    $dargs = @('doctor', '--http')
    if ($haveCaddy) { $dargs += @('--caddy-exe', $P.CaddyExe, '--caddyfile', $P.Caddyfile) }
    $rc = Invoke-Odnas -Release $CurrentRelease @dargs
    if ($rc -ne 0) { Write-Warn2 'odnas doctor reported a failure (see above).' }
    & (Join-Path $P.Current 'python\python.exe') -m odnas audit-event install $Version 2>$null | Out-Null
}

Write-Step 'Done. Next steps (docs\INSTALL-WINDOWS.md):'
Write-Info "1. Escrow: move everything in $($P.Escrow) into the IT password manager / safe, then delete it there."
Write-Info "2. Upload $($P.Keys)\entra-app.crt to the Entra app registration (needs Mark's OK)."
Write-Info "3. Open $BaseUrl from a PC on the LAN (after DNS and Caddy are set up) and sign in as an admin."
