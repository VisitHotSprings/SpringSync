# SpringSync.psm1 - shared helpers for install.ps1, update.ps1, rollback.ps1, uninstall.ps1, set-secret.ps1
# (SPEC 11.5). Plain PowerShell 5.1 (the version built into Windows 11); no downloads, no encoded commands,
# no Invoke-Expression. Ready for Authenticode signing (see docs/INSTALL-WINDOWS.md).

Set-StrictMode -Version 3.0

$script:Slug           = 'springsync'
$script:AppRoot        = Join-Path $env:ProgramFiles 'SpringSync'
$script:DataRoot       = Join-Path $env:ProgramData 'SpringSync'
$script:ServiceAccount = 'svc-springsync'
$script:WebService     = 'springsync-web'
$script:WorkerService  = 'springsync-worker'
$script:CaddyService   = 'springsync-caddy'
$script:FirewallRule   = 'SpringSync-HTTPS'

function Get-SSPaths {
    [CmdletBinding()] param()
    [pscustomobject]@{
        AppRoot    = $script:AppRoot
        Bin        = Join-Path $script:AppRoot 'bin'
        Releases   = Join-Path $script:AppRoot 'releases'
        Current    = Join-Path $script:AppRoot 'current'
        Previous   = Join-Path $script:AppRoot 'previous.txt'
        DataRoot   = $script:DataRoot
        Config     = Join-Path $script:DataRoot 'springsync.toml'
        Keys       = Join-Path $script:DataRoot 'keys'
        Incoming   = Join-Path $script:DataRoot 'keys\incoming'
        Escrow     = Join-Path $script:DataRoot 'escrow'
        Db         = Join-Path $script:DataRoot 'db\springsync.db'
        Logs       = Join-Path $script:DataRoot 'logs'
        Backups    = Join-Path $script:DataRoot 'backups'
        CaddyDir   = Join-Path $script:DataRoot 'caddy'
        Caddyfile  = Join-Path $script:DataRoot 'caddy\Caddyfile'
        RcloneExe  = Join-Path $script:AppRoot 'bin\rclone.exe'
        CaddyExe   = Join-Path $script:AppRoot 'bin\caddy.exe'
    }
}

function Write-Step  { param([string]$Text) Write-Host ''; Write-Host "==> $Text" -ForegroundColor Cyan }
function Write-Ok    { param([string]$Text) Write-Host "    OK    $Text" -ForegroundColor Green }
function Write-Warn2 { param([string]$Text) Write-Host "    WARN  $Text" -ForegroundColor Yellow }
function Write-Info  { param([string]$Text) Write-Host "          $Text" }

function Assert-Administrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this in PowerShell opened with "Run as administrator".'
    }
}

function Get-FileSha256 {
    param([Parameter(Mandatory)][string]$Path)
    (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Assert-FileSha256 {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Expected, [string]$Label = $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "$Label is missing: $Path" }
    $got = Get-FileSha256 -Path $Path
    if ($got -ne $Expected.ToLowerInvariant()) {
        throw "SHA-256 mismatch for ${Label}: expected $Expected, got $got. Do not continue; get a fresh copy."
    }
    Write-Ok "$Label SHA-256 $got"
}

function Test-PackageSums {
    # Verifies every line of SHA256SUMS.txt ("<sha256>  <relative path>", forward slashes) in the package.
    param([Parameter(Mandatory)][string]$PackageRoot)
    $sums = Join-Path $PackageRoot 'SHA256SUMS.txt'
    if (-not (Test-Path -LiteralPath $sums)) { throw "SHA256SUMS.txt not found in $PackageRoot" }
    $n = 0
    foreach ($line in Get-Content -LiteralPath $sums) {
        if ($line -match '^\s*$' -or $line.StartsWith('#')) { continue }
        if ($line -notmatch '^([0-9a-f]{64})\s+\*?(.+)$') { throw "bad line in SHA256SUMS.txt: $line" }
        $hash = $Matches[1]; $rel = $Matches[2].Trim()
        if ($rel.Contains('..')) { throw "bad path in SHA256SUMS.txt: $rel" }
        $file = Join-Path $PackageRoot ($rel -replace '/', '\')
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "missing from package: $rel" }
        if ((Get-FileSha256 -Path $file) -ne $hash) { throw "SHA-256 mismatch: $rel (package damaged or changed)" }
        $n++
    }
    Write-Ok "package contents match SHA256SUMS.txt ($n files)"
}

function Unblock-PackageFiles {
    # Removes the "downloaded from the internet" mark from the package files ONLY (not anything else).
    param([Parameter(Mandatory)][string]$PackageRoot)
    Get-ChildItem -LiteralPath $PackageRoot -Recurse -File | Unblock-File
    Write-Ok "unblocked the files in $PackageRoot"
}

function Get-Pins {
    param([Parameter(Mandatory)][string]$PackageRoot)
    Import-PowerShellDataFile -LiteralPath (Join-Path $PackageRoot 'app\deploy\windows\pins.psd1')
}

function Get-PackageVersion {
    param([Parameter(Mandatory)][string]$PackageRoot)
    $v = (Get-Content -LiteralPath (Join-Path $PackageRoot 'VERSION') -TotalCount 1).Trim()
    if ($v -notmatch '^\d+\.\d+\.\d+$') { throw "bad VERSION file: $v" }
    $v
}

function Set-DataAcl {
    # SPEC 11.5.2: inheritance off; SYSTEM + Administrators full control, the service account Modify.
    param([Parameter(Mandatory)][string]$Path, [switch]$AdminsOnly)
    # *S-1-5-18 = SYSTEM, *S-1-5-32-544 = Administrators (SIDs, so this works in any Windows language)
    $acct = "$env:COMPUTERNAME\$script:ServiceAccount"
    $grants = @('*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F')
    if (-not $AdminsOnly) { $grants += "${acct}:(OI)(CI)M" }
    $out = & icacls.exe $Path /inheritance:r /grant:r @grants 2>&1
    if ($LASTEXITCODE -ne 0) { throw "icacls failed on ${Path}: $out" }
}

function Invoke-Odnas {
    # Runs "python -m odnas <args>" from a release folder, as the CURRENT user (Administrator).
    # Commands that need the DPAPI secrets only work inside the services; see doctor-service.json.
    param([Parameter(Mandatory)][string]$Release, [Parameter(ValueFromRemainingArguments)][string[]]$Arguments)
    $py = Join-Path $Release 'python\python.exe'
    $env:ODNAS_CONFIG = (Get-SSPaths).Config
    & $py -m odnas @Arguments | Out-Host
    $LASTEXITCODE
}

function Get-JunctionTarget {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.LinkType -ne 'Junction') { throw "$Path exists but is not a junction" }
    @($item.Target)[0]
}

function Set-CurrentJunction {
    # Points <AppRoot>\current at a release. Removes ONLY the junction itself, never the target's contents.
    param([Parameter(Mandatory)][string]$Target)
    $cur = (Get-SSPaths).Current
    if (Test-Path -LiteralPath $cur) {
        $null = Get-JunctionTarget -Path $cur       # throws if it is a real folder
        [System.IO.Directory]::Delete($cur, $false)
    }
    New-Item -ItemType Junction -Path $cur -Target $Target | Out-Null
}

function Wait-Healthy {
    # GET http://127.0.0.1:8080/healthz until it answers with worker_alive=true (SPEC 11.4: 60 s).
    param([int]$Seconds = 60)
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $r = Invoke-RestMethod -Uri 'http://127.0.0.1:8080/healthz' -TimeoutSec 5 -UseBasicParsing
            if ($r.worker_alive -eq $true) { return $true }
        } catch { }
        Start-Sleep -Seconds 5
    }
    $false
}

function Stop-SSServices {
    foreach ($s in @($script:CaddyService, $script:WebService, $script:WorkerService)) {
        if (Get-Service -Name $s -ErrorAction SilentlyContinue) {
            Stop-Service -Name $s -ErrorAction SilentlyContinue
        }
    }
    # The worker drains for up to ~150 s (CTRL_BREAK to rclone, then hard stop); wait for it.
    $w = Get-Service -Name $script:WorkerService -ErrorAction SilentlyContinue
    if ($w) { $w.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(180)) }
}

function Start-SSServices {
    foreach ($s in @($script:WorkerService, $script:WebService, $script:CaddyService)) {
        if (Get-Service -Name $s -ErrorAction SilentlyContinue) { Start-Service -Name $s }
    }
}

function Get-ReleaseVersions {
    $r = (Get-SSPaths).Releases
    if (-not (Test-Path -LiteralPath $r)) { return @() }
    @(Get-ChildItem -LiteralPath $r -Directory | Where-Object { Test-Path (Join-Path $_.FullName '.complete') } |
        Sort-Object { [version]$_.Name } | ForEach-Object { $_.Name })
}

function Install-Release {
    # Builds <AppRoot>\releases\<ver> from a verified package: official embeddable Python, pip from the
    # shipped wheel with --require-hashes against requirements-windows.lock, and the app files.
    # Idempotent: an existing release with a .complete marker is reused.
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$PackageRoot, [Parameter(Mandatory)]$Pins)
    $ver = Get-PackageVersion -PackageRoot $PackageRoot
    $rel = Join-Path (Get-SSPaths).Releases $ver
    if (Test-Path -LiteralPath (Join-Path $rel '.complete')) { Write-Ok "release $ver already built"; return $rel }
    if (-not $PSCmdlet.ShouldProcess($rel, 'build release')) { return $rel }
    if (Test-Path -LiteralPath $rel) { Remove-Item -LiteralPath $rel -Recurse -Force }
    New-Item -ItemType Directory -Path $rel | Out-Null

    $vendor = Join-Path $PackageRoot 'vendor'
    $pyZip = Join-Path $vendor $Pins.Python.File
    Assert-FileSha256 -Path $pyZip -Expected $Pins.Python.Sha256 -Label "Python $($Pins.Python.Version)"
    Expand-Archive -LiteralPath $pyZip -DestinationPath (Join-Path $rel 'python')
    # Embeddable Python: sys.path comes only from the ._pth file. Add site-packages and the app, enable site.
    $pth = Join-Path $rel ('python\' + $Pins.Python.PthFile)
    $base = [IO.Path]::GetFileNameWithoutExtension($Pins.Python.PthFile)
    Set-Content -LiteralPath $pth -Encoding ASCII -Value @("$base.zip", '.', 'Lib\site-packages', '..\app', 'import site')

    Copy-Item -LiteralPath (Join-Path $PackageRoot 'app') -Destination (Join-Path $rel 'app') -Recurse

    $pipWhl = Join-Path $vendor $Pins.Pip.File
    Assert-FileSha256 -Path $pipWhl -Expected $Pins.Pip.Sha256 -Label "pip $($Pins.Pip.Version)"
    $py = Join-Path $rel 'python\python.exe'
    $site = Join-Path $rel 'python\Lib\site-packages'
    $lock = Join-Path $rel 'app\requirements-windows.lock'
    $pipArgs = @("$pipWhl\pip", 'install', '--no-index', '--find-links', (Join-Path $vendor 'wheels'),
                 '--require-hashes', '--only-binary=:all:', '--no-compile', '--disable-pip-version-check',
                 '--target', $site, '-r', $lock)
    & $py @pipArgs | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "pip install from requirements-windows.lock failed (exit $LASTEXITCODE)" }
    Write-Ok 'Python packages installed from the hash-locked wheels'
    Set-Content -LiteralPath (Join-Path $rel '.complete') -Value (Get-Date -Format o) -Encoding ASCII
    $rel
}

function Install-Rclone {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$PackageRoot, [Parameter(Mandatory)]$Pins)
    $paths = Get-SSPaths
    if ((Test-Path -LiteralPath $paths.RcloneExe) -and ((Get-FileSha256 $paths.RcloneExe) -eq $Pins.Rclone.ExeSha256)) {
        Write-Ok "rclone $($Pins.Rclone.Version) already installed"; return
    }
    $zip = Join-Path $PackageRoot ('vendor\' + $Pins.Rclone.File)
    Assert-FileSha256 -Path $zip -Expected $Pins.Rclone.Sha256 -Label "rclone $($Pins.Rclone.Version) zip"
    if (-not $PSCmdlet.ShouldProcess($paths.RcloneExe, 'install rclone')) { return }
    $tmp = Join-Path $env:TEMP ('springsync-rclone-' + [guid]::NewGuid().ToString('N'))
    Expand-Archive -LiteralPath $zip -DestinationPath $tmp
    $exe = Join-Path $tmp ([IO.Path]::GetFileNameWithoutExtension($Pins.Rclone.File) + '\rclone.exe')
    Assert-FileSha256 -Path $exe -Expected $Pins.Rclone.ExeSha256 -Label 'rclone.exe'
    New-Item -ItemType Directory -Force -Path $paths.Bin | Out-Null
    Copy-Item -LiteralPath $exe -Destination $paths.RcloneExe -Force
    Remove-Item -LiteralPath $tmp -Recurse -Force
}

function Test-CaddyBuild {
    # caddy.exe must be v2.11.7 with googleclouddns at the pinned version AND go.sum hash (as install.sh).
    param([Parameter(Mandatory)][string]$Exe, [Parameter(Mandatory)]$Pins)
    $ver = (& $Exe version) 2>&1 | Select-Object -First 1
    if ("$ver" -notlike "$($Pins.Caddy.Version)*") { throw "caddy.exe is '$ver', expected $($Pins.Caddy.Version)" }
    $mods = (& $Exe list-modules) 2>&1
    if (-not ($mods -match '^dns\.providers\.googleclouddns$')) { throw 'caddy.exe has no dns.providers.googleclouddns module' }
    $want = "dep`t$($Pins.Caddy.DnsModule)`t$($Pins.Caddy.DnsModuleVersion)`t$($Pins.Caddy.DnsModuleH1)"
    $info = (& $Exe build-info) 2>&1 | ForEach-Object { ($_ -replace '\s+', "`t").Trim() }
    if (-not ($info -contains $want)) { throw "caddy.exe googleclouddns is not $($Pins.Caddy.DnsModuleVersion) ($($Pins.Caddy.DnsModuleH1))" }
    Write-Ok "caddy.exe $ver with googleclouddns $($Pins.Caddy.DnsModuleVersion) (pinned hash)"
}

function Set-ServiceEnvironment {
    # Per-service environment (REG_MULTI_SZ "Environment"), the Windows equivalent of systemd Environment=.
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string[]]$Pairs)
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    New-ItemProperty -Path $key -Name 'Environment' -PropertyType MultiString -Value $Pairs -Force | Out-Null
}

function Set-ServiceRecovery {
    # Restart on failure 3 times (60 s apart), counter reset after a day; also on non-crash failures.
    param([Parameter(Mandatory)][string]$Name)
    & sc.exe failure $Name reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
    & sc.exe failureflag $Name 1 | Out-Null
    & sc.exe config $Name start= delayed-auto | Out-Null
}

Export-ModuleMember -Function * -Variable Slug, AppRoot, DataRoot, ServiceAccount, WebService, WorkerService, CaddyService, FirewallRule
