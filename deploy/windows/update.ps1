<#
.SYNOPSIS
    Updates SpringSync to a new release zip with automatic rollback (SPEC 11.4 on Windows). Run as Administrator.

.DESCRIPTION
    1. Checks the zip against the SHA-256 you were given, extracts it, checks SHA256SUMS.txt, unblocks its files.
    2. Builds the new release next to the current one (official Python + hash-locked wheels).
    3. Smoke tests with the NEW release (imports, pytest --smoke, odnas doctor). Nothing has changed yet.
    4. Drains the worker (waits up to -DrainTimeout seconds for running syncs), then backs up the DB (pre-<ver>).
    5. Stops the services, upgrades the DB (expand-only), switches the "current" junction, starts the services.
    6. Waits up to 60 s for /healthz with a live worker; if not healthy, rolls back automatically.
    7. Writes an audit entry and keeps the last 3 releases.

.EXAMPLE
    .\update.ps1 -Zip C:\Temp\SpringSync-0.10.1-windows.zip -Sha256 <hash from the release notes>
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Zip,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$Sha256,
    [int]$DrainTimeout = 1800,
    [switch]$SkipSmokeTests
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
# Works from the package root (app\deploy\windows\...) and from the installed copy (same folder).
$mod = Join-Path $here 'SpringSync.psm1'
if (-not (Test-Path -LiteralPath $mod)) { $mod = Join-Path $here 'app\deploy\windows\SpringSync.psm1' }
Import-Module $mod -Force
Assert-Administrator
$P = Get-SSPaths
$old = Get-JunctionTarget -Path $P.Current
if (-not $old) { throw 'SpringSync is not installed (no current release). Use install.ps1.' }

Write-Step '1. Verify and extract'
Assert-FileSha256 -Path $Zip -Expected $Sha256 -Label (Split-Path -Leaf $Zip)
Unblock-File -LiteralPath $Zip
$stage = Join-Path $env:TEMP ('springsync-update-' + [guid]::NewGuid().ToString('N'))
Expand-Archive -LiteralPath $Zip -DestinationPath $stage
$pkg = @(Get-ChildItem -LiteralPath $stage -Directory)[0].FullName
Test-PackageSums -PackageRoot $pkg
Unblock-PackageFiles -PackageRoot $pkg
$pins = Get-Pins -PackageRoot $pkg
$ver = Get-PackageVersion -PackageRoot $pkg
if ((Split-Path -Leaf $old) -eq $ver) { Write-Ok "$ver is already current"; return }

Write-Step "2. Build release $ver"
if (-not $PSCmdlet.ShouldProcess("SpringSync $ver", 'update')) { return }
$new = Install-Release -PackageRoot $pkg -Pins $pins
Install-Rclone -PackageRoot $pkg -Pins $pins

Write-Step '3. Smoke tests against the new release (nothing changed yet)'
$py = Join-Path $new 'python\python.exe'
& $py -c 'import odnas.web.app, odnas.worker, odnas.winservice, odnas.winshare, odnas.dpapi, win32service, servicemanager'
if ($LASTEXITCODE -ne 0) { throw 'new release cannot import its modules; nothing changed' }
if (-not $SkipSmokeTests) {
    if (Test-Path -LiteralPath (Join-Path $new 'app\tests')) {
        Push-Location (Join-Path $new 'app')
        try { & $py -m pytest -q --smoke -p no:cacheprovider tests } finally { Pop-Location }
        if ($LASTEXITCODE -ne 0) { throw 'smoke tests failed; nothing changed (use -SkipSmokeTests only if you know why)' }
    }
}
if ((Invoke-Odnas -Release $new doctor) -ne 0) { Write-Warn2 'doctor (new release, as Administrator) reported a failure; continuing' }

Write-Step "4. Drain (up to $DrainTimeout s) and back up the database"
if ((Invoke-Odnas -Release $old worker drain --timeout $DrainTimeout) -ne 0) {
    Invoke-Odnas -Release $old worker undrain | Out-Null
    throw 'drain timed out; nothing changed'
}
if ((Invoke-Odnas -Release $old backup --tag "pre-$ver") -ne 0) { throw 'DB backup failed; nothing changed' }

Write-Step '5. Stop, migrate, switch, start'
Stop-SSServices
if ((Invoke-Odnas -Release $new db-upgrade) -ne 0) {
    Start-SSServices; throw 'db-upgrade failed; old release restarted (migrations are expand-only)'
}
Set-Content -LiteralPath $P.Previous -Value $old -Encoding ASCII
Set-CurrentJunction -Target $new
Start-SSServices

Write-Step '6. Health check (60 s)'
if (-not (Wait-Healthy -Seconds 60)) {
    Write-Warn2 "not healthy: rolling back to $(Split-Path -Leaf $old)"
    & (Join-Path $old 'app\deploy\windows\rollback.ps1') -Auto
    throw "update to $ver failed and was rolled back"
}
Write-Ok "SpringSync $ver is running"

Write-Step '7. Audit and prune (keep 3 releases)'
Invoke-Odnas -Release $new audit-event deploy $ver --from (Split-Path -Leaf $old) | Out-Null
$keep = @($new, $old)
$all = Get-ReleaseVersions
$drop = @($all | Select-Object -SkipLast 3)
foreach ($v in $drop) {
    $dir = Join-Path $P.Releases $v
    if ($keep -notcontains $dir) { Remove-Item -LiteralPath $dir -Recurse -Force; Write-Info "removed old release $v" }
}
Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
Write-Ok "updated to $ver"
