<#
.SYNOPSIS
    Rolls SpringSync back to the previous release (SPEC 11.4 step 8 on Windows). Run as Administrator.
.PARAMETER RestoreDb
    Also restore the newest pre-<version> DB backup. Only needed if a migration was not backward compatible
    (migrations are expand-only within a minor version, so normally not).
#>
[CmdletBinding(SupportsShouldProcess)]
param([switch]$RestoreDb, [switch]$Auto)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'SpringSync.psm1') -Force
Assert-Administrator
$P = Get-SSPaths
$cur = Get-JunctionTarget -Path $P.Current
$prev = if (Test-Path -LiteralPath $P.Previous) { (Get-Content -LiteralPath $P.Previous -TotalCount 1).Trim() } else { '' }
if (-not $prev -or -not (Test-Path -LiteralPath (Join-Path $prev '.complete')) -or $prev -eq $cur) {
    throw 'no previous release recorded'
}
if (-not $PSCmdlet.ShouldProcess("$cur -> $prev", 'roll back')) { return }
Stop-SSServices
if ($RestoreDb) {
    $b = Get-ChildItem -LiteralPath $P.Backups -Filter 'db-pre-*.sqlite' | Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if (-not $b) { throw 'no pre-<version> DB backup found' }
    $stamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    Copy-Item -LiteralPath $P.Db -Destination "$($P.Db).rollback-$stamp"
    foreach ($x in '-wal', '-shm') { Remove-Item -LiteralPath "$($P.Db)$x" -ErrorAction SilentlyContinue }
    Copy-Item -LiteralPath $b.FullName -Destination $P.Db -Force
    Write-Ok "restored DB from $($b.Name)"
}
Set-CurrentJunction -Target $prev
Set-Content -LiteralPath $P.Previous -Value $cur -Encoding ASCII
Start-SSServices
if (Wait-Healthy -Seconds 60) { Write-Ok "rolled back to $(Split-Path -Leaf $prev)$(if ($Auto) { ' (automatic)' })" }
else { Write-Warn2 "rolled back to $(Split-Path -Leaf $prev) but /healthz is not healthy; see $($P.Logs)" }
& (Join-Path $P.Current 'python\python.exe') -m odnas audit-event rollback (Split-Path -Leaf $prev) --from (Split-Path -Leaf $cur) 2>$null | Out-Null
