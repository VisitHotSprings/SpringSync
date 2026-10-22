<#
.SYNOPSIS
    Removes the SpringSync services, firewall rule and program files. KEEPS all data unless -PurgeData.
.DESCRIPTION
    Default: stop and delete the services springsync-caddy, springsync-web, springsync-worker; delete the
    firewall rule; delete C:\Program Files\SpringSync. C:\ProgramData\SpringSync (database, keys, settings,
    logs, backups) and the svc-springsync account are KEPT, so a re-install picks up where it left off.
    Nothing on the NAS or in OneDrive / Google Drive is touched, ever.
.PARAMETER PurgeData
    Also delete C:\ProgramData\SpringSync. Asks you to type PURGE. The keys are gone for good afterwards:
    only do this when the escrowed copies are safe or no longer needed.
.PARAMETER RemoveAccount
    Also delete the local account svc-springsync.
#>
[CmdletBinding(SupportsShouldProcess)]
param([switch]$PurgeData, [switch]$RemoveAccount)
$ErrorActionPreference = 'Stop'
$mod = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'SpringSync.psm1'
if (-not (Test-Path $mod)) { $mod = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'app\deploy\windows\SpringSync.psm1' }
Import-Module $mod -Force
Assert-Administrator
$P = Get-SSPaths
if ($PurgeData) {
    $answer = Read-Host "This deletes $($P.DataRoot) (database, keys, settings, logs, backups). Type PURGE to confirm"
    if ($answer -cne 'PURGE') { throw 'not confirmed; nothing removed' }
}
Write-Step 'Stop and remove services'
foreach ($s in $CaddyService, $WebService, $WorkerService) {
    if (Get-Service -Name $s -ErrorAction SilentlyContinue) {
        if ($PSCmdlet.ShouldProcess($s, 'stop and delete service')) {
            Stop-Service -Name $s -ErrorAction SilentlyContinue
            if ($s -eq $WorkerService) { (Get-Service $s).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(180)) }
            & sc.exe delete $s | Out-Null
            Write-Ok "removed $s"
        }
    }
}
if (Get-NetFirewallRule -Name $FirewallRule -ErrorAction SilentlyContinue) {
    if ($PSCmdlet.ShouldProcess($FirewallRule, 'remove firewall rule')) { Remove-NetFirewallRule -Name $FirewallRule; Write-Ok 'firewall rule removed' }
}
Write-Step 'Remove program files'
if ((Test-Path -LiteralPath $P.AppRoot) -and $PSCmdlet.ShouldProcess($P.AppRoot, 'delete')) {
    if (Test-Path -LiteralPath $P.Current) { [System.IO.Directory]::Delete($P.Current, $false) }   # the junction only
    Remove-Item -LiteralPath $P.AppRoot -Recurse -Force
    Write-Ok "deleted $($P.AppRoot)"
}
if ($PurgeData) {
    if ((Test-Path -LiteralPath $P.DataRoot) -and $PSCmdlet.ShouldProcess($P.DataRoot, 'delete ALL data')) {
        Remove-Item -LiteralPath $P.DataRoot -Recurse -Force
        Write-Ok "deleted $($P.DataRoot)"
    }
} else { Write-Info "kept $($P.DataRoot) (database, keys, settings, logs, backups)" }
if ($RemoveAccount -and (Get-LocalUser -Name $ServiceAccount -ErrorAction SilentlyContinue)) {
    if ($PSCmdlet.ShouldProcess($ServiceAccount, 'delete local account')) { Remove-LocalUser -Name $ServiceAccount; Write-Ok "deleted $ServiceAccount" }
}
Write-Ok 'uninstall finished'
