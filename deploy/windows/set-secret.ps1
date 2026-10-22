<#
.SYNOPSIS
    Hands a secret to SpringSync without it ever appearing on a command line or in a log (SPEC 11.5.4).
.DESCRIPTION
    Asks for the value with a hidden prompt (or copies it from -FromFile), writes it to
    C:\ProgramData\SpringSync\keys\incoming\<Name> (Administrators + svc-springsync only), and restarts the
    services; on start they protect it with DPAPI for svc-springsync and delete the plain copy.
.EXAMPLE
    .\set-secret.ps1 -Name google-client.secret
    .\set-secret.ps1 -Name data.key -FromFile E:\escrow\data.key      # restore after a lost DPAPI key
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidateSet('google-client.secret', 'entra-client-secret', 'entra-app.key', 'data.key', 'data.key.old')]
    [string]$Name,
    [string]$FromFile = '',
    [switch]$NoRestart
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'SpringSync.psm1') -Force
Assert-Administrator
$P = Get-SSPaths
$dst = Join-Path $P.Incoming $Name
if (-not $PSCmdlet.ShouldProcess($dst, 'write secret for DPAPI ingest')) { return }
New-Item -ItemType Directory -Force -Path $P.Incoming | Out-Null
if ($FromFile) {
    Copy-Item -LiteralPath $FromFile -Destination $dst -Force
} else {
    if ($Name -like 'data.key*' -or $Name -eq 'entra-app.key') { throw "$Name is a file: use -FromFile" }
    $sec = Read-Host -AsSecureString "Value for $Name (hidden)"
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    try {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        [IO.File]::WriteAllText($dst, $plain, (New-Object Text.UTF8Encoding($false)))
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        Remove-Variable plain -ErrorAction SilentlyContinue
    }
}
Write-Ok "$Name placed in keys\incoming"
if (-not $NoRestart) {
    Stop-SSServices; Start-SSServices
    Start-Sleep -Seconds 10
    if (Test-Path -LiteralPath $dst) { Write-Warn2 "$Name is still in keys\incoming; check $($P.Logs)\worker.log" }
    else { Write-Ok "$Name is now DPAPI-protected ($($P.Keys)\$Name.dpapi)" }
}
