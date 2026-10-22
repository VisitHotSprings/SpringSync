# Parses every PowerShell file under deploy/windows and fails on any syntax error.
# CI runs it twice: in PowerShell 7 (pwsh) and in Windows PowerShell 5.1 (powershell.exe).
$ErrorActionPreference = 'Stop'
$root = Join-Path $PSScriptRoot '..\..\deploy\windows'
$files = @(Get-ChildItem -Path $root -Recurse -File | Where-Object { $_.Extension -in '.ps1', '.psm1', '.psd1' })
if ($files.Count -eq 0) { Write-Output 'no PowerShell files found'; exit 1 }
$bad = 0
foreach ($f in $files) {
    $tok = $null; $err = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tok, [ref]$err)
    foreach ($e in $err) {
        Write-Output ("{0}:{1}: {2}" -f $f.Name, $e.Extent.StartLineNumber, $e.Message)
        $bad++
    }
}
Write-Output ("PowerShell {0}: parsed {1} files, {2} errors" -f $PSVersionTable.PSVersion, $files.Count, $bad)
if ($bad) { exit 1 }
