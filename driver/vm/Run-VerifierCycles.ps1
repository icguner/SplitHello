[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [switch]$DisposableVmAcknowledged,

    [ValidateRange(1, 1000)]
    [int]$Cycles = 100,

    [switch]$EnableVerifier
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $DisposableVmAcknowledged) {
    throw 'This script is restricted to a disposable VM.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell in the VM.'
}

if ($EnableVerifier) {
    & verifier.exe /reset
    & verifier.exe /standard /driver SplitHelloWfp.sys
    if ($LASTEXITCODE -ne 0) {
        throw "verifier configuration failed with exit code $LASTEXITCODE"
    }
    Write-Host 'Driver Verifier enabled. Reboot the VM, then run this script without -EnableVerifier.'
    return
}

& verifier.exe /querysettings
$controller = Join-Path $PSScriptRoot 'SplitHelloWfpCtl.exe'
if (-not (Test-Path -LiteralPath $controller -PathType Leaf)) {
    throw "Missing controller: $controller"
}
& $controller probe $Cycles
if ($LASTEXITCODE -ne 0) {
    throw "load/unload probe failed with exit code $LASTEXITCODE"
}
Write-Host "Completed $Cycles verified load/query/unload cycles."
