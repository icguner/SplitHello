[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [switch]$DisposableVmAcknowledged
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

$packageRoot = $PSScriptRoot
$certificate = Join-Path $packageRoot 'SplitHelloWfp.cer'
$inf = Join-Path $packageRoot 'SplitHelloWfp.inf'
foreach ($path in @($certificate, $inf)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Missing package file: $path"
    }
}

Import-Certificate -FilePath $certificate -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
Import-Certificate -FilePath $certificate `
    -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null

& pnputil.exe /add-driver $inf /install
if ($LASTEXITCODE -ne 0) {
    throw "pnputil failed with exit code $LASTEXITCODE"
}

Write-Host 'Test driver package installed. Enable Driver Verifier and reboot next.'
