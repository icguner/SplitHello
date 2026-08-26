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

& verifier.exe /reset
& sc.exe stop SplitHelloWfp | Out-Null
& sc.exe delete SplitHelloWfp | Out-Null

$drivers = Get-WindowsDriver -Online -All |
    Where-Object { $_.ProviderName -eq 'SplitHello' }
foreach ($driver in $drivers) {
    Remove-WindowsDriver -Online -Driver $driver.Driver -NoRestart | Out-Null
}

$certificatePath = Join-Path $PSScriptRoot 'SplitHelloWfp.cer'
if (Test-Path -LiteralPath $certificatePath -PathType Leaf) {
    $thumbprint = (Get-PfxCertificate -FilePath $certificatePath).Thumbprint
    foreach ($store in @('Root', 'TrustedPublisher')) {
        $path = "Cert:\LocalMachine\$store\$thumbprint"
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Force
        }
    }
}

Write-Host 'Verifier reset, driver package/service removed, and test certificate removed.'
Write-Host 'Reboot the VM before taking a clean snapshot.'
