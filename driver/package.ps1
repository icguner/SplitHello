[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$driverRoot = $PSScriptRoot
$sourceRoot = Join-Path $driverRoot "out\$Configuration\x64"
$catalogRoot = Join-Path $sourceRoot 'SplitHelloWfp'
$packageRoot = [IO.Path]::GetFullPath(
    (Join-Path $driverRoot "out\package\$Configuration"))

$resolvedDriverRoot = (Resolve-Path -LiteralPath $driverRoot).Path
$expectedPackageParent = [IO.Path]::GetFullPath(
    (Join-Path $resolvedDriverRoot 'out\package'))
if (-not [string]::Equals(
        [IO.Path]::GetDirectoryName($packageRoot),
        $expectedPackageParent,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Package output escaped the driver workspace.'
}

$required = @(
    (Join-Path $sourceRoot 'SplitHelloWfp.sys'),
    (Join-Path $sourceRoot 'SplitHelloWfp.inf'),
    (Join-Path $sourceRoot 'SplitHelloWfp.cer'),
    (Join-Path $sourceRoot 'SplitHelloWfpCtl.exe'),
    (Join-Path $catalogRoot 'splithellowfp.cat')
)
foreach ($path in $required) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Missing build artifact: $path"
    }
}

if (Test-Path -LiteralPath $packageRoot) {
    Remove-Item -LiteralPath $packageRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $packageRoot -Force | Out-Null
foreach ($path in $required) {
    Copy-Item -LiteralPath $path -Destination $packageRoot -Force
}
Copy-Item -LiteralPath (Join-Path $driverRoot 'vm\Install-TestDriver.ps1') `
    -Destination $packageRoot -Force
Copy-Item -LiteralPath (Join-Path $driverRoot 'vm\Run-VerifierCycles.ps1') `
    -Destination $packageRoot -Force
Copy-Item -LiteralPath (Join-Path $driverRoot 'vm\Uninstall-TestDriver.ps1') `
    -Destination $packageRoot -Force

Get-ChildItem -LiteralPath $packageRoot -File |
    Where-Object { $_.Name -ne 'SHA256SUMS.txt' } |
    Get-FileHash -Algorithm SHA256 |
    Sort-Object Path |
    ForEach-Object { '{0}  {1}' -f $_.Hash, (Split-Path $_.Path -Leaf) } |
    Set-Content -LiteralPath (Join-Path $packageRoot 'SHA256SUMS.txt') -Encoding ascii

Write-Host "VM package ready: $packageRoot"
