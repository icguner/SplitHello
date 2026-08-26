[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',

    [switch]$Rebuild,

    [switch]$Analyze
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$driverRoot = $PSScriptRoot
$toolsDirectory = Join-Path $driverRoot '.tools'
$nugetPath = Join-Path $toolsDirectory 'nuget.exe'
$nugetUrl = 'https://dist.nuget.org/win-x86-commandline/v7.9.0/nuget.exe'
$nugetSha256 = '992D70CAC5B06C38EFEC91806CABA64CDCC07E6D963A0959DBBBAF264D33B800'

if (-not (Test-Path -LiteralPath $nugetPath -PathType Leaf)) {
    New-Item -ItemType Directory -Path $toolsDirectory -Force | Out-Null
    Invoke-WebRequest -Uri $nugetUrl -OutFile $nugetPath
}

$actualNugetSha256 = (Get-FileHash -LiteralPath $nugetPath -Algorithm SHA256).Hash
if ($actualNugetSha256 -ne $nugetSha256) {
    throw "NuGet hash mismatch. Expected $nugetSha256, got $actualNugetSha256."
}

& $nugetPath restore (Join-Path $driverRoot 'packages.config') `
    -PackagesDirectory (Join-Path $driverRoot 'packages') `
    -NonInteractive
if ($LASTEXITCODE -ne 0) {
    throw "NuGet restore failed with exit code $LASTEXITCODE."
}

$vswherePath = Join-Path ${env:ProgramFiles(x86)} `
    'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswherePath -PathType Leaf)) {
    throw 'Visual Studio Installer (vswhere.exe) was not found.'
}

$msbuildPath = & $vswherePath -latest -products '*' `
    -requires Microsoft.Component.MSBuild `
    -find 'MSBuild\**\Bin\amd64\MSBuild.exe' |
    Select-Object -First 1
if ([string]::IsNullOrWhiteSpace($msbuildPath)) {
    throw '64-bit MSBuild was not found in a Visual Studio installation.'
}

$target = if ($Rebuild) { 'Rebuild' } else { 'Build' }
$solutionPath = Join-Path $driverRoot 'SplitHelloWfp.sln'

& $msbuildPath $solutionPath /m "/t:$target" `
    "/p:Configuration=$Configuration" /p:Platform=x64 /v:minimal
if ($LASTEXITCODE -ne 0) {
    throw "MSBuild failed with exit code $LASTEXITCODE."
}

if ($Analyze) {
    $rulesetPath = Join-Path $driverRoot `
        'packages\Microsoft.Windows.WDK.x64.10.0.28000.2526\c\CodeAnalysis\DriverMinimumRules.ruleset'
    $driverProject = Join-Path $driverRoot 'sys\SplitHelloWfp.vcxproj'
    & $msbuildPath $driverProject /m /t:Rebuild `
        "/p:Configuration=$Configuration" /p:Platform=x64 `
        /p:RunCodeAnalysis=true /p:EnablePREfast=true `
        "/p:CodeAnalysisRuleSet=$rulesetPath" /v:minimal
    if ($LASTEXITCODE -ne 0) {
        throw "Driver code analysis failed with exit code $LASTEXITCODE."
    }
}
