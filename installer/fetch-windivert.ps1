# Puts the WinDivert 2.2.2 x64 runtime (WinDivert.dll, WinDivert64.sys and
# its license) next to splithello.exe. The official archive is pinned by
# SHA-256, so a build can never silently ship different driver bytes.
param(
    [string]$OutDir = (Join-Path $PSScriptRoot '..\target\release')
)
$ErrorActionPreference = 'Stop'

$url = 'https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip'
$sha256 = '63CB41763BB4B20F600B6DE04E991A9C2BE73279E317D4D82F237B150C5F3F15'

New-Item -ItemType Directory -Force $OutDir | Out-Null
$work = Join-Path ([System.IO.Path]::GetTempPath()) ("windivert-" + [guid]::NewGuid())
New-Item -ItemType Directory $work | Out-Null
try {
    $zip = Join-Path $work 'windivert.zip'
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
    $actual = (Get-FileHash $zip -Algorithm SHA256).Hash
    if ($actual -ne $sha256) { throw "WinDivert archive hash mismatch: $actual" }
    Expand-Archive $zip -DestinationPath $work
    $root = Join-Path $work 'WinDivert-2.2.2-A'
    Copy-Item (Join-Path $root 'x64\WinDivert.dll'), (Join-Path $root 'x64\WinDivert64.sys') $OutDir -Force
    Copy-Item (Join-Path $root 'LICENSE') (Join-Path $OutDir 'WinDivert-LICENSE.txt') -Force
    Write-Host "WinDivert 2.2.2 -> $((Resolve-Path $OutDir).Path)"
} finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
