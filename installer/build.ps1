# Builds dist\SplitHello-Setup-<version>.exe from an already built splithello.exe.
# Needs Inno Setup 6 (winget install JRSoftware.InnoSetup).
param(
    [string]$Version = '2.0.0',
    [string]$BuildDir = (Join-Path $PSScriptRoot '..\target\release')
)
$ErrorActionPreference = 'Stop'

if (-not (Test-Path (Join-Path $BuildDir 'splithello.exe'))) {
    throw "splithello.exe not found in $BuildDir. Run: cargo build --release"
}
if (-not (Test-Path (Join-Path $BuildDir 'WinDivert64.sys'))) {
    & (Join-Path $PSScriptRoot 'fetch-windivert.ps1') -OutDir $BuildDir
}

$iscc = @(
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw 'Inno Setup 6 not found. Run: winget install JRSoftware.InnoSetup' }

# Wizard artwork is drawn from the app icon at 100% and 200% DPI so the repo
# carries no binary images.
Add-Type -AssemblyName System.Drawing
$gen = Join-Path $PSScriptRoot 'gen'
New-Item -ItemType Directory -Force $gen | Out-Null
$logo = [System.Drawing.Image]::FromFile((Resolve-Path (Join-Path $PSScriptRoot '..\assets\splithello-icon.png')))

function New-Canvas($width, $height) {
    $bitmap = New-Object System.Drawing.Bitmap $width, $height
    $g = [System.Drawing.Graphics]::FromImage($bitmap)
    $g.SmoothingMode = 'AntiAlias'
    $g.InterpolationMode = 'HighQualityBicubic'
    $g.TextRenderingHint = 'AntiAliasGridFit'
    return $bitmap, $g
}

foreach ($scale in 100, 200) {
    $k = $scale / 100

    # Welcome / finish panel, 164x314 at 100%.
    $panel, $g = New-Canvas (164 * $k) (314 * $k)
    $area = New-Object System.Drawing.Rectangle 0, 0, $panel.Width, $panel.Height
    $top = [System.Drawing.Color]::FromArgb(10, 36, 99)
    $bottom = [System.Drawing.Color]::FromArgb(0, 150, 190)
    $g.FillRectangle((New-Object System.Drawing.Drawing2D.LinearGradientBrush $area, $top, $bottom, 90), $area)
    $g.DrawImage($logo, (22 * $k), (70 * $k), (120 * $k), (120 * $k))
    $font = New-Object System.Drawing.Font 'Segoe UI Semibold', (17 * $k), ([System.Drawing.FontStyle]::Regular), ([System.Drawing.GraphicsUnit]::Pixel)
    $center = New-Object System.Drawing.StringFormat
    $center.Alignment = 'Center'
    $g.DrawString('SplitHello', $font, [System.Drawing.Brushes]::White,
        (New-Object System.Drawing.RectangleF 0, (200 * $k), $panel.Width, (30 * $k)), $center)
    $panel.Save("$gen\wizard-$scale.bmp", [System.Drawing.Imaging.ImageFormat]::Bmp)
    $g.Dispose(); $panel.Dispose()

    # Header badge on the inner pages, 55x55 at 100%.
    $badge, $g = New-Canvas (55 * $k) (55 * $k)
    $g.Clear([System.Drawing.Color]::White)
    $g.DrawImage($logo, 0, 0, $badge.Width, $badge.Height)
    $badge.Save("$gen\small-$scale.bmp", [System.Drawing.Imaging.ImageFormat]::Bmp)
    $g.Dispose(); $badge.Dispose()
}
$logo.Dispose()

& $iscc "/DAppVersion=$Version" "/DBuildDir=$((Resolve-Path $BuildDir).Path)" (Join-Path $PSScriptRoot 'splithello.iss')
if ($LASTEXITCODE -ne 0) { throw "ISCC failed with exit code $LASTEXITCODE" }
