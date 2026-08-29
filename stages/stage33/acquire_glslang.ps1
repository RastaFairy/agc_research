[CmdletBinding()]
param(
    [string]$Version = "16.5.0"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$StageDir    = (Resolve-Path -LiteralPath (Split-Path -Parent $MyInvocation.MyCommand.Path)).Path
$ThirdParty  = Join-Path $StageDir "third_party"
$DownloadDir = Join-Path $ThirdParty "downloads"
$ExtractDir  = Join-Path $ThirdParty "_extract_glslang_$Version"
$InstallDir  = Join-Path $ThirdParty "glslang-$Version"

New-Item -ItemType Directory -Force -Path $ThirdParty  | Out-Null
New-Item -ItemType Directory -Force -Path $DownloadDir | Out-Null

Write-Host ""
Write-Host "==> Query Khronos glslang $Version" -ForegroundColor Cyan

$ApiUrl = "https://api.github.com/repos/KhronosGroup/glslang/releases/tags/$Version"

$Headers = @{
    "Accept"     = "application/vnd.github+json"
    "User-Agent" = "agc-ps5-stage33"
}

$Release = Invoke-RestMethod `
    -Uri $ApiUrl `
    -Headers $Headers `
    -Method Get

if ($Release.tag_name -ne $Version) {
    throw "Requested $Version but received $($Release.tag_name)."
}

Write-Host "Release: $($Release.tag_name)"
Write-Host "URL:     $($Release.html_url)"

$AssetName = "glslang-$Version-windows-x86_64-release.zip"

$Asset = @($Release.assets) |
    Where-Object { $_.name -eq $AssetName } |
    Select-Object -First 1

if (-not $Asset) {
    throw "Official asset not found: $AssetName"
}

$ZipPath = Join-Path $DownloadDir $Asset.name

Write-Host ""
Write-Host "==> Download"

if (-not (Test-Path -LiteralPath $ZipPath -PathType Leaf)) {
    Invoke-WebRequest `
        -Uri $Asset.browser_download_url `
        -Headers @{ "User-Agent" = "agc-ps5-stage33" } `
        -OutFile $ZipPath
}
else {
    Write-Host "Using existing download:"
    Write-Host "  $ZipPath"
}

$ZipHash = (
    Get-FileHash `
        -LiteralPath $ZipPath `
        -Algorithm SHA256
).Hash.ToLowerInvariant()

Write-Host "SHA256=$ZipHash"

Write-Host ""
Write-Host "==> Extract"

if (Test-Path -LiteralPath $ExtractDir) {
    Remove-Item -LiteralPath $ExtractDir -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $ExtractDir | Out-Null

Expand-Archive `
    -LiteralPath $ZipPath `
    -DestinationPath $ExtractDir `
    -Force

$ExtractedGlslang = Get-ChildItem `
    -Path $ExtractDir `
    -Filter "glslang.exe" `
    -Recurse `
    -File `
    -ErrorAction SilentlyContinue |
    Select-Object -First 1

if (-not $ExtractedGlslang) {
    throw "glslang.exe was not found after extraction."
}

Write-Host ""
Write-Host "Found:"
Write-Host "  $($ExtractedGlslang.FullName)"

Write-Host ""
Write-Host "==> Install"

if (Test-Path -LiteralPath $InstallDir) {
    Remove-Item -LiteralPath $InstallDir -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

# IMPORTANT:
# Use -Path, not -LiteralPath, because the source deliberately contains '*'.
$ExtractedItems = Get-ChildItem `
    -Path $ExtractDir `
    -Force

foreach ($Item in $ExtractedItems) {
    Copy-Item `
        -Path $Item.FullName `
        -Destination $InstallDir `
        -Recurse `
        -Force
}

$InstalledGlslang = Get-ChildItem `
    -Path $InstallDir `
    -Filter "glslang.exe" `
    -Recurse `
    -File `
    -ErrorAction SilentlyContinue |
    Select-Object -First 1

if (-not $InstalledGlslang) {
    throw "Installation completed but glslang.exe was not found."
}

Write-Host ""
Write-Host "Installed:"
Write-Host "  $($InstalledGlslang.FullName)"

Write-Host ""
Write-Host "==> Version"

& $InstalledGlslang.FullName --version

if ($LASTEXITCODE -ne 0) {
    throw "glslang.exe --version failed with exit code $LASTEXITCODE."
}

$BinaryHash = (
    Get-FileHash `
        -LiteralPath $InstalledGlslang.FullName `
        -Algorithm SHA256
).Hash.ToLowerInvariant()

$Manifest = [ordered]@{
    requested_version = $Version
    release_tag       = $Release.tag_name
    release_url       = $Release.html_url
    asset_name        = $Asset.name
    asset_url         = $Asset.browser_download_url
    zip_path          = $ZipPath
    zip_sha256        = $ZipHash
    installed_binary  = $InstalledGlslang.FullName
    binary_sha256     = $BinaryHash
}

$Manifest |
    ConvertTo-Json -Depth 5 |
    Set-Content `
        -LiteralPath (Join-Path $InstallDir "INSTALL_MANIFEST.json") `
        -Encoding UTF8

Write-Host ""
Write-Host "SUCCESS" -ForegroundColor Green
Write-Host "glslang $Version installed correctly."
Write-Host ""