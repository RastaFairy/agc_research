[CmdletBinding()]
param(
    [string]$StageDir = "D:\agc_ps5_stage39",
    [string]$StubDir  = "D:\agc_work\sce_stubs",
    [string]$OutDir   = "D:\agc_work\stage39_results",
    [string]$Sdk      = "/opt/ps5-payload-sdk"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# ============================================================
# Resolve Windows paths
# ============================================================

$StageDir = (Resolve-Path -LiteralPath $StageDir).Path
$StubDir  = (Resolve-Path -LiteralPath $StubDir).Path

if (-not (Test-Path -LiteralPath $OutDir)) {
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
}
else {
    Remove-Item -LiteralPath $OutDir -Recurse -Force
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
}

# ============================================================
# Helpers
# ============================================================

function Write-Step {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Info {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host "[INFO] $Message"
}

function Write-Warn {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Convert-ToWslPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$WindowsPath
    )

    $Resolved = (Resolve-Path -LiteralPath $WindowsPath).Path

    if ($Resolved -notmatch '^(?<drive>[A-Za-z]):\\(?<rest>.*)$') {
        throw "Unsupported Windows path: $Resolved"
    }

    $Drive = $Matches.drive.ToLowerInvariant()
    $Rest  = $Matches.rest -replace '\\', '/'

    return "/mnt/$Drive/$Rest"
}

function Invoke-WslChecked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command
    )

    Write-Host ""
    Write-Host "[WSL] $Command" -ForegroundColor DarkCyan

    & wsl.exe `
        -d Ubuntu-24.04 `
        --cd / `
        -- bash -lc $Command |
        ForEach-Object {
            Write-Host $_
        }

    $ExitCode = $LASTEXITCODE

    if ($ExitCode -ne 0) {
        throw "WSL command failed with exit code $ExitCode."
    }
}

function Get-Sha256 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }

    return (
        Get-FileHash `
            -LiteralPath $Path `
            -Algorithm SHA256
    ).Hash.ToLowerInvariant()
}

# ============================================================
# Validate inputs
# ============================================================

$ProbeC  = Join-Path $StageDir "stage39_probe.c"
$DriverO = Join-Path $StubDir "libSceAgcDriver.o"

if (-not (Test-Path -LiteralPath $ProbeC -PathType Leaf)) {
    throw "Missing probe source: $ProbeC"
}

if (-not (Test-Path -LiteralPath $DriverO -PathType Leaf)) {
    throw "Missing AGC Driver object: $DriverO"
}

# ============================================================
# Convert Windows paths to WSL paths
# ============================================================

$StageUnix = Convert-ToWslPath -WindowsPath $StageDir
$StubUnix  = Convert-ToWslPath -WindowsPath $StubDir
$OutUnix   = Convert-ToWslPath -WindowsPath $OutDir

$ProbeUnix  = "$StageUnix/stage39_probe.c"
$DriverUnix = "$StubUnix/libSceAgcDriver.o"

# ============================================================
# Linux temporary workspace
# ============================================================

$TmpRoot       = "/tmp/agc_stage39"
$TmpProbe      = "$TmpRoot/stage39_probe.c"
$TmpProbeO     = "$TmpRoot/stage39_probe.o"
$TmpDriverO    = "$TmpRoot/libSceAgcDriver.o"
$TmpLinkedO    = "$TmpRoot/stage39_linked.o"
$TmpSymbols    = "$TmpRoot/linked_symbols.txt"
$TmpCompileLog = "$TmpRoot/probe_compile.log"
$TmpLinkLog    = "$TmpRoot/partial_link.log"

# ============================================================
# Banner
# ============================================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "AGC PS5 Stage 39 - Native Stub Link Test" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Info "StageDir      = $StageDir"
Write-Info "StubDir       = $StubDir"
Write-Info "OutDir        = $OutDir"
Write-Info "Stage WSL     = $StageUnix"
Write-Info "Stub WSL      = $StubUnix"
Write-Info "Output WSL    = $OutUnix"
Write-Info "SDK           = $Sdk"
Write-Info "Probe         = $ProbeC"
Write-Info "Driver object = $DriverO"

try {

    # ========================================================
    # Prepare Linux workspace
    # ========================================================

    Write-Step "Prepare Linux build workspace"

    Invoke-WslChecked @"
rm -rf '$TmpRoot' &&
mkdir -p '$TmpRoot' &&
cp '$ProbeUnix' '$TmpProbe' &&
cp '$DriverUnix' '$TmpDriverO' &&
ls -lh '$TmpProbe' '$TmpDriverO'
"@

    # ========================================================
    # Verify Prospero toolchain
    # ========================================================

    Write-Step "Verify Prospero toolchain"

    Invoke-WslChecked @"
test -x '$Sdk/bin/prospero-clang' &&
test -x '$Sdk/bin/prospero-llvm-config' &&
test -x '$Sdk/bin/prospero-lld' &&
echo '--- prospero-clang ---' &&
'$Sdk/bin/prospero-clang' --version &&
echo '--- prospero-llvm-config ---' &&
'$Sdk/bin/prospero-llvm-config' --version &&
echo '--- prospero-lld ---' &&
'$Sdk/bin/prospero-lld' --version
"@

    # ========================================================
    # Compile probe source
    # ========================================================

    Write-Step "Compile stage39_probe.c"

    Invoke-WslChecked @"
'$Sdk/bin/prospero-clang' \
    -ffreestanding \
    -fno-builtin \
    -nostdlib \
    -fPIC \
    -target x86_64-sie-ps5 \
    -fno-plt \
    -fno-stack-protector \
    -Wall \
    -Werror \
    -fvisibility-nodllstorageclass=default \
    -c '$TmpProbe' \
    -o '$TmpProbeO' \
    >'$TmpCompileLog' 2>&1
"@

    Invoke-WslChecked @"
ls -lh '$TmpProbeO'
"@

    # ========================================================
    # Partial link
    #
    # IMPORTANT:
    # Use prospero-lld directly.
    # We deliberately use -r so this is a relocatable link.
    # No CRT, libc or payload runtime is involved.
    # ========================================================

    Write-Step "Partial link probe + libSceAgcDriver.o"

    Invoke-WslChecked @"
'$Sdk/bin/prospero-lld' \
    -r \
    '$TmpProbeO' \
    '$TmpDriverO' \
    -o '$TmpLinkedO' \
    >'$TmpLinkLog' 2>&1
"@

    Invoke-WslChecked @"
ls -lh '$TmpLinkedO'
"@

    # ========================================================
    # Inspect linked symbols
    # ========================================================

    Write-Step "Inspect linked symbols"

    Invoke-WslChecked @"
'$Sdk/bin/prospero-nm' -C '$TmpLinkedO' |
    grep -E 'sceAgcDriverSubmitDcb|stage39_probe' |
    sort > '$TmpSymbols'
"@

    Invoke-WslChecked @"
cat '$TmpSymbols'
"@

    # ========================================================
    # Collect artefacts
    # ========================================================

    Write-Step "Collect Stage 39 artefacts"

    Invoke-WslChecked @"
mkdir -p '$OutUnix' &&
cp '$TmpProbe' '$OutUnix/stage39_probe.c' &&
cp '$TmpProbeO' '$OutUnix/stage39_probe.o' &&
cp '$TmpDriverO' '$OutUnix/libSceAgcDriver.o' &&
cp '$TmpLinkedO' '$OutUnix/stage39_linked.o' &&
cp '$TmpSymbols' '$OutUnix/linked_symbols.txt' &&
cp '$TmpCompileLog' '$OutUnix/probe_compile.log' &&
cp '$TmpLinkLog' '$OutUnix/partial_link.log'
"@

    # ========================================================
    # Verify result
    # ========================================================

    $LinkedSymbolsPath = Join-Path $OutDir "linked_symbols.txt"

    if (-not (Test-Path -LiteralPath $LinkedSymbolsPath -PathType Leaf)) {
        throw "linked_symbols.txt was not produced."
    }

    $LinkedSymbols = @(
        Get-Content -LiteralPath $LinkedSymbolsPath
    )

    $SubmitLinked = (
        @(
            $LinkedSymbols |
                Where-Object {
                    $_ -match "sceAgcDriverSubmitDcb"
                }
        ).Count -gt 0
    )

    $ProbeLinked = (
        @(
            $LinkedSymbols |
                Where-Object {
                    $_ -match "stage39_probe"
                }
        ).Count -gt 0
    )

    # ========================================================
    # Hash artifacts
    # ========================================================

    Write-Step "Hash artefacts"

    $ArtifactNames = @(
        "stage39_probe.c",
        "stage39_probe.o",
        "libSceAgcDriver.o",
        "stage39_linked.o",
        "linked_symbols.txt",
        "probe_compile.log",
        "partial_link.log"
    )

    $Artifacts = @()

    foreach ($Name in $ArtifactNames) {

        $Path = Join-Path $OutDir $Name

        if (Test-Path -LiteralPath $Path -PathType Leaf) {

            $Item = Get-Item -LiteralPath $Path

            $Artifacts += [ordered]@{
                file   = $Name
                size   = $Item.Length
                sha256 = Get-Sha256 -Path $Path
            }
        }
    }

    # ========================================================
    # Report
    # ========================================================

    $Report = [ordered]@{
        stage = 39

        timestamp = (Get-Date).ToString("o")

        submit_dcb = [ordered]@{
            name   = "sceAgcDriverSubmitDcb"
            nid    = "UglJIZjGssM"
            linked = $SubmitLinked
        }

        probe = [ordered]@{
            linked = $ProbeLinked
        }

        execution = [ordered]@{
            performed = $false
        }

        link = [ordered]@{
            mode   = "relocatable"
            target = "x86_64-sie-ps5"
            linker = "prospero-lld"
            flags  = "-r"
        }

        sdk = $Sdk

        paths = [ordered]@{
            stage_windows  = $StageDir
            stage_wsl      = $StageUnix
            stub_windows   = $StubDir
            stub_wsl       = $StubUnix
            output_windows = $OutDir
            output_wsl     = $OutUnix
        }

        artifacts = $Artifacts
    }

    $ReportPath = Join-Path $OutDir "STAGE39_REPORT.json"

    $Report |
        ConvertTo-Json -Depth 10 |
        Set-Content `
            -LiteralPath $ReportPath `
            -Encoding UTF8

    # ========================================================
    # Final status
    # ========================================================

    Write-Host ""
    Write-Host "============================================" -ForegroundColor Green

    if ($SubmitLinked) {
        Write-Host "SUBMIT_DCB_LINKED = PASS" -ForegroundColor Green
    }
    else {
        Write-Host "SUBMIT_DCB_LINKED = FAIL" -ForegroundColor Red
    }

    if ($ProbeLinked) {
        Write-Host "PROBE_SYMBOL_LINKED = PASS" -ForegroundColor Green
    }
    else {
        Write-Host "PROBE_SYMBOL_LINKED = FAIL" -ForegroundColor Red
    }

    Write-Host "EXECUTED_SUBMIT_DCB = NO" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""

    Write-Host "Results:"
    Write-Host "  $OutDir"

    Write-Host ""
    Write-Host "Report:"
    Write-Host "  $ReportPath"
}
catch {

    Write-Host ""
    Write-Host "FATAL ERROR" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red

    # Preserve linker/compiler logs if they exist.
    Write-Host ""

    $CompileLogWin = Join-Path $OutDir "probe_compile.log"
    $LinkLogWin    = Join-Path $OutDir "partial_link.log"

    if (Test-Path -LiteralPath $CompileLogWin -PathType Leaf) {
        Write-Host "---- probe_compile.log ----" -ForegroundColor Yellow
        Get-Content -LiteralPath $CompileLogWin
        Write-Host "----------------------------" -ForegroundColor Yellow
    }

    if (Test-Path -LiteralPath $LinkLogWin -PathType Leaf) {
        Write-Host "---- partial_link.log ----" -ForegroundColor Yellow
        Get-Content -LiteralPath $LinkLogWin
        Write-Host "---------------------------" -ForegroundColor Yellow
    }

    throw
}