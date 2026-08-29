[CmdletBinding()]
param(
    [string]$StageDir = "D:\agc_ps5_stage40",
    [string]$StubDir  = "D:\agc_work\sce_stubs",
    [string]$OutDir   = "D:\agc_work\stage40_results",
    [string]$Sdk      = "/opt/ps5-payload-sdk"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# ============================================================
# Resolve Windows paths
# ============================================================

$StageDir = (Resolve-Path -LiteralPath $StageDir).Path
$StubDir  = (Resolve-Path -LiteralPath $StubDir).Path

if (Test-Path -LiteralPath $OutDir) {
    Remove-Item -LiteralPath $OutDir -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

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
        throw "WSL command failed with exit code $ExitCode.`n$Command"
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
# Inputs
# ============================================================

$ProbeC  = Join-Path $StageDir "stage40_probe.c"
$DriverO = Join-Path $StubDir "libSceAgcDriver.o"

if (-not (Test-Path -LiteralPath $ProbeC -PathType Leaf)) {
    throw "Missing probe source: $ProbeC"
}

if (-not (Test-Path -LiteralPath $DriverO -PathType Leaf)) {
    throw "Missing AGC Driver object: $DriverO"
}

# ============================================================
# Windows -> WSL paths
# ============================================================

$StageUnix = Convert-ToWslPath -WindowsPath $StageDir
$StubUnix  = Convert-ToWslPath -WindowsPath $StubDir
$OutUnix   = Convert-ToWslPath -WindowsPath $OutDir

$ProbeUnix  = "$StageUnix/stage40_probe.c"
$DriverUnix = "$StubUnix/libSceAgcDriver.o"
$MakeUnix   = "$StageUnix/stage40_sdk.mk"

# Linux temporary build workspace
$TmpRoot      = "/tmp/agc_stage40"
$TmpProbe     = "$TmpRoot/stage40_probe.c"
$TmpProbeO    = "$TmpRoot/stage40_probe.o"
$TmpDriverO   = "$TmpRoot/libSceAgcDriver.o"
$TmpMake      = "$TmpRoot/Makefile"
$TmpBuildLog  = "$TmpRoot/build.log"

$FinalElfUnix = "$OutUnix/stage40_probe.elf"

# ============================================================
# Banner
# ============================================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "AGC PS5 Stage 40 - Complete ELF Link Test" -ForegroundColor Cyan
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
    # Create Makefile safely in PowerShell
    # ========================================================

    Write-Step "Create SDK-native Makefile"

    $Tab = [char]9

    $MakeLines = @(
        'PS5_PAYLOAD_SDK := /opt/ps5-payload-sdk'
        'include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk'
        ''
        'CFLAGS := -O0 -g -Wall -Werror -ffreestanding -fno-builtin -fPIC -fno-stack-protector'
        'ELF := stage40_probe.elf'
        'OBJS := stage40_probe.o libSceAgcDriver.o'
        ''
        'all: $(ELF)'
        ''
        '$(ELF): $(OBJS)'
        ($Tab + '$(CC) $(CFLAGS) -o $@ $(OBJS)')
        ''
        'stage40_probe.o: stage40_probe.c'
        ($Tab + '$(CC) $(CFLAGS) -c $< -o $@')
        ''
        'clean:'
        ($Tab + 'rm -f stage40_probe.o stage40_probe.elf')
    )

    $MakeText = $MakeLines -join "`n"

    $MakeWindows = Join-Path $StageDir "stage40_sdk.mk"

    Set-Content `
        -LiteralPath $MakeWindows `
        -Value $MakeText `
        -Encoding UTF8 `
        -NoNewline

    Write-Info "Makefile:"
    Write-Host ""
    Get-Content -LiteralPath $MakeWindows
    Write-Host ""

    # ========================================================
    # Prepare Linux workspace
    # ========================================================

    Write-Step "Prepare Linux workspace"

    Invoke-WslChecked @"
rm -rf '$TmpRoot' &&
mkdir -p '$TmpRoot' '$OutUnix' &&
cp '$ProbeUnix' '$TmpProbe' &&
cp '$DriverUnix' '$TmpDriverO' &&
cp '$MakeUnix' '$TmpMake' &&
ls -lh '$TmpProbe' '$TmpDriverO' '$TmpMake'
"@

    # ========================================================
    # Verify SDK
    # ========================================================

    Write-Step "Verify SDK"

    Invoke-WslChecked @"
test -x '$Sdk/bin/prospero-clang' &&
test -x '$Sdk/bin/prospero-llvm-config' &&
test -x '$Sdk/bin/prospero-lld' &&
test -f '$Sdk/target/lib/crt1.o' &&
test -f '$Sdk/ldscripts/elf_x86_64.x' &&
echo '--- prospero-clang ---' &&
'$Sdk/bin/prospero-clang' --version &&
echo '--- prospero-llvm-config ---' &&
'$Sdk/bin/prospero-llvm-config' --version &&
echo '--- Makefile ---' &&
cat '$TmpMake'
"@

    # ========================================================
    # Build complete ELF
    # ========================================================

    Write-Step "Build complete ELF with prospero.mk"

    Invoke-WslChecked @"
cd '$TmpRoot' &&
make -f '$TmpMake' clean &&
make -f '$TmpMake' all > '$TmpBuildLog' 2>&1
"@

    # ========================================================
    # Verify ELF
    # ========================================================

    Write-Step "Verify ELF"

    Invoke-WslChecked @"
test -f '$TmpRoot/stage40_probe.elf' &&
file '$TmpRoot/stage40_probe.elf' &&
ls -lh '$TmpRoot/stage40_probe.elf'
"@

    # ========================================================
    # Inspect ELF header
    # ========================================================

    Write-Step "Inspect ELF header"

    Invoke-WslChecked @"
readelf -h '$TmpRoot/stage40_probe.elf' > '$TmpRoot/elf_header.txt' &&
cat '$TmpRoot/elf_header.txt'
"@

    # ========================================================
    # Inspect symbols
    # ========================================================

    Write-Step "Inspect symbols"

    Invoke-WslChecked @"
'$Sdk/bin/prospero-nm' -C '$TmpRoot/stage40_probe.elf' |
    grep -E 'sceAgcDriverSubmitDcb|stage40_probe' |
    sort > '$TmpRoot/elf_symbols.txt' || true

cat '$TmpRoot/elf_symbols.txt'
"@

    # ========================================================
    # Inspect dynamic information
    # ========================================================

    Write-Step "Inspect ELF dynamic information"

    Invoke-WslChecked @"
readelf -d '$TmpRoot/stage40_probe.elf' > '$TmpRoot/elf_dynamic.txt' 2>&1 || true
cat '$TmpRoot/elf_dynamic.txt'
"@

    # ========================================================
    # Collect results
    # ========================================================

    Write-Step "Collect Stage 40 artefacts"

    Invoke-WslChecked @"
cp '$TmpRoot/stage40_probe.elf' '$FinalElfUnix' &&
cp '$TmpRoot/stage40_probe.o' '$OutUnix/stage40_probe.o' &&
cp '$TmpRoot/libSceAgcDriver.o' '$OutUnix/libSceAgcDriver.o' &&
cp '$TmpRoot/Makefile' '$OutUnix/stage40_Makefile' &&
cp '$TmpRoot/build.log' '$OutUnix/build.log' &&
cp '$TmpRoot/elf_header.txt' '$OutUnix/elf_header.txt' &&
cp '$TmpRoot/elf_symbols.txt' '$OutUnix/elf_symbols.txt' &&
cp '$TmpRoot/elf_dynamic.txt' '$OutUnix/elf_dynamic.txt'
"@

    # ========================================================
    # Windows-side verification
    # ========================================================

    $ElfPath    = Join-Path $OutDir "stage40_probe.elf"
    $SymbolPath = Join-Path $OutDir "elf_symbols.txt"

    if (-not (Test-Path -LiteralPath $ElfPath -PathType Leaf)) {
        throw "stage40_probe.elf was not produced."
    }

    $Symbols = @()

    if (Test-Path -LiteralPath $SymbolPath -PathType Leaf) {
        $Symbols = @(
            Get-Content -LiteralPath $SymbolPath
        )
    }

    $SubmitInElf = (
        @(
            $Symbols |
                Where-Object {
                    $_ -match "sceAgcDriverSubmitDcb"
                }
        ).Count -gt 0
    )

    # ELF magic
    $Bytes = [IO.File]::ReadAllBytes($ElfPath)

    $ElfMagic =
        $Bytes.Length -ge 4 -and
        $Bytes[0] -eq 0x7F -and
        $Bytes[1] -eq 0x45 -and
        $Bytes[2] -eq 0x4C -and
        $Bytes[3] -eq 0x46

    # ========================================================
    # Hash artifacts
    # ========================================================

    Write-Step "Hash artefacts"

    $ArtifactNames = @(
        "stage40_probe.elf",
        "stage40_probe.o",
        "libSceAgcDriver.o",
        "stage40_sdk.mk",
        "stage40_Makefile",
        "build.log",
        "elf_header.txt",
        "elf_symbols.txt",
        "elf_dynamic.txt"
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
        stage = 40

        timestamp = (Get-Date).ToString("o")

        elf = [ordered]@{
            built           = $true
            valid_elf_magic = $ElfMagic
            submit_dcb      = $SubmitInElf
            executed        = $false
        }

        submit_dcb = [ordered]@{
            name = "sceAgcDriverSubmitDcb"
            nid  = "UglJIZjGssM"
        }

        target = [ordered]@{
            triple = "x86_64-sie-ps5"
            sdk    = $Sdk
        }

        artifacts = $Artifacts
    }

    $ReportPath = Join-Path $OutDir "STAGE40_REPORT.json"

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
    Write-Host "Stage 40 result" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green

    if ($ElfMagic) {
        Write-Host "STAGE40_ELF_BUILT = TRUE" -ForegroundColor Green
    }
    else {
        Write-Host "STAGE40_ELF_BUILT = FALSE" -ForegroundColor Red
    }

    if ($SubmitInElf) {
        Write-Host "SUBMIT_DCB_IN_ELF = TRUE" -ForegroundColor Green
    }
    else {
        Write-Host "SUBMIT_DCB_IN_ELF = FALSE" -ForegroundColor Yellow
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

    $BuildLogPath = Join-Path $OutDir "build.log"

    if (Test-Path -LiteralPath $BuildLogPath -PathType Leaf) {
        Write-Host ""
        Write-Host "========== build.log ==========" -ForegroundColor Yellow
        Get-Content -LiteralPath $BuildLogPath
        Write-Host "===============================" -ForegroundColor Yellow
    }

    throw
}