[CmdletBinding()]
param(
    [string]$SprxPath = "D:\agc_work\sce_stubs\libSceAgcDriver.sprx",
    [string]$OutDir   = "D:\agc_work\stage43_results"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Write-Step {
    param([string]$Message)

    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Info {
    param([string]$Message)

    Write-Host "[INFO] $Message"
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

    $Command = $Command -replace "`r`n", "`n"
    $Command = $Command -replace "`r", ""

    Write-Host ""
    Write-Host "[WSL] $Command" -ForegroundColor DarkCyan

    $Output = & wsl.exe `
        -d Ubuntu-24.04 `
        --cd / `
        -- bash -lc $Command 2>&1

    $ExitCode = $LASTEXITCODE

    foreach ($Line in $Output) {
        Write-Host $Line
    }

    if ($ExitCode -ne 0) {
        throw "WSL command failed with exit code $ExitCode."
    }

    return @($Output)
}

function Get-Sha256 {
    param([string]$Path)

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
# Input validation
# ============================================================

if (-not (Test-Path -LiteralPath $SprxPath -PathType Leaf)) {
    throw "SPRX not found: $SprxPath"
}

$SprxPath = (Resolve-Path -LiteralPath $SprxPath).Path

if (Test-Path -LiteralPath $OutDir) {
    Remove-Item -LiteralPath $OutDir -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$SprxUnix = Convert-ToWslPath $SprxPath
$OutUnix  = Convert-ToWslPath $OutDir

$TmpRoot = "/tmp/agc_stage43"

# ============================================================
# Python static analysis program
# ============================================================

$PythonLocal = Join-Path $OutDir "analyze_submitdcb.py"

$PythonCode = @'
from elftools.elf.elffile import ELFFile
import json
import os
import struct
import sys

sprx = sys.argv[1]
out_dir = sys.argv[2]

TARGET_NID = "UglJIZjGssM"
TARGET_VA  = 0x28b0

# Bytes from Stage 42:
# 48 89 fe
# 48 8d 3d fe 7f 01 00
# e9 f1 ef ff ff

JMP_DISP = struct.unpack("<i", bytes.fromhex("f1 ef ff ff"))[0]

# jmp is 5 bytes and starts at VA 0x28ba.
JMP_NEXT = TARGET_VA + 10 + 5
JMP_TARGET = JMP_NEXT + JMP_DISP

# lea starts at VA 0x28b3.
# Its instruction is 7 bytes.
LEA_NEXT = TARGET_VA + 3 + 7
LEA_DISP = 0x17ffe
LEA_TARGET = LEA_NEXT + LEA_DISP

with open(sprx, "rb") as f:
    elf = ELFFile(f)

    # --------------------------------------------------------
    # Symbol data from PT_DYNAMIC, same mechanism as genstub.
    # --------------------------------------------------------

    dynamic = None

    for seg in elf.iter_segments():
        if seg.header.p_type == "PT_DYNAMIC":
            dynamic = seg
            break

    if dynamic is None:
        raise RuntimeError("No PT_DYNAMIC")

    dynamic_symbols = []

    for sym in dynamic.iter_symbols():

        name = sym.name

        if not name:
            continue

        value = int(sym["st_value"])
        size = int(sym["st_size"])

        dynamic_symbols.append({
            "name": name,
            "value": value,
            "size": size,
            "type": str(sym["st_info"]["type"]),
            "bind": str(sym["st_info"]["bind"])
        })

    # --------------------------------------------------------
    # Map VA -> file offset.
    # --------------------------------------------------------

    def va_to_file_offset(va):
        for seg in elf.iter_segments():

            if seg.header.p_type != "PT_LOAD":
                continue

            vaddr = int(seg.header.p_vaddr)
            memsz = int(seg.header.p_memsz)
            offset = int(seg.header.p_offset)

            if vaddr <= va < vaddr + memsz:
                return offset + (va - vaddr)

        return None

    # --------------------------------------------------------
    # Read bytes around branch target and LEA target.
    # --------------------------------------------------------

    analyses = {}

    for label, va, size in [
        ("submit_export", TARGET_VA, 15),
        ("jmp_target", JMP_TARGET, 128),
        ("lea_target", LEA_TARGET, 128)
    ]:

        off = va_to_file_offset(va)

        entry = {
            "va": va,
            "file_offset": off,
            "read_size": size,
            "bytes_hex": None
        }

        if off is not None:

            f.seek(off)
            data = f.read(size)

            entry["bytes_hex"] = data.hex(" ")
            entry["bytes_count"] = len(data)

        analyses[label] = entry

    # --------------------------------------------------------
    # Find dynamic exports/symbols around calculated targets.
    # --------------------------------------------------------

    def nearby_symbols(target, radius=256):

        result = []

        for sym in dynamic_symbols:

            if not sym["name"]:
                continue

            value = sym["value"]
            delta = value - target

            if -radius <= delta <= radius:

                result.append({
                    "delta": delta,
                    "value": value,
                    "size": sym["size"],
                    "type": sym["type"],
                    "bind": sym["bind"],
                    "name": sym["name"]
                })

        result.sort(
            key=lambda x: (x["value"], x["name"])
        )

        return result

    nearby_jmp = nearby_symbols(JMP_TARGET, 512)
    nearby_lea = nearby_symbols(LEA_TARGET, 512)

    result = {
        "submit_dcb": {
            "nid": TARGET_NID,
            "va": TARGET_VA,
            "size": 15
        },

        "decoded": {
            "jmp_displacement": JMP_DISP,
            "jmp_next": JMP_NEXT,
            "jmp_target": JMP_TARGET,

            "lea_displacement": LEA_DISP,
            "lea_next": LEA_NEXT,
            "lea_target": LEA_TARGET
        },

        "analyses": analyses,

        "nearby_jmp_symbols": nearby_jmp,
        "nearby_lea_symbols": nearby_lea
    }

with open(
    os.path.join(out_dir, "stage43_static.json"),
    "w",
    encoding="utf-8"
) as fp:
    json.dump(result, fp, indent=2)

print(json.dumps(result, indent=2))
'@

$PythonCode = $PythonCode -replace "`r`n", "`n"
$PythonCode = $PythonCode -replace "`r", ""

[System.IO.File]::WriteAllText(
    $PythonLocal,
    $PythonCode,
    [System.Text.UTF8Encoding]::new($false)
)

$PythonUnix = Convert-ToWslPath $PythonLocal

# ============================================================
# Banner
# ============================================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "AGC PS5 Stage 43 - SubmitDcb Target Analysis" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Info "SPRX      = $SprxPath"
Write-Info "SPRX WSL  = $SprxUnix"
Write-Info "Output    = $OutDir"
Write-Info "Output WSL= $OutUnix"
Write-Info "Submit VA = 0x28b0"
Write-Info "Submit NID= UglJIZjGssM"

try {

    # ========================================================
    # Prepare Linux workspace
    # ========================================================

    Write-Step "Prepare Linux workspace"

    Invoke-WslChecked @"
rm -rf '$TmpRoot'
mkdir -p '$TmpRoot'
mkdir -p '$OutUnix'
cp '$PythonUnix' '$TmpRoot/analyze_submitdcb.py'
python3 -m py_compile '$TmpRoot/analyze_submitdcb.py'
"@ | Out-Null

    # ========================================================
    # Static ELF analysis
    # ========================================================

    Write-Step "Decode SubmitDcb thunk targets"

    Invoke-WslChecked @"
python3 '$TmpRoot/analyze_submitdcb.py' '$SprxUnix' '$TmpRoot'
"@ | Out-Null

    # ========================================================
    # Copy report
    # ========================================================

    Write-Step "Collect static analysis"

    Invoke-WslChecked @"
cp '$TmpRoot/stage43_static.json' '$OutUnix/stage43_static.json'
cat '$TmpRoot/stage43_static.json'
"@ | Out-Null

    # ========================================================
    # Native objdump around the internal target
    # ========================================================

    Write-Step "Disassemble internal SubmitDcb target region"

    Invoke-WslChecked @"
objdump \
    -D \
    '$SprxUnix' \
    --start-address=0x1800 \
    --stop-address=0x1b00 \
    > '$TmpRoot/target_disassembly.txt' 2>&1

cp '$TmpRoot/target_disassembly.txt' '$OutUnix/target_disassembly.txt'

cat '$TmpRoot/target_disassembly.txt'
"@ | Out-Null

    # ========================================================
    # Dump bytes around target and context object
    # ========================================================

    Write-Step "Inspect raw mapped regions"

    Invoke-WslChecked @"
objdump \
    -s \
    '$SprxUnix' \
    --start-address=0x1800 \
    --stop-address=0x1b00 \
    > '$TmpRoot/target_raw.txt' 2>&1 || true

cp '$TmpRoot/target_raw.txt' '$OutUnix/target_raw.txt'
"@ | Out-Null

    # ========================================================
    # Search for references to the internal target value.
    # ========================================================

    Write-Step "Search nearby symbols and references"

    Invoke-WslChecked @"
grep -n -E '28b0|28c0|2910|18b0|1a8b8' \
    '$OutUnix/target_disassembly.txt' \
    > '$OutUnix/target_matches.txt' || true

cat '$OutUnix/target_matches.txt' 2>/dev/null || true
"@ | Out-Null

    # ========================================================
    # Hash artefacts
    # ========================================================

    Write-Step "Hash artefacts"

    $ArtifactNames = @(
        "stage43_static.json",
        "target_disassembly.txt",
        "target_raw.txt",
        "target_matches.txt"
    )

    $Artifacts = @()

    foreach ($Name in $ArtifactNames) {

        $Path = Join-Path $OutDir $Name

        if (Test-Path -LiteralPath $Path -PathType Leaf) {

            $Item = Get-Item -LiteralPath $Path

            $Hash = Get-Sha256 $Path

            $Artifacts += [ordered]@{
                file   = $Name
                size   = $Item.Length
                sha256 = $Hash
            }

            Write-Info "$Name SHA256=$Hash"
        }
    }

    # ========================================================
    # Final report
    # ========================================================

    $StaticPath = Join-Path $OutDir "stage43_static.json"

    $Static = (
        Get-Content `
            -LiteralPath $StaticPath `
            -Raw
    ) | ConvertFrom-Json

    $Report = [ordered]@{
        stage = 43

        timestamp = (Get-Date).ToString("o")

        target = [ordered]@{
            name = "sceAgcDriverSubmitDcb"
            nid  = "UglJIZjGssM"
            va   = "0x28b0"
            size = 15
        }

        decoded = $Static.decoded

        execution = [ordered]@{
            performed = $false
        }

        prototype = [ordered]@{
            inferred = $false
        }

        artifacts = $Artifacts
    }

    $ReportPath = Join-Path $OutDir "STAGE43_REPORT.json"

    $Report |
        ConvertTo-Json -Depth 12 |
        Set-Content `
            -LiteralPath $ReportPath `
            -Encoding UTF8

    Write-Host ""
    Write-Host "============================================" -ForegroundColor Green
    Write-Host "Stage 43 completed" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "SUBMIT_DCB_THUNK_DECODED = PASS" -ForegroundColor Green
    Write-Host "EXECUTED_SUBMIT_DCB = NO" -ForegroundColor Green
    Write-Host "ABI_PROTOTYPE_INFERRED = NO" -ForegroundColor Green
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

    throw
}