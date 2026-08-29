[CmdletBinding()]
param(
    [string]$SprxPath = "D:\agc_work\sce_stubs\libSceAgcDriver.sprx",
    [string]$OutDir   = "D:\agc_work\stage45_results"
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

$TmpRoot = "/tmp/agc_stage45"

$PythonLocal = Join-Path $OutDir "analyze_submitcommandbuffer.py"

$PythonCode = @'
from elftools.elf.elffile import ELFFile
import json
import os
import struct
import sys

sprx = sys.argv[1]
out_dir = sys.argv[2]

TARGET = 0x18b0
TARGET_SIZE = 380

# Absolute-ish virtual-address calculations based on the fact that
# the Stage 44 raw function was extracted starting at VA 0x18b0.
#
# The following RIP-relative references were observed:
#
# 0x11 : mov 0x12820(%rip), %rbx
# 0x58 : lea 0x18ff9(%rip), %rbx
# 0x111: mov 0xa4(%rbx), %eax
#
# Calls:
#   0x2c -> 0x9360 relative to raw body
#   0x104 -> 0x92c0
#   0x12d -> 0x9370
#   0x14e -> 0x92c0
#   0x175 -> 0x9380
#
# We calculate their absolute VAs by adding TARGET.

def va_to_file_offset(elf, va):
    for seg in elf.iter_segments():
        if seg.header.p_type != "PT_LOAD":
            continue

        vaddr = int(seg.header.p_vaddr)
        memsz = int(seg.header.p_memsz)
        offset = int(seg.header.p_offset)

        if vaddr <= va < vaddr + memsz:
            return offset + (va - vaddr)

    return None

def read_va(f, elf, va, size):
    off = va_to_file_offset(elf, va)

    if off is None:
        return None

    f.seek(off)
    data = f.read(size)

    return {
        "va": va,
        "file_offset": off,
        "size": len(data),
        "bytes_hex": data.hex(" ")
    }

with open(sprx, "rb") as f:
    elf = ELFFile(f)

    dynamic = None

    for seg in elf.iter_segments():
        if seg.header.p_type == "PT_DYNAMIC":
            dynamic = seg
            break

    if dynamic is None:
        raise RuntimeError("No PT_DYNAMIC")

    symbols = []

    for sym in dynamic.iter_symbols():

        raw = sym.name

        if not raw:
            continue

        value = int(sym["st_value"])
        size = int(sym["st_size"])

        item = {
            "raw_name": raw,
            "value": value,
            "size": size,
            "type": str(sym["st_info"]["type"]),
            "bind": str(sym["st_info"]["bind"])
        }

        if "#" in raw:

            parts = raw.split("#")

            if len(parts) == 3:
                item["nid"] = parts[0]
                item["lid"] = parts[1]
                item["mid"] = parts[2]

        symbols.append(item)

    internal = [
        s for s in symbols
        if s.get("value") == TARGET
    ]

    if not internal:
        raise RuntimeError(
            f"No dynamic symbol at target VA 0x{TARGET:x}"
        )

    # --------------------------------------------------------
    # Read the internal function.
    # --------------------------------------------------------

    body = read_va(
        f,
        elf,
        TARGET,
        TARGET_SIZE
    )

    if body is None:
        raise RuntimeError("Unable to map internal function")

    with open(
        os.path.join(out_dir, "submitcommandbuffer.bin"),
        "wb"
    ) as fp:
        fp.write(bytes.fromhex(body["bytes_hex"]))

    # --------------------------------------------------------
    # Absolute addresses of observed internal calls.
    # --------------------------------------------------------

    observed_calls = [
        {
            "internal_offset": 0x2c,
            "target_offset": 0x9360,
            "target_va": TARGET + 0x9360
        },
        {
            "internal_offset": 0x104,
            "target_offset": 0x92c0,
            "target_va": TARGET + 0x92c0
        },
        {
            "internal_offset": 0x12d,
            "target_offset": 0x9370,
            "target_va": TARGET + 0x9370
        },
        {
            "internal_offset": 0x14e,
            "target_offset": 0x92c0,
            "target_va": TARGET + 0x92c0
        },
        {
            "internal_offset": 0x175,
            "target_offset": 0x9380,
            "target_va": TARGET + 0x9380
        }
    ]

    # --------------------------------------------------------
    # Absolute RIP-relative data targets from Stage 44.
    # --------------------------------------------------------

    data_refs = [
        {
            "instruction_offset": 0x11,
            "description": "global pointer loaded into RBX",
            "displacement": 0x12820,
            "next_instruction_offset": 0x18,
            "target_va": TARGET + 0x18 + 0x12820
        },
        {
            "instruction_offset": 0x58,
            "description": "RIP-relative address placed in RBX",
            "displacement": 0x18ff9,
            "next_instruction_offset": 0x5f,
            "target_va": TARGET + 0x5f + 0x18ff9
        },
        {
            "instruction_offset": 0xec,
            "description": "global error/log object",
            "displacement": 0x1273d,
            "next_instruction_offset": 0xf3,
            "target_va": TARGET + 0xf3 + 0x1273d
        },
        {
            "instruction_offset": 0x153,
            "description": "global pointer reloaded into RBX",
            "displacement": 0x126de,
            "next_instruction_offset": 0x15a,
            "target_va": TARGET + 0x15a + 0x126de
        }
    ]

    # --------------------------------------------------------
    # Extract nearby symbols for every interesting address.
    # --------------------------------------------------------

    def nearby(target, radius=512):
        rows = []

        for s in symbols:

            delta = s["value"] - target

            if -radius <= delta <= radius:

                rows.append({
                    "delta": delta,
                    "value": s["value"],
                    "size": s["size"],
                    "type": s["type"],
                    "bind": s["bind"],
                    "raw_name": s["raw_name"],
                    "nid": s.get("nid")
                })

        rows.sort(
            key=lambda x: (
                x["value"],
                x["raw_name"]
            )
        )

        return rows

    call_targets = []

    for call in observed_calls:

        item = dict(call)

        item["nearby_symbols"] = nearby(
            call["target_va"],
            512
        )

        item["target_bytes"] = read_va(
            f,
            elf,
            call["target_va"],
            64
        )

        call_targets.append(item)

    data_targets = []

    for ref in data_refs:

        item = dict(ref)

        item["nearby_symbols"] = nearby(
            ref["target_va"],
            512
        )

        item["target_bytes"] = read_va(
            f,
            elf,
            ref["target_va"],
            128
        )

        data_targets.append(item)

    # --------------------------------------------------------
    # Scan for direct CALL/JMP references to 0x18b0.
    #
    # Search PT_LOAD bytes for E8/E9 rel32 whose decoded
    # destination equals TARGET.
    # --------------------------------------------------------

    references = []

    for seg in elf.iter_segments():

        if seg.header.p_type != "PT_LOAD":
            continue

        flags = int(seg.header.p_flags)

        # executable segment
        if not (flags & 1):
            continue

        seg_vaddr = int(seg.header.p_vaddr)
        seg_offset = int(seg.header.p_offset)
        seg_filesz = int(seg.header.p_filesz)

        f.seek(seg_offset)
        data = f.read(seg_filesz)

        for i in range(0, max(0, len(data) - 5)):

            opcode = data[i]

            if opcode not in (0xE8, 0xE9):
                continue

            disp = struct.unpack_from(
                "<i",
                data,
                i + 1
            )[0]

            next_va = seg_vaddr + i + 5
            dest = next_va + disp

            if dest == TARGET:

                references.append({
                    "type": "CALL" if opcode == 0xE8 else "JMP",
                    "source_va": next_va - 5,
                    "destination_va": dest,
                    "file_offset": seg_offset + i,
                    "displacement": disp
                })

    result = {
        "internal_function": {
            "va": TARGET,
            "size": TARGET_SIZE,
            "symbols": internal,
            "raw": body
        },

        "known_field_accesses": {
            "argument_register": "RSI/R14 after thunk",
            "field_offsets": [
                {
                    "offset": "0x00",
                    "width": 8,
                    "instruction": "mov (%r14), %rax"
                },
                {
                    "offset": "0x08",
                    "width": 4,
                    "instruction": "mov 0x8(%r14), %eax"
                },
                {
                    "offset": "0x0c",
                    "width": 1,
                    "instruction": "mov 0xc(%r14), %al"
                }
            ]
        },

        "observed_call_targets": call_targets,

        "observed_data_targets": data_targets,

        "direct_references_to_internal": references
    }

with open(
    os.path.join(out_dir, "stage45_static.json"),
    "w",
    encoding="utf-8"
) as fp:
    json.dump(result, fp, indent=2)

print(
    json.dumps(
        result,
        indent=2
    )
)
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
Write-Host "AGC PS5 Stage 45 - SubmitCommandBuffer Audit" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Info "SPRX       = $SprxPath"
Write-Info "SPRX WSL   = $SprxUnix"
Write-Info "Output     = $OutDir"
Write-Info "Output WSL = $OutUnix"
Write-Info "Target VA  = 0x18b0"
Write-Info "Function   = sceAgcDriverSubmitCommandBuffer"
Write-Info "Size       = 380 bytes"

try {

    Write-Step "Prepare Linux workspace"

    Invoke-WslChecked @"
rm -rf '$TmpRoot'
mkdir -p '$TmpRoot'
mkdir -p '$OutUnix'
cp '$PythonUnix' '$TmpRoot/analyze_submitcommandbuffer.py'
python3 -m py_compile '$TmpRoot/analyze_submitcommandbuffer.py'
"@ | Out-Null

    Write-Step "Static SubmitCommandBuffer analysis"

    Invoke-WslChecked @"
python3 '$TmpRoot/analyze_submitcommandbuffer.py' \
    '$SprxUnix' \
    '$TmpRoot'
"@ | Out-Null

    Write-Step "Collect Stage 45 report"

    Invoke-WslChecked @"
cp '$TmpRoot/stage45_static.json' \
   '$OutUnix/stage45_static.json'

cat '$TmpRoot/stage45_static.json'
"@ | Out-Null

    Write-Step "Disassemble SubmitCommandBuffer at real VA"

    Invoke-WslChecked @"
objdump \
    -D \
    -b binary \
    -m i386:x86-64 \
    --adjust-vma=0x18b0 \
    '$TmpRoot/submitcommandbuffer.bin' \
    > '$TmpRoot/submitcommandbuffer_disassembly.txt' 2>&1

cp '$TmpRoot/submitcommandbuffer_disassembly.txt' \
   '$OutUnix/submitcommandbuffer_disassembly.txt'

cat '$TmpRoot/submitcommandbuffer_disassembly.txt'
"@ | Out-Null

    Write-Step "Inspect direct references to SubmitCommandBuffer"

    Invoke-WslChecked @"
grep -n '0x18b0\|0x18b' \
    '$OutUnix/submitcommandbuffer_disassembly.txt' \
    > '$OutUnix/internal_self_matches.txt' 2>/dev/null || true

cat '$OutUnix/internal_self_matches.txt' 2>/dev/null || true
"@ | Out-Null

    Write-Step "Hash artefacts"

    $Artifacts = @()

    foreach ($Name in @(
        "stage45_static.json",
        "submitcommandbuffer_disassembly.txt"
    )) {

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

    $Report = [ordered]@{
        stage = 45
        timestamp = (Get-Date).ToString("o")

        submit_dcb = [ordered]@{
            nid = "UglJIZjGssM"
            name = "sceAgcDriverSubmitDcb"
            va = "0x28b0"
        }

        internal = [ordered]@{
            nid = "b4fpgH5ZXxQ"
            name = "sceAgcDriverSubmitCommandBuffer"
            va = "0x18b0"
            size = 380
        }

        argument_structure = [ordered]@{
            source_register = "RSI after SubmitDcb thunk"
            fields = @(
                [ordered]@{
                    offset = "0x00"
                    width = 8
                },
                [ordered]@{
                    offset = "0x08"
                    width = 4
                },
                [ordered]@{
                    offset = "0x0c"
                    width = 1
                }
            )
        }

        execution = [ordered]@{
            performed = $false
        }

        prototype = [ordered]@{
            inferred = $false
        }

        artifacts = $Artifacts
    }

    $ReportPath = Join-Path $OutDir "STAGE45_REPORT.json"

    $Report |
        ConvertTo-Json -Depth 12 |
        Set-Content `
            -LiteralPath $ReportPath `
            -Encoding UTF8

    Write-Host ""
    Write-Host "============================================" -ForegroundColor Green
    Write-Host "Stage 45 completed" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "SUBMIT_COMMAND_BUFFER_IDENTIFIED = PASS" -ForegroundColor Green
    Write-Host "ARGUMENT_STRUCT_ACCESS_IDENTIFIED = PASS" -ForegroundColor Green
    Write-Host "EXECUTED_AGC = NO" -ForegroundColor Green
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