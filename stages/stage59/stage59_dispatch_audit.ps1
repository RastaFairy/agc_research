#requires -Version 7.0

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ============================================================
# AGC PS5 Stage 59
# Dispatch Table / Indirect Backend Target Audit
# ============================================================

$StageDir = $PSScriptRoot

$Sprx = 'D:\agc_work\sce_stubs\libSceAgcDriver.sprx'
$NidDb = 'D:\sdk-master\sce_stubs\aerolib.csv'

$PreviousResults = 'D:\agc_work\stage58_results'
$OutputDir = 'D:\agc_work\stage59_results'

$Sdk = '/opt/ps5-payload-sdk'

$SprxWsl = '/mnt/d/agc_work/sce_stubs/libSceAgcDriver.sprx'
$NidDbWsl = '/mnt/d/sdk-master/sce_stubs/aerolib.csv'
$PreviousWsl = '/mnt/d/agc_work/stage58_results'
$OutputWsl = '/mnt/d/agc_work/stage59_results'

$WorkWsl = '/tmp/agc_stage59'

$AnalyzerWindows = Join-Path $OutputDir 'analyze_dispatch.py'
$AnalyzerWsl = "$OutputWsl/analyze_dispatch.py"

$StaticWindows = Join-Path $OutputDir 'stage59_static.json'
$SummaryWindows = Join-Path $OutputDir 'dispatch_summary.txt'
$DisassemblyWindows = Join-Path $OutputDir 'dispatch_disassembly.txt'
$CandidatesWindows = Join-Path $OutputDir 'dispatch_candidates.txt'
$GlobalHitsWindows = Join-Path $OutputDir 'global_dispatch_hits.txt'
$ReportWindows = Join-Path $OutputDir 'STAGE59_REPORT.json'

# ============================================================
# Helpers
# ============================================================

function Write-Section {
    param(
        [string]$Text
    )

    Write-Host ''
    Write-Host '============================================' -ForegroundColor Cyan
    Write-Host $Text -ForegroundColor Cyan
    Write-Host '============================================' -ForegroundColor Cyan
}

function Write-Step {
    param(
        [string]$Text
    )

    Write-Host ''
    Write-Host "==> $Text" -ForegroundColor Yellow
}

function Quote-Bash {
    param(
        [string]$Text
    )

    return "'" + ($Text -replace "'", "'\''") + "'"
}

function Invoke-Wsl {
    param(
        [Parameter(Mandatory)]
        [string]$Command
    )

    $Normalized = $Command `
        -replace "`r`n", "`n" `
        -replace "`r", ""

    Write-Host ''
    Write-Host '[WSL] ' -NoNewline -ForegroundColor DarkGray
    Write-Host $Normalized -ForegroundColor DarkGray

    & wsl.exe `
        -d Ubuntu-24.04 `
        --cd / `
        -- bash -lc $Normalized

    $Code = $LASTEXITCODE

    if ($Code -ne 0) {
        throw "WSL command failed with exit code $Code."
    }
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Content
    )

    $Encoding = New-Object System.Text.UTF8Encoding($false)

    [System.IO.File]::WriteAllText(
        $Path,
        (
            $Content `
                -replace "`r`n", "`n" `
                -replace "`r", ""
        ),
        $Encoding
    )
}

function Get-Sha256 {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }

    return (
        Get-FileHash `
            -Algorithm SHA256 `
            -LiteralPath $Path
    ).Hash.ToLowerInvariant()
}

# ============================================================
# Validación
# ============================================================

if (-not (Test-Path -LiteralPath $Sprx -PathType Leaf)) {
    throw "No existe SPRX: $Sprx"
}

if (-not (Test-Path -LiteralPath $NidDb -PathType Leaf)) {
    throw "No existe NID DB: $NidDb"
}

if (-not (Test-Path -LiteralPath $PreviousResults -PathType Container)) {
    throw "No existe Stage 58 results: $PreviousResults"
}

New-Item `
    -ItemType Directory `
    -Force `
    -Path $OutputDir |
    Out-Null

# ============================================================
# Banner
# ============================================================

Write-Section `
    'AGC PS5 Stage 59 - Dispatch Table / Indirect Backend Target Audit'

Write-Host "[INFO] StageDir        = $StageDir"
Write-Host "[INFO] SPRX            = $Sprx"
Write-Host "[INFO] NID DB          = $NidDb"
Write-Host "[INFO] Previous stage  = $PreviousResults"
Write-Host "[INFO] Output          = $OutputDir"
Write-Host "[INFO] SPRX WSL        = $SprxWsl"
Write-Host "[INFO] Previous WSL    = $PreviousWsl"
Write-Host "[INFO] Output WSL      = $OutputWsl"
Write-Host "[INFO] SDK             = $Sdk"

# ============================================================
# Python analyzer
# ============================================================

$Python = @'
import json
import os
import re
import struct
import subprocess
import sys
import tempfile

from elftools.elf.elffile import ELFFile


SPRX = sys.argv[1]
NID_DB = sys.argv[2]
PREVIOUS = sys.argv[3]
OUT_DIR = sys.argv[4]

os.makedirs(OUT_DIR, exist_ok=True)

TARGET_NAME = "sceAgcDriverSubmitCommandBuffer"
TARGET_NID = "b4fpgH5ZXxQ"
TARGET_VA = 0x18B0
TARGET_SIZE = 380

MULTI_NAME = "sceAgcDriverSubmitMultiCommandBuffers"
MULTI_VA = 0x4650
MULTI_SIZE = 579

GLOBAL_CONTEXT_VA = 0x1A908
GLOBAL_DISPATCH_CONTEXT_OFFSET = 0x48
GLOBAL_INDEX_OFFSET = 0xA4
DISPATCH_STRIDE = 0x78
DISPATCH_FUNCTION_OFFSET = 0x50

# ============================================================
# ELF
# ============================================================

FP = open(SPRX, "rb")
ELF = ELFFile(FP)


def load_segments():
    result = []

    for seg in ELF.iter_segments():
        if seg["p_type"] != "PT_LOAD":
            continue

        result.append(
            {
                "offset": int(seg["p_offset"]),
                "vaddr": int(seg["p_vaddr"]),
                "filesz": int(seg["p_filesz"]),
                "memsz": int(seg["p_memsz"]),
                "flags": int(seg["p_flags"]),
            }
        )

    return result


SEGMENTS = load_segments()


def executable_segments():
    return [
        seg
        for seg in SEGMENTS
        if (seg["flags"] & 1) and seg["filesz"] > 0
    ]


def va_to_file(va):
    for seg in SEGMENTS:
        start = seg["vaddr"]
        end = start + seg["filesz"]

        if start <= va < end:
            return seg["offset"] + (va - start)

    return None


def read_va(va, size):
    offset = va_to_file(va)

    if offset is None:
        return b""

    FP.seek(offset)
    return FP.read(size)


def va_is_executable(va):
    for seg in executable_segments():
        start = seg["vaddr"]
        end = start + seg["filesz"]

        if start <= va < end:
            return True

    return False


# ============================================================
# Disassembler
# ============================================================

def disassemble(raw, start_va):
    if not raw:
        return ""

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            suffix=".bin",
            prefix="agc_stage59_",
            dir=OUT_DIR,
            delete=False,
        ) as tf:
            tf.write(raw)
            tf.flush()
            temp_path = tf.name

        commands = [
            [
                "objdump",
                "-D",
                "-b",
                "binary",
                "-m",
                "i386:x86-64",
                "--adjust-vma=0x%x" % start_va,
                temp_path,
            ],
            [
                "llvm-objdump",
                "-D",
                "--triple=x86_64",
                "--adjust-vma=0x%x" % start_va,
                temp_path,
            ],
        ]

        last_output = ""

        for command in commands:
            try:
                proc = subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    check=False,
                )
            except FileNotFoundError as exc:
                last_output = str(exc)
                continue

            if proc.returncode == 0:
                return proc.stdout

            last_output = proc.stdout

        return "DISASSEMBLY_UNAVAILABLE\n" + last_output

    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except OSError:
                pass


# ============================================================
# Symbols
# ============================================================

def parse_nm(text):
    result = []

    for raw in text.splitlines():
        line = raw.strip()

        if not line:
            continue

        parts = line.split()

        if len(parts) < 4:
            continue

        if not re.fullmatch(r"[0-9A-Fa-f]+", parts[0]):
            continue

        if not re.fullmatch(r"[0-9A-Fa-f]+", parts[1]):
            continue

        try:
            va = int(parts[0], 16)
            size = int(parts[1], 16)
        except ValueError:
            continue

        typ = parts[2]

        if typ.upper() not in {"T", "W", "I", "V", "F"}:
            continue

        if size <= 0:
            continue

        result.append(
            {
                "va": va,
                "size": size,
                "type": typ,
                "name": " ".join(parts[3:]),
            }
        )

    return result


def get_symbols():
    commands = [
        [
            "prospero-nm",
            "-D",
            "--defined-only",
            "--print-size",
            "-n",
            SPRX,
        ],
        [
            "prospero-nm",
            "--defined-only",
            "--print-size",
            "-n",
            SPRX,
        ],
        [
            "llvm-nm",
            "-D",
            "--defined-only",
            "--print-size",
            "-n",
            SPRX,
        ],
        [
            "llvm-nm",
            "--defined-only",
            "--print-size",
            "-n",
            SPRX,
        ],
    ]

    for command in commands:
        try:
            proc = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            continue

        symbols = parse_nm(proc.stdout)

        if symbols:
            return symbols

    return []


SYMBOLS = get_symbols()


def symbol_for_va(va):
    for symbol in SYMBOLS:
        start = symbol["va"]
        end = start + symbol["size"]

        if start <= va < end:
            return symbol

    return None


# ============================================================
# Byte helpers
# ============================================================

def find_all(blob, needle):
    position = 0

    while True:
        found = blob.find(needle, position)

        if found < 0:
            return

        yield found
        position = found + 1


# ============================================================
# Raw executable data
# ============================================================

EXECUTABLE_DATA = []

for segment_index, seg in enumerate(executable_segments()):
    FP.seek(seg["offset"])
    raw = FP.read(seg["filesz"])

    EXECUTABLE_DATA.append(
        {
            "segment_index": segment_index,
            "segment": seg,
            "raw": raw,
        }
    )


# ============================================================
# Global-context references
# ============================================================

def scan_global_references():
    result = []

    patterns = [
        (b"\x48\x8d\x1d", "lea_global_context_rbx"),
        (b"\x48\x8d\x0d", "lea_global_context_rcx"),
        (b"\x48\x8d\x05", "lea_global_context_rax"),
        (b"\x4c\x8d\x15", "lea_global_context_r10"),
        (b"\x4c\x8d\x25", "lea_global_context_r12"),
        (b"\x4c\x8d\x2d", "lea_global_context_r13"),
        (b"\x4c\x8d\x35", "lea_global_context_r14"),
        (b"\x4c\x8d\x3d", "lea_global_context_r15"),
    ]

    for item in EXECUTABLE_DATA:
        segment_index = item["segment_index"]
        seg = item["segment"]
        blob = item["raw"]
        base = seg["vaddr"]

        for needle, kind in patterns:
            for position in find_all(blob, needle):
                if position + 7 > len(blob):
                    continue

                displacement = struct.unpack(
                    "<i",
                    blob[position + 3:position + 7],
                )[0]

                instruction_va = base + position
                target_va = instruction_va + 7 + displacement

                if target_va != GLOBAL_CONTEXT_VA:
                    continue

                symbol = symbol_for_va(instruction_va)

                result.append(
                    {
                        "segment_index": segment_index,
                        "instruction_va": instruction_va,
                        "file_offset": seg["offset"] + position,
                        "kind": kind,
                        "target_va": target_va,
                        "symbol_name": (
                            symbol["name"]
                            if symbol
                            else None
                        ),
                    }
                )

    return result


GLOBAL_REFS = scan_global_references()


# ============================================================
# SubmitCommandBuffer dispatch pattern
#
# Exact relevant machine code:
#
#   8b 83 a4 00 00 00      mov 0xa4(%rbx),%eax
#   48 6b c0 78            imul $0x78,%rax,%rax
#   ff 54 03 50            call *0x50(%rbx,%rax,1)
#
# The exact first two instructions can use another register in
# other functions, so a wider scanner is used as supporting
# evidence.
# ============================================================

def scan_exact_dispatch_patterns():
    result = []

    for item in EXECUTABLE_DATA:
        segment_index = item["segment_index"]
        seg = item["segment"]
        blob = item["raw"]
        base = seg["vaddr"]

        call_needle = b"\xff\x54\x03\x50"

        for position in find_all(blob, call_needle):
            call_va = base + position

            window_start = max(0, position - 0x30)
            window = blob[window_start:position]

            has_index_load = (
                b"\x8b\x83\xa4\x00\x00\x00" in window
                or
                b"\x8b\x81\xa4\x00\x00\x00" in window
                or
                b"\x8b\x87\xa4\x00\x00\x00" in window
                or
                b"\x8b\x89\xa4\x00\x00\x00" in window
            )

            has_stride_mul = (
                b"\x48\x6b\xc0\x78" in window
                or
                b"\x48\x6b\xc9\x78" in window
                or
                b"\x48\x6b\xf6\x78" in window
                or
                b"\x48\x6b\xd2\x78" in window
            )

            symbol = symbol_for_va(call_va)

            result.append(
                {
                    "segment_index": segment_index,
                    "call_va": call_va,
                    "file_offset": seg["offset"] + position,
                    "has_index_load": has_index_load,
                    "has_stride_mul": has_stride_mul,
                    "symbol_name": (
                        symbol["name"]
                        if symbol
                        else None
                    ),
                }
            )

    return result


DISPATCH_CALLS = scan_exact_dispatch_patterns()


# ============================================================
# Generic register-relative dispatch candidates
# ============================================================

def scan_register_relative_calls():
    result = []

    # ff 54 xx 50 = call *0x50(base,index,1)
    #
    # Accept ModRM/SIB variants sharing the exact disp8=0x50.
    #
    for item in EXECUTABLE_DATA:
        segment_index = item["segment_index"]
        seg = item["segment"]
        blob = item["raw"]
        base = seg["vaddr"]

        for position in find_all(blob, b"\xff\x54"):
            if position + 4 > len(blob):
                continue

            if blob[position + 3] != 0x50:
                continue

            sib = blob[position + 2]

            # Only accept a genuine SIB-based memory call.
            if (sib & 0x07) != 0x00 and (sib & 0x07) != 0x04:
                continue

            call_va = base + position

            window_start = max(0, position - 0x40)
            window = blob[window_start:position]

            has_78_stride = (
                b"\x48\x6b" in window
                and b"\x78" in window
            )

            has_a4_load = (
                b"\xa4\x00\x00\x00" in window
            )

            symbol = symbol_for_va(call_va)

            result.append(
                {
                    "segment_index": segment_index,
                    "call_va": call_va,
                    "file_offset": seg["offset"] + position,
                    "sib_byte": sib,
                    "has_78_stride": has_78_stride,
                    "has_a4_reference": has_a4_load,
                    "symbol_name": (
                        symbol["name"]
                        if symbol
                        else None
                    ),
                }
            )

    return result


GENERIC_DISPATCH_CALLS = scan_register_relative_calls()


# ============================================================
# Target / Multi disassembly
# ============================================================

TARGET_RAW = read_va(
    TARGET_VA,
    TARGET_SIZE,
)

TARGET_DISASM = disassemble(
    TARGET_RAW,
    TARGET_VA,
)

MULTI_RAW = read_va(
    MULTI_VA,
    MULTI_SIZE,
)

MULTI_DISASM = disassemble(
    MULTI_RAW,
    MULTI_VA,
)


# ============================================================
# Find windows around dispatch calls
# ============================================================

def dispatch_windows(calls):
    result = []

    for call in calls:
        call_va = call["call_va"]

        start_va = max(
            0,
            call_va - 0x100,
        )

        raw = read_va(
            start_va,
            0x180,
        )

        result.append(
            {
                "call_va": call_va,
                "start_va": start_va,
                "disassembly": disassemble(
                    raw,
                    start_va,
                ),
            }
        )

    return result


DISPATCH_WINDOWS = dispatch_windows(
    DISPATCH_CALLS
)


# ============================================================
# Search likely table initialization writes
#
# IMPORTANT:
# The dispatch table is in BSS/RW runtime state. Static
# analysis cannot read the final pointer values.
#
# We therefore search for:
#
#   global_context LEA
#   followed by stores with offsets in the dispatch area
#
# without claiming that any single hit proves an entry target.
# ============================================================

def scan_dispatch_area_windows():
    result = []

    for item in GLOBAL_REFS:
        instruction_va = item["instruction_va"]

        start_va = max(
            0,
            instruction_va - 0x20,
        )

        raw = read_va(
            start_va,
            0x180,
        )

        text = disassemble(
            raw,
            start_va,
        )

        lower = text.lower()

        interesting_tokens = [
            "0x50",
            "0x58",
            "0x20",
            "0x28",
            "0x78",
            "0xa4",
        ]

        if not any(
            token in lower
            for token in interesting_tokens
        ):
            continue

        result.append(
            {
                "global_reference_va":
                    instruction_va,
                "global_reference_kind":
                    item["kind"],
                "window_start_va":
                    start_va,
                "disassembly":
                    text,
            }
        )

    return result


DISPATCH_AREA_WINDOWS = scan_dispatch_area_windows()


# ============================================================
# Function-like regions without requiring symbols
# ============================================================

def function_starts():
    starts = set()

    prologues = [
        b"\x55\x48\x89\xe5",
        b"\x41\x57\x41\x56\x41\x55\x41\x54\x53",
        b"\x53\x48\x83\xec",
        b"\x48\x83\xec",
    ]

    for item in EXECUTABLE_DATA:
        seg = item["segment"]
        blob = item["raw"]
        base = seg["vaddr"]

        for needle in prologues:
            for position in find_all(blob, needle):
                starts.add(base + position)

    starts.add(TARGET_VA)
    starts.add(MULTI_VA)

    return sorted(starts)


FUNCTION_STARTS = function_starts()


def nearest_function_start(va):
    candidates = [
        start
        for start in FUNCTION_STARTS
        if start <= va
    ]

    if not candidates:
        return None

    return max(candidates)


# ============================================================
# Group dispatch evidence by likely function
# ============================================================

FUNCTION_GROUPS = {}


def get_group(start):
    if start not in FUNCTION_GROUPS:
        FUNCTION_GROUPS[start] = {
            "start_va": start,
            "dispatch_calls": [],
            "global_refs": [],
        }

    return FUNCTION_GROUPS[start]


for item in DISPATCH_CALLS:
    start = nearest_function_start(
        item["call_va"]
    )

    if start is not None:
        get_group(start)["dispatch_calls"].append(item)


for item in GLOBAL_REFS:
    start = nearest_function_start(
        item["instruction_va"]
    )

    if start is not None:
        get_group(start)["global_refs"].append(item)


RANKED_FUNCTIONS = []

for start, group in FUNCTION_GROUPS.items():
    raw = read_va(start, 0x300)
    text = disassemble(raw, start)

    score = 0

    if group["dispatch_calls"]:
        score += 100

    if group["global_refs"]:
        score += 20

    if "0xa4" in text:
        score += 30

    if "0x78" in text:
        score += 30

    if "0x50" in text:
        score += 30

    symbol = symbol_for_va(start)

    RANKED_FUNCTIONS.append(
        {
            "start_va": start,
            "score": score,
            "symbol_name": (
                symbol["name"]
                if symbol
                else None
            ),
            "dispatch_call_count":
                len(group["dispatch_calls"]),
            "global_ref_count":
                len(group["global_refs"]),
            "disassembly": text,
        }
    )


RANKED_FUNCTIONS.sort(
    key=lambda item: (
        -item["score"],
        item["start_va"],
    )
)


# ============================================================
# Direct evidence about target and multi
# ============================================================

target_dispatch_call_match = any(
    TARGET_VA <= item["call_va"] < TARGET_VA + TARGET_SIZE
    for item in DISPATCH_CALLS
)

multi_dispatch_call_match = any(
    MULTI_VA <= item["call_va"] < MULTI_VA + MULTI_SIZE
    for item in DISPATCH_CALLS
)


# ============================================================
# Conclusions
# ============================================================

dispatch_consumer_identified = (
    len(DISPATCH_CALLS) > 0
)

index_usage_proven = any(
    item["has_index_load"]
    for item in DISPATCH_CALLS
)

stride_usage_proven = any(
    item["has_stride_mul"]
    for item in DISPATCH_CALLS
)

runtime_pointer_resolved = False

backend_consumer_identified = False


# ============================================================
# Summary
# ============================================================

summary = []

summary.append(
    "AGC PS5 Stage 59 - Dispatch Table / Indirect Backend Target Audit"
)

summary.append("")
summary.append("=== TARGET ===")
summary.append(
    "sceAgcDriverSubmitCommandBuffer = 0x%X"
    % TARGET_VA
)
summary.append(
    "NID = %s"
    % TARGET_NID
)
summary.append(
    "global_context = 0x%X"
    % GLOBAL_CONTEXT_VA
)
summary.append(
    "global_context + 0xA4 = dispatch index"
)
summary.append(
    "dispatch stride = 0x%X"
    % DISPATCH_STRIDE
)
summary.append(
    "dispatch function offset = 0x%X"
    % DISPATCH_FUNCTION_OFFSET
)
summary.append(
    "dispatch formula = global_context + 0x50 + index * 0x78"
)

summary.append("")
summary.append("=== EXACT DISPATCH CALLS ===")

if not DISPATCH_CALLS:
    summary.append("NONE")
else:
    for item in DISPATCH_CALLS:
        summary.append(
            (
                "call=0x%X "
                "index_load=%s "
                "stride_mul=%s "
                "symbol=%s"
            )
            % (
                item["call_va"],
                item["has_index_load"],
                item["has_stride_mul"],
                item["symbol_name"] or "<none>",
            )
        )

summary.append("")
summary.append("=== GENERIC INDIRECT DISPATCH CALLS ===")

summary.append(
    "count=%d"
    % len(GENERIC_DISPATCH_CALLS)
)

for item in GENERIC_DISPATCH_CALLS[:100]:
    summary.append(
        (
            "call=0x%X "
            "sib=0x%02X "
            "has_78_stride=%s "
            "has_a4_reference=%s "
            "symbol=%s"
        )
        % (
            item["call_va"],
            item["sib_byte"],
            item["has_78_stride"],
            item["has_a4_reference"],
            item["symbol_name"] or "<none>",
        )
    )

summary.append("")
summary.append("=== GLOBAL CONTEXT REFERENCES ===")

summary.append(
    "count=%d"
    % len(GLOBAL_REFS)
)

for item in GLOBAL_REFS[:100]:
    summary.append(
        "0x%X -> 0x%X %s symbol=%s"
        % (
            item["instruction_va"],
            item["target_va"],
            item["kind"],
            item["symbol_name"] or "<none>",
        )
    )

summary.append("")
summary.append("=== FUNCTION-LIKE REGIONS WITH DISPATCH EVIDENCE ===")

for item in RANKED_FUNCTIONS[:40]:
    summary.append(
        (
            "VA=0x%X "
            "score=%d "
            "dispatch_calls=%d "
            "global_refs=%d "
            "symbol=%s"
        )
        % (
            item["start_va"],
            item["score"],
            item["dispatch_call_count"],
            item["global_ref_count"],
            item["symbol_name"] or "<none>",
        )
    )

summary.append("")
summary.append("=== DIRECT TARGET FLAGS ===")
summary.append(
    "target_function_contains_dispatch_call=%s"
    % target_dispatch_call_match
)
summary.append(
    "multi_function_contains_dispatch_call=%s"
    % multi_dispatch_call_match
)

summary.append("")
summary.append("=== LIMITS ===")
summary.append(
    "The dispatch object is runtime RW/BSS state."
)
summary.append(
    "Its actual function-pointer contents are not file-backed."
)
summary.append(
    "Therefore the final backend target address is not fabricated."
)
summary.append(
    "The static indirect-call expression is proven."
)

summary_path = os.path.join(
    OUT_DIR,
    "dispatch_summary.txt",
)

with open(
    summary_path,
    "w",
    encoding="utf-8",
    newline="\n",
) as fp:
    fp.write(
        "\n".join(summary)
        + "\n"
    )


# ============================================================
# Global hit file
# ============================================================

global_hits_path = os.path.join(
    OUT_DIR,
    "global_dispatch_hits.txt",
)

with open(
    global_hits_path,
    "w",
    encoding="utf-8",
    newline="\n",
) as fp:
    fp.write(
        "AGC PS5 Stage 59 - Global Dispatch Evidence\n\n"
    )

    for item in GLOBAL_REFS:
        fp.write(
            "VA=0x%X "
            "FILE_OFFSET=0x%X "
            "KIND=%s "
            "TARGET=0x%X "
            "SYMBOL=%s\n"
            % (
                item["instruction_va"],
                item["file_offset"],
                item["kind"],
                item["target_va"],
                item["symbol_name"] or "<none>",
            )
        )


# ============================================================
# Candidate report
# ============================================================

candidate_lines = []

candidate_lines.append(
    "AGC PS5 Stage 59 - Dispatch Candidate Functions"
)
candidate_lines.append("")

for index, item in enumerate(
    RANKED_FUNCTIONS[:50],
    start=1,
):
    candidate_lines.append(
        "============================================"
    )
    candidate_lines.append(
        "CANDIDATE %02d"
        % index
    )
    candidate_lines.append(
        "============================================"
    )
    candidate_lines.append(
        "VA = 0x%X"
        % item["start_va"]
    )
    candidate_lines.append(
        "score = %d"
        % item["score"]
    )
    candidate_lines.append(
        "dispatch_calls = %d"
        % item["dispatch_call_count"]
    )
    candidate_lines.append(
        "global_refs = %d"
        % item["global_ref_count"]
    )
    candidate_lines.append(
        "symbol = %s"
        % (item["symbol_name"] or "<none>")
    )
    candidate_lines.append("")
    candidate_lines.append(
        item["disassembly"]
    )
    candidate_lines.append("")


candidate_path = os.path.join(
    OUT_DIR,
    "dispatch_candidates.txt",
)

with open(
    candidate_path,
    "w",
    encoding="utf-8",
    newline="\n",
) as fp:
    fp.write(
        "\n".join(candidate_lines)
    )


# ============================================================
# Disassembly report
# ============================================================

disassembly_path = os.path.join(
    OUT_DIR,
    "dispatch_disassembly.txt",
)

with open(
    disassembly_path,
    "w",
    encoding="utf-8",
    newline="\n",
) as fp:
    fp.write(
        "AGC PS5 Stage 59 - Dispatch Disassembly\n\n"
    )

    fp.write(
        "=== SubmitCommandBuffer ===\n\n"
    )
    fp.write(TARGET_DISASM)
    fp.write("\n\n")

    fp.write(
        "=== SubmitMultiCommandBuffers ===\n\n"
    )
    fp.write(MULTI_DISASM)
    fp.write("\n\n")

    fp.write(
        "=== Dispatch Call Windows ===\n\n"
    )

    for item in DISPATCH_WINDOWS:
        fp.write(
            "--------------------------------------------\n"
        )
        fp.write(
            "CALL VA=0x%X\n"
            % item["call_va"]
        )
        fp.write(
            item["disassembly"]
        )
        fp.write("\n")


# ============================================================
# Static JSON
# ============================================================

static = {
    "stage": 59,
    "target": {
        "name": TARGET_NAME,
        "nid": TARGET_NID,
        "va": TARGET_VA,
        "size": TARGET_SIZE,
    },
    "multi_source": {
        "name": MULTI_NAME,
        "va": MULTI_VA,
        "size": MULTI_SIZE,
    },
    "dispatch_model": {
        "global_context": GLOBAL_CONTEXT_VA,
        "index_offset": GLOBAL_INDEX_OFFSET,
        "stride": DISPATCH_STRIDE,
        "function_pointer_offset": DISPATCH_FUNCTION_OFFSET,
        "formula":
            "global_context + 0x50 + index * 0x78",
    },
    "previous_stage": {
        "path": PREVIOUS,
        "available": os.path.isdir(PREVIOUS),
    },
    "elf_segments": SEGMENTS,
    "symbol_inventory": {
        "count": len(SYMBOLS),
        "method": "prospero-nm/llvm-nm",
    },
    "global_context_references": GLOBAL_REFS,
    "dispatch_calls": DISPATCH_CALLS,
    "generic_dispatch_calls": GENERIC_DISPATCH_CALLS,
    "function_starts": FUNCTION_STARTS,
    "ranked_functions":
        RANKED_FUNCTIONS[:100],
    "dispatch_windows":
        DISPATCH_WINDOWS,
    "conclusions": {
        "DISPATCH_CONSUMER_IDENTIFIED":
            dispatch_consumer_identified,

        "GLOBAL_CONTEXT_REFERENCE_SCAN_COMPLETED":
            True,

        "DISPATCH_INDEX_FIELD_USAGE_PROVEN":
            index_usage_proven,

        "DISPATCH_STRIDE_0x78_USAGE_PROVEN":
            stride_usage_proven,

        "TARGET_FUNCTION_DISPATCH_PATTERN_FOUND":
            target_dispatch_call_match,

        "MULTI_FUNCTION_DISPATCH_PATTERN_FOUND":
            multi_dispatch_call_match,

        "RUNTIME_FUNCTION_POINTER_RESOLVED":
            runtime_pointer_resolved,

        "BACKEND_CONSUMER_IDENTIFIED":
            backend_consumer_identified,

        "FIELD_00_POINTER_SEMANTICS_PROVEN":
            False,

        "FIELD_08_SIZE_SEMANTICS_PROVEN":
            False,

        "FIELD_08_COUNT_SEMANTICS_PROVEN":
            False,

        "FIELD_08_INDEX_SEMANTICS_PROVEN":
            False,

        "FIELD_0C_FLAG_SEMANTICS_PROVEN":
            False,

        "EXACT_STRUCT_SIZE_PROVEN":
            False,

        "SEMANTIC_PROTOTYPE_INFERRED":
            False,

        "EXECUTED_AGC":
            False,
    },
    "notes": [
        "Stage 58 had no usable symbol inventory.",
        "Stage 59 separates indirect-dispatch evidence from consumer naming.",
        "The dispatch table is runtime writable/BSS data.",
        "The actual function-pointer values are not statically recoverable from this file alone.",
        "The indirect-call expression and index/stride relationship are statically recoverable.",
        "No backend function pointer is invented or promoted to proven status without initialization evidence.",
    ],
}


static_path = os.path.join(
    OUT_DIR,
    "stage59_static.json",
)

with open(
    static_path,
    "w",
    encoding="utf-8",
) as fp:
    json.dump(
        static,
        fp,
        indent=2,
    )


# ============================================================
# Console JSON
# ============================================================

print(
    json.dumps(
        static,
        indent=2,
    )
)
'@

# ============================================================
# Write analyzer
# ============================================================

Write-Utf8NoBom `
    -Path $AnalyzerWindows `
    -Content $Python

# ============================================================
# Prepare workspace
# ============================================================

Write-Step 'Preparar workspace Linux'

$Prepare = @"
set -e

rm -rf $(Quote-Bash $WorkWsl)

mkdir -p $(Quote-Bash $WorkWsl)
mkdir -p $(Quote-Bash $OutputWsl)

cp $(Quote-Bash $AnalyzerWsl) \
   $(Quote-Bash "$WorkWsl/analyze_dispatch.py")

sed -i 's/\r$//' \
    $(Quote-Bash "$WorkWsl/analyze_dispatch.py")

python3 -m py_compile \
    $(Quote-Bash "$WorkWsl/analyze_dispatch.py")

ls -lh \
    $(Quote-Bash "$WorkWsl/analyze_dispatch.py")
"@

Invoke-Wsl -Command $Prepare

# ============================================================
# Verify toolchain
# ============================================================

Write-Step 'Verificar Python + pyelftools + toolchain'

$Verify = @"
set -e

test -x $(Quote-Bash "$Sdk/bin/prospero-clang")
test -x $(Quote-Bash "$Sdk/bin/prospero-nm")
test -x $(Quote-Bash "$Sdk/bin/prospero-lld")

echo '--- prospero-clang ---'
$(Quote-Bash "$Sdk/bin/prospero-clang") --version

echo '--- prospero-nm ---'
$(Quote-Bash "$Sdk/bin/prospero-nm") --version

echo '--- pyelftools ---'
python3 -c "from elftools.elf.elffile import ELFFile; print('pyelftools=OK')"

echo '--- objdump ---'
command -v objdump

echo '--- llvm-objdump ---'
command -v llvm-objdump
"@

Invoke-Wsl -Command $Verify

# ============================================================
# Run analyzer
# ============================================================

Write-Step 'Analizar tabla de dispatch y llamadas indirectas'

$Analyze = @"
set -e

python3 $(Quote-Bash "$WorkWsl/analyze_dispatch.py") \
    $(Quote-Bash $SprxWsl) \
    $(Quote-Bash $NidDbWsl) \
    $(Quote-Bash $PreviousWsl) \
    $(Quote-Bash $OutputWsl)
"@

Invoke-Wsl -Command $Analyze

# ============================================================
# Verify outputs
# ============================================================

Write-Step 'Verificar artefactos Stage 59'

$VerifyArtifacts = @"
set -e

test -f $(Quote-Bash "$OutputWsl/stage59_static.json")
test -f $(Quote-Bash "$OutputWsl/dispatch_summary.txt")
test -f $(Quote-Bash "$OutputWsl/dispatch_disassembly.txt")
test -f $(Quote-Bash "$OutputWsl/dispatch_candidates.txt")
test -f $(Quote-Bash "$OutputWsl/global_dispatch_hits.txt")

echo '--- dispatch_summary.txt ---'
cat $(Quote-Bash "$OutputWsl/dispatch_summary.txt")

echo '--- output files ---'
find $(Quote-Bash $OutputWsl) \
    -maxdepth 2 \
    -type f |
    sort
"@

Invoke-Wsl -Command $VerifyArtifacts

# ============================================================
# Load static results
# ============================================================

$Static = Get-Content `
    -LiteralPath $StaticWindows `
    -Raw |
    ConvertFrom-Json

$DispatchConsumer =
    [bool]$Static.conclusions.DISPATCH_CONSUMER_IDENTIFIED

$IndexProven =
    [bool]$Static.conclusions.DISPATCH_INDEX_FIELD_USAGE_PROVEN

$StrideProven =
    [bool]$Static.conclusions.DISPATCH_STRIDE_0x78_USAGE_PROVEN

$TargetDispatch =
    [bool]$Static.conclusions.TARGET_FUNCTION_DISPATCH_PATTERN_FOUND

$MultiDispatch =
    [bool]$Static.conclusions.MULTI_FUNCTION_DISPATCH_PATTERN_FOUND

$RuntimeResolved =
    [bool]$Static.conclusions.RUNTIME_FUNCTION_POINTER_RESOLVED

# ============================================================
# Hashes
# ============================================================

Write-Step 'Hash artefactos'

$HashStatic = Get-Sha256 $StaticWindows
$HashSummary = Get-Sha256 $SummaryWindows
$HashDisassembly = Get-Sha256 $DisassemblyWindows
$HashCandidates = Get-Sha256 $CandidatesWindows
$HashGlobalHits = Get-Sha256 $GlobalHitsWindows

Write-Host "[INFO] stage59_static.json SHA256=$HashStatic"
Write-Host "[INFO] dispatch_summary.txt SHA256=$HashSummary"
Write-Host "[INFO] dispatch_disassembly.txt SHA256=$HashDisassembly"
Write-Host "[INFO] dispatch_candidates.txt SHA256=$HashCandidates"
Write-Host "[INFO] global_dispatch_hits.txt SHA256=$HashGlobalHits"

# ============================================================
# Report
# ============================================================

$Report = [ordered]@{
    stage = 59

    target = [ordered]@{
        name = 'sceAgcDriverSubmitCommandBuffer'
        nid = 'b4fpgH5ZXxQ'
        va = '0x18b0'
        size = 380
    }

    dispatch = [ordered]@{
        global_context = '0x1a908'
        index_offset = '0xa4'
        stride = '0x78'
        function_pointer_offset = '0x50'
        formula = 'global_context + 0x50 + index * 0x78'
    }

    conclusions = [ordered]@{
        DISPATCH_CONSUMER_IDENTIFIED =
            $DispatchConsumer

        GLOBAL_CONTEXT_REFERENCE_SCAN_COMPLETED =
            $true

        DISPATCH_INDEX_FIELD_USAGE_PROVEN =
            $IndexProven

        DISPATCH_STRIDE_0x78_USAGE_PROVEN =
            $StrideProven

        TARGET_FUNCTION_DISPATCH_PATTERN_FOUND =
            $TargetDispatch

        MULTI_FUNCTION_DISPATCH_PATTERN_FOUND =
            $MultiDispatch

        RUNTIME_FUNCTION_POINTER_RESOLVED =
            $RuntimeResolved

        BACKEND_CONSUMER_IDENTIFIED =
            $false

        FIELD_00_POINTER_SEMANTICS_PROVEN =
            $false

        FIELD_08_SIZE_SEMANTICS_PROVEN =
            $false

        FIELD_08_COUNT_SEMANTICS_PROVEN =
            $false

        FIELD_08_INDEX_SEMANTICS_PROVEN =
            $false

        FIELD_0C_FLAG_SEMANTICS_PROVEN =
            $false

        EXACT_STRUCT_SIZE_PROVEN =
            $false

        SEMANTIC_PROTOTYPE_INFERRED =
            $false

        EXECUTED_AGC =
            $false
    }

    hashes = [ordered]@{
        'stage59_static.json' =
            $HashStatic

        'dispatch_summary.txt' =
            $HashSummary

        'dispatch_disassembly.txt' =
            $HashDisassembly

        'dispatch_candidates.txt' =
            $HashCandidates

        'global_dispatch_hits.txt' =
            $HashGlobalHits
    }
}

Write-Utf8NoBom `
    -Path $ReportWindows `
    -Content (
        $Report |
        ConvertTo-Json -Depth 20
    )

# ============================================================
# Final
# ============================================================

Write-Host ''
Write-Host '============================================' -ForegroundColor Green
Write-Host 'Stage 59 completado' -ForegroundColor Green
Write-Host '============================================' -ForegroundColor Green
Write-Host ''

Write-Host `
    "DISPATCH_CONSUMER_IDENTIFIED = $DispatchConsumer"

Write-Host `
    'GLOBAL_CONTEXT_REFERENCE_SCAN_COMPLETED = True'

Write-Host `
    "DISPATCH_INDEX_FIELD_USAGE_PROVEN = $IndexProven"

Write-Host `
    "DISPATCH_STRIDE_0x78_USAGE_PROVEN = $StrideProven"

Write-Host `
    "TARGET_FUNCTION_DISPATCH_PATTERN_FOUND = $TargetDispatch"

Write-Host `
    "MULTI_FUNCTION_DISPATCH_PATTERN_FOUND = $MultiDispatch"

Write-Host `
    "RUNTIME_FUNCTION_POINTER_RESOLVED = $RuntimeResolved"

Write-Host `
    'BACKEND_CONSUMER_IDENTIFIED = False'

Write-Host `
    'FIELD_00_POINTER_SEMANTICS_PROVEN = False'

Write-Host `
    'FIELD_08_SIZE_SEMANTICS_PROVEN = False'

Write-Host `
    'FIELD_08_COUNT_SEMANTICS_PROVEN = False'

Write-Host `
    'FIELD_08_INDEX_SEMANTICS_PROVEN = False'

Write-Host `
    'FIELD_0C_FLAG_SEMANTICS_PROVEN = False'

Write-Host `
    'EXACT_STRUCT_SIZE_PROVEN = False'

Write-Host `
    'SEMANTIC_PROTOTYPE_INFERRED = False'

Write-Host `
    'EXECUTED_AGC = False'

Write-Host ''
Write-Host 'Resultados:'
Write-Host "  $OutputDir"

Write-Host ''
Write-Host 'Reporte:'
Write-Host "  $ReportWindows"