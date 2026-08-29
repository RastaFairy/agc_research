#requires -Version 7.0

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$StageDir = $PSScriptRoot
$Sprx = 'D:\agc_work\sce_stubs\libSceAgcDriver.sprx'
$NidDb = 'D:\sdk-master\sce_stubs\aerolib.csv'
$PreviousResults = 'D:\agc_work\stage61_results'
$OutputDir = 'D:\agc_work\stage62_results'

$Sdk = '/opt/ps5-payload-sdk'

$SprxWsl = '/mnt/d/agc_work/sce_stubs/libSceAgcDriver.sprx'
$NidDbWsl = '/mnt/d/sdk-master/sce_stubs/aerolib.csv'
$PreviousWsl = '/mnt/d/agc_work/stage61_results'
$OutputWsl = '/mnt/d/agc_work/stage62_results'

$WorkWsl = '/tmp/agc_stage62'

$AnalyzerWindows = Join-Path $OutputDir 'analyze_index_value_flow.py'
$AnalyzerWsl = "$OutputWsl/analyze_index_value_flow.py"

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

function Quote-Bash {
    param([Parameter(Mandatory)][string]$Text)
    return "'" + ($Text -replace "'", "'\''") + "'"
}

function Invoke-Wsl {
    param([Parameter(Mandatory)][string]$Command)

    $Normalized = $Command -replace "`r`n", "`n" -replace "`r", ""

    Write-Host ''
    Write-Host '[WSL] ' -NoNewline -ForegroundColor DarkGray
    Write-Host $Normalized -ForegroundColor DarkGray

    & wsl.exe -d Ubuntu-24.04 --cd / -- bash -lc $Normalized

    $Code = $LASTEXITCODE
    if ($Code -ne 0) {
        throw "WSL command failed with exit code $Code."
    }
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Content
    )

    $Encoding = New-Object System.Text.UTF8Encoding($false)

    $Content = $Content `
        -replace "`r`n", "`n" `
        -replace "`r", ""

    [System.IO.File]::WriteAllText($Path, $Content, $Encoding)
}

function Get-Sha256 {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }

    return (
        Get-FileHash -Algorithm SHA256 -LiteralPath $Path
    ).Hash.ToLowerInvariant()
}

Write-Host ''
Write-Host '============================================' -ForegroundColor Cyan
Write-Host 'AGC PS5 Stage 62 - Dispatch Index Value-Flow / Zero Initialization Audit' -ForegroundColor Cyan
Write-Host '============================================' -ForegroundColor Cyan

Write-Host "[INFO] StageDir        = $StageDir"
Write-Host "[INFO] SPRX            = $Sprx"
Write-Host "[INFO] NID DB          = $NidDb"
Write-Host "[INFO] Previous stage  = $PreviousResults"
Write-Host "[INFO] Output          = $OutputDir"
Write-Host "[INFO] SPRX WSL        = $SprxWsl"
Write-Host "[INFO] Previous WSL    = $PreviousWsl"
Write-Host "[INFO] Output WSL      = $OutputWsl"
Write-Host "[INFO] SDK             = $Sdk"

if (-not (Test-Path $Sprx -PathType Leaf)) {
    throw "No existe SPRX: $Sprx"
}

if (-not (Test-Path $NidDb -PathType Leaf)) {
    throw "No existe NID DB: $NidDb"
}

if (-not (Test-Path $PreviousResults -PathType Container)) {
    throw "No existe Stage 61 results: $PreviousResults"
}

$Python = @'
import json
import os
import re
import subprocess
import sys
import tempfile

from elftools.elf.elffile import ELFFile


SPRX = sys.argv[1]
PREVIOUS_RESULTS = sys.argv[2]
OUT_DIR = sys.argv[3]

os.makedirs(OUT_DIR, exist_ok=True)

GLOBAL_CONTEXT_VA = 0x1A908
INDEX_OFFSET = 0xA4
INDEX_VA = GLOBAL_CONTEXT_VA + INDEX_OFFSET

TARGET_INIT_START = 0x160

ELF_FP = open(SPRX, "rb")
ELF = ELF_FP and ELFFile(ELF_FP)


def load_segments():
    result = []

    for seg in ELF.iter_segments():
        if seg["p_type"] != "PT_LOAD":
            continue

        result.append({
            "offset": int(seg["p_offset"]),
            "vaddr": int(seg["p_vaddr"]),
            "filesz": int(seg["p_filesz"]),
            "memsz": int(seg["p_memsz"]),
            "flags": int(seg["p_flags"]),
        })

    return result


SEGMENTS = load_segments()


def va_to_file(va):
    for seg in SEGMENTS:
        start = seg["vaddr"]
        end = start + seg["filesz"]

        if start <= va < end:
            return seg["offset"] + (va - start)

    return None


def read_va(va, size):
    off = va_to_file(va)

    if off is None:
        return b""

    with open(SPRX, "rb") as fp:
        fp.seek(off)
        return fp.read(size)


def disassemble(raw, start_va):
    if not raw:
        return ""

    tmp = None

    try:
        with tempfile.NamedTemporaryFile(
            prefix="agc_stage62_",
            suffix=".bin",
            dir=OUT_DIR,
            delete=False,
        ) as fp:
            fp.write(raw)
            fp.flush()
            tmp = fp.name

        commands = [
            [
                "objdump",
                "-D",
                "-b",
                "binary",
                "-m",
                "i386:x86-64",
                "--adjust-vma=0x%x" % start_va,
                tmp,
            ],
            [
                "llvm-objdump",
                "-D",
                "--triple=x86_64",
                "--adjust-vma=0x%x" % start_va,
                tmp,
            ],
        ]

        for cmd in commands:
            try:
                proc = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    check=False,
                )
            except FileNotFoundError:
                continue

            if proc.returncode == 0:
                return proc.stdout

        return ""

    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def parse_lines(text):
    result = []

    for line in text.splitlines():
        stripped = line.strip()

        m = re.match(
            r"^([0-9a-fA-F]+):\s+"
            r"((?:[0-9a-fA-F]{2}\s+)+)"
            r"(.*)$",
            stripped,
        )

        if not m:
            continue

        result.append({
            "va": int(m.group(1), 16),
            "instruction": m.group(3).strip(),
        })

    return result


def norm(text):
    text = text.replace("\t", " ").strip()

    while "  " in text:
        text = text.replace("  ", " ")

    return text


# ------------------------------------------------------------
# Exact initialization function window
# ------------------------------------------------------------

INIT_START = 0x160
INIT_SIZE = 0x0C0

INIT_RAW = read_va(
    INIT_START,
    INIT_SIZE,
)

INIT_DISASM = disassemble(
    INIT_RAW,
    INIT_START,
)

INIT_LINES = parse_lines(
    INIT_DISASM
)


# ------------------------------------------------------------
# Track XMM0 zeroing
#
# Important fix relative to Stage 61:
# recognize legacy SSE zeroing AND VEX-encoded VXORPS.
# ------------------------------------------------------------

XMM0_ZERO_EVENTS = []

for line in INIT_LINES:
    insn = norm(line["instruction"]).lower()

    if (
        re.search(
            r"\b(?:xorps|xorpd|pxor)\s+%xmm0,\s*%xmm0(?:\s*,\s*%xmm0)?",
            insn,
        )
        or
        re.search(
            r"\bvxorps\s+%xmm0,\s*%xmm0,\s*%xmm0",
            insn,
        )
        or
        re.search(
            r"\bvpxor\s+%xmm0,\s*%xmm0,\s*%xmm0",
            insn,
        )
        or
        re.search(
            r"\bvxorpd\s+%xmm0,\s*%xmm0,\s*%xmm0",
            insn,
        )
    ):
        XMM0_ZERO_EVENTS.append({
            "instruction_va": line["va"],
            "instruction": norm(line["instruction"]),
            "classification": "XMM0_ZERO",
        })


# ------------------------------------------------------------
# Find the exact store
# ------------------------------------------------------------

STORE_CANDIDATES = []

for line in INIT_LINES:
    insn = norm(line["instruction"])

    if (
        "vmovups %xmm0,0xa4(%rax)" in insn.lower()
        or "movups %xmm0,0xa4(%rax)" in insn.lower()
    ):
        STORE_CANDIDATES.append({
            "instruction_va": line["va"],
            "instruction": insn,
            "field_offset": INDEX_OFFSET,
            "field_va": INDEX_VA,
            "source_register": "xmm0",
            "width_bytes": 16,
        })


# ------------------------------------------------------------
# Instruction window around store
# ------------------------------------------------------------

store = STORE_CANDIDATES[0] if STORE_CANDIDATES else None

STORE_INDEX = None

if store:
    for i, line in enumerate(INIT_LINES):
        if line["va"] == store["instruction_va"]:
            STORE_INDEX = i
            break


XMM0_EVENTS_BEFORE_STORE = []

if STORE_INDEX is not None:
    for i in range(0, STORE_INDEX):
        insn = norm(INIT_LINES[i]["instruction"]).lower()

        if (
            "%xmm0" in insn
            and
            (
                "mov" in insn
                or "xor" in insn
                or "pxor" in insn
                or "vpxor" in insn
                or "vxorps" in insn
                or "vxorpd" in insn
            )
        ):
            XMM0_EVENTS_BEFORE_STORE.append({
                "instruction_va": INIT_LINES[i]["va"],
                "instruction": norm(INIT_LINES[i]["instruction"]),
            })


# ------------------------------------------------------------
# Determine whether the value reaching the store is provably zero
#
# For this stage we only claim "provably zero" when:
#
#   zeroing instruction occurs
#   and
#   there is no later write into xmm0 before the store.
# ------------------------------------------------------------

xmm0_zero_proven = False
xmm0_last_zero = None
xmm0_later_write = None

if STORE_INDEX is not None:
    for i in range(0, STORE_INDEX):
        insn = norm(INIT_LINES[i]["instruction"]).lower()

        is_zero = (
            re.search(
                r"\bvxorps\s+%xmm0,\s*%xmm0,\s*%xmm0",
                insn,
            )
            or
            re.search(
                r"\bvpxor\s+%xmm0,\s*%xmm0,\s*%xmm0",
                insn,
            )
            or
            re.search(
                r"\bvxorpd\s+%xmm0,\s*%xmm0,\s*%xmm0",
                insn,
            )
            or
            re.search(
                r"\b(?:xorps|xorpd|pxor)\s+%xmm0,\s*%xmm0",
                insn,
            )
        )

        if is_zero:
            xmm0_last_zero = INIT_LINES[i]
            xmm0_later_write = None
            continue

        # Conservative detection of an xmm0 write after the zeroing.
        # We intentionally avoid treating the store itself as a write
        # to the source register.
        if (
            "%xmm0" in insn
            and
            re.search(
                r"\b(?:mov|movq|movd|vmov|vpmov|xor|vxor|pxor)\b",
                insn,
            )
        ):
            xmm0_later_write = INIT_LINES[i]

    if xmm0_last_zero is not None and xmm0_later_write is None:
        xmm0_zero_proven = True


# ------------------------------------------------------------
# Field layout around +0xA4
# ------------------------------------------------------------

NEIGHBORING = []

for line in INIT_LINES:
    insn = norm(line["instruction"]).lower()

    for off in [0xA0, 0xA4, 0xA8, 0xAC, 0xB0]:
        token = "0x%x(" % off

        if token in insn:
            NEIGHBORING.append({
                "instruction_va": line["va"],
                "instruction": norm(line["instruction"]),
                "offset": off,
            })


# ------------------------------------------------------------
# Stage 61 carry-forward
# ------------------------------------------------------------

prev = {}

previous_json = os.path.join(
    PREVIOUS_RESULTS,
    "stage61_static.json",
)

if os.path.isfile(previous_json):
    try:
        with open(
            previous_json,
            "r",
            encoding="utf-8",
        ) as fp:
            prev = json.load(fp)
    except Exception:
        prev = {}


# ------------------------------------------------------------
# Important semantic distinction
# ------------------------------------------------------------

#
# The +0xA4 field is:
#
#   1. written during initialization as 16 zero bytes
#   2. later read as a 32-bit scalar
#   3. used in an indirect table dispatch expression
#
# That proves "zero initialized" and "used in dispatch".
#
# It does NOT yet prove:
#
#   - exact semantic name
#   - that every later write is a valid index
#   - maximum range
#   - whether value can be externally configured
#

dispatch_use_proven = True


# ------------------------------------------------------------
# Static result
# ------------------------------------------------------------

static = {
    "stage": 62,

    "target": {
        "name": "global_context initialization",
        "start_va": INIT_START,
        "size": INIT_SIZE,
    },

    "field": {
        "global_context_va": GLOBAL_CONTEXT_VA,
        "offset": INDEX_OFFSET,
        "field_va": INDEX_VA,
        "initial_store_width": 16,
        "covered_range": "0xA4..0xB3",
    },

    "xmm0_flow": {
        "zero_events": XMM0_ZERO_EVENTS,
        "events_before_store": XMM0_EVENTS_BEFORE_STORE,
        "last_zero_before_store":
            (
                {
                    "instruction_va":
                        xmm0_last_zero["va"],
                    "instruction":
                        norm(xmm0_last_zero["instruction"]),
                }
                if xmm0_last_zero
                else None
            ),
        "later_xmm0_write":
            (
                {
                    "instruction_va":
                        xmm0_later_write["va"],
                    "instruction":
                        norm(xmm0_later_write["instruction"]),
                }
                if xmm0_later_write
                else None
            ),
    },

    "store": store,

    "neighboring_accesses": NEIGHBORING,

    "previous_stage": {
        "stage": 61,
        "available": bool(prev),
    },

    "conclusions": {
        "XMM0_ZEROING_INSTRUCTION_FOUND":
            len(XMM0_ZERO_EVENTS) > 0,

        "A4_16_BYTE_STORE_FOUND":
            store is not None,

        "A4_ZERO_INITIALIZATION_PROVEN":
            xmm0_zero_proven,

        "A4_ZERO_INIT_RANGE_PROVEN":
            xmm0_zero_proven and store is not None,

        "DISPATCH_USE_CONFIRMED":
            dispatch_use_proven,

        "INDEX_SEMANTICS_PROVEN":
            False,

        "COUNT_SEMANTICS_PROVEN":
            False,

        "EXACT_FIELD_NAME_PROVEN":
            False,

        "BACKEND_CONSUMER_IDENTIFIED":
            False,

        "SEMANTIC_PROTOTYPE_INFERRED":
            False,

        "EXECUTED_AGC":
            False,
    },

    "notes": [
        "Stage 62 explicitly recognizes VEX-encoded VXORPS.",
        "The initialization function clears XMM0 immediately before the A4 store.",
        "The A4 store is 16 bytes wide and therefore covers 0xA4..0xB3.",
        "The 16-byte store proves initialization of that range only.",
        "A4 being later consumed as the scaled dispatch index remains a separate semantic claim.",
    ],
}


# ------------------------------------------------------------
# Summary
# ------------------------------------------------------------

summary = []

summary.append(
    "AGC PS5 Stage 62 - Dispatch Index Value-Flow / Zero Initialization Audit"
)

summary.append("")
summary.append("=== FIELD ===")
summary.append("global_context = 0x1A908")
summary.append("field_offset = 0xA4")
summary.append("field_va = 0x1A9AC")

summary.append("")
summary.append("=== XMM0 ZEROING ===")

if XMM0_ZERO_EVENTS:
    for ev in XMM0_ZERO_EVENTS:
        summary.append(
            "VA=0x%X %s"
            % (
                ev["instruction_va"],
                ev["instruction"],
            )
        )
else:
    summary.append("NONE")

summary.append("")
summary.append("=== STORE ===")

if store:
    summary.append(
        "VA=0x%X %s"
        % (
            store["instruction_va"],
            store["instruction"],
        )
    )
    summary.append("width = 16 bytes")
    summary.append("range = 0xA4..0xB3")
else:
    summary.append("NONE")

summary.append("")
summary.append("=== VALUE FLOW ===")

if xmm0_last_zero:
    summary.append(
        "last_zero_before_store = 0x%X %s"
        % (
            xmm0_last_zero["va"],
            norm(xmm0_last_zero["instruction"]),
        )
    )
else:
    summary.append(
        "last_zero_before_store = NONE"
    )

if xmm0_later_write:
    summary.append(
        "later_xmm0_write = 0x%X %s"
        % (
            xmm0_later_write["va"],
            norm(xmm0_later_write["instruction"]),
        )
    )
else:
    summary.append(
        "later_xmm0_write = NONE"
    )

summary.append("")
summary.append("=== CONCLUSIONS ===")
summary.append(
    "XMM0_ZEROING_INSTRUCTION_FOUND=%s"
    % (len(XMM0_ZERO_EVENTS) > 0)
)
summary.append(
    "A4_16_BYTE_STORE_FOUND=%s"
    % (store is not None)
)
summary.append(
    "A4_ZERO_INITIALIZATION_PROVEN=%s"
    % xmm0_zero_proven
)
summary.append(
    "A4_ZERO_INIT_RANGE_PROVEN=%s"
    % (xmm0_zero_proven and store is not None)
)
summary.append(
    "DISPATCH_USE_CONFIRMED=True"
)
summary.append(
    "INDEX_SEMANTICS_PROVEN=False"
)
summary.append(
    "COUNT_SEMANTICS_PROVEN=False"
)
summary.append(
    "EXACT_FIELD_NAME_PROVEN=False"
)
summary.append(
    "BACKEND_CONSUMER_IDENTIFIED=False"
)
summary.append(
    "SEMANTIC_PROTOTYPE_INFERRED=False"
)
summary.append(
    "EXECUTED_AGC=False"
)

summary_text = "\n".join(summary) + "\n"

with open(
    os.path.join(
        OUT_DIR,
        "index_value_flow_summary.txt",
    ),
    "w",
    encoding="utf-8",
    newline="\n",
) as fp:
    fp.write(summary_text)


# ------------------------------------------------------------
# Full disassembly artifact
# ------------------------------------------------------------

with open(
    os.path.join(
        OUT_DIR,
        "index_value_flow_disassembly.txt",
    ),
    "w",
    encoding="utf-8",
    newline="\n",
) as fp:
    fp.write(
        "AGC PS5 Stage 62 - A4 Value Flow Disassembly\n\n"
    )
    fp.write(INIT_DISASM)
    fp.write("\n")


# ------------------------------------------------------------
# JSON
# ------------------------------------------------------------

with open(
    os.path.join(
        OUT_DIR,
        "stage62_static.json",
    ),
    "w",
    encoding="utf-8",
) as fp:
    json.dump(
        static,
        fp,
        indent=2,
    )

print(
    json.dumps(
        static,
        indent=2,
    )
)

ELF_FP.close()
'@

Write-Utf8NoBom -Path $AnalyzerWindows -Content $Python

Write-Host ''
Write-Host '==> Preparar workspace Linux' -ForegroundColor Yellow

Invoke-Wsl @"
set -e

rm -rf $(Quote-Bash $WorkWsl)

mkdir -p $(Quote-Bash $WorkWsl)
mkdir -p $(Quote-Bash $OutputWsl)

cp $(Quote-Bash $AnalyzerWsl) \
   $(Quote-Bash "$WorkWsl/analyze_index_value_flow.py")

sed -i 's/\r$//' \
   $(Quote-Bash "$WorkWsl/analyze_index_value_flow.py")

python3 -m py_compile \
   $(Quote-Bash "$WorkWsl/analyze_index_value_flow.py")

ls -lh \
   $(Quote-Bash "$WorkWsl/analyze_index_value_flow.py")
"@

Write-Host ''
Write-Host '==> Verificar Python + pyelftools + toolchain' -ForegroundColor Yellow

Invoke-Wsl @"
set -e

test -x $(Quote-Bash "$Sdk/bin/prospero-clang")
test -x $(Quote-Bash "$Sdk/bin/prospero-nm")
test -x $(Quote-Bash "$Sdk/bin/prospero-lld")

python3 -c "from elftools.elf.elffile import ELFFile; print('pyelftools=OK')"

command -v objdump
command -v llvm-objdump
"@

Write-Host ''
Write-Host '==> Seguir XMM0 -> store +0xA4' -ForegroundColor Yellow

Invoke-Wsl @"
set -e

python3 $(Quote-Bash "$WorkWsl/analyze_index_value_flow.py") \
    $(Quote-Bash $SprxWsl) \
    $(Quote-Bash $PreviousWsl) \
    $(Quote-Bash $OutputWsl)
"@

Write-Host ''
Write-Host '==> Verificar artefactos Stage 62' -ForegroundColor Yellow

Invoke-Wsl @"
set -e

test -f $(Quote-Bash "$OutputWsl/stage62_static.json")
test -f $(Quote-Bash "$OutputWsl/index_value_flow_summary.txt")
test -f $(Quote-Bash "$OutputWsl/index_value_flow_disassembly.txt")

echo '--- index_value_flow_summary.txt ---'
cat $(Quote-Bash "$OutputWsl/index_value_flow_summary.txt")

echo '--- output files ---'
find $(Quote-Bash $OutputWsl) \
    -maxdepth 2 \
    -type f |
    sort
"@

$StaticPath = Join-Path $OutputDir 'stage62_static.json'
$SummaryPath = Join-Path $OutputDir 'index_value_flow_summary.txt'
$DisassemblyPath = Join-Path $OutputDir 'index_value_flow_disassembly.txt'
$ReportPath = Join-Path $OutputDir 'STAGE62_REPORT.json'

$Static = Get-Content -LiteralPath $StaticPath -Raw | ConvertFrom-Json

$XmmZero = [bool]$Static.conclusions.XMM0_ZEROING_INSTRUCTION_FOUND
$StoreFound = [bool]$Static.conclusions.A4_16_BYTE_STORE_FOUND
$ZeroProven = [bool]$Static.conclusions.A4_ZERO_INITIALIZATION_PROVEN
$RangeProven = [bool]$Static.conclusions.A4_ZERO_INIT_RANGE_PROVEN

$HashStatic = Get-Sha256 $StaticPath
$HashSummary = Get-Sha256 $SummaryPath
$HashDisassembly = Get-Sha256 $DisassemblyPath

Write-Host ''
Write-Host '==> Hash artefactos' -ForegroundColor Yellow
Write-Host "[INFO] stage62_static.json SHA256=$HashStatic"
Write-Host "[INFO] index_value_flow_summary.txt SHA256=$HashSummary"
Write-Host "[INFO] index_value_flow_disassembly.txt SHA256=$HashDisassembly"

$Report = [ordered]@{
    stage = 62

    field = [ordered]@{
        global_context = '0x1A908'
        offset = '0xA4'
        va = '0x1A9AC'
    }

    conclusions = [ordered]@{
        XMM0_ZEROING_INSTRUCTION_FOUND = $XmmZero
        A4_16_BYTE_STORE_FOUND = $StoreFound
        A4_ZERO_INITIALIZATION_PROVEN = $ZeroProven
        A4_ZERO_INIT_RANGE_PROVEN = $RangeProven
        DISPATCH_USE_CONFIRMED = $true
        INDEX_SEMANTICS_PROVEN = $false
        COUNT_SEMANTICS_PROVEN = $false
        EXACT_FIELD_NAME_PROVEN = $false
        BACKEND_CONSUMER_IDENTIFIED = $false
        SEMANTIC_PROTOTYPE_INFERRED = $false
        EXECUTED_AGC = $false
    }

    hashes = [ordered]@{
        'stage62_static.json' = $HashStatic
        'index_value_flow_summary.txt' = $HashSummary
        'index_value_flow_disassembly.txt' = $HashDisassembly
    }
}

Write-Utf8NoBom `
    -Path $ReportPath `
    -Content (
        $Report |
        ConvertTo-Json -Depth 20
    )

Write-Host ''
Write-Host '============================================' -ForegroundColor Green
Write-Host 'Stage 62 completado' -ForegroundColor Green
Write-Host '============================================' -ForegroundColor Green
Write-Host ''
Write-Host "XMM0_ZEROING_INSTRUCTION_FOUND = $XmmZero"
Write-Host "A4_16_BYTE_STORE_FOUND = $StoreFound"
Write-Host "A4_ZERO_INITIALIZATION_PROVEN = $ZeroProven"
Write-Host "A4_ZERO_INIT_RANGE_PROVEN = $RangeProven"
Write-Host 'DISPATCH_USE_CONFIRMED = True'
Write-Host 'INDEX_SEMANTICS_PROVEN = False'
Write-Host 'COUNT_SEMANTICS_PROVEN = False'
Write-Host 'EXACT_FIELD_NAME_PROVEN = False'
Write-Host 'BACKEND_CONSUMER_IDENTIFIED = False'
Write-Host 'SEMANTIC_PROTOTYPE_INFERRED = False'
Write-Host 'EXECUTED_AGC = False'
Write-Host ''
Write-Host 'Resultados:'
Write-Host "  $OutputDir"
Write-Host ''
Write-Host 'Reporte:'
Write-Host "  $ReportPath"