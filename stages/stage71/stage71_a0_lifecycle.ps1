$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ============================================================
# AGC PS5 Stage 71
# Global +0xA0 Lifecycle / Reset / Consumer Provenance Audit
# ============================================================

$StageDir = Split-Path -Parent $MyInvocation.MyCommand.Path

$Sprx = 'D:\agc_work\sce_stubs\libSceAgcDriver.sprx'
$NidDb = 'D:\sdk-master\sce_stubs\aerolib.csv'

$PreviousStageDir = 'D:\agc_work\stage70_results'
$OutputDir = 'D:\agc_work\stage71_results'

$SprxWsl = '/mnt/d/agc_work/sce_stubs/libSceAgcDriver.sprx'
$NidDbWsl = '/mnt/d/sdk-master/sce_stubs/aerolib.csv'

$PreviousWsl = '/mnt/d/agc_work/stage70_results'
$OutputWsl = '/mnt/d/agc_work/stage71_results'

$TmpWsl = '/tmp/agc_stage71'

$Sdk = '/opt/ps5-payload-sdk'
$Clang = "$Sdk/bin/prospero-clang"
$Nm = "$Sdk/bin/prospero-nm"
$Lld = "$Sdk/bin/prospero-lld"

Write-Host ''
Write-Host '============================================'
Write-Host 'AGC PS5 Stage 71 - Global +0xA0 Lifecycle / Reset / Consumer Audit'
Write-Host '============================================'
Write-Host "[INFO] StageDir        = $StageDir"
Write-Host "[INFO] SPRX            = $Sprx"
Write-Host "[INFO] NID DB          = $NidDb"
Write-Host "[INFO] Previous stage  = $PreviousStageDir"
Write-Host "[INFO] Output          = $OutputDir"
Write-Host "[INFO] SPRX WSL        = $SprxWsl"
Write-Host "[INFO] Previous WSL    = $PreviousWsl"
Write-Host "[INFO] Output WSL      = $OutputWsl"
Write-Host "[INFO] SDK             = $Sdk"

if (-not (Test-Path -LiteralPath $Sprx)) {
    throw "No existe el SPRX: $Sprx"
}

if (-not (Test-Path -LiteralPath $NidDb)) {
    throw "No existe el NID DB: $NidDb"
}

if (-not (Test-Path -LiteralPath $PreviousStageDir)) {
    throw "No existe el directorio Stage 70: $PreviousStageDir"
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

function Invoke-WslStep {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Label,

        [Parameter(Mandatory = $true)]
        [string]$Command
    )

    Write-Host ''
    Write-Host "==> $Label"
    Write-Host ''
    Write-Host '[WSL] set -e'
    Write-Host ''
    Write-Host $Command

    $Output = & wsl.exe bash -lc "set -e; $Command" 2>&1
    $Code = $LASTEXITCODE

    foreach ($Line in $Output) {
        Write-Host $Line
    }

    if ($Code -ne 0) {
        throw "WSL command failed with exit code $Code."
    }

    return ($Output -join "`n")
}

function Get-Sha256 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }

    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

# ============================================================
# Preparar workspace
# ============================================================

$PrepCommand = @"
rm -rf '$TmpWsl'

mkdir -p '$TmpWsl'
mkdir -p '$OutputWsl'

test -f '$SprxWsl'
test -f '$NidDbWsl'
test -d '$PreviousWsl'

echo 'Workspace preparado'
"@

Invoke-WslStep `
    -Label 'Preparar workspace Linux' `
    -Command $PrepCommand | Out-Null

# ============================================================
# Verificar toolchain
# ============================================================

$CheckCommand = @"
test -x '$Clang'
test -x '$Nm'
test -x '$Lld'

echo '--- prospero-clang ---'
'$Clang' --version

echo '--- prospero-nm ---'
'$Nm' --version

echo '--- pyelftools ---'
python3 -c "from elftools.elf.elffile import ELFFile; print('pyelftools=OK')"

echo '--- objdump ---'
command -v objdump

echo '--- llvm-objdump ---'
command -v llvm-objdump
"@

Invoke-WslStep `
    -Label 'Verificar Python + pyelftools + toolchain' `
    -Command $CheckCommand | Out-Null

# ============================================================
# Analyzer
# ============================================================

$AnalyzerPath = Join-Path $OutputDir 'analyze_a0_lifecycle.py'

$Python = @'
#!/usr/bin/env python3

import json
import re
import subprocess
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile


SPRX = Path(sys.argv[1])
NID_DB = Path(sys.argv[2])
PREVIOUS_DIR = Path(sys.argv[3])
OUTPUT_DIR = Path(sys.argv[4])

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

GLOBAL_CONTEXT_VA = 0x1A908
A0_OFFSET = 0xA0
A4_OFFSET = 0xA4

FIELD_VA = GLOBAL_CONTEXT_VA + A0_OFFSET
A4_VA = GLOBAL_CONTEXT_VA + A4_OFFSET

TABLE_STRIDE = 0x78

SUBMIT_VA = 0x18B0
SUBMIT_SIZE = 380

MULTI_VA = 0x4650
MULTI_SIZE = 579

TARGET_NAME = "sceAgcDriverSubmitCommandBuffer"
TARGET_NID = "b4fpgH5ZXxQ"


def write_json(path, obj):
    path.write_text(
        json.dumps(
            obj,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
        newline="\n",
    )


def write_text(path, text):
    path.write_text(
        text,
        encoding="utf-8",
        newline="\n",
    )


def load_previous():
    candidates = [
        PREVIOUS_DIR / "stage70_static.json",
        PREVIOUS_DIR / "STAGE70_REPORT.json",
        PREVIOUS_DIR / "a0_provenance.json",
    ]

    for path in candidates:
        if not path.exists():
            continue

        try:
            with path.open("r", encoding="utf-8") as fp:
                return json.load(fp)
        except Exception:
            pass

    return {}


PREVIOUS = load_previous()


def previous_conclusions(obj):
    if not isinstance(obj, dict):
        return {}

    merged = {}

    for key in (
        "conclusions",
        "result",
    ):
        value = obj.get(key)

        if isinstance(value, dict):
            nested = value.get("conclusions")

            if isinstance(nested, dict):
                merged.update(nested)

            for k, v in value.items():
                if isinstance(k, str) and k.isupper():
                    merged[k] = v

    return merged


PREVIOUS_CONCLUSIONS = previous_conclusions(PREVIOUS)


def load_segments():
    segments = []

    with SPRX.open("rb") as fp:
        elf = ELFFile(fp)

        for seg in elf.iter_segments():
            if seg.header.p_type != "PT_LOAD":
                continue

            segments.append(
                {
                    "offset": int(seg.header.p_offset),
                    "vaddr": int(seg.header.p_vaddr),
                    "filesz": int(seg.header.p_filesz),
                    "memsz": int(seg.header.p_memsz),
                    "flags": int(seg.header.p_flags),
                }
            )

    return segments


SEGMENTS = load_segments()


def is_exec(seg):
    return bool(seg["flags"] & 1)


def dump_segment(seg, index):
    path = OUTPUT_DIR / f".stage71_seg_{index}.bin"

    with SPRX.open("rb") as fp:
        fp.seek(seg["offset"])
        data = fp.read(seg["filesz"])

    path.write_bytes(data)
    return path


def disassemble_segment(seg, index):
    path = dump_segment(seg, index)

    cmd = [
        "objdump",
        "-D",
        "-b",
        "binary",
        "-m",
        "i386:x86-64",
        "--adjust-vma=0x{:x}".format(seg["vaddr"]),
        str(path),
    ]

    try:
        return subprocess.check_output(
            cmd,
            stderr=subprocess.STDOUT,
            text=True,
        )
    finally:
        try:
            path.unlink()
        except Exception:
            pass


def parse_disassembly(text):
    rows = []

    rx = re.compile(
        r"^\s*([0-9a-fA-F]+):\s+"
        r"((?:[0-9a-fA-F]{2}\s+)+)"
        r"(.*)$"
    )

    for line in text.splitlines():
        m = rx.match(line)

        if not m:
            continue

        try:
            va = int(m.group(1), 16)
        except ValueError:
            continue

        raw = []

        for token in m.group(2).strip().split():
            try:
                raw.append(int(token, 16))
            except ValueError:
                pass

        rows.append(
            {
                "va": va,
                "bytes": raw,
                "instruction": m.group(3).strip(),
            }
        )

    return rows


def norm(ins):
    return re.sub(r"\s+", " ", ins.strip().lower())


def extract_memory_base(ins):
    low = norm(ins)

    patterns = [
        r"0xa0\(%([a-z0-9]+)\)",
        r"0xa0\(%([a-z0-9]+),",
    ]

    for p in patterns:
        m = re.search(p, low)

        if m:
            return m.group(1)

    return None


def parse_lea_global(ins):
    low = norm(ins)

    if not low.startswith("lea "):
        return None

    if "# 0x1a908" not in low:
        return None

    m = re.search(
        r",%([a-z0-9]+)",
        low,
    )

    if not m:
        return None

    return m.group(1)


def parse_immediate_store(ins):
    low = norm(ins)

    if "0xa0(" not in low:
        return None

    m = re.match(
        r"^mov(?:b|w|l|q)?\s+\$"
        r"(0x[0-9a-f]+|[0-9]+),"
        r".*0xa0\(",
        low,
    )

    if not m:
        return None

    raw = m.group(1)

    try:
        if raw.startswith("0x"):
            return int(raw, 16)

        return int(raw, 10)
    except ValueError:
        return None


def classify_a0_access(ins):
    low = norm(ins)

    if "0xa0(" not in low:
        return None

    imm = parse_immediate_store(low)

    if imm is not None:
        return {
            "type": "STORE_IMMEDIATE",
            "value": imm,
        }

    if low.startswith(
        (
            "vmovups ",
            "mov ",
            "movb ",
            "movw ",
            "movl ",
            "movq ",
        )
    ):
        operands = low.split(" ", 1)[1]

        if "," in operands:
            src, dst = operands.split(",", 1)

            if "0xa0(" in dst and "0xa0(" not in src:
                return {
                    "type": "STORE",
                    "value": None,
                }

            if "0xa0(" in src and "0xa0(" not in dst:
                return {
                    "type": "READ",
                    "value": None,
                }

    if low.startswith(
        (
            "cmp ",
            "cmpl ",
            "test ",
            "add ",
            "sub ",
            "and ",
            "or ",
            "xor ",
            "imul ",
        )
    ):
        return {
            "type": "OTHER",
            "value": None,
        }

    return {
        "type": "OTHER",
        "value": None,
    }


def previous_global_lea(rows, index, base, max_back=96):
    start = max(0, index - max_back)

    for j in range(index - 1, start - 1, -1):
        reg = parse_lea_global(rows[j]["instruction"])

        if reg == base:
            return {
                "va": rows[j]["va"],
                "instruction": rows[j]["instruction"],
                "register": reg,
                "distance": index - j,
            }

        low = norm(rows[j]["instruction"])

        if re.search(
            r"\b(?:mov|lea|xor|add|sub|and|or)\b.*,%{}".format(
                re.escape(base)
            ),
            low,
        ):
            break

    return None


def function_owner(va):
    try:
        with SPRX.open("rb") as fp:
            elf = ELFFile(fp)

            sections = []

            symtab = elf.get_section_by_name(".symtab")
            dynsym = elf.get_section_by_name(".dynsym")

            if symtab is not None:
                sections.append(symtab)

            if dynsym is not None:
                sections.append(dynsym)

            for section in sections:
                for sym in section.iter_symbols():
                    if sym["st_info"]["type"] != "STT_FUNC":
                        continue

                    start = int(sym["st_value"])
                    size = int(sym["st_size"])

                    if size <= 0:
                        continue

                    if start <= va < start + size:
                        return {
                            "name": sym.name,
                            "start_va": start,
                            "size": size,
                        }

    except Exception:
        pass

    return None


def function_range(va):
    owner = function_owner(va)

    if owner is not None:
        return owner

    if SUBMIT_VA <= va < SUBMIT_VA + SUBMIT_SIZE:
        return {
            "name": TARGET_NAME,
            "start_va": SUBMIT_VA,
            "size": SUBMIT_SIZE,
        }

    if MULTI_VA <= va < MULTI_VA + MULTI_SIZE:
        return {
            "name": "sceAgcDriverSubmitMultiCommandBuffers",
            "start_va": MULTI_VA,
            "size": MULTI_SIZE,
        }

    return None


def make_window(rows, va, before=16, after=32):
    pos = None

    for i, row in enumerate(rows):
        if row["va"] == va:
            pos = i
            break

    if pos is None:
        return []

    start = max(0, pos - before)
    end = min(len(rows), pos + after + 1)

    return rows[start:end]


def window_text(rows):
    return "\n".join(
        "0x{:X}: {}".format(
            row["va"],
            row["instruction"],
        )
        for row in rows
    )


# ============================================================
# Desensamblado global
# ============================================================

ALL_ROWS = []

for index, seg in enumerate(SEGMENTS):
    if not is_exec(seg):
        continue

    text = disassemble_segment(seg, index)
    ALL_ROWS.extend(parse_disassembly(text))

ALL_ROWS.sort(key=lambda x: x["va"])


# ============================================================
# Escaneo A0
# ============================================================

A0_ACCESSES = []

for i, row in enumerate(ALL_ROWS):
    classification = classify_a0_access(row["instruction"])

    if classification is None:
        continue

    base = extract_memory_base(row["instruction"])

    global_lea = None

    if base:
        global_lea = previous_global_lea(
            ALL_ROWS,
            i,
            base,
        )

    owner = function_range(row["va"])

    A0_ACCESSES.append(
        {
            "instruction_va": row["va"],
            "instruction": row["instruction"],
            "base_register": base,
            "access_type": classification["type"],
            "immediate_value": classification["value"],
            "global_context_proven": global_lea is not None,
            "global_context_lea": global_lea,
            "owner": owner,
        }
    )


GLOBAL_A0 = [
    x for x in A0_ACCESSES
    if x["global_context_proven"]
]


GLOBAL_A0_STORES = [
    x for x in GLOBAL_A0
    if x["access_type"]
    in (
        "STORE",
        "STORE_IMMEDIATE",
    )
]


GLOBAL_A0_READS = [
    x for x in GLOBAL_A0
    if x["access_type"] == "READ"
]


GLOBAL_A0_OTHER = [
    x for x in GLOBAL_A0
    if x["access_type"] == "OTHER"
]


# ============================================================
# Ciclo de vida de stores
# ============================================================

STORE_EVENTS = sorted(
    GLOBAL_A0_STORES,
    key=lambda x: x["instruction_va"],
)


INITIAL_VALUE_EVENT = None
RESET_EVENTS = []

for event in STORE_EVENTS:
    if (
        event["access_type"] == "STORE_IMMEDIATE"
        and event["immediate_value"] == 1
        and INITIAL_VALUE_EVENT is None
    ):
        INITIAL_VALUE_EVENT = event

    if (
        event["access_type"] == "STORE_IMMEDIATE"
        and event["immediate_value"] == 0
    ):
        RESET_EVENTS.append(event)


FIRST_RESET_AFTER_INIT = None

if INITIAL_VALUE_EVENT is not None:
    for event in RESET_EVENTS:
        if (
            event["instruction_va"]
            > INITIAL_VALUE_EVENT["instruction_va"]
        ):
            FIRST_RESET_AFTER_INIT = event
            break


OTHER_POST_INIT_STORES = []

if INITIAL_VALUE_EVENT is not None:
    for event in STORE_EVENTS:
        if (
            event["instruction_va"]
            > INITIAL_VALUE_EVENT["instruction_va"]
            and event["instruction_va"]
            != (
                FIRST_RESET_AFTER_INIT["instruction_va"]
                if FIRST_RESET_AFTER_INIT is not None
                else -1
            )
        ):
            OTHER_POST_INIT_STORES.append(event)


# ============================================================
# Submit/Multi readers
# ============================================================

SUBMIT_A0_READS = [
    x for x in GLOBAL_A0_READS
    if SUBMIT_VA
    <= x["instruction_va"]
    < SUBMIT_VA + SUBMIT_SIZE
]


MULTI_A0_READS = [
    x for x in GLOBAL_A0_READS
    if MULTI_VA
    <= x["instruction_va"]
    < MULTI_VA + MULTI_SIZE
]


def nearby_stride_loop(read):
    va = read["instruction_va"]

    rows = make_window(
        ALL_ROWS,
        va,
        before=0,
        after=30,
    )

    joined = " ".join(
        norm(x["instruction"])
        for x in rows
    )

    return (
        "0x78" in joined
        and any(
            token in joined
            for token in (
                "cmp ",
                "cmpl ",
                "test ",
                "jne ",
                "jae ",
                "jb ",
                "jbe ",
            )
        )
    )


SUBMIT_BOUND_EVIDENCE = [
    x for x in SUBMIT_A0_READS
    if nearby_stride_loop(x)
]


MULTI_BOUND_EVIDENCE = [
    x for x in MULTI_A0_READS
    if nearby_stride_loop(x)
]


# ============================================================
# Correlación con A4 dispatch
# ============================================================

def has_a4_dispatch_near(va):
    rows = make_window(
        ALL_ROWS,
        va,
        before=0,
        after=26,
    )

    saw_scale = False
    saw_call = False

    for row in rows:
        low = norm(row["instruction"])

        if (
            "imul" in low
            and "0x78" in low
        ):
            saw_scale = True

        if (
            "call" in low
            and (
                "0x50(" in low
                or "0x58(" in low
            )
        ):
            saw_call = True

    return saw_scale and saw_call


SUBMIT_A4_CORRELATED = any(
    has_a4_dispatch_near(x["instruction_va"])
    for x in SUBMIT_A0_READS
)

MULTI_A4_CORRELATED = any(
    has_a4_dispatch_near(x["instruction_va"])
    for x in MULTI_A0_READS
)


# ============================================================
# Proveniencia de los resets
# ============================================================

RESET_ANALYSIS = []

for reset in RESET_EVENTS:
    owner = reset["owner"]

    reset_window = make_window(
        ALL_ROWS,
        reset["instruction_va"],
        before=12,
        after=20,
    )

    RESET_ANALYSIS.append(
        {
            "event": reset,
            "owner": owner,
            "window": reset_window,
            "window_text": window_text(reset_window),
        }
    )


# ============================================================
# Clasificación conservadora
# ============================================================

stage70_count_proven = bool(
    PREVIOUS_CONCLUSIONS.get(
        "A0_COUNT_SEMANTICS_STRENGTHENED",
        False,
    )
    or PREVIOUS_CONCLUSIONS.get(
        "STAGE69_COUNT_SEMANTICS_CARRIED_FORWARD",
        False,
    )
    or PREVIOUS_CONCLUSIONS.get(
        "COUNT_SEMANTICS_PROVEN",
        False,
    )
)

a0_initialization_proven = (
    INITIAL_VALUE_EVENT is not None
    and INITIAL_VALUE_EVENT["global_context_proven"]
)

a0_reset_proven = (
    FIRST_RESET_AFTER_INIT is not None
    and FIRST_RESET_AFTER_INIT["global_context_proven"]
    and FIRST_RESET_AFTER_INIT["immediate_value"] == 0
)

a0_has_other_post_init_stores = (
    len(OTHER_POST_INIT_STORES) > 0
)

lifecycle_proven = (
    a0_initialization_proven
    and a0_reset_proven
)

count_semantics_proven = (
    stage70_count_proven
    and (
        len(SUBMIT_BOUND_EVIDENCE) > 0
        or len(MULTI_BOUND_EVIDENCE) > 0
    )
)

dispatch_correlation_proven = (
    SUBMIT_A4_CORRELATED
    and MULTI_A4_CORRELATED
)


# ============================================================
# Resultado
# ============================================================

RESULT = {
    "stage": 71,

    "target": {
        "global_context_va": GLOBAL_CONTEXT_VA,
        "a0_offset": A0_OFFSET,
        "a0_va": FIELD_VA,
        "a4_offset": A4_OFFSET,
        "table_stride": TABLE_STRIDE,
        "submit_va": SUBMIT_VA,
        "multi_va": MULTI_VA,
    },

    "previous_stage": {
        "stage70_available": bool(PREVIOUS),
        "stage70_count_semantics":
            stage70_count_proven,
    },

    "global_a0_accesses": A0_ACCESSES,

    "global_a0_stores": GLOBAL_A0_STORES,

    "lifecycle": {
        "initial_value_event":
            INITIAL_VALUE_EVENT,

        "reset_events":
            RESET_EVENTS,

        "first_reset_after_initialization":
            FIRST_RESET_AFTER_INIT,

        "other_post_initialization_stores":
            OTHER_POST_INIT_STORES,
    },

    "submit": {
        "a0_reads":
            SUBMIT_A0_READS,

        "bound_evidence":
            SUBMIT_BOUND_EVIDENCE,

        "a4_dispatch_correlation":
            SUBMIT_A4_CORRELATED,
    },

    "multi": {
        "a0_reads":
            MULTI_A0_READS,

        "bound_evidence":
            MULTI_BOUND_EVIDENCE,

        "a4_dispatch_correlation":
            MULTI_A4_CORRELATED,
    },

    "reset_analysis":
        RESET_ANALYSIS,

    "conclusions": {
        "GLOBAL_A0_SCAN_COMPLETED":
            True,

        "A0_INITIALIZATION_TO_1_PROVEN":
            a0_initialization_proven,

        "A0_RESET_TO_0_PROVEN":
            a0_reset_proven,

        "A0_LIFECYCLE_INITIALIZE_RESET_PROVEN":
            lifecycle_proven,

        "A0_OTHER_POST_INITIALIZATION_STORES_FOUND":
            a0_has_other_post_init_stores,

        "SUBMIT_A0_BOUND_USAGE_CORROBORATED":
            len(SUBMIT_BOUND_EVIDENCE) > 0,

        "MULTI_A0_BOUND_USAGE_CORROBORATED":
            len(MULTI_BOUND_EVIDENCE) > 0,

        "SUBMIT_A4_DISPATCH_CORRELATED":
            SUBMIT_A4_CORRELATED,

        "MULTI_A4_DISPATCH_CORRELATED":
            MULTI_A4_CORRELATED,

        "A0_COUNT_SEMANTICS_PROVEN":
            count_semantics_proven,

        "A0_TABLE_LIFECYCLE_CORROBORATED":
            (
                lifecycle_proven
                and count_semantics_proven
            ),

        "INDEX_SEMANTICS_PROVEN":
            dispatch_correlation_proven,

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
        "Stage 71 reconstruye la secuencia de escrituras sobre global_context+0xA0.",
        "La escritura de 1 se trata como inicialización únicamente si la base llega por LEA directa de 0x1A908.",
        "La escritura posterior de 0 se trata como reset cuando también queda demostrada sobre el mismo global_context.",
        "Los lectores de SubmitCommandBuffer y SubmitMultiCommandBuffers se mantienen separados.",
        "El uso de +0xA4 como índice de dispatch sigue siendo evidencia independiente.",
        "La etapa no asigna un nombre público de SDK al campo +0xA0.",
        "La etapa no declara ejecución real de AGC."
    ],
}


# ============================================================
# Archivos
# ============================================================

write_json(
    OUTPUT_DIR / "stage71_static.json",
    RESULT,
)


summary = []

summary.append(
    "AGC PS5 Stage 71 - Global +0xA0 Lifecycle / Reset / Consumer Audit"
)
summary.append("")

summary.append("=== TARGET ===")
summary.append(
    "global_context = 0x{:X}".format(
        GLOBAL_CONTEXT_VA
    )
)
summary.append(
    "field_offset = 0x{:X}".format(
        A0_OFFSET
    )
)
summary.append(
    "field_va = 0x{:X}".format(
        FIELD_VA
    )
)
summary.append(
    "table_stride = 0x{:X}".format(
        TABLE_STRIDE
    )
)
summary.append("")

summary.append("=== GLOBAL +0xA0 STORES ===")

if GLOBAL_A0_STORES:
    for x in GLOBAL_A0_STORES:
        owner = (
            x["owner"]["name"]
            if x["owner"]
            else "<unknown>"
        )

        summary.append(
            "VA=0x{:X} owner={} type={} value={} base={} | {}".format(
                x["instruction_va"],
                owner,
                x["access_type"],
                x["immediate_value"],
                x["base_register"],
                x["instruction"],
            )
        )
else:
    summary.append("NONE")

summary.append("")
summary.append("=== INITIALIZATION ===")

if INITIAL_VALUE_EVENT is None:
    summary.append(
        "INITIALIZATION_TO_1 = NOT FOUND"
    )
else:
    summary.append(
        "VA=0x{:X}".format(
            INITIAL_VALUE_EVENT["instruction_va"]
        )
    )
    summary.append(
        INITIAL_VALUE_EVENT["instruction"]
    )
    summary.append(
        "global_context_base_proven = {}".format(
            INITIAL_VALUE_EVENT["global_context_proven"]
        )
    )

summary.append("")
summary.append("=== RESET EVENTS ===")

if RESET_EVENTS:
    for event in RESET_EVENTS:
        summary.append(
            "VA=0x{:X} | {} | base={} | proven={}".format(
                event["instruction_va"],
                event["instruction"],
                event["base_register"],
                event["global_context_proven"],
            )
        )
else:
    summary.append("NONE")

summary.append("")
summary.append("=== POST-INITIALIZATION OTHER STORES ===")

if OTHER_POST_INIT_STORES:
    for event in OTHER_POST_INIT_STORES:
        summary.append(
            "VA=0x{:X} | {} | value={} | base={}".format(
                event["instruction_va"],
                event["instruction"],
                event["immediate_value"],
                event["base_register"],
            )
        )
else:
    summary.append("NONE")

summary.append("")
summary.append("=== SUBMIT +0xA0 ===")

for read in SUBMIT_A0_READS:
    summary.append(
        "VA=0x{:X} | {} | bound_evidence={}".format(
            read["instruction_va"],
            read["instruction"],
            read in SUBMIT_BOUND_EVIDENCE,
        )
    )

if not SUBMIT_A0_READS:
    summary.append("NONE")

summary.append("")
summary.append("=== MULTI +0xA0 ===")

for read in MULTI_A0_READS:
    summary.append(
        "VA=0x{:X} | {} | bound_evidence={}".format(
            read["instruction_va"],
            read["instruction"],
            read in MULTI_BOUND_EVIDENCE,
        )
    )

if not MULTI_A0_READS:
    summary.append("NONE")

summary.append("")
summary.append("=== A4 DISPATCH CORRELATION ===")
summary.append(
    "SUBMIT_A4_DISPATCH_CORRELATED={}".format(
        SUBMIT_A4_CORRELATED
    )
)
summary.append(
    "MULTI_A4_DISPATCH_CORRELATED={}".format(
        MULTI_A4_CORRELATED
    )
)

summary.append("")
summary.append("=== CONCLUSIONS ===")

for key, value in RESULT["conclusions"].items():
    summary.append(
        "{}={}".format(
            key,
            value,
        )
    )

summary.append("")
summary.append("=== LIMIT ===")
summary.append(
    "La etapa demuestra el ciclo de vida observable de +0xA0 "
    "solo cuando la base del acceso puede seguirse estáticamente "
    "hasta global_context=0x1A908. Esto no convierte el campo en "
    "un nombre público de API ni demuestra ejecución real."
)

write_text(
    OUTPUT_DIR / "a0_lifecycle_summary.txt",
    "\n".join(summary) + "\n",
)


# ============================================================
# Disassembly focalizado
# ============================================================

disassembly = []

disassembly.append(
    "AGC PS5 Stage 71 - A0 Lifecycle Focused Disassembly"
)
disassembly.append("")


for label, events in (
    ("INITIALIZATION", [INITIAL_VALUE_EVENT] if INITIAL_VALUE_EVENT else []),
    ("RESET EVENTS", RESET_EVENTS),
):

    disassembly.append(
        "=== {} ===".format(label)
    )

    if not events:
        disassembly.append("NONE")
        disassembly.append("")
        continue

    for event in events:
        disassembly.append(
            "EVENT VA=0x{:X}".format(
                event["instruction_va"]
            )
        )

        window = make_window(
            ALL_ROWS,
            event["instruction_va"],
            before=18,
            after=28,
        )

        disassembly.append(
            window_text(window)
        )

        disassembly.append("")


disassembly.append(
    "=== SUBMIT A0 READS ==="
)

for event in SUBMIT_A0_READS:
    disassembly.append(
        window_text(
            make_window(
                ALL_ROWS,
                event["instruction_va"],
                before=4,
                after=28,
            )
        )
    )
    disassembly.append("")


disassembly.append(
    "=== MULTI A0 READS ==="
)

for event in MULTI_A0_READS:
    disassembly.append(
        window_text(
            make_window(
                ALL_ROWS,
                event["instruction_va"],
                before=4,
                after=28,
            )
        )
    )
    disassembly.append("")


write_text(
    OUTPUT_DIR / "a0_lifecycle_disassembly.txt",
    "\n".join(disassembly) + "\n",
)


# ============================================================
# JSON de correlación
# ============================================================

correlation = {
    "global_context": {
        "va": GLOBAL_CONTEXT_VA,
        "a0_offset": A0_OFFSET,
        "a0_va": FIELD_VA,
    },

    "lifecycle": {
        "initialize_to_1": INITIAL_VALUE_EVENT,
        "reset_to_0": FIRST_RESET_AFTER_INIT,
        "additional_post_init_stores":
            OTHER_POST_INIT_STORES,
    },

    "consumers": {
        "submit": SUBMIT_A0_READS,
        "multi": MULTI_A0_READS,
    },

    "semantic_status": {
        "count_semantics_proven":
            count_semantics_proven,

        "index_semantics_proven":
            dispatch_correlation_proven,

        "exact_field_name_proven":
            False,
    },
}

write_json(
    OUTPUT_DIR / "a0_lifecycle.json",
    correlation,
)


# ============================================================
# Report
# ============================================================

REPORT = {
    "stage": 71,
    "result": RESULT["conclusions"],
    "artifacts": {
        "stage71_static.json":
            "stage71_static.json",

        "a0_lifecycle_summary.txt":
            "a0_lifecycle_summary.txt",

        "a0_lifecycle_disassembly.txt":
            "a0_lifecycle_disassembly.txt",

        "a0_lifecycle.json":
            "a0_lifecycle.json",
    },
}

write_json(
    OUTPUT_DIR / "STAGE71_REPORT.json",
    REPORT,
)


print(
    json.dumps(
        RESULT,
        indent=2,
        ensure_ascii=False,
    )
)
'@

$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

[System.IO.File]::WriteAllText(
    $AnalyzerPath,
    $Python,
    $Utf8NoBom
)

$AnalyzerWsl = '/mnt/d/agc_work/stage71_results/analyze_a0_lifecycle.py'

# ============================================================
# Validar analyzer
# ============================================================

$PrepareAnalyzerCommand = @"
cp '$AnalyzerWsl' '$TmpWsl/analyze_a0_lifecycle.py'

sed -i 's/\r$//' \
    '$TmpWsl/analyze_a0_lifecycle.py'

python3 -m py_compile \
    '$TmpWsl/analyze_a0_lifecycle.py'

ls -lh \
    '$TmpWsl/analyze_a0_lifecycle.py'
"@

Invoke-WslStep `
    -Label 'Validar analizador Stage 71' `
    -Command $PrepareAnalyzerCommand | Out-Null

# ============================================================
# Ejecutar análisis
# ============================================================

$RunCommand = @"
python3 '$TmpWsl/analyze_a0_lifecycle.py' \
    '$SprxWsl' \
    '$NidDbWsl' \
    '$PreviousWsl' \
    '$OutputWsl'
"@

Invoke-WslStep `
    -Label 'Reconstruir ciclo de vida de global_context +0xA0' `
    -Command $RunCommand | Out-Null

# ============================================================
# Verificar artefactos
# ============================================================

$VerifyCommand = @"
set -e

test -f '$OutputWsl/stage71_static.json'
test -f '$OutputWsl/a0_lifecycle_summary.txt'
test -f '$OutputWsl/a0_lifecycle_disassembly.txt'
test -f '$OutputWsl/a0_lifecycle.json'
test -f '$OutputWsl/STAGE71_REPORT.json'

echo '--- a0_lifecycle_summary.txt ---'
cat '$OutputWsl/a0_lifecycle_summary.txt'

echo '--- output files ---'
find '$OutputWsl' \
    -maxdepth 1 \
    -type f |
    sort
"@

Invoke-WslStep `
    -Label 'Verificar artefactos Stage 71' `
    -Command $VerifyCommand | Out-Null

# ============================================================
# Hash
# ============================================================

Write-Host ''
Write-Host '==> Hash artefactos'

$FilesToHash = @(
    'stage71_static.json',
    'a0_lifecycle_summary.txt',
    'a0_lifecycle_disassembly.txt',
    'a0_lifecycle.json',
    'STAGE71_REPORT.json'
)

foreach ($Name in $FilesToHash) {
    $Path = Join-Path $OutputDir $Name

    if (Test-Path -LiteralPath $Path) {
        Write-Host (
            "[INFO] {0} SHA256={1}" -f
            $Name,
            (Get-Sha256 -Path $Path)
        )
    }
}

# ============================================================
# Limpiar temporales
# ============================================================

$CleanupCommand = @"
rm -rf '$TmpWsl'
"@

Invoke-WslStep `
    -Label 'Limpiar temporales Stage 71' `
    -Command $CleanupCommand | Out-Null

# ============================================================
# Resultado final
# ============================================================

$ReportPath = Join-Path $OutputDir 'STAGE71_REPORT.json'

if (-not (Test-Path -LiteralPath $ReportPath)) {
    throw "No existe STAGE71_REPORT.json"
}

$Report = Get-Content `
    -LiteralPath $ReportPath `
    -Raw |
    ConvertFrom-Json

Write-Host ''
Write-Host '============================================'
Write-Host 'Stage 71 completado'
Write-Host '============================================'

foreach ($Property in $Report.result.PSObject.Properties) {
    Write-Host (
        "{0} = {1}" -f
        $Property.Name,
        $Property.Value
    )
}

Write-Host ''
Write-Host 'Resultados:'
Write-Host "  $OutputDir"

Write-Host ''
Write-Host 'Reporte:'
Write-Host "  $ReportPath"