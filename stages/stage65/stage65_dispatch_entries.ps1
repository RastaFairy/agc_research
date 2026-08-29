#requires -Version 7.0

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$StageDir        = $PSScriptRoot
$Sprx            = 'D:\agc_work\sce_stubs\libSceAgcDriver.sprx'
$NidDb           = 'D:\sdk-master\sce_stubs\aerolib.csv'
$PreviousResults = 'D:\agc_work\stage64_results'
$OutputDir       = 'D:\agc_work\stage65_results'

$Sdk = '/opt/ps5-payload-sdk'

$SprxWsl        = '/mnt/d/agc_work/sce_stubs/libSceAgcDriver.sprx'
$NidDbWsl       = '/mnt/d/sdk-master/sce_stubs/aerolib.csv'
$PreviousWsl    = '/mnt/d/agc_work/stage64_results'
$OutputWsl      = '/mnt/d/agc_work/stage65_results'

$WorkWsl = '/tmp/agc_stage65'

$AnalyzerWindows = Join-Path $OutputDir 'analyze_dispatch_entries.py'
$AnalyzerWsl     = "$OutputWsl/analyze_dispatch_entries.py"
$ReportPath      = Join-Path $OutputDir 'STAGE65_REPORT.json'

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

function Quote-Bash {
    param(
        [Parameter(Mandatory)]
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

    & wsl.exe -d Ubuntu-24.04 --cd / -- bash -lc $Normalized

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

    $Content = $Content `
        -replace "`r`n", "`n" `
        -replace "`r", ""

    [System.IO.File]::WriteAllText(
        $Path,
        $Content,
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

Write-Host ''
Write-Host '============================================' -ForegroundColor Cyan
Write-Host 'AGC PS5 Stage 65 - Dispatch Table Entry / Consumer Audit' -ForegroundColor Cyan
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

if (-not (Test-Path -LiteralPath $Sprx -PathType Leaf)) {
    throw "No existe SPRX: $Sprx"
}

if (-not (Test-Path -LiteralPath $NidDb -PathType Leaf)) {
    throw "No existe NID DB: $NidDb"
}

if (-not (Test-Path -LiteralPath $PreviousResults -PathType Container)) {
    throw "No existe Stage 64 results: $PreviousResults"
}

# ============================================================
# Embedded Python analyzer
# ============================================================

$Python = @'
import csv
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
PREVIOUS_RESULTS = sys.argv[3]
OUT_DIR = sys.argv[4]

os.makedirs(OUT_DIR, exist_ok=True)


GLOBAL_CONTEXT_VA = 0x1A908
A4_OFFSET = 0xA4
A4_VA = GLOBAL_CONTEXT_VA + A4_OFFSET

DISPATCH_STRIDE = 0x78

SUBMIT_TABLE_OFFSET = 0x50
MULTI_TABLE_OFFSET = 0x58

SUBMIT_VA = 0x18B0
SUBMIT_SIZE = 380

MULTI_VA = 0x4650
MULTI_SIZE = 579


# ------------------------------------------------------------
# ELF helpers
# ------------------------------------------------------------

with open(
    SPRX,
    "rb",
) as elf_fp:
    ELF = ELFFile(elf_fp)

    SEGMENTS = []

    for seg in ELF.iter_segments():
        if seg["p_type"] != "PT_LOAD":
            continue

        SEGMENTS.append(
            {
                "offset": int(seg["p_offset"]),
                "vaddr": int(seg["p_vaddr"]),
                "filesz": int(seg["p_filesz"]),
                "memsz": int(seg["p_memsz"]),
                "flags": int(seg["p_flags"]),
            }
        )


def va_to_file(va):
    for seg in SEGMENTS:
        start = seg["vaddr"]
        end = start + seg["filesz"]

        if start <= va < end:
            return seg["offset"] + (va - start)

    return None


def va_in_memory(va):
    for seg in SEGMENTS:
        start = seg["vaddr"]
        end = start + seg["memsz"]

        if start <= va < end:
            return True

    return False


def read_va(va, size):
    off = va_to_file(va)

    if off is None:
        return b""

    with open(
        SPRX,
        "rb",
    ) as fp:
        fp.seek(off)
        return fp.read(size)


# ------------------------------------------------------------
# Symbol inventory
# ------------------------------------------------------------

SYMBOLS = []

with open(
    SPRX,
    "rb",
) as fp:
    elf = ELFFile(fp)

    seen = set()

    for section in elf.iter_sections():
        if section["sh_type"] not in (
            "SHT_SYMTAB",
            "SHT_DYNSYM",
        ):
            continue

        try:
            for sym in section.iter_symbols():
                value = int(sym["st_value"])
                size = int(sym["st_size"])

                if value == 0:
                    continue

                name = sym.name or ""

                key = (
                    value,
                    size,
                    name,
                )

                if key in seen:
                    continue

                seen.add(key)

                SYMBOLS.append(
                    {
                        "value": value,
                        "size": size,
                        "name": name,
                        "bind": str(
                            sym["st_info"]["bind"]
                        ),
                        "type": str(
                            sym["st_info"]["type"]
                        ),
                    }
                )
        except Exception:
            continue


def symbol_at(va):
    exact = []

    for sym in SYMBOLS:
        if sym["value"] == va:
            exact.append(sym)

    if exact:
        return exact

    owners = []

    for sym in SYMBOLS:
        if sym["size"] <= 0:
            continue

        if (
            sym["value"]
            <= va
            < sym["value"] + sym["size"]
        ):
            owners.append(sym)

    return owners


# ------------------------------------------------------------
# NID CSV lookup
# ------------------------------------------------------------

NID_MAP = {}

if os.path.isfile(NID_DB):
    try:
        with open(
            NID_DB,
            "r",
            encoding="utf-8",
            errors="replace",
        ) as fp:
            reader = csv.reader(fp)

            for row in reader:
                if not row:
                    continue

                values = [
                    item.strip()
                    for item in row
                ]

                if len(values) < 2:
                    continue

                nid = values[0]

                if nid:
                    NID_MAP[nid] = values[1]

    except Exception:
        NID_MAP = {}


def map_symbol_name(
    name,
):
    if not name:
        return None

    clean = name.split("#", 1)[0]

    if clean in NID_MAP:
        return NID_MAP[clean]

    return None


def enrich_symbol(sym):
    result = dict(sym)

    raw = result.get(
        "name",
        "",
    )

    result["mapped_name"] = map_symbol_name(
        raw
    )

    return result


# ------------------------------------------------------------
# Disassembly
# ------------------------------------------------------------

def disassemble(
    raw,
    start_va,
):
    if not raw:
        return ""

    tmp = None

    try:
        with tempfile.NamedTemporaryFile(
            prefix="agc_stage65_",
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
                "--adjust-vma=0x%x"
                % start_va,
                tmp,
            ],
            [
                "llvm-objdump",
                "-D",
                "--triple=x86_64",
                "--adjust-vma=0x%x"
                % start_va,
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


def parse_disassembly(
    text,
):
    result = []

    for line in text.splitlines():
        stripped = line.strip()

        m = re.match(
            r"^([0-9a-fA-F]+):\s+(.*)$",
            stripped,
        )

        if not m:
            continue

        va = int(
            m.group(1),
            16,
        )

        rest = m.group(2)

        tokens = rest.split()

        idx = 0

        while idx < len(tokens):
            token = tokens[idx]

            if re.fullmatch(
                r"[0-9a-fA-F]{2}",
                token,
            ):
                idx += 1
                continue

            break

        instruction = " ".join(
            tokens[idx:]
        ).strip()

        if not instruction:
            continue

        result.append(
            {
                "va": va,
                "instruction": instruction,
            }
        )

    return result


# ------------------------------------------------------------
# Read target functions
# ------------------------------------------------------------

submit_raw = read_va(
    SUBMIT_VA,
    SUBMIT_SIZE,
)

multi_raw = read_va(
    MULTI_VA,
    MULTI_SIZE,
)

submit_disassembly = disassemble(
    submit_raw,
    SUBMIT_VA,
)

multi_disassembly = disassemble(
    multi_raw,
    MULTI_VA,
)

submit_instructions = parse_disassembly(
    submit_disassembly
)

multi_instructions = parse_disassembly(
    multi_disassembly
)


# ------------------------------------------------------------
# Proven dispatch instructions
# ------------------------------------------------------------

def find_matching_scale_and_call(
    instructions,
    table_offset,
):
    matches = []

    for idx, ins in enumerate(
        instructions
    ):
        text = ins["instruction"]

        if (
            "imul" in text
            and "0x78" in text
            and "rax" in text
        ):
            nearby = []

            for next_ins in instructions[
                idx + 1 : idx + 7
            ]:
                nearby.append(
                    next_ins
                )

                if (
                    "call" in
                    next_ins["instruction"]
                ):
                    break

            calls = [
                x
                for x in nearby
                if "call" in x["instruction"]
            ]

            for call in calls:
                if (
                    (
                        "0x%x"
                        % table_offset
                    )
                    in call["instruction"]
                    and
                    "rax" in call[
                        "instruction"
                    ]
                ):
                    matches.append(
                        {
                            "scale": ins,
                            "nearby": nearby,
                            "call": call,
                        }
                    )

    return matches


submit_dispatch = find_matching_scale_and_call(
    submit_instructions,
    SUBMIT_TABLE_OFFSET,
)

multi_dispatch = find_matching_scale_and_call(
    multi_instructions,
    MULTI_TABLE_OFFSET,
)


# ------------------------------------------------------------
# Tables
# ------------------------------------------------------------

submit_table_base = None
multi_table_base = None


for idx, ins in enumerate(
    submit_instructions
):
    text = ins["instruction"]

    if (
        "lea" in text
        and "0x1a908" in text
        and "%rbx" in text
    ):
        if ins["va"] <= 0x1910:
            submit_table_base = GLOBAL_CONTEXT_VA
            break


for idx, ins in enumerate(
    multi_instructions
):
    text = ins["instruction"]

    if (
        "lea" in text
        and "0x1a908" in text
        and "%rcx" in text
    ):
        if ins["va"] <= 0x4770:
            multi_table_base = GLOBAL_CONTEXT_VA
            break


# ------------------------------------------------------------
# Extract base registers from proven dispatch
# ------------------------------------------------------------

def parse_dispatch_call(
    instruction,
):
    text = instruction.strip()

    m = re.search(
        r"call\s+\*0x([0-9a-fA-F]+)\(%([a-z0-9]+),%rax,1\)",
        text,
    )

    if not m:
        return None

    return {
        "table_offset": int(
            m.group(1),
            16,
        ),
        "base_register": m.group(2),
    }


submit_calls = [
    parse_dispatch_call(
        item["call"]["instruction"]
    )
    for item in submit_dispatch
]

submit_calls = [
    x
    for x in submit_calls
    if x
]

multi_calls = [
    parse_dispatch_call(
        item["call"]["instruction"]
    )
    for item in multi_dispatch
]

multi_calls = [
    x
    for x in multi_calls
    if x
]


# ------------------------------------------------------------
# Static table entry extraction
# ------------------------------------------------------------

def extract_entries(
    base_va,
    table_offset,
    count,
):
    entries = []

    if base_va is None:
        return entries

    table_start = (
        base_va
        + table_offset
    )

    for index in range(count):
        slot_va = (
            table_start
            + index
            * DISPATCH_STRIDE
        )

        raw = read_va(
            slot_va,
            8,
        )

        if len(raw) < 8:
            entries.append(
                {
                    "index": index,
                    "slot_va": slot_va,
                    "entry_va": slot_va,
                    "raw_hex": raw.hex(" "),
                    "static_bytes_available": False,
                    "resolved_target": None,
                    "symbols": [],
                }
            )
            continue

        target_va = struct.unpack(
            "<Q",
            raw,
        )[0]

        symbols = [
            enrich_symbol(x)
            for x in symbol_at(
                target_va
            )
        ]

        entries.append(
            {
                "index": index,
                "slot_va": slot_va,
                "entry_va": slot_va,
                "raw_hex": raw.hex(" "),
                "static_bytes_available": True,
                "resolved_target": target_va,
                "resolved_target_hex":
                    "0x%x" % target_va,
                "target_in_loaded_memory":
                    va_in_memory(
                        target_va
                    ),
                "symbols": symbols,
            }
        )

    return entries


# Use a bounded scan. The index field is 32-bit, but the executable
# table should be reasonably sized; scanning an enormous sparse range
# is neither useful nor justified statically.
SCAN_COUNT = 32

submit_entries = extract_entries(
    submit_table_base,
    SUBMIT_TABLE_OFFSET,
    SCAN_COUNT,
)

multi_entries = extract_entries(
    multi_table_base,
    MULTI_TABLE_OFFSET,
    SCAN_COUNT,
)


# ------------------------------------------------------------
# Cross-family correlation
# ------------------------------------------------------------

def normalized_target(entry):
    value = entry.get(
        "resolved_target"
    )

    if value is None:
        return None

    return value


submit_targets = {}

for entry in submit_entries:
    target = normalized_target(
        entry
    )

    if target is None:
        continue

    submit_targets.setdefault(
        target,
        []
    ).append(
        entry["index"]
    )


multi_targets = {}

for entry in multi_entries:
    target = normalized_target(
        entry
    )

    if target is None:
        continue

    multi_targets.setdefault(
        target,
        []
    ).append(
        entry["index"]
    )


shared_targets = []

for target in sorted(
    set(submit_targets)
    &
    set(multi_targets)
):
    shared_targets.append(
        {
            "target_va": target,
            "target_va_hex":
                "0x%x" % target,
            "submit_indices":
                submit_targets[target],
            "multi_indices":
                multi_targets[target],
            "symbols":
                [
                    enrich_symbol(x)
                    for x in symbol_at(
                        target
                    )
                ],
        }
    )


# ------------------------------------------------------------
# Nearby table references in other code
# ------------------------------------------------------------

table_reference_candidates = []

all_functions = [
    (
        "sceAgcDriverSubmitCommandBuffer",
        SUBMIT_VA,
        submit_instructions,
    ),
    (
        "sceAgcDriverSubmitMultiCommandBuffers",
        MULTI_VA,
        multi_instructions,
    ),
]

for function_name, start, instructions in all_functions:
    for ins in instructions:
        text = ins["instruction"]

        if (
            "0x50(%rbx,%rax,1)"
            in text
            or
            "0x58(%rcx,%rax,1)"
            in text
        ):
            table_reference_candidates.append(
                {
                    "function": function_name,
                    "instruction_va":
                        ins["va"],
                    "instruction":
                        text,
                }
            )


# ------------------------------------------------------------
# Symbol evidence
# ------------------------------------------------------------

resolved_symbol_entries = []

for family, entries in (
    (
        "submit",
        submit_entries,
    ),
    (
        "multi",
        multi_entries,
    ),
):
    for entry in entries:
        if not entry.get(
            "symbols"
        ):
            continue

        for symbol in entry[
            "symbols"
        ]:
            resolved_symbol_entries.append(
                {
                    "family": family,
                    "index": entry[
                        "index"
                    ],
                    "entry_va": entry[
                        "entry_va"
                    ],
                    "target_va":
                        entry.get(
                            "resolved_target"
                        ),
                    "target_va_hex":
                        entry.get(
                            "resolved_target_hex"
                        ),
                    "symbol": symbol,
                }
            )


# ------------------------------------------------------------
# Conclusions
# ------------------------------------------------------------

submit_table_identified = (
    submit_table_base
    is not None
)

multi_table_identified = (
    multi_table_base
    is not None
)

submit_entry_bytes_available = any(
    entry[
        "static_bytes_available"
    ]
    for entry in submit_entries
)

multi_entry_bytes_available = any(
    entry[
        "static_bytes_available"
    ]
    for entry in multi_entries
)

resolved_any_targets = (
    len(
        resolved_symbol_entries
    ) > 0
)

same_targets_across_families = (
    len(shared_targets) > 0
)

semantic_family_evidence = (
    resolved_any_targets
    and
    same_targets_across_families
)


conclusions = {
    "SUBMIT_DISPATCH_TABLE_BASE_IDENTIFIED":
        submit_table_identified,

    "MULTI_DISPATCH_TABLE_BASE_IDENTIFIED":
        multi_table_identified,

    "SUBMIT_TABLE_ENTRY_SCAN_COMPLETED":
        True,

    "MULTI_TABLE_ENTRY_SCAN_COMPLETED":
        True,

    "SUBMIT_TABLE_ENTRY_BYTES_STATICALLY_AVAILABLE":
        submit_entry_bytes_available,

    "MULTI_TABLE_ENTRY_BYTES_STATICALLY_AVAILABLE":
        multi_entry_bytes_available,

    "DISPATCH_TARGET_SYMBOLS_RESOLVED":
        resolved_any_targets,

    "CROSS_FAMILY_SHARED_DISPATCH_TARGETS_FOUND":
        same_targets_across_families,

    "SEMANTIC_FAMILY_CORROBORATION_FOUND":
        semantic_family_evidence,

    "INDEX_SEMANTICS_PROVEN":
        True,

    "COUNT_SEMANTICS_PROVEN":
        False,

    "EXACT_FIELD_NAME_PROVEN":
        False,

    "BACKEND_CONSUMER_IDENTIFIED":
        semantic_family_evidence,

    "SEMANTIC_PROTOTYPE_INFERRED":
        False,

    "EXECUTED_AGC":
        False,
}


# ------------------------------------------------------------
# Static output
# ------------------------------------------------------------

static = {
    "stage": 65,

    "target": {
        "global_context_va":
            GLOBAL_CONTEXT_VA,
        "a4_offset":
            A4_OFFSET,
        "a4_va":
            A4_VA,
        "dispatch_stride":
            DISPATCH_STRIDE,
    },

    "dispatch_sites": {
        "submit": {
            "table_base":
                submit_table_base,
            "table_base_hex":
                (
                    "0x%x"
                    % submit_table_base
                    if submit_table_base
                    is not None
                    else None
                ),
            "table_offset":
                SUBMIT_TABLE_OFFSET,
            "table_offset_hex":
                "0x%x"
                % SUBMIT_TABLE_OFFSET,
            "calls":
                submit_calls,
        },

        "multi": {
            "table_base":
                multi_table_base,
            "table_base_hex":
                (
                    "0x%x"
                    % multi_table_base
                    if multi_table_base
                    is not None
                    else None
                ),
            "table_offset":
                MULTI_TABLE_OFFSET,
            "table_offset_hex":
                "0x%x"
                % MULTI_TABLE_OFFSET,
            "calls":
                multi_calls,
        },
    },

    "submit_entries":
        submit_entries,

    "multi_entries":
        multi_entries,

    "resolved_symbol_entries":
        resolved_symbol_entries,

    "shared_targets":
        shared_targets,

    "table_reference_candidates":
        table_reference_candidates,

    "conclusions":
        conclusions,
}


with open(
    os.path.join(
        OUT_DIR,
        "stage65_static.json",
    ),
    "w",
    encoding="utf-8",
) as fp:
    json.dump(
        static,
        fp,
        indent=2,
    )


# ------------------------------------------------------------
# Summary
# ------------------------------------------------------------

lines = []

lines.append(
    "AGC PS5 Stage 65 - Dispatch Table Entry / Consumer Audit"
)

lines.append("")
lines.append("=== TARGET ===")
lines.append(
    "global_context = 0x1A908"
)
lines.append(
    "field +0xA4 = 0x1A9AC"
)
lines.append(
    "dispatch stride = 0x78"
)

lines.append("")
lines.append(
    "=== SUBMIT DISPATCH ==="
)

lines.append(
    "table_base = %s"
    % (
        "0x%x"
        % submit_table_base
        if submit_table_base is not None
        else "UNKNOWN"
    )
)

lines.append(
    "table offset = 0x50"
)

for call in submit_calls:
    lines.append(
        "call = base=%s offset=0x%x"
        % (
            call["base_register"],
            call["table_offset"],
        )
    )

lines.append("")
lines.append(
    "=== SUBMIT TABLE ENTRIES ==="
)

for entry in submit_entries:
    target = entry.get(
        "resolved_target_hex"
    )

    if target is None:
        target = "UNRESOLVED"

    symbol_text = []

    for symbol in entry.get(
        "symbols",
        [],
    ):
        mapped = symbol.get(
            "mapped_name"
        )

        raw = symbol.get(
            "name",
            "",
        )

        if mapped:
            symbol_text.append(
                "%s [%s]"
                % (
                    mapped,
                    raw,
                )
            )
        else:
            symbol_text.append(
                raw
            )

    if not symbol_text:
        symbol_text.append(
            "<no symbol>"
        )

    lines.append(
        "index=%02d slot=0x%X target=%s symbols=%s"
        % (
            entry["index"],
            entry["entry_va"],
            target,
            ", ".join(
                symbol_text
            ),
        )
    )

lines.append("")
lines.append(
    "=== MULTI DISPATCH ==="
)

lines.append(
    "table_base = %s"
    % (
        "0x%x"
        % multi_table_base
        if multi_table_base is not None
        else "UNKNOWN"
    )
)

lines.append(
    "table offset = 0x58"
)

for call in multi_calls:
    lines.append(
        "call = base=%s offset=0x%x"
        % (
            call["base_register"],
            call["table_offset"],
        )
    )

lines.append("")
lines.append(
    "=== MULTI TABLE ENTRIES ==="
)

for entry in multi_entries:
    target = entry.get(
        "resolved_target_hex"
    )

    if target is None:
        target = "UNRESOLVED"

    symbol_text = []

    for symbol in entry.get(
        "symbols",
        [],
    ):
        mapped = symbol.get(
            "mapped_name"
        )

        raw = symbol.get(
            "name",
            "",
        )

        if mapped:
            symbol_text.append(
                "%s [%s]"
                % (
                    mapped,
                    raw,
                )
            )
        else:
            symbol_text.append(
                raw
            )

    if not symbol_text:
        symbol_text.append(
            "<no symbol>"
        )

    lines.append(
        "index=%02d slot=0x%X target=%s symbols=%s"
        % (
            entry["index"],
            entry["entry_va"],
            target,
            ", ".join(
                symbol_text
            ),
        )
    )

lines.append("")
lines.append(
    "=== SHARED TARGETS ==="
)

if shared_targets:
    for item in shared_targets:
        symbols = []

        for symbol in item.get(
            "symbols",
            [],
        ):
            symbols.append(
                symbol.get(
                    "mapped_name"
                )
                or
                symbol.get(
                    "name"
                )
                or
                "<unnamed>"
            )

        lines.append(
            "target=%s submit_indices=%s multi_indices=%s symbols=%s"
            % (
                item[
                    "target_va_hex"
                ],
                ",".join(
                    str(x)
                    for x in item[
                        "submit_indices"
                    ]
                ),
                ",".join(
                    str(x)
                    for x in item[
                        "multi_indices"
                    ]
                ),
                ", ".join(
                    symbols
                ) if symbols
                else "<none>",
            )
        )
else:
    lines.append(
        "NONE"
    )

lines.append("")
lines.append(
    "=== CONCLUSIONS ==="
)

for key, value in conclusions.items():
    lines.append(
        "%s=%s"
        % (
            key,
            str(value),
        )
    )

lines.append("")
lines.append(
    "=== INTERPRETATION LIMIT ==="
)

lines.append(
    "The +0xA4 value is already proven as a dispatch index."
)

lines.append(
    "Stage 65 attempts to resolve the indexed table entries themselves."
)

lines.append(
    "A resolved function symbol may provide semantic family evidence."
)

lines.append(
    "Absence of symbols does not invalidate the dispatch-index conclusion."
)

lines.append(
    "No exact source-level field name is assigned unless static evidence supports it."
)

summary = (
    "\n".join(lines)
    + "\n"
)

with open(
    os.path.join(
        OUT_DIR,
        "dispatch_entries_summary.txt",
    ),
    "w",
    encoding="utf-8",
    newline="\n",
) as fp:
    fp.write(
        summary
    )


# ------------------------------------------------------------
# Entry-focused machine-readable artifact
# ------------------------------------------------------------

focused = {
    "dispatch_stride":
        DISPATCH_STRIDE,

    "a4_va":
        A4_VA,

    "submit": {
        "table_base":
            submit_table_base,
        "table_offset":
            SUBMIT_TABLE_OFFSET,
        "entries":
            submit_entries,
    },

    "multi": {
        "table_base":
            multi_table_base,
        "table_offset":
            MULTI_TABLE_OFFSET,
        "entries":
            multi_entries,
    },

    "shared_targets":
        shared_targets,

    "resolved_symbol_entries":
        resolved_symbol_entries,

    "conclusions":
        conclusions,
}

with open(
    os.path.join(
        OUT_DIR,
        "dispatch_entries.json",
    ),
    "w",
    encoding="utf-8",
) as fp:
    json.dump(
        focused,
        fp,
        indent=2,
    )


# ------------------------------------------------------------
# Disassembly artifact
# ------------------------------------------------------------

with open(
    os.path.join(
        OUT_DIR,
        "dispatch_entries_disassembly.txt",
    ),
    "w",
    encoding="utf-8",
    newline="\n",
) as fp:

    fp.write(
        "AGC PS5 Stage 65 - Dispatch Table Evidence\n\n"
    )

    fp.write(
        "=== SubmitCommandBuffer ===\n\n"
    )

    fp.write(
        submit_disassembly
    )

    fp.write(
        "\n\n=== SubmitMultiCommandBuffers ===\n\n"
    )

    fp.write(
        multi_disassembly
    )


print(
    json.dumps(
        static,
        indent=2,
    )
)
'@

Write-Utf8NoBom `
    -Path $AnalyzerWindows `
    -Content $Python


# ============================================================
# Prepare Linux workspace
# ============================================================

Write-Host ''
Write-Host '==> Preparar workspace Linux' -ForegroundColor Yellow

Invoke-Wsl @"
set -e

rm -rf $(Quote-Bash $WorkWsl)

mkdir -p $(Quote-Bash $WorkWsl)
mkdir -p $(Quote-Bash $OutputWsl)

cp $(Quote-Bash $AnalyzerWsl) \
   $(Quote-Bash "$WorkWsl/analyze_dispatch_entries.py")

sed -i 's/\r$//' \
   $(Quote-Bash "$WorkWsl/analyze_dispatch_entries.py")

python3 -m py_compile \
   $(Quote-Bash "$WorkWsl/analyze_dispatch_entries.py")

ls -lh \
   $(Quote-Bash "$WorkWsl/analyze_dispatch_entries.py")
"@


# ============================================================
# Toolchain
# ============================================================

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


# ============================================================
# Analysis
# ============================================================

Write-Host ''
Write-Host '==> Resolver entradas de tabla dispatch y consumidores potenciales' -ForegroundColor Yellow

Invoke-Wsl @"
set -e

python3 $(Quote-Bash "$WorkWsl/analyze_dispatch_entries.py") \
    $(Quote-Bash $SprxWsl) \
    $(Quote-Bash $NidDbWsl) \
    $(Quote-Bash $PreviousWsl) \
    $(Quote-Bash $OutputWsl)
"@


# ============================================================
# Verify artifacts
# ============================================================

Write-Host ''
Write-Host '==> Verificar artefactos Stage 65' -ForegroundColor Yellow

Invoke-Wsl @"
set -e

test -f $(Quote-Bash "$OutputWsl/stage65_static.json")
test -f $(Quote-Bash "$OutputWsl/dispatch_entries_summary.txt")
test -f $(Quote-Bash "$OutputWsl/dispatch_entries_disassembly.txt")
test -f $(Quote-Bash "$OutputWsl/dispatch_entries.json")

echo '--- dispatch_entries_summary.txt ---'

cat $(Quote-Bash "$OutputWsl/dispatch_entries_summary.txt")

echo '--- output files ---'

find $(Quote-Bash $OutputWsl) \
    -maxdepth 2 \
    -type f |
    sort
"@


# ============================================================
# Read conclusions
# ============================================================

$StaticPath = Join-Path `
    $OutputDir `
    'stage65_static.json'

$SummaryPath = Join-Path `
    $OutputDir `
    'dispatch_entries_summary.txt'

$DisassemblyPath = Join-Path `
    $OutputDir `
    'dispatch_entries_disassembly.txt'

$FocusedPath = Join-Path `
    $OutputDir `
    'dispatch_entries.json'

$Static = Get-Content `
    -LiteralPath $StaticPath `
    -Raw |
    ConvertFrom-Json

$SubmitBase =
    [bool]$Static.conclusions.SUBMIT_DISPATCH_TABLE_BASE_IDENTIFIED

$MultiBase =
    [bool]$Static.conclusions.MULTI_DISPATCH_TABLE_BASE_IDENTIFIED

$SubmitScan =
    [bool]$Static.conclusions.SUBMIT_TABLE_ENTRY_SCAN_COMPLETED

$MultiScan =
    [bool]$Static.conclusions.MULTI_TABLE_ENTRY_SCAN_COMPLETED

$SubmitBytes =
    [bool]$Static.conclusions.SUBMIT_TABLE_ENTRY_BYTES_STATICALLY_AVAILABLE

$MultiBytes =
    [bool]$Static.conclusions.MULTI_TABLE_ENTRY_BYTES_STATICALLY_AVAILABLE

$Symbols =
    [bool]$Static.conclusions.DISPATCH_TARGET_SYMBOLS_RESOLVED

$Shared =
    [bool]$Static.conclusions.CROSS_FAMILY_SHARED_DISPATCH_TARGETS_FOUND

$Semantic =
    [bool]$Static.conclusions.SEMANTIC_FAMILY_CORROBORATION_FOUND

$IndexProven =
    [bool]$Static.conclusions.INDEX_SEMANTICS_PROVEN

$Backend =
    [bool]$Static.conclusions.BACKEND_CONSUMER_IDENTIFIED


# ============================================================
# Hashes
# ============================================================

$HashStatic = Get-Sha256 `
    -Path $StaticPath

$HashSummary = Get-Sha256 `
    -Path $SummaryPath

$HashDisassembly = Get-Sha256 `
    -Path $DisassemblyPath

$HashFocused = Get-Sha256 `
    -Path $FocusedPath

Write-Host ''
Write-Host '==> Hash artefactos' -ForegroundColor Yellow

Write-Host "[INFO] stage65_static.json SHA256=$HashStatic"
Write-Host "[INFO] dispatch_entries_summary.txt SHA256=$HashSummary"
Write-Host "[INFO] dispatch_entries_disassembly.txt SHA256=$HashDisassembly"
Write-Host "[INFO] dispatch_entries.json SHA256=$HashFocused"


# ============================================================
# Report
# ============================================================

$Report = [ordered]@{
    stage = 65

    target = [ordered]@{
        global_context = '0x1A908'
        field = '0xA4'
        dispatch_stride = '0x78'
    }

    conclusions = [ordered]@{
        SUBMIT_DISPATCH_TABLE_BASE_IDENTIFIED = $SubmitBase
        MULTI_DISPATCH_TABLE_BASE_IDENTIFIED = $MultiBase

        SUBMIT_TABLE_ENTRY_SCAN_COMPLETED = $SubmitScan
        MULTI_TABLE_ENTRY_SCAN_COMPLETED = $MultiScan

        SUBMIT_TABLE_ENTRY_BYTES_STATICALLY_AVAILABLE = $SubmitBytes
        MULTI_TABLE_ENTRY_BYTES_STATICALLY_AVAILABLE = $MultiBytes

        DISPATCH_TARGET_SYMBOLS_RESOLVED = $Symbols
        CROSS_FAMILY_SHARED_DISPATCH_TARGETS_FOUND = $Shared
        SEMANTIC_FAMILY_CORROBORATION_FOUND = $Semantic

        INDEX_SEMANTICS_PROVEN = $IndexProven
        BACKEND_CONSUMER_IDENTIFIED = $Backend

        COUNT_SEMANTICS_PROVEN = $false
        EXACT_FIELD_NAME_PROVEN = $false
        SEMANTIC_PROTOTYPE_INFERRED = $false
        EXECUTED_AGC = $false
    }

    hashes = [ordered]@{
        'stage65_static.json' = $HashStatic
        'dispatch_entries_summary.txt' = $HashSummary
        'dispatch_entries_disassembly.txt' = $HashDisassembly
        'dispatch_entries.json' = $HashFocused
    }
}

Write-Utf8NoBom `
    -Path $ReportPath `
    -Content (
        $Report |
        ConvertTo-Json -Depth 20
    )


# ============================================================
# Final
# ============================================================

Write-Host ''
Write-Host '============================================' -ForegroundColor Green
Write-Host 'Stage 65 completado' -ForegroundColor Green
Write-Host '============================================' -ForegroundColor Green
Write-Host ''

Write-Host "SUBMIT_DISPATCH_TABLE_BASE_IDENTIFIED = $SubmitBase"
Write-Host "MULTI_DISPATCH_TABLE_BASE_IDENTIFIED = $MultiBase"

Write-Host "SUBMIT_TABLE_ENTRY_SCAN_COMPLETED = $SubmitScan"
Write-Host "MULTI_TABLE_ENTRY_SCAN_COMPLETED = $MultiScan"

Write-Host "SUBMIT_TABLE_ENTRY_BYTES_STATICALLY_AVAILABLE = $SubmitBytes"
Write-Host "MULTI_TABLE_ENTRY_BYTES_STATICALLY_AVAILABLE = $MultiBytes"

Write-Host "DISPATCH_TARGET_SYMBOLS_RESOLVED = $Symbols"
Write-Host "CROSS_FAMILY_SHARED_DISPATCH_TARGETS_FOUND = $Shared"
Write-Host "SEMANTIC_FAMILY_CORROBORATION_FOUND = $Semantic"

Write-Host "INDEX_SEMANTICS_PROVEN = $IndexProven"
Write-Host "BACKEND_CONSUMER_IDENTIFIED = $Backend"

Write-Host 'COUNT_SEMANTICS_PROVEN = False'
Write-Host 'EXACT_FIELD_NAME_PROVEN = False'
Write-Host 'SEMANTIC_PROTOTYPE_INFERRED = False'
Write-Host 'EXECUTED_AGC = False'

Write-Host ''
Write-Host 'Resultados:'
Write-Host "  $OutputDir"

Write-Host ''
Write-Host 'Reporte:'
Write-Host "  $ReportPath"