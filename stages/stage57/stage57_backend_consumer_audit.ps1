#requires -Version 7.0

[CmdletBinding()]
param(
    [string]$StageDir = $PSScriptRoot,
    [string]$Sprx = 'D:\agc_work\sce_stubs\libSceAgcDriver.sprx',
    [string]$NidDb = 'D:\sdk-master\sce_stubs\aerolib.csv',
    [string]$PreviousResults = 'D:\agc_work\stage56_results',
    [string]$OutDir = 'D:\agc_work\stage57_results',
    [string]$Sdk = '/opt/ps5-payload-sdk'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Section {
    param([string]$Text)

    Write-Host ''
    Write-Host '============================================' -ForegroundColor Cyan
    Write-Host $Text -ForegroundColor Cyan
    Write-Host '============================================' -ForegroundColor Cyan
}

function Write-Step {
    param([string]$Text)

    Write-Host ''
    Write-Host "==> $Text" -ForegroundColor Yellow
}

function Normalize-Lf {
    param([string]$Text)

    return (
        $Text `
            -replace "`r`n", "`n" `
            -replace "`r", ""
    )
}

function Write-Utf8NoBom {
    param(
        [string]$Path,
        [string]$Content
    )

    $Encoding = New-Object System.Text.UTF8Encoding($false)

    [System.IO.File]::WriteAllText(
        $Path,
        (Normalize-Lf $Content),
        $Encoding
    )
}

function Quote-Bash {
    param([string]$Text)

    return (
        "'" +
        ($Text -replace "'", "'\''") +
        "'"
    )
}

function Convert-ToWslPath {
    param([string]$WindowsPath)

    $FullPath = [System.IO.Path]::GetFullPath($WindowsPath)

    if ($FullPath -match '^[A-Za-z]:\\') {

        $Drive = $FullPath.Substring(
            0,
            1
        ).ToLowerInvariant()

        $Rest = $FullPath.Substring(2)

        $Rest = $Rest.Replace(
            '\',
            '/'
        )

        $Rest = $Rest.TrimStart('/')

        return "/mnt/$Drive/$Rest"
    }

    return (
        $FullPath.Replace(
            '\',
            '/'
        )
    )
}

function Invoke-WslBash {
    param(
        [string]$Command,
        [switch]$AllowFailure
    )

    $Command = Normalize-Lf $Command

    Write-Host ''
    Write-Host '[WSL] ' -NoNewline -ForegroundColor DarkGray
    Write-Host $Command -ForegroundColor DarkGray

    & wsl.exe `
        -d Ubuntu-24.04 `
        --cd / `
        -- bash -lc $Command

    $Code = $LASTEXITCODE

    if (
        ($Code -ne 0) `
        -and `
        (-not $AllowFailure)
    ) {
        throw "WSL command failed with exit code $Code."
    }

    return $Code
}

function Get-Sha256 {
    param([string]$Path)

    if (
        -not (
            Test-Path `
                -LiteralPath $Path `
                -PathType Leaf
        )
    ) {
        return $null
    }

    return (
        Get-FileHash `
            -Algorithm SHA256 `
            -LiteralPath $Path
    ).Hash.ToLowerInvariant()
}

# ------------------------------------------------------------
# Resolve paths
# ------------------------------------------------------------

$StageDir = (
    Resolve-Path `
        -LiteralPath $StageDir
).Path

$Sprx = (
    Resolve-Path `
        -LiteralPath $Sprx
).Path

$NidDb = (
    Resolve-Path `
        -LiteralPath $NidDb
).Path

$PreviousResults = (
    Resolve-Path `
        -LiteralPath $PreviousResults
).Path

New-Item `
    -ItemType Directory `
    -Force `
    -Path $OutDir |
    Out-Null

$OutDir = (
    Resolve-Path `
        -LiteralPath $OutDir
).Path

$SprxWsl = Convert-ToWslPath $Sprx
$NidDbWsl = Convert-ToWslPath $NidDb
$PreviousWsl = Convert-ToWslPath $PreviousResults
$OutWsl = Convert-ToWslPath $OutDir

$WorkWsl = '/tmp/agc_stage57'

$AnalyzerWin = Join-Path `
    $OutDir `
    'analyze_backend_consumers.py'

$StaticWin = Join-Path `
    $OutDir `
    'stage57_static.json'

$SummaryWin = Join-Path `
    $OutDir `
    'backend_consumer_summary.txt'

$DisasmWin = Join-Path `
    $OutDir `
    'consumer_candidate_disassembly.txt'

$ReportWin = Join-Path `
    $OutDir `
    'STAGE57_REPORT.json'

$AnalyzerWsl = "$OutWsl/analyze_backend_consumers.py"

# ------------------------------------------------------------
# Banner
# ------------------------------------------------------------

Write-Section `
    'AGC PS5 Stage 57 - Backend Consumer / Field Semantic Audit'

Write-Host "[INFO] StageDir        = $StageDir"
Write-Host "[INFO] SPRX            = $Sprx"
Write-Host "[INFO] NID DB          = $NidDb"
Write-Host "[INFO] Previous stage  = $PreviousResults"
Write-Host "[INFO] Output          = $OutDir"
Write-Host "[INFO] SPRX WSL        = $SprxWsl"
Write-Host "[INFO] Previous WSL    = $PreviousWsl"
Write-Host "[INFO] Output WSL      = $OutWsl"
Write-Host "[INFO] SDK             = $Sdk"

# ------------------------------------------------------------
# Python analyzer
# ------------------------------------------------------------

$Python = @'
import json
import os
import re
import struct
import subprocess
import sys

from elftools.elf.elffile import ELFFile


SPRX = sys.argv[1]
NID_DB = sys.argv[2]
PREVIOUS = sys.argv[3]
OUT_DIR = sys.argv[4]

os.makedirs(OUT_DIR, exist_ok=True)

TARGET_NAME = "sceAgcDriverSubmitCommandBuffer"
TARGET_VA = 0x18B0
TARGET_SIZE = 380

MULTI_NAME = "sceAgcDriverSubmitMultiCommandBuffers"
MULTI_VA = 0x4650
MULTI_SIZE = 579


def load_elf():
    fp = open(SPRX, "rb")
    elf = ELFFile(fp)
    return fp, elf


def load_segments(elf):
    segments = []

    for seg in elf.iter_segments():
        if seg["p_type"] != "PT_LOAD":
            continue

        segments.append({
            "offset": int(seg["p_offset"]),
            "vaddr": int(seg["p_vaddr"]),
            "filesz": int(seg["p_filesz"]),
            "memsz": int(seg["p_memsz"]),
            "flags": int(seg["p_flags"]),
        })

    return segments


FP, ELF = load_elf()
SEGMENTS = load_segments(ELF)


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

    FP.seek(off)

    return FP.read(size)


def is_executable_va(va):
    for seg in SEGMENTS:
        start = seg["vaddr"]
        end = start + seg["filesz"]

        if start <= va < end:
            return bool(seg["flags"] & 1)

    return False


def load_symbols():
    funcs = []

    seen = set()

    for section in ELF.iter_sections():

        if section["sh_type"] not in (
            "SHT_DYNSYM",
            "SHT_SYMTAB",
        ):
            continue

        for sym in section.iter_symbols():

            info = sym["st_info"]

            if info["type"] != "STT_FUNC":
                continue

            va = int(sym["st_value"])
            size = int(sym["st_size"])

            if va == 0 or size == 0:
                continue

            if not is_executable_va(va):
                continue

            key = (
                va,
                size,
                sym.name,
            )

            if key in seen:
                continue

            seen.add(key)

            raw_name = sym.name

            nid = None

            if "#" in raw_name:
                nid = raw_name.split("#", 1)[0]

            funcs.append({
                "va": va,
                "size": size,
                "name": raw_name,
                "nid": nid,
                "bind": info["bind"],
                "type": info["type"],
            })

    funcs.sort(
        key=lambda x: (
            x["va"],
            x["size"],
            x["name"],
        )
    )

    return funcs


SYMBOLS = load_symbols()


def nid_map():
    mapping = {}

    if not os.path.isfile(NID_DB):
        return mapping

    with open(
        NID_DB,
        "r",
        encoding="utf-8",
        errors="replace",
    ) as fp:

        for line in fp:
            line = line.strip()

            if not line:
                continue

            parts = line.split()

            if len(parts) < 2:
                continue

            nid = parts[0]

            name = parts[1]

            if nid not in mapping:
                mapping[nid] = name

    return mapping


NID_NAMES = nid_map()


def mapped_name(symbol):
    nid = symbol.get("nid")

    if nid and nid in NID_NAMES:
        return NID_NAMES[nid]

    raw = symbol.get("name", "")

    if "#" in raw:
        return NID_NAMES.get(
            raw.split("#", 1)[0],
            raw,
        )

    return raw


def disassemble(raw, va):
    tmp = os.path.join(
        OUT_DIR,
        "_consumer_tmp.bin",
    )

    with open(tmp, "wb") as fp:
        fp.write(raw)

    proc = subprocess.run(
        [
            "objdump",
            "-D",
            "-b",
            "binary",
            "-m",
            "i386:x86-64",
            "--adjust-vma=0x%x" % va,
            tmp,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    try:
        os.remove(tmp)
    except OSError:
        pass

    return proc.stdout.decode(
        "utf-8",
        errors="replace",
    )


def find_all(blob, needle):
    positions = []

    start = 0

    while True:
        pos = blob.find(
            needle,
            start,
        )

        if pos < 0:
            break

        positions.append(pos)

        start = pos + 1

    return positions


def symbol_for_va(va):
    best = None

    for sym in SYMBOLS:

        start = sym["va"]
        end = start + sym["size"]

        if start <= va < end:

            if (
                best is None
                or sym["size"] < best["size"]
            ):
                best = sym

    return best


def candidate_patterns():
    # Exact / common x86-64 patterns for memory access based on RSI.
    #
    # +0x00:
    #   48 8b 06     mov (%rsi), %rax
    #   48 8b 0e     mov (%rsi), %rcx
    #   48 8b 16     mov (%rsi), %rdx
    #   48 8b 1e     mov (%rsi), %rbx
    #
    # +0x08:
    #   48 8b 46 08   mov 0x8(%rsi), %rax
    #   8b 46 08      mov 0x8(%rsi), %eax
    #
    # +0x0c:
    #   48 8b 46 0c
    #   8b 46 0c
    #   0f b6 46 0c
    #
    # Store forms are also scanned because consumers may rewrite or
    # forward fields.
    #

    patterns = []

    # Field +0x00, 64-bit loads.
    for reg_opcode, reg_name in [
        (0x06, "RAX"),
        (0x0E, "RCX"),
        (0x16, "RDX"),
        (0x1E, "RBX"),
        (0x2E, "RSP"),
        (0x36, "RSI"),
        (0x3E, "RDI"),
    ]:
        patterns.append({
            "field": "field_00",
            "offset": 0,
            "width": 8,
            "kind": "LOAD64",
            "needle": bytes([
                0x48,
                0x8B,
                reg_opcode,
            ]),
            "description":
                "64-bit load from [RSI+0x00] -> %s"
                % reg_name,
        })

    # Field +0x08, 32-bit loads.
    for opcode, reg_name in [
        (0x46, "EAX"),
        (0x4E, "ECX"),
        (0x56, "EDX"),
        (0x5E, "EBX"),
        (0x7E, "EDI"),
    ]:
        patterns.append({
            "field": "field_08",
            "offset": 8,
            "width": 4,
            "kind": "LOAD32",
            "needle": bytes([
                0x8B,
                opcode,
                0x08,
            ]),
            "description":
                "32-bit load from [RSI+0x08] -> %s"
                % reg_name,
        })

    # Field +0x08, 64-bit load.
    patterns.append({
        "field": "field_08",
        "offset": 8,
        "width": 8,
        "kind": "LOAD64",
        "needle":
            b"\x48\x8b\x46\x08",
        "description":
            "64-bit load from [RSI+0x08] -> RAX",
    })

    # Field +0x0c, byte load.
    patterns.extend([
        {
            "field": "field_0c",
            "offset": 12,
            "width": 1,
            "kind": "LOAD8_ZEROEXT",
            "needle":
                b"\x0f\xb6\x46\x0c",
            "description":
                "zero-extended byte load from [RSI+0x0c]",
        },
        {
            "field": "field_0c",
            "offset": 12,
            "width": 1,
            "kind": "LOAD8",
            "needle":
                b"\x8a\x46\x0c",
            "description":
                "byte load from [RSI+0x0c]",
        },
    ])

    # Store forms into structures.
    patterns.extend([
        {
            "field": "field_00",
            "offset": 0,
            "width": 8,
            "kind": "STORE_FROM_RSI",
            "needle":
                b"\x48\x8b\x06",
            "description":
                "field_00 loaded as 64-bit value",
        },
        {
            "field": "field_08",
            "offset": 8,
            "width": 4,
            "kind": "STORE_FROM_RSI",
            "needle":
                b"\x8b\x46\x08",
            "description":
                "field_08 loaded as 32-bit value",
        },
    ])

    return patterns


PATTERNS = candidate_patterns()


def analyze_function(sym):
    raw = read_va(
        sym["va"],
        sym["size"],
    )

    if not raw:
        return None

    findings = []

    for pattern in PATTERNS:

        positions = find_all(
            raw,
            pattern["needle"],
        )

        for pos in positions:

            instruction_va = (
                sym["va"] + pos
            )

            findings.append({
                "instruction_va":
                    instruction_va,

                "field":
                    pattern["field"],

                "field_offset":
                    pattern["offset"],

                "width":
                    pattern["width"],

                "kind":
                    pattern["kind"],

                "description":
                    pattern["description"],
            })

    if not findings:
        return None

    return {
        "symbol": sym,
        "mapped_name":
            mapped_name(sym),
        "va":
            sym["va"],
        "size":
            sym["size"],
        "findings":
            findings,
        "bytes_hex":
            raw.hex(" "),
    }


def load_previous():
    path = os.path.join(
        PREVIOUS,
        "stage56_static.json",
    )

    if not os.path.isfile(path):
        raise RuntimeError(
            "No existe stage56_static.json: %s"
            % path
        )

    with open(
        path,
        "r",
        encoding="utf-8",
    ) as fp:

        return json.load(fp)


def score_candidate(item):
    score = 0

    name = (
        item["mapped_name"]
        or
        item["symbol"]["name"]
    ).lower()

    # Strong hints from names, but these remain only ranking signals.
    strong_words = [
        "submit",
        "commandbuffer",
        "command_buffer",
        "dcb",
        "agr",
        "acb",
    ]

    medium_words = [
        "queue",
        "command",
        "buffer",
        "draw",
        "dispatch",
    ]

    for word in strong_words:
        if word in name:
            score += 20

    for word in medium_words:
        if word in name:
            score += 5

    fields = set(
        x["field"]
        for x in item["findings"]
    )

    if "field_00" in fields:
        score += 20

    if "field_08" in fields:
        score += 20

    if "field_0c" in fields:
        score += 20

    if len(fields) == 3:
        score += 50

    return score


def main():
    previous = load_previous()

    candidates = []

    for sym in SYMBOLS:

        # Avoid treating SubmitCommandBuffer itself as a backend
        # consumer candidate.
        if sym["va"] == TARGET_VA:
            continue

        result = analyze_function(sym)

        if result is None:
            continue

        result["score"] = score_candidate(
            result
        )

        candidates.append(result)

    candidates.sort(
        key=lambda x: (
            -x["score"],
            x["va"],
        )
    )

    # --------------------------------------------------------
    # Focus on candidates that read all three fields.
    # --------------------------------------------------------

    all_three = []

    for item in candidates:

        fields = set(
            f["field"]
            for f in item["findings"]
        )

        if fields == {
            "field_00",
            "field_08",
            "field_0c",
        }:

            all_three.append(item)

    # --------------------------------------------------------
    # Focus on functions that read field 00 + field 08.
    # --------------------------------------------------------

    field00_field08 = []

    for item in candidates:

        fields = set(
            f["field"]
            for f in item["findings"]
        )

        if (
            "field_00" in fields
            and
            "field_08" in fields
        ):

            field00_field08.append(item)

    # --------------------------------------------------------
    # Readable candidate details.
    # --------------------------------------------------------

    candidate_disassembly = []

    for index, item in enumerate(
        candidates[:40],
        1,
    ):

        candidate_disassembly.append(
            "============================================"
        )

        candidate_disassembly.append(
            "CANDIDATE %02d" % index
        )

        candidate_disassembly.append(
            "============================================"
        )

        candidate_disassembly.append(
            "name = %s"
            % item["mapped_name"]
        )

        candidate_disassembly.append(
            "raw_name = %s"
            % item["symbol"]["name"]
        )

        candidate_disassembly.append(
            "VA = 0x%x"
            % item["va"]
        )

        candidate_disassembly.append(
            "size = %d"
            % item["size"]
        )

        candidate_disassembly.append(
            "score = %d"
            % item["score"]
        )

        candidate_disassembly.append("")

        candidate_disassembly.append(
            "FIELD FINDINGS:"
        )

        for finding in item["findings"]:

            candidate_disassembly.append(
                "  0x%x field=%s offset=0x%x "
                "width=%d kind=%s"
                % (
                    finding["instruction_va"],
                    finding["field"],
                    finding["field_offset"],
                    finding["width"],
                    finding["kind"],
                )
            )

            candidate_disassembly.append(
                "    %s"
                % finding["description"]
            )

        candidate_disassembly.append("")

        # Only disassemble a limited number of top candidates,
        # preventing giant artefacts.
        if index <= 20:

            raw = read_va(
                item["va"],
                item["size"],
            )

            if raw:

                candidate_disassembly.append(
                    disassemble(
                        raw,
                        item["va"],
                    )
                )

    disasm_text = (
        "\n".join(candidate_disassembly)
        +
        "\n"
    )

    disasm_path = os.path.join(
        OUT_DIR,
        "consumer_candidate_disassembly.txt",
    )

    with open(
        disasm_path,
        "w",
        encoding="utf-8",
        newline="\n",
    ) as fp:

        fp.write(
            disasm_text
        )

    # --------------------------------------------------------
    # Specific function-family checks.
    # --------------------------------------------------------

    known_related = []

    for item in candidates:

        name = (
            item["mapped_name"]
            or
            item["symbol"]["name"]
        )

        lname = name.lower()

        if (
            "submitcommandbuffer" in lname
            or
            "submitdcb" in lname
            or
            "submitacb" in lname
            or
            "submitmulti" in lname
        ):

            known_related.append(item)

    # --------------------------------------------------------
    # Conclusions
    # --------------------------------------------------------

    field00_consumer = any(
        "field_00"
        in set(
            f["field"]
            for f in item["findings"]
        )
        for item in candidates
    )

    field08_consumer = any(
        "field_08"
        in set(
            f["field"]
            for f in item["findings"]
        )
        for item in candidates
    )

    field0c_consumer = any(
        "field_0c"
        in set(
            f["field"]
            for f in item["findings"]
        )
        for item in candidates
    )

    all_three_consumer = (
        len(all_three) > 0
    )

    result = {
        "stage": 57,

        "target": {
            "name":
                TARGET_NAME,

            "va":
                TARGET_VA,

            "size":
                TARGET_SIZE,
        },

        "previous_stage": {
            "stage":
                56,

            "field_00_downstream_use_proven":
                bool(
                    previous[
                        "conclusions"
                    ][
                        "FIELD_00_DOWNSTREAM_USE_PROVEN"
                    ]
                ),

            "field_08_downstream_use_proven":
                bool(
                    previous[
                        "conclusions"
                    ][
                        "FIELD_08_DOWNSTREAM_USE_PROVEN"
                    ]
                ),

            "field_0c_downstream_use_proven":
                bool(
                    previous[
                        "conclusions"
                    ][
                        "FIELD_0C_DOWNSTREAM_USE_PROVEN"
                    ]
                ),

            "packed_record_consumed":
                bool(
                    previous[
                        "conclusions"
                    ][
                        "PACKED_RECORD_CONSUMED_BY_BACKEND_CALL"
                    ]
                ),
        },

        "symbol_inventory": {
            "function_count":
                len(SYMBOLS),

            "candidate_count":
                len(candidates),

            "all_three_field_candidates":
                len(all_three),

            "field00_field08_candidates":
                len(field00_field08),

            "known_related_candidates":
                len(known_related),
        },

        "top_candidates": [
            {
                "name":
                    x["mapped_name"],

                "raw_name":
                    x["symbol"]["name"],

                "va":
                    x["va"],

                "size":
                    x["size"],

                "score":
                    x["score"],

                "fields": sorted(
                    list(
                        set(
                            f["field"]
                            for f in x["findings"]
                        )
                    )
                ),

                "findings":
                    x["findings"],
            }

            for x in candidates[:40]
        ],

        "all_three_field_candidates": [
            {
                "name":
                    x["mapped_name"],

                "raw_name":
                    x["symbol"]["name"],

                "va":
                    x["va"],

                "size":
                    x["size"],

                "score":
                    x["score"],

                "findings":
                    x["findings"],
            }

            for x in all_three
        ],

        "known_related_candidates": [
            {
                "name":
                    x["mapped_name"],

                "raw_name":
                    x["symbol"]["name"],

                "va":
                    x["va"],

                "size":
                    x["size"],

                "score":
                    x["score"],

                "findings":
                    x["findings"],
            }

            for x in known_related
        ],

        "conclusions": {
            "FIELD_00_CONSUMER_CANDIDATE_FOUND":
                field00_consumer,

            "FIELD_08_CONSUMER_CANDIDATE_FOUND":
                field08_consumer,

            "FIELD_0C_CONSUMER_CANDIDATE_FOUND":
                field0c_consumer,

            "ALL_THREE_FIELDS_CONSUMED_BY_ONE_FUNCTION_CANDIDATE":
                all_three_consumer,

            "BACKEND_CONSUMER_IDENTIFIED":
                False,

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

        "scanner_notes": [
            "Candidate ranking is heuristic only.",
            "Finding RSI-relative loads does not prove semantic names.",
            "A true backend consumer requires control/data-flow confirmation.",
            "Indirect dispatch target is not assumed from table index alone.",
        ],
    }

    static_path = os.path.join(
        OUT_DIR,
        "stage57_static.json",
    )

    with open(
        static_path,
        "w",
        encoding="utf-8",
    ) as fp:

        json.dump(
            result,
            fp,
            indent=2,
        )

    # --------------------------------------------------------
    # Human summary
    # --------------------------------------------------------

    summary = []

    summary.append(
        "AGC PS5 Stage 57 - Backend Consumer / Field Semantic Audit"
    )

    summary.append("")

    summary.append(
        "=== SYMBOL INVENTORY ==="
    )

    summary.append(
        "function_count = %d"
        % len(SYMBOLS)
    )

    summary.append(
        "candidate_count = %d"
        % len(candidates)
    )

    summary.append(
        "all_three_field_candidates = %d"
        % len(all_three)
    )

    summary.append(
        "field00_field08_candidates = %d"
        % len(field00_field08)
    )

    summary.append("")

    summary.append(
        "=== TOP CONSUMER CANDIDATES ==="
    )

    if not candidates:

        summary.append(
            "NO RSI FIELD ACCESS CANDIDATES FOUND"
        )

    else:

        for index, item in enumerate(
            candidates[:20],
            1,
        ):

            fields = sorted(
                list(
                    set(
                        f["field"]
                        for f in item["findings"]
                    )
                )
            )

            summary.append(
                "%02d. %s VA=0x%x SIZE=%d SCORE=%d FIELDS=%s"
                % (
                    index,
                    item["mapped_name"],
                    item["va"],
                    item["size"],
                    item["score"],
                    ",".join(fields),
                )
            )

    summary.append("")

    summary.append(
        "=== ALL-THREE FIELD CANDIDATES ==="
    )

    if not all_three:

        summary.append(
            "NONE"
        )

    else:

        for item in all_three:

            summary.append(
                "%s VA=0x%x SIZE=%d SCORE=%d"
                % (
                    item["mapped_name"],
                    item["va"],
                    item["size"],
                    item["score"],
                )
            )

    summary.append("")

    summary.append(
        "=== IMPORTANT LIMIT ==="
    )

    summary.append(
        "RSI-relative field reads establish candidate consumers,"
    )

    summary.append(
        "but they do not by themselves prove semantic field names."
    )

    summary.append("")

    summary.append(
        "=== CONCLUSIONS ==="
    )

    for key, value in result[
        "conclusions"
    ].items():

        summary.append(
            "%s=%s"
            % (
                key,
                value,
            )
        )

    summary_path = os.path.join(
        OUT_DIR,
        "backend_consumer_summary.txt",
    )

    with open(
        summary_path,
        "w",
        encoding="utf-8",
        newline="\n",
    ) as fp:

        fp.write(
            "\n".join(summary)
            +
            "\n"
        )

    print(
        json.dumps(
            result,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
'@

Write-Utf8NoBom `
    -Path $AnalyzerWin `
    -Content $Python

# ------------------------------------------------------------
# Prepare workspace
# ------------------------------------------------------------

Write-Step `
    'Preparar workspace Linux'

$PrepareCommand = @"
set -e

rm -rf $(Quote-Bash $WorkWsl)

mkdir -p $(Quote-Bash $WorkWsl)
mkdir -p $(Quote-Bash $OutWsl)

cp $(Quote-Bash $AnalyzerWsl) \
   $(Quote-Bash "$WorkWsl/analyze_backend_consumers.py")

sed -i 's/\r$//' \
   $(Quote-Bash "$WorkWsl/analyze_backend_consumers.py")

python3 -m py_compile \
   $(Quote-Bash "$WorkWsl/analyze_backend_consumers.py")

ls -lh \
   $(Quote-Bash "$WorkWsl/analyze_backend_consumers.py")
"@

Invoke-WslBash $PrepareCommand

# ------------------------------------------------------------
# Verify toolchain
# ------------------------------------------------------------

Write-Step `
    'Verificar Python + pyelftools + toolchain'

$VerifyCommand = @"
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
"@

Invoke-WslBash $VerifyCommand

# ------------------------------------------------------------
# Run analyzer
# ------------------------------------------------------------

Write-Step `
    'Buscar consumidores backend del registro SubmitCommandBuffer'

$AnalyzeCommand = @"
set -e

python3 $(Quote-Bash "$WorkWsl/analyze_backend_consumers.py") \
    $(Quote-Bash $SprxWsl) \
    $(Quote-Bash $NidDbWsl) \
    $(Quote-Bash $PreviousWsl) \
    $(Quote-Bash $OutWsl)
"@

Invoke-WslBash $AnalyzeCommand

# ------------------------------------------------------------
# Verify outputs
# ------------------------------------------------------------

Write-Step `
    'Verificar artefactos Stage 57'

$VerifyArtifactsCommand = @"
set -e

test -f $(Quote-Bash "$OutWsl/stage57_static.json")
test -f $(Quote-Bash "$OutWsl/backend_consumer_summary.txt")
test -f $(Quote-Bash "$OutWsl/consumer_candidate_disassembly.txt")

echo '--- backend_consumer_summary.txt ---'

cat $(Quote-Bash "$OutWsl/backend_consumer_summary.txt")

echo '--- output files ---'

find $(Quote-Bash $OutWsl) \
    -maxdepth 2 \
    -type f |
    sort
"@

Invoke-WslBash $VerifyArtifactsCommand

# ------------------------------------------------------------
# Read static result
# ------------------------------------------------------------

$Static = (
    Get-Content `
        -LiteralPath $StaticWin `
        -Raw
) | ConvertFrom-Json

$Field00Consumer = [bool](
    $Static.conclusions.FIELD_00_CONSUMER_CANDIDATE_FOUND
)

$Field08Consumer = [bool](
    $Static.conclusions.FIELD_08_CONSUMER_CANDIDATE_FOUND
)

$Field0CConsumer = [bool](
    $Static.conclusions.FIELD_0C_CONSUMER_CANDIDATE_FOUND
)

$AllThree = [bool](
    $Static.conclusions.ALL_THREE_FIELDS_CONSUMED_BY_ONE_FUNCTION_CANDIDATE
)

$BackendIdentified = [bool](
    $Static.conclusions.BACKEND_CONSUMER_IDENTIFIED
)

# ------------------------------------------------------------
# Hash artefacts
# ------------------------------------------------------------

Write-Step 'Hash artefactos'

$HashStatic = Get-Sha256 `
    $StaticWin

$HashSummary = Get-Sha256 `
    $SummaryWin

$HashDisasm = Get-Sha256 `
    $DisasmWin

Write-Host `
    "[INFO] stage57_static.json SHA256=$HashStatic"

Write-Host `
    "[INFO] backend_consumer_summary.txt SHA256=$HashSummary"

Write-Host `
    "[INFO] consumer_candidate_disassembly.txt SHA256=$HashDisasm"

# ------------------------------------------------------------
# Report
# ------------------------------------------------------------

$Report = [ordered]@{
    stage = 57

    target = [ordered]@{
        name = 'sceAgcDriverSubmitCommandBuffer'
        nid = 'b4fpgH5ZXxQ'
        va = '0x18b0'
        size = 380
    }

    conclusions = [ordered]@{
        FIELD_00_CONSUMER_CANDIDATE_FOUND =
            $Field00Consumer

        FIELD_08_CONSUMER_CANDIDATE_FOUND =
            $Field08Consumer

        FIELD_0C_CONSUMER_CANDIDATE_FOUND =
            $Field0CConsumer

        ALL_THREE_FIELDS_CONSUMED_BY_ONE_FUNCTION_CANDIDATE =
            $AllThree

        BACKEND_CONSUMER_IDENTIFIED =
            $BackendIdentified

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
        'stage57_static.json' =
            $HashStatic

        'backend_consumer_summary.txt' =
            $HashSummary

        'consumer_candidate_disassembly.txt' =
            $HashDisasm
    }
}

Write-Utf8NoBom `
    -Path $ReportWin `
    -Content (
        $Report |
        ConvertTo-Json -Depth 20
    )

# ------------------------------------------------------------
# Final
# ------------------------------------------------------------

Write-Host ''
Write-Host '============================================' -ForegroundColor Green
Write-Host 'Stage 57 completado' -ForegroundColor Green
Write-Host '============================================' -ForegroundColor Green
Write-Host ''

Write-Host `
    "FIELD_00_CONSUMER_CANDIDATE_FOUND = $Field00Consumer"

Write-Host `
    "FIELD_08_CONSUMER_CANDIDATE_FOUND = $Field08Consumer"

Write-Host `
    "FIELD_0C_CONSUMER_CANDIDATE_FOUND = $Field0CConsumer"

Write-Host `
    "ALL_THREE_FIELDS_CONSUMED_BY_ONE_FUNCTION_CANDIDATE = $AllThree"

Write-Host `
    "BACKEND_CONSUMER_IDENTIFIED = $BackendIdentified"

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
Write-Host "  $OutDir"

Write-Host ''
Write-Host 'Reporte:'
Write-Host "  $ReportWin"