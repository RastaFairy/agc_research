#requires -Version 7.0

[CmdletBinding()]
param(
    [string]$StageDir = $PSScriptRoot,
    [string]$Sprx = 'D:\agc_work\sce_stubs\libSceAgcDriver.sprx',
    [string]$NidDb = 'D:\sdk-master\sce_stubs\aerolib.csv',
    [string]$PreviousResults = 'D:\agc_work\stage56_results',
    [string]$OutDir = 'D:\agc_work\stage58_results',
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

# ============================================================
# Resolve paths
# ============================================================

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

$WorkWsl = '/tmp/agc_stage58'

$AnalyzerWin = Join-Path `
    $OutDir `
    'analyze_backend_consumers.py'

$StaticWin = Join-Path `
    $OutDir `
    'stage58_static.json'

$SummaryWin = Join-Path `
    $OutDir `
    'backend_consumer_summary.txt'

$DisasmWin = Join-Path `
    $OutDir `
    'consumer_candidate_disassembly.txt'

$GlobalHitsWin = Join-Path `
    $OutDir `
    'global_field_hits.txt'

$NmWin = Join-Path `
    $OutDir `
    'symbol_inventory.txt'

$ReportWin = Join-Path `
    $OutDir `
    'STAGE58_REPORT.json'

$AnalyzerWsl = "$OutWsl/analyze_backend_consumers.py"

# ============================================================
# Banner
# ============================================================

Write-Section `
    'AGC PS5 Stage 58 - Global Backend Consumer / Field Provenance Audit'

Write-Host "[INFO] StageDir        = $StageDir"
Write-Host "[INFO] SPRX            = $Sprx"
Write-Host "[INFO] NID DB          = $NidDb"
Write-Host "[INFO] Previous stage  = $PreviousResults"
Write-Host "[INFO] Output          = $OutDir"
Write-Host "[INFO] SPRX WSL       = $SprxWsl"
Write-Host "[INFO] Previous WSL   = $PreviousWsl"
Write-Host "[INFO] Output WSL     = $OutWsl"
Write-Host "[INFO] SDK             = $Sdk"

# ============================================================
# Python analyzer
# ============================================================

$Python = @'
import json
import os
import re
import subprocess
import sys
import tempfile

from elftools.elf.elffile import ELFFile


SPRX = sys.argv[1]
NID_DB = sys.argv[2]
PREVIOUS = sys.argv[3]
OUT_DIR = sys.argv[4]

os.makedirs(
    OUT_DIR,
    exist_ok=True,
)

TARGET_NAME = "sceAgcDriverSubmitCommandBuffer"
TARGET_VA = 0x18B0
TARGET_SIZE = 380

MULTI_NAME = "sceAgcDriverSubmitMultiCommandBuffers"
MULTI_VA = 0x4650
MULTI_SIZE = 579


# ============================================================
# ELF
# ============================================================

FP = open(
    SPRX,
    "rb",
)

ELF = ELFFile(FP)


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


def executable_segments():
    return [
        seg
        for seg in SEGMENTS
        if (
            seg["flags"] & 1
            and seg["filesz"] > 0
        )
    ]


def va_to_file(va):
    for seg in SEGMENTS:

        start = seg["vaddr"]
        end = (
            start
            + seg["filesz"]
        )

        if (
            start <= va
            and va < end
        ):
            return (
                seg["offset"]
                + (
                    va
                    - seg["vaddr"]
                )
            )

    return None


def read_va(va, size):
    file_off = va_to_file(va)

    if file_off is None:
        return b""

    FP.seek(file_off)

    return FP.read(size)


# ============================================================
# IMPORTANT: disassembly helper
# ============================================================

def disassemble(raw, start_va):
    """
    Disassemble an arbitrary byte window using objdump.

    The previous Stage 58 script called this function from
    build_windows() without defining it. This implementation
    keeps disassembly completely optional: a failure produces
    an explanatory string rather than aborting the audit.
    """

    if not raw:
        return ""

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            prefix="agc_stage58_",
            suffix=".bin",
            dir=OUT_DIR,
            delete=False,
        ) as temp:

            temp.write(raw)

            temp.flush()

            temp_path = temp.name

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

        last_error = ""

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

                last_error = str(exc)

                continue

            if proc.returncode == 0:

                return proc.stdout

            last_error = proc.stdout

        if last_error:

            return (
                "DISASSEMBLY_UNAVAILABLE\n"
                + last_error
            )

        return (
            "DISASSEMBLY_UNAVAILABLE\n"
            "No objdump implementation found."
        )

    finally:

        if (
            temp_path
            and
            os.path.exists(temp_path)
        ):

            try:
                os.unlink(temp_path)
            except OSError:
                pass


# ============================================================
# Symbols
# ============================================================

def parse_nm_lines(text):
    symbols = []

    for raw_line in text.splitlines():

        line = raw_line.strip()

        if not line:
            continue

        parts = line.split()

        if len(parts) < 4:
            continue

        address = parts[0]
        size = parts[1]
        typ = parts[2]
        name = " ".join(parts[3:])

        if not re.fullmatch(
            r"[0-9A-Fa-f]+",
            address,
        ):
            continue

        if not re.fullmatch(
            r"[0-9A-Fa-f]+",
            size,
        ):
            continue

        try:
            va = int(
                address,
                16,
            )

            sz = int(
                size,
                16,
            )

        except ValueError:
            continue

        if va == 0:
            continue

        if sz <= 0:
            continue

        if typ.upper() not in (
            "T",
            "W",
            "I",
            "V",
            "F",
        ):
            continue

        symbols.append({
            "va": va,
            "size": sz,
            "type": typ,
            "name": name,
        })

    return symbols


def get_symbol_inventory():
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

    best = []

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

        parsed = parse_nm_lines(
            proc.stdout
        )

        if len(parsed) > len(best):
            best = parsed

        if parsed:
            break

    seen = set()

    unique = []

    for sym in sorted(
        best,
        key=lambda x: (
            x["va"],
            x["size"],
            x["name"],
        ),
    ):

        key = (
            sym["va"],
            sym["size"],
            sym["name"],
        )

        if key in seen:
            continue

        seen.add(key)

        unique.append(sym)

    return unique


SYMBOLS = get_symbol_inventory()


# ============================================================
# NID mapping
# ============================================================

def load_nid_names():
    result = {}

    if not os.path.isfile(
        NID_DB
    ):
        return result

    with open(
        NID_DB,
        "r",
        encoding="utf-8",
        errors="replace",
    ) as fp:

        for line in fp:

            parts = line.strip().split()

            if len(parts) < 2:
                continue

            nid = parts[0]
            name = parts[1]

            if nid not in result:
                result[nid] = name

    return result


NID_NAMES = load_nid_names()


def mapped_name(raw_name):
    if "#" in raw_name:

        nid = raw_name.split(
            "#",
            1,
        )[0]

        return NID_NAMES.get(
            nid,
            raw_name,
        )

    return raw_name


def symbol_for_va(va):
    matches = []

    for sym in SYMBOLS:

        start = sym["va"]

        end = (
            start
            + sym["size"]
        )

        if (
            start <= va
            and va < end
        ):
            matches.append(sym)

    if not matches:
        return None

    matches.sort(
        key=lambda x: (
            x["size"],
            x["va"],
        )
    )

    return matches[0]


# ============================================================
# Byte patterns
# ============================================================

PATTERNS = [
    (
        "field_00",
        0x00,
        8,
        b"\x49\x8b\x06",
        "mov (%r14),%rax / field_00",
    ),

    (
        "field_00",
        0x00,
        8,
        b"\x48\x8b\x06",
        "mov (%rsi),%rax / field_00",
    ),

    (
        "field_00",
        0x00,
        8,
        b"\x48\x8b\x0e",
        "mov (%rsi),%rcx / field_00",
    ),

    (
        "field_00",
        0x00,
        8,
        b"\x48\x8b\x16",
        "mov (%rsi),%rdx / field_00",
    ),

    (
        "field_00",
        0x00,
        8,
        b"\x48\x8b\x1e",
        "mov (%rsi),%rbx / field_00",
    ),

    (
        "field_08",
        0x08,
        4,
        b"\x41\x8b\x46\x08",
        "mov 0x8(%r14),%eax / field_08",
    ),

    (
        "field_08",
        0x08,
        4,
        b"\x8b\x46\x08",
        "mov 0x8(%rsi),%eax / field_08",
    ),

    (
        "field_08",
        0x08,
        4,
        b"\x8b\x4e\x08",
        "mov 0x8(%rsi),%ecx / field_08",
    ),

    (
        "field_08",
        0x08,
        4,
        b"\x8b\x56\x08",
        "mov 0x8(%rsi),%edx / field_08",
    ),

    (
        "field_0c",
        0x0C,
        1,
        b"\x41\x8a\x46\x0c",
        "mov 0xc(%r14),%al / field_0c",
    ),

    (
        "field_0c",
        0x0C,
        1,
        b"\x8a\x46\x0c",
        "mov 0xc(%rsi),%al / field_0c",
    ),

    (
        "field_0c",
        0x0C,
        1,
        b"\x0f\xb6\x46\x0c",
        "movzbl 0xc(%rsi),reg / field_0c",
    ),
]


COPY_PATTERNS = [
    (
        b"\x49\x89\xf6",
        "RSI->R14",
    ),

    (
        b"\x49\x89\xf5",
        "RSI->R13",
    ),

    (
        b"\x49\x89\xff",
        "RSI->R15",
    ),

    (
        b"\x48\x89\xf3",
        "RSI->RBX",
    ),

    (
        b"\x48\x89\xf1",
        "RSI->RCX",
    ),

    (
        b"\x48\x89\xf2",
        "RSI->RDX",
    ),

    (
        b"\x48\x89\xf0",
        "RSI->RAX",
    ),
]


def find_all(blob, needle):
    pos = 0

    while True:

        found = blob.find(
            needle,
            pos,
        )

        if found < 0:
            break

        yield found

        pos = found + 1


def scan_global():
    findings = []

    for seg_index, seg in enumerate(
        executable_segments()
    ):

        FP.seek(
            seg["offset"]
        )

        blob = FP.read(
            seg["filesz"]
        )

        base_va = seg["vaddr"]

        for (
            field,
            offset,
            width,
            needle,
            desc,
        ) in PATTERNS:

            for local_pos in find_all(
                blob,
                needle,
            ):

                va = (
                    base_va
                    + local_pos
                )

                sym = symbol_for_va(
                    va
                )

                findings.append({
                    "segment_index":
                        seg_index,

                    "instruction_va":
                        va,

                    "file_offset":
                        seg["offset"]
                        + local_pos,

                    "field":
                        field,

                    "field_offset":
                        offset,

                    "width":
                        width,

                    "pattern":
                        needle.hex(" "),

                    "description":
                        desc,

                    "symbol_va":
                        sym["va"]
                        if sym
                        else None,

                    "symbol_size":
                        sym["size"]
                        if sym
                        else None,

                    "raw_symbol":
                        sym["name"]
                        if sym
                        else None,

                    "mapped_name":
                        mapped_name(
                            sym["name"]
                        )
                        if sym
                        else None,
                })

        for (
            needle,
            copy_name,
        ) in COPY_PATTERNS:

            for local_pos in find_all(
                blob,
                needle,
            ):

                va = (
                    base_va
                    + local_pos
                )

                sym = symbol_for_va(
                    va
                )

                findings.append({
                    "segment_index":
                        seg_index,

                    "instruction_va":
                        va,

                    "file_offset":
                        seg["offset"]
                        + local_pos,

                    "kind":
                        "REGISTER_COPY",

                    "copy":
                        copy_name,

                    "symbol_va":
                        sym["va"]
                        if sym
                        else None,

                    "symbol_size":
                        sym["size"]
                        if sym
                        else None,

                    "raw_symbol":
                        sym["name"]
                        if sym
                        else None,

                    "mapped_name":
                        mapped_name(
                            sym["name"]
                        )
                        if sym
                        else None,
                })

    findings.sort(
        key=lambda x: (
            x["instruction_va"],
            x.get(
                "field",
                "",
            ),
        )
    )

    return findings


GLOBAL_FINDINGS = scan_global()


# ============================================================
# Group by function
# ============================================================

def group_field_findings():
    groups = {}

    for item in GLOBAL_FINDINGS:

        if "field" not in item:
            continue

        sym_va = item.get(
            "symbol_va"
        )

        if sym_va is not None:

            key = (
                "sym",
                sym_va,
            )

        else:

            key = (
                "window",
                item["instruction_va"]
                & ~0x3f,
            )

        if key not in groups:

            groups[key] = {
                "symbol_va":
                    sym_va,

                "symbol_size":
                    item.get(
                        "symbol_size"
                    ),

                "raw_symbol":
                    item.get(
                        "raw_symbol"
                    ),

                "mapped_name":
                    item.get(
                        "mapped_name"
                    ),

                "findings": [],
            }

        groups[
            key
        ]["findings"].append(
            item
        )

    result = list(
        groups.values()
    )

    for group in result:

        fields = sorted(
            set(
                x["field"]
                for x
                in group["findings"]
            )
        )

        group[
            "fields"
        ] = fields

        score = 0

        if "field_00" in fields:
            score += 20

        if "field_08" in fields:
            score += 20

        if "field_0c" in fields:
            score += 20

        if len(fields) == 3:
            score += 50

        name = (
            group.get(
                "mapped_name"
            )
            or
            group.get(
                "raw_symbol"
            )
            or
            ""
        ).lower()

        for token in (
            "submit",
            "command",
            "buffer",
            "dcb",
            "agr",
            "acb",
        ):

            if token in name:
                score += 10

        group[
            "score"
        ] = score

    result.sort(
        key=lambda x: (
            -x["score"],
            (
                x["symbol_va"]
                if x["symbol_va"]
                is not None
                else
                0
            ),
        )
    )

    return result


GROUPS = group_field_findings()


# ============================================================
# Consumer windows
# ============================================================

def build_windows():
    windows = []

    for group in GROUPS:

        if not group[
            "findings"
        ]:
            continue

        addresses = [
            x["instruction_va"]
            for x
            in group[
                "findings"
            ]
        ]

        start = max(
            0,
            min(addresses)
            - 0x80,
        )

        end = (
            max(addresses)
            + 0x120
        )

        if group.get(
            "symbol_va"
        ) is not None:

            start = group[
                "symbol_va"
            ]

            size = group.get(
                "symbol_size"
            )

            if (
                size
                and size > 0
            ):

                end = (
                    start
                    + size
                )

        size = max(
            0,
            end - start,
        )

        raw = read_va(
            start,
            size,
        )

        text = ""

        if raw:
            text = disassemble(
                raw,
                start,
            )

        windows.append({
            "start_va":
                start,

            "end_va":
                end,

            "group":
                group,

            "disassembly":
                text,
        })

    return windows


WINDOWS = build_windows()


# ============================================================
# Previous stage
# ============================================================

previous_path = os.path.join(
    PREVIOUS,
    "stage56_static.json",
)

if os.path.isfile(
    previous_path
):

    with open(
        previous_path,
        "r",
        encoding="utf-8",
    ) as fp:

        previous = json.load(
            fp
        )

else:
    previous = {}


# ============================================================
# Target / Multi
# ============================================================

def findings_for_target(va):
    return [
        x
        for x in GLOBAL_FINDINGS
        if x.get(
            "symbol_va"
        ) == va
    ]


target_findings = findings_for_target(
    TARGET_VA
)

multi_findings = findings_for_target(
    MULTI_VA
)


# ============================================================
# Consumer candidates
# ============================================================

consumer_candidates = []

for group in GROUPS:

    va = group.get(
        "symbol_va"
    )

    if va in (
        TARGET_VA,
        MULTI_VA,
    ):
        continue

    if not group[
        "fields"
    ]:
        continue

    candidate = {
        "name":
            group.get(
                "mapped_name"
            )
            or
            "",

        "raw_symbol":
            group.get(
                "raw_symbol"
            ),

        "va":
            va,

        "size":
            group.get(
                "symbol_size"
            ),

        "fields":
            group[
                "fields"
            ],

        "score":
            group[
                "score"
            ],

        "findings":
            group[
                "findings"
            ],
    }

    consumer_candidates.append(
        candidate
    )


all_three = [
    x
    for x in consumer_candidates
    if set(
        x["fields"]
    ) == {
        "field_00",
        "field_08",
        "field_0c",
    }
]


field00_field08 = [
    x
    for x in consumer_candidates
    if (
        "field_00" in x["fields"]
        and
        "field_08" in x["fields"]
    )
]


# ============================================================
# Conservative conclusions
# ============================================================

field00_found = any(
    "field_00"
    in x["fields"]
    for x
    in consumer_candidates
)

field08_found = any(
    "field_08"
    in x["fields"]
    for x
    in consumer_candidates
)

field0c_found = any(
    "field_0c"
    in x["fields"]
    for x
    in consumer_candidates
)

all_three_found = (
    len(all_three) > 0
)

backend_consumer_identified = False


# ============================================================
# Global field report
# ============================================================

global_lines = []

global_lines.append(
    "AGC PS5 Stage 58 - GLOBAL FIELD ACCESS SCAN"
)

global_lines.append("")

global_lines.append(
    "Executable PT_LOAD segments:"
)

for index, seg in enumerate(
    executable_segments()
):

    global_lines.append(
        "  segment=%d "
        "VA=0x%x "
        "FILE=0x%x "
        "FILESZ=0x%x "
        "MEMSZ=0x%x "
        "FLAGS=0x%x"
        % (
            index,
            seg["vaddr"],
            seg["offset"],
            seg["filesz"],
            seg["memsz"],
            seg["flags"],
        )
    )

global_lines.append("")

global_lines.append(
    "=== FIELD HITS ==="
)

for item in GLOBAL_FINDINGS:

    if "field" not in item:
        continue

    global_lines.append(
        "0x%x file=0x%x "
        "%s offset=0x%x "
        "width=%d "
        "symbol=%s"
        % (
            item["instruction_va"],
            item["file_offset"],
            item["field"],
            item["field_offset"],
            item["width"],
            item.get(
                "mapped_name"
            )
            or
            "<no-symbol>",
        )
    )

global_lines.append("")

global_lines.append(
    "=== RSI / REGISTER COPY HITS ==="
)

for item in GLOBAL_FINDINGS:

    if item.get(
        "kind"
    ) != "REGISTER_COPY":
        continue

    global_lines.append(
        "0x%x file=0x%x "
        "%s symbol=%s"
        % (
            item["instruction_va"],
            item["file_offset"],
            item["copy"],
            item.get(
                "mapped_name"
            )
            or
            "<no-symbol>",
        )
    )

global_hits_path = os.path.join(
    OUT_DIR,
    "global_field_hits.txt",
)

with open(
    global_hits_path,
    "w",
    encoding="utf-8",
    newline="\n",
) as fp:

    fp.write(
        "\n".join(
            global_lines
        )
        + "\n"
    )


# ============================================================
# Symbol inventory
# ============================================================

symbol_lines = []

symbol_lines.append(
    "AGC PS5 Stage 58 - Symbol Inventory"
)

symbol_lines.append("")

symbol_lines.append(
    "symbol_count = %d"
    % len(SYMBOLS)
)

symbol_lines.append("")

for sym in SYMBOLS:

    symbol_lines.append(
        "0x%x size=%d type=%s "
        "raw=%s mapped=%s"
        % (
            sym["va"],
            sym["size"],
            sym["type"],
            sym["name"],
            mapped_name(
                sym["name"]
            ),
        )
    )

symbol_path = os.path.join(
    OUT_DIR,
    "symbol_inventory.txt",
)

with open(
    symbol_path,
    "w",
    encoding="utf-8",
    newline="\n",
) as fp:

    fp.write(
        "\n".join(
            symbol_lines
        )
        + "\n"
    )


# ============================================================
# Candidate disassembly
# ============================================================

disasm_lines = []

for index, window in enumerate(
    WINDOWS[:40],
    1,
):

    group = window[
        "group"
    ]

    disasm_lines.append(
        "============================================"
    )

    disasm_lines.append(
        "CANDIDATE WINDOW %02d"
        % index
    )

    disasm_lines.append(
        "============================================"
    )

    disasm_lines.append(
        "name=%s"
        %
        (
            group.get(
                "mapped_name"
            )
            or
            "<no-symbol>"
        )
    )

    disasm_lines.append(
        "raw_symbol=%s"
        %
        (
            group.get(
                "raw_symbol"
            )
            or
            "<none>"
        )
    )

    if group.get(
        "symbol_va"
    ) is not None:

        disasm_lines.append(
            "VA=0x%x"
            %
            group[
                "symbol_va"
            ]
        )

    else:

        disasm_lines.append(
            "VA=<window>"
        )

    disasm_lines.append(
        "fields=%s"
        %
        ",".join(
            group[
                "fields"
            ]
        )
    )

    disasm_lines.append(
        "score=%d"
        %
        group[
            "score"
        ]
    )

    disasm_lines.append("")

    for finding in group[
        "findings"
    ]:

        disasm_lines.append(
            "  0x%x "
            "field=%s "
            "offset=0x%x "
            "width=%d "
            "%s"
            % (
                finding[
                    "instruction_va"
                ],
                finding[
                    "field"
                ],
                finding[
                    "field_offset"
                ],
                finding[
                    "width"
                ],
                finding[
                    "description"
                ],
            )
        )

    disasm_lines.append("")

    if window[
        "disassembly"
    ]:

        disasm_lines.append(
            window[
                "disassembly"
            ]
        )

    disasm_lines.append("")


consumer_disasm_path = os.path.join(
    OUT_DIR,
    "consumer_candidate_disassembly.txt",
)

with open(
    consumer_disasm_path,
    "w",
    encoding="utf-8",
    newline="\n",
) as fp:

    fp.write(
        "\n".join(
            disasm_lines
        )
        + "\n"
    )


# ============================================================
# Static JSON
# ============================================================

result = {
    "stage": 58,

    "target": {
        "name":
            TARGET_NAME,

        "va":
            TARGET_VA,

        "size":
            TARGET_SIZE,
    },

    "multi_source": {
        "name":
            MULTI_NAME,

        "va":
            MULTI_VA,

        "size":
            MULTI_SIZE,
    },

    "previous_stage_available":
        bool(previous),

    "elf_segments":
        SEGMENTS,

    "symbol_inventory": {
        "count":
            len(SYMBOLS),

        "method":
            "prospero-nm/llvm-nm",
    },

    "global_scan": {
        "field_hit_count":
            len([
                x
                for x
                in GLOBAL_FINDINGS
                if "field"
                in x
            ]),

        "register_copy_count":
            len([
                x
                for x
                in GLOBAL_FINDINGS
                if x.get(
                    "kind"
                )
                ==
                "REGISTER_COPY"
            ]),

        "target_field_hit_count":
            len(target_findings),

        "multi_field_hit_count":
            len(multi_findings),
    },

    "target_findings":
        target_findings,

    "multi_findings":
        multi_findings,

    "consumer_candidates":
        consumer_candidates[:100],

    "all_three_field_candidates":
        all_three,

    "field00_field08_candidates":
        field00_field08,

    "conclusions": {
        "GLOBAL_FIELD_SCAN_COMPLETED":
            True,

        "SYMBOL_INVENTORY_AVAILABLE":
            len(SYMBOLS) > 0,

        "FIELD_00_CONSUMER_CANDIDATE_FOUND":
            field00_found,

        "FIELD_08_CONSUMER_CANDIDATE_FOUND":
            field08_found,

        "FIELD_0C_CONSUMER_CANDIDATE_FOUND":
            field0c_found,

        "ALL_THREE_FIELDS_CONSUMED_BY_ONE_FUNCTION_CANDIDATE":
            all_three_found,

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
        "Stage 57 reported zero functions.",
        "Stage 58 scans executable PT_LOAD segments directly.",
        "Symbols are supplementary and come from prospero-nm/llvm-nm.",
        "Disassembly is optional and no longer aborts the analysis if objdump is unavailable.",
        "A field-access hit alone does not prove semantic field names.",
        "An indirect backend dispatch target is not assumed.",
    ],
}


static_path = os.path.join(
    OUT_DIR,
    "stage58_static.json",
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


# ============================================================
# Human summary
# ============================================================

summary = []

summary.append(
    "AGC PS5 Stage 58 - Global Backend Consumer / Field Provenance Audit"
)

summary.append("")

summary.append(
    "=== INVENTORY ==="
)

summary.append(
    "symbols = %d"
    % len(SYMBOLS)
)

summary.append(
    "executable_segments = %d"
    % len(
        executable_segments()
    )
)

summary.append(
    "global_field_hits = %d"
    %
    len([
        x
        for x
        in GLOBAL_FINDINGS
        if "field"
        in x
    ])
)

summary.append(
    "register_copy_hits = %d"
    %
    len([
        x
        for x
        in GLOBAL_FINDINGS
        if x.get(
            "kind"
        )
        ==
        "REGISTER_COPY"
    ])
)

summary.append("")

summary.append(
    "=== TARGET FIELD HITS ==="
)

if target_findings:

    for item in target_findings:

        summary.append(
            "0x%x %s"
            % (
                item[
                    "instruction_va"
                ],
                item[
                    "description"
                ],
            )
        )

else:

    summary.append(
        "No target field hits detected."
    )

summary.append("")

summary.append(
    "=== TOP CONSUMER CANDIDATES ==="
)

if consumer_candidates:

    for index, item in enumerate(
        consumer_candidates[:30],
        1,
    ):

        summary.append(
            "%02d. %s VA=%s "
            "SIZE=%s SCORE=%d "
            "FIELDS=%s"
            % (
                index,

                item["name"]
                or
                "<no-symbol>",

                (
                    "0x%x"
                    % item["va"]
                    if item["va"]
                    is not None
                    else
                    "<none>"
                ),

                (
                    item["size"]
                    if item["size"]
                    is not None
                    else
                    "<none>"
                ),

                item["score"],

                ",".join(
                    item["fields"]
                ),
            )
        )

else:

    summary.append(
        "NONE"
    )

summary.append("")

summary.append(
    "=== ALL-THREE FIELD CANDIDATES ==="
)

if all_three:

    for item in all_three:

        summary.append(
            "%s VA=%s SIZE=%s SCORE=%d"
            % (
                item["name"]
                or
                "<no-symbol>",

                (
                    "0x%x"
                    % item["va"]
                    if item["va"]
                    is not None
                    else
                    "<none>"
                ),

                (
                    item["size"]
                    if item["size"]
                    is not None
                    else
                    "<none>"
                ),

                item["score"],
            )
        )

else:

    summary.append(
        "NONE"
    )

summary.append("")

summary.append(
    "=== IMPORTANT LIMIT ==="
)

summary.append(
    "Global field matches do not by themselves establish"
)

summary.append(
    "pointer/size/count/index/flag semantic names."
)

summary.append(
    "A real backend consumer still requires confirmed"
)

summary.append(
    "register/data flow through an actual call target."
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
        %
        (
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
        "\n".join(
            summary
        )
        + "\n"
    )


print(
    json.dumps(
        result,
        indent=2,
    )
)
'@

# ============================================================
# Write analyzer
# ============================================================

Write-Utf8NoBom `
    -Path $AnalyzerWin `
    -Content $Python

# ============================================================
# Prepare workspace
# ============================================================

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

Invoke-WslBash `
    -Command $PrepareCommand

# ============================================================
# Verify toolchain
# ============================================================

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

echo '--- objdump ---'

command -v objdump || true

echo '--- llvm-objdump ---'

command -v llvm-objdump || true
"@

Invoke-WslBash `
    -Command $VerifyCommand

# ============================================================
# Run analyzer
# ============================================================

Write-Step `
    'Escaneo global de segmentos ejecutables y consumidores candidatos'

$AnalyzeCommand = @"
set -e

python3 $(Quote-Bash "$WorkWsl/analyze_backend_consumers.py") \
    $(Quote-Bash $SprxWsl) \
    $(Quote-Bash $NidDbWsl) \
    $(Quote-Bash $PreviousWsl) \
    $(Quote-Bash $OutWsl)
"@

Invoke-WslBash `
    -Command $AnalyzeCommand

# ============================================================
# Verify artefacts
# ============================================================

Write-Step `
    'Verificar artefactos Stage 58'

$VerifyArtifactsCommand = @"
set -e

test -f $(Quote-Bash "$OutWsl/stage58_static.json")
test -f $(Quote-Bash "$OutWsl/backend_consumer_summary.txt")
test -f $(Quote-Bash "$OutWsl/consumer_candidate_disassembly.txt")
test -f $(Quote-Bash "$OutWsl/global_field_hits.txt")
test -f $(Quote-Bash "$OutWsl/symbol_inventory.txt")

echo '--- backend_consumer_summary.txt ---'

cat $(Quote-Bash "$OutWsl/backend_consumer_summary.txt")

echo '--- output files ---'

find $(Quote-Bash $OutWsl) \
    -maxdepth 2 \
    -type f |
    sort
"@

Invoke-WslBash `
    -Command $VerifyArtifactsCommand

# ============================================================
# Load JSON
# ============================================================

$Static = (
    Get-Content `
        -LiteralPath $StaticWin `
        -Raw
) | ConvertFrom-Json

$SymbolAvailable = [bool](
    $Static.conclusions.SYMBOL_INVENTORY_AVAILABLE
)

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

# ============================================================
# Hash
# ============================================================

Write-Step `
    'Hash artefactos'

$HashStatic = Get-Sha256 `
    $StaticWin

$HashSummary = Get-Sha256 `
    $SummaryWin

$HashDisasm = Get-Sha256 `
    $DisasmWin

$HashGlobal = Get-Sha256 `
    $GlobalHitsWin

$HashNm = Get-Sha256 `
    $NmWin

Write-Host `
    "[INFO] stage58_static.json SHA256=$HashStatic"

Write-Host `
    "[INFO] backend_consumer_summary.txt SHA256=$HashSummary"

Write-Host `
    "[INFO] consumer_candidate_disassembly.txt SHA256=$HashDisasm"

Write-Host `
    "[INFO] global_field_hits.txt SHA256=$HashGlobal"

Write-Host `
    "[INFO] symbol_inventory.txt SHA256=$HashNm"

# ============================================================
# Report
# ============================================================

$Report = [ordered]@{
    stage = 58

    target = [ordered]@{
        name = 'sceAgcDriverSubmitCommandBuffer'
        nid = 'b4fpgH5ZXxQ'
        va = '0x18b0'
        size = 380
    }

    conclusions = [ordered]@{
        GLOBAL_FIELD_SCAN_COMPLETED =
            $true

        SYMBOL_INVENTORY_AVAILABLE =
            $SymbolAvailable

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
        'stage58_static.json' =
            $HashStatic

        'backend_consumer_summary.txt' =
            $HashSummary

        'consumer_candidate_disassembly.txt' =
            $HashDisasm

        'global_field_hits.txt' =
            $HashGlobal

        'symbol_inventory.txt' =
            $HashNm
    }
}

Write-Utf8NoBom `
    -Path $ReportWin `
    -Content (
        $Report |
        ConvertTo-Json -Depth 20
    )

# ============================================================
# Final
# ============================================================

Write-Host ''
Write-Host '============================================' -ForegroundColor Green
Write-Host 'Stage 58 completado' -ForegroundColor Green
Write-Host '============================================' -ForegroundColor Green
Write-Host ''

Write-Host `
    'GLOBAL_FIELD_SCAN_COMPLETED = True'

Write-Host `
    "SYMBOL_INVENTORY_AVAILABLE = $SymbolAvailable"

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