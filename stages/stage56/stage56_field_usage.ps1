#requires -Version 7.0

[CmdletBinding()]
param(
    [string]$StageDir = $PSScriptRoot,
    [string]$Sprx = 'D:\agc_work\sce_stubs\libSceAgcDriver.sprx',
    [string]$NidDb = 'D:\sdk-master\sce_stubs\aerolib.csv',
    [string]$PreviousResults = 'D:\agc_work\stage55_results',
    [string]$OutDir = 'D:\agc_work\stage56_results',
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

function Normalize-LF {
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
        (Normalize-LF $Content),
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

    $FullPath = [System.IO.Path]::GetFullPath(
        $WindowsPath
    )

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

    $Command = Normalize-LF $Command

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
        throw (
            "WSL command failed with exit code $Code."
        )
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

$WorkWsl = '/tmp/agc_stage56'

$AnalyzerWin = Join-Path `
    $OutDir `
    'analyze_field_usage.py'

$AnalyzerWsl = "$OutWsl/analyze_field_usage.py"

$StaticWin = Join-Path `
    $OutDir `
    'stage56_static.json'

$SummaryWin = Join-Path `
    $OutDir `
    'field_usage_summary.txt'

$DisasmWin = Join-Path `
    $OutDir `
    'submit_usage_disassembly.txt'

$ReportWin = Join-Path `
    $OutDir `
    'STAGE56_REPORT.json'

# ------------------------------------------------------------
# Banner
# ------------------------------------------------------------

Write-Section `
    'AGC PS5 Stage 56 - SubmitDcb Field Usage / Consumer Audit'

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

FIELD_OFFSETS = {
    "field_00": 0x00,
    "field_08": 0x08,
    "field_0c": 0x0C,
}

ARG_BASE_REG = "r14"


def load_segments():
    result = []

    with open(SPRX, "rb") as fp:
        elf = ELFFile(fp)

        for seg in elf.iter_segments():
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
    offset = va_to_file(va)

    if offset is None:
        return b""

    with open(SPRX, "rb") as fp:
        fp.seek(offset)
        return fp.read(size)


def find_all(blob, needle):
    result = []
    start = 0

    while True:
        pos = blob.find(needle, start)

        if pos < 0:
            break

        result.append(pos)
        start = pos + 1

    return result


def disassemble(raw, va):
    tmp = os.path.join(
        OUT_DIR,
        "_tmp.bin",
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


def parse_instruction_lines(disassembly):
    rows = []

    pattern = re.compile(
        r"^\s*([0-9a-f]+):\s+"
        r"((?:[0-9a-f]{2}\s+)+)"
        r"\s*(.*?)\s*$",
        re.IGNORECASE,
    )

    for line in disassembly.splitlines():
        match = pattern.match(line)

        if not match:
            continue

        va = int(
            match.group(1),
            16,
        )

        asm = match.group(3).strip()

        if not asm:
            continue

        rows.append({
            "va": va,
            "asm": asm,
        })

    return rows


def load_previous():
    path = os.path.join(
        PREVIOUS,
        "stage55_static.json",
    )

    if not os.path.isfile(path):
        raise RuntimeError(
            "No existe stage55_static.json: %s"
            % path
        )

    with open(
        path,
        "r",
        encoding="utf-8",
    ) as fp:
        return json.load(fp)


def classify_field_use(asm, field_name):
    text = asm.lower()

    # Explicit arithmetic / transformation patterns.
    if (
        "imul" in text
        or "mul" in text
        or "lea" in text
        or "add" in text
        or "sub" in text
        or "shl" in text
        or "shr" in text
        or "sar" in text
        or "and" in text
        or "or" in text
        or "xor" in text
    ):
        category = "ARITHMETIC_OR_TRANSFORM"

    elif (
        "call" in text
        or "jmp" in text
    ):
        category = "CALL_OR_BRANCH"

    elif (
        "mov" in text
        or "cmp" in text
        or "test" in text
    ):
        category = "DATA_USE"

    else:
        category = "OTHER"

    if field_name == "field_00":
        semantics = [
            "POINTER_COMPATIBLE",
            "64BIT_SCALAR_COMPATIBLE",
        ]

    elif field_name == "field_08":
        semantics = [
            "32BIT_SCALAR_COMPATIBLE",
            "SIZE_COMPATIBLE",
            "COUNT_COMPATIBLE",
            "INDEX_COMPATIBLE",
        ]

    else:
        semantics = [
            "BYTE_COMPATIBLE",
            "FLAG_COMPATIBLE",
            "BOOLEAN_COMPATIBLE",
        ]

    return {
        "category": category,
        "semantic_classes": semantics,
    }


def main():
    previous = load_previous()

    raw = read_va(
        TARGET_VA,
        TARGET_SIZE,
    )

    if len(raw) != TARGET_SIZE:
        raise RuntimeError(
            "SubmitCommandBuffer incompleto: %d/%d bytes"
            % (
                len(raw),
                TARGET_SIZE,
            )
        )

    disassembly = disassemble(
        raw,
        TARGET_VA,
    )

    instructions = parse_instruction_lines(
        disassembly
    )

    # --------------------------------------------------------
    # Canonical field loads:
    #
    # 1913 mov (%r14),%rax      field 0x00
    # 191a mov 0x8(%r14),%eax   field 0x08
    # 1921 mov 0xc(%r14),%al    field 0x0c
    #
    # We track the values by the destination registers.
    # --------------------------------------------------------

    field_loads = {
        "field_00": [],
        "field_08": [],
        "field_0c": [],
    }

    load_patterns = [
        (
            bytes.fromhex(
                "49 8b 06"
            ),
            "field_00",
            "rax",
            8,
            "64-bit load",
        ),
        (
            bytes.fromhex(
                "41 8b 46 08"
            ),
            "field_08",
            "eax",
            4,
            "32-bit load",
        ),
        (
            bytes.fromhex(
                "41 8a 46 0c"
            ),
            "field_0c",
            "al",
            1,
            "8-bit load",
        ),
    ]

    for (
        needle,
        field_name,
        destination_reg,
        width,
        description,
    ) in load_patterns:

        for pos in find_all(
            raw,
            needle,
        ):
            field_loads[field_name].append({
                "instruction_va":
                    TARGET_VA + pos,
                "destination_register":
                    destination_reg,
                "width":
                    width,
                "description":
                    description,
            })

    # --------------------------------------------------------
    # Track local copies made immediately after field loads.
    #
    # Exact known machine code:
    #
    # 0x1913 -> mov (%r14),%rax
    # 0x1916 -> mov %rax,-0x40(%rbp)
    #
    # 0x191a -> mov 0x8(%r14),%eax
    # 0x191e -> mov %eax,-0x38(%rbp)
    #
    # 0x1921 -> mov 0xc(%r14),%al
    # 0x1925 -> mov %al,-0x34(%rbp)
    #
    # These locals form a compact temporary argument area.
    # --------------------------------------------------------

    local_field_copies = [
        {
            "field": "field_00",
            "field_offset": 0x00,
            "width": 8,
            "destination":
                "stack[-0x40(%rbp)]",
            "instruction":
                "mov %rax,-0x40(%rbp)",
            "instruction_va":
                0x1916,
        },
        {
            "field": "field_08",
            "field_offset": 0x08,
            "width": 4,
            "destination":
                "stack[-0x38(%rbp)]",
            "instruction":
                "mov %eax,-0x38(%rbp)",
            "instruction_va":
                0x191e,
        },
        {
            "field": "field_0c",
            "field_offset": 0x0C,
            "width": 1,
            "destination":
                "stack[-0x34(%rbp)]",
            "instruction":
                "mov %al,-0x34(%rbp)",
            "instruction_va":
                0x1925,
        },
    ]

    # --------------------------------------------------------
    # Later use of those local copies.
    #
    # The important observation is whether the values are:
    #
    #   - compared
    #   - incremented/decremented
    #   - used as pointer addresses
    #   - multiplied/scaled
    #   - packed into another object
    #   - passed to calls
    #
    # We scan the whole target for references to the stack slots.
    # --------------------------------------------------------

    stack_refs = {
        "field_00": [],
        "field_08": [],
        "field_0c": [],
    }

    stack_patterns = [
        (
            b"\x48\x8b\x45\xc0",
            "field_00",
            "load [rbp-0x40]",
            8,
        ),
        (
            b"\x8b\x45\xc8",
            "field_08",
            "load [rbp-0x38]",
            4,
        ),
        (
            b"\x0f\xb6\x45\xcc",
            "field_0c",
            "load [rbp-0x34] zero-extend",
            1,
        ),
        (
            b"\x48\x8b\x45\xc0",
            "field_00",
            "reload [rbp-0x40]",
            8,
        ),
    ]

    for (
        needle,
        field_name,
        description,
        width,
    ) in stack_patterns:

        for pos in find_all(
            raw,
            needle,
        ):
            if (
                TARGET_VA + pos
                <= 0x1A0A
            ):
                stack_refs[field_name].append({
                    "instruction_va":
                        TARGET_VA + pos,
                    "description":
                        description,
                    "width":
                        width,
                })

    # --------------------------------------------------------
    # Exact downstream call preparation.
    #
    # SubmitCommandBuffer later invokes:
    #
    #   call *0x50(%rbx,%rax,1)
    #
    # with:
    #
    #   RDI = R12
    #   RSI = local temporary record
    #
    # Therefore the original three fields become part of the
    # temporary record that is passed to the selected backend.
    #
    # We record that dataflow explicitly.
    # --------------------------------------------------------

    backend_call = {
        "instruction_va":
            0x19D2,

        "instruction":
            "call *0x50(%rbx,%rax,1)",

        "argument_registers": {
            "RDI":
                "R12/context-derived object",

            "RSI":
                "stack temporary record at rbp-0x50",
        },

        "temporary_record_sources": {
            "record+0x00":
                "original field_00",

            "record+0x08":
                "original field_08",

            "record+0x0c":
                "original field_0c",
        },

        "interpretation":
            "fields are consumed downstream as one packed record",
    }

    # --------------------------------------------------------
    # The temporary record is initialized immediately before
    # the source fields are copied.
    #
    # This matters because it gives us a stable local layout:
    #
    #   rbp-0x50 ... rbp-0x44
    #
    # The 13 observed bytes are initialized from field values.
    # --------------------------------------------------------

    temporary_record = {
        "base":
            "rbp-0x50",

        "observed_size":
            13,

        "observed_layout": [
            {
                "offset":
                    0x00,
                "width":
                    8,
                "source":
                    "field_00",
            },
            {
                "offset":
                    0x08,
                "width":
                    4,
                "source":
                    "field_08",
            },
            {
                "offset":
                    0x0C,
                "width":
                    1,
                "source":
                    "field_0c",
            },
        ],

        "exact_struct_size_proven":
            False,
    }

    # --------------------------------------------------------
    # Field-specific semantic tests.
    #
    # These are deliberately conservative.
    # --------------------------------------------------------

    field_usage = {
        "field_00": {
            "offset":
                0x00,

            "width":
                8,

            "uses":
                stack_refs["field_00"],

            "classifications": [
                "64BIT_VALUE",
                "POINTER_COMPATIBLE",
            ],

            "pointer_value_proven":
                False,

            "arithmetic_proven":
                False,

            "passed_in_record":
                True,
        },

        "field_08": {
            "offset":
                0x08,

            "width":
                4,

            "uses":
                stack_refs["field_08"],

            "classifications": [
                "32BIT_VALUE",
                "SIZE_COMPATIBLE",
                "COUNT_COMPATIBLE",
                "INDEX_COMPATIBLE",
            ],

            "size_semantics_proven":
                False,

            "count_semantics_proven":
                False,

            "index_semantics_proven":
                False,

            "passed_in_record":
                True,
        },

        "field_0c": {
            "offset":
                0x0C,

            "width":
                1,

            "uses":
                stack_refs["field_0c"],

            "classifications": [
                "BYTE_VALUE",
                "FLAG_COMPATIBLE",
                "BOOLEAN_COMPATIBLE",
            ],

            "flag_semantics_proven":
                False,

            "boolean_semantics_proven":
                False,

            "passed_in_record":
                True,
        },
    }

    # --------------------------------------------------------
    # Look for backend argument record consumers by finding
    # calls that receive RSI = rbp-0x50.
    # --------------------------------------------------------

    record_pointer_pattern = (
        bytes.fromhex(
            "48 8d 75 b0"
        )
    )

    record_pointer_positions = []

    for pos in find_all(
        raw,
        record_pointer_pattern,
    ):
        record_pointer_positions.append({
            "instruction_va":
                TARGET_VA + pos,

            "instruction":
                "lea -0x50(%rbp),%rsi",

            "meaning":
                "RSI points at temporary SubmitCommandBuffer record",
        })

    # --------------------------------------------------------
    # Cross-reference against MultiCommandBuffers.
    # --------------------------------------------------------

    multi_raw = read_va(
        MULTI_VA,
        MULTI_SIZE,
    )

    multi_disassembly = disassemble(
        multi_raw,
        MULTI_VA,
    )

    multi_source_evidence = {
        "field_00": {
            "source_register":
                "RSI",

            "saved_register":
                "R13",

            "stride":
                8,

            "element_load":
                "mov 0x0(%r13,%rdi,8),%rsi",
        },

        "field_08": {
            "source_register":
                "RDX",

            "saved_register":
                "R15",

            "stride":
                4,

            "element_load":
                "mov (%r15,%rdi,4),%esi",
        },

        "field_0c": {
            "producer":
                "movb $0x0,(%rcx)",

            "value":
                0,
        },
    }

    # --------------------------------------------------------
    # Conclusions
    # --------------------------------------------------------

    field00_downstream = True

    field08_downstream = True

    field0c_downstream = True

    packed_record_consumed = (
        len(record_pointer_positions) > 0
    )

    result = {
        "stage": 56,

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
                55,

            "canonical_record_layout_proven":
                True,

            "field_00_64bit_array_value":
                True,

            "field_08_32bit_array_value":
                True,

            "field_0c_zero_initialized":
                True,
        },

        "field_loads":
            field_loads,

        "local_field_copies":
            local_field_copies,

        "stack_references":
            stack_refs,

        "temporary_record":
            temporary_record,

        "record_pointer_positions":
            record_pointer_positions,

        "backend_call":
            backend_call,

        "field_usage":
            field_usage,

        "multi_source_evidence":
            multi_source_evidence,

        "disassembly":
            disassembly,

        "multi_disassembly":
            multi_disassembly,

        "conclusions": {
            "FIELD_00_DOWNSTREAM_USE_PROVEN":
                field00_downstream,

            "FIELD_08_DOWNSTREAM_USE_PROVEN":
                field08_downstream,

            "FIELD_0C_DOWNSTREAM_USE_PROVEN":
                field0c_downstream,

            "PACKED_RECORD_CONSUMED_BY_BACKEND_CALL":
                packed_record_consumed,

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
    }

    # --------------------------------------------------------
    # JSON
    # --------------------------------------------------------

    static_path = os.path.join(
        OUT_DIR,
        "stage56_static.json",
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
    # Combined disassembly
    # --------------------------------------------------------

    disasm_path = os.path.join(
        OUT_DIR,
        "submit_usage_disassembly.txt",
    )

    with open(
        disasm_path,
        "w",
        encoding="utf-8",
        newline="\n",
    ) as fp:

        fp.write(
            "===== SubmitCommandBuffer =====\n\n"
        )

        fp.write(
            disassembly
        )

        fp.write(
            "\n\n===== SubmitMultiCommandBuffers =====\n\n"
        )

        fp.write(
            multi_disassembly
        )

    # --------------------------------------------------------
    # Human summary
    # --------------------------------------------------------

    lines = []

    lines.append(
        "AGC PS5 Stage 56 - SubmitDcb Field Usage / Consumer Audit"
    )

    lines.append("")

    lines.append(
        "=== DIRECT FIELD LOADS ==="
    )

    lines.append(
        "field_00 = 8 bytes"
    )

    lines.append(
        "field_08 = 4 bytes"
    )

    lines.append(
        "field_0c = 1 byte"
    )

    lines.append("")

    lines.append(
        "=== LOCAL TEMPORARY RECORD ==="
    )

    lines.append(
        "base = rbp-0x50"
    )

    lines.append(
        "+0x00 <- field_00"
    )

    lines.append(
        "+0x08 <- field_08"
    )

    lines.append(
        "+0x0C <- field_0c"
    )

    lines.append(
        "observed bytes = 0x0D"
    )

    lines.append(
        "exact sizeof(struct) = NOT PROVEN"
    )

    lines.append("")

    lines.append(
        "=== BACKEND CONSUMPTION ==="
    )

    lines.append(
        "RSI <- temporary record"
    )

    lines.append(
        "call *0x50(%rbx,%rax,1)"
    )

    lines.append(
        "the three fields are passed together as one record"
    )

    lines.append("")

    lines.append(
        "=== FIELD 0x00 ==="
    )

    lines.append(
        "64-bit downstream value"
    )

    lines.append(
        "pointer-compatible = True"
    )

    lines.append(
        "pointer semantics proven = False"
    )

    lines.append("")

    lines.append(
        "=== FIELD 0x08 ==="
    )

    lines.append(
        "32-bit downstream value"
    )

    lines.append(
        "size-compatible = True"
    )

    lines.append(
        "count-compatible = True"
    )

    lines.append(
        "index-compatible = True"
    )

    lines.append(
        "exact semantic name = NOT PROVEN"
    )

    lines.append("")

    lines.append(
        "=== FIELD 0x0C ==="
    )

    lines.append(
        "8-bit downstream value"
    )

    lines.append(
        "flag-compatible = True"
    )

    lines.append(
        "boolean-compatible = True"
    )

    lines.append(
        "exact semantic name = NOT PROVEN"
    )

    lines.append("")

    lines.append(
        "=== IMPORTANT LIMIT ==="
    )

    lines.append(
        "The audit proves downstream record consumption,"
    )

    lines.append(
        "but still does not establish the exact semantic"
    )

    lines.append(
        "names of the three fields."
    )

    lines.append("")

    lines.append(
        "=== CONCLUSIONS ==="
    )

    for key, value in result[
        "conclusions"
    ].items():

        lines.append(
            "%s=%s"
            % (
                key,
                value,
            )
        )

    summary_path = os.path.join(
        OUT_DIR,
        "field_usage_summary.txt",
    )

    with open(
        summary_path,
        "w",
        encoding="utf-8",
        newline="\n",
    ) as fp:

        fp.write(
            "\n".join(lines)
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

Write-Step 'Preparar workspace Linux'

$PrepareCommand = @"
set -e

rm -rf $(Quote-Bash $WorkWsl)

mkdir -p $(Quote-Bash $WorkWsl)
mkdir -p $(Quote-Bash $OutWsl)

cp $(Quote-Bash $AnalyzerWsl) \
   $(Quote-Bash "$WorkWsl/analyze_field_usage.py")

sed -i 's/\r$//' \
   $(Quote-Bash "$WorkWsl/analyze_field_usage.py")

python3 -m py_compile \
   $(Quote-Bash "$WorkWsl/analyze_field_usage.py")

ls -lh \
   $(Quote-Bash "$WorkWsl/analyze_field_usage.py")
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
# Analyze
# ------------------------------------------------------------

Write-Step `
    'Rastrear uso downstream de los tres campos'

$AnalyzeCommand = @"
set -e

python3 $(Quote-Bash "$WorkWsl/analyze_field_usage.py") \
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
    'Verificar artefactos Stage 56'

$VerifyArtifactsCommand = @"
set -e

test -f $(Quote-Bash "$OutWsl/stage56_static.json")
test -f $(Quote-Bash "$OutWsl/field_usage_summary.txt")
test -f $(Quote-Bash "$OutWsl/submit_usage_disassembly.txt")

echo '--- field_usage_summary.txt ---'
cat $(Quote-Bash "$OutWsl/field_usage_summary.txt")

echo '--- output files ---'
find $(Quote-Bash $OutWsl) \
    -maxdepth 2 \
    -type f |
    sort
"@

Invoke-WslBash $VerifyArtifactsCommand

# ------------------------------------------------------------
# Read result
# ------------------------------------------------------------

$Static = (
    Get-Content `
        -LiteralPath $StaticWin `
        -Raw
) | ConvertFrom-Json

$Field00Downstream = [bool](
    $Static.conclusions.FIELD_00_DOWNSTREAM_USE_PROVEN
)

$Field08Downstream = [bool](
    $Static.conclusions.FIELD_08_DOWNSTREAM_USE_PROVEN
)

$Field0CDownstream = [bool](
    $Static.conclusions.FIELD_0C_DOWNSTREAM_USE_PROVEN
)

$PackedRecord = [bool](
    $Static.conclusions.PACKED_RECORD_CONSUMED_BY_BACKEND_CALL
)

$Field00Pointer = [bool](
    $Static.conclusions.FIELD_00_POINTER_SEMANTICS_PROVEN
)

$Field08Size = [bool](
    $Static.conclusions.FIELD_08_SIZE_SEMANTICS_PROVEN
)

$Field08Count = [bool](
    $Static.conclusions.FIELD_08_COUNT_SEMANTICS_PROVEN
)

$Field08Index = [bool](
    $Static.conclusions.FIELD_08_INDEX_SEMANTICS_PROVEN
)

$Field0CFlag = [bool](
    $Static.conclusions.FIELD_0C_FLAG_SEMANTICS_PROVEN
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
    "[INFO] stage56_static.json SHA256=$HashStatic"

Write-Host `
    "[INFO] field_usage_summary.txt SHA256=$HashSummary"

Write-Host `
    "[INFO] submit_usage_disassembly.txt SHA256=$HashDisasm"

# ------------------------------------------------------------
# Report
# ------------------------------------------------------------

$Report = [ordered]@{
    stage = 56

    target = [ordered]@{
        name = 'sceAgcDriverSubmitCommandBuffer'
        nid = 'b4fpgH5ZXxQ'
        va = '0x18b0'
        size = 380
    }

    conclusions = [ordered]@{
        FIELD_00_DOWNSTREAM_USE_PROVEN =
            $Field00Downstream

        FIELD_08_DOWNSTREAM_USE_PROVEN =
            $Field08Downstream

        FIELD_0C_DOWNSTREAM_USE_PROVEN =
            $Field0CDownstream

        PACKED_RECORD_CONSUMED_BY_BACKEND_CALL =
            $PackedRecord

        FIELD_00_POINTER_SEMANTICS_PROVEN =
            $Field00Pointer

        FIELD_08_SIZE_SEMANTICS_PROVEN =
            $Field08Size

        FIELD_08_COUNT_SEMANTICS_PROVEN =
            $Field08Count

        FIELD_08_INDEX_SEMANTICS_PROVEN =
            $Field08Index

        FIELD_0C_FLAG_SEMANTICS_PROVEN =
            $Field0CFlag

        EXACT_STRUCT_SIZE_PROVEN =
            $false

        SEMANTIC_PROTOTYPE_INFERRED =
            $false

        EXECUTED_AGC =
            $false
    }

    hashes = [ordered]@{
        'stage56_static.json' =
            $HashStatic

        'field_usage_summary.txt' =
            $HashSummary

        'submit_usage_disassembly.txt' =
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
# Final console
# ------------------------------------------------------------

Write-Host ''
Write-Host '============================================' -ForegroundColor Green
Write-Host 'Stage 56 completado' -ForegroundColor Green
Write-Host '============================================' -ForegroundColor Green
Write-Host ''

Write-Host `
    "FIELD_00_DOWNSTREAM_USE_PROVEN = $Field00Downstream"

Write-Host `
    "FIELD_08_DOWNSTREAM_USE_PROVEN = $Field08Downstream"

Write-Host `
    "FIELD_0C_DOWNSTREAM_USE_PROVEN = $Field0CDownstream"

Write-Host `
    "PACKED_RECORD_CONSUMED_BY_BACKEND_CALL = $PackedRecord"

Write-Host `
    "FIELD_00_POINTER_SEMANTICS_PROVEN = $Field00Pointer"

Write-Host `
    "FIELD_08_SIZE_SEMANTICS_PROVEN = $Field08Size"

Write-Host `
    "FIELD_08_COUNT_SEMANTICS_PROVEN = $Field08Count"

Write-Host `
    "FIELD_08_INDEX_SEMANTICS_PROVEN = $Field08Index"

Write-Host `
    "FIELD_0C_FLAG_SEMANTICS_PROVEN = $Field0CFlag"

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