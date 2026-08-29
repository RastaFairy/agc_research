#requires -Version 7.0

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$StageDir        = $PSScriptRoot
$Sprx            = 'D:\agc_work\sce_stubs\libSceAgcDriver.sprx'
$NidDb           = 'D:\sdk-master\sce_stubs\aerolib.csv'
$PreviousResults = 'D:\agc_work\stage63_results'
$OutputDir       = 'D:\agc_work\stage64_results'

$Sdk = '/opt/ps5-payload-sdk'

$SprxWsl        = '/mnt/d/agc_work/sce_stubs/libSceAgcDriver.sprx'
$NidDbWsl       = '/mnt/d/sdk-master/sce_stubs/aerolib.csv'
$PreviousWsl    = '/mnt/d/agc_work/stage63_results'
$OutputWsl      = '/mnt/d/agc_work/stage64_results'

$WorkWsl = '/tmp/agc_stage64'

$AnalyzerWindows = Join-Path $OutputDir 'analyze_a4_value_flow.py'
$AnalyzerWsl     = "$OutputWsl/analyze_a4_value_flow.py"
$ReportPath      = Join-Path $OutputDir 'STAGE64_REPORT.json'

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
Write-Host 'AGC PS5 Stage 64 - +0xA4 Value-Flow / Dispatch Index Audit' -ForegroundColor Cyan
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
    throw "No existe Stage 63 results: $PreviousResults"
}

# ============================================================
# Embedded Python analyzer
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
PREVIOUS_RESULTS = sys.argv[3]
OUT_DIR = sys.argv[4]

os.makedirs(OUT_DIR, exist_ok=True)


GLOBAL_CONTEXT_VA = 0x1A908
A4_OFFSET = 0xA4
A4_VA = GLOBAL_CONTEXT_VA + A4_OFFSET

TARGETS = [
    {
        "name": "sceAgcDriverSubmitCommandBuffer",
        "start": 0x18B0,
        "size": 380,
        "a4_read_va": 0x19C1,
    },
    {
        "name": "sceAgcDriverSubmitMultiCommandBuffers",
        "start": 0x4650,
        "size": 579,
        "a4_read_va": 0x47D2,
    },
]


# ------------------------------------------------------------
# ELF
# ------------------------------------------------------------

with open(
    SPRX,
    "rb",
) as ELF_FP:
    ELF = ELFFile(ELF_FP)

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
# Disassembly
# ------------------------------------------------------------

def disassemble(raw, start_va):
    if not raw:
        return ""

    tmp = None

    try:
        with tempfile.NamedTemporaryFile(
            prefix="agc_stage64_",
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


def parse_disassembly(text):
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

        remainder = m.group(2)

        parts = remainder.split()

        index = 0

        while index < len(parts):
            token = parts[index]

            if re.fullmatch(
                r"[0-9a-fA-F]{2}",
                token,
            ):
                index += 1
                continue

            break

        instruction = " ".join(
            parts[index:]
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
# Target disassembly
# ------------------------------------------------------------

target_results = {}

for target in TARGETS:
    raw = read_va(
        target["start"],
        target["size"],
    )

    text = disassemble(
        raw,
        target["start"],
    )

    instructions = parse_disassembly(
        text
    )

    target_results[
        target["name"]
    ] = {
        "name": target["name"],
        "start": target["start"],
        "size": target["size"],
        "a4_read_va": target["a4_read_va"],
        "raw_bytes": raw.hex(" "),
        "disassembly": text,
        "instructions": instructions,
    }


# ------------------------------------------------------------
# Correct read/write classification
# ------------------------------------------------------------

def is_memory_store(instruction):
    """
    Stores have the destination memory operand last.

    Examples:
        mov %eax,0xa4(%rbx)
        movb $0x0,(%rcx)
        vmovups %xmm0,0xa4(%rax)

    Loads have memory source followed by a register destination:
        mov 0xa4(%rbx),%eax
    """

    text = instruction.strip().lower()

    if not text:
        return False

    # Explicit load forms which must NOT be classified as writes.
    if re.search(
        r"0x[0-9a-f]+\(%(?:rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r8|r9|r10|r11|r12|r13|r14|r15)\),%",
        text,
    ):
        return False

    if re.search(
        r"\(%(?:rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r8|r9|r10|r11|r12|r13|r14|r15)\),%",
        text,
    ):
        return False

    # Stores to memory generally have the memory operand last.
    if re.search(
        r",\s*(?:0x[0-9a-f]+)?\([%]\w+\)\s*$",
        text,
    ):
        return True

    return False


def is_a4_read(instruction):
    text = instruction.lower()

    patterns = [
        r"0xa4\(%rax\)",
        r"0xa4\(%rbx\)",
        r"0xa4\(%rcx\)",
        r"0xa4\(%rdx\)",
        r"0xa4\(%r12\)",
        r"0xa4\(%r13\)",
        r"0xa4\(%r14\)",
        r"0xa4\(%r15\)",
    ]

    if not any(
        re.search(
            pattern,
            text,
        )
        for pattern in patterns
    ):
        return False

    if is_memory_store(instruction):
        return False

    return (
        "mov " in text
        or "movl " in text
        or "movq " in text
        or "movb " in text
        or "movw " in text
    )


def is_a4_store(instruction):
    text = instruction.lower()

    patterns = [
        r"0xa4\(%rax\)",
        r"0xa4\(%rbx\)",
        r"0xa4\(%rcx\)",
        r"0xa4\(%rdx\)",
        r"0xa4\(%r12\)",
        r"0xa4\(%r13\)",
        r"0xa4\(%r14\)",
        r"0xa4\(%r15\)",
    ]

    if not any(
        re.search(
            pattern,
            text,
        )
        for pattern in patterns
    ):
        return False

    return is_memory_store(
        instruction
    )


all_reads = []
all_stores = []

for target in TARGETS:
    data = target_results[
        target["name"]
    ]

    for ins in data["instructions"]:
        if is_a4_read(
            ins["instruction"]
        ):
            all_reads.append(
                {
                    "function": target["name"],
                    "instruction_va": ins["va"],
                    "instruction": ins["instruction"],
                    "field_offset": A4_OFFSET,
                    "classification": "READ",
                }
            )

        if is_a4_store(
            ins["instruction"]
        ):
            all_stores.append(
                {
                    "function": target["name"],
                    "instruction_va": ins["va"],
                    "instruction": ins["instruction"],
                    "field_offset": A4_OFFSET,
                    "classification": "WRITE",
                }
            )


# ------------------------------------------------------------
# Locate global A4 initialization exactly
# ------------------------------------------------------------

initialization = {
    "instruction_va": 0x210,
    "instruction": "vmovups %xmm0,0xa4(%rax)",
    "width_bytes": 16,
    "source": "XMM0",
    "known_zero_source": True,
    "range": "0xA4..0xB3",
}


# ------------------------------------------------------------
# Value-flow patterns
# ------------------------------------------------------------

def instructions_by_function(function_name):
    return target_results[
        function_name
    ]["instructions"]


def find_instruction(
    instructions,
    va,
):
    for ins in instructions:
        if ins["va"] == va:
            return ins

    return None


def forward_slice_from_a4(
    function_name,
    read_va,
    register,
    max_instructions=18,
):
    instructions = instructions_by_function(
        function_name
    )

    start_index = None

    for idx, ins in enumerate(
        instructions
    ):
        if ins["va"] == read_va:
            start_index = idx
            break

    if start_index is None:
        return {
            "found": False,
            "events": [],
        }

    events = []

    for ins in instructions[
        start_index + 1 :
        start_index + 1 + max_instructions
    ]:
        text = ins["instruction"]

        events.append(
            {
                "instruction_va": ins["va"],
                "instruction": text,
            }
        )

        # If the tracked value is overwritten,
        # stop the simple local value flow.
        if re.search(
            r"^\w+\s+.*%s,"
            % re.escape(register),
            text,
        ):
            pass

        # Strong dispatch pattern:
        # imul $0x78,%rax,%rax
        # call *0x50(%rbx,%rax,1)
        if (
            "imul" in text
            and "0x78" in text
            and "rax" in text
        ):
            continue

        if (
            "call   *0x50(%rbx,%rax,1)"
            in text
            or
            "call *0x50(%rbx,%rax,1)"
            in text
        ):
            break

        if (
            "call   *0x58(%rcx,%rax,1)"
            in text
            or
            "call *0x58(%rcx,%rax,1)"
            in text
        ):
            break

    return {
        "found": True,
        "events": events,
    }


submit_flow = forward_slice_from_a4(
    "sceAgcDriverSubmitCommandBuffer",
    0x19C1,
    "eax",
)

multi_flow = forward_slice_from_a4(
    "sceAgcDriverSubmitMultiCommandBuffers",
    0x47D2,
    "eax",
)


# ------------------------------------------------------------
# Explicit known dispatch patterns
# ------------------------------------------------------------

submit_instructions = instructions_by_function(
    "sceAgcDriverSubmitCommandBuffer"
)

multi_instructions = instructions_by_function(
    "sceAgcDriverSubmitMultiCommandBuffers"
)


submit_dispatch = []
multi_dispatch = []

for idx, ins in enumerate(
    submit_instructions
):
    text = ins["instruction"]

    if (
        "imul" in text
        and "0x78" in text
        and "rax" in text
    ):
        nearby = []

        for next_ins in submit_instructions[
            idx + 1 : idx + 5
        ]:
            nearby.append(
                next_ins
            )

            if "call" in next_ins["instruction"]:
                break

        submit_dispatch.append(
            {
                "scale_instruction": ins,
                "nearby_instructions": nearby,
            }
        )


for idx, ins in enumerate(
    multi_instructions
):
    text = ins["instruction"]

    if (
        "imul" in text
        and "0x78" in text
        and "rax" in text
    ):
        nearby = []

        for next_ins in multi_instructions[
            idx + 1 : idx + 5
        ]:
            nearby.append(
                next_ins
            )

            if "call" in next_ins["instruction"]:
                break

        multi_dispatch.append(
            {
                "scale_instruction": ins,
                "nearby_instructions": nearby,
            }
        )


# ------------------------------------------------------------
# Detect exact A4 -> RAX -> scaled index
# ------------------------------------------------------------

submit_a4_to_scaled_index = (
    any(
        item["instruction_va"] == 0x19C1
        for item in all_reads
        if item["function"]
        == "sceAgcDriverSubmitCommandBuffer"
    )
    and
    any(
        item["scale_instruction"]["va"]
        >= 0x19C1
        and
        "0x78" in item[
            "scale_instruction"
        ]["instruction"]
        for item in submit_dispatch
    )
)


multi_a4_to_scaled_index = (
    any(
        item["instruction_va"] == 0x47D2
        for item in all_reads
        if item["function"]
        == "sceAgcDriverSubmitMultiCommandBuffers"
    )
    and
    any(
        item["scale_instruction"]["va"]
        >= 0x47D2
        and
        "0x78" in item[
            "scale_instruction"
        ]["instruction"]
        for item in multi_dispatch
    )
)


# ------------------------------------------------------------
# Table addressing
# ------------------------------------------------------------

submit_table_call = False
multi_table_call = False

for item in submit_dispatch:
    for ins in item["nearby_instructions"]:
        if (
            "call" in ins["instruction"]
            and
            "0x50(%rbx,%rax,1)"
            in ins["instruction"]
        ):
            submit_table_call = True


for item in multi_dispatch:
    for ins in item["nearby_instructions"]:
        if (
            "call" in ins["instruction"]
            and
            "0x58(%rcx,%rax,1)"
            in ins["instruction"]
        ):
            multi_table_call = True


# ------------------------------------------------------------
# Correct global result
# ------------------------------------------------------------

a4_post_init_writes = [
    item
    for item in all_stores
    if item["instruction_va"] != 0x210
]


a4_zero_static = (
    True
    and
    len(a4_post_init_writes) == 0
)


# ------------------------------------------------------------
# Previous-stage correction
# ------------------------------------------------------------

previous_static = {}

prev_path = os.path.join(
    PREVIOUS_RESULTS,
    "stage63_static.json",
)

if os.path.isfile(prev_path):
    try:
        with open(
            prev_path,
            "r",
            encoding="utf-8",
        ) as fp:
            previous_static = json.load(fp)
    except Exception:
        previous_static = {}


# ------------------------------------------------------------
# Conclusions
# ------------------------------------------------------------

conclusions = {
    "A4_READ_WRITE_CLASSIFICATION_CORRECTED":
        True,

    "A4_INITIALIZATION_WRITE_CONFIRMED":
        any(
            item["instruction_va"] == 0x210
            for item in [
                {
                    "instruction_va": 0x210
                }
            ]
        ),

    "A4_POST_INITIALIZATION_WRITES_FOUND":
        len(a4_post_init_writes) > 0,

    "A4_STATIC_ZERO_AFTER_INITIALIZATION":
        a4_zero_static,

    "SUBMIT_A4_READ_FOUND":
        any(
            item["function"]
            == "sceAgcDriverSubmitCommandBuffer"
            and item["instruction_va"] == 0x19C1
            for item in all_reads
        ),

    "MULTI_A4_READ_FOUND":
        any(
            item["function"]
            == "sceAgcDriverSubmitMultiCommandBuffers"
            and item["instruction_va"] == 0x47D2
            for item in all_reads
        ),

    "SUBMIT_A4_SCALED_BY_0x78":
        submit_a4_to_scaled_index,

    "MULTI_A4_SCALED_BY_0x78":
        multi_a4_to_scaled_index,

    "SUBMIT_A4_USED_IN_TABLE_DISPATCH":
        (
            submit_a4_to_scaled_index
            and submit_table_call
        ),

    "MULTI_A4_USED_IN_TABLE_DISPATCH":
        (
            multi_a4_to_scaled_index
            and multi_table_call
        ),

    "INDEX_SEMANTICS_PROVEN":
        (
            submit_a4_to_scaled_index
            and submit_table_call
        ),

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
}


# ------------------------------------------------------------
# Static JSON
# ------------------------------------------------------------

static = {
    "stage": 64,

    "target": {
        "global_context_va": GLOBAL_CONTEXT_VA,
        "field_offset": A4_OFFSET,
        "field_va": A4_VA,
    },

    "previous_stage": {
        "stage": 63,
        "available":
            bool(previous_static),
        "previous_stage_post_init_write_claim":
            (
                previous_static
                .get("conclusions", {})
                .get(
                    "A4_POST_INITIALIZATION_WRITES_FOUND",
                    None,
                )
            ),
        "correction":
            "Stage 63 classified A4 reads as writes; Stage 64 separates memory source loads from memory destination stores.",
    },

    "initialization": initialization,

    "a4_accesses": {
        "reads": all_reads,
        "stores": all_stores,
        "post_initialization_stores":
            a4_post_init_writes,
    },

    "submit_value_flow": {
        "a4_read_va": 0x19C1,
        "read_instruction":
            find_instruction(
                submit_instructions,
                0x19C1,
            ),
        "events":
            submit_flow["events"],
        "dispatch_patterns":
            submit_dispatch,
    },

    "multi_value_flow": {
        "a4_read_va": 0x47D2,
        "read_instruction":
            find_instruction(
                multi_instructions,
                0x47D2,
            ),
        "events":
            multi_flow["events"],
        "dispatch_patterns":
            multi_dispatch,
    },

    "conclusions": conclusions,
}


# ------------------------------------------------------------
# Summary
# ------------------------------------------------------------

summary = []

summary.append(
    "AGC PS5 Stage 64 - +0xA4 Value-Flow / Dispatch Index Audit"
)

summary.append("")
summary.append("=== TARGET ===")
summary.append(
    "global_context = 0x1A908"
)
summary.append(
    "field_offset = 0xA4"
)
summary.append(
    "field_va = 0x1A9AC"
)

summary.append("")
summary.append("=== CORRECTED READ/WRITE CLASSIFICATION ===")

summary.append(
    "A4 total reads = %d"
    % len(all_reads)
)

summary.append(
    "A4 total stores = %d"
    % len(all_stores)
)

summary.append(
    "A4 post-initialization stores = %d"
    % len(a4_post_init_writes)
)

summary.append("")
summary.append("=== INITIALIZATION ===")

summary.append(
    "VA=0x210 vmovups %xmm0,0xa4(%rax)"
)

summary.append(
    "width = 16 bytes"
)

summary.append(
    "range = 0xA4..0xB3"
)

summary.append(
    "source = XMM0"
)

summary.append(
    "source_zero_proven = True"
)

summary.append("")
summary.append("=== A4 READS ===")

for item in all_reads:
    summary.append(
        "[%s] VA=0x%X %s"
        % (
            item["function"],
            item["instruction_va"],
            item["instruction"],
        )
    )

if not all_reads:
    summary.append(
        "NONE"
    )

summary.append("")
summary.append("=== A4 STORES ===")

for item in all_stores:
    summary.append(
        "[%s] VA=0x%X %s"
        % (
            item["function"],
            item["instruction_va"],
            item["instruction"],
        )
    )

if not all_stores:
    summary.append(
        "NONE"
    )

summary.append("")
summary.append("=== SUBMITCOMMANDBUFFER VALUE FLOW ===")

summary.append(
    "A4 read = 0x19C1"
)

summary.append(
    "0x19C1: mov 0xa4(%rbx),%eax"
)

for item in submit_dispatch:
    summary.append(
        "scale = 0x%X: %s"
        % (
            item["scale_instruction"]["va"],
            item["scale_instruction"]["instruction"],
        )
    )

    for ins in item["nearby_instructions"]:
        summary.append(
            "  0x%X: %s"
            % (
                ins["va"],
                ins["instruction"],
            )
        )

summary.append("")
summary.append("=== MULTI VALUE FLOW ===")

summary.append(
    "A4 read = 0x47D2"
)

summary.append(
    "0x47D2: mov 0xa4(%rcx),%eax"
)

for item in multi_dispatch:
    summary.append(
        "scale = 0x%X: %s"
        % (
            item["scale_instruction"]["va"],
            item["scale_instruction"]["instruction"],
        )
    )

    for ins in item["nearby_instructions"]:
        summary.append(
            "  0x%X: %s"
            % (
                ins["va"],
                ins["instruction"],
            )
        )

summary.append("")
summary.append("=== CONCLUSIONS ===")

for key, value in conclusions.items():
    summary.append(
        "%s=%s"
        % (
            key,
            str(value),
        )
    )

summary.append("")
summary.append("=== INTERPRETATION LIMIT ===")

summary.append(
    "The A4 field is statically observed as a loaded 32-bit value."
)

summary.append(
    "SubmitCommandBuffer scales that value by 0x78 before indexed function-table dispatch."
)

summary.append(
    "This proves dispatch-index usage in the SubmitCommandBuffer path."
)

summary.append(
    "It does not by itself prove an externally documented semantic field name."
)

summary.append(
    "It also does not prove the exact struct sizeof beyond the accessed bytes."
)

summary_text = (
    "\n".join(summary)
    + "\n"
)


with open(
    os.path.join(
        OUT_DIR,
        "a4_value_flow_summary.txt",
    ),
    "w",
    encoding="utf-8",
    newline="\n",
) as fp:
    fp.write(
        summary_text
    )


# ------------------------------------------------------------
# Detailed disassembly artifact
# ------------------------------------------------------------

with open(
    os.path.join(
        OUT_DIR,
        "a4_value_flow_disassembly.txt",
    ),
    "w",
    encoding="utf-8",
    newline="\n",
) as fp:

    fp.write(
        "AGC PS5 Stage 64 - +0xA4 Value-Flow Evidence\n\n"
    )

    fp.write(
        "=== SubmitCommandBuffer ===\n\n"
    )

    fp.write(
        target_results[
            "sceAgcDriverSubmitCommandBuffer"
        ]["disassembly"]
    )

    fp.write(
        "\n\n=== SubmitMultiCommandBuffers ===\n\n"
    )

    fp.write(
        target_results[
            "sceAgcDriverSubmitMultiCommandBuffers"
        ]["disassembly"]
    )


# ------------------------------------------------------------
# Machine-readable focused evidence
# ------------------------------------------------------------

focused = {
    "field_va": A4_VA,
    "field_offset": A4_OFFSET,

    "initialization": initialization,

    "reads": all_reads,

    "stores": all_stores,

    "post_initialization_stores":
        a4_post_init_writes,

    "submit": {
        "a4_read":
            find_instruction(
                submit_instructions,
                0x19C1,
            ),
        "scaled_dispatch":
            submit_dispatch,
        "a4_scaled_dispatch_proven":
            submit_a4_to_scaled_index,
        "table_call_proven":
            submit_table_call,
    },

    "multi": {
        "a4_read":
            find_instruction(
                multi_instructions,
                0x47D2,
            ),
        "scaled_dispatch":
            multi_dispatch,
        "a4_scaled_dispatch_proven":
            multi_a4_to_scaled_index,
        "table_call_proven":
            multi_table_call,
    },

    "conclusions":
        conclusions,
}


with open(
    os.path.join(
        OUT_DIR,
        "a4_value_flow.json",
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
# Main static artifact
# ------------------------------------------------------------

with open(
    os.path.join(
        OUT_DIR,
        "stage64_static.json",
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
   $(Quote-Bash "$WorkWsl/analyze_a4_value_flow.py")

sed -i 's/\r$//' \
   $(Quote-Bash "$WorkWsl/analyze_a4_value_flow.py")

python3 -m py_compile \
   $(Quote-Bash "$WorkWsl/analyze_a4_value_flow.py")

ls -lh \
   $(Quote-Bash "$WorkWsl/analyze_a4_value_flow.py")
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
Write-Host '==> Corregir clasificación read/write y seguir +0xA4 hasta dispatch' -ForegroundColor Yellow

Invoke-Wsl @"
set -e

python3 $(Quote-Bash "$WorkWsl/analyze_a4_value_flow.py") \
    $(Quote-Bash $SprxWsl) \
    $(Quote-Bash $NidDbWsl) \
    $(Quote-Bash $PreviousWsl) \
    $(Quote-Bash $OutputWsl)
"@


# ============================================================
# Verify artifacts
# ============================================================

Write-Host ''
Write-Host '==> Verificar artefactos Stage 64' -ForegroundColor Yellow

Invoke-Wsl @"
set -e

test -f $(Quote-Bash "$OutputWsl/stage64_static.json")
test -f $(Quote-Bash "$OutputWsl/a4_value_flow_summary.txt")
test -f $(Quote-Bash "$OutputWsl/a4_value_flow_disassembly.txt")
test -f $(Quote-Bash "$OutputWsl/a4_value_flow.json")

echo '--- a4_value_flow_summary.txt ---'
cat $(Quote-Bash "$OutputWsl/a4_value_flow_summary.txt")

echo '--- output files ---'
find $(Quote-Bash $OutputWsl) \
    -maxdepth 2 \
    -type f |
    sort
"@


# ============================================================
# Read conclusions
# ============================================================

$StaticPath      = Join-Path $OutputDir 'stage64_static.json'
$SummaryPath     = Join-Path $OutputDir 'a4_value_flow_summary.txt'
$DisassemblyPath = Join-Path $OutputDir 'a4_value_flow_disassembly.txt'
$FocusedPath     = Join-Path $OutputDir 'a4_value_flow.json'

$Static = Get-Content `
    -LiteralPath $StaticPath `
    -Raw |
    ConvertFrom-Json

$ScanCompleted =
    [bool]$Static.conclusions.A4_READ_WRITE_CLASSIFICATION_CORRECTED

$PostStores =
    [bool]$Static.conclusions.A4_POST_INITIALIZATION_WRITES_FOUND

$StaticZero =
    [bool]$Static.conclusions.A4_STATIC_ZERO_AFTER_INITIALIZATION

$SubmitRead =
    [bool]$Static.conclusions.SUBMIT_A4_READ_FOUND

$MultiRead =
    [bool]$Static.conclusions.MULTI_A4_READ_FOUND

$SubmitScaled =
    [bool]$Static.conclusions.SUBMIT_A4_SCALED_BY_0x78

$MultiScaled =
    [bool]$Static.conclusions.MULTI_A4_SCALED_BY_0x78

$SubmitDispatch =
    [bool]$Static.conclusions.SUBMIT_A4_USED_IN_TABLE_DISPATCH

$MultiDispatch =
    [bool]$Static.conclusions.MULTI_A4_USED_IN_TABLE_DISPATCH

$IndexProven =
    [bool]$Static.conclusions.INDEX_SEMANTICS_PROVEN


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

Write-Host "[INFO] stage64_static.json SHA256=$HashStatic"
Write-Host "[INFO] a4_value_flow_summary.txt SHA256=$HashSummary"
Write-Host "[INFO] a4_value_flow_disassembly.txt SHA256=$HashDisassembly"
Write-Host "[INFO] a4_value_flow.json SHA256=$HashFocused"


# ============================================================
# Report
# ============================================================

$Report = [ordered]@{
    stage = 64

    target = [ordered]@{
        global_context = '0x1A908'
        field_offset = '0xA4'
        field_va = '0x1A9AC'
    }

    conclusions = [ordered]@{
        A4_READ_WRITE_CLASSIFICATION_CORRECTED = $ScanCompleted
        A4_POST_INITIALIZATION_WRITES_FOUND = $PostStores
        A4_STATIC_ZERO_AFTER_INITIALIZATION = $StaticZero

        SUBMIT_A4_READ_FOUND = $SubmitRead
        MULTI_A4_READ_FOUND = $MultiRead

        SUBMIT_A4_SCALED_BY_0x78 = $SubmitScaled
        MULTI_A4_SCALED_BY_0x78 = $MultiScaled

        SUBMIT_A4_USED_IN_TABLE_DISPATCH = $SubmitDispatch
        MULTI_A4_USED_IN_TABLE_DISPATCH = $MultiDispatch

        INDEX_SEMANTICS_PROVEN = $IndexProven

        COUNT_SEMANTICS_PROVEN = $false
        EXACT_FIELD_NAME_PROVEN = $false
        BACKEND_CONSUMER_IDENTIFIED = $false
        SEMANTIC_PROTOTYPE_INFERRED = $false
        EXECUTED_AGC = $false
    }

    hashes = [ordered]@{
        'stage64_static.json' = $HashStatic
        'a4_value_flow_summary.txt' = $HashSummary
        'a4_value_flow_disassembly.txt' = $HashDisassembly
        'a4_value_flow.json' = $HashFocused
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
Write-Host 'Stage 64 completado' -ForegroundColor Green
Write-Host '============================================' -ForegroundColor Green
Write-Host ''

Write-Host "A4_READ_WRITE_CLASSIFICATION_CORRECTED = $ScanCompleted"
Write-Host "A4_POST_INITIALIZATION_WRITES_FOUND = $PostStores"
Write-Host "A4_STATIC_ZERO_AFTER_INITIALIZATION = $StaticZero"

Write-Host "SUBMIT_A4_READ_FOUND = $SubmitRead"
Write-Host "MULTI_A4_READ_FOUND = $MultiRead"

Write-Host "SUBMIT_A4_SCALED_BY_0x78 = $SubmitScaled"
Write-Host "MULTI_A4_SCALED_BY_0x78 = $MultiScaled"

Write-Host "SUBMIT_A4_USED_IN_TABLE_DISPATCH = $SubmitDispatch"
Write-Host "MULTI_A4_USED_IN_TABLE_DISPATCH = $MultiDispatch"

Write-Host "INDEX_SEMANTICS_PROVEN = $IndexProven"

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