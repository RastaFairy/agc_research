#requires -Version 7.0

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$StageDir        = $PSScriptRoot
$Sprx            = 'D:\agc_work\sce_stubs\libSceAgcDriver.sprx'
$NidDb           = 'D:\sdk-master\sce_stubs\aerolib.csv'
$PreviousResults = 'D:\agc_work\stage66_results'
$OutputDir       = 'D:\agc_work\stage67_results'

$Sdk = '/opt/ps5-payload-sdk'

$SprxWsl     = '/mnt/d/agc_work/sce_stubs/libSceAgcDriver.sprx'
$NidDbWsl    = '/mnt/d/sdk-master/sce_stubs/aerolib.csv'
$PreviousWsl = '/mnt/d/agc_work/stage66_results'
$OutputWsl   = '/mnt/d/agc_work/stage67_results'
$WorkWsl     = '/tmp/agc_stage67'

$AnalyzerWindows = Join-Path $OutputDir 'analyze_dispatch_store_provenance.py'
$ReportPath      = Join-Path $OutputDir 'STAGE67_REPORT.json'

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

function Bash-Quote {
    param(
        [Parameter(Mandatory)]
        [string]$Text
    )

    "'" + ($Text -replace "'", "'\''") + "'"
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

    $Encoding = [System.Text.UTF8Encoding]::new($false)

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

    (
        Get-FileHash `
            -Algorithm SHA256 `
            -LiteralPath $Path
    ).Hash.ToLowerInvariant()
}

function Get-JsonProperty {
    param(
        [Parameter(Mandatory)]
        [object]$Object,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter()]
        [object]$Default = $false
    )

    if ($null -eq $Object) {
        return $Default
    }

    $Properties = $Object.PSObject.Properties

    $Property = $Properties |
        Where-Object {
            $_.Name -eq $Name
        } |
        Select-Object -First 1

    if ($null -eq $Property) {
        return $Default
    }

    return $Property.Value
}

function Get-BooleanJsonProperty {
    param(
        [Parameter(Mandatory)]
        [object]$Object,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter()]
        [bool]$Default = $false
    )

    $Value = Get-JsonProperty `
        -Object $Object `
        -Name $Name `
        -Default $Default

    if ($Value -is [bool]) {
        return [bool]$Value
    }

    if ($null -eq $Value) {
        return $Default
    }

    $Text = [string]$Value

    if ($Text -eq 'True' -or $Text -eq 'true') {
        return $true
    }

    if ($Text -eq 'False' -or $Text -eq 'false') {
        return $false
    }

    return $Default
}

Write-Host ''
Write-Host '============================================' -ForegroundColor Cyan
Write-Host 'AGC PS5 Stage 67 - Dispatch Store Base Provenance Audit' -ForegroundColor Cyan
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
    throw "No existe Stage 66: $PreviousResults"
}

$PythonAnalyzer = @'
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
SUBMIT_TABLE_OFFSET = 0x50
MULTI_TABLE_OFFSET = 0x58

SUBMIT_VA = 0x18B0
SUBMIT_SIZE = 380

MULTI_VA = 0x4650
MULTI_SIZE = 579


with open(SPRX, "rb") as fp:
    ELF = ELFFile(fp)

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

    with open(SPRX, "rb") as fp:
        fp.seek(off)
        return fp.read(size)


def executable_ranges():
    result = []

    for seg in SEGMENTS:
        if seg["flags"] & 1:
            result.append(
                {
                    "start": seg["vaddr"],
                    "end": seg["vaddr"] + seg["filesz"],
                }
            )

    return result


def disassemble(raw, start_va):
    if not raw:
        return ""

    temp = None

    try:
        with tempfile.NamedTemporaryFile(
            prefix="agc67_",
            suffix=".bin",
            dir=OUT_DIR,
            delete=False,
        ) as fp:
            fp.write(raw)
            temp = fp.name

        commands = [
            [
                "objdump",
                "-D",
                "-b",
                "binary",
                "-m",
                "i386:x86-64",
                "--adjust-vma=0x%x" % start_va,
                temp,
            ],
            [
                "llvm-objdump",
                "-D",
                "--triple=x86_64",
                "--adjust-vma=0x%x" % start_va,
                temp,
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
        if temp:
            try:
                os.unlink(temp)
            except OSError:
                pass


def parse_instructions(text):
    result = []

    for line in text.splitlines():
        s = line.strip()

        m = re.match(
            r"^([0-9A-Fa-f]+):\s+(.*)$",
            s,
        )

        if not m:
            continue

        va = int(m.group(1), 16)
        rest = m.group(2)

        tokens = rest.split()
        i = 0

        while i < len(tokens):
            if re.fullmatch(
                r"[0-9A-Fa-f]{2}",
                tokens[i],
            ):
                i += 1
            else:
                break

        ins = " ".join(tokens[i:]).strip()

        if ins:
            result.append(
                {
                    "va": va,
                    "instruction": ins,
                }
            )

    return result


ALIASES = {
    "rax": "rax",
    "eax": "rax",
    "ax": "rax",
    "al": "rax",

    "rbx": "rbx",
    "ebx": "rbx",

    "rcx": "rcx",
    "ecx": "rcx",

    "rdx": "rdx",
    "edx": "rdx",

    "rsi": "rsi",
    "esi": "rsi",

    "rdi": "rdi",
    "edi": "rdi",

    "rbp": "rbp",
    "ebp": "rbp",

    "rsp": "rsp",
    "esp": "rsp",

    "r8": "r8",
    "r8d": "r8",

    "r9": "r9",
    "r9d": "r9",

    "r10": "r10",
    "r10d": "r10",

    "r11": "r11",
    "r11d": "r11",

    "r12": "r12",
    "r12d": "r12",

    "r13": "r13",
    "r13d": "r13",

    "r14": "r14",
    "r14d": "r14",

    "r15": "r15",
    "r15d": "r15",
}


def normreg(name):
    name = name.strip().lstrip("%")
    return ALIASES.get(name, name)


MEM_RE = re.compile(
    r"(?P<disp>-?0x[0-9A-Fa-f]+|-?\d+)?"
    r"\(%(?P<base>[A-Za-z0-9]+)"
    r"(?:,%(?P<index>[A-Za-z0-9]+)"
    r"(?:,(?P<scale>[1248]))?)?"
    r"\)"
)


def parse_mem_operands(instruction):
    out = []

    for m in MEM_RE.finditer(instruction):
        disp_text = m.group("disp")

        if disp_text is None:
            disp = 0
        else:
            if disp_text.startswith("-0x"):
                disp = -int(
                    disp_text[1:],
                    16,
                )
            elif disp_text.startswith("0x"):
                disp = int(
                    disp_text,
                    16,
                )
            else:
                disp = int(
                    disp_text,
                    10,
                )

        out.append(
            {
                "text": m.group(0),
                "offset": disp,
                "base": normreg(
                    m.group("base")
                ),
                "index": (
                    normreg(
                        m.group("index")
                    )
                    if m.group("index")
                    else None
                ),
                "scale": (
                    int(m.group("scale"))
                    if m.group("scale")
                    else 1
                ),
            }
        )

    return out


def memory_is_destination(
    instruction,
    mem,
):
    text = instruction.strip()

    if text.startswith(
        (
            "lea ",
            "call ",
            "jmp ",
            "push ",
        )
    ):
        return False

    if re.search(
        r",%[A-Za-z0-9]+$",
        text,
    ):
        return False

    return mem["text"] in text


def global_context_lea(instruction):
    if "# 0x1a908" not in instruction.lower():
        return None

    m = re.search(
        r"lea\s+.*,%([A-Za-z0-9]+)",
        instruction,
    )

    if not m:
        return None

    return normreg(
        m.group(1)
    )


def direct_mov_register(instruction):
    m = re.match(
        r"mov[a-z]*\s+%([A-Za-z0-9]+),%([A-Za-z0-9]+)$",
        instruction.strip(),
    )

    if not m:
        return None

    return (
        normreg(m.group(1)),
        normreg(m.group(2)),
    )


def direct_lea_register_copy(instruction):
    m = re.match(
        r"lea\s+0x0\(%([A-Za-z0-9]+)\),%([A-Za-z0-9]+)$",
        instruction.strip(),
    )

    if not m:
        return None

    return (
        normreg(m.group(1)),
        normreg(m.group(2)),
    )


def instruction_writes_register(
    instruction
):
    text = instruction.strip()

    patterns = [
        r"mov[a-z]*\s+.*,%([A-Za-z0-9]+)$",
        r"lea\s+.*,%([A-Za-z0-9]+)$",
        r"xor[a-z]*\s+.*,%([A-Za-z0-9]+)$",
        r"add[a-z]*\s+.*,%([A-Za-z0-9]+)$",
        r"sub[a-z]*\s+.*,%([A-Za-z0-9]+)$",
        r"and[a-z]*\s+.*,%([A-Za-z0-9]+)$",
        r"or[a-z]*\s+.*,%([A-Za-z0-9]+)$",
        r"imul[a-z]*\s+.*,%([A-Za-z0-9]+)$",
        r"inc[a-z]*\s+%([A-Za-z0-9]+)$",
        r"dec[a-z]*\s+%([A-Za-z0-9]+)$",
    ]

    for pattern in patterns:
        m = re.search(
            pattern,
            text,
        )

        if m:
            return normreg(
                m.group(1)
            )

    return None


def scan_segment(
    start,
    end,
):
    size = end - start

    raw = read_va(
        start,
        size,
    )

    text = disassemble(
        raw,
        start,
    )

    instructions = parse_instructions(
        text
    )

    candidates = []

    for ins in instructions:
        text_i = ins["instruction"]

        for mem in parse_mem_operands(
            text_i
        ):
            if mem["offset"] not in (
                SUBMIT_TABLE_OFFSET,
                MULTI_TABLE_OFFSET,
            ):
                continue

            if not memory_is_destination(
                text_i,
                mem,
            ):
                continue

            candidates.append(
                {
                    "instruction_va":
                        ins["va"],
                    "instruction":
                        text_i,
                    "base_register":
                        mem["base"],
                    "index_register":
                        mem["index"],
                    "scale":
                        mem["scale"],
                    "offset":
                        mem["offset"],
                    "classification":
                        "STORE_CANDIDATE",
                }
            )

    return {
        "disassembly": text,
        "instructions": instructions,
        "candidates": candidates,
    }


all_scans = []

for rng in executable_ranges():
    all_scans.append(
        scan_segment(
            rng["start"],
            rng["end"],
        )
    )


candidate_map = {}

for scan in all_scans:
    for candidate in scan[
        "candidates"
    ]:
        candidate_map[
            candidate["instruction_va"]
        ] = candidate


store_candidates = [
    candidate_map[k]
    for k in sorted(
        candidate_map
    )
]


previous_stage_exists = os.path.exists(
    os.path.join(
        PREVIOUS_RESULTS,
        "stage66_static.json",
    )
)

KNOWN_FUNCTIONS = [
    {
        "name":
            "sceAgcDriverSubmitCommandBuffer",
        "va":
            0x18B0,
        "size":
            380,
    },
    {
        "name":
            "sceAgcDriverSubmitDcb",
        "va":
            0x28B0,
        "size":
            15,
    },
    {
        "name":
            "sceAgcDriverAgrSubmitDcb",
        "va":
            0x28C0,
        "size":
            72,
    },
    {
        "name":
            "sceAgcDriverSubmitAcb",
        "va":
            0x2910,
        "size":
            67,
    },
    {
        "name":
            "sceAgcDriverSubmitMultiCommandBuffers",
        "va":
            0x4650,
        "size":
            579,
    },
    {
        "name":
            "sceAgcDriverSubmitMultiDcbs",
        "va":
            0x48A0,
        "size":
            20,
    },
    {
        "name":
            "sceAgcDriverAgrSubmitMultiDcbs",
        "va":
            0x48C0,
        "size":
            77,
    },
    {
        "name":
            "sceAgcDriverSubmitMultiAcbs",
        "va":
            0x4910,
        "size":
            67,
    },
]


def owner_for_va(va):
    for fn in KNOWN_FUNCTIONS:
        if fn["va"] <= va < (
            fn["va"] + fn["size"]
        ):
            return dict(fn)

    return None


def local_analysis_window(
    candidate_va,
):
    owner = owner_for_va(
        candidate_va
    )

    if owner:
        return {
            "start":
                owner["va"],
            "end":
                owner["va"] +
                owner["size"],
            "owner":
                owner,
            "source":
                "KNOWN_FUNCTION",
        }

    start = max(
        0,
        candidate_va - 0x400,
    )

    end = candidate_va + 0x400

    for r in executable_ranges():
        if r["start"] <= candidate_va < r["end"]:
            start = max(
                start,
                r["start"],
            )
            end = min(
                end,
                r["end"],
            )
            break

    return {
        "start":
            start,
        "end":
            end,
        "owner":
            None,
        "source":
            "LOCAL_WINDOW",
    }


def trace_candidate(
    candidate
):
    va = candidate[
        "instruction_va"
    ]

    window = local_analysis_window(
        va
    )

    raw = read_va(
        window["start"],
        window["end"] -
        window["start"],
    )

    text = disassemble(
        raw,
        window["start"],
    )

    instructions = parse_instructions(
        text
    )

    candidate_idx = None

    for i, ins in enumerate(
        instructions
    ):
        if ins["va"] == va:
            candidate_idx = i
            break

    if candidate_idx is None:
        return {
            "candidate_va": va,
            "instruction":
                candidate[
                    "instruction"
                ],
            "base_register":
                candidate[
                    "base_register"
                ],
            "offset":
                candidate[
                    "offset"
                ],
            "owner":
                window[
                    "owner"
                ],
            "window_source":
                window[
                    "source"
                ],
            "proven_global_context_base":
                False,
            "global_source_va":
                None,
            "status":
                "CANDIDATE_NOT_REACHED",
            "evidence": [],
            "function_disassembly":
                text,
        }

    tracked = {}
    evidence = []

    for ins in instructions[
        :candidate_idx + 1
    ]:
        ins_va = ins["va"]
        instruction = ins[
            "instruction"
        ]

        global_reg = global_context_lea(
            instruction
        )

        if global_reg:
            tracked[
                global_reg
            ] = {
                "source_va":
                    ins_va,
                "source_instruction":
                    instruction,
            }

            evidence.append(
                {
                    "va":
                        ins_va,
                    "instruction":
                        instruction,
                    "effect":
                        "%s := global_context"
                        % global_reg,
                }
            )

            continue

        mov = direct_mov_register(
            instruction
        )

        if mov:
            src, dst = mov

            if src in tracked:
                tracked[
                    dst
                ] = dict(
                    tracked[src]
                )

                evidence.append(
                    {
                        "va":
                            ins_va,
                        "instruction":
                            instruction,
                        "effect":
                            "%s := %s"
                            % (
                                dst,
                                src,
                            ),
                    }
                )
            else:
                tracked.pop(
                    dst,
                    None,
                )

            continue

        lea = direct_lea_register_copy(
            instruction
        )

        if lea:
            src, dst = lea

            if src in tracked:
                tracked[
                    dst
                ] = dict(
                    tracked[src]
                )

                evidence.append(
                    {
                        "va":
                            ins_va,
                        "instruction":
                            instruction,
                        "effect":
                            "%s := %s via LEA"
                            % (
                                dst,
                                src,
                            ),
                    }
                )
            else:
                tracked.pop(
                    dst,
                    None,
                )

            continue

        written = instruction_writes_register(
            instruction
        )

        if written:
            tracked.pop(
                written,
                None
            )

    base = candidate[
        "base_register"
    ]

    provenance = tracked.get(
        base
    )

    proven = provenance is not None

    return {
        "candidate_va":
            va,
        "instruction":
            candidate[
                "instruction"
            ],
        "base_register":
            base,
        "index_register":
            candidate[
                "index_register"
            ],
        "scale":
            candidate[
                "scale"
            ],
        "offset":
            candidate[
                "offset"
            ],
        "owner":
            window[
                "owner"
            ],
        "window_source":
            window[
                "source"
            ],
        "window_start":
            window[
                "start"
            ],
        "window_end":
            window[
                "end"
            ],
        "proven_global_context_base":
            proven,
        "global_source_va":
            (
                provenance[
                    "source_va"
                ]
                if proven
                else None
            ),
        "status":
            (
                "GLOBAL_CONTEXT_BASE_PROVEN"
                if proven
                else
                "BASE_NOT_PROVEN"
            ),
        "evidence":
            evidence,
        "function_disassembly":
            text,
    }


candidate_results = [
    trace_candidate(c)
    for c in store_candidates
]

proven = [
    c
    for c in candidate_results
    if c[
        "proven_global_context_base"
    ]
]

unproven = [
    c
    for c in candidate_results
    if not c[
        "proven_global_context_base"
    ]
]


def analyze_known_dispatch(
    start_va,
    size,
    table_offset,
):
    raw = read_va(
        start_va,
        size,
    )

    text = disassemble(
        raw,
        start_va,
    )

    instructions = parse_instructions(
        text
    )

    tracked = {}
    events = []

    for ins in instructions:
        va = ins["va"]
        instruction = ins[
            "instruction"
        ]

        global_reg = global_context_lea(
            instruction
        )

        if global_reg:
            tracked[
                global_reg
            ] = {
                "source_va":
                    va,
            }
            continue

        mov = direct_mov_register(
            instruction
        )

        if mov:
            src, dst = mov

            if src in tracked:
                tracked[
                    dst
                ] = dict(
                    tracked[src]
                )
            else:
                tracked.pop(
                    dst,
                    None
                )

            continue

        lea = direct_lea_register_copy(
            instruction
        )

        if lea:
            src, dst = lea

            if src in tracked:
                tracked[
                    dst
                ] = dict(
                    tracked[src]
                )
            else:
                tracked.pop(
                    dst,
                    None
                )

            continue

        if "call *" not in instruction:
            continue

        for mem in parse_mem_operands(
            instruction
        ):
            if mem["offset"] != table_offset:
                continue

            base = mem[
                "base"
            ]

            if base not in tracked:
                continue

            events.append(
                {
                    "va":
                        va,
                    "instruction":
                        instruction,
                    "table_offset":
                        table_offset,
                    "base_register":
                        base,
                    "global_source_va":
                        tracked[
                            base
                        ][
                            "source_va"
                        ],
                    "base_proven":
                        True,
                }
            )

    return {
        "start_va":
            start_va,
        "size":
            size,
        "table_offset":
            table_offset,
        "events":
            events,
        "disassembly":
            text,
    }


submit_dispatch = analyze_known_dispatch(
    SUBMIT_VA,
    SUBMIT_SIZE,
    SUBMIT_TABLE_OFFSET,
)

multi_dispatch = analyze_known_dispatch(
    MULTI_VA,
    MULTI_SIZE,
    MULTI_TABLE_OFFSET,
)


submit_global_stores = [
    x
    for x in proven
    if x["offset"] ==
    SUBMIT_TABLE_OFFSET
]

multi_global_stores = [
    x
    for x in proven
    if x["offset"] ==
    MULTI_TABLE_OFFSET
]


conclusions = {
    "STORE_SCAN_COMPLETED":
        True,

    "STORE_CANDIDATES_FOUND":
        len(store_candidates) > 0,

    "FUNCTION_OWNER_RESOLUTION_COMPLETED":
        True,

    "GLOBAL_CONTEXT_BASE_PROVEN_FOR_ANY_STORE":
        len(proven) > 0,

    "GLOBAL_CONTEXT_SUBMIT_TABLE_STORE_PROVEN":
        len(submit_global_stores) > 0,

    "GLOBAL_CONTEXT_MULTI_TABLE_STORE_PROVEN":
        len(multi_global_stores) > 0,

    "DISPATCH_TABLE_RUNTIME_INITIALIZATION_PROVEN":
        (
            len(submit_global_stores) > 0
            or
            len(multi_global_stores) > 0
        ),

    "SUBMIT_DISPATCH_GLOBAL_BASE_PROVEN":
        len(
            submit_dispatch[
                "events"
            ]
        ) > 0,

    "MULTI_DISPATCH_GLOBAL_BASE_PROVEN":
        len(
            multi_dispatch[
                "events"
            ]
        ) > 0,

    "INDEX_SEMANTICS_PROVEN":
        True,

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


static = {
    "stage":
        67,

    "target": {
        "global_context_va":
            GLOBAL_CONTEXT_VA,
        "submit_table_offset":
            SUBMIT_TABLE_OFFSET,
        "multi_table_offset":
            MULTI_TABLE_OFFSET,
    },

    "executable_ranges":
        executable_ranges(),

    "stage66_previous_available":
        previous_stage_exists,

    "store_candidates":
        store_candidates,

    "candidate_results":
        candidate_results,

    "proven_global_context_stores":
        proven,

    "unproven_store_candidates":
        unproven,

    "submit_global_context_stores":
        submit_global_stores,

    "multi_global_context_stores":
        multi_global_stores,

    "submit_dispatch":
        submit_dispatch,

    "multi_dispatch":
        multi_dispatch,

    "conclusions":
        conclusions,
}


static_path = os.path.join(
    OUT_DIR,
    "stage67_static.json",
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


lines = []

lines.append(
    "AGC PS5 Stage 67 - Dispatch Store Base Provenance Audit"
)

lines.append("")
lines.append(
    "=== TARGET ==="
)
lines.append(
    "global_context = 0x1A908"
)
lines.append(
    "submit table offset = 0x50"
)
lines.append(
    "multi table offset = 0x58"
)

lines.append("")
lines.append(
    "=== GLOBAL EXECUTABLE STORE SCAN ==="
)

lines.append(
    "store_candidate_count = %d"
    % len(store_candidates)
)

for c in candidate_results:
    owner = c.get("owner")

    if owner:
        owner_text = (
            "%s@0x%X"
            % (
                owner["name"],
                owner["va"],
            )
        )
    else:
        owner_text = "LOCAL_UNKNOWN"

    source = c.get(
        "global_source_va"
    )

    source_text = (
        "0x%X"
        % source
        if source is not None
        else "UNKNOWN"
    )

    lines.append(
        (
            "VA=0x%X owner=%s "
            "base=%s offset=0x%X "
            "source=%s status=%s | %s"
        )
        % (
            c[
                "candidate_va"
            ],
            owner_text,
            c[
                "base_register"
            ],
            c[
                "offset"
            ],
            source_text,
            c[
                "status"
            ],
            c[
                "instruction"
            ],
        )
    )

lines.append("")
lines.append(
    "=== PROVEN GLOBAL-CONTEXT STORE CANDIDATES ==="
)

if proven:
    for c in proven:
        owner = c.get(
            "owner"
        )

        owner_text = (
            owner["name"]
            if owner
            else "LOCAL_UNKNOWN"
        )

        lines.append(
            (
                "VA=0x%X owner=%s "
                "global_source=0x%X "
                "base=%s offset=0x%X | %s"
            )
            % (
                c[
                    "candidate_va"
                ],
                owner_text,
                c[
                    "global_source_va"
                ],
                c[
                    "base_register"
                ],
                c[
                    "offset"
                ],
                c[
                    "instruction"
                ],
            )
        )
else:
    lines.append(
        "NONE"
    )

lines.append("")
lines.append(
    "=== KNOWN SUBMIT DISPATCH ==="
)

if submit_dispatch[
    "events"
]:
    for e in submit_dispatch[
        "events"
    ]:
        lines.append(
            (
                "VA=0x%X global_source=0x%X "
                "base=%s offset=0x%X | %s"
            )
            % (
                e["va"],
                e[
                    "global_source_va"
                ],
                e[
                    "base_register"
                ],
                e[
                    "table_offset"
                ],
                e[
                    "instruction"
                ],
            )
        )
else:
    lines.append(
        "NONE"
    )

lines.append("")
lines.append(
    "=== KNOWN MULTI DISPATCH ==="
)

if multi_dispatch[
    "events"
]:
    for e in multi_dispatch[
        "events"
    ]:
        lines.append(
            (
                "VA=0x%X global_source=0x%X "
                "base=%s offset=0x%X | %s"
            )
            % (
                e["va"],
                e[
                    "global_source_va"
                ],
                e[
                    "base_register"
                ],
                e[
                    "table_offset"
                ],
                e[
                    "instruction"
                ],
            )
        )
else:
    lines.append(
        "NONE"
    )

lines.append("")
lines.append(
    "=== IMPORTANT LIMIT ==="
)

lines.append(
    "Los candidatos de escritura se redescubren directamente desde los segmentos ejecutables del SPRX."
)

lines.append(
    "El análisis no depende de STT_FUNC, porque este SPRX no expone símbolos de función utilizables."
)

lines.append(
    "Cuando existe una función conocida de stages anteriores se usa su rango; en otros candidatos se usa una ventana local conservadora."
)

lines.append(
    "La proveniencia solo se considera demostrada cuando el registro base puede rastrearse hasta una LEA directa de 0x1A908."
)

lines.append(
    "La presencia de +0x50/+0x58 por sí sola no demuestra que la base sea global_context."
)

lines.append("")
lines.append(
    "=== CONCLUSIONS ==="
)

for key in [
    "STORE_SCAN_COMPLETED",
    "STORE_CANDIDATES_FOUND",
    "FUNCTION_OWNER_RESOLUTION_COMPLETED",
    "GLOBAL_CONTEXT_BASE_PROVEN_FOR_ANY_STORE",
    "GLOBAL_CONTEXT_SUBMIT_TABLE_STORE_PROVEN",
    "GLOBAL_CONTEXT_MULTI_TABLE_STORE_PROVEN",
    "DISPATCH_TABLE_RUNTIME_INITIALIZATION_PROVEN",
    "SUBMIT_DISPATCH_GLOBAL_BASE_PROVEN",
    "MULTI_DISPATCH_GLOBAL_BASE_PROVEN",
    "INDEX_SEMANTICS_PROVEN",
    "COUNT_SEMANTICS_PROVEN",
    "EXACT_FIELD_NAME_PROVEN",
    "BACKEND_CONSUMER_IDENTIFIED",
    "SEMANTIC_PROTOTYPE_INFERRED",
    "EXECUTED_AGC",
]:
    lines.append(
        "%s=%s"
        % (
            key,
            str(
                conclusions[
                    key
                ]
            ),
        )
    )

summary_path = os.path.join(
    OUT_DIR,
    "dispatch_store_provenance_summary.txt",
)

with open(
    summary_path,
    "w",
    encoding="utf-8",
    newline="\n",
) as fp:
    fp.write(
        "\n".join(lines)
        + "\n"
    )


disassembly_path = os.path.join(
    OUT_DIR,
    "dispatch_store_provenance_disassembly.txt",
)

with open(
    disassembly_path,
    "w",
    encoding="utf-8",
    newline="\n",
) as fp:

    for n, c in enumerate(
        candidate_results,
        1,
    ):

        fp.write(
            "============================================\n"
        )

        fp.write(
            "STORE CANDIDATE %d\n"
            % n
        )

        fp.write(
            "============================================\n"
        )

        fp.write(
            "VA=0x%X\n"
            % c[
                "candidate_va"
            ]
        )

        owner = c.get(
            "owner"
        )

        if owner:
            fp.write(
                "owner=%s VA=0x%X SIZE=%d\n"
                % (
                    owner["name"],
                    owner["va"],
                    owner["size"],
                )
            )
        else:
            fp.write(
                "owner=LOCAL_UNKNOWN\n"
            )

        fp.write(
            "base=%s offset=0x%X\n"
            % (
                c[
                    "base_register"
                ],
                c[
                    "offset"
                ],
            )
        )

        source = c.get(
            "global_source_va"
        )

        if source is not None:
            fp.write(
                "global_source=0x%X\n"
                % source
            )
        else:
            fp.write(
                "global_source=UNKNOWN\n"
            )

        fp.write(
            "status=%s\n\n"
            % c[
                "status"
            ]
        )

        fp.write(
            "--- provenance evidence ---\n"
        )

        for e in c.get(
            "evidence",
            [],
        ):
            fp.write(
                "0x%X: %s | %s\n"
                % (
                    e[
                        "va"
                    ],
                    e[
                        "instruction"
                    ],
                    e[
                        "effect"
                    ],
                )
            )

        fp.write(
            "\n--- disassembly ---\n"
        )

        fp.write(
            c.get(
                "function_disassembly",
                "",
            )
        )

        fp.write(
            "\n\n"
        )

    fp.write(
        "============================================\n"
    )
    fp.write(
        "KNOWN SUBMIT DISPATCH\n"
    )
    fp.write(
        "============================================\n"
    )
    fp.write(
        submit_dispatch[
            "disassembly"
        ]
    )

    fp.write(
        "\n\n============================================\n"
    )
    fp.write(
        "KNOWN MULTI DISPATCH\n"
    )
    fp.write(
        "============================================\n"
    )
    fp.write(
        multi_dispatch[
            "disassembly"
        ]
    )


focus = {
    "stage":
        67,

    "global_context_va":
        GLOBAL_CONTEXT_VA,

    "submit_table_offset":
        SUBMIT_TABLE_OFFSET,

    "multi_table_offset":
        MULTI_TABLE_OFFSET,

    "store_candidates":
        store_candidates,

    "proven_global_context_stores":
        proven,

    "submit_global_context_stores":
        submit_global_stores,

    "multi_global_context_stores":
        multi_global_stores,

    "submit_dispatch":
        submit_dispatch,

    "multi_dispatch":
        multi_dispatch,

    "conclusions":
        conclusions,
}

focus_path = os.path.join(
    OUT_DIR,
    "dispatch_store_provenance.json",
)

with open(
    focus_path,
    "w",
    encoding="utf-8",
) as fp:
    json.dump(
        focus,
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
    -Content $PythonAnalyzer

Write-Host ''
Write-Host '==> Preparar workspace Linux' -ForegroundColor Yellow

Invoke-Wsl @"
set -e

rm -rf $(Bash-Quote $WorkWsl)

mkdir -p $(Bash-Quote $WorkWsl)
mkdir -p $(Bash-Quote $OutputWsl)

cp $(Bash-Quote "$OutputWsl/analyze_dispatch_store_provenance.py") \
   $(Bash-Quote "$WorkWsl/analyze_dispatch_store_provenance.py")

sed -i 's/\r$//' \
   $(Bash-Quote "$WorkWsl/analyze_dispatch_store_provenance.py")

python3 -m py_compile \
   $(Bash-Quote "$WorkWsl/analyze_dispatch_store_provenance.py")

ls -lh \
   $(Bash-Quote "$WorkWsl/analyze_dispatch_store_provenance.py")
"@

Write-Host ''
Write-Host '==> Verificar Python + pyelftools + toolchain' -ForegroundColor Yellow

Invoke-Wsl @"
set -e

test -x $(Bash-Quote "$Sdk/bin/prospero-clang")
test -x $(Bash-Quote "$Sdk/bin/prospero-nm")
test -x $(Bash-Quote "$Sdk/bin/prospero-lld")

python3 -c "from elftools.elf.elffile import ELFFile; print('pyelftools=OK')"

command -v objdump
command -v llvm-objdump
"@

Write-Host ''
Write-Host '==> Redescubrir globalmente las escrituras +0x50/+0x58 y rastrear su base' -ForegroundColor Yellow

Invoke-Wsl @"
set -e

python3 $(Bash-Quote "$WorkWsl/analyze_dispatch_store_provenance.py") \
    $(Bash-Quote $SprxWsl) \
    $(Bash-Quote $NidDbWsl) \
    $(Bash-Quote $PreviousWsl) \
    $(Bash-Quote $OutputWsl)
"@

Write-Host ''
Write-Host '==> Verificar artefactos Stage 67' -ForegroundColor Yellow

Invoke-Wsl @"
set -e

test -f $(Bash-Quote "$OutputWsl/stage67_static.json")
test -f $(Bash-Quote "$OutputWsl/dispatch_store_provenance_summary.txt")
test -f $(Bash-Quote "$OutputWsl/dispatch_store_provenance_disassembly.txt")
test -f $(Bash-Quote "$OutputWsl/dispatch_store_provenance.json")

echo '--- dispatch_store_provenance_summary.txt ---'
cat $(Bash-Quote "$OutputWsl/dispatch_store_provenance_summary.txt")

echo '--- output files ---'
find $(Bash-Quote $OutputWsl) \
    -maxdepth 2 \
    -type f |
    sort
"@

$StaticPath = Join-Path `
    $OutputDir `
    'stage67_static.json'

$SummaryPath = Join-Path `
    $OutputDir `
    'dispatch_store_provenance_summary.txt'

$DisassemblyPath = Join-Path `
    $OutputDir `
    'dispatch_store_provenance_disassembly.txt'

$FocusPath = Join-Path `
    $OutputDir `
    'dispatch_store_provenance.json'

$StaticRaw = Get-Content `
    -LiteralPath $StaticPath `
    -Raw

$Static = $StaticRaw |
    ConvertFrom-Json

$Conclusions = Get-JsonProperty `
    -Object $Static `
    -Name 'conclusions' `
    -Default ([pscustomobject]@{})

$StoreScanCompleted =
    Get-BooleanJsonProperty `
        -Object $Conclusions `
        -Name 'STORE_SCAN_COMPLETED'

$StoreCandidatesFound =
    Get-BooleanJsonProperty `
        -Object $Conclusions `
        -Name 'STORE_CANDIDATES_FOUND'

$OwnerResolved =
    Get-BooleanJsonProperty `
        -Object $Conclusions `
        -Name 'FUNCTION_OWNER_RESOLUTION_COMPLETED'

$AnyProven =
    Get-BooleanJsonProperty `
        -Object $Conclusions `
        -Name 'GLOBAL_CONTEXT_BASE_PROVEN_FOR_ANY_STORE'

$SubmitProven =
    Get-BooleanJsonProperty `
        -Object $Conclusions `
        -Name 'GLOBAL_CONTEXT_SUBMIT_TABLE_STORE_PROVEN'

$MultiProven =
    Get-BooleanJsonProperty `
        -Object $Conclusions `
        -Name 'GLOBAL_CONTEXT_MULTI_TABLE_STORE_PROVEN'

$RuntimeProven =
    Get-BooleanJsonProperty `
        -Object $Conclusions `
        -Name 'DISPATCH_TABLE_RUNTIME_INITIALIZATION_PROVEN'

$SubmitDispatchProven =
    Get-BooleanJsonProperty `
        -Object $Conclusions `
        -Name 'SUBMIT_DISPATCH_GLOBAL_BASE_PROVEN'

$MultiDispatchProven =
    Get-BooleanJsonProperty `
        -Object $Conclusions `
        -Name 'MULTI_DISPATCH_GLOBAL_BASE_PROVEN'

$IndexProven =
    Get-BooleanJsonProperty `
        -Object $Conclusions `
        -Name 'INDEX_SEMANTICS_PROVEN'

$CountProven =
    Get-BooleanJsonProperty `
        -Object $Conclusions `
        -Name 'COUNT_SEMANTICS_PROVEN'

$FieldProven =
    Get-BooleanJsonProperty `
        -Object $Conclusions `
        -Name 'EXACT_FIELD_NAME_PROVEN'

$BackendProven =
    Get-BooleanJsonProperty `
        -Object $Conclusions `
        -Name 'BACKEND_CONSUMER_IDENTIFIED'

$AbiProven =
    Get-BooleanJsonProperty `
        -Object $Conclusions `
        -Name 'SEMANTIC_PROTOTYPE_INFERRED'

$Executed =
    Get-BooleanJsonProperty `
        -Object $Conclusions `
        -Name 'EXECUTED_AGC'

$HashStatic =
    Get-Sha256 `
        -Path $StaticPath

$HashSummary =
    Get-Sha256 `
        -Path $SummaryPath

$HashDisassembly =
    Get-Sha256 `
        -Path $DisassemblyPath

$HashFocus =
    Get-Sha256 `
        -Path $FocusPath

Write-Host ''
Write-Host '==> Hash artefactos' -ForegroundColor Yellow

Write-Host "[INFO] stage67_static.json SHA256=$HashStatic"
Write-Host "[INFO] dispatch_store_provenance_summary.txt SHA256=$HashSummary"
Write-Host "[INFO] dispatch_store_provenance_disassembly.txt SHA256=$HashDisassembly"
Write-Host "[INFO] dispatch_store_provenance.json SHA256=$HashFocus"

$Report = [ordered]@{
    stage = 67

    target = [ordered]@{
        global_context =
            '0x1A908'

        submit_table_offset =
            '0x50'

        multi_table_offset =
            '0x58'

        known_submit_va =
            '0x18B0'

        known_multi_va =
            '0x4650'
    }

    conclusions = [ordered]@{
        STORE_SCAN_COMPLETED =
            $StoreScanCompleted

        STORE_CANDIDATES_FOUND =
            $StoreCandidatesFound

        FUNCTION_OWNER_RESOLUTION_COMPLETED =
            $OwnerResolved

        GLOBAL_CONTEXT_BASE_PROVEN_FOR_ANY_STORE =
            $AnyProven

        GLOBAL_CONTEXT_SUBMIT_TABLE_STORE_PROVEN =
            $SubmitProven

        GLOBAL_CONTEXT_MULTI_TABLE_STORE_PROVEN =
            $MultiProven

        DISPATCH_TABLE_RUNTIME_INITIALIZATION_PROVEN =
            $RuntimeProven

        SUBMIT_DISPATCH_GLOBAL_BASE_PROVEN =
            $SubmitDispatchProven

        MULTI_DISPATCH_GLOBAL_BASE_PROVEN =
            $MultiDispatchProven

        INDEX_SEMANTICS_PROVEN =
            $IndexProven

        COUNT_SEMANTICS_PROVEN =
            $CountProven

        EXACT_FIELD_NAME_PROVEN =
            $FieldProven

        BACKEND_CONSUMER_IDENTIFIED =
            $BackendProven

        SEMANTIC_PROTOTYPE_INFERRED =
            $AbiProven

        EXECUTED_AGC =
            $Executed
    }

    hashes = [ordered]@{
        'stage67_static.json' =
            $HashStatic

        'dispatch_store_provenance_summary.txt' =
            $HashSummary

        'dispatch_store_provenance_disassembly.txt' =
            $HashDisassembly

        'dispatch_store_provenance.json' =
            $HashFocus
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
Write-Host 'Stage 67 completado' -ForegroundColor Green
Write-Host '============================================' -ForegroundColor Green

Write-Host ''
Write-Host "STORE_SCAN_COMPLETED = $StoreScanCompleted"
Write-Host "STORE_CANDIDATES_FOUND = $StoreCandidatesFound"
Write-Host "FUNCTION_OWNER_RESOLUTION_COMPLETED = $OwnerResolved"
Write-Host "GLOBAL_CONTEXT_BASE_PROVEN_FOR_ANY_STORE = $AnyProven"
Write-Host "GLOBAL_CONTEXT_SUBMIT_TABLE_STORE_PROVEN = $SubmitProven"
Write-Host "GLOBAL_CONTEXT_MULTI_TABLE_STORE_PROVEN = $MultiProven"
Write-Host "DISPATCH_TABLE_RUNTIME_INITIALIZATION_PROVEN = $RuntimeProven"
Write-Host "SUBMIT_DISPATCH_GLOBAL_BASE_PROVEN = $SubmitDispatchProven"
Write-Host "MULTI_DISPATCH_GLOBAL_BASE_PROVEN = $MultiDispatchProven"
Write-Host "INDEX_SEMANTICS_PROVEN = $IndexProven"
Write-Host "COUNT_SEMANTICS_PROVEN = $CountProven"
Write-Host "EXACT_FIELD_NAME_PROVEN = $FieldProven"
Write-Host "BACKEND_CONSUMER_IDENTIFIED = $BackendProven"
Write-Host "SEMANTIC_PROTOTYPE_INFERRED = $AbiProven"
Write-Host "EXECUTED_AGC = $Executed"

Write-Host ''
Write-Host 'Resultados:'
Write-Host "  $OutputDir"

Write-Host ''
Write-Host 'Reporte:'
Write-Host "  $ReportPath"