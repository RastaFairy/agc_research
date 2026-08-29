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

SUBMIT_TABLE_OFFSET = 0x50
MULTI_TABLE_OFFSET = 0x58
DISPATCH_STRIDE = 0x78

SUBMIT_VA = 0x18B0
SUBMIT_SIZE = 380

MULTI_VA = 0x4650
MULTI_SIZE = 579


# ------------------------------------------------------------
# ELF segments
# ------------------------------------------------------------

def load_segments():
    result = []

    with open(
        SPRX,
        "rb",
    ) as fp:
        elf = ELFFile(fp)

        for seg in elf.iter_segments():
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


def segment_containing_va(
    va,
    memory=False,
):
    for seg in SEGMENTS:
        size = (
            seg["memsz"]
            if memory
            else seg["filesz"]
        )

        start = seg["vaddr"]
        end = start + size

        if start <= va < end:
            return seg

    return None


def va_to_file(
    va,
):
    seg = segment_containing_va(
        va,
        memory=False,
    )

    if seg is None:
        return None

    return (
        seg["offset"]
        + (
            va
            - seg["vaddr"]
        )
    )


def va_is_memory_mapped(
    va,
):
    return (
        segment_containing_va(
            va,
            memory=True,
        )
        is not None
    )


def read_va(
    va,
    size,
):
    file_offset = va_to_file(
        va
    )

    if file_offset is None:
        return b""

    with open(
        SPRX,
        "rb",
    ) as fp:
        fp.seek(file_offset)
        return fp.read(size)


# ------------------------------------------------------------
# Segment classification
# ------------------------------------------------------------

def classify_va(
    va,
):
    for seg in SEGMENTS:
        mem_start = seg["vaddr"]
        mem_end = (
            mem_start
            + seg["memsz"]
        )

        if mem_start <= va < mem_end:
            in_file = (
                va
                <
                seg["vaddr"]
                + seg["filesz"]
            )

            if seg["flags"] == 6:
                perm = "RW"
            elif seg["flags"] == 5:
                perm = "RX"
            elif seg["flags"] == 4:
                perm = "R"
            elif seg["flags"] == 3:
                perm = "RWX"
            else:
                perm = str(
                    seg["flags"]
                )

            return {
                "region":
                    (
                        "FILE_BACKED"
                        if in_file
                        else "BSS_OR_ZERO_FILL"
                    ),
                "permissions":
                    perm,
                "segment_vaddr":
                    seg["vaddr"],
                "segment_filesz":
                    seg["filesz"],
                "segment_memsz":
                    seg["memsz"],
                "segment_offset":
                    seg["offset"],
                "in_file":
                    in_file,
            }

    return {
        "region": "UNMAPPED",
        "permissions": "",
        "segment_vaddr": None,
        "segment_filesz": None,
        "segment_memsz": None,
        "segment_offset": None,
        "in_file": False,
    }


# ------------------------------------------------------------
# Find the actual RW/BSS segment containing global context
# ------------------------------------------------------------

GLOBAL_SEGMENT = None

for seg in SEGMENTS:
    start = seg["vaddr"]
    end = (
        start
        + seg["memsz"]
    )

    if (
        start
        <= GLOBAL_CONTEXT_VA
        < end
        and
        seg["flags"] == 6
    ):
        GLOBAL_SEGMENT = seg
        break


if GLOBAL_SEGMENT is None:
    raise RuntimeError(
        "No se pudo localizar el PT_LOAD RW que contiene global_context"
    )


GLOBAL_SEGMENT_MEM_START = GLOBAL_SEGMENT["vaddr"]
GLOBAL_SEGMENT_MEM_END = (
    GLOBAL_SEGMENT["vaddr"]
    + GLOBAL_SEGMENT["memsz"]
)

GLOBAL_SEGMENT_FILE_END = (
    GLOBAL_SEGMENT["vaddr"]
    + GLOBAL_SEGMENT["filesz"]
)


# ------------------------------------------------------------
# Dispatch slot boundaries
# ------------------------------------------------------------

SUBMIT_SLOT0_VA = (
    GLOBAL_CONTEXT_VA
    + SUBMIT_TABLE_OFFSET
)

MULTI_SLOT0_VA = (
    GLOBAL_CONTEXT_VA
    + MULTI_TABLE_OFFSET
)


def slots_inside_segment(
    first_slot,
    stride,
    slot_width=8,
):
    result = []

    index = 0
    current = first_slot

    while (
        current + slot_width
        <= GLOBAL_SEGMENT_MEM_END
    ):
        result.append(
            {
                "index":
                    index,
                "slot_va":
                    current,
                "slot_end_va":
                    current + slot_width,
                "within_rw_segment":
                    True,
                "within_file_backed_bytes":
                    (
                        current + slot_width
                        <= GLOBAL_SEGMENT_FILE_END
                    ),
            }
        )

        index += 1

        current = (
            first_slot
            + index
            * stride
        )

    return result


SUBMIT_VALID_SLOTS = slots_inside_segment(
    SUBMIT_SLOT0_VA,
    DISPATCH_STRIDE,
)

MULTI_VALID_SLOTS = slots_inside_segment(
    MULTI_SLOT0_VA,
    DISPATCH_STRIDE,
)


# ------------------------------------------------------------
# Disassembly helpers
# ------------------------------------------------------------

def disassemble_blob(
    raw,
    start_va,
):
    if not raw:
        return ""

    tmp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            prefix="agc_stage66_",
            suffix=".bin",
            dir=OUT_DIR,
            delete=False,
        ) as fp:
            fp.write(raw)
            fp.flush()
            tmp_path = fp.name

        candidates = [
            [
                "objdump",
                "-D",
                "-b",
                "binary",
                "-m",
                "i386:x86-64",
                "--adjust-vma=0x%x"
                % start_va,
                tmp_path,
            ],
            [
                "llvm-objdump",
                "-D",
                "--triple=x86_64",
                "--adjust-vma=0x%x"
                % start_va,
                tmp_path,
            ],
        ]

        for cmd in candidates:
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
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def parse_instruction_lines(
    text,
):
    instructions = []

    for line in text.splitlines():
        stripped = line.strip()

        match = re.match(
            r"^([0-9a-fA-F]+):\s+(.*)$",
            stripped,
        )

        if not match:
            continue

        va = int(
            match.group(1),
            16,
        )

        rest = match.group(2)

        tokens = rest.split()

        idx = 0

        while idx < len(tokens):
            if re.fullmatch(
                r"[0-9a-fA-F]{2}",
                tokens[idx],
            ):
                idx += 1
            else:
                break

        instruction = " ".join(
            tokens[idx:]
        ).strip()

        if not instruction:
            continue

        instructions.append(
            {
                "va": va,
                "instruction":
                    instruction,
            }
        )

    return instructions


# ------------------------------------------------------------
# Executable ranges
# ------------------------------------------------------------

EXEC_SEGMENTS = [
    seg
    for seg in SEGMENTS
    if (
        seg["flags"] & 1
    ) != 0
    and
    seg["filesz"] > 0
]


def disassemble_executable_segment(
    seg,
):
    raw = read_va(
        seg["vaddr"],
        seg["filesz"],
    )

    return disassemble_blob(
        raw,
        seg["vaddr"],
    )


EXEC_DISASSEMBLIES = []

for seg in EXEC_SEGMENTS:
    text = disassemble_executable_segment(
        seg
    )

    instructions = parse_instruction_lines(
        text
    )

    EXEC_DISASSEMBLIES.append(
        {
            "segment": seg,
            "text": text,
            "instructions":
                instructions,
        }
    )


# ------------------------------------------------------------
# Simple register tracking for global context
# ------------------------------------------------------------

REGISTER_ALIASES = {
    "rax": "rax",
    "eax": "rax",
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


def normalize_register(
    reg,
):
    reg = reg.strip()

    if reg.startswith("%"):
        reg = reg[1:]

    return REGISTER_ALIASES.get(
        reg,
        reg,
    )


def extract_loaded_global_register(
    instruction,
):
    text = instruction.strip()

    # LEA displacement with objdump resolving the target.
    if (
        "lea" in text
        and
        "# 0x1a908" in text
    ):
        match = re.search(
            r",%([a-z0-9]+)",
            text,
        )

        if match:
            return normalize_register(
                match.group(1)
            )

    return None


def extract_store_memory_operand(
    instruction,
):
    text = instruction.strip()

    if not any(
        mnemonic in text
        for mnemonic in (
            "mov ",
            "movq ",
            "movl ",
            "movb ",
            "movw ",
            "movd ",
            "movups ",
            "vmovups ",
        )
    ):
        return None

    # Destination memory is after the second comma.
    parts = text.split(
        ","
    )

    if len(parts) != 2:
        return None

    source = parts[0].strip()
    destination = parts[1].strip()

    if "(" not in destination:
        return None

    if not destination.startswith(
        (
            "0x",
            "-0x",
        )
    ) and not re.match(
        r"^-?\d+\(",
        destination,
    ):
        return None

    return {
        "source": source,
        "destination":
            destination,
    }


def parse_memory_offset(
    operand,
):
    # Handles:
    #   0x50(%rbx)
    #   0x50(%rbx,%rax,1)
    #   (%rbx,%rax,1)
    #   -0x10(%rbp)
    match = re.match(
        r"^(-?0x[0-9a-fA-F]+|-?\d+)?\((.*)\)$",
        operand,
    )

    if not match:
        return None

    offset_text = match.group(1)

    if offset_text is None:
        offset = 0
    elif offset_text.lower().startswith(
        (
            "0x",
            "-0x",
        )
    ):
        offset = int(
            offset_text,
            16,
        )
    else:
        offset = int(
            offset_text,
            10,
        )

    inside = match.group(2)

    pieces = [
        x.strip()
        for x in inside.split(
            ","
        )
    ]

    base = (
        normalize_register(
            pieces[0]
        )
        if pieces
        and pieces[0]
        else None
    )

    index = (
        normalize_register(
            pieces[1]
        )
        if len(pieces) >= 2
        and pieces[1]
        else None
    )

    scale = (
        int(
            pieces[2],
            0,
        )
        if len(pieces) >= 3
        and pieces[2]
        else 1
    )

    return {
        "offset":
            offset,
        "base":
            base,
        "index":
            index,
        "scale":
            scale,
    }


# ------------------------------------------------------------
# Function-like windows
# ------------------------------------------------------------

def function_name_for_va(
    va,
):
    # Stage 65/previous stages may have symbol data,
    # but this analyzer intentionally does not require symbols.
    return None


# ------------------------------------------------------------
# Scan executable code for global_context + dispatch stores
# ------------------------------------------------------------

dispatch_store_candidates = []
dispatch_load_candidates = []

for blob in EXEC_DISASSEMBLIES:
    instructions = blob[
        "instructions"
    ]

    tracked = set()

    for ins in instructions:
        text = ins[
            "instruction"
        ]

        loaded_reg = extract_loaded_global_register(
            text
        )

        if loaded_reg:
            tracked.add(
                loaded_reg
            )

        # Simple register copies.
        copy_match = re.match(
            r"mov\s+%([a-z0-9]+),%([a-z0-9]+)",
            text,
        )

        if copy_match:
            src = normalize_register(
                copy_match.group(1)
            )

            dst = normalize_register(
                copy_match.group(2)
            )

            if src in tracked:
                tracked.add(
                    dst
                )

        # Loads/stores using tracked global context.
        mem_match = re.search(
            r"(-?0x[0-9a-fA-F]+|-?\d+)?\(%([a-z0-9]+)(?:,%([a-z0-9]+),([1248]))?\)",
            text,
        )

        if not mem_match:
            continue

        offset_text = (
            mem_match.group(1)
        )

        base_reg = normalize_register(
            mem_match.group(2)
        )

        index_reg = (
            normalize_register(
                mem_match.group(3)
            )
            if mem_match.group(3)
            else None
        )

        scale = (
            int(
                mem_match.group(4)
            )
            if mem_match.group(4)
            else 1
        )

        if base_reg not in tracked:
            continue

        if offset_text is None:
            offset = 0
        else:
            offset = int(
                offset_text,
                16
            ) if offset_text.lower().startswith(
                (
                    "0x",
                    "-0x",
                )
            ) else int(
                offset_text
            )

        candidate = {
            "instruction_va":
                ins["va"],
            "instruction":
                text,
            "base_register":
                base_reg,
            "index_register":
                index_reg,
            "scale":
                scale,
            "offset":
                offset,
        }

        # A dispatch slot is either +0x50 or +0x58.
        if offset in (
            SUBMIT_TABLE_OFFSET,
            MULTI_TABLE_OFFSET,
        ):
            if index_reg:
                candidate["classification"] = (
                    "INDEXED_DISPATCH_MEMORY_ACCESS"
                )
            else:
                candidate["classification"] = (
                    "NON_INDEXED_DISPATCH_MEMORY_ACCESS"
                )

            # Correct read/write classification:
            # destination memory normally appears after the comma.
            store_info = extract_store_memory_operand(
                text
            )

            if store_info is not None:
                dst = store_info[
                    "destination"
                ]

                if (
                    "(" in dst
                    and
                    (
                        "0x%x" % offset
                    ) in dst
                ):
                    candidate[
                        "classification"
                    ] = (
                        "STORE_CANDIDATE"
                    )

                    dispatch_store_candidates.append(
                        candidate
                    )
                    continue

            dispatch_load_candidates.append(
                candidate
            )


# ------------------------------------------------------------
# Focused target-function analysis
# ------------------------------------------------------------

def focused_accesses(
    instructions,
):
    result = []

    tracked = set()

    for ins in instructions:
        text = ins[
            "instruction"
        ]

        loaded_reg = extract_loaded_global_register(
            text
        )

        if loaded_reg:
            tracked.add(
                loaded_reg
            )

        copy_match = re.match(
            r"mov\s+%([a-z0-9]+),%([a-z0-9]+)",
            text,
        )

        if copy_match:
            src = normalize_register(
                copy_match.group(1)
            )
            dst = normalize_register(
                copy_match.group(2)
            )

            if src in tracked:
                tracked.add(
                    dst
                )

        mem_match = re.search(
            r"(-?0x[0-9a-fA-F]+|-?\d+)?\(%([a-z0-9]+)(?:,%([a-z0-9]+),([1248]))?\)",
            text,
        )

        if not mem_match:
            continue

        base = normalize_register(
            mem_match.group(2)
        )

        if base not in tracked:
            continue

        offset_text = (
            mem_match.group(1)
        )

        offset = (
            0
            if offset_text is None
            else
            (
                int(
                    offset_text,
                    16,
                )
                if offset_text.lower().startswith(
                    (
                        "0x",
                        "-0x",
                    )
                )
                else
                int(
                    offset_text
                )
            )
        )

        if offset not in (
            SUBMIT_TABLE_OFFSET,
            MULTI_TABLE_OFFSET,
        ):
            continue

        result.append(
            {
                "instruction_va":
                    ins["va"],
                "instruction":
                    text,
                "base_register":
                    base,
                "offset":
                    offset,
                "index_register":
                    (
                        normalize_register(
                            mem_match.group(3)
                        )
                        if mem_match.group(3)
                        else None
                    ),
                "scale":
                    (
                        int(
                            mem_match.group(4)
                        )
                        if mem_match.group(4)
                        else 1
                    ),
            }
        )

    return result


submit_raw = read_va(
    SUBMIT_VA,
    SUBMIT_SIZE,
)

multi_raw = read_va(
    MULTI_VA,
    MULTI_SIZE,
)

submit_text = disassemble_blob(
    submit_raw,
    SUBMIT_VA,
)

multi_text = disassemble_blob(
    multi_raw,
    MULTI_VA,
)

submit_instructions = parse_instruction_lines(
    submit_text
)

multi_instructions = parse_instruction_lines(
    multi_text
)

submit_focused = focused_accesses(
    submit_instructions
)

multi_focused = focused_accesses(
    multi_instructions
)


# ------------------------------------------------------------
# Valid static slots
# ------------------------------------------------------------

def enrich_slot(
    slot,
):
    raw = read_va(
        slot["slot_va"],
        8,
    )

    data = dict(
        slot
    )

    data["raw_hex"] = (
        raw.hex(" ")
        if raw
        else ""
    )

    data["static_bytes_available"] = (
        len(raw) == 8
    )

    if len(raw) == 8:
        value = struct.unpack(
            "<Q",
            raw,
        )[0]

        data[
            "raw_u64"
        ] = value

        data[
            "raw_u64_hex"
        ] = "0x%x" % value

        data[
            "interpretation"
        ] = (
            "ZERO"
            if value == 0
            else
            (
                "NONZERO_STATIC_VALUE"
            )
        )
    else:
        data[
            "raw_u64"
        ] = None
        data[
            "raw_u64_hex"
        ] = None
        data[
            "interpretation"
        ] = "UNAVAILABLE"

    return data


submit_slots = [
    enrich_slot(
        slot
    )
    for slot in SUBMIT_VALID_SLOTS
]

multi_slots = [
    enrich_slot(
        slot
    )
    for slot in MULTI_VALID_SLOTS
]


# ------------------------------------------------------------
# Check what Stage 65 got wrong
# ------------------------------------------------------------

stage65_false_external_reads = []

stage65_path = os.path.join(
    PREVIOUS_RESULTS,
    "stage65_static.json",
)

if os.path.isfile(
    stage65_path
):
    try:
        with open(
            stage65_path,
            "r",
            encoding="utf-8",
        ) as fp:
            previous = json.load(
                fp
            )

        for family_name in (
            "submit_entries",
            "multi_entries",
        ):
            for entry in previous.get(
                family_name,
                [],
            ):
                slot_va = entry.get(
                    "slot_va"
                )

                if slot_va is None:
                    continue

                if not (
                    GLOBAL_SEGMENT_MEM_START
                    <= slot_va
                    <
                    GLOBAL_SEGMENT_MEM_END
                ):
                    stage65_false_external_reads.append(
                        {
                            "family":
                                family_name,
                            "index":
                                entry.get(
                                    "index"
                                ),
                            "slot_va":
                                slot_va,
                            "slot_va_hex":
                                "0x%x"
                                % slot_va,
                            "reason":
                                "OUTSIDE_GLOBAL_RW_SEGMENT",
                        }
                    )

    except Exception:
        pass


# ------------------------------------------------------------
# Summarize dynamic write candidates
# ------------------------------------------------------------

submit_dynamic_writes = [
    x
    for x in dispatch_store_candidates
    if x["offset"]
    == SUBMIT_TABLE_OFFSET
]

multi_dynamic_writes = [
    x
    for x in dispatch_store_candidates
    if x["offset"]
    == MULTI_TABLE_OFFSET
]


# ------------------------------------------------------------
# Conclusions
# ------------------------------------------------------------

conclusions = {
    "GLOBAL_RW_SEGMENT_IDENTIFIED":
        True,

    "SUBMIT_TABLE_FIRST_SLOT_IN_RW_SEGMENT":
        (
            GLOBAL_SEGMENT_MEM_START
            <= SUBMIT_SLOT0_VA
            <
            GLOBAL_SEGMENT_MEM_END
        ),

    "MULTI_TABLE_FIRST_SLOT_IN_RW_SEGMENT":
        (
            GLOBAL_SEGMENT_MEM_START
            <= MULTI_SLOT0_VA
            <
            GLOBAL_SEGMENT_MEM_END
        ),

    "SUBMIT_STATIC_SLOT_BOUNDARY_PROVEN":
        len(submit_slots) > 0,

    "MULTI_STATIC_SLOT_BOUNDARY_PROVEN":
        len(multi_slots) > 0,

    "STAGE65_EXTERNAL_REGION_READS_IDENTIFIED":
        len(
            stage65_false_external_reads
        ) > 0,

    "SUBMIT_DYNAMIC_TABLE_STORE_CANDIDATE_FOUND":
        len(
            submit_dynamic_writes
        ) > 0,

    "MULTI_DYNAMIC_TABLE_STORE_CANDIDATE_FOUND":
        len(
            multi_dynamic_writes
        ) > 0,

    "DISPATCH_TABLE_RUNTIME_INITIALIZATION_CANDIDATE_FOUND":
        (
            len(submit_dynamic_writes)
            > 0
            or
            len(multi_dynamic_writes)
            > 0
        ),

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


# ------------------------------------------------------------
# Static report
# ------------------------------------------------------------

static = {
    "stage":
        66,

    "target": {
        "global_context_va":
            GLOBAL_CONTEXT_VA,
        "a4_va":
            A4_VA,
        "a4_offset":
            A4_OFFSET,
        "dispatch_stride":
            DISPATCH_STRIDE,
    },

    "global_rw_segment": {
        "start":
            GLOBAL_SEGMENT_MEM_START,
        "start_hex":
            "0x%x"
            % GLOBAL_SEGMENT_MEM_START,
        "end":
            GLOBAL_SEGMENT_MEM_END,
        "end_hex":
            "0x%x"
            % GLOBAL_SEGMENT_MEM_END,
        "files_end":
            GLOBAL_SEGMENT_FILE_END,
        "files_end_hex":
            "0x%x"
            % GLOBAL_SEGMENT_FILE_END,
        "filesz":
            GLOBAL_SEGMENT[
                "filesz"
            ],
        "memsz":
            GLOBAL_SEGMENT[
                "memsz"
            ],
        "flags":
            GLOBAL_SEGMENT[
                "flags"
            ],
    },

    "dispatch_regions": {
        "submit": {
            "table_base":
                GLOBAL_CONTEXT_VA,
            "pointer_offset":
                SUBMIT_TABLE_OFFSET,
            "first_slot_va":
                SUBMIT_SLOT0_VA,
            "first_slot_va_hex":
                "0x%x"
                % SUBMIT_SLOT0_VA,
            "valid_slot_count":
                len(
                    submit_slots
                ),
            "slots":
                submit_slots,
        },

        "multi": {
            "table_base":
                GLOBAL_CONTEXT_VA,
            "pointer_offset":
                MULTI_TABLE_OFFSET,
            "first_slot_va":
                MULTI_SLOT0_VA,
            "first_slot_va_hex":
                "0x%x"
                % MULTI_SLOT0_VA,
            "valid_slot_count":
                len(
                    multi_slots
                ),
            "slots":
                multi_slots,
        },
    },

    "dynamic_store_candidates":
        dispatch_store_candidates,

    "submit_dynamic_writes":
        submit_dynamic_writes,

    "multi_dynamic_writes":
        multi_dynamic_writes,

    "submit_focused_accesses":
        submit_focused,

    "multi_focused_accesses":
        multi_focused,

    "stage65_external_region_reads":
        stage65_false_external_reads,

    "executable_segments": [
        {
            "vaddr":
                x["vaddr"],
            "vaddr_hex":
                "0x%x"
                % x["vaddr"],
            "filesz":
                x["filesz"],
            "memsz":
                x["memsz"],
            "flags":
                x["flags"],
        }
        for x in EXEC_SEGMENTS
    ],

    "conclusions":
        conclusions,
}


with open(
    os.path.join(
        OUT_DIR,
        "stage66_static.json",
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
    "AGC PS5 Stage 66 - Dispatch Bounds / Dynamic Initialization Audit"
)

lines.append("")
lines.append(
    "=== GLOBAL RW SEGMENT ==="
)

lines.append(
    "start = 0x%x"
    % GLOBAL_SEGMENT_MEM_START
)

lines.append(
    "end = 0x%x"
    % GLOBAL_SEGMENT_MEM_END
)

lines.append(
    "files_end = 0x%x"
    % GLOBAL_SEGMENT_FILE_END
)

lines.append(
    "filesz = 0x%x"
    % GLOBAL_SEGMENT["filesz"]
)

lines.append(
    "memsz = 0x%x"
    % GLOBAL_SEGMENT["memsz"]
)

lines.append("")
lines.append(
    "=== SUBMIT TABLE ==="
)

lines.append(
    "base = 0x%x"
    % GLOBAL_CONTEXT_VA
)

lines.append(
    "pointer offset = 0x50"
)

lines.append(
    "first pointer slot = 0x%x"
    % SUBMIT_SLOT0_VA
)

lines.append(
    "valid static pointer slots = %d"
    % len(
        submit_slots
    )
)

for slot in submit_slots:
    lines.append(
        "index=%02d slot=0x%X raw=%s interpretation=%s"
        % (
            slot[
                "index"
            ],
            slot[
                "slot_va"
            ],
            slot[
                "raw_hex"
            ] or "<unavailable>",
            slot[
                "interpretation"
            ],
        )
    )

lines.append("")
lines.append(
    "=== MULTI TABLE ==="
)

lines.append(
    "base = 0x%x"
    % GLOBAL_CONTEXT_VA
)

lines.append(
    "pointer offset = 0x58"
)

lines.append(
    "first pointer slot = 0x%x"
    % MULTI_SLOT0_VA
)

lines.append(
    "valid static pointer slots = %d"
    % len(
        multi_slots
    )
)

for slot in multi_slots:
    lines.append(
        "index=%02d slot=0x%X raw=%s interpretation=%s"
        % (
            slot[
                "index"
            ],
            slot[
                "slot_va"
            ],
            slot[
                "raw_hex"
            ] or "<unavailable>",
            slot[
                "interpretation"
            ],
        )
    )

lines.append("")
lines.append(
    "=== STAGE 65 CORRECTION ==="
)

if stage65_false_external_reads:
    for item in stage65_false_external_reads:
        lines.append(
            "%s index=%d slot=0x%s reason=%s"
            % (
                item[
                    "family"
                ],
                item[
                    "index"
                ],
                item[
                    "slot_va_hex"
                ],
                item[
                    "reason"
                ],
            )
        )
else:
    lines.append(
        "NONE"
    )

lines.append("")
lines.append(
    "=== DYNAMIC STORE CANDIDATES ==="
)

if dispatch_store_candidates:
    for item in dispatch_store_candidates:
        lines.append(
            "VA=0x%X offset=0x%X base=%s index=%s scale=%d | %s"
            % (
                item[
                    "instruction_va"
                ],
                item[
                    "offset"
                ],
                item[
                    "base_register"
                ],
                item[
                    "index_register"
                ] or "NONE",
                item[
                    "scale"
                ],
                item[
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
    "=== FOCUSED SUBMIT ACCESSES ==="
)

for item in submit_focused:
    lines.append(
        "VA=0x%X offset=0x%X base=%s index=%s scale=%d | %s"
        % (
            item[
                "instruction_va"
            ],
            item[
                "offset"
            ],
            item[
                "base_register"
            ],
            item[
                "index_register"
            ] or "NONE",
            item[
                "scale"
            ],
            item[
                "instruction"
            ],
        )
    )

lines.append("")
lines.append(
    "=== FOCUSED MULTI ACCESSES ==="
)

for item in multi_focused:
    lines.append(
        "VA=0x%X offset=0x%X base=%s index=%s scale=%d | %s"
        % (
            item[
                "instruction_va"
            ],
            item[
                "offset"
            ],
            item[
                "base_register"
            ],
            item[
                "index_register"
            ] or "NONE",
            item[
                "scale"
            ],
            item[
                "instruction"
            ],
        )
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
    "Stage 64 ya demuestra que +0xA4 se usa como índice de dispatch."
)

lines.append(
    "Stage 66 limita el análisis al PT_LOAD RW que realmente contiene global_context."
)

lines.append(
    "Los bytes posteriores al final de ese segmento no se consideran entradas de la tabla."
)

lines.append(
    "Los slots estánticos del BSS no contienen targets válidos en el fichero porque el BSS no está respaldado por bytes de archivo."
)

lines.append(
    "La resolución de los punteros reales depende de inicialización runtime salvo que exista una escritura estática identificable."
)

lines.append(
    "No se asigna un nombre semántico a +0xA4 sin evidencia adicional."
)

summary = "\n".join(
    lines
) + "\n"

with open(
    os.path.join(
        OUT_DIR,
        "dispatch_bounds_summary.txt",
    ),
    "w",
    encoding="utf-8",
    newline="\n",
) as fp:
    fp.write(
        summary
    )


# ------------------------------------------------------------
# Disassembly artifact
# ------------------------------------------------------------

with open(
    os.path.join(
        OUT_DIR,
        "dispatch_bounds_disassembly.txt",
    ),
    "w",
    encoding="utf-8",
    newline="\n",
) as fp:
    fp.write(
        "AGC PS5 Stage 66 - Dispatch Access Disassembly\n\n"
    )

    fp.write(
        "=== SubmitCommandBuffer ===\n\n"
    )

    fp.write(
        submit_text
    )

    fp.write(
        "\n\n=== SubmitMultiCommandBuffers ===\n\n"
    )

    fp.write(
        multi_text
    )


# ------------------------------------------------------------
# Machine-readable focused artifact
# ------------------------------------------------------------

focused = {
    "global_rw_segment": {
        "start":
            GLOBAL_SEGMENT_MEM_START,
        "end":
            GLOBAL_SEGMENT_MEM_END,
        "files_end":
            GLOBAL_SEGMENT_FILE_END,
    },

    "submit": {
        "first_slot":
            SUBMIT_SLOT0_VA,
        "valid_slots":
            submit_slots,
        "dynamic_writes":
            submit_dynamic_writes,
    },

    "multi": {
        "first_slot":
            MULTI_SLOT0_VA,
        "valid_slots":
            multi_slots,
        "dynamic_writes":
            multi_dynamic_writes,
    },

    "stage65_external_reads":
        stage65_false_external_reads,

    "conclusions":
        conclusions,
}

with open(
    os.path.join(
        OUT_DIR,
        "dispatch_bounds.json",
    ),
    "w",
    encoding="utf-8",
) as fp:
    json.dump(
        focused,
        fp,
        indent=2,
    )


print(
    json.dumps(
        static,
        indent=2,
    )
)