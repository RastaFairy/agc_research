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

TARGET_NAME = "sceAgcDriverSubmitCommandBuffer"
TARGET_VA = 0x18B0
TARGET_SIZE = 380

MULTI_NAME = "sceAgcDriverSubmitMultiCommandBuffers"
MULTI_VA = 0x4650

GLOBAL_CONTEXT_VA = 0x1A908
INDEX_OFFSET = 0xA4
INDEX_FIELD_VA = GLOBAL_CONTEXT_VA + INDEX_OFFSET

DISPATCH_BASE_OFFSET = 0x50
DISPATCH_STRIDE = 0x78

WINDOW_BEFORE = 0x100
WINDOW_AFTER = 0x100

ELF_FP = open(SPRX, "rb")
ELF = ELFFile(ELF_FP)


# ============================================================
# ELF
# ============================================================

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


def executable_segments():
    return [
        seg
        for seg in SEGMENTS
        if (seg["flags"] & 1) and seg["filesz"] > 0
    ]


# ============================================================
# Disassembly
# ============================================================

def disassemble(raw, start_va):
    if not raw:
        return ""

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            prefix="agc_stage61_",
            suffix=".bin",
            dir=OUT_DIR,
            delete=False,
        ) as fp:
            fp.write(raw)
            fp.flush()
            temp_path = fp.name

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

            if proc.returncode == 0:
                return proc.stdout

        return ""

    finally:
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                pass


def parse_disassembly_lines(text):
    result = []

    for line in text.splitlines():
        stripped = line.strip()

        if not stripped:
            continue

        match = re.match(
            r"^([0-9a-fA-F]+):\s+"
            r"((?:[0-9a-fA-F]{2}\s+)+)"
            r"(.*)$",
            stripped,
        )

        if not match:
            continue

        result.append(
            {
                "va": int(match.group(1), 16),
                "instruction": match.group(3).strip(),
            }
        )

    return result


def normalize_instruction(text):
    text = text.replace("\t", " ").strip()

    while "  " in text:
        text = text.replace("  ", " ")

    return text


# ============================================================
# Function-start heuristics
# ============================================================

PROLOGUES = [
    b"\x55\x48\x89\xe5",
    b"\x41\x57\x41\x56\x41\x55\x41\x54\x53",
    b"\x53\x48\x83\xec",
    b"\x48\x83\xec",
]


def find_function_starts():
    starts = set()

    for seg in executable_segments():
        with open(SPRX, "rb") as fp:
            fp.seek(seg["offset"])
            blob = fp.read(seg["filesz"])

        base = seg["vaddr"]

        for needle in PROLOGUES:
            pos = 0

            while True:
                found = blob.find(needle, pos)

                if found < 0:
                    break

                starts.add(base + found)
                pos = found + 1

    starts.add(TARGET_VA)
    starts.add(MULTI_VA)

    return sorted(starts)


FUNCTION_STARTS = find_function_starts()


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
# Find all instructions that reference global_context
# ============================================================

GLOBAL_LEA_ENCODINGS = [
    (b"\x48\x8d\x05", "rax"),
    (b"\x48\x8d\x0d", "rcx"),
    (b"\x48\x8d\x1d", "rbx"),
    (b"\x4c\x8d\x25", "r12"),
    (b"\x4c\x8d\x2d", "r13"),
    (b"\x4c\x8d\x35", "r14"),
    (b"\x4c\x8d\x3d", "r15"),
]


def scan_global_leas():
    result = []

    for seg in executable_segments():
        with open(SPRX, "rb") as fp:
            fp.seek(seg["offset"])
            blob = fp.read(seg["filesz"])

        base = seg["vaddr"]

        for encoding, register in GLOBAL_LEA_ENCODINGS:
            pos = 0

            while True:
                found = blob.find(encoding, pos)

                if found < 0:
                    break

                if found + 7 > len(blob):
                    break

                displacement = int.from_bytes(
                    blob[found + 3:found + 7],
                    "little",
                    signed=True,
                )

                instruction_va = base + found
                target_va = instruction_va + 7 + displacement

                if target_va == GLOBAL_CONTEXT_VA:
                    result.append(
                        {
                            "instruction_va": instruction_va,
                            "register": register,
                            "target_va": target_va,
                            "file_offset": seg["offset"] + found,
                        }
                    )

                pos = found + 1

    return result


GLOBAL_LEAS = scan_global_leas()


# ============================================================
# Build targeted windows
# ============================================================

def build_windows():
    windows = []

    seen = set()

    for ref in GLOBAL_LEAS:
        key = (
            ref["instruction_va"],
            ref["register"],
        )

        if key in seen:
            continue

        seen.add(key)

        start = max(
            0,
            ref["instruction_va"] - WINDOW_BEFORE,
        )

        raw = read_va(
            start,
            WINDOW_BEFORE + WINDOW_AFTER,
        )

        text = disassemble(
            raw,
            start,
        )

        windows.append(
            {
                "reference": ref,
                "start_va": start,
                "disassembly": text,
            }
        )

    return windows


WINDOWS = build_windows()


# ============================================================
# Helpers for memory operands
# ============================================================

def parse_number(text):
    text = text.strip()

    if text.lower().startswith("0x"):
        return int(text, 16)

    return int(text, 10)


def extract_memory_operands(instruction):
    result = []

    pattern = re.compile(
        r"(?P<disp>[+-]?(?:0x[0-9a-fA-F]+|\d+))?"
        r"\(%(?P<base>[a-z0-9]+)"
        r"(?:,%(?P<index>[a-z0-9]+)"
        r"(?:,(?P<scale>[1248]))?)?"
        r"\)"
    )

    for match in pattern.finditer(instruction):
        disp_text = match.group("disp")
        displacement = 0

        if disp_text:
            try:
                displacement = parse_number(disp_text)
            except ValueError:
                continue

        result.append(
            {
                "expression": match.group(0),
                "base": match.group("base"),
                "index": match.group("index"),
                "scale":
                    int(match.group("scale"))
                    if match.group("scale")
                    else 1,
                "displacement": displacement,
            }
        )

    return result


def writes_memory(instruction):
    text = normalize_instruction(instruction).lower()

    if re.match(
        r"^(?:mov|movq|movl|movw|movb|vmovups|vmovdqu|vmovdqa|"
        r"movups|movdqu|movdqa|stos|testb|andb|orb|xorb|inc|dec|add|sub|"
        r"cmp|cmpl|cmpq|xadd)",
        text,
    ):
        operands = text.split(None, 1)

        if len(operands) != 2:
            return False

        body = operands[1]

        if "," not in body:
            return False

        destination = body.split(",", 1)[1]

        return "(" in destination

    return False


def reads_memory(instruction):
    text = normalize_instruction(instruction).lower()

    if "(" not in text:
        return False

    if text.startswith(
        (
            "mov ",
            "movq ",
            "movl ",
            "movw ",
            "movb ",
            "vmovups ",
            "vmovdqu ",
            "vmovdqa ",
            "movups ",
            "movdqu ",
            "movdqa ",
            "lea ",
            "cmp ",
            "cmpl ",
            "cmpq ",
            "test ",
            "testb ",
            "and ",
            "andb ",
        )
    ):
        return True

    return False


# ============================================================
# Exact +0xA4 writes
# ============================================================

def scan_index_writes():
    result = []

    for window in WINDOWS:
        reference = window["reference"]

        lines = parse_disassembly_lines(
            window["disassembly"]
        )

        for line in lines:
            instruction = normalize_instruction(
                line["instruction"]
            )

            for operand in extract_memory_operands(
                instruction
            ):
                if operand["displacement"] != INDEX_OFFSET:
                    continue

                if operand["base"] == "":
                    continue

                write = writes_memory(instruction)

                if not write:
                    continue

                result.append(
                    {
                        "instruction_va": line["va"],
                        "instruction": instruction,
                        "base_register": operand["base"],
                        "index_register":
                            operand["index"],
                        "scale":
                            operand["scale"],
                        "field_offset":
                            operand["displacement"],
                        "field_va":
                            GLOBAL_CONTEXT_VA +
                            operand["displacement"],
                        "reference_va":
                            reference["instruction_va"],
                    }
                )

    unique = {}

    for item in result:
        key = (
            item["instruction_va"],
            item["instruction"],
            item["field_offset"],
        )

        unique[key] = item

    return list(unique.values())


INDEX_WRITES = scan_index_writes()


# ============================================================
# Exact +0xA4 reads
# ============================================================

def scan_index_reads():
    result = []

    for window in WINDOWS:
        reference = window["reference"]

        lines = parse_disassembly_lines(
            window["disassembly"]
        )

        for line in lines:
            instruction = normalize_instruction(
                line["instruction"]
            )

            for operand in extract_memory_operands(
                instruction
            ):
                if operand["displacement"] != INDEX_OFFSET:
                    continue

                if not reads_memory(instruction):
                    continue

                result.append(
                    {
                        "instruction_va": line["va"],
                        "instruction": instruction,
                        "base_register": operand["base"],
                        "index_register":
                            operand["index"],
                        "scale":
                            operand["scale"],
                        "field_offset":
                            operand["displacement"],
                        "field_va":
                            GLOBAL_CONTEXT_VA +
                            operand["displacement"],
                        "reference_va":
                            reference["instruction_va"],
                    }
                )

    unique = {}

    for item in result:
        key = (
            item["instruction_va"],
            item["instruction"],
            item["field_offset"],
        )

        unique[key] = item

    return list(unique.values())


INDEX_READS = scan_index_reads()


# ============================================================
# Provenance of RAX and XMM0 around writes
# ============================================================

def find_register_origin(lines, write_index, register):
    evidence = []

    start = max(
        0,
        write_index - 40,
    )

    for pos in range(
        start,
        write_index,
    ):
        instruction = normalize_instruction(
            lines[pos]["instruction"]
        )

        lower = instruction.lower()

        if register == "rax":
            if re.search(
                r"\blea\b.*#\s*0x1a908\b",
                lower,
            ):
                evidence.append(
                    {
                        "instruction_va":
                            lines[pos]["va"],
                        "instruction":
                            instruction,
                        "kind":
                            "GLOBAL_CONTEXT_LEA",
                    }
                )

            if re.search(
                r"\bmov\b.*%rax\b",
                lower,
            ):
                evidence.append(
                    {
                        "instruction_va":
                            lines[pos]["va"],
                        "instruction":
                            instruction,
                        "kind":
                            "RAX_ASSIGNMENT",
                    }
                )

        elif register == "xmm0":
            if re.search(
                r"\b(?:xorps|pxor|xorpd)\s+%xmm0,\s*%xmm0",
                lower,
            ):
                evidence.append(
                    {
                        "instruction_va":
                            lines[pos]["va"],
                        "instruction":
                            instruction,
                        "kind":
                            "XMM0_ZERO",
                    }
                )

            if re.search(
                r"\b(?:movups|movaps|movdqu|movdqa|vmovups|vmovdqu|vmovdqa)\b.*%xmm0",
                lower,
            ):
                evidence.append(
                    {
                        "instruction_va":
                            lines[pos]["va"],
                        "instruction":
                            instruction,
                        "kind":
                            "XMM0_LOAD_OR_ASSIGN",
                    }
                )

            if re.search(
                r"\b(?:movd|movq)\b.*%xmm0",
                lower,
            ):
                evidence.append(
                    {
                        "instruction_va":
                            lines[pos]["va"],
                        "instruction":
                            instruction,
                        "kind":
                            "XMM0_SCALAR_ASSIGN",
                    }
                )

    return evidence


def analyze_write_origins():
    result = []

    for candidate in INDEX_WRITES:
        function_start = nearest_function_start(
            candidate["instruction_va"]
        )

        if function_start is None:
            function_start = max(
                0,
                candidate["instruction_va"] - 0x80,
            )

        window_start = max(
            function_start,
            candidate["instruction_va"] - 0x100,
        )

        raw = read_va(
            window_start,
            candidate["instruction_va"] -
            window_start +
            0x40,
        )

        text = disassemble(
            raw,
            window_start,
        )

        lines = parse_disassembly_lines(
            text
        )

        write_index = None

        for index, line in enumerate(lines):
            if line["va"] == candidate["instruction_va"]:
                write_index = index
                break

        rax_origin = []
        xmm0_origin = []

        if write_index is not None:
            rax_origin = find_register_origin(
                lines,
                write_index,
                candidate["base_register"],
            )

            if "%xmm0" in candidate["instruction"].lower():
                xmm0_origin = find_register_origin(
                    lines,
                    write_index,
                    "xmm0",
                )

        result.append(
            {
                "candidate": candidate,
                "function_start": function_start,
                "rax_origin": rax_origin,
                "xmm0_origin": xmm0_origin,
                "window_disassembly": text,
            }
        )

    return result


WRITE_ORIGINS = analyze_write_origins()


# ============================================================
# Explicit special handling of vmovups %xmm0,0xa4(%rax)
# ============================================================

SPECIAL_VMOVUPS = []

for item in WRITE_ORIGINS:
    instruction = item["candidate"]["instruction"]

    if (
        "vmovups" in instruction.lower()
        and "%xmm0" in instruction.lower()
        and "0xa4(%rax)" in instruction.lower()
    ):
        special = dict(item)

        special["classification"] = {
            "width_bytes": 16,
            "store_instruction":
                "vmovups %xmm0,0xa4(%rax)",
            "writes_range":
                "0xA4..0xB3",
            "target_field_start":
                INDEX_FIELD_VA,
            "target_field_end":
                INDEX_FIELD_VA + 15,
        }

        xmm_zero = any(
            ev["kind"] == "XMM0_ZERO"
            for ev in item["xmm0_origin"]
        )

        xmm_load = any(
            ev["kind"] == "XMM0_LOAD_OR_ASSIGN"
            or ev["kind"] == "XMM0_SCALAR_ASSIGN"
            for ev in item["xmm0_origin"]
        )

        if xmm_zero:
            special["value_origin_class"] = "ZERO_INITIALIZATION_CANDIDATE"
        elif xmm_load:
            special["value_origin_class"] = "NONZERO_OR_EXTERNAL_XMM0_SOURCE"
        else:
            special["value_origin_class"] = "UNRESOLVED_XMM0_SOURCE"

        SPECIAL_VMOVUPS.append(
            special
        )


# ============================================================
# Byte-range analysis
# ============================================================

def writes_covering_index(candidate):
    instruction = candidate["instruction"].lower()

    width = 1

    if "vmovups" in instruction:
        width = 16
    elif "vmovdqu" in instruction:
        width = 16
    elif "vmovdqa" in instruction:
        width = 16
    elif "movups" in instruction:
        width = 16
    elif "movdqu" in instruction:
        width = 16
    elif "movdqa" in instruction:
        width = 16
    elif re.search(r"\bmovq\b", instruction):
        width = 8
    elif re.search(r"\bmovl\b|\bcmpl\b", instruction):
        width = 4
    elif re.search(r"\bmovw\b", instruction):
        width = 2
    elif re.search(r"\bmovb\b|\btestb\b", instruction):
        width = 1

    return {
        "start": INDEX_OFFSET,
        "width": width,
        "end_exclusive":
            INDEX_OFFSET + width,
    }


RANGE_ANALYSIS = []

for candidate in INDEX_WRITES:
    range_info = writes_covering_index(
        candidate
    )

    RANGE_ANALYSIS.append(
        {
            "candidate": candidate,
            "range": range_info,
        }
    )


# ============================================================
# Other accesses surrounding A4
# ============================================================

SURROUNDING_FIELD_ACCESS_OFFSETS = [
    0x98,
    0x9C,
    0xA0,
    0xA4,
    0xA8,
    0xAC,
    0xB0,
    0xB4,
]


def scan_surrounding_fields():
    result = []

    for window in WINDOWS:
        lines = parse_disassembly_lines(
            window["disassembly"]
        )

        for line in lines:
            instruction = normalize_instruction(
                line["instruction"]
            )

            operands = extract_memory_operands(
                instruction
            )

            for operand in operands:
                displacement = operand[
                    "displacement"
                ]

                if displacement not in SURROUNDING_FIELD_ACCESS_OFFSETS:
                    continue

                result.append(
                    {
                        "instruction_va":
                            line["va"],
                        "instruction":
                            instruction,
                        "offset":
                            displacement,
                        "context_register":
                            operand["base"],
                        "access_class":
                            "WRITE"
                            if writes_memory(instruction)
                            else
                            "READ_OR_MEMORY",
                    }
                )

    unique = {}

    for item in result:
        key = (
            item["instruction_va"],
            item["offset"],
            item["instruction"],
        )

        unique[key] = item

    return list(unique.values())


SURROUNDING_ACCESSES = scan_surrounding_fields()


# ============================================================
# Read Stage 60 report
# ============================================================

previous_static_path = os.path.join(
    PREVIOUS_RESULTS,
    "stage60_static.json",
)

previous_static = {}

if os.path.isfile(previous_static_path):
    try:
        with open(
            previous_static_path,
            "r",
            encoding="utf-8",
        ) as fp:
            previous_static = json.load(fp)
    except Exception:
        previous_static = {}


# ============================================================
# Semantic-safe conclusions
# ============================================================

index_write_proven = len(
    INDEX_WRITES
) > 0

index_read_proven = len(
    INDEX_READS
) > 0

special_vmovups_found = len(
    SPECIAL_VMOVUPS
) > 0

zero_initialization_candidate = any(
    item.get("value_origin_class")
    == "ZERO_INITIALIZATION_CANDIDATE"
    for item in SPECIAL_VMOVUPS
)

xmm0_origin_resolved = any(
    item.get("value_origin_class")
    != "UNRESOLVED_XMM0_SOURCE"
    for item in SPECIAL_VMOVUPS
)


# It is not safe to call +0xA4 a count/index field merely because
# it participates in a scaled dispatch expression. Stage 61 therefore
# reports the structural role, but deliberately does not upgrade
# semantic naming.

semantic_name_proven = False
count_semantics_proven = False
index_semantics_proven = False


# ============================================================
# Summary
# ============================================================

summary = []

summary.append(
    "AGC PS5 Stage 61 - Dispatch Index (+0xA4) Value Provenance Audit"
)

summary.append("")
summary.append("=== TARGET FIELD ===")
summary.append(
    "global_context = 0x%X"
    % GLOBAL_CONTEXT_VA
)
summary.append(
    "field_offset = 0x%X"
    % INDEX_OFFSET
)
summary.append(
    "field_va = 0x%X"
    % INDEX_FIELD_VA
)

summary.append("")
summary.append("=== STAGE 60 CARRY-FORWARD ===")
summary.append(
    "dispatch_base_offset = 0x%X"
    % DISPATCH_BASE_OFFSET
)
summary.append(
    "dispatch_stride = 0x%X"
    % DISPATCH_STRIDE
)
summary.append(
    "dispatch_expression = global_context + 0x50 + index * 0x78"
)

summary.append("")
summary.append("=== +0xA4 WRITES ===")

if not INDEX_WRITES:
    summary.append("NONE")
else:
    for item in INDEX_WRITES:
        summary.append(
            "VA=0x%X base=%s %s"
            % (
                item["instruction_va"],
                item["base_register"],
                item["instruction"],
            )
        )

summary.append("")
summary.append("=== +0xA4 READS ===")

if not INDEX_READS:
    summary.append("NONE")
else:
    for item in INDEX_READS:
        summary.append(
            "VA=0x%X base=%s %s"
            % (
                item["instruction_va"],
                item["base_register"],
                item["instruction"],
            )
        )

summary.append("")
summary.append("=== SPECIAL vmovups STORE ===")

if not SPECIAL_VMOVUPS:
    summary.append("NONE")
else:
    for item in SPECIAL_VMOVUPS:
        summary.append(
            "VA=0x%X"
            % item["candidate"]["instruction_va"]
        )

        summary.append(
            "instruction = %s"
            % item["candidate"]["instruction"]
        )

        summary.append(
            "range = %s"
            % item["classification"]["writes_range"]
        )

        summary.append(
            "value_origin_class = %s"
            % item["value_origin_class"]
        )

        summary.append(
            "function_start = 0x%X"
            % item["function_start"]
        )

        summary.append(
            "rax_origin_evidence_count = %d"
            % len(item["rax_origin"])
        )

        summary.append(
            "xmm0_origin_evidence_count = %d"
            % len(item["xmm0_origin"])
        )

summary.append("")
summary.append("=== SURROUNDING FIELD ACCESSES ===")

for item in SURROUNDING_ACCESSES:
    summary.append(
        "VA=0x%X offset=0x%X class=%s %s"
        % (
            item["instruction_va"],
            item["offset"],
            item["access_class"],
            item["instruction"],
        )
    )

summary.append("")
summary.append("=== CONCLUSIONS ===")
summary.append(
    "DISPATCH_INDEX_WRITE_PROVEN=%s"
    % index_write_proven
)
summary.append(
    "DISPATCH_INDEX_READ_PROVEN=%s"
    % index_read_proven
)
summary.append(
    "SPECIAL_16_BYTE_INDEX_STORE_FOUND=%s"
    % special_vmovups_found
)
summary.append(
    "XMM0_ORIGIN_PARTIALLY_RESOLVED=%s"
    % xmm0_origin_resolved
)
summary.append(
    "ZERO_INITIALIZATION_CANDIDATE=%s"
    % zero_initialization_candidate
)
summary.append(
    "INDEX_SEMANTICS_PROVEN=%s"
    % index_semantics_proven
)
summary.append(
    "COUNT_SEMANTICS_PROVEN=%s"
    % count_semantics_proven
)
summary.append(
    "EXACT_FIELD_NAME_PROVEN=%s"
    % semantic_name_proven
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
        "index_provenance_summary.txt",
    ),
    "w",
    encoding="utf-8",
    newline="\n",
) as fp:
    fp.write(summary_text)


# ============================================================
# Candidate report
# ============================================================

with open(
    os.path.join(
        OUT_DIR,
        "index_write_candidates.txt",
    ),
    "w",
    encoding="utf-8",
    newline="\n",
) as fp:
    fp.write(
        "AGC PS5 Stage 61 - +0xA4 write candidates\n\n"
    )

    for item in WRITE_ORIGINS:
        candidate = item["candidate"]

        fp.write(
            "==================================================\n"
        )

        fp.write(
            "WRITE VA = 0x%X\n"
            % candidate["instruction_va"]
        )

        fp.write(
            "INSTRUCTION = %s\n"
            % candidate["instruction"]
        )

        fp.write(
            "BASE REGISTER = %s\n"
            % candidate["base_register"]
        )

        fp.write(
            "FIELD VA = 0x%X\n"
            % candidate["field_va"]
        )

        fp.write(
            "FUNCTION START = 0x%X\n"
            % item["function_start"]
        )

        fp.write("\nRAX ORIGIN:\n")

        for evidence in item["rax_origin"]:
            fp.write(
                "  0x%X: %s [%s]\n"
                % (
                    evidence["instruction_va"],
                    evidence["instruction"],
                    evidence["kind"],
                )
            )

        fp.write("\nXMM0 ORIGIN:\n")

        for evidence in item["xmm0_origin"]:
            fp.write(
                "  0x%X: %s [%s]\n"
                % (
                    evidence["instruction_va"],
                    evidence["instruction"],
                    evidence["kind"],
                )
            )

        fp.write("\n")


# ============================================================
# Disassembly report
# ============================================================

with open(
    os.path.join(
        OUT_DIR,
        "index_provenance_disassembly.txt",
    ),
    "w",
    encoding="utf-8",
    newline="\n",
) as fp:
    fp.write(
        "AGC PS5 Stage 61 - +0xA4 Provenance Disassembly\n\n"
    )

    for item in WRITE_ORIGINS:
        candidate = item["candidate"]

        fp.write(
            "==================================================\n"
        )

        fp.write(
            "WRITE VA = 0x%X\n"
            % candidate["instruction_va"]
        )

        fp.write(
            "INSTRUCTION = %s\n"
            % candidate["instruction"]
        )

        fp.write(
            "FUNCTION START = 0x%X\n\n"
            % item["function_start"]
        )

        fp.write(
            item["window_disassembly"]
        )

        fp.write("\n\n")


# ============================================================
# Static JSON
# ============================================================

static = {
    "stage": 61,

    "target": {
        "name": TARGET_NAME,
        "va": TARGET_VA,
        "size": TARGET_SIZE,
    },

    "global_context": {
        "va": GLOBAL_CONTEXT_VA,
    },

    "dispatch_index": {
        "offset": INDEX_OFFSET,
        "va": INDEX_FIELD_VA,
        "dispatch_base_offset":
            DISPATCH_BASE_OFFSET,
        "dispatch_stride":
            DISPATCH_STRIDE,
        "formula":
            "global_context + 0x50 + index * 0x78",
    },

    "previous_stage": {
        "stage": 60,
        "results_path": PREVIOUS_RESULTS,
        "available":
            bool(previous_static),
    },

    "global_leas": GLOBAL_LEAS,

    "index_writes": INDEX_WRITES,

    "index_reads": INDEX_READS,

    "write_origins": WRITE_ORIGINS,

    "special_vmovups": SPECIAL_VMOVUPS,

    "range_analysis": RANGE_ANALYSIS,

    "surrounding_accesses": SURROUNDING_ACCESSES,

    "conclusions": {
        "DISPATCH_INDEX_WRITE_PROVEN":
            index_write_proven,

        "DISPATCH_INDEX_READ_PROVEN":
            index_read_proven,

        "SPECIAL_16_BYTE_INDEX_STORE_FOUND":
            special_vmovups_found,

        "XMM0_ORIGIN_PARTIALLY_RESOLVED":
            xmm0_origin_resolved,

        "ZERO_INITIALIZATION_CANDIDATE":
            zero_initialization_candidate,

        "INDEX_SEMANTICS_PROVEN":
            index_semantics_proven,

        "COUNT_SEMANTICS_PROVEN":
            count_semantics_proven,

        "EXACT_FIELD_NAME_PROVEN":
            semantic_name_proven,

        "BACKEND_CONSUMER_IDENTIFIED":
            False,

        "SEMANTIC_PROTOTYPE_INFERRED":
            False,

        "EXECUTED_AGC":
            False,
    },

    "notes": [
        "Stage 60 established the indirect dispatch expression.",
        "Stage 61 traces the producer of global_context + 0xA4.",
        "The 0xA4 write is analyzed together with its base-register origin.",
        "A 16-byte vmovups store is treated as a range write covering 0xA4..0xB3.",
        "No semantic name is inferred solely from dispatch usage.",
        "Index/count semantics remain unproven unless the producer establishes them independently.",
    ],
}


with open(
    os.path.join(
        OUT_DIR,
        "stage61_static.json",
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


try:
    ELF_FP.close()
except Exception:
    pass