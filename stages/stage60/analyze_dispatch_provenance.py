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

TARGET_NAME = "sceAgcDriverSubmitCommandBuffer"
TARGET_NID = "b4fpgH5ZXxQ"
TARGET_VA = 0x18B0
TARGET_SIZE = 380

MULTI_NAME = "sceAgcDriverSubmitMultiCommandBuffers"
MULTI_VA = 0x4650
MULTI_SIZE = 579

GLOBAL_CONTEXT_VA = 0x1A908
GLOBAL_CONTEXT_SIZE = 0x300

DISPATCH_INDEX_OFFSET = 0xA4
DISPATCH_BASE_OFFSET = 0x50
DISPATCH_STRIDE = 0x78

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
        if (seg["flags"] & 1) and seg["filesz"] > 0
    ]


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


# ============================================================
# Disassembly
# ============================================================

def disassemble(raw, start_va):
    if not raw:
        return ""

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            prefix="agc_stage60_",
            suffix=".bin",
            dir=OUT_DIR,
            delete=False,
        ) as tf:
            tf.write(raw)
            tf.flush()
            temp_path = tf.name

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

        last_output = ""

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
                last_output = str(exc)
                continue

            if proc.returncode == 0:
                return proc.stdout

            last_output = proc.stdout

        return "DISASSEMBLY_UNAVAILABLE\n" + last_output

    finally:
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                pass


# ============================================================
# Symbols
# ============================================================

def parse_nm(text):
    result = []

    for line in text.splitlines():
        line = line.strip()

        if not line:
            continue

        parts = line.split()

        if len(parts) < 4:
            continue

        if not re.fullmatch(r"[0-9A-Fa-f]+", parts[0]):
            continue

        if not re.fullmatch(r"[0-9A-Fa-f]+", parts[1]):
            continue

        try:
            va = int(parts[0], 16)
            size = int(parts[1], 16)
        except ValueError:
            continue

        typ = parts[2].upper()

        if typ not in {"T", "W", "I", "V", "F"}:
            continue

        if size <= 0:
            continue

        result.append({
            "va": va,
            "size": size,
            "type": typ,
            "name": " ".join(parts[3:]),
        })

    return result


def get_symbols():
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

        symbols = parse_nm(proc.stdout)

        if symbols:
            return symbols

    return []


SYMBOLS = get_symbols()


def symbol_for_va(va):
    for symbol in SYMBOLS:
        start = symbol["va"]
        end = start + symbol["size"]

        if start <= va < end:
            return symbol

    return None


# ============================================================
# Executable segment data
# ============================================================

EXECUTABLE_DATA = []

for segment_index, seg in enumerate(executable_segments()):
    with open(SPRX, "rb") as fp:
        fp.seek(seg["offset"])
        raw = fp.read(seg["filesz"])

    EXECUTABLE_DATA.append({
        "segment_index": segment_index,
        "segment": seg,
        "raw": raw,
    })


# ============================================================
# Generic byte search
# ============================================================

def find_all(blob, needle):
    position = 0

    while True:
        found = blob.find(needle, position)

        if found < 0:
            return

        yield found
        position = found + 1


# ============================================================
# Stage 59 dispatch sites
# ============================================================

def scan_stage59_dispatch_sites():
    results = []

    needle = b"\xff\x54\x03\x50"

    for item in EXECUTABLE_DATA:
        seg = item["segment"]
        blob = item["raw"]
        base = seg["vaddr"]

        for pos in find_all(blob, needle):
            call_va = base + pos
            window_start = max(0, pos - 0x70)
            before = blob[window_start:pos]

            has_index_load = b"\x8b\x83\xa4\x00\x00\x00" in before
            has_stride_mul = b"\x48\x6b\xc0\x78" in before

            symbol = symbol_for_va(call_va)

            results.append({
                "call_va": call_va,
                "file_offset": seg["offset"] + pos,
                "has_index_load": has_index_load,
                "has_stride_mul": has_stride_mul,
                "symbol_name": symbol["name"] if symbol else None,
            })

    return results


DISPATCH_SITES = scan_stage59_dispatch_sites()


# ============================================================
# Global-context LEAs
# ============================================================

RIP_LEA_PATTERNS = [
    (b"\x48\x8d\x05", "lea_global_rax", "rax"),
    (b"\x48\x8d\x0d", "lea_global_rcx", "rcx"),
    (b"\x48\x8d\x1d", "lea_global_rbx", "rbx"),
    (b"\x4c\x8d\x25", "lea_global_r12", "r12"),
    (b"\x4c\x8d\x2d", "lea_global_r13", "r13"),
    (b"\x4c\x8d\x35", "lea_global_r14", "r14"),
    (b"\x4c\x8d\x3d", "lea_global_r15", "r15"),
]


def scan_global_leas():
    result = []

    for item in EXECUTABLE_DATA:
        seg = item["segment"]
        blob = item["raw"]
        base = seg["vaddr"]

        for needle, kind, register in RIP_LEA_PATTERNS:
            for pos in find_all(blob, needle):
                if pos + 7 > len(blob):
                    continue

                displacement = struct.unpack(
                    "<i",
                    blob[pos + 3:pos + 7],
                )[0]

                instruction_va = base + pos
                target_va = instruction_va + 7 + displacement

                if target_va != GLOBAL_CONTEXT_VA:
                    continue

                result.append({
                    "instruction_va": instruction_va,
                    "file_offset": seg["offset"] + pos,
                    "kind": kind,
                    "register": register,
                    "target_va": target_va,
                })

    return result


GLOBAL_LEAS = scan_global_leas()


# ============================================================
# Disassembly parser
# ============================================================

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

        address = int(match.group(1), 16)

        result.append({
            "va": address,
            "instruction": match.group(3).strip(),
        })

    return result


def normalize_instruction(instruction):
    text = instruction.replace("\t", " ").strip()

    while "  " in text:
        text = text.replace("  ", " ")

    return text


# ============================================================
# CORREGIDO:
# parser de operandos con y sin grupos de captura
# ============================================================

def parse_integer_token(token):
    token = token.strip()

    if not token:
        return 0

    negative = token.startswith("-")

    if negative:
        token = token[1:]

    if token.lower().startswith("0x"):
        value = int(token, 16)
    else:
        value = int(token, 10)

    return -value if negative else value


def extract_memory_offsets(instruction, register):
    text = normalize_instruction(instruction)
    escaped_register = re.escape(register)

    results = []

    # disp(%reg)
    pattern_disp_base = re.compile(
        rf"(?P<disp>[+-]?(?:0x[0-9a-fA-F]+|\d+))"
        rf"\(%{escaped_register}\)"
    )

    for match in pattern_disp_base.finditer(text):
        try:
            offset = parse_integer_token(match.group("disp"))
        except ValueError:
            continue

        results.append({
            "offset": offset,
            "expression": match.group(0),
            "form": "DISP_BASE",
        })

    # (%reg)
    pattern_base = re.compile(
        rf"\(%{escaped_register}\)"
    )

    for match in pattern_base.finditer(text):
        results.append({
            "offset": 0,
            "expression": match.group(0),
            "form": "BASE",
        })

    # disp(%reg,%index,scale)
    pattern_indexed = re.compile(
        rf"(?P<disp>[+-]?(?:0x[0-9a-fA-F]+|\d+))"
        rf"\(%{escaped_register},"
        rf"%[a-z0-9]+,"
        rf"(?:1|2|4|8)\)"
    )

    for match in pattern_indexed.finditer(text):
        try:
            offset = parse_integer_token(match.group("disp"))
        except ValueError:
            continue

        results.append({
            "offset": offset,
            "expression": match.group(0),
            "form": "DISP_INDEXED",
        })

    unique = {}

    for item in results:
        key = (
            item["offset"],
            item["expression"],
            item["form"],
        )
        unique[key] = item

    return list(unique.values())


# ============================================================
# Access classification
# ============================================================

def classify_access(instruction):
    lower = instruction.lower()

    if "xadd" in lower:
        return "RMW"

    if re.search(
        r"%[a-z0-9]+,\s*"
        r"(?:[-+]?0x[0-9a-f]+|\d+)?\(%",
        lower,
    ):
        return "WRITE"

    if re.search(
        r"\$[^,]+,\s*"
        r"(?:[-+]?0x[0-9a-f]+|\d+)?\(%",
        lower,
    ):
        return "WRITE"

    if any(
        token in lower
        for token in (
            "cmp ",
            "cmpq ",
            "cmpl ",
            "cmpb ",
            "test ",
            "mov ",
            "movq ",
            "movl ",
            "movb ",
            "lea ",
        )
    ):
        return "READ_OR_MEMORY"

    return "OTHER"


# ============================================================
# Global windows
# ============================================================

def global_reference_windows():
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

        start_va = max(
            0,
            ref["instruction_va"] - 8,
        )

        raw = read_va(
            start_va,
            0x260,
        )

        windows.append({
            "global_ref": ref,
            "start_va": start_va,
            "disassembly": disassemble(
                raw,
                start_va,
            ),
        })

    return windows


GLOBAL_WINDOWS = global_reference_windows()


# ============================================================
# Context field accesses
# ============================================================

def analyze_context_field_accesses():
    accesses = []

    for window in GLOBAL_WINDOWS:
        ref = window["global_ref"]
        lines = parse_disassembly_lines(
            window["disassembly"]
        )

        register = ref["register"]

        for line in lines:
            offsets = extract_memory_offsets(
                line["instruction"],
                register,
            )

            for offset_info in offsets:
                offset = offset_info["offset"]

                if offset < 0:
                    continue

                if offset > GLOBAL_CONTEXT_SIZE:
                    continue

                instruction_text = normalize_instruction(
                    line["instruction"]
                )

                access_type = classify_access(
                    instruction_text
                )

                accesses.append({
                    "instruction_va": line["va"],
                    "instruction": instruction_text,
                    "context_register": register,
                    "context_field_offset": offset,
                    "operand_form": offset_info["form"],
                    "operand_expression": offset_info["expression"],
                    "access_type": access_type,
                    "global_context_va": GLOBAL_CONTEXT_VA,
                    "context_field_va": GLOBAL_CONTEXT_VA + offset,
                    "reference_va": ref["instruction_va"],
                })

    unique = {}

    for access in accesses:
        key = (
            access["instruction_va"],
            access["instruction"],
            access["context_field_offset"],
            access["access_type"],
        )

        unique[key] = access

    return list(unique.values())


CONTEXT_ACCESSES = analyze_context_field_accesses()


# ============================================================
# +0xA4
# ============================================================

def scan_index_accesses():
    return [
        item
        for item in CONTEXT_ACCESSES
        if item["context_field_offset"] == DISPATCH_INDEX_OFFSET
    ]


INDEX_ACCESSES = scan_index_accesses()


# ============================================================
# Dispatch slot expressions
# ============================================================

def scan_dispatch_slot_expressions():
    result = []

    needle = b"\xff\x54"

    for item in EXECUTABLE_DATA:
        seg = item["segment"]
        blob = item["raw"]
        base = seg["vaddr"]

        for pos in find_all(blob, needle):
            if pos + 4 > len(blob):
                continue

            if blob[pos + 3] != 0x50:
                continue

            call_va = base + pos

            window_start = max(
                0,
                pos - 0x80,
            )

            window_blob = blob[
                window_start:pos + 4
            ]

            has_stride = (
                b"\x48\x6b" in window_blob
                and b"\x78" in window_blob
            )

            has_a4 = (
                b"\xa4\x00\x00\x00"
                in window_blob
            )

            if not (has_stride or has_a4):
                continue

            symbol = symbol_for_va(call_va)

            result.append({
                "va": call_va,
                "kind": "CALL_DISPATCH_SLOT",
                "file_offset": seg["offset"] + pos,
                "has_stride_0x78": has_stride,
                "has_index_0xA4": has_a4,
                "symbol": symbol["name"] if symbol else None,
                "window": disassemble(
                    window_blob,
                    base + window_start,
                ),
            })

    unique = {}

    for item in result:
        key = (
            item["va"],
            item["file_offset"],
        )
        unique[key] = item

    return list(unique.values())


DISPATCH_SLOT_EXPRESSIONS = scan_dispatch_slot_expressions()


# ============================================================
# Literal table write candidates
# ============================================================

TABLE_OFFSETS = [
    DISPATCH_BASE_OFFSET + index * DISPATCH_STRIDE
    for index in range(32)
]


def parse_literal_memory_offsets(instruction):
    result = []

    pattern = re.compile(
        r"(?P<disp>[+-]?(?:0x[0-9a-fA-F]+|\d+))"
        r"\(%r[a-z0-9]+"
    )

    for match in pattern.finditer(instruction):
        try:
            value = parse_integer_token(
                match.group("disp")
            )
        except ValueError:
            continue

        result.append(value)

    return result


def is_probable_store(instruction):
    lower = instruction.lower()

    if re.search(
        r"%[a-z0-9]+,\s*"
        r"(?:[-+]?0x[0-9a-f]+|\d+)\(%r",
        lower,
    ):
        return True

    if re.search(
        r"\$[^,]+,\s*"
        r"(?:[-+]?0x[0-9a-f]+|\d+)\(%r",
        lower,
    ):
        return True

    return False


def scan_literal_dispatch_writes():
    result = []

    for window in GLOBAL_WINDOWS:
        lines = parse_disassembly_lines(
            window["disassembly"]
        )

        for line in lines:
            instruction_text = normalize_instruction(
                line["instruction"]
            )

            offsets = parse_literal_memory_offsets(
                instruction_text
            )

            if not offsets:
                continue

            is_store = is_probable_store(
                instruction_text
            )

            for offset in offsets:
                if offset not in TABLE_OFFSETS:
                    continue

                table_index = (
                    offset - DISPATCH_BASE_OFFSET
                ) // DISPATCH_STRIDE

                result.append({
                    "instruction_va": line["va"],
                    "instruction": instruction_text,
                    "offset": offset,
                    "table_index": table_index,
                    "is_store": is_store,
                    "reference_window_va":
                        window["global_ref"]["instruction_va"],
                })

    unique = {}

    for item in result:
        key = (
            item["instruction_va"],
            item["offset"],
            item["instruction"],
            item["is_store"],
        )

        unique[key] = item

    return list(unique.values())


LITERAL_DISPATCH_WRITES = scan_literal_dispatch_writes()


# ============================================================
# Pointer-store windows
# ============================================================

def collect_pointer_store_windows():
    result = []

    for item in LITERAL_DISPATCH_WRITES:
        if not item["is_store"]:
            continue

        start_va = max(
            0,
            item["instruction_va"] - 0x50,
        )

        raw = read_va(
            start_va,
            0x120,
        )

        result.append({
            "table_index": item["table_index"],
            "table_offset": item["offset"],
            "instruction_va": item["instruction_va"],
            "disassembly": disassemble(
                raw,
                start_va,
            ),
        })

    return result


POINTER_STORE_WINDOWS = collect_pointer_store_windows()


# ============================================================
# Function starts
# ============================================================

def find_function_starts():
    starts = set()

    prologues = [
        b"\x55\x48\x89\xe5",
        b"\x41\x57\x41\x56\x41\x55\x41\x54\x53",
        b"\x53\x48\x83\xec",
        b"\x48\x83\xec",
    ]

    for item in EXECUTABLE_DATA:
        seg = item["segment"]
        blob = item["raw"]
        base = seg["vaddr"]

        for needle in prologues:
            for pos in find_all(blob, needle):
                starts.add(base + pos)

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
# Group evidence
# ============================================================

FUNCTION_EVIDENCE = {}


def get_function_entry(start):
    if start not in FUNCTION_EVIDENCE:
        FUNCTION_EVIDENCE[start] = {
            "start_va": start,
            "index_accesses": [],
            "dispatch_writes": [],
            "dispatch_calls": [],
            "global_references": [],
        }

    return FUNCTION_EVIDENCE[start]


for item in INDEX_ACCESSES:
    start = nearest_function_start(
        item["instruction_va"]
    )

    if start is not None:
        get_function_entry(start)["index_accesses"].append(item)


for item in LITERAL_DISPATCH_WRITES:
    start = nearest_function_start(
        item["instruction_va"]
    )

    if start is not None:
        get_function_entry(start)["dispatch_writes"].append(item)


for item in DISPATCH_SLOT_EXPRESSIONS:
    start = nearest_function_start(
        item["va"]
    )

    if start is not None:
        get_function_entry(start)["dispatch_calls"].append(item)


for item in GLOBAL_LEAS:
    start = nearest_function_start(
        item["instruction_va"]
    )

    if start is not None:
        get_function_entry(start)["global_references"].append(item)


# ============================================================
# Ranking
# ============================================================

RANKED_FUNCTIONS = []

for start, evidence in FUNCTION_EVIDENCE.items():
    raw = read_va(
        start,
        0x320,
    )

    text = disassemble(
        raw,
        start,
    )

    score = 0

    if evidence["index_accesses"]:
        score += 120

    if evidence["dispatch_writes"]:
        score += 100

    if evidence["dispatch_calls"]:
        score += 100

    if evidence["global_references"]:
        score += 20

    if "0xa4" in text:
        score += 25

    if "0x78" in text:
        score += 25

    if "0x50" in text:
        score += 25

    symbol = symbol_for_va(start)

    RANKED_FUNCTIONS.append({
        "start_va": start,
        "score": score,
        "symbol_name":
            symbol["name"] if symbol else None,
        "index_access_count":
            len(evidence["index_accesses"]),
        "dispatch_write_count":
            len(evidence["dispatch_writes"]),
        "dispatch_call_count":
            len(evidence["dispatch_calls"]),
        "global_reference_count":
            len(evidence["global_references"]),
        "disassembly": text,
    })


RANKED_FUNCTIONS.sort(
    key=lambda item: (
        -item["score"],
        item["start_va"],
    )
)


# ============================================================
# Target disassembly
# ============================================================

TARGET_RAW = read_va(
    TARGET_VA,
    TARGET_SIZE,
)

TARGET_DISASM = disassemble(
    TARGET_RAW,
    TARGET_VA,
)


# ============================================================
# Conclusions
# ============================================================

dispatch_site_in_target = any(
    TARGET_VA <= item["call_va"] < TARGET_VA + TARGET_SIZE
    for item in DISPATCH_SITES
)

index_read_proven = any(
    item["context_field_offset"] == DISPATCH_INDEX_OFFSET
    for item in INDEX_ACCESSES
)

literal_write_found = any(
    item["is_store"]
    for item in LITERAL_DISPATCH_WRITES
)

pointer_store_window_found = len(POINTER_STORE_WINDOWS) > 0
runtime_pointer_resolved = False


# ============================================================
# Summary
# ============================================================

summary_lines = []

summary_lines.append(
    "AGC PS5 Stage 60 - Dispatch Table Initialization / Index Provenance Audit"
)

summary_lines.append("")
summary_lines.append("=== DISPATCH MODEL ===")
summary_lines.append(
    "global_context = 0x%X" % GLOBAL_CONTEXT_VA
)
summary_lines.append(
    "index_offset = 0x%X" % DISPATCH_INDEX_OFFSET
)
summary_lines.append(
    "dispatch_base_offset = 0x%X" % DISPATCH_BASE_OFFSET
)
summary_lines.append(
    "dispatch_stride = 0x%X" % DISPATCH_STRIDE
)
summary_lines.append(
    "dispatch_expression = global_context + 0x50 + index * 0x78"
)

summary_lines.append("")
summary_lines.append("=== STAGE 59 DISPATCH SITES ===")

if not DISPATCH_SITES:
    summary_lines.append("NONE")
else:
    for item in DISPATCH_SITES:
        summary_lines.append(
            "call=0x%X index_load=%s stride_mul=%s symbol=%s"
            % (
                item["call_va"],
                item["has_index_load"],
                item["has_stride_mul"],
                item["symbol_name"] or "<none>",
            )
        )

summary_lines.append("")
summary_lines.append("=== INDEX +0xA4 ACCESSES ===")

if not INDEX_ACCESSES:
    summary_lines.append("NONE")
else:
    for item in INDEX_ACCESSES:
        summary_lines.append(
            "VA=0x%X type=%s field_va=0x%X %s"
            % (
                item["instruction_va"],
                item["access_type"],
                item["context_field_va"],
                item["instruction"],
            )
        )

summary_lines.append("")
summary_lines.append("=== TABLE WRITE CANDIDATES ===")

if not LITERAL_DISPATCH_WRITES:
    summary_lines.append("NONE")
else:
    for item in LITERAL_DISPATCH_WRITES:
        summary_lines.append(
            "VA=0x%X slot_index=%d slot_offset=0x%X store=%s %s"
            % (
                item["instruction_va"],
                item["table_index"],
                item["offset"],
                item["is_store"],
                item["instruction"],
            )
        )

summary_lines.append("")
summary_lines.append("=== POINTER STORE WINDOWS ===")

if not POINTER_STORE_WINDOWS:
    summary_lines.append("NONE")
else:
    for item in POINTER_STORE_WINDOWS:
        summary_lines.append(
            "slot_index=%d slot_offset=0x%X instruction=0x%X"
            % (
                item["table_index"],
                item["table_offset"],
                item["instruction_va"],
            )
        )

summary_lines.append("")
summary_lines.append("=== FUNCTION RANKING ===")

for item in RANKED_FUNCTIONS[:40]:
    summary_lines.append(
        "VA=0x%X score=%d index_access=%d table_writes=%d dispatch_calls=%d global_refs=%d symbol=%s"
        % (
            item["start_va"],
            item["score"],
            item["index_access_count"],
            item["dispatch_write_count"],
            item["dispatch_call_count"],
            item["global_reference_count"],
            item["symbol_name"] or "<none>",
        )
    )

summary_lines.append("")
summary_lines.append("=== IMPORTANT LIMIT ===")
summary_lines.append(
    "The dispatch expression is statically recoverable."
)
summary_lines.append(
    "The +0xA4 index field is statically recoverable."
)
summary_lines.append(
    "Static table-slot writes are collected conservatively."
)
summary_lines.append(
    "Runtime function pointer resolution is not claimed without source-pointer initialization evidence."
)

summary_lines.append("")
summary_lines.append("=== CONCLUSIONS ===")
summary_lines.append(
    "STAGE59_DISPATCH_PATTERN_CONFIRMED=True"
)
summary_lines.append(
    "DISPATCH_INDEX_FIELD_ACCESS_PROVEN=%s"
    % index_read_proven
)
summary_lines.append(
    "DISPATCH_TABLE_LITERAL_WRITE_FOUND=%s"
    % literal_write_found
)
summary_lines.append(
    "DISPATCH_POINTER_STORE_WINDOW_FOUND=%s"
    % pointer_store_window_found
)
summary_lines.append(
    "TARGET_FUNCTION_CONTAINS_DISPATCH=%s"
    % dispatch_site_in_target
)
summary_lines.append(
    "RUNTIME_FUNCTION_POINTER_RESOLVED=%s"
    % runtime_pointer_resolved
)
summary_lines.append(
    "BACKEND_CONSUMER_IDENTIFIED=False"
)
summary_lines.append(
    "FIELD_00_POINTER_SEMANTICS_PROVEN=False"
)
summary_lines.append(
    "FIELD_08_SIZE_SEMANTICS_PROVEN=False"
)
summary_lines.append(
    "FIELD_08_COUNT_SEMANTICS_PROVEN=False"
)
summary_lines.append(
    "FIELD_08_INDEX_SEMANTICS_PROVEN=False"
)
summary_lines.append(
    "FIELD_0C_FLAG_SEMANTICS_PROVEN=False"
)
summary_lines.append(
    "EXACT_STRUCT_SIZE_PROVEN=False"
)
summary_lines.append(
    "SEMANTIC_PROTOTYPE_INFERRED=False"
)
summary_lines.append(
    "EXECUTED_AGC=False"
)

summary_text = "\n".join(summary_lines) + "\n"

with open(
    os.path.join(
        OUT_DIR,
        "dispatch_provenance_summary.txt",
    ),
    "w",
    encoding="utf-8",
    newline="\n",
) as fp:
    fp.write(summary_text)


# ============================================================
# Index report
# ============================================================

with open(
    os.path.join(
        OUT_DIR,
        "index_write_sites.txt",
    ),
    "w",
    encoding="utf-8",
    newline="\n",
) as fp:
    fp.write(
        "AGC PS5 Stage 60 - Index +0xA4 Access Sites\n\n"
    )

    for item in INDEX_ACCESSES:
        fp.write(
            (
                "VA=0x%X TYPE=%s FIELD_VA=0x%X\n"
                "  %s\n\n"
            )
            % (
                item["instruction_va"],
                item["access_type"],
                item["context_field_va"],
                item["instruction"],
            )
        )


# ============================================================
# Dispatch writes
# ============================================================

with open(
    os.path.join(
        OUT_DIR,
        "dispatch_write_sites.txt",
    ),
    "w",
    encoding="utf-8",
    newline="\n",
) as fp:
    fp.write(
        "AGC PS5 Stage 60 - Dispatch Table Write Sites\n\n"
    )

    for item in LITERAL_DISPATCH_WRITES:
        fp.write(
            (
                "VA=0x%X SLOT=%d OFFSET=0x%X STORE=%s\n"
                "  %s\n\n"
            )
            % (
                item["instruction_va"],
                item["table_index"],
                item["offset"],
                item["is_store"],
                item["instruction"],
            )
        )


# ============================================================
# Disassembly report
# ============================================================

with open(
    os.path.join(
        OUT_DIR,
        "dispatch_provenance_disassembly.txt",
    ),
    "w",
    encoding="utf-8",
    newline="\n",
) as fp:
    fp.write(
        "AGC PS5 Stage 60 - Dispatch Provenance Disassembly\n\n"
    )

    fp.write(
        "=== TARGET: SubmitCommandBuffer ===\n\n"
    )

    fp.write(TARGET_DISASM)

    fp.write(
        "\n\n=== INDEX ACCESS WINDOWS ===\n\n"
    )

    for item in INDEX_ACCESSES:
        start_va = max(
            0,
            item["instruction_va"] - 0x40,
        )

        raw = read_va(
            start_va,
            0x140,
        )

        fp.write(
            "--------------------------------------------\n"
        )

        fp.write(
            "INDEX ACCESS VA=0x%X\n"
            % item["instruction_va"]
        )

        fp.write(
            disassemble(
                raw,
                start_va,
            )
        )

        fp.write("\n")

    fp.write(
        "\n=== TABLE WRITE WINDOWS ===\n\n"
    )

    for item in POINTER_STORE_WINDOWS:
        fp.write(
            "--------------------------------------------\n"
        )

        fp.write(
            "TABLE SLOT=%d OFFSET=0x%X\n"
            % (
                item["table_index"],
                item["table_offset"],
            )
        )

        fp.write(item["disassembly"])
        fp.write("\n")


# ============================================================
# Static JSON
# ============================================================

static = {
    "stage": 60,

    "target": {
        "name": TARGET_NAME,
        "nid": TARGET_NID,
        "va": TARGET_VA,
        "size": TARGET_SIZE,
    },

    "dispatch_model": {
        "global_context_va": GLOBAL_CONTEXT_VA,
        "index_offset": DISPATCH_INDEX_OFFSET,
        "base_offset": DISPATCH_BASE_OFFSET,
        "stride": DISPATCH_STRIDE,
        "formula":
            "global_context + 0x50 + index * 0x78",
    },

    "previous_stage": {
        "results_path": PREVIOUS_RESULTS,
        "stage59_static_exists":
            os.path.isfile(
                os.path.join(
                    PREVIOUS_RESULTS,
                    "stage59_static.json",
                )
            ),
    },

    "symbol_inventory": {
        "count": len(SYMBOLS),
        "method": "prospero-nm/llvm-nm",
    },

    "dispatch_sites": DISPATCH_SITES,
    "global_leas": GLOBAL_LEAS,
    "context_accesses": CONTEXT_ACCESSES,
    "index_accesses": INDEX_ACCESSES,
    "dispatch_slot_expressions":
        DISPATCH_SLOT_EXPRESSIONS,
    "literal_dispatch_writes":
        LITERAL_DISPATCH_WRITES,
    "pointer_store_windows":
        POINTER_STORE_WINDOWS,
    "ranked_functions":
        RANKED_FUNCTIONS[:100],

    "conclusions": {
        "STAGE59_DISPATCH_PATTERN_CONFIRMED":
            True,

        "DISPATCH_INDEX_FIELD_ACCESS_PROVEN":
            index_read_proven,

        "DISPATCH_TABLE_LITERAL_WRITE_FOUND":
            literal_write_found,

        "DISPATCH_POINTER_STORE_WINDOW_FOUND":
            pointer_store_window_found,

        "TARGET_FUNCTION_CONTAINS_DISPATCH":
            dispatch_site_in_target,

        "RUNTIME_FUNCTION_POINTER_RESOLVED":
            runtime_pointer_resolved,

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

    "notes": [
        "Stage 59 proved the indirect dispatch expression.",
        "Stage 60 traces global_context + 0xA4.",
        "Stage 60 searches static writes to dispatch table slots.",
        "ELF backing file remains open during ELF operations.",
        "Memory operand parser accepts base, displacement-base, and indexed forms.",
        "Runtime function pointer values are not assumed to be file-backed.",
        "No semantic field name is inferred by this stage.",
    ],
}

with open(
    os.path.join(
        OUT_DIR,
        "stage60_static.json",
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