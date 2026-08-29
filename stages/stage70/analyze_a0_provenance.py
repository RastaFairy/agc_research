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

TARGET_NAME = "sceAgcDriverSubmitCommandBuffer"
TARGET_NID = "b4fpgH5ZXxQ"

GLOBAL_CONTEXT_VA = 0x1A908
FIELD_OFFSET = 0xA0
FIELD_VA = GLOBAL_CONTEXT_VA + FIELD_OFFSET

A4_OFFSET = 0xA4

SUBMIT_VA = 0x18B0
SUBMIT_SIZE = 380

MULTI_VA = 0x4650
MULTI_SIZE = 579

TABLE_STRIDE = 0x78


def load_previous_stage():
    candidates = [
        PREVIOUS_DIR / "stage69_static.json",
        PREVIOUS_DIR / "STAGE69_REPORT.json",
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


def load_segments():
    with SPRX.open("rb") as fp:
        elf = ELFFile(fp)

        segments = []

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


def is_executable(flags):
    return bool(flags & 0x1)


def read_segment(seg):
    with SPRX.open("rb") as fp:
        fp.seek(seg["offset"])
        return fp.read(seg["filesz"])


def write_temp_segment(seg, index):
    path = OUTPUT_DIR / "stage70_segment_{:02d}.bin".format(index)
    path.write_bytes(read_segment(seg))
    return path


def disassemble_segment(seg, index):
    path = write_temp_segment(seg, index)

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
        out = subprocess.check_output(
            cmd,
            stderr=subprocess.STDOUT,
            text=True,
        )
    finally:
        try:
            path.unlink()
        except Exception:
            pass

    return out


def parse_disassembly(disasm):
    rows = []

    pattern = re.compile(
        r"^\s*([0-9a-f]+):\s+"
        r"((?:[0-9a-f]{2}\s+)+)"
        r"\s*(.*)$",
        re.IGNORECASE,
    )

    for line in disasm.splitlines():
        match = pattern.match(line)

        if not match:
            continue

        va = int(match.group(1), 16)

        raw_bytes = []

        for token in match.group(2).strip().split():
            try:
                raw_bytes.append(int(token, 16))
            except ValueError:
                pass

        rows.append(
            {
                "va": va,
                "bytes": raw_bytes,
                "instruction": match.group(3).strip(),
            }
        )

    return rows


def normalize(ins):
    return re.sub(r"\s+", " ", ins.strip().lower())


def is_memory_operand_for_a0(ins):
    return "0xa0(" in normalize(ins)


def looks_like_read(ins):
    low = normalize(ins)

    if low.startswith("mov "):
        operands = low.split(" ", 1)[1]
        if "," in operands:
            src, dst = operands.split(",", 1)
            if "0xa0(" in src and "0xa0(" not in dst:
                return True

    prefixes = (
        "test ",
        "cmp ",
        "add ",
        "sub ",
        "and ",
        "or ",
        "xor ",
        "imul ",
    )

    if low.startswith(prefixes) and "0xa0(" in low:
        return True

    return False


def looks_like_store(ins):
    low = normalize(ins)

    if "0xa0(" not in low:
        return False

    if not low.startswith(
        (
            "mov ",
            "movb ",
            "movw ",
            "movl ",
            "movq ",
            "movups ",
            "vmovups ",
            "vmovdqu ",
        )
    ):
        return False

    if " " not in low:
        return False

    operands = low.split(" ", 1)[1]

    if "," not in operands:
        return False

    src, dst = operands.split(",", 1)

    return "0xa0(" in dst and "0xa0(" not in src


def is_immediate_store(ins):
    low = normalize(ins)

    if "0xa0(" not in low:
        return None

    pattern = re.compile(
        r"^mov(?:b|w|l|q)?\s+\$"
        r"(0x[0-9a-f]+|[0-9]+),"
        r".*0xa0\(",
        re.IGNORECASE,
    )

    match = pattern.match(low)

    if not match:
        return None

    raw_value = match.group(1)

    if raw_value.lower().startswith("0x"):
        return int(raw_value, 16)

    return int(raw_value, 10)


def extract_mem_base(ins):
    low = normalize(ins)

    match = re.search(
        r"0xa0\(%([a-z0-9]+)\)",
        low,
        re.IGNORECASE,
    )

    if not match:
        return None

    return match.group(1)


def extract_lea_global(ins):
    low = normalize(ins)

    if not low.startswith("lea "):
        return None

    if "# 0x1a908" not in low:
        return None

    match = re.search(
        r",%([a-z0-9]+)",
        low,
        re.IGNORECASE,
    )

    if not match:
        return None

    return match.group(1)


def owner_from_symbol_table(va):
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

            best = None

            for section in sections:
                for sym in section.iter_symbols():
                    if sym["st_info"]["type"] != "STT_FUNC":
                        continue

                    start = int(sym["st_value"])
                    size = int(sym["st_size"])

                    if size <= 0:
                        continue

                    if start <= va < start + size:
                        candidate = {
                            "name": sym.name,
                            "start_va": start,
                            "size": size,
                        }

                        if best is None:
                            best = candidate

            return best

    except Exception:
        return None


def find_nearest_global_lea(rows, index, base_register, lookback=64):
    start = max(0, index - lookback)

    for j in range(index - 1, start - 1, -1):
        reg = extract_lea_global(rows[j]["instruction"])

        if reg is not None:
            if reg == base_register:
                return {
                    "va": rows[j]["va"],
                    "instruction": rows[j]["instruction"],
                    "register": reg,
                    "distance_instructions": index - j,
                }

        current = normalize(rows[j]["instruction"])

        # Operaciones que escriben el mismo registro rompen la
        # procedencia inmediata.
        if re.search(
            r"\b(?:mov|lea|xor|sub|add|and|or)\b.*,%{}".format(
                re.escape(base_register)
            ),
            current,
        ):
            break

    return None


def analyze_accesses(rows):
    accesses = []

    for index, row in enumerate(rows):
        ins = row["instruction"]

        if not is_memory_operand_for_a0(ins):
            continue

        immediate = is_immediate_store(ins)

        if immediate is not None:
            access_type = "STORE_IMMEDIATE"
        elif looks_like_store(ins):
            access_type = "STORE"
        elif looks_like_read(ins):
            access_type = "READ"
        else:
            access_type = "OTHER"

        base = extract_mem_base(ins)

        if base is not None:
            lea = find_nearest_global_lea(
                rows,
                index,
                base,
            )
        else:
            lea = None

        accesses.append(
            {
                "instruction_va": row["va"],
                "instruction": ins,
                "base_register": base,
                "owner": owner_from_symbol_table(row["va"]),
                "access_type": access_type,
                "immediate_value": immediate,
                "global_context_proven": lea is not None,
                "global_context_lea": lea,
            }
        )

    return accesses


def find_window(rows, va, before=10, after=14):
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


def make_window(rows, va, before=10, after=14):
    """
    Compatibilidad explícita con llamadas antiguas.
    La causa del fallo anterior era que se definía find_window()
    y se invocaba make_window().
    """
    return find_window(
        rows,
        va,
        before=before,
        after=after,
    )


def make_window_text(rows):
    return "\n".join(
        "{:08x}: {}".format(
            row["va"],
            row["instruction"],
        )
        for row in rows
    )


# ============================================================
# Desensamblar segmentos ejecutables
# ============================================================

all_rows = []
segment_disassemblies = []

for index, seg in enumerate(SEGMENTS):
    if not is_executable(seg["flags"]):
        continue

    disasm = disassemble_segment(seg, index)

    segment_disassemblies.append(
        {
            "segment": seg,
            "disassembly": disasm,
        }
    )

    all_rows.extend(
        parse_disassembly(disasm)
    )

all_rows.sort(key=lambda x: x["va"])

A0_ACCESSES = analyze_accesses(all_rows)

A0_READS = [
    x for x in A0_ACCESSES
    if x["access_type"] == "READ"
]

A0_STORES = [
    x for x in A0_ACCESSES
    if x["access_type"] in (
        "STORE",
        "STORE_IMMEDIATE",
    )
]

A0_IMMEDIATE_STORES = [
    x for x in A0_ACCESSES
    if x["access_type"] == "STORE_IMMEDIATE"
]

GLOBAL_A0_STORES = [
    x for x in A0_STORES
    if x["global_context_proven"]
]

GLOBAL_A0_READS = [
    x for x in A0_READS
    if x["global_context_proven"]
]

initializer_candidates = sorted(
    [
        x for x in A0_IMMEDIATE_STORES
        if x["global_context_proven"]
    ],
    key=lambda x: x["instruction_va"],
)

initializer = (
    initializer_candidates[0]
    if initializer_candidates
    else None
)

initializer_value = (
    initializer["immediate_value"]
    if initializer is not None
    else None
)

post_init_stores = []

if initializer is not None:
    init_va = initializer["instruction_va"]

    post_init_stores = [
        x for x in GLOBAL_A0_STORES
        if x["instruction_va"] > init_va
    ]


SUBMIT_ACCESSES = [
    x for x in A0_ACCESSES
    if SUBMIT_VA <= x["instruction_va"] < SUBMIT_VA + SUBMIT_SIZE
]

MULTI_ACCESSES = [
    x for x in A0_ACCESSES
    if MULTI_VA <= x["instruction_va"] < MULTI_VA + MULTI_SIZE
]

SUBMIT_READS = [
    x for x in SUBMIT_ACCESSES
    if x["access_type"] == "READ"
]

MULTI_READS = [
    x for x in MULTI_ACCESSES
    if x["access_type"] == "READ"
]


# ============================================================
# Cargar Stage 69
# ============================================================

PREVIOUS = load_previous_stage()


def extract_previous_conclusions(obj):
    if not isinstance(obj, dict):
        return {}

    result = {}

    conclusions = obj.get("conclusions")

    if isinstance(conclusions, dict):
        result.update(conclusions)

    result_obj = obj.get("result")

    if isinstance(result_obj, dict):
        nested = result_obj.get("conclusions")

        if isinstance(nested, dict):
            result.update(nested)

        result.update(
            {
                k: v
                for k, v in result_obj.items()
                if k.isupper()
            }
        )

    return result


PREVIOUS_CONCLUSIONS = extract_previous_conclusions(PREVIOUS)

stage69_count_proven = bool(
    PREVIOUS_CONCLUSIONS.get(
        "COUNT_SEMANTICS_PROVEN",
        False,
    )
)

stage69_submit_dispatch = bool(
    PREVIOUS_CONCLUSIONS.get(
        "SUBMIT_A4_DISPATCH_CONFIRMED",
        False,
    )
)

stage69_multi_dispatch = bool(
    PREVIOUS_CONCLUSIONS.get(
        "MULTI_A4_DISPATCH_CONFIRMED",
        False,
    )
)


a0_global_store_found = (
    len(GLOBAL_A0_STORES) > 0
)

a0_initialization_proven = (
    initializer is not None
    and initializer_value is not None
)

a0_initial_value_is_one = (
    a0_initialization_proven
    and initializer_value == 1
)

a0_post_init_write_free = (
    a0_initialization_proven
    and len(post_init_stores) == 0
)

a0_static_value_after_init = (
    a0_initial_value_is_one
    and a0_post_init_write_free
)

a0_count_semantics_strengthened = (
    stage69_count_proven
    and a0_initialization_proven
)


result = {
    "stage": 70,

    "target": {
        "name": TARGET_NAME,
        "nid": TARGET_NID,
        "global_context_va": GLOBAL_CONTEXT_VA,
        "field_offset": FIELD_OFFSET,
        "field_va": FIELD_VA,
        "a4_offset": A4_OFFSET,
        "submit_va": SUBMIT_VA,
        "multi_va": MULTI_VA,
        "table_stride": TABLE_STRIDE,
    },

    "stage69": {
        "available": bool(PREVIOUS),
        "count_semantics_proven": stage69_count_proven,
        "submit_a4_dispatch_confirmed":
            stage69_submit_dispatch,
        "multi_a4_dispatch_confirmed":
            stage69_multi_dispatch,
    },

    "a0_accesses": A0_ACCESSES,
    "a0_reads": A0_READS,
    "a0_stores": A0_STORES,
    "global_a0_reads": GLOBAL_A0_READS,
    "global_a0_stores": GLOBAL_A0_STORES,

    "initializer": initializer,

    "initializer_window": (
        make_window(
            all_rows,
            initializer["instruction_va"],
            before=20,
            after=28,
        )
        if initializer is not None
        else []
    ),

    "post_initialization_stores":
        post_init_stores,

    "submit_reads":
        SUBMIT_READS,

    "multi_reads":
        MULTI_READS,

    "value_provenance": {
        "field_va": FIELD_VA,

        "initialization_store_va": (
            initializer["instruction_va"]
            if initializer is not None
            else None
        ),

        "initialization_instruction": (
            initializer["instruction"]
            if initializer is not None
            else None
        ),

        "initial_value":
            initializer_value,

        "global_context_base_proven": (
            initializer["global_context_proven"]
            if initializer is not None
            else False
        ),

        "post_initialization_store_count":
            len(post_init_stores),
    },

    "conclusions": {
        "A0_GLOBAL_ACCESS_SCAN_COMPLETED": True,

        "A0_GLOBAL_CONTEXT_STORE_FOUND":
            a0_global_store_found,

        "A0_INITIALIZATION_STORE_FOUND":
            initializer is not None,

        "A0_INITIALIZATION_BASE_PROVEN":
            (
                initializer is not None
                and initializer["global_context_proven"]
            ),

        "A0_INITIAL_VALUE_PROVEN":
            a0_initialization_proven,

        "A0_INITIAL_VALUE_IS_1":
            a0_initial_value_is_one,

        "A0_POST_INITIALIZATION_STORES_FOUND":
            len(post_init_stores) > 0,

        "A0_POST_INITIALIZATION_STORE_FREE":
            a0_post_init_write_free,

        "A0_STATIC_VALUE_AFTER_INITIALIZATION":
            a0_static_value_after_init,

        "A0_COUNT_SEMANTICS_STRENGTHENED":
            a0_count_semantics_strengthened,

        "STAGE69_COUNT_SEMANTICS_CARRIED_FORWARD":
            stage69_count_proven,

        "INDEX_SEMANTICS_PROVEN":
            (
                stage69_submit_dispatch
                and stage69_multi_dispatch
            ),

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
        "Stage 70 rastrea la procedencia del registro base de global_context+0xA0.",
        "Una escritura inmediata solo se considera inicialización global cuando su base procede de LEA directa de 0x1A908.",
        "El valor inicial se conserva como literal de máquina.",
        "La ausencia de escrituras posteriores se limita a los segmentos ejecutables analizados.",
        "La semántica count/límite se hereda de Stage 69 y se refuerza con la procedencia del valor.",
        "No se asigna un nombre público de SDK.",
        "No se declara ejecución real de AGC."
    ],
}


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


write_json(
    OUTPUT_DIR / "stage70_static.json",
    result,
)


summary = []

summary.append(
    "AGC PS5 Stage 70 - Global +0xA0 Value Provenance / Initialization Audit"
)
summary.append("")

summary.append("=== TARGET ===")
summary.append(
    "global_context = 0x{:X}".format(GLOBAL_CONTEXT_VA)
)
summary.append(
    "field_offset = 0x{:X}".format(FIELD_OFFSET)
)
summary.append(
    "field_va = 0x{:X}".format(FIELD_VA)
)
summary.append(
    "table_stride = 0x{:X}".format(TABLE_STRIDE)
)
summary.append("")

summary.append("=== GLOBAL +0xA0 ACCESS COUNT ===")
summary.append(
    "reads = {}".format(len(GLOBAL_A0_READS))
)
summary.append(
    "stores = {}".format(len(GLOBAL_A0_STORES))
)
summary.append("")

summary.append("=== GLOBAL +0xA0 READS ===")

if GLOBAL_A0_READS:
    for x in GLOBAL_A0_READS:
        owner = (
            x["owner"]["name"]
            if x.get("owner")
            else "<unknown>"
        )

        summary.append(
            "VA=0x{:X} owner={} base={} | {}".format(
                x["instruction_va"],
                owner,
                x["base_register"],
                x["instruction"],
            )
        )
else:
    summary.append("NONE")

summary.append("")
summary.append("=== GLOBAL +0xA0 STORES ===")

if GLOBAL_A0_STORES:
    for x in GLOBAL_A0_STORES:
        summary.append(
            "VA=0x{:X} base={} type={} value={} | {}".format(
                x["instruction_va"],
                x["base_register"],
                x["access_type"],
                x["immediate_value"],
                x["instruction"],
            )
        )
else:
    summary.append("NONE")

summary.append("")
summary.append("=== INITIALIZATION ===")

if initializer is None:
    summary.append(
        "NO PROVEN GLOBAL-CONTEXT IMMEDIATE INITIALIZER FOUND"
    )
else:
    summary.append(
        "VA=0x{:X}".format(
            initializer["instruction_va"]
        )
    )
    summary.append(
        "instruction = {}".format(
            initializer["instruction"]
        )
    )
    summary.append(
        "base_register = {}".format(
            initializer["base_register"]
        )
    )
    summary.append(
        "global_context_base_proven = {}".format(
            initializer["global_context_proven"]
        )
    )
    summary.append(
        "initial_value = {}".format(
            initializer_value
        )
    )
    summary.append(
        "global_context_lea = {}".format(
            initializer["global_context_lea"]
        )
    )

summary.append("")
summary.append("=== INITIALIZER WINDOW ===")

if initializer is None:
    summary.append("NONE")
else:
    for row in make_window(
        all_rows,
        initializer["instruction_va"],
        before=20,
        after=28,
    ):
        summary.append(
            "0x{:X} {}".format(
                row["va"],
                row["instruction"],
            )
        )

summary.append("")
summary.append("=== POST-INITIALIZATION GLOBAL +0xA0 STORES ===")

if post_init_stores:
    for x in post_init_stores:
        summary.append(
            "VA=0x{:X} | {} | base={} | proven={}".format(
                x["instruction_va"],
                x["instruction"],
                x["base_register"],
                x["global_context_proven"],
            )
        )
else:
    summary.append("NONE")

summary.append("")
summary.append("=== STAGE 69 CORRELATION ===")
summary.append(
    "COUNT_SEMANTICS_PROVEN={}".format(
        stage69_count_proven
    )
)
summary.append(
    "SUBMIT_A4_DISPATCH_CONFIRMED={}".format(
        stage69_submit_dispatch
    )
)
summary.append(
    "MULTI_A4_DISPATCH_CONFIRMED={}".format(
        stage69_multi_dispatch
    )
)

summary.append("")
summary.append("=== CONCLUSIONS ===")

for key, value in result["conclusions"].items():
    summary.append(
        "{}={}".format(
            key,
            value
        )
    )

summary.append("")
summary.append("=== LIMIT ===")
summary.append(
    "La procedencia del valor de +0xA0 se restringe a las "
    "escrituras que pueden seguirse estáticamente hasta "
    "global_context. La ausencia de escrituras posteriores "
    "se limita al código ejecutable analizado."
)

write_text(
    OUTPUT_DIR / "a0_provenance_summary.txt",
    "\n".join(summary) + "\n",
)


focused = []

focused.append(
    "============================================"
)
focused.append(
    "GLOBAL +0xA0 ACCESS INVENTORY"
)
focused.append(
    "============================================"
)

for x in A0_ACCESSES:
    owner = (
        x["owner"]["name"]
        if x.get("owner")
        else "<unknown>"
    )

    focused.append(
        "VA=0x{:X} owner={} type={} base={} proven={} | {}".format(
            x["instruction_va"],
            owner,
            x["access_type"],
            x["base_register"],
            x["global_context_proven"],
            x["instruction"],
        )
    )

if initializer is not None:
    focused.append("")
    focused.append(
        "============================================"
    )
    focused.append(
        "INITIALIZER WINDOW"
    )
    focused.append(
        "============================================"
    )

    focused.append(
        make_window_text(
            make_window(
                all_rows,
                initializer["instruction_va"],
                before=24,
                after=32,
            )
        )
    )

write_text(
    OUTPUT_DIR / "a0_provenance_disassembly.txt",
    "\n".join(focused) + "\n",
)


correlation = {
    "stage69": {
        "count_semantics_proven":
            stage69_count_proven,
        "submit_a4_dispatch_confirmed":
            stage69_submit_dispatch,
        "multi_a4_dispatch_confirmed":
            stage69_multi_dispatch,
    },

    "stage70": {
        "initializer":
            initializer,
        "initial_value":
            initializer_value,
        "post_initialization_stores":
            post_init_stores,
        "static_after_initialization":
            a0_static_value_after_init,
    },

    "interpretation": {
        "a0_role":
            "dispatch-table bound/count-like field",
        "public_field_name":
            None,
        "semantic_name_proven":
            False,
    },
}

write_json(
    OUTPUT_DIR / "a0_provenance.json",
    correlation,
)


report = {
    "stage": 70,
    "result": result["conclusions"],
    "artifacts": {
        "stage70_static.json":
            "stage70_static.json",
        "a0_provenance_summary.txt":
            "a0_provenance_summary.txt",
        "a0_provenance_disassembly.txt":
            "a0_provenance_disassembly.txt",
        "a0_provenance.json":
            "a0_provenance.json",
    },
}

write_json(
    OUTPUT_DIR / "STAGE70_REPORT.json",
    report,
)


print(
    json.dumps(
        result,
        indent=2,
        ensure_ascii=False,
    )
)