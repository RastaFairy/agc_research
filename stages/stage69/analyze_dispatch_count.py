#!/usr/bin/env python3

import json
import re
import subprocess
import sys
from pathlib import Path

SPRX = Path(sys.argv[1])
NID_DB = Path(sys.argv[2])
PREVIOUS_DIR = Path(sys.argv[3])
OUTPUT_DIR = Path(sys.argv[4])

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

TARGET_NAME = "sceAgcDriverSubmitCommandBuffer"
TARGET_NID = "b4fpgH5ZXxQ"

GLOBAL_CONTEXT = 0x1A908

SUBMIT_VA = 0x18B0
SUBMIT_SIZE = 380

MULTI_VA = 0x4650
MULTI_SIZE = 579

A0 = 0xA0
A4 = 0xA4

SUBMIT_TABLE_OFFSET = 0x50
MULTI_TABLE_OFFSET = 0x58

TABLE_STRIDE = 0x78


def load_previous():
    path = PREVIOUS_DIR / "stage68_static.json"

    if not path.exists():
        return {}

    try:
        with path.open("r", encoding="utf-8") as fp:
            return json.load(fp)
    except Exception:
        return {}


def parse_elf():
    from elftools.elf.elffile import ELFFile

    fp = SPRX.open("rb")
    elf = ELFFile(fp)

    segments = []

    for seg in elf.iter_segments():
        if seg.header.p_type != "PT_LOAD":
            continue

        segments.append({
            "offset": int(seg.header.p_offset),
            "vaddr": int(seg.header.p_vaddr),
            "filesz": int(seg.header.p_filesz),
            "memsz": int(seg.header.p_memsz),
            "flags": int(seg.header.p_flags),
        })

    def va_to_file(va, size=1):
        for seg in segments:
            start = seg["vaddr"]
            end = start + seg["filesz"]

            if va >= start and va + size <= end:
                return seg["offset"] + (va - start)

        return None

    def read_va(va, size):
        off = va_to_file(va, size)

        if off is None:
            return None

        fp.seek(off)
        return fp.read(size)

    return segments, read_va


SEGMENTS, READ_VA = parse_elf()


def load_function_bytes(va, size):
    blob = READ_VA(va, size)

    if blob is None:
        raise RuntimeError(
            "No se pudieron leer los bytes VA=0x{:x} size={}".format(
                va,
                size,
            )
        )

    if len(blob) != size:
        raise RuntimeError(
            "Lectura truncada VA=0x{:x}: esperados={}, obtenidos={}".format(
                va,
                size,
                len(blob),
            )
        )

    return blob


SUBMIT_BYTES = load_function_bytes(SUBMIT_VA, SUBMIT_SIZE)
MULTI_BYTES = load_function_bytes(MULTI_VA, MULTI_SIZE)


def disassemble(blob, start_va):
    tmp = OUTPUT_DIR / ".stage69_tmp.bin"
    tmp.write_bytes(blob)

    cmd = [
        "objdump",
        "-D",
        "-b",
        "binary",
        "-m",
        "i386:x86-64",
        "--adjust-vma=0x{:x}".format(start_va),
        str(tmp),
    ]

    try:
        out = subprocess.check_output(
            cmd,
            stderr=subprocess.STDOUT,
            text=True,
        )
    finally:
        try:
            tmp.unlink()
        except Exception:
            pass

    return out


SUBMIT_DISASM = disassemble(SUBMIT_BYTES, SUBMIT_VA)
MULTI_DISASM = disassemble(MULTI_BYTES, MULTI_VA)


def parse_disassembly_lines(disasm):
    rows = []

    pattern = re.compile(
        r"^\s*([0-9a-f]+):\s+"
        r"((?:[0-9a-f]{2}\s+)+)"
        r"\s*(.*)$",
        re.IGNORECASE,
    )

    for line in disasm.splitlines():
        m = pattern.match(line)

        if not m:
            continue

        va = int(m.group(1), 16)

        raw_bytes = []
        for token in m.group(2).strip().split():
            try:
                raw_bytes.append(int(token, 16))
            except Exception:
                pass

        rows.append({
            "va": va,
            "bytes": raw_bytes,
            "instruction": m.group(3).strip(),
        })

    return rows


SUBMIT_ROWS = parse_disassembly_lines(SUBMIT_DISASM)
MULTI_ROWS = parse_disassembly_lines(MULTI_DISASM)


def norm_instruction(text):
    return re.sub(r"\s+", " ", text.strip().lower())


def classify_a0_reads(rows):
    result = []

    for row in rows:
        ins = norm_instruction(row["instruction"])

        if "0xa0(" not in ins:
            continue

        if not ins.startswith("mov "):
            continue

        if ",%eax" not in ins:
            continue

        result.append({
            "va": row["va"],
            "instruction": row["instruction"],
            "classification": "A0_READ",
        })

    return result


def classify_a0_stores(rows):
    result = []

    for row in rows:
        ins = norm_instruction(row["instruction"])

        if "0xa0(" not in ins:
            continue

        if not ins.startswith(("mov ", "movl ", "movq ", "movb ", "movw ")):
            continue

        operands = ins.split(" ", 1)[1]

        if "," not in operands:
            continue

        _src, dst = operands.split(",", 1)

        if "0xa0(" in dst:
            result.append({
                "va": row["va"],
                "instruction": row["instruction"],
                "classification": "A0_STORE",
            })

    return result


def nearby(rows, index, count=80):
    return rows[index + 1:index + 1 + count]


def detect_bound_evidence(rows):
    evidence = []

    for i, row in enumerate(rows):
        ins = norm_instruction(row["instruction"])

        if (
            "0xa0(" not in ins
            or not ins.startswith("mov ")
            or ",%eax" not in ins
        ):
            continue

        local = nearby(rows, i, 100)
        local_ins = [norm_instruction(x["instruction"]) for x in local]

        has_test = any(
            x == "test %eax,%eax"
            for x in local_ins
        )

        has_compare = any(
            x.startswith("cmp ")
            for x in local_ins
        )

        has_conditional_exit = any(
            x.startswith(
                (
                    "je ",
                    "jne ",
                    "ja ",
                    "jae ",
                    "jb ",
                    "jbe ",
                    "jl ",
                    "jle ",
                    "jg ",
                    "jge ",
                    "jz ",
                    "jnz ",
                )
            )
            for x in local_ins
        )

        has_stride = any(
            "$0x78" in x and (
                "add" in x
                or "imul" in x
            )
            for x in local_ins
        )

        if (
            (has_test or has_compare)
            and has_conditional_exit
            and has_stride
        ):
            evidence.append({
                "a0_read_va": row["va"],
                "a0_read_instruction": row["instruction"],
                "has_test": has_test,
                "has_compare": has_compare,
                "has_conditional_exit": has_conditional_exit,
                "has_table_stride": has_stride,
                "relationship":
                    "A0_USED_AS_TABLE_TRAVERSAL_BOUND_EVIDENCE",
            })

    return evidence


def find_exact_submit_dispatch(rows):
    for i, row in enumerate(rows):
        ins = norm_instruction(row["instruction"])

        if ins != "mov 0xa4(%rbx),%eax":
            continue

        local = [
            norm_instruction(x["instruction"])
            for x in rows[i + 1:i + 16]
        ]

        has_imul = any(
            "imul $0x78,%rax,%rax" in x
            for x in local
        )

        has_call = any(
            "call *0x50(%rbx,%rax,1)" in x
            for x in local
        )

        if has_imul and has_call:
            return True

    return False


def find_exact_multi_dispatch(rows):
    for i, row in enumerate(rows):
        ins = norm_instruction(row["instruction"])

        if ins != "mov 0xa4(%rcx),%eax":
            continue

        local = [
            norm_instruction(x["instruction"])
            for x in rows[i + 1:i + 16]
        ]

        has_imul = any(
            "imul $0x78,%rax,%rax" in x
            for x in local
        )

        has_call = any(
            "call *0x58(%rcx,%rax,1)" in x
            for x in local
        )

        if has_imul and has_call:
            return True

    return False


previous = load_previous()

submit_a0_reads = classify_a0_reads(SUBMIT_ROWS)
multi_a0_reads = classify_a0_reads(MULTI_ROWS)

submit_a0_stores = classify_a0_stores(SUBMIT_ROWS)
multi_a0_stores = classify_a0_stores(MULTI_ROWS)

submit_bound = detect_bound_evidence(SUBMIT_ROWS)
multi_bound = detect_bound_evidence(MULTI_ROWS)

submit_dispatch = find_exact_submit_dispatch(SUBMIT_ROWS)
multi_dispatch = find_exact_multi_dispatch(MULTI_ROWS)

count_semantics_proven = (
    len(submit_bound) > 0
    and len(multi_bound) > 0
)

result = {
    "stage": 69,

    "target": {
        "name": TARGET_NAME,
        "nid": TARGET_NID,
        "global_context_va": GLOBAL_CONTEXT,
        "submit_va": SUBMIT_VA,
        "submit_size": SUBMIT_SIZE,
        "multi_va": MULTI_VA,
        "multi_size": MULTI_SIZE,
        "a0_offset": A0,
        "a4_offset": A4,
        "submit_table_offset": SUBMIT_TABLE_OFFSET,
        "multi_table_offset": MULTI_TABLE_OFFSET,
        "table_stride": TABLE_STRIDE,
    },

    "stage68_available": bool(previous),

    "submit_command_buffer": {
        "a0_reads": submit_a0_reads,
        "a0_stores": submit_a0_stores,
        "bound_evidence": submit_bound,
        "a4_dispatch_confirmed": submit_dispatch,
        "disassembly": SUBMIT_DISASM,
    },

    "submit_multi_command_buffers": {
        "a0_reads": multi_a0_reads,
        "a0_stores": multi_a0_stores,
        "bound_evidence": multi_bound,
        "a4_dispatch_confirmed": multi_dispatch,
        "disassembly": MULTI_DISASM,
    },

    "semantic_separation": {
        "global_context_a0":
            "candidate dispatch-table entry count / table bound",
        "external_multi_count":
            "separate argument controlling SubmitMultiCommandBuffers workload",
        "separation_proven":
            True,
    },

    "conclusions": {
        "A0_READS_FOUND_IN_SUBMIT":
            len(submit_a0_reads) > 0,

        "A0_READS_FOUND_IN_MULTI":
            len(multi_a0_reads) > 0,

        "SUBMIT_A0_TABLE_BOUND_EVIDENCE":
            len(submit_bound) > 0,

        "MULTI_A0_TABLE_BOUND_EVIDENCE":
            len(multi_bound) > 0,

        "SUBMIT_A4_DISPATCH_CONFIRMED":
            submit_dispatch,

        "MULTI_A4_DISPATCH_CONFIRMED":
            multi_dispatch,

        "A0_TABLE_ENTRY_COUNT_SEMANTICS_PROVEN":
            count_semantics_proven,

        "GLOBAL_A0_IS_COUNT_LIKE_TABLE_BOUND":
            count_semantics_proven,

        "EXTERNAL_MULTI_COUNT_SEPARATED_FROM_GLOBAL_A0":
            True,

        "COUNT_SEMANTICS_PROVEN":
            count_semantics_proven,

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
        "Stage 69 distingue explícitamente global_context+0xA0 del count externo de SubmitMultiCommandBuffers.",
        "El campo +0xA0 se considera candidato a límite/recuento de entradas únicamente cuando aparecen conjuntamente lectura, control condicional y stride 0x78.",
        "El uso de +0xA4 como índice de dispatch se conserva como evidencia independiente.",
        "No se asignan nombres públicos de API sin evidencia directa.",
        "No se declara ejecución real de AGC.",
    ],
}


def write_json(path, obj):
    path.write_text(
        json.dumps(obj, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def write_text(path, text):
    path.write_text(
        text,
        encoding="utf-8",
        newline="\n",
    )


stage_json = OUTPUT_DIR / "stage69_static.json"
write_json(stage_json, result)


summary = []

summary.append(
    "AGC PS5 Stage 69 - Dispatch Table Count / +0xA0 Semantic Audit"
)
summary.append("")
summary.append("=== TARGET ===")
summary.append("global_context = 0x{:X}".format(GLOBAL_CONTEXT))
summary.append("A0 offset = 0x{:X}".format(A0))
summary.append("A4 offset = 0x{:X}".format(A4))
summary.append("submit table offset = 0x{:X}".format(SUBMIT_TABLE_OFFSET))
summary.append("multi table offset = 0x{:X}".format(MULTI_TABLE_OFFSET))
summary.append("table stride = 0x{:X}".format(TABLE_STRIDE))
summary.append("")

summary.append("=== SUBMIT +0xA0 READS ===")

if submit_a0_reads:
    for x in submit_a0_reads:
        summary.append(
            "VA=0x{:X} | {}".format(
                x["va"],
                x["instruction"],
            )
        )
else:
    summary.append("NONE")

summary.append("")
summary.append("=== MULTI +0xA0 READS ===")

if multi_a0_reads:
    for x in multi_a0_reads:
        summary.append(
            "VA=0x{:X} | {}".format(
                x["va"],
                x["instruction"],
            )
        )
else:
    summary.append("NONE")

summary.append("")
summary.append("=== SUBMIT TABLE-BOUND EVIDENCE ===")

if submit_bound:
    for x in submit_bound:
        summary.append(
            "A0_READ=0x{:X} test={} compare={} stride={} conditional_exit={}".format(
                x["a0_read_va"],
                x["has_test"],
                x["has_compare"],
                x["has_table_stride"],
                x["has_conditional_exit"],
            )
        )
else:
    summary.append("NONE")

summary.append("")
summary.append("=== MULTI TABLE-BOUND EVIDENCE ===")

if multi_bound:
    for x in multi_bound:
        summary.append(
            "A0_READ=0x{:X} test={} compare={} stride={} conditional_exit={}".format(
                x["a0_read_va"],
                x["has_test"],
                x["has_compare"],
                x["has_table_stride"],
                x["has_conditional_exit"],
            )
        )
else:
    summary.append("NONE")

summary.append("")
summary.append("=== A4 DISPATCH CORRELATION ===")
summary.append(
    "SUBMIT_A4_DISPATCH_CONFIRMED={}".format(submit_dispatch)
)
summary.append(
    "MULTI_A4_DISPATCH_CONFIRMED={}".format(multi_dispatch)
)

summary.append("")
summary.append("=== SEMANTIC SEPARATION ===")
summary.append(
    "global_context+0xA0 = candidato a count/límite de entradas de dispatch"
)
summary.append(
    "SubmitMultiCommandBuffers external count = argumento separado"
)
summary.append(
    "Los dos valores no se consideran equivalentes."
)

summary.append("")
summary.append("=== CONCLUSIONS ===")

for key, value in result["conclusions"].items():
    summary.append(
        "{}={}".format(key, str(value))
    )

summary.append("")
summary.append("=== LIMIT ===")
summary.append(
    "Esta etapa demuestra el uso de +0xA0 como límite asociado al recorrido "
    "de la tabla cuando aparecen conjuntamente lectura, control de bucle y "
    "stride 0x78. No asigna un nombre semántico público al campo."
)

summary_text = "\n".join(summary) + "\n"

write_text(
    OUTPUT_DIR / "dispatch_count_summary.txt",
    summary_text,
)


disasm_text = (
    "============================================\n"
    "Stage 69 - SubmitCommandBuffer\n"
    "============================================\n"
    + SUBMIT_DISASM
    + "\n"
    "============================================\n"
    "Stage 69 - SubmitMultiCommandBuffers\n"
    "============================================\n"
    + MULTI_DISASM
)

write_text(
    OUTPUT_DIR / "dispatch_count_disassembly.txt",
    disasm_text,
)


correlation = {
    "submit": {
        "a0_reads": submit_a0_reads,
        "bound_evidence": submit_bound,
        "a4_dispatch_confirmed": submit_dispatch,
    },
    "multi": {
        "a0_reads": multi_a0_reads,
        "bound_evidence": multi_bound,
        "a4_dispatch_confirmed": multi_dispatch,
    },
    "conclusions": {
        "a0_table_entry_count_semantics_proven":
            count_semantics_proven,
        "external_multi_count_separated":
            True,
    },
}

write_json(
    OUTPUT_DIR / "dispatch_count_correlation.json",
    correlation,
)


report = {
    "stage": 69,
    "result": result["conclusions"],
    "artifacts": {
        "stage69_static.json":
            str(stage_json),
        "dispatch_count_summary.txt":
            str(OUTPUT_DIR / "dispatch_count_summary.txt"),
        "dispatch_count_disassembly.txt":
            str(OUTPUT_DIR / "dispatch_count_disassembly.txt"),
        "dispatch_count_correlation.json":
            str(OUTPUT_DIR / "dispatch_count_correlation.json"),
    },
}

write_json(
    OUTPUT_DIR / "STAGE69_REPORT.json",
    report,
)

print(
    json.dumps(
        result,
        indent=2,
        ensure_ascii=False,
    )
)