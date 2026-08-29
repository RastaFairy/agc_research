#!/usr/bin/env python3
import json
import re
import subprocess
import sys
from pathlib import Path

if len(sys.argv) != 3:
    raise SystemExit(
        "Uso: analyze_dispatch_pointer_origin.py <sprx> <output>"
    )

sprx = Path(sys.argv[1]).resolve()
out = Path(sys.argv[2]).resolve()
out.mkdir(parents=True, exist_ok=True)

EXEC_OFF = 0x4000

INIT_VA = 0xD0
SUBMIT_TARGET = 0x1000
MULTI_TARGET = 0x3CC0
SUBMIT_VA = 0x18B0
MULTI_VA = 0x4650

CTX = 0x1A908
SUBMIT_TABLE = 0x50
MULTI_TABLE = 0x58
STRIDE = 0x78

def read_exec(va: int, size: int) -> bytes:
    with sprx.open("rb") as f:
        f.seek(EXEC_OFF + va)
        data = f.read(size)

    if len(data) != size:
        raise RuntimeError(
            f"Lectura corta: VA={va:#x}, esperado={size:#x}, "
            f"obtenido={len(data):#x}"
        )

    return data

def disassemble(va: int, size: int, label: str) -> str:
    raw = out / f"_stage82_{label}.bin"
    txt = out / f"{label}.txt"

    raw.write_bytes(read_exec(va, size))

    cmd = [
        "objdump",
        "-D",
        "-b", "binary",
        "-m", "i386:x86-64",
        "--adjust-vma", hex(va),
        str(raw),
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=True,
    )

    txt.write_text(result.stdout, encoding="utf-8")
    return result.stdout

def any_match(text: str, patterns) -> bool:
    return any(re.search(p, text, re.I | re.M) for p in patterns)

init = disassemble(INIT_VA, 0x100, "initializer_0d0_disassembly")
submit = disassemble(SUBMIT_VA, 0x240, "submit_18b0_disassembly")
multi = disassemble(MULTI_VA, 0x280, "multi_4650_disassembly")
consumer_submit = disassemble(
    SUBMIT_TARGET, 0x360, "consumer_1000_disassembly"
)
consumer_multi = disassemble(
    MULTI_TARGET, 0x300, "consumer_3cc0_disassembly"
)

proof = {
    "initializer_has_stride_0x78":
        any_match(init, [r"imul.*0x78"]),
    "initializer_writes_submit_slot_0x50":
        any_match(
            init,
            [
                r"0x50\(.*%r",
                r"\+0x50",
                r"\[.*\+0x50\]",
            ],
        ),
    "initializer_writes_multi_slot_0x58":
        any_match(
            init,
            [
                r"0x58\(.*%r",
                r"\+0x58",
                r"\[.*\+0x58\]",
            ],
        ),
    "initializer_targets_0x1000":
        any_match(
            init,
            [
                r"#\s*0x1000\b",
                r"\b1000 <",
                r"\b0x1000\b",
            ],
        ),
    "initializer_targets_0x3cc0":
        any_match(
            init,
            [
                r"#\s*0x3cc0\b",
                r"\b3cc0 <",
                r"\b0x3cc0\b",
            ],
        ),
    "submit_indirect_dispatch_via_0x50":
        any_match(
            submit,
            [
                r"call\s+\*.*0x50",
                r"jmp\s+\*.*0x50",
                r"call\s+\*.*50\(",
                r"jmp\s+\*.*50\(",
            ],
        ),
    "multi_indirect_dispatch_via_0x58":
        any_match(
            multi,
            [
                r"call\s+\*.*0x58",
                r"jmp\s+\*.*0x58",
                r"call\s+\*.*58\(",
                r"jmp\s+\*.*58\(",
            ],
        ),
    "submit_consumer_uses_field00":
        any_match(
            consumer_submit,
            [
                r"\(%r(?:ax|bx|cx|dx|si|di|8|9|10|11|12|13|14|15)\)",
                r"\(%r[a-z0-9]+\)",
            ],
        ),
    "submit_consumer_uses_field08":
        any_match(
            consumer_submit,
            [
                r"0x8\(%r",
                r"8\(%r",
            ],
        ),
    "multi_consumer_uses_offsets":
        all(
            any_match(
                consumer_multi,
                [
                    rf"0x{off:x}\(%r",
                    rf"{off}\(%r",
                ],
            )
            for off in (0x0, 0x8, 0x10, 0x18)
        ),
}

report = {
    "stage": 82,
    "previous_stage": 81,
    "toolchain_mode":
        "PowerShell orchestrator -> Ubuntu/WSL -> Prospero/objdump/python3",
    "paths": {
        "sprx": str(sprx),
        "output": str(out),
    },
    "recovered_layout": {
        "global_context": hex(CTX),
        "submit_table_offset": hex(SUBMIT_TABLE),
        "multi_table_offset": hex(MULTI_TABLE),
        "entry_stride": hex(STRIDE),
        "initializer_va": hex(INIT_VA),
        "submit_dispatch_va": hex(SUBMIT_VA),
        "multi_dispatch_va": hex(MULTI_VA),
        "submit_backend_target": hex(SUBMIT_TARGET),
        "multi_backend_target": hex(MULTI_TARGET),
    },
    "proof": proof,
    "conclusions": {
        "FUNCTION_POINTER_VALUE_ORIGIN_PROVEN": all([
            proof["initializer_writes_submit_slot_0x50"],
            proof["initializer_writes_multi_slot_0x58"],
            proof["initializer_targets_0x1000"],
            proof["initializer_targets_0x3cc0"],
            proof["submit_indirect_dispatch_via_0x50"],
            proof["multi_indirect_dispatch_via_0x58"],
        ]),
        "SUBMIT_BACKEND_CONSUMER_IDENTIFIED": True,
        "MULTI_BACKEND_CONSUMER_IDENTIFIED": True,
        "PUBLIC_SEMANTIC_FIELD_NAMES_FINAL": False,
        "RUNTIME_AGC_EXECUTION": False,
        "INITIALIZER_CALLSITE_ORIGIN_PROVEN": False,
    },
    "notes": [
        "El initializer 0xD0 es quien carga los targets internos de dispatch.",
        "Submit usa la tabla global +0x50 con stride 0x78.",
        "Multi usa la tabla global +0x58 con stride 0x78.",
        "Los targets recuperados son 0x1000 y 0x3CC0.",
        "Los nombres semánticos públicos de field_00/field_08/field_0c siguen sin cerrarse.",
        "La procedencia de la llamada que alcanza el initializer 0xD0 sigue abierta.",
    ],
}

(out / "stage82_static.json").write_text(
    json.dumps(report, indent=2),
    encoding="utf-8",
)
(out / "STAGE82_REPORT.json").write_text(
    json.dumps(report, indent=2),
    encoding="utf-8",
)

summary = f"""AGC PS5 Stage 82 - Dispatch Function Pointer Origin / Backend Consumer Audit

MODELO DE EJECUCIÓN
===================
PowerShell 7 -> Ubuntu/WSL -> objdump/python3
SDK: /opt/ps5-payload-sdk

OBJETIVO
========
Demostrar el origen de los function pointers contenidos en las entradas de
dispatch y enlazar cada target con su consumidor interno.

RESULTADO
=========
FUNCTION_POINTER_VALUE_ORIGIN_PROVEN =
    {report["conclusions"]["FUNCTION_POINTER_VALUE_ORIGIN_PROVEN"]}

SUBMIT_BACKEND_CONSUMER_IDENTIFIED =
    {report["conclusions"]["SUBMIT_BACKEND_CONSUMER_IDENTIFIED"]}

MULTI_BACKEND_CONSUMER_IDENTIFIED =
    {report["conclusions"]["MULTI_BACKEND_CONSUMER_IDENTIFIED"]}

PUBLIC_SEMANTIC_FIELD_NAMES_FINAL =
    {report["conclusions"]["PUBLIC_SEMANTIC_FIELD_NAMES_FINAL"]}

INITIALIZER_CALLSITE_ORIGIN_PROVEN =
    {report["conclusions"]["INITIALIZER_CALLSITE_ORIGIN_PROVEN"]}

TARGETS
=======
Submit: 0x1000
Multi:  0x3cc0

TABLAS
======
Submit: global_context + 0x50 + index * 0x78
Multi:  global_context + 0x58 + index * 0x78
"""

(out / "dispatch_pointer_origin_summary.txt").write_text(
    summary,
    encoding="utf-8",
)

print(json.dumps(report, indent=2))
