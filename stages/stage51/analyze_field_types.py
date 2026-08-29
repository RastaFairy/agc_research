from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from typing import Optional


SPRX = sys.argv[1]
NID_DB = sys.argv[2]
OUT_DIR = sys.argv[3]

TARGETS = {
    "sceAgcDriverSubmitDcb": {
        "nid": "UglJIZjGssM",
        "va": 0x28B0,
        "size": 0x0F,
    },
    "sceAgcDriverAgrSubmitDcb": {
        "nid": "AhGvpITrf4M",
        "va": 0x28C0,
        "size": 0x48,
    },
    "sceAgcDriverSubmitAcb": {
        "nid": "gSRnr79F8tQ",
        "va": 0x2910,
        "size": 0x43,
    },
    "sceAgcDriverSubmitCommandBuffer": {
        "nid": "b4fpgH5ZXxQ",
        "va": 0x18B0,
        "size": 0x17C,
    },
    "sceAgcDriverSubmitMultiCommandBuffers": {
        "nid": "Fj7r9EHzF38",
        "va": 0x4650,
        "size": 0x243,
    },
    "sceAgcDriverSubmitMultiDcbs": {
        "nid": "6UzEidRZwkg",
        "va": 0x48A0,
        "size": 0x14,
    },
    "sceAgcDriverAgrSubmitMultiDcbs": {
        "nid": "+T8Xo6LtFJI",
        "va": 0x48C0,
        "size": 0x4D,
    },
    "sceAgcDriverSubmitMultiAcbs": {
        "nid": "HF3YllT3mXU",
        "va": 0x4910,
        "size": 0x43,
    },
}

CONTEXTS = {
    "global_context": 0x1A908,
    "agr_context": 0x1A868,
    "dcb_context": 0x1A8B8,
    "acb_table": 0x18460,
}

SUBMIT_ARGUMENT_REG = "r14"

# Known context offsets established in previous stages.
KNOWN_CONTEXT_FIELDS = {
    "global_context": {
        0x000: "unknown_pointer_or_lockword",
        0x048: "callback_table_or_context_array",
        0x0A0: "count_or_active_count",
        0x0A4: "index_or_selector",
        0x140: "atomic_sequence_or_ticket",
        0x148: "mode_or_feature_state",
    },
    "dcb_context": {},
    "agr_context": {},
    "acb_table": {},
}


def load_load_segments():
    from elftools.elf.elffile import ELFFile

    loads = []

    with open(SPRX, "rb") as fp:
        elf = ELFFile(fp)

        for segment in elf.iter_segments():
            if segment["p_type"] != "PT_LOAD":
                continue

            loads.append({
                "p_offset": int(segment["p_offset"]),
                "p_vaddr": int(segment["p_vaddr"]),
                "p_filesz": int(segment["p_filesz"]),
                "p_memsz": int(segment["p_memsz"]),
                "p_flags": int(segment["p_flags"]),
            })

    return loads


LOADS = load_load_segments()


def va_to_file_offset(va: int) -> Optional[int]:
    for seg in LOADS:
        start = seg["p_vaddr"]
        end = start + seg["p_filesz"]

        if start <= va < end:
            return seg["p_offset"] + (va - start)

    return None


def read_va(va: int, size: int) -> bytes:
    offset = va_to_file_offset(va)

    if offset is None:
        return b""

    with open(SPRX, "rb") as fp:
        fp.seek(offset)
        return fp.read(size)


def disassemble(raw: bytes, base_va: int, name: str):
    if not raw:
        return []

    safe = re.sub(
        r"[^A-Za-z0-9_.-]",
        "_",
        name,
    )

    path = os.path.join(
        OUT_DIR,
        safe + ".bin",
    )

    with open(path, "wb") as fp:
        fp.write(raw)

    proc = subprocess.run(
        [
            "objdump",
            "-D",
            "-b",
            "binary",
            "-m",
            "i386:x86-64",
            "--adjust-vma=0x%x" % base_va,
            path,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    text = proc.stdout.decode(
        "utf-8",
        errors="replace",
    )

    result = []

    for line in text.splitlines():

        match = re.match(
            r"^\s*([0-9a-fA-F]+)\s*:\s+"
            r"((?:[0-9a-fA-F]{2}\s*)+)"
            r"(.+?)\s*$",
            line,
        )

        if not match:
            continue

        address = int(
            match.group(1),
            16,
        )

        bytes_text = match.group(2).strip()
        text_part = match.group(3).strip()

        result.append({
            "address": address,
            "bytes": bytes_text,
            "text": text_part,
        })

    return result


def split_operands(text: str):
    if " " not in text:
        return []

    return [
        x.strip()
        for x in text.split(None, 1)[1].split(",")
    ]


def mnemonic(text: str) -> str:
    if not text:
        return ""

    return text.split(None, 1)[0].lower()


def register_width(register: str) -> Optional[int]:

    r = register.lower()

    if r.endswith("b"):
        return 1

    if r.endswith("w"):
        return 2

    if r.endswith("d"):
        return 4

    if r.startswith("xmm") or r.startswith("ymm"):
        return 16

    if r in {
        "rax", "rbx", "rcx", "rdx",
        "rsi", "rdi", "rbp", "rsp",
        "r8", "r9", "r10", "r11",
        "r12", "r13", "r14", "r15",
    }:
        return 8

    if re.fullmatch(r"e?[a-z]{2,3}", r):
        return 4

    return None


def infer_access_size(
    text: str,
    bytes_text: str,
    access_kind: str,
) -> Optional[int]:

    m = mnemonic(text)

    if m.endswith("b"):
        return 1

    if m.endswith("w"):
        return 2

    if m.endswith("l"):
        return 4

    if m.endswith("q"):
        return 8

    operands = split_operands(text)

    if not operands:
        return None

    # mov source,destination
    if m.startswith("mov"):
        if len(operands) >= 2:

            src = operands[0]
            dst = operands[-1]

            # Register source -> memory destination.
            if "(" in dst:
                reg = re.search(
                    r"%([a-zA-Z0-9]+)",
                    src,
                )

                if reg:
                    return register_width(
                        reg.group(1)
                    )

            # Memory source -> register destination.
            if "(" in src:
                reg = re.search(
                    r"%([a-zA-Z0-9]+)",
                    dst,
                )

                if reg:
                    return register_width(
                        reg.group(1)
                    )

    if m == "xadd":
        if len(operands) >= 2:

            reg = re.search(
                r"%([a-zA-Z0-9]+)",
                operands[0],
            )

            if reg:
                return register_width(
                    reg.group(1)
                )

    if m in {
        "inc", "dec"
    }:
        # incq/decq normally carry suffix; unsuffixed forms in
        # objdump for this code are 64-bit where the operand is
        # explicitly a quadword register/address.
        if "q" in bytes_text.lower():
            return 8

    if m == "lea":
        return 8

    if m in {
        "cmpl",
        "addl",
        "subl",
        "andl",
        "orl",
        "xorl",
    }:
        return 4

    if m in {
        "cmpb",
        "addb",
        "subb",
        "andb",
        "orb",
    }:
        return 1

    return None


def parse_rip_lea(
    instruction,
):

    text = instruction["text"]

    match = re.search(
        r"\blea\s+"
        r"(-?0x[0-9a-fA-F]+|[-+]?\d+)"
        r"\(%rip\)\s*,\s*%([a-zA-Z0-9]+)",
        text,
        re.IGNORECASE,
    )

    if not match:
        return None

    try:
        displacement = int(
            match.group(1),
            0,
        )
    except ValueError:
        return None

    register = match.group(2).lower()

    byte_count = len(
        instruction["bytes"].split()
    )

    target = (
        instruction["address"] +
        byte_count +
        displacement
    )

    for name, va in CONTEXTS.items():

        if target == va:

            return {
                "instruction_va": instruction["address"],
                "instruction": text,
                "register": register,
                "context": name,
                "target_va": target,
                "displacement": displacement,
            }

    return None


def parse_memory_operands(text: str):

    result = []

    # This intentionally handles:
    #
    #   (%rbx)
    #   0xa0(%rbx)
    #   0x140(%rcx)
    #   -0x50(%rbp)
    #
    # and does not interpret RIP-relative references as
    # context-field accesses.
    pattern = (
        r"(?P<disp>-?0x[0-9a-fA-F]+|-?\d+)?"
        r"\(%(?P<base>[a-zA-Z0-9]+)"
        r"(?:,%[a-zA-Z0-9]+(?:,[1248]))?"
        r"\)"
    )

    for match in re.finditer(
        pattern,
        text,
    ):

        disp_text = match.group("disp")

        if disp_text is None:
            displacement = 0
        else:
            try:
                displacement = int(
                    disp_text,
                    0,
                )
            except ValueError:
                continue

        result.append({
            "base_register": match.group("base").lower(),
            "field_offset": displacement,
        })

    return result


def classify_access(
    text: str,
    memory_operand: dict,
):

    m = mnemonic(text)
    operands = split_operands(text)

    if not operands:
        return "UNKNOWN"

    # Explicit RMW operations.
    if m in {
        "xadd",
        "xchg",
        "inc",
        "incq",
        "dec",
        "decq",
    }:
        return "RMW"

    if m in {
        "add",
        "addb",
        "addl",
        "addq",
        "sub",
        "subb",
        "subl",
        "subq",
        "and",
        "andb",
        "andl",
        "andq",
        "or",
        "orb",
        "orl",
        "orq",
    }:
        return "RMW"

    # Indirect calls/jumps are not fields themselves.
    if m in {
        "call",
        "jmp",
    }:
        return "INDIRECT_CONTROL"

    if len(operands) >= 2:

        source = operands[0]
        destination = operands[-1]

        if "(" in destination:
            return "WRITE"

        if "(" in source:
            return "READ"

    # cmpl $imm, memory is a memory read.
    if m.startswith("cmp"):
        return "READ"

    # lea from a tracked context register creates a derived
    # pointer; it is not itself a memory load/store.
    if m == "lea":
        return "POINTER_DERIVATION"

    return "MEMORY_ACCESS"


def update_aliases(
    aliases,
    instruction,
):

    text = instruction["text"]
    m = mnemonic(text)
    operands = split_operands(text)

    if len(operands) < 2:
        return

    source = operands[0]
    destination = operands[-1]

    src_match = re.fullmatch(
        r"%([a-zA-Z0-9]+)",
        source,
    )

    dst_match = re.fullmatch(
        r"%([a-zA-Z0-9]+)",
        destination,
    )

    if not dst_match:
        return

    dst = dst_match.group(1).lower()

    # Do not automatically propagate a memory load as an alias.
    if src_match:

        src = src_match.group(1).lower()

        if src in aliases:
            aliases[dst] = dict(
                aliases[src]
            )
        else:
            aliases.pop(
                dst,
                None,
            )

        return

    # Any direct non-register write kills the known alias.
    if destination.startswith("%") is False:
        return

    aliases.pop(
        dst,
        None,
    )


def analyze_function(
    name,
    info,
):

    raw = read_va(
        info["va"],
        info["size"],
    )

    instructions = disassemble(
        raw,
        info["va"],
        name,
    )

    aliases = {}
    context_refs = []
    accesses = []

    for instruction in instructions:

        text = instruction["text"]
        m = mnemonic(text)

        # Fresh context pointer.
        lea = parse_rip_lea(
            instruction
        )

        if lea:

            aliases[
                lea["register"]
            ] = {
                "context": lea["context"],
                "context_va": lea["target_va"],
                "origin_va": lea[
                    "instruction_va"
                ],
            }

            context_refs.append(
                lea
            )

        # Register aliases.
        update_aliases(
            aliases,
            instruction,
        )

        # Analyze memory operands.
        for memory in parse_memory_operands(text):

            base = memory[
                "base_register"
            ]

            if base not in aliases:
                continue

            kind = classify_access(
                text,
                memory,
            )

            if kind in {
                "INDIRECT_CONTROL",
                "POINTER_DERIVATION",
            }:
                # A LEA off a tracked base is still useful and
                # recorded below as a derived pointer.
                if kind == "POINTER_DERIVATION":

                    size = infer_access_size(
                        text,
                        instruction["bytes"],
                        kind,
                    )

                    accesses.append({
                        "instruction_va": instruction[
                            "address"
                        ],
                        "instruction": text,
                        "context": aliases[base][
                            "context"
                        ],
                        "context_va": aliases[base][
                            "context_va"
                        ],
                        "base_register": base,
                        "field_offset": memory[
                            "field_offset"
                        ],
                        "field_offset_hex": (
                            "0x%x"
                            % memory["field_offset"]
                        ),
                        "access_type": kind,
                        "access_size": size,
                        "confidence": (
                            "TRACKED_CONTEXT_BASE"
                        ),
                    })

                continue

            size = infer_access_size(
                text,
                instruction["bytes"],
                kind,
            )

            accesses.append({
                "instruction_va": instruction[
                    "address"
                ],
                "instruction": text,
                "context": aliases[base][
                    "context"
                ],
                "context_va": aliases[base][
                    "context_va"
                ],
                "base_register": base,
                "field_offset": memory[
                    "field_offset"
                ],
                "field_offset_hex": (
                    "0x%x"
                    % memory["field_offset"]
                ),
                "access_type": kind,
                "access_size": size,
                "access_size_hex": (
                    None
                    if size is None
                    else "0x%x" % size
                ),
                "confidence": (
                    "TRACKED_CONTEXT_BASE"
                ),
            })

    # Separately detect the function's normal argument-struct
    # accesses once R14 is known to be the second argument after
    # the SubmitDcb thunk.
    argument_fields = []

    if name == "sceAgcDriverSubmitCommandBuffer":

        for instruction in instructions:

            for memory in parse_memory_operands(
                instruction["text"]
            ):

                if memory["base_register"] != SUBMIT_ARGUMENT_REG:
                    continue

                kind = classify_access(
                    instruction["text"],
                    memory,
                )

                size = infer_access_size(
                    instruction["text"],
                    instruction["bytes"],
                    kind,
                )

                argument_fields.append({
                    "instruction_va": instruction[
                        "address"
                    ],
                    "instruction": instruction[
                        "text"
                    ],
                    "base_register": SUBMIT_ARGUMENT_REG,
                    "field_offset": memory[
                        "field_offset"
                    ],
                    "field_offset_hex": (
                        "0x%x"
                        % memory["field_offset"]
                    ),
                    "access_type": kind,
                    "access_size": size,
                    "access_size_hex": (
                        None
                        if size is None
                        else "0x%x" % size
                    ),
                })

    return {
        "name": name,
        "nid": info["nid"],
        "va": info["va"],
        "size": info["size"],
        "file_offset": va_to_file_offset(
            info["va"]
        ),
        "context_references": context_refs,
        "context_accesses": accesses,
        "argument_struct_fields": argument_fields,
        "raw_bytes": raw.hex(" "),
        "instructions": [
            {
                "va": ins["address"],
                "bytes": ins["bytes"],
                "text": ins["text"],
            }
            for ins in instructions
        ],
    }


def build_context_field_map(functions):

    result = defaultdict(dict)

    for function_name, data in functions.items():

        for access in data[
            "context_accesses"
        ]:

            context = access["context"]
            offset = access["field_offset"]

            if offset not in result[
                context
            ]:

                result[context][
                    offset
                ] = {
                    "offset": offset,
                    "offset_hex": (
                        "0x%x" % offset
                    ),
                    "accesses": [],
                    "functions": set(),
                    "access_types": set(),
                    "sizes": set(),
                }

            row = result[
                context
            ][offset]

            row["functions"].add(
                function_name
            )

            row["access_types"].add(
                access["access_type"]
            )

            if access["access_size"] is not None:

                row["sizes"].add(
                    access["access_size"]
                )

            row["accesses"].append({
                "function": function_name,
                "instruction_va": access[
                    "instruction_va"
                ],
                "instruction": access[
                    "instruction"
                ],
                "access_type": access[
                    "access_type"
                ],
                "access_size": access[
                    "access_size"
                ],
            })

    serializable = {}

    for context, offsets in result.items():

        rows = []

        for offset in sorted(
            offsets.keys()
        ):

            row = offsets[offset]

            rows.append({
                "offset": row["offset"],
                "offset_hex": row[
                    "offset_hex"
                ],
                "functions": sorted(
                    row["functions"]
                ),
                "access_types": sorted(
                    row["access_types"]
                ),
                "sizes": sorted(
                    row["sizes"]
                ),
                "known_field_hint": (
                    KNOWN_CONTEXT_FIELDS
                    .get(context, {})
                    .get(offset)
                ),
                "accesses": row[
                    "accesses"
                ],
            })

        serializable[
            context
        ] = rows

    return serializable


def build_argument_struct_map(
    submit_fields
):

    result = {}

    for access in submit_fields:

        offset = access[
            "field_offset"
        ]

        row = result.setdefault(
            offset,
            {
                "offset": offset,
                "offset_hex": (
                    "0x%x" % offset
                ),
                "sizes": set(),
                "access_types": set(),
                "accesses": [],
            },
        )

        if access[
            "access_size"
        ] is not None:

            row["sizes"].add(
                access[
                    "access_size"
                ]
            )

        row["access_types"].add(
            access[
                "access_type"
            ]
        )

        row["accesses"].append(
            access
        )

    return [
        {
            "offset": row["offset"],
            "offset_hex": row["offset_hex"],
            "sizes": sorted(
                row["sizes"]
            ),
            "access_types": sorted(
                row["access_types"]
            ),
            "accesses": row["accesses"],
        }
        for _, row in sorted(
            result.items()
        )
    ]


def write_summary(
    functions,
    context_map,
    argument_map,
):

    path = os.path.join(
        OUT_DIR,
        "field_types_summary.txt",
    )

    with open(
        path,
        "w",
        encoding="utf-8",
    ) as fp:

        fp.write(
            "AGC PS5 Stage 51 - Precise Field Type / Access Audit\n\n"
        )

        fp.write(
            "=== CONTEXT REFERENCES ===\n\n"
        )

        for name, data in functions.items():

            if not data[
                "context_references"
            ]:
                continue

            fp.write(
                f"[{name}] VA=0x{data['va']:x}\n"
            )

            for ref in data[
                "context_references"
            ]:

                fp.write(
                    "  0x{:x}: {} -> {} "
                    "0x{:x}\n".format(
                        ref["instruction_va"],
                        ref["instruction"],
                        ref["context"],
                        ref["target_va"],
                    )
                )

            fp.write("\n")

        fp.write(
            "=== CONTEXT FIELD TYPES ===\n\n"
        )

        for context, rows in context_map.items():

            fp.write(
                f"[{context}]\n"
            )

            for row in rows:

                fp.write(
                    "  {} sizes={} "
                    "types={} "
                    "functions={}\n".format(
                        row["offset_hex"],
                        (
                            "-"
                            if not row["sizes"]
                            else ",".join(
                                str(x)
                                for x in row["sizes"]
                            )
                        ),
                        ",".join(
                            row["access_types"]
                        ),
                        ", ".join(
                            row["functions"]
                        ),
                    )
                )

                if row[
                    "known_field_hint"
                ]:

                    fp.write(
                        "      hint={}\n".format(
                            row[
                                "known_field_hint"
                            ]
                        )
                    )

            fp.write("\n")

        fp.write(
            "=== SubmitCommandBuffer ARGUMENT STRUCT ===\n\n"
        )

        for row in argument_map:

            fp.write(
                "offset={} sizes={} types={}\n".format(
                    row["offset_hex"],
                    (
                        "-"
                        if not row["sizes"]
                        else ",".join(
                            str(x)
                            for x in row["sizes"]
                        )
                    ),
                    ",".join(
                        row["access_types"]
                    ),
                )
            )

            for access in row[
                "accesses"
            ]:

                fp.write(
                    "  0x{:x}: {} "
                    "size={} type={}\n".format(
                        access[
                            "instruction_va"
                        ],
                        access[
                            "instruction"
                        ],
                        access[
                            "access_size"
                        ],
                        access[
                            "access_type"
                        ],
                    )
                )

            fp.write("\n")

        fp.write(
            "=== INTERPRETATION ===\n\n"
        )

        fp.write(
            "This stage does not assert a final C ABI signature.\n"
        )

        fp.write(
            "It records exact machine-code access width where "
            "the opcode/register encoding permits it.\n"
        )

        fp.write(
            "A NULL size means the width could not be established "
            "reliably by this static pass.\n"
        )

    return path


def write_submit_disassembly(
    functions
):

    data = functions[
        "sceAgcDriverSubmitCommandBuffer"
    ]

    path = os.path.join(
        OUT_DIR,
        "submit_commandbuffer_disassembly.txt",
    )

    with open(
        path,
        "w",
        encoding="utf-8",
    ) as fp:

        fp.write(
            "sceAgcDriverSubmitCommandBuffer\n"
        )

        fp.write(
            "VA=0x{:x} SIZE=0x{:x}\n\n".format(
                data["va"],
                data["size"],
            )
        )

        for instruction in data[
            "instructions"
        ]:

            fp.write(
                "0x{:x}: {}\n".format(
                    instruction["va"],
                    instruction["text"],
                )
            )

    return path


def write_function_bins(functions):

    directory = os.path.join(
        OUT_DIR,
        "functions",
    )

    os.makedirs(
        directory,
        exist_ok=True,
    )

    for name, data in functions.items():

        safe = re.sub(
            r"[^A-Za-z0-9_.+-]",
            "_",
            name,
        )

        path = os.path.join(
            directory,
            safe + ".bin",
        )

        with open(
            path,
            "wb",
        ) as fp:

            fp.write(
                bytes.fromhex(
                    data["raw_bytes"]
                )
            )


def main():

    os.makedirs(
        OUT_DIR,
        exist_ok=True,
    )

    functions = {}

    for name, info in TARGETS.items():

        functions[
            name
        ] = analyze_function(
            name,
            info,
        )

    context_map = build_context_field_map(
        functions
    )

    submit = functions[
        "sceAgcDriverSubmitCommandBuffer"
    ]

    argument_map = build_argument_struct_map(
        submit[
            "argument_struct_fields"
        ]
    )

    context_reference_count = sum(
        len(
            data["context_references"]
        )
        for data in functions.values()
    )

    context_access_count = sum(
        len(
            data["context_accesses"]
        )
        for data in functions.values()
    )

    precise_width_count = sum(
        1
        for data in functions.values()
        for access in data[
            "context_accesses"
        ]
        if access["access_size"] is not None
    )

    submit_arg_field_count = len(
        argument_map
    )

    write_count = sum(
        1
        for data in functions.values()
        for access in data[
            "context_accesses"
        ]
        if access["access_type"] == "WRITE"
    )

    rmw_count = sum(
        1
        for data in functions.values()
        for access in data[
            "context_accesses"
        ]
        if access["access_type"] == "RMW"
    )

    report = {
        "stage": 51,
        "contexts": CONTEXTS,
        "context_reference_count": context_reference_count,
        "context_access_count": context_access_count,
        "precise_width_count": precise_width_count,
        "submit_argument_field_count": submit_arg_field_count,
        "context_write_count": write_count,
        "context_rmw_count": rmw_count,
        "functions": functions,
        "context_field_map": context_map,
        "submit_command_buffer_argument_fields": argument_map,
        "conclusions": {
            "CONTEXT_REGISTER_TRACKING": (
                context_reference_count > 0
            ),
            "CONTEXT_ACCESS_SIZES_IDENTIFIED": (
                precise_width_count > 0
            ),
            "SUBMIT_ARGUMENT_FIELDS_IDENTIFIED": (
                submit_arg_field_count > 0
            ),
            "CONTEXT_WRITES_FOUND": (
                write_count > 0
            ),
            "CONTEXT_RMW_FOUND": (
                rmw_count > 0
            ),
            "ABI_PROTOTYPE_INFERRED": False,
            "EXECUTED_AGC": False,
        },
    }

    static_path = os.path.join(
        OUT_DIR,
        "stage51_static.json",
    )

    with open(
        static_path,
        "w",
        encoding="utf-8",
    ) as fp:

        json.dump(
            report,
            fp,
            indent=2,
        )

    write_function_bins(
        functions
    )

    write_summary(
        functions,
        context_map,
        argument_map,
    )

    write_submit_disassembly(
        functions
    )

    print(
        json.dumps(
            report,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()