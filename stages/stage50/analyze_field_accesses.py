from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from typing import Dict, List, Optional


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


def load_segments():

    result = []

    from elftools.elf.elffile import ELFFile

    with open(SPRX, "rb") as fp:

        elf = ELFFile(fp)

        for segment in elf.iter_segments():

            if segment["p_type"] != "PT_LOAD":
                continue

            result.append({
                "p_offset": int(segment["p_offset"]),
                "p_vaddr": int(segment["p_vaddr"]),
                "p_filesz": int(segment["p_filesz"]),
                "p_memsz": int(segment["p_memsz"]),
                "p_flags": int(segment["p_flags"]),
            })

    return result


LOADS = load_segments()


def va_to_file_offset(va: int) -> Optional[int]:

    for seg in LOADS:

        start = seg["p_vaddr"]
        end = start + seg["p_filesz"]

        if start <= va < end:
            return (
                seg["p_offset"] +
                va -
                start
            )

    return None


def read_va(va: int, size: int) -> bytes:

    offset = va_to_file_offset(va)

    if offset is None:
        return b""

    with open(SPRX, "rb") as fp:

        fp.seek(offset)

        return fp.read(size)


def write_temp_binary(
    name: str,
    raw: bytes
) -> str:

    path = os.path.join(
        OUT_DIR,
        name,
    )

    with open(path, "wb") as fp:
        fp.write(raw)

    return path


def disassemble(
    raw: bytes,
    base_va: int,
    temp_name: str,
) -> List[dict]:

    if not raw:
        return []

    path = write_temp_binary(
        temp_name,
        raw,
    )

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

    instructions = []

    for line in text.splitlines():

        # Example:
        #
        # 1908: 48 8d 1d f9 ...   lea 0x18ff9(%rip),%rbx
        #
        match = re.match(
            r"^\s*([0-9a-fA-F]+)\s*:\s+"
            r"((?:[0-9a-fA-F]{2}\s+)+)"
            r"(.+?)\s*$",
            line,
        )

        if not match:
            continue

        try:
            address = int(
                match.group(1),
                16,
            )
        except ValueError:
            continue

        bytes_text = (
            match.group(2)
            .strip()
        )

        text = (
            match.group(3)
            .strip()
        )

        instructions.append({
            "address": address,
            "bytes": bytes_text,
            "text": text,
            "raw_line": line,
        })

    return instructions


def parse_rip_lea(
    instruction: dict
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

    # Determine instruction length directly from its byte field.
    byte_count = len(
        instruction["bytes"].split()
    )

    target = (
        instruction["address"] +
        byte_count +
        displacement
    )

    for context_name, context_va in CONTEXTS.items():

        if target == context_va:

            return {
                "instruction_va": instruction["address"],
                "instruction": instruction["text"],
                "register": register,
                "context": context_name,
                "target_va": target,
                "displacement": displacement,
            }

    return None


def split_operands(text: str):

    if " " not in text:
        return []

    mnemonic, operands = text.split(
        None,
        1,
    )

    # The AT&T operands in these functions are simple enough
    # that comma splitting is safe for our purposes.
    return [
        operand.strip()
        for operand in operands.split(",")
    ]


def memory_operands(text: str):

    result = []

    for match in re.finditer(
        r"(?:(-?0x[0-9a-fA-F]+|[-+]?\d+))?"
        r"\(%([a-zA-Z0-9]+)\)",
        text,
    ):

        displacement_text = match.group(1)
        base_register = match.group(2).lower()

        if displacement_text is None:
            displacement = 0
        else:
            try:
                displacement = int(
                    displacement_text,
                    0,
                )
            except ValueError:
                continue

        result.append({
            "base_register": base_register,
            "field_offset": displacement,
        })

    return result


def classify_access(
    text: str,
    memory: dict,
):

    mnemonic = (
        text.split(
            None,
            1,
        )[0].lower()
    )

    operands = split_operands(text)

    if not operands:
        return "UNKNOWN"

    memory_expr = (
        "(" +
        memory["base_register"] +
        ")"
    )

    # RMW operations.
    if mnemonic in {
        "xadd",
        "xchg",
        "inc",
        "dec",
        "lock",
    }:
        return "RMW"

    if mnemonic in {
        "and",
        "andb",
        "andl",
        "andq",
        "or",
        "orb",
        "orl",
        "orq",
        "add",
        "addb",
        "addl",
        "addq",
        "sub",
        "subb",
        "subl",
        "subq",
    }:
        return "RMW"

    # Call/jmp indirect slots are not useful as data-field accesses.
    if mnemonic in {
        "call",
        "jmp",
    }:
        return "INDIRECT_CONTROL"

    # AT&T: source, destination.
    if len(operands) >= 2:

        destination = operands[-1]

        if "(" + memory["base_register"] + ")" in destination:
            return "WRITE"

        source = operands[0]

        if "(" + memory["base_register"] + ")" in source:
            return "READ"

    return "MEMORY_ACCESS"


def analyze_function(
    name: str,
    info: dict,
):

    raw = read_va(
        info["va"],
        info["size"],
    )

    instructions = disassemble(
        raw,
        info["va"],
        re.sub(
            r"[^A-Za-z0-9_.-]",
            "_",
            name,
        ) + ".bin",
    )

    active_contexts = {}

    context_refs = []
    context_accesses = []

    for instruction in instructions:

        lea = parse_rip_lea(
            instruction
        )

        if lea is not None:

            active_contexts[
                lea["register"]
            ] = lea

            context_refs.append(
                lea
            )

        # --------------------------------------------------------
        # Propagate register-to-register context pointers.
        # --------------------------------------------------------

        text_lower = (
            instruction["text"]
            .lower()
            .strip()
        )

        move = re.match(
            r"^mov\s+%([a-z0-9]+)\s*,\s*%([a-z0-9]+)$",
            text_lower,
        )

        if move:

            src = move.group(1)
            dst = move.group(2)

            if src in active_contexts:

                active_contexts[dst] = dict(
                    active_contexts[src]
                )

            else:

                active_contexts.pop(
                    dst,
                    None,
                )

        # --------------------------------------------------------
        # Search every memory operand using a tracked context base.
        # --------------------------------------------------------

        for memory in memory_operands(
            instruction["text"]
        ):

            base = memory["base_register"]

            if base not in active_contexts:
                continue

            kind = classify_access(
                instruction["text"],
                memory,
            )

            if kind == "INDIRECT_CONTROL":
                continue

            context_info = active_contexts[
                base
            ]

            context_accesses.append({
                "instruction_va": instruction["address"],
                "instruction": instruction["text"],
                "base_register": base,
                "context": context_info["context"],
                "context_va": context_info["target_va"],
                "field_offset": memory["field_offset"],
                "field_offset_hex": (
                    "0x%x" % memory["field_offset"]
                ),
                "access_type": kind,
                "confidence": "TRACKED_CONTEXT_BASE",
            })

        # --------------------------------------------------------
        # Clear a tracked register when it is the explicit
        # destination of an instruction, except a fresh LEA
        # or the register copy handled above.
        # --------------------------------------------------------

        written_registers = set()

        operands = split_operands(
            instruction["text"]
        )

        if len(operands) >= 2:

            destination = operands[-1]

            dst_match = re.fullmatch(
                r"%([a-z0-9]+)",
                destination.lower(),
            )

            if dst_match:
                written_registers.add(
                    dst_match.group(1)
                )

        if lea is not None:
            written_registers.discard(
                lea["register"]
            )

        if move is not None:
            written_registers.discard(
                move.group(2)
            )

        for register in written_registers:

            active_contexts.pop(
                register,
                None,
            )

    return {
        "name": name,
        "nid": info["nid"],
        "va": info["va"],
        "size": info["size"],
        "file_offset": va_to_file_offset(
            info["va"]
        ),
        "context_references": context_refs,
        "context_accesses": context_accesses,
        "raw_bytes": raw.hex(" "),
    }


def build_field_map(functions):

    result = {}

    for function_name, data in functions.items():

        for access in data["context_accesses"]:

            context = access["context"]
            offset = int(
                access["field_offset"]
            )

            by_offset = result.setdefault(
                context,
                {},
            )

            entry = by_offset.setdefault(
                offset,
                {
                    "offset": offset,
                    "offset_hex": (
                        "0x%x" % offset
                    ),
                    "functions": set(),
                    "reads": 0,
                    "writes": 0,
                    "rmw": 0,
                    "accesses": [],
                },
            )

            entry["functions"].add(
                function_name
            )

            access_type = access["access_type"]

            if access_type == "READ":
                entry["reads"] += 1

            elif access_type == "WRITE":
                entry["writes"] += 1

            elif access_type == "RMW":
                entry["rmw"] += 1

            entry["accesses"].append({
                "function": function_name,
                "instruction_va": access[
                    "instruction_va"
                ],
                "instruction": access[
                    "instruction"
                ],
                "access_type": access_type,
                "base_register": access[
                    "base_register"
                ],
            })

    serializable = {}

    for context, offsets in result.items():

        rows = []

        for offset in sorted(offsets):

            entry = offsets[offset]

            rows.append({
                "offset": entry["offset"],
                "offset_hex": entry[
                    "offset_hex"
                ],
                "functions": sorted(
                    entry["functions"]
                ),
                "reads": entry["reads"],
                "writes": entry["writes"],
                "rmw": entry["rmw"],
                "access_count": len(
                    entry["accesses"]
                ),
                "accesses": entry[
                    "accesses"
                ],
            })

        serializable[context] = rows

    return serializable


def write_summary(
    functions,
    field_map,
):

    path = os.path.join(
        OUT_DIR,
        "field_summary.txt",
    )

    with open(
        path,
        "w",
        encoding="utf-8",
    ) as fp:

        fp.write(
            "AGC PS5 Stage 50 - Register / Context Field Audit\n\n"
        )

        fp.write(
            "=== CONTEXT LEA REFERENCES ===\n"
        )

        for name, data in functions.items():

            refs = data[
                "context_references"
            ]

            if not refs:
                continue

            fp.write(
                f"\n[{name}] VA=0x{data['va']:x}\n"
            )

            for ref in refs:

                fp.write(
                    "  0x{:x}: {} "
                    "register={} "
                    "{}=0x{:x}\n".format(
                        ref["instruction_va"],
                        ref["instruction"],
                        ref["register"],
                        ref["context"],
                        ref["target_va"],
                    )
                )

        fp.write(
            "\n=== CONTEXT MEMORY ACCESSES ===\n"
        )

        total = 0

        for name, data in functions.items():

            accesses = data[
                "context_accesses"
            ]

            if not accesses:
                continue

            fp.write(
                f"\n[{name}]\n"
            )

            for access in accesses:

                total += 1

                fp.write(
                    "  0x{:x}: {} | "
                    "{} + {} | "
                    "base={} | "
                    "type={} | "
                    "confidence={}\n".format(
                        access["instruction_va"],
                        access["instruction"],
                        access["context"],
                        access["field_offset_hex"],
                        access["base_register"],
                        access["access_type"],
                        access["confidence"],
                    )
                )

        fp.write(
            "\nTOTAL_CONTEXT_MEMORY_ACCESSES = {}\n".format(
                total
            )
        )

        fp.write(
            "\n=== FIELD MAP ===\n"
        )

        for context, rows in field_map.items():

            fp.write(
                f"\n{context}\n"
            )

            for row in rows:

                fp.write(
                    "  {} reads={} writes={} rmw={} "
                    "accesses={} functions={}\n".format(
                        row["offset_hex"],
                        row["reads"],
                        row["writes"],
                        row["rmw"],
                        row["access_count"],
                        ", ".join(
                            row["functions"]
                        ),
                    )
                )

    return path


def write_family_disassembly(
    functions,
):

    path = os.path.join(
        OUT_DIR,
        "submit_family_disassembly.txt",
    )

    with open(
        path,
        "w",
        encoding="utf-8",
    ) as fp:

        for name, data in functions.items():

            raw = bytes.fromhex(
                data["raw_bytes"]
            )

            binary_name = re.sub(
                r"[^A-Za-z0-9_.-]",
                "_",
                name,
            ) + "_family.bin"

            instructions = disassemble(
                raw,
                data["va"],
                binary_name,
            )

            fp.write(
                "=" * 72 + "\n"
            )

            fp.write(
                "{} VA=0x{:x} SIZE=0x{:x}\n".format(
                    name,
                    data["va"],
                    data["size"],
                )
            )

            fp.write(
                "=" * 72 + "\n\n"
            )

            for instruction in instructions:

                fp.write(
                    "0x{:x}: {}\n".format(
                        instruction["address"],
                        instruction["text"],
                    )
                )

            fp.write("\n")

    return path


def write_function_binaries(functions):

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

        functions[name] = analyze_function(
            name,
            info,
        )

    field_map = build_field_map(
        functions
    )

    context_reference_count = sum(
        len(
            data["context_references"]
        )
        for data in functions.values()
    )

    context_memory_access_count = sum(
        len(
            data["context_accesses"]
        )
        for data in functions.values()
    )

    submit = functions[
        "sceAgcDriverSubmitCommandBuffer"
    ]

    report = {
        "stage": 50,
        "contexts": CONTEXTS,
        "context_reference_count": (
            context_reference_count
        ),
        "context_memory_access_count": (
            context_memory_access_count
        ),
        "functions": functions,
        "field_map": field_map,
        "submit_command_buffer": {
            "va": submit["va"],
            "size": submit["size"],
            "context_references": submit[
                "context_references"
            ],
            "context_accesses": submit[
                "context_accesses"
            ],
        },
        "conclusions": {
            "CONTEXT_REGISTER_TRACKING": (
                context_reference_count > 0
            ),
            "CONTEXT_MEMORY_ACCESS_FOUND": (
                context_memory_access_count > 0
            ),
            "SUBMIT_CONTEXT_ACCESS_FOUND": bool(
                submit["context_references"] or
                submit["context_accesses"]
            ),
            "WRITE_SITES_PROVEN": any(
                access["access_type"] in {
                    "WRITE",
                    "RMW",
                }
                for data in functions.values()
                for access in data[
                    "context_accesses"
                ]
            ),
            "ABI_PROTOTYPE_INFERRED": False,
            "EXECUTED_AGC": False,
        },
    }

    with open(
        os.path.join(
            OUT_DIR,
            "stage50_static.json",
        ),
        "w",
        encoding="utf-8",
    ) as fp:

        json.dump(
            report,
            fp,
            indent=2,
        )

    write_function_binaries(
        functions
    )

    write_summary(
        functions,
        field_map,
    )

    write_family_disassembly(
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