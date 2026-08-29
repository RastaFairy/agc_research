from elftools.elf.elffile import ELFFile
import json
import os
import struct
import sys

sprx = sys.argv[1]
out_dir = sys.argv[2]

TARGET = 0x18b0
TARGET_SIZE = 380

# Absolute-ish virtual-address calculations based on the fact that
# the Stage 44 raw function was extracted starting at VA 0x18b0.
#
# The following RIP-relative references were observed:
#
# 0x11 : mov 0x12820(%rip), %rbx
# 0x58 : lea 0x18ff9(%rip), %rbx
# 0x111: mov 0xa4(%rbx), %eax
#
# Calls:
#   0x2c -> 0x9360 relative to raw body
#   0x104 -> 0x92c0
#   0x12d -> 0x9370
#   0x14e -> 0x92c0
#   0x175 -> 0x9380
#
# We calculate their absolute VAs by adding TARGET.

def va_to_file_offset(elf, va):
    for seg in elf.iter_segments():
        if seg.header.p_type != "PT_LOAD":
            continue

        vaddr = int(seg.header.p_vaddr)
        memsz = int(seg.header.p_memsz)
        offset = int(seg.header.p_offset)

        if vaddr <= va < vaddr + memsz:
            return offset + (va - vaddr)

    return None

def read_va(f, elf, va, size):
    off = va_to_file_offset(elf, va)

    if off is None:
        return None

    f.seek(off)
    data = f.read(size)

    return {
        "va": va,
        "file_offset": off,
        "size": len(data),
        "bytes_hex": data.hex(" ")
    }

with open(sprx, "rb") as f:
    elf = ELFFile(f)

    dynamic = None

    for seg in elf.iter_segments():
        if seg.header.p_type == "PT_DYNAMIC":
            dynamic = seg
            break

    if dynamic is None:
        raise RuntimeError("No PT_DYNAMIC")

    symbols = []

    for sym in dynamic.iter_symbols():

        raw = sym.name

        if not raw:
            continue

        value = int(sym["st_value"])
        size = int(sym["st_size"])

        item = {
            "raw_name": raw,
            "value": value,
            "size": size,
            "type": str(sym["st_info"]["type"]),
            "bind": str(sym["st_info"]["bind"])
        }

        if "#" in raw:

            parts = raw.split("#")

            if len(parts) == 3:
                item["nid"] = parts[0]
                item["lid"] = parts[1]
                item["mid"] = parts[2]

        symbols.append(item)

    internal = [
        s for s in symbols
        if s.get("value") == TARGET
    ]

    if not internal:
        raise RuntimeError(
            f"No dynamic symbol at target VA 0x{TARGET:x}"
        )

    # --------------------------------------------------------
    # Read the internal function.
    # --------------------------------------------------------

    body = read_va(
        f,
        elf,
        TARGET,
        TARGET_SIZE
    )

    if body is None:
        raise RuntimeError("Unable to map internal function")

    with open(
        os.path.join(out_dir, "submitcommandbuffer.bin"),
        "wb"
    ) as fp:
        fp.write(bytes.fromhex(body["bytes_hex"]))

    # --------------------------------------------------------
    # Absolute addresses of observed internal calls.
    # --------------------------------------------------------

    observed_calls = [
        {
            "internal_offset": 0x2c,
            "target_offset": 0x9360,
            "target_va": TARGET + 0x9360
        },
        {
            "internal_offset": 0x104,
            "target_offset": 0x92c0,
            "target_va": TARGET + 0x92c0
        },
        {
            "internal_offset": 0x12d,
            "target_offset": 0x9370,
            "target_va": TARGET + 0x9370
        },
        {
            "internal_offset": 0x14e,
            "target_offset": 0x92c0,
            "target_va": TARGET + 0x92c0
        },
        {
            "internal_offset": 0x175,
            "target_offset": 0x9380,
            "target_va": TARGET + 0x9380
        }
    ]

    # --------------------------------------------------------
    # Absolute RIP-relative data targets from Stage 44.
    # --------------------------------------------------------

    data_refs = [
        {
            "instruction_offset": 0x11,
            "description": "global pointer loaded into RBX",
            "displacement": 0x12820,
            "next_instruction_offset": 0x18,
            "target_va": TARGET + 0x18 + 0x12820
        },
        {
            "instruction_offset": 0x58,
            "description": "RIP-relative address placed in RBX",
            "displacement": 0x18ff9,
            "next_instruction_offset": 0x5f,
            "target_va": TARGET + 0x5f + 0x18ff9
        },
        {
            "instruction_offset": 0xec,
            "description": "global error/log object",
            "displacement": 0x1273d,
            "next_instruction_offset": 0xf3,
            "target_va": TARGET + 0xf3 + 0x1273d
        },
        {
            "instruction_offset": 0x153,
            "description": "global pointer reloaded into RBX",
            "displacement": 0x126de,
            "next_instruction_offset": 0x15a,
            "target_va": TARGET + 0x15a + 0x126de
        }
    ]

    # --------------------------------------------------------
    # Extract nearby symbols for every interesting address.
    # --------------------------------------------------------

    def nearby(target, radius=512):
        rows = []

        for s in symbols:

            delta = s["value"] - target

            if -radius <= delta <= radius:

                rows.append({
                    "delta": delta,
                    "value": s["value"],
                    "size": s["size"],
                    "type": s["type"],
                    "bind": s["bind"],
                    "raw_name": s["raw_name"],
                    "nid": s.get("nid")
                })

        rows.sort(
            key=lambda x: (
                x["value"],
                x["raw_name"]
            )
        )

        return rows

    call_targets = []

    for call in observed_calls:

        item = dict(call)

        item["nearby_symbols"] = nearby(
            call["target_va"],
            512
        )

        item["target_bytes"] = read_va(
            f,
            elf,
            call["target_va"],
            64
        )

        call_targets.append(item)

    data_targets = []

    for ref in data_refs:

        item = dict(ref)

        item["nearby_symbols"] = nearby(
            ref["target_va"],
            512
        )

        item["target_bytes"] = read_va(
            f,
            elf,
            ref["target_va"],
            128
        )

        data_targets.append(item)

    # --------------------------------------------------------
    # Scan for direct CALL/JMP references to 0x18b0.
    #
    # Search PT_LOAD bytes for E8/E9 rel32 whose decoded
    # destination equals TARGET.
    # --------------------------------------------------------

    references = []

    for seg in elf.iter_segments():

        if seg.header.p_type != "PT_LOAD":
            continue

        flags = int(seg.header.p_flags)

        # executable segment
        if not (flags & 1):
            continue

        seg_vaddr = int(seg.header.p_vaddr)
        seg_offset = int(seg.header.p_offset)
        seg_filesz = int(seg.header.p_filesz)

        f.seek(seg_offset)
        data = f.read(seg_filesz)

        for i in range(0, max(0, len(data) - 5)):

            opcode = data[i]

            if opcode not in (0xE8, 0xE9):
                continue

            disp = struct.unpack_from(
                "<i",
                data,
                i + 1
            )[0]

            next_va = seg_vaddr + i + 5
            dest = next_va + disp

            if dest == TARGET:

                references.append({
                    "type": "CALL" if opcode == 0xE8 else "JMP",
                    "source_va": next_va - 5,
                    "destination_va": dest,
                    "file_offset": seg_offset + i,
                    "displacement": disp
                })

    result = {
        "internal_function": {
            "va": TARGET,
            "size": TARGET_SIZE,
            "symbols": internal,
            "raw": body
        },

        "known_field_accesses": {
            "argument_register": "RSI/R14 after thunk",
            "field_offsets": [
                {
                    "offset": "0x00",
                    "width": 8,
                    "instruction": "mov (%r14), %rax"
                },
                {
                    "offset": "0x08",
                    "width": 4,
                    "instruction": "mov 0x8(%r14), %eax"
                },
                {
                    "offset": "0x0c",
                    "width": 1,
                    "instruction": "mov 0xc(%r14), %al"
                }
            ]
        },

        "observed_call_targets": call_targets,

        "observed_data_targets": data_targets,

        "direct_references_to_internal": references
    }

with open(
    os.path.join(out_dir, "stage45_static.json"),
    "w",
    encoding="utf-8"
) as fp:
    json.dump(result, fp, indent=2)

print(
    json.dumps(
        result,
        indent=2
    )
)