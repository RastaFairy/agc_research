from elftools.elf.elffile import ELFFile
import json
import os
import struct
import sys

sprx = sys.argv[1]
out_dir = sys.argv[2]

TARGET_NID = "UglJIZjGssM"
TARGET_VA  = 0x28b0

# Bytes from Stage 42:
# 48 89 fe
# 48 8d 3d fe 7f 01 00
# e9 f1 ef ff ff

JMP_DISP = struct.unpack("<i", bytes.fromhex("f1 ef ff ff"))[0]

# jmp is 5 bytes and starts at VA 0x28ba.
JMP_NEXT = TARGET_VA + 10 + 5
JMP_TARGET = JMP_NEXT + JMP_DISP

# lea starts at VA 0x28b3.
# Its instruction is 7 bytes.
LEA_NEXT = TARGET_VA + 3 + 7
LEA_DISP = 0x17ffe
LEA_TARGET = LEA_NEXT + LEA_DISP

with open(sprx, "rb") as f:
    elf = ELFFile(f)

    # --------------------------------------------------------
    # Symbol data from PT_DYNAMIC, same mechanism as genstub.
    # --------------------------------------------------------

    dynamic = None

    for seg in elf.iter_segments():
        if seg.header.p_type == "PT_DYNAMIC":
            dynamic = seg
            break

    if dynamic is None:
        raise RuntimeError("No PT_DYNAMIC")

    dynamic_symbols = []

    for sym in dynamic.iter_symbols():

        name = sym.name

        if not name:
            continue

        value = int(sym["st_value"])
        size = int(sym["st_size"])

        dynamic_symbols.append({
            "name": name,
            "value": value,
            "size": size,
            "type": str(sym["st_info"]["type"]),
            "bind": str(sym["st_info"]["bind"])
        })

    # --------------------------------------------------------
    # Map VA -> file offset.
    # --------------------------------------------------------

    def va_to_file_offset(va):
        for seg in elf.iter_segments():

            if seg.header.p_type != "PT_LOAD":
                continue

            vaddr = int(seg.header.p_vaddr)
            memsz = int(seg.header.p_memsz)
            offset = int(seg.header.p_offset)

            if vaddr <= va < vaddr + memsz:
                return offset + (va - vaddr)

        return None

    # --------------------------------------------------------
    # Read bytes around branch target and LEA target.
    # --------------------------------------------------------

    analyses = {}

    for label, va, size in [
        ("submit_export", TARGET_VA, 15),
        ("jmp_target", JMP_TARGET, 128),
        ("lea_target", LEA_TARGET, 128)
    ]:

        off = va_to_file_offset(va)

        entry = {
            "va": va,
            "file_offset": off,
            "read_size": size,
            "bytes_hex": None
        }

        if off is not None:

            f.seek(off)
            data = f.read(size)

            entry["bytes_hex"] = data.hex(" ")
            entry["bytes_count"] = len(data)

        analyses[label] = entry

    # --------------------------------------------------------
    # Find dynamic exports/symbols around calculated targets.
    # --------------------------------------------------------

    def nearby_symbols(target, radius=256):

        result = []

        for sym in dynamic_symbols:

            if not sym["name"]:
                continue

            value = sym["value"]
            delta = value - target

            if -radius <= delta <= radius:

                result.append({
                    "delta": delta,
                    "value": value,
                    "size": sym["size"],
                    "type": sym["type"],
                    "bind": sym["bind"],
                    "name": sym["name"]
                })

        result.sort(
            key=lambda x: (x["value"], x["name"])
        )

        return result

    nearby_jmp = nearby_symbols(JMP_TARGET, 512)
    nearby_lea = nearby_symbols(LEA_TARGET, 512)

    result = {
        "submit_dcb": {
            "nid": TARGET_NID,
            "va": TARGET_VA,
            "size": 15
        },

        "decoded": {
            "jmp_displacement": JMP_DISP,
            "jmp_next": JMP_NEXT,
            "jmp_target": JMP_TARGET,

            "lea_displacement": LEA_DISP,
            "lea_next": LEA_NEXT,
            "lea_target": LEA_TARGET
        },

        "analyses": analyses,

        "nearby_jmp_symbols": nearby_jmp,
        "nearby_lea_symbols": nearby_lea
    }

with open(
    os.path.join(out_dir, "stage43_static.json"),
    "w",
    encoding="utf-8"
) as fp:
    json.dump(result, fp, indent=2)

print(json.dumps(result, indent=2))