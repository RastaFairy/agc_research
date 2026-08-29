from elftools.elf.elffile import ELFFile
import json
import os
import struct
import sys

sprx = sys.argv[1]
nid_db = sys.argv[2]
out_dir = sys.argv[3]

TARGET_FUNC = 0x18B0

CONTEXT_DCB     = 0x1A8B8
CONTEXT_AGR     = 0x1A868
CONTEXT_GLOBAL  = 0x1A908
ACB_TABLE       = 0x18460

TARGETS = {
    "submit_dcb_context": CONTEXT_DCB,
    "agr_submit_dcb_context": CONTEXT_AGR,
    "global_state_context": CONTEXT_GLOBAL,
    "acb_table": ACB_TABLE,
}

with open(
    nid_db,
    "r",
    encoding="utf-8",
    errors="replace"
) as fp:

    nid_map = {}

    for line in fp:

        line = line.strip()

        if not line:
            continue

        parts = line.split(" ", 1)

        if len(parts) == 2:
            nid_map[parts[0]] = parts[1]

with open(sprx, "rb") as f:

    elf = ELFFile(f)

    # --------------------------------------------------------
    # Dynamic symbols
    # --------------------------------------------------------

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
                item["mapped_name"] = nid_map.get(parts[0])

        symbols.append(item)

    # --------------------------------------------------------
    # PT_LOAD information
    # --------------------------------------------------------

    loads = []

    for seg in elf.iter_segments():

        if seg.header.p_type != "PT_LOAD":
            continue

        loads.append({
            "offset": int(seg.header.p_offset),
            "vaddr": int(seg.header.p_vaddr),
            "filesz": int(seg.header.p_filesz),
            "memsz": int(seg.header.p_memsz),
            "flags": int(seg.header.p_flags)
        })

    def classify_va(va):

        for seg in loads:

            start = seg["vaddr"]
            mem_end = start + seg["memsz"]
            file_end = start + seg["filesz"]

            if start <= va < mem_end:

                if va < file_end:
                    region = "FILE_BACKED"
                else:
                    region = "BSS_OR_ZERO_FILL"

                flags = seg["flags"]

                perms = ""

                if flags & 4:
                    perms += "R"

                if flags & 2:
                    perms += "W"

                if flags & 1:
                    perms += "X"

                return {
                    "region": region,
                    "permissions": perms,
                    "segment_vaddr": start,
                    "segment_filesz": seg["filesz"],
                    "segment_memsz": seg["memsz"],
                    "in_file": va < file_end
                }

        return {
            "region": "UNMAPPED",
            "permissions": "",
            "in_file": False
        }

    # --------------------------------------------------------
    # VA -> file offset
    # --------------------------------------------------------

    def va_to_file_offset(va):

        for seg in loads:

            start = seg["vaddr"]
            filesz = seg["filesz"]

            if start <= va < start + filesz:

                return (
                    seg["offset"] +
                    (va - start)
                )

        return None

    def read_va(va, size):

        off = va_to_file_offset(va)

        if off is None:

            return {
                "va": va,
                "file_offset": None,
                "size": 0,
                "bytes_hex": None
            }

        f.seek(off)

        data = f.read(size)

        return {
            "va": va,
            "file_offset": off,
            "size": len(data),
            "bytes_hex": data.hex(" ")
        }

    # --------------------------------------------------------
    # Symbol lookup
    # --------------------------------------------------------

    def nearby_symbols(target, radius=0x200):

        result = []

        for sym in symbols:

            delta = sym["value"] - target

            if -radius <= delta <= radius:

                result.append({
                    "delta": delta,
                    "value": sym["value"],
                    "size": sym["size"],
                    "type": sym["type"],
                    "bind": sym["bind"],
                    "raw_name": sym["raw_name"],
                    "nid": sym.get("nid"),
                    "mapped_name": sym.get("mapped_name")
                })

        result.sort(
            key=lambda x: (
                x["value"],
                x["raw_name"]
            )
        )

        return result

    # --------------------------------------------------------
    # Context / table inspection
    # --------------------------------------------------------

    targets = {}

    for name, va in TARGETS.items():

        targets[name] = {
            "va": va,
            "classification": classify_va(va),
            "nearby_symbols": nearby_symbols(va),
            "dump_256": read_va(va, 256)
        }

    # ACB table is interesting because SubmitAcb uses:
    #
    #   base + index * 0x90 + 0x08
    #
    # Capture multiple entries.
    acb_entries = []

    for index in range(8):

        entry_va = ACB_TABLE + (index * 0x90)

        acb_entries.append({
            "index": index,
            "entry_va": entry_va,
            "entry_plus_8": entry_va + 8,
            "bytes": read_va(entry_va, 0x90),
            "classification": classify_va(entry_va)
        })

    # --------------------------------------------------------
    # Scan executable segments for RIP-relative references
    # to our context addresses.
    #
    # This recognizes:
    #   48 8d xx disp32
    #   48 8b xx disp32
    #   4c 8d xx disp32
    #   4c 8b xx disp32
    #
    # using generic ModRM decoding only for RIP-relative forms.
    # --------------------------------------------------------

    rip_references = []

    interesting = set(TARGETS.values())
    interesting.add(TARGET_FUNC)

    for seg in elf.iter_segments():

        if seg.header.p_type != "PT_LOAD":
            continue

        flags = int(seg.header.p_flags)

        if not (flags & 1):
            continue

        seg_vaddr = int(seg.header.p_vaddr)
        seg_offset = int(seg.header.p_offset)
        seg_filesz = int(seg.header.p_filesz)

        f.seek(seg_offset)

        data = f.read(seg_filesz)

        for i in range(0, max(0, len(data) - 7)):

            b0 = data[i]

            # Scan common REX + opcode forms that use ModRM.
            if b0 not in (
                0x48,
                0x4C,
            ):
                continue

            if i + 7 > len(data):
                continue

            op = data[i + 1]
            modrm = data[i + 2]

            # RIP relative addressing:
            # mod=00 and r/m=101
            if (modrm & 0xC7) != 0x05:
                continue

            if op not in (
                0x8B,  # MOV r64,r/m64
                0x8D,  # LEA
            ):
                continue

            disp = struct.unpack_from(
                "<i",
                data,
                i + 3
            )[0]

            instruction_va = seg_vaddr + i
            next_va = instruction_va + 7
            target_va = next_va + disp

            if target_va in interesting:

                rip_references.append({
                    "instruction_va": instruction_va,
                    "target_va": target_va,
                    "opcode": f"0x{op:02x}",
                    "displacement": disp,
                    "file_offset": seg_offset + i
                })

    # --------------------------------------------------------
    # Scan all file-backed data for literal 64-bit pointers
    # to context/table addresses.
    # --------------------------------------------------------

    pointer_references = []

    target_bytes = {}

    for name, va in TARGETS.items():

        target_bytes[va] = name

    for seg in elf.iter_segments():

        if seg.header.p_type != "PT_LOAD":
            continue

        seg_vaddr = int(seg.header.p_vaddr)
        seg_offset = int(seg.header.p_offset)
        seg_filesz = int(seg.header.p_filesz)

        f.seek(seg_offset)
        data = f.read(seg_filesz)

        for i in range(
            0,
            max(0, len(data) - 8),
            8
        ):

            value = struct.unpack_from(
                "<Q",
                data,
                i
            )[0]

            if value in target_bytes:

                pointer_references.append({
                    "file_offset": seg_offset + i,
                    "va": seg_vaddr + i,
                    "points_to": value,
                    "target_name": target_bytes[value]
                })

    # --------------------------------------------------------
    # Cross-reference to context field offsets used by
    # SubmitCommandBuffer.
    # --------------------------------------------------------

    field_offsets = [
        0x00,
        0x08,
        0x0C,
        0x14,
        0x20,
        0x28,
        0x30,
        0x38,
        0x48,
        0xA0,
        0xA4,
        0x140,
        0x148
    ]

    context_field_layout = []

    for offset in field_offsets:

        context_field_layout.append({
            "offset": f"0x{offset:x}",
            "dcb_va": CONTEXT_DCB + offset,
            "agr_va": CONTEXT_AGR + offset
        })

    result = {
        "targets": targets,

        "acb_table": {
            "base": ACB_TABLE,
            "stride": 0x90,
            "entry_count_dumped": len(acb_entries),
            "entries": acb_entries
        },

        "rip_references": rip_references,

        "pointer_references": pointer_references,

        "submit_command_buffer_fields": context_field_layout,

        "loads": loads
    }

with open(
    os.path.join(out_dir, "stage47_static.json"),
    "w",
    encoding="utf-8"
) as fp:

    json.dump(
        result,
        fp,
        indent=2
    )

print(
    json.dumps(
        result,
        indent=2
    )
)