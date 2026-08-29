from elftools.elf.elffile import ELFFile
import json
import os
import struct
import sys

sprx = sys.argv[1]
nid_db = sys.argv[2]
out_dir = sys.argv[3]

TARGETS = {
    "submit_command_buffer": 0x18B0,
    "submit_dcb_context": 0x1A8B8,
    "agr_submit_dcb_context": 0x1A868,
    "global_state_context": 0x1A908,
    "acb_table": 0x18460,
}

WINDOW_BEFORE = 48
WINDOW_AFTER = 96

# ------------------------------------------------------------
# NID map
# ------------------------------------------------------------

nid_map = {}

with open(
    nid_db,
    "r",
    encoding="utf-8",
    errors="replace"
) as fp:

    for line in fp:

        line = line.strip()

        if not line:
            continue

        parts = line.split(" ", 1)

        if len(parts) == 2:
            nid_map[parts[0]] = parts[1]

# ------------------------------------------------------------
# ELF
# ------------------------------------------------------------

with open(sprx, "rb") as f:

    elf = ELFFile(f)

    dynamic = None

    for seg in elf.iter_segments():

        if seg.header.p_type == "PT_DYNAMIC":
            dynamic = seg
            break

    if dynamic is None:
        raise RuntimeError("PT_DYNAMIC not found")

    symbols = []

    for sym in dynamic.iter_symbols():

        if not sym.name:
            continue

        raw = sym.name

        item = {
            "raw_name": raw,
            "value": int(sym["st_value"]),
            "size": int(sym["st_size"]),
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

    # --------------------------------------------------------
    # Read
    # --------------------------------------------------------

    def read_va(va, size):

        off = va_to_file_offset(va)

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

    # --------------------------------------------------------
    # Find symbol owner
    # --------------------------------------------------------

    def owners(va):

        result = []

        for sym in symbols:

            start = sym["value"]
            size = sym["size"]

            if size <= 0:
                continue

            if start <= va < start + size:

                result.append(sym)

        return result

    # --------------------------------------------------------
    # Find functions containing an address
    # --------------------------------------------------------

    def function_owner(va):

        matches = []

        for sym in symbols:

            if sym.get("type") != "STT_FUNC":
                continue

            start = sym["value"]
            size = sym["size"]

            if size <= 0:
                continue

            if start <= va < start + size:

                matches.append(sym)

        if matches:
            matches.sort(
                key=lambda x: (
                    x["size"],
                    x["value"]
                )
            )

            return matches[0]

        return None

    # --------------------------------------------------------
    # Executable bytes
    # --------------------------------------------------------

    executable_segments = []

    for seg in loads:

        if seg["flags"] & 1:

            executable_segments.append(seg)

    # --------------------------------------------------------
    # Reference scanner
    #
    # We identify RIP-relative LEA/MOV references to the
    # exact context addresses, then generate disassembly
    # windows around those locations.
    # --------------------------------------------------------

    references = []

    for seg in executable_segments:

        seg_vaddr = seg["vaddr"]
        seg_offset = seg["offset"]
        seg_filesz = seg["filesz"]

        f.seek(seg_offset)

        data = f.read(seg_filesz)

        i = 0

        while i + 7 <= len(data):

            rex = data[i]
            op  = data[i + 1]
            modrm = data[i + 2]

            if rex not in (0x48, 0x4C):
                i += 1
                continue

            if op not in (0x8B, 0x8D):
                i += 1
                continue

            # RIP-relative ModRM:
            # mod = 00
            # r/m = 101
            if (modrm & 0xC7) != 0x05:
                i += 1
                continue

            disp = struct.unpack_from(
                "<i",
                data,
                i + 3
            )[0]

            insn_va = seg_vaddr + i
            next_va = insn_va + 7
            target_va = next_va + disp

            matched_target = None

            for name, target in TARGETS.items():

                if target_va == target:
                    matched_target = name
                    break

            if matched_target is not None:

                owner = function_owner(insn_va)

                references.append({
                    "instruction_va": insn_va,
                    "target_va": target_va,
                    "target_name": matched_target,
                    "opcode": f"0x{op:02x}",
                    "displacement": disp,
                    "file_offset": seg_offset + i,
                    "owner": owner
                })

            i += 1

    # --------------------------------------------------------
    # Group references
    # --------------------------------------------------------

    by_target = {}

    for name in TARGETS:

        by_target[name] = []

    for ref in references:

        by_target[
            ref["target_name"]
        ].append(ref)

    # --------------------------------------------------------
    # Extract windows
    # --------------------------------------------------------

    windows = []

    for ref in references:

        start_va = max(
            0,
            ref["instruction_va"] - WINDOW_BEFORE
        )

        size = (
            WINDOW_BEFORE +
            7 +
            WINDOW_AFTER
        )

        raw = read_va(
            start_va,
            size
        )

        if raw is None:
            continue

        windows.append({
            "target_name": ref["target_name"],
            "target_va": ref["target_va"],
            "instruction_va": ref["instruction_va"],
            "owner": ref["owner"],
            "raw": raw
        })

    # --------------------------------------------------------
    # Write static result
    # --------------------------------------------------------

    result = {
        "targets": TARGETS,
        "reference_count": len(references),
        "references": references,
        "references_by_target": by_target,
        "windows": windows,
        "loads": loads
    }

with open(
    os.path.join(out_dir, "stage48_static.json"),
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