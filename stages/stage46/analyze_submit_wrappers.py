from elftools.elf.elffile import ELFFile
import json
import os
import struct
import sys

sprx = sys.argv[1]
nid_db = sys.argv[2]
out_dir = sys.argv[3]

TARGET = 0x18b0

nid_map = {}

with open(nid_db, "r", encoding="utf-8", errors="replace") as fp:
    for line in fp:
        line = line.strip()

        if not line:
            continue

        parts = line.split(" ", 1)

        if len(parts) == 2:
            nid_map[parts[0]] = parts[1]

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
                item["mapped_name"] = nid_map.get(parts[0])

        symbols.append(item)

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

    def owning_symbols(va):

        result = []

        for sym in symbols:

            start = sym["value"]
            size = sym["size"]

            if size <= 0:
                continue

            if start <= va < start + size:
                result.append(sym)

        return result

    refs = []

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

        for i in range(0, max(0, len(data) - 5)):

            opcode = data[i]

            if opcode not in (0xE8, 0xE9):
                continue

            disp = struct.unpack_from(
                "<i",
                data,
                i + 1
            )[0]

            source = seg_vaddr + i
            destination = source + 5 + disp

            if destination != TARGET:
                continue

            refs.append({
                "opcode": "CALL" if opcode == 0xE8 else "JMP",
                "source_va": source,
                "destination_va": destination,
                "file_offset": seg_offset + i,
                "displacement": disp
            })

    refs.sort(key=lambda x: x["source_va"])

    wrappers = []

    for ref in refs:

        source = ref["source_va"]

        start = max(0, source - 32)
        size = 48

        wrappers.append({
            "reference": ref,
            "source_region": read_va(start, size),
            "owning_symbols": owning_symbols(source)
        })

    result = {
        "target": {
            "va": TARGET,
            "known_name": "sceAgcDriverSubmitCommandBuffer",
            "known_nid": "b4fpgH5ZXxQ"
        },
        "direct_references": refs,
        "wrappers": wrappers,
        "summary": {
            "reference_count": len(refs)
        }
    }

with open(
    os.path.join(out_dir, "stage46_static.json"),
    "w",
    encoding="utf-8"
) as fp:
    json.dump(result, fp, indent=2)

print(json.dumps(result, indent=2))