from elftools.elf.elffile import ELFFile
import json
import os
import struct
import sys

sprx = sys.argv[1]
nid_db = sys.argv[2]
out_dir = sys.argv[3]

SUBMIT_NID = "UglJIZjGssM"
INTERNAL_NID = "b4fpgH5ZXxQ"

SUBMIT_VA = 0x28b0
INTERNAL_VA = 0x18b0
INTERNAL_SIZE = 380

CTX_VA = 0x1a8b8

with open(nid_db, "r", encoding="utf-8", errors="replace") as fp:
    nid_map = {}

    for line in fp:
        line = line.strip()

        if not line:
            continue

        parts = line.split(" ", 1)

        if len(parts) != 2:
            continue

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

        entry = {
            "raw_name": raw,
            "value": value,
            "size": size,
            "type": str(sym["st_info"]["type"]),
            "bind": str(sym["st_info"]["bind"])
        }

        if "#" in raw:

            parts = raw.split("#")

            if len(parts) == 3:

                entry["nid"] = parts[0]
                entry["lid"] = parts[1]
                entry["mid"] = parts[2]

                entry["mapped_name"] = nid_map.get(parts[0])

        symbols.append(entry)

    # --------------------------------------------------------
    # VA -> file offset
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
    # Read bytes from a virtual-address range.
    # --------------------------------------------------------

    def read_va(va, size):

        off = va_to_file_offset(va)

        if off is None:
            return {
                "va": va,
                "file_offset": None,
                "size": size,
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
    # Relevant symbols.
    # --------------------------------------------------------

    submit = [
        s for s in symbols
        if s.get("nid") == SUBMIT_NID
    ]

    internal = [
        s for s in symbols
        if s.get("nid") == INTERNAL_NID
    ]

    # --------------------------------------------------------
    # Internal function raw bytes.
    # --------------------------------------------------------

    internal_bytes = read_va(
        INTERNAL_VA,
        INTERNAL_SIZE
    )

    # --------------------------------------------------------
    # Context target.
    # --------------------------------------------------------

    context_bytes = read_va(
        CTX_VA,
        256
    )

    # --------------------------------------------------------
    # Search dynamic symbols around both targets.
    # --------------------------------------------------------

    def nearby(target, radius):

        rows = []

        for s in symbols:

            value = s["value"]
            delta = value - target

            if -radius <= delta <= radius:

                rows.append({
                    "delta": delta,
                    "value": value,
                    "size": s["size"],
                    "type": s["type"],
                    "bind": s["bind"],
                    "raw_name": s["raw_name"],
                    "nid": s.get("nid"),
                    "mapped_name": s.get("mapped_name")
                })

        rows.sort(
            key=lambda x: (
                x["value"],
                x["raw_name"]
            )
        )

        return rows

    nearby_internal = nearby(
        INTERNAL_VA,
        1024
    )

    nearby_context = nearby(
        CTX_VA,
        1024
    )

    # --------------------------------------------------------
    # Raw bytes around submit thunk.
    # --------------------------------------------------------

    submit_bytes = read_va(
        SUBMIT_VA,
        15
    )

    # --------------------------------------------------------
    # PT_LOAD info.
    # --------------------------------------------------------

    loads = []

    for seg in elf.iter_segments():

        if seg.header.p_type != "PT_LOAD":
            continue

        loads.append({
            "p_offset": int(seg.header.p_offset),
            "p_vaddr": int(seg.header.p_vaddr),
            "p_filesz": int(seg.header.p_filesz),
            "p_memsz": int(seg.header.p_memsz),
            "p_flags": int(seg.header.p_flags)
        })

    result = {
        "submit": {
            "nid": SUBMIT_NID,
            "aerolib_name": nid_map.get(SUBMIT_NID),
            "symbols": submit,
            "raw": submit_bytes
        },

        "internal": {
            "nid": INTERNAL_NID,
            "aerolib_name": nid_map.get(INTERNAL_NID),
            "symbols": internal,
            "va": INTERNAL_VA,
            "size": INTERNAL_SIZE,
            "raw": internal_bytes
        },

        "context_target": {
            "va": CTX_VA,
            "raw": context_bytes
        },

        "nearby_internal": nearby_internal,
        "nearby_context": nearby_context,

        "pt_loads": loads
    }

with open(
    os.path.join(out_dir, "stage44_static.json"),
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