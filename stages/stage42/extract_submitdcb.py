from elftools.elf.elffile import ELFFile
import json
import os
import sys

TARGET_NID = "UglJIZjGssM"
TARGET_NAME = "sceAgcDriverSubmitDcb"

sprx = sys.argv[1]
out_dir = sys.argv[2]

os.makedirs(out_dir, exist_ok=True)

with open(sprx, "rb") as f:
    elf = ELFFile(f)

    dynamic = None

    for segment in elf.iter_segments():
        if segment.header.p_type == "PT_DYNAMIC":
            dynamic = segment
            break

    if dynamic is None:
        raise RuntimeError("No PT_DYNAMIC segment found")

    match = None

    # This is the same symbol-table access model used by the
    # SDK's genstub.py.
    for sym in dynamic.iter_symbols():

        raw_name = sym.name

        if not raw_name:
            continue

        if "#" not in raw_name:
            continue

        parts = raw_name.split("#")

        if len(parts) != 3:
            continue

        nid, lid, mid = parts

        if nid != TARGET_NID:
            continue

        match = {
            "name": TARGET_NAME,
            "raw_name": raw_name,
            "nid": nid,
            "lid": lid,
            "mid": mid,
            "st_value": int(sym["st_value"]),
            "st_size": int(sym["st_size"]),
            "binding": str(sym["st_info"]["bind"]),
            "type": str(sym["st_info"]["type"]),
            "section_index": str(sym["st_shndx"])
        }

        break

    if match is None:
        raise RuntimeError(
            "Target NID not found in PT_DYNAMIC: " + TARGET_NID
        )

    target_addr = match["st_value"]
    target_size = match["st_size"]

    if target_size <= 0:
        raise RuntimeError(
            f"Target symbol has invalid size: {target_size}"
        )

    # --------------------------------------------------------
    # VA -> file offset using PT_LOAD
    # --------------------------------------------------------

    file_offset = None

    for seg in elf.iter_segments():

        if seg.header.p_type != "PT_LOAD":
            continue

        vaddr = int(seg.header.p_vaddr)
        memsz = int(seg.header.p_memsz)
        offset = int(seg.header.p_offset)

        if vaddr <= target_addr < (vaddr + memsz):
            file_offset = offset + (target_addr - vaddr)
            break

    if file_offset is None:
        raise RuntimeError(
            f"Could not map VA 0x{target_addr:x} to file offset"
        )

    # --------------------------------------------------------
    # Read exact function body
    # --------------------------------------------------------

    with open(sprx, "rb") as f:
        f.seek(file_offset)
        code = f.read(target_size)

    if len(code) != target_size:
        raise RuntimeError(
            f"Short read: expected {target_size} bytes, got {len(code)}"
        )

    result = {
        "export": match,
        "file_offset": file_offset,
        "bytes_hex": code.hex(" "),
        "byte_count": len(code)
    }

    with open(
        os.path.join(out_dir, "export_metadata.json"),
        "w",
        encoding="utf-8"
    ) as fp:
        json.dump(result, fp, indent=2)

    with open(
        os.path.join(out_dir, "export_bytes.bin"),
        "wb"
    ) as fp:
        fp.write(code)

    with open(
        os.path.join(out_dir, "export_bytes.hex"),
        "w",
        encoding="utf-8"
    ) as fp:
        fp.write(code.hex(" ") + "\n")

    print(json.dumps(result, indent=2))