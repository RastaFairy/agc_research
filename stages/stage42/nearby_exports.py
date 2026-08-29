from elftools.elf.elffile import ELFFile
import sys

sprx = sys.argv[1]
out = sys.argv[2]

target = 10416

with open(sprx, "rb") as f:
    elf = ELFFile(f)

    dynamic = None

    for segment in elf.iter_segments():
        if segment.header.p_type == "PT_DYNAMIC":
            dynamic = segment
            break

    if dynamic is None:
        raise RuntimeError("No PT_DYNAMIC")

    rows = []

    for sym in dynamic.iter_symbols():

        raw_name = sym.name

        if not raw_name or "#" not in raw_name:
            continue

        parts = raw_name.split("#")

        if len(parts) != 3:
            continue

        value = int(sym["st_value"])
        size = int(sym["st_size"])
        distance = value - target

        if -128 <= distance <= 128:
            rows.append(
                (
                    distance,
                    value,
                    size,
                    str(sym["st_info"]["type"]),
                    str(sym["st_info"]["bind"]),
                    raw_name
                )
            )

rows.sort()

with open(out, "w", encoding="utf-8") as fp:
    for row in rows:
        fp.write(
            f"delta={row[0]:+d} "
            f"va=0x{row[1]:x} "
            f"size={row[2]} "
            f"type={row[3]} "
            f"bind={row[4]} "
            f"{row[5]}\n"
        )

for row in rows:
    print(
        f"delta={row[0]:+d} "
        f"va=0x{row[1]:x} "
        f"size={row[2]} "
        f"type={row[3]} "
        f"bind={row[4]} "
        f"{row[5]}"
    )