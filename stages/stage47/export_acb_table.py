import json
import os
import sys

json_path = sys.argv[1]
out_dir = sys.argv[2]

os.makedirs(out_dir, exist_ok=True)

with open(json_path, "r", encoding="utf-8") as fp:
    data = json.load(fp)

for entry in data["acb_table"]["entries"]:

    raw = entry["bytes"]["bytes_hex"]

    if not raw:
        continue

    blob = bytes.fromhex(raw)

    name = "entry_{:02d}.bin".format(
        entry["index"]
    )

    path = os.path.join(
        out_dir,
        name
    )

    with open(path, "wb") as fp:
        fp.write(blob)

    print(
        "{} VA=0x{:x} size={}".format(
            path,
            entry["entry_va"],
            len(blob)
        )
    )