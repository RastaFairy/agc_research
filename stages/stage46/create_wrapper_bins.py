import json
import os
import shutil
import sys

json_path = sys.argv[1]
tmp_dir = sys.argv[2]
out_dir = sys.argv[3]

os.makedirs(tmp_dir, exist_ok=True)
os.makedirs(out_dir, exist_ok=True)

with open(json_path, "r", encoding="utf-8") as fp:
    data = json.load(fp)

for index, wrapper in enumerate(data["wrappers"], 1):

    region = wrapper.get("source_region")

    if not region:
        continue

    data_bytes = bytes.fromhex(
        region["bytes_hex"]
    )

    name = f"wrapper_{index:02d}.bin"

    tmp_path = os.path.join(
        tmp_dir,
        name
    )

    out_path = os.path.join(
        out_dir,
        name
    )

    with open(tmp_path, "wb") as fp:
        fp.write(data_bytes)

    shutil.copyfile(
        tmp_path,
        out_path
    )

    print(
        f"{name} "
        f"start=0x{int(region['va']):x} "
        f"size={len(data_bytes)} "
        f"out={out_path}"
    )