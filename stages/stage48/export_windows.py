import json
import os
import sys

src = sys.argv[1]
out_dir = sys.argv[2]

os.makedirs(out_dir, exist_ok=True)

with open(src, "r", encoding="utf-8") as fp:
    data = json.load(fp)

for index, window in enumerate(data["windows"], 1):

    raw = window["raw"]

    blob = bytes.fromhex(
        raw["bytes_hex"]
    )

    base = (
        f"{index:04d}_"
        f"{window['target_name']}_"
        f"0x{window['instruction_va']:x}"
    )

    bin_path = os.path.join(
        out_dir,
        base + ".bin"
    )

    json_path = os.path.join(
        out_dir,
        base + ".json"
    )

    with open(
        bin_path,
        "wb"
    ) as fp:
        fp.write(blob)

    with open(
        json_path,
        "w",
        encoding="utf-8"
    ) as fp:
        json.dump(
            window,
            fp,
            indent=2
        )

    print(
        f"{base}: "
        f"VA=0x{raw['va']:x} "
        f"size={len(blob)}"
    )