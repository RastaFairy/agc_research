import json
import re
import sys
from pathlib import Path
from zipfile import ZipFile


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def read_kyty_cpp(path: Path) -> str:
    if path.is_dir():
        source = path / "src" / "libs" / "agc.cpp"
        if not source.is_file():
            raise RuntimeError(f"KytyPlus agc.cpp no encontrado: {source}")
        return read_text(source)

    if not path.is_file():
        raise RuntimeError(f"KytyPlus path no encontrado: {path}")

    with ZipFile(path) as zf:
        candidates = [name for name in zf.namelist() if name.endswith("/src/libs/agc.cpp")]
        if len(candidates) != 1:
            raise RuntimeError(f"KytyPlus agc.cpp no resuelto de forma univoca: {candidates}")
        return zf.read(candidates[0]).decode("utf-8", errors="replace")


def prove(results, name: str, condition: bool, detail: str) -> bool:
    status = "PROVEN" if condition else "FAIL"
    results[name] = {"status": status, "detail": detail}
    print(f"[{'OK' if condition else 'ERR'}] {name}: {detail}")
    return condition


def main() -> int:
    if len(sys.argv) != 7:
        print(
            "usage: stage83_verify.py <stage79_contract> <submit_disasm> "
            "<consumer_disasm> <stage82_report> <kyty_root_or_zip> <out_json>",
            file=sys.stderr,
        )
        return 2

    stage79_path = Path(sys.argv[1])
    submit_path = Path(sys.argv[2])
    consumer_path = Path(sys.argv[3])
    stage82_path = Path(sys.argv[4])
    kyty_path = Path(sys.argv[5])
    out_path = Path(sys.argv[6])

    stage79 = read_text(stage79_path)
    submit = read_text(submit_path)
    consumer = read_text(consumer_path)
    stage82 = json.loads(read_text(stage82_path))
    kyty = read_kyty_cpp(kyty_path)

    proofs = {}
    all_ok = True

    def check(name: str, pattern: str, text: str, detail: str) -> None:
        nonlocal all_ok
        found = re.search(pattern, text, re.IGNORECASE | re.MULTILINE) is not None
        all_ok = prove(proofs, name, found, detail) and all_ok

    print("=== A. Stage 79 ABI baseline ===")
    abi_ok = all(
        token in stage79
        for token in (
            "+0x00 = 8 bytes",
            "+0x08 = 4 bytes",
            "+0x0C = 1 byte",
        )
    )
    all_ok = prove(
        proofs,
        "STAGE79_ABI_LAYOUT_PROVEN",
        abi_ok,
        "Stage79 fija los accesos publicos +0x00/+0x08/+0x0C.",
    ) and all_ok

    print("=== B. Stage 82 submit_dispatch @ 0x18B0 ===")
    check(
        "SUBMIT_READS_PUBLIC_FIELD_00",
        r"\b1913:\s+[0-9a-f ]+\s+mov\s+\(%r14\),%rax\b",
        submit,
        "0x1913 lee arg+0x00 como 64 bits.",
    )
    check(
        "SUBMIT_COPIES_FIELD_00_TO_LOCAL",
        r"\b1916:\s+[0-9a-f ]+\s+mov\s+%rax,-0x40\(%rbp\)",
        submit,
        "arg+0x00 -> local -0x40.",
    )
    check(
        "SUBMIT_READS_PUBLIC_FIELD_08",
        r"\b191a:\s+[0-9a-f ]+\s+mov\s+0x8\(%r14\),%eax\b",
        submit,
        "0x191A lee arg+0x08 como 32 bits.",
    )
    check(
        "SUBMIT_COPIES_FIELD_08_TO_LOCAL",
        r"\b191e:\s+[0-9a-f ]+\s+mov\s+%eax,-0x38\(%rbp\)",
        submit,
        "arg+0x08 -> local -0x38.",
    )
    check(
        "SUBMIT_READS_PUBLIC_FIELD_0C",
        r"\b1921:\s+[0-9a-f ]+\s+mov\s+0xc\(%r14\),%al\b",
        submit,
        "0x1921 lee arg+0x0C como 1 byte.",
    )
    check(
        "SUBMIT_COPIES_FIELD_0C_TO_LOCAL",
        r"\b1925:\s+[0-9a-f ]+\s+mov\s+%al,-0x34\(%rbp\)",
        submit,
        "arg+0x0C -> local -0x34.",
    )
    check(
        "SUBMIT_PASSES_LOCAL_BASE_TO_BACKEND",
        r"\b19c7:\s+[0-9a-f ]+\s+lea\s+-0x50\(%rbp\),%rsi\b",
        submit,
        "0x19C7 pasa base local -0x50 como segundo argumento.",
    )
    check(
        "SUBMIT_DISPATCH_CALL_USES_TABLE_PLUS_0x50",
        r"\b19d2:\s+[0-9a-f ]+\s+call\s+\*0x50\(%rbx,%rax,1\)",
        submit,
        "0x19D2 usa tabla de submit +0x50.",
    )

    print("=== C. Stage 82 backend @ 0x1000 ===")
    check(
        "BACKEND_USES_LOCAL_PLUS_0x10_AS_64BIT_VALUE",
        r"\b1299:\s+[0-9a-f ]+\s+mov\s+0x10\(%r9\),%rsi\b",
        consumer,
        "0x1299 carga qword desde +0x10 del registro recibido.",
    )
    check(
        "BACKEND_USES_LOCAL_PLUS_0x18_AS_32BIT_VALUE",
        r"\b12b8:\s+[0-9a-f ]+\s+mov\s+0x18\(%r9\),%edi\b",
        consumer,
        "0x12B8 carga dword desde +0x18 del registro recibido.",
    )
    check(
        "BACKEND_BUILDS_PM4_IB_HEADER",
        r"0xc0023f00|c0023f00",
        consumer,
        "El consumidor contiene el valor 0xC0023F00.",
    )

    proof82 = stage82.get("proof", {})
    proof82_ok = (
        proof82.get("initializer_targets_0x1000") is True
        and proof82.get("submit_consumer_uses_field00") is True
        and proof82.get("submit_consumer_uses_field08") is True
    )
    all_ok = prove(
        proofs,
        "STAGE82_BACKEND_TARGET_CONFIRMED",
        proof82_ok,
        "Stage82 report confirma target 0x1000 y uso de field_00/field_08.",
    ) and all_ok

    print("=== D. KytyPlus source ===")
    packet_match = re.search(
        r"struct\s+Packet\s*\{"
        r".*?uint32_t\s*\*\s*addr\s*;"
        r".*?uint32_t\s+dw_num\s*;"
        r".*?uint8_t\s+pad\s*\[4\]\s*;"
        r".*?\}",
        kyty,
        re.DOTALL,
    )
    all_ok = prove(
        proofs,
        "KYTYPPLUS_PACKET_LAYOUT",
        packet_match is not None,
        "KytyPlus contiene Packet.addr, Packet.dw_num y Packet.pad[4].",
    ) and all_ok

    submit_dcb_match = re.search(
        r"GraphicsDriverSubmitDcb\s*\([^)]*\)\s*\{"
        r".*?submit_dcb\s*\(\s*packet->addr\s*,\s*packet->dw_num\s*\)\s*;",
        kyty,
        re.DOTALL,
    )
    all_ok = prove(
        proofs,
        "KYTYPPLUS_GRAPHICS_DRIVER_SUBMIT_DCB_SEMANTICS",
        submit_dcb_match is not None,
        "GraphicsDriverSubmitDcb pasa Packet.addr y Packet.dw_num a submit_dcb.",
    ) and all_ok

    field00 = all(
        proofs[name]["status"] == "PROVEN"
        for name in (
            "STAGE79_ABI_LAYOUT_PROVEN",
            "SUBMIT_READS_PUBLIC_FIELD_00",
            "SUBMIT_COPIES_FIELD_00_TO_LOCAL",
            "SUBMIT_PASSES_LOCAL_BASE_TO_BACKEND",
            "BACKEND_USES_LOCAL_PLUS_0x10_AS_64BIT_VALUE",
            "KYTYPPLUS_PACKET_LAYOUT",
            "KYTYPPLUS_GRAPHICS_DRIVER_SUBMIT_DCB_SEMANTICS",
        )
    )

    field08 = all(
        proofs[name]["status"] == "PROVEN"
        for name in (
            "STAGE79_ABI_LAYOUT_PROVEN",
            "SUBMIT_READS_PUBLIC_FIELD_08",
            "SUBMIT_COPIES_FIELD_08_TO_LOCAL",
            "SUBMIT_PASSES_LOCAL_BASE_TO_BACKEND",
            "BACKEND_USES_LOCAL_PLUS_0x18_AS_32BIT_VALUE",
            "KYTYPPLUS_PACKET_LAYOUT",
            "KYTYPPLUS_GRAPHICS_DRIVER_SUBMIT_DCB_SEMANTICS",
        )
    )

    conclusions = {
        "FIELD_00_IS_DCB_GPU_ADDR": field00,
        "FIELD_08_IS_DCB_NUM_DWORDS": field08,
        "FIELD_0C_PADDING_CONFIRMED": False,
        "PUBLIC_SEMANTIC_FIELD_NAMES_FINAL": False,
        "REAL_PS5_EXECUTION": False,
    }

    overall = all_ok and field00 and field08

    report = {
        "stage": 83,
        "variant": "SEMANTIC_FIELD_PROOF",
        "proofs": proofs,
        "field_mapping": {
            "public_0x00": "dcb_gpu_addr",
            "public_0x08": "dcb_num_dwords",
            "public_0x0c": "unknown_byte_not_closed",
        },
        "derived_offsets": {
            "public_0x00_to_backend_0x10": True,
            "public_0x08_to_backend_0x18": True,
            "public_0x0c_to_backend_0x1c": True,
        },
        "conclusions": conclusions,
        "overall": overall,
        "source_mode": "directory" if kyty_path.is_dir() else "zip",
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    print("")
    print("=== CONCLUSIONES STAGE 83 ===")
    for key, value in conclusions.items():
        print(f"  {key} = {value}")
    print(f"  STAGE83_LIMITED_SEMANTIC_PROOF = {overall}")

    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())