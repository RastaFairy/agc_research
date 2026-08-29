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
    "agr_context": 0x1A868,
    "dcb_context": 0x1A8B8,
    "global_context": 0x1A908,
    "acb_table": 0x18460,
}

# Known instruction sizes for the RIP-relative patterns we care
# about. This analyzer intentionally recognizes only common
# x86-64 forms and does not attempt to fully decode every opcode.

RIP_REL_PATTERNS = {
    # mov r64, [rip+disp32]
    (0x48, 0x8B): "MOV_R64_RIP",

    # mov r32, [rip+disp32]
    (0x8B,): "MOV_R32_RIP",

    # lea r64, [rip+disp32]
    (0x48, 0x8D): "LEA_R64_RIP",

    # lea r32, [rip+disp32]
    (0x8D,): "LEA_R32_RIP",

    # mov [rip+disp32], imm32
    (0xC7,): "MOV_RIP_IMM32",

    # mov byte [rip+disp32], imm8
    (0xC6,): "MOV_RIP_IMM8",
}

WRITE_MNEMONIC_BYTES = {
    0x88: "MOV_MEM8",
    0x89: "MOV_MEM",
    0x8A: "MOV_LOAD8",
    0x8B: "MOV_LOAD",
    0xC6: "MOV_MEM8_IMM",
    0xC7: "MOV_MEM_IMM",
    0xD9: "X87_STORE",
    0x0F: "EXTENDED",
    0xF0: "LOCK",
}

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
            return None

        f.seek(off)

        data = f.read(size)

        return {
            "va": va,
            "file_offset": off,
            "size": len(data),
            "bytes_hex": data.hex(" ")
        }

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

        if not matches:
            return None

        matches.sort(
            key=lambda x: (
                x["size"],
                x["value"]
            )
        )

        return matches[0]

    # --------------------------------------------------------
    # Get executable image bytes
    # --------------------------------------------------------

    executable = []

    for seg in loads:

        if not (seg["flags"] & 1):
            continue

        f.seek(seg["offset"])

        data = f.read(seg["filesz"])

        executable.append({
            "vaddr": seg["vaddr"],
            "offset": seg["offset"],
            "data": data
        })

    # --------------------------------------------------------
    # 1. Exact RIP-relative references
    # --------------------------------------------------------

    rip_refs = []

    for seg in executable:

        data = seg["data"]
        base_va = seg["vaddr"]
        base_off = seg["offset"]

        i = 0

        while i + 7 <= len(data):

            # REX.W + opcode + ModRM + disp32
            if (
                data[i] == 0x48 and
                data[i+1] in (0x8B, 0x8D)
            ):

                modrm = data[i+2]

                if (modrm & 0xC7) == 0x05:

                    disp = struct.unpack_from(
                        "<i",
                        data,
                        i + 3
                    )[0]

                    insn_va = base_va + i
                    next_va = insn_va + 7
                    target_va = next_va + disp

                    target_name = None

                    for name, addr in TARGETS.items():

                        if target_va == addr:
                            target_name = name
                            break

                    if target_name is not None:

                        rip_refs.append({
                            "instruction_va": insn_va,
                            "file_offset": base_off + i,
                            "opcode": (
                                "LEA"
                                if data[i+1] == 0x8D
                                else "MOV"
                            ),
                            "target_va": target_va,
                            "target_name": target_name,
                            "displacement": disp,
                            "owner": function_owner(insn_va)
                        })

            i += 1

    # --------------------------------------------------------
    # 2. Look for immediate absolute-address constructions
    #    and stores to nearby context offsets.
    #
    # Since BSS is not in the file, we cannot inspect the data;
    # we only inspect instructions that can form effective
    # addresses.
    # --------------------------------------------------------

    candidate_accesses = []

    for seg in executable:

        data = seg["data"]
        base_va = seg["vaddr"]
        base_off = seg["offset"]

        # Simple byte-oriented scan.
        #
        # We are primarily interested in:
        #
        #   mov [reg + disp8/disp32], reg
        #   mov [reg + disp8/disp32], imm
        #
        # immediately following a LEA of a known target.
        #
        # Therefore first collect every known-target LEA/MOV.
        #
        local_known = []

        i = 0

        while i + 7 <= len(data):

            if (
                data[i] == 0x48 and
                data[i+1] in (0x8B, 0x8D)
            ):

                modrm = data[i+2]

                if (modrm & 0xC7) == 0x05:

                    disp = struct.unpack_from(
                        "<i",
                        data,
                        i + 3
                    )[0]

                    insn_va = base_va + i
                    next_va = insn_va + 7
                    target_va = next_va + disp

                    target_name = None

                    for name, addr in TARGETS.items():

                        if target_va == addr:
                            target_name = name
                            break

                    if target_name is not None:

                        # Capture a forward window of 96 bytes.
                        local_known.append({
                            "offset": i,
                            "instruction_va": insn_va,
                            "target_name": target_name,
                            "target_va": target_va,
                        })

            i += 1

        # Analyze forward windows.
        for known in local_known:

            start = known["offset"]
            end = min(
                len(data),
                start + 96
            )

            window = data[start:end]

            # Search common store encodings.
            #
            # 89 /r   mov r/m32/64, r32/64
            # 88 /r   mov r/m8, r8
            #
            # Look for ModRM using a register as base and
            # a displacement.
            #
            j = 7

            while j + 3 < len(window):

                op = window[j]

                if op in (0x88, 0x89):

                    modrm = window[j+1]

                    mod = (modrm >> 6) & 0x3
                    rm  = modrm & 0x7

                    # Exclude register-direct form.
                    if mod != 3:

                        disp_size = 0

                        if mod == 1:
                            disp_size = 1

                        elif mod == 2:
                            disp_size = 4

                        # SIB can add another byte.
                        sib_extra = (
                            1
                            if rm == 4
                            else 0
                        )

                        total = (
                            2 +
                            sib_extra +
                            disp_size
                        )

                        if j + total <= len(window):

                            displacement = 0

                            cursor = j + 2

                            if rm == 4:
                                cursor += 1

                            if disp_size == 1:

                                displacement = struct.unpack_from(
                                    "<b",
                                    window,
                                    cursor
                                )[0]

                            elif disp_size == 4:

                                displacement = struct.unpack_from(
                                    "<i",
                                    window,
                                    cursor
                                )[0]

                            candidate_accesses.append({
                                "context_reference": known,
                                "access_va": (
                                    known["instruction_va"] +
                                    j
                                ),
                                "opcode": (
                                    "MOV_STORE8"
                                    if op == 0x88
                                    else "MOV_STORE"
                                ),
                                "mod": mod,
                                "rm": rm,
                                "displacement": displacement,
                                "relative_to_context": True
                            })

                j += 1

    # --------------------------------------------------------
    # 3. Export windows centered on important submit functions
    # --------------------------------------------------------

    important_functions = [
        "sceAgcDriverSubmitDcb",
        "sceAgcDriverAgrSubmitDcb",
        "sceAgcDriverSubmitAcb",
        "sceAgcDriverSubmitReprojectionAcb",
        "sceAgcDriverSubmitMultiAcbs",
        "sceAgcDriverSubmitMultiDcbs",
        "sceAgcDriverAgrSubmitMultiDcbs",
        "sceAgcDriverSubmitMultiCommandBuffers",
        "sceAgcDriverSuspendPointSubmit",
    ]

    important_windows = []

    for sym in symbols:

        name = sym.get("mapped_name")

        if name not in important_functions:
            continue

        va = sym["value"]
        size = sym["size"]

        raw = read_va(
            va,
            min(size, 1600)
        )

        if raw is None:
            continue

        important_windows.append({
            "name": name,
            "nid": sym.get("nid"),
            "va": va,
            "size": size,
            "raw": raw
        })

    # --------------------------------------------------------
    # 4. Specifically search the known functions for stores
    #    after context LEAs.
    # --------------------------------------------------------

    function_store_candidates = []

    for item in important_windows:

        raw = bytes.fromhex(
            item["raw"]["bytes_hex"]
        )

        base_va = item["va"]

        # Reuse a lightweight scan.
        i = 0

        while i + 7 <= len(raw):

            if (
                raw[i] == 0x48 and
                raw[i+1] in (0x8B, 0x8D)
            ):

                modrm = raw[i+2]

                if (modrm & 0xC7) == 0x05:

                    disp = struct.unpack_from(
                        "<i",
                        raw,
                        i + 3
                    )[0]

                    insn_va = base_va + i
                    next_va = insn_va + 7
                    target_va = next_va + disp

                    target_name = None

                    for name, addr in TARGETS.items():

                        if target_va == addr:
                            target_name = name
                            break

                    if target_name is not None:

                        # Capture instructions after the LEA.
                        after = raw[i+7:i+7+96]

                        function_store_candidates.append({
                            "function": item["name"],
                            "function_va": item["va"],
                            "lea_va": insn_va,
                            "target_name": target_name,
                            "target_va": target_va,
                            "following_bytes": after.hex(" ")
                        })

            i += 1

    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------

    result = {
        "targets": TARGETS,
        "rip_references": rip_refs,
        "candidate_store_accesses": candidate_accesses,
        "important_functions": important_windows,
        "function_context_windows": function_store_candidates,
        "loads": loads
    }

with open(
    os.path.join(out_dir, "stage49_static.json"),
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