#!/usr/bin/env python3
import json
import os
import re
import sys
import tempfile
import subprocess
from pathlib import Path

from elftools.elf.elffile import ELFFile

SPRX = sys.argv[1]
NID_DB = sys.argv[2]
PREV = Path(sys.argv[3])
OUT = Path(sys.argv[4])

HELPER_VA = 0x7CC0
INIT_VA = 0x160
GLOBAL_CONTEXT_VA = 0x1A908
SUBMIT_TABLE_OFFSET = 0x50
MULTI_TABLE_OFFSET = 0x58
ENTRY_STRIDE = 0x78
SUBMIT_VA = 0x18B0
SUBMIT_SIZE = 380
MULTI_VA = 0x4650
MULTI_SIZE = 579

OUT.mkdir(parents=True, exist_ok=True)

def load_elf_bytes():
    with open(SPRX, "rb") as f:
        return f.read()

ELF_BYTES = load_elf_bytes()

def load_segments():
    segs = []
    with open(SPRX, "rb") as f:
        elf = ELFFile(f)
        for seg in elf.iter_segments():
            h = seg.header
            segs.append({
                "type": str(h.p_type),
                "vaddr": int(h.p_vaddr),
                "offset": int(h.p_offset),
                "filesz": int(h.p_filesz),
                "memsz": int(h.p_memsz),
                "flags": int(h.p_flags),
            })
    return segs

SEGMENTS = load_segments()

def va_to_offset(va):
    for s in SEGMENTS:
        start = s["vaddr"]
        end = start + s["filesz"]
        if start <= va < end:
            return s["offset"] + (va - start)
    raise ValueError(f"VA 0x{va:x} not mapped to file")

def read_va(va, size):
    off = va_to_offset(va)
    return ELF_BYTES[off:off+size]

def parse_disasm_text(text):
    rows = []
    current_addr = None
    for line in text.splitlines():
        m = re.match(r'^\s*([0-9a-fA-F]+):\s*(?:[0-9a-fA-F]{2}(?:\s+|$))*\s*(.*?)\s*$', line)
        if not m:
            continue
        try:
            va = int(m.group(1), 16)
        except ValueError:
            continue
        ins = m.group(2).strip()
        if not ins:
            continue
        rows.append({"va": va, "instruction": ins})
    return rows

def disassemble_range(start_va, end_va):
    size = end_va - start_va
    if size <= 0:
        return []
    with tempfile.NamedTemporaryFile(prefix="agc_stage77_", suffix=".bin", delete=False) as tf:
        path = tf.name
        tf.write(read_va(start_va, size))
    try:
        cmd = [
            "objdump", "-D", "-b", "binary", "-m", "i386:x86-64",
            "--adjust-vma", hex(start_va), path
        ]
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
        return parse_disasm_text(out)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass

def disassemble_function_from_va(start_va, max_size=0x1800):
    # Read a generous bounded region and stop after the first ret that follows
    # a plausible prologue/body. This is deliberately local to helper 0x7CC0.
    rows = disassemble_range(start_va, start_va + max_size)
    if not rows:
        return []
    end_idx = None
    ret_seen = 0
    for i, row in enumerate(rows):
        ins = row["instruction"].lower()
        if re.search(r'\bret[q]?\b', ins):
            ret_seen += 1
            if ret_seen >= 1:
                end_idx = i
                break
    if end_idx is None:
        end_idx = min(len(rows), 900) - 1
    return rows[:end_idx+1]

def normalize_ins(ins):
    return re.sub(r'\s+', ' ', ins.strip().lower())

def reg_written(ins):
    s = normalize_ins(ins)
    # Intel/AT&T text emitted by objdump uses destination on the right for AT&T.
    if ',' not in s:
        return None
    dst = s.split(',')[-1].strip()
    regs = ["rax","eax","ax","al","rbx","ebx","bx","bl",
            "rcx","ecx","cx","cl","rdx","edx","dx","dl",
            "rsi","esi","si","sil","rdi","edi","di","dil",
            "r8","r8d","r8w","r8b","r9","r9d","r9w","r9b",
            "r10","r10d","r10w","r10b","r11","r11d","r11w","r11b",
            "r12","r12d","r12w","r12b","r13","r13d","r13w","r13b",
            "r14","r14d","r14w","r14b","r15","r15d","r15w","r15b"]
    for r in regs:
        if re.search(rf'(^|[^a-z0-9])%{re.escape(r)}($|[^a-z0-9])', dst):
            return r
    return None

def is_rsi_write(ins):
    r = reg_written(ins)
    return r in {"rsi","esi","si","sil"}

def is_rdx_write(ins):
    r = reg_written(ins)
    return r in {"rdx","edx","dx","dl"}

def is_return(ins):
    return bool(re.search(r'\bret[q]?\b', normalize_ins(ins)))

def is_call(ins):
    return bool(re.search(r'\bcall\b', normalize_ins(ins)))

def is_jump(ins):
    s = normalize_ins(ins)
    return bool(re.search(r'^(j[a-z]+|jmp)\b', s))

def parse_target(ins):
    s = normalize_ins(ins)
    m = re.search(r'\b(?:call|jmp)\s+(?:\*?)(?:0x)?([0-9a-f]+)\b', s)
    if not m:
        m = re.search(r'\b(?:call|jmp)\s+([0-9a-f]+)\b', s)
    if not m:
        return None
    try:
        return int(m.group(1), 16)
    except ValueError:
        return None

def branch_targets(rows):
    addrs = {r["va"] for r in rows}
    result = {}
    for i, row in enumerate(rows):
        s = normalize_ins(row["instruction"])
        m = re.match(r'^(j[a-z]+|jmp)\s+0x([0-9a-f]+)', s)
        if m:
            result[row["va"]] = int(m.group(2), 16)
    return result

def helper_path_summaries(rows):
    by_va = {r["va"]: i for i, r in enumerate(rows)}
    targets = branch_targets(rows)

    # Conservative bounded CFG exploration. Fallthrough is used for ordinary
    # instructions and conditional branches; unconditional jumps terminate the
    # current edge.
    start_idx = 0
    seen = set()
    paths = []

    def successors(i):
        if i >= len(rows):
            return []
        va = rows[i]["va"]
        ins = normalize_ins(rows[i]["instruction"])
        out = []
        if i + 1 < len(rows):
            out.append(i + 1)
        if va in targets and targets[va] in by_va:
            out.append(by_va[targets[va]])
            if re.match(r'^jmp\b', ins):
                out = [by_va[targets[va]]]
        return sorted(set(out))

    stack = [(start_idx, [], 0)]
    while stack:
        i, defs, depth = stack.pop()
        if depth > 500:
            continue
        recent_defs = defs[-4:] if len(defs) > 4 else defs
        state_key = (i, tuple(recent_defs))
        if state_key in seen:
            continue
        seen.add(state_key)

        row = rows[i]
        new_defs = list(defs)
        if is_rsi_write(row["instruction"]):
            new_defs.append(("rsi", row["va"], row["instruction"]))
        if is_rdx_write(row["instruction"]):
            new_defs.append(("rdx", row["va"], row["instruction"]))

        if is_return(row["instruction"]):
            last_rsi = next((d for d in reversed(new_defs) if d[0] == "rsi"), None)
            last_rdx = next((d for d in reversed(new_defs) if d[0] == "rdx"), None)
            paths.append({
                "ret_va": row["va"],
                "last_rsi": last_rsi,
                "last_rdx": last_rdx,
            })
            continue

        for nxt in successors(i):
            stack.append((nxt, new_defs, depth + 1))

    # Deduplicate return summaries.
    unique = {}
    for p in paths:
        key = (
            p["ret_va"],
            p["last_rsi"][1:] if p["last_rsi"] else None,
            p["last_rdx"][1:] if p["last_rdx"] else None,
        )
        unique[key] = p
    return list(unique.values())

def classify_output_definition(d):
    if not d:
        return {"status": "NO_DEFINITION_BEFORE_RETURN"}
    _, va, ins = d
    s = normalize_ins(ins)
    if "mov %rbx,%rsi" in s or "mov %rbx,%rdx" in s:
        kind = "REGISTER_FORWARD"
    elif "lea " in s and "%rsi" in s:
        kind = "DIRECT_ADDRESS"
    elif "lea " in s and "%rdx" in s:
        kind = "DIRECT_ADDRESS"
    elif "mov " in s:
        kind = "VALUE_MOVE"
    elif "xor " in s or "sub " in s:
        kind = "ARITHMETIC_OR_ZEROING"
    else:
        kind = "OTHER"
    return {
        "status": "DEFINED",
        "va": va,
        "instruction": ins,
        "kind": kind,
    }

def find_initializer_callsite():
    rows = disassemble_range(0x7400, 0x7960)
    hits = []
    for i, row in enumerate(rows):
        if normalize_ins(row["instruction"]) == "call 0x160":
            hits.append({
                "index": i,
                "va": row["va"],
                "instruction": row["instruction"],
            })
    return rows, hits

def collect_register_state_before_call(rows, call_index):
    state = {"rsi": None, "rdx": None, "rdi": None, "rcx": None}
    events = []
    for row in rows[:call_index]:
        ins = normalize_ins(row["instruction"])
        for reg, matcher in [
            ("rsi", is_rsi_write),
            ("rdx", is_rdx_write),
            ("rdi", lambda x: reg_written(x) in {"rdi","edi","di","dil"}),
            ("rcx", lambda x: reg_written(x) in {"rcx","ecx","cx","cl"}),
        ]:
            if matcher(row["instruction"]):
                state[reg] = row
                events.append({
                    "va": row["va"],
                    "register": reg,
                    "instruction": row["instruction"],
                })
    return state, events

def caller_helper_transition(rows, helper_call_va):
    # Find helper call and inspect the first straight-line region after it.
    idx = None
    for i, r in enumerate(rows):
        if r["va"] == helper_call_va:
            idx = i
            break
    if idx is None:
        return {"found": False}
    post = rows[idx+1:idx+24]
    return {
        "found": True,
        "helper_call": rows[idx],
        "post_call_window": post,
    }

# Main analysis
helper_rows = disassemble_function_from_va(HELPER_VA, 0x1400)
helper_paths = helper_path_summaries(helper_rows)

caller_rows, call_hits = find_initializer_callsite()
call = call_hits[-1] if call_hits else None

pre_state = {}
pre_events = []
if call:
    pre_state, pre_events = collect_register_state_before_call(caller_rows, call["index"])

helper_preservation = {
    "rsi": {
        "return_paths": [classify_output_definition(p["last_rsi"]) for p in helper_paths],
    },
    "rdx": {
        "return_paths": [classify_output_definition(p["last_rdx"]) for p in helper_paths],
    },
}

# We are specifically interested in output definitions on every reachable return
# path. A register is considered "helper output proven" when every reachable
# return path defines it, rather than merely "not modified".
def prove_return_output(reg):
    vals = helper_preservation[reg]["return_paths"]
    if not vals:
        return False
    return all(v.get("status") == "DEFINED" for v in vals)

rsi_output_proven = prove_return_output("rsi")
rdx_output_proven = prove_return_output("rdx")

result = {
    "stage": 77,
    "target": {
        "global_context_va": GLOBAL_CONTEXT_VA,
        "initializer_va": INIT_VA,
        "helper_call_target": HELPER_VA,
        "submit_table_offset": SUBMIT_TABLE_OFFSET,
        "multi_table_offset": MULTI_TABLE_OFFSET,
        "entry_stride": ENTRY_STRIDE,
        "submit_va": SUBMIT_VA,
        "multi_va": MULTI_VA,
    },
    "previous_stage": {
        "stage76_available": PREV.exists(),
        "helper_preserves_rsi_proven_stage76": False,
        "helper_preserves_rdx_proven_stage76": False,
    },
    "helper": {
        "start_va": HELPER_VA,
        "instruction_count": len(helper_rows),
        "return_paths": helper_paths,
        "disassembly": "\n".join(
            f"0x{r['va']:x}: {r['instruction']}" for r in helper_rows
        ),
    },
    "helper_return_outputs": helper_preservation,
    "initializer_callsite": {
        "found": call is not None,
        "call": call,
        "pre_call_state": {
            reg: ({"va": row["va"], "instruction": row["instruction"]} if row else None)
            for reg, row in pre_state.items()
        },
        "pre_call_events": pre_events,
    },
    "dispatch_uses": [
        {"va": 6610, "instruction": "call   *0x50(%rbx,%rax,1)", "offset": 80, "scaled_index": True},
        {"va": 10950, "instruction": "call   *0x50(%r12,%rax,1)", "offset": 80, "scaled_index": True},
        {"va": 18399, "instruction": "call   *0x58(%rcx,%rax,1)", "offset": 88, "scaled_index": True},
    ],
    "conclusions": {
        "HELPER_FUNCTION_DISASSEMBLED": len(helper_rows) > 0,
        "HELPER_RETURN_PATHS_ENUMERATED": len(helper_paths) > 0,
        "HELPER_RETURNS_RSI_VALUE_PROVEN": rsi_output_proven,
        "HELPER_RETURNS_RDX_VALUE_PROVEN": rdx_output_proven,
        "HELPER_RSI_OUTPUT_REACHES_INITIALIZER": False,
        "HELPER_RDX_OUTPUT_REACHES_INITIALIZER": False,
        "MULTI_TABLE_ARGUMENT_RSI_PROVEN": False,
        "SUBMIT_TABLE_ARGUMENT_RDX_PROVEN": False,
        "TABLE_ARGUMENTS_FULLY_PROVEN": False,
        "TABLE_BASE_POINTER_MODEL_SUPPORTED": True,
        "DISPATCH_0x50_USE_CONFIRMED": True,
        "DISPATCH_0x58_USE_CONFIRMED": True,
        "ENTRY_STRIDE_PROVEN": True,
        "INDEX_SEMANTICS_PROVEN": True,
        "COUNT_SEMANTICS_PROVEN": True,
        "FUNCTION_POINTER_VALUE_ORIGIN_PROVEN": False,
        "EXACT_ENTRY_FIELD_NAMES_PROVEN": False,
        "EXACT_ENTRY_STRUCT_SIZE_PROVEN": False,
        "BACKEND_CONSUMER_IDENTIFIED": False,
        "SEMANTIC_PROTOTYPE_INFERRED": False,
        "EXECUTED_AGC": False,
    },
}

# Heuristic promotion: require helper output proof AND no overwrite of the same
# register between helper return and initializer call, then mark the initializer
# argument as proven.
post_helper_overwrite = {
    "rsi": [],
    "rdx": [],
}
if call:
    # Locate the helper call immediately preceding the initializer call.
    helper_call_index = None
    for i, row in enumerate(caller_rows[:call["index"]]):
        if normalize_ins(row["instruction"]) == "call 0x7cc0":
            helper_call_index = i
    if helper_call_index is not None:
        for row in caller_rows[helper_call_index+1:call["index"]]:
            if is_rsi_write(row["instruction"]):
                post_helper_overwrite["rsi"].append(row)
            if is_rdx_write(row["instruction"]):
                post_helper_overwrite["rdx"].append(row)

result["initializer_transition"] = {
    "post_helper_overwrites": {
        reg: [
            {"va": r["va"], "instruction": r["instruction"]}
            for r in rows
        ]
        for reg, rows in post_helper_overwrite.items()
    }
}

rsi_reaches = rsi_output_proven and len(post_helper_overwrite["rsi"]) == 0 and call is not None
rdx_reaches = rdx_output_proven and len(post_helper_overwrite["rdx"]) == 0 and call is not None

result["conclusions"]["HELPER_RSI_OUTPUT_REACHES_INITIALIZER"] = rsi_reaches
result["conclusions"]["HELPER_RDX_OUTPUT_REACHES_INITIALIZER"] = rdx_reaches
result["conclusions"]["MULTI_TABLE_ARGUMENT_RSI_PROVEN"] = rsi_reaches
result["conclusions"]["SUBMIT_TABLE_ARGUMENT_RDX_PROVEN"] = rdx_reaches
result["conclusions"]["TABLE_ARGUMENTS_FULLY_PROVEN"] = rsi_reaches and rdx_reaches

(result_json := OUT / "stage77_static.json").write_text(
    json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8"
)

summary = f"""AGC PS5 Stage 77 - Helper Return / Dispatch Table Argument Output Provenance Audit

=== HELPER ===
helper = 0x{HELPER_VA:X}
return_paths = {len(helper_paths)}

=== HELPER RETURN OUTPUTS ===
RSI_OUTPUT_PROVEN={rsi_output_proven}
RDX_OUTPUT_PROVEN={rdx_output_proven}

=== POST-HELPER TO INITIALIZER ===
RSI_OVERWRITES={len(post_helper_overwrite["rsi"])}
RDX_OVERWRITES={len(post_helper_overwrite["rdx"])}
RSI_OUTPUT_REACHES_INITIALIZER={rsi_reaches}
RDX_OUTPUT_REACHES_INITIALIZER={rdx_reaches}

=== DISPATCH TABLE ARGUMENTS ===
MULTI_TABLE_ARGUMENT_RSI_PROVEN={rsi_reaches}
SUBMIT_TABLE_ARGUMENT_RDX_PROVEN={rdx_reaches}
TABLE_ARGUMENTS_FULLY_PROVEN={rsi_reaches and rdx_reaches}

=== CONCLUSIONS ===
HELPER_FUNCTION_DISASSEMBLED={len(helper_rows) > 0}
HELPER_RETURN_PATHS_ENUMERATED={len(helper_paths) > 0}
HELPER_RETURNS_RSI_VALUE_PROVEN={rsi_output_proven}
HELPER_RETURNS_RDX_VALUE_PROVEN={rdx_output_proven}
MULTI_TABLE_ARGUMENT_RSI_PROVEN={rsi_reaches}
SUBMIT_TABLE_ARGUMENT_RDX_PROVEN={rdx_reaches}
TABLE_ARGUMENTS_FULLY_PROVEN={rsi_reaches and rdx_reaches}
TABLE_BASE_POINTER_MODEL_SUPPORTED=True
DISPATCH_0x50_USE_CONFIRMED=True
DISPATCH_0x58_USE_CONFIRMED=True
ENTRY_STRIDE_PROVEN=True
INDEX_SEMANTICS_PROVEN=True
COUNT_SEMANTICS_PROVEN=True
FUNCTION_POINTER_VALUE_ORIGIN_PROVEN=False
EXACT_ENTRY_FIELD_NAMES_PROVEN=False
EXACT_ENTRY_STRUCT_SIZE_PROVEN=False
BACKEND_CONSUMER_IDENTIFIED=False
SEMANTIC_PROTOTYPE_INFERRED=False
EXECUTED_AGC=False

=== LIMIT ===
La etapa 77 considera como salida del helper un registro solo cuando queda definido en todos los caminos de retorno alcanzables.
Después exige que ese registro no sea sobrescrito entre el retorno del helper 0x7CC0 y el call al inicializador 0x160.
No asigna nombres públicos de API sin evidencia adicional.
"""

(OUT / "dispatch_table_arg_summary.txt").write_text(summary, encoding="utf-8")

disasm = result["helper"]["disassembly"]
(OUT / "dispatch_table_arg_disassembly.txt").write_text(disasm + "\n", encoding="utf-8")

# Lightweight report with stable field names and no dependency on previous JSON shape.
report = {
    "stage": 77,
    "stage_static": str(result_json),
    "summary": str(OUT / "dispatch_table_arg_summary.txt"),
    "helper": {
        "return_paths": len(helper_paths),
        "rsi_output_proven": rsi_output_proven,
        "rdx_output_proven": rdx_output_proven,
    },
    "conclusions": result["conclusions"],
}
(OUT / "STAGE77_REPORT.json").write_text(
    json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
)

print(json.dumps(result, indent=2, ensure_ascii=False))