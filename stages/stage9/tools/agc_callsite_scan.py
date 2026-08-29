#!/usr/bin/env python3
import argparse, json, os, re, subprocess, sys
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional

ARG_REGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
REG_ALIAS = {
    "edi":"rdi", "esi":"rsi", "edx":"rdx", "ecx":"rcx",
    "r8d":"r8", "r9d":"r9", "di":"rdi", "si":"rsi",
    "dx":"rdx", "cx":"rcx", "r8w":"r8", "r9w":"r9",
    "dil":"rdi", "sil":"rsi", "dl":"rdx", "cl":"rcx",
    "r8b":"r8", "r9b":"r9",
}
CALL_RE = re.compile(r"\bcall(?:q)?\s+(.+)$", re.I)
FUNC_RE = re.compile(r"^\s*([0-9a-fA-F]+)\s+<([^>]+)>:\s*$")
INSN_RE = re.compile(r"^\s*([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{2}\s+)+\s*(.*)$")
WRITE_RE = re.compile(r"\b(?:mov|lea|xor|or|and|add|sub|imul|movabs)\w*\s+([^,]+),\s*(%?[A-Za-z0-9]+)\b", re.I)
STACK_RE = re.compile(r"\[[^\]]*(?:rsp|rbp)[^\]]*\]", re.I)

@dataclass
class Instruction:
    addr: str
    text: str


def normalize_target(s: str) -> str:
    return s.split("@plt")[0].split("@@")[0].strip()


def load_disasm(args) -> str:
    if args.disasm:
        with open(args.disasm, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    if not args.elf:
        raise SystemExit("must provide --elf or --disasm")
    cmd = ["objdump", "-d", "-C", args.elf]
    return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)


def parse(text: str, target: str, window: int) -> List[dict]:
    funcs: List[tuple[str, str, List[Instruction]]] = []
    cur_name = "<unknown>"
    cur_addr = ""
    cur: List[Instruction] = []
    for line in text.splitlines():
        m = FUNC_RE.match(line)
        if m:
            if cur:
                funcs.append((cur_name, cur_addr, cur))
            cur_addr, cur_name, cur = m.group(1), m.group(2), []
            continue
        m = INSN_RE.match(line)
        if m:
            cur.append(Instruction(m.group(1), m.group(2).strip()))
    if cur:
        funcs.append((cur_name, cur_addr, cur))

    out = []
    norm_target = normalize_target(target)
    for fn, fn_addr, insns in funcs:
        for i, ins in enumerate(insns):
            cm = CALL_RE.search(ins.text)
            if not cm:
                continue
            callee = normalize_target(cm.group(1))
            if callee != norm_target and norm_target not in callee:
                continue
            before = insns[max(0, i-window):i]
            writes: Dict[str, List[str]] = {r: [] for r in ARG_REGS}
            stack_refs: List[str] = []
            for b in before:
                if STACK_RE.search(b.text):
                    stack_refs.append(f"{b.addr}: {b.text}")
                # Intel syntax is easier to read from objdump -M intel; detect dest register at end.
                parts = [p.strip() for p in b.text.split(None, 1)]
                if len(parts) != 2:
                    continue
                op = parts[0].lower()
                operands = [p.strip() for p in parts[1].split(",", 1)]
                if len(operands) != 2:
                    continue
                dst = operands[0].lstrip("%").lower()
                dst = REG_ALIAS.get(dst, dst)
                if dst in ARG_REGS:
                    writes[dst].append(f"{b.addr}: {b.text}")
            out.append({
                "function": fn,
                "function_address": fn_addr,
                "call_site": ins.addr,
                "callee": callee,
                "instructions_before": [f"{x.addr}: {x.text}" for x in before],
                "register_writes": {k:v for k,v in writes.items() if v},
                "stack_refs": stack_refs,
                "note": "Static candidate extraction only; does not establish a Sony C prototype."
            })
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf")
    ap.add_argument("--disasm")
    ap.add_argument("--target", required=True)
    ap.add_argument("--window", type=int, default=24)
    ap.add_argument("--out")
    args = ap.parse_args()
    text = load_disasm(args)
    result = {
        "tool": "AGC PS5 Stage 9",
        "target": args.target,
        "source": args.elf or args.disasm,
        "calls": parse(text, args.target, args.window),
    }
    data = json.dumps(result, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(data + "\n")
    else:
        print(data)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
