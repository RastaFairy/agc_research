#!/bin/sh
set -eu
cd "$(dirname "$0")"
if ! command -v gcc >/dev/null 2>&1; then echo "gcc unavailable"; exit 1; fi
gcc -c sample_calls.S -o sample_calls.o
# Scan disassembly with Intel syntax for deterministic register evidence.
objdump -d -M intel sample_calls.o > sample_calls.asm.txt
python3 tools/agc_callsite_scan.py --disasm sample_calls.asm.txt --target sceAgcInit --out sample_result.json
python3 - <<'PY'
import json
x=json.load(open('sample_result.json'))
assert x['calls'], 'no call-site found'
w=x['calls'][0]['register_writes']
for r in ('rdi','rsi','rdx','rcx'):
    assert r in w, r
print('Stage 9 static call-site extractor: PASS')
print('observed registers:', ', '.join(w))
PY
