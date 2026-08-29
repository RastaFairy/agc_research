#!/usr/bin/env python3
"""Heuristic scanner for code that writes the callback slot entry+0x48."""
from pathlib import Path
import subprocess, re, sys

if len(sys.argv) != 2:
    print(f"usage: {sys.argv[0]} libSceAgcDriver.sprx")
    raise SystemExit(2)
path=Path(sys.argv[1])
b=path.read_bytes()
code=b[0x4000:0x4000+0xaed2]
tmp=Path('/tmp/agc_driver_stage14.bin')
tmp.write_bytes(code)
text=subprocess.check_output(
    ['objdump','-D','-b','binary','-m','i386:x86-64',str(tmp)],
    text=True, errors='replace')

patterns = [
    r'48 89 .*0x48\(%',
    r'4c 89 .*0x48\(%',
    r'48 8d .*0x48\(%',
]
for line in text.splitlines():
    if '0x48(' in line or '48(%' in line:
        print(line)
