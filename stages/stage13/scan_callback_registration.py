#!/usr/bin/env python3
"""Heuristic scanner for callback-table references in the stripped PS5 AGC driver."""
from pathlib import Path
import subprocess, re, sys

if len(sys.argv) != 2:
    print(f"usage: {sys.argv[0]} libSceAgcDriver.sprx")
    raise SystemExit(2)
path=Path(sys.argv[1])
b=path.read_bytes()
# first executable LOAD in these SPRX observed at file offset 0x4000.
code=b[0x4000:0x4000+0xaed2]
tmp=Path('/tmp/agc_driver_code.bin')
tmp.write_bytes(code)
text=subprocess.check_output([
    'objdump','-D','-b','binary','-m','i386:x86-64','--adjust-vma=0',str(tmp)
],text=True,errors='replace')
for line in text.splitlines():
    if any(tok in line for tok in ('1a908','1a868','1a8b8')):
        print(line)
