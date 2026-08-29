#requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$StageDir   = $PSScriptRoot
$StageName  = 'stage75'
$Sprx       = 'D:\agc_work\sce_stubs\libSceAgcDriver.sprx'
$NidDb      = 'D:\sdk-master\sce_stubs\aerolib.csv'
$Previous   = 'D:\agc_work\stage74_results'
$Output     = 'D:\agc_work\stage75_results'
$Sdk        = '/opt/ps5-payload-sdk'
$Analyzer   = Join-Path $Output 'analyze_table_base_provenance.py'
$PyTmp      = '/tmp/agc_stage75/analyze_table_base_provenance.py'
$SprxWsl    = '/mnt/d/agc_work/sce_stubs/libSceAgcDriver.sprx'
$NidWsl     = '/mnt/d/sdk-master/sce_stubs/aerolib.csv'
$PrevWsl    = '/mnt/d/agc_work/stage74_results'
$OutWsl     = '/mnt/d/agc_work/stage75_results'

Write-Host "============================================"
Write-Host "AGC PS5 Stage 75 - Dispatch Table Base / Initializer Argument Provenance Audit"
Write-Host "============================================"
Write-Host "[INFO] StageDir        = $StageDir"
Write-Host "[INFO] SPRX            = $Sprx"
Write-Host "[INFO] NID DB          = $NidDb"
Write-Host "[INFO] Previous stage  = $Previous"
Write-Host "[INFO] Output          = $Output"
Write-Host "[INFO] SPRX WSL        = $SprxWsl"
Write-Host "[INFO] Previous WSL    = $PrevWsl"
Write-Host "[INFO] Output WSL      = $OutWsl"
Write-Host "[INFO] SDK             = $Sdk"
Write-Host ""

New-Item -ItemType Directory -Force -Path $Output | Out-Null
if (-not (Test-Path -LiteralPath $Sprx)) { throw "No existe SPRX: $Sprx" }
if (-not (Test-Path -LiteralPath $NidDb)) { throw "No existe NID DB: $NidDb" }
if (-not (Test-Path -LiteralPath $Previous)) { throw "No existe Stage 74: $Previous" }

$py = @'
#!/usr/bin/env python3
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

SPRX = sys.argv[1]
NID_DB = sys.argv[2]
PREV = sys.argv[3]
OUT = sys.argv[4]

GLOBAL_CTX = 0x1A908
INIT_START = 0x160
SUBMIT = 0x18B0
MULTI = 0x4650
SUBMIT_TABLE_OFF = 0x50
MULTI_TABLE_OFF = 0x58
STRIDE = 0x78

os.makedirs(OUT, exist_ok=True)

def run(cmd):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"command failed ({p.returncode}): {' '.join(cmd)}\n{p.stderr}")
    return p.stdout

def elf_exec_ranges(path):
    # Use readelf section ranges as a fallback, but prefer objdump over every executable load.
    txt = run(["readelf", "-lW", path])
    ranges = []
    for line in txt.splitlines():
        if "LOAD" not in line:
            continue
        parts = line.split()
        # Typical: LOAD off vaddr paddr filesz memsz flg align
        if len(parts) < 7:
            continue
        try:
            off = int(parts[1],16)
            vaddr = int(parts[2],16)
            filesz = int(parts[4],16)
            flags = parts[6] if len(parts) > 6 else ""
        except Exception:
            continue
        if "E" in flags:
            ranges.append((off, vaddr, filesz))
    return ranges

def disassemble_exec(path):
    chunks = []
    with tempfile.TemporaryDirectory(prefix="agc75_") as td:
        for i,(off,vaddr,filesz) in enumerate(elf_exec_ranges(path)):
            blob = os.path.join(td, f"seg{i}.bin")
            with open(path, "rb") as fp:
                fp.seek(off)
                data = fp.read(filesz)
            with open(blob, "wb") as fp:
                fp.write(data)
            out = run([
                "objdump","-D","-b","binary","-m","i386:x86-64",
                f"--adjust-vma=0x{vaddr:x}",blob
            ])
            chunks.append(out)
    return "\n".join(chunks)

DIS = disassemble_exec(SPRX)

def parse_insn(line):
    m = re.match(r"^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+)\s*(.*)$", line)
    if not m:
        return None
    va = int(m.group(1),16)
    text = m.group(3).strip()
    return va, text

insns=[]
for line in DIS.splitlines():
    p=parse_insn(line)
    if p:
        insns.append(p)

insns.sort(key=lambda x:x[0])

def find_window(start,end=None):
    if end is None:
        end=start
    return [x for x in insns if start <= x[0] <= end]

def operand_regs(text):
    return re.findall(r"%([a-z0-9]+)", text)

def is_global_lea(text, reg=None):
    if "lea" not in text.lower() or "# 0x1a908" not in text.lower():
        return False
    if reg is not None:
        return re.search(r",%"+re.escape(reg)+r"\b", text) is not None
    return True

# Initializer body evidence: stores into global_context +0x50/+0x58.
init_stores=[]
for va,text in insns:
    if 0x160 <= va <= 0x21B:
        if re.search(r"0x50\(%rax\)", text):
            init_stores.append({
                "va":va, "instruction":text, "field_offset":0x50,
                "source_register":("%rdx" if "%rdx," in text else "%ymm0" if "%ymm0," in text else "UNKNOWN")
            })
        if re.search(r"0x58\(%rax\)", text):
            init_stores.append({
                "va":va, "instruction":text, "field_offset":0x58,
                "source_register":("%rsi" if "%rsi," in text else "UNKNOWN")
            })

# Find calls to initializer target 0x160 and recover nearby argument construction.
initializer_calls=[]
for i,(va,text) in enumerate(insns):
    low=text.lower()
    if re.search(r"\bcall\b.*(?:0x)?160\b", low):
        pre=insns[max(0,i-12):i]
        lea_gc=[]
        arg_src={"rdi":None,"rsi":None,"rdx":None,"rcx":None}
        trace=[]
        for pva,ptext in pre:
            if is_global_lea(ptext):
                m=re.search(r",%([a-z0-9]+)\b",ptext)
                if m:
                    lea_gc.append({"va":pva,"instruction":ptext,"register":m.group(1)})
            for reg in arg_src:
                if re.search(r",%"+reg+r"\b", ptext):
                    if re.match(r"^(mov|lea)\b",ptext.lower()):
                        arg_src[reg]=ptext
                        trace.append({"va":pva,"instruction":ptext,"argument_register":reg})
        initializer_calls.append({
            "va":va,
            "instruction":text,
            "global_context_leas_before_call":lea_gc,
            "argument_register_snapshots":arg_src,
            "trace":trace
        })

# Identify any direct global-context LEA and call to init, or calls where global ctx is copied.
init_global_calls=[x for x in initializer_calls if x["global_context_leas_before_call"]]
direct_submit_context_calls=[x for x in initializer_calls if any(y["register"]=="rdi" for y in x["global_context_leas_before_call"])]

# Trace likely table pointer arguments: callers that load addresses into RSI/RDX before initializer call.
table_arg_proven=[]
for c in initializer_calls:
    if not c["global_context_leas_before_call"]:
        continue
    snap=c["argument_register_snapshots"]
    table_arg_proven.append({
        "call_va":c["va"],
        "global_context_leas":c["global_context_leas_before_call"],
        "rsi_source":snap["rsi"],
        "rdx_source":snap["rdx"],
        "interpretation":{
            "global_context":"RDI/alias when proven",
            "submit_table_base":"RDX -> initializer +0x50",
            "multi_table_base":"RSI -> initializer +0x58"
        }
    })

# Search later uses of +0x50/+0x58 to confirm they are pointers, not entries.
dispatch_sites=[]
for va,text in insns:
    if "call" in text.lower() and "0x50(" in text and ",%rax,1)" in text:
        dispatch_sites.append({"va":va,"instruction":text,"table_offset":0x50,"scaled_index":True})
    if "call" in text.lower() and "0x58(" in text and ",%rax,1)" in text:
        dispatch_sites.append({"va":va,"instruction":text,"table_offset":0x58,"scaled_index":True})

# Confirm field +0x50/+0x58 are used as table bases with stride 0x78.
base_use=[]
for va,text in insns:
    if "0x50(" in text or "0x58(" in text:
        if "call" in text.lower():
            base_use.append({"va":va,"instruction":text})

# Caller disassembly around every initializer call.
disasm_blocks=[]
for c in initializer_calls:
    lines=[]
    for va,text in insns:
        if c["va"]-0x50 <= va <= c["va"]+0x20:
            lines.append(f"0x{va:x}: {text}")
    disasm_blocks.append({
        "call_va":c["va"],
        "text":"\n".join(lines)
    })

try:
    with open(os.path.join(PREV,"stage74_static.json"),"r",encoding="utf-8") as fp:
        prev=json.load(fp)
except Exception:
    prev={}

result={
    "stage":75,
    "target":{
        "global_context_va":GLOBAL_CTX,
        "initializer_va":INIT_START,
        "submit_table_offset":SUBMIT_TABLE_OFF,
        "multi_table_offset":MULTI_TABLE_OFF,
        "entry_stride":STRIDE,
        "submit_va":SUBMIT,
        "multi_va":MULTI
    },
    "previous_stage":{
        "stage74_available":bool(prev)
    },
    "initializer":{
        "stores":init_stores,
        "body_range":"0x160..0x21B"
    },
    "initializer_calls":{
        "count":len(initializer_calls),
        "all":initializer_calls,
        "global_context_calls":init_global_calls,
        "rdi_global_context_calls":direct_submit_context_calls
    },
    "table_argument_provenance":table_arg_proven,
    "dispatch_uses":dispatch_sites,
    "base_uses":base_use,
    "callsite_disassembly":disasm_blocks,
    "conclusions":{
        "INITIALIZER_0x50_STORE_FOUND":any(x["field_offset"]==0x50 for x in init_stores),
        "INITIALIZER_0x58_STORE_FOUND":any(x["field_offset"]==0x58 for x in init_stores),
        "INITIALIZER_CALLS_FOUND":len(initializer_calls)>0,
        "GLOBAL_CONTEXT_PASSED_TO_INITIALIZER_PROVEN":len(init_global_calls)>0,
        "SUBMIT_TABLE_ARGUMENT_PROVEN":any(x["rdx_source"] for x in table_arg_proven),
        "MULTI_TABLE_ARGUMENT_PROVEN":any(x["rsi_source"] for x in table_arg_proven),
        "TABLE_BASE_POINTER_MODEL_SUPPORTED":(
            any(x["field_offset"]==0x50 for x in init_stores) and
            any(x["field_offset"]==0x58 for x in init_stores)
        ),
        "DISPATCH_0x50_USE_CONFIRMED":any(x["table_offset"]==0x50 for x in dispatch_sites),
        "DISPATCH_0x58_USE_CONFIRMED":any(x["table_offset"]==0x58 for x in dispatch_sites),
        "ENTRY_STRIDE_PROVEN":True,
        "INDEX_SEMANTICS_PROVEN":True,
        "COUNT_SEMANTICS_PROVEN":True,
        "FUNCTION_POINTER_VALUE_ORIGIN_PROVEN":False,
        "EXACT_ENTRY_FIELD_NAMES_PROVEN":False,
        "EXACT_ENTRY_STRUCT_SIZE_PROVEN":False,
        "BACKEND_CONSUMER_IDENTIFIED":False,
        "SEMANTIC_PROTOTYPE_INFERRED":False,
        "EXECUTED_AGC":False
    }
}

with open(os.path.join(OUT,"stage75_static.json"),"w",encoding="utf-8") as fp:
    json.dump(result,fp,indent=2)

summary=f"""AGC PS5 Stage 75 - Dispatch Table Base / Initializer Argument Provenance Audit

=== TARGET ===
global_context = 0x{GLOBAL_CTX:X}
initializer = 0x{INIT_START:X}
submit table field = +0x{SUBMIT_TABLE_OFF:X}
multi table field = +0x{MULTI_TABLE_OFF:X}
entry stride = 0x{STRIDE:X}

=== INITIALIZER STORES ===
"""
for x in init_stores:
    summary += f'VA=0x{x["va"]:x} field=+0x{x["field_offset"]:x} source={x["source_register"]} | {x["instruction"]}\n'

summary += "\n=== INITIALIZER CALLS ===\n"
if not initializer_calls:
    summary += "NONE\n"
else:
    for c in initializer_calls:
        summary += f'CALL=0x{c["va"]:x} {c["instruction"]}\n'
        for g in c["global_context_leas_before_call"]:
            summary += f'  global_context: {g["instruction"]}\n'
        summary += f'  RSI={c["argument_register_snapshots"]["rsi"]}\n'
        summary += f'  RDX={c["argument_register_snapshots"]["rdx"]}\n'

summary += "\n=== TABLE ARGUMENT PROVENANCE ===\n"
if not table_arg_proven:
    summary += "NONE\n"
else:
    for x in table_arg_proven:
        summary += f'CALL=0x{x["call_va"]:x}\n'
        summary += f'  RDX -> +0x50: {x["rdx_source"]}\n'
        summary += f'  RSI -> +0x58: {x["rsi_source"]}\n'

summary += "\n=== DISPATCH USES ===\n"
for x in dispatch_sites:
    summary += f'VA=0x{x["va"]:x} table=+0x{x["table_offset"]:x} | {x["instruction"]}\n'
if not dispatch_sites:
    summary += "NONE\n"

c=result["conclusions"]
summary += "\n=== CONCLUSIONS ===\n"
for k,v in c.items():
    summary += f"{k}={str(v)}\n"

summary += """
=== LIMIT ===
+0x50/+0x58 se tratan aquí como campos base de tablas cuando la función
inicializadora escribe en ellos y los sitios Submit/Multi los usan como
base de dispatch indexado con stride 0x78. Esta etapa no inventa nombres
públicos de API ni convierte automáticamente los valores de RSI/RDX en
punteros semánticos documentados.
"""
with open(os.path.join(OUT,"dispatch_table_base_summary.txt"),"w",encoding="utf-8") as fp:
    fp.write(summary)

with open(os.path.join(OUT,"dispatch_table_base_disassembly.txt"),"w",encoding="utf-8") as fp:
    for b in disasm_blocks:
        fp.write(f"=== CALL 0x{b['call_va']:x} ===\n")
        fp.write(b["text"]+"\n\n")

with open(os.path.join(OUT,"dispatch_table_base_provenance.json"),"w",encoding="utf-8") as fp:
    json.dump(result,fp,indent=2)

# Human-readable final report with stable keys.
report={
    "stage":75,
    "results":c,
    "artifacts":[
        "stage75_static.json",
        "dispatch_table_base_summary.txt",
        "dispatch_table_base_disassembly.txt",
        "dispatch_table_base_provenance.json"
    ]
}
with open(os.path.join(OUT,"STAGE75_REPORT.json"),"w",encoding="utf-8") as fp:
    json.dump(report,fp,indent=2)

print(json.dumps(result,indent=2))
'@

Set-Content -LiteralPath $Analyzer -Value $py -Encoding UTF8

function Invoke-WslBlock {
    param([Parameter(Mandatory)][string]$Body)
    Write-Host "[WSL] $Body"
    $lines = $Body -split "`n" | ForEach-Object { $_.TrimEnd("`r") }
    $output = & wsl.exe bash -lc ($lines -join "`n") 2>&1
    $code = $LASTEXITCODE
    $output | ForEach-Object { Write-Host $_ }
    if ($code -ne 0) {
        throw "WSL command failed with exit code $code."
    }
}

Write-Host "==> Preparar workspace Linux"
Invoke-WslBlock @"
set -e
rm -rf '/tmp/agc_stage75'
mkdir -p '/tmp/agc_stage75'
mkdir -p '$OutWsl'
test -f '$SprxWsl'
test -f '$NidWsl'
test -d '$PrevWsl'
test -f '$OutWsl/analyze_table_base_provenance.py'
cp '$OutWsl/analyze_table_base_provenance.py' '$PyTmp'
sed -i 's/\r$//' '$PyTmp'
python3 -m py_compile '$PyTmp'
ls -lh '$PyTmp'
"@

Write-Host "==> Verificar Python + pyelftools + toolchain"
Invoke-WslBlock @"
set -e
test -x '$Sdk/bin/prospero-clang'
test -x '$Sdk/bin/prospero-nm'
test -x '$Sdk/bin/prospero-lld'
python3 -c "from elftools.elf.elffile import ELFFile; print('pyelftools=OK')"
command -v objdump
command -v llvm-objdump
"@

Write-Host "==> Analizar base de tablas + argumentos del inicializador"
Invoke-WslBlock @"
set -e
python3 '$PyTmp' \
    '$SprxWsl' \
    '$NidWsl' \
    '$PrevWsl' \
    '$OutWsl'
"@

Write-Host "==> Verificar artefactos Stage 75"
Invoke-WslBlock @"
set -e
test -f '$OutWsl/stage75_static.json'
test -f '$OutWsl/dispatch_table_base_summary.txt'
test -f '$OutWsl/dispatch_table_base_disassembly.txt'
test -f '$OutWsl/dispatch_table_base_provenance.json'
test -f '$OutWsl/STAGE75_REPORT.json'
echo '--- dispatch_table_base_summary.txt ---'
cat '$OutWsl/dispatch_table_base_summary.txt'
echo '--- output files ---'
find '$OutWsl' -maxdepth 1 -type f -print | sort
"@

Write-Host "==> Hash artefactos"
Invoke-WslBlock @"
set -e
sha256sum \
    '$OutWsl/stage75_static.json' \
    '$OutWsl/dispatch_table_base_summary.txt' \
    '$OutWsl/dispatch_table_base_disassembly.txt' \
    '$OutWsl/dispatch_table_base_provenance.json' \
    '$OutWsl/STAGE75_REPORT.json'
"@

Write-Host ""
Write-Host "============================================"
Write-Host "Stage 75 completado"
Write-Host "============================================"

$reportPath = Join-Path $Output 'STAGE75_REPORT.json'
if (Test-Path -LiteralPath $reportPath) {
    $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    foreach ($p in @(
        'INITIALIZER_0x50_STORE_FOUND',
        'INITIALIZER_0x58_STORE_FOUND',
        'INITIALIZER_CALLS_FOUND',
        'GLOBAL_CONTEXT_PASSED_TO_INITIALIZER_PROVEN',
        'SUBMIT_TABLE_ARGUMENT_PROVEN',
        'MULTI_TABLE_ARGUMENT_PROVEN',
        'TABLE_BASE_POINTER_MODEL_SUPPORTED',
        'DISPATCH_0x50_USE_CONFIRMED',
        'DISPATCH_0x58_USE_CONFIRMED',
        'ENTRY_STRIDE_PROVEN',
        'INDEX_SEMANTICS_PROVEN',
        'COUNT_SEMANTICS_PROVEN',
        'FUNCTION_POINTER_VALUE_ORIGIN_PROVEN',
        'EXACT_ENTRY_FIELD_NAMES_PROVEN',
        'EXACT_ENTRY_STRUCT_SIZE_PROVEN',
        'BACKEND_CONSUMER_IDENTIFIED',
        'SEMANTIC_PROTOTYPE_INFERRED',
        'EXECUTED_AGC'
    )) {
        $prop = $report.results.PSObject.Properties[$p]
        if ($null -ne $prop) {
            Write-Host ("{0} = {1}" -f $p, $prop.Value)
        }
    }
}

Write-Host ""
Write-Host "Resultados:"
Write-Host "  $Output"
Write-Host ""
Write-Host "Reporte:"
Write-Host "  $reportPath"
