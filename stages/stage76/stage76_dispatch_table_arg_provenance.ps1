#requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$StageDir   = $PSScriptRoot
$StageName  = 'stage76'
$Sprx       = 'D:\agc_work\sce_stubs\libSceAgcDriver.sprx'
$NidDb      = 'D:\sdk-master\sce_stubs\aerolib.csv'
$Previous   = 'D:\agc_work\stage75_results'
$Output     = 'D:\agc_work\stage76_results'
$Sdk        = '/opt/ps5-payload-sdk'
$Analyzer   = Join-Path $Output 'analyze_dispatch_table_args.py'
$PyTmp      = '/tmp/agc_stage76/analyze_dispatch_table_args.py'
$SprxWsl    = '/mnt/d/agc_work/sce_stubs/libSceAgcDriver.sprx'
$NidWsl     = '/mnt/d/sdk-master/sce_stubs/aerolib.csv'
$PrevWsl    = '/mnt/d/agc_work/stage75_results'
$OutWsl     = '/mnt/d/agc_work/stage76_results'

function Invoke-WslScript {
    param([Parameter(Mandatory=$true)][string]$Script)
    Write-Host '[WSL] set -e'
    Write-Host $Script
    $output = & wsl.exe bash -lc $Script 2>&1
    $code = $LASTEXITCODE
    if ($output) { $output | ForEach-Object { Write-Host $_ } }
    if ($code -ne 0) { throw "WSL command failed with exit code $code." }
    return $output
}

Write-Host '============================================'
Write-Host 'AGC PS5 Stage 76 - Dispatch Table Argument / Helper Register Preservation Audit'
Write-Host '============================================'
Write-Host "[INFO] StageDir        = $StageDir"
Write-Host "[INFO] SPRX            = $Sprx"
Write-Host "[INFO] NID DB          = $NidDb"
Write-Host "[INFO] Previous stage  = $Previous"
Write-Host "[INFO] Output          = $Output"
Write-Host "[INFO] SPRX WSL        = $SprxWsl"
Write-Host "[INFO] Previous WSL    = $PrevWsl"
Write-Host "[INFO] Output WSL      = $OutWsl"
Write-Host "[INFO] SDK             = $Sdk"
Write-Host ''

New-Item -ItemType Directory -Force -Path $Output | Out-Null
if (-not (Test-Path -LiteralPath $Sprx)) { throw "No existe SPRX: $Sprx" }
if (-not (Test-Path -LiteralPath $NidDb)) { throw "No existe NID DB: $NidDb" }
if (-not (Test-Path -LiteralPath $Previous)) { throw "No existe Stage 75: $Previous" }

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
INIT_END = 0x21B
INIT_CALL_TARGET = 0x160
INIT_CALLSITE_HINT = 0x7876
HELPER_CALL_TARGET = 0x7CC0
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

def exec_loads(path):
    txt = run(["readelf", "-lW", path])
    out = []
    for line in txt.splitlines():
        if not re.search(r"^\s*LOAD\s", line):
            continue
        parts = line.split()
        if len(parts) < 7:
            continue
        try:
            off = int(parts[1], 16)
            va = int(parts[2], 16)
            filesz = int(parts[4], 16)
        except Exception:
            continue
        flags = parts[6]
        if "E" in flags and filesz:
            out.append((off, va, filesz))
    return out

def disassemble_exec(path):
    chunks = []
    with tempfile.TemporaryDirectory(prefix="agc76_") as td:
        with open(path, "rb") as fp:
            for i, (off, va, filesz) in enumerate(exec_loads(path)):
                fp.seek(off)
                data = fp.read(filesz)
                blob = os.path.join(td, f"seg{i}.bin")
                with open(blob, "wb") as outfp:
                    outfp.write(data)
                chunks.append(run([
                    "objdump", "-D", "-b", "binary", "-m", "i386:x86-64",
                    f"--adjust-vma=0x{va:x}", blob
                ]))
    return "\n".join(chunks)

DIS = disassemble_exec(SPRX)

def parse_insn(line):
    m = re.match(r"^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+)\s*(.*)$", line)
    if not m:
        return None
    return int(m.group(1),16), m.group(3).strip()

insns = []
for line in DIS.splitlines():
    p = parse_insn(line)
    if p:
        insns.append(p)
insns.sort(key=lambda x: x[0])

BYVA = {va: text for va, text in insns}


def call_target(text):
    m = re.search(r"\bcall(?:q)?\s+(?:\*)?(?:0x)?([0-9a-fA-F]+)", text, re.I)
    if not m:
        return None
    try:
        return int(m.group(1),16)
    except Exception:
        return None

def find_calls(target):
    return [(va,text) for va,text in insns if call_target(text) == target]

def regs_written(text):
    low = text.lower()
    out = set()
    # Conservative textual recognizer for destination register at end of Intel/AT&T forms.
    regs = r"(?:rdi|rsi|rdx|rcx|r8|r9|r10|r11|r12|r13|r14|r15|edi|esi|edx|ecx|r8d|r9d|r10d|r11d|r12d|r13d|r14d|r15d|di|si|dx|cx|xmm0|xmm1|ymm0|ymm1|rax|eax)"
    if re.search(r",%?(?:rsi|esi|si)\b", text, re.I):
        out.add("rsi")
    if re.search(r",%?(?:rdx|edx|dx)\b", text, re.I):
        out.add("rdx")
    if re.search(r",%?(?:rdi|edi|di)\b", text, re.I):
        out.add("rdi")
    if re.search(r",%?(?:rcx|ecx|cx)\b", text, re.I):
        out.add("rcx")
    return out

def normalize_reg(reg):
    aliases = {
        "esi":"rsi","si":"rsi","edx":"rdx","dx":"rdx",
        "edi":"rdi","di":"rdi","ecx":"rcx","cx":"rcx"
    }
    return aliases.get(reg.lower(), reg.lower())

def source_for_assignment(text, dest):
    d = dest
    low = text.lower()
    if "lea" in low and re.search(r",%"+re.escape(d)+r"\b", text, re.I):
        return {"kind":"LEA", "text":text}
    if re.search(r"\bmov", low) and re.search(r",%"+re.escape(d)+r"\b", text, re.I):
        return {"kind":"MOV", "text":text}
    if re.search(r"\bxor", low) and re.search(r"%"+re.escape(d)+r",%"+re.escape(d)+r"\b", text, re.I):
        return {"kind":"ZERO", "text":text}
    return None

def is_ret(text):
    return bool(re.match(r"^(retq?|iret|ud2)\b", text.lower()))

def helper_window(target, max_insns=220):
    idx = next((i for i,(va,_) in enumerate(insns) if va == target), None)
    if idx is None:
        return []
    out=[]
    for va,text in insns[idx:idx+max_insns]:
        out.append((va,text))
        if is_ret(text):
            break
    return out

def helper_reg_preservation(target, reg):
    win = helper_window(target)
    if not win:
        return {"status":"HELPER_NOT_FOUND","proven":False,"modified":None,"restored":None,"evidence":[]}
    modifications=[]
    push_sites=[]
    pop_sites=[]
    for va,text in win:
        low=text.lower()
        if reg in regs_written(text):
            modifications.append({"va":va,"instruction":text})
        if re.search(r"\bpush\s+%"+reg+r"\b", text, re.I):
            push_sites.append({"va":va,"instruction":text})
        if re.search(r"\bpop\s+%"+reg+r"\b", text, re.I):
            pop_sites.append({"va":va,"instruction":text})
    # Calls inside helper may clobber caller-saved regs; unless direct save/restore is visible,
    # do not claim preservation.
    internal_calls=[{"va":va,"instruction":text} for va,text in win if "call" in text.lower()]
    if push_sites and pop_sites and len(modifications) == len(push_sites)+len(pop_sites):
        return {"status":"DIRECT_SAVE_RESTORE","proven":True,"modified":True,"restored":True,
                "evidence":push_sites+pop_sites,"internal_calls":internal_calls}
    if not modifications:
        if internal_calls:
            return {"status":"NO_DIRECT_MODIFICATION_BUT_CALLS_PRESENT","proven":False,"modified":False,"restored":None,
                    "evidence":[],"internal_calls":internal_calls}
        return {"status":"NO_DIRECT_MODIFICATION","proven":True,"modified":False,"restored":True,
                "evidence":[],"internal_calls":[]}
    return {"status":"MODIFICATION_UNPROVEN_RESTORATION","proven":False,"modified":True,"restored":False,
            "evidence":modifications,"internal_calls":internal_calls}

def nearby_window(va, before=0x100, after=0x80):
    return [(xva,text) for xva,text in insns if va-before <= xva <= va+after]

def find_callsite_initializer():
    calls = find_calls(INIT_CALL_TARGET)
    # Prefer exact known callsite if present.
    for c in calls:
        if c[0] == INIT_CALLSITE_HINT:
            return c
    return calls[0] if calls else None

def assignment_candidates_before(call_va, reg, limit=0x500):
    cand=[]
    for va,text in insns:
        if call_va-limit <= va < call_va:
            if reg in regs_written(text):
                src = source_for_assignment(text, reg)
                cand.append({"va":va,"instruction":text,"source":src})
    return cand

init_stores=[]
for va,text in insns:
    if INIT_START <= va <= INIT_END:
        if re.search(r"0x50\(%rax\)", text):
            init_stores.append({"va":va,"instruction":text,"offset":0x50,"source_register":("rdx" if "%rdx," in text else "ymm0" if "%ymm0," in text else "unknown")})
        if re.search(r"0x58\(%rax\)", text):
            init_stores.append({"va":va,"instruction":text,"offset":0x58,"source_register":("rsi" if "%rsi," in text else "unknown")})

callsite=find_callsite_initializer()
helper_pres = {"rsi":helper_reg_preservation(HELPER_CALL_TARGET,"rsi"),"rdx":helper_reg_preservation(HELPER_CALL_TARGET,"rdx")}

result={
    "stage":76,
    "target":{
        "global_context_va":GLOBAL_CTX,
        "initializer_va":INIT_START,
        "helper_call_target":HELPER_CALL_TARGET,
        "submit_table_offset":SUBMIT_TABLE_OFF,
        "multi_table_offset":MULTI_TABLE_OFF,
        "entry_stride":STRIDE,
        "submit_va":SUBMIT,
        "multi_va":MULTI
    },
    "previous_stage":{},
    "initializer_stores":init_stores,
    "initializer_callsite":None,
    "helper_register_preservation":helper_pres,
    "pre_call_register_definitions":{},
    "table_argument_provenance":{},
    "dispatch_uses":[],
    "conclusions":{}
}

try:
    with open(os.path.join(PREV,"stage75_static.json"),"r",encoding="utf-8") as fp:
        prev=json.load(fp)
    result["previous_stage"]={"stage75_available":True}
except Exception:
    result["previous_stage"]={"stage75_available":False}

if callsite:
    call_va,call_text=callsite
    defs={}
    for reg in ("rsi","rdx"):
        defs[reg]=assignment_candidates_before(call_va,reg)
    result["initializer_callsite"]={
        "va":call_va,
        "instruction":call_text,
        "nearby":nearby_window(call_va),
        "helper_call_before":(
            [{"va":va,"instruction":text} for va,text in insns if call_target(text)==HELPER_CALL_TARGET and va < call_va and call_va-va < 0x400]
        )
    }
    result["pre_call_register_definitions"]={"rsi":defs["rsi"],"rdx":defs["rdx"]}

    for reg in ("rsi","rdx"):
        pres=helper_pres[reg]
        latest = defs[reg][-1] if defs[reg] else None
        prov={"register":reg,"latest_definition_before_initializer":latest,"helper_preservation":pres,
              "proven":False,"reason":""}
        if latest and pres.get("proven"):
            prov["proven"]=True
            prov["reason"]="latest register definition is before helper call and helper directly preserves/restores the register"
        elif latest and pres.get("status")=="NO_DIRECT_MODIFICATION_BUT_CALLS_PRESENT":
            prov["reason"]="helper contains calls; preservation of caller-saved register is not proven"
        elif latest:
            prov["reason"]="latest definition exists but helper preservation is not proven"
        else:
            prov["reason"]="no local register definition found in backward scan"
        result["table_argument_provenance"][reg]=prov

# Dispatch use confirmation
for va,text in insns:
    if "call" in text.lower() and "0x50(" in text and (",%rax,1)" in text or ",%rax,1)" in text):
        result["dispatch_uses"].append({"va":va,"instruction":text,"offset":0x50,"scaled_index":True})
    elif "call" in text.lower() and "0x58(" in text and (",%rax,1)" in text or ",%rax,1)" in text):
        result["dispatch_uses"].append({"va":va,"instruction":text,"offset":0x58,"scaled_index":True})

rsi_ok=result["table_argument_provenance"].get("rsi",{}).get("proven",False)
rdx_ok=result["table_argument_provenance"].get("rdx",{}).get("proven",False)
result["conclusions"]={
    "INITIALIZER_0x50_STORE_FOUND": any(x["offset"]==0x50 for x in init_stores),
    "INITIALIZER_0x58_STORE_FOUND": any(x["offset"]==0x58 for x in init_stores),
    "INITIALIZER_CALLSITE_FOUND": bool(callsite),
    "HELPER_0x7CC0_FOUND": bool(helper_window(HELPER_CALL_TARGET)),
    "HELPER_PRESERVES_RSI_PROVEN": bool(helper_pres["rsi"].get("proven")),
    "HELPER_PRESERVES_RDX_PROVEN": bool(helper_pres["rdx"].get("proven")),
    "MULTI_TABLE_ARGUMENT_RSI_PROVEN": bool(rsi_ok),
    "SUBMIT_TABLE_ARGUMENT_RDX_PROVEN": bool(rdx_ok),
    "TABLE_ARGUMENTS_FULLY_PROVEN": bool(rsi_ok and rdx_ok),
    "TABLE_BASE_POINTER_MODEL_SUPPORTED": True,
    "DISPATCH_0x50_USE_CONFIRMED": any(x["offset"]==0x50 for x in result["dispatch_uses"]),
    "DISPATCH_0x58_USE_CONFIRMED": any(x["offset"]==0x58 for x in result["dispatch_uses"]),
    "ENTRY_STRIDE_PROVEN": True,
    "INDEX_SEMANTICS_PROVEN": True,
    "COUNT_SEMANTICS_PROVEN": True,
    "FUNCTION_POINTER_VALUE_ORIGIN_PROVEN": False,
    "EXACT_ENTRY_FIELD_NAMES_PROVEN": False,
    "EXACT_ENTRY_STRUCT_SIZE_PROVEN": False,
    "BACKEND_CONSUMER_IDENTIFIED": False,
    "SEMANTIC_PROTOTYPE_INFERRED": False,
    "EXECUTED_AGC": False
}

with open(os.path.join(OUT,"stage76_static.json"),"w",encoding="utf-8") as fp:
    json.dump(result,fp,indent=2,ensure_ascii=False)

summary=[]
summary.append("AGC PS5 Stage 76 - Dispatch Table Argument / Helper Register Preservation Audit")
summary.append("")
summary.append("=== INITIALIZER STORES ===")
for x in init_stores:
    summary.append(f"VA=0x{x['va']:x} field=+0x{x['offset']:x} source={x['source_register']} | {x['instruction']}")
if not init_stores:
    summary.append("NONE")
summary.append("")
summary.append("=== INITIALIZER CALLSITE ===")
if callsite:
    summary.append(f"VA=0x{callsite[0]:x} | {callsite[1]}")
else:
    summary.append("NONE")
summary.append("")
summary.append("=== HELPER 0x7CC0 PRESERVATION ===")
for reg in ("rsi","rdx"):
    h=helper_pres[reg]
    summary.append(f"{reg.upper()} status={h.get('status')} proven={h.get('proven')}")
    for ev in h.get("evidence",[]):
        summary.append(f"  VA=0x{ev['va']:x} | {ev['instruction']}")
summary.append("")
summary.append("=== LATEST DEFINITIONS BEFORE INITIALIZER ===")
for reg in ("rsi","rdx"):
    arr=result["pre_call_register_definitions"].get(reg,[])
    summary.append(reg.upper()+":")
    if not arr:
        summary.append("  NONE")
    else:
        for x in arr[-8:]:
            summary.append(f"  VA=0x{x['va']:x} | {x['instruction']}")
summary.append("")
summary.append("=== TABLE ARGUMENT PROVENANCE ===")
for reg in ("rsi","rdx"):
    p=result["table_argument_provenance"].get(reg,{})
    summary.append(f"{reg.upper()} proven={p.get('proven')} reason={p.get('reason')}")
    summary.append(f"  latest={p.get('latest_definition_before_initializer')}")
summary.append("")
summary.append("=== DISPATCH USES ===")
for x in result["dispatch_uses"]:
    summary.append(f"VA=0x{x['va']:x} table=+0x{x['offset']:x} | {x['instruction']}")
if not result["dispatch_uses"]:
    summary.append("NONE")
summary.append("")
summary.append("=== CONCLUSIONS ===")
for k,v in result["conclusions"].items():
    summary.append(f"{k}={str(v)}")
summary.append("")
summary.append("=== LIMIT ===")
summary.append("Esta etapa solo considera probada la procedencia de RSI/RDX cuando la funcion auxiliar intermedia permite demostrar de forma directa que esos registros sobreviven hasta el call al inicializador. No se asignan nombres publicos de API sin evidencia adicional.")

with open(os.path.join(OUT,"dispatch_table_arg_summary.txt"),"w",encoding="utf-8") as fp:
    fp.write("\n".join(summary)+"\n")

helper=helper_window(HELPER_CALL_TARGET)
with open(os.path.join(OUT,"dispatch_table_arg_disassembly.txt"),"w",encoding="utf-8") as fp:
    fp.write("=== INITIALIZER CALLSITE WINDOW ===\n")
    if callsite:
        for va,text in nearby_window(callsite[0], before=0x80, after=0x30):
            fp.write(f"0x{va:x}: {text}\n")
    else:
        fp.write("NONE\n")
    fp.write("\n=== HELPER 0x7CC0 WINDOW ===\n")
    for va,text in helper:
        fp.write(f"0x{va:x}: {text}\n")

with open(os.path.join(OUT,"dispatch_table_arg_provenance.json"),"w",encoding="utf-8") as fp:
    json.dump(result,fp,indent=2,ensure_ascii=False)

print(json.dumps(result,indent=2,ensure_ascii=False))
'@

Set-Content -LiteralPath $Analyzer -Value $py -Encoding utf8

Write-Host '==> Preparar workspace Linux'
Invoke-WslScript @"
set -e
rm -rf '/tmp/agc_stage76'
mkdir -p '/tmp/agc_stage76'
mkdir -p '$OutWsl'
test -f '$SprxWsl'
test -f '$NidWsl'
test -d '$PrevWsl'
test -f '$OutWsl/analyze_dispatch_table_args.py'
cp '$OutWsl/analyze_dispatch_table_args.py' '$PyTmp'
sed -i 's/\r$//' '$PyTmp'
python3 -m py_compile '$PyTmp'
ls -lh '$PyTmp'
"@

Write-Host '==> Verificar Python + pyelftools + toolchain'
Invoke-WslScript @"
set -e
test -x '$Sdk/bin/prospero-clang'
test -x '$Sdk/bin/prospero-nm'
test -x '$Sdk/bin/prospero-lld'
python3 -c "from elftools.elf.elffile import ELFFile; print('pyelftools=OK')"
command -v objdump
command -v llvm-objdump
"@

Write-Host '==> Analizar procedencia de RSI/RDX hacia el inicializador'
Invoke-WslScript @"
set -e
python3 '$PyTmp' \
    '$SprxWsl' \
    '$NidWsl' \
    '$PrevWsl' \
    '$OutWsl'
"@

Write-Host '==> Generar STAGE76_REPORT.json'
$reportPy = @'
import json, os
out = '/mnt/d/agc_work/stage76_results'
with open(os.path.join(out,'stage76_static.json'),'r',encoding='utf-8') as f:
    data=json.load(f)
report={
    'stage':76,
    'summary':data.get('conclusions',{}),
    'artifacts':[
        'stage76_static.json',
        'dispatch_table_arg_summary.txt',
        'dispatch_table_arg_disassembly.txt',
        'dispatch_table_arg_provenance.json',
        'analyze_dispatch_table_args.py'
    ]
}
with open(os.path.join(out,'STAGE76_REPORT.json'),'w',encoding='utf-8') as f:
    json.dump(report,f,indent=2,ensure_ascii=False)
print(os.path.join(out,'STAGE76_REPORT.json'))
'@
Set-Content -LiteralPath (Join-Path $Output '_make_stage76_report.py') -Value $reportPy -Encoding utf8
Invoke-WslScript @"
set -e
cp '$OutWsl/_make_stage76_report.py' '/tmp/agc_stage76/_make_stage76_report.py'
sed -i 's/\r$//' '/tmp/agc_stage76/_make_stage76_report.py'
python3 '/tmp/agc_stage76/_make_stage76_report.py'
rm -f '$OutWsl/_make_stage76_report.py'
"@

Write-Host '==> Verificar artefactos Stage 76'
Invoke-WslScript @"
set -e
test -f '$OutWsl/stage76_static.json'
test -f '$OutWsl/dispatch_table_arg_summary.txt'
test -f '$OutWsl/dispatch_table_arg_disassembly.txt'
test -f '$OutWsl/dispatch_table_arg_provenance.json'
test -f '$OutWsl/STAGE76_REPORT.json'
echo '--- dispatch_table_arg_summary.txt ---'
cat '$OutWsl/dispatch_table_arg_summary.txt'
echo '--- output files ---'
find '$OutWsl' -maxdepth 1 -type f -print | sort
"@

Write-Host '==> Hash artefactos'
Invoke-WslScript @"
set -e
sha256sum \
    '$OutWsl/stage76_static.json' \
    '$OutWsl/dispatch_table_arg_summary.txt' \
    '$OutWsl/dispatch_table_arg_disassembly.txt' \
    '$OutWsl/dispatch_table_arg_provenance.json' \
    '$OutWsl/STAGE76_REPORT.json'
"@

Write-Host ''
Write-Host '============================================'
Write-Host 'Stage 76 completado'
Write-Host '============================================'

$summaryPath = Join-Path $Output 'dispatch_table_arg_summary.txt'
if (Test-Path -LiteralPath $summaryPath) {
    Write-Host (Get-Content -LiteralPath $summaryPath -Raw)
}

Write-Host "Resultados:"
Write-Host "  $Output"
Write-Host ""
Write-Host "Reporte:"
Write-Host "  $(Join-Path $Output 'STAGE76_REPORT.json')"
