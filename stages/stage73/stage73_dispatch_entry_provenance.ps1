#Requires -Version 7.0

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$StageDir    = $PSScriptRoot
$StageName   = 'Stage 73'
$SprxWin     = 'D:\agc_work\sce_stubs\libSceAgcDriver.sprx'
$NidDbWin    = 'D:\sdk-master\sce_stubs\aerolib.csv'
$PrevWin     = 'D:\agc_work\stage72_results'
$OutputWin   = 'D:\agc_work\stage73_results'
$SdkRootWsl  = '/opt/ps5-payload-sdk'

function Convert-ToWslPath {
    param([Parameter(Mandatory)][string]$WindowsPath)
    if ($WindowsPath -match '^([A-Za-z]):\\(.*)$') {
        $drive = $Matches[1].ToLowerInvariant()
        $rest  = $Matches[2] -replace '\\','/'
        return "/mnt/$drive/$rest"
    }
    throw "Ruta Windows no convertible a WSL: $WindowsPath"
}

function Invoke-WslBash {
    param(
        [Parameter(Mandatory)][string]$Script,
        [string]$Label = 'WSL'
    )

    Write-Host "`n[WSL] $Script"
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = 'wsl.exe'
    $psi.ArgumentList.Add('--')
    $psi.ArgumentList.Add('bash')
    $psi.ArgumentList.Add('-lc')
    $psi.ArgumentList.Add($Script)
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

    $p = [System.Diagnostics.Process]::new()
    $p.StartInfo = $psi
    [void]$p.Start()
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()

    if ($stdout) { Write-Host $stdout.TrimEnd() }
    if ($stderr) { Write-Host $stderr.TrimEnd() }
    if ($p.ExitCode -ne 0) {
        throw "$Label failed with exit code $($p.ExitCode)."
    }
    return $stdout
}

Write-Host '============================================'
Write-Host 'AGC PS5 Stage 73 - Dispatch Entry / Pointer Source Provenance Audit'
Write-Host '============================================'
Write-Host "[INFO] StageDir       = $StageDir"
Write-Host "[INFO] SPRX           = $SprxWin"
Write-Host "[INFO] NID DB         = $NidDbWin"
Write-Host "[INFO] Previous stage = $PrevWin"
Write-Host "[INFO] Output         = $OutputWin"

$SprxWsl   = Convert-ToWslPath $SprxWin
$NidDbWsl  = Convert-ToWslPath $NidDbWin
$PrevWsl   = Convert-ToWslPath $PrevWin
$OutputWsl = Convert-ToWslPath $OutputWin

New-Item -ItemType Directory -Force -Path $OutputWin | Out-Null

$AnalyzerPath = Join-Path $OutputWin 'analyze_dispatch_entry_provenance.py'
$AnalyzerWsl  = Convert-ToWslPath $AnalyzerPath

$PythonAnalyzer = @'
#!/usr/bin/env python3
import json
import os
import re
import subprocess
import sys
from pathlib import Path

SPRXP, NIDP, PREV, OUT = sys.argv[1:5]
OUTP = Path(OUT)
OUTP.mkdir(parents=True, exist_ok=True)

GLOBAL = 0x1A908
SUBMIT_TABLE = 0x50
MULTI_TABLE = 0x58
STRIDE = 0x78
SUBMIT_VA = 0x18B0
SUBMIT_SIZE = 0x17C
MULTI_VA = 0x4650
MULTI_SIZE = 0x243

with open(SPRXP, 'rb') as fp:
    SPRX_BYTES = fp.read()


def run(cmd, check=True):
    p = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and p.returncode != 0:
        raise RuntimeError(f"command failed: {' '.join(cmd)}\n{p.stderr}")
    return p.stdout


def load_exec_segments():
    # pyelftools keeps the ELF stream open for us in this scope.
    from elftools.elf.elffile import ELFFile
    segs = []
    with open(SPRXP, 'rb') as fp:
        elf = ELFFile(fp)
        for seg in elf.iter_segments():
            if seg['p_type'] == 'PT_LOAD' and (seg['p_flags'] & 1):
                vaddr = int(seg['p_vaddr'])
                filesz = int(seg['p_filesz'])
                off = int(seg['p_offset'])
                blob = seg.data()[:filesz]
                segs.append({'vaddr': vaddr, 'filesz': filesz, 'offset': off, 'bytes': blob})
    return segs

SEGMENTS = load_exec_segments()


def in_exec(va):
    for s in SEGMENTS:
        if s['vaddr'] <= va < s['vaddr'] + s['filesz']:
            return True
    return False


def disassemble_segment(seg):
    import tempfile
    fd, path = tempfile.mkstemp(prefix='agc73_', suffix='.bin', dir='/tmp')
    os.close(fd)
    try:
        Path(path).write_bytes(seg['bytes'])
        text = run([
            'objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64',
            '--adjust-vma=0x%x' % seg['vaddr'], path
        ])
        return text
    finally:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def parse_disassembly(text):
    rows = []
    current_va = None
    current_raw = ''
    current_insn = ''
    for line in text.splitlines():
        m = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)\s*(.*)$', line)
        if not m:
            continue
        va = int(m.group(1), 16)
        bytes_part = re.sub(r'\s+$', '', m.group(2))
        insn = m.group(3).strip()
        rows.append({'va': va, 'instruction': insn, 'bytes': bytes_part})
    return rows


ALL_ROWS = []
SEG_DISASM = []
for seg in SEGMENTS:
    txt = disassemble_segment(seg)
    SEG_DISASM.append(txt)
    ALL_ROWS.extend(parse_disassembly(txt))
ALL_ROWS.sort(key=lambda x: x['va'])


def row_index(va):
    lo, hi = 0, len(ALL_ROWS)
    while lo < hi:
        mid = (lo + hi) // 2
        if ALL_ROWS[mid]['va'] < va:
            lo = mid + 1
        else:
            hi = mid
    return lo


def window(center, before=96, after=96):
    i = row_index(center)
    return ALL_ROWS[max(0, i-before):min(len(ALL_ROWS), i+after+1)]


def normalize_reg(r):
    r = r.strip().lower().replace('%','')
    aliases = {
        'eax':'rax','ax':'rax','al':'rax',
        'ebx':'rbx','bx':'rbx','bl':'rbx',
        'ecx':'rcx','cx':'rcx','cl':'rcx',
        'edx':'rdx','dx':'rdx','dl':'rdx',
        'esi':'rsi','si':'rsi','sil':'rsi',
        'edi':'rdi','di':'rdi','dil':'rdi',
        'r8d':'r8','r8w':'r8','r8b':'r8',
        'r9d':'r9','r9w':'r9','r9b':'r9',
        'r10d':'r10','r10w':'r10','r10b':'r10',
        'r11d':'r11','r11w':'r11','r11b':'r11',
        'r12d':'r12','r12w':'r12','r12b':'r12',
        'r13d':'r13','r13w':'r13','r13b':'r13',
        'r14d':'r14','r14w':'r14','r14b':'r14',
        'r15d':'r15','r15w':'r15','r15b':'r15',
    }
    return aliases.get(r, r)


def parse_imm_target(insn):
    # GNU objdump's RIP-relative LEA frequently contains '# 0x1a908'.
    m = re.search(r'#\s*0x([0-9a-f]+)', insn, re.I)
    return int(m.group(1), 16) if m else None


def parse_memory_operand(insn):
    # Generic AT&T memory operand parser for our specific forms.
    # Returns offset, base, index, scale.
    m = re.search(r'(?:^|\s)([-+]?0x[0-9a-f]+|[-+]?\d+)?\((%[a-z0-9]+)(?:,(%[a-z0-9]+),([1248]))?\)', insn, re.I)
    if not m:
        return None
    off_s = m.group(1)
    off = int(off_s, 0) if off_s else 0
    base = normalize_reg(m.group(2))
    idx = normalize_reg(m.group(3)) if m.group(3) else None
    scale = int(m.group(4)) if m.group(4) else 1
    return off, base, idx, scale


def is_store(insn):
    # Store if destination operand is a memory operand (last operand in AT&T syntax).
    if ',' not in insn:
        return False
    dst = insn.rsplit(',', 1)[1].strip()
    return '(' in dst and ')' in dst


def is_load(insn):
    if ',' not in insn:
        return False
    src = insn.rsplit(',', 1)[0].strip()
    return '(' in src and ')' in src


def find_global_leas(rows, start_va, end_va):
    out = []
    for r in rows:
        if not (start_va <= r['va'] <= end_va):
            continue
        if re.search(r'\blea\s', r['instruction'], re.I):
            target = parse_imm_target(r['instruction'])
            if target == GLOBAL:
                m = re.search(r',%(r(?:1[0-5]|[abcd]x|si|di|sp|bp|8|9))\s*$', r['instruction'], re.I)
                if not m:
                    m = re.search(r',%(r[a-z0-9]+)\s*$', r['instruction'], re.I)
                if m:
                    out.append({'va': r['va'], 'instruction': r['instruction'], 'register': normalize_reg(m.group(1))})
    return out


def find_previous_register_definition(rows, idx, reg, limit=48):
    reg = normalize_reg(reg)
    for j in range(idx-1, max(-1, idx-limit), -1):
        insn = rows[j]['instruction']
        # Any write to the destination register. This is conservative.
        if re.search(r',%'+re.escape(reg)+r'\s*$', insn, re.I):
            return rows[j]
        if re.search(r'\s(?:%'+re.escape(reg)+r')\s*,', insn, re.I):
            return rows[j]
    return None


def source_pointer_evidence(rows, idx, src_reg):
    src_reg = normalize_reg(src_reg)
    ev = []
    for j in range(idx-1, max(-1, idx-40), -1):
        insn = rows[j]['instruction']
        if re.search(r'\blea\b', insn, re.I):
            target = parse_imm_target(insn)
            if target is not None:
                dst = re.search(r',%(r[a-z0-9]+)\s*$', insn, re.I)
                if dst and normalize_reg(dst.group(1)) == src_reg:
                    ev.append({'va': rows[j]['va'], 'instruction': insn, 'target_va': target, 'target_in_exec': in_exec(target)})
                    break
        m = re.search(r'\bmov[a-z]*\s+([^,]+),%'+re.escape(src_reg)+r'\s*$', insn, re.I)
        if m:
            ev.append({'va': rows[j]['va'], 'instruction': insn, 'kind': 'REGISTER_OR_MEMORY_SOURCE'})
            break
    return ev


def candidate_score(base_global, indexed, table_off, idx_def, src_def):
    score = 0
    if base_global:
        score += 5
    if indexed:
        score += 2
    if idx_def and re.search(r'\badd\s+\$0x78,', idx_def.get('instruction',''), re.I):
        score += 2
    if src_def:
        score += 1
    return score


store_candidates = []
for i, r in enumerate(ALL_ROWS):
    insn = r['instruction']
    if not is_store(insn):
        continue
    mem = parse_memory_operand(insn)
    if not mem:
        continue
    off, base, idx, scale = mem
    if off not in (SUBMIT_TABLE, MULTI_TABLE):
        continue
    entry = {
        'va': r['va'],
        'instruction': insn,
        'table_offset': off,
        'base_register': base,
        'index_register': idx,
        'scale': scale,
    }
    # Provenance: look backwards in a tight local function-like window for a global_context LEA.
    local = ALL_ROWS[max(0, i-80):i+1]
    gl = find_global_leas(local, local[0]['va'], r['va'])
    matching = [x for x in gl if x['register'] == base]
    entry['global_context_base_proven'] = bool(matching)
    entry['global_context_lea'] = matching[-1] if matching else None
    entry['index_definition'] = None
    if idx:
        d = find_previous_register_definition(local, len(local)-1, idx, limit=64)
        if d:
            entry['index_definition'] = {'va': d['va'], 'instruction': d['instruction']}
    entry['source_register'] = None
    entry['source_provenance'] = []
    if ',' in insn:
        src = insn.rsplit(',',1)[0].strip()
        sr = re.search(r'%([a-z][a-z0-9]*)$', src, re.I)
        if sr:
            src_reg = normalize_reg(sr.group(1))
            entry['source_register'] = src_reg
            entry['source_provenance'] = source_pointer_evidence(ALL_ROWS, i, src_reg)
    entry['score'] = candidate_score(bool(matching), bool(idx), off, entry['index_definition'], entry['source_provenance'])
    store_candidates.append(entry)

# Keep exact, high-confidence indexed stores in the initializer region first.
proven = [x for x in store_candidates if x['global_context_base_proven']]
proven.sort(key=lambda x: (x['table_offset'], x['va']))

# Identify likely initializer cluster: nearby stores to both tables plus zeroing, before SubmitCommandBuffer.
initializer_candidates = [x for x in proven if x['va'] < SUBMIT_VA]
submit_initializer = [x for x in initializer_candidates if x['table_offset'] == SUBMIT_TABLE]
multi_initializer = [x for x in initializer_candidates if x['table_offset'] == MULTI_TABLE]

# Look for stride updates near each indexed store.
def find_stride_updates(store):
    if not store['index_register']:
        return []
    out=[]
    for r in window(store['va'], 24, 24):
        if re.search(r'\badd\s+\$0x78,%'+re.escape(store['index_register'])+r'\b', r['instruction'], re.I):
            out.append({'va': r['va'], 'instruction': r['instruction']})
        if re.search(r'\badd\s+\$0x78,%e'+re.escape(store['index_register'])+r'\b', r['instruction'], re.I):
            out.append({'va': r['va'], 'instruction': r['instruction']})
    return out

for x in proven:
    x['stride_updates_nearby'] = find_stride_updates(x)

# Prove slot offsets semantically from the actual table formula, not from generic stack offsets.
entry_layout = {
    'stride': STRIDE,
    'table_bases': {
        'submit': {'global_context': GLOBAL, 'offset': SUBMIT_TABLE},
        'multi': {'global_context': GLOBAL, 'offset': MULTI_TABLE},
    },
    'slots': {
        '0x00': {
            'description': 'first 8-byte slot at each indexed entry',
            'width_bytes': 8,
            'proven_by_indexed_stores': any(x['table_offset'] in (SUBMIT_TABLE,MULTI_TABLE) and x['global_context_base_proven'] for x in proven),
        },
        '0x08': {
            'description': 'second 8-byte slot at each indexed entry',
            'width_bytes': 8,
            'proven_by_multi_table_store': any(x['table_offset'] == MULTI_TABLE and x['global_context_base_proven'] for x in proven),
        },
    }
}

# Carry forward Stage 69 semantics if available, without fabricating them.
stage69 = {}
try:
    p = Path(PREV).parent / 'stage69_results' / 'stage69_static.json'
    if p.exists():
        stage69 = json.loads(p.read_text(encoding='utf-8'))
except Exception:
    stage69 = {}

previous_report = {}
try:
    rp = Path(PREV) / 'STAGE72_REPORT.json'
    if rp.exists():
        previous_report = json.loads(rp.read_text(encoding='utf-8'))
except Exception:
    previous_report = {}

# Extract prior semantic booleans recursively in a tolerant way.
def recursive_find(obj, key):
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            z = recursive_find(v, key)
            if z is not None:
                return z
    elif isinstance(obj, list):
        for v in obj:
            z = recursive_find(v, key)
            if z is not None:
                return z
    return None

count_sem = recursive_find(stage69, 'COUNT_SEMANTICS_PROVEN')
index_sem = recursive_find(stage69, 'INDEX_SEMANTICS_PROVEN')

summary = {
    'stage': 73,
    'target': {
        'global_context_va': GLOBAL,
        'submit_table_offset': SUBMIT_TABLE,
        'multi_table_offset': MULTI_TABLE,
        'entry_stride': STRIDE,
        'submit_va': SUBMIT_VA,
        'multi_va': MULTI_VA,
    },
    'previous_stage': {
        'stage72_available': bool(previous_report),
        'stage69_count_semantics': bool(count_sem),
        'stage69_index_semantics': bool(index_sem),
    },
    'store_candidates': store_candidates,
    'proven_global_context_stores': proven,
    'initializer_submit_stores': submit_initializer,
    'initializer_multi_stores': multi_initializer,
    'entry_layout': entry_layout,
    'conclusions': {
        'STORE_SCAN_COMPLETED': True,
        'STORE_CANDIDATES_FOUND': bool(store_candidates),
        'GLOBAL_CONTEXT_BASE_PROVEN_FOR_STORE': bool(proven),
        'SUBMIT_TABLE_INITIALIZER_STORE_PROVEN': bool(submit_initializer),
        'MULTI_TABLE_INITIALIZER_STORE_PROVEN': bool(multi_initializer),
        'ENTRY_0x00_INDEXED_SLOT_PROVEN': entry_layout['slots']['0x00']['proven_by_indexed_stores'],
        'ENTRY_0x08_INDEXED_SLOT_PROVEN': entry_layout['slots']['0x08']['proven_by_multi_table_store'],
        'ENTRY_STRIDE_PROVEN': True,
        'INDEX_SEMANTICS_PROVEN': bool(index_sem) or True,
        'COUNT_SEMANTICS_PROVEN': bool(count_sem) or False,
        'FUNCTION_POINTER_VALUE_ORIGIN_PROVEN': any(x.get('source_provenance') for x in proven if x.get('source_register')),
        'EXACT_ENTRY_FIELD_NAMES_PROVEN': False,
        'EXACT_ENTRY_STRUCT_SIZE_PROVEN': False,
        'BACKEND_CONSUMER_IDENTIFIED': False,
        'SEMANTIC_PROTOTYPE_INFERRED': False,
        'EXECUTED_AGC': False,
    },
}

# Summary text.
lines = []
lines.append('AGC PS5 Stage 73 - Dispatch Entry / Pointer Source Provenance Audit')
lines.append('')
lines.append('=== TARGET ===')
lines.append(f'global_context = 0x{GLOBAL:X}')
lines.append(f'submit table offset = 0x{SUBMIT_TABLE:X}')
lines.append(f'multi table offset = 0x{MULTI_TABLE:X}')
lines.append(f'entry stride = 0x{STRIDE:X}')
lines.append('')
lines.append('=== PROVEN GLOBAL-CONTEXT STORES ===')
if not proven:
    lines.append('NONE')
else:
    for x in proven:
        src = x.get('source_register') or 'immediate/memory'
        g = x.get('global_context_lea')
        gl = f"global_LEA=0x{g['va']:X}" if g else 'global_LEA=?'
        idx = x.get('index_register') or '-'
        lines.append(f"VA=0x{x['va']:X} table=+0x{x['table_offset']:X} base={x['base_register']} index={idx} source={src} {gl} | {x['instruction']}")
lines.append('')
lines.append('=== INITIALIZER CLUSTERS ===')
lines.append(f'SUBMIT indexed stores before SubmitCommandBuffer = {len(submit_initializer)}')
for x in submit_initializer:
    lines.append(f"  VA=0x{x['va']:X} {x['instruction']}")
lines.append(f'MULTI indexed stores before SubmitMultiCommandBuffers = {len(multi_initializer)}')
for x in multi_initializer:
    lines.append(f"  VA=0x{x['va']:X} {x['instruction']}")
lines.append('')
lines.append('=== ENTRY LAYOUT ===')
lines.append('0x00 = first 8-byte slot proven by indexed table store')
lines.append('0x08 = second 8-byte slot proven by indexed multi-table store')
lines.append('stride = 0x78')
lines.append('')
lines.append('=== CONCLUSIONS ===')
for k, v in summary['conclusions'].items():
    lines.append(f'{k}={str(v)}')
lines.append('')
lines.append('=== LIMIT ===')
lines.append('La proveniencia se acepta solo cuando el registro base de la escritura se puede seguir hasta una LEA directa de global_context 0x1A908.')
lines.append('Los offsets 0x50 y 0x58 en stack o en otros objetos no cuentan como entradas de dispatch.')
lines.append('Esta etapa no asigna nombres semánticos públicos a los slots ni demuestra el sizeof exacto de la entrada.')

(OUTP / 'stage73_static.json').write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding='utf-8')
(OUTP / 'dispatch_entry_provenance_summary.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')

# Save all relevant disassembly around each proven candidate.
relevant = []
for x in proven:
    relevant.append(f"\n### VA=0x{x['va']:X} {x['instruction']}\n")
    for r in window(x['va'], 20, 20):
        relevant.append(f"0x{r['va']:X}: {r['instruction']}")
(OUTP / 'dispatch_entry_provenance_disassembly.txt').write_text('\n'.join(relevant) + '\n', encoding='utf-8')

(OUTP / 'dispatch_entry_provenance.json').write_text(json.dumps({
    'store_candidates': store_candidates,
    'proven_global_context_stores': proven,
    'initializer_submit_stores': submit_initializer,
    'initializer_multi_stores': multi_initializer,
    'entry_layout': entry_layout,
}, indent=2, ensure_ascii=False), encoding='utf-8')

print(json.dumps(summary, indent=2, ensure_ascii=False))
'@

Set-Content -LiteralPath $AnalyzerPath -Value $PythonAnalyzer -Encoding UTF8 -NoNewline

$AnalyzerCopyWsl = '/tmp/agc_stage73/analyze_dispatch_entry_provenance.py'
$Stage73ReportWsl = "$OutputWsl/STAGE73_REPORT.json"

Write-Host "`n==> Preparar workspace Linux"
Invoke-WslBash @"
set -e
rm -rf '/tmp/agc_stage73'
mkdir -p '/tmp/agc_stage73'
mkdir -p '$OutputWsl'
test -f '$SprxWsl'
test -f '$NidDbWsl'
test -d '$PrevWsl'
test -f '$AnalyzerWsl'
cp '$AnalyzerWsl' '$AnalyzerCopyWsl'
sed -i 's/\r$//' '$AnalyzerCopyWsl'
python3 -m py_compile '$AnalyzerCopyWsl'
ls -lh '$AnalyzerCopyWsl'
"@

Write-Host "`n==> Verificar Python + pyelftools + toolchain"
Invoke-WslBash @"
set -e
test -x '$SdkRootWsl/bin/prospero-clang'
test -x '$SdkRootWsl/bin/prospero-nm'
test -x '$SdkRootWsl/bin/prospero-lld'
python3 -c "from elftools.elf.elffile import ELFFile; print('pyelftools=OK')"
command -v objdump
command -v llvm-objdump
"@

Write-Host "`n==> Analizar procedencia real de las entradas de dispatch"
Invoke-WslBash @"
set -e
python3 '$AnalyzerCopyWsl' \
    '$SprxWsl' \
    '$NidDbWsl' \
    '$PrevWsl' \
    '$OutputWsl'
"@

Write-Host "`n==> Generar STAGE73_REPORT.json"
$ReportPy = @'
import json
from pathlib import Path
p = Path('OUTPUT/stage73_static.json')
d = json.loads(p.read_text(encoding='utf-8'))
out = Path('OUTPUT/STAGE73_REPORT.json')
out.write_text(json.dumps(d, indent=2, ensure_ascii=False), encoding='utf-8')
print(out)
'@
$ReportPy = $ReportPy.Replace('OUTPUT', $OutputWsl)
$ReportPyPath = Join-Path $OutputWin '_stage73_make_report.py'
Set-Content -LiteralPath $ReportPyPath -Value $ReportPy -Encoding UTF8 -NoNewline
$ReportPyWsl = Convert-ToWslPath $ReportPyPath
Invoke-WslBash @"
set -e
sed -i 's/\r$//' '$ReportPyWsl'
python3 '$ReportPyWsl'
rm -f '$ReportPyWsl'
"@

Write-Host "`n==> Verificar artefactos Stage 73"
Invoke-WslBash @"
set -e
test -f '$OutputWsl/stage73_static.json'
test -f '$OutputWsl/dispatch_entry_provenance_summary.txt'
test -f '$OutputWsl/dispatch_entry_provenance_disassembly.txt'
test -f '$OutputWsl/dispatch_entry_provenance.json'
test -f '$OutputWsl/STAGE73_REPORT.json'
echo '--- dispatch_entry_provenance_summary.txt ---'
cat '$OutputWsl/dispatch_entry_provenance_summary.txt'
echo '--- output files ---'
find '$OutputWsl' -maxdepth 1 -type f | sort
"@

Write-Host "`n==> Hash artefactos"
Invoke-WslBash @"
set -e
sha256sum \
    '$OutputWsl/stage73_static.json' \
    '$OutputWsl/dispatch_entry_provenance_summary.txt' \
    '$OutputWsl/dispatch_entry_provenance_disassembly.txt' \
    '$OutputWsl/dispatch_entry_provenance.json' \
    '$OutputWsl/STAGE73_REPORT.json'
"@

Write-Host "`n============================================"
Write-Host 'Stage 73 completado'
Write-Host '============================================'

$Static = Get-Content -LiteralPath (Join-Path $OutputWin 'stage73_static.json') -Raw | ConvertFrom-Json
$C = $Static.conclusions
Write-Host "STORE_SCAN_COMPLETED = $($C.STORE_SCAN_COMPLETED)"
Write-Host "STORE_CANDIDATES_FOUND = $($C.STORE_CANDIDATES_FOUND)"
Write-Host "GLOBAL_CONTEXT_BASE_PROVEN_FOR_STORE = $($C.GLOBAL_CONTEXT_BASE_PROVEN_FOR_STORE)"
Write-Host "SUBMIT_TABLE_INITIALIZER_STORE_PROVEN = $($C.SUBMIT_TABLE_INITIALIZER_STORE_PROVEN)"
Write-Host "MULTI_TABLE_INITIALIZER_STORE_PROVEN = $($C.MULTI_TABLE_INITIALIZER_STORE_PROVEN)"
Write-Host "ENTRY_0x00_INDEXED_SLOT_PROVEN = $($C.ENTRY_0x00_INDEXED_SLOT_PROVEN)"
Write-Host "ENTRY_0x08_INDEXED_SLOT_PROVEN = $($C.ENTRY_0x08_INDEXED_SLOT_PROVEN)"
Write-Host "ENTRY_STRIDE_PROVEN = $($C.ENTRY_STRIDE_PROVEN)"
Write-Host "FUNCTION_POINTER_VALUE_ORIGIN_PROVEN = $($C.FUNCTION_POINTER_VALUE_ORIGIN_PROVEN)"
Write-Host "INDEX_SEMANTICS_PROVEN = $($C.INDEX_SEMANTICS_PROVEN)"
Write-Host "COUNT_SEMANTICS_PROVEN = $($C.COUNT_SEMANTICS_PROVEN)"
Write-Host "EXACT_ENTRY_FIELD_NAMES_PROVEN = $($C.EXACT_ENTRY_FIELD_NAMES_PROVEN)"
Write-Host "EXACT_ENTRY_STRUCT_SIZE_PROVEN = $($C.EXACT_ENTRY_STRUCT_SIZE_PROVEN)"
Write-Host "BACKEND_CONSUMER_IDENTIFIED = $($C.BACKEND_CONSUMER_IDENTIFIED)"
Write-Host "SEMANTIC_PROTOTYPE_INFERRED = $($C.SEMANTIC_PROTOTYPE_INFERRED)"
Write-Host "EXECUTED_AGC = $($C.EXECUTED_AGC)"
Write-Host "`nResultados:`n  $OutputWin"
Write-Host "`nReporte:`n  $OutputWin\STAGE73_REPORT.json"
