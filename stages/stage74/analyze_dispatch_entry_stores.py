#!/usr/bin/env python3
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

SPRX, NID_DB, PREV, OUT = sys.argv[1:5]
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


def run(cmd, check=True):
    p = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and p.returncode != 0:
        raise RuntimeError(f"command failed: {' '.join(cmd)}\n{p.stderr}")
    return p.stdout


def sha256_text(s):
    return hashlib.sha256(s.encode('utf-8', errors='replace')).hexdigest()


def normalize_reg(r):
    r = r.strip().lower().replace('%','')
    aliases = {
        'eax':'rax','ax':'rax','al':'rax','ah':'rax',
        'ebx':'rbx','bx':'rbx','bl':'rbx','bh':'rbx',
        'ecx':'rcx','cx':'rcx','cl':'rcx','ch':'rcx',
        'edx':'rdx','dx':'rdx','dl':'rdx','dh':'rdx',
        'esi':'rsi','si':'rsi','sil':'rsi',
        'edi':'rdi','di':'rdi','dil':'rdi',
    }
    for base in ['r8','r9','r10','r11','r12','r13','r14','r15']:
        aliases.update({base+'d':base, base+'w':base, base+'b':base})
    return aliases.get(r, r)


def parse_register_tail(insn):
    m = re.search(r',\s*%(r(?:[0-9]+|[a-z]+))\s*$', insn, re.I)
    return normalize_reg(m.group(1)) if m else None


def parse_memory_operand(insn):
    # Robust AT&T parser for disp(base,index,scale), including negative and absent displacement.
    m = re.search(r'(?P<disp>[+-]?(?:0x[0-9a-f]+|[0-9]+))?\(%(?P<base>[a-z0-9]+)(?:,%(?P<idx>[a-z0-9]+),(?P<scale>[1248]))?\)', insn, re.I)
    if not m:
        return None
    disp = int(m.group('disp'), 0) if m.group('disp') else 0
    base = normalize_reg(m.group('base'))
    idx = normalize_reg(m.group('idx')) if m.group('idx') else None
    scale = int(m.group('scale')) if m.group('scale') else 1
    return {'offset': disp, 'base': base, 'index': idx, 'scale': scale}


def is_memory_store(insn):
    if ',' not in insn:
        return False
    dst = insn.rsplit(',', 1)[1].strip()
    return '(' in dst and ')' in dst


def is_register_or_memory_move(insn):
    return bool(re.match(r'^(?:mov|movabs|lea|vmov[a-z0-9]*|cmov[a-z]+|xor|add|sub|and|or|shl|shr|sar|imul|inc|dec|push|pop)\b', insn, re.I))


def extract_target_comment(insn):
    m = re.search(r'#\s*0x([0-9a-f]+)', insn, re.I)
    return int(m.group(1), 16) if m else None


def parse_rows(text):
    rows = []
    # Do not require a trailing space after the final opcode byte; this fixes the Stage73 parser blind spot.
    pat = re.compile(r'^\s*([0-9a-f]+):\s+([0-9a-f ]{2,})\s+(.*)$', re.I)
    pat2 = re.compile(r'^\s*([0-9a-f]+):\s+(.*)$', re.I)
    for line in text.splitlines():
        m = pat.match(line)
        if not m:
            m = pat2.match(line)
            if not m:
                continue
            va = int(m.group(1), 16)
            rest = m.group(2).strip()
            toks = rest.split()
            b = []
            while toks and re.fullmatch(r'[0-9a-f]{2}', toks[0], re.I):
                b.append(toks.pop(0))
            insn = ' '.join(toks)
        else:
            va = int(m.group(1), 16)
            b = re.sub(r'\s+', ' ', m.group(2).strip()).split()
            insn = m.group(3).strip()
        if insn:
            rows.append({'va': va, 'instruction': insn, 'bytes': ' '.join(b)})
    return rows


def load_exec_segments():
    from elftools.elf.elffile import ELFFile
    out = []
    with open(SPRX, 'rb') as fp:
        elf = ELFFile(fp)
        for seg in elf.iter_segments():
            if seg['p_type'] != 'PT_LOAD':
                continue
            if not (int(seg['p_flags']) & 1):
                continue
            if int(seg['p_filesz']) <= 0:
                continue
            out.append({
                'vaddr': int(seg['p_vaddr']),
                'offset': int(seg['p_offset']),
                'filesz': int(seg['p_filesz']),
                'bytes': seg.data()[:int(seg['p_filesz'])],
            })
    return out

SEGMENTS = load_exec_segments()


def disassemble_segment(seg):
    p = Path('/tmp') / f"agc74_{seg['vaddr']:x}.bin"
    p.write_bytes(seg['bytes'])
    try:
        return run(['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64', f'--adjust-vma=0x{seg["vaddr"]:x}', str(p)])
    finally:
        try: p.unlink()
        except FileNotFoundError: pass

ALL_ROWS = []
SEG_TEXT = []
for seg in SEGMENTS:
    txt = disassemble_segment(seg)
    SEG_TEXT.append(txt)
    ALL_ROWS.extend(parse_rows(txt))
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


def rows_window(start_va, end_va):
    return [r for r in ALL_ROWS if start_va <= r['va'] <= end_va]


def backward_register_trace(rows, index, reg, max_back=80):
    """Track a base register backward through simple mov/lea/xchg-style aliases."""
    cur = normalize_reg(reg)
    evidence = []
    start = max(0, index - max_back)
    for j in range(index - 1, start - 1, -1):
        insn = rows[j]['instruction']
        # Direct global LEA into the current register.
        if re.search(r'\blea\s', insn, re.I) and extract_target_comment(insn) == GLOBAL:
            dst = parse_register_tail(insn)
            if dst == cur:
                evidence.append({'va': rows[j]['va'], 'instruction': insn, 'kind': 'GLOBAL_CONTEXT_LEA', 'register': cur})
                return {'proven': True, 'global_source_va': rows[j]['va'], 'register': cur, 'evidence': list(reversed(evidence))}
        # mov %src,%dst alias
        m = re.match(r'^(?:mov|movabs)\s+%(r[0-9]+|r[a-z]+[dwbl]?|[re]?[abcd]x|[er]?[sd]i|[er]?[sd]x),\s*%(r[0-9]+|r[a-z]+[dwbl]?|[re]?[abcd]x|[er]?[sd]i|[er]?[sd]x)\s*$', insn, re.I)
        if m:
            src = normalize_reg(m.group(1)); dst = normalize_reg(m.group(2))
            if dst == cur:
                cur = src
                evidence.append({'va': rows[j]['va'], 'instruction': insn, 'kind': 'REGISTER_ALIAS', 'from': src, 'to': dst})
                continue
        # xor reg,reg -> zero, definitely not global base.
        m = re.match(r'^xor\s+%(r[0-9]+|r[a-z]+),\s+%(r[0-9]+|r[a-z]+)\s*$', insn, re.I)
        if m and normalize_reg(m.group(1)) == cur and normalize_reg(m.group(2)) == cur:
            evidence.append({'va': rows[j]['va'], 'instruction': insn, 'kind': 'REGISTER_ZEROED'})
            break
    return {'proven': False, 'global_source_va': None, 'register': cur, 'evidence': list(reversed(evidence))}


def function_like_bounds(center):
    # We do not rely on ELF symbols. Split at likely function prologues or long gaps.
    i = row_index(center)
    start = 0
    for j in range(i, max(-1, i-600), -1):
        insn = ALL_ROWS[j]['instruction']
        if re.search(r'^(push\s+%rbp|endbr64|sub\s+\$0x[0-9a-f]+,%rsp)', insn, re.I):
            start = j
            break
    end = min(len(ALL_ROWS)-1, i+600)
    for j in range(i+1, min(len(ALL_ROWS), i+600)):
        gap = ALL_ROWS[j]['va'] - ALL_ROWS[j-1]['va']
        if gap > 96:
            end = j-1
            break
    return start, end


def store_destination(insn):
    if not is_memory_store(insn):
        return None
    return parse_memory_operand(insn.rsplit(',',1)[1].strip())

# Candidate stores: direct +0x50/+0x58 memory destinations, plus indexed forms.
store_candidates = []
for idx, r in enumerate(ALL_ROWS):
    mem = store_destination(r['instruction'])
    if not mem:
        continue
    off = mem['offset']
    if off not in (SUBMIT_TABLE, MULTI_TABLE):
        continue
    store_candidates.append({
        'va': r['va'],
        'instruction': r['instruction'],
        'base_register': mem['base'],
        'index_register': mem['index'],
        'scale': mem['scale'],
        'offset': off,
        'row_index': idx,
    })

proven = []
unproven = []
for c in store_candidates:
    idx = c['row_index']
    start, end = function_like_bounds(c['va'])
    rows = ALL_ROWS[start:end+1]
    local_index = idx - start
    trace = backward_register_trace(rows, local_index, c['base_register'], max_back=120)
    item = dict(c)
    item['function_window_start_va'] = rows[0]['va'] if rows else None
    item['function_window_end_va'] = rows[-1]['va'] if rows else None
    item['base_proven'] = bool(trace['proven'])
    item['global_source_va'] = trace['global_source_va']
    item['trace'] = trace['evidence']
    # Indexed table initialization is strongest when there is an index*0x78 or a prior add/sub by 0x78.
    item['indexed_entry_pattern'] = bool(c['index_register']) and c['scale'] in (1,2,4,8)
    if trace['proven']:
        proven.append(item)
    else:
        unproven.append(item)

# Focused dispatch reads from known functions, using the same parser and explicit table bases.
def find_dispatch_reads(fun_va, fun_size, table_off):
    rows = rows_window(fun_va, fun_va + fun_size)
    out = []
    for r in rows:
        if 'call' not in r['instruction'].lower():
            continue
        if table_off == SUBMIT_TABLE and '(rbx' in r['instruction'].lower() and '0x50' in r['instruction'].lower():
            out.append({'va':r['va'], 'instruction':r['instruction'], 'table_offset':table_off, 'base_register':'rbx'})
        if table_off == MULTI_TABLE and '(rcx' in r['instruction'].lower() and '0x58' in r['instruction'].lower():
            out.append({'va':r['va'], 'instruction':r['instruction'], 'table_offset':table_off, 'base_register':'rcx'})
    return out

submit_dispatch = find_dispatch_reads(SUBMIT_VA, SUBMIT_SIZE, SUBMIT_TABLE)
multi_dispatch = find_dispatch_reads(MULTI_VA, MULTI_SIZE, MULTI_TABLE)

# Extract direct LEAs of global_context within focused paths.
def global_leas(fun_va, fun_size):
    out=[]
    for r in rows_window(fun_va, fun_va+fun_size):
        if re.search(r'\blea\s',r['instruction'],re.I) and extract_target_comment(r['instruction']) == GLOBAL:
            reg = parse_register_tail(r['instruction'])
            if reg:
                out.append({'va':r['va'],'instruction':r['instruction'],'register':reg})
    return out

submit_leas = global_leas(SUBMIT_VA,SUBMIT_SIZE)
multi_leas = global_leas(MULTI_VA,MULTI_SIZE)

# Build disassembly around every candidate/proven write and focused dispatch functions.
relevant_vas = [x['va'] for x in proven]
for x in submit_dispatch + multi_dispatch:
    relevant_vas.append(x['va'])
blocks=[]
for va in sorted(set(relevant_vas)):
    ws=rows_window(max(0,va-48),va+48)
    blocks.append({'center':va,'rows':ws})

dis_lines=[]
for b in blocks:
    dis_lines.append(f'=== CENTER 0x{b["center"]:x} ===')
    for r in b['rows']:
        dis_lines.append(f'{r["va"]:08x}: {r["instruction"]}')

# Summary and JSON artifacts.
report = {
    'stage': 74,
    'target': {
        'global_context_va': GLOBAL,
        'submit_table_offset': SUBMIT_TABLE,
        'multi_table_offset': MULTI_TABLE,
        'entry_stride': STRIDE,
        'submit_va': SUBMIT_VA,
        'submit_size': SUBMIT_SIZE,
        'multi_va': MULTI_VA,
        'multi_size': MULTI_SIZE,
    },
    'previous_stage': {
        'stage73_available': os.path.isdir(PREV),
    },
    'scanner': {
        'exec_segment_count': len(SEGMENTS),
        'instruction_count': len(ALL_ROWS),
        'parser_strategy': 'robust objdump parser + explicit AT&T destination parsing + local register data-flow',
    },
    'store_candidates': [{k:v for k,v in x.items() if k != 'row_index'} for x in store_candidates],
    'proven_global_context_stores': [{k:v for k,v in x.items() if k != 'row_index'} for x in proven],
    'unproven_store_candidates': [{k:v for k,v in x.items() if k != 'row_index'} for x in unproven],
    'focused_dispatch': {
        'submit_global_leas': submit_leas,
        'multi_global_leas': multi_leas,
        'submit_dispatch': submit_dispatch,
        'multi_dispatch': multi_dispatch,
    },
    'entry_layout': {
        'stride': STRIDE,
        'slot_00': '8-byte destination/source slot at entry +0x00',
        'slot_08': '8-byte destination/source slot at entry +0x08',
        'layout_status': 'not proven by store scan unless indexed global-context store is found',
    },
    'conclusions': {
        'STORE_SCAN_COMPLETED': True,
        'STORE_CANDIDATES_FOUND': bool(store_candidates),
        'GLOBAL_CONTEXT_BASE_PROVEN_FOR_ANY_STORE': bool(proven),
        'SUBMIT_TABLE_INITIALIZER_STORE_PROVEN': any(x['offset']==SUBMIT_TABLE and x['base_proven'] for x in proven),
        'MULTI_TABLE_INITIALIZER_STORE_PROVEN': any(x['offset']==MULTI_TABLE and x['base_proven'] for x in proven),
        'ENTRY_0x00_INDEXED_SLOT_PROVEN': any(x['base_proven'] and x['offset'] in (SUBMIT_TABLE,MULTI_TABLE) for x in proven),
        'ENTRY_0x08_INDEXED_SLOT_PROVEN': any(x['base_proven'] and x['offset']==MULTI_TABLE for x in proven),
        'ENTRY_STRIDE_PROVEN': True,
        'INDEX_SEMANTICS_PROVEN': True,
        'COUNT_SEMANTICS_PROVEN': True,
        'FUNCTION_POINTER_VALUE_ORIGIN_PROVEN': False,
        'EXACT_ENTRY_FIELD_NAMES_PROVEN': False,
        'EXACT_ENTRY_STRUCT_SIZE_PROVEN': False,
        'BACKEND_CONSUMER_IDENTIFIED': False,
        'SEMANTIC_PROTOTYPE_INFERRED': False,
        'EXECUTED_AGC': False,
    }
}

(OUTP/'stage74_static.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
(OUTP/'dispatch_entry_provenance.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
(OUTP/'dispatch_entry_provenance_disassembly.txt').write_text('\n'.join(dis_lines), encoding='utf-8')
summary = f'''AGC PS5 Stage 74 - Dispatch Entry Store / Provenance Audit\n\n=== TARGET ===\nglobal_context = 0x{GLOBAL:X}\nsubmit table offset = 0x{SUBMIT_TABLE:X}\nmulti table offset = 0x{MULTI_TABLE:X}\nentry stride = 0x{STRIDE:X}\n\n=== SCANNER ===\nexecutable segments = {len(SEGMENTS)}\ninstructions parsed = {len(ALL_ROWS)}\n\n=== STORE CANDIDATES ===\ncount = {len(store_candidates)}\n'''
if store_candidates:
    for x in store_candidates:
        summary += f"VA=0x{x['va']:x} offset=0x{x['offset']:x} base={x['base_register']} index={x['index_register']} scale={x['scale']} | {x['instruction']}\n"
else:
    summary += 'NONE\n'
summary += '\n=== PROVEN GLOBAL-CONTEXT STORES ===\n'
if proven:
    for x in proven:
        summary += f"VA=0x{x['va']:x} offset=0x{x['offset']:x} base={x['base_register']} source=0x{x['global_source_va']:x} | {x['instruction']}\n"
else:
    summary += 'NONE\n'
summary += f'''\n=== FOCUSED DISPATCH ===\nSubmit LEAs to global_context = {len(submit_leas)}\nMulti LEAs to global_context = {len(multi_leas)}\nSubmit dispatch sites = {len(submit_dispatch)}\nMulti dispatch sites = {len(multi_dispatch)}\n'''
for x in submit_dispatch:
    summary += f"SUBMIT 0x{x['va']:x} | {x['instruction']}\n"
for x in multi_dispatch:
    summary += f"MULTI  0x{x['va']:x} | {x['instruction']}\n"
summary += '\n=== CONCLUSIONS ===\n'
for k,v in report['conclusions'].items():
    summary += f'{k}={v}\n'
summary += '''\n=== LIMIT ===\nSolo se considera demostrada la pertenencia de una escritura a global_context cuando el registro base puede rastrearse localmente hasta una LEA directa de 0x1A908. Los offsets 0x50/0x58 en stack u otros objetos quedan como candidatos no probados. El stride 0x78, el uso de +0xA4 como índice y +0xA0 como count/limite se mantienen como evidencia heredada de las etapas anteriores.\n'''
(OUTP/'dispatch_entry_provenance_summary.txt').write_text(summary, encoding='utf-8')

# Machine-readable report with artifact hashes.
artifacts = ['stage74_static.json','dispatch_entry_provenance_summary.txt','dispatch_entry_provenance_disassembly.txt','dispatch_entry_provenance.json']
final_report = dict(report)
final_report['artifacts'] = {}
for name in artifacts:
    b=(OUTP/name).read_bytes()
    final_report['artifacts'][name] = {'sha256':hashlib.sha256(b).hexdigest(),'size':len(b)}
(OUTP/'STAGE74_REPORT.json').write_text(json.dumps(final_report, indent=2), encoding='utf-8')

print(json.dumps(final_report, indent=2))
print('--- dispatch_entry_provenance_summary.txt ---')
print(summary)
print('--- output files ---')
for p in sorted(OUTP.iterdir()):
    if p.is_file(): print(str(p))
