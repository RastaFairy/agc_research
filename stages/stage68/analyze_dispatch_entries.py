#!/usr/bin/env python3
import json, os, re, subprocess, sys
from pathlib import Path

SPRX, NID_DB, PREVIOUS, OUTPUT = sys.argv[1:5]

GLOBAL_CONTEXT = 0x1A908
SUBMIT_TABLE = 0x50
MULTI_TABLE = 0x58
SUBMIT_VA, SUBMIT_SIZE = 6320, 380
MULTI_VA, MULTI_SIZE = 18000, 579

def run(*cmd):
    return subprocess.check_output(list(cmd), text=True, stderr=subprocess.STDOUT)

def disasm():
    for cmd in (
        ('llvm-objdump','-d','--no-show-raw-insn',SPRX),
        ('objdump','-D','-b','elf64-x86-64','-m','i386:x86-64',SPRX),
    ):
        try:
            return run(*cmd)
        except Exception:
            pass
    raise RuntimeError("Unable to disassemble SPRX.")

DIS = disasm()
LINES = DIS.splitlines()

def va_of(line):
    m = re.match(r'\s*([0-9a-fA-F]+):', line)
    return int(m.group(1),16) if m else None

def norm(line):
    return re.sub(r'\s+', ' ', line.strip())

def window(start, size):
    return [x for x in LINES if (va_of(x) is not None and start <= va_of(x) < start+size)]

def trace_block(block):
    alias = {}
    events = []
    for raw in block:
        va = va_of(raw)
        if va is None:
            continue
        s = norm(raw)

        m = re.search(r'\blea\s+.*,\s*%([a-z0-9]+)\s*#\s*0x1a908\b', s, re.I)
        if m:
            r = m.group(1).lower()
            alias[r] = GLOBAL_CONTEXT
            events.append({
                'va': va, 'instruction': s,
                'kind': 'GLOBAL_CONTEXT_LEA',
                'register': r,
            })
            continue

        m = re.search(r'\bmov\s+%([a-z0-9]+),%([a-z0-9]+)$', s, re.I)
        if m:
            src, dst = m.group(1).lower(), m.group(2).lower()
            if src in alias:
                alias[dst] = alias[src]
                events.append({
                    'va': va, 'instruction': s,
                    'kind': 'REGISTER_ALIAS',
                    'source': src, 'destination': dst,
                    'value': alias[src],
                })
            continue

        m = re.search(
            r',0x(50|58)\(%([a-z0-9]+)(?:,%([a-z0-9]+),([1248]))?\)',
            s, re.I
        )
        if m:
            off = int(m.group(1),16)
            base = m.group(2).lower()
            idx  = m.group(3).lower() if m.group(3) else None
            scale = int(m.group(4)) if m.group(4) else 1
            events.append({
                'va': va,
                'instruction': s,
                'kind': 'TABLE_STORE',
                'table_offset': off,
                'base_register': base,
                'index_register': idx,
                'scale': scale,
                'base_proven': alias.get(base) == GLOBAL_CONTEXT,
                'global_source_va': GLOBAL_CONTEXT if alias.get(base) == GLOBAL_CONTEXT else None,
            })
    return events

init_block = [x for x in LINES if (va_of(x) is not None and 0xC0 <= va_of(x) < 0x180)]
init_events = trace_block(init_block)
proven_stores = [
    x for x in init_events
    if x.get('kind') == 'TABLE_STORE' and x.get('base_proven')
]

def dispatches(start, size):
    out=[]
    for raw in window(start,size):
        va = va_of(raw)
        s = norm(raw)
        if va is None:
            continue
        m = re.search(
            r'call\s+\*0x(50|58)\(%([a-z0-9]+),%([a-z0-9]+),([1248])\)',
            s, re.I
        )
        if m:
            out.append({
                'va': va,
                'instruction': s,
                'table_offset': int(m.group(1),16),
                'base_register': m.group(2).lower(),
                'index_register': m.group(3).lower(),
                'scale': int(m.group(4)),
            })
    return out

submit_dispatch = dispatches(SUBMIT_VA,SUBMIT_SIZE)
multi_dispatch  = dispatches(MULTI_VA,MULTI_SIZE)

multi_count_evidence=[]
for raw in window(MULTI_VA,MULTI_SIZE):
    va=va_of(raw)
    if va is None: continue
    s=norm(raw)
    if re.search(r'\b(test|cmp|sub|add|inc|dec|cmov[a-z]*|j[a-z]+)\b.*(%r12d|%r12)\b', s, re.I):
        multi_count_evidence.append({'va':va,'instruction':s})
    if re.search(r'\bmov\s+%[er]?(?:dx|cx|8d),%r12d\b', s, re.I):
        multi_count_evidence.append({'va':va,'instruction':s})

result = {
    'stage':68,
    'target':{
        'global_context_va':GLOBAL_CONTEXT,
        'submit_table_offset':SUBMIT_TABLE,
        'multi_table_offset':MULTI_TABLE,
        'submit_va':SUBMIT_VA,
        'submit_size':SUBMIT_SIZE,
        'multi_va':MULTI_VA,
        'multi_size':MULTI_SIZE,
    },
    'stage67_available': os.path.isdir(PREVIOUS),
    'initializer':{
        'window':'0xC0..0x180',
        'events':init_events,
        'proven_global_context_stores':proven_stores,
    },
    'submit_dispatch':submit_dispatch,
    'multi_dispatch':multi_dispatch,
    'multi_count_evidence':multi_count_evidence,
    'conclusions':{
        'STORE_SCAN_COMPLETED':True,
        'STORE_CANDIDATES_FOUND':bool(proven_stores),
        'SUBMIT_TABLE_RUNTIME_INITIALIZATION_PROVEN':any(x['table_offset']==SUBMIT_TABLE for x in proven_stores),
        'MULTI_TABLE_RUNTIME_INITIALIZATION_PROVEN':any(x['table_offset']==MULTI_TABLE for x in proven_stores),
        'SUBMIT_DISPATCH_PATTERN_FOUND':bool(submit_dispatch),
        'MULTI_DISPATCH_PATTERN_FOUND':bool(multi_dispatch),
        'COUNT_LIKE_CONTROL_FLOW_OBSERVED':bool(multi_count_evidence),
        'COUNT_SEMANTICS_PROVEN':False,
        'EXACT_FIELD_NAME_PROVEN':False,
        'BACKEND_CONSUMER_IDENTIFIED':False,
        'SEMANTIC_PROTOTYPE_INFERRED':False,
        'EXECUTED_AGC':False,
    },
    'notes':[
        'Table writes are treated as proven only when base-register flow reaches LEA global_context 0x1A908.',
        'Dispatch index use is established independently by the existing Submit/Multi call sites.',
        'Count-like control flow is reported as evidence only; it is not promoted to a public semantic name.',
        'Exact dispatch-entry size/semantic names remain unproven unless directly established by machine-code data-flow.',
    ],
}

Path(OUTPUT,'stage68_static.json').write_text(json.dumps(result,indent=2),encoding='utf-8')

summary=[
'AGC PS5 Stage 68 - Dispatch Entry / Count Semantics Audit',
'',
'=== TARGET ===',
f'global_context = 0x{GLOBAL_CONTEXT:X}',
'submit table offset = 0x50',
'multi table offset = 0x58',
'',
'=== PROVEN GLOBAL-CONTEXT TABLE STORES ===',
]
if proven_stores:
    for x in proven_stores:
        summary.append(
            f"VA=0x{x['va']:X} offset=0x{x['table_offset']:X} "
            f"base={x['base_register']} source=global_context | {x['instruction']}"
        )
else:
    summary.append('NONE')
summary += ['', '=== SUBMIT DISPATCH ===']
if submit_dispatch:
    for x in submit_dispatch:
        summary.append(
            f"VA=0x{x['va']:X} offset=0x{x['table_offset']:X} "
            f"base={x['base_register']} index={x['index_register']} "
            f"scale={x['scale']} | {x['instruction']}"
        )
else:
    summary.append('NONE')
summary += ['', '=== MULTI DISPATCH ===']
if multi_dispatch:
    for x in multi_dispatch:
        summary.append(
            f"VA=0x{x['va']:X} offset=0x{x['table_offset']:X} "
            f"base={x['base_register']} index={x['index_register']} "
            f"scale={x['scale']} | {x['instruction']}"
        )
else:
    summary.append('NONE')
summary += ['', '=== COUNT-LIKE CONTROL FLOW ===']
if multi_count_evidence:
    summary += [f"VA=0x{x['va']:X} | {x['instruction']}" for x in multi_count_evidence]
else:
    summary.append('NONE')
summary += ['', '=== CONCLUSIONS ===']
summary += [f'{k}={v}' for k,v in result['conclusions'].items()]
summary += [
    '',
    '=== LIMIT ===',
    'This stage correlates runtime table initialization with the known dispatch sites.',
    'It does not prove public semantic field names or exact API documentation.'
]
Path(OUTPUT,'dispatch_entry_summary.txt').write_text('\n'.join(summary)+'\n',encoding='utf-8')

Path(OUTPUT,'dispatch_entry_disassembly.txt').write_text(
    '=== INITIALIZER 0xC0..0x180 ===\n' + '\n'.join(init_block) +
    '\n\n=== SUBMIT ===\n' + '\n'.join(window(SUBMIT_VA,SUBMIT_SIZE)) +
    '\n\n=== MULTI ===\n' + '\n'.join(window(MULTI_VA,MULTI_SIZE)) + '\n',
    encoding='utf-8'
)

print(json.dumps(result,indent=2))
