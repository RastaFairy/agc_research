#!/usr/bin/env python3
import json
import hashlib
import re
import subprocess
import sys
from pathlib import Path

EXPECTED_PROJECT = [
    'agcProjectSubmitCommandBufferV1',
    'agcProjectSubmitAcbV1',
    'agcProjectAgrSubmitDcbV1',
    'agcProjectSubmitMultiDcbsV1',
    'agcProjectSubmitMultiCommandBuffersV1',
    'agcProjectSubmitMultiAcbsV1',
    'agcProjectAgrSubmitMultiDcbsV1',
    'agcProjectSubmitDcbV1',
]
EXPECTED_DRIVER = [
    'sceAgcDriverSubmitMultiCommandBuffers',
    'sceAgcDriverSubmitCommandBuffer',
    'sceAgcDriverSubmitAcb',
    'sceAgcDriverAgrSubmitMultiDcbs',
    'sceAgcDriverAgrSubmitDcb',
    'sceAgcDriverSubmitMultiDcbs',
    'sceAgcDriverSubmitDcb',
    'sceAgcDriverSubmitMultiAcbs',
]

def fail(msg):
    print('[FAIL] ' + msg)
    raise SystemExit(1)

def run(cmd, out=None):
    p = subprocess.run(cmd, text=True, capture_output=True)
    if p.returncode != 0:
        print(p.stdout)
        print(p.stderr, file=sys.stderr)
        fail(f'Command failed: {cmd}')
    if out is not None:
        Path(out).write_text(p.stdout, encoding='utf-8')
    return p.stdout

def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1024*1024), b''):
            h.update(b)
    return h.hexdigest()

def nm_defined(archive, nm):
    txt = run([nm, '-C', str(archive)])
    return set(re.findall(r'^\S+\s+[A-Za-z]\s+(\S+)\s*$', txt, re.M))

def main():
    if len(sys.argv) != 8:
        fail('uso: stage84_install_layout.py <stage79> <stage80> <stage81> <output> <clang> <nm> <lld>')
    stage79, stage80, stage81, out = map(Path, sys.argv[1:5])
    clang, nm, lld = sys.argv[5:8]
    out = out.resolve()
    pkg = out / 'package'
    inc = pkg / 'include'
    lib = pkg / 'lib'
    src = pkg / 'src'
    meta = pkg / 'meta'
    for d in (inc, lib, src, meta):
        d.mkdir(parents=True, exist_ok=True)

    required = [
        stage79/'agc_abi_v1.h', stage79/'agc_abi_v1.c', stage79/'libSceAgcDriver_abi_v1.a',
        stage79/'ABI_V1_CONTRACT.txt', stage79/'STAGE79_REPORT.json',
        stage80/'agc_project_v1.h', stage80/'agc_project_v1.c', stage80/'libagc_project_v1.a',
        stage80/'AGC_PROJECT_V1_CONTRACT.txt', stage80/'STAGE80_REPORT.json',
        stage81/'STAGE81_REPORT.json', stage81/'END_TO_END_LINK_CONTRACT.txt', stage81/'stage81_linked.o'
    ]
    for p in required:
        if not p.is_file(): fail(f'artefacto requerido ausente: {p}')

    copies = [
        (stage79/'agc_abi_v1.h', inc/'agc_abi_v1.h'),
        (stage80/'agc_project_v1.h', inc/'agc_project_v1.h'),
        (stage79/'libSceAgcDriver_abi_v1.a', lib/'libSceAgcDriver_abi_v1.a'),
        (stage80/'libagc_project_v1.a', lib/'libagc_project_v1.a'),
        (stage79/'agc_abi_v1.c', src/'agc_abi_v1.c'),
        (stage80/'agc_project_v1.c', src/'agc_project_v1.c'),
        (stage79/'ABI_V1_CONTRACT.txt', meta/'ABI_V1_CONTRACT.txt'),
        (stage80/'AGC_PROJECT_V1_CONTRACT.txt', meta/'AGC_PROJECT_V1_CONTRACT.txt'),
        (stage79/'STAGE79_REPORT.json', meta/'STAGE79_REPORT.json'),
        (stage80/'STAGE80_REPORT.json', meta/'STAGE80_REPORT.json'),
        (stage81/'STAGE81_REPORT.json', meta/'STAGE81_REPORT.json'),
        (stage81/'END_TO_END_LINK_CONTRACT.txt', meta/'END_TO_END_LINK_CONTRACT.txt'),
    ]
    import shutil
    for s, d in copies:
        shutil.copyfile(s, d)
        print(f'[OK] {s.name} -> {d.relative_to(pkg)}')

    project_syms = nm_defined(lib/'libagc_project_v1.a', nm)
    driver_syms = nm_defined(lib/'libSceAgcDriver_abi_v1.a', nm)
    project_ok = sorted(set(EXPECTED_PROJECT) <= project_syms)
    driver_ok = sorted(set(EXPECTED_DRIVER) <= driver_syms)
    if not project_ok: fail('faltan símbolos agcProject en la librería de proyecto')
    if not driver_ok: fail('faltan símbolos sceAgcDriver en la librería ABI')
    print('[OK] 8 símbolos agcProject presentes en libagc_project_v1.a')
    print('[OK] 8 símbolos sceAgcDriver presentes en libSceAgcDriver_abi_v1.a')

    smoke = out/'stage84_smoke.c'
    smoke.write_text('''#include "agc_project_v1.h"\n#include "agc_abi_v1.h"\nint stage84_smoke(void) {\n    AgcSubmitCommandBufferArgsV1 a = {0, 0, 0};\n    return agcProjectSubmitCommandBufferV1((void*)0, &a);\n}\n''', encoding='utf-8')
    smoke_o = out/'stage84_smoke.o'
    smoke_linked = out/'stage84_smoke_linked.o'
    run([clang, '-target', 'x86_64-sie-ps5', '-ffreestanding', '-fno-builtin', '-I', str(inc), '-c', str(smoke), '-o', str(smoke_o)])
    run([lld, '-r', str(smoke_o), str(lib/'libagc_project_v1.a'), str(lib/'libSceAgcDriver_abi_v1.a'), '-o', str(smoke_linked)])
    run([nm, '-u', str(smoke_linked)], out=out/'stage84_smoke_undefined.txt')
    undef = (out/'stage84_smoke_undefined.txt').read_text(encoding='utf-8', errors='replace')
    bad = [x for x in undef.splitlines() if 'agcProject' in x or 'sceAgcDriver' in x]
    if bad: fail('quedan referencias AGC undefined en smoke-link')
    print('[OK] smoke compile + relocatable link')
    print('[OK] 0 referencias AGC/proyecto sin resolver')

    sums = []
    for p in sorted(pkg.rglob('*')):
        if p.is_file():
            sums.append(f'{sha256(p)}  {p.relative_to(pkg).as_posix()}')
    (out/'SHA256SUMS.txt').write_text('\n'.join(sums) + '\n', encoding='utf-8')
    smoke_compile = smoke_o.is_file() and smoke_o.stat().st_size > 0
    smoke_link = smoke_linked.is_file() and smoke_linked.stat().st_size > 0
    smoke_clean = len(bad) == 0
    package_ok = all((pkg / rel).is_file() for rel in [
        'include/agc_abi_v1.h', 'include/agc_project_v1.h',
        'lib/libSceAgcDriver_abi_v1.a', 'lib/libagc_project_v1.a',
        'src/agc_abi_v1.c', 'src/agc_project_v1.c'
    ])
    report = {
        'stage': 84,
        'previous_stage': 83,
        'layout': {'include': True, 'lib': True, 'src': True, 'meta': True},
        'inputs': {'stage79': str(stage79), 'stage80': str(stage80), 'stage81': str(stage81)},
        'outputs': {
            'package': str(pkg), 'smoke_object': str(smoke_o),
            'smoke_linked': str(smoke_linked), 'sha256': str(out/'SHA256SUMS.txt')
        },
        'proof': {
            'PROJECT_SYMBOL_SET_PRESENT': project_ok,
            'DRIVER_SYMBOL_SET_PRESENT': driver_ok,
            'SMOKE_COMPILE': smoke_compile,
            'SMOKE_RELOCATABLE_LINK': smoke_link,
            'AGC_UNDEFINED_REFERENCES': len(bad),
        },
        'conclusions': {
            'INSTALLABLE_LAYOUT_BUILT': package_ok and project_ok and driver_ok and smoke_compile and smoke_link and smoke_clean,
            'PROJECT_AND_ABI_ARCHIVES_PACKAGED': package_ok and project_ok and driver_ok,
            'SMOKE_LINK_CLEAN': smoke_compile and smoke_link and smoke_clean,
            'PUBLIC_SEMANTIC_FIELD_NAMES_FINAL': False,
            'REAL_AGC_EXECUTION': False,
        }
    }
    (out/'STAGE84_REPORT.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    contract = '''AGC PS5 Stage 84 - INSTALLABLE BUILD LAYOUT\n\nLAYOUT\n=======\ninclude/agc_abi_v1.h\ninclude/agc_project_v1.h\nlib/libSceAgcDriver_abi_v1.a\nlib/libagc_project_v1.a\nsrc/agc_abi_v1.c\nsrc/agc_project_v1.c\nmeta/ -> contracts and stage reports\n\nVERIFICADO\n===========\n- Las dos bibliotecas proceden directamente de Stage 79 y Stage 80.\n- Se conserva la ABI recuperada sin renombrar field_00/field_08/field_0c.\n- Los 8 símbolos agcProjectV1 están presentes.\n- Los 8 símbolos sceAgcDriver recuperados están presentes.\n- Un cliente de prueba compila contra include/ y enlaza como relocatable.\n- El smoke-link no deja referencias AGC/proyecto sin resolver.\n\nNO DEMUESTRA\n============\n- ejecución real en PS5\n- runtime GPU\n- nombres semánticos públicos definitivos para field_0c\n- validez de la librería como implementación real del driver Sony\n'''
    (out/'STAGE84_INSTALL_CONTRACT.txt').write_text(contract, encoding='utf-8')
    print('[OK] STAGE84_REPORT.json')
    print('[OK] STAGE84_INSTALL_CONTRACT.txt')
    print('[OK] SHA256SUMS.txt')

if __name__ == '__main__':
    main()
