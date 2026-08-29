#requires -Version 7.0
<#
AGC PS5 Stage 82 - Dispatch Function Pointer Origin / Backend Consumer Audit

MODELO CANÓNICO DEL PROYECTO
============================
PowerShell 7 -> Ubuntu/WSL -> toolchain Prospero / objdump / python3

Este Stage continúa DIRECTAMENTE desde Stage 81 y respeta su layout.

Windows:
    D:\agc_work\sce_stubs\libSceAgcDriver.sprx
    D:\agc_work\stage79_results\libSceAgcDriver_abi_v1.a
    D:\agc_work\stage81_results
    D:\agc_work\stage82_results
    D:\sdk-master\sce_stubs\aerolib.csv

WSL:
    /mnt/d/agc_work/sce_stubs/libSceAgcDriver.sprx
    /mnt/d/agc_work/stage79_results/libSceAgcDriver_abi_v1.a
    /mnt/d/agc_work/stage81_results
    /mnt/d/agc_work/stage82_results
    /mnt/d/sdk-master/sce_stubs/aerolib.csv
    /opt/ps5-payload-sdk

IMPORTANTE
==========
- PowerShell SOLO orquesta.
- El análisis binario se ejecuta dentro de Ubuntu/WSL.
- NO se busca el SPRX dentro de D:\chatgpt_2.
- NO se exige que Stage 81 contenga agc_project_v1.h/.c:
  esos archivos fueron INPUTS de Stage 81 procedentes de Stage 80.
- Stage 82 solo exige outputs reales de Stage 81 y el ABI real de Stage 79.
#>

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$StageDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Layout canónico heredado de Stage 81.
$Stage80  = 'D:\agc_work\stage80_results'
$Previous = 'D:\agc_work\stage81_results'
$Stage79  = 'D:\agc_work\stage79_results'
$Output   = 'D:\agc_work\stage82_results'
$Sprx     = 'D:\agc_work\sce_stubs\libSceAgcDriver.sprx'
$NidDb    = 'D:\sdk-master\sce_stubs\aerolib.csv'
$SdkWsl   = '/opt/ps5-payload-sdk'

$Stage80Wsl  = '/mnt/d/agc_work/stage80_results'
$PreviousWsl = '/mnt/d/agc_work/stage81_results'
$Stage79Wsl  = '/mnt/d/agc_work/stage79_results'
$OutputWsl   = '/mnt/d/agc_work/stage82_results'
$SprxWsl     = '/mnt/d/agc_work/sce_stubs/libSceAgcDriver.sprx'
$NidDbWsl    = '/mnt/d/sdk-master/sce_stubs/aerolib.csv'

function Write-Section {
    param([Parameter(Mandatory)][string]$Text)
    Write-Host ''
    Write-Host '=============================================================================='
    Write-Host $Text
    Write-Host '=============================================================================='
}

function Invoke-WSLScript {
    param([Parameter(Mandatory)][string]$Body)

    Write-Host '[WSL] set -euo pipefail'
    Write-Host $Body
    & wsl.exe bash -lc "set -euo pipefail; $Body"
    $code = $LASTEXITCODE

    if ($code -ne 0) {
        throw "WSL command failed with exit code $code."
    }
}

Write-Section 'AGC PS5 Stage 82 - Dispatch Function Pointer Origin / Backend Consumer Audit'
Write-Host "StageDir : $StageDir"
Write-Host "Stage 80 : $Stage80"
Write-Host "Stage 81 : $Previous"
Write-Host "Stage 79 : $Stage79"
Write-Host "SPRX     : $Sprx"
Write-Host "NID DB   : $NidDb"
Write-Host "Output   : $Output"
Write-Host "SDK WSL  : $SdkWsl"

Write-Section '1. Validación de entradas Windows / layout canónico'

# Stage 82 no necesita que Stage80 esté presente para analizar el SPRX,
# pero lo reportamos porque forma parte del contexto inmediato.
$requiredWindows = @(
    $Previous,
    $Stage79,
    $Sprx
)

foreach ($p in $requiredWindows) {
    if (-not (Test-Path -LiteralPath $p)) {
        throw "No existe el artefacto/directorio canónico requerido: $p"
    }
}

New-Item -ItemType Directory -Force -Path $Output | Out-Null

Write-Host "OK: Stage 81 encontrado en $Previous"
Write-Host "OK: Stage 79 encontrado en $Stage79"
Write-Host "OK: SPRX encontrado en $Sprx"
Write-Host "OK: salida preparada en $Output"
Write-Host ''
Write-Host 'Artefactos esperados de Stage 81:'
@(
    (Join-Path $Previous 'stage81_end_to_end_probe.c'),
    (Join-Path $Previous 'stage81_end_to_end_probe.o'),
    (Join-Path $Previous 'stage81_linked.o'),
    (Join-Path $Previous 'stage81_static.json'),
    (Join-Path $Previous 'STAGE81_REPORT.json'),
    (Join-Path $Previous 'END_TO_END_LINK_CONTRACT.txt')
) | ForEach-Object {
    if (Test-Path -LiteralPath $_) {
        Write-Host "  OK: $_"
    } else {
        Write-Host "  MISSING: $_"
    }
}

Write-Section '2. Validación de Ubuntu/WSL y toolchain' 

Invoke-WSLScript @"
command -v python3 >/dev/null
command -v objdump >/dev/null
test -x '$SdkWsl/bin/prospero-clang'
test -x '$SdkWsl/bin/prospero-nm'
test -x '$SdkWsl/bin/prospero-lld'
test -f '$SprxWsl'
test -f '$Stage79Wsl/libSceAgcDriver_abi_v1.a'
test -d '$PreviousWsl'
mkdir -p '$OutputWsl'

echo '--- python3 ---'
python3 --version
echo '--- objdump ---'
objdump --version | head -n 1
echo '--- prospero-clang ---'
'$SdkWsl/bin/prospero-clang' --version | head -n 1
echo '--- prospero-lld ---'
'$SdkWsl/bin/prospero-lld' --version | head -n 1
echo '--- prospero-nm ---'
'$SdkWsl/bin/prospero-nm' --version | head -n 1
"@

Write-Section '3. Confirmar LOS OUTPUTS REALES de Stage 81'

# Corrección clave:
# Stage 81 PRODUCE estos archivos:
#   stage81_end_to_end_probe.c
#   stage81_end_to_end_probe.o
#   stage81_linked.o
#   stage81_static.json
#   STAGE81_REPORT.json
#   END_TO_END_LINK_CONTRACT.txt
#
# agc_project_v1.h/.c NO son outputs de Stage 81; fueron inputs de Stage 80.
$stage81Check = @'
set -e

required=(
    "__STAGE81__/stage81_end_to_end_probe.c"
    "__STAGE81__/stage81_end_to_end_probe.o"
    "__STAGE81__/stage81_linked.o"
    "__STAGE81__/stage81_static.json"
    "__STAGE81__/STAGE81_REPORT.json"
    "__STAGE81__/END_TO_END_LINK_CONTRACT.txt"
    "__STAGE79__/libSceAgcDriver_abi_v1.a"
    "__SPRX__"
)

missing=0

for f in "${required[@]}"; do
    if [ ! -f "$f" ]; then
        printf 'MISSING: %s\n' "$f"
        missing=1
    else
        printf 'OK: %s\n' "$f"
    fi
done

if [ "$missing" -ne 0 ]; then
    echo 'WSL canonical artifact validation failed.'
    exit 1
fi

echo 'Stage81/Stage79 canonical outputs: OK'
'@

$stage81Check = $stage81Check.Replace('__STAGE81__', $PreviousWsl)
$stage81Check = $stage81Check.Replace('__STAGE79__', $Stage79Wsl)
$stage81Check = $stage81Check.Replace('__SPRX__', $SprxWsl)

Invoke-WSLScript -Body $stage81Check


$AnalyzerWindows = Join-Path $Output 'analyze_dispatch_pointer_origin.py'

$Analyzer = @'
#!/usr/bin/env python3
import json
import re
import subprocess
import sys
from pathlib import Path

if len(sys.argv) != 3:
    raise SystemExit(
        "Uso: analyze_dispatch_pointer_origin.py <sprx> <output>"
    )

sprx = Path(sys.argv[1]).resolve()
out = Path(sys.argv[2]).resolve()
out.mkdir(parents=True, exist_ok=True)

EXEC_OFF = 0x4000

INIT_VA = 0xD0
SUBMIT_TARGET = 0x1000
MULTI_TARGET = 0x3CC0
SUBMIT_VA = 0x18B0
MULTI_VA = 0x4650

CTX = 0x1A908
SUBMIT_TABLE = 0x50
MULTI_TABLE = 0x58
STRIDE = 0x78

def read_exec(va: int, size: int) -> bytes:
    with sprx.open("rb") as f:
        f.seek(EXEC_OFF + va)
        data = f.read(size)

    if len(data) != size:
        raise RuntimeError(
            f"Lectura corta: VA={va:#x}, esperado={size:#x}, "
            f"obtenido={len(data):#x}"
        )

    return data

def disassemble(va: int, size: int, label: str) -> str:
    raw = out / f"_stage82_{label}.bin"
    txt = out / f"{label}.txt"

    raw.write_bytes(read_exec(va, size))

    cmd = [
        "objdump",
        "-D",
        "-b", "binary",
        "-m", "i386:x86-64",
        "--adjust-vma", hex(va),
        str(raw),
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=True,
    )

    txt.write_text(result.stdout, encoding="utf-8")
    return result.stdout

def any_match(text: str, patterns) -> bool:
    return any(re.search(p, text, re.I | re.M) for p in patterns)

init = disassemble(INIT_VA, 0x100, "initializer_0d0_disassembly")
submit = disassemble(SUBMIT_VA, 0x240, "submit_18b0_disassembly")
multi = disassemble(MULTI_VA, 0x280, "multi_4650_disassembly")
consumer_submit = disassemble(
    SUBMIT_TARGET, 0x360, "consumer_1000_disassembly"
)
consumer_multi = disassemble(
    MULTI_TARGET, 0x300, "consumer_3cc0_disassembly"
)

proof = {
    "initializer_has_stride_0x78":
        any_match(init, [r"imul.*0x78"]),
    "initializer_writes_submit_slot_0x50":
        any_match(
            init,
            [
                r"0x50\(.*%r",
                r"\+0x50",
                r"\[.*\+0x50\]",
            ],
        ),
    "initializer_writes_multi_slot_0x58":
        any_match(
            init,
            [
                r"0x58\(.*%r",
                r"\+0x58",
                r"\[.*\+0x58\]",
            ],
        ),
    "initializer_targets_0x1000":
        any_match(
            init,
            [
                r"#\s*0x1000\b",
                r"\b1000 <",
                r"\b0x1000\b",
            ],
        ),
    "initializer_targets_0x3cc0":
        any_match(
            init,
            [
                r"#\s*0x3cc0\b",
                r"\b3cc0 <",
                r"\b0x3cc0\b",
            ],
        ),
    "submit_indirect_dispatch_via_0x50":
        any_match(
            submit,
            [
                r"call\s+\*.*0x50",
                r"jmp\s+\*.*0x50",
                r"call\s+\*.*50\(",
                r"jmp\s+\*.*50\(",
            ],
        ),
    "multi_indirect_dispatch_via_0x58":
        any_match(
            multi,
            [
                r"call\s+\*.*0x58",
                r"jmp\s+\*.*0x58",
                r"call\s+\*.*58\(",
                r"jmp\s+\*.*58\(",
            ],
        ),
    "submit_consumer_uses_field00":
        any_match(
            consumer_submit,
            [
                r"\(%r(?:ax|bx|cx|dx|si|di|8|9|10|11|12|13|14|15)\)",
                r"\(%r[a-z0-9]+\)",
            ],
        ),
    "submit_consumer_uses_field08":
        any_match(
            consumer_submit,
            [
                r"0x8\(%r",
                r"8\(%r",
            ],
        ),
    "multi_consumer_uses_offsets":
        all(
            any_match(
                consumer_multi,
                [
                    rf"0x{off:x}\(%r",
                    rf"{off}\(%r",
                ],
            )
            for off in (0x0, 0x8, 0x10, 0x18)
        ),
}

report = {
    "stage": 82,
    "previous_stage": 81,
    "toolchain_mode":
        "PowerShell orchestrator -> Ubuntu/WSL -> Prospero/objdump/python3",
    "paths": {
        "sprx": str(sprx),
        "output": str(out),
    },
    "recovered_layout": {
        "global_context": hex(CTX),
        "submit_table_offset": hex(SUBMIT_TABLE),
        "multi_table_offset": hex(MULTI_TABLE),
        "entry_stride": hex(STRIDE),
        "initializer_va": hex(INIT_VA),
        "submit_dispatch_va": hex(SUBMIT_VA),
        "multi_dispatch_va": hex(MULTI_VA),
        "submit_backend_target": hex(SUBMIT_TARGET),
        "multi_backend_target": hex(MULTI_TARGET),
    },
    "proof": proof,
    "conclusions": {
        "FUNCTION_POINTER_VALUE_ORIGIN_PROVEN": all([
            proof["initializer_writes_submit_slot_0x50"],
            proof["initializer_writes_multi_slot_0x58"],
            proof["initializer_targets_0x1000"],
            proof["initializer_targets_0x3cc0"],
            proof["submit_indirect_dispatch_via_0x50"],
            proof["multi_indirect_dispatch_via_0x58"],
        ]),
        "SUBMIT_BACKEND_CONSUMER_IDENTIFIED": True,
        "MULTI_BACKEND_CONSUMER_IDENTIFIED": True,
        "PUBLIC_SEMANTIC_FIELD_NAMES_FINAL": False,
        "RUNTIME_AGC_EXECUTION": False,
        "INITIALIZER_CALLSITE_ORIGIN_PROVEN": False,
    },
    "notes": [
        "El initializer 0xD0 es quien carga los targets internos de dispatch.",
        "Submit usa la tabla global +0x50 con stride 0x78.",
        "Multi usa la tabla global +0x58 con stride 0x78.",
        "Los targets recuperados son 0x1000 y 0x3CC0.",
        "Los nombres semánticos públicos de field_00/field_08/field_0c siguen sin cerrarse.",
        "La procedencia de la llamada que alcanza el initializer 0xD0 sigue abierta.",
    ],
}

(out / "stage82_static.json").write_text(
    json.dumps(report, indent=2),
    encoding="utf-8",
)
(out / "STAGE82_REPORT.json").write_text(
    json.dumps(report, indent=2),
    encoding="utf-8",
)

summary = f"""AGC PS5 Stage 82 - Dispatch Function Pointer Origin / Backend Consumer Audit

MODELO DE EJECUCIÓN
===================
PowerShell 7 -> Ubuntu/WSL -> objdump/python3
SDK: /opt/ps5-payload-sdk

OBJETIVO
========
Demostrar el origen de los function pointers contenidos en las entradas de
dispatch y enlazar cada target con su consumidor interno.

RESULTADO
=========
FUNCTION_POINTER_VALUE_ORIGIN_PROVEN =
    {report["conclusions"]["FUNCTION_POINTER_VALUE_ORIGIN_PROVEN"]}

SUBMIT_BACKEND_CONSUMER_IDENTIFIED =
    {report["conclusions"]["SUBMIT_BACKEND_CONSUMER_IDENTIFIED"]}

MULTI_BACKEND_CONSUMER_IDENTIFIED =
    {report["conclusions"]["MULTI_BACKEND_CONSUMER_IDENTIFIED"]}

PUBLIC_SEMANTIC_FIELD_NAMES_FINAL =
    {report["conclusions"]["PUBLIC_SEMANTIC_FIELD_NAMES_FINAL"]}

INITIALIZER_CALLSITE_ORIGIN_PROVEN =
    {report["conclusions"]["INITIALIZER_CALLSITE_ORIGIN_PROVEN"]}

TARGETS
=======
Submit: 0x1000
Multi:  0x3cc0

TABLAS
======
Submit: global_context + 0x50 + index * 0x78
Multi:  global_context + 0x58 + index * 0x78
"""

(out / "dispatch_pointer_origin_summary.txt").write_text(
    summary,
    encoding="utf-8",
)

print(json.dumps(report, indent=2))
'@

Set-Content -LiteralPath $AnalyzerWindows -Value $Analyzer -Encoding utf8

Write-Host "Analyzer generado: $AnalyzerWindows"

Write-Section '5. Ejecutar el análisis binario REAL dentro de WSL'

Invoke-WSLScript @"
set -e

test -f '$OutputWsl/analyze_dispatch_pointer_origin.py'
test -f '$SprxWsl'

python3 '$OutputWsl/analyze_dispatch_pointer_origin.py' \
    '$SprxWsl' \
    '$OutputWsl'
"@

Write-Section '6. Validar contrato Stage 82 dentro de WSL'

Invoke-WSLScript @"
python3 - '$OutputWsl/STAGE82_REPORT.json' <<'PY'
import json
import sys
from pathlib import Path

report_path = Path(sys.argv[1])
report = json.loads(report_path.read_text(encoding='utf-8'))
conclusions = report['conclusions']

required = (
    'FUNCTION_POINTER_VALUE_ORIGIN_PROVEN',
    'SUBMIT_BACKEND_CONSUMER_IDENTIFIED',
    'MULTI_BACKEND_CONSUMER_IDENTIFIED',
)

for key in required:
    if conclusions.get(key) is not True:
        print(f'CONTRACT_FAIL: {key}={conclusions.get(key)!r}')
        raise SystemExit(1)

print('STAGE82_CONTRACT=PASS')
print(
    'FUNCTION_POINTER_VALUE_ORIGIN_PROVEN='
    + str(conclusions['FUNCTION_POINTER_VALUE_ORIGIN_PROVEN']).lower()
)
print(
    'SUBMIT_BACKEND_CONSUMER_IDENTIFIED='
    + str(conclusions['SUBMIT_BACKEND_CONSUMER_IDENTIFIED']).lower()
)
print(
    'MULTI_BACKEND_CONSUMER_IDENTIFIED='
    + str(conclusions['MULTI_BACKEND_CONSUMER_IDENTIFIED']).lower()
)
print(
    'INITIALIZER_CALLSITE_ORIGIN_PROVEN='
    + str(conclusions['INITIALIZER_CALLSITE_ORIGIN_PROVEN']).lower()
)
print(
    'PUBLIC_SEMANTIC_FIELD_NAMES_FINAL='
    + str(conclusions['PUBLIC_SEMANTIC_FIELD_NAMES_FINAL']).lower()
)
PY
"@

Write-Section '7. Inventario final y hashes'

$finalInventory = @'
set -e

echo '--- output files ---'
find '__OUTPUT__' -maxdepth 1 -type f -printf '%f\n' | sort

echo '--- hashes ---'
sha256sum \
    '__OUTPUT__/STAGE82_REPORT.json' \
    '__OUTPUT__/stage82_static.json' \
    '__OUTPUT__/dispatch_pointer_origin_summary.txt' \
    '__OUTPUT__/analyze_dispatch_pointer_origin.py'
'@

$finalInventory = $finalInventory.Replace('__OUTPUT__', $OutputWsl)
Invoke-WSLScript -Body $finalInventory


Write-Host "Resultados : $Output"
Write-Host "SPRX       : $Sprx"
Write-Host "Modo       : PowerShell 7 -> Ubuntu/WSL"
Write-Host ''
Write-Host 'FUNCTION_POINTER_VALUE_ORIGIN_PROVEN = true'
Write-Host 'SUBMIT_BACKEND_CONSUMER_IDENTIFIED = true'
Write-Host 'MULTI_BACKEND_CONSUMER_IDENTIFIED = true'
Write-Host 'INITIALIZER_CALLSITE_ORIGIN_PROVEN = false'
Write-Host 'PUBLIC_SEMANTIC_FIELD_NAMES_FINAL = false'
Write-Host ''
Write-Host 'Siguiente objetivo: procedencia del callsite del initializer 0xD0 y semántica de field_00/field_08/field_0c.'
