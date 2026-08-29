#requires -Version 7.0
<#
AGC PS5 - Stage 82 FINAL-LINK
Project Eight-Function Consumer / End-to-End Link Validation

CONTINUIDAD
===========
Stage 79 : ABI v1 estática construida.
Stage 80 : libagc_project_v1.a construida.
Stage 81 : enlace ABI + proyecto cerrado con auditoría exacta.

NOTA SOBRE LA NUMERACIÓN
=========================
El workspace actualizado ya contiene D:\agc_work\stage82_results con el
reversing de dispatch/function-pointer origin. Ese contenido NO se pisa.

Este script es el cierre operativo que el Prompt maestro describe como
"Stage 82": compilar un cliente real que fuerce las ocho funciones públicas
agcProject*V1 y verificar que la cadena completa enlaza contra la ABI v1.

Salida nueva:
    D:\agc_work\stage82_link_results

No modifica:
    D:\agc_work\stage82_results

MODELO
======
PowerShell 7
  -> wsl.exe
    -> Ubuntu
      -> /opt/ps5-payload-sdk
        -> prospero-clang
        -> prospero-lld
        -> prospero-nm

NO DEMUESTRA
============
- ejecución real en PS5;
- semántica pública definitiva de field_00/field_08/field_0c;
- corrección GPU/runtime;
- que los targets 0x1000/0x3cc0 sean todos los backends posibles.
#>

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$StageDir = Split-Path -Parent $MyInvocation.MyCommand.Path

$Stage79 = 'D:\agc_work\stage79_results'
$Stage80 = 'D:\agc_work\stage80_results'
$Stage81 = 'D:\agc_work\stage81_results'

$Output = 'D:\agc_work\stage82_link_results'

$Stage79Wsl = '/mnt/d/agc_work/stage79_results'
$Stage80Wsl = '/mnt/d/agc_work/stage80_results'
$Stage81Wsl = '/mnt/d/agc_work/stage81_results'
$OutputWsl  = '/mnt/d/agc_work/stage82_link_results'

$Sdk = '/opt/ps5-payload-sdk'

$ProjectSymbols = @(
    'agcProjectSubmitCommandBufferV1'
    'agcProjectSubmitDcbV1'
    'agcProjectAgrSubmitDcbV1'
    'agcProjectSubmitMultiCommandBuffersV1'
    'agcProjectSubmitAcbV1'
    'agcProjectSubmitMultiAcbsV1'
    'agcProjectSubmitMultiDcbsV1'
    'agcProjectAgrSubmitMultiDcbsV1'
)

$DriverSymbols = @(
    'sceAgcDriverSubmitCommandBuffer'
    'sceAgcDriverSubmitDcb'
    'sceAgcDriverAgrSubmitDcb'
    'sceAgcDriverSubmitMultiCommandBuffers'
    'sceAgcDriverSubmitAcb'
    'sceAgcDriverSubmitMultiAcbs'
    'sceAgcDriverSubmitMultiDcbs'
    'sceAgcDriverAgrSubmitMultiDcbs'
)

function Write-Section {
    param([Parameter(Mandatory)][string]$Title)
    Write-Host ''
    Write-Host '=============================================================================='
    Write-Host $Title
    Write-Host '=============================================================================='
}

function Invoke-WSLScript {
    param([Parameter(Mandatory)][string]$Body)

    & wsl.exe bash -lc "set -e; $Body"
    $code = $LASTEXITCODE

    if ($code -ne 0) {
        throw "WSL command failed with exit code $code."
    }
}

function Invoke-WSLCapture {
    param([Parameter(Mandatory)][string]$CommandLine)

    $result = & wsl.exe bash -lc $CommandLine
    $code = $LASTEXITCODE

    if ($code -ne 0) {
        throw "WSL capture failed with exit code $code."
    }

    return (($result | Out-String).Trim())
}

Write-Section 'AGC PS5 Stage 82 FINAL-LINK - Eight-Function Project Consumer Audit'

Write-Host "StageDir : $StageDir"
Write-Host "Stage79  : $Stage79"
Write-Host "Stage80  : $Stage80"
Write-Host "Stage81  : $Stage81"
Write-Host "Output   : $Output"
Write-Host "SDK WSL  : $Sdk"
Write-Host ''
Write-Host 'NO se toca: D:\agc_work\stage82_results'
Write-Host 'Salida nueva: D:\agc_work\stage82_link_results'

if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    throw 'No se encontró wsl.exe.'
}

Write-Section '1. Validación de inputs Windows'

@(
    $Stage79
    $Stage80
    $Stage81
) | ForEach-Object {
    if (-not (Test-Path -LiteralPath $_)) {
        throw "No existe: $_"
    }
    Write-Host "[OK] $_"
}

New-Item -ItemType Directory -Force -Path $Output | Out-Null

Write-Section '2. Validación real del entorno WSL / SDK'

Invoke-WSLScript @"
set -e

test -f '$Stage79Wsl/libSceAgcDriver_abi_v1.a'
test -f '$Stage80Wsl/libagc_project_v1.a'
test -f '$Stage80Wsl/agc_project_v1.h'
test -f '$Stage81Wsl/STAGE81_REPORT.json'
test -f '$Stage81Wsl/stage81_linked.o'

test -x '$Sdk/bin/prospero-clang'
test -x '$Sdk/bin/prospero-lld'
test -x '$Sdk/bin/prospero-nm'

mkdir -p '$OutputWsl'

echo 'workspace=OK'
echo '--- versions ---'
'$Sdk/bin/prospero-clang' --version | head -n 1
'$Sdk/bin/prospero-lld' --version | head -n 1
'$Sdk/bin/prospero-nm' --version | head -n 1
"@

Write-Section '3. Crear consumidor real de las ocho funciones'

$probeSource = @'
#include "agc_project_v1.h"

/*
 * Stage 82 FINAL-LINK:
 * fuerza referencias reales desde un cliente de proyecto a las ocho
 * funciones agcProject*V1.
 *
 * Este objeto no se ejecuta. Su finalidad es verificar compilación y
 * resolución de la cadena:
 *
 * cliente -> agc_project_v1.a -> libSceAgcDriver_abi_v1.a
 */

int stage82_project_consumer(
    AgcContextV1 context,
    AgcSubmitCommandBufferArgsV1 *args,
    const uint64_t *field00_array,
    const uint32_t *field08_array)
{
    int rc = 0;

    rc += agcProjectSubmitCommandBufferV1(context, args);
    rc += agcProjectSubmitDcbV1(args);
    rc += agcProjectAgrSubmitDcbV1(args);

    rc += agcProjectSubmitMultiCommandBuffersV1(
        context,
        field00_array,
        field08_array,
        1
    );

    rc += agcProjectSubmitAcbV1(args);
    rc += agcProjectSubmitMultiAcbsV1(args);
    rc += agcProjectSubmitMultiDcbsV1(args);
    rc += agcProjectAgrSubmitMultiDcbsV1(args);

    return rc;
}
'@

$contract = @'
AGC PS5 Stage 82 FINAL-LINK

OBJETIVO
========
Validar que un cliente del proyecto pueda consumir las ocho funciones
agcProject*V1 y que la cadena completa se enlace con la ABI v1 recuperada.

CAPAS
=====
Cliente
  -> libagc_project_v1.a
  -> libSceAgcDriver_abi_v1.a

REQUISITOS PASS
===============
1. Probe compila con prospero-clang.
2. Probe object existe y no está vacío.
3. Relocatable final se genera con prospero-lld -r.
4. No existen referencias undefined a sceAgcDriver*/agcProject*.
5. Existen individualmente las 8 funciones agcProject*V1.
6. Existen individualmente las 8 funciones sceAgcDriver*.
7. STAGE82_FINAL_LINK_CONTRACT=PASS se emite solo si todas las
   comprobaciones reales pasan.

NO DEMUESTRA
============
- ejecución PS5;
- ejecución AGC;
- semántica pública definitiva;
- estado GPU;
- corrección runtime de function pointers.
'@

Set-Content -LiteralPath (Join-Path $Output 'stage82_project_consumer.c') `
    -Value $probeSource -NoNewline -Encoding ascii

Set-Content -LiteralPath (Join-Path $Output 'STAGE82_FINAL_LINK_CONTRACT.txt') `
    -Value $contract -NoNewline -Encoding ascii

Write-Host "[OK] $Output\stage82_project_consumer.c"
Write-Host "[OK] $Output\STAGE82_FINAL_LINK_CONTRACT.txt"

Write-Section '4. py_compile del analizador auxiliar'

$pythonCheck = @'
#!/usr/bin/env python3
import json
import sys
from pathlib import Path

if len(sys.argv) != 3:
    raise SystemExit("usage: stage82_verify.py <nm_dump> <report>")

nm = Path(sys.argv[1])
report = Path(sys.argv[2])

if not nm.is_file():
    raise SystemExit("missing nm dump")

if not report.parent.is_dir():
    report.parent.mkdir(parents=True, exist_ok=True)

lines = nm.read_text(encoding="utf-8", errors="replace").splitlines()

project = [
    "agcProjectSubmitCommandBufferV1",
    "agcProjectSubmitDcbV1",
    "agcProjectAgrSubmitDcbV1",
    "agcProjectSubmitMultiCommandBuffersV1",
    "agcProjectSubmitAcbV1",
    "agcProjectSubmitMultiAcbsV1",
    "agcProjectSubmitMultiDcbsV1",
    "agcProjectAgrSubmitMultiDcbsV1",
]

driver = [
    "sceAgcDriverSubmitCommandBuffer",
    "sceAgcDriverSubmitDcb",
    "sceAgcDriverAgrSubmitDcb",
    "sceAgcDriverSubmitMultiCommandBuffers",
    "sceAgcDriverSubmitAcb",
    "sceAgcDriverSubmitMultiAcbs",
    "sceAgcDriverSubmitMultiDcbs",
    "sceAgcDriverAgrSubmitMultiDcbs",
]

present_project = {
    name: any(name in line for line in lines)
    for name in project
}

present_driver = {
    name: any(name in line for line in lines)
    for name in driver
}

result = {
    "project": present_project,
    "driver": present_driver,
    "project_count": sum(present_project.values()),
    "driver_count": sum(present_driver.values()),
}

report.write_text(
    json.dumps(result, indent=2),
    encoding="utf-8",
)

if result["project_count"] != 8:
    raise SystemExit(1)

if result["driver_count"] != 8:
    raise SystemExit(1)
'@

$PythonPath = Join-Path $Output 'stage82_verify.py'
Set-Content -LiteralPath $PythonPath -Value $pythonCheck -Encoding ascii

Invoke-WSLScript @"
set -e

python3 -m py_compile '$OutputWsl/stage82_verify.py'
test -f '$OutputWsl/__pycache__/stage82_verify.cpython-312.pyc' || true

echo 'py_compile=OK'
"@

Write-Section '5. Compilar consumidor dentro de WSL'

Invoke-WSLScript @"
set -e

rm -rf /tmp/agc_stage82_final_link
mkdir -p /tmp/agc_stage82_final_link

cp '$Stage80Wsl/agc_project_v1.h' \
   /tmp/agc_stage82_final_link/agc_project_v1.h

'$Sdk/bin/prospero-clang' \
    -target x86_64-sie-ps5 \
    -ffreestanding \
    -fno-builtin \
    -nostdlib \
    -fPIC \
    -fno-plt \
    -fno-stack-protector \
    -Wall \
    -Wextra \
    -Werror \
    -fvisibility=hidden \
    -I/tmp/agc_stage82_final_link \
    -c '$OutputWsl/stage82_project_consumer.c' \
    -o '$OutputWsl/stage82_project_consumer.o'

test -s '$OutputWsl/stage82_project_consumer.o'

echo 'compile=OK'
file '$OutputWsl/stage82_project_consumer.o'
"@

Write-Section '6. Enlace real del consumidor + project + ABI'

Invoke-WSLScript @"
set -e

'$Sdk/bin/prospero-lld' \
    -r \
    -o '$OutputWsl/stage82_project_linked.o' \
    '$OutputWsl/stage82_project_consumer.o' \
    '$Stage80Wsl/libagc_project_v1.a' \
    '$Stage79Wsl/libSceAgcDriver_abi_v1.a'

test -s '$OutputWsl/stage82_project_linked.o'

echo 'link=OK'
file '$OutputWsl/stage82_project_linked.o'
"@

Write-Section '7. Capturar symbol table y undefined REAL'

$NmC = Invoke-WSLCapture `
    "'$Sdk/bin/prospero-nm' -C '$OutputWsl/stage82_project_linked.o'"

$NmU = Invoke-WSLCapture `
    "'$Sdk/bin/prospero-nm' -u '$OutputWsl/stage82_project_linked.o' || true"

$NmCPath = Join-Path $Output 'stage82_project_nm_C.txt'
$NmUPath = Join-Path $Output 'stage82_project_nm_undefined.txt'

Set-Content -LiteralPath $NmCPath -Value $NmC -Encoding ascii
Set-Content -LiteralPath $NmUPath -Value $NmU -Encoding ascii

$UndefinedRelevant = @(
    ($NmU -split "`r?`n") |
    Where-Object { $_ -match 'sceAgcDriver|agcProject' }
)

Write-Host "--- AGC/project undefined ---"

if ($UndefinedRelevant.Count -eq 0) {
    Write-Host '[OK] 0'
} else {
    $UndefinedRelevant | ForEach-Object { Write-Host $_ }
    throw "Hay referencias AGC/project undefined: $($UndefinedRelevant.Count)"
}

Write-Section '8. Auditoría exacta de los 16 símbolos'

$ProjectPresent = [ordered]@{}
$DriverPresent = [ordered]@{}

$NmLines = $NmC -split "`r?`n"

foreach ($symbol in $ProjectSymbols) {
    $ProjectPresent[$symbol] = @(
        $NmLines | Where-Object {
            $_ -match "\b$([regex]::Escape($symbol))\b"
        }
    ).Count -gt 0
}

foreach ($symbol in $DriverSymbols) {
    $DriverPresent[$symbol] = @(
        $NmLines | Where-Object {
            $_ -match "\b$([regex]::Escape($symbol))\b"
        }
    ).Count -gt 0
}

Write-Host '--- agcProject*V1 ---'

foreach ($symbol in $ProjectSymbols) {
    if ($ProjectPresent[$symbol]) {
        Write-Host "[OK] $symbol"
    } else {
        Write-Host "[MISSING] $symbol"
    }
}

Write-Host '--- sceAgcDriver* ---'

foreach ($symbol in $DriverSymbols) {
    if ($DriverPresent[$symbol]) {
        Write-Host "[OK] $symbol"
    } else {
        Write-Host "[MISSING] $symbol"
    }
}

$ProjectCount = @(
    $ProjectPresent.GetEnumerator() |
    Where-Object { $_.Value }
).Count

$DriverCount = @(
    $DriverPresent.GetEnumerator() |
    Where-Object { $_.Value }
).Count

Write-Host ''
Write-Host "project_exact_count = $ProjectCount / 8"
Write-Host "driver_exact_count  = $DriverCount / 8"
Write-Host "undefined_AGC_count = $($UndefinedRelevant.Count)"

if ($ProjectCount -ne 8) {
    throw "Stage 82 FAIL: project symbols $ProjectCount/8"
}

if ($DriverCount -ne 8) {
    throw "Stage 82 FAIL: driver symbols $DriverCount/8"
}

Write-Host '[PASS] Los 16 símbolos están presentes.'

Write-Section '9. Ejecutar verificador Python sobre la symbol table'

Invoke-WSLScript @"
set -e

python3 '$OutputWsl/stage82_verify.py' \
    '$OutputWsl/stage82_project_nm_C.txt' \
    '$OutputWsl/stage82_python_symbol_report.json'

echo 'python_symbol_audit=OK'
"@

Write-Section '10. Generar metadata REAL'

$report = [ordered]@{
    stage = 82
    variant = 'FINAL-LINK'
    generated_at = (Get-Date).ToString('o')

    continuity = [ordered]@{
        stage79 = $Stage79
        stage80 = $Stage80
        stage81 = $Stage81
        existing_dispatch_stage82_preserved = 'D:\agc_work\stage82_results'
    }

    execution_model = [ordered]@{
        orchestrator = 'PowerShell 7'
        execution = 'Ubuntu WSL'
        sdk = $Sdk
        clang = 'prospero-clang'
        lld = 'prospero-lld'
        nm = 'prospero-nm'
    }

    inputs = [ordered]@{
        abi_archive = "$Stage79\libSceAgcDriver_abi_v1.a"
        project_archive = "$Stage80\libagc_project_v1.a"
        project_header = "$Stage80\agc_project_v1.h"
        stage81_report = "$Stage81\STAGE81_REPORT.json"
    }

    outputs = [ordered]@{
        consumer_source = 'stage82_project_consumer.c'
        consumer_object = 'stage82_project_consumer.o'
        linked_object = 'stage82_project_linked.o'
        nm_C = 'stage82_project_nm_C.txt'
        nm_u = 'stage82_project_nm_undefined.txt'
        python_symbol_report = 'stage82_python_symbol_report.json'
        contract = 'STAGE82_FINAL_LINK_CONTRACT.txt'
    }

    counts = [ordered]@{
        project_exact = $ProjectCount
        driver_exact = $DriverCount
        undefined_agc_project = $UndefinedRelevant.Count
    }

    expected = [ordered]@{
        project_exact = 8
        driver_exact = 8
        undefined_agc_project = 0
    }

    conclusions = [ordered]@{
        PROJECT_CLIENT_COMPILED = $true
        PROJECT_AND_ABI_ARCHIVES_LINKED = $true
        EIGHT_PROJECT_FUNCTIONS_CONSUMABLE = ($ProjectCount -eq 8)
        EIGHT_DRIVER_FUNCTIONS_RESOLVED = ($DriverCount -eq 8)
        AGC_PROJECT_UNDEFINED_ZERO = ($UndefinedRelevant.Count -eq 0)
        FINAL_LINK_CONTRACT_PASS = (
            ($ProjectCount -eq 8) -and
            ($DriverCount -eq 8) -and
            ($UndefinedRelevant.Count -eq 0)
        )
        REAL_PS5_EXECUTION = $false
        PUBLIC_SEMANTIC_FIELD_NAMES_FINAL = $false
    }
}

$json = $report | ConvertTo-Json -Depth 10

Set-Content -LiteralPath (Join-Path $Output 'STAGE82_FINAL_LINK_REPORT.json') `
    -Value $json -Encoding utf8

Set-Content -LiteralPath (Join-Path $Output 'stage82_final_link_static.json') `
    -Value $json -Encoding utf8

Write-Host '[OK] STAGE82_FINAL_LINK_REPORT.json'
Write-Host '[OK] stage82_final_link_static.json'

Write-Section '11. Hashes SHA256'

$Artifacts = @(
    'stage82_project_consumer.c'
    'stage82_project_consumer.o'
    'stage82_project_linked.o'
    'stage82_project_nm_C.txt'
    'stage82_project_nm_undefined.txt'
    'stage82_python_symbol_report.json'
    'STAGE82_FINAL_LINK_CONTRACT.txt'
    'STAGE82_FINAL_LINK_REPORT.json'
    'stage82_final_link_static.json'
    'stage82_verify.py'
)

$HashLines = New-Object System.Collections.Generic.List[string]

foreach ($name in $Artifacts) {
    $path = Join-Path $Output $name

    if (-not (Test-Path -LiteralPath $path)) {
        throw "Falta artefacto antes de hash: $path"
    }

    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    $line = "$hash  $name"
    $HashLines.Add($line)
    Write-Host $line
}

Set-Content -LiteralPath (Join-Path $Output 'stage82_final_link_sha256.txt') `
    -Value ($HashLines -join [Environment]::NewLine) `
    -Encoding ascii

Write-Host '[OK] stage82_final_link_sha256.txt'

Write-Section '12. Verificación final de artefactos'

foreach ($name in ($Artifacts + 'stage82_final_link_sha256.txt')) {
    $path = Join-Path $Output $name

    if (-not (Test-Path -LiteralPath $path)) {
        throw "Artefacto final faltante: $path"
    }

    if ((Get-Item -LiteralPath $path).Length -le 0) {
        throw "Artefacto final vacío: $path"
    }

    Write-Host "[OK] $name"
}

Write-Section '13. Contrato final Stage 82 FINAL-LINK'

$pass = (
    ($ProjectCount -eq 8) -and
    ($DriverCount -eq 8) -and
    ($UndefinedRelevant.Count -eq 0)
)

if (-not $pass) {
    throw 'STAGE82_FINAL_LINK_CONTRACT=FAIL'
}

Write-Host 'STAGE82_FINAL_LINK_CONTRACT=PASS'
Write-Host 'PROJECT_CLIENT_COMPILED=True'
Write-Host 'PROJECT_AND_ABI_ARCHIVES_LINKED=True'
Write-Host 'EIGHT_PROJECT_FUNCTIONS_CONSUMABLE=True'
Write-Host 'EIGHT_DRIVER_FUNCTIONS_RESOLVED=True'
Write-Host 'AGC_PROJECT_UNDEFINED_ZERO=True'
Write-Host 'REAL_PS5_EXECUTION=False'
Write-Host 'PUBLIC_SEMANTIC_FIELD_NAMES_FINAL=False'
Write-Host ''
Write-Host "Resultados: $Output"
Write-Host ''
Write-Host 'El Stage 82 de reversing permanece intacto en:'
Write-Host '  D:\agc_work\stage82_results'
