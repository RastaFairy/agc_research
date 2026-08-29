#requires -Version 7.0
<#
AGC PS5 - Stage 81 FINAL
End-to-End Project Link / ABI Resolution Audit

FUENTE DE CONTINUIDAD
=====================
Este script continúa el Stage 81 v3 incluido en la actualización del proyecto.
Mantiene el modelo canónico:

    PowerShell 7
        -> wsl.exe
            -> Ubuntu
                -> /opt/ps5-payload-sdk
                    -> prospero-clang
                    -> prospero-lld
                    -> prospero-nm

LAYOUT WINDOWS
==============
    D:\agc_work\stage79_results
    D:\agc_work\stage80_results
    D:\agc_work\stage81_results

LAYOUT WSL
==========
    /mnt/d/agc_work/stage79_results
    /mnt/d/agc_work/stage80_results
    /mnt/d/agc_work/stage81_results
    /opt/ps5-payload-sdk

OBJETIVO DE CIERRE
==================
1. Compilar el cliente de prueba con las 8 funciones agcProject*V1.
2. Enlazar:
       probe.o
       + libagc_project_v1.a
       + libSceAgcDriver_abi_v1.a
3. Verificar que no quedan U/undefined para sceAgcDriver*/agcProject*.
4. Verificar individualmente los 8 símbolos agcProject*V1.
5. Verificar individualmente los 8 símbolos sceAgcDriver*.
6. Generar counts, reporte, contrato y SHA256.
7. No hardcodear conclusiones positivas.
8. Fallar inmediatamente si algún requisito objetivo no se cumple.

NO DEMUESTRA
============
- ejecución AGC real;
- estado GPU correcto;
- semántica pública definitiva de field_00/field_08/field_0c;
- corrección runtime de function pointers en el proceso PS5.
#>

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$StageDir = Split-Path -Parent $MyInvocation.MyCommand.Path

$Stage79 = 'D:\agc_work\stage79_results'
$Stage80 = 'D:\agc_work\stage80_results'
$Output  = 'D:\agc_work\stage81_results'
$Sdk     = '/opt/ps5-payload-sdk'

$Stage79Wsl = '/mnt/d/agc_work/stage79_results'
$Stage80Wsl = '/mnt/d/agc_work/stage80_results'
$OutputWsl  = '/mnt/d/agc_work/stage81_results'

$ExpectedProjectSymbols = @(
    'agcProjectSubmitCommandBufferV1'
    'agcProjectSubmitDcbV1'
    'agcProjectAgrSubmitDcbV1'
    'agcProjectSubmitMultiCommandBuffersV1'
    'agcProjectSubmitAcbV1'
    'agcProjectSubmitMultiAcbsV1'
    'agcProjectSubmitMultiDcbsV1'
    'agcProjectAgrSubmitMultiDcbsV1'
)

$ExpectedDriverSymbols = @(
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
        throw "WSL failed (exit $code)."
    }
}

function Invoke-WSLCapture {
    param([Parameter(Mandatory)][string]$CommandLine)

    $captured = & wsl.exe bash -lc $CommandLine
    $code = $LASTEXITCODE

    if ($code -ne 0) {
        throw "WSL capture failed (exit $code). CMD: $CommandLine"
    }

    return ($captured | Out-String).Trim()
}

Write-Section 'AGC PS5 Stage 81 FINAL - End-to-End Project Link / ABI Resolution Audit'

Write-Host "StageDir : $StageDir"
Write-Host "Stage79  : $Stage79"
Write-Host "Stage80  : $Stage80"
Write-Host "Output   : $Output"
Write-Host "SDK WSL  : $Sdk"
Write-Host ''
Write-Host 'Modelo: PowerShell 7 -> Ubuntu/WSL -> Prospero toolchain'
Write-Host 'Cierre: compile + link + undefined audit + exact symbol audit + metadata'

if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    throw 'No se encontró wsl.exe. Este Stage requiere WSL/Ubuntu.'
}

Write-Section '1. Validación del workspace Windows'

$requiredWindows = @(
    $Stage79,
    $Stage80
)

foreach ($p in $requiredWindows) {
    if (-not (Test-Path -LiteralPath $p)) {
        throw "No existe: $p"
    }
}

New-Item -ItemType Directory -Force -Path $Output | Out-Null

Write-Host "OK: $Stage79"
Write-Host "OK: $Stage80"
Write-Host "OK: $Output"

Write-Section '2. Validación real del workspace dentro de WSL'

Invoke-WSLScript @"
set -e

test -f '$Stage79Wsl/libSceAgcDriver_abi_v1.a'
test -f '$Stage80Wsl/libagc_project_v1.a'
test -f '$Stage80Wsl/agc_project_v1.h'

test -x '$Sdk/bin/prospero-clang'
test -x '$Sdk/bin/prospero-lld'
test -x '$Sdk/bin/prospero-nm'

mkdir -p '$OutputWsl'

echo 'workspace=OK'
echo '--- inputs ---'
ls -lh \
    '$Stage79Wsl/libSceAgcDriver_abi_v1.a' \
    '$Stage80Wsl/libagc_project_v1.a' \
    '$Stage80Wsl/agc_project_v1.h'
echo '--- toolchain ---'
'$Sdk/bin/prospero-clang' --version | head -n 1
'$Sdk/bin/prospero-lld' --version | head -n 1
'$Sdk/bin/prospero-nm' --version | head -n 1
"@

Write-Section '3. Generar probe y contrato Stage 81'

$probeSource = @'
#include "agc_project_v1.h"

/*
 * Stage 81 end-to-end probe.
 *
 * El probe no se ejecuta.
 * Su finalidad es forzar referencias a las ocho entradas públicas
 * agcProject*V1 para que el linker deba resolver la cadena completa:
 *
 *   agcProject*V1
 *       -> sceAgcDriver* recuperados en Stage 79
 */
int stage81_end_to_end_probe(
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
        context, field00_array, field08_array, 1
    );
    rc += agcProjectSubmitAcbV1(args);
    rc += agcProjectSubmitMultiAcbsV1(args);
    rc += agcProjectSubmitMultiDcbsV1(args);
    rc += agcProjectAgrSubmitMultiDcbsV1(args);

    return rc;
}
'@

$contract = @'
AGC PS5 Stage 81 FINAL - End-to-End Project Link / ABI Resolution Audit

INPUTS
======
Stage 79
--------
libSceAgcDriver_abi_v1.a

Stage 80
--------
libagc_project_v1.a
agc_project_v1.h

PROOF OBJECTIVE
===============
Este Stage fuerza desde un cliente de integración referencias a las ocho
entradas agcProject*V1 y verifica que la cadena completa pueda compilarse
y enlazarse como objeto relocatable.

REQUIREMENTS FOR PASS
=====================
R1. stage81_end_to_end_probe.c compila con prospero-clang.
R2. stage81_end_to_end_probe.o existe y no está vacío.
R3. stage81_linked.o se genera con prospero-lld -r.
R4. No quedan referencias undefined a sceAgcDriver* ni agcProject*.
R5. Están presentes individualmente las ocho funciones agcProject*V1.
R6. Están presentes individualmente las ocho funciones sceAgcDriver*
    recuperadas por Stage 79, independientemente de que el binding del
    stub sea T/W/w.
R7. Los contadores auditados son derivados del objeto enlazado real.
R8. STAGE81_REPORT.json y stage81_static.json contienen conclusiones
    derivadas de los resultados reales, nunca hardcodeadas.

THIS STAGE DOES NOT PROVE
=========================
- ejecución AGC real;
- estado GPU correcto;
- nombres semánticos públicos definitivos de field_00/field_08/field_0c;
- corrección runtime de function pointers en el proceso PS5.
'@

Set-Content -LiteralPath (Join-Path $Output 'stage81_end_to_end_probe.c') `
    -Value $probeSource -NoNewline -Encoding ascii

Set-Content -LiteralPath (Join-Path $Output 'END_TO_END_LINK_CONTRACT.txt') `
    -Value $contract -NoNewline -Encoding ascii

Write-Host "OK: $Output\stage81_end_to_end_probe.c"
Write-Host "OK: $Output\END_TO_END_LINK_CONTRACT.txt"

Write-Section '4. Compilar probe dentro de Ubuntu/WSL'

Invoke-WSLScript @"
set -e

rm -rf /tmp/agc_stage81_final
mkdir -p /tmp/agc_stage81_final

cp '$Stage80Wsl/agc_project_v1.h' \
   /tmp/agc_stage81_final/agc_project_v1.h

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
    -I/tmp/agc_stage81_final \
    -c '$OutputWsl/stage81_end_to_end_probe.c' \
    -o '$OutputWsl/stage81_end_to_end_probe.o'

test -s '$OutputWsl/stage81_end_to_end_probe.o'

echo 'compile=OK'
file '$OutputWsl/stage81_end_to_end_probe.o'
"@

Write-Section '5. Enlace final: Stage 80 + Stage 79'

Invoke-WSLScript @"
set -e

'$Sdk/bin/prospero-lld' \
    -r \
    -o '$OutputWsl/stage81_linked.o' \
    '$OutputWsl/stage81_end_to_end_probe.o' \
    '$Stage80Wsl/libagc_project_v1.a' \
    '$Stage79Wsl/libSceAgcDriver_abi_v1.a'

test -s '$OutputWsl/stage81_linked.o'

echo 'link=OK'
file '$OutputWsl/stage81_linked.o'
"@

Write-Section '6. Capturar tabla de símbolos REAL'

$nmOutput = Invoke-WSLCapture `
    "'$Sdk/bin/prospero-nm' -C '$OutputWsl/stage81_linked.o'"

$nmOutputPath = Join-Path $Output 'stage81_nm_C.txt'
Set-Content -LiteralPath $nmOutputPath -Value $nmOutput -Encoding ascii

$nmUndefined = Invoke-WSLCapture `
    "'$Sdk/bin/prospero-nm' -u '$OutputWsl/stage81_linked.o' || true"

$undefinedPath = Join-Path $Output 'stage81_nm_undefined.txt'
Set-Content -LiteralPath $undefinedPath -Value $nmUndefined -Encoding ascii

Write-Host "Tabla completa: $nmOutputPath"
Write-Host "Undefined:      $undefinedPath"

Write-Host ''
Write-Host '--- undefined references relacionadas con AGC/proyecto ---'

$undefinedRelevant = @(
    ($nmUndefined -split "`r?`n") |
    Where-Object {
        $_ -match 'sceAgcDriver|agcProject'
    }
)

if ($undefinedRelevant.Count -eq 0) {
    Write-Host '[OK] 0 referencias undefined sceAgcDriver*/agcProject*'
} else {
    $undefinedRelevant | ForEach-Object { Write-Host $_ }
}

Write-Section '7. Auditoría exacta de los 16 símbolos'

$projectPresent = @{}
$driverPresent = @{}

foreach ($symbol in $ExpectedProjectSymbols) {
    # Symbol names are matched literally after nm -C.
    $hit = $nmOutput -split "`r?`n" |
        Where-Object {
            $_ -match "(^|[[:space:]])[TtWw][[:space:]]+$([regex]::Escape($symbol))$"
        }

    # Second fallback handles nm output with additional whitespace/annotations.
    if ($null -eq $hit -or @($hit).Count -eq 0) {
        $hit = $nmOutput -split "`r?`n" |
            Where-Object {
                $_ -match "\b$([regex]::Escape($symbol))\b"
            }
    }

    $projectPresent[$symbol] = ($null -ne $hit -and @($hit).Count -gt 0)
}

foreach ($symbol in $ExpectedDriverSymbols) {
    $hit = $nmOutput -split "`r?`n" |
        Where-Object {
            $_ -match "(^|[[:space:]])[TtWw][[:space:]]+$([regex]::Escape($symbol))$"
        }

    if ($null -eq $hit -or @($hit).Count -eq 0) {
        $hit = $nmOutput -split "`r?`n" |
            Where-Object {
                $_ -match "\b$([regex]::Escape($symbol))\b"
            }
    }

    $driverPresent[$symbol] = ($null -ne $hit -and @($hit).Count -gt 0)
}

Write-Host '--- agcProject*V1 ---'
foreach ($symbol in $ExpectedProjectSymbols) {
    $state = if ($projectPresent[$symbol]) { 'OK' } else { 'MISSING' }
    Write-Host ("[{0}] {1}" -f $state, $symbol)
}

Write-Host '--- sceAgcDriver* ---'
foreach ($symbol in $ExpectedDriverSymbols) {
    $state = if ($driverPresent[$symbol]) { 'OK' } else { 'MISSING' }
    Write-Host ("[{0}] {1}" -f $state, $symbol)
}

$projectCount = @(
    $projectPresent.GetEnumerator() |
    Where-Object { $_.Value }
).Count

$driverCount = @(
    $driverPresent.GetEnumerator() |
    Where-Object { $_.Value }
).Count

$undefinedCount = $undefinedRelevant.Count

Write-Host ''
Write-Host "project_exact_count   = $projectCount / 8"
Write-Host "driver_exact_count    = $driverCount / 8"
Write-Host "undefined_AGC_count   = $undefinedCount"

if ($undefinedCount -ne 0) {
    throw "Stage 81 FAIL: existen $undefinedCount referencias undefined AGC/proyecto."
}

if ($projectCount -ne 8) {
    throw "Stage 81 FAIL: se esperaban 8 agcProject*V1 y se encontraron $projectCount."
}

if ($driverCount -ne 8) {
    throw "Stage 81 FAIL: se esperaban 8 sceAgcDriver* y se encontraron $driverCount."
}

Write-Host ''
Write-Host '[PASS] Los 16 símbolos requeridos están presentes y resueltos.'

Write-Section '8. Guardar contadores y evidencia'

$countsText = @"
Stage 81 FINAL audit counts

undefined_agc_project=$undefinedCount
agcProject_exact=$projectCount
sceAgcDriver_exact=$driverCount

expected_agcProject=8
expected_sceAgcDriver=8

agcProject_symbols:
$($ExpectedProjectSymbols -join [Environment]::NewLine)

sceAgcDriver_symbols:
$($ExpectedDriverSymbols -join [Environment]::NewLine)
"@

$countsPath = Join-Path $Output 'stage81_audit_counts.txt'
Set-Content -LiteralPath $countsPath -Value $countsText -Encoding ascii

Write-Host "OK: $countsPath"

Write-Section '9. Metadata FINAL derivada de la auditoría real'

$probePath = Join-Path $Output 'stage81_end_to_end_probe.o'
$linkedPath = Join-Path $Output 'stage81_linked.o'

$probeOk = (Test-Path -LiteralPath $probePath) -and
    ((Get-Item -LiteralPath $probePath).Length -gt 0)

$linkedOk = (Test-Path -LiteralPath $linkedPath) -and
    ((Get-Item -LiteralPath $linkedPath).Length -gt 0)

$conclusions = [ordered]@{
    PROJECT_CLIENT_COMPILED             = $probeOk
    PROJECT_AND_ABI_ARCHIVES_LINKED     = $linkedOk
    END_TO_END_RELOCATABLE_BUILT        = $linkedOk
    RECOVERED_SYMBOLS_RESOLVED          = ($undefinedCount -eq 0)
    PROJECT_WRAPPER_SYMBOLS_PRESENT     = ($projectCount -eq 8)
    SCE_DRIVER_SYMBOLS_PRESENT          = ($driverCount -eq 8)
    EXACT_REQUIRED_SYMBOL_SET_PRESENT   = (($projectCount -eq 8) -and ($driverCount -eq 8))
    PUBLIC_SEMANTIC_FIELD_NAMES_FINAL   = $false
    REAL_AGC_EXECUTION                  = $false
}

$report = [ordered]@{
    stage = 81
    version = 'final'
    generated_at = (Get-Date).ToString('o')
    previous_stage = 80

    execution_model = [ordered]@{
        orchestrator = 'PowerShell 7'
        build_environment = 'Ubuntu WSL'
        sdk = $Sdk
    }

    inputs = [ordered]@{
        stage79_abi_archive = "$Stage79\libSceAgcDriver_abi_v1.a"
        stage80_project_archive = "$Stage80\libagc_project_v1.a"
        stage80_project_header = "$Stage80\agc_project_v1.h"
    }

    outputs = [ordered]@{
        probe_source = 'stage81_end_to_end_probe.c'
        probe_object = 'stage81_end_to_end_probe.o'
        linked_object = 'stage81_linked.o'
        contract = 'END_TO_END_LINK_CONTRACT.txt'
        symbol_dump = 'stage81_nm_C.txt'
        undefined_dump = 'stage81_nm_undefined.txt'
        audit_counts = 'stage81_audit_counts.txt'
    }

    audit_counts = [ordered]@{
        undefined_agc_project = $undefinedCount
        agcProject_exact = $projectCount
        sceAgcDriver_exact = $driverCount
    }

    expected = [ordered]@{
        agcProject_exact = 8
        sceAgcDriver_exact = 8
        undefined_agc_project = 0
    }

    symbol_presence = [ordered]@{
        agcProject = $projectPresent
        sceAgcDriver = $driverPresent
    }

    conclusions = $conclusions
}

$json = $report | ConvertTo-Json -Depth 8

Set-Content -LiteralPath (Join-Path $Output 'STAGE81_REPORT.json') `
    -Value $json -Encoding utf8

Set-Content -LiteralPath (Join-Path $Output 'stage81_static.json') `
    -Value $json -Encoding utf8

Write-Host '[OK] STAGE81_REPORT.json'
Write-Host '[OK] stage81_static.json'

Write-Section '10. Verificación final de artefactos'

$expectedOutputs = @(
    'stage81_end_to_end_probe.c'
    'stage81_end_to_end_probe.o'
    'stage81_linked.o'
    'stage81_audit_counts.txt'
    'stage81_nm_C.txt'
    'stage81_nm_undefined.txt'
    'stage81_static.json'
    'STAGE81_REPORT.json'
    'END_TO_END_LINK_CONTRACT.txt'
)

foreach ($name in $expectedOutputs) {
    $path = Join-Path $Output $name

    if (-not (Test-Path -LiteralPath $path)) {
        throw "Artefacto faltante: $path"
    }

    $length = (Get-Item -LiteralPath $path).Length
    if ($length -le 0) {
        throw "Artefacto vacío: $path"
    }

    Write-Host ("[OK] {0} ({1} bytes)" -f $name, $length)
}

Write-Section '11. SHA256 final'

$hashes = [ordered]@{}

foreach ($name in $expectedOutputs) {
    $path = Join-Path $Output $name
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    $hashes[$name] = $hash
    Write-Host "$hash  $name"
}

$hashLines = foreach ($kv in $hashes.GetEnumerator()) {
    "$($kv.Value)  $($kv.Key)"
}

Set-Content -LiteralPath (Join-Path $Output 'stage81_sha256.txt') `
    -Value ($hashLines -join [Environment]::NewLine) `
    -Encoding ascii

Write-Host '[OK] stage81_sha256.txt'

Write-Section '12. Contrato de cierre'

$finalPass = (
    $probeOk -and
    $linkedOk -and
    ($undefinedCount -eq 0) -and
    ($projectCount -eq 8) -and
    ($driverCount -eq 8) -and
    $conclusions.EXACT_REQUIRED_SYMBOL_SET_PRESENT
)

if (-not $finalPass) {
    throw 'STAGE81_FINAL_CONTRACT=FAIL'
}

Write-Host 'STAGE81_FINAL_CONTRACT=PASS'
Write-Host 'PROJECT_CLIENT_COMPILED=True'
Write-Host 'PROJECT_AND_ABI_ARCHIVES_LINKED=True'
Write-Host 'END_TO_END_RELOCATABLE_BUILT=True'
Write-Host 'RECOVERED_SYMBOLS_RESOLVED=True'
Write-Host 'PROJECT_WRAPPER_SYMBOLS_PRESENT=True'
Write-Host 'SCE_DRIVER_SYMBOLS_PRESENT=True'
Write-Host 'EXACT_REQUIRED_SYMBOL_SET_PRESENT=True'
Write-Host 'PUBLIC_SEMANTIC_FIELD_NAMES_FINAL=False'
Write-Host 'REAL_AGC_EXECUTION=False'
Write-Host ''
Write-Host "Resultados: $Output"
Write-Host ''
Write-Host 'Stage 81 queda cerrada en cuanto este script alcance STAGE81_FINAL_CONTRACT=PASS.'
