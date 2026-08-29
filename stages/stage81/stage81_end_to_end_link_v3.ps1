$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Stage79    = 'D:\agc_work\stage79_results'
$Stage80    = 'D:\agc_work\stage80_results'
$Output     = 'D:\agc_work\stage81_results'
$Sdk        = '/opt/ps5-payload-sdk'
$Stage79Wsl = '/mnt/d/agc_work/stage79_results'
$Stage80Wsl = '/mnt/d/agc_work/stage80_results'
$OutputWsl  = '/mnt/d/agc_work/stage81_results'

Write-Host '============================================'
Write-Host 'AGC PS5 Stage 81 v3 - End-to-End Link / ABI Audit'
Write-Host '============================================'
Write-Host "  Stage79  = $Stage79"
Write-Host "  Stage80  = $Stage80"
Write-Host "  Output   = $Output"
Write-Host ''
Write-Host 'Correcciones v3:'
Write-Host '  - Sin variables Bash en wsl -lc: todo expandido desde PS'
Write-Host '  - Patron sceAgcDriver usa [TtWw] (stubs son tipo W weak)'
Write-Host '  - Metadata y SHA256 en PowerShell puro (cero Python/WSL)'
Write-Host ''

function Invoke-WSLScript {
    param([Parameter(Mandatory)][string]$Body)
    & wsl.exe bash -lc "set -e; $Body"
    if ($LASTEXITCODE -ne 0) { throw "WSL failed (exit $LASTEXITCODE)." }
}

# Ejecuta exactamente una linea bash, devuelve stdout como string limpio
function Invoke-WSLCapture {
    param([Parameter(Mandatory)][string]$OneLiner)
    $out = & wsl.exe bash -lc $OneLiner
    if ($LASTEXITCODE -ne 0) { throw "WSL capture failed (exit $LASTEXITCODE). cmd: $OneLiner" }
    return ($out | Out-String).Trim()
}

# ─── Fuente del probe (single-quoted = sin expansion PS) ─────────────────────
$probeSource = @'
#include "agc_project_v1.h"

/* Stage 81 probe: llama las 8 funciones agcProject*V1.
   No se ejecuta; la prueba es que el linkado resuelva todos los simbolos. */
int stage81_end_to_end_probe(
    AgcContextV1               context,
    AgcSubmitCommandBufferArgsV1 *args,
    const uint64_t             *field00_array,
    const uint32_t             *field08_array)
{
    int rc = 0;
    rc += agcProjectSubmitCommandBufferV1(context, args);
    rc += agcProjectSubmitDcbV1(args);
    rc += agcProjectAgrSubmitDcbV1(args);
    rc += agcProjectSubmitMultiCommandBuffersV1(context, field00_array, field08_array, 1);
    rc += agcProjectSubmitAcbV1(args);
    rc += agcProjectSubmitMultiAcbsV1(args);
    rc += agcProjectSubmitMultiDcbsV1(args);
    rc += agcProjectAgrSubmitMultiDcbsV1(args);
    return rc;
}
'@

$contract = @'
AGC PS5 Stage 81 v3 - End-to-End Project Link / ABI Resolution Audit

INPUTS
======
- Stage 79: libSceAgcDriver_abi_v1.a  (ABI stubs, simbolos tipo W weak)
- Stage 80: libagc_project_v1.a / agc_project_v1.h

PRUEBA
======
- Las 8 entradas agcProject*V1 compilan sin warnings.
- El objeto enlazado resuelve todos los simbolos sceAgcDriver* / agcProject*.
- 0 referencias sin resolver al final del link -r.
- 8 simbolos W/T sceAgcDriver* presentes (stubs ABI).
- 8 simbolos T agcProject*V1 presentes (wrappers proyecto).

METODO DE AUDITORIA (v3)
=========================
Cada contador se calcula en una llamada wsl.exe bash -lc individual,
capturada en variable PS. Sin variables Bash intermedias en el script.
awk siempre sale con exit 0: seguro con cualquier conteo.
Patron sceAgcDriver: [TtWw] para cubrir simbolos weak (W) del stub ABI.
Metadata y SHA256 generados en PowerShell puro, sin Python ni heredocs WSL.

NO DEMOSTRADO
=============
- Ejecucion AGC real en GPU.
- Nombres semanticos publicos de field_00/field_08/field_0c.
'@

New-Item -ItemType Directory -Force -Path $Output | Out-Null
Set-Content -LiteralPath "$Output\stage81_end_to_end_probe.c"   -Value $probeSource -NoNewline -Encoding ascii
Set-Content -LiteralPath "$Output\END_TO_END_LINK_CONTRACT.txt" -Value $contract   -NoNewline -Encoding ascii
Write-Host '[INFO] Probe source + contract escritos.'

# ─── 1. Workspace ────────────────────────────────────────────────────────────
Write-Host ''
Write-Host '==> 1. Verificar workspace'
Invoke-WSLScript @"
mkdir -p '$OutputWsl'
test -f '$Stage79Wsl/libSceAgcDriver_abi_v1.a' || { echo MISS:libSceAgcDriver_abi_v1.a >&2; exit 1; }
test -f '$Stage80Wsl/libagc_project_v1.a'       || { echo MISS:libagc_project_v1.a      >&2; exit 1; }
test -f '$Stage80Wsl/agc_project_v1.h'           || { echo MISS:agc_project_v1.h         >&2; exit 1; }
test -f '$OutputWsl/stage81_end_to_end_probe.c'  || { echo MISS:probe.c                  >&2; exit 1; }
echo workspace=OK
"@

# ─── 2. Toolchain ────────────────────────────────────────────────────────────
Write-Host ''
Write-Host '==> 2. Verificar toolchain'
Invoke-WSLScript @"
test -x '$Sdk/bin/prospero-clang' || { echo MISS:prospero-clang >&2; exit 1; }
test -x '$Sdk/bin/prospero-nm'    || { echo MISS:prospero-nm    >&2; exit 1; }
test -x '$Sdk/bin/prospero-lld'   || { echo MISS:prospero-lld   >&2; exit 1; }
'$Sdk/bin/prospero-clang' --version | head -n1
'$Sdk/bin/prospero-lld'   --version | head -n1
echo toolchain=OK
"@

# ─── 3. Compilar probe ───────────────────────────────────────────────────────
Write-Host ''
Write-Host '==> 3. Compilar stage81_end_to_end_probe.c'
Invoke-WSLScript @"
rm -rf /tmp/agc_s81 && mkdir -p /tmp/agc_s81
cp '$Stage80Wsl/agc_project_v1.h' /tmp/agc_s81/agc_project_v1.h
'$Sdk/bin/prospero-clang' -target x86_64-sie-ps5 -ffreestanding -fno-builtin -nostdlib -fPIC -fno-plt -fno-stack-protector -Wall -Wextra -Werror -fvisibility=hidden -I/tmp/agc_s81 -c '$OutputWsl/stage81_end_to_end_probe.c' -o '$OutputWsl/stage81_end_to_end_probe.o'
test -s '$OutputWsl/stage81_end_to_end_probe.o' || { echo 'FAIL: probe.o vacio' >&2; exit 1; }
echo compile=OK
"@

# ─── 4. Link ─────────────────────────────────────────────────────────────────
Write-Host ''
Write-Host '==> 4. Link: probe.o + libagc_project_v1.a + libSceAgcDriver_abi_v1.a'
Invoke-WSLScript @"
'$Sdk/bin/prospero-lld' -r -o '$OutputWsl/stage81_linked.o' '$OutputWsl/stage81_end_to_end_probe.o' '$Stage80Wsl/libagc_project_v1.a' '$Stage79Wsl/libSceAgcDriver_abi_v1.a'
test -s '$OutputWsl/stage81_linked.o' || { echo 'FAIL: linked.o vacio' >&2; exit 1; }
echo link=OK
"@

# ─── 5. Display simbolos (informativo, no bloquea) ───────────────────────────
Write-Host ''
Write-Host '==> 5. Simbolos del objeto enlazado (informativo)'
Invoke-WSLScript @"
echo '--- undefined ---'
'$Sdk/bin/prospero-nm' -u '$OutputWsl/stage81_linked.o' || true
echo '--- sceAgcDriver ---'
'$Sdk/bin/prospero-nm' -C '$OutputWsl/stage81_linked.o' | grep sceAgcDriver || true
echo '--- agcProject ---'
'$Sdk/bin/prospero-nm' -C '$OutputWsl/stage81_linked.o' | grep agcProject || true
"@

# ─── 6. AUDITORIA: awk single-line, captura en PS, validacion en PS ──────────
Write-Host ''
Write-Host '==> 6. Auditoria con awk (single-line per call, sin variables Bash)'

# Cmd strings pre-expandidas: PS expande $Sdk y $OutputWsl antes de llamar a bash
$cmdUnresolved = "'$Sdk/bin/prospero-nm' -u '$OutputWsl/stage81_linked.o' | awk '/sceAgcDriver|agcProject/{ n++ } END{ print n+0 }'"
$cmdLower      = "'$Sdk/bin/prospero-nm' -C '$OutputWsl/stage81_linked.o' | awk '/[[:space:]][TtWw][[:space:]]sceAgcDriver/{ n++ } END{ print n+0 }'"
$cmdProject    = "'$Sdk/bin/prospero-nm' -C '$OutputWsl/stage81_linked.o' | awk '/[[:space:]][Tt][[:space:]]agcProject/{ n++ } END{ print n+0 }'"

$nUnresolved = [int](Invoke-WSLCapture $cmdUnresolved)
$nLower      = [int](Invoke-WSLCapture $cmdLower)
$nProject    = [int](Invoke-WSLCapture $cmdProject)

Write-Host "  unresolved_agc_project  = $nUnresolved"
Write-Host "  sceAgcDriver_[TWw]_syms = $nLower"
Write-Host "  agcProject_T_syms       = $nProject"

if ($nUnresolved -ne 0) { throw "FAIL: $nUnresolved simbolos sin resolver (esperado 0)" }
if ($nLower -lt 8)      { throw "FAIL: sceAgcDriver symbols = $nLower (esperado >= 8)" }
if ($nProject -lt 8)    { throw "FAIL: agcProject symbols = $nProject (esperado >= 8)" }

# Escribir counts desde PS (sin WSL ni heredoc)
@"
audit_unresolved=$nUnresolved
audit_lower=$nLower
audit_project=$nProject
"@ | Set-Content -LiteralPath "$Output\stage81_audit_counts.txt" -Encoding ascii

Write-Host 'AUDIT PASSED'

# ─── 7. Metadata en PowerShell puro (sin Python, sin WSL) ────────────────────
Write-Host ''
Write-Host '==> 7. Generar metadata (PowerShell puro)'

$probeOk  = (Test-Path "$Output\stage81_end_to_end_probe.o") -and ((Get-Item "$Output\stage81_end_to_end_probe.o").Length -gt 0)
$linkedOk = (Test-Path "$Output\stage81_linked.o")           -and ((Get-Item "$Output\stage81_linked.o").Length -gt 0)

$conclusions = [ordered]@{
    PROJECT_CLIENT_COMPILED         = $probeOk
    PROJECT_AND_ABI_ARCHIVES_LINKED = $linkedOk
    END_TO_END_RELOCATABLE_BUILT    = $linkedOk
    RECOVERED_SYMBOLS_RESOLVED      = ($nUnresolved -eq 0)
    PROJECT_WRAPPER_SYMBOLS_PRESENT = ($nProject -ge 8)
    SCE_DRIVER_SYMBOLS_PRESENT      = ($nLower -ge 8)
    PUBLIC_SEMANTIC_FIELD_NAMES_FINAL = $false
    REAL_AGC_EXECUTION              = $false
}

$report = [ordered]@{
    stage          = 81
    version        = 3
    previous_stage = 80
    inputs = [ordered]@{
        project_archive = "$Stage80\libagc_project_v1.a"
        abi_archive     = "$Stage79\libSceAgcDriver_abi_v1.a"
    }
    audit_counts = [ordered]@{
        unresolved_agc_project_symbols = $nUnresolved
        sceAgcDriver_defined_symbols   = $nLower
        agcProject_T_symbols           = $nProject
    }
    conclusions = $conclusions
}

$json = $report | ConvertTo-Json -Depth 5
$json | Set-Content -LiteralPath "$Output\STAGE81_REPORT.json"   -Encoding ascii
$json | Set-Content -LiteralPath "$Output\stage81_static.json"   -Encoding ascii
Write-Host 'Conclusiones:'
foreach ($k in $conclusions.Keys) { Write-Host "  $k = $($conclusions[$k])" }

# ─── 8. Verificar artefactos ─────────────────────────────────────────────────
Write-Host ''
Write-Host '==> 8. Verificar artefactos'
@(
    'stage81_end_to_end_probe.c'
    'stage81_end_to_end_probe.o'
    'stage81_linked.o'
    'stage81_audit_counts.txt'
    'stage81_static.json'
    'STAGE81_REPORT.json'
    'END_TO_END_LINK_CONTRACT.txt'
) | ForEach-Object {
    $p = Join-Path $Output $_
    if ((Test-Path $p) -and (Get-Item $p).Length -gt 0) {
        Write-Host "  [OK] $_"
    } else {
        throw "FAIL: artefacto faltante o vacio: $_"
    }
}

# ─── 9. SHA256 en PowerShell puro ────────────────────────────────────────────
Write-Host ''
Write-Host '==> 9. SHA256'
@(
    'stage81_end_to_end_probe.c'
    'stage81_end_to_end_probe.o'
    'stage81_linked.o'
    'stage81_audit_counts.txt'
    'stage81_static.json'
    'STAGE81_REPORT.json'
    'END_TO_END_LINK_CONTRACT.txt'
) | ForEach-Object {
    $p = Join-Path $Output $_
    $h = (Get-FileHash $p -Algorithm SHA256).Hash.ToLower()
    Write-Host "  $h  $_"
}

# ─── Resumen ──────────────────────────────────────────────────────────────────
Write-Host ''
Write-Host '============================================'
Write-Host "Stage 81 v3 completado OK"
Write-Host '============================================'
Write-Host "  unresolved = $nUnresolved  (target: 0)"
Write-Host "  sceAgcDriver symbols = $nLower  (target: >=8)"
Write-Host "  agcProject symbols   = $nProject  (target: >=8)"
Write-Host ''
Write-Host "Report: $Output\STAGE81_REPORT.json"
Write-Host ''
Write-Host 'Pendiente:'
Write-Host '  PUBLIC_SEMANTIC_FIELD_NAMES_FINAL = False'
Write-Host '  REAL_AGC_EXECUTION = False'
