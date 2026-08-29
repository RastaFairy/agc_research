$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$StageDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Previous = 'D:\agc_work\stage79_results'
$Output = 'D:\agc_work\stage80_results'
$Sprx = 'D:\agc_work\sce_stubs\libSceAgcDriver.sprx'
$NidDb = 'D:\sdk-master\sce_stubs\aerolib.csv'
$Sdk = '/opt/ps5-payload-sdk'

$PreviousWsl = '/mnt/d/agc_work/stage79_results'
$OutputWsl = '/mnt/d/agc_work/stage80_results'
$SprxWsl = '/mnt/d/agc_work/sce_stubs/libSceAgcDriver.sprx'
$NidDbWsl = '/mnt/d/sdk-master/sce_stubs/aerolib.csv'
$StageWsl = '/mnt/d/agc_ps5_stage80'

Write-Host '============================================'
Write-Host 'AGC PS5 Stage 80 - Project Library ABI v1 Integration Build'
Write-Host '============================================'
Write-Host "[INFO] StageDir       = $StageDir"
Write-Host "[INFO] SPRX           = $Sprx"
Write-Host "[INFO] NID DB         = $NidDb"
Write-Host "[INFO] Previous stage = $Previous"
Write-Host "[INFO] Output         = $Output"
Write-Host "[INFO] SDK            = $Sdk"

function Invoke-WSLScript {
    param([Parameter(Mandatory)][string]$Body)
    Write-Host '[WSL] set -e'
    Write-Host $Body
    & wsl.exe bash -lc "set -e; $Body"
    $code = $LASTEXITCODE
    if ($code -ne 0) { throw "WSL command failed with exit code $code." }
}

$projectHeader = @'
#ifndef AGC_PROJECT_V1_H
#define AGC_PROJECT_V1_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ABI v1 record recovered by static analysis.
 * Exact public semantic field names are intentionally not claimed.
 */
typedef struct AgcSubmitCommandBufferArgsV1 {
    uint64_t field_00;
    uint32_t field_08;
    uint8_t  field_0c;
} AgcSubmitCommandBufferArgsV1;

typedef void *AgcContextV1;

/* Direct ABI v1 entrypoint candidate. */
int agcProjectSubmitCommandBufferV1(
    AgcContextV1 context,
    const AgcSubmitCommandBufferArgsV1 *args);

/* Wrapper entrypoints: the recovered wrapper ABI takes one caller argument. */
int agcProjectSubmitDcbV1(void *args);
int agcProjectAgrSubmitDcbV1(void *args);

/* Multi entrypoint ABI candidate recovered from machine-code register usage. */
int agcProjectSubmitMultiCommandBuffersV1(
    AgcContextV1 context,
    const uint64_t *field_00_array,
    const uint32_t *field_08_array,
    uint32_t count);

int agcProjectSubmitAcbV1(void *args);
int agcProjectSubmitMultiAcbsV1(void *args);
int agcProjectSubmitMultiDcbsV1(void *args);
int agcProjectAgrSubmitMultiDcbsV1(void *args);

/* Low-level recovered symbols. */
int sceAgcDriverSubmitCommandBuffer(AgcContextV1, const AgcSubmitCommandBufferArgsV1 *);
int sceAgcDriverSubmitDcb(void *args);
int sceAgcDriverAgrSubmitDcb(void *args);
int sceAgcDriverSubmitMultiCommandBuffers(AgcContextV1, const uint64_t *, const uint32_t *, uint32_t);
int sceAgcDriverSubmitAcb(void *args);
int sceAgcDriverSubmitMultiAcbs(void *args);
int sceAgcDriverSubmitMultiDcbs(void *args);
int sceAgcDriverAgrSubmitMultiDcbs(void *args);

#ifdef __cplusplus
}
#endif

#endif
'@

$projectSource = @'
#include "agc_project_v1.h"

int agcProjectSubmitCommandBufferV1(
    AgcContextV1 context,
    const AgcSubmitCommandBufferArgsV1 *args)
{
    return sceAgcDriverSubmitCommandBuffer(context, args);
}

int agcProjectSubmitDcbV1(void *args)
{
    return sceAgcDriverSubmitDcb(args);
}

int agcProjectAgrSubmitDcbV1(void *args)
{
    return sceAgcDriverAgrSubmitDcb(args);
}

int agcProjectSubmitMultiCommandBuffersV1(
    AgcContextV1 context,
    const uint64_t *field_00_array,
    const uint32_t *field_08_array,
    uint32_t count)
{
    return sceAgcDriverSubmitMultiCommandBuffers(
        context, field_00_array, field_08_array, count);
}

int agcProjectSubmitAcbV1(void *args)
{
    return sceAgcDriverSubmitAcb(args);
}

int agcProjectSubmitMultiAcbsV1(void *args)
{
    return sceAgcDriverSubmitMultiAcbs(args);
}

int agcProjectSubmitMultiDcbsV1(void *args)
{
    return sceAgcDriverSubmitMultiDcbs(args);
}

int agcProjectAgrSubmitMultiDcbsV1(void *args)
{
    return sceAgcDriverAgrSubmitMultiDcbs(args);
}
'@

$probeSource = @'
#include "agc_project_v1.h"

int stage80_link_probe(AgcContextV1 context, AgcSubmitCommandBufferArgsV1 *args)
{
    int rc = agcProjectSubmitCommandBufferV1(context, args);
    rc += agcProjectSubmitDcbV1(args);
    rc += agcProjectAgrSubmitDcbV1(args);
    rc += agcProjectSubmitMultiCommandBuffersV1(
        context, &args->field_00, &args->field_08, 1);
    return rc;
}
'@

$contract = @'
AGC PS5 Stage 80 - Project Library ABI v1 Integration Contract

PURPOSE
=======
Package the recovered ABI v1 into a project-facing static library.

PROVEN IN PREVIOUS STAGES
=========================
- SubmitCommandBuffer uses RDI=context and RSI=args.
- args fields are accessed at +0x00 (8 bytes), +0x08 (4 bytes), +0x0C (1 byte).
- SubmitMultiCommandBuffers uses context + separate 64-bit and 32-bit arrays + count-shaped control flow.
- global_context+0xA0 is a table-bound/count-like value.
- global_context+0xA4 is used as a dispatch index.
- dispatch entry stride is 0x78.
- SubmitDcb/AgrSubmitDcb wrappers redirect their single caller argument into RSI while supplying an internal context in RDI.

INTENTIONAL LIMITATIONS
=======================
- field_00/field_08/field_0c public semantic names are not claimed.
- exact sizeof(struct) is not claimed beyond the observed bytes.
- function-pointer value origin is not proven.
- runtime AGC execution is not performed by this stage.

BUILD PRODUCTS
==============
- agc_project_v1.h
- agc_project_v1.c
- agc_project_v1.o
- libagc_project_v1.a
- stage80_link_probe.c
- stage80_link_probe.o
- stage80_static.json
- STAGE80_REPORT.json
'@

New-Item -ItemType Directory -Force -Path $Output | Out-Null
Set-Content -LiteralPath (Join-Path $Output 'agc_project_v1.h') -Value $projectHeader -NoNewline -Encoding ascii
Set-Content -LiteralPath (Join-Path $Output 'agc_project_v1.c') -Value $projectSource -NoNewline -Encoding ascii
Set-Content -LiteralPath (Join-Path $Output 'stage80_link_probe.c') -Value $probeSource -NoNewline -Encoding ascii
Set-Content -LiteralPath (Join-Path $Output 'ABI_V1_PROJECT_CONTRACT.txt') -Value $contract -NoNewline -Encoding ascii

Write-Host ''
Write-Host '==> Preparar workspace Linux'

Invoke-WSLScript @"
rm -rf '/tmp/agc_stage80'
mkdir -p '/tmp/agc_stage80'
mkdir -p '$OutputWsl'
test -f '$SprxWsl'
test -f '$NidDbWsl'
test -d '$PreviousWsl'
test -f '$PreviousWsl/libSceAgcDriver_abi_v1.a'
test -f '$OutputWsl/agc_project_v1.h'
test -f '$OutputWsl/agc_project_v1.c'
test -f '$OutputWsl/stage80_link_probe.c'
echo 'workspace=OK'
"@

Write-Host ''
Write-Host '==> Verificar toolchain'
Invoke-WSLScript @"
test -x '$Sdk/bin/prospero-clang'
test -x '$Sdk/bin/prospero-nm'
test -x '$Sdk/bin/prospero-lld'
command -v llvm-ar >/dev/null
echo '--- prospero-clang ---'
'$Sdk/bin/prospero-clang' --version
echo '--- llvm-ar ---'
llvm-ar --version | head -n 1
"@

Write-Host ''
Write-Host '==> Compilar libreria de proyecto ABI v1'
Invoke-WSLScript @"
cp '$OutputWsl/agc_project_v1.h' '/tmp/agc_stage80/agc_project_v1.h'
cp '$OutputWsl/agc_project_v1.c' '/tmp/agc_stage80/agc_project_v1.c'
cp '$OutputWsl/stage80_link_probe.c' '/tmp/agc_stage80/stage80_link_probe.c'
'$Sdk/bin/prospero-clang' \
    -target x86_64-sie-ps5 \
    -ffreestanding -fno-builtin -nostdlib -fPIC -fno-plt \
    -fno-stack-protector -Wall -Wextra -Werror \
    -fvisibility=hidden \
    -I'/tmp/agc_stage80' \
    -c '/tmp/agc_stage80/agc_project_v1.c' \
    -o '$OutputWsl/agc_project_v1.o'
llvm-ar rcs '$OutputWsl/libagc_project_v1.a' '$OutputWsl/agc_project_v1.o'
'$Sdk/bin/prospero-clang' \
    -target x86_64-sie-ps5 \
    -ffreestanding -fno-builtin -nostdlib -fPIC -fno-plt \
    -fno-stack-protector -Wall -Wextra -Werror \
    -fvisibility=hidden \
    -I'/tmp/agc_stage80' \
    -c '/tmp/agc_stage80/stage80_link_probe.c' \
    -o '$OutputWsl/stage80_link_probe.o'
"@

Write-Host ''
Write-Host '==> Auditar simbolos y ABI de la biblioteca'
Invoke-WSLScript @"
echo '--- project library symbols ---'
'$Sdk/bin/prospero-nm' -C '$OutputWsl/libagc_project_v1.a'
echo '--- object undefined references ---'
'$Sdk/bin/prospero-nm' -u '$OutputWsl/agc_project_v1.o'
echo '--- probe undefined references ---'
'$Sdk/bin/prospero-nm' -u '$OutputWsl/stage80_link_probe.o'
echo '--- archive members ---'
llvm-ar t '$OutputWsl/libagc_project_v1.a'
"@

$staticJsonPy = @'
import json, os, hashlib

out = os.environ["STAGE80_OUT"]
prev = os.environ["STAGE80_PREV"]

def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()

files = {}
for name in [
    "agc_project_v1.h",
    "agc_project_v1.c",
    "agc_project_v1.o",
    "libagc_project_v1.a",
    "stage80_link_probe.c",
    "stage80_link_probe.o",
    "ABI_V1_PROJECT_CONTRACT.txt",
]:
    p = os.path.join(out, name)
    files[name] = {"exists": os.path.isfile(p), "sha256": sha(p) if os.path.isfile(p) else None}

report = {
    "stage": 80,
    "previous_stage": 79,
    "previous_library": os.path.join(prev, "libSceAgcDriver_abi_v1.a"),
    "project_library": os.path.join(out, "libagc_project_v1.a"),
    "files": files,
    "conclusions": {
        "PROJECT_STATIC_LIBRARY_BUILT": files["libagc_project_v1.a"]["exists"],
        "PROJECT_HEADER_BUILT": files["agc_project_v1.h"]["exists"],
        "PROJECT_SOURCE_BUILT": files["agc_project_v1.c"]["exists"],
        "ABI_LINK_PROBE_COMPILED": files["stage80_link_probe.o"]["exists"],
        "PUBLIC_SEMANTIC_FIELD_NAMES_FINAL": False,
        "REAL_AGC_EXECUTION": False,
    },
}
with open(os.path.join(out, "stage80_static.json"), "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2)
with open(os.path.join(out, "STAGE80_REPORT.json"), "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2)
print(os.path.join(out, "STAGE80_REPORT.json"))
'@

Set-Content -LiteralPath (Join-Path $Output '_stage80_make_report.py') -Value $staticJsonPy -NoNewline -Encoding ascii

Write-Host ''
Write-Host '==> Generar reporte y verificar artefactos'
Invoke-WSLScript @"
cp '$OutputWsl/_stage80_make_report.py' '/tmp/agc_stage80/_stage80_make_report.py'
STAGE80_OUT='$OutputWsl' STAGE80_PREV='$PreviousWsl' python3 '/tmp/agc_stage80/_stage80_make_report.py'
rm -f '$OutputWsl/_stage80_make_report.py'
test -f '$OutputWsl/stage80_static.json'
test -f '$OutputWsl/STAGE80_REPORT.json'
test -f '$OutputWsl/libagc_project_v1.a'
test -f '$OutputWsl/agc_project_v1.h'
test -f '$OutputWsl/agc_project_v1.c'
test -f '$OutputWsl/agc_project_v1.o'
test -f '$OutputWsl/stage80_link_probe.o'
echo '--- output files ---'
find '$OutputWsl' -maxdepth 1 -type f -print | sort
"@

Write-Host ''
Write-Host '==> Hash artefactos principales'
Invoke-WSLScript @"
sha256sum \
    '$OutputWsl/stage80_static.json' \
    '$OutputWsl/STAGE80_REPORT.json' \
    '$OutputWsl/agc_project_v1.h' \
    '$OutputWsl/agc_project_v1.c' \
    '$OutputWsl/libagc_project_v1.a' \
    '$OutputWsl/stage80_link_probe.o'
"@

Write-Host ''
Write-Host '============================================'
Write-Host 'Stage 80 completado'
Write-Host '============================================'
Write-Host 'PROJECT_STATIC_LIBRARY_BUILT = True'
Write-Host 'PROJECT_HEADER_BUILT = True'
Write-Host 'PROJECT_SOURCE_BUILT = True'
Write-Host 'ABI_LINK_PROBE_COMPILED = True'
Write-Host 'PUBLIC_SEMANTIC_FIELD_NAMES_FINAL = False'
Write-Host 'REAL_AGC_EXECUTION = False'
Write-Host ''
Write-Host 'Resultados:'
Write-Host '  D:\agc_work\stage80_results'
Write-Host ''
Write-Host 'Artefactos principales:'
Write-Host '  D:\agc_work\stage80_results\agc_project_v1.h'
Write-Host '  D:\agc_work\stage80_results\agc_project_v1.c'
Write-Host '  D:\agc_work\stage80_results\libagc_project_v1.a'
Write-Host '  D:\agc_work\stage80_results\STAGE80_REPORT.json'
