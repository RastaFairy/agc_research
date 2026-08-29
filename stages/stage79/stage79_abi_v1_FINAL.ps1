$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$StageDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$StageName  = 'stage79'
$WorkRoot   = 'D:\agc_work'
$Sprx       = Join-Path $WorkRoot 'sce_stubs\libSceAgcDriver.sprx'
$NidDb      = 'D:\sdk-master\sce_stubs\aerolib.csv'
$Previous   = Join-Path $WorkRoot 'stage78_results'
$Output     = Join-Path $WorkRoot 'stage79_results'
$SdkWsl     = '/opt/ps5-payload-sdk'
$SprxWsl    = '/mnt/d/agc_work/sce_stubs/libSceAgcDriver.sprx'
$NidDbWsl   = '/mnt/d/sdk-master/sce_stubs/aerolib.csv'
$PrevWsl    = '/mnt/d/agc_work/stage78_results'
$OutputWsl  = '/mnt/d/agc_work/stage79_results'
$TmpWsl     = '/tmp/agc_stage79'

Write-Host '============================================'
Write-Host 'AGC PS5 Stage 79 - ABI v1 Library Build / Contract Audit'
Write-Host '============================================'
Write-Host "[INFO] StageDir       = $StageDir"
Write-Host "[INFO] SPRX           = $Sprx"
Write-Host "[INFO] NID DB         = $NidDb"
Write-Host "[INFO] Previous stage = $Previous"
Write-Host "[INFO] Output         = $Output"
Write-Host "[INFO] SDK            = $SdkWsl"

if (-not (Test-Path -LiteralPath $Sprx)) { throw "SPRX not found: $Sprx" }
if (-not (Test-Path -LiteralPath $NidDb)) { throw "NID DB not found: $NidDb" }
if (-not (Test-Path -LiteralPath $Previous)) { throw "Previous stage not found: $Previous" }
New-Item -ItemType Directory -Force -Path $Output | Out-Null

$Header = @'
#ifndef AGC_ABI_V1_H
#define AGC_ABI_V1_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Stage 79 ABI contract derived from static machine-code evidence.
 * Semantic names are intentionally conservative.
 */
typedef struct SceAgcSubmitCommandBufferArgs {
    uint64_t field_00; /* observed 8-byte load */
    uint32_t field_08; /* observed 4-byte load */
    uint8_t  field_0c; /* observed 1-byte load */
} SceAgcSubmitCommandBufferArgs;

_Static_assert(offsetof(SceAgcSubmitCommandBufferArgs, field_00) == 0x00, "field_00 offset");
_Static_assert(offsetof(SceAgcSubmitCommandBufferArgs, field_08) == 0x08, "field_08 offset");
_Static_assert(offsetof(SceAgcSubmitCommandBufferArgs, field_0c) == 0x0C, "field_0c offset");
_Static_assert(sizeof(SceAgcSubmitCommandBufferArgs) == 0x10, "ABI v1 packed size/alignment");

/* Direct ABI-compatible candidates proven in stages 52-56. */
int sceAgcDriverSubmitCommandBuffer(void *context,
                                     const SceAgcSubmitCommandBufferArgs *args);
int sceAgcDriverSubmitDcb(void *dcb_context,
                          const SceAgcSubmitCommandBufferArgs *args);
int sceAgcDriverAgrSubmitDcb(void *agr_context,
                             const SceAgcSubmitCommandBufferArgs *args);

/* Multi-command-buffer ABI candidate from stage 55. */
int sceAgcDriverSubmitMultiCommandBuffers(void *context,
                                          const uint64_t *field00_array,
                                          const uint32_t *field08_array,
                                          uint32_t count);

/* Additional family exports established in stage 50. */
int sceAgcDriverSubmitMultiDcbs(void *context, const void *args);
int sceAgcDriverAgrSubmitMultiDcbs(void *context, const void *args);
int sceAgcDriverSubmitAcb(void *context, const void *args);
int sceAgcDriverSubmitMultiAcbs(void *context, const void *args);

/* Known NIDs from aerolib.csv / Stage 50 extraction. */
#define SCEAGCDRIVER_NID_SubmitDcb                "UglJIZjGssM"
#define SCEAGCDRIVER_NID_AgrSubmitDcb             "AhGvpITrf4M"
#define SCEAGCDRIVER_NID_SubmitAcb                "gSRnr79F8tQ"
#define SCEAGCDRIVER_NID_SubmitCommandBuffer      "b4fpgH5ZXxQ"
#define SCEAGCDRIVER_NID_SubmitMultiCommandBuffers "Fj7r9EHzF38"
#define SCEAGCDRIVER_NID_SubmitMultiDcbs         "6UzEidRZwkg"
#define SCEAGCDRIVER_NID_AgrSubmitMultiDcbs      "+T8Xo6LtFJI"
#define SCEAGCDRIVER_NID_SubmitMultiAcbs         "HF3YllT3mXU"

#ifdef __cplusplus
}
#endif

#endif /* AGC_ABI_V1_H */
'@

$Source = @'
#include "agc_abi_v1.h"

/*
 * ABI v1 build layer.
 * These are intentionally weak forwarding symbols. A final PS5 import/stub
 * layer can override them with the real NID-backed implementation.
 */
#if defined(__GNUC__)
#define AGC_WEAK __attribute__((weak))
#else
#define AGC_WEAK
#endif

AGC_WEAK int sceAgcDriverSubmitCommandBuffer(void *context,
                                              const SceAgcSubmitCommandBufferArgs *args)
{
    (void)context;
    (void)args;
    return -1;
}

AGC_WEAK int sceAgcDriverSubmitDcb(void *dcb_context,
                                   const SceAgcSubmitCommandBufferArgs *args)
{
    return sceAgcDriverSubmitCommandBuffer(dcb_context, args);
}

AGC_WEAK int sceAgcDriverAgrSubmitDcb(void *agr_context,
                                      const SceAgcSubmitCommandBufferArgs *args)
{
    return sceAgcDriverSubmitCommandBuffer(agr_context, args);
}

AGC_WEAK int sceAgcDriverSubmitMultiCommandBuffers(void *context,
                                                   const uint64_t *field00_array,
                                                   const uint32_t *field08_array,
                                                   uint32_t count)
{
    (void)context;
    (void)field00_array;
    (void)field08_array;
    (void)count;
    return -1;
}

AGC_WEAK int sceAgcDriverSubmitMultiDcbs(void *context, const void *args)
{
    (void)context;
    (void)args;
    return -1;
}

AGC_WEAK int sceAgcDriverAgrSubmitMultiDcbs(void *context, const void *args)
{
    (void)context;
    (void)args;
    return -1;
}

AGC_WEAK int sceAgcDriverSubmitAcb(void *context, const void *args)
{
    (void)context;
    (void)args;
    return -1;
}

AGC_WEAK int sceAgcDriverSubmitMultiAcbs(void *context, const void *args)
{
    (void)context;
    (void)args;
    return -1;
}
'@

$Probe = @'
#include "agc_abi_v1.h"
#include <stdint.h>

_Static_assert(sizeof(SceAgcSubmitCommandBufferArgs) == 16, "expected ABI v1 size");

int stage79_probe(void *ctx, const SceAgcSubmitCommandBufferArgs *args)
{
    return sceAgcDriverSubmitCommandBuffer(ctx, args);
}

int stage79_probe_dcb(void *ctx, const SceAgcSubmitCommandBufferArgs *args)
{
    return sceAgcDriverSubmitDcb(ctx, args);
}

int stage79_probe_multi(void *ctx,
                        const uint64_t *a0,
                        const uint32_t *a8,
                        uint32_t count)
{
    return sceAgcDriverSubmitMultiCommandBuffers(ctx, a0, a8, count);
}
'@

$Contract = @'
AGC PS5 Stage 79 - ABI v1 Contract

=== PROVEN ARGUMENT ABI ===
sceAgcDriverSubmitCommandBuffer
  RDI = context
  RSI = args
  return = EAX

args observed loads:
  +0x00 = 8 bytes
  +0x08 = 4 bytes
  +0x0C = 1 byte

ABI v1 C representation uses the natural 16-byte struct footprint for x86-64:
  uint64_t field_00;
  uint32_t field_08;
  uint8_t  field_0c;
  trailing alignment/padding = 3 bytes

=== WRAPPERS ===
sceAgcDriverSubmitDcb
  original RDI -> RSI
  RDI <- dcb_context
  tail-jump -> SubmitCommandBuffer

sceAgcDriverAgrSubmitDcb
  original RDI -> RSI
  RDI <- agr_context
  tail-jump -> SubmitCommandBuffer

=== MULTI ABI CANDIDATE ===
sceAgcDriverSubmitMultiCommandBuffers
  RDI = context
  RSI = uint64_t array
  RDX = uint32_t array
  RCX = count

=== GLOBAL DISPATCH CONTRACT ===
global_context = 0x1A908
+0xA0 = table entry count / traversal bound
+0xA4 = dispatch index
+0x50 = Submit dispatch table base
+0x58 = Multi dispatch table base
entry stride = 0x78

=== STATUS ===
ABI_LAYOUT_PROVEN = True
WRAPPER_REGISTER_PLACEMENT_PROVEN = True
MULTI_ABI_COMPATIBLE_CANDIDATE = True
DISPATCH_INDEX_PROVEN = True
DISPATCH_COUNT_PROVEN = True
SEMANTIC_FIELD_NAMES_FINAL = False
REAL_AGC_EXECUTION = False

=== IMPLEMENTATION NOTE ===
The static library produced by Stage 79 is an ABI v1 compatibility layer.
Its weak functions return -1 until replaced/overridden by the real NID-backed
PS5 import implementation. This deliberately separates ABI validation from
runtime reverse-engineering and allows the final project to compile now.
'@

$NidMap = @'
{
  "stage": 79,
  "functions": {
    "sceAgcDriverSubmitDcb": "UglJIZjGssM",
    "sceAgcDriverAgrSubmitDcb": "AhGvpITrf4M",
    "sceAgcDriverSubmitAcb": "gSRnr79F8tQ",
    "sceAgcDriverSubmitCommandBuffer": "b4fpgH5ZXxQ",
    "sceAgcDriverSubmitMultiCommandBuffers": "Fj7r9EHzF38",
    "sceAgcDriverSubmitMultiDcbs": "6UzEidRZwkg",
    "sceAgcDriverAgrSubmitMultiDcbs": "+T8Xo6LtFJI",
    "sceAgcDriverSubmitMultiAcbs": "HF3YllT3mXU"
  },
  "abi": {
    "context_register": "RDI",
    "argument_register": "RSI",
    "return_register": "EAX",
    "args": {
      "0x00": { "width": 8 },
      "0x08": { "width": 4 },
      "0x0C": { "width": 1 },
      "sizeof_c_struct": 16
    }
  },
  "dispatch": {
    "global_context": "0x1A908",
    "table_count_or_bound_offset": "0xA0",
    "dispatch_index_offset": "0xA4",
    "submit_table_offset": "0x50",
    "multi_table_offset": "0x58",
    "entry_stride": "0x78"
  },
  "runtime": {
    "executed_agc": false
  }
}
'@

Set-Content -LiteralPath (Join-Path $Output 'agc_abi_v1.h') -Value $Header -Encoding utf8NoBOM
Set-Content -LiteralPath (Join-Path $Output 'agc_abi_v1.c') -Value $Source -Encoding utf8NoBOM
Set-Content -LiteralPath (Join-Path $Output 'stage79_probe.c') -Value $Probe -Encoding utf8NoBOM
Set-Content -LiteralPath (Join-Path $Output 'ABI_V1_CONTRACT.txt') -Value $Contract -Encoding utf8NoBOM
Set-Content -LiteralPath (Join-Path $Output 'stage79_nids.json') -Value $NidMap -Encoding utf8NoBOM

$Wslscript = @"
set -e
rm -rf '$TmpWsl'
mkdir -p '$TmpWsl'
mkdir -p '$OutputWsl'

cp '$OutputWsl/agc_abi_v1.h' '$TmpWsl/agc_abi_v1.h'
cp '$OutputWsl/agc_abi_v1.c' '$TmpWsl/agc_abi_v1.c'
cp '$OutputWsl/stage79_probe.c' '$TmpWsl/stage79_probe.c'
sed -i 's/\r`$//' '$TmpWsl/agc_abi_v1.h' '$TmpWsl/agc_abi_v1.c' '$TmpWsl/stage79_probe.c'

printf '%s\\n' '--- prospero-clang ---'
'$SdkWsl/bin/prospero-clang' --version
printf '%s\\n' '--- pyelftools ---'
python3 -c "from elftools.elf.elffile import ELFFile; print('pyelftools=OK')"

'$SdkWsl/bin/prospero-clang' \\
  -target x86_64-sie-ps5 \\
  -ffreestanding \\
  -fno-builtin \\
  -nostdlib \\
  -fPIC \\
  -fno-plt \\
  -fno-stack-protector \\
  -I'$TmpWsl' \\
  -Wall -Wextra -Werror \\
  -c '$TmpWsl/agc_abi_v1.c' \\
  -o '$TmpWsl/agc_abi_v1.o'

command -v llvm-ar >/dev/null
llvm-ar rcs '$TmpWsl/libSceAgcDriver_abi_v1.a' '$TmpWsl/agc_abi_v1.o'

'$SdkWsl/bin/prospero-clang' \\
  -target x86_64-sie-ps5 \\
  -ffreestanding \\
  -fno-builtin \\
  -nostdlib \\
  -fPIC \\
  -fno-plt \\
  -fno-stack-protector \\
  -I'$TmpWsl' \\
  -Wall -Wextra -Werror \\
  -S '$TmpWsl/stage79_probe.c' \\
  -o '$TmpWsl/stage79_probe.s'

cp '$TmpWsl/libSceAgcDriver_abi_v1.a' '$OutputWsl/libSceAgcDriver_abi_v1.a'
cp '$TmpWsl/stage79_probe.s' '$OutputWsl/stage79_probe.s'

printf '%s\\n' '--- nm ---'
'$SdkWsl/bin/prospero-nm' -g '$OutputWsl/libSceAgcDriver_abi_v1.a' || true
printf '%s\\n' '--- probe ABI ---'
grep -n -A14 -B2 'stage79_probe:' '$OutputWsl/stage79_probe.s' || true

python3 - <<'PY'
from pathlib import Path
import json, hashlib
out = Path('/mnt/d/agc_work/stage79_results')
checks = {}
for name in ['agc_abi_v1.h','agc_abi_v1.c','stage79_probe.c','ABI_V1_CONTRACT.txt','stage79_nids.json','libSceAgcDriver_abi_v1.a','stage79_probe.s']:
    p = out/name
    checks[name] = {
        'exists': p.exists(),
        'size': p.stat().st_size if p.exists() else 0,
        'sha256': hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None,
    }
report = {
  'stage': 79,
  'previous_stage': 78,
  'artifact_checks': checks,
  'conclusions': {
      'ABI_LAYOUT_PROVEN': True,
      'WRAPPER_REGISTER_PLACEMENT_PROVEN': True,
      'MULTI_ABI_COMPATIBLE_CANDIDATE': True,
      'DISPATCH_INDEX_PROVEN': True,
      'DISPATCH_COUNT_PROVEN': True,
      'ABI_V1_STATIC_LIBRARY_BUILT': checks['libSceAgcDriver_abi_v1.a']['exists'],
      'PROBE_ASSEMBLY_BUILT': checks['stage79_probe.s']['exists'],
      'SEMANTIC_FIELD_NAMES_FINAL': False,
      'REAL_AGC_EXECUTION': False,
  }
}
(out/'stage79_static.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
PY

cp '$TmpWsl/agc_abi_v1.o' '$OutputWsl/agc_abi_v1.o'

printf '%s\\n' '--- output files ---'
find '$OutputWsl' -maxdepth 1 -type f -printf '%f\\n' | sort

sha256sum \\
 '$OutputWsl/stage79_static.json' \\
 '$OutputWsl/ABI_V1_CONTRACT.txt' \\
 '$OutputWsl/agc_abi_v1.h' \\
 '$OutputWsl/libSceAgcDriver_abi_v1.a' \\
 '$OutputWsl/stage79_probe.s'
"@

$WslExe = @('bash','-lc',$Wslscript)
& wsl.exe @WslExe
if ($LASTEXITCODE -ne 0) { throw "WSL stage79 build failed with exit code $LASTEXITCODE." }

$ReportPath = Join-Path $Output 'STAGE79_REPORT.json'
$Report = @{
    stage = 79
    previous_stage = 78
    output = $Output
    abi_v1 = @{
        submit_command_buffer = 'int sceAgcDriverSubmitCommandBuffer(void *context, const SceAgcSubmitCommandBufferArgs *args)'
        submit_dcb = 'int sceAgcDriverSubmitDcb(void *dcb_context, const SceAgcSubmitCommandBufferArgs *args)'
        agr_submit_dcb = 'int sceAgcDriverAgrSubmitDcb(void *agr_context, const SceAgcSubmitCommandBufferArgs *args)'
        args = @(
            @{ offset='0x00'; width=8 },
            @{ offset='0x08'; width=4 },
            @{ offset='0x0C'; width=1 }
        )
    }
    dispatch = @{
        global_context='0x1A908'
        table_count_or_bound='0xA0'
        dispatch_index='0xA4'
        submit_table='0x50'
        multi_table='0x58'
        entry_stride='0x78'
    }
    conclusions = @{
        ABI_V1_STATIC_LIBRARY_BUILT = $true
        ABI_LAYOUT_PROVEN = $true
        WRAPPER_REGISTER_PLACEMENT_PROVEN = $true
        MULTI_ABI_COMPATIBLE_CANDIDATE = $true
        DISPATCH_INDEX_PROVEN = $true
        DISPATCH_COUNT_PROVEN = $true
        SEMANTIC_FIELD_NAMES_FINAL = $false
        REAL_AGC_EXECUTION = $false
    }
}
$Report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ReportPath -Encoding utf8NoBOM

Write-Host ''
Write-Host '============================================'
Write-Host 'Stage 79 completado'
Write-Host '============================================'
Write-Host 'ABI_V1_STATIC_LIBRARY_BUILT = True'
Write-Host 'ABI_LAYOUT_PROVEN = True'
Write-Host 'WRAPPER_REGISTER_PLACEMENT_PROVEN = True'
Write-Host 'MULTI_ABI_COMPATIBLE_CANDIDATE = True'
Write-Host 'DISPATCH_INDEX_PROVEN = True'
Write-Host 'DISPATCH_COUNT_PROVEN = True'
Write-Host 'SEMANTIC_FIELD_NAMES_FINAL = False'
Write-Host 'REAL_AGC_EXECUTION = False'
Write-Host ''
Write-Host 'Resultados:'
Write-Host "  $Output"
Write-Host ''
Write-Host 'Artefactos principales:'
Write-Host "  $(Join-Path $Output 'agc_abi_v1.h')"
Write-Host "  $(Join-Path $Output 'agc_abi_v1.c')"
Write-Host "  $(Join-Path $Output 'libSceAgcDriver_abi_v1.a')"
Write-Host "  $(Join-Path $Output 'ABI_V1_CONTRACT.txt')"
Write-Host "  $ReportPath"
