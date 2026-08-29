#requires -Version 7.0
<#
    AGC PS5 Stage 82
    Semantic ABI / Public Structure Audit

    Objetivo
    --------
    Cerrar la capa semántica recuperada de KytyPlus para:
      - ShaderRegister
      - ShaderUserData
      - ShaderSpecialRegs
      - Shader
      - CommandBuffer
      - Label
      - RegisterDefaults

    Y separar explícitamente:
      A) semántica recuperada / verificada en KytyPlus
      B) símbolos SCEAgc / SCEAgcDriver recuperados
      C) tareas ABI todavía pendientes
      D) REAL_AGC_EXECUTION = False

    IMPORTANTE
    ----------
    Este Stage NO afirma las firmas exactas de sceAgc*.
    No genera ni ejecuta una llamada real a sceAgcInit().
    No inventa headers Sony.

    Fuentes esperadas:
      - Stage 81 output
      - KytyPlus/src/libs/agc.h
      - KytyPlus/src/libs/agc.cpp
      - KytyPlus/src/graphics/shader/shader.h
      - PS5-3.20_Libs/libSceAgc.c
      - PS5-3.20_Libs/libSceAgcDriver.c
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Host "============================================"
Write-Host "AGC PS5 Stage 82 - Semantic ABI / Field Audit"
Write-Host "============================================"

# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------

$Stage81 = if ($env:AGC_STAGE81) {
    $env:AGC_STAGE81
} else {
    "D:\agc_work\stage81_results"
}

$Output = if ($env:AGC_STAGE82) {
    $env:AGC_STAGE82
} else {
    "D:\agc_work\stage82_results"
}

# Permite trabajar con clones locales; no modifica ni descarga repositorios.
$KytyRoot = if ($env:KYTYPLUS_ROOT) {
    $env:KYTYPLUS_ROOT
} else {
    "D:\agc_sources\KytyPlus"
}

$LibsRoot = if ($env:PS5_LIBS_ROOT) {
    $env:PS5_LIBS_ROOT
} else {
    "D:\agc_sources\PS5-3.20_Libs"
}

New-Item -ItemType Directory -Force -Path $Output | Out-Null

Write-Host "  Stage81 = $Stage81"
Write-Host "  KytyPlus = $KytyRoot"
Write-Host "  PS5-3.20_Libs = $LibsRoot"
Write-Host "  Output = $Output"
Write-Host ""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Require-File {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Label
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "[FAIL] $Label no encontrado: $Path"
    }

    Write-Host "  [OK] $Label"
}

function Read-Text {
    param([Parameter(Mandatory=$true)][string]$Path)
    return Get-Content -LiteralPath $Path -Raw -Encoding UTF8
}

function Assert-Contains {
    param(
        [Parameter(Mandatory=$true)][string]$Text,
        [Parameter(Mandatory=$true)][string]$Pattern,
        [Parameter(Mandatory=$true)][string]$Label
    )

    if ($Text -notmatch $Pattern) {
        throw "[FAIL] No se encontró '$Label'"
    }

    Write-Host "  [OK] $Label"
}

function Get-Count {
    param(
        [Parameter(Mandatory=$true)][string]$Text,
        [Parameter(Mandatory=$true)][string]$Pattern
    )

    return ([regex]::Matches($Text, $Pattern, [System.Text.RegularExpressions.RegexOptions]::Multiline)).Count
}

# ---------------------------------------------------------------------------
# 1. Workspace / Stage 81
# ---------------------------------------------------------------------------

Write-Host "==> 1. Verificar Stage 81"

Require-File (Join-Path $Stage81 "STAGE81_REPORT.json") "STAGE81_REPORT.json"
Require-File (Join-Path $Stage81 "stage81_audit_counts.txt") "stage81_audit_counts.txt"
Require-File (Join-Path $Stage81 "END_TO_END_LINK_CONTRACT.txt") "END_TO_END_LINK_CONTRACT.txt"

Write-Host ""

# ---------------------------------------------------------------------------
# 2. Fuentes de referencia
# ---------------------------------------------------------------------------

Write-Host "==> 2. Verificar fuentes locales"

$KytyAgcH   = Join-Path $KytyRoot "src\libs\agc.h"
$KytyAgcCpp = Join-Path $KytyRoot "src\libs\agc.cpp"
$KytyShader = Join-Path $KytyRoot "src\graphics\shader\shader.h"

$LibAgc     = Join-Path $LibsRoot "libSceAgc.c"
$LibAgcDrv  = Join-Path $LibsRoot "libSceAgcDriver.c"

Require-File $KytyAgcH   "KytyPlus agc.h"
Require-File $KytyAgcCpp "KytyPlus agc.cpp"
Require-File $KytyShader "KytyPlus shader.h"
Require-File $LibAgc     "PS5-3.20_Libs libSceAgc.c"
Require-File $LibAgcDrv  "PS5-3.20_Libs libSceAgcDriver.c"

$agcH   = Read-Text $KytyAgcH
$agcCpp = Read-Text $KytyAgcCpp
$shader = Read-Text $KytyShader
$libAgc = Read-Text $LibAgc
$libDrv = Read-Text $LibAgcDrv

Write-Host ""

# ---------------------------------------------------------------------------
# 3. Semántica: ShaderRegister
# ---------------------------------------------------------------------------

Write-Host "==> 3. ShaderRegister"

Assert-Contains $shader 'struct\s+ShaderRegister\s*\{' 'struct ShaderRegister'
Assert-Contains $shader 'uint32_t\s+offset\s*;' 'ShaderRegister.offset'
Assert-Contains $shader 'uint32_t\s+value\s*;' 'ShaderRegister.value'

Write-Host ""

# ---------------------------------------------------------------------------
# 4. Semántica: ShaderUserData
# ---------------------------------------------------------------------------

Write-Host "==> 4. ShaderUserData"

Assert-Contains $shader 'struct\s+ShaderUserData\s*\{' 'struct ShaderUserData'
Assert-Contains $shader 'direct_resource_offset' 'direct_resource_offset'
Assert-Contains $shader 'sharp_resource_offset\[4\]' 'sharp_resource_offset[4]'
Assert-Contains $shader 'eud_size_dw' 'eud_size_dw'
Assert-Contains $shader 'srt_size_dw' 'srt_size_dw'
Assert-Contains $shader 'direct_resource_count' 'direct_resource_count'
Assert-Contains $shader 'sharp_resource_count\[4\]' 'sharp_resource_count[4]'

Write-Host ""

# ---------------------------------------------------------------------------
# 5. Semántica: ShaderSpecialRegs
# ---------------------------------------------------------------------------

Write-Host "==> 5. ShaderSpecialRegs"

Assert-Contains $shader 'struct\s+ShaderSpecialRegs\s*\{' 'struct ShaderSpecialRegs'
Assert-Contains $shader 'ge_cntl' 'ShaderSpecialRegs.ge_cntl'
Assert-Contains $shader 'vgt_shader_stages_en' 'ShaderSpecialRegs.vgt_shader_stages_en'
Assert-Contains $shader 'dispatch_modifier' 'ShaderSpecialRegs.dispatch_modifier'
Assert-Contains $shader 'user_data_range' 'ShaderSpecialRegs.user_data_range'
Assert-Contains $shader 'draw_modifier' 'ShaderSpecialRegs.draw_modifier'
Assert-Contains $shader 'vgt_gs_out_prim_type' 'ShaderSpecialRegs.vgt_gs_out_prim_type'
Assert-Contains $shader 'ge_user_vgpr_en' 'ShaderSpecialRegs.ge_user_vgpr_en'

Write-Host ""

# ---------------------------------------------------------------------------
# 6. Semántica: Shader
# ---------------------------------------------------------------------------

Write-Host "==> 6. Shader"

Assert-Contains $shader 'struct\s+Shader\s*\{' 'struct Shader'
Assert-Contains $shader 'file_header' 'Shader.file_header'
Assert-Contains $shader 'version' 'Shader.version'
Assert-Contains $shader 'user_data' 'Shader.user_data'
Assert-Contains $shader 'code' 'Shader.code'
Assert-Contains $shader 'cx_registers' 'Shader.cx_registers'
Assert-Contains $shader 'sh_registers' 'Shader.sh_registers'
Assert-Contains $shader 'specials' 'Shader.specials'
Assert-Contains $shader 'input_semantics' 'Shader.input_semantics'
Assert-Contains $shader 'output_semantics' 'Shader.output_semantics'
Assert-Contains $shader 'header_size' 'Shader.header_size'
Assert-Contains $shader 'shader_size' 'Shader.shader_size'
Assert-Contains $shader 'embedded_constant_buffer_size_dqw' 'Shader.embedded_constant_buffer_size_dqw'
Assert-Contains $shader 'target' 'Shader.target'
Assert-Contains $shader 'num_input_semantics' 'Shader.num_input_semantics'
Assert-Contains $shader 'scratch_size_dw_per_thread' 'Shader.scratch_size_dw_per_thread'
Assert-Contains $shader 'num_output_semantics' 'Shader.num_output_semantics'
Assert-Contains $shader 'special_sizes_bytes' 'Shader.special_sizes_bytes'
Assert-Contains $shader 'num_cx_registers' 'Shader.num_cx_registers'
Assert-Contains $shader 'num_sh_registers' 'Shader.num_sh_registers'

Write-Host ""

# ---------------------------------------------------------------------------
# 7. Semántica: RegisterDefaults
# ---------------------------------------------------------------------------

Write-Host "==> 7. RegisterDefaults"

Assert-Contains $agcH 'struct\s+RegisterDefaults\s*\{' 'KytyPlus RegisterDefaults'
Assert-Contains $agcH 'tbl0' 'RegisterDefaults.tbl0'
Assert-Contains $agcH 'tbl1' 'RegisterDefaults.tbl1'
Assert-Contains $agcH 'tbl2' 'RegisterDefaults.tbl2'
Assert-Contains $agcH 'tbl3' 'RegisterDefaults.tbl3'
Assert-Contains $agcH 'tbl0_register_count' 'RegisterDefaults.tbl0_register_count'
Assert-Contains $agcH 'tbl1_register_count' 'RegisterDefaults.tbl1_register_count'
Assert-Contains $agcH 'tbl2_register_count' 'RegisterDefaults.tbl2_register_count'
Assert-Contains $agcH 'tbl3_register_count' 'RegisterDefaults.tbl3_register_count'
Assert-Contains $agcH 'uint32_t\s*\*\s*types' 'RegisterDefaults.types'
Assert-Contains $agcH 'uint32_t\s*count' 'RegisterDefaults.count'

# KytyPlus contiene una comprobación explícita de offsetof(count) == 0x38.
Assert-Contains $agcCpp 'offsetof\(RegisterDefaults,\s*count\)\s*==\s*0x38' `
    'RegisterDefaults.count offset == 0x38'

Write-Host ""

# ---------------------------------------------------------------------------
# 8. Semántica: CommandBuffer
# ---------------------------------------------------------------------------

Write-Host "==> 8. CommandBuffer"

Assert-Contains $agcCpp 'struct\s+CommandBuffer\s*\{' 'KytyPlus CommandBuffer'
Assert-Contains $agcCpp 'uint32_t\s*\*\s*bottom' 'CommandBuffer.bottom'
Assert-Contains $agcCpp 'uint32_t\s*\*\s*top' 'CommandBuffer.top'
Assert-Contains $agcCpp 'uint32_t\s*\*\s*cursor_up' 'CommandBuffer.cursor_up'
Assert-Contains $agcCpp 'uint32_t\s*\*\s*cursor_down' 'CommandBuffer.cursor_down'
Assert-Contains $agcCpp 'Callback\s+callback' 'CommandBuffer.callback'
Assert-Contains $agcCpp 'void\s*\*\s*user_data' 'CommandBuffer.user_data'
Assert-Contains $agcCpp 'uint32_t\s+reserved_dw' 'CommandBuffer.reserved_dw'
Assert-Contains $agcCpp 'GetAvailableSizeDW' 'CommandBuffer.GetAvailableSizeDW'
Assert-Contains $agcCpp 'ReserveDW' 'CommandBuffer.ReserveDW'
Assert-Contains $agcCpp 'AllocateDW' 'CommandBuffer.AllocateDW'

Write-Host ""

# ---------------------------------------------------------------------------
# 9. Semántica: Label
# ---------------------------------------------------------------------------

Write-Host "==> 9. Label"

Assert-Contains $agcCpp 'struct\s+Label\s*\{' 'KytyPlus Label'
Assert-Contains $agcCpp 'volatile\s+uint64_t\s+m_value' 'Label.m_value'
Assert-Contains $agcCpp 'uint64_t\s+m_reserved\[3\]' 'Label.m_reserved[3]'

Write-Host ""

# ---------------------------------------------------------------------------
# 10. Operaciones Gen5 necesarias para el primer renderer
# ---------------------------------------------------------------------------

Write-Host "==> 10. Operaciones Gen5 relevantes"

$requiredGen5 = @(
    'GraphicsInit',
    'GraphicsGetRegisterDefaults2',
    'GraphicsCreateShader',
    'GraphicsDcbWaitUntilSafeForRendering',
    'GraphicsDcbSetShRegisterDirect',
    'GraphicsDcbSetCxRegisterDirect',
    'GraphicsDcbSetIndexBuffer',
    'GraphicsDcbSetIndexCount',
    'GraphicsDcbDrawIndex',
    'GraphicsDcbSetFlip'
)

$gen5Results = @()

foreach ($name in $requiredGen5) {
    $foundHeader = $agcH -match "\b$name\s*\("
    $foundCpp    = $agcCpp -match "\b$name\s*\("

    $status = $foundHeader -and $foundCpp

    $gen5Results += [pscustomobject]@{
        Symbol = $name
        Header = $foundHeader
        Source = $foundCpp
        Verified = $status
    }

    if ($status) {
        Write-Host "  [OK] $name"
    } else {
        Write-Host "  [WARN] $name no está verificado en ambas fuentes"
    }
}

Write-Host ""

# ---------------------------------------------------------------------------
# 11. Símbolos SCE reales recuperados
# ---------------------------------------------------------------------------

Write-Host "==> 11. Símbolos SCE AGC recuperados"

$requiredSceAgc = @(
    'sceAgcInit',
    'sceAgcGetRegisterDefaults2',
    'sceAgcLinkShaders',
    'sceAgcFuseShaderHalves',
    'sceAgcGetPacketSize'
)

$sceAgcResults = @()

foreach ($name in $requiredSceAgc) {
    $found = $libAgc -match "\.global\s+$name\b"

    $sceAgcResults += [pscustomobject]@{
        Symbol = $name
        Present = $found
    }

    if ($found) {
        Write-Host "  [OK] $name"
    } else {
        Write-Host "  [WARN] $name no encontrado"
    }
}

$requiredDriver = @(
    'sceAgcDriverSubmitDcb',
    'sceAgcDriverSubmitMultiDcbs',
    'sceAgcDriverSubmitCommandBuffer',
    'sceAgcDriverSubmitMultiCommandBuffers',
    'sceAgcDriverAgrSubmitDcb',
    'sceAgcDriverAgrSubmitMultiDcbs',
    'sceAgcDriverSubmitAcb',
    'sceAgcDriverSubmitMultiAcbs'
)

$driverResults = @()

foreach ($name in $requiredDriver) {
    $found = $libDrv -match "\.global\s+$name\b"

    $driverResults += [pscustomobject]@{
        Symbol = $name
        Present = $found
    }

    if ($found) {
        Write-Host "  [OK] $name"
    } else {
        Write-Host "  [WARN] $name no encontrado"
    }
}

Write-Host ""

# ---------------------------------------------------------------------------
# 12. Tareas ABI que permanecen deliberadamente abiertas
# ---------------------------------------------------------------------------

Write-Host "==> 12. Tareas pendientes"

$pending = @(
    "PUBLIC_SEMANTIC_FIELD_NAMES_FINAL = False",
    "Determinar firmas exactas de sceAgc* antes de emitir llamadas reales",
    "Determinar ABI exacta de las estructuras que cruzan la frontera sceAgc*",
    "Determinar ABI exacta del submit sceAgcDriver* utilizada por el runtime objetivo",
    "Generar Stage 83: probe real de sceAgcInit",
    "Generar Stage 84: probe real de sceAgcGetRegisterDefaults2",
    "REAL_AGC_EXECUTION = False"
)

foreach ($item in $pending) {
    Write-Host "  [PENDIENTE] $item"
}

Write-Host ""

# ---------------------------------------------------------------------------
# 13. Resultado
# ---------------------------------------------------------------------------

$semanticChecks =
    ($gen5Results | Where-Object { $_.Verified }).Count -eq $requiredGen5.Count

$sceChecks =
    ($sceAgcResults | Where-Object { $_.Present }).Count -eq $requiredSceAgc.Count

$driverChecks =
    ($driverResults | Where-Object { $_.Present }).Count -eq $requiredDriver.Count

$report = [ordered]@{
    STAGE = 82
    TITLE = "Semantic ABI / Public Structure Audit"

    SOURCE_REPOS = [ordered]@{
        KYTYPLUS = $KytyRoot
        PS5_3_20_LIBS = $LibsRoot
    }

    SEMANTIC_STRUCTURES = [ordered]@{
        ShaderRegister = $true
        ShaderUserData = $true
        ShaderSpecialRegs = $true
        Shader = $true
        CommandBuffer = $true
        Label = $true
        RegisterDefaults = $true
    }

    GEN5_OPERATIONS_VERIFIED = $semanticChecks
    SCE_AGC_SYMBOLS_VERIFIED = $sceChecks
    SCE_AGC_DRIVER_SYMBOLS_VERIFIED = $driverChecks

    PUBLIC_SEMANTIC_FIELD_NAMES_FINAL = $false

    EXACT_SCE_SIGNATURES_FINAL = $false
    EXACT_CROSSING_ABI_FINAL = $false

    REAL_AGC_EXECUTION = $false

    NEXT_STAGE = "Stage 83 - real sceAgcInit execution probe"

    PENDING = $pending

    COUNTS = [ordered]@{
        Gen5Operations = $requiredGen5.Count
        SceAgcSymbols = $requiredSceAgc.Count
        SceAgcDriverSymbols = $requiredDriver.Count
    }
}

$jsonPath = Join-Path $Output "STAGE82_REPORT.json"
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

$semanticPath = Join-Path $Output "stage82_semantic_checks.json"
[ordered]@{
    gen5 = $gen5Results
    sceAgc = $sceAgcResults
    sceAgcDriver = $driverResults
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $semanticPath -Encoding UTF8

$contract = @"
AGC PS5 STAGE 82 CONTRACT
=========================

SEMANTIC STRUCTURES VERIFIED FROM KYTYPLUS
------------------------------------------
ShaderRegister
ShaderUserData
ShaderSpecialRegs
Shader
CommandBuffer
Label
RegisterDefaults

GEN5 OPERATIONS RECOGNIZED
--------------------------
GraphicsInit
GraphicsGetRegisterDefaults2
GraphicsCreateShader
GraphicsDcbWaitUntilSafeForRendering
GraphicsDcbSetShRegisterDirect
GraphicsDcbSetCxRegisterDirect
GraphicsDcbSetIndexBuffer
GraphicsDcbSetIndexCount
GraphicsDcbDrawIndex
GraphicsDcbSetFlip

SCE SYMBOLS RECOVERED
---------------------
sceAgcInit
sceAgcGetRegisterDefaults2
sceAgcLinkShaders
sceAgcFuseShaderHalves
sceAgcGetPacketSize

SCE DRIVER SYMBOLS RECOVERED
----------------------------
sceAgcDriverSubmitDcb
sceAgcDriverSubmitMultiDcbs
sceAgcDriverSubmitCommandBuffer
sceAgcDriverSubmitMultiCommandBuffers
sceAgcDriverAgrSubmitDcb
sceAgcDriverAgrSubmitMultiDcbs
sceAgcDriverSubmitAcb
sceAgcDriverSubmitMultiAcbs

EXPLICITLY NOT CLAIMED
----------------------
- Exact Sony sceAgc* function signatures are NOT finalized.
- Exact ABI of all cross-boundary structures is NOT finalized.
- Real AGC execution is NOT demonstrated.
- No real sceAgcInit call is performed by Stage 82.

PENDING
-------
PUBLIC_SEMANTIC_FIELD_NAMES_FINAL = False
EXACT_SCE_SIGNATURES_FINAL = False
EXACT_CROSSING_ABI_FINAL = False
REAL_AGC_EXECUTION = False

NEXT
----
Stage 83:
Real PS5 execution probe for sceAgcInit.
"@

$contractPath = Join-Path $Output "STAGE82_CONTRACT.txt"
Set-Content -LiteralPath $contractPath -Value $contract -Encoding UTF8

# ---------------------------------------------------------------------------
# 14. Resumen final
# ---------------------------------------------------------------------------

Write-Host "============================================"
Write-Host "Stage 82 completado"
Write-Host "============================================"
Write-Host "  Semantic structures = OK"
Write-Host "  Gen5 semantic ops   = $semanticChecks"
Write-Host "  sceAgc symbols      = $sceChecks"
Write-Host "  sceAgcDriver symbols= $driverChecks"
Write-Host ""
Write-Host "  PUBLIC_SEMANTIC_FIELD_NAMES_FINAL = False"
Write-Host "  EXACT_SCE_SIGNATURES_FINAL        = False"
Write-Host "  EXACT_CROSSING_ABI_FINAL          = False"
Write-Host "  REAL_AGC_EXECUTION                = False"
Write-Host ""
Write-Host "  Report: $jsonPath"
Write-Host "  Checks: $semanticPath"
Write-Host "  Contract: $contractPath"
Write-Host "============================================"
