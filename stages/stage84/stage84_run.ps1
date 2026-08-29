#requires -Version 7.0

[CmdletBinding()]
param(
    [string]$Stage79      = $(if ($env:AGC_STAGE79)     { $env:AGC_STAGE79     } else { 'D:\agc_work\stage79_results' }),
    [string]$Stage80      = $(if ($env:AGC_STAGE80)     { $env:AGC_STAGE80     } else { 'D:\agc_work\stage80_results' }),
    [string]$Stage81      = $(if ($env:AGC_STAGE81)     { $env:AGC_STAGE81     } else { 'D:\agc_work\stage81_results' }),
    [string]$Output       = $(if ($env:AGC_STAGE84)     { $env:AGC_STAGE84     } else { 'D:\agc_work\stage84_results' }),
    [string]$Sdk          = $(if ($env:AGC_SDK)          { $env:AGC_SDK          } else { '/opt/ps5-payload-sdk' }),
    [string]$UbuntuDistro = $(if ($env:AGC_WSL_DISTRO)  { $env:AGC_WSL_DISTRO  } else { 'Ubuntu-24.04' })
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Section {
    param([Parameter(Mandatory)][string]$Text)
    Write-Host ''
    Write-Host '============================================' -ForegroundColor Cyan
    Write-Host $Text -ForegroundColor Cyan
    Write-Host '============================================' -ForegroundColor Cyan
}

function Write-Step {
    param([Parameter(Mandatory)][string]$Text)
    Write-Host ''
    Write-Host "==> $Text" -ForegroundColor Yellow
}

function Normalize-LF {
    param([Parameter(Mandatory)][string]$Text)
    return ($Text -replace "`r`n", "`n" -replace "`r", "")
}

function Quote-Bash {
    param([Parameter(Mandatory)][string]$Text)
    return "'" + ($Text -replace "'", "'\''") + "'"
}

function Convert-ToWslPath {
    param([Parameter(Mandatory)][string]$WindowsPath)
    $full = [System.IO.Path]::GetFullPath($WindowsPath)
    if ($full -match '^[A-Za-z]:\\') {
        $drive = $full.Substring(0,1).ToLowerInvariant()
        $rest  = $full.Substring(2).Replace('\','/').TrimStart('/')
        return "/mnt/$drive/$rest"
    }
    return $full.Replace('\','/')
}

function Invoke-WslBash {
    param(
        [Parameter(Mandatory)][string]$Command,
        [switch]$AllowFailure
    )
    $cmd = Normalize-LF $Command
    Write-Host ''
    Write-Host '[WSL] ' -NoNewline -ForegroundColor DarkGray
    Write-Host ($cmd.Substring(0,[Math]::Min(100,$cmd.Length))) -ForegroundColor DarkGray
    & wsl.exe -d $UbuntuDistro --cd / -- bash -lc $cmd
    $code = $LASTEXITCODE
    if (($code -ne 0) -and (-not $AllowFailure)) {
        throw "WSL command failed (exit $code)."
    }
    return $code
}

function Require-File {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Label
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "[FAIL] $Label no encontrado: $Path"
    }
    Write-Host "[OK] $Label"
}

# ─── banner ───────────────────────────────────────────────────────────────

Write-Section 'A — Stage 84: Installable Build Layout'
Write-Host "Stage79      = $Stage79"
Write-Host "Stage80      = $Stage80"
Write-Host "Stage81      = $Stage81"
Write-Host "Output       = $Output"
Write-Host "Sdk          = $Sdk"
Write-Host "WSL distro   = $UbuntuDistro"

if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) { throw 'wsl.exe no encontrado.' }

# ─── Step 1: Verificar entradas ───────────────────────────────────────────

Write-Step 'Verificar artefactos de entrada'

Require-File (Join-Path $Stage79 'agc_abi_v1.h')                'Stage79 agc_abi_v1.h'
Require-File (Join-Path $Stage79 'agc_abi_v1.c')                'Stage79 agc_abi_v1.c'
Require-File (Join-Path $Stage79 'libSceAgcDriver_abi_v1.a')    'Stage79 libSceAgcDriver_abi_v1.a'
Require-File (Join-Path $Stage79 'ABI_V1_CONTRACT.txt')         'Stage79 ABI_V1_CONTRACT.txt'
Require-File (Join-Path $Stage79 'STAGE79_REPORT.json')         'Stage79 STAGE79_REPORT.json'
Require-File (Join-Path $Stage80 'agc_project_v1.h')            'Stage80 agc_project_v1.h'
Require-File (Join-Path $Stage80 'agc_project_v1.c')            'Stage80 agc_project_v1.c'
Require-File (Join-Path $Stage80 'libagc_project_v1.a')         'Stage80 libagc_project_v1.a'
Require-File (Join-Path $Stage80 'AGC_PROJECT_V1_CONTRACT.txt') 'Stage80 AGC_PROJECT_V1_CONTRACT.txt'
Require-File (Join-Path $Stage80 'STAGE80_REPORT.json')         'Stage80 STAGE80_REPORT.json'
Require-File (Join-Path $Stage81 'STAGE81_REPORT.json')         'Stage81 STAGE81_REPORT.json'
Require-File (Join-Path $Stage81 'END_TO_END_LINK_CONTRACT.txt') 'Stage81 END_TO_END_LINK_CONTRACT.txt'
Require-File (Join-Path $Stage81 'stage81_linked.o')            'Stage81 stage81_linked.o'

$ScriptWin = Join-Path $Output 'stage84_install_layout.py'
Require-File $ScriptWin 'stage84_install_layout.py'

# ─── Step 2: Verificar toolchain en WSL ───────────────────────────────────

Write-Step 'Verificar toolchain SDK en WSL'

$ClangBin = "$Sdk/bin/prospero-clang"
$NmBin    = "$Sdk/bin/prospero-nm"
$LldBin   = "$Sdk/bin/prospero-lld"

Invoke-WslBash @"
set -e
test -x $(Quote-Bash $ClangBin) || { echo 'prospero-clang no encontrado'; exit 1; }
test -x $(Quote-Bash $NmBin)    || { echo 'prospero-nm no encontrado';    exit 1; }
test -x $(Quote-Bash $LldBin)   || { echo 'prospero-lld no encontrado';   exit 1; }
$(Quote-Bash $ClangBin) --version | head -1
echo 'toolchain=OK'
"@

# ─── Step 3: Limpiar output parcial previo ────────────────────────────────

Write-Step 'Limpiar estado parcial previo en package/'

$OutputWsl  = Convert-ToWslPath $Output
$PackageWsl = "$OutputWsl/package"

Invoke-WslBash @"
set -e
# Borrar solo el contenido del package (no el script Python)
rm -rf $(Quote-Bash "$PackageWsl/include") \
       $(Quote-Bash "$PackageWsl/lib")     \
       $(Quote-Bash "$PackageWsl/src")     \
       $(Quote-Bash "$PackageWsl/meta")
mkdir -p $(Quote-Bash "$PackageWsl/include") \
         $(Quote-Bash "$PackageWsl/lib")     \
         $(Quote-Bash "$PackageWsl/src")     \
         $(Quote-Bash "$PackageWsl/meta")
echo 'clean=OK'
"@

# ─── Step 4: Ejecutar stage84_install_layout.py ───────────────────────────

Write-Step 'Ejecutar stage84_install_layout.py via WSL Python'

$Stage79Wsl = Convert-ToWslPath $Stage79
$Stage80Wsl = Convert-ToWslPath $Stage80
$Stage81Wsl = Convert-ToWslPath $Stage81
$ScriptWsl  = Convert-ToWslPath $ScriptWin

# sed por si el script tiene CRLF (fue escrito en Windows)
$runCmd = 'set -e' + "`n" +
    "sed -i 's/\r$//' " + (Quote-Bash $ScriptWsl) + "`n" +
    'python3 ' + (Quote-Bash $ScriptWsl) + ' ' +
    (Quote-Bash $Stage79Wsl) + ' ' +
    (Quote-Bash $Stage80Wsl) + ' ' +
    (Quote-Bash $Stage81Wsl) + ' ' +
    (Quote-Bash $OutputWsl)  + ' ' +
    (Quote-Bash $ClangBin)   + ' ' +
    (Quote-Bash $NmBin)      + ' ' +
    (Quote-Bash $LldBin)

Invoke-WslBash $runCmd

# ─── Step 5: Verificar artefactos de salida ───────────────────────────────

Write-Step 'Verificar artefactos generados'

$Expected = @(
    @{ Path = Join-Path $Output 'package\include\agc_abi_v1.h';              Label = 'package/include/agc_abi_v1.h' },
    @{ Path = Join-Path $Output 'package\include\agc_project_v1.h';          Label = 'package/include/agc_project_v1.h' },
    @{ Path = Join-Path $Output 'package\lib\libSceAgcDriver_abi_v1.a';      Label = 'package/lib/libSceAgcDriver_abi_v1.a' },
    @{ Path = Join-Path $Output 'package\lib\libagc_project_v1.a';           Label = 'package/lib/libagc_project_v1.a' },
    @{ Path = Join-Path $Output 'package\src\agc_abi_v1.c';                  Label = 'package/src/agc_abi_v1.c' },
    @{ Path = Join-Path $Output 'package\src\agc_project_v1.c';              Label = 'package/src/agc_project_v1.c' },
    @{ Path = Join-Path $Output 'STAGE84_REPORT.json';                        Label = 'STAGE84_REPORT.json' },
    @{ Path = Join-Path $Output 'STAGE84_INSTALL_CONTRACT.txt';               Label = 'STAGE84_INSTALL_CONTRACT.txt' },
    @{ Path = Join-Path $Output 'SHA256SUMS.txt';                             Label = 'SHA256SUMS.txt' },
    @{ Path = Join-Path $Output 'stage84_smoke.o';                            Label = 'stage84_smoke.o' },
    @{ Path = Join-Path $Output 'stage84_smoke_linked.o';                     Label = 'stage84_smoke_linked.o' }
)

foreach ($item in $Expected) {
    Require-File $item.Path $item.Label
}

# ─── Step 6: Validar STAGE84_REPORT.json ──────────────────────────────────

Write-Step 'Validar STAGE84_REPORT.json'

$R84 = Get-Content -LiteralPath (Join-Path $Output 'STAGE84_REPORT.json') -Raw -Encoding UTF8 |
       ConvertFrom-Json

$installOk  = $R84.conclusions.INSTALLABLE_LAYOUT_BUILT
$smokeOk    = $R84.conclusions.SMOKE_LINK_CLEAN
$archiveOk  = $R84.conclusions.PROJECT_AND_ABI_ARCHIVES_PACKAGED
$execFalse  = $R84.conclusions.REAL_AGC_EXECUTION -eq $false

if (-not $installOk) { throw '[FAIL] INSTALLABLE_LAYOUT_BUILT != true en STAGE84_REPORT.json' }
if (-not $smokeOk)   { throw '[FAIL] SMOKE_LINK_CLEAN != true en STAGE84_REPORT.json' }
if (-not $archiveOk) { throw '[FAIL] PROJECT_AND_ABI_ARCHIVES_PACKAGED != true' }
if (-not $execFalse) { throw '[FAIL] REAL_AGC_EXECUTION deberia ser false' }

Write-Host '[OK] STAGE84_REPORT.json: todas las conclusiones correctas'
Write-Host "[OK] AGC undefined refs: $($R84.proof.AGC_UNDEFINED_REFERENCES)"

# ─── Summary ───────────────────────────────────────────────────────────────

Write-Section 'A completado — Stage 84 Build Layout OK'
Write-Host "  package/  = $(Join-Path $Output 'package')"
Write-Host "  Report    = $(Join-Path $Output 'STAGE84_REPORT.json')"
Write-Host "  SHA256    = $(Join-Path $Output 'SHA256SUMS.txt')"
Write-Host ''
Write-Host '  INSTALLABLE_LAYOUT_BUILT          = true'
Write-Host '  PROJECT_AND_ABI_ARCHIVES_PACKAGED = true'
Write-Host '  SMOKE_LINK_CLEAN                  = true'
Write-Host '  REAL_AGC_EXECUTION                = false'