[CmdletBinding()]
param(
    [string]$Sprx = "D:\agc_work\sce_stubs\libSceAgcDriver.sprx",
    [string]$StubC = "D:\agc_work\sce_stubs\libSceAgcDriver.c",
    [string]$NidDb = "D:\sdk-master\sce_stubs\aerolib.csv",
    [string]$OutDir = "D:\agc_work\stage41_results",
    [string]$Python = "python.exe"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Write-Step([string]$Message) {
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Info([string]$Message) {
    Write-Host "[INFO] $Message"
}

function Convert-ToWslPath([string]$WindowsPath) {
    $Resolved = (Resolve-Path -LiteralPath $WindowsPath).Path
    if ($Resolved -notmatch '^(?<drive>[A-Za-z]):\\(?<rest>.*)$') {
        throw "Unsupported Windows path: $Resolved"
    }
    $drive = $Matches.drive.ToLowerInvariant()
    $rest = $Matches.rest -replace '\\','/'
    return "/mnt/$drive/$rest"
}

function Invoke-WslChecked([string]$Command) {
    Write-Host ""
    Write-Host "[WSL] $Command" -ForegroundColor DarkCyan
    & wsl.exe -d Ubuntu-24.04 --cd / -- bash -lc $Command | ForEach-Object { Write-Host $_ }
    if ($LASTEXITCODE -ne 0) {
        throw "WSL command failed with exit code $LASTEXITCODE."
    }
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

if (-not (Test-Path -LiteralPath $Sprx -PathType Leaf)) { throw "Missing SPRX: $Sprx" }
if (-not (Test-Path -LiteralPath $StubC -PathType Leaf)) { throw "Missing stub C: $StubC" }
if (-not (Test-Path -LiteralPath $NidDb -PathType Leaf)) { throw "Missing aerolib.csv: $NidDb" }

if (Test-Path -LiteralPath $OutDir) {
    Remove-Item -LiteralPath $OutDir -Recurse -Force
}
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$SprxUnix = Convert-ToWslPath $Sprx
$StubUnix = Convert-ToWslPath $StubC
$NidUnix  = Convert-ToWslPath $NidDb
$OutUnix  = Convert-ToWslPath $OutDir
$WorkUnix = "/tmp/agc_stage41"

$TargetNid = "UglJIZjGssM"
$TargetName = "sceAgcDriverSubmitDcb"

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "AGC PS5 Stage 41 - SubmitDcb ABI Audit" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Info "SPRX   = $Sprx"
Write-Info "Stub C = $StubC"
Write-Info "NID DB = $NidDb"
Write-Info "Output = $OutDir"
Write-Info "NID    = $TargetNid"
Write-Info "Name   = $TargetName"

Write-Step "Verify Python + pyelftools"
$probe = @'
from elftools.elf.elffile import ELFFile
print("pyelftools=OK")
'@
$probeFile = Join-Path $OutDir "pyelftools_probe.py"
Set-Content -LiteralPath $probeFile -Value $probe -Encoding UTF8
& $Python $probeFile
if ($LASTEXITCODE -ne 0) { throw "pyelftools is unavailable in $Python." }
Remove-Item -LiteralPath $probeFile -Force

Write-Step "Read NID database mapping"
$Mapping = Select-String -LiteralPath $NidDb -Pattern ("^{0} " -f [regex]::Escape($TargetNid)) -SimpleMatch:$false
$NidMapped = $null
if ($Mapping) {
    $NidMapped = $Mapping.Line
    Write-Info "aerolib: $NidMapped"
} else {
    Write-Host "[WARN] Target NID not found in aerolib.csv" -ForegroundColor Yellow
}

Write-Step "Inspect generated stub"
$StubText = Get-Content -LiteralPath $StubC -Raw
$StubNamePresent = $StubText.Contains($TargetName)
$StubNidPresent = $StubText.Contains($TargetNid)
$StubDlsymRegex = [regex]::Escape($TargetNid)
$StubDlsymHits = @(
    $StubText -split "`n" |
        Where-Object { $_ -match "sprx_dlsym.*$StubDlsymRegex|$StubDlsymRegex.*sprx_dlsym" }
)
Write-Info "stub name present : $StubNamePresent"
Write-Info "stub NID literal  : $StubNidPresent"
Write-Info "stub dlsym hits   : $($StubDlsymHits.Count)"

Write-Step "Extract SPRX dynamic symbol evidence"
$SprxJson = Join-Path $OutDir "sprx_dynamic_symbols.json"
$SprxReportPy = @'
import json, sys
from elftools.elf.elffile import ELFFile
sprx = sys.argv[1]
out = sys.argv[2]
target_nid = sys.argv[3]
records = []
with open(sprx, 'rb') as f:
    elf = ELFFile(f)
    for seg in elf.iter_segments():
        if seg.header.p_type != 'PT_DYNAMIC':
            continue
        for sym in seg.iter_symbols():
            name = sym.name or ''
            if not name or '#' not in name:
                continue
            parts = name.split('#')
            if len(parts) != 3:
                continue
            nid, lid, mid = parts
            if nid != target_nid:
                continue
            records.append({
                'raw_name': name,
                'nid': nid,
                'lid': lid,
                'mid': mid,
                'st_value': int(sym.entry['st_value']),
                'st_size': int(sym.entry['st_size']),
                'binding': sym.entry['st_info']['bind'],
                'type': sym.entry['st_info']['type'],
                'section_index': str(sym.entry['st_shndx'])
            })
with open(out, 'w', encoding='utf-8') as g:
    json.dump(records, g, indent=2)
print(json.dumps(records, indent=2))
'@
$PyFile = Join-Path $OutDir "extract_sprx.py"
Set-Content -LiteralPath $PyFile -Value $SprxReportPy -Encoding UTF8
& $Python $PyFile $Sprx $SprxJson $TargetNid
if ($LASTEXITCODE -ne 0) { throw "SPRX symbol extraction failed." }
Remove-Item -LiteralPath $PyFile -Force

$DynamicRecords = Get-Content -LiteralPath $SprxJson -Raw | ConvertFrom-Json
$DynamicCount = @($DynamicRecords).Count
Write-Info "matching SPRX exports: $DynamicCount"

Write-Step "Audit related Submit/CommandBuffer exports"
$Related = @(
    Select-String -LiteralPath $StubC -Pattern 'sceAgcDriver.*Submit|sceAgc.*CommandBuffer|sceAgcCbBranch' |
        ForEach-Object {
            [ordered]@{ line = $_.LineNumber; text = $_.Line.Trim() }
        }
)
$Related | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $OutDir "related_exports.json") -Encoding UTF8
Write-Info "related stub lines: $($Related.Count)"

Write-Step "Static conclusion"
$IdentityPass = (
    $NidMapped -eq "$TargetNid $TargetName" -and
    $StubNamePresent -and
    $DynamicCount -gt 0
)

$Report = [ordered]@{
    stage = 41
    timestamp = (Get-Date).ToString('o')
    target = [ordered]@{ name = $TargetName; nid = $TargetNid }
    sources = [ordered]@{
        sprx = $Sprx
        sprx_sha256 = Get-Sha256 $Sprx
        stub_c = $StubC
        stub_c_sha256 = Get-Sha256 $StubC
        aerolib = $NidDb
        aerolib_sha256 = Get-Sha256 $NidDb
    }
    identity = [ordered]@{
        aerolib_mapping = $NidMapped
        stub_name_present = $StubNamePresent
        stub_nid_literal_present = $StubNidPresent
        stub_dlsym_hits = $StubDlsymHits
        sprx_matching_exports = @($DynamicRecords)
        identity_confirmed = $IdentityPass
    }
    abi = [ordered]@{
        argument_count_confirmed = $false
        argument_types_confirmed = $false
        return_type_confirmed = $false
        execution_performed = $false
        note = 'Stage 41 is static. It does not infer a C prototype from the export name and does not invoke SubmitDcb.'
    }
}

$ReportPath = Join-Path $OutDir "STAGE41_REPORT.json"
$Report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $ReportPath -Encoding UTF8

$Summary = @(
    "AGC PS5 Stage 41",
    "=================",
    "",
    "Identity confirmed : $IdentityPass",
    "NID                : $TargetNid",
    "Name               : $TargetName",
    "SPRX exports found : $DynamicCount",
    "Stub name present  : $StubNamePresent",
    "Stub NID literal   : $StubNidPresent",
    "",
    "ABI prototype      : NOT inferred",
    "Execution          : NO",
    "",
    "Report             : $ReportPath"
)
$Summary | Set-Content -LiteralPath (Join-Path $OutDir "STAGE41_REPORT.txt") -Encoding UTF8

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
if ($IdentityPass) {
    Write-Host "SUBMIT_DCB_IDENTITY = PASS" -ForegroundColor Green
} else {
    Write-Host "SUBMIT_DCB_IDENTITY = FAIL" -ForegroundColor Red
}
Write-Host "ABI_PROTOTYPE_INFERRED = NO" -ForegroundColor Yellow
Write-Host "EXECUTED_SUBMIT_DCB = NO" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "Results: $OutDir"
