[CmdletBinding()]
param(
    [string]$SprxPath = "D:\agc_work\sce_stubs\libSceAgcDriver.sprx",
    [string]$OutDir   = "D:\agc_work\stage42_results"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Write-Step {
    param([string]$Message)

    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Info {
    param([string]$Message)

    Write-Host "[INFO] $Message"
}

function Convert-ToWslPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$WindowsPath
    )

    $Resolved = (Resolve-Path -LiteralPath $WindowsPath).Path

    if ($Resolved -notmatch '^(?<drive>[A-Za-z]):\\(?<rest>.*)$') {
        throw "Unsupported Windows path: $Resolved"
    }

    $Drive = $Matches.drive.ToLowerInvariant()
    $Rest  = $Matches.rest -replace '\\', '/'

    return "/mnt/$Drive/$Rest"
}

function Invoke-WslChecked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command
    )

    # Force LF only so Bash never receives CR characters.
    $Command = $Command -replace "`r`n", "`n"
    $Command = $Command -replace "`r", ""

    Write-Host ""
    Write-Host "[WSL] $Command" -ForegroundColor DarkCyan

    $Output = & wsl.exe `
        -d Ubuntu-24.04 `
        --cd / `
        -- bash -lc $Command 2>&1

    $ExitCode = $LASTEXITCODE

    foreach ($Line in $Output) {
        Write-Host $Line
    }

    if ($ExitCode -ne 0) {
        throw "WSL command failed with exit code $ExitCode."
    }

    return @($Output)
}

function Get-Sha256 {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }

    return (
        Get-FileHash -LiteralPath $Path -Algorithm SHA256
    ).Hash.ToLowerInvariant()
}

# ------------------------------------------------------------
# Paths
# ------------------------------------------------------------

if (-not (Test-Path -LiteralPath $SprxPath -PathType Leaf)) {
    throw "SPRX not found: $SprxPath"
}

$SprxPath = (Resolve-Path -LiteralPath $SprxPath).Path

if (Test-Path -LiteralPath $OutDir) {
    Remove-Item -LiteralPath $OutDir -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$SprxUnix = Convert-ToWslPath $SprxPath
$OutUnix  = Convert-ToWslPath $OutDir

$TmpRoot     = "/tmp/agc_stage42"
$PythonLocal = Join-Path $OutDir "extract_submitdcb.py"
$PythonUnix  = "$OutUnix/extract_submitdcb.py"

# ------------------------------------------------------------
# Python program
#
# Important:
# The SPRX has PT_DYNAMIC symbol information but apparently no
# normal .dynsym/.symtab section table. We therefore reproduce
# the same mechanism used by genstub.py:
#
#   PT_DYNAMIC -> iter_symbols()
# ------------------------------------------------------------

$PythonCode = @'
from elftools.elf.elffile import ELFFile
import json
import os
import sys

TARGET_NID = "UglJIZjGssM"
TARGET_NAME = "sceAgcDriverSubmitDcb"

sprx = sys.argv[1]
out_dir = sys.argv[2]

os.makedirs(out_dir, exist_ok=True)

with open(sprx, "rb") as f:
    elf = ELFFile(f)

    dynamic = None

    for segment in elf.iter_segments():
        if segment.header.p_type == "PT_DYNAMIC":
            dynamic = segment
            break

    if dynamic is None:
        raise RuntimeError("No PT_DYNAMIC segment found")

    match = None

    # This is the same symbol-table access model used by the
    # SDK's genstub.py.
    for sym in dynamic.iter_symbols():

        raw_name = sym.name

        if not raw_name:
            continue

        if "#" not in raw_name:
            continue

        parts = raw_name.split("#")

        if len(parts) != 3:
            continue

        nid, lid, mid = parts

        if nid != TARGET_NID:
            continue

        match = {
            "name": TARGET_NAME,
            "raw_name": raw_name,
            "nid": nid,
            "lid": lid,
            "mid": mid,
            "st_value": int(sym["st_value"]),
            "st_size": int(sym["st_size"]),
            "binding": str(sym["st_info"]["bind"]),
            "type": str(sym["st_info"]["type"]),
            "section_index": str(sym["st_shndx"])
        }

        break

    if match is None:
        raise RuntimeError(
            "Target NID not found in PT_DYNAMIC: " + TARGET_NID
        )

    target_addr = match["st_value"]
    target_size = match["st_size"]

    if target_size <= 0:
        raise RuntimeError(
            f"Target symbol has invalid size: {target_size}"
        )

    # --------------------------------------------------------
    # VA -> file offset using PT_LOAD
    # --------------------------------------------------------

    file_offset = None

    for seg in elf.iter_segments():

        if seg.header.p_type != "PT_LOAD":
            continue

        vaddr = int(seg.header.p_vaddr)
        memsz = int(seg.header.p_memsz)
        offset = int(seg.header.p_offset)

        if vaddr <= target_addr < (vaddr + memsz):
            file_offset = offset + (target_addr - vaddr)
            break

    if file_offset is None:
        raise RuntimeError(
            f"Could not map VA 0x{target_addr:x} to file offset"
        )

    # --------------------------------------------------------
    # Read exact function body
    # --------------------------------------------------------

    with open(sprx, "rb") as f:
        f.seek(file_offset)
        code = f.read(target_size)

    if len(code) != target_size:
        raise RuntimeError(
            f"Short read: expected {target_size} bytes, got {len(code)}"
        )

    result = {
        "export": match,
        "file_offset": file_offset,
        "bytes_hex": code.hex(" "),
        "byte_count": len(code)
    }

    with open(
        os.path.join(out_dir, "export_metadata.json"),
        "w",
        encoding="utf-8"
    ) as fp:
        json.dump(result, fp, indent=2)

    with open(
        os.path.join(out_dir, "export_bytes.bin"),
        "wb"
    ) as fp:
        fp.write(code)

    with open(
        os.path.join(out_dir, "export_bytes.hex"),
        "w",
        encoding="utf-8"
    ) as fp:
        fp.write(code.hex(" ") + "\n")

    print(json.dumps(result, indent=2))
'@

# Write Python in UTF-8 without BOM and with LF.
$PythonCode = $PythonCode -replace "`r`n", "`n"
$PythonCode = $PythonCode -replace "`r", ""

[System.IO.File]::WriteAllText(
    $PythonLocal,
    $PythonCode,
    [System.Text.UTF8Encoding]::new($false)
)

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "AGC PS5 Stage 42 - SubmitDcb Export Disasm" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Info "SPRX       = $SprxPath"
Write-Info "SPRX WSL   = $SprxUnix"
Write-Info "Output     = $OutDir"
Write-Info "Output WSL = $OutUnix"

try {

    # --------------------------------------------------------
    # Prepare workspace
    # --------------------------------------------------------

    Write-Step "Prepare Linux workspace"

    Invoke-WslChecked @"
rm -rf '$TmpRoot'
mkdir -p '$TmpRoot'
mkdir -p '$OutUnix'
cp '$PythonUnix' '$TmpRoot/extract_submitdcb.py'
python3 -m py_compile '$TmpRoot/extract_submitdcb.py'
ls -lh '$TmpRoot/extract_submitdcb.py'
"@ | Out-Null

    # --------------------------------------------------------
    # Verify pyelftools
    # --------------------------------------------------------

    Write-Step "Verify Python + pyelftools"

    Invoke-WslChecked 'python3 -c "from elftools.elf.elffile import ELFFile; print(\"pyelftools=OK\")"' | Out-Null

    # --------------------------------------------------------
    # Extract exact 15-byte export
    # --------------------------------------------------------

    Write-Step "Extract SubmitDcb export from PT_DYNAMIC"

    Invoke-WslChecked @"
python3 '$TmpRoot/extract_submitdcb.py' '$SprxUnix' '$TmpRoot'
"@ | Out-Null

    # --------------------------------------------------------
    # Copy primary evidence
    # --------------------------------------------------------

    Write-Step "Collect export metadata"

    Invoke-WslChecked @"
cp '$TmpRoot/export_metadata.json' '$OutUnix/export_metadata.json'
cp '$TmpRoot/export_bytes.bin' '$OutUnix/export_bytes.bin'
cp '$TmpRoot/export_bytes.hex' '$OutUnix/export_bytes.hex'
cat '$TmpRoot/export_metadata.json'
"@ | Out-Null

    # --------------------------------------------------------
    # Disassemble exact bytes
    # --------------------------------------------------------

    Write-Step "Disassemble exact export body"

    Invoke-WslChecked @"
objdump -D \
    -b binary \
    -m i386:x86-64 \
    '$TmpRoot/export_bytes.bin' \
    > '$TmpRoot/export_disassembly.txt' 2>&1
cat '$TmpRoot/export_disassembly.txt'
cp '$TmpRoot/export_disassembly.txt' '$OutUnix/export_disassembly.txt'
"@ | Out-Null

    # --------------------------------------------------------
    # Nearby dynamic exports
    # --------------------------------------------------------

    Write-Step "Inspect nearby dynamic exports"

    $NearbyLocal = Join-Path $OutDir "nearby_exports.py"
    $NearbyUnix  = "$OutUnix/nearby_exports.py"

    $NearbyCode = @'
from elftools.elf.elffile import ELFFile
import sys

sprx = sys.argv[1]
out = sys.argv[2]

target = 10416

with open(sprx, "rb") as f:
    elf = ELFFile(f)

    dynamic = None

    for segment in elf.iter_segments():
        if segment.header.p_type == "PT_DYNAMIC":
            dynamic = segment
            break

    if dynamic is None:
        raise RuntimeError("No PT_DYNAMIC")

    rows = []

    for sym in dynamic.iter_symbols():

        raw_name = sym.name

        if not raw_name or "#" not in raw_name:
            continue

        parts = raw_name.split("#")

        if len(parts) != 3:
            continue

        value = int(sym["st_value"])
        size = int(sym["st_size"])
        distance = value - target

        if -128 <= distance <= 128:
            rows.append(
                (
                    distance,
                    value,
                    size,
                    str(sym["st_info"]["type"]),
                    str(sym["st_info"]["bind"]),
                    raw_name
                )
            )

rows.sort()

with open(out, "w", encoding="utf-8") as fp:
    for row in rows:
        fp.write(
            f"delta={row[0]:+d} "
            f"va=0x{row[1]:x} "
            f"size={row[2]} "
            f"type={row[3]} "
            f"bind={row[4]} "
            f"{row[5]}\n"
        )

for row in rows:
    print(
        f"delta={row[0]:+d} "
        f"va=0x{row[1]:x} "
        f"size={row[2]} "
        f"type={row[3]} "
        f"bind={row[4]} "
        f"{row[5]}"
    )
'@

    $NearbyCode = $NearbyCode -replace "`r`n", "`n"
    $NearbyCode = $NearbyCode -replace "`r", ""

    [System.IO.File]::WriteAllText(
        $NearbyLocal,
        $NearbyCode,
        [System.Text.UTF8Encoding]::new($false)
    )

    Invoke-WslChecked @"
cp '$NearbyUnix' '$TmpRoot/nearby_exports.py'
python3 -m py_compile '$TmpRoot/nearby_exports.py'
python3 '$TmpRoot/nearby_exports.py' '$SprxUnix' '$TmpRoot/nearby_exports.txt'
cp '$TmpRoot/nearby_exports.txt' '$OutUnix/nearby_exports.txt'
cat '$TmpRoot/nearby_exports.txt'
"@ | Out-Null

    # --------------------------------------------------------
    # Create report
    # --------------------------------------------------------

    $MetadataPath = Join-Path $OutDir "export_metadata.json"

    if (-not (Test-Path -LiteralPath $MetadataPath -PathType Leaf)) {
        throw "Missing export_metadata.json"
    }

    $Metadata = (
        Get-Content -LiteralPath $MetadataPath -Raw
    ) | ConvertFrom-Json

    $ArtifactNames = @(
        "export_metadata.json",
        "export_bytes.bin",
        "export_bytes.hex",
        "export_disassembly.txt",
        "nearby_exports.txt"
    )

    $Artifacts = @()

    foreach ($Name in $ArtifactNames) {

        $Path = Join-Path $OutDir $Name

        if (Test-Path -LiteralPath $Path -PathType Leaf) {

            $Item = Get-Item -LiteralPath $Path

            $Artifacts += [ordered]@{
                file   = $Name
                size   = $Item.Length
                sha256 = Get-Sha256 $Path
            }
        }
    }

    $Report = [ordered]@{
        stage = 42

        timestamp = (Get-Date).ToString("o")

        target = [ordered]@{
            name = "sceAgcDriverSubmitDcb"
            nid  = "UglJIZjGssM"
        }

        export = $Metadata.export

        evidence = [ordered]@{
            source              = "PT_DYNAMIC"
            exact_body_extracted = $true
            byte_count           = $Metadata.byte_count
            executed             = $false
            abi_prototype_inferred = $false
        }

        artifacts = $Artifacts
    }

    $ReportPath = Join-Path $OutDir "STAGE42_REPORT.json"

    $Report |
        ConvertTo-Json -Depth 12 |
        Set-Content `
            -LiteralPath $ReportPath `
            -Encoding UTF8

    Write-Host ""
    Write-Host "============================================" -ForegroundColor Green
    Write-Host "Stage 42 completed" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "EXPORT_FOUND = TRUE" -ForegroundColor Green
    Write-Host "EXECUTED_SUBMIT_DCB = NO" -ForegroundColor Green
    Write-Host ""
    Write-Host "Results:"
    Write-Host "  $OutDir"
    Write-Host ""
    Write-Host "Report:"
    Write-Host "  $ReportPath"
}
catch {

    Write-Host ""
    Write-Host "FATAL ERROR" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red

    throw
}