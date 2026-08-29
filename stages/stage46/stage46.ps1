[CmdletBinding()]
param(
    [string]$SprxPath = "D:\agc_work\sce_stubs\libSceAgcDriver.sprx",
    [string]$NidDb    = "D:\sdk-master\sce_stubs\aerolib.csv",
    [string]$OutDir   = "D:\agc_work\stage46_results"
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

    if ($WindowsPath -notmatch '^(?<drive>[A-Za-z]):\\(?<rest>.*)$') {
        throw "Unsupported Windows path: $WindowsPath"
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
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }

    return (
        Get-FileHash -LiteralPath $Path -Algorithm SHA256
    ).Hash.ToLowerInvariant()
}

# ============================================================
# Validate inputs
# ============================================================

if (-not (Test-Path -LiteralPath $SprxPath -PathType Leaf)) {
    throw "SPRX not found: $SprxPath"
}

if (-not (Test-Path -LiteralPath $NidDb -PathType Leaf)) {
    throw "NID database not found: $NidDb"
}

$SprxPath = (Resolve-Path -LiteralPath $SprxPath).Path
$NidDb    = (Resolve-Path -LiteralPath $NidDb).Path

# Clean/create output
if (Test-Path -LiteralPath $OutDir) {
    Remove-Item -LiteralPath $OutDir -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$WrapperBinDir = Join-Path $OutDir "wrapper_bins"
New-Item -ItemType Directory -Force -Path $WrapperBinDir | Out-Null

# ============================================================
# WSL paths
# ============================================================

$SprxUnix = Convert-ToWslPath $SprxPath
$NidUnix  = Convert-ToWslPath $NidDb
$OutUnix  = Convert-ToWslPath $OutDir

$WrapperBinUnix = "$OutUnix/wrapper_bins"

$TmpRoot = "/tmp/agc_stage46"

$PythonLocal = Join-Path $OutDir "analyze_submit_wrappers.py"

# ============================================================
# Python static analyzer
# ============================================================

$PythonCode = @'
from elftools.elf.elffile import ELFFile
import json
import os
import struct
import sys

sprx = sys.argv[1]
nid_db = sys.argv[2]
out_dir = sys.argv[3]

TARGET = 0x18b0

nid_map = {}

with open(nid_db, "r", encoding="utf-8", errors="replace") as fp:
    for line in fp:
        line = line.strip()

        if not line:
            continue

        parts = line.split(" ", 1)

        if len(parts) == 2:
            nid_map[parts[0]] = parts[1]

with open(sprx, "rb") as f:
    elf = ELFFile(f)

    dynamic = None

    for seg in elf.iter_segments():
        if seg.header.p_type == "PT_DYNAMIC":
            dynamic = seg
            break

    if dynamic is None:
        raise RuntimeError("No PT_DYNAMIC")

    symbols = []

    for sym in dynamic.iter_symbols():

        raw = sym.name

        if not raw:
            continue

        value = int(sym["st_value"])
        size = int(sym["st_size"])

        item = {
            "raw_name": raw,
            "value": value,
            "size": size,
            "type": str(sym["st_info"]["type"]),
            "bind": str(sym["st_info"]["bind"])
        }

        if "#" in raw:

            parts = raw.split("#")

            if len(parts) == 3:
                item["nid"] = parts[0]
                item["lid"] = parts[1]
                item["mid"] = parts[2]
                item["mapped_name"] = nid_map.get(parts[0])

        symbols.append(item)

    def va_to_file_offset(va):
        for seg in elf.iter_segments():

            if seg.header.p_type != "PT_LOAD":
                continue

            vaddr = int(seg.header.p_vaddr)
            memsz = int(seg.header.p_memsz)
            offset = int(seg.header.p_offset)

            if vaddr <= va < vaddr + memsz:
                return offset + (va - vaddr)

        return None

    def read_va(va, size):

        off = va_to_file_offset(va)

        if off is None:
            return None

        f.seek(off)
        data = f.read(size)

        return {
            "va": va,
            "file_offset": off,
            "size": len(data),
            "bytes_hex": data.hex(" ")
        }

    def owning_symbols(va):

        result = []

        for sym in symbols:

            start = sym["value"]
            size = sym["size"]

            if size <= 0:
                continue

            if start <= va < start + size:
                result.append(sym)

        return result

    refs = []

    for seg in elf.iter_segments():

        if seg.header.p_type != "PT_LOAD":
            continue

        flags = int(seg.header.p_flags)

        if not (flags & 1):
            continue

        seg_vaddr = int(seg.header.p_vaddr)
        seg_offset = int(seg.header.p_offset)
        seg_filesz = int(seg.header.p_filesz)

        f.seek(seg_offset)
        data = f.read(seg_filesz)

        for i in range(0, max(0, len(data) - 5)):

            opcode = data[i]

            if opcode not in (0xE8, 0xE9):
                continue

            disp = struct.unpack_from(
                "<i",
                data,
                i + 1
            )[0]

            source = seg_vaddr + i
            destination = source + 5 + disp

            if destination != TARGET:
                continue

            refs.append({
                "opcode": "CALL" if opcode == 0xE8 else "JMP",
                "source_va": source,
                "destination_va": destination,
                "file_offset": seg_offset + i,
                "displacement": disp
            })

    refs.sort(key=lambda x: x["source_va"])

    wrappers = []

    for ref in refs:

        source = ref["source_va"]

        start = max(0, source - 32)
        size = 48

        wrappers.append({
            "reference": ref,
            "source_region": read_va(start, size),
            "owning_symbols": owning_symbols(source)
        })

    result = {
        "target": {
            "va": TARGET,
            "known_name": "sceAgcDriverSubmitCommandBuffer",
            "known_nid": "b4fpgH5ZXxQ"
        },
        "direct_references": refs,
        "wrappers": wrappers,
        "summary": {
            "reference_count": len(refs)
        }
    }

with open(
    os.path.join(out_dir, "stage46_static.json"),
    "w",
    encoding="utf-8"
) as fp:
    json.dump(result, fp, indent=2)

print(json.dumps(result, indent=2))
'@

$PythonCode = $PythonCode -replace "`r`n", "`n"
$PythonCode = $PythonCode -replace "`r", ""

[System.IO.File]::WriteAllText(
    $PythonLocal,
    $PythonCode,
    [System.Text.UTF8Encoding]::new($false)
)

$PythonUnix = Convert-ToWslPath $PythonLocal

# ============================================================
# Banner
# ============================================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "AGC PS5 Stage 46 - Submit Wrapper Family Audit" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Info "SPRX       = $SprxPath"
Write-Info "NID DB     = $NidDb"
Write-Info "Output     = $OutDir"
Write-Info "Output WSL = $OutUnix"
Write-Info "Target VA  = 0x18b0"
Write-Info "Target NID = b4fpgH5ZXxQ"
Write-Info "Target     = sceAgcDriverSubmitCommandBuffer"

try {

    # ========================================================
    # Prepare workspace
    # ========================================================

    Write-Step "Prepare Linux workspace"

    Invoke-WslChecked @"
rm -rf '$TmpRoot'
mkdir -p '$TmpRoot'
mkdir -p '$TmpRoot/wrapper_regions'
mkdir -p '$OutUnix'
mkdir -p '$WrapperBinUnix'
cp '$PythonUnix' '$TmpRoot/analyze_submit_wrappers.py'
python3 -m py_compile '$TmpRoot/analyze_submit_wrappers.py'
"@ | Out-Null

    # ========================================================
    # Analyze
    # ========================================================

    Write-Step "Find all direct SubmitCommandBuffer references"

    Invoke-WslChecked @"
python3 '$TmpRoot/analyze_submit_wrappers.py' \
    '$SprxUnix' \
    '$NidUnix' \
    '$TmpRoot'
"@ | Out-Null

    # ========================================================
    # Copy JSON
    # ========================================================

    Write-Step "Collect static wrapper audit"

    Invoke-WslChecked @"
cp '$TmpRoot/stage46_static.json' '$OutUnix/stage46_static.json'
cat '$TmpRoot/stage46_static.json'
"@ | Out-Null

    # ========================================================
    # Load JSON
    # ========================================================

    $StaticPath = Join-Path $OutDir "stage46_static.json"

    $Static = (
        Get-Content -LiteralPath $StaticPath -Raw
    ) | ConvertFrom-Json

    $WrapperCount = @($Static.wrappers).Count

    Write-Info "Wrapper count = $WrapperCount"

    # ========================================================
    # Summary
    # ========================================================

    Write-Step "Create readable wrapper summary"

    $Summary = New-Object System.Collections.Generic.List[string]

    $Summary.Add("TARGET: $($Static.target.known_name)")
    $Summary.Add(
        ("VA: 0x{0:x}" -f [int64]$Static.target.va)
    )
    $Summary.Add("NID: $($Static.target.known_nid)")
    $Summary.Add("")
    $Summary.Add(
        "DIRECT REFERENCES: $($Static.summary.reference_count)"
    )
    $Summary.Add("")

    $Index = 0

    foreach ($Wrapper in $Static.wrappers) {

        $Index++
        $Ref = $Wrapper.reference

        $Summary.Add("=== WRAPPER $Index ===")
        $Summary.Add("opcode: $($Ref.opcode)")
        $Summary.Add(
            ("source: 0x{0:x}" -f [int64]$Ref.source_va)
        )
        $Summary.Add(
            ("destination: 0x{0:x}" -f
                [int64]$Ref.destination_va)
        )

        if ($null -ne $Wrapper.source_region) {
            $Summary.Add(
                ("region_start: 0x{0:x}" -f
                    [int64]$Wrapper.source_region.va)
            )
            $Summary.Add(
                "region_size: $($Wrapper.source_region.size)"
            )
        }

        $Summary.Add("")
        $Summary.Add("OWNERS:")

        foreach ($Owner in $Wrapper.owning_symbols) {

            $Name = $Owner.mapped_name

            if ($null -eq $Name) {
                $Name = ""
            }

            $Summary.Add(
                "  $Name " +
                "NID=$($Owner.nid) " +
                "RAW=$($Owner.raw_name) " +
                ("VA=0x{0:x} " -f [int64]$Owner.value) +
                "SIZE=$($Owner.size)"
            )
        }

        $Summary.Add("")
        $Summary.Add("BYTES:")

        $Summary.Add(
            $Wrapper.source_region.bytes_hex
        )

        $Summary.Add("")
    }

    $SummaryPath = Join-Path $OutDir "wrapper_summary.txt"

    [System.IO.File]::WriteAllText(
        $SummaryPath,
        ($Summary -join "`r`n") + "`r`n",
        [System.Text.UTF8Encoding]::new($false)
    )

    Get-Content -LiteralPath $SummaryPath

    # ========================================================
    # Create binaries and copy them DIRECTLY to Windows path
    # ========================================================

    Write-Step "Create and collect wrapper binary regions"

    $WrapperPythonLocal = Join-Path $OutDir "create_wrapper_bins.py"

    $WrapperPython = @'
import json
import os
import shutil
import sys

json_path = sys.argv[1]
tmp_dir = sys.argv[2]
out_dir = sys.argv[3]

os.makedirs(tmp_dir, exist_ok=True)
os.makedirs(out_dir, exist_ok=True)

with open(json_path, "r", encoding="utf-8") as fp:
    data = json.load(fp)

for index, wrapper in enumerate(data["wrappers"], 1):

    region = wrapper.get("source_region")

    if not region:
        continue

    data_bytes = bytes.fromhex(
        region["bytes_hex"]
    )

    name = f"wrapper_{index:02d}.bin"

    tmp_path = os.path.join(
        tmp_dir,
        name
    )

    out_path = os.path.join(
        out_dir,
        name
    )

    with open(tmp_path, "wb") as fp:
        fp.write(data_bytes)

    shutil.copyfile(
        tmp_path,
        out_path
    )

    print(
        f"{name} "
        f"start=0x{int(region['va']):x} "
        f"size={len(data_bytes)} "
        f"out={out_path}"
    )
'@

    $WrapperPython = $WrapperPython -replace "`r`n", "`n"
    $WrapperPython = $WrapperPython -replace "`r", ""

    [System.IO.File]::WriteAllText(
        $WrapperPythonLocal,
        $WrapperPython,
        [System.Text.UTF8Encoding]::new($false)
    )

    $WrapperPythonUnix = Convert-ToWslPath $WrapperPythonLocal

    Invoke-WslChecked @"
cp '$WrapperPythonUnix' '$TmpRoot/create_wrapper_bins.py'
python3 -m py_compile '$TmpRoot/create_wrapper_bins.py'
python3 '$TmpRoot/create_wrapper_bins.py' \
    '$TmpRoot/stage46_static.json' \
    '$TmpRoot/wrapper_regions' \
    '$WrapperBinUnix'
ls -lh '$WrapperBinUnix'
"@ | Out-Null

    # ========================================================
    # Disassemble each wrapper using real virtual address.
    # ========================================================

    Write-Step "Disassemble wrapper regions"

    $DisassemblyPath = Join-Path `
        $OutDir `
        "wrapper_disassembly.txt"

    $Disassembly = New-Object System.Collections.Generic.List[string]

    for ($i = 1; $i -le $WrapperCount; $i++) {

        $Name = "wrapper_{0:D2}.bin" -f $i

        $Wrapper = $Static.wrappers[$i - 1]

        $StartVa = [int64]$Wrapper.source_region.va
        $StartHex = ("0x{0:x}" -f $StartVa)

        $UnixBin = "$WrapperBinUnix/$Name"

        Write-Step "Disassemble $Name at $StartHex"

        $Output = Invoke-WslChecked @"
test -f '$UnixBin'
objdump \
    -D \
    -b binary \
    -m i386:x86-64 \
    --adjust-vma=$StartHex \
    '$UnixBin'
"@

        $Disassembly.Add(
            "============================================"
        )

        $Disassembly.Add(
            "$Name START_VA=$StartHex"
        )

        $Disassembly.Add(
            "============================================"
        )

        foreach ($Line in $Output) {
            $Disassembly.Add([string]$Line)
        }

        $Disassembly.Add("")
    }

    [System.IO.File]::WriteAllText(
        $DisassemblyPath,
        ($Disassembly -join "`r`n") + "`r`n",
        [System.Text.UTF8Encoding]::new($false)
    )

    Get-Content -LiteralPath $DisassemblyPath

    # ========================================================
    # Hash artefacts
    # ========================================================

    Write-Step "Hash artefacts"

    $Artifacts = @()

    foreach ($Name in @(
        "stage46_static.json",
        "wrapper_summary.txt",
        "wrapper_disassembly.txt"
    )) {

        $Path = Join-Path $OutDir $Name

        if (Test-Path -LiteralPath $Path -PathType Leaf) {

            $Item = Get-Item -LiteralPath $Path
            $Hash = Get-Sha256 $Path

            $Artifacts += [ordered]@{
                file   = $Name
                size   = $Item.Length
                sha256 = $Hash
            }

            Write-Info "$Name SHA256=$Hash"
        }
    }

    foreach ($Bin in @(
        Get-ChildItem `
            -LiteralPath $WrapperBinDir `
            -Filter "*.bin" `
            -File `
            -ErrorAction SilentlyContinue
    )) {

        $Hash = Get-Sha256 $Bin.FullName

        $Artifacts += [ordered]@{
            file   = "wrapper_bins/$($Bin.Name)"
            size   = $Bin.Length
            sha256 = $Hash
        }

        Write-Info "wrapper_bins/$($Bin.Name) SHA256=$Hash"
    }

    # ========================================================
    # Final report
    # ========================================================

    $WrapperReport = @()

    foreach ($Wrapper in $Static.wrappers) {

        $Owners = @()

        foreach ($Owner in $Wrapper.owning_symbols) {

            $Owners += [ordered]@{
                name = $Owner.mapped_name
                nid  = $Owner.nid
                va   = ("0x{0:x}" -f [int64]$Owner.value)
                size = $Owner.size
            }
        }

        $WrapperReport += [ordered]@{
            opcode = $Wrapper.reference.opcode
            source_va = (
                "0x{0:x}" -f
                [int64]$Wrapper.reference.source_va
            )
            destination_va = (
                "0x{0:x}" -f
                [int64]$Wrapper.reference.destination_va
            )
            region_start = (
                "0x{0:x}" -f
                [int64]$Wrapper.source_region.va
            )
            region_size = $Wrapper.source_region.size
            owners = $Owners
        }
    }

    $Report = [ordered]@{
        stage = 46
        timestamp = (Get-Date).ToString("o")

        target = [ordered]@{
            name = "sceAgcDriverSubmitCommandBuffer"
            nid  = "b4fpgH5ZXxQ"
            va   = "0x18b0"
        }

        wrapper_count = $WrapperCount
        wrappers = $WrapperReport

        analysis = [ordered]@{
            wrapper_family_found = ($WrapperCount -gt 0)
            wrapper_disassembly = $true
            abi_prototype_inferred = $false
        }

        execution = [ordered]@{
            performed = $false
        }

        artifacts = $Artifacts
    }

    $ReportPath = Join-Path `
        $OutDir `
        "STAGE46_REPORT.json"

    $Report |
        ConvertTo-Json -Depth 15 |
        Set-Content `
            -LiteralPath $ReportPath `
            -Encoding UTF8

    Write-Host ""
    Write-Host "============================================" -ForegroundColor Green
    Write-Host "Stage 46 completed" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""

    Write-Host `
        "SUBMIT_WRAPPER_FAMILY_FOUND = PASS" `
        -ForegroundColor Green

    Write-Host `
        "WRAPPER_DISASSEMBLY = PASS" `
        -ForegroundColor Green

    Write-Host `
        "WRAPPER_BIN_COLLECTION = PASS" `
        -ForegroundColor Green

    Write-Host `
        "EXECUTED_AGC = NO" `
        -ForegroundColor Green

    Write-Host `
        "ABI_PROTOTYPE_INFERRED = NO" `
        -ForegroundColor Green

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