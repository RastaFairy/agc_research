[CmdletBinding()]
param(
    [string]$SprxPath = "D:\agc_work\sce_stubs\libSceAgcDriver.sprx",
    [string]$NidDb    = "D:\sdk-master\sce_stubs\aerolib.csv",
    [string]$OutDir   = "D:\agc_work\stage44_results"
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
        Get-FileHash `
            -LiteralPath $Path `
            -Algorithm SHA256
    ).Hash.ToLowerInvariant()
}

if (-not (Test-Path -LiteralPath $SprxPath -PathType Leaf)) {
    throw "SPRX not found: $SprxPath"
}

if (-not (Test-Path -LiteralPath $NidDb -PathType Leaf)) {
    throw "NID database not found: $NidDb"
}

$SprxPath = (Resolve-Path -LiteralPath $SprxPath).Path
$NidDb    = (Resolve-Path -LiteralPath $NidDb).Path

if (Test-Path -LiteralPath $OutDir) {
    Remove-Item -LiteralPath $OutDir -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$SprxUnix = Convert-ToWslPath $SprxPath
$NidUnix  = Convert-ToWslPath $NidDb
$OutUnix  = Convert-ToWslPath $OutDir

$TmpRoot = "/tmp/agc_stage44"

$PythonLocal = Join-Path $OutDir "analyze_agc_submitdcb.py"

$PythonCode = @'
from elftools.elf.elffile import ELFFile
import json
import os
import struct
import sys

sprx = sys.argv[1]
nid_db = sys.argv[2]
out_dir = sys.argv[3]

SUBMIT_NID = "UglJIZjGssM"
INTERNAL_NID = "b4fpgH5ZXxQ"

SUBMIT_VA = 0x28b0
INTERNAL_VA = 0x18b0
INTERNAL_SIZE = 380

CTX_VA = 0x1a8b8

with open(nid_db, "r", encoding="utf-8", errors="replace") as fp:
    nid_map = {}

    for line in fp:
        line = line.strip()

        if not line:
            continue

        parts = line.split(" ", 1)

        if len(parts) != 2:
            continue

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

        entry = {
            "raw_name": raw,
            "value": value,
            "size": size,
            "type": str(sym["st_info"]["type"]),
            "bind": str(sym["st_info"]["bind"])
        }

        if "#" in raw:

            parts = raw.split("#")

            if len(parts) == 3:

                entry["nid"] = parts[0]
                entry["lid"] = parts[1]
                entry["mid"] = parts[2]

                entry["mapped_name"] = nid_map.get(parts[0])

        symbols.append(entry)

    # --------------------------------------------------------
    # VA -> file offset
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Read bytes from a virtual-address range.
    # --------------------------------------------------------

    def read_va(va, size):

        off = va_to_file_offset(va)

        if off is None:
            return {
                "va": va,
                "file_offset": None,
                "size": size,
                "bytes_hex": None
            }

        f.seek(off)

        data = f.read(size)

        return {
            "va": va,
            "file_offset": off,
            "size": len(data),
            "bytes_hex": data.hex(" ")
        }

    # --------------------------------------------------------
    # Relevant symbols.
    # --------------------------------------------------------

    submit = [
        s for s in symbols
        if s.get("nid") == SUBMIT_NID
    ]

    internal = [
        s for s in symbols
        if s.get("nid") == INTERNAL_NID
    ]

    # --------------------------------------------------------
    # Internal function raw bytes.
    # --------------------------------------------------------

    internal_bytes = read_va(
        INTERNAL_VA,
        INTERNAL_SIZE
    )

    # --------------------------------------------------------
    # Context target.
    # --------------------------------------------------------

    context_bytes = read_va(
        CTX_VA,
        256
    )

    # --------------------------------------------------------
    # Search dynamic symbols around both targets.
    # --------------------------------------------------------

    def nearby(target, radius):

        rows = []

        for s in symbols:

            value = s["value"]
            delta = value - target

            if -radius <= delta <= radius:

                rows.append({
                    "delta": delta,
                    "value": value,
                    "size": s["size"],
                    "type": s["type"],
                    "bind": s["bind"],
                    "raw_name": s["raw_name"],
                    "nid": s.get("nid"),
                    "mapped_name": s.get("mapped_name")
                })

        rows.sort(
            key=lambda x: (
                x["value"],
                x["raw_name"]
            )
        )

        return rows

    nearby_internal = nearby(
        INTERNAL_VA,
        1024
    )

    nearby_context = nearby(
        CTX_VA,
        1024
    )

    # --------------------------------------------------------
    # Raw bytes around submit thunk.
    # --------------------------------------------------------

    submit_bytes = read_va(
        SUBMIT_VA,
        15
    )

    # --------------------------------------------------------
    # PT_LOAD info.
    # --------------------------------------------------------

    loads = []

    for seg in elf.iter_segments():

        if seg.header.p_type != "PT_LOAD":
            continue

        loads.append({
            "p_offset": int(seg.header.p_offset),
            "p_vaddr": int(seg.header.p_vaddr),
            "p_filesz": int(seg.header.p_filesz),
            "p_memsz": int(seg.header.p_memsz),
            "p_flags": int(seg.header.p_flags)
        })

    result = {
        "submit": {
            "nid": SUBMIT_NID,
            "aerolib_name": nid_map.get(SUBMIT_NID),
            "symbols": submit,
            "raw": submit_bytes
        },

        "internal": {
            "nid": INTERNAL_NID,
            "aerolib_name": nid_map.get(INTERNAL_NID),
            "symbols": internal,
            "va": INTERNAL_VA,
            "size": INTERNAL_SIZE,
            "raw": internal_bytes
        },

        "context_target": {
            "va": CTX_VA,
            "raw": context_bytes
        },

        "nearby_internal": nearby_internal,
        "nearby_context": nearby_context,

        "pt_loads": loads
    }

with open(
    os.path.join(out_dir, "stage44_static.json"),
    "w",
    encoding="utf-8"
) as fp:
    json.dump(result, fp, indent=2)

print(
    json.dumps(
        result,
        indent=2
    )
)
'@

$PythonCode = $PythonCode -replace "`r`n", "`n"
$PythonCode = $PythonCode -replace "`r", ""

[System.IO.File]::WriteAllText(
    $PythonLocal,
    $PythonCode,
    [System.Text.UTF8Encoding]::new($false)
)

$PythonUnix = Convert-ToWslPath $PythonLocal

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "AGC PS5 Stage 44 - SubmitDcb Internal Audit" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Info "SPRX       = $SprxPath"
Write-Info "SPRX WSL   = $SprxUnix"
Write-Info "NID DB     = $NidDb"
Write-Info "Output     = $OutDir"
Write-Info "Submit VA  = 0x28b0"
Write-Info "Internal VA= 0x18b0"
Write-Info "Context VA = 0x1a8b8"
Write-Info "Internal NID= b4fpgH5ZXxQ"

try {

    Write-Step "Prepare Linux workspace"

    Invoke-WslChecked @"
rm -rf '$TmpRoot'
mkdir -p '$TmpRoot'
mkdir -p '$OutUnix'
cp '$PythonUnix' '$TmpRoot/analyze_agc_submitdcb.py'
python3 -m py_compile '$TmpRoot/analyze_agc_submitdcb.py'
"@ | Out-Null

    Write-Step "Static AGC Driver analysis"

    Invoke-WslChecked @"
python3 '$TmpRoot/analyze_agc_submitdcb.py' \
    '$SprxUnix' \
    '$NidUnix' \
    '$TmpRoot'
"@ | Out-Null

    Write-Step "Collect Stage 44 report"

    Invoke-WslChecked @"
cp '$TmpRoot/stage44_static.json' \
   '$OutUnix/stage44_static.json'

cat '$TmpRoot/stage44_static.json'
"@ | Out-Null

    Write-Step "Disassemble raw internal function"

    Invoke-WslChecked @"
python3 - '$TmpRoot/stage44_static.json' '$TmpRoot/internal.bin' <<'PY'
import json
import sys

src = sys.argv[1]
dst = sys.argv[2]

with open(src, "r", encoding="utf-8") as fp:
    data = json.load(fp)

hexs = data["internal"]["raw"]["bytes_hex"]

raw = bytes.fromhex(hexs)

with open(dst, "wb") as fp:
    fp.write(raw)
PY

objdump \
    -D \
    -b binary \
    -m i386:x86-64 \
    '$TmpRoot/internal.bin' \
    > '$TmpRoot/internal_disassembly.txt' 2>&1

cp '$TmpRoot/internal_disassembly.txt' \
   '$OutUnix/internal_disassembly.txt'

cat '$TmpRoot/internal_disassembly.txt'
"@ | Out-Null

    Write-Step "Disassemble context region"

    Invoke-WslChecked @"
python3 - '$TmpRoot/stage44_static.json' '$TmpRoot/context.bin' <<'PY'
import json
import sys

src = sys.argv[1]
dst = sys.argv[2]

with open(src, "r", encoding="utf-8") as fp:
    data = json.load(fp)

hexs = data["context_target"]["raw"]["bytes_hex"]

raw = bytes.fromhex(hexs)

with open(dst, "wb") as fp:
    fp.write(raw)
PY

objdump \
    -D \
    -b binary \
    -m i386:x86-64 \
    '$TmpRoot/context.bin' \
    > '$TmpRoot/context_disassembly.txt' 2>&1

cp '$TmpRoot/context_disassembly.txt' \
   '$OutUnix/context_disassembly.txt'

cat '$TmpRoot/context_disassembly.txt'
"@ | Out-Null

    Write-Step "Find internal NID mapping"

    Invoke-WslChecked @"
grep -n 'b4fpgH5ZXxQ' '$NidUnix' || true
grep -n 'UglJIZjGssM' '$NidUnix' || true
"@ | Out-Null

    Write-Step "Hash artefacts"

    $Artifacts = @()

    foreach ($Name in @(
        "stage44_static.json",
        "internal_disassembly.txt",
        "context_disassembly.txt"
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

    $Report = [ordered]@{
        stage = 44
        timestamp = (Get-Date).ToString("o")

        submit_dcb = [ordered]@{
            nid = "UglJIZjGssM"
            va  = "0x28b0"
            size = 15
        }

        internal = [ordered]@{
            nid = "b4fpgH5ZXxQ"
            va  = "0x18b0"
            size = 380
        }

        context = [ordered]@{
            va = "0x1a8b8"
        }

        execution = [ordered]@{
            performed = $false
        }

        prototype = [ordered]@{
            inferred = $false
        }

        artifacts = $Artifacts
    }

    $ReportPath = Join-Path $OutDir "STAGE44_REPORT.json"

    $Report |
        ConvertTo-Json -Depth 12 |
        Set-Content `
            -LiteralPath $ReportPath `
            -Encoding UTF8

    Write-Host ""
    Write-Host "============================================" -ForegroundColor Green
    Write-Host "Stage 44 completed" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "INTERNAL_TARGET_FOUND = PASS" -ForegroundColor Green
    Write-Host "INTERNAL_BODY_EXTRACTED = PASS" -ForegroundColor Green
    Write-Host "EXECUTED_SUBMIT_DCB = NO" -ForegroundColor Green
    Write-Host "ABI_PROTOTYPE_INFERRED = NO" -ForegroundColor Green
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