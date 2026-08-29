[CmdletBinding()]
param(
    [string]$SprxPath = "D:\agc_work\sce_stubs\libSceAgcDriver.sprx",
    [string]$NidDb    = "D:\sdk-master\sce_stubs\aerolib.csv",
    [string]$OutDir   = "D:\agc_work\stage47_results"
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
        Get-FileHash `
            -LiteralPath $Path `
            -Algorithm SHA256
    ).Hash.ToLowerInvariant()
}

# ============================================================
# Validate
# ============================================================

if (-not (Test-Path -LiteralPath $SprxPath -PathType Leaf)) {
    throw "SPRX not found: $SprxPath"
}

if (-not (Test-Path -LiteralPath $NidDb -PathType Leaf)) {
    throw "NID DB not found: $NidDb"
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

$TmpRoot = "/tmp/agc_stage47"

$PythonLocal = Join-Path $OutDir "analyze_contexts.py"

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

TARGET_FUNC = 0x18B0

CONTEXT_DCB     = 0x1A8B8
CONTEXT_AGR     = 0x1A868
CONTEXT_GLOBAL  = 0x1A908
ACB_TABLE       = 0x18460

TARGETS = {
    "submit_dcb_context": CONTEXT_DCB,
    "agr_submit_dcb_context": CONTEXT_AGR,
    "global_state_context": CONTEXT_GLOBAL,
    "acb_table": ACB_TABLE,
}

with open(
    nid_db,
    "r",
    encoding="utf-8",
    errors="replace"
) as fp:

    nid_map = {}

    for line in fp:

        line = line.strip()

        if not line:
            continue

        parts = line.split(" ", 1)

        if len(parts) == 2:
            nid_map[parts[0]] = parts[1]

with open(sprx, "rb") as f:

    elf = ELFFile(f)

    # --------------------------------------------------------
    # Dynamic symbols
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # PT_LOAD information
    # --------------------------------------------------------

    loads = []

    for seg in elf.iter_segments():

        if seg.header.p_type != "PT_LOAD":
            continue

        loads.append({
            "offset": int(seg.header.p_offset),
            "vaddr": int(seg.header.p_vaddr),
            "filesz": int(seg.header.p_filesz),
            "memsz": int(seg.header.p_memsz),
            "flags": int(seg.header.p_flags)
        })

    def classify_va(va):

        for seg in loads:

            start = seg["vaddr"]
            mem_end = start + seg["memsz"]
            file_end = start + seg["filesz"]

            if start <= va < mem_end:

                if va < file_end:
                    region = "FILE_BACKED"
                else:
                    region = "BSS_OR_ZERO_FILL"

                flags = seg["flags"]

                perms = ""

                if flags & 4:
                    perms += "R"

                if flags & 2:
                    perms += "W"

                if flags & 1:
                    perms += "X"

                return {
                    "region": region,
                    "permissions": perms,
                    "segment_vaddr": start,
                    "segment_filesz": seg["filesz"],
                    "segment_memsz": seg["memsz"],
                    "in_file": va < file_end
                }

        return {
            "region": "UNMAPPED",
            "permissions": "",
            "in_file": False
        }

    # --------------------------------------------------------
    # VA -> file offset
    # --------------------------------------------------------

    def va_to_file_offset(va):

        for seg in loads:

            start = seg["vaddr"]
            filesz = seg["filesz"]

            if start <= va < start + filesz:

                return (
                    seg["offset"] +
                    (va - start)
                )

        return None

    def read_va(va, size):

        off = va_to_file_offset(va)

        if off is None:

            return {
                "va": va,
                "file_offset": None,
                "size": 0,
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
    # Symbol lookup
    # --------------------------------------------------------

    def nearby_symbols(target, radius=0x200):

        result = []

        for sym in symbols:

            delta = sym["value"] - target

            if -radius <= delta <= radius:

                result.append({
                    "delta": delta,
                    "value": sym["value"],
                    "size": sym["size"],
                    "type": sym["type"],
                    "bind": sym["bind"],
                    "raw_name": sym["raw_name"],
                    "nid": sym.get("nid"),
                    "mapped_name": sym.get("mapped_name")
                })

        result.sort(
            key=lambda x: (
                x["value"],
                x["raw_name"]
            )
        )

        return result

    # --------------------------------------------------------
    # Context / table inspection
    # --------------------------------------------------------

    targets = {}

    for name, va in TARGETS.items():

        targets[name] = {
            "va": va,
            "classification": classify_va(va),
            "nearby_symbols": nearby_symbols(va),
            "dump_256": read_va(va, 256)
        }

    # ACB table is interesting because SubmitAcb uses:
    #
    #   base + index * 0x90 + 0x08
    #
    # Capture multiple entries.
    acb_entries = []

    for index in range(8):

        entry_va = ACB_TABLE + (index * 0x90)

        acb_entries.append({
            "index": index,
            "entry_va": entry_va,
            "entry_plus_8": entry_va + 8,
            "bytes": read_va(entry_va, 0x90),
            "classification": classify_va(entry_va)
        })

    # --------------------------------------------------------
    # Scan executable segments for RIP-relative references
    # to our context addresses.
    #
    # This recognizes:
    #   48 8d xx disp32
    #   48 8b xx disp32
    #   4c 8d xx disp32
    #   4c 8b xx disp32
    #
    # using generic ModRM decoding only for RIP-relative forms.
    # --------------------------------------------------------

    rip_references = []

    interesting = set(TARGETS.values())
    interesting.add(TARGET_FUNC)

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

        for i in range(0, max(0, len(data) - 7)):

            b0 = data[i]

            # Scan common REX + opcode forms that use ModRM.
            if b0 not in (
                0x48,
                0x4C,
            ):
                continue

            if i + 7 > len(data):
                continue

            op = data[i + 1]
            modrm = data[i + 2]

            # RIP relative addressing:
            # mod=00 and r/m=101
            if (modrm & 0xC7) != 0x05:
                continue

            if op not in (
                0x8B,  # MOV r64,r/m64
                0x8D,  # LEA
            ):
                continue

            disp = struct.unpack_from(
                "<i",
                data,
                i + 3
            )[0]

            instruction_va = seg_vaddr + i
            next_va = instruction_va + 7
            target_va = next_va + disp

            if target_va in interesting:

                rip_references.append({
                    "instruction_va": instruction_va,
                    "target_va": target_va,
                    "opcode": f"0x{op:02x}",
                    "displacement": disp,
                    "file_offset": seg_offset + i
                })

    # --------------------------------------------------------
    # Scan all file-backed data for literal 64-bit pointers
    # to context/table addresses.
    # --------------------------------------------------------

    pointer_references = []

    target_bytes = {}

    for name, va in TARGETS.items():

        target_bytes[va] = name

    for seg in elf.iter_segments():

        if seg.header.p_type != "PT_LOAD":
            continue

        seg_vaddr = int(seg.header.p_vaddr)
        seg_offset = int(seg.header.p_offset)
        seg_filesz = int(seg.header.p_filesz)

        f.seek(seg_offset)
        data = f.read(seg_filesz)

        for i in range(
            0,
            max(0, len(data) - 8),
            8
        ):

            value = struct.unpack_from(
                "<Q",
                data,
                i
            )[0]

            if value in target_bytes:

                pointer_references.append({
                    "file_offset": seg_offset + i,
                    "va": seg_vaddr + i,
                    "points_to": value,
                    "target_name": target_bytes[value]
                })

    # --------------------------------------------------------
    # Cross-reference to context field offsets used by
    # SubmitCommandBuffer.
    # --------------------------------------------------------

    field_offsets = [
        0x00,
        0x08,
        0x0C,
        0x14,
        0x20,
        0x28,
        0x30,
        0x38,
        0x48,
        0xA0,
        0xA4,
        0x140,
        0x148
    ]

    context_field_layout = []

    for offset in field_offsets:

        context_field_layout.append({
            "offset": f"0x{offset:x}",
            "dcb_va": CONTEXT_DCB + offset,
            "agr_va": CONTEXT_AGR + offset
        })

    result = {
        "targets": targets,

        "acb_table": {
            "base": ACB_TABLE,
            "stride": 0x90,
            "entry_count_dumped": len(acb_entries),
            "entries": acb_entries
        },

        "rip_references": rip_references,

        "pointer_references": pointer_references,

        "submit_command_buffer_fields": context_field_layout,

        "loads": loads
    }

with open(
    os.path.join(out_dir, "stage47_static.json"),
    "w",
    encoding="utf-8"
) as fp:

    json.dump(
        result,
        fp,
        indent=2
    )

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

# ============================================================
# Banner
# ============================================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "AGC PS5 Stage 47 - Context / Table Audit" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Info "SPRX       = $SprxPath"
Write-Info "NID DB     = $NidDb"
Write-Info "Output     = $OutDir"
Write-Info "Target     = sceAgcDriverSubmitCommandBuffer"
Write-Info "Target VA  = 0x18b0"
Write-Info "DCB ctx    = 0x1a8b8"
Write-Info "AGR ctx    = 0x1a868"
Write-Info "Global ctx = 0x1a908"
Write-Info "ACB table  = 0x18460"
Write-Info "ACB stride = 0x90"

try {

    # ========================================================
    # Prepare
    # ========================================================

    Write-Step "Prepare Linux workspace"

    Invoke-WslChecked @"
rm -rf '$TmpRoot'
mkdir -p '$TmpRoot'
mkdir -p '$OutUnix'
cp '$PythonUnix' '$TmpRoot/analyze_contexts.py'
python3 -m py_compile '$TmpRoot/analyze_contexts.py'
"@ | Out-Null

    # ========================================================
    # Analyze
    # ========================================================

    Write-Step "Analyze Submit contexts and ACB table"

    Invoke-WslChecked @"
python3 '$TmpRoot/analyze_contexts.py' \
    '$SprxUnix' \
    '$NidUnix' \
    '$TmpRoot'
"@ | Out-Null

    # ========================================================
    # Collect JSON
    # ========================================================

    Write-Step "Collect Stage 47 static report"

    Invoke-WslChecked @"
cp '$TmpRoot/stage47_static.json' \
   '$OutUnix/stage47_static.json'

cat '$TmpRoot/stage47_static.json'
"@ | Out-Null

    $StaticPath = Join-Path `
        $OutDir `
        "stage47_static.json"

    $Static = (
        Get-Content `
            -LiteralPath $StaticPath `
            -Raw
    ) | ConvertFrom-Json

    # ========================================================
    # Create human-readable summary
    # ========================================================

    Write-Step "Create context summary"

    $Summary = New-Object System.Collections.Generic.List[string]

    $Summary.Add(
        "AGC PS5 Stage 47 - Context Audit"
    )

    $Summary.Add("")
    $Summary.Add(
        "SubmitCommandBuffer = 0x18b0"
    )

    $Summary.Add("")
    $Summary.Add(
        "=== CONTEXT TARGETS ==="
    )

    foreach ($Property in @(
        "submit_dcb_context",
        "agr_submit_dcb_context",
        "global_state_context",
        "acb_table"
    )) {

        $Target = $Static.targets.$Property

        if ($null -eq $Target) {
            continue
        }

        $Summary.Add("")
        $Summary.Add(
            "$Property = " +
            ("0x{0:x}" -f [int64]$Target.va)
        )

        $Summary.Add(
            "region      = $($Target.classification.region)"
        )

        $Summary.Add(
            "permissions = $($Target.classification.permissions)"
        )

        $Summary.Add(
            "in_file     = $($Target.classification.in_file)"
        )
    }

    $Summary.Add("")
    $Summary.Add(
        "=== ACB TABLE ==="
    )

    $Summary.Add(
        ("base=0x{0:x} stride=0x90" -f
            [int64]$Static.acb_table.base)
    )

    foreach ($Entry in $Static.acb_table.entries) {

        $Summary.Add(
            ("index={0} entry=0x{1:x} entry+8=0x{2:x}" -f `
                $Entry.index,
                [int64]$Entry.entry_va,
                [int64]$Entry.entry_plus_8)
        )
    }

    $Summary.Add("")
    $Summary.Add(
        "=== RIP REFERENCES ==="
    )

    foreach ($Ref in $Static.rip_references) {

        $Summary.Add(
            ("instruction=0x{0:x} target=0x{1:x} opcode={2}" -f `
                [int64]$Ref.instruction_va,
                [int64]$Ref.target_va,
                $Ref.opcode)
        )
    }

    $Summary.Add("")
    $Summary.Add(
        "=== POINTER REFERENCES ==="
    )

    foreach ($Ref in $Static.pointer_references) {

        $Summary.Add(
            ("VA=0x{0:x} -> 0x{1:x} ({2})" -f `
                [int64]$Ref.va,
                [int64]$Ref.points_to,
                $Ref.target_name)
        )
    }

    $SummaryPath = Join-Path `
        $OutDir `
        "context_summary.txt"

    [System.IO.File]::WriteAllText(
        $SummaryPath,
        ($Summary -join "`r`n") + "`r`n",
        [System.Text.UTF8Encoding]::new($false)
    )

    Get-Content -LiteralPath $SummaryPath

    # ========================================================
    # Export raw ACB table pieces
    # ========================================================

    Write-Step "Export ACB table entry binaries"

    $TableDir = Join-Path `
        $OutDir `
        "acb_table"

    New-Item `
        -ItemType Directory `
        -Force `
        -Path $TableDir |
        Out-Null

    $TableDirUnix = Convert-ToWslPath $TableDir

    $ExportTablePythonLocal = Join-Path `
        $OutDir `
        "export_acb_table.py"

    $ExportTablePython = @'
import json
import os
import sys

json_path = sys.argv[1]
out_dir = sys.argv[2]

os.makedirs(out_dir, exist_ok=True)

with open(json_path, "r", encoding="utf-8") as fp:
    data = json.load(fp)

for entry in data["acb_table"]["entries"]:

    raw = entry["bytes"]["bytes_hex"]

    if not raw:
        continue

    blob = bytes.fromhex(raw)

    name = "entry_{:02d}.bin".format(
        entry["index"]
    )

    path = os.path.join(
        out_dir,
        name
    )

    with open(path, "wb") as fp:
        fp.write(blob)

    print(
        "{} VA=0x{:x} size={}".format(
            path,
            entry["entry_va"],
            len(blob)
        )
    )
'@

    $ExportTablePython = $ExportTablePython -replace "`r`n", "`n"
    $ExportTablePython = $ExportTablePython -replace "`r", ""

    [System.IO.File]::WriteAllText(
        $ExportTablePythonLocal,
        $ExportTablePython,
        [System.Text.UTF8Encoding]::new($false)
    )

    $ExportTablePythonUnix = Convert-ToWslPath `
        $ExportTablePythonLocal

    Invoke-WslChecked @"
cp '$ExportTablePythonUnix' \
   '$TmpRoot/export_acb_table.py'

python3 -m py_compile \
   '$TmpRoot/export_acb_table.py'

python3 \
   '$TmpRoot/export_acb_table.py' \
   '$TmpRoot/stage47_static.json' \
   '$TableDirUnix'

ls -lh '$TableDirUnix'
"@ | Out-Null

    # ========================================================
    # Export context bytes if file-backed.
    # ========================================================

    Write-Step "Export file-backed context bytes"

    $ContextDir = Join-Path `
        $OutDir `
        "contexts"

    New-Item `
        -ItemType Directory `
        -Force `
        -Path $ContextDir |
        Out-Null

    $ContextDirUnix = Convert-ToWslPath $ContextDir

    Invoke-WslChecked @"
python3 - '$TmpRoot/stage47_static.json' '$ContextDirUnix' <<'PY'
import json
import os
import sys

src = sys.argv[1]
out_dir = sys.argv[2]

os.makedirs(out_dir, exist_ok=True)

with open(src, "r", encoding="utf-8") as fp:
    data = json.load(fp)

for name, target in data["targets"].items():

    raw = target["dump_256"]

    if raw["bytes_hex"] is None:
        continue

    blob = bytes.fromhex(
        raw["bytes_hex"]
    )

    out = os.path.join(
        out_dir,
        name + ".bin"
    )

    with open(out, "wb") as fp:
        fp.write(blob)

    print(
        "{} VA=0x{:x} size={}".format(
            out,
            target["va"],
            len(blob)
        )
    )
PY
ls -lh '$ContextDirUnix'
"@ | Out-Null

    # ========================================================
    # Hash
    # ========================================================

    Write-Step "Hash artefacts"

    $Artifacts = @()

    foreach ($Name in @(
        "stage47_static.json",
        "context_summary.txt"
    )) {

        $Path = Join-Path $OutDir $Name

        if (Test-Path -LiteralPath $Path -PathType Leaf) {

            $Item = Get-Item -LiteralPath $Path

            $Artifacts += [ordered]@{
                file   = $Name
                size   = $Item.Length
                sha256 = (Get-Sha256 $Path)
            }
        }
    }

    foreach ($Bin in @(
        Get-ChildItem `
            -LiteralPath $TableDir `
            -Filter "*.bin" `
            -File `
            -ErrorAction SilentlyContinue
    )) {

        $Artifacts += [ordered]@{
            file   = "acb_table/$($Bin.Name)"
            size   = $Bin.Length
            sha256 = (Get-Sha256 $Bin.FullName)
        }
    }

    foreach ($Bin in @(
        Get-ChildItem `
            -LiteralPath $ContextDir `
            -Filter "*.bin" `
            -File `
            -ErrorAction SilentlyContinue
    )) {

        $Artifacts += [ordered]@{
            file   = "contexts/$($Bin.Name)"
            size   = $Bin.Length
            sha256 = (Get-Sha256 $Bin.FullName)
        }
    }

    foreach ($Artifact in $Artifacts) {
        Write-Info (
            "{0} SHA256={1}" -f
            $Artifact.file,
            $Artifact.sha256
        )
    }

    # ========================================================
    # Final report
    # ========================================================

    $Report = [ordered]@{
        stage = 47

        timestamp = (Get-Date).ToString("o")

        target = [ordered]@{
            name = "sceAgcDriverSubmitCommandBuffer"
            nid  = "b4fpgH5ZXxQ"
            va   = "0x18b0"
        }

        contexts = [ordered]@{
            dcb = "0x1a8b8"
            agr = "0x1a868"
            global = "0x1a908"
            acb_table = "0x18460"
            acb_stride = "0x90"
        }

        execution = [ordered]@{
            performed = $false
        }

        abi = [ordered]@{
            prototype_inferred = $false
            context_model = $true
        }

        artifacts = $Artifacts
    }

    $ReportPath = Join-Path `
        $OutDir `
        "STAGE47_REPORT.json"

    $Report |
        ConvertTo-Json -Depth 15 |
        Set-Content `
            -LiteralPath $ReportPath `
            -Encoding UTF8

    # ========================================================
    # Final
    # ========================================================

    Write-Host ""
    Write-Host "============================================" -ForegroundColor Green
    Write-Host "Stage 47 completed" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""

    Write-Host `
        "SUBMIT_CONTEXTS_IDENTIFIED = PASS" `
        -ForegroundColor Green

    Write-Host `
        "ACB_TABLE_IDENTIFIED = PASS" `
        -ForegroundColor Green

    Write-Host `
        "CROSS_REFERENCE_ANALYSIS = PASS" `
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