[CmdletBinding()]
param(
    [string]$SprxPath = "D:\agc_work\sce_stubs\libSceAgcDriver.sprx",
    [string]$NidDb    = "D:\sdk-master\sce_stubs\aerolib.csv",
    [string]$OutDir   = "D:\agc_work\stage48_results"
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

New-Item `
    -ItemType Directory `
    -Force `
    -Path $OutDir |
    Out-Null

$SprxUnix = Convert-ToWslPath $SprxPath
$NidUnix  = Convert-ToWslPath $NidDb
$OutUnix  = Convert-ToWslPath $OutDir

$TmpRoot = "/tmp/agc_stage48"

$PythonLocal = Join-Path `
    $OutDir `
    "analyze_context_refs.py"

# ============================================================
# Python analyzer
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

TARGETS = {
    "submit_command_buffer": 0x18B0,
    "submit_dcb_context": 0x1A8B8,
    "agr_submit_dcb_context": 0x1A868,
    "global_state_context": 0x1A908,
    "acb_table": 0x18460,
}

WINDOW_BEFORE = 48
WINDOW_AFTER = 96

# ------------------------------------------------------------
# NID map
# ------------------------------------------------------------

nid_map = {}

with open(
    nid_db,
    "r",
    encoding="utf-8",
    errors="replace"
) as fp:

    for line in fp:

        line = line.strip()

        if not line:
            continue

        parts = line.split(" ", 1)

        if len(parts) == 2:
            nid_map[parts[0]] = parts[1]

# ------------------------------------------------------------
# ELF
# ------------------------------------------------------------

with open(sprx, "rb") as f:

    elf = ELFFile(f)

    dynamic = None

    for seg in elf.iter_segments():

        if seg.header.p_type == "PT_DYNAMIC":
            dynamic = seg
            break

    if dynamic is None:
        raise RuntimeError("PT_DYNAMIC not found")

    symbols = []

    for sym in dynamic.iter_symbols():

        if not sym.name:
            continue

        raw = sym.name

        item = {
            "raw_name": raw,
            "value": int(sym["st_value"]),
            "size": int(sym["st_size"]),
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

    # --------------------------------------------------------
    # Read
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Find symbol owner
    # --------------------------------------------------------

    def owners(va):

        result = []

        for sym in symbols:

            start = sym["value"]
            size = sym["size"]

            if size <= 0:
                continue

            if start <= va < start + size:

                result.append(sym)

        return result

    # --------------------------------------------------------
    # Find functions containing an address
    # --------------------------------------------------------

    def function_owner(va):

        matches = []

        for sym in symbols:

            if sym.get("type") != "STT_FUNC":
                continue

            start = sym["value"]
            size = sym["size"]

            if size <= 0:
                continue

            if start <= va < start + size:

                matches.append(sym)

        if matches:
            matches.sort(
                key=lambda x: (
                    x["size"],
                    x["value"]
                )
            )

            return matches[0]

        return None

    # --------------------------------------------------------
    # Executable bytes
    # --------------------------------------------------------

    executable_segments = []

    for seg in loads:

        if seg["flags"] & 1:

            executable_segments.append(seg)

    # --------------------------------------------------------
    # Reference scanner
    #
    # We identify RIP-relative LEA/MOV references to the
    # exact context addresses, then generate disassembly
    # windows around those locations.
    # --------------------------------------------------------

    references = []

    for seg in executable_segments:

        seg_vaddr = seg["vaddr"]
        seg_offset = seg["offset"]
        seg_filesz = seg["filesz"]

        f.seek(seg_offset)

        data = f.read(seg_filesz)

        i = 0

        while i + 7 <= len(data):

            rex = data[i]
            op  = data[i + 1]
            modrm = data[i + 2]

            if rex not in (0x48, 0x4C):
                i += 1
                continue

            if op not in (0x8B, 0x8D):
                i += 1
                continue

            # RIP-relative ModRM:
            # mod = 00
            # r/m = 101
            if (modrm & 0xC7) != 0x05:
                i += 1
                continue

            disp = struct.unpack_from(
                "<i",
                data,
                i + 3
            )[0]

            insn_va = seg_vaddr + i
            next_va = insn_va + 7
            target_va = next_va + disp

            matched_target = None

            for name, target in TARGETS.items():

                if target_va == target:
                    matched_target = name
                    break

            if matched_target is not None:

                owner = function_owner(insn_va)

                references.append({
                    "instruction_va": insn_va,
                    "target_va": target_va,
                    "target_name": matched_target,
                    "opcode": f"0x{op:02x}",
                    "displacement": disp,
                    "file_offset": seg_offset + i,
                    "owner": owner
                })

            i += 1

    # --------------------------------------------------------
    # Group references
    # --------------------------------------------------------

    by_target = {}

    for name in TARGETS:

        by_target[name] = []

    for ref in references:

        by_target[
            ref["target_name"]
        ].append(ref)

    # --------------------------------------------------------
    # Extract windows
    # --------------------------------------------------------

    windows = []

    for ref in references:

        start_va = max(
            0,
            ref["instruction_va"] - WINDOW_BEFORE
        )

        size = (
            WINDOW_BEFORE +
            7 +
            WINDOW_AFTER
        )

        raw = read_va(
            start_va,
            size
        )

        if raw is None:
            continue

        windows.append({
            "target_name": ref["target_name"],
            "target_va": ref["target_va"],
            "instruction_va": ref["instruction_va"],
            "owner": ref["owner"],
            "raw": raw
        })

    # --------------------------------------------------------
    # Write static result
    # --------------------------------------------------------

    result = {
        "targets": TARGETS,
        "reference_count": len(references),
        "references": references,
        "references_by_target": by_target,
        "windows": windows,
        "loads": loads
    }

with open(
    os.path.join(out_dir, "stage48_static.json"),
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
Write-Host "AGC PS5 Stage 48 - Context Reference Audit" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Info "SPRX       = $SprxPath"
Write-Info "NID DB     = $NidDb"
Write-Info "Output     = $OutDir"
Write-Info "Submit     = 0x18b0"
Write-Info "DCB ctx    = 0x1a8b8"
Write-Info "AGR ctx    = 0x1a868"
Write-Info "Global     = 0x1a908"
Write-Info "ACB table  = 0x18460"

try {

    # ========================================================
    # Prepare
    # ========================================================

    Write-Step "Prepare Linux workspace"

    Invoke-WslChecked @"
rm -rf '$TmpRoot'
mkdir -p '$TmpRoot'
mkdir -p '$OutUnix'
cp '$PythonUnix' '$TmpRoot/analyze_context_refs.py'
python3 -m py_compile '$TmpRoot/analyze_context_refs.py'
"@ | Out-Null

    # ========================================================
    # Analyze
    # ========================================================

    Write-Step "Scan context references"

    Invoke-WslChecked @"
python3 '$TmpRoot/analyze_context_refs.py' \
    '$SprxUnix' \
    '$NidUnix' \
    '$TmpRoot'
"@ | Out-Null

    # ========================================================
    # Collect JSON
    # ========================================================

    Write-Step "Collect static report"

    Invoke-WslChecked @"
cp '$TmpRoot/stage48_static.json' \
   '$OutUnix/stage48_static.json'

cat '$TmpRoot/stage48_static.json'
"@ | Out-Null

    $StaticPath = Join-Path `
        $OutDir `
        "stage48_static.json"

    $Static = (
        Get-Content `
            -LiteralPath $StaticPath `
            -Raw
    ) | ConvertFrom-Json

    # ========================================================
    # Summary
    # ========================================================

    Write-Step "Create reference summary"

    $Summary = New-Object System.Collections.Generic.List[string]

    $Summary.Add(
        "AGC PS5 Stage 48 - Context Reference Audit"
    )

    $Summary.Add("")
    $Summary.Add(
        "TARGETS"
    )

    $Summary.Add(
        "  SubmitCommandBuffer = 0x18b0"
    )

    $Summary.Add(
        "  DCB context          = 0x1a8b8"
    )

    $Summary.Add(
        "  AGR context          = 0x1a868"
    )

    $Summary.Add(
        "  Global context       = 0x1a908"
    )

    $Summary.Add(
        "  ACB table            = 0x18460"
    )

    $Summary.Add("")

    $Summary.Add(
        "TOTAL REFERENCES: $($Static.reference_count)"
    )

    foreach ($TargetName in @(
        "submit_command_buffer",
        "submit_dcb_context",
        "agr_submit_dcb_context",
        "global_state_context",
        "acb_table"
    )) {

        $Refs = @(
            $Static.references_by_target.$TargetName
        )

        $Summary.Add("")
        $Summary.Add(
            "=== $TargetName ==="
        )

        $Summary.Add(
            "count=$($Refs.Count)"
        )

        foreach ($Ref in $Refs) {

            $OwnerName = ""

            if ($null -ne $Ref.owner) {
                $OwnerName = $Ref.owner.mapped_name
            }

            if ([string]::IsNullOrWhiteSpace($OwnerName)) {
                $OwnerName = "<unknown>"
            }

            $Summary.Add(
                ("0x{0:x} -> 0x{1:x} opcode={2} owner={3}" -f `
                    [int64]$Ref.instruction_va,
                    [int64]$Ref.target_va,
                    $Ref.opcode,
                    $OwnerName)
            )
        }
    }

    $SummaryPath = Join-Path `
        $OutDir `
        "reference_summary.txt"

    [System.IO.File]::WriteAllText(
        $SummaryPath,
        ($Summary -join "`r`n") + "`r`n",
        [System.Text.UTF8Encoding]::new($false)
    )

    Get-Content `
        -LiteralPath $SummaryPath

    # ========================================================
    # Export windows
    # ========================================================

    Write-Step "Export reference windows"

    $WindowDir = Join-Path `
        $OutDir `
        "windows"

    New-Item `
        -ItemType Directory `
        -Force `
        -Path $WindowDir |
        Out-Null

    $WindowDirUnix = Convert-ToWslPath $WindowDir

    # Export every window to a binary and a metadata file.
    # Use Python to avoid PowerShell path/WSL quoting issues.
    # ========================================================

    $ExportWindowsLocal = Join-Path `
        $OutDir `
        "export_windows.py"

    $ExportWindows = @'
import json
import os
import sys

src = sys.argv[1]
out_dir = sys.argv[2]

os.makedirs(out_dir, exist_ok=True)

with open(src, "r", encoding="utf-8") as fp:
    data = json.load(fp)

for index, window in enumerate(data["windows"], 1):

    raw = window["raw"]

    blob = bytes.fromhex(
        raw["bytes_hex"]
    )

    base = (
        f"{index:04d}_"
        f"{window['target_name']}_"
        f"0x{window['instruction_va']:x}"
    )

    bin_path = os.path.join(
        out_dir,
        base + ".bin"
    )

    json_path = os.path.join(
        out_dir,
        base + ".json"
    )

    with open(
        bin_path,
        "wb"
    ) as fp:
        fp.write(blob)

    with open(
        json_path,
        "w",
        encoding="utf-8"
    ) as fp:
        json.dump(
            window,
            fp,
            indent=2
        )

    print(
        f"{base}: "
        f"VA=0x{raw['va']:x} "
        f"size={len(blob)}"
    )
'@

    $ExportWindows = $ExportWindows -replace "`r`n", "`n"
    $ExportWindows = $ExportWindows -replace "`r", ""

    [System.IO.File]::WriteAllText(
        $ExportWindowsLocal,
        $ExportWindows,
        [System.Text.UTF8Encoding]::new($false)
    )

    $ExportWindowsUnix = Convert-ToWslPath `
        $ExportWindowsLocal

    Invoke-WslChecked @"
cp '$ExportWindowsUnix' \
   '$TmpRoot/export_windows.py'

python3 -m py_compile \
   '$TmpRoot/export_windows.py'

python3 \
   '$TmpRoot/export_windows.py' \
   '$TmpRoot/stage48_static.json' \
   '$WindowDirUnix'

ls -lh '$WindowDirUnix' | head -80
"@ | Out-Null

    # ========================================================
    # Generate disassembly for important windows
    # ========================================================

    Write-Step "Disassemble context reference windows"

    $DisassemblyPath = Join-Path `
        $OutDir `
        "context_reference_disassembly.txt"

    $Disassembly = New-Object `
        System.Collections.Generic.List[string]

    $JsonWindows = @(
        Get-ChildItem `
            -LiteralPath $WindowDir `
            -Filter "*.json" `
            -File `
            -ErrorAction SilentlyContinue
    )

    foreach ($JsonWindow in $JsonWindows) {

        $Data = (
            Get-Content `
                -LiteralPath $JsonWindow.FullName `
                -Raw
        ) | ConvertFrom-Json

        $BinName = (
            [System.IO.Path]::GetFileNameWithoutExtension(
                $JsonWindow.Name
            ) + ".bin"
        )

        $BinPath = Join-Path `
            $WindowDir `
            $BinName

        if (-not (Test-Path -LiteralPath $BinPath)) {
            continue
        }

        $BinUnix = Convert-ToWslPath $BinPath

        $StartVa = [int64]$Data.raw.va
        $StartHex = ("0x{0:x}" -f $StartVa)

        $Disassembly.Add(
            "============================================"
        )

        $Disassembly.Add(
            "$($JsonWindow.BaseName)"
        )

        $Disassembly.Add(
            "TARGET=$($Data.target_name)"
        )

        $Disassembly.Add(
            "INSTRUCTION_VA=" +
            ("0x{0:x}" -f [int64]$Data.instruction_va)
        )

        $Disassembly.Add(
            "WINDOW_START=$StartHex"
        )

        $Disassembly.Add(
            "============================================"
        )

        $Output = Invoke-WslChecked @"
objdump \
    -D \
    -b binary \
    -m i386:x86-64 \
    --adjust-vma=$StartHex \
    '$BinUnix'
"@

        foreach ($Line in $Output) {
            $Disassembly.Add(
                [string]$Line
            )
        }

        $Disassembly.Add("")
    }

    [System.IO.File]::WriteAllText(
        $DisassemblyPath,
        ($Disassembly -join "`r`n") + "`r`n",
        [System.Text.UTF8Encoding]::new($false)
    )

    # ========================================================
    # Hash
    # ========================================================

    Write-Step "Hash artefacts"

    foreach ($Path in @(
        (Join-Path $OutDir "stage48_static.json"),
        (Join-Path $OutDir "reference_summary.txt"),
        (Join-Path $OutDir "context_reference_disassembly.txt")
    )) {

        if (Test-Path -LiteralPath $Path -PathType Leaf) {

            Write-Info (
                "{0} SHA256={1}" -f
                [System.IO.Path]::GetFileName($Path),
                (Get-Sha256 $Path)
            )
        }
    }

    # ========================================================
    # Report
    # ========================================================

    $Counts = [ordered]@{}

    foreach ($TargetName in $Static.references_by_target.psobject.Properties.Name) {

        $Counts[$TargetName] = @(
            $Static.references_by_target.$TargetName
        ).Count
    }

    $Report = [ordered]@{
        stage = 48

        timestamp = (Get-Date).ToString("o")

        target = [ordered]@{
            name = "sceAgcDriverSubmitCommandBuffer"
            va   = "0x18b0"
        }

        references = $Counts

        analysis = [ordered]@{
            contexts_are_bss = $true
            reference_windows_extracted = $true
            write_sites_not_yet_proven = $true
        }

        execution = [ordered]@{
            performed = $false
        }

        abi = [ordered]@{
            prototype_inferred = $false
        }
    }

    $ReportPath = Join-Path `
        $OutDir `
        "STAGE48_REPORT.json"

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
    Write-Host "Stage 48 completed" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""

    Write-Host `
        "CONTEXT_REFERENCE_SCAN = PASS" `
        -ForegroundColor Green

    Write-Host `
        "REFERENCE_WINDOWS_EXTRACTED = PASS" `
        -ForegroundColor Green

    Write-Host `
        "WRITE_SITES_PROVEN = NO" `
        -ForegroundColor Yellow

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