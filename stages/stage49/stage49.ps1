[CmdletBinding()]
param(
    [string]$SprxPath = "D:\agc_work\sce_stubs\libSceAgcDriver.sprx",
    [string]$NidDb    = "D:\sdk-master\sce_stubs\aerolib.csv",
    [string]$OutDir   = "D:\agc_work\stage49_results"
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

$TmpRoot = "/tmp/agc_stage49"

$PythonLocal = Join-Path `
    $OutDir `
    "analyze_context_writes.py"

# ============================================================
# Python analyzer
#
# Goals:
#   1. Locate exact context LEA references.
#   2. Decode common RIP-relative loads/stores.
#   3. Track register aliases approximately.
#   4. Identify stores whose effective base is one of:
#        0x1A868
#        0x1A8B8
#        0x1A908
#   5. Identify accesses expressed as base+constant offsets.
#
# This is deliberately conservative. It reports candidates
# rather than pretending to have proven data-flow in every
# case.
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
    "agr_context": 0x1A868,
    "dcb_context": 0x1A8B8,
    "global_context": 0x1A908,
    "acb_table": 0x18460,
}

# Known instruction sizes for the RIP-relative patterns we care
# about. This analyzer intentionally recognizes only common
# x86-64 forms and does not attempt to fully decode every opcode.

RIP_REL_PATTERNS = {
    # mov r64, [rip+disp32]
    (0x48, 0x8B): "MOV_R64_RIP",

    # mov r32, [rip+disp32]
    (0x8B,): "MOV_R32_RIP",

    # lea r64, [rip+disp32]
    (0x48, 0x8D): "LEA_R64_RIP",

    # lea r32, [rip+disp32]
    (0x8D,): "LEA_R32_RIP",

    # mov [rip+disp32], imm32
    (0xC7,): "MOV_RIP_IMM32",

    # mov byte [rip+disp32], imm8
    (0xC6,): "MOV_RIP_IMM8",
}

WRITE_MNEMONIC_BYTES = {
    0x88: "MOV_MEM8",
    0x89: "MOV_MEM",
    0x8A: "MOV_LOAD8",
    0x8B: "MOV_LOAD",
    0xC6: "MOV_MEM8_IMM",
    0xC7: "MOV_MEM_IMM",
    0xD9: "X87_STORE",
    0x0F: "EXTENDED",
    0xF0: "LOCK",
}

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
            return None

        f.seek(off)

        data = f.read(size)

        return {
            "va": va,
            "file_offset": off,
            "size": len(data),
            "bytes_hex": data.hex(" ")
        }

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

        if not matches:
            return None

        matches.sort(
            key=lambda x: (
                x["size"],
                x["value"]
            )
        )

        return matches[0]

    # --------------------------------------------------------
    # Get executable image bytes
    # --------------------------------------------------------

    executable = []

    for seg in loads:

        if not (seg["flags"] & 1):
            continue

        f.seek(seg["offset"])

        data = f.read(seg["filesz"])

        executable.append({
            "vaddr": seg["vaddr"],
            "offset": seg["offset"],
            "data": data
        })

    # --------------------------------------------------------
    # 1. Exact RIP-relative references
    # --------------------------------------------------------

    rip_refs = []

    for seg in executable:

        data = seg["data"]
        base_va = seg["vaddr"]
        base_off = seg["offset"]

        i = 0

        while i + 7 <= len(data):

            # REX.W + opcode + ModRM + disp32
            if (
                data[i] == 0x48 and
                data[i+1] in (0x8B, 0x8D)
            ):

                modrm = data[i+2]

                if (modrm & 0xC7) == 0x05:

                    disp = struct.unpack_from(
                        "<i",
                        data,
                        i + 3
                    )[0]

                    insn_va = base_va + i
                    next_va = insn_va + 7
                    target_va = next_va + disp

                    target_name = None

                    for name, addr in TARGETS.items():

                        if target_va == addr:
                            target_name = name
                            break

                    if target_name is not None:

                        rip_refs.append({
                            "instruction_va": insn_va,
                            "file_offset": base_off + i,
                            "opcode": (
                                "LEA"
                                if data[i+1] == 0x8D
                                else "MOV"
                            ),
                            "target_va": target_va,
                            "target_name": target_name,
                            "displacement": disp,
                            "owner": function_owner(insn_va)
                        })

            i += 1

    # --------------------------------------------------------
    # 2. Look for immediate absolute-address constructions
    #    and stores to nearby context offsets.
    #
    # Since BSS is not in the file, we cannot inspect the data;
    # we only inspect instructions that can form effective
    # addresses.
    # --------------------------------------------------------

    candidate_accesses = []

    for seg in executable:

        data = seg["data"]
        base_va = seg["vaddr"]
        base_off = seg["offset"]

        # Simple byte-oriented scan.
        #
        # We are primarily interested in:
        #
        #   mov [reg + disp8/disp32], reg
        #   mov [reg + disp8/disp32], imm
        #
        # immediately following a LEA of a known target.
        #
        # Therefore first collect every known-target LEA/MOV.
        #
        local_known = []

        i = 0

        while i + 7 <= len(data):

            if (
                data[i] == 0x48 and
                data[i+1] in (0x8B, 0x8D)
            ):

                modrm = data[i+2]

                if (modrm & 0xC7) == 0x05:

                    disp = struct.unpack_from(
                        "<i",
                        data,
                        i + 3
                    )[0]

                    insn_va = base_va + i
                    next_va = insn_va + 7
                    target_va = next_va + disp

                    target_name = None

                    for name, addr in TARGETS.items():

                        if target_va == addr:
                            target_name = name
                            break

                    if target_name is not None:

                        # Capture a forward window of 96 bytes.
                        local_known.append({
                            "offset": i,
                            "instruction_va": insn_va,
                            "target_name": target_name,
                            "target_va": target_va,
                        })

            i += 1

        # Analyze forward windows.
        for known in local_known:

            start = known["offset"]
            end = min(
                len(data),
                start + 96
            )

            window = data[start:end]

            # Search common store encodings.
            #
            # 89 /r   mov r/m32/64, r32/64
            # 88 /r   mov r/m8, r8
            #
            # Look for ModRM using a register as base and
            # a displacement.
            #
            j = 7

            while j + 3 < len(window):

                op = window[j]

                if op in (0x88, 0x89):

                    modrm = window[j+1]

                    mod = (modrm >> 6) & 0x3
                    rm  = modrm & 0x7

                    # Exclude register-direct form.
                    if mod != 3:

                        disp_size = 0

                        if mod == 1:
                            disp_size = 1

                        elif mod == 2:
                            disp_size = 4

                        # SIB can add another byte.
                        sib_extra = (
                            1
                            if rm == 4
                            else 0
                        )

                        total = (
                            2 +
                            sib_extra +
                            disp_size
                        )

                        if j + total <= len(window):

                            displacement = 0

                            cursor = j + 2

                            if rm == 4:
                                cursor += 1

                            if disp_size == 1:

                                displacement = struct.unpack_from(
                                    "<b",
                                    window,
                                    cursor
                                )[0]

                            elif disp_size == 4:

                                displacement = struct.unpack_from(
                                    "<i",
                                    window,
                                    cursor
                                )[0]

                            candidate_accesses.append({
                                "context_reference": known,
                                "access_va": (
                                    known["instruction_va"] +
                                    j
                                ),
                                "opcode": (
                                    "MOV_STORE8"
                                    if op == 0x88
                                    else "MOV_STORE"
                                ),
                                "mod": mod,
                                "rm": rm,
                                "displacement": displacement,
                                "relative_to_context": True
                            })

                j += 1

    # --------------------------------------------------------
    # 3. Export windows centered on important submit functions
    # --------------------------------------------------------

    important_functions = [
        "sceAgcDriverSubmitDcb",
        "sceAgcDriverAgrSubmitDcb",
        "sceAgcDriverSubmitAcb",
        "sceAgcDriverSubmitReprojectionAcb",
        "sceAgcDriverSubmitMultiAcbs",
        "sceAgcDriverSubmitMultiDcbs",
        "sceAgcDriverAgrSubmitMultiDcbs",
        "sceAgcDriverSubmitMultiCommandBuffers",
        "sceAgcDriverSuspendPointSubmit",
    ]

    important_windows = []

    for sym in symbols:

        name = sym.get("mapped_name")

        if name not in important_functions:
            continue

        va = sym["value"]
        size = sym["size"]

        raw = read_va(
            va,
            min(size, 1600)
        )

        if raw is None:
            continue

        important_windows.append({
            "name": name,
            "nid": sym.get("nid"),
            "va": va,
            "size": size,
            "raw": raw
        })

    # --------------------------------------------------------
    # 4. Specifically search the known functions for stores
    #    after context LEAs.
    # --------------------------------------------------------

    function_store_candidates = []

    for item in important_windows:

        raw = bytes.fromhex(
            item["raw"]["bytes_hex"]
        )

        base_va = item["va"]

        # Reuse a lightweight scan.
        i = 0

        while i + 7 <= len(raw):

            if (
                raw[i] == 0x48 and
                raw[i+1] in (0x8B, 0x8D)
            ):

                modrm = raw[i+2]

                if (modrm & 0xC7) == 0x05:

                    disp = struct.unpack_from(
                        "<i",
                        raw,
                        i + 3
                    )[0]

                    insn_va = base_va + i
                    next_va = insn_va + 7
                    target_va = next_va + disp

                    target_name = None

                    for name, addr in TARGETS.items():

                        if target_va == addr:
                            target_name = name
                            break

                    if target_name is not None:

                        # Capture instructions after the LEA.
                        after = raw[i+7:i+7+96]

                        function_store_candidates.append({
                            "function": item["name"],
                            "function_va": item["va"],
                            "lea_va": insn_va,
                            "target_name": target_name,
                            "target_va": target_va,
                            "following_bytes": after.hex(" ")
                        })

            i += 1

    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------

    result = {
        "targets": TARGETS,
        "rip_references": rip_refs,
        "candidate_store_accesses": candidate_accesses,
        "important_functions": important_windows,
        "function_context_windows": function_store_candidates,
        "loads": loads
    }

with open(
    os.path.join(out_dir, "stage49_static.json"),
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
Write-Host "AGC PS5 Stage 49 - Context Write Audit" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Info "SPRX       = $SprxPath"
Write-Info "NID DB     = $NidDb"
Write-Info "Output     = $OutDir"
Write-Info "Submit     = 0x18b0"
Write-Info "AGR ctx    = 0x1a868"
Write-Info "DCB ctx    = 0x1a8b8"
Write-Info "Global     = 0x1a908"
Write-Info "ACB table  = 0x18460"

try {

    Write-Step "Prepare Linux workspace"

    Invoke-WslChecked @"
rm -rf '$TmpRoot'
mkdir -p '$TmpRoot'
mkdir -p '$OutUnix'
cp '$PythonUnix' '$TmpRoot/analyze_context_writes.py'
python3 -m py_compile '$TmpRoot/analyze_context_writes.py'
"@ | Out-Null

    Write-Step "Analyze context accesses and candidate stores"

    Invoke-WslChecked @"
python3 '$TmpRoot/analyze_context_writes.py' \
    '$SprxUnix' \
    '$NidUnix' \
    '$TmpRoot'
"@ | Out-Null

    Write-Step "Collect static analysis"

    Invoke-WslChecked @"
cp '$TmpRoot/stage49_static.json' \
   '$OutUnix/stage49_static.json'

cat '$TmpRoot/stage49_static.json'
"@ | Out-Null

    $StaticPath = Join-Path `
        $OutDir `
        "stage49_static.json"

    $Static = (
        Get-Content `
            -LiteralPath $StaticPath `
            -Raw
    ) | ConvertFrom-Json

    # ========================================================
    # Candidate summary
    # ========================================================

    Write-Step "Create candidate write summary"

    $Summary = New-Object `
        System.Collections.Generic.List[string]

    $Summary.Add(
        "AGC PS5 Stage 49 - Context Write Audit"
    )

    $Summary.Add("")
    $Summary.Add(
        "The following are STATIC CANDIDATES only."
    )

    $Summary.Add(
        "No AGC code is executed."
    )

    $Summary.Add("")

    $Summary.Add(
        "=== EXACT RIP REFERENCES ==="
    )

    $RipRefs = @(
        $Static.rip_references
    )

    $Summary.Add(
        "count=$($RipRefs.Count)"
    )

    foreach ($Ref in $RipRefs) {

        $Owner = "<unknown>"

        if ($null -ne $Ref.owner) {

            if (-not [string]::IsNullOrWhiteSpace(
                [string]$Ref.owner.mapped_name
            )) {
                $Owner = [string]$Ref.owner.mapped_name
            }
        }

        $Summary.Add(
            ("0x{0:x} {1} -> {2}  owner={3}" -f `
                [int64]$Ref.instruction_va,
                $Ref.opcode,
                $Ref.target_name,
                $Owner)
        )
    }

    $Summary.Add("")
    $Summary.Add(
        "=== IMPORTANT AGC FUNCTIONS ==="
    )

    foreach ($Fn in @(
        $Static.function_context_windows
    )) {

        $Summary.Add(
            ("{0} @ 0x{1:x} -> {2}" -f `
                $Fn.function,
                [int64]$Fn.lea_va,
                $Fn.target_name)
        )
    }

    $Summary.Add("")
    $Summary.Add(
        "=== CANDIDATE STORE ACCESSES ==="
    )

    $Candidates = @(
        $Static.candidate_store_accesses
    )

    $Summary.Add(
        "count=$($Candidates.Count)"
    )

    foreach ($Candidate in $Candidates) {

        $TargetName = $Candidate.context_reference.target_name

        $Summary.Add(
            ("0x{0:x} {1} + 0x{2:x} target={3}" -f `
                [int64]$Candidate.access_va,
                $Candidate.opcode,
                ([int64]$Candidate.displacement),
                $TargetName)
        )
    }

    $SummaryPath = Join-Path `
        $OutDir `
        "context_write_summary.txt"

    [System.IO.File]::WriteAllText(
        $SummaryPath,
        ($Summary -join "`r`n") + "`r`n",
        [System.Text.UTF8Encoding]::new($false)
    )

    Get-Content `
        -LiteralPath $SummaryPath

    # ========================================================
    # Export important function binaries
    # ========================================================

    Write-Step "Export important Submit-family binaries"

    $FunctionDir = Join-Path `
        $OutDir `
        "functions"

    New-Item `
        -ItemType Directory `
        -Force `
        -Path $FunctionDir |
        Out-Null

    $FunctionDirUnix = Convert-ToWslPath $FunctionDir

    Invoke-WslChecked @"
mkdir -p '$FunctionDirUnix'

python3 - '$TmpRoot/stage49_static.json' '$FunctionDirUnix' <<'PY'
import json
import os
import sys

src = sys.argv[1]
out_dir = sys.argv[2]

with open(src, "r", encoding="utf-8") as fp:
    data = json.load(fp)

for item in data["important_functions"]:

    raw = item["raw"]
    blob = bytes.fromhex(raw["bytes_hex"])

    safe = item["name"].replace("/", "_")

    path = os.path.join(
        out_dir,
        safe + ".bin"
    )

    with open(path, "wb") as fp:
        fp.write(blob)

    print(
        f"{item['name']} "
        f"VA=0x{item['va']:x} "
        f"size={len(blob)} "
        f"out={path}"
    )
PY

ls -lh '$FunctionDirUnix'
"@ | Out-Null

    # ========================================================
    # Disassemble the important functions
    # ========================================================

    Write-Step "Disassemble important Submit-family functions"

    $DisassemblyPath = Join-Path `
        $OutDir `
        "submit_family_disassembly.txt"

    $Disassembly = New-Object `
        System.Collections.Generic.List[string]

    $FunctionFiles = @(
        Get-ChildItem `
            -LiteralPath $FunctionDir `
            -Filter "*.bin" `
            -File
    )

    foreach ($FunctionFile in $FunctionFiles) {

        $Name = $FunctionFile.BaseName
        $BinUnix = Convert-ToWslPath $FunctionFile.FullName

        $Fn = @(
            $Static.important_functions
        ) |
            Where-Object {
                $_.name -eq $Name
            } |
            Select-Object -First 1

        if ($null -eq $Fn) {
            continue
        }

        $StartHex = ("0x{0:x}" -f [int64]$Fn.va)

        $Disassembly.Add(
            "============================================"
        )

        $Disassembly.Add(
            "$Name START_VA=$StartHex"
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
        (Join-Path $OutDir "stage49_static.json"),
        (Join-Path $OutDir "context_write_summary.txt"),
        (Join-Path $OutDir "submit_family_disassembly.txt")
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

    $FunctionCandidates = @(
        $Static.function_context_windows
    ).Count

    $StoreCandidates = @(
        $Static.candidate_store_accesses
    ).Count

    $Report = [ordered]@{
        stage = 49

        timestamp = (Get-Date).ToString("o")

        target = [ordered]@{
            name = "sceAgcDriverSubmitCommandBuffer"
            va   = "0x18b0"
        }

        contexts = [ordered]@{
            agr = "0x1a868"
            dcb = "0x1a8b8"
            global = "0x1a908"
            acb = "0x18460"
        }

        static = [ordered]@{
            exact_rip_references = @(
                $Static.rip_references
            ).Count

            submit_family_context_windows = $FunctionCandidates

            candidate_store_accesses = $StoreCandidates
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
        "STAGE49_REPORT.json"

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
    Write-Host "Stage 49 completed" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""

    Write-Host `
        "CONTEXT_REFERENCE_SCAN = PASS" `
        -ForegroundColor Green

    Write-Host `
        "SUBMIT_FAMILY_ANALYSIS = PASS" `
        -ForegroundColor Green

    if ($StoreCandidates -gt 0) {

        Write-Host `
            "CANDIDATE_STORE_SITES = FOUND" `
            -ForegroundColor Yellow
    }
    else {

        Write-Host `
            "CANDIDATE_STORE_SITES = NONE" `
            -ForegroundColor Yellow
    }

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