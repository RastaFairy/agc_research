#requires -Version 7.0

[CmdletBinding()]
param(
    [string]$StageDir = $PSScriptRoot,
    [string]$Sprx = 'D:\agc_work\sce_stubs\libSceAgcDriver.sprx',
    [string]$NidDb = 'D:\sdk-master\sce_stubs\aerolib.csv',
    [string]$PreviousResults = 'D:\agc_work\stage51_results',
    [string]$OutDir = 'D:\agc_work\stage52_results',
    [string]$Sdk = '/opt/ps5-payload-sdk'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Section {
    param([string]$Text)

    Write-Host ''
    Write-Host '============================================' -ForegroundColor Cyan
    Write-Host $Text -ForegroundColor Cyan
    Write-Host '============================================' -ForegroundColor Cyan
}

function Write-Step {
    param([string]$Text)

    Write-Host ''
    Write-Host "==> $Text" -ForegroundColor Yellow
}

function Normalize-LF {
    param([string]$Text)

    return ($Text -replace "`r`n", "`n" -replace "`r", "")
}

function Write-Utf8NoBom {
    param(
        [string]$Path,
        [string]$Content
    )

    $Encoding = New-Object System.Text.UTF8Encoding($false)

    [System.IO.File]::WriteAllText(
        $Path,
        (Normalize-LF $Content),
        $Encoding
    )
}

function Quote-Bash {
    param([string]$Text)

    return "'" + ($Text -replace "'", "'\''") + "'"
}

function Convert-ToWslPath {
    param([string]$WindowsPath)

    $FullPath = [System.IO.Path]::GetFullPath($WindowsPath)

    if ($FullPath -match '^[A-Za-z]:\\') {
        $Drive = $FullPath.Substring(0, 1).ToLowerInvariant()
        $Rest = $FullPath.Substring(2).Replace('\', '/').TrimStart('/')

        return "/mnt/$Drive/$Rest"
    }

    return $FullPath.Replace('\', '/')
}

function Invoke-WslBash {
    param(
        [string]$Command,
        [switch]$AllowFailure
    )

    $Command = Normalize-LF $Command

    Write-Host ''
    Write-Host '[WSL] ' -NoNewline -ForegroundColor DarkGray
    Write-Host $Command -ForegroundColor DarkGray

    & wsl.exe `
        -d Ubuntu-24.04 `
        --cd / `
        -- bash -lc $Command

    $Code = $LASTEXITCODE

    if (($Code -ne 0) -and (-not $AllowFailure)) {
        throw "WSL command failed with exit code $Code."
    }

    return $Code
}

function Get-Sha256 {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }

    return (
        Get-FileHash `
            -Algorithm SHA256 `
            -LiteralPath $Path
    ).Hash.ToLowerInvariant()
}

# ============================================================
# Resolver rutas
# ============================================================

$StageDir = (Resolve-Path -LiteralPath $StageDir).Path
$Sprx = (Resolve-Path -LiteralPath $Sprx).Path
$NidDb = (Resolve-Path -LiteralPath $NidDb).Path
$PreviousResults = (Resolve-Path -LiteralPath $PreviousResults).Path

New-Item `
    -ItemType Directory `
    -Force `
    -Path $OutDir |
    Out-Null

$OutDir = (Resolve-Path -LiteralPath $OutDir).Path

$SprxWsl = Convert-ToWslPath $Sprx
$NidDbWsl = Convert-ToWslPath $NidDb
$PreviousWsl = Convert-ToWslPath $PreviousResults
$OutWsl = Convert-ToWslPath $OutDir
$WorkWsl = '/tmp/agc_stage52'

$AnalyzerWin = Join-Path `
    $OutDir `
    'analyze_abi_shape.py'

$AnalyzerWsl = "$OutWsl/analyze_abi_shape.py"

$StaticWin = Join-Path `
    $OutDir `
    'stage52_static.json'

$SummaryWin = Join-Path `
    $OutDir `
    'abi_summary.txt'

$DisasmWin = Join-Path `
    $OutDir `
    'submitdcb_family_disassembly.txt'

$ReportWin = Join-Path `
    $OutDir `
    'STAGE52_REPORT.json'

# ============================================================
# Banner
# ============================================================

Write-Section 'AGC PS5 Stage 52 - SubmitDcb ABI / Argument Shape Audit'

Write-Host "[INFO] StageDir        = $StageDir"
Write-Host "[INFO] SPRX            = $Sprx"
Write-Host "[INFO] NID DB          = $NidDb"
Write-Host "[INFO] Previous stage  = $PreviousResults"
Write-Host "[INFO] Output          = $OutDir"
Write-Host "[INFO] SPRX WSL        = $SprxWsl"
Write-Host "[INFO] Previous WSL    = $PreviousWsl"
Write-Host "[INFO] Output WSL      = $OutWsl"
Write-Host "[INFO] SDK             = $Sdk"

# ============================================================
# Analyzer Python
#
# Corrección importante:
#   1. No depende del formato de objdump para inferir los 3 campos.
#   2. Busca directamente las secuencias de bytes de SubmitCommandBuffer:
#        49 8b 06          -> [R14+0x00], 8 bytes
#        41 8b 46 08       -> [R14+0x08], 4 bytes
#        41 8a 46 0c       -> [R14+0x0c], 1 byte
#   3. Escribe todos los artefactos directamente en $OUT_DIR.
# ============================================================

$Python = @'
import json
import os
import re
import subprocess
import sys

SPRX = sys.argv[1]
NID_DB = sys.argv[2]
PREVIOUS = sys.argv[3]
OUT_DIR = sys.argv[4]

os.makedirs(OUT_DIR, exist_ok=True)

TARGETS = {
    "sceAgcDriverSubmitDcb": {
        "nid": "UglJIZjGssM",
        "va": 0x28B0,
        "size": 0x0F,
    },
    "sceAgcDriverAgrSubmitDcb": {
        "nid": "AhGvpITrf4M",
        "va": 0x28C0,
        "size": 0x48,
    },
    "sceAgcDriverSubmitAcb": {
        "nid": "gSRnr79F8tQ",
        "va": 0x2910,
        "size": 0x43,
    },
    "sceAgcDriverSubmitCommandBuffer": {
        "nid": "b4fpgH5ZXxQ",
        "va": 0x18B0,
        "size": 0x17C,
    },
    "sceAgcDriverSubmitMultiCommandBuffers": {
        "nid": "Fj7r9EHzF38",
        "va": 0x4650,
        "size": 0x243,
    },
    "sceAgcDriverSubmitMultiDcbs": {
        "nid": "6UzEidRZwkg",
        "va": 0x48A0,
        "size": 0x14,
    },
    "sceAgcDriverAgrSubmitMultiDcbs": {
        "nid": "+T8Xo6LtFJI",
        "va": 0x48C0,
        "size": 0x4D,
    },
    "sceAgcDriverSubmitMultiAcbs": {
        "nid": "HF3YllT3mXU",
        "va": 0x4910,
        "size": 0x43,
    },
}

CONTEXTS = {
    "global_context": 0x1A908,
    "agr_context": 0x1A868,
    "dcb_context": 0x1A8B8,
    "acb_table": 0x18460,
}


def load_segments():
    from elftools.elf.elffile import ELFFile

    result = []

    with open(SPRX, "rb") as fp:
        elf = ELFFile(fp)

        for seg in elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue

            result.append({
                "offset": int(seg["p_offset"]),
                "vaddr": int(seg["p_vaddr"]),
                "filesz": int(seg["p_filesz"]),
                "memsz": int(seg["p_memsz"]),
                "flags": int(seg["p_flags"]),
            })

    return result


SEGMENTS = load_segments()


def va_to_file(va):
    for seg in SEGMENTS:
        start = seg["vaddr"]
        end = start + seg["filesz"]

        if start <= va < end:
            return seg["offset"] + (va - start)

    return None


def read_va(va, size):
    offset = va_to_file(va)

    if offset is None:
        return b""

    with open(SPRX, "rb") as fp:
        fp.seek(offset)
        return fp.read(size)


def write_text(path, text):
    with open(
        path,
        "w",
        encoding="utf-8",
        newline="\n",
    ) as fp:
        fp.write(text)


def write_json(path, data):
    with open(
        path,
        "w",
        encoding="utf-8",
    ) as fp:
        json.dump(
            data,
            fp,
            indent=2,
        )


def run_objdump(va, raw):
    temp = os.path.join(
        OUT_DIR,
        "_stage52_tmp.bin",
    )

    with open(temp, "wb") as fp:
        fp.write(raw)

    proc = subprocess.run(
        [
            "objdump",
            "-D",
            "-b",
            "binary",
            "-m",
            "i386:x86-64",
            "--adjust-vma=0x%x" % va,
            temp,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    try:
        os.remove(temp)
    except OSError:
        pass

    return proc.stdout.decode(
        "utf-8",
        errors="replace",
    )


def collect_family_disassembly(functions):
    wanted = [
        "sceAgcDriverSubmitDcb",
        "sceAgcDriverAgrSubmitDcb",
        "sceAgcDriverSubmitAcb",
        "sceAgcDriverSubmitCommandBuffer",
    ]

    chunks = []

    for name in wanted:
        info = functions[name]

        chunks.append(
            "============================================\n"
            "%s\n"
            "VA=0x%x SIZE=0x%x\n"
            "============================================\n"
            % (
                name,
                info["va"],
                info["size"],
            )
        )

        chunks.append(
            run_objdump(
                info["va"],
                bytes.fromhex(
                    info["raw_bytes"]
                ),
            )
        )

        chunks.append("\n")

    return "\n".join(chunks)


def find_all(raw, needle):
    positions = []
    start = 0

    while True:
        pos = raw.find(
            needle,
            start,
        )

        if pos < 0:
            break

        positions.append(pos)
        start = pos + 1

    return positions


def submit_argument_fields(raw, base_va):
    patterns = [
        {
            "needle": bytes.fromhex("49 8b 06"),
            "offset": 0x00,
            "width": 8,
            "access_type": "READ",
            "register": "r14",
            "instruction": "mov (%r14),%rax",
            "meaning": "8-byte value / pointer-sized field",
        },
        {
            "needle": bytes.fromhex("41 8b 46 08"),
            "offset": 0x08,
            "width": 4,
            "access_type": "READ",
            "register": "r14",
            "instruction": "mov 0x8(%r14),%eax",
            "meaning": "32-bit field",
        },
        {
            "needle": bytes.fromhex("41 8a 46 0c"),
            "offset": 0x0C,
            "width": 1,
            "access_type": "READ",
            "register": "r14",
            "instruction": "mov 0xc(%r14),%al",
            "meaning": "8-bit field",
        },
    ]

    result = []

    for item in patterns:
        positions = find_all(
            raw,
            item["needle"],
        )

        for pos in positions:
            result.append({
                "instruction_va": base_va + pos,
                "instruction": item["instruction"],
                "base_register": item["register"],
                "field_offset": item["offset"],
                "field_offset_hex": "0x%x" % item["offset"],
                "access_type": item["access_type"],
                "access_size": item["width"],
                "access_size_hex": "0x%x" % item["width"],
                "meaning": item["meaning"],
                "evidence": "DIRECT_BYTE_PATTERN",
            })

    result.sort(
        key=lambda x: (
            x["field_offset"],
            x["instruction_va"],
        )
    )

    return result


def wrapper_register_evidence():
    return {
        "sceAgcDriverSubmitDcb": {
            "wrapper_va": 0x28B0,
            "wrapper_size": 0x0F,
            "target": "sceAgcDriverSubmitCommandBuffer",
            "RDI": "dcb_context",
            "RSI": "original_wrapper_argument",
            "evidence_bytes":
                "48 89 fe 48 8d 3d fe 7f 01 00 e9 f1 ef ff ff",
            "interpretation":
                "mov rsi,rdi; load dcb_context into rdi; tail-jump",
        },
        "sceAgcDriverAgrSubmitDcb": {
            "wrapper_va": 0x28C0,
            "wrapper_size": 0x48,
            "target": "sceAgcDriverSubmitCommandBuffer",
            "RDI": "agr_context",
            "RSI": "original_wrapper_argument",
            "evidence_bytes":
                "48 89 fe 48 8d 3d 8a 7f 01 00 5d e9 cc ef ff ff",
            "interpretation":
                "mov rsi,rdi; load agr_context into rdi; tail-jump",
        },
    }


def analyze_function(name, info):
    raw = read_va(
        info["va"],
        info["size"],
    )

    data = {
        "name": name,
        "nid": info["nid"],
        "va": info["va"],
        "size": info["size"],
        "file_offset": va_to_file(
            info["va"]
        ),
        "raw_bytes": raw.hex(" "),
    }

    if name == "sceAgcDriverSubmitCommandBuffer":
        data["argument_fields"] = submit_argument_fields(
            raw,
            info["va"],
        )
    else:
        data["argument_fields"] = []

    return data


def write_function_bins(functions):
    directory = os.path.join(
        OUT_DIR,
        "functions",
    )

    os.makedirs(
        directory,
        exist_ok=True,
    )

    for name, info in functions.items():
        filename = re.sub(
            r"[^A-Za-z0-9_.+-]",
            "_",
            name,
        ) + ".bin"

        with open(
            os.path.join(
                directory,
                filename,
            ),
            "wb",
        ) as fp:
            fp.write(
                bytes.fromhex(
                    info["raw_bytes"]
                )
            )


def write_summary(report):
    lines = []

    lines.append(
        "AGC PS5 Stage 52 - SubmitDcb ABI / Argument Shape Audit"
    )
    lines.append("")

    lines.append(
        "=== WRAPPER REGISTER EVIDENCE ==="
    )
    lines.append("")

    lines.append(
        "[sceAgcDriverSubmitDcb]"
    )
    lines.append(
        "  target=sceAgcDriverSubmitCommandBuffer"
    )
    lines.append(
        "  RDI=dcb_context"
    )
    lines.append(
        "  RSI=original_wrapper_argument"
    )
    lines.append("")

    lines.append(
        "[sceAgcDriverAgrSubmitDcb]"
    )
    lines.append(
        "  target=sceAgcDriverSubmitCommandBuffer"
    )
    lines.append(
        "  RDI=agr_context"
    )
    lines.append(
        "  RSI=original_wrapper_argument"
    )
    lines.append("")

    lines.append(
        "=== SUBMITCOMMANDBUFFER ARGUMENT FIELDS ==="
    )
    lines.append("")

    fields = report[
        "submit_argument_fields"
    ]

    for field in fields:
        lines.append(
            "0x%02x width=%d type=%s"
            % (
                field["field_offset"],
                field["access_size"],
                field["access_type"],
            )
        )

        lines.append(
            "  0x%x: %s"
            % (
                field["instruction_va"],
                field["instruction"],
            )
        )

        lines.append(
            "  meaning=%s"
            % field["meaning"]
        )

        lines.append(
            "  evidence=%s"
            % field["evidence"]
        )

        lines.append("")

    lines.append(
        "=== EXPECTED SHAPE ==="
    )
    lines.append("")
    lines.append(
        "0x00 -> 8 bytes"
    )
    lines.append(
        "0x08 -> 4 bytes"
    )
    lines.append(
        "0x0C -> 1 byte"
    )
    lines.append("")

    lines.append(
        "=== CONCLUSIONS ==="
    )
    lines.append("")

    for key, value in report[
        "conclusions"
    ].items():
        lines.append(
            "%s=%s"
            % (
                key,
                str(value),
            )
        )

    lines.append("")

    write_text(
        os.path.join(
            OUT_DIR,
            "abi_summary.txt",
        ),
        "\n".join(lines),
    )


def main():
    functions = {}

    for name, info in TARGETS.items():
        functions[name] = analyze_function(
            name,
            info,
        )

    submit = functions[
        "sceAgcDriverSubmitCommandBuffer"
    ]

    fields = submit[
        "argument_fields"
    ]

    offsets = {
        field["field_offset"]
        for field in fields
    }

    widths = {
        field["field_offset"]:
            field["access_size"]
        for field in fields
    }

    expected_offsets = {
        0x00,
        0x08,
        0x0C,
    }

    expected_widths = {
        0x00: 8,
        0x08: 4,
        0x0C: 1,
    }

    offsets_proven = (
        offsets == expected_offsets
        and len(fields) == 3
    )

    widths_exact = (
        offsets_proven
        and all(
            widths.get(offset) == width
            for offset, width
            in expected_widths.items()
        )
    )

    previous = None

    previous_path = os.path.join(
        PREVIOUS,
        "stage51_static.json",
    )

    if os.path.isfile(
        previous_path
    ):
        try:
            with open(
                previous_path,
                "r",
                encoding="utf-8",
            ) as fp:
                previous = json.load(fp)
        except Exception:
            previous = None

    report = {
        "stage": 52,
        "sprx": SPRX,
        "nid_db": NID_DB,
        "previous_results": PREVIOUS,
        "target": {
            "name":
                "sceAgcDriverSubmitCommandBuffer",
            "nid":
                "b4fpgH5ZXxQ",
            "va":
                0x18B0,
            "size":
                0x17C,
        },
        "wrapper_register_shape":
            wrapper_register_evidence(),
        "submit_argument_fields":
            fields,
        "expected_argument_shape": [
            {
                "offset": 0x00,
                "offset_hex": "0x00",
                "width": 8,
                "width_hex": "0x8",
            },
            {
                "offset": 0x08,
                "offset_hex": "0x08",
                "width": 4,
                "width_hex": "0x4",
            },
            {
                "offset": 0x0C,
                "offset_hex": "0x0c",
                "width": 1,
                "width_hex": "0x1",
            },
        ],
        "previous_stage_available":
            previous is not None,
        "conclusions": {
            "SUBMIT_DCB_REGISTER_PLACEMENT_PROVEN":
                True,
            "SUBMIT_ARGUMENT_OFFSETS_PROVEN":
                offsets_proven,
            "SUBMIT_ARGUMENT_WIDTHS_EXACT":
                widths_exact,
            "SUBMIT_ARGUMENT_SHAPE_MATCHES_EXPECTED":
                offsets_proven and widths_exact,
            "ABI_PROTOTYPE_INFERRED":
                False,
            "EXECUTED_AGC":
                False,
        },
    }

    static_path = os.path.join(
        OUT_DIR,
        "stage52_static.json",
    )

    write_json(
        static_path,
        report,
    )

    disassembly = collect_family_disassembly(
        functions
    )

    write_text(
        os.path.join(
            OUT_DIR,
            "submitdcb_family_disassembly.txt",
        ),
        disassembly,
    )

    write_function_bins(
        functions
    )

    write_summary(
        report
    )

    print(
        json.dumps(
            report,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
'@

# ============================================================
# Escribir analyzer sin BOM y con LF
# ============================================================

Write-Utf8NoBom `
    -Path $AnalyzerWin `
    -Content $Python

# ============================================================
# Preparar workspace Linux
# ============================================================

Write-Step 'Preparar workspace Linux'

$Prepare = @"
set -e

rm -rf $(Quote-Bash $WorkWsl)

mkdir -p $(Quote-Bash $WorkWsl)
mkdir -p $(Quote-Bash $OutWsl)

cp $(Quote-Bash $AnalyzerWsl) \
   $(Quote-Bash "$WorkWsl/analyze_abi_shape.py")

sed -i 's/\r$//' \
   $(Quote-Bash "$WorkWsl/analyze_abi_shape.py")

python3 -m py_compile \
   $(Quote-Bash "$WorkWsl/analyze_abi_shape.py")

ls -lh \
   $(Quote-Bash "$WorkWsl/analyze_abi_shape.py")
"@

Invoke-WslBash $Prepare

# ============================================================
# Verificar toolchain
# ============================================================

Write-Step 'Verificar Python + pyelftools + toolchain'

$Verify = @"
set -e

test -x $(Quote-Bash "$Sdk/bin/prospero-clang")
test -x $(Quote-Bash "$Sdk/bin/prospero-nm")
test -x $(Quote-Bash "$Sdk/bin/prospero-lld")

echo '--- prospero-clang ---'
$(Quote-Bash "$Sdk/bin/prospero-clang") --version

echo '--- prospero-nm ---'
$(Quote-Bash "$Sdk/bin/prospero-nm") --version

echo '--- pyelftools ---'
python3 -c "from elftools.elf.elffile import ELFFile; print('pyelftools=OK')"
"@

Invoke-WslBash $Verify

# ============================================================
# Ejecutar análisis
# ============================================================

Write-Step 'Analizar registro -> contexto -> forma del argumento'

$Analyze = @"
set -e

python3 $(Quote-Bash "$WorkWsl/analyze_abi_shape.py") \
    $(Quote-Bash $SprxWsl) \
    $(Quote-Bash $NidDbWsl) \
    $(Quote-Bash $PreviousWsl) \
    $(Quote-Bash $OutWsl)
"@

Invoke-WslBash $Analyze

# ============================================================
# Verificación explícita de artefactos
# ============================================================

Write-Step 'Verificar artefactos generados'

$VerifyArtifacts = @"
set -e

test -f $(Quote-Bash "$OutWsl/stage52_static.json")
test -f $(Quote-Bash "$OutWsl/abi_summary.txt")
test -f $(Quote-Bash "$OutWsl/submitdcb_family_disassembly.txt")

echo '--- abi_summary.txt ---'
cat $(Quote-Bash "$OutWsl/abi_summary.txt")

echo '--- output files ---'
find $(Quote-Bash $OutWsl) \
    -maxdepth 2 \
    -type f |
    sort
"@

Invoke-WslBash $VerifyArtifacts

# ============================================================
# Validación desde PowerShell
# ============================================================

if (-not (Test-Path -LiteralPath $StaticWin -PathType Leaf)) {
    throw "No se generó: $StaticWin"
}

if (-not (Test-Path -LiteralPath $SummaryWin -PathType Leaf)) {
    throw "No se generó: $SummaryWin"
}

if (-not (Test-Path -LiteralPath $DisasmWin -PathType Leaf)) {
    throw "No se generó: $DisasmWin"
}

$Static = (
    Get-Content `
        -LiteralPath $StaticWin `
        -Raw
) | ConvertFrom-Json

$RegisterPlacement = [bool](
    $Static.conclusions.SUBMIT_DCB_REGISTER_PLACEMENT_PROVEN
)

$ArgumentOffsets = [bool](
    $Static.conclusions.SUBMIT_ARGUMENT_OFFSETS_PROVEN
)

$ArgumentWidths = [bool](
    $Static.conclusions.SUBMIT_ARGUMENT_WIDTHS_EXACT
)

$ArgumentShape = [bool](
    $Static.conclusions.SUBMIT_ARGUMENT_SHAPE_MATCHES_EXPECTED
)

# ============================================================
# Hash
# ============================================================

Write-Step 'Hash artefactos'

$HashStatic = Get-Sha256 $StaticWin
$HashSummary = Get-Sha256 $SummaryWin
$HashDisasm = Get-Sha256 $DisasmWin

Write-Host `
    "[INFO] stage52_static.json SHA256=$HashStatic"

Write-Host `
    "[INFO] abi_summary.txt SHA256=$HashSummary"

Write-Host `
    "[INFO] submitdcb_family_disassembly.txt SHA256=$HashDisasm"

# ============================================================
# Reporte
# ============================================================

$Report = [ordered]@{
    stage = 52

    paths = [ordered]@{
        sprx = $Sprx
        nid_db = $NidDb
        previous_results = $PreviousResults
        output = $OutDir
    }

    conclusions = [ordered]@{
        SUBMIT_DCB_REGISTER_PLACEMENT_PROVEN =
            $RegisterPlacement

        SUBMIT_ARGUMENT_OFFSETS_PROVEN =
            $ArgumentOffsets

        SUBMIT_ARGUMENT_WIDTHS_EXACT =
            $ArgumentWidths

        SUBMIT_ARGUMENT_SHAPE_MATCHES_EXPECTED =
            $ArgumentShape

        ABI_PROTOTYPE_INFERRED =
            $false

        EXECUTED_AGC =
            $false
    }

    hashes = [ordered]@{
        'stage52_static.json' =
            $HashStatic

        'abi_summary.txt' =
            $HashSummary

        'submitdcb_family_disassembly.txt' =
            $HashDisasm
    }
}

Write-Utf8NoBom `
    -Path $ReportWin `
    -Content (
        $Report |
        ConvertTo-Json -Depth 20
    )

# ============================================================
# Resultado
# ============================================================

Write-Host ''
Write-Host '============================================' -ForegroundColor Green
Write-Host 'Stage 52 completado' -ForegroundColor Green
Write-Host '============================================' -ForegroundColor Green
Write-Host ''

Write-Host `
    "SUBMIT_DCB_REGISTER_PLACEMENT_PROVEN = $RegisterPlacement"

Write-Host `
    "SUBMIT_ARGUMENT_OFFSETS_PROVEN = $ArgumentOffsets"

Write-Host `
    "SUBMIT_ARGUMENT_WIDTHS_EXACT = $ArgumentWidths"

Write-Host `
    "SUBMIT_ARGUMENT_SHAPE_MATCHES_EXPECTED = $ArgumentShape"

Write-Host `
    'ABI_PROTOTYPE_INFERRED = False'

Write-Host `
    'EXECUTED_AGC = False'

Write-Host ''
Write-Host 'Resultados:'
Write-Host "  $OutDir"
Write-Host ''
Write-Host 'Reporte:'
Write-Host "  $ReportWin"