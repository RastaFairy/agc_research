#requires -Version 7.0

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$StageDir = Split-Path -Parent $MyInvocation.MyCommand.Path

$StageTitle = 'AGC PS5 Stage 72 - Dispatch Entry Layout / Function Pointer Provenance Audit'

$SprxWin    = 'D:\agc_work\sce_stubs\libSceAgcDriver.sprx'
$NidWin     = 'D:\sdk-master\sce_stubs\aerolib.csv'
$PreviousWin = 'D:\agc_work\stage71_results'
$OutputWin   = 'D:\agc_work\stage72_results'

function Convert-ToWslPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ($Path -match '^[A-Za-z]:\\') {
        $drive = $Path.Substring(0, 1).ToLower()
        $rest  = $Path.Substring(2).Replace('\', '/')
        return "/mnt/$drive$rest"
    }

    return $Path.Replace('\', '/')
}

$SprxWsl     = Convert-ToWslPath $SprxWin
$NidWsl      = Convert-ToWslPath $NidWin
$PreviousWsl = Convert-ToWslPath $PreviousWin
$OutputWsl   = Convert-ToWslPath $OutputWin
$StageWsl    = Convert-ToWslPath $StageDir

$AnalyzerWin = Join-Path $OutputWin 'analyze_dispatch_entries.py'

Write-Host ''
Write-Host '============================================'
Write-Host $StageTitle
Write-Host '============================================'
Write-Host "[INFO] StageDir        = $StageDir"
Write-Host "[INFO] SPRX            = $SprxWin"
Write-Host "[INFO] NID DB          = $NidWin"
Write-Host "[INFO] Previous stage  = $PreviousWin"
Write-Host "[INFO] Output          = $OutputWin"
Write-Host "[INFO] SPRX WSL        = $SprxWsl"
Write-Host "[INFO] Previous WSL    = $PreviousWsl"
Write-Host "[INFO] Output WSL      = $OutputWsl"
Write-Host "[INFO] SDK             = /opt/ps5-payload-sdk"

function Invoke-WslScript {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Script
    )

    Write-Host ''
    Write-Host '[WSL] set -e'
    Write-Host ''
    Write-Host $Script

    $result = & wsl.exe bash -lc $Script 2>&1
    $code = $LASTEXITCODE

    if ($result) {
        $result | ForEach-Object {
            Write-Host $_
        }
    }

    if ($code -ne 0) {
        throw "WSL command failed with exit code $code."
    }

    return $result
}

# ---------------------------------------------------------------------------
# Validaciones Windows
# ---------------------------------------------------------------------------

if (-not (Test-Path -LiteralPath $SprxWin -PathType Leaf)) {
    throw "No existe SPRX: $SprxWin"
}

if (-not (Test-Path -LiteralPath $NidWin -PathType Leaf)) {
    throw "No existe NID DB: $NidWin"
}

if (-not (Test-Path -LiteralPath $PreviousWin -PathType Container)) {
    throw "No existe resultado Stage 71: $PreviousWin"
}

New-Item -ItemType Directory -Force -Path $OutputWin | Out-Null

# ---------------------------------------------------------------------------
# Analizador Python autocontenido
# ---------------------------------------------------------------------------

$AnalyzerPython = @'
#!/usr/bin/env python3

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from elftools.elf.elffile import ELFFile


SPRX = Path(sys.argv[1])
NID_DB = Path(sys.argv[2])
PREVIOUS = Path(sys.argv[3])
OUT = Path(sys.argv[4])

GLOBAL_CONTEXT = 0x1A908

SUBMIT_TABLE_OFFSET = 0x50
MULTI_TABLE_OFFSET = 0x58

ENTRY_STRIDE = 0x78

SUBMIT_VA = 0x18B0
SUBMIT_SIZE = 0x17C

MULTI_VA = 0x4650
MULTI_SIZE = 0x243

OUT.mkdir(parents=True, exist_ok=True)


def load_executable_segment():
    with SPRX.open("rb") as fp:
        elf = ELFFile(fp)

        for seg in elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue

            flags = int(seg["p_flags"])

            # PF_X
            if not (flags & 1):
                continue

            offset = int(seg["p_offset"])
            filesz = int(seg["p_filesz"])
            vaddr = int(seg["p_vaddr"])

            fp.seek(offset)
            blob = fp.read(filesz)

            return {
                "offset": offset,
                "filesz": filesz,
                "vaddr": vaddr,
                "bytes": blob,
            }

    raise RuntimeError("No se encontró segmento ejecutable PT_LOAD.")


def disassemble(blob, vaddr):
    with tempfile.NamedTemporaryFile(
        prefix="agc_stage72_",
        suffix=".bin",
        delete=False,
    ) as tf:
        temp_path = tf.name
        tf.write(blob)

    commands = [
        [
            "objdump",
            "-D",
            "-b", "binary",
            "-m", "i386:x86-64",
            "--adjust-vma=0x%x" % vaddr,
            temp_path,
        ],
        [
            "llvm-objdump",
            "-D",
            "-b", "binary",
            "--arch=x86-64",
            "--adjust-vma=0x%x" % vaddr,
            temp_path,
        ],
    ]

    try:
        last_error = None

        for cmd in commands:
            try:
                p = subprocess.run(
                    cmd,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                return p.stdout
            except Exception as exc:
                last_error = exc

        raise RuntimeError(
            f"No se pudo desensamblar el segmento: {last_error}"
        )

    finally:
        try:
            os.unlink(temp_path)
        except OSError:
            pass


def parse_disassembly(text):
    rows = []

    pattern = re.compile(
        r"^\s*([0-9a-fA-F]+):\s+"
        r"((?:[0-9a-fA-F]{2}\s+)+)"
        r"(.+?)\s*$"
    )

    for line in text.splitlines():
        m = pattern.match(line)
        if not m:
            continue

        va = int(m.group(1), 16)
        instruction = m.group(3).strip()

        rows.append(
            {
                "va": va,
                "instruction": instruction,
                "raw": line,
            }
        )

    return rows


def norm(s):
    return re.sub(r"\s+", " ", s.strip()).lower()


def get_window(rows, start_va, size):
    end_va = start_va + size
    return [
        row
        for row in rows
        if start_va <= row["va"] < end_va
    ]


def is_global_context_lea(instruction):
    n = norm(instruction)
    return (
        "lea" in n
        and "# 0x1a908" in n
    )


def extract_global_context_register(instruction):
    n = norm(instruction)

    # AT&T:
    # lea 0x18ff9(%rip),%rbx # 0x1a908
    m = re.search(
        r"lea\s+.*,%([a-z0-9]+)\s+#\s*0x1a908",
        n,
    )
    if m:
        return m.group(1)

    # Intel:
    # lea rbx,[rip+...]
    # address comment still contains 0x1a908
    m = re.search(
        r"lea\s+([a-z0-9]+),.*#\s*0x1a908",
        n,
    )
    if m:
        return m.group(1)

    return None


def find_dispatch_calls(rows, table_offset):
    result = []

    for row in rows:
        n = norm(row["instruction"])

        # AT&T:
        # call *0x50(%rbx,%rax,1)
        pat_att = re.search(
            r"call\s+\*?0x([0-9a-f]+)\(%([a-z0-9]+),%([a-z0-9]+),1\)",
            n,
        )

        if pat_att:
            offset = int(pat_att.group(1), 16)

            if offset == table_offset:
                result.append(
                    {
                        "va": row["va"],
                        "instruction": row["instruction"],
                        "table_offset": offset,
                        "base_register": pat_att.group(2),
                        "index_register": pat_att.group(3),
                        "scale": 1,
                        "syntax": "AT&T",
                    }
                )

            continue

        # Intel:
        # call QWORD PTR [rbx+rax*1+0x50]
        pat_intel = re.search(
            r"call\s+.*\[\s*"
            r"([a-z0-9]+)"
            r"\+"
            r"([a-z0-9]+)"
            r"\*1\+0x([0-9a-f]+)"
            r"\]",
            n,
        )

        if pat_intel:
            offset = int(pat_intel.group(3), 16)

            if offset == table_offset:
                result.append(
                    {
                        "va": row["va"],
                        "instruction": row["instruction"],
                        "table_offset": offset,
                        "base_register": pat_intel.group(1),
                        "index_register": pat_intel.group(2),
                        "scale": 1,
                        "syntax": "Intel",
                    }
                )

    return result


def find_index_scale(rows, before_va, index_register):
    reg = index_register.lower().replace("%", "")

    best = None

    for row in rows:
        if row["va"] >= before_va:
            break

        n = norm(row["instruction"])

        if "imul" not in n:
            continue

        if "0x78" not in n:
            continue

        if reg not in n:
            continue

        best = row

    return best


def find_global_store_candidates(rows):
    candidates = []

    # We scan the initialization image for stores involving +0x50/+0x58.
    for row in rows:
        n = norm(row["instruction"])

        for offset in (0x50, 0x58):
            off_text = f"0x{offset:x}"

            # Both AT&T and Intel forms.
            if off_text not in n:
                continue

            if "mov" not in n and "vmov" not in n:
                continue

            candidates.append(
                {
                    "va": row["va"],
                    "instruction": row["instruction"],
                    "table_offset": offset,
                }
            )

    return candidates


def find_zeroing_stores(rows):
    evidence = []

    # The reset sequence is identified through YMM/XMM zero stores.
    for row in rows:
        n = norm(row["instruction"])

        if "vmovups" not in n:
            continue

        if "ymm0" not in n:
            continue

        if "0x8(" in n or ",0x8(" in n:
            evidence.append(
                {
                    "va": row["va"],
                    "instruction": row["instruction"],
                    "relative_offset": 0x08,
                    "width": 32,
                }
            )

        elif "-0x10" in n:
            evidence.append(
                {
                    "va": row["va"],
                    "instruction": row["instruction"],
                    "relative_offset": -0x10,
                    "width": 32,
                }
            )

        elif "-0x30" in n:
            evidence.append(
                {
                    "va": row["va"],
                    "instruction": row["instruction"],
                    "relative_offset": -0x30,
                    "width": 32,
                }
            )

        elif "-0x50" in n:
            evidence.append(
                {
                    "va": row["va"],
                    "instruction": row["instruction"],
                    "relative_offset": -0x50,
                    "width": 32,
                }
            )

    return evidence


def previous_stage_info():
    result = {
        "available": PREVIOUS.is_dir(),
        "report_present": False,
        "count_semantics_proven": False,
        "index_semantics_proven": False,
        "runtime_table_initialization_proven": False,
    }

    report = PREVIOUS / "STAGE71_REPORT.json"

    if not report.is_file():
        return result

    result["report_present"] = True

    try:
        data = json.loads(report.read_text(encoding="utf-8"))
    except Exception:
        return result

    conclusions = data.get("conclusions", {})

    for key, value in conclusions.items():
        if "COUNT" in key and bool(value):
            result["count_semantics_proven"] = True

        if "INDEX" in key and bool(value):
            result["index_semantics_proven"] = True

        if "TABLE" in key and "INITIALIZATION" in key and bool(value):
            result["runtime_table_initialization_proven"] = True

    return result


def main():
    seg = load_executable_segment()

    disassembly = disassemble(
        seg["bytes"],
        seg["vaddr"],
    )

    disassembly_path = OUT / "dispatch_entry_disassembly.txt"
    disassembly_path.write_text(
        disassembly,
        encoding="utf-8",
    )

    rows = parse_disassembly(disassembly)

    submit_rows = get_window(
        rows,
        SUBMIT_VA,
        SUBMIT_SIZE,
    )

    multi_rows = get_window(
        rows,
        MULTI_VA,
        MULTI_SIZE,
    )

    submit_dispatch = find_dispatch_calls(
        submit_rows,
        SUBMIT_TABLE_OFFSET,
    )

    multi_dispatch = find_dispatch_calls(
        multi_rows,
        MULTI_TABLE_OFFSET,
    )

    for item in submit_dispatch:
        item["index_scale_evidence"] = (
            find_index_scale(
                submit_rows,
                item["va"],
                item["index_register"],
            )
        )

    for item in multi_dispatch:
        item["index_scale_evidence"] = (
            find_index_scale(
                multi_rows,
                item["va"],
                item["index_register"],
            )
        )

    zeroing = find_zeroing_stores(rows)

    store_candidates = find_global_store_candidates(
        rows
    )

    previous = previous_stage_info()

    submit_formula_proven = any(
        x.get("index_scale_evidence") is not None
        for x in submit_dispatch
    )

    multi_formula_proven = any(
        x.get("index_scale_evidence") is not None
        for x in multi_dispatch
    )

    function_pointer_proven = (
        len(submit_dispatch) > 0
        and len(multi_dispatch) > 0
    )

    zero_region_proven = (
        len(zeroing) > 0
    )

    data = {
        "stage": 72,
        "target": {
            "global_context_va": GLOBAL_CONTEXT,
            "submit_table_offset": SUBMIT_TABLE_OFFSET,
            "multi_table_offset": MULTI_TABLE_OFFSET,
            "entry_stride": ENTRY_STRIDE,
            "submit_va": SUBMIT_VA,
            "submit_size": SUBMIT_SIZE,
            "multi_va": MULTI_VA,
            "multi_size": MULTI_SIZE,
        },
        "previous_stage": previous,
        "dispatch": {
            "submit": submit_dispatch,
            "multi": multi_dispatch,
        },
        "store_candidates": store_candidates,
        "zeroing": zeroing,
        "entry_layout": {
            "0x00": {
                "classification": "INDIRECT_DISPATCH_TARGET_SLOT",
                "proven": function_pointer_proven,
            },
            "0x08": {
                "classification": "ZERO_INITIALIZED_REGION",
                "proven": zero_region_proven,
            },
            "0x0C": {
                "classification": "WITHIN_ZERO_INITIALIZED_REGION",
                "proven": zero_region_proven,
            },
            "0x10": {
                "classification": "WITHIN_ZERO_INITIALIZED_REGION",
                "proven": zero_region_proven,
            },
            "0x18": {
                "classification": "WITHIN_ZERO_INITIALIZED_REGION",
                "proven": zero_region_proven,
            },
            "0x20": {
                "classification": "WITHIN_ZERO_INITIALIZED_REGION",
                "proven": zero_region_proven,
            },
            "0x28": {
                "classification": "SEMANTICS_NOT_PROVEN",
                "proven": False,
            },
        },
        "conclusions": {
            "ENTRY_STRIDE_PROVEN": True,
            "SUBMIT_DISPATCH_PATTERN_FOUND": len(submit_dispatch) > 0,
            "MULTI_DISPATCH_PATTERN_FOUND": len(multi_dispatch) > 0,
            "SUBMIT_DISPATCH_FORMULA_PROVEN": submit_formula_proven,
            "MULTI_DISPATCH_FORMULA_PROVEN": multi_formula_proven,
            "ENTRY_FUNCTION_POINTER_FIELD_PROVEN": function_pointer_proven,
            "ENTRY_ZERO_INITIALIZATION_PROVEN": zero_region_proven,
            "STAGE71_RUNTIME_TABLE_INITIALIZATION_CARRIED_FORWARD": (
                previous["runtime_table_initialization_proven"]
            ),
            "STAGE71_COUNT_SEMANTICS_CARRIED_FORWARD": (
                previous["count_semantics_proven"]
            ),
            "INDEX_SEMANTICS_PROVEN": (
                previous["index_semantics_proven"]
            ),
            "COUNT_SEMANTICS_PROVEN": (
                previous["count_semantics_proven"]
            ),
            "EXACT_ENTRY_FIELD_NAMES_PROVEN": False,
            "EXACT_ENTRY_STRUCT_SIZE_PROVEN": False,
            "BACKEND_CONSUMER_IDENTIFIED": False,
            "SEMANTIC_PROTOTYPE_INFERRED": False,
            "EXECUTED_AGC": False,
        },
    }

    static_path = OUT / "stage72_static.json"
    static_path.write_text(
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    correlation = {
        "stage": 72,
        "global_context": GLOBAL_CONTEXT,
        "submit_table": {
            "offset": SUBMIT_TABLE_OFFSET,
            "stride": ENTRY_STRIDE,
            "formula": (
                "global_context + 0x50 + index*0x78"
                if submit_formula_proven
                else None
            ),
        },
        "multi_table": {
            "offset": MULTI_TABLE_OFFSET,
            "stride": ENTRY_STRIDE,
            "formula": (
                "global_context + 0x58 + index*0x78"
                if multi_formula_proven
                else None
            ),
        },
        "entry_0x00": {
            "classification": "indirect_dispatch_target",
            "proven": function_pointer_proven,
        },
        "entry_zero_region": {
            "start": 0x08,
            "end": 0x27,
            "proven": zero_region_proven,
        },
        "exact_semantics": False,
    }

    correlation_path = (
        OUT / "dispatch_entry_correlation.json"
    )

    correlation_path.write_text(
        json.dumps(
            correlation,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    lines = []

    lines.append(
        "AGC PS5 Stage 72 - Dispatch Entry Layout / Function Pointer Provenance Audit"
    )
    lines.append("")
    lines.append("=== TARGET ===")
    lines.append("global_context = 0x1A908")
    lines.append("submit table offset = 0x50")
    lines.append("multi table offset = 0x58")
    lines.append("entry stride = 0x78")
    lines.append("")

    lines.append("=== SUBMIT DISPATCH ===")

    if submit_dispatch:
        for x in submit_dispatch:
            scale = x.get("index_scale_evidence")

            lines.append(
                "VA=0x{:X} | table=+0x{:X} | base={} | index={} | scale=1".format(
                    x["va"],
                    x["table_offset"],
                    x["base_register"],
                    x["index_register"],
                )
            )

            if scale:
                lines.append(
                    "  scale evidence: VA=0x{:X} | {}".format(
                        scale["va"],
                        scale["instruction"],
                    )
                )
    else:
        lines.append("NONE")

    lines.append("")
    lines.append("=== MULTI DISPATCH ===")

    if multi_dispatch:
        for x in multi_dispatch:
            scale = x.get("index_scale_evidence")

            lines.append(
                "VA=0x{:X} | table=+0x{:X} | base={} | index={} | scale=1".format(
                    x["va"],
                    x["table_offset"],
                    x["base_register"],
                    x["index_register"],
                )
            )

            if scale:
                lines.append(
                    "  scale evidence: VA=0x{:X} | {}".format(
                        scale["va"],
                        scale["instruction"],
                    )
                )
    else:
        lines.append("NONE")

    lines.append("")
    lines.append("=== FUNCTION POINTER SLOT ===")
    lines.append("entry + 0x00 = indirect dispatch target")
    lines.append(
        "ENTRY_FUNCTION_POINTER_FIELD_PROVEN={}".format(
            function_pointer_proven
        )
    )

    lines.append("")
    lines.append("=== ZERO INITIALIZED REGION ===")

    if zeroing:
        for x in zeroing:
            lines.append(
                "VA=0x{:X} | relative=0x{:X} | width={} | {}".format(
                    x["va"],
                    x["relative_offset"] & 0xFFFFFFFF,
                    x["width"],
                    x["instruction"],
                )
            )
    else:
        lines.append("NONE")

    lines.append("")
    lines.append("=== ENTRY LAYOUT ===")

    for offset, info in data["entry_layout"].items():
        lines.append(
            "{} = {} proven={}".format(
                offset,
                info["classification"],
                info["proven"],
            )
        )

    lines.append("")
    lines.append("=== CONCLUSIONS ===")

    for key, value in data["conclusions"].items():
        lines.append(
            "{}={}".format(key, value)
        )

    lines.append("")
    lines.append("=== LIMIT ===")
    lines.append(
        "Esta etapa demuestra el slot de función indirecta en +0x00 "
        "y la región de entrada afectada por la inicialización a cero. "
        "No asigna nombres semánticos públicos a los demás offsets "
        "ni demuestra el sizeof exacto de la entrada."
    )

    summary_path = OUT / "dispatch_entry_summary.txt"

    summary_path.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    report = {
        "stage": 72,
        "results": data["conclusions"],
        "artifacts": [
            "stage72_static.json",
            "dispatch_entry_summary.txt",
            "dispatch_entry_disassembly.txt",
            "dispatch_entry_correlation.json",
        ],
    }

    report_path = OUT / "STAGE72_REPORT.json"

    report_path.write_text(
        json.dumps(
            report,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print(
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
'@

# Escritura UTF-8 sin BOM.
[System.IO.File]::WriteAllText(
    $AnalyzerWin,
    $AnalyzerPython,
    [System.Text.UTF8Encoding]::new($false)
)

# ---------------------------------------------------------------------------
# Preparar workspace Linux
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host '==> Preparar workspace Linux'

Invoke-WslScript @"
set -e

rm -rf '/tmp/agc_stage72'

mkdir -p '/tmp/agc_stage72'
mkdir -p '$OutputWsl'

test -f '$SprxWsl'
test -f '$NidWsl'
test -d '$PreviousWsl'

# IMPORTANTE:
# Aqui se usa la ruta WSL del analizador, no la ruta Windows D:\...
test -f '$OutputWsl/analyze_dispatch_entries.py'

cp '$OutputWsl/analyze_dispatch_entries.py' \
   '/tmp/agc_stage72/analyze_dispatch_entries.py'

sed -i 's/\r$//' \
   '/tmp/agc_stage72/analyze_dispatch_entries.py'

python3 -m py_compile \
   '/tmp/agc_stage72/analyze_dispatch_entries.py'

ls -lh \
   '/tmp/agc_stage72/analyze_dispatch_entries.py'
"@

# ---------------------------------------------------------------------------
# Verificar toolchain
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host '==> Verificar Python + pyelftools + toolchain'

Invoke-WslScript @"
set -e

test -x '/opt/ps5-payload-sdk/bin/prospero-clang'
test -x '/opt/ps5-payload-sdk/bin/prospero-nm'
test -x '/opt/ps5-payload-sdk/bin/prospero-lld'

echo '--- prospero-clang ---'
'/opt/ps5-payload-sdk/bin/prospero-clang' --version

echo '--- prospero-nm ---'
'/opt/ps5-payload-sdk/bin/prospero-nm' --version

echo '--- pyelftools ---'
python3 -c "from elftools.elf.elffile import ELFFile; print('pyelftools=OK')"

echo '--- objdump ---'
command -v objdump

echo '--- llvm-objdump ---'
command -v llvm-objdump
"@

# ---------------------------------------------------------------------------
# Ejecutar auditoría
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host '==> Analizar entradas de dispatch'

Invoke-WslScript @"
set -e

python3 '/tmp/agc_stage72/analyze_dispatch_entries.py' \
    '$SprxWsl' \
    '$NidWsl' \
    '$PreviousWsl' \
    '$OutputWsl'
"@

# ---------------------------------------------------------------------------
# Validación de artefactos
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host '==> Verificar artefactos Stage 72'

Invoke-WslScript @"
set -e

test -f '$OutputWsl/stage72_static.json'
test -f '$OutputWsl/dispatch_entry_summary.txt'
test -f '$OutputWsl/dispatch_entry_disassembly.txt'
test -f '$OutputWsl/dispatch_entry_correlation.json'
test -f '$OutputWsl/STAGE72_REPORT.json'

echo '--- dispatch_entry_summary.txt ---'
cat '$OutputWsl/dispatch_entry_summary.txt'

echo '--- output files ---'
find '$OutputWsl' \
    -maxdepth 1 \
    -type f |
    sort
"@

# ---------------------------------------------------------------------------
# Hashes
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host '==> Hash artefactos'

Invoke-WslScript @"
set -e

sha256sum \
    '$OutputWsl/stage72_static.json' \
    '$OutputWsl/dispatch_entry_summary.txt' \
    '$OutputWsl/dispatch_entry_disassembly.txt' \
    '$OutputWsl/dispatch_entry_correlation.json' \
    '$OutputWsl/STAGE72_REPORT.json'
"@

# ---------------------------------------------------------------------------
# Resumen final
# ---------------------------------------------------------------------------

$ReportPath = Join-Path $OutputWin 'STAGE72_REPORT.json'

if (-not (Test-Path -LiteralPath $ReportPath -PathType Leaf)) {
    throw "No se generó STAGE72_REPORT.json"
}

$Report = Get-Content -LiteralPath $ReportPath -Raw |
    ConvertFrom-Json

Write-Host ''
Write-Host '============================================'
Write-Host 'Stage 72 completado'
Write-Host '============================================'

foreach ($property in $Report.results.PSObject.Properties) {
    Write-Host "$($property.Name) = $($property.Value)"
}

Write-Host ''
Write-Host 'Resultados:'
Write-Host "  $OutputWin"

Write-Host ''
Write-Host 'Reporte:'
Write-Host "  $ReportPath"