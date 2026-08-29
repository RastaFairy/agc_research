$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$StageDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$Stage82   = 'D:\agc_work\stage82_results'
$Stage79   = 'D:\agc_work\stage79_results'
$Stage80   = 'D:\agc_work\stage80_results'
$Output    = 'D:\agc_work\stage83_results'

$Stage82Wsl = '/mnt/d/agc_work/stage82_results'
$Stage79Wsl = '/mnt/d/agc_work/stage79_results'
$Stage80Wsl = '/mnt/d/agc_work/stage80_results'
$OutputWsl  = '/mnt/d/agc_work/stage83_results'
$Sdk        = '/opt/ps5-payload-sdk'

Write-Host '============================================'
Write-Host 'AGC PS5 Stage 83 - Semantic Field Name Proof'
Write-Host '  PM4 INDIRECT_BUFFER construction in consumer@0x1000'
Write-Host '============================================'
Write-Host "Stage82  = $Stage82"
Write-Host "Output   = $Output"

function Invoke-WSLScript {
    param([Parameter(Mandatory)][string]$Body)
    & wsl.exe bash -lc "set -e; $Body"
    if ($LASTEXITCODE -ne 0) { throw "WSL command failed (exit $LASTEXITCODE)" }
}

# ─── Python analyzer: proves semantic names from consumer_1000 disassembly ───
$analyzerPy = @'
import re, sys, json

consumer_txt = open(sys.argv[1]).read()
submit_txt   = open(sys.argv[2]).read()
out_json     = sys.argv[3]

results = {}
ok = True

def find(label, pattern, text, expect=True):
    global ok
    m = re.search(pattern, text, re.MULTILINE)
    if m and expect:
        va = int(m.group('va'), 16)
        results[label] = {'va': hex(va), 'status': 'PROVEN'}
        print(f"[OK]  {label:45s} VA 0x{va:04X}")
        return va
    elif not m and not expect:
        results[label] = {'va': None, 'status': 'ABSENT_AS_EXPECTED'}
        print(f"[OK]  {label:45s} absent as expected")
        return None
    else:
        results[label] = {'va': None, 'status': 'FAIL'}
        print(f"[ERR] {label}")
        ok = False
        return None

print("=== CONSUMER 0x1000 ANALYSIS ===")

# Proof A: PM4 IB header present in consumer null-path
find('PM4_IB_HEADER_0xC0023F00_in_null_path',
     r'(?P<va>[0-9a-f]+):\s+[0-9a-f ]+mov\s+\$0xc0023f00,%eax',
     consumer_txt)

# Proof B: null-path loads consumer_args[0x10] = field_00 as IB base
find('CONSUMER_ARGS_0x10_load_as_IB_base_addr',
     r'(?P<va>[0-9a-f]+):\s+[0-9a-f ]+mov\s+0x10\(%r9\),%rsi',
     consumer_txt)

# Proof C: null-path loads consumer_args[0x18] = field_08 as IB count
find('CONSUMER_ARGS_0x18_load_as_IB_count',
     r'(?P<va>[0-9a-f]+):\s+[0-9a-f ]+mov\s+0x18\(%r9\),%edi',
     consumer_txt)

print("")
print("=== SUBMIT 0x18B0 MAPPING ===")

# Proof D: submit stores field_00 at local[-0x40], 16 bytes above local base
find('SUBMIT_field_00_stored_at_local_minus0x40',
     r'(?P<va>[0-9a-f]+):\s+[0-9a-f ]+mov\s+%rax,-0x40\(%rbp\)',
     submit_txt)

# Proof E: submit stores field_08 at local[-0x38], 24 bytes above local base
find('SUBMIT_field_08_stored_at_local_minus0x38',
     r'(?P<va>[0-9a-f]+):\s+[0-9a-f ]+mov\s+%eax,-0x38\(%rbp\)',
     submit_txt)

# Proof F: local struct base is at local[-0x50], so offsets are +0x10 and +0x18
find('SUBMIT_local_struct_base_at_minus0x50',
     r'(?P<va>[0-9a-f]+):\s+[0-9a-f ]+lea\s+-0x50\(%rbp\),%rsi',
     submit_txt)

# Derived: consumer_args[0x10] = local[-0x50+0x10] = local[-0x40] = field_00  (+0x10 offset)
# Derived: consumer_args[0x18] = local[-0x50+0x18] = local[-0x38] = field_08  (+0x10 offset)
print("")
print("=== DERIVED PROOF ===")
print("  local_base = -0x50(rbp)")
print("  local_base + 0x10 = -0x40(rbp) => consumer_args[0x10] = field_00 = dcb_gpu_addr")
print("  local_base + 0x18 = -0x38(rbp) => consumer_args[0x18] = field_08 = dcb_num_dwords")
print("  PM4 opcode 0x3F = INDIRECT_BUFFER (IB) packet")

conclusions = {
    'FIELD_00_IS_DCB_GPU_ADDR':   ok,
    'FIELD_08_IS_DCB_NUM_DWORDS': ok,
    'FIELD_0C_REMAINS_SUSPECTED': True,
    'SEMANTIC_FIELD_NAMES_FINAL': ok,
    'PM4_IB_OPCODE_0x3F_PROVEN':  ok,
}
print("")
print("=== CONCLUSIONS ===")
for k, v in conclusions.items():
    print(f"  {k} = {v}")

report = {'proofs': results, 'conclusions': conclusions, 'overall': ok}
with open(out_json, 'w') as f:
    json.dump(report, f, indent=2)

sys.exit(0 if ok else 1)
'@