from pathlib import Path

root = Path(__file__).parent
# Stage 14 dispatcher disassembly is retained as the primary dispatcher source.
dispatch = (Path('/mnt/data/agc_ps5_stage14') / 'dispatcher_1800_1a30.asm').read_text()
reg = (root / 'callback_registration_6240_6410.asm').read_text()
assert '4d 8d 6f 48' in dispatch
assert 'ff d1' in dispatch
assert '4a 89 54 38 48' in reg
assert '4a 8d 14 3b' in (root / 'callback_registration_5f80_6245.asm').read_text()
print('Stage 15 callback-slot provenance checks: PASS')
print('Submit dispatcher enters the logical +0x48 slot.')
print('Registration writes +0x48 from a pointer derived as RBX + R15.')
print('Pointer target remains unresolved by design.')
