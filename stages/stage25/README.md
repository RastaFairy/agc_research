# AGC PS5 Stage 25 — P0 decoder + IR

Stage 25 implements the P0 profile from Stage 24 as a host-only decoder.

## Scope

Supported Type-3 PM4 opcodes:

- `INDEX_BASE` 0x26
- `DRAW_INDEX` 0x2B
- `DRAW_INDEX_AUTO` 0x2D
- `WRITE_DATA` 0x37
- `WAIT_REG_MEM` 0x3C
- `EVENT_WRITE` 0x46
- `RELEASE_MEM` 0x49
- `SET_CONTEXT_REG` 0x69
- `SET_SH_REG` 0x76
- `SET_UCONFIG_REG` 0x79

Anything outside this set fails closed with a byte/dword offset and opcode.

## IR boundary

The decoder produces only five semantic classes:

- `SetReg`
- `Draw`
- `WriteData`
- `Sync`
- `Present`

`Present` is **not** claimed to be a PM4 opcode. It is a host-side semantic boundary added by the VideoOut/presentation layer after the DCB has been decoded. This prevents inventing a Sony flip opcode while preserving the IR shape needed by the renderer.

## Design rule

This stage does not contain Sony C prototypes and does not embed KytyPlus/SharpEmu code. It uses their semantics as reference material only. KytyPlus keeps Prospero guest GPU processing separate from the host Vulkan backend, while the project targets Vulkan 1.3 on the host. The same separation is maintained here: decode first, execute later.

## Build

```sh
make
./test_decoder
```
