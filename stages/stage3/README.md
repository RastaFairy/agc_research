# AGC PS5 Stage 3 — DCB builder

This stage does **not** claim to submit to the PS5 GPU. It freezes the part of the AGC command-buffer representation that is currently supported by the public reverse-engineering references.

## Sources used

- DNNDHH/PS5-3.20_Libs: real `libSceAgc` / `libSceAgcDriver` exports for firmware 3.20.
- Kyty/prosper: reconstructed Gen5 DCB layout and PM4 packet encoding.
- prosper `hle_agc.cpp`: current independent implementation of the same reverse-engineered DCB frontend.

## Reconstructed DCB layout

The ring is represented as:

- `bottom` at offset `0x00`
- `top` at `0x08`
- `cursor_up` at `0x10`
- `cursor_down` at `0x18`
- callback at `0x20`
- `user_data` at `0x28`
- `reserved_dw` at `0x30`

The builder intentionally omits the callback semantics for now; this stage is only for deterministic packet construction and size validation.

## Packet information currently frozen

From prosper's current Gen5 frontend:

- `SetIndexBuffer`: 3 dwords
- `SetIndexCount`: 2 dwords
- `DrawIndex`: 7 dwords
- `DrawIndexOffset`: 3 dwords
- PM4 custom operations are encoded in an IT_NOP packet.

The PM4 header formula is the one used by the current reference implementation.

## Important limitation

The exact C prototypes of Sony's `sceAgc*` functions are still not claimed here. The generated PS5-3.20 stubs themselves are naked NID-resolving jumps and therefore do not encode the original source-level parameter types. The next stage must map the ABI calls separately.

## Self-test

On a normal host:

```sh
gcc -std=c11 -Wall -Wextra -Werror -O2 agc_ps5_dcb.c test_dcb.c -o test_dcb
./test_dcb
```

Expected first line:

`AGC DCB builder self-test: PASS`
