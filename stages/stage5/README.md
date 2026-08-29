# AGC PS5 Stage 5 — real stub bridge boundary

This stage connects the reconstructed DCB submit packet to the PS5 Payload SDK's generated SCE-stub model.

## Evidence

The official ps5-payload-dev SDK documents that decrypted SPRX libraries can be turned into SDK stubs with `make -C sce_stubs stubs`.
The generated stubs in PS5-3.20_Libs use `sprx_dlopen`/`sprx_dlsym` and export a callable symbol with a generated trampoline.

For FW 3.20, `libSceAgcDriver.c` resolves:

- `sceAgcDriverSubmitDcb`
- NID `UglJIZjGssM`
- module `libSceAgcDriver`

This stage uses that real symbol/NID, but the function prototype remains explicitly marked as a reverse-engineered ABI model. No Sony public header is claimed.

## Build modes

Host build:

```sh
make
./test_driver
```

PS5 build with generated stubs:

```sh
make CFLAGS="... -DAGC_PS5_SCE_STUBS ..."
```

In that mode `agc_ps5_resolve_submit_dcb()` binds to the generated `sceAgcDriverSubmitDcb` symbol. The caller still goes through the 16-byte packet structure reconstructed from the independent `prosper` implementation.

## Important

This does NOT yet prove that a PS5 payload can successfully execute the submitted DCB. It proves that the software layers now line up:

```text
DCB builder
  -> 16-byte SubmitDcb packet
  -> generated SCE stub
  -> sceAgcDriverSubmitDcb
```

The next unresolved blocker is GPU/runtime initialization and a DCB that reaches the real GPU command processor with valid AGC state.
