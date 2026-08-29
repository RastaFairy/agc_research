# AGC PS5 stage 1

This stage adds an ABI-discovery layer for the PS5 FW 3.20 AGC environment.

It deliberately does **not** call `sceAgc*` functions yet. The generated
`PS5-3.20_Libs` stubs give us the exported symbol names and NIDs, but not the
original Sony C prototypes. Calling an AGC function with a guessed prototype
would turn the current project back into the speculative approach we are
trying to eliminate.

Resolved first-milestone symbols:

- sceAgcCreateShader
- sceAgcDcbWaitUntilSafeForRendering
- sceAgcDcbSetFlip
- sceAgcDcbSetIndexBuffer
- sceAgcDcbSetIndexCount
- sceAgcDcbDrawIndex
- sceAgcDriverAgrSubmitDcb

Target ABI: PS5 FW 3.20, matching DNNDHH/PS5-3.20_Libs.

Next milestone:

1. recover exact prototypes/structures for the above symbols;
2. add typed wrappers in `agc_ps5_abi_call.h`;
3. allocate/initialize DCB memory;
4. emit a wait-safe + render state + draw + flip sequence;
5. submit the DCB with `sceAgcDriverAgrSubmitDcb`;
6. validate a triangle before integrating RetroArch frame upload.
