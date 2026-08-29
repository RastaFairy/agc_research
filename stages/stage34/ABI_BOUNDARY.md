# Native ABI boundary

Known from the project evidence:

- libSceAgc / libSceAgcDriver are resolved dynamically through PS5 payload SDK stubs.
- The project has frozen NIDs for `sceAgcCreateShader`, DCB helpers, and `sceAgcDriverSubmitDcb` / `sceAgcDriverAgrSubmitDcb`.
- The generated 3.20 stubs provide symbol resolution, not the original C prototypes.

Therefore Stage 34 deliberately exposes an internal operations vtable instead of declaring speculative Sony signatures.

The real implementation can later replace `agc_ps5_native_dryrun_ops()` with a PS5 implementation once each operation's ABI is verified.
