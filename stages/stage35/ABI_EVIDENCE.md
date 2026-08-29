# ABI evidence matrix

| Elemento | Estado | Evidencia |
|---|---|---|
| `sceAgcDriverSubmitDcb` | CONFIRMED NAME/NID | PS5-3.20_Libs: `UglJIZjGssM` |
| `sceAgcDriverAgrSubmitDcb` | CONFIRMED NAME/NID | PS5-3.20_Libs: `AhGvpITrf4M` |
| `sceAgcCbBranch` | CONFIRMED name/NID | `w1KFAHVqpaU`, prosper #2173 |
| Submit path reaches command processor | CONFIRMED in prosper HLE | prosper v0.1 milestone |
| DCB is supplied as address + dword count packet | STRONG/experimental | previous stages + prosper model |
| Native C prototype on PS5 | NOT VERIFIED | no typed Sony header/call-site in supplied evidence |
| Calling convention for direct native invocation | NOT VERIFIED | keep disabled |
| 16-byte packet layout | EXPERIMENTAL | retained for compatibility with previous stage |
