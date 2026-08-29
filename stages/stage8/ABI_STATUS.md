# ABI status

| Symbol | NID | Status | Allowed now |
|---|---|---|---|
| sceAgcInit | kW3GLb7QfPg | export/NID verified | inventory only |
| sceAgcGetRegisterDefaults2 | 2JtWUUiYBXs | export/NID verified | inventory only |
| sceAgcCreateShader | f3dg2CSgRKY | export/NID verified | inventory only |
| sceAgcLinkShaders | MqAdbRMdNz4 | export/NID verified | inventory only |
| sceAgcDriverGetReservedDmemForAgc | Um-jkyDy9rI | export/NID verified | inventory only |
| sceAgcDriverInitResourceRegistration | F0Y42t-3e18 | export/NID verified | inventory only |
| sceAgcDriverNotifyDefaultStates | nR6xhiFsOoc | export/NID verified | inventory only |
| sceAgcDriverSubmitDcb | UglJIZjGssM | export/NID verified | not called until exact C ABI is verified |
| sceAgcDriverAgrSubmitDcb | AhGvpITrf4M | export/NID verified | not called until exact C ABI is verified |
| sceAgcCbBranch | w1KFAHVqpaU | export/NID verified | treat as branch, not submit |

## Next evidence target

Need one of:
1. a typed AGC header/prototype from a matching 3.20 development environment;
2. disassembly/call-site evidence showing argument registers/stack layout for `sceAgcInit` and `sceAgcGetRegisterDefaults2`;
3. a captured real call from an executable running on matching firmware.

Until then, source code should keep these calls behind an explicit experimental boundary.
