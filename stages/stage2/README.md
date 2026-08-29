# AGC PS5 — Stage 2: ABI inventory / submission boundary

This stage supersedes Stage 1's symbol inventory.

## Important correction

FW 3.20 exposes both:

- `sceAgcDriverAgrSubmitDcb` — NID `AhGvpITrf4M`
- `sceAgcDriverSubmitDcb` — NID `UglJIZjGssM`

They are distinct exports and must not be treated as aliases.

The 3.20 export table also confirms that `w1KFAHVqpaU` is `sceAgcCbBranch`, not a submit entry.

## What this stage does

It resolves the subset of AGC/AGC-driver symbols needed to build the first DCB milestone, while still refusing to call Sony functions through guessed prototypes.

The following are now part of the inventory:

- `sceAgcCreateShader`
- `sceAgcDcbWaitUntilSafeForRendering`
- `sceAgcDcbSetFlip`
- `sceAgcDcbSetIndexBuffer`
- `sceAgcDcbSetIndexCount`
- `sceAgcDcbDrawIndex`
- `sceAgcDcbDrawIndexGetSize`
- `sceAgcDcbSetIndexSize`
- `sceAgcDcbNop`
- `sceAgcDcbNopGetSize`
- `sceAgcDriverGetReservedDmemForAgc`
- `sceAgcDriverNotifyDefaultStates`
- `sceAgcDriverSetFlip`
- `sceAgcDriverSubmitDcb`
- `sceAgcDriverAgrSubmitDcb`
- `sceAgcDriverSubmitMultiDcbs`
- `sceAgcDriverWaitUntilSafeForRendering`

## Deliberately not implemented yet

`sceAgcInit`, `sceAgcGetRegisterDefaults2`, and `sceAgcLinkShaders` are listed semantically in the design but their exact FW-3.20 export NIDs have not yet been extracted into this standalone stage. Do not substitute guessed NIDs.

## Next stage

The next task is to recover the exact callable prototypes and structures from independent clean-room implementations / public RE evidence, then add typed wrappers. Only after that should `agc_ps5_gpu_init()` issue its first real AGC call.
