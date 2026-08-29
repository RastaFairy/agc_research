# AGC PS5 Stage 41 — SubmitDcb ABI Audit

This stage is static only.

It cross-checks `UglJIZjGssM` / `sceAgcDriverSubmitDcb` across:

1. the 3.20 `libSceAgcDriver.sprx` dynamic symbol table;
2. the SDK `aerolib.csv` mapping;
3. the generated `libSceAgcDriver.c` stub.

It deliberately does **not** infer a C prototype, execute `sceAgcDriverSubmitDcb`, or modify the Sony SPRX.

Expected result:

```text
SUBMIT_DCB_IDENTITY = PASS
ABI_PROTOTYPE_INFERRED = NO
EXECUTED_SUBMIT_DCB = NO
```

Run from PowerShell 7:

```powershell
cd D:\agc_ps5_stage41
.\stage41_abi_audit.ps1
```
