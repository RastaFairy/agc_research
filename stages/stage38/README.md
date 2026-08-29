# AGC PS5 Stage 38 — compile generated SCE stubs on Windows 11

Stage 37 demonstrated that `genstub.py` generated:

- `libSceAgc.c`
- `libSceAgcDriver.c`
- `libSceAgcVsh.c`

and that the generated driver stub maps `UglJIZjGssM` to `sceAgcDriverSubmitDcb`.

Stage 38 only compiles those generated C stubs to PS5-targeted object files using the SDK's Windows Prospero wrapper. It does NOT link a payload and does NOT invoke any SCE function.

Usage:

```powershell
cd D:\agc_work\sce_stubs
powershell -ExecutionPolicy Bypass -File .\stage38_compile_stubs.ps1
```

Expected outputs are under:

`D:\agc_work\sce_stubs\stage38_results\`
