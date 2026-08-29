# AGC PS5 Stage 40

Objetivo: producir un ELF PS5 completo usando el toolchain oficial instalado en `/opt/ps5-payload-sdk` y el objeto `libSceAgcDriver.o` generado desde `libSceAgcDriver.sprx` 3.20.

No se ejecuta `sceAgcDriverSubmitDcb`.

El enlace usa la receta oficial `toolchain/prospero.mk`; el CI del SDK compila sus muestras con ese mismo toolchain y el README documenta `PS5_PAYLOAD_SDK` + `make -C samples/...`. Esto se usa aquí como referencia de integración. 

Uso en Windows 11:

```powershell
cd D:\agc_ps5_stage40
.\stage40_link.ps1
```

Entradas esperadas:

- `D:\agc_ps5_stage40\stage40_probe.c`
- `D:\agc_work\sce_stubs\libSceAgcDriver.o`
- WSL2 Ubuntu-24.04
- `/opt/ps5-payload-sdk`

Resultado esperado:

```text
STAGE40_ELF_BUILT = TRUE
SUBMIT_DCB_IN_ELF = TRUE
EXECUTED_SUBMIT_DCB = NO
```
