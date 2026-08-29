# AGC PS5 Stage 39

Objetivo: demostrar que `sceAgcDriverSubmitDcb` puede resolverse mediante el stub `libSceAgcDriver.o` y el linker/toolchain Prospero, sin ejecutar la función.

El stage:
- compila un objeto mínimo `stage39_probe.o` para `x86_64-sie-ps5`;
- enlaza con `libSceAgcDriver.o`;
- inspecciona símbolos del ELF resultante;
- NO invoca `sceAgcDriverSubmitDcb`.

Se ejecuta desde PowerShell llamando a WSL2.
