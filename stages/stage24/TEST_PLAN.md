# Stage 24 test plan

## Test 1 — Clear/present

- un color target
- ningún shader de textura
- write de estado mínimo
- clear o draw de triángulo fullscreen
- present

## Test 2 — Solid fullscreen triangle

- vertex shader mínimo
- pixel shader mínimo
- draw index auto
- una llamada de submit
- verificar checksum del framebuffer final

## Test 3 — RetroArch framebuffer upload

- framebuffer CPU RGBA8
- `WRITE_DATA`/ruta de upload mínima
- fullscreen draw
- present

Criterio de salida de Stage 24:
- tener un trace AGC mínimo reproducible;
- tener una tabla de opcodes/estado suficiente para construir el backend experimental;
- no ejecutar todavía las firmas reconstruidas de `sceAgcInit`/`SubmitDcb`.
