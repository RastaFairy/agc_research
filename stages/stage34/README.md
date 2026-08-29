# AGC PS5 Stage 34 — Native AGC / RetroArch bridge

Objetivo: volver al camino final del proyecto:

RetroArch -> video_agc_ps5.c -> native AGC backend -> VideoOut

La IR P0 de Stage 25 se conserva como referencia semántica, pero esta etapa no usa Vulkan host para ejecutar el renderer final.

## Qué sí implementa

- frontera interna `video_agc_ps5 -> agc_ps5_native_backend`;
- inventario de operaciones nativas necesarias para P0;
- separación estricta entre ABI Sony y API interna del proyecto;
- puente de framebuffer RetroArch a un contrato AGC de alto nivel;
- modo `dry-run` host que registra la secuencia sin llamar funciones Sony.

## Qué NO implementa todavía

- prototipos C inventados para `sceAgcInit`, `sceAgcCreateShader`, etc.;
- creación real de recursos AGC;
- creación real de shaders AGC;
- llamada real a `sceAgcDriverSubmitDcb`;
- rasterización PS5.

La razón es que los stubs dinámicos de 3.20 proporcionan nombres/NID/resolución, pero no las firmas C originales; esa frontera se mantiene deliberadamente.

## Secuencia P0

init
 -> AGC ABI resolve
 -> VideoOut ready
 -> begin frame
 -> upload framebuffer resource
 -> fullscreen draw
 -> submit
 -> flip/present

La operación `present` pertenece al puente VideoOut, no se etiqueta como opcode PM4.
