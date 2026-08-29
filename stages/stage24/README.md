# AGC PS5 Stage 24 — Minimal AGC profile for RetroArch

Objetivo:
- detener temporalmente el reversing del callback `entry+0x48`;
- extraer de SharpEmu y KytyPlus el subconjunto mínimo de semántica AGC necesario para un primer renderer de RetroArch;
- mantener separadas las capas `guest AGC -> estado GPU -> backend/presentación`;
- no inventar ABI de Sony ni asumir que Vulkan puede ejecutarse nativamente como backend del PS5 payload.

Estado de las fuentes:
- SharpEmu: `AgcExports.cs` contiene decodificación DCB/ACB, registros GFX10, draws, writes, waits, DMA, eventos, shaders y rutas de presentación.
- KytyPlus: arquitectura declarada `guest_gpu` -> `shader/recompiler` -> `host_gpu`, con Vulkan 1.3 como backend del host.
- Proyecto propio: el SPRX real sigue siendo la fuente para ABI/NID PS5 cuando sea necesario.

Decisión de ingeniería:
La primera prueba no necesita una implementación completa de AGC. Debe limitarse a un fullscreen blit/triangle y a la presentación del framebuffer. El objetivo es validar el dueño del estado GPU y la sincronización antes de integrar shaders de RetroArch.
