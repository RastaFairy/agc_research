# Stage 29 — Offscreen RGBA8 contract

## Resource
- formato lógico: RGBA8 UNORM
- uso: color attachment + transfer source para readback
- dimensión de la prueba: 64x64
- una sola muestra

## Pipeline
1. Vulkan instance
2. physical device
3. graphics queue family
4. logical device + graphics queue
5. image RGBA8 UNORM
6. device-local memory
7. image view
8. render pass con un color attachment
9. graphics pipeline con vertex+fragment SPIR-V
10. framebuffer
11. command pool/buffer
12. clear + draw
13. image barrier a TRANSFER_SRC
14. buffer de staging
15. copy image -> buffer
16. map/readback

## Decisión
No se incluye un SPIR-V inventado. El pipeline pasa a `SHADER_UNAVAILABLE` hasta disponer de un compilador o binario SPIR-V reproducible.
