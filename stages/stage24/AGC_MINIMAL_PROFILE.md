# AGC Minimal Profile

## P0 — imprescindible para la primera prueba

| Grupo | Elementos | Razón |
|---|---|---|
| Packet/control | `SET_CONTEXT_REG`, `SET_SH_REG`, `SET_UCONFIG_REG` | Programar estado de pipeline y recursos desde el stream |
| Draw | `INDEX_BASE`, `INDEX_COUNT`, `DRAW_INDEX_AUTO` / draw index equivalente | Permitir fullscreen triangle/quad sin depender del path completo de indirect draws |
| Data upload | `WRITE_DATA` | Subir pequeños bloques/constantes y validar el camino CPU→GPU |
| Present/sync | `EVENT_WRITE`, `RELEASE_MEM`, `WAIT_REG_MEM`, `FLIP`/equivalente | Hacer visible la relación submit→GPU→presentación |
| Shader | `CreateShader` + estado mínimo de VS/PS | Necesario para un triangle/fullscreen blit real |
| Render target | `CB_COLOR0_*` + viewport/scissor básicos | Crear un único target RGBA8 para la prueba |

## P1 — inmediatamente después

`DRAW_INDEX_INDIRECT`, `DRAW_INDIRECT`, `SET_BASE`, `INDIRECT_BUFFER`, `DMA_DATA`, `ACQUIRE_MEM`, `RELEASE_MEM` completo, múltiples color targets, texture descriptors y shader resource tables.

## P2 — no bloquear el primer framebuffer

Compute (`DISPATCH_DIRECT/INDIRECT`), predication, depth/stencil completo, geometry/tessellation, NGG, múltiples colas/engines y comandos de depuración.

## Decisión sobre dispatch

Se deja fuera de P0. SharpEmu soporta también `DISPATCH_DIRECT/INDIRECT`, pero el objetivo inmediato es validar un pipeline gráfico mínimo de presentación. Añadir compute antes de tener un draw estable aumenta el espacio de estados sin aportar una prueba mínima necesaria.

## Decisión sobre shader

No se debe copiar el backend Vulkan de KytyPlus al payload. KytyPlus es un emulador y su Vulkan es el host backend. Se aprovecha su separación conceptual y la semántica de guest GPU/recompiler como referencia.
