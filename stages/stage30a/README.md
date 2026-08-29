# AGC PS5 Stage 30A — Vulkan ICD candidate resolution

Objetivo: resolver un ICD Vulkan funcional antes de Stage 31.

## Resultado

El candidato que sobrevive es **SwiftShader** incluido en Chromium:

- Manifest: `/usr/lib/chromium/vk_swiftshader_icd.json`
- Biblioteca: `/usr/lib/chromium/libvk_swiftshader.so`
- Selección reproducible: `VK_DRIVER_FILES=/usr/lib/chromium/vk_swiftshader_icd.json`

Probe real:

- `vkCreateInstance` = `VK_SUCCESS`
- physical devices = 1
- device = `SwiftShader Device (Subzero)`
- Vulkan API = `1.3.0`
- vendor = `0x1ae0`
- device type = `CPU`
- queue 0 = `GRAPHICS | COMPUTE | TRANSFER`
- RGBA8_UNORM (format 37) soporta uso de color attachment + transfer
- `vkCreateDevice` = `VK_SUCCESS`
- `vkGetDeviceQueue` = PASS

## Candidatos descartados

1. Mesa/RADV/ANV/Lavapipe del sistema: no hay ICD manifest instalado en las rutas estándar y `mesa-vulkan-drivers` no está instalado.
2. NVIDIA/AMD/Intel hardware ICD: no hay dispositivo `/dev/dri` visible en el entorno.
3. MoltenVK: es una ruta para macOS; el entorno actual es Linux/x86-64 y no hay MoltenVK instalada.
4. “Vulkan nativo de PS5”: las fuentes revisadas de SharpEmu/KytyPlus describen Vulkan como backend del **host** del emulador, no como un ICD público para ejecutar sobre PS5. No se debe inferir que PS5 exponga una ICD Vulkan pública.

## Importante

SwiftShader es un **ICD host de validación**, no una solución para convertir la GPU PS5 en Vulkan.
Su función en el proyecto es permitir validar Stage 31 (imagen, pipeline, SPIR-V, draw y readback) sin depender de una GPU física en el entorno de desarrollo.
