# AGC PS5 Stage 27 — Vulkan bootstrap adapter

Stage 27 mantiene exactamente la IR de Stage 25/26 y añade una frontera de backend Vulkan.

## Validación

- Compilación C host: requerida.
- Carga dinámica de `libvulkan.so.1`: requerida y verificada en este entorno.
- `vkGetInstanceProcAddr`: requerido y verificado.
- Creación de `VkInstance`: intentada cuando el entorno ofrece un ICD funcional.
- Enumeración de GPUs: intentada después de crear la instancia.

Este entorno tiene el loader (`libvulkan.so.1`) pero no un ICD funcional accesible; por eso `vkCreateInstance` devuelve `VK_ERROR_INCOMPATIBLE_DRIVER (-9)`. Se registra como limitación del entorno y no como éxito de un renderer Vulkan.

No se inventa ABI Sony y todavía no se implementan pipeline/render pass/present.
