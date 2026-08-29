# AGC PS5 Stage 32 — canonical Vulkan ABI probe

Objetivo:
- eliminar los typedefs C incompletos que provocaron SIGILL en Stage 31;
- usar `ctypes` con layouts que siguen la especificación Vulkan para `VkImageCreateInfo`, `VkImageViewCreateInfo`, `VkComponentMapping` y `VkImageSubresourceRange`;
- ejecutar el probe contra el ICD SwiftShader ya validado;
- demostrar `VkImage -> allocation -> bind -> VkImageView` sin shader ni pipeline.

Resultado esperado:
- `vkCreateInstance = 0`
- `vkCreateDevice = 0`
- `vkCreateImage = 0`
- `vkAllocateMemory = 0`
- `vkBindImageMemory = 0`
- `vkCreateImageView = 0`

No se mezclan todavía AGC, SPIR-V ni VideoOut.
