# AGC PS5 Stage 31 — Vulkan offscreen resource boundary

Estado: PARTIAL / VERIFIED

## Qué se ha ejecutado realmente

Con `VK_DRIVER_FILES=/usr/lib/chromium/vk_swiftshader_icd.json`:

- `vkCreateInstance` → PASS
- physical device discovery → PASS
- graphics queue family discovery → PASS
- `vkCreateDevice` → PASS
- queue retrieval → PASS
- `vkCreateImage` para `VK_FORMAT_R8G8B8A8_UNORM` 64x64 → PASS (`VK_SUCCESS`)
- `vkGetImageMemoryRequirements` → PASS
- `vkAllocateMemory` → PASS (`VK_SUCCESS`)
- `vkBindImageMemory` → PASS (`VK_SUCCESS`)

## Bloqueos intencionados

- `VkImageView`: NO se declara PASS. El probe con structs Vulkan definidos manualmente provoca SIGILL en la ruta `vkCreateImageView`; esto se considera un problema de ABI de los bindings del probe, no una validación del ICD.
- SPIR-V/shader modules: BLOCKED. El entorno no contiene `glslc`, `glslangValidator`, `shaderc` ni headers/toolchain equivalente. No se acepta SPIR-V artesanal como evidencia del pipeline.
- Render pass / pipeline / draw / readback: BLOCKED hasta disponer de bindings Vulkan fiables y un compilador SPIR-V reproducible.

## Conclusión

El ICD SwiftShader ya es funcional y la frontera real de recursos Vulkan está comprobada. La siguiente fase debe introducir una representación fiable de los headers Vulkan o generar bindings desde el SDK antes de continuar con ImageView/Pipeline.
