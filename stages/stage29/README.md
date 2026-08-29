# AGC PS5 Stage 29 — Vulkan RGBA8 offscreen contract

Objetivo:
- fijar la frontera exacta para un recurso RGBA8 offscreen;
- preparar shader SPIR-V y render pass/pipeline sin inventar binarios de shader;
- probar dinámicamente el camino instance -> physical device -> logical device -> queue cuando exista un ICD Vulkan;
- validar en host la topología y fallar de forma explícita cuando el entorno no tenga un driver.

No se introduce ninguna ABI Sony ni se afirma que este renderer sea ejecutable en PS5.
