# Source notes

SharpEmu `AgcExports.cs` enumera explícitamente los iniciadores y paquetes que necesitamos como referencia semántica: `SET_CONTEXT_REG`, `SET_SH_REG`, `SET_UCONFIG_REG`, `WRITE_DATA`, `DISPATCH_*`, `EVENT_WRITE`, `RELEASE_MEM`, `DMA_DATA`, además de `DRAW_INDEX_*`, `DRAW_INDEX_AUTO`, `INDEX_BASE` e `INDEX_COUNT`.

También mantiene definiciones de registros GFX10 para shader program, viewport, scissor y color target, y estructuras de shader (`CreateShader`) usadas por la traducción.

KytyPlus documenta la separación:
`src/graphics/guest_gpu`
`src/graphics/shader/recompiler`
`src/graphics/host_gpu`
con Vulkan 1.3 como renderer de host.

Estos datos sirven para diseñar el subconjunto y las interfaces internas. No constituyen evidencia de que el mismo código pueda enlazarse como payload PS5.
