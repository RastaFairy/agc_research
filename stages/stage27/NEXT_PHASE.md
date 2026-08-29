# Next phase — Stage 28

Implementar el backend de render P0 sobre Vulkan:
1. physical device / queue family;
2. device + queue;
3. RGBA8 image y staging buffer;
4. shader SPIR-V mínimo;
5. fullscreen/triangle draw para la IR `Draw`;
6. readback y comparación contra `stage26_reference.ppm`.

El backend debe seguir consumiendo exclusivamente la IR de Stage 25.
