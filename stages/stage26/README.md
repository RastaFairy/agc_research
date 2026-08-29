# AGC PS5 Stage 26 — deterministic host executor

Objetivo: ejecutar la IR P0 de Stage 25 en un backend host determinista antes de conectar Vulkan o una ABI nativa PS5.

La implementación contiene:
- `agc_p0_decoder.*` heredado de Stage 25;
- `agc_p0_host.*`, un executor RGBA8 con memoria lineal de prueba;
- `test_host.c`, que decodifica un trace dorado, ejecuta toda la IR y comprueba sus efectos;
- `stage26_reference.ppm`, salida visual determinista.

Importante: el rectángulo dibujado es un backend de referencia de testing. No pretende reproducir la rasterización AGC real. Su objetivo es validar la frontera `PM4 -> IR -> backend` y sus efectos observables.

No se utiliza ninguna función SCE, ningún SPRX ni Vulkan en esta etapa.
