# AGC PS5 Stage 33 — reproducible SPIR-V toolchain

Objetivo: eliminar el último bloqueo de Stage 31/32 sin introducir SPIR-V artesanal.

## Fuente fijada

Khronos glslang **16.5.0**. La release 16.5.0 está publicada por Khronos y proporciona builds Linux x86_64; el proyecto glslang genera SPIR-V desde GLSL. El workflow reproducible usa la URL oficial:

`https://github.com/KhronosGroup/glslang/releases/download/16.5.0/glslang-16.5.0-linux-x86_64-release.tar.gz`

La compilación usa el ejecutable `glslang`/`glslangValidator` del paquete y después valida el `.spv` con `spirv-val` si está disponible.

## Estado en este entorno

`toolchain=UNAVAILABLE` porque el runtime no tiene salida DNS para descargar el asset. No se ha generado ningún SPIR-V ficticio.

## Shader P0

- `shaders/fullscreen.vert`
- `shaders/solid.frag`

El vertex shader genera un triángulo fullscreen a partir de `gl_VertexIndex`.
El fragment shader devuelve un color constante RGBA.

## Reproducibilidad

`tools/bootstrap_glslang.sh` descarga exactamente 16.5.0.
`tools/build_shaders.sh` compila ambos shaders a SPIR-V.
`tools/check_spirv.sh` valida que los módulos son SPIR-V válidos y registra SHA-256.

No se fijan hashes de los binarios descargados porque no hemos podido obtenerlos de forma verificable dentro de este entorno.
