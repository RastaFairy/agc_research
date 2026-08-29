# AGC PS5 Stage 10 — SPRX binary evidence

Esta etapa pasa de la tabla de NID a evidencia directa del código de los SPRX suministrados.

Objetivo:
- mapear los exports/NID a direcciones reales del SPRX;
- conservar el código desensamblado de las funciones críticas;
- inferir sólo lo que está demostrado por las instrucciones;
- no convertir esas inferencias en prototipos C definitivos.

## Evidencia obtenida

### libSceAgc.sprx
- `kW3GLb7QfPg#E#A` -> offset/VA `0x84a0`, tamaño 51: wrapper de `sceAgcInit`.
- `2JtWUUiYBXs#E#A` -> `0x8770`, tamaño 200: `sceAgcGetRegisterDefaults2`.
- `f3dg2CSgRKY#E#A` -> `0xc380`, tamaño 874: `sceAgcCreateShader`.
- `MqAdbRMdNz4#E#A` -> `0xd390`, tamaño 1105: `sceAgcLinkShaders`.
- `q88lQ+GP5Yk#E#A` -> `0x4760`, tamaño 213: `sceAgcDcbDrawIndex`.
- `l4fM9K-Lyks#E#A` -> `0x5e20`, tamaño 146: `sceAgcDcbSetIndexBuffer`.
- `8N2tmT3jmC8#E#A` -> `0x5ec0`, tamaño 142: `sceAgcDcbSetIndexCount`.
- `MWiElSNE8j8#E#A` -> `0x6c60`, tamaño 159: `sceAgcDcbWaitUntilSafeForRendering`.
- `w1KFAHVqpaU#E#A` -> `0x1f00`, tamaño 408: `sceAgcCbBranch`.

### libSceAgcDriver.sprx
- `UglJIZjGssM#F#A` -> `0x28b0`, tamaño 15: `sceAgcDriverSubmitDcb`.
- `AhGvpITrf4M#F#A` -> `0x28c0`, tamaño 72: `sceAgcDriverAgrSubmitDcb`.
- `b4fpgH5ZXxQ#F#A` -> `0x18b0`, tamaño 380: `sceAgcDriverSubmitCommandBuffer`.
- `Fj7r9EHzF38#F#A` -> `0x4650`, tamaño 579: `sceAgcDriverSubmitMultiCommandBuffers`.
- `Um-jkyDy9rI#F#A` -> `0x8f0`, tamaño 73: `sceAgcDriverGetReservedDmemForAgc`.
- `F0Y42t-3e18#F#A` -> `0x69f0`, tamaño 6: `sceAgcDriverInitResourceRegistration`.
- `nR6xhiFsOoc#F#A` -> `0x3630`, size 1159: `sceAgcDriverNotifyDefaultStates`.

## ABI inference boundary

`libSceAgc.sprx` demuestra que la entrada de `sceAgcInit` recibe tres valores en los registros SysV x86-64:
- `RDI` se conserva como puntero/valor de 64 bits;
- `ESI` se conserva como entero de 32 bits;
- `EDX` se conserva como entero de 32 bits.

La rutina exportada es un wrapper y salta a `0x75e0`; esto no demuestra todavía los tipos C exactos ni el significado de cada argumento.

`libSceAgc.sprx` demuestra que `sceAgcGetRegisterDefaults2` despacha inicialmente sobre `EDI` y devuelve direcciones de tablas/objetos internas para determinados valores. No se declara todavía un prototipo C porque falta evidencia de llamada real/call-site externo.

## Importante

Los SPRX sí contienen `DT_SYMTAB`, `DT_STRTAB`, `DT_HASH` y relocaciones, pero los nombres de exportación están ofuscados/representados como NID strings (`#E#A`, `#F#A`). El nombre de API se obtiene de la correspondencia con los stubs 3.20 ya verificados.
