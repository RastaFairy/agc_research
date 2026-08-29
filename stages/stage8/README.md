# AGC PS5 Stage 8 — ABI correction and bootstrap gate

Objetivo de esta etapa:
- corregir el inventario AGC/AGC Driver de Stage 7 con evidencia primaria del stub 3.20;
- separar claramente APIs exportadas, NID y semántica reconstruida;
- prohibir por diseño cualquier llamada a `sceAgcInit` o `sceAgcGetRegisterDefaults2` mientras no exista una firma tipada verificada;
- dejar preparada la siguiente etapa para reconstruir el bootstrap real.

## Evidencia congelada

`libSceAgc.c` de PS5-3.20_Libs muestra directamente:
- `sceAgcInit` -> `kW3GLb7QfPg`
- `sceAgcGetRegisterDefaults` -> `Wi82ArQtAwg`
- `sceAgcGetRegisterDefaults2` -> `2JtWUUiYBXs`
- `sceAgcCreateShader` -> `f3dg2CSgRKY`
- `sceAgcLinkShaders` -> `MqAdbRMdNz4`
- `sceAgcDcbSetIndexBuffer` -> `l4fM9K-Lyks`
- `sceAgcDcbSetIndexCount` -> `8N2tmT3jmC8`
- `sceAgcDcbDrawIndex` -> `q88lQ+GP5Yk`
- `sceAgcDcbWaitUntilSafeForRendering` -> `MWiElSNE8j8`
- `sceAgcCbBranch` -> `w1KFAHVqpaU`

`libSceAgcDriver.c` muestra directamente:
- `sceAgcDriverGetReservedDmemForAgc` -> `Um-jkyDy9rI`
- `sceAgcDriverInitResourceRegistration` -> `F0Y42t-3e18`
- `sceAgcDriverNotifyDefaultStates` -> `nR6xhiFsOoc`
- `sceAgcDriverSubmitDcb` -> `UglJIZjGssM`
- `sceAgcDriverAgrSubmitDcb` -> `AhGvpITrf4M`
- `sceAgcDriverSubmitCommandBuffer` -> `b4fpgH5ZXxQ`
- `sceAgcDriverSubmitMultiCommandBuffers` -> `Fj7r9EHzF38`

## Corrección importante

`w1KFAHVqpaU` NO se mantiene como un supuesto segundo método de submit. El stub 3.20 lo nombra `sceAgcCbBranch`. Por tanto Stage 8 lo trata como comando/branch de command-buffer y no como alternativa de `sceAgcDriverSubmitDcb`.

## Límite actual

Este stage todavía NO implementa:
- prototipo C de `sceAgcInit`;
- estructura real de sus argumentos;
- prototipo C de `sceAgcGetRegisterDefaults2`;
- estructura real de registros/defaults;
- memoria AGC inicial;
- primer DCB ejecutado en hardware.

Eso queda deliberadamente bloqueado hasta obtener una fuente de ABI tipada o evidencia de ejecución que permita validar los argumentos.

## Test

`make` compila una prueba host que valida que el inventario corregido conserva sólo identificadores/NID y que `w1KFAHVqpaU` aparece como `sceAgcCbBranch`.
