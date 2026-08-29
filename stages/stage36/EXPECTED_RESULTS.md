# Interpretación

## STUB_UNAVAILABLE
La instalación del SDK no contiene `libSceAgcDriver.a`. Esto no es un fallo del proyecto: el SDK oficial indica que las bibliotecas SCE adicionales se incorporan generando stubs a partir de SPRX.

Siguiente acción: generar/instalar el stub de `libSceAgcDriver` desde el SPRX real de 3.20 y repetir la prueba.

## STUB_FOUND + build PASS
Hemos demostrado que el bridge compila contra el SDK/toolchain real y que el símbolo `sceAgcDriverSubmitDcb` existe en la biblioteca enlazada. La invocación sigue desactivada.

## build FAIL
Conservar `discovery.txt`, `build.log` y `status.txt`: el error de toolchain/linking se analizará antes de tocar ABI.
