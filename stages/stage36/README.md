# AGC PS5 Stage 36 — real SDK stub integration probe

Objetivo:
- usar el SDK PS5 real mediante `PS5_PAYLOAD_SDK` y `toolchain/prospero.mk`;
- localizar si la instalación contiene stubs `libSceAgcDriver` reales;
- compilar el bridge contra el toolchain real cuando el stub exista;
- verificar que `sceAgcDriverSubmitDcb` puede resolverse como símbolo de enlace;
- NO invocar el símbolo todavía.

No se asume que `libSceAgcDriver` forme parte del SDK binario base. El SDK oficial documenta que bibliotecas SCE adicionales se añaden generando stubs desde SPRX. Por eso el script inspecciona la instalación y, si no encuentra el stub, informa exactamente qué falta en vez de fabricar una dependencia.
