# AGC PS5 Stage 6 — submit/import boundary and bootstrap probe

Objetivo:
- congelar el ABI reconstruido de `sceAgcDriverSubmitDcb` como frontera experimental;
- separar resolución de símbolos de invocación;
- añadir un probe seguro que NO ejecuta AGC en un host normal;
- preparar la siguiente etapa: `sceAgcInit` / registro inicial / primer submit en PS5.

Fuentes de diseño:
- PS5-3.20_Libs: exports/NID y mecanismo de stubs dinámicos.
- prosper: modelo `Packet { addr, dw_num, pad }` para SubmitDcb y procesamiento del stream PM4.
- Kyty/KytyPlus: semántica conceptual de DCB/AGC.

Importante:
- No se inventa un prototipo público de Sony.
- El `Packet` de 16 bytes es una reconstrucción de ingeniería inversa.
- El probe por defecto sólo valida layout y símbolo/NID; no llama a `sceAgcDriverSubmitDcb`.
- La llamada real queda detrás de una función explícita y de un guard de compilación para que no se ejecute accidentalmente fuera del payload PS5.

Estado:
Stage 6 no demuestra todavía que el primer DCB ejecute en una PS5. La siguiente etapa debe aportar el contexto AGC y las precondiciones de inicialización.
