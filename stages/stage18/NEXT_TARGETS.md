# Next targets

1. Enumerate every function that obtains `0x1a908` and classificar los stores
   a offsets 0x48..0x88 by entry-stride.
2. Buscar una función que reciba un puntero de función como argumento y lo
   almacene en `base + 0x48 + index*0x78`.
3. Correlacionar esa función con símbolos/NIDs exportados de `libSceAgcDriver`
   y `libSceAgc` cuando exista evidencia.
4. Mantener `sceAgcDriverSubmitDcb` como frontera separada; no activar llamadas
   tipadas hasta disponer de prototipo confirmado.
