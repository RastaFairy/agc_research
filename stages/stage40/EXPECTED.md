# Expected result

Stage 40 pasa si:

1. `stage40_probe.elf` se genera como ELF target PS5.
2. `readelf -s` encuentra `sceAgcDriverSubmitDcb`.
3. No se ejecuta ninguna llamada AGC.

Un fallo del enlace debe analizarse desde `build.log`; no se debe inventar una firma ABI nueva por un simple error de linker.
