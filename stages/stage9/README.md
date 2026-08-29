# AGC PS5 Stage 9 — call-site ABI evidence extractor

Objetivo:
- avanzar desde la lista de NID hacia evidencia de ABI tipada sin inventar prototipos;
- analizar un ELF/disassembly x86-64 y localizar call-sites de `sceAgcInit`, `sceAgcGetRegisterDefaults2` u otras funciones;
- registrar las escrituras recientes a registros de argumento y referencias de stack previas a cada `call`;
- producir candidatos de argumentos, NO una firma C definitiva.

## Por qué esta etapa

Stage 8 confirma exports/NID, pero no los tipos ni el layout de argumentos. Esta herramienta permite que, cuando dispongamos de un ELF 3.20 real que invoque AGC, podamos reconstruir el ABI desde los call-sites.

## Registro de evidencia

Para cada llamada se inspeccionan los últimos bloques de instrucciones antes del `call` y se anotan las asignaciones observables a:

`RDI RSI RDX RCX R8 R9`

además de accesos a stack (`[rsp+...]`, `[rbp-...]`, etc.). Esto es un *heuristic* basado en ABI x86-64; no convierte automáticamente los datos en una firma Sony.

## Uso

```sh
python3 tools/agc_callsite_scan.py --elf ./sample.elf --target sceAgcInit
python3 tools/agc_callsite_scan.py --disasm ./sample.asm.txt --target sceAgcInit
```

Opcionalmente se puede pasar `--target sceAgcGetRegisterDefaults2` o cualquier otro símbolo.

Salida JSON: `calls[]`, con `function`, `call_site`, `instructions_before`, `register_writes` y `stack_refs`.

## Límite

No se ejecuta código PS5 ni se llama a ninguna función SCE. La herramienta sólo extrae evidencia estática. Las conclusiones de ABI deben validarse con múltiples call-sites o una cabecera/SDK coincidente.
