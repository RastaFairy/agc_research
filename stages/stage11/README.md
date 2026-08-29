# AGC PS5 Stage 11 — SubmitDcb ABI refinement

Objetivo:
- corregir la identificación de las funciones exportadas de libSceAgcDriver;
- distinguir `sceAgcDriverSubmitDcb` de `sceAgcDriverSubmitCommandBuffer`;
- documentar la estructura de 16 bytes que el thunk de SubmitDcb entrega a la rutina interna;
- aislar qué parte está verificada por código real del SPRX y qué parte sigue siendo semántica inferida.

## Evidencia directa del SPRX

` sceAgcDriverSubmitDcb ` está en `0x28b0` y hace:

1. `mov rdi, rsi` — conserva el argumento original como segundo argumento.
2. carga en `rdi` un contexto global (`0x1a8b8`).
3. salta a `0x18b0`.

La rutina `0x18b0` corresponde al export `sceAgcDriverSubmitCommandBuffer` según la tabla de símbolos recuperada en Stage 10.

Dentro de `0x18b0`:

- `rdi` se trata como contexto interno del driver;
- `rsi` se trata como puntero a una estructura del llamador;
- se leen exactamente estos campos iniciales:
  - `*(uint64_t *)(rsi + 0x00)` → puntero a stream/buffer;
  - `*(uint32_t *)(rsi + 0x08)` → contador de dwords;
  - `*(uint8_t  *)(rsi + 0x0c)` → byte de control/estado;
- esos 16 bytes se copian a un registro local de trabajo;
- la rutina selecciona un callback de procesamiento y le entrega el contexto interno y esa copia local.

Por tanto, el layout de 16 bytes está respaldado directamente por el desmontado del binario.

## ABI provisional

```c
typedef struct agc_submit_command_buffer_desc {
    const uint32_t *addr;   /* +0x00 */
    uint32_t        dw_num; /* +0x08 */
    uint8_t         flags;  /* +0x0c */
    uint8_t         _pad[3];
} agc_submit_command_buffer_desc_t;
```

El nombre `flags` es deliberadamente provisional. El binario sólo demuestra que el byte existe y se copia; no demuestra todavía su semántica.

## Corrección de Stage 10

La siguiente cadena es la correcta:

`caller -> sceAgcDriverSubmitDcb (0x28b0) -> sceAgcDriverSubmitCommandBuffer (0x18b0) -> callback/processor`

No debe documentarse `0x18b0` como `sceAgcDriverSubmitDcb`.

## Límites

Todavía NO están verificados:
- prototipo C completo de `sceAgcDriverSubmitDcb`;
- significado semántico de `+0x0c`;
- reglas de validez para `dw_num`;
- formato PM4/AGC del stream apuntado por `addr`;
- ABI de `sceAgcInit` y `sceAgcGetRegisterDefaults2`.

No se habilita ninguna llamada de hardware en este stage.
