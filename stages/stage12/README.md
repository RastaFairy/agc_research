# AGC PS5 Stage 12 — SubmitDcb call path and packet semantics

## Objetivo
Seguir el flujo real del SPRX `libSceAgcDriver.sprx` desde `sceAgcDriverSubmitDcb` hasta `sceAgcDriverSubmitCommandBuffer`, y separar lo demostrado de lo todavía inferido.

## Evidencia directa del binario

### `sceAgcDriverSubmitDcb` @ 0x28b0

La exportación hace únicamente:

1. mueve `RDI -> RSI`;
2. carga en `RDI` el objeto/estado global situado en `0x1a8b8`;
3. salta directamente a `0x18b0`.

Por tanto, `RDI` de la API pública es el puntero al paquete de submit y la rutina común recibe:

```text
RDI = contexto interno del driver
RSI = puntero al submit packet
```

No hay argumentos adicionales en este thunk.

### `sceAgcDriverAgrSubmitDcb` @ 0x28c0

La ruta es paralela, pero selecciona otro contexto (`0x1a868`) cuando el estado interno lo permite. Si no está habilitado devuelve `0x8a6d0003`.

Esto demuestra que `SubmitDcb` y `AgrSubmitDcb` comparten la misma rutina de procesamiento, pero con contextos distintos.

## `sceAgcDriverSubmitCommandBuffer` @ 0x18b0

La rutina copia exactamente 16 bytes del paquete apuntado por `RSI`:

```text
+0x00  uint64  addr
+0x08  uint32  dw_num
+0x0c  byte    field_0c
+0x0d..0x0f  no usados por esta copia
```

El puntero y el número de dwords sí son consumidos por la ruta de procesamiento. El byte de `+0x0c` se copia a una variable local, pero no aparece una lectura posterior en esta función antes del retorno; por tanto NO lo denominamos todavía `flags`, `reserved` ni le damos otro significado semántico.

## Paso importante: el command buffer no se ejecuta directamente aquí

La rutina crea/actualiza estado interno, incrementa contadores, y selecciona callbacks registrados. El camino termina en un callback de procesamiento que recibe un puntero al contexto y el paquete local.

Esto confirma que `SubmitDcb` es una frontera de entrega de un stream de dwords, no el parser PM4 final.

## Inferencia permitida

Podemos congelar ya esta frontera experimental:

```c
typedef struct agc_submit_packet_observed {
    const uint32_t *addr;  /* observado */
    uint32_t dw_num;       /* observado */
    uint8_t  byte_0c;      /* significado no resuelto */
    uint8_t  pad[3];
} agc_submit_packet_observed_t;
```

El tamaño observado es 16 bytes.

No se declara aún una firma completa de Sony para `sceAgcDriverSubmitDcb`, porque el call-site del consumidor sigue sin estar disponible.

## Nueva pista de alto valor

La función `sceAgcDriverAgrSubmitDcb` construye exactamente el mismo patrón de paquete y llama al mismo cuerpo `0x18b0`. Esto permite comparar los estados internos de ambos contextos cuando aparezca un consumidor real.

## Próximo objetivo

1. seguir los callbacks internos seleccionados en `0x18b0`;
2. identificar la función que consume `addr`/`dw_num` como stream de PM4;
3. correlacionar los primeros opcodes con `prosper`/KytyPlus;
4. localizar cómo se generan los packets mínimos para `WaitUntilSafeForRendering`, `DrawIndex`, `SetIndexBuffer` y `SetIndexCount`.

Regla: ningún significado de opcode/campo se marca como `VERIFIED` sólo por similitud con una implementación HLE.
