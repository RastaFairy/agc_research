# AGC PS5 Stage 14 — callback registration evidence

## Objetivo

Avanzar un nivel desde Stage 13: demostrar cómo se construyen las entradas de la tabla de callbacks y qué funciones internas quedan almacenadas en ellas, sin asignar nombres Sony a funciones internas no exportadas.

## Hallazgo principal

El propio `libSceAgcDriver.sprx` contiene rutinas internas que inicializan y gestionan la tabla global en `0x1a908`.

La rutina en `0xD0` recibe un índice en `EDI`, calcula `entry = 0x1a908 + index * 0x78` y rellena múltiples campos de la entrada. Entre ellos quedan demostrados:

- `entry+0x28 = 0x1000e00000078`
- `entry+0x35 = 0xff`
- `entry+0x50 = 0x1000` (puntero/fallback de función)
- `entry+0x58 = 0x3cc0`
- `entry+0x68 = 0x1a30`
- `entry+0x80 = 0x67e0`
- `entry+0x88 = 0x6810`

La rutina en `0x160` inicializa la primera entrada de la tabla cuando el contador `0xa0` es cero y fija:

- `entry+0xa0 = 1` (contador de callbacks activos)
- `entry+0x50 = 0x1000`
- `entry+0x58 = 0x3cc0`
- `entry+0x68 = 0x1a30`
- `entry+0x80 = 0x67e0`
- `entry+0x88 = 0x6810`

Esto constituye evidencia directa de que la tabla no es una abstracción inventada por el análisis anterior.

## Relación con el dispatcher

`0x1820` recorre `entry+0x48` con stride `0x78` y llama al puntero de callback cuando es no nulo:

```text
RDI = contexto submit
RSI = packet de 16 bytes
EDX = 1
CALL *entry+0x48
```

Cuando no hay callback activo, se selecciona la entrada indicada por `base+0xa4` y se hace salto a `entry+0x50`.

## Corrección de interpretación

No debe confundirse el callback de `entry+0x48` con el fallback de `entry+0x50`. El primer campo es el que recibe `(context, packet, 1)` desde el dispatcher. El segundo pertenece a la ruta alternativa/fallback.

Tampoco se asignan nombres como `PM4Parser` a `0x3cc0`, `0x1a30`, `0x67e0` o `0x6810` sólo por su posición. Sus funciones reales se analizarán por comportamiento.

## Nueva pista importante

La función `0x3cc0` consume una estructura cuyo `dword +0x04` determina varias rutas y trabaja con tablas de 0x90 bytes. Esto parece más cercano a la capa de recursos/colas que al simple dispatcher de submit, por lo que no se etiquetará todavía como parser PM4.

## Próximo objetivo

1. Determinar qué rutina escribe `entry+0x48`.
2. Analizar el comportamiento de la función realmente instalada como callback.
3. Seguir la primera lectura de `packet.addr` y `packet.dw_num` hasta el bucle de consumo de dwords.
4. Correlacionar después ese bucle con Prosper/KytyPlus.
