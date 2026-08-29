# AGC PS5 Stage 13 — callback dispatcher mapping

## Objetivo
Seguir el dispatcher interno que recibe el paquete de `sceAgcDriverSubmitDcb` y documentar, sin asignar nombres inventados, cómo selecciona y llama a los callbacks.

## Evidencia directa del `libSceAgcDriver.sprx`

En la rutina alrededor de `0x1820` se observa una tabla global en `0x1a908` con:

- `+0xa0`: número de callbacks activos/registrados que se recorre.
- `+0xa4`: índice/selector utilizado cuando no hay callbacks individuales.
- cada entrada tiene stride `0x78` bytes.
- `+0x00` de cada entrada se trata como puntero a función.
- `+0x50` de cada entrada también contiene un puntero a función usado por la ruta de fallback.

Cuando existe una entrada de callback válida, el dispatcher ejecuta exactamente el patrón:

```text
RDI = contexto interno de submit
RSI = submit packet de 16 bytes
EDX = 1
CALL *callback_entry
```

La rutina repite el recorrido hasta alcanzar `+0xa0` y después selecciona un callback de fallback mediante `+0xa4` y `entry+0x50`.

## Qué significa esto

`0x18b0` no es todavía el parser PM4. Es una capa de despacho. El stream de dwords (`addr`, `dw_num`) se entrega a uno o varios callbacks registrados.

Esto es importante porque el siguiente objetivo correcto es localizar las funciones que escriben/registran las entradas de esa tabla, y a partir de ellas obtener la identidad del consumidor real del command buffer.

## Lo que NO se afirma todavía

- No se asignan nombres Sony a los callbacks internos.
- No se afirma que todos los callbacks sean parsers PM4.
- No se fijan opcodes PM4/AGC.
- No se considera `+0x0c` del submit packet como `flags` o `reserved`.

## Artefactos

- `dispatcher_1820_1a30.asm`: desmontado del dispatcher y la rutina común de submit.
- `callback_table_refs.txt`: referencias de código a los objetos globales de callback/contexto.
- `scan_callback_registration.py`: analizador básico para ayudar a localizar escrituras sobre la tabla en futuros SPRX.

## Próximo objetivo

1. identificar los call-sites que registran las entradas de `0x1a908`;
2. determinar cuál callback consume el stream `addr/dw_num`;
3. desensamblar ese callback hasta el primer bucle de lectura del command buffer;
4. sólo entonces correlacionar opcodes con Prosper/KytyPlus.

Regla: una correlación externa sirve como hipótesis hasta que el opcode aparezca en el código PS5 real.
