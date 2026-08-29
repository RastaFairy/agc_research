# AGC PS5 Stage 21 — separar el falso positivo 0x2354/0x2364

Fuente canónica: `libSceAgcDriver.sprx` del Stage 20.

## Hallazgo principal

La instrucción en `0x2364`:

`movq %rdx, 0x48(%rax,%r15)`

no escribe el callback slot de `0x1a908 + index*0x78 + 0x48`.

La procedencia de los registros muestra otra estructura:

- en `0x1fb8..0x1fd1` se seleccionan bases auxiliares `0x1a8b8` / `0x1a868`;
- en la ruta `0x200a` se carga una base indirecta desde `0x1a860`;
- en `0x1ff6..0x2005` se calcula un índice a partir de `arg-0x58`;
- en `0x2091..0x20aa` se calcula el índice alternativo a partir de `arg-0x20`;
- `0x2040..0x204b` convierte ese índice a un stride de `0x90` (`index * 9 * 16`);
- `0x2354..0x2369` escribe campos dentro de esa estructura de stride `0x90`.

Por tanto `+0x48` aquí es un campo de una estructura de registro/recurso auxiliar, no el slot `+0x48` de la callback table.

## Consecuencia

El hallazgo NO identifica todavía quién escribe:

`0x1a908 + index*0x78 + 0x48`

Seguimos sin una escritura directa demostrada del callback principal en la tabla global.

## Evidencia independiente

El dispatcher `0x1820` y la ruta `0x45b0` siguen demostrando el consumo de `0x1a908 + 0x48`, stride `0x78` y llamada indirecta.

## Siguiente objetivo

Buscar la rutina/API de registro que alimenta la tabla global, priorizando:

1. punteros derivados de las estructuras globales `0x1a860/0x1a868/0x1a8b8`;
2. call-sites que reciban un puntero de callback y un índice antes de entrar en esa lógica;
3. referencias cruzadas desde otros SPRX de la misma cadena AGC.
