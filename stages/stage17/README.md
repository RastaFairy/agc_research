# AGC PS5 Stage 17 — real SPRX write-site audit for callback slot

## Objetivo
Determinar si `libSceAgcDriver.sprx` contiene una escritura interna verificable al slot global:

`0x1a908 + index*0x78 + 0x48`

que alimenta la llamada indirecta del dispatcher de `0x1820`.

## Hallazgos

1. El dispatcher `0x1820` construye la base `0x1a908`, avanza por entradas de `0x78` bytes y carga el callback desde `+0x48` antes de `call *%rcx`.
2. La rutina de inicialización en `0xd0` limpia partes de cada entrada mediante stores vectoriales que cubren también `+0x48`; por tanto, el estado inicial del slot callback es cero.
3. En el SPRX auditado no se encontró una escritura directa posterior que pueda atribuirse sin ambigüedad a `0x1a908 + index*0x78 + 0x48`.
4. El store de `0x2364` continúa descartado como candidato: la base procede de `[RBP-0x48]` y esa ruta usa estructuras de stride `0x90`.
5. En `0x6262` existe otro `mov ... ,0x48(%rax)`, pero `RAX` pertenece a otra estructura de recurso; no es la tabla `0x1a908`.
6. Por tanto, todavía no está demostrado quién rellena el callback `+0x48`. La hipótesis más conservadora es que lo haga una ruta externa/de registro o una estructura/alias que todavía no hemos identificado.

## Consecuencia
No se debe convertir `+0x48` en una API C inventada ni asignar un callback concreto todavía.

## Próximo objetivo — Stage 18
Seguir la procedencia del slot mediante:

- identificación de todas las referencias al rango de memoria `0x1a908..0x1b??`;
- búsqueda de APIs exportadas/importadas relacionadas con registro/configuración de callbacks;
- contraste con relocaciones/dynamic symbols del SPRX;
- comprobación cruzada con `libSceAgc.sprx` y `libSceAgcVsh.sprx` por referencias al mismo estado;
- sólo después intentar identificar el escritor externo del slot `+0x48`.

## Límite de evidencia
Este Stage no afirma todavía que el escritor sea otro módulo concreto. Sólo demuestra que los candidatos `0x2364` y `0x6262` no prueban esa escritura sobre la tabla global.
