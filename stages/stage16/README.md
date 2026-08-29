# AGC PS5 Stage 16 — callback-table correction and proven write sites

## Objetivo
Corregir Stage 15 y separar definitivamente tres familias de estructuras:

1. la tabla global de callbacks en `0x1a908`, con entradas de `0x78` bytes;
2. las estructuras/objetos de recursos usados por la rutina alrededor de `0x20b6`/`0x2364`;
3. el estado interno de `sceAgcInit`/otras tablas, donde aparecen campos también en offset `0x48`.

## Resultado principal
El `mov %rdx,0x48(%rax,%r15,1)` en `0x2364` NO demuestra una escritura de `entry+0x48` de la tabla global `0x1a908`.

La función carga `RAX` desde `-0x48(%rbp)` en `0x20dc`, y después usa ese `RAX` como base de estructuras con stride de `0x90` (el `R15` se forma como índice * 0x90 en el camino de registro). Por tanto, el valor escrito en `0x2364` pertenece a otra estructura.

El dispatcher de `0x1820` sí usa de forma inequívoca la tabla global `0x1a908`:

- base `0x1a908`;
- entradas de `0x78` bytes;
- slot lógico `+0x48` cargado en `0x1846`;
- llamada indirecta `call *%rcx` en `0x1872`;
- fallback en `+0x50` cuando no hay callback activo.

## Evidencia adicional
La rutina de inicialización/gestión en `0xd0` escribe campos de las entradas `0x1a908 + index*0x78`, incluyendo `+0x50`, `+0x58`, `+0x68`, `+0x80` y `+0x88`, pero no encontramos en la evidencia reunida una escritura equivalente de `+0x48` que pueda atribuirse con seguridad a una función callback.

## Consecuencia
No debemos hacer todavía ninguna de estas afirmaciones:

- que `RBX + R15` sea una dirección ejecutable;
- que `0x2364` sea el registro del callback dispatcher;
- que el valor de `+0x48` de `0x1a908` haya sido rellenado por esa rutina.

## Siguiente objetivo de Stage 17
Localizar las escrituras que realmente apuntan a `0x1a908 + index*0x78 + 0x48` y, para cada una:

1. reconstruir la base y el índice;
2. comprobar si el valor almacenado cae dentro de una región `PF_X` del módulo;
3. seguir su origen hasta una tabla de funciones/callbacks;
4. sólo entonces asignar un prototipo o nombre lógico.

## Fuentes externas actuales
- `PS5-3.20_Libs` documenta stubs generados por NID para firmware 3.20, por lo que los nombres/NID deben tratarse como ABI exportada, no como firmas C originales.
- `prosper` documenta que su implementación HLE decodifica un DCB real y recorre el submit path, pero su código es una reimplementación en host, no una prueba de la ABI C privada de Sony.
- El issue reciente de prosper confirma la corrección de `w1KFAHVqpaU` como `sceAgcCbBranch`, reforzando la necesidad de no inferir nombres por contexto.
