# AGC PS5 Stage 15 — callback slot correction and pointer provenance

## Objetivo
Corregir una ambigüedad de Stage 14 y seguir el origen exacto del valor escrito en el campo `+0x48`.

## Corrección
El dispatcher de `SubmitCommandBuffer` no lee `entry+0x00` del registro lógico de la tabla principal. Hace:

```c
entry = base + 0x48;
entry += index * 0x78;
callback = *(entry + 0x00);
```

Por tanto, el callback lógico de cada entrada corresponde al byte-offset `0x48` respecto del comienzo de la estructura de 0x78 bytes.

## Nuevo hallazgo
En la ruta de registro alrededor de `0x6354-0x6364` aparece:

```asm
movl   $0x38,(%r14)
movq   $0,0x14(%rax,%r15)
mov    %rdx,0x48(%rax,%r15)
```

pero el valor guardado en `0x48` procede de `RDX = RBX + R15` en `0x61cb-0x61cf`.

Esto demuestra que **sí existe una escritura explícita del campo `+0x48`, pero todavía no permite etiquetar ese valor como función sin resolver qué objeto representan `RBX` y `R15` en esa ruta**. No se debe convertir automáticamente en un callback C.

## Lo que queda demostrado
1. `SubmitCommandBuffer` carga el valor del slot lógico `+0x48` y lo invoca indirectamente.
2. Existe una rutina de registro que escribe dicho slot.
3. El origen inmediato del valor almacenado es un puntero calculado como `RBX + R15`.
4. La identidad/ejecutabilidad de ese puntero sigue pendiente de resolver.

## Lo que NO se asume
- que `RBX + R15` sea una dirección de código;
- que `0x48` contenga siempre una función;
- que `0x50` sea un fallback universal;
- que las estructuras de `0x78` bytes sean idénticas a una estructura pública de Sony.

## Siguiente evidencia objetivo
Resolver qué base representa `RBX` en la función de registro y cruzar los objetos de `0x1e908`/`0x1c460` con sus usos. A continuación debemos identificar una entrada concreta cuyo `+0x48` contenga una dirección que caiga dentro de la región ejecutable del SPRX.
