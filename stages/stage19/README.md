# AGC PS5 Stage 19 — binary consistency audit

Objetivo: resolver la discrepancia encontrada entre los análisis de Stage 14/18 y Stage 15.

## Hallazgo principal

Stage 14/18 identifica la tabla del dispatcher en `0x1a908`.

El Stage 15 contiene una rutina que escribe en `0x48(%rax,%r15,1)` después de cargar `rax = 0x1e908`.

Estas dos direcciones difieren exactamente en `0x4000`.

Por tanto, el store de Stage 15 **no puede demostrarse como escritura sobre la tabla `0x1a908`** del binario analizado por Stage 14/18. La explicación más consistente es que Stage 15 fue generado contra otra imagen/layout del mismo SPRX (o contra una versión distinta del binario).

## Consecuencia

No debemos continuar intentando identificar el callback `+0x48` mezclando offsets procedentes de ambas imágenes.

Primero hay que congelar una única copia de `libSceAgcDriver.sprx` y regenerar:

- referencias a `0x1a908`;
- dispatcher `0x1820`;
- initializer `0xd0` / `0x160`;
- todos los stores `entry+0x48` y `entry+0x50`;
- referencias a cualquier tabla alternativa `0x1e908`.

Hasta entonces, la conclusión de Stage 18 —que no se ha demostrado un store sobre `1a908 + index*0x78 + 0x48`— sigue siendo la correcta para su imagen de referencia.

## Regla para siguientes stages

Toda nueva evidencia debe registrar explícitamente:

1. hash del SPRX;
2. tamaño del archivo;
3. dirección base/layout usado por el disassembler;
4. dirección absoluta del símbolo/tabla;
5. comando exacto de desensamblado.

Esto evitará volver a mezclar imágenes.
