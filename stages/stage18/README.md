# AGC PS5 Stage 18 — callback-slot initialization and table layout

Objetivo:
- aprovechar la evidencia directa de `libSceAgcDriver.sprx` para separar el
  callback principal del dispatcher de los callbacks/fallbacks auxiliares;
- documentar exactamente qué slots de cada entrada de 0x78 bytes se inicializan
  por las rutinas internas 0xd0 y 0x160;
- evitar volver a atribuir el store de Stage 15 a la tabla global de callbacks.

Evidencia principal:
- Dispatcher 0x1820:
  `base = 0x1a908`, itera con stride 0x78 y llama indirectamente al puntero
  situado en `base + 0x48 + index*0x78`.
- Inicializador 0xd0:
  limpia varios campos y escribe por entrada los punteros 0x1000, 0x3cc0,
  0x1a30, 0x67e0 y 0x6810 en offsets 0x50, 0x58, 0x68, 0x80 y 0x88.
  No escribe el slot 0x48.
- Inicializador 0x160:
  repite la inicialización de la primera entrada cuando `0xa0 == 0`, instala
  los mismos punteros por entrada y finalmente marca `0xa0 = 1`.
- Destrucción/limpieza 0x220:
  selecciona una entrada por índice y limpia la zona de la estructura con
  operaciones vectoriales, después deja `0xa0 = 0`.

Conclusión de esta etapa:
1. `entry+0x48` sigue siendo el callback que consume el dispatcher y su valor
   no queda explicado por 0xd0/0x160.
2. Los punteros en +0x50/+0x58/+0x68/+0x80/+0x88 son otra familia de funciones
   auxiliares/fallbacks y no deben confundirse con el callback de Submit.
3. La escritura de Stage 15 en 0x2364 continúa descartada: su base es una
   estructura distinta con stride/offsets diferentes.
4. La próxima búsqueda debe seguir las referencias a `0x1a908` y localizar la
   API interna que asigna específicamente `entry+0x48`.
