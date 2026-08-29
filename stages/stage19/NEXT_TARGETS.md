# Next targets

1. Obtener una única copia canónica de `libSceAgcDriver.sprx`.
2. Calcular SHA-256, tamaño y layout.
3. Regenerar todas las referencias a `0x1a908` desde ese mismo archivo.
4. Buscar stores a `base+0x48` con stride exacto `0x78`.
5. Sólo después clasificar el callback y seguir su consumidor.
