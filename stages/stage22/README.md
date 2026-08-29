# AGC PS5 Stage 22 — callback dispatch clarified

Fuente canónica:
- libSceAgcDriver.sprx
- SHA-256 2765597643c1bc6bac755b33c2fb00926b24057660521bd2bdb6510caeb18212

Objetivo:
- continuar desde Stage 21;
- separar definitivamente los consumidores del callback table de las estructuras auxiliares;
- identificar qué campos de la entrada se consumen en cada ruta.

Resultado:
- 0x45b0 recorre 0x1a908 + index*0x78 + 0x48 y llama al puntero con tres argumentos:
  rdi = objeto/contexto, rsi = segundo argumento conservado por la función llamante,
  rdx = tercer argumento.
- 0x4650 construye un buffer temporal de 0x20 bytes por elemento y después entra en
  la misma ruta; si no hay callbacks en +0x48, usa el callback seleccionado por
  +0x58 de la entrada indexada por 0xa4.
- El store de 0x6364 sigue descartado como escritor del callback table porque su base
  procede de 0x1e868 y usa otra estructura/stride.
- No se ha demostrado todavía el escritor de 0x1a908 + index*0x78 + 0x48.

No se asignan nombres Sony a las funciones internas sin evidencia adicional.
