# Evidence — Stage 19

## A. Stage 14/18

Dispatcher:

`0x182e: lea ... # 0x1a908`

Initializer:

`0xd3: lea ... # 0x1a908`

Stage 18 concluyó que estas rutinas preparan la tabla en `0x1a908` y que no se observó un store inequívoco al offset `+0x48` de esa tabla.

## B. Stage 15

El Stage 15 contiene:

`0x6136: lea ... # 0x1e908`

seguido de:

`0x6364: 4a 89 54 38 48    mov %rdx,0x48(%rax,%r15,1)`

Por tanto, en esa imagen el store apunta a `0x1e908 + index*0x90?`/stride calculado por el propio código, no a `0x1a908`.

La discrepancia literal de las tablas es:

`0x1e908 - 0x1a908 = 0x4000`.

## C. Conclusión

La evidencia del Stage 15 no debe reutilizarse como prueba de registro del callback principal del dispatcher `0x1820` del Stage 14/18.
