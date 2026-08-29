# Evidence — Stage 21

### Callback table canónica
- base: `0x1a908`
- callback: `+0x48`
- stride: `0x78`
- consumer: `0x1820`
- consumer independiente: `0x45b0`

### Candidato 0x2354/0x2364
`0x2364: movq %rdx, 0x48(%rax,%r15)`

Pero `r15` se construye como `index * 0x90` en la ruta que llega al bloque, y `rax` proviene de una base auxiliar (`0x1a8b8/0x1a868` o una base indirecta asociada). Por ello no coincide con la geometría de la tabla global (`0x78`).

Este candidato queda clasificado como **estructura auxiliar de registro/recurso**, no como escritor de callback.

### Estado
- escritor del callback principal: no identificado
- consumidor del callback principal: demostrado
- ABI C Sony: no tipada todavía
