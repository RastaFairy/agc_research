# Evidence — Stage 20

## 1. Identidad del binario

`libSceAgcDriver.sprx`
- size = 139680 bytes
- SHA-256 = 2765597643c1bc6bac755b33c2fb00926b24057660521bd2bdb6510caeb18212

## 2. Dispatcher

En `0x1820`:

`lea r15, [rip + ...] -> 0x1a908`

`lea r13, [r15 + 0x48]`

bucle:
- `mov rcx, [r13]`
- `call rcx`
- `add r13, 0x78`

Esto demuestra:
- tabla base = `0x1a908`
- callback slot = `+0x48`
- stride = `0x78`

## 3. Inicialización

En `0xd0`:
- limpia regiones de la entrada
- escribe callbacks internos en `+0x50`, `+0x58`, `+0x68`, `+0x80`, `+0x88`
- no escribe `+0x48`

En `0x160` ocurre la misma pauta para la entrada global.

## 4. Consumidor independiente

En `0x45b0`:
- obtiene otra vez `0x1a908`
- `lea rbx, [rcx + 0x48]`
- itera `add rbx, 0x78`
- carga `[rbx]`
- ejecuta `call rcx`

Esto confirma que `+0x48` es un callback consumido por múltiples rutas.

## 5. Falsos positivos descartados

`0x5f21`, `0x6262`, `0x63e2` contienen escrituras con desplazamiento `+0x48`, pero los registros base apuntan a buffers/estructuras locales. No son stores a la tabla `0x1a908`.

## 6. Estado

Callback principal: consumidor demostrado.
Escritor del callback principal: todavía no demostrado.
ABI Sony tipada: todavía no reconstruida.
