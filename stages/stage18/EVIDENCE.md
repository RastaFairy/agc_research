# Evidence — Stage 18

## 0x1820 dispatcher

```
182e  lea 0x190d3(%rip), %r15        # 0x1a908
1846  lea 0x48(%r15), %r13
...
185e  mov 0x0(%r13), %rcx
...
1872  call *%rcx
...
1884  imul $0x78, %rax, %rax
188e  mov 0x50(%r15,%rax,1), %rax
18a1  jmp *%rax
```

Esto demuestra dos entradas de ejecución diferentes por elemento:
- `+0x48`: callback principal recorrido durante la iteración;
- `+0x50`: destino alternativo/fallback asociado al índice seleccionado.

## 0xd0 initializer

```
d3   lea ... # 0x1a908
f6   imul $0x78, %rax, %rax
fa   vmovups %ymm0, 0x80(%rcx,%rax)
103  vmovups %ymm0, 0x30(%rcx,%rax)
109  vmovups %ymm0, 0x50(%rcx,%rax)
10f  vmovups %ymm0, 0x70(%rcx,%rax)
115  mov %rdx, 0x28(%rcx,%rax)
11f  mov %rsi, 0x50(%rcx,%rax)
12b  mov %rdi, 0x58(%rcx,%rax)
137  mov %rsi, 0x68(%rcx,%rax)
143  mov %rdi, 0x80(%rcx,%rax)
14b  mov %rsi, 0x88(%rcx,%rax)
```

Los punteros construidos justo antes son:
- `0x1000`
- `0x3cc0`
- `0x1a30`
- `0x67e0`
- `0x6810`

No aparece ningún store a `entry+0x48`.

## 0x160 initialization

La segunda rutina vuelve a preparar la tabla cuando `0xa0 == 0` y escribe:
- `+0x50 = 0x1000`
- `+0x58 = 0x3cc0`
- `+0x68 = 0x1a30`
- `+0x80 = 0x67e0`
- `+0x88 = 0x6810`

y después hace `+0xa0 = 1`.

## Implicación

El slot `+0x48` no es un default instalado por estas rutinas. Hay que localizar
una ruta adicional de registro/configuración del callback principal.
