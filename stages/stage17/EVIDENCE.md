# Evidence summary

### Dispatcher 0x1820
- `lea 0x190d3(%rip), %r15` -> `0x1a908`
- `lea 0x48(%r15), %r13`
- `add $0x78, %r13` per entry
- `mov (%r13), %rcx`
- `call *%rcx`

### Table initialization 0xd0
- base `0x1a908`
- index scaled by `0x78`
- vector stores at `+0x30`, `+0x50`, `+0x70` zero the entry ranges; `+0x48` is covered by the `+0x30` 32-byte clear.
- fixed internal pointers are installed at `+0x58`, `+0x68`, `+0x80`, `+0x88`.

### Rejected store 0x2364
`mov %rdx,0x48(%rax,%r15,1)`

The `RAX` base comes from `[RBP-0x48]`, not from `0x1a908`; the path derives a separate resource structure with `index*0x90`.

### Rejected store 0x6262
`mov %ecx,0x48(%rax)`

This belongs to a resource/command structure initialized around `0x1e908` and is unrelated to the global callback table.
