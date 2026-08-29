# AGC PS5 Stage 23 — canonical callback-slot write audit

Reference binary: libSceAgcDriver.sprx execution dump `libdrv_exec.asm`.

Goal:
- audit all observed writes to offset +0x48;
- distinguish the real callback table at 0x1a908 (stride 0x78) from unrelated structures;
- correct Stage 22 if a candidate was misclassified.

Result:
- `0x45b0` / `0x4763-0x478e` consumes the callback table at `0x1a908 + 0x48 + index*0x78`.
- The store at `0x2364` is NOT a write to that table. In its containing function, `r15` is formed at `0x2040-0x204b` as `index * 0x90`, so `0x48(%rax,%r15)` addresses a different 0x90-byte structure.
- `0x8281` writes to `0x48(%rax)` where `rax = 0x1ab50`; this is unrelated to the callback table.
- `0x63e2` writes a PM4/command-buffer field at `0x48(%rdi)`; unrelated.
- The actual callback-table slot `0x1a908 + index*0x78 + 0x48` has not yet been observed being populated with a non-zero code pointer.
- The table initializer at `0xd0` zeroes the byte range containing `+0x48` as part of `vmovups` to `+0x30`, confirming the slot begins NULL.

Important conclusion:
The callback at `entry + 0x48` is a dynamically registered/late-populated field, not one of the fixed callbacks installed by the generic initializer at `0xd0`.
