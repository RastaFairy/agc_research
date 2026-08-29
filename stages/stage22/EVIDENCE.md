# Evidence

Canonical binary SHA-256:
2765597643c1bc6bac755b33c2fb00926b24057660521bd2bdb6510caeb18212

## 0x45b0

45be: lea 0x1a908,%rax
45ce: read entry_count at +0xa0
45d8: lea 0x1a908,%rcx
45e2: lea 0x48(%rcx),%rbx
45f5: add $0x78,%rbx
45fe: mov (%rbx),%rcx
4606-460f: call *%rcx with rdi/rsi/rdx preserved as three arguments
4620: fallback loads entry index from +0xa4
4636-463e: stride 0x78; indirect call through +0x58

## 0x4650

4650: function prologue
4730-474d: creates 0x20-byte temporary records
4752: load entry_count from 0x1a908 + 0xa0
4763: base = 0x1a908
476c: callback slot base = base + 0x48
4785: stride = 0x78
478e-479e: load +0x48 and indirect call
47c0-47df: fallback indexed by 0xa4, stride 0x78, field +0x58

## False positive rejected

0x6364:
mov %rdx,0x48(%rax,%r15,1)

The surrounding setup uses 0x1e868/related resource structures and does not derive
its base from 0x1a908. It is therefore not evidence for callback-table registration.
