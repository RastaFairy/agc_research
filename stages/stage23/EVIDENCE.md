# Evidence — Stage 23

## 1. Consumer is confirmed

At `0x45b0`:
- base = `0x1a908`
- callback cursor = `base + 0x48`
- increment = `0x78`
- load = `mov (%rbx), %rcx`
- indirect call = `call *%rcx`

At `0x4763` / `0x478e` the same `0x78` traversal is repeated.

## 2. Candidate 0x2364 is a false positive

At `0x2040`:
- `r15 = r12d * 9`
- `r15 <<= 4`
- therefore `r15 = r12d * 0x90`.

At `0x20b6`:
- `rax = 0x1a908`.

But the later store is:
- `0x2364: mov %rdx, 0x48(%rax,%r15,1)`.

Because `r15` is a `0x90` stride, this cannot address the `0x78` callback table.

## 3. Generic initializer does not populate +0x48

At `0xd0`, the initializer uses `index * 0x78` and installs fixed fields:
- `+0x50 = 0x1000`
- `+0x58 = 0x3cc0`
- `+0x68 = 0x1a30`
- `+0x80 = 0x67e0`
- `+0x88 = 0x6810`

It also zeroes the 0x30..0x4f range, which includes `+0x48`.

At `0x160`, the same fixed callback/fallback fields are installed for entry 0 and `+0x48` is still not assigned.

## 4. Other +0x48 stores

- `0x63e2: mov %rcx, 0x48(%rdi)` is inside a command-buffer construction routine and is not based on the callback-table base.
- `0x8281: mov %rcx, 0x48(%rax)` targets global object `0x1ab50`.

Both are unrelated.

## 5. Current status

What is proven:
- consumer location;
- table base;
- table stride;
- callback slot offset;
- fixed callbacks/fallbacks in adjacent fields.

What is not yet proven:
- writer/registration API for `+0x48`;
- identity of the code pointer stored there;
- native C signature of that callback.
