# Next targets

1. Trace the producer of the callback pointer consumed at 0x45fe/0x478e.
2. Search call sites of the function(s) that initialize per-entry state after the 0xd0/0x160 table bootstrap.
3. Cross-reference the public/exported registration surface of libSceAgcDriver with these internal paths.
4. Keep ABI typing frozen: no Sony C prototype until a call site or independent typed source proves it.
