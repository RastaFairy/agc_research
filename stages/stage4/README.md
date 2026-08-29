# AGC PS5 Stage 4 — typed SubmitDcb packet boundary

This stage adds the first typed boundary between the DCB we build and the `sceAgcDriverSubmitDcb` ABI model.

## Evidence source

The packet layout is reconstructed from the current `prosper` implementation of `sceAgcDriverSubmitDcb`:

```c
struct Packet {
    uint32_t* addr;
    uint32_t  dw_num;
    uint8_t   pad[4];
};
```

The handler treats its first argument as `const Packet*`, rejects null/zero values, and feeds `addr + dw_num` into the command-buffer processor.

The 3.20 export/NID recorded by `prosper` is:

- `sceAgcDriverSubmitDcb`
- NID `UglJIZjGssM`

## Important boundary

This is an ABI *model* derived from reverse engineering. It is not a public Sony header and does not yet prove that our payload can invoke the firmware entry point directly with this prototype.

We therefore keep the following layers separate:

```text
our DCB builder
    ↓
our SubmitDcb packet model
    ↓
[future: real PS5 import/stub invocation]
```

## Self-test

The included test builds a 12-DWORD DCB and verifies that the submit packet points at the DCB base and carries `dw_num = 12`.
