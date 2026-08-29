# Next targets

1. Find functions that receive a callback/function pointer as an argument and also operate on the `0x1a908` state object.
2. Trace writes to the table through register-held base pointers, including byte/quad/vector stores whose effective address covers `+0x48`.
3. Inspect cross-references to the state fields around `0x1a860..0x1a9f8`, especially initialization/count fields and registration calls.
4. Once a non-zero function pointer is recovered, verify whether it lies in an executable SPRX region and recover its call argument pattern from the caller.
5. Only then assign a semantic name or candidate prototype.
