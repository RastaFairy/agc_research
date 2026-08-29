# Golden trace

The host test uses a deterministic Type-3 stream containing:

1. SET_CONTEXT_REG
2. SET_SH_REG
3. SET_UCONFIG_REG
4. INDEX_BASE
5. DRAW_INDEX_AUTO
6. WRITE_DATA
7. EVENT_WRITE
8. WAIT_REG_MEM
9. RELEASE_MEM
10. host Present semantic marker

The expected IR sequence is exactly:

`SetReg, SetReg, SetReg, Draw, Draw, WriteData, Sync, Sync, Sync, Present`

This trace is intentionally small and independent of a PS5 runtime.
