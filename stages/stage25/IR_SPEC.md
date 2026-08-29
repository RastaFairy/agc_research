# Stage 25 IR

## SetReg

Carries register class (`context`, `sh`, `uconfig`), starting register, and a copied value array.

## Draw

Carries indexed/non-indexed semantic state, vertex/index count, initiator, and optional index base. `INDEX_BASE` is represented as a state-bearing Draw op so the next execution layer can fold it into a draw state object without inventing another AGC API.

## WriteData

Carries the PM4 control word, 64-bit address and copied dword payload.

## Sync

Carries `WAIT_REG_MEM`, `EVENT_WRITE`, or `RELEASE_MEM` plus an opaque copied payload. This intentionally preserves the packet semantics without prematurely assigning Sony-specific field names.

## Present

A semantic operation containing `buffer_index` and `flip_arg`, injected only by the presentation layer. `source_dword = SIZE_MAX` marks it as non-DCB-originated.
