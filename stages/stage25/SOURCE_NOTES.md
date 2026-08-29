# Source notes

The P0 opcode numbers are cross-checked against public AMD PM4 opcode tables:

- INDEX_BASE = 0x26
- DRAW_INDEX = 0x2B
- DRAW_INDEX_AUTO = 0x2D
- WRITE_DATA = 0x37
- WAIT_REG_MEM = 0x3C
- EVENT_WRITE = 0x46
- RELEASE_MEM = 0x49
- SET_CONTEXT_REG = 0x69
- SET_SH_REG = 0x76
- SET_UCONFIG_REG = 0x79

KytyPlus documentation separates `src/graphics/guest_gpu`, `src/graphics/shader/recompiler`, and `src/graphics/host_gpu`, with Vulkan 1.3 as host renderer. The decoder mirrors that separation conceptually but contains no KytyPlus source.

SharpEmu is used as a semantic reference for AGC/PM4 coverage; this stage does not import its code.
