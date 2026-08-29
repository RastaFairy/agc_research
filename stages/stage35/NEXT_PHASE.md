# Next phase

Stage 36 should use a real PS5 build environment with the generated `libSceAgcDriver` stub linked into a payload. The first runtime probe must:

1. resolve `sceAgcDriverSubmitDcb` through the SDK stub;
2. print the resolved address/NID;
3. NOT invoke it yet;
4. separately verify the native call ABI from an actual PS5 call-site or equivalent disassembly evidence;
5. only then enable a one-submit DCB probe.

No Vulkan host work is required for Stage 36.
