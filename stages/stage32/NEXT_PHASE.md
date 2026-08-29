# Next phase — Stage 33

1. Keep the Stage 32 ctypes ABI as the validated reference.
2. Add `VkImageView`-backed render target state.
3. Obtain a reproducible SPIR-V compiler or checked-in SPIR-V binaries.
4. Create shader modules and a minimal graphics pipeline.
5. Execute the first real triangle/quad on SwiftShader and read back the image.

SPIR-V must be real Vulkan SPIR-V; do not hand-wave or label guessed binary words as valid shader modules.
