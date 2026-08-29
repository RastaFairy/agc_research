# Next phase

Stage 32 should eliminate the manual-Vulkan-struct bottleneck.

Preferred route:
1. obtain/use canonical Vulkan headers and typedefs;
2. keep SwiftShader ICD as the execution target;
3. compile a known-valid SPIR-V shader using a reproducible compiler/toolchain;
4. create ImageView → RenderPass/DynamicRendering → Pipeline → CommandBuffer → Readback;
5. compare output against Stage 26 deterministic reference.
