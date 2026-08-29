# AGC PS5 Stage 30 — Vulkan capability contract

This stage freezes the minimum Vulkan capabilities required by the AGC P0 backend:

- a graphics-capable queue family;
- compute capability is recorded but not required for P0 draw;
- `VK_FORMAT_R8G8B8A8_UNORM` color attachment support;
- transfer source/destination support for the offscreen readback path;
- device-local memory;
- host-visible memory for staging/readback.

No Sony/AGC ABI is assumed. The capability query runs only after a real Vulkan
physical device has been obtained. A host without an ICD remains an expected
`UNAVAILABLE` condition.
