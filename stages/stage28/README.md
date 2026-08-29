# AGC PS5 Stage 28 — Vulkan device/queue boundary

Stage 28 keeps the Stage 25 P0 IR unchanged and advances the host Vulkan adapter from loader/instance probing to physical-device, graphics-queue selection, logical-device creation and queue acquisition.

The Vulkan structs and device-creation sequence follow the Vulkan 1.4 specification. No Sony/AGC ABI is assumed here.

A host without a Vulkan ICD is an expected `UNAVAILABLE` result, not a test failure.
