# Stage 30 test plan

1. Host compile with `-Wall -Wextra -Werror`.
2. Capability structure smoke test.
3. Vulkan device probe when an ICD is present.
4. If `vkCreateInstance` returns `VK_ERROR_INCOMPATIBLE_DRIVER`, record `UNAVAILABLE` rather than claiming a renderer test passed.
5. Stage 31 performs actual image/pipeline/readback validation.
