# Stage 30 capability matrix

| Capability | P0 requirement | Rationale |
|---|---|---|
| Graphics queue | required | fullscreen draw |
| Compute queue | recorded, not required | future shader/compute expansion |
| R8G8B8A8_UNORM color attachment | required | deterministic framebuffer |
| R8G8B8A8_UNORM transfer source | required | readback |
| R8G8B8A8_UNORM transfer destination | required | upload path |
| Device-local memory | required | GPU render target |
| Host-visible memory | required | staging/readback |
