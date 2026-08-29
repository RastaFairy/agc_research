# Next phase — Stage 31

When an ICD is available, Stage 31 should create the actual RGBA8 image,
image view, render pass/pipeline, staging buffer, synchronization objects,
submit one draw, copy the result to host-visible memory and compare readback
against the deterministic Stage 26 reference.
