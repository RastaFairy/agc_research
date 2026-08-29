# RetroArch integration point

The existing `video_agc_ps5` contract already provides:

- `init`
- `frame`
- `set_nonblock_state`
- `alive`
- `focus`
- `set_shader`
- `free`
- viewport/rotation hooks

Stage 34 maps the frame path to an internal backend contract:

RetroArch `frame()`
  -> `agc_ps5_frame()`
  -> `agc_ps5_native_render_frame()`
  -> begin
  -> upload framebuffer
  -> fullscreen draw
  -> submit
  -> present/VideoOut

No Vulkan host dependency is part of this final path.
