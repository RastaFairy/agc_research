#ifndef AGC_PS5_NATIVE_BACKEND_H
#define AGC_PS5_NATIVE_BACKEND_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct agc_ps5_frame {
    const void *pixels;
    unsigned width;
    unsigned height;
    unsigned pitch;
    unsigned buffer_index;
} agc_ps5_frame_t;

typedef struct agc_ps5_native_backend agc_ps5_native_backend_t;

typedef struct agc_ps5_native_ops {
    bool (*init)(agc_ps5_native_backend_t *backend);
    void (*shutdown)(agc_ps5_native_backend_t *backend);
    bool (*begin_frame)(agc_ps5_native_backend_t *backend, unsigned buffer_index);
    bool (*upload_frame)(agc_ps5_native_backend_t *backend,
                         const void *pixels,
                         unsigned width,
                         unsigned height,
                         unsigned pitch);
    bool (*draw_fullscreen)(agc_ps5_native_backend_t *backend);
    bool (*submit)(agc_ps5_native_backend_t *backend);
    bool (*present)(agc_ps5_native_backend_t *backend, unsigned buffer_index, int64_t flip_arg);
} agc_ps5_native_ops_t;

struct agc_ps5_native_backend {
    const agc_ps5_native_ops_t *ops;
    bool initialized;
    bool frame_open;
    unsigned frame_width;
    unsigned frame_height;
    unsigned frame_pitch;
    unsigned buffer_index;
    uint64_t dryrun_seq;
};

const agc_ps5_native_ops_t *agc_ps5_native_dryrun_ops(void);

bool agc_ps5_native_init(agc_ps5_native_backend_t *backend,
                         const agc_ps5_native_ops_t *ops);
void agc_ps5_native_shutdown(agc_ps5_native_backend_t *backend);

bool agc_ps5_native_render_frame(agc_ps5_native_backend_t *backend,
                                 const agc_ps5_frame_t *frame,
                                 int64_t flip_arg);

#ifdef __cplusplus
}
#endif

#endif
