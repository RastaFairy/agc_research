#include "agc_ps5_native_backend.h"

#include <string.h>

static bool dry_init(agc_ps5_native_backend_t *b)
{
    if (!b) return false;
    b->dryrun_seq++;
    return true;
}

static void dry_shutdown(agc_ps5_native_backend_t *b)
{
    if (b) b->dryrun_seq++;
}

static bool dry_begin(agc_ps5_native_backend_t *b, unsigned buffer_index)
{
    if (!b || !b->initialized) return false;
    b->buffer_index = buffer_index;
    b->frame_open = true;
    b->dryrun_seq++;
    return true;
}

static bool dry_upload(agc_ps5_native_backend_t *b,
                       const void *pixels,
                       unsigned width,
                       unsigned height,
                       unsigned pitch)
{
    if (!b || !b->frame_open || !pixels || width == 0 || height == 0 || pitch == 0)
        return false;
    b->frame_width = width;
    b->frame_height = height;
    b->frame_pitch = pitch;
    b->dryrun_seq++;
    return true;
}

static bool dry_draw(agc_ps5_native_backend_t *b)
{
    if (!b || !b->frame_open) return false;
    b->dryrun_seq++;
    return true;
}

static bool dry_submit(agc_ps5_native_backend_t *b)
{
    if (!b || !b->frame_open) return false;
    b->dryrun_seq++;
    return true;
}

static bool dry_present(agc_ps5_native_backend_t *b,
                        unsigned buffer_index,
                        int64_t flip_arg)
{
    (void)flip_arg;
    if (!b || !b->frame_open || b->buffer_index != buffer_index)
        return false;
    b->frame_open = false;
    b->dryrun_seq++;
    return true;
}

static const agc_ps5_native_ops_t g_dryrun_ops = {
    dry_init,
    dry_shutdown,
    dry_begin,
    dry_upload,
    dry_draw,
    dry_submit,
    dry_present
};

const agc_ps5_native_ops_t *agc_ps5_native_dryrun_ops(void)
{
    return &g_dryrun_ops;
}

bool agc_ps5_native_init(agc_ps5_native_backend_t *backend,
                         const agc_ps5_native_ops_t *ops)
{
    if (!backend || !ops || !ops->init || !ops->shutdown ||
        !ops->begin_frame || !ops->upload_frame || !ops->draw_fullscreen ||
        !ops->submit || !ops->present)
        return false;

    memset(backend, 0, sizeof(*backend));
    backend->ops = ops;

    if (!backend->ops->init(backend))
    {
        backend->ops = NULL;
        return false;
    }

    backend->initialized = true;
    return true;
}

void agc_ps5_native_shutdown(agc_ps5_native_backend_t *backend)
{
    if (!backend) return;
    if (backend->initialized && backend->ops && backend->ops->shutdown)
        backend->ops->shutdown(backend);
    memset(backend, 0, sizeof(*backend));
}

bool agc_ps5_native_render_frame(agc_ps5_native_backend_t *backend,
                                 const agc_ps5_frame_t *frame,
                                 int64_t flip_arg)
{
    if (!backend || !backend->initialized || !frame)
        return false;

    if (!backend->ops->begin_frame(backend, frame->buffer_index))
        return false;

    if (!backend->ops->upload_frame(backend, frame->pixels,
                                    frame->width, frame->height,
                                    frame->pitch))
        return false;

    if (!backend->ops->draw_fullscreen(backend))
        return false;

    if (!backend->ops->submit(backend))
        return false;

    return backend->ops->present(backend, frame->buffer_index, flip_arg);
}
