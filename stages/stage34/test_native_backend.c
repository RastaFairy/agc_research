#include "agc_ps5_native_backend.h"
#include <stdio.h>
#include <stdint.h>

int main(void)
{
    uint32_t pixels[4] = { 0xffffffffu, 0xff0000ffu,
                           0xff00ff00u, 0xffff0000u };
    agc_ps5_native_backend_t backend;
    agc_ps5_frame_t frame = {
        pixels, 2, 2, 2 * sizeof(uint32_t), 0
    };

    if (!agc_ps5_native_init(&backend, agc_ps5_native_dryrun_ops()))
        return 1;

    if (!agc_ps5_native_render_frame(&backend, &frame, 0))
        return 2;

    if (backend.frame_open)
        return 3;

    if (backend.dryrun_seq != 6)
        return 4;

    printf("Stage 34 native AGC bridge: PASS\n");
    printf("sequence=init,begin,upload,draw,submit,present\n");
    printf("Sony calls executed: 0\n");

    agc_ps5_native_shutdown(&backend);
    return 0;
}
