#include "agc_abi_v1.h"
#include <stdint.h>

_Static_assert(sizeof(SceAgcSubmitCommandBufferArgs) == 16, "expected ABI v1 size");

int stage79_probe(void *ctx, const SceAgcSubmitCommandBufferArgs *args)
{
    return sceAgcDriverSubmitCommandBuffer(ctx, args);
}

int stage79_probe_dcb(void *ctx, const SceAgcSubmitCommandBufferArgs *args)
{
    return sceAgcDriverSubmitDcb(ctx, args);
}

int stage79_probe_multi(void *ctx,
                        const uint64_t *a0,
                        const uint32_t *a8,
                        uint32_t count)
{
    return sceAgcDriverSubmitMultiCommandBuffers(ctx, a0, a8, count);
}
