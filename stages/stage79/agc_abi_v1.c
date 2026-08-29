#include "agc_abi_v1.h"

/*
 * ABI v1 build layer.
 * These are intentionally weak forwarding symbols. A final PS5 import/stub
 * layer can override them with the real NID-backed implementation.
 */
#if defined(__GNUC__)
#define AGC_WEAK __attribute__((weak))
#else
#define AGC_WEAK
#endif

AGC_WEAK int sceAgcDriverSubmitCommandBuffer(void *context,
                                              const SceAgcSubmitCommandBufferArgs *args)
{
    (void)context;
    (void)args;
    return -1;
}

AGC_WEAK int sceAgcDriverSubmitDcb(void *dcb_context,
                                   const SceAgcSubmitCommandBufferArgs *args)
{
    return sceAgcDriverSubmitCommandBuffer(dcb_context, args);
}

AGC_WEAK int sceAgcDriverAgrSubmitDcb(void *agr_context,
                                      const SceAgcSubmitCommandBufferArgs *args)
{
    return sceAgcDriverSubmitCommandBuffer(agr_context, args);
}

AGC_WEAK int sceAgcDriverSubmitMultiCommandBuffers(void *context,
                                                   const uint64_t *field00_array,
                                                   const uint32_t *field08_array,
                                                   uint32_t count)
{
    (void)context;
    (void)field00_array;
    (void)field08_array;
    (void)count;
    return -1;
}

AGC_WEAK int sceAgcDriverSubmitMultiDcbs(void *context, const void *args)
{
    (void)context;
    (void)args;
    return -1;
}

AGC_WEAK int sceAgcDriverAgrSubmitMultiDcbs(void *context, const void *args)
{
    (void)context;
    (void)args;
    return -1;
}

AGC_WEAK int sceAgcDriverSubmitAcb(void *context, const void *args)
{
    (void)context;
    (void)args;
    return -1;
}

AGC_WEAK int sceAgcDriverSubmitMultiAcbs(void *context, const void *args)
{
    (void)context;
    (void)args;
    return -1;
}
