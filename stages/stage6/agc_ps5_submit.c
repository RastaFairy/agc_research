#include "agc_ps5_submit.h"

#include <string.h>

/*
 * The PS5-3.20_Libs generated stub exposes the symbol by name and
 * resolves it through sprx_dlopen/sprx_dlsym. We intentionally don't
 * re-declare the Sony prototype here.
 */
extern void sceAgcDriverSubmitDcb(void *opaque); /* experimental bridge only */

#if defined(AGC_PS5_REAL_CALL)
#define AGC_PS5_REAL_CALL_ENABLED 1
#else
#define AGC_PS5_REAL_CALL_ENABLED 0
#endif

int agc_ps5_make_submit_packet(
    agc_ps5_submit_packet_t *packet,
    const uint32_t *dcb,
    size_t dwords)
{
    if (!packet || !dcb || dwords == 0 || dwords > UINT32_MAX)
        return -1;

    memset(packet, 0, sizeof(*packet));
    packet->addr = dcb;
    packet->dw_num = (uint32_t)dwords;
    return 0;
}

void *agc_ps5_get_submit_dcb_address(void)
{
    /*
     * Taking the address is enough to verify that the linked stub symbol
     * exists. No invocation is performed.
     */
    return (void *)(uintptr_t)&sceAgcDriverSubmitDcb;
}

int agc_ps5_submit_dcb_probe(const agc_ps5_submit_packet_t *packet)
{
    if (!packet || !packet->addr || packet->dw_num == 0)
        return -1;

#if AGC_PS5_REAL_CALL_ENABLED
    /*
     * IMPORTANT:
     * This is intentionally not enabled by default. The exact native
     * prototype/calling convention must be confirmed on the target
     * firmware before activating it.
     */
    sceAgcDriverSubmitDcb((void *)packet);
    return 0;
#else
    (void)packet;
    return 1; /* probe-only: validated packet, call intentionally disabled */
#endif
}
