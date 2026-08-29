#include "agc_ps5_driver.h"

#include <stddef.h>
#include <string.h>

bool agc_ps5_make_submit_packet(const agc_ps5_dcb_t *dcb,
                                agc_ps5_submit_packet_t *packet)
{
    size_t used;

    if (!dcb || !packet || !dcb->bottom || !dcb->cursor_up)
        return false;

    used = agc_ps5_dcb_used_dw(dcb);
    if (used == 0 || used > UINT32_MAX)
        return false;

    memset(packet, 0, sizeof(*packet));
    packet->addr = dcb->bottom;
    packet->dw_num = (uint32_t)used;
    return true;
}

bool agc_ps5_resolve_submit_dcb(agc_ps5_submit_dcb_fn *out_fn)
{
#ifdef AGC_PS5_SCE_STUBS
    /* The SDK-generated libSceAgcDriver stub exposes the symbol directly. */
    extern int sceAgcDriverSubmitDcb(const agc_ps5_submit_packet_t *packet);
    if (!out_fn)
        return false;
    *out_fn = sceAgcDriverSubmitDcb;
    return true;
#else
    /*
     * Keep the host build independent of PS5 CRT/Sce stubs. A PS5 build that
     * does not use generated stubs can provide its own resolver implementation.
     */
    (void)out_fn;
    return false;
#endif
}

int agc_ps5_submit_dcb(agc_ps5_submit_dcb_fn fn,
                       const agc_ps5_submit_packet_t *packet)
{
    if (!fn || !packet || !packet->addr || packet->dw_num == 0)
        return -1;

    return fn(packet);
}
