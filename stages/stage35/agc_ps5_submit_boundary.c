#include "agc_ps5_submit_boundary.h"
#include <string.h>
#include <limits.h>

int agc_ps5_submit_packet_init(
    agc_ps5_submit_packet_t *out,
    const uint32_t *dcb,
    size_t dwords)
{
    if (!out || !dcb || dwords == 0 || dwords > UINT32_MAX)
        return -1;

    memset(out, 0, sizeof(*out));
    out->addr = dcb;
    out->dw_num = (uint32_t)dwords;
    return 0;
}

void *agc_ps5_submit_symbol_address(void *resolved_symbol)
{
    return resolved_symbol;
}

int agc_ps5_submit_native_disabled(const agc_ps5_submit_packet_t *packet)
{
    if (!packet || !packet->addr || packet->dw_num == 0)
        return -1;

    return 1;
}
