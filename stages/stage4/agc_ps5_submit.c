#include "agc_ps5_submit.h"

#include <stdio.h>
#include <string.h>

bool agc_ps5_submit_packet_init(agc_ps5_submit_packet_t *packet,
                                const agc_ps5_dcb_t *dcb)
{
    if (!packet || !dcb || !dcb->bottom || !dcb->cursor_up)
        return false;

    size_t used = agc_ps5_dcb_used_dw(dcb);
    if (used == 0 || used > UINT32_MAX)
        return false;

    memset(packet, 0, sizeof(*packet));
    packet->addr = dcb->bottom;
    packet->dw_num = (uint32_t)used;
    return true;
}

bool agc_ps5_submit_packet_validate(const agc_ps5_submit_packet_t *packet)
{
    if (!packet || !packet->addr || packet->dw_num == 0)
        return false;
    return true;
}

void agc_ps5_submit_packet_dump(const agc_ps5_submit_packet_t *packet)
{
    if (!packet)
        return;

    printf("SubmitDcb NID=%s\\n", AGC_PS5_NID_SUBMIT_DCB);
    printf("  addr   = %p\\n", (void *)packet->addr);
    printf("  dw_num = %u\\n", packet->dw_num);
    printf("  size   = %zu bytes\\n", sizeof(*packet));
    printf("  pad    = %02x %02x %02x %02x\\n",
           packet->pad[0], packet->pad[1], packet->pad[2], packet->pad[3]);
}
