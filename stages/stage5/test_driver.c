#include "agc_ps5_driver.h"

#include <stdio.h>
#include <stdlib.h>

static int fake_submit(const agc_ps5_submit_packet_t *packet)
{
    if (!packet || !packet->addr || packet->dw_num != 12)
        return -99;
    return 0;
}

int main(void)
{
    uint32_t words[32] = {0};
    agc_ps5_dcb_t dcb;
    agc_ps5_submit_packet_t packet;

    if (!agc_ps5_dcb_init(&dcb, words, sizeof(words)))
        return 1;

    if (!agc_ps5_dcb_set_index_buffer(&dcb, 0x123456789abcdef0ULL))
        return 2;
    if (!agc_ps5_dcb_set_index_count(&dcb, 3))
        return 3;
    if (!agc_ps5_dcb_draw_index(&dcb, 3))
        return 4;

    if (!agc_ps5_make_submit_packet(&dcb, &packet))
        return 5;

    printf("packet.size=%zu\n", sizeof(packet));
    printf("packet.addr=%p\n", (void *)packet.addr);
    printf("packet.dw_num=%u\n", packet.dw_num);

    if (sizeof(packet) != 16 || packet.addr != words || packet.dw_num != 12)
        return 6;

    if (agc_ps5_submit_dcb(fake_submit, &packet) != 0)
        return 7;

    printf("AGC PS5 Stage 5 submit bridge self-test: PASS\n");
    return 0;
}
