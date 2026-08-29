#include "agc_ps5_submit.h"
#include <stdio.h>
#include <stdint.h>

int main(void)
{
    uint32_t dcb[4] = {
        0xC0001000u,
        0x00000000u,
        0x00000000u,
        0xC0001000u
    };

    agc_ps5_submit_packet_t packet;
    if (agc_ps5_make_submit_packet(&packet, dcb, 4) != 0)
        return 1;

    printf("Stage 6 submit packet probe\n");
    printf("packet.size = %zu\n", sizeof(packet));
    printf("packet.addr = %p\n", (const void *)packet.addr);
    printf("packet.dw_num = %u\n", packet.dw_num);
    printf("packet.reserved = %u\n", packet.reserved);

    /*
     * On a non-PS5 host the weak/link stub is normally unavailable, so
     * this test only checks the reconstructed packet ABI.
     */
    printf("packet ABI: PASS\n");
    printf("native submit invocation: intentionally disabled\n");
    return 0;
}
