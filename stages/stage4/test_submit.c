#include "agc_ps5_dcb.h"
#include "agc_ps5_submit.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

int main(void)
{
    uint32_t storage[64];
    agc_ps5_dcb_t dcb;
    agc_ps5_submit_packet_t packet;

    memset(storage, 0, sizeof(storage));
    if (!agc_ps5_dcb_init(&dcb, storage, sizeof(storage))) {
        fprintf(stderr, "DCB init failed\\n");
        return 1;
    }

    if (!agc_ps5_dcb_set_index_buffer(&dcb, UINT64_C(0x123456789abcdef0)) ||
        !agc_ps5_dcb_set_index_count(&dcb, 3) ||
        !agc_ps5_dcb_draw_index(&dcb, 3)) {
        fprintf(stderr, "DCB build failed\\n");
        return 2;
    }

    if (!agc_ps5_submit_packet_init(&packet, &dcb)) {
        fprintf(stderr, "Submit packet init failed\\n");
        return 3;
    }

    if (!agc_ps5_submit_packet_validate(&packet)) {
        fprintf(stderr, "Submit packet validation failed\\n");
        return 4;
    }

    if (packet.addr != storage || packet.dw_num != 12) {
        fprintf(stderr, "Unexpected submit packet: addr=%p dw=%u\\n",
                (void *)packet.addr, packet.dw_num);
        return 5;
    }

    agc_ps5_submit_packet_dump(&packet);
    agc_ps5_dcb_dump(&dcb);
    puts("AGC PS5 Stage 4 submit-packet self-test: PASS");
    return 0;
}
