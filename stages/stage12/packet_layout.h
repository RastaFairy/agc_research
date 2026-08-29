#ifndef AGC_PS5_STAGE12_PACKET_LAYOUT_H
#define AGC_PS5_STAGE12_PACKET_LAYOUT_H
#include <stdint.h>
#include <stddef.h>

typedef struct agc_submit_packet_observed {
    const uint32_t *addr;
    uint32_t dw_num;
    uint8_t byte_0c;
    uint8_t pad[3];
} agc_submit_packet_observed_t;

_Static_assert(sizeof(agc_submit_packet_observed_t) == 16, "observed submit packet must be 16 bytes");
_Static_assert(offsetof(agc_submit_packet_observed_t, addr) == 0, "addr");
_Static_assert(offsetof(agc_submit_packet_observed_t, dw_num) == 8, "dw_num");
_Static_assert(offsetof(agc_submit_packet_observed_t, byte_0c) == 12, "byte_0c");

#endif
