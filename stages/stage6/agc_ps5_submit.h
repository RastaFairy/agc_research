#ifndef AGC_PS5_SUBMIT_H
#define AGC_PS5_SUBMIT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct agc_ps5_submit_packet {
    const uint32_t *addr;
    uint32_t dw_num;
    uint32_t reserved;
} agc_ps5_submit_packet_t;

_Static_assert(sizeof(agc_ps5_submit_packet_t) == 16, "Submit packet must be 16 bytes");
_Static_assert(offsetof(agc_ps5_submit_packet_t, addr) == 0, "addr offset");
_Static_assert(offsetof(agc_ps5_submit_packet_t, dw_num) == 8, "dw_num offset");
_Static_assert(offsetof(agc_ps5_submit_packet_t, reserved) == 12, "reserved offset");

#define AGC_PS5_LIB_AGC_DRIVER "libSceAgcDriver.sprx"
#define AGC_PS5_SUBMIT_DCB_NID  "UglJIZjGssM"

int agc_ps5_make_submit_packet(
    agc_ps5_submit_packet_t *packet,
    const uint32_t *dcb,
    size_t dwords);

/*
 * Returns the resolved address of sceAgcDriverSubmitDcb when the
 * PS5 Payload SDK stub has been linked and its resolver has run.
 *
 * This function does NOT invoke the function.
 */
void *agc_ps5_get_submit_dcb_address(void);

/*
 * Deliberately separate from the probe. This symbol is only meaningful
 * inside the real PS5 payload build once the exact call ABI has been
 * verified on the target firmware.
 */
int agc_ps5_submit_dcb_probe(const agc_ps5_submit_packet_t *packet);

#ifdef __cplusplus
}
#endif

#endif
