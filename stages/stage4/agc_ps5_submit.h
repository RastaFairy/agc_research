#ifndef AGC_PS5_SUBMIT_H
#define AGC_PS5_SUBMIT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "agc_ps5_dcb.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Reconstructed from prosper's RE of sceAgcDriverSubmitDcb on PS5 3.20.
 *
 * This is an ABI model, NOT an assertion that Sony publishes this struct.
 * prosper's current handler treats a0 as a pointer to:
 *   +0x00 : uint32_t *addr
 *   +0x08 : uint32_t dw_num
 *   +0x0c : uint8_t pad[4]
 *
 * The packet is therefore 16 bytes on x86-64.
 */
typedef struct agc_ps5_submit_packet {
    uint32_t *addr;
    uint32_t  dw_num;
    uint8_t   pad[4];
} agc_ps5_submit_packet_t;

_Static_assert(offsetof(agc_ps5_submit_packet_t, addr) == 0x00, "addr offset");
_Static_assert(offsetof(agc_ps5_submit_packet_t, dw_num) == 0x08, "dw_num offset");
_Static_assert(offsetof(agc_ps5_submit_packet_t, pad) == 0x0c, "pad offset");
_Static_assert(sizeof(agc_ps5_submit_packet_t) == 0x10, "submit packet size");

/*
 * Build a submit record from a live DCB. No platform calls are made here.
 */
bool agc_ps5_submit_packet_init(agc_ps5_submit_packet_t *packet,
                                 const agc_ps5_dcb_t *dcb);

/*
 * Structural validation only. This intentionally does not dereference packet->addr.
 */
bool agc_ps5_submit_packet_validate(const agc_ps5_submit_packet_t *packet);

/*
 * Debug helper: print the exact ABI-shaped packet without submitting it.
 */
void agc_ps5_submit_packet_dump(const agc_ps5_submit_packet_t *packet);

/*
 * NID recorded by prosper for sceAgcDriverSubmitDcb on PS5 3.20.
 */
#define AGC_PS5_NID_SUBMIT_DCB "UglJIZjGssM"

#ifdef __cplusplus
}
#endif

#endif
