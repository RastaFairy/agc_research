#ifndef AGC_PS5_SUBMIT_BOUNDARY_H
#define AGC_PS5_SUBMIT_BOUNDARY_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct agc_ps5_submit_packet {
    const uint32_t *addr;
    uint32_t dw_num;
    uint32_t reserved;
} agc_ps5_submit_packet_t;

_Static_assert(sizeof(agc_ps5_submit_packet_t) == 16, "experimental packet layout");
_Static_assert(offsetof(agc_ps5_submit_packet_t, addr) == 0, "addr offset");
_Static_assert(offsetof(agc_ps5_submit_packet_t, dw_num) == 8, "dw_num offset");
_Static_assert(offsetof(agc_ps5_submit_packet_t, reserved) == 12, "reserved offset");

#define AGC_PS5_SUBMIT_DCB_NAME "sceAgcDriverSubmitDcb"
#define AGC_PS5_SUBMIT_DCB_NID  "UglJIZjGssM"
#define AGC_PS5_AGR_SUBMIT_NAME "sceAgcDriverAgrSubmitDcb"
#define AGC_PS5_AGR_SUBMIT_NID  "AhGvpITrf4M"

int agc_ps5_submit_packet_init(
    agc_ps5_submit_packet_t *out,
    const uint32_t *dcb,
    size_t dwords);

/*
 * Returns a symbol address supplied by the platform-specific resolver.
 * The address is opaque by design. This layer does not invent a C prototype.
 */
void *agc_ps5_submit_symbol_address(void *resolved_symbol);

/*
 * Deliberately disabled unless a future stage supplies a verified native ABI.
 */
int agc_ps5_submit_native_disabled(const agc_ps5_submit_packet_t *packet);

#ifdef __cplusplus
}
#endif

#endif
