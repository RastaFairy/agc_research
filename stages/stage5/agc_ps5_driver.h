#ifndef AGC_PS5_DRIVER_H
#define AGC_PS5_DRIVER_H

#include <stdbool.h>
#include <stdint.h>

#include "agc_ps5_dcb.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct agc_ps5_submit_packet {
    uint32_t *addr;
    uint32_t  dw_num;
    uint8_t   pad[4];
} agc_ps5_submit_packet_t;

_Static_assert(sizeof(agc_ps5_submit_packet_t) == 16, "Submit packet must be 16 bytes");
_Static_assert(_Alignof(agc_ps5_submit_packet_t) >= _Alignof(void *), "pointer alignment mismatch");

/* FW 3.20 export NID for sceAgcDriverSubmitDcb. */
#define AGC_PS5_SCE_AGC_DRIVER_SUBMIT_DCB_NID "UglJIZjGssM"
#define AGC_PS5_SCE_AGC_DRIVER_LIB "libSceAgcDriver"

/* This return type/argument shape is a reverse-engineered ABI model, not a Sony header. */
typedef int (*agc_ps5_submit_dcb_fn)(const agc_ps5_submit_packet_t *packet);

/* Pure packet construction; safe on host and PS5. */
bool agc_ps5_make_submit_packet(const agc_ps5_dcb_t *dcb,
                                agc_ps5_submit_packet_t *packet);

/* Optional PS5 runtime resolver. Returns false on non-PS5 or unresolved symbol. */
bool agc_ps5_resolve_submit_dcb(agc_ps5_submit_dcb_fn *out_fn);

/* Calls the resolved entry point; never resolves or invents another NID. */
int agc_ps5_submit_dcb(agc_ps5_submit_dcb_fn fn,
                       const agc_ps5_submit_packet_t *packet);

#ifdef __cplusplus
}
#endif

#endif
