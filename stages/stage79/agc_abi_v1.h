#ifndef AGC_ABI_V1_H
#define AGC_ABI_V1_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Stage 79 ABI contract derived from static machine-code evidence.
 * Semantic names are intentionally conservative.
 */
typedef struct SceAgcSubmitCommandBufferArgs {
    uint64_t field_00; /* observed 8-byte load */
    uint32_t field_08; /* observed 4-byte load */
    uint8_t  field_0c; /* observed 1-byte load */
} SceAgcSubmitCommandBufferArgs;

_Static_assert(offsetof(SceAgcSubmitCommandBufferArgs, field_00) == 0x00, "field_00 offset");
_Static_assert(offsetof(SceAgcSubmitCommandBufferArgs, field_08) == 0x08, "field_08 offset");
_Static_assert(offsetof(SceAgcSubmitCommandBufferArgs, field_0c) == 0x0C, "field_0c offset");
_Static_assert(sizeof(SceAgcSubmitCommandBufferArgs) == 0x10, "ABI v1 packed size/alignment");

/* Direct ABI-compatible candidates proven in stages 52-56. */
int sceAgcDriverSubmitCommandBuffer(void *context,
                                     const SceAgcSubmitCommandBufferArgs *args);
int sceAgcDriverSubmitDcb(void *dcb_context,
                          const SceAgcSubmitCommandBufferArgs *args);
int sceAgcDriverAgrSubmitDcb(void *agr_context,
                             const SceAgcSubmitCommandBufferArgs *args);

/* Multi-command-buffer ABI candidate from stage 55. */
int sceAgcDriverSubmitMultiCommandBuffers(void *context,
                                          const uint64_t *field00_array,
                                          const uint32_t *field08_array,
                                          uint32_t count);

/* Additional family exports established in stage 50. */
int sceAgcDriverSubmitMultiDcbs(void *context, const void *args);
int sceAgcDriverAgrSubmitMultiDcbs(void *context, const void *args);
int sceAgcDriverSubmitAcb(void *context, const void *args);
int sceAgcDriverSubmitMultiAcbs(void *context, const void *args);

/* Known NIDs from aerolib.csv / Stage 50 extraction. */
#define SCEAGCDRIVER_NID_SubmitDcb                "UglJIZjGssM"
#define SCEAGCDRIVER_NID_AgrSubmitDcb             "AhGvpITrf4M"
#define SCEAGCDRIVER_NID_SubmitAcb                "gSRnr79F8tQ"
#define SCEAGCDRIVER_NID_SubmitCommandBuffer      "b4fpgH5ZXxQ"
#define SCEAGCDRIVER_NID_SubmitMultiCommandBuffers "Fj7r9EHzF38"
#define SCEAGCDRIVER_NID_SubmitMultiDcbs         "6UzEidRZwkg"
#define SCEAGCDRIVER_NID_AgrSubmitMultiDcbs      "+T8Xo6LtFJI"
#define SCEAGCDRIVER_NID_SubmitMultiAcbs         "HF3YllT3mXU"

#ifdef __cplusplus
}
#endif

#endif /* AGC_ABI_V1_H */
