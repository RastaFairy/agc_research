#ifndef AGC_PROJECT_V1_H
#define AGC_PROJECT_V1_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ABI v1 record recovered by static analysis.
 * Exact public semantic field names are intentionally not claimed.
 */
typedef struct AgcSubmitCommandBufferArgsV1 {
    uint64_t field_00;
    uint32_t field_08;
    uint8_t  field_0c;
} AgcSubmitCommandBufferArgsV1;

typedef void *AgcContextV1;

/* Direct ABI v1 entrypoint candidate. */
int agcProjectSubmitCommandBufferV1(
    AgcContextV1 context,
    const AgcSubmitCommandBufferArgsV1 *args);

/* Wrapper entrypoints: the recovered wrapper ABI takes one caller argument. */
int agcProjectSubmitDcbV1(void *args);
int agcProjectAgrSubmitDcbV1(void *args);

/* Multi entrypoint ABI candidate recovered from machine-code register usage. */
int agcProjectSubmitMultiCommandBuffersV1(
    AgcContextV1 context,
    const uint64_t *field_00_array,
    const uint32_t *field_08_array,
    uint32_t count);

int agcProjectSubmitAcbV1(void *args);
int agcProjectSubmitMultiAcbsV1(void *args);
int agcProjectSubmitMultiDcbsV1(void *args);
int agcProjectAgrSubmitMultiDcbsV1(void *args);

/* Low-level recovered symbols. */
int sceAgcDriverSubmitCommandBuffer(AgcContextV1, const AgcSubmitCommandBufferArgsV1 *);
int sceAgcDriverSubmitDcb(void *args);
int sceAgcDriverAgrSubmitDcb(void *args);
int sceAgcDriverSubmitMultiCommandBuffers(AgcContextV1, const uint64_t *, const uint32_t *, uint32_t);
int sceAgcDriverSubmitAcb(void *args);
int sceAgcDriverSubmitMultiAcbs(void *args);
int sceAgcDriverSubmitMultiDcbs(void *args);
int sceAgcDriverAgrSubmitMultiDcbs(void *args);

#ifdef __cplusplus
}
#endif

#endif