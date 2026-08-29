#include "agc_project_v1.h"

int agcProjectSubmitCommandBufferV1(
    AgcContextV1 context,
    const AgcSubmitCommandBufferArgsV1 *args)
{
    return sceAgcDriverSubmitCommandBuffer(context, args);
}

int agcProjectSubmitDcbV1(void *args)
{
    return sceAgcDriverSubmitDcb(args);
}

int agcProjectAgrSubmitDcbV1(void *args)
{
    return sceAgcDriverAgrSubmitDcb(args);
}

int agcProjectSubmitMultiCommandBuffersV1(
    AgcContextV1 context,
    const uint64_t *field_00_array,
    const uint32_t *field_08_array,
    uint32_t count)
{
    return sceAgcDriverSubmitMultiCommandBuffers(
        context, field_00_array, field_08_array, count);
}

int agcProjectSubmitAcbV1(void *args)
{
    return sceAgcDriverSubmitAcb(args);
}

int agcProjectSubmitMultiAcbsV1(void *args)
{
    return sceAgcDriverSubmitMultiAcbs(args);
}

int agcProjectSubmitMultiDcbsV1(void *args)
{
    return sceAgcDriverSubmitMultiDcbs(args);
}

int agcProjectAgrSubmitMultiDcbsV1(void *args)
{
    return sceAgcDriverAgrSubmitMultiDcbs(args);
}