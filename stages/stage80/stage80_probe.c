#include "agc_project_v1.h"

static AgcProjectSubmitRecord g_record = {0};

int stage80_probe(void *context) {
    int rc = 0;
    rc += agcProjectSubmitCommandBuffer(context, &g_record);
    rc += agcProjectSubmitDcb(context, &g_record);
    rc += agcProjectAgrSubmitDcb(context, &g_record);
    return rc;
}

int stage80_multi_probe(
    void *context,
    const uint64_t *a0,
    const uint32_t *a8,
    uint32_t count,
    const void *args
) {
    int rc = 0;
    rc += agcProjectSubmitMultiCommandBuffers(context, a0, a8, count);
    rc += agcProjectSubmitMultiDcbs(context, args);
    rc += agcProjectAgrSubmitMultiDcbs(context, args);
    rc += agcProjectSubmitAcb(context, args);
    rc += agcProjectSubmitMultiAcbs(context, args);
    return rc;
}
