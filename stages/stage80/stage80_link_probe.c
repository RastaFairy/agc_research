#include "agc_project_v1.h"

int stage80_link_probe(AgcContextV1 context, AgcSubmitCommandBufferArgsV1 *args)
{
    int rc = agcProjectSubmitCommandBufferV1(context, args);
    rc += agcProjectSubmitDcbV1(args);
    rc += agcProjectAgrSubmitDcbV1(args);
    rc += agcProjectSubmitMultiCommandBuffersV1(
        context, &args->field_00, &args->field_08, 1);
    return rc;
}