#include "agc_project_v1.h"

/*
 * Stage 81 end-to-end probe.
 *
 * El probe no se ejecuta.
 * Su finalidad es forzar referencias a las ocho entradas p?blicas
 * agcProject*V1 para que el linker deba resolver la cadena completa:
 *
 *   agcProject*V1
 *       -> sceAgcDriver* recuperados en Stage 79
 */
int stage81_end_to_end_probe(
    AgcContextV1 context,
    AgcSubmitCommandBufferArgsV1 *args,
    const uint64_t *field00_array,
    const uint32_t *field08_array)
{
    int rc = 0;

    rc += agcProjectSubmitCommandBufferV1(context, args);
    rc += agcProjectSubmitDcbV1(args);
    rc += agcProjectAgrSubmitDcbV1(args);
    rc += agcProjectSubmitMultiCommandBuffersV1(
        context, field00_array, field08_array, 1
    );
    rc += agcProjectSubmitAcbV1(args);
    rc += agcProjectSubmitMultiAcbsV1(args);
    rc += agcProjectSubmitMultiDcbsV1(args);
    rc += agcProjectAgrSubmitMultiDcbsV1(args);

    return rc;
}