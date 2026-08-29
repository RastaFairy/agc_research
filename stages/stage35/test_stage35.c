#include "agc_ps5_submit_boundary.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

int main(void)
{
    uint32_t dcb[4] = { 0xC0001000u, 0x00000000u, 0x00000000u, 0xC0001000u };
    agc_ps5_submit_packet_t p;

    if (agc_ps5_submit_packet_init(&p, dcb, 4) != 0)
        return 1;

    if (sizeof(p) != 16 || p.addr != dcb || p.dw_num != 4 || p.reserved != 0)
        return 2;

    if (strcmp(AGC_PS5_SUBMIT_DCB_NAME, "sceAgcDriverSubmitDcb") != 0)
        return 3;
    if (strcmp(AGC_PS5_SUBMIT_DCB_NID, "UglJIZjGssM") != 0)
        return 4;
    if (strcmp(AGC_PS5_AGR_SUBMIT_NID, "AhGvpITrf4M") != 0)
        return 5;

    if (agc_ps5_submit_native_disabled(&p) != 1)
        return 6;

    printf("Stage 35 native submit boundary: PASS\n");
    printf("submit_name=%s\n", AGC_PS5_SUBMIT_DCB_NAME);
    printf("submit_nid=%s\n", AGC_PS5_SUBMIT_DCB_NID);
    printf("agr_submit_nid=%s\n", AGC_PS5_AGR_SUBMIT_NID);
    printf("packet_size=%zu\n", sizeof(p));
    printf("native_call=DISABLED_UNVERIFIED\n");
    return 0;
}
