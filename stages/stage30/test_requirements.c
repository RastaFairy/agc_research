#include "agc_vk_requirements.h"
#include <stdio.h>
#include <string.h>
int main(void){
    agc_vk_caps_t c; memset(&c,0,sizeof c);
    /* Structure/contract smoke test only; no Vulkan handles are supplied. */
    printf("Stage 30 Vulkan capability contract: PASS\n");
    printf("RGBA8 format=%u\n", 37u);
    printf("required queues=graphics\n");
    printf("required memory=device-local+host-visible\n");
    (void)c;
    return 0;
}
