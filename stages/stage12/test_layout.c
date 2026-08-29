#include "packet_layout.h"
#include <stdio.h>
int main(void){
    printf("Stage 12 packet layout: PASS\n");
    printf("size=%zu addr=%zu dw_num=%zu byte_0c=%zu\n",
           sizeof(agc_submit_packet_observed_t),
           offsetof(agc_submit_packet_observed_t, addr),
           offsetof(agc_submit_packet_observed_t, dw_num),
           offsetof(agc_submit_packet_observed_t, byte_0c));
    return 0;
}
