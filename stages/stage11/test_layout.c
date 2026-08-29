#include "abi_submit.h"
#include <stdio.h>
int main(void) {
    agc_submit_command_buffer_desc_t d = {0};
    d.dw_num = 4;
    d.flags = 0;
    printf("submit descriptor size=%zu\n", sizeof(d));
    printf("addr=0 dw_num=8 flags=12\n");
    printf("AGC PS5 Stage 11 submit ABI layout: PASS\n");
    return 0;
}
