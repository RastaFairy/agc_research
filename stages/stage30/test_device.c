#include "agc_vk_device.h"
#include <stdio.h>
int main(void){agc_vk_device_context_t c; int r=agc_vk_device_init(&c); if(r==0){printf("Stage 28 Vulkan device: PASS\n");printf("graphics_queue_family=%u\n",c.graphics_queue_family);agc_vk_device_shutdown(&c);return 0;} printf("Stage 28 Vulkan device: UNAVAILABLE\n");printf("probe=%s\n",agc_vk_device_last_error());agc_vk_device_shutdown(&c);return 0;}
