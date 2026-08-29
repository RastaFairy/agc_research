#ifndef AGC_VK_REQUIREMENTS_H
#define AGC_VK_REQUIREMENTS_H
#include <stdint.h>
#include <stdbool.h>

typedef struct agc_vk_caps {
    uint32_t graphics_queue_family;
    bool has_graphics_queue;
    bool has_compute_queue;
    bool rgba8_color_attachment;
    bool rgba8_transfer_src;
    bool rgba8_transfer_dst;
    bool host_visible_memory;
    bool device_local_memory;
} agc_vk_caps_t;

int agc_vk_query_min_caps(void *instance, void *physical_device, agc_vk_caps_t *caps);
const char *agc_vk_caps_last_error(void);

#endif
