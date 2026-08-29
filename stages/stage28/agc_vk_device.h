#ifndef AGC_VK_DEVICE_H
#define AGC_VK_DEVICE_H
#include <stdint.h>
#include <stdbool.h>
typedef struct agc_vk_device_context {
    void *loader;
    void *instance;
    void *physical_device;
    void *device;
    void *queue;
    uint32_t graphics_queue_family;
    bool has_graphics_queue;
} agc_vk_device_context_t;
int agc_vk_device_init(agc_vk_device_context_t *ctx);
void agc_vk_device_shutdown(agc_vk_device_context_t *ctx);
const char *agc_vk_device_last_error(void);
#endif
