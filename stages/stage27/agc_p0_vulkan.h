#ifndef AGC_P0_VULKAN_H
#define AGC_P0_VULKAN_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct agc_vk_context {
    void *loader;
    void *instance;
    uint32_t physical_device_count;
    uint32_t queue_family_count;
} agc_vk_context_t;

int agc_vk_init(agc_vk_context_t *ctx);
void agc_vk_shutdown(agc_vk_context_t *ctx);
int agc_vk_probe_devices(const agc_vk_context_t *ctx, uint32_t *count_out);
const char *agc_vk_last_error(void);

#ifdef __cplusplus
}
#endif

#endif
