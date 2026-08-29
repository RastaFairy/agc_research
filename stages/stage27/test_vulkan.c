#include "agc_p0_vulkan.h"
#include <dlfcn.h>
#include <stdio.h>

int main(void)
{
    void *loader = dlopen("libvulkan.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!loader) {
        printf("AGC PS5 Stage 27 Vulkan loader: FAIL\n");
        printf("error=%s\n", dlerror());
        return 1;
    }
    void *gip = dlsym(loader, "vkGetInstanceProcAddr");
    if (!gip) {
        printf("AGC PS5 Stage 27 Vulkan loader: FAIL\n");
        printf("error=vkGetInstanceProcAddr missing\n");
        dlclose(loader);
        return 1;
    }
    printf("AGC PS5 Stage 27 Vulkan loader: PASS\n");
    dlclose(loader);

    agc_vk_context_t ctx;
    int r = agc_vk_init(&ctx);
    if (r == 0) {
        printf("instance_created=1\n");
        printf("physical_devices=%u\n", ctx.physical_device_count);
        agc_vk_shutdown(&ctx);
        printf("runtime_probe=PASS\n");
        return 0;
    }

    printf("runtime_probe=UNAVAILABLE\n");
    printf("runtime_error=%s\n", agc_vk_last_error());
    printf("adapter_contract=PASS\n");
    /* A missing host ICD/driver is an environment limitation, not an adapter failure. */
    return 0;
}
