#define _GNU_SOURCE
#include "agc_p0_vulkan.h"

#include <dlfcn.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* Minimal Vulkan declarations sufficient for loader/instance/device probing.
 * This deliberately avoids depending on vulkan.h in the host environment. */
typedef uint32_t VkFlags;
typedef uint32_t VkBool32;
typedef uint64_t VkDeviceSize;
typedef int32_t VkResult;
typedef struct VkInstance_T *VkInstance;
typedef struct VkPhysicalDevice_T *VkPhysicalDevice;
typedef struct VkAllocationCallbacks VkAllocationCallbacks;
typedef struct VkInstanceCreateInfo VkInstanceCreateInfo;
typedef struct VkApplicationInfo VkApplicationInfo;
typedef struct VkPhysicalDeviceProperties VkPhysicalDeviceProperties;

enum { VK_SUCCESS = 0 };
enum { VK_API_VERSION_1_0 = 1 << 22 };

typedef void (*PFN_vkVoidFunction)(void);
typedef PFN_vkVoidFunction (*PFN_vkGetInstanceProcAddr)(VkInstance, const char *);
typedef VkResult (*PFN_vkCreateInstance)(const VkInstanceCreateInfo *, const VkAllocationCallbacks *, VkInstance *);
typedef void (*PFN_vkDestroyInstance)(VkInstance, const VkAllocationCallbacks *);
typedef VkResult (*PFN_vkEnumeratePhysicalDevices)(VkInstance, uint32_t *, VkPhysicalDevice *);
typedef void (*PFN_vkGetPhysicalDeviceProperties)(VkPhysicalDevice, VkPhysicalDeviceProperties *);
typedef void (*PFN_vkGetPhysicalDeviceQueueFamilyProperties)(VkPhysicalDevice, uint32_t *, void *);

struct VkApplicationInfo {
    int sType;
    const void *pNext;
    const char *pApplicationName;
    uint32_t applicationVersion;
    const char *pEngineName;
    uint32_t engineVersion;
    uint32_t apiVersion;
};
struct VkInstanceCreateInfo {
    int sType;
    const void *pNext;
    VkFlags flags;
    const VkApplicationInfo *pApplicationInfo;
    uint32_t enabledLayerCount;
    const char * const *ppEnabledLayerNames;
    uint32_t enabledExtensionCount;
    const char * const *ppEnabledExtensionNames;
};

struct VkPhysicalDeviceProperties {
    uint32_t apiVersion, driverVersion, vendorID, deviceID, deviceType;
    char deviceName[256];
    uint8_t opaque[1024];
};

static char g_error[256];
static PFN_vkDestroyInstance g_destroy_instance;
static PFN_vkEnumeratePhysicalDevices g_enumerate_devices;
static PFN_vkGetPhysicalDeviceQueueFamilyProperties g_get_queue_families;

static void set_error(const char *msg)
{
    snprintf(g_error, sizeof(g_error), "%s", msg ? msg : "unknown error");
}

const char *agc_vk_last_error(void) { return g_error; }

int agc_vk_init(agc_vk_context_t *ctx)
{
    if (!ctx) { set_error("null context"); return -1; }
    memset(ctx, 0, sizeof(*ctx));

    void *loader = dlopen("libvulkan.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!loader) { set_error(dlerror()); return -2; }

    PFN_vkGetInstanceProcAddr gip = (PFN_vkGetInstanceProcAddr)dlsym(loader, "vkGetInstanceProcAddr");
    if (!gip) { set_error("vkGetInstanceProcAddr not found"); dlclose(loader); return -3; }

    PFN_vkCreateInstance create_instance = (PFN_vkCreateInstance)gip(NULL, "vkCreateInstance");
    if (!create_instance) { set_error("vkCreateInstance not found"); dlclose(loader); return -4; }

    VkApplicationInfo app = {
        0, NULL, "AGC-P0", 1, "AGC-P0", 1,
        (1u << 22) /* VK_API_VERSION_1_0 */
    };
    VkInstanceCreateInfo ci = {
        1, NULL, 0, &app, 0, NULL, 0, NULL
    };
    VkInstance instance = NULL;
    VkResult r = create_instance(&ci, NULL, &instance);
    if (r != VK_SUCCESS || !instance) {
        char buf[64]; snprintf(buf, sizeof(buf), "vkCreateInstance failed: %d", r);
        set_error(buf); dlclose(loader); return -5;
    }

    ctx->loader = loader;
    ctx->instance = instance;
    g_destroy_instance = (PFN_vkDestroyInstance)gip(instance, "vkDestroyInstance");
    g_enumerate_devices = (PFN_vkEnumeratePhysicalDevices)gip(instance, "vkEnumeratePhysicalDevices");
    g_get_queue_families = (PFN_vkGetPhysicalDeviceQueueFamilyProperties)gip(instance, "vkGetPhysicalDeviceQueueFamilyProperties");
    if (!g_destroy_instance || !g_enumerate_devices || !g_get_queue_families) {
        set_error("required Vulkan instance functions missing");
        agc_vk_shutdown(ctx);
        return -6;
    }
    return agc_vk_probe_devices(ctx, &ctx->physical_device_count);
}

int agc_vk_probe_devices(const agc_vk_context_t *ctx, uint32_t *count_out)
{
    if (!ctx || !ctx->instance || !g_enumerate_devices || !count_out) { set_error("invalid probe state"); return -1; }
    uint32_t count = 0;
    VkResult r = g_enumerate_devices((VkInstance)ctx->instance, &count, NULL);
    if (r != VK_SUCCESS) { char b[64]; snprintf(b, sizeof(b), "vkEnumeratePhysicalDevices(count) failed: %d", r); set_error(b); return -2; }
    *count_out = count;
    return 0;
}

void agc_vk_shutdown(agc_vk_context_t *ctx)
{
    if (!ctx) return;
    if (ctx->instance && g_destroy_instance)
        g_destroy_instance((VkInstance)ctx->instance, NULL);
    if (ctx->loader) dlclose(ctx->loader);
    memset(ctx, 0, sizeof(*ctx));
    g_destroy_instance = NULL;
    g_enumerate_devices = NULL;
    g_get_queue_families = NULL;
}
