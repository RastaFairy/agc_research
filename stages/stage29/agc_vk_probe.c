#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Minimal Vulkan ABI declarations used only for loader probing. */
typedef uint32_t VkFlags;
typedef uint32_t VkBool32;
typedef int32_t VkResult;
typedef struct VkInstance_T* VkInstance;
typedef struct VkPhysicalDevice_T* VkPhysicalDevice;
typedef struct VkDevice_T* VkDevice;
typedef struct VkQueue_T* VkQueue;
typedef void (*PFN_vkVoidFunction)(void);
typedef PFN_vkVoidFunction (*PFN_vkGetInstanceProcAddr)(VkInstance, const char*);

typedef enum VkStructureType {
    VK_STRUCTURE_TYPE_APPLICATION_INFO = 0,
    VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO = 1,
    VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO = 2,
    VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO = 3
} VkStructureType;

typedef struct VkApplicationInfo {
    VkStructureType sType;
    const void *pNext;
    const char *pApplicationName;
    uint32_t applicationVersion;
    const char *pEngineName;
    uint32_t engineVersion;
    uint32_t apiVersion;
} VkApplicationInfo;

typedef struct VkInstanceCreateInfo {
    VkStructureType sType;
    const void *pNext;
    VkFlags flags;
    const VkApplicationInfo *pApplicationInfo;
    uint32_t enabledLayerCount;
    const char * const *ppEnabledLayerNames;
    uint32_t enabledExtensionCount;
    const char * const *ppEnabledExtensionNames;
} VkInstanceCreateInfo;

typedef struct VkDeviceQueueCreateInfo {
    VkStructureType sType;
    const void *pNext;
    VkFlags flags;
    uint32_t queueFamilyIndex;
    uint32_t queueCount;
    const float *pQueuePriorities;
} VkDeviceQueueCreateInfo;

typedef struct VkDeviceCreateInfo {
    VkStructureType sType;
    const void *pNext;
    VkFlags flags;
    uint32_t queueCreateInfoCount;
    const VkDeviceQueueCreateInfo *pQueueCreateInfos;
    uint32_t enabledLayerCount;
    const char * const *ppEnabledLayerNames;
    uint32_t enabledExtensionCount;
    const char * const *ppEnabledExtensionNames;
    const void *pEnabledFeatures;
} VkDeviceCreateInfo;

typedef VkResult (*PFN_vkCreateInstance)(const VkInstanceCreateInfo*, const void*, VkInstance*);
typedef void (*PFN_vkDestroyInstance)(VkInstance, const void*);
typedef VkResult (*PFN_vkEnumeratePhysicalDevices)(VkInstance, uint32_t*, VkPhysicalDevice*);
typedef VkResult (*PFN_vkCreateDevice)(VkPhysicalDevice, const VkDeviceCreateInfo*, const void*, VkDevice*);
typedef void (*PFN_vkDestroyDevice)(VkDevice, const void*);
typedef void (*PFN_vkGetDeviceQueue)(VkDevice, uint32_t, uint32_t, VkQueue*);

#define VK_SUCCESS 0
#define VK_API_VERSION_1_0 ((1u<<22)|(0u<<12)|0u)

typedef struct loader {
    void *so;
    PFN_vkGetInstanceProcAddr gip;
    PFN_vkCreateInstance create_instance;
    PFN_vkDestroyInstance destroy_instance;
    PFN_vkEnumeratePhysicalDevices enumerate_physical_devices;
    PFN_vkCreateDevice create_device;
    PFN_vkGetDeviceQueue get_device_queue;
    PFN_vkDestroyDevice destroy_device;
} loader;

static void *sym(void *so, const char *name) { return dlsym(so, name); }
static void *instsym(loader *l, const char *name) { return (void*)l->gip(NULL, name); }

int main(void) {
    loader l = {0};
    l.so = dlopen("libvulkan.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!l.so) { puts("loader=UNAVAILABLE"); return 2; }
    l.gip = (PFN_vkGetInstanceProcAddr)sym(l.so, "vkGetInstanceProcAddr");
    if (!l.gip) { puts("get_instance_proc_addr=UNAVAILABLE"); return 3; }
    l.create_instance = (PFN_vkCreateInstance)instsym(&l, "vkCreateInstance");
    if (!l.create_instance) { puts("vkCreateInstance=UNAVAILABLE"); return 4; }

    VkApplicationInfo app = {VK_STRUCTURE_TYPE_APPLICATION_INFO, NULL, "agc-stage29", 1, "agc", 1, VK_API_VERSION_1_0};
    VkInstanceCreateInfo ci = {VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO, NULL, 0, &app, 0, NULL, 0, NULL};
    VkInstance instance = NULL;
    VkResult r = l.create_instance(&ci, NULL, &instance);
    if (r != VK_SUCCESS || !instance) {
        printf("instance=UNAVAILABLE result=%d\n", r);
        return 0;
    }
    puts("instance=PASS");

    l.destroy_instance = (PFN_vkDestroyInstance)instsym(&l, "vkDestroyInstance");
    l.enumerate_physical_devices = (PFN_vkEnumeratePhysicalDevices)instsym(&l, "vkEnumeratePhysicalDevices");
    l.create_device = (PFN_vkCreateDevice)instsym(&l, "vkCreateDevice");
    l.get_device_queue = (PFN_vkGetDeviceQueue)instsym(&l, "vkGetDeviceQueue");
    if (!l.destroy_instance || !l.enumerate_physical_devices || !l.create_device || !l.get_device_queue) {
        puts("device_entrypoints=UNAVAILABLE");
        l.destroy_instance(instance, NULL); return 5;
    }

    uint32_t count = 0;
    r = l.enumerate_physical_devices(instance, &count, NULL);
    if (r != VK_SUCCESS || count == 0) {
        printf("physical_device=UNAVAILABLE result=%d count=%u\n", r, count);
        l.destroy_instance(instance, NULL); return 0;
    }

    VkPhysicalDevice pd = NULL;
    r = l.enumerate_physical_devices(instance, &count, &pd);
    if (r != VK_SUCCESS || !pd) {
        printf("physical_device=UNAVAILABLE result=%d\n", r);
        l.destroy_instance(instance, NULL); return 0;
    }
    puts("physical_device=PASS");

    /* Queue-family discovery is intentionally deferred until full Vulkan structs are vendored. */
    puts("queue_family_discovery=DEFERRED");
    puts("offscreen_pipeline=CONTRACT_ONLY");
    puts("shader_spirv=UNAVAILABLE");

    l.destroy_instance(instance, NULL);
    dlclose(l.so);
    return 0;
}
