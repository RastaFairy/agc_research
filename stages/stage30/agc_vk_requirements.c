#define _GNU_SOURCE
#include "agc_vk_requirements.h"
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef int32_t VkResult;
typedef uint32_t VkFlags;
typedef uint32_t VkBool32;
typedef uint32_t VkFormat;
typedef uint32_t VkFormatFeatureFlags;
typedef uint32_t VkMemoryPropertyFlags;
typedef uint64_t VkDeviceSize;
typedef struct VkInstance_T *VkInstance;
typedef struct VkPhysicalDevice_T *VkPhysicalDevice;
typedef struct VkAllocationCallbacks VkAllocationCallbacks;

typedef struct { uint32_t queueFlags; uint32_t queueCount; uint32_t timestampValidBits; uint32_t minImageTransferGranularity[3]; } VkQueueFamilyProperties;
typedef struct { VkFormatFeatureFlags linearTilingFeatures; VkFormatFeatureFlags optimalTilingFeatures; VkFormatFeatureFlags bufferFeatures; } VkFormatProperties;
typedef struct { uint32_t propertyFlags; uint32_t heapIndex; } VkMemoryType;
typedef struct { uint32_t memoryTypeCount; VkMemoryType memoryTypes[32]; } VkPhysicalDeviceMemoryProperties;

typedef void (*PFN_vkGetPhysicalDeviceQueueFamilyProperties)(VkPhysicalDevice,uint32_t*,VkQueueFamilyProperties*);
typedef void (*PFN_vkGetPhysicalDeviceFormatProperties)(VkPhysicalDevice,VkFormat,VkFormatProperties*);
typedef void (*PFN_vkGetPhysicalDeviceMemoryProperties)(VkPhysicalDevice,VkPhysicalDeviceMemoryProperties*);
typedef void *(*PFN_vkGetInstanceProcAddr)(VkInstance,const char*);

static char g_err[256];
static void seterr(const char *s){snprintf(g_err,sizeof g_err,"%s",s?s:"unknown");}
const char *agc_vk_caps_last_error(void){return g_err;}

#define VK_QUEUE_GRAPHICS_BIT 0x00000001u
#define VK_QUEUE_COMPUTE_BIT  0x00000002u
#define VK_FORMAT_R8G8B8A8_UNORM 37u
#define VK_FORMAT_FEATURE_TRANSFER_DST_BIT 0x00004000u
#define VK_FORMAT_FEATURE_TRANSFER_SRC_BIT 0x00008000u
#define VK_FORMAT_FEATURE_COLOR_ATTACHMENT_BIT 0x00000100u
#define VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT 0x00000001u
#define VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT 0x00000002u

int agc_vk_query_min_caps(void *instance, void *physical_device, agc_vk_caps_t *caps){
    if(!instance||!physical_device||!caps){seterr("null input");return -1;}
    memset(caps,0,sizeof(*caps));
    PFN_vkGetInstanceProcAddr gip=NULL;
    void *loader=dlopen("libvulkan.so.1",RTLD_NOW|RTLD_LOCAL);
    if(!loader){seterr(dlerror());return -2;}
    gip=(PFN_vkGetInstanceProcAddr)dlsym(loader,"vkGetInstanceProcAddr");
    if(!gip){seterr("vkGetInstanceProcAddr missing");dlclose(loader);return -3;}
    PFN_vkGetPhysicalDeviceQueueFamilyProperties qf=(PFN_vkGetPhysicalDeviceQueueFamilyProperties)gip((VkInstance)instance,"vkGetPhysicalDeviceQueueFamilyProperties");
    PFN_vkGetPhysicalDeviceFormatProperties fp=(PFN_vkGetPhysicalDeviceFormatProperties)gip((VkInstance)instance,"vkGetPhysicalDeviceFormatProperties");
    PFN_vkGetPhysicalDeviceMemoryProperties mp=(PFN_vkGetPhysicalDeviceMemoryProperties)gip((VkInstance)instance,"vkGetPhysicalDeviceMemoryProperties");
    if(!qf||!fp||!mp){seterr("required capability queries missing");dlclose(loader);return -4;}
    uint32_t n=0; qf((VkPhysicalDevice)physical_device,&n,NULL); if(!n){seterr("no queue families");dlclose(loader);return -5;}
    VkQueueFamilyProperties props[32]; if(n>32)n=32; qf((VkPhysicalDevice)physical_device,&n,props);
    for(uint32_t i=0;i<n;i++){
        if(props[i].queueCount && (props[i].queueFlags&VK_QUEUE_GRAPHICS_BIT)){
            caps->has_graphics_queue=true; caps->graphics_queue_family=i;
        }
        if(props[i].queueCount && (props[i].queueFlags&VK_QUEUE_COMPUTE_BIT)) caps->has_compute_queue=true;
    }
    VkFormatProperties r8; memset(&r8,0,sizeof r8); fp((VkPhysicalDevice)physical_device,VK_FORMAT_R8G8B8A8_UNORM,&r8);
    caps->rgba8_color_attachment = (r8.optimalTilingFeatures & VK_FORMAT_FEATURE_COLOR_ATTACHMENT_BIT)!=0;
    caps->rgba8_transfer_src = (r8.optimalTilingFeatures & VK_FORMAT_FEATURE_TRANSFER_SRC_BIT)!=0;
    caps->rgba8_transfer_dst = (r8.optimalTilingFeatures & VK_FORMAT_FEATURE_TRANSFER_DST_BIT)!=0;
    VkPhysicalDeviceMemoryProperties mem; memset(&mem,0,sizeof mem); mp((VkPhysicalDevice)physical_device,&mem);
    for(uint32_t i=0;i<mem.memoryTypeCount && i<32;i++){
        if(mem.memoryTypes[i].propertyFlags&VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) caps->host_visible_memory=true;
        if(mem.memoryTypes[i].propertyFlags&VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT) caps->device_local_memory=true;
    }
    dlclose(loader); seterr("ok"); return 0;
}
