#define _GNU_SOURCE
#include "agc_vk_device.h"
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int32_t VkResult; typedef uint32_t VkFlags; typedef uint32_t VkBool32; typedef uint64_t VkDeviceSize;
typedef struct VkInstance_T *VkInstance; typedef struct VkPhysicalDevice_T *VkPhysicalDevice; typedef struct VkDevice_T *VkDevice; typedef struct VkQueue_T *VkQueue;
typedef struct VkAllocationCallbacks VkAllocationCallbacks;
typedef void (*PFN_vkVoidFunction)(void); typedef PFN_vkVoidFunction (*PFN_vkGetInstanceProcAddr)(VkInstance,const char*);
typedef VkResult (*PFN_vkCreateInstance)(const void*,const VkAllocationCallbacks*,VkInstance*);
typedef void (*PFN_vkDestroyInstance)(VkInstance,const VkAllocationCallbacks*);
typedef VkResult (*PFN_vkEnumeratePhysicalDevices)(VkInstance,uint32_t*,VkPhysicalDevice*);
typedef void (*PFN_vkGetPhysicalDeviceQueueFamilyProperties)(VkPhysicalDevice,uint32_t*,void*);
typedef VkResult (*PFN_vkCreateDevice)(VkPhysicalDevice,const void*,const VkAllocationCallbacks*,VkDevice*);
typedef void (*PFN_vkDestroyDevice)(VkDevice,const VkAllocationCallbacks*);
typedef void (*PFN_vkGetDeviceQueue)(VkDevice,uint32_t,uint32_t,VkQueue*);

typedef struct { uint32_t sType; const void* pNext; uint32_t flags; const void* pApplicationInfo; uint32_t enabledLayerCount; const char* const* ppEnabledLayerNames; uint32_t enabledExtensionCount; const char* const* ppEnabledExtensionNames; } VkInstanceCreateInfo;
typedef struct { uint32_t sType; const void* pNext; uint32_t flags; uint32_t queueFamilyIndex; uint32_t queueCount; const float* pQueuePriorities; } VkDeviceQueueCreateInfo;
typedef struct { uint32_t sType; const void* pNext; uint32_t flags; uint32_t queueCreateInfoCount; const VkDeviceQueueCreateInfo* pQueueCreateInfos; uint32_t enabledLayerCount; const char* const* ppEnabledLayerNames; uint32_t enabledExtensionCount; const char* const* ppEnabledExtensionNames; const void* pEnabledFeatures; } VkDeviceCreateInfo;
typedef struct { uint32_t queueFlags; uint32_t queueCount; uint32_t timestampValidBits; uint32_t minImageTransferGranularity[3]; } VkQueueFamilyProperties;
static char errbuf[256];
static PFN_vkDestroyInstance pDestroyInstance; static PFN_vkEnumeratePhysicalDevices pEnumPhys; static PFN_vkGetPhysicalDeviceQueueFamilyProperties pGetQF; static PFN_vkCreateDevice pCreateDevice; static PFN_vkDestroyDevice pDestroyDevice; static PFN_vkGetDeviceQueue pGetQueue;
static void err(const char*s){snprintf(errbuf,sizeof(errbuf),"%s",s?s:"unknown");}
const char *agc_vk_device_last_error(void){return errbuf;}
int agc_vk_device_init(agc_vk_device_context_t *ctx){
 if(!ctx){err("null context");return -1;} memset(ctx,0,sizeof(*ctx));
 void*loader=dlopen("libvulkan.so.1",RTLD_NOW|RTLD_LOCAL); if(!loader){err(dlerror());return -2;}
 PFN_vkGetInstanceProcAddr gip=(PFN_vkGetInstanceProcAddr)dlsym(loader,"vkGetInstanceProcAddr"); if(!gip){err("vkGetInstanceProcAddr missing");dlclose(loader);return -3;}
 PFN_vkCreateInstance ci=(PFN_vkCreateInstance)gip(NULL,"vkCreateInstance"); if(!ci){err("vkCreateInstance missing");dlclose(loader);return -4;}
 struct App{uint32_t sType;const void*pNext;const char*pApp;uint32_t appVer;const char*pEng;uint32_t engVer;uint32_t apiVer;} app={0,NULL,"AGC-P0",1,"AGC-P0",1,1u<<22};
 VkInstanceCreateInfo ici={1,NULL,0,&app,0,NULL,0,NULL}; VkInstance inst=NULL; VkResult r=ci(&ici,NULL,&inst); if(r!=0||!inst){char b[64];snprintf(b,sizeof b,"vkCreateInstance failed: %d",r);err(b);dlclose(loader);return -5;}
 pDestroyInstance=(PFN_vkDestroyInstance)gip(inst,"vkDestroyInstance"); pEnumPhys=(PFN_vkEnumeratePhysicalDevices)gip(inst,"vkEnumeratePhysicalDevices"); pGetQF=(PFN_vkGetPhysicalDeviceQueueFamilyProperties)gip(inst,"vkGetPhysicalDeviceQueueFamilyProperties"); pCreateDevice=(PFN_vkCreateDevice)gip(inst,"vkCreateDevice");
 if(!pDestroyInstance||!pEnumPhys||!pGetQF||!pCreateDevice){err("required instance/device entry points missing");pDestroyInstance(inst,NULL);dlclose(loader);return -6;}
 uint32_t n=0; r=pEnumPhys(inst,&n,NULL); if(r!=0||n==0){char b[96];snprintf(b,sizeof b,"no Vulkan physical device: result=%d count=%u",r,n);err(b);pDestroyInstance(inst,NULL);dlclose(loader);return -7;}
 VkPhysicalDevice phys=NULL; uint32_t one=1; r=pEnumPhys(inst,&one,&phys); if(r!=0||!phys){err("failed to enumerate physical device");pDestroyInstance(inst,NULL);dlclose(loader);return -8;}
 uint32_t qn=0; pGetQF(phys,&qn,NULL); if(qn==0){err("physical device has no queue families");pDestroyInstance(inst,NULL);dlclose(loader);return -9;}
 VkQueueFamilyProperties *qfp=(VkQueueFamilyProperties*)calloc(qn,sizeof(*qfp)); if(!qfp){err("out of memory");pDestroyInstance(inst,NULL);dlclose(loader);return -10;} pGetQF(phys,&qn,qfp); int gi=-1; for(uint32_t i=0;i<qn;i++) if(qfp[i].queueCount && (qfp[i].queueFlags&1u)){gi=(int)i;break;} if(gi<0){free(qfp);err("no graphics-capable queue family");pDestroyInstance(inst,NULL);dlclose(loader);return -11;}
 float prio=1.0f; VkDeviceQueueCreateInfo qci={2,NULL,0,(uint32_t)gi,1,&prio}; VkDeviceCreateInfo dci={3,NULL,0,1,&qci,0,NULL,0,NULL,NULL}; VkDevice dev=NULL; r=pCreateDevice(phys,&dci,NULL,&dev); free(qfp); if(r!=0||!dev){char b[96];snprintf(b,sizeof b,"vkCreateDevice failed: %d",r);err(b);pDestroyInstance(inst,NULL);dlclose(loader);return -12;}
 pDestroyDevice=(PFN_vkDestroyDevice)gip(inst,"vkDestroyDevice"); pGetQueue=(PFN_vkGetDeviceQueue)gip(inst,"vkGetDeviceQueue"); if(!pDestroyDevice||!pGetQueue){err("device entry points missing");pDestroyDevice(dev,NULL);pDestroyInstance(inst,NULL);dlclose(loader);return -13;}
 VkQueue queue=NULL; pGetQueue(dev,(uint32_t)gi,0,&queue); if(!queue){err("vkGetDeviceQueue returned NULL");pDestroyDevice(dev,NULL);pDestroyInstance(inst,NULL);dlclose(loader);return -14;}
 ctx->loader=loader;ctx->instance=inst;ctx->physical_device=phys;ctx->device=dev;ctx->queue=queue;ctx->graphics_queue_family=(uint32_t)gi;ctx->has_graphics_queue=true;err("ok");return 0;
}
void agc_vk_device_shutdown(agc_vk_device_context_t*ctx){if(!ctx)return; if(ctx->device&&pDestroyDevice)pDestroyDevice((VkDevice)ctx->device,NULL); if(ctx->instance&&pDestroyInstance)pDestroyInstance((VkInstance)ctx->instance,NULL); if(ctx->loader)dlclose(ctx->loader); memset(ctx,0,sizeof(*ctx));}
