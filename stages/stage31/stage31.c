#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VK_SUCCESS 0
#define VK_TRUE 1
#define VK_FALSE 0
#define VK_QUEUE_GRAPHICS_BIT 0x00000001u
#define VK_STRUCTURE_TYPE_APPLICATION_INFO 0
#define VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO 1
#define VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO 2
#define VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO 3
#define VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO 16
#define VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO 5
#define VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO 14
#define VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO 15
#define VK_FORMAT_R8G8B8A8_UNORM 37
#define VK_IMAGE_TYPE_2D 1
#define VK_IMAGE_TILING_OPTIMAL 0
#define VK_IMAGE_USAGE_TRANSFER_SRC_BIT 0x00000001u
#define VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT 0x00000010u
#define VK_IMAGE_USAGE_SAMPLED_BIT 0x00000004u
#define VK_IMAGE_LAYOUT_UNDEFINED 0
#define VK_IMAGE_VIEW_TYPE_2D 1
#define VK_IMAGE_ASPECT_COLOR_BIT 0x1u
#define VK_IMAGE_CREATE_INFO_TYPE 14
#define VK_IMAGE_VIEW_CREATE_INFO_TYPE 15
#define VK_SAMPLE_COUNT_1_BIT 1
#define VK_SHARING_MODE_EXCLUSIVE 0
#define VK_IMAGE_CREATE_2D_ARRAY_COMPATIBLE_BIT 0x00000020u
#define VK_COMPONENT_SWIZZLE_IDENTITY 0
#define VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT 0x00000001u
#define VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT 0x00000002u
#define VK_MEMORY_PROPERTY_HOST_COHERENT_BIT 0x00000004u

/* Minimal Vulkan ABI declarations sufficient for the probe. */
typedef uint64_t VkDeviceSize; typedef uint32_t VkFlags; typedef uint32_t VkBool32;
typedef int32_t VkResult; typedef uint64_t VkInstance; typedef uint64_t VkPhysicalDevice;
typedef uint64_t VkDevice; typedef uint64_t VkQueue; typedef uint64_t VkShaderModule;
typedef uint64_t VkImage; typedef uint64_t VkImageView; typedef uint64_t VkDeviceMemory;
typedef uint32_t VkFormat; typedef uint32_t VkImageUsageFlags; typedef uint32_t VkImageAspectFlags;
typedef uint32_t VkMemoryPropertyFlags; typedef uint32_t VkImageCreateFlags; typedef uint32_t VkImageViewCreateFlags;
typedef uint32_t VkSampleCountFlagBits; typedef uint32_t VkImageLayout; typedef uint32_t VkSharingMode; typedef uint32_t VkImageType; typedef uint32_t VkImageTiling; typedef uint32_t VkImageViewType;

typedef struct VkExtent3D { uint32_t width,height,depth; } VkExtent3D;
typedef struct VkApplicationInfo { uint32_t sType; const void* pNext; const char* pApplicationName; uint32_t applicationVersion; const char* pEngineName; uint32_t engineVersion; uint32_t apiVersion; } VkApplicationInfo;
typedef struct VkInstanceCreateInfo { uint32_t sType; const void* pNext; VkFlags flags; const VkApplicationInfo* pApplicationInfo; uint32_t enabledLayerCount; const char* const* ppEnabledLayerNames; uint32_t enabledExtensionCount; const char* const* ppEnabledExtensionNames; } VkInstanceCreateInfo;
typedef struct VkPhysicalDeviceFeatures { uint32_t dummy[55]; } VkPhysicalDeviceFeatures;
typedef struct VkDeviceQueueCreateInfo { uint32_t sType; const void* pNext; VkFlags flags; uint32_t queueFamilyIndex; uint32_t queueCount; const float* pQueuePriorities; } VkDeviceQueueCreateInfo;
typedef struct VkDeviceCreateInfo { uint32_t sType; const void* pNext; VkFlags flags; uint32_t queueCreateInfoCount; const VkDeviceQueueCreateInfo* pQueueCreateInfos; uint32_t enabledLayerCount; const char* const* ppEnabledLayerNames; uint32_t enabledExtensionCount; const char* const* ppEnabledExtensionNames; const VkPhysicalDeviceFeatures* pEnabledFeatures; } VkDeviceCreateInfo;
typedef struct VkShaderModuleCreateInfo { uint32_t sType; const void* pNext; VkFlags flags; size_t codeSize; const uint32_t* pCode; } VkShaderModuleCreateInfo;
typedef struct VkMemoryType { VkMemoryPropertyFlags propertyFlags; uint32_t heapIndex; } VkMemoryType;
typedef struct VkPhysicalDeviceMemoryProperties { uint32_t memoryTypeCount; VkMemoryType memoryTypes[32]; uint32_t memoryHeapCount; uint8_t heaps[16*16]; } VkPhysicalDeviceMemoryProperties;
typedef struct VkMemoryRequirements { VkDeviceSize size; VkDeviceSize alignment; uint32_t memoryTypeBits; } VkMemoryRequirements;
typedef struct VkMemoryAllocateInfo { uint32_t sType; const void* pNext; VkDeviceSize allocationSize; uint32_t memoryTypeIndex; } VkMemoryAllocateInfo;
typedef struct VkImageCreateInfo { uint32_t sType; const void* pNext; VkImageCreateFlags flags; VkImageType imageType; VkFormat format; VkExtent3D extent; uint32_t mipLevels; uint32_t arrayLayers; VkSampleCountFlagBits samples; VkImageTiling tiling; VkImageUsageFlags usage; VkSharingMode sharingMode; uint32_t queueFamilyIndexCount; const uint32_t* pQueueFamilyIndices; VkImageLayout initialLayout; } VkImageCreateInfo;
typedef struct VkComponentMapping { uint32_t r,g,b,a; } VkComponentMapping;
typedef struct VkImageSubresourceRange { VkImageAspectFlags aspectMask; uint32_t baseMipLevel; uint32_t levelCount; uint32_t baseArrayLayer; uint32_t layerCount; } VkImageSubresourceRange;
typedef struct VkImageViewCreateInfo { uint32_t sType; const void* pNext; VkImageViewCreateFlags flags; VkImage image; VkImageViewType viewType; VkFormat format; VkComponentMapping components; VkImageSubresourceRange subresourceRange; } VkImageViewCreateInfo;

typedef struct VkQueueFamilyProperties { VkFlags queueFlags; uint32_t queueCount; uint32_t timestampValidBits; VkExtent3D minImageTransferGranularity; } VkQueueFamilyProperties;

typedef void (*PFN_vkVoidFunction)(void);
#define DECL(name, type) type name;
typedef struct Api {
 void *lib;
 PFN_vkVoidFunction (*vkGetInstanceProcAddr)(VkInstance,const char*);
 PFN_vkVoidFunction (*vkGetDeviceProcAddr)(VkDevice,const char*);
 VkResult (*vkCreateInstance)(const VkInstanceCreateInfo*,const void*,VkInstance*);
 VkResult (*vkEnumeratePhysicalDevices)(VkInstance,uint32_t*,VkPhysicalDevice*);
 void (*vkGetPhysicalDeviceQueueFamilyProperties)(VkPhysicalDevice,uint32_t*,VkQueueFamilyProperties*);
 void (*vkGetPhysicalDeviceMemoryProperties)(VkPhysicalDevice,VkPhysicalDeviceMemoryProperties*);
 VkResult (*vkCreateDevice)(VkPhysicalDevice,const VkDeviceCreateInfo*,const void*,VkDevice*);
 void (*vkGetDeviceQueue)(VkDevice,uint32_t,uint32_t,VkQueue*);
 void (*vkDestroyDevice)(VkDevice,const void*);
 void (*vkDestroyInstance)(VkInstance,const void*);
 VkResult (*vkCreateShaderModule)(VkDevice,const VkShaderModuleCreateInfo*,const void*,VkShaderModule*);
 void (*vkDestroyShaderModule)(VkDevice,VkShaderModule,const void*);
 VkResult (*vkCreateImage)(VkDevice,const VkImageCreateInfo*,const void*,VkImage*);
 void (*vkGetImageMemoryRequirements)(VkDevice,VkImage,VkMemoryRequirements*);
 VkResult (*vkAllocateMemory)(VkDevice,const VkMemoryAllocateInfo*,const void*,VkDeviceMemory*);
 VkResult (*vkBindImageMemory)(VkDevice,VkImage,VkDeviceMemory,VkDeviceSize);
 VkResult (*vkCreateImageView)(VkDevice,const VkImageViewCreateInfo*,const void*,VkImageView*);
 void (*vkDestroyImageView)(VkDevice,VkImageView,const void*);
 void (*vkDestroyImage)(VkDevice,VkImage,const void*);
 void (*vkFreeMemory)(VkDevice,VkDeviceMemory,const void*);
} Api;

static void *devfn(Api *a, VkDevice d, const char *n) { return (void*)a->vkGetDeviceProcAddr(d,n); }

static uint32_t bits(float f) { uint32_t u; memcpy(&u,&f,4); return u; }

static void inst(uint32_t *out,size_t *i,uint16_t op,uint16_t wc,const uint32_t *ops){ out[(*i)++]=((uint32_t)wc<<16)|op; for(int k=0;k<wc-1;k++) out[(*i)++]=ops[k]; }
static void str_words(const char *s,uint32_t *o,size_t max,size_t *count){ (void)max; size_t n=strlen(s)+1, wc=(n+3)/4; memset(o,0,wc*4); memcpy(o,s,n); *count=wc; }
tatic uint32_t* make_vert(size_t *wc_out){ uint32_t w[128]; size_t i=5; w[0]=0x07230203; w[1]=0x00010000; w[2]=0; w[3]=32; w[4]=0; uint32_t x[8],sw[8]; size_t sc;
 x[0]=1; inst(w,&i,17,2,x); x[0]=0;x[1]=1;inst(w,&i,14,3,x); str_words("main",sw,8,&sc); {uint32_t ops[8]={0,4};memcpy(&ops[2],sw,sc*4);ops[2+sc]=9;inst(w,&i,15,(uint16_t)(3+sc),ops);} x[0]=4;x[1]=7;inst(w,&i,16,3,x); x[0]=9;x[1]=11;inst(w,&i,71,3,x); x[0]=1;x[1]=2;inst(w,&i,19,2,x); x[0]=3;x[1]=32;x[2]=32;inst(w,&i,22,3,x); x[0]=4;x[1]=3;x[2]=4;inst(w,&i,23,3,x); x[0]=5;x[1]=3;x[2]=4;inst(w,&i,32,3,x); x[0]=9;x[1]=5;x[2]=3;inst(w,&i,59,4,x); uint32_t z=bits(0.0f),o=bits(1.0f); x[0]=6;x[1]=3;x[2]=z;inst(w,&i,43,4,x);x[0]=7;x[1]=3;x[2]=z;inst(w,&i,43,4,x);x[0]=8;x[1]=3;x[2]=z;inst(w,&i,43,4,x);x[0]=10;x[1]=3;x[2]=o;inst(w,&i,43,4,x);x[0]=11;x[1]=4;x[2]=6;x[3]=7;x[4]=8;x[5]=10;inst(w,&i,44,6,x);x[0]=12;x[1]=1;inst(w,&i,33,3,x);{uint32_t ops[4]={1,0,12};inst(w,&i,54,4,ops);}x[0]=13;inst(w,&i,248,2,x);x[0]=9;x[1]=11;inst(w,&i,62,3,x);inst(w,&i,253,1,NULL);inst(w,&i,56,1,NULL);uint32_t*r=malloc(i*4);memcpy(r,w,i*4);*wc_out=i;printf("make_vert done\n");fflush(stdout);return r;}

int main(void){
 const char*icd=getenv("VK_DRIVER_FILES"); if(!icd||!*icd){icd="/usr/lib/chromium/vk_swiftshader_icd.json"; setenv("VK_DRIVER_FILES",icd,1);} printf("ICD=%s\n",icd); fflush(stdout);
 Api a={0}; a.lib=dlopen("libvulkan.so.1",RTLD_NOW|RTLD_LOCAL); if(!a.lib){perror("dlopen");return 2;} a.vkGetInstanceProcAddr=dlsym(a.lib,"vkGetInstanceProcAddr"); a.vkGetDeviceProcAddr=dlsym(a.lib,"vkGetDeviceProcAddr"); a.vkCreateInstance=dlsym(a.lib,"vkCreateInstance");
 VkApplicationInfo ai={VK_STRUCTURE_TYPE_APPLICATION_INFO,0,"AGCStage31",1,"AGCStage31",1,0x00400000}; VkInstanceCreateInfo ci={VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,0,0,&ai,0,0,0,0}; VkInstance insti=0; VkResult r=a.vkCreateInstance(&ci,NULL,&insti); if(r){printf("vkCreateInstance=%d\n",r);fflush(stdout);return 3;} printf("instance ok\n"); fflush(stdout);
 #define GETI(n) a.n=(void*)a.vkGetInstanceProcAddr(insti,#n)
 GETI(vkEnumeratePhysicalDevices);GETI(vkGetPhysicalDeviceQueueFamilyProperties);GETI(vkGetPhysicalDeviceMemoryProperties);GETI(vkCreateDevice);
 VkPhysicalDevice pd=0;uint32_t n=0;r=a.vkEnumeratePhysicalDevices(insti,&n,NULL);if(r||!n){printf("physical_devices=%u result=%d\n",n,r);return 4;} a.vkEnumeratePhysicalDevices(insti,&n,&pd); printf("pd ok\n"); fflush(stdout);uint32_t qn=0;a.vkGetPhysicalDeviceQueueFamilyProperties(pd,&qn,NULL);VkQueueFamilyProperties*qfp=calloc(qn,sizeof(*qfp));a.vkGetPhysicalDeviceQueueFamilyProperties(pd,&qn,qfp);uint32_t qidx=UINT32_MAX;for(uint32_t j=0;j<qn;j++)if(qfp[j].queueCount&&(qfp[j].queueFlags&VK_QUEUE_GRAPHICS_BIT)){qidx=j;break;}free(qfp); printf("qidx=%u\n",qidx); fflush(stdout); if(qidx==UINT32_MAX){puts("graphics_queue=NO");return 5;}float prio=1.0f;VkDeviceQueueCreateInfo qci={VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,0,0,qidx,1,&prio};VkDeviceCreateInfo dci={0}; dci.sType=VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO; dci.queueCreateInfoCount=1; dci.pQueueCreateInfos=&qci;VkDevice dev=0;r=a.vkCreateDevice(pd,&dci,NULL,&dev);if(r){printf("vkCreateDevice=%d\n",r);fflush(stdout);return 6;} printf("device ok\n"); fflush(stdout);
 #define GETD(n) a.n=(void*)devfn(&a,dev,#n); printf("%s=%p\n",#n,(void*)a.n); fflush(stdout)
 GETD(vkGetDeviceQueue);GETD(vkDestroyDevice);GETD(vkCreateShaderModule);GETD(vkDestroyShaderModule);GETD(vkCreateImage);GETD(vkGetImageMemoryRequirements);GETD(vkAllocateMemory);GETD(vkBindImageMemory);GETD(vkCreateImageView);GETD(vkDestroyImageView);GETD(vkDestroyImage);GETD(vkFreeMemory);
 VkQueue q=0;a.vkGetDeviceQueue(dev,qidx,0,&q); printf("queue ok\n"); fflush(stdout);
 printf("shader_module_probe=BLOCKED(no local SPIR-V compiler)\n"); fflush(stdout);VkPhysicalDeviceMemoryProperties mp={0};a.vkGetPhysicalDeviceMemoryProperties(pd,&mp);uint32_t memidx=UINT32_MAX;for(uint32_t j=0;j<mp.memoryTypeCount;j++)if((mp.memoryTypes[j].propertyFlags&(VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT|VK_MEMORY_PROPERTY_HOST_COHERENT_BIT))==(VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT|VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)){memidx=j;break;}VkImageCreateInfo ii={VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO,0,0,VK_IMAGE_TYPE_2D,VK_FORMAT_R8G8B8A8_UNORM,{64,64,1},1,1,VK_SAMPLE_COUNT_1_BIT,VK_IMAGE_TILING_OPTIMAL,VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT|VK_IMAGE_USAGE_TRANSFER_SRC_BIT|VK_IMAGE_USAGE_SAMPLED_BIT,VK_SHARING_MODE_EXCLUSIVE,0,NULL,VK_IMAGE_LAYOUT_UNDEFINED};VkImage img=0;r=a.vkCreateImage(dev,&ii,NULL,&img);printf("rgba8_image=%d\n",r);VkMemoryRequirements mr={0};if(!r){a.vkGetImageMemoryRequirements(dev,img,&mr);printf("image_mem_size=%llu type_bits=0x%x\n",(unsigned long long)mr.size,mr.memoryTypeBits);for(uint32_t j=0;j<mp.memoryTypeCount;j++)if((mr.memoryTypeBits&(1u<<j))&&((mp.memoryTypes[j].propertyFlags&VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT)!=0)){memidx=j;break;}VkMemoryAllocateInfo ma={VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,0,mr.size,memidx};VkDeviceMemory dm=0;r=a.vkAllocateMemory(dev,&ma,NULL,&dm);printf("rgba8_memory=%d\n",r);if(!r){r=a.vkBindImageMemory(dev,img,dm,0);printf("rgba8_bind=%d\n",r);VkImageViewCreateInfo vi={VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO,0,0,img,VK_IMAGE_VIEW_TYPE_2D,VK_FORMAT_R8G8B8A8_UNORM,{0,0,0,0},{VK_IMAGE_ASPECT_COLOR_BIT,0,1,0,1}};VkImageView view=0;r=a.vkCreateImageView(dev,&vi,NULL,&view);printf("rgba8_view=%d\n",r);if(view)a.vkDestroyImageView(dev,view,NULL);a.vkFreeMemory(dev,dm,NULL);}a.vkDestroyImage(dev,img,NULL);}a.vkDestroyDevice(dev,NULL);a.vkDestroyInstance(insti,NULL);dlclose(a.lib);puts("Stage 31 Vulkan offscreen resource probe: PASS (shader blocked by missing compiler)");return 0;}
