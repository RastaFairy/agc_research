#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define S_APP 0
#define S_INSTANCE 1
#define S_QUEUE 2
#define S_DEVICE 3
#define S_MEMORY_ALLOC 5
#define S_IMAGE 14
#define S_IMAGE_VIEW 15
#define SUCCESS 0
#define GRAPHICS 1u
#define FMT_RGBA8 37u
#define IMAGE_2D 1u
#define TILING_OPTIMAL 0u
#define USAGE_TRANSFER_SRC 1u
#define USAGE_SAMPLED 4u
#define USAGE_COLOR_ATTACHMENT 16u
#define SHARING_EXCLUSIVE 0u
#define LAYOUT_UNDEFINED 0u
#define VIEW_2D 1u
#define ASPECT_COLOR 1u
#define SAMPLES_1 1u
#define MEM_DEVICE_LOCAL 1u

typedef int32_t VkResult; typedef uint32_t VkFlags; typedef uint64_t VkDeviceSize;
typedef uint64_t VkInstance, VkPhysicalDevice, VkDevice, VkQueue, VkImage, VkImageView, VkDeviceMemory;
typedef struct { uint32_t width,height,depth; } Ext3D;
typedef struct { uint32_t sType; const void *pNext; const char *app; uint32_t appv; const char *eng; uint32_t engv; uint32_t api; } AppInfo;
typedef struct { uint32_t sType; const void *pNext; VkFlags flags; const AppInfo *app; uint32_t lc; const char *const *ln; uint32_t ec; const char *const *en; } InstCI;
typedef struct { uint32_t sType; const void *pNext; VkFlags flags; uint32_t qfi,qc; const float *prio; } QCI;
typedef struct { uint32_t sType; const void *pNext; VkFlags flags; uint32_t qcount; const QCI *qcis; uint32_t lc; const char *const *ln; uint32_t ec; const char *const *en; const void *features; } DevCI;
typedef struct { uint32_t qflags,qcount,timestamp; Ext3D gran; } QFP;
typedef struct { uint32_t flags,heap; } MemType;
typedef struct { uint32_t count; MemType types[32]; uint32_t heapCount; uint8_t heaps[256]; } MemProps;
typedef struct { VkDeviceSize size,align; uint32_t typeBits; } MemReq;
typedef struct { uint32_t sType; const void *pNext; VkDeviceSize size; uint32_t typeIndex; } MemAI;
typedef struct { uint32_t sType; const void *pNext; uint32_t flags,imageType,format; Ext3D extent; uint32_t mipLevels,layers,samples,tiling,usage,sharing,queueCount; const uint32_t *queues; uint32_t initialLayout; } ImageCI;
typedef struct { uint32_t r,g,b,a; } CompMap;
typedef struct { uint32_t aspect,baseMip,levels,baseLayer,layers; } Subres;
typedef struct { uint32_t sType; const void *pNext; uint32_t flags; VkImage image,viewType,format; CompMap comp; Subres sub; } ViewCI;

typedef void *(*GIPA)(VkInstance,const char*);
typedef void *(*GDPA)(VkDevice,const char*);
typedef VkResult (*CreateInst)(const InstCI*,const void*,VkInstance*);
typedef VkResult (*EnumPD)(VkInstance,uint32_t*,VkPhysicalDevice*);
typedef void (*GetQFP)(VkPhysicalDevice,uint32_t*,QFP*);
typedef void (*GetMP)(VkPhysicalDevice,MemProps*);
typedef VkResult (*CreateDev)(VkPhysicalDevice,const DevCI*,const void*,VkDevice*);
typedef void (*GetQ)(VkDevice,uint32_t,uint32_t,VkQueue*);
typedef VkResult (*CreateImg)(VkDevice,const ImageCI*,const void*,VkImage*);
typedef void (*GetReq)(VkDevice,VkImage,MemReq*);
typedef VkResult (*Alloc)(VkDevice,const MemAI*,const void*,VkDeviceMemory*);
typedef VkResult (*Bind)(VkDevice,VkImage,VkDeviceMemory,VkDeviceSize);
typedef VkResult (*CreateView)(VkDevice,const ViewCI*,const void*,VkImageView*);
typedef void (*DestroyView)(VkDevice,VkImageView,const void*);
typedef void (*DestroyImg)(VkDevice,VkImage,const void*);
typedef void (*FreeMem)(VkDevice,VkDeviceMemory,const void*);
typedef void (*DestroyDev)(VkDevice,const void*);
typedef void (*DestroyInst)(VkInstance,const void*);

int main(void){
 const char *icd=getenv("VK_DRIVER_FILES"); if(!icd) icd="/usr/lib/chromium/vk_swiftshader_icd.json"; setenv("VK_DRIVER_FILES",icd,1); printf("ICD=%s\n",icd);
 void *lib=dlopen("libvulkan.so.1",RTLD_NOW); if(!lib){puts("loader=FAIL");return 2;} GIPA gipa=(GIPA)dlsym(lib,"vkGetInstanceProcAddr"); CreateInst ci=(CreateInst)dlsym(lib,"vkCreateInstance");
 AppInfo ai={S_APP,0,"AGCStage31",1,"AGCStage31",1,0x00400000}; InstCI ici={S_INSTANCE,0,0,&ai,0,0,0,0}; VkInstance inst=0; VkResult r=ci(&ici,0,&inst); if(r){printf("instance=%d\n",r);return 3;} printf("instance=PASS\n");
 EnumPD enumPD=(EnumPD)gipa(inst,"vkEnumeratePhysicalDevices"); GetQFP getQFP=(GetQFP)gipa(inst,"vkGetPhysicalDeviceQueueFamilyProperties"); GetMP getMP=(GetMP)gipa(inst,"vkGetPhysicalDeviceMemoryProperties"); CreateDev createDev=(CreateDev)gipa(inst,"vkCreateDevice"); VkPhysicalDevice pd=0; uint32_t n=0; r=enumPD(inst,&n,NULL); if(r||!n){printf("physical_devices=%u result=%d\n",n,r);return 4;} enumPD(inst,&n,&pd); uint32_t qn=0; getQFP(pd,&qn,NULL); QFP *q=calloc(qn,sizeof(*q)); getQFP(pd,&qn,q); uint32_t qi=UINT32_MAX; for(uint32_t i=0;i<qn;i++) if(q[i].qcount && (q[i].qflags&GRAPHICS)){qi=i;break;} free(q); printf("graphics_queue_family=%s\n",qi==UINT32_MAX?"NO":"PASS"); if(qi==UINT32_MAX)return 5;
 float pr=1.0f; QCI qci={S_QUEUE,0,0,qi,1,&pr}; DevCI dci={0}; dci.sType=S_DEVICE; dci.qcount=1; dci.qcis=&qci; VkDevice dev=0; r=createDev(pd,&dci,0,&dev); if(r){printf("device=%d\n",r);return 6;} printf("device=PASS\n");
 GDPA gdpa=(GDPA)gipa(inst,"vkGetDeviceProcAddr"); GetQ getQ=(GetQ)gdpa(dev,"vkGetDeviceQueue"); CreateImg createImg=(CreateImg)gdpa(dev,"vkCreateImage"); GetReq getReq=(GetReq)gdpa(dev,"vkGetImageMemoryRequirements"); Alloc alloc=(Alloc)gdpa(dev,"vkAllocateMemory"); Bind bind=(Bind)gdpa(dev,"vkBindImageMemory"); CreateView createView=(CreateView)gdpa(dev,"vkCreateImageView"); DestroyView destroyView=(DestroyView)gdpa(dev,"vkDestroyImageView"); DestroyImg destroyImg=(DestroyImg)gdpa(dev,"vkDestroyImage"); FreeMem freeMem=(FreeMem)gdpa(dev,"vkFreeMemory"); DestroyDev destroyDev=(DestroyDev)gdpa(dev,"vkDestroyDevice"); DestroyInst destroyInst=(DestroyInst)gipa(inst,"vkDestroyInstance");
 VkQueue queue=0; getQ(dev,qi,0,&queue); printf("queue=PASS\n");
 ImageCI ii={S_IMAGE,0,0,IMAGE_2D,FMT_RGBA8,{64,64,1},1,1,SAMPLES_1,TILING_OPTIMAL,USAGE_TRANSFER_SRC|USAGE_COLOR_ATTACHMENT|USAGE_SAMPLED,SHARING_EXCLUSIVE,0,NULL,LAYOUT_UNDEFINED}; VkImage img=0; r=createImg(dev,&ii,0,&img); printf("rgba8_image=%d\n",r); if(r){destroyDev(dev,0);destroyInst(inst,0);return 7;} MemReq mr={0}; getReq(dev,img,&mr); MemProps mp={0}; getMP(pd,&mp); uint32_t mi=UINT32_MAX; for(uint32_t i=0;i<mp.count;i++) if((mr.typeBits&(1u<<i)) && (mp.types[i].flags&MEM_DEVICE_LOCAL)){mi=i;break;} if(mi==UINT32_MAX){puts("memory_type=NO_DEVICE_LOCAL");return 8;} MemAI mai={S_MEMORY_ALLOC,0,mr.size,mi}; VkDeviceMemory mem=0; r=alloc(dev,&mai,0,&mem); printf("memory_alloc=%d\n",r); if(!r){r=bind(dev,img,mem,0); printf("image_bind=%d\n",r);} ViewCI vi={S_IMAGE_VIEW,0,0,img,VIEW_2D,FMT_RGBA8,{0,0,0,0},{ASPECT_COLOR,0,1,0,1}}; VkImageView view=0; if(!r){r=createView(dev,&vi,0,&view); printf("rgba8_view=%d\n",r);} if(view)destroyView(dev,view,0); if(mem)freeMem(dev,mem,0); destroyImg(dev,img,0); destroyDev(dev,0); destroyInst(inst,0); dlclose(lib); puts("Stage 31 Vulkan RGBA8 resource probe: PASS"); return 0;
}
