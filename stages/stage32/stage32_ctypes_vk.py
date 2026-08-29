import ctypes as C, os, sys
from pathlib import Path

os.environ.setdefault('VK_DRIVER_FILES','/usr/lib/chromium/vk_swiftshader_icd.json')
lib=C.CDLL('libvulkan.so.1')

c_void_p=C.c_void_p; u32=C.c_uint32; u64=C.c_uint64; i32=C.c_int32; f32=C.c_float; size_t=C.c_size_t
VkInstance=c_void_p; VkPhysicalDevice=c_void_p; VkDevice=c_void_p; VkQueue=c_void_p
VkImage=u64; VkImageView=u64; VkDeviceMemory=u64

SUCCESS=0
S_INSTANCE_CREATE_INFO=1
S_DEVICE_QUEUE_CREATE_INFO=2
S_DEVICE_CREATE_INFO=3
S_MEMORY_ALLOCATE_INFO=5
S_IMAGE_CREATE_INFO=14
S_IMAGE_VIEW_CREATE_INFO=15
VK_FORMAT_R8G8B8A8_UNORM=37
VK_IMAGE_TYPE_2D=1
VK_IMAGE_TILING_OPTIMAL=0
VK_IMAGE_USAGE_TRANSFER_SRC=1
VK_IMAGE_USAGE_SAMPLED=4
VK_IMAGE_USAGE_COLOR_ATTACHMENT=16
VK_SHARING_MODE_EXCLUSIVE=0
VK_IMAGE_LAYOUT_UNDEFINED=0
VK_SAMPLE_COUNT_1=1
VK_IMAGE_VIEW_TYPE_2D=1
VK_IMAGE_ASPECT_COLOR=1
VK_COMPONENT_SWIZZLE_IDENTITY=0
VK_MEMORY_PROPERTY_DEVICE_LOCAL=1

class VkApplicationInfo(C.Structure):
    _fields_=[('sType',u32),('pNext',c_void_p),('pApplicationName',C.c_char_p),('applicationVersion',u32),('pEngineName',C.c_char_p),('engineVersion',u32),('apiVersion',u32)]
class VkInstanceCreateInfo(C.Structure):
    _fields_=[('sType',u32),('pNext',c_void_p),('flags',u32),('pApplicationInfo',C.POINTER(VkApplicationInfo)),('enabledLayerCount',u32),('ppEnabledLayerNames',C.POINTER(C.c_char_p)),('enabledExtensionCount',u32),('ppEnabledExtensionNames',C.POINTER(C.c_char_p))]
class VkDeviceQueueCreateInfo(C.Structure):
    _fields_=[('sType',u32),('pNext',c_void_p),('flags',u32),('queueFamilyIndex',u32),('queueCount',u32),('pQueuePriorities',C.POINTER(f32))]
class VkDeviceCreateInfo(C.Structure):
    _fields_=[('sType',u32),('pNext',c_void_p),('flags',u32),('queueCreateInfoCount',u32),('pQueueCreateInfos',C.POINTER(VkDeviceQueueCreateInfo)),('enabledLayerCount',u32),('ppEnabledLayerNames',C.POINTER(C.c_char_p)),('enabledExtensionCount',u32),('ppEnabledExtensionNames',C.POINTER(C.c_char_p)),('pEnabledFeatures',c_void_p)]
class VkExtent3D(C.Structure):
    _fields_=[('width',u32),('height',u32),('depth',u32)]
class VkImageCreateInfo(C.Structure):
    _fields_=[('sType',u32),('pNext',c_void_p),('flags',u32),('imageType',u32),('format',u32),('extent',VkExtent3D),('mipLevels',u32),('arrayLayers',u32),('samples',u32),('tiling',u32),('usage',u32),('sharingMode',u32),('queueFamilyIndexCount',u32),('pQueueFamilyIndices',C.POINTER(u32)),('initialLayout',u32)]
class VkMemoryRequirements(C.Structure):
    _fields_=[('size',u64),('alignment',u64),('memoryTypeBits',u32)]
class VkMemoryType(C.Structure):
    _fields_=[('propertyFlags',u32),('heapIndex',u32)]
class VkMemoryHeap(C.Structure):
    _fields_=[('size',u64),('flags',u32)]
class VkPhysicalDeviceMemoryProperties(C.Structure):
    _fields_=[('memoryTypeCount',u32),('memoryTypes',VkMemoryType*32),('memoryHeapCount',u32),('memoryHeaps',VkMemoryHeap*16)]
class VkMemoryAllocateInfo(C.Structure):
    _fields_=[('sType',u32),('pNext',c_void_p),('allocationSize',u64),('memoryTypeIndex',u32)]
class VkComponentMapping(C.Structure):
    _fields_=[('r',u32),('g',u32),('b',u32),('a',u32)]
class VkImageSubresourceRange(C.Structure):
    _fields_=[('aspectMask',u32),('baseMipLevel',u32),('levelCount',u32),('baseArrayLayer',u32),('layerCount',u32)]
class VkImageViewCreateInfo(C.Structure):
    _fields_=[('sType',u32),('pNext',c_void_p),('flags',u32),('image',VkImage),('viewType',u32),('format',u32),('components',VkComponentMapping),('subresourceRange',VkImageSubresourceRange)]

for cls in [VkImageCreateInfo,VkImageViewCreateInfo]:
    print(cls.__name__, C.sizeof(cls))

# global functions
lib.vkCreateInstance.argtypes=[C.POINTER(VkInstanceCreateInfo), c_void_p, C.POINTER(VkInstance)]
lib.vkCreateInstance.restype=i32
lib.vkEnumeratePhysicalDevices.argtypes=[VkInstance,C.POINTER(u32),C.POINTER(VkPhysicalDevice)]
lib.vkEnumeratePhysicalDevices.restype=i32
lib.vkDestroyInstance.argtypes=[VkInstance,c_void_p]
lib.vkGetInstanceProcAddr.argtypes=[VkInstance,C.c_char_p]
lib.vkGetInstanceProcAddr.restype=c_void_p

def inst_fn(name, restype, argtypes):
    addr=lib.vkGetInstanceProcAddr(inst,name.encode())
    if not addr: raise RuntimeError(f'missing {name}')
    fn=C.CFUNCTYPE(restype,*argtypes)(addr)
    return fn

ai=VkApplicationInfo(S_INSTANCE_CREATE_INFO-1,None,b'Stage32',1,b'Stage32',1,0x00400000)
ici=VkInstanceCreateInfo(S_INSTANCE_CREATE_INFO,None,0,C.pointer(ai),0,None,0,None)
inst=VkInstance()
r=lib.vkCreateInstance(C.byref(ici),None,C.byref(inst)); print('createInstance',r)
if r!=SUCCESS: sys.exit(2)

enumPD=inst_fn('vkEnumeratePhysicalDevices',i32,[VkInstance,C.POINTER(u32),C.POINTER(VkPhysicalDevice)])
getQFP=inst_fn('vkGetPhysicalDeviceQueueFamilyProperties',None,[VkPhysicalDevice,C.POINTER(u32),c_void_p])
createDev=inst_fn('vkCreateDevice',i32,[VkPhysicalDevice,C.POINTER(VkDeviceCreateInfo),c_void_p,C.POINTER(VkDevice)])
getMemProps=inst_fn('vkGetPhysicalDeviceMemoryProperties',None,[VkPhysicalDevice,C.POINTER(VkPhysicalDeviceMemoryProperties)])

n=u32(); r=enumPD(inst,C.byref(n),None); print('enumPD',r,n.value)
pds=(VkPhysicalDevice*n.value)(); r=enumPD(inst,C.byref(n),pds); pd=pds[0]

# first queue family with graphics; property struct is 24 bytes: flags,count,timestamp,extent
qcount=u32(); getQFP(pd,C.byref(qcount),None)
raw=(C.c_ubyte*(qcount.value*24))(); getQFP(pd,C.byref(qcount),C.cast(raw,c_void_p))
qi=None
for i in range(qcount.value):
    flags=u32.from_buffer(raw,i*24).value
    count=u32.from_buffer(raw,i*24+4).value
    if count and (flags&1): qi=i; break
print('graphics_family',qi)

prio=f32(1.0); qci=VkDeviceQueueCreateInfo(S_DEVICE_QUEUE_CREATE_INFO,None,0,qi,1,C.pointer(prio)); dci=VkDeviceCreateInfo(S_DEVICE_CREATE_INFO,None,0,1,C.pointer(qci),0,None,0,None,None)
dev=VkDevice(); createDev=pd_create=createDev
r=createDev(pd,C.byref(dci),None,C.byref(dev)); print('createDevice',r)
if r!=SUCCESS: sys.exit(3)

gdpa_addr=inst_fn('vkGetDeviceProcAddr',c_void_p,[VkDevice,C.c_char_p])(dev,b'vkGetDeviceProcAddr') if False else None
# GetDeviceProcAddr is instance proc
getDPA=inst_fn('vkGetDeviceProcAddr',c_void_p,[VkDevice,C.c_char_p])
def dev_fn(name,restype,argtypes):
    addr=getDPA(dev,name.encode())
    if not addr: raise RuntimeError('missing '+name)
    return C.CFUNCTYPE(restype,*argtypes)(addr)

createImage=dev_fn('vkCreateImage',i32,[VkDevice,C.POINTER(VkImageCreateInfo),c_void_p,C.POINTER(VkImage)])
getReq=dev_fn('vkGetImageMemoryRequirements',None,[VkDevice,VkImage,C.POINTER(VkMemoryRequirements)])
alloc=dev_fn('vkAllocateMemory',i32,[VkDevice,C.POINTER(VkMemoryAllocateInfo),c_void_p,C.POINTER(VkDeviceMemory)])
bind=dev_fn('vkBindImageMemory',i32,[VkDevice,VkImage,VkDeviceMemory,u64])
createView=dev_fn('vkCreateImageView',i32,[VkDevice,C.POINTER(VkImageViewCreateInfo),c_void_p,C.POINTER(VkImageView)])
destroyView=dev_fn('vkDestroyImageView',None,[VkDevice,VkImageView,c_void_p])
destroyImage=dev_fn('vkDestroyImage',None,[VkDevice,VkImage,c_void_p])
freeMem=dev_fn('vkFreeMemory',None,[VkDevice,VkDeviceMemory,c_void_p])
getQ=dev_fn('vkGetDeviceQueue',None,[VkDevice,u32,u32,C.POINTER(VkQueue)])
destroyDev=dev_fn('vkDestroyDevice',None,[VkDevice,c_void_p])

img=VkImage(); ii=VkImageCreateInfo(S_IMAGE_CREATE_INFO,None,0,VK_IMAGE_TYPE_2D,VK_FORMAT_R8G8B8A8_UNORM,VkExtent3D(64,64,1),1,1,VK_SAMPLE_COUNT_1,VK_IMAGE_TILING_OPTIMAL,VK_IMAGE_USAGE_TRANSFER_SRC|VK_IMAGE_USAGE_SAMPLED|VK_IMAGE_USAGE_COLOR_ATTACHMENT,VK_SHARING_MODE_EXCLUSIVE,0,None,VK_IMAGE_LAYOUT_UNDEFINED)
r=createImage(dev,C.byref(ii),None,C.byref(img)); print('createImage',r,hex(img.value))
mr=VkMemoryRequirements(); getReq(dev,img,C.byref(mr)); mp=VkPhysicalDeviceMemoryProperties(); getMemProps(pd,C.byref(mp))
mi=None
for i in range(mp.memoryTypeCount):
    if (mr.memoryTypeBits&(1<<i)) and (mp.memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_DEVICE_LOCAL): mi=i; break
if mi is None: raise RuntimeError('no device local')
mem=VkDeviceMemory(); r=alloc(dev,C.byref(VkMemoryAllocateInfo(S_MEMORY_ALLOCATE_INFO,None,mr.size,mi)),None,C.byref(mem)); print('alloc',r)
r=bind(dev,img,mem,0); print('bind',r)
vi=VkImageViewCreateInfo(S_IMAGE_VIEW_CREATE_INFO,None,0,img,VK_IMAGE_VIEW_TYPE_2D,VK_FORMAT_R8G8B8A8_UNORM,VkComponentMapping(0,0,0,0),VkImageSubresourceRange(VK_IMAGE_ASPECT_COLOR,0,1,0,1))
view=VkImageView(); r=createView(dev,C.byref(vi),None,C.byref(view)); print('createView',r,hex(view.value) if view.value else 0)
if view.value: destroyView(dev,view,None)
freeMem(dev,mem,None); destroyImage(dev,img,None); destroyDev(dev,None); lib.vkDestroyInstance(inst,None)
print('PASS' if r==SUCCESS else 'FAIL')
