# Sources

The layouts used by the probe are derived from Khronos Vulkan specification reference pages:

- `VkImageCreateInfo`: sType/pNext/flags/imageType/format/extent/mipLevels/arrayLayers/samples/tiling/usage/sharingMode/queueFamilyIndexCount/pQueueFamilyIndices/initialLayout.
- `VkImageViewCreateInfo`: sType/pNext/flags/image/viewType/format/components/subresourceRange.
- `VkComponentMapping`: r/g/b/a.
- `VkImageSubresourceRange`: aspectMask/baseMipLevel/levelCount/baseArrayLayer/layerCount.
- `VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO = 14`, `VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO = 15`.
- `VK_FORMAT_R8G8B8A8_UNORM = 37`, `VK_IMAGE_VIEW_TYPE_2D = 1`.

Runtime ICD:
`/usr/lib/chromium/vk_swiftshader_icd.json`
