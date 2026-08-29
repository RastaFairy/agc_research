#ifndef AGC_PS5_GPU_H
#define AGC_PS5_GPU_H

#include "agc_ps5_abi.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct agc_ps5_gpu
{
   agc_ps5_abi_t abi;

   /* Deliberately opaque until the exact Sony ABI is mapped. */
   void *context;
   void *graphics_memory;
   size_t graphics_memory_size;

   void *dcb;
   size_t dcb_size;
   size_t dcb_used;

   void *vertex_buffer;
   void *index_buffer;
   void *vertex_shader;
   void *pixel_shader;

   bool initialized;
} agc_ps5_gpu_t;

bool agc_ps5_gpu_init_abi(agc_ps5_gpu_t *gpu);
void agc_ps5_gpu_free_abi(agc_ps5_gpu_t *gpu);

#endif /* AGC_PS5_GPU_H */
