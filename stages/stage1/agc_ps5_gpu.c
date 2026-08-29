#include "agc_ps5_gpu.h"

#include <string.h>

bool agc_ps5_gpu_init_abi(agc_ps5_gpu_t *gpu)
{
   if (!gpu)
      return false;

   memset(gpu, 0, sizeof(*gpu));

   /*
    * Milestone 1 is intentionally only ABI bring-up.  We do not call any
    * AGC function yet because the public 3.20 generated stubs expose symbol
    * addresses/NIDs but not the original C prototypes.
    */
   if (!agc_ps5_abi_init(&gpu->abi))
      return false;

   if (!agc_ps5_abi_complete(&gpu->abi))
   {
      agc_ps5_abi_shutdown(&gpu->abi);
      return false;
   }

   gpu->initialized = true;
   return true;
}

void agc_ps5_gpu_free_abi(agc_ps5_gpu_t *gpu)
{
   if (!gpu)
      return;

   agc_ps5_abi_shutdown(&gpu->abi);
   memset(gpu, 0, sizeof(*gpu));
}
