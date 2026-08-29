#include "agc_ps5_abi.h"

#include <string.h>

/* Provided by ps5-payload-dev's dynamic-linking runtime. */
extern int sprx_dlopen(const char *libname, unsigned short *handle);
extern int sprx_dlclose(unsigned int handle);
extern int sprx_dlsym(unsigned int handle, const char *nid, void *addr);

static bool resolve_one(unsigned short handle,
                        agc_ps5_abi_symbol_t *symbol)
{
   void *address = NULL;

   if (!symbol || !symbol->nid || !symbol->name)
      return false;

   if (sprx_dlsym(handle, symbol->nid, &address) != 0 || !address)
      return false;

   symbol->address = address;
   return true;
}

void *agc_ps5_abi_resolve(unsigned short handle, const char *nid)
{
   void *address = NULL;

   if (!handle || !nid)
      return NULL;

   if (sprx_dlsym(handle, nid, &address) != 0)
      return NULL;

   return address;
}

bool agc_ps5_abi_init(agc_ps5_abi_t *abi)
{
   bool ok = true;

   if (!abi)
      return false;

   memset(abi, 0, sizeof(*abi));

   /*
    * These NIDs are from DNNDHH/PS5-3.20_Libs generated stubs.
    * We intentionally resolve only the operations required for the first
    * renderer milestone.
    */
   abi->create_shader = (agc_ps5_abi_symbol_t){
      "sceAgcCreateShader", "f3dg2CSgRKY", NULL
   };
   abi->dcb_wait_safe = (agc_ps5_abi_symbol_t){
      "sceAgcDcbWaitUntilSafeForRendering", "GPbUp9jXQa8", NULL
   };
   abi->dcb_set_flip = (agc_ps5_abi_symbol_t){
      "sceAgcDcbSetFlip", "YUeqkyT7mEQ", NULL
   };
   abi->dcb_set_index_buffer = (agc_ps5_abi_symbol_t){
      "sceAgcDcbSetIndexBuffer", "l4fM9K-Lyks", NULL
   };
   abi->dcb_set_index_count = (agc_ps5_abi_symbol_t){
      "sceAgcDcbSetIndexCount", "8N2tmT3jmC8", NULL
   };
   abi->dcb_draw_index = (agc_ps5_abi_symbol_t){
      "sceAgcDcbDrawIndex", "q88lQ+GP5Yk", NULL
   };
   abi->driver_submit_dcb = (agc_ps5_abi_symbol_t){
      "sceAgcDriverAgrSubmitDcb", "AhGvpITrf4M", NULL
   };

   if (sprx_dlopen("libSceAgc", &abi->agc_handle) != 0)
      return false;

   abi->agc_loaded = true;

   if (sprx_dlopen("libSceAgcDriver", &abi->agc_driver_handle) != 0)
   {
      agc_ps5_abi_shutdown(abi);
      return false;
   }

   abi->agc_driver_loaded = true;

   ok &= resolve_one(abi->agc_handle, &abi->create_shader);
   ok &= resolve_one(abi->agc_handle, &abi->dcb_wait_safe);
   ok &= resolve_one(abi->agc_handle, &abi->dcb_set_flip);
   ok &= resolve_one(abi->agc_handle, &abi->dcb_set_index_buffer);
   ok &= resolve_one(abi->agc_handle, &abi->dcb_set_index_count);
   ok &= resolve_one(abi->agc_handle, &abi->dcb_draw_index);
   ok &= resolve_one(abi->agc_driver_handle, &abi->driver_submit_dcb);

   if (!ok)
   {
      agc_ps5_abi_shutdown(abi);
      return false;
   }

   return true;
}

bool agc_ps5_abi_complete(const agc_ps5_abi_t *abi)
{
   if (!abi || !abi->agc_loaded || !abi->agc_driver_loaded)
      return false;

   return abi->create_shader.address != NULL &&
          abi->dcb_wait_safe.address != NULL &&
          abi->dcb_set_flip.address != NULL &&
          abi->dcb_set_index_buffer.address != NULL &&
          abi->dcb_set_index_count.address != NULL &&
          abi->dcb_draw_index.address != NULL &&
          abi->driver_submit_dcb.address != NULL;
}

void agc_ps5_abi_shutdown(agc_ps5_abi_t *abi)
{
   if (!abi)
      return;

   if (abi->agc_driver_loaded)
   {
      (void)sprx_dlclose(abi->agc_driver_handle);
      abi->agc_driver_loaded = false;
      abi->agc_driver_handle = 0;
   }

   if (abi->agc_loaded)
   {
      (void)sprx_dlclose(abi->agc_handle);
      abi->agc_loaded = false;
      abi->agc_handle = 0;
   }

   abi->create_shader.address = NULL;
   abi->dcb_wait_safe.address = NULL;
   abi->dcb_set_flip.address = NULL;
   abi->dcb_set_index_buffer.address = NULL;
   abi->dcb_set_index_count.address = NULL;
   abi->dcb_draw_index.address = NULL;
   abi->driver_submit_dcb.address = NULL;
}
