#include "agc_ps5_abi.h"

#include <string.h>

extern int sprx_dlopen(const char *libname, unsigned short *handle);
extern int sprx_dlclose(unsigned int handle);
extern int sprx_dlsym(unsigned int handle, const char *nid, void *addr);

static bool resolve_one(unsigned short handle, agc_ps5_abi_symbol_t *s)
{
   void *address = NULL;
   if (!s || !s->name || !s->nid)
      return false;
   if (sprx_dlsym(handle, s->nid, &address) != 0 || !address)
      return false;
   s->address = address;
   return true;
}

#define SYM(name_, nid_) { name_, nid_, NULL }

bool agc_ps5_abi_init(agc_ps5_abi_t *abi)
{
   bool ok = true;
   if (!abi)
      return false;

   memset(abi, 0, sizeof(*abi));

   /* NIDs verified against DNNDHH/PS5-3.20_Libs. */
   abi->init = SYM("sceAgcInit", NULL);
   abi->get_register_defaults2 = SYM("sceAgcGetRegisterDefaults2", NULL);
   abi->create_shader = SYM("sceAgcCreateShader", "f3dg2CSgRKY");
   abi->link_shaders = SYM("sceAgcLinkShaders", NULL);

   abi->dcb_wait_safe = SYM("sceAgcDcbWaitUntilSafeForRendering", "GPbUp9jXQa8");
   abi->dcb_set_flip = SYM("sceAgcDcbSetFlip", "YUeqkyT7mEQ");
   abi->dcb_set_index_buffer = SYM("sceAgcDcbSetIndexBuffer", "l4fM9K-Lyks");
   abi->dcb_set_index_count = SYM("sceAgcDcbSetIndexCount", "8N2tmT3jmC8");
   abi->dcb_draw_index = SYM("sceAgcDcbDrawIndex", "q88lQ+GP5Yk");
   abi->dcb_draw_index_get_size = SYM("sceAgcDcbDrawIndexGetSize", "6ee9Hd3EWXQ");
   abi->dcb_set_index_size = SYM("sceAgcDcbSetIndexSize", "GIIW2J37e70");
   abi->dcb_nop = SYM("sceAgcDcbNop", "LtTouSCZjHM");
   abi->dcb_nop_get_size = SYM("sceAgcDcbNopGetSize", "t7PlZ9nt5Lc");

   abi->driver_get_reserved_dmem = SYM("sceAgcDriverGetReservedDmemForAgc", "Um-jkyDy9rI");
   abi->driver_notify_default_states = SYM("sceAgcDriverNotifyDefaultStates", "nR6xhiFsOoc");
   abi->driver_set_flip = SYM("sceAgcDriverSetFlip", "cwbxjPSJ7WQ");
   abi->driver_submit_dcb = SYM("sceAgcDriverSubmitDcb", "UglJIZjGssM");
   abi->driver_agr_submit_dcb = SYM("sceAgcDriverAgrSubmitDcb", "AhGvpITrf4M");
   abi->driver_submit_multi_dcbs = SYM("sceAgcDriverSubmitMultiDcbs", "6UzEidRZwkg");
   abi->driver_wait_safe = SYM("sceAgcDriverWaitUntilSafeForRendering", "u8BkdHb1+Po");

   /* Do not attempt calls with placeholder NIDs. */
   if (sprx_dlopen("libSceAgc", &abi->agc_handle) != 0)
      return false;
   abi->agc_loaded = true;

   if (sprx_dlopen("libSceAgcDriver", &abi->driver_handle) != 0)
   {
      agc_ps5_abi_shutdown(abi);
      return false;
   }
   abi->driver_loaded = true;

   ok &= resolve_one(abi->agc_handle, &abi->create_shader);
   ok &= resolve_one(abi->agc_handle, &abi->dcb_wait_safe);
   ok &= resolve_one(abi->agc_handle, &abi->dcb_set_flip);
   ok &= resolve_one(abi->agc_handle, &abi->dcb_set_index_buffer);
   ok &= resolve_one(abi->agc_handle, &abi->dcb_set_index_count);
   ok &= resolve_one(abi->agc_handle, &abi->dcb_draw_index);
   ok &= resolve_one(abi->agc_handle, &abi->dcb_draw_index_get_size);
   ok &= resolve_one(abi->agc_handle, &abi->dcb_set_index_size);
   ok &= resolve_one(abi->agc_handle, &abi->dcb_nop);
   ok &= resolve_one(abi->agc_handle, &abi->dcb_nop_get_size);

   ok &= resolve_one(abi->driver_handle, &abi->driver_get_reserved_dmem);
   ok &= resolve_one(abi->driver_handle, &abi->driver_notify_default_states);
   ok &= resolve_one(abi->driver_handle, &abi->driver_set_flip);
   ok &= resolve_one(abi->driver_handle, &abi->driver_submit_dcb);
   ok &= resolve_one(abi->driver_handle, &abi->driver_agr_submit_dcb);
   ok &= resolve_one(abi->driver_handle, &abi->driver_submit_multi_dcbs);
   ok &= resolve_one(abi->driver_handle, &abi->driver_wait_safe);

   if (!ok)
   {
      agc_ps5_abi_shutdown(abi);
      return false;
   }

   /* init/link_shaders remain intentionally unresolved until their exact
    * FW-3.20 NIDs are extracted from the complete export table. */
   return true;
}

bool agc_ps5_abi_symbols_ready(const agc_ps5_abi_t *abi)
{
   if (!abi || !abi->agc_loaded || !abi->driver_loaded)
      return false;

   return abi->create_shader.address &&
          abi->dcb_wait_safe.address &&
          abi->dcb_set_flip.address &&
          abi->dcb_set_index_buffer.address &&
          abi->dcb_set_index_count.address &&
          abi->dcb_draw_index.address &&
          abi->driver_submit_dcb.address &&
          abi->driver_agr_submit_dcb.address;
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

void agc_ps5_abi_shutdown(agc_ps5_abi_t *abi)
{
   if (!abi)
      return;

   if (abi->driver_loaded)
   {
      (void)sprx_dlclose(abi->driver_handle);
      abi->driver_loaded = false;
      abi->driver_handle = 0;
   }
   if (abi->agc_loaded)
   {
      (void)sprx_dlclose(abi->agc_handle);
      abi->agc_loaded = false;
      abi->agc_handle = 0;
   }

   memset(abi, 0, sizeof(*abi));
}

#undef SYM
