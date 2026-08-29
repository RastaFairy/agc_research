#ifndef AGC_PS5_ABI_H
#define AGC_PS5_ABI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct agc_ps5_abi_symbol
{
   const char *name;
   const char *nid;
   void       *address;
} agc_ps5_abi_symbol_t;

typedef struct agc_ps5_abi
{
   unsigned short agc_handle;
   unsigned short driver_handle;
   bool agc_loaded;
   bool driver_loaded;

   /* Library-level AGC. */
   agc_ps5_abi_symbol_t init;
   agc_ps5_abi_symbol_t get_register_defaults2;
   agc_ps5_abi_symbol_t create_shader;
   agc_ps5_abi_symbol_t link_shaders;

   /* DCB packet helpers. */
   agc_ps5_abi_symbol_t dcb_wait_safe;
   agc_ps5_abi_symbol_t dcb_set_flip;
   agc_ps5_abi_symbol_t dcb_set_index_buffer;
   agc_ps5_abi_symbol_t dcb_set_index_count;
   agc_ps5_abi_symbol_t dcb_draw_index;
   agc_ps5_abi_symbol_t dcb_draw_index_get_size;
   agc_ps5_abi_symbol_t dcb_set_index_size;
   agc_ps5_abi_symbol_t dcb_nop;
   agc_ps5_abi_symbol_t dcb_nop_get_size;

   /* Driver-side submission/control. */
   agc_ps5_abi_symbol_t driver_get_reserved_dmem;
   agc_ps5_abi_symbol_t driver_notify_default_states;
   agc_ps5_abi_symbol_t driver_set_flip;
   agc_ps5_abi_symbol_t driver_submit_dcb;
   agc_ps5_abi_symbol_t driver_agr_submit_dcb;
   agc_ps5_abi_symbol_t driver_submit_multi_dcbs;
   agc_ps5_abi_symbol_t driver_wait_safe;
} agc_ps5_abi_t;

bool agc_ps5_abi_init(agc_ps5_abi_t *abi);
void agc_ps5_abi_shutdown(agc_ps5_abi_t *abi);

/* Capability checks only; no guessed Sony prototypes are invoked. */
bool agc_ps5_abi_symbols_ready(const agc_ps5_abi_t *abi);
void *agc_ps5_abi_resolve(unsigned short handle, const char *nid);

#ifdef __cplusplus
}
#endif

#endif
