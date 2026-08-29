#ifndef AGC_PS5_ABI_H
#define AGC_PS5_ABI_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ABI discovery layer for the PS5 FW 3.20 AGC stubs.
 *
 * IMPORTANT:
 *   This header deliberately contains addresses + NIDs, not guessed C
 *   prototypes. The public generated stubs expose symbols/NIDs, but not the
 *   original Sony function signatures.
 */

typedef struct agc_ps5_abi_symbol
{
   const char *name;
   const char *nid;
   void       *address;
} agc_ps5_abi_symbol_t;

typedef struct agc_ps5_abi
{
   unsigned short agc_handle;
   unsigned short agc_driver_handle;
   bool            agc_loaded;
   bool            agc_driver_loaded;

   agc_ps5_abi_symbol_t create_shader;
   agc_ps5_abi_symbol_t dcb_wait_safe;
   agc_ps5_abi_symbol_t dcb_set_flip;
   agc_ps5_abi_symbol_t dcb_set_index_buffer;
   agc_ps5_abi_symbol_t dcb_set_index_count;
   agc_ps5_abi_symbol_t dcb_draw_index;
   agc_ps5_abi_symbol_t driver_submit_dcb;
} agc_ps5_abi_t;

bool agc_ps5_abi_init(agc_ps5_abi_t *abi);
void agc_ps5_abi_shutdown(agc_ps5_abi_t *abi);
bool agc_ps5_abi_complete(const agc_ps5_abi_t *abi);

/* Returns NULL when the symbol is not available. */
void *agc_ps5_abi_resolve(unsigned short handle, const char *nid);

#ifdef __cplusplus
}
#endif

#endif /* AGC_PS5_ABI_H */
