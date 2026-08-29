#ifndef AGC_PS5_BOOTSTRAP_H
#define AGC_PS5_BOOTSTRAP_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum agc_ps5_boot_state {
    AGC_PS5_BOOT_UNLOADED = 0,
    AGC_PS5_BOOT_ABI_RESOLVED,
    AGC_PS5_BOOT_AGC_READY,
    AGC_PS5_BOOT_REG_DEFAULTS_READY,
    AGC_PS5_BOOT_DCB_READY,
    AGC_PS5_BOOT_SUBMIT_READY
} agc_ps5_boot_state_t;

typedef struct agc_ps5_nid_entry {
    const char *name;
    const char *nid;
} agc_ps5_nid_entry_t;

const agc_ps5_nid_entry_t *agc_ps5_bootstrap_table(size_t *count);
int agc_ps5_bootstrap_advance(agc_ps5_boot_state_t *state,
                              agc_ps5_boot_state_t next);
const char *agc_ps5_bootstrap_state_name(agc_ps5_boot_state_t state);

#ifdef __cplusplus
}
#endif

#endif
