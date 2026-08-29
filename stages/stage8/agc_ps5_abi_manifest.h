#ifndef AGC_PS5_ABI_MANIFEST_H
#define AGC_PS5_ABI_MANIFEST_H

#include <stddef.h>

typedef enum agc_ps5_symbol_kind {
    AGC_PS5_SYMBOL_AGC = 0,
    AGC_PS5_SYMBOL_AGC_DRIVER = 1
} agc_ps5_symbol_kind_t;

typedef struct agc_ps5_symbol {
    const char *name;
    const char *nid;
    agc_ps5_symbol_kind_t kind;
} agc_ps5_symbol_t;

const agc_ps5_symbol_t *agc_ps5_abi_manifest(size_t *count);

#endif
