#include "agc_ps5_abi_manifest.h"
#include <stdio.h>
#include <string.h>

static int has(const agc_ps5_symbol_t *s, size_t n, const char *name, const char *nid)
{
    for (size_t i = 0; i < n; ++i)
        if (strcmp(s[i].name, name) == 0 && strcmp(s[i].nid, nid) == 0)
            return 1;
    return 0;
}

int main(void)
{
    size_t n = 0;
    const agc_ps5_symbol_t *s = agc_ps5_abi_manifest(&n);
    if (!s || n != 17) return 1;

    if (!has(s, n, "sceAgcInit", "kW3GLb7QfPg")) return 2;
    if (!has(s, n, "sceAgcGetRegisterDefaults2", "2JtWUUiYBXs")) return 3;
    if (!has(s, n, "sceAgcDriverSubmitDcb", "UglJIZjGssM")) return 4;
    if (!has(s, n, "sceAgcDriverAgrSubmitDcb", "AhGvpITrf4M")) return 5;
    if (!has(s, n, "sceAgcCbBranch", "w1KFAHVqpaU")) return 6;
    if (has(s, n, "sceAgcSubmitVariant", "w1KFAHVqpaU")) return 7;

    printf("Stage 8 ABI manifest: PASS\\n");
    printf("symbols = %zu\\n", n);
    printf("w1KFAHVqpaU = sceAgcCbBranch\\n");
    printf("sceAgcDriverSubmitDcb = UglJIZjGssM\\n");
    printf("No typed Sony ABI call enabled.\\n");
    return 0;
}
