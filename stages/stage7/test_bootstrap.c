#include "agc_ps5_bootstrap.h"
#include <stdio.h>
#include <string.h>

int main(void)
{
    size_t count = 0;
    const agc_ps5_nid_entry_t *table = agc_ps5_bootstrap_table(&count);

    if (!table || count != 12) return 1;

    if (strcmp(table[0].name, "sceAgcInit") != 0 ||
        strcmp(table[0].nid, "kW3GLb7QfPg") != 0) return 2;

    if (strcmp(table[10].name, "sceAgcDriverSubmitDcb") != 0 ||
        strcmp(table[10].nid, "UglJIZjGssM") != 0) return 3;

    if (strcmp(table[11].name, "sceAgcDriverAgrSubmitDcb") != 0 ||
        strcmp(table[11].nid, "AhGvpITrf4M") != 0) return 4;

    agc_ps5_boot_state_t state = AGC_PS5_BOOT_UNLOADED;
    for (agc_ps5_boot_state_t next = AGC_PS5_BOOT_ABI_RESOLVED;
         next <= AGC_PS5_BOOT_SUBMIT_READY; next++) {
        if (agc_ps5_bootstrap_advance(&state, next) != 0) return 5;
    }

    printf("NID table entries = %zu\n", count);
    printf("final state = %s\n", agc_ps5_bootstrap_state_name(state));
    printf("AGC PS5 Stage 7 bootstrap inventory: PASS\n");
    printf("No Sony function prototype has been assumed.\n");
    return 0;
}
