#include "agc_ps5_submit_boundary.h"

/*
 * This declaration is intentionally only used as a symbol-presence/link probe.
 * We do not call it and do not claim this is Sony's verified C prototype.
 */
extern void sceAgcDriverSubmitDcb(void);

void agc_ps5_stage36_force_symbol_reference(void)
{
    /* Force the linker to retain a relocation to the symbol without invoking it. */
    (void)&sceAgcDriverSubmitDcb;
}
