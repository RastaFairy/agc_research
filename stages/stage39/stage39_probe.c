#include <stdint.h>

/* Deliberately redeclared only for the link-resolution probe.
 * No call is performed in this stage. */
extern void sceAgcDriverSubmitDcb(void);

volatile uintptr_t stage39_submit_symbol(void)
{
    return (uintptr_t)&sceAgcDriverSubmitDcb;
}

int main(void)
{
    /* Keep a live reference without executing the imported function. */
    return stage39_submit_symbol() != 0;
}
