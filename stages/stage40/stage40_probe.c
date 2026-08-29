#include <stdint.h>

extern void sceAgcDriverSubmitDcb(void);

volatile uintptr_t stage40_submit_address(void)
{
    return (uintptr_t)&sceAgcDriverSubmitDcb;
}

int main(void)
{
    /* Deliberately do not call sceAgcDriverSubmitDcb. */
    return stage40_submit_address() != 0 ? 0 : 1;
}
