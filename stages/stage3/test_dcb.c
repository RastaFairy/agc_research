#include "agc_ps5_dcb.h"
#include <assert.h>
#include <stdio.h>

int main(void)
{
    uint32_t memory[32] = {0};
    agc_ps5_dcb_t dcb;

    assert(agc_ps5_dcb_init(&dcb, memory, sizeof(memory)));
    assert(agc_ps5_dcb_set_index_buffer(&dcb, 0x123456789abcdef0ull));
    assert(agc_ps5_dcb_set_index_count(&dcb, 3));
    assert(agc_ps5_dcb_draw_index(&dcb, 3));
    assert(agc_ps5_dcb_used_dw(&dcb) == 12);

    /* Header and payload sanity checks. */
    assert(memory[0] == (0xC0000000u | (((3u - 2u) & 0x3fffu) << 16) |
                         (AGC_PS5_IT_NOP << 8) | (AGC_PS5_R_SET_INDEX_BASE << 2)));
    assert(memory[1] == 0x9abcdef0u);
    assert(memory[2] == 0x12345678u);
    assert(memory[4] == 3u);

    puts("AGC DCB builder self-test: PASS");
    agc_ps5_dcb_dump(&dcb);
    return 0;
}
