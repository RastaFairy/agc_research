#include "agc_ps5_dcb.h"

#include <stdio.h>
#include <string.h>

static uint32_t agc_ps5_pm4(uint32_t len_dw, uint32_t op, uint32_t r)
{
    /* Kyty/prosper encoding: packet length includes header + payload. */
    return 0xC0000000u
         | (((len_dw - 2u) & 0x3fffu) << 16u)
         | ((op & 0xffu) << 8u)
         | ((r & 0x3fu) << 2u);
}

static uint32_t *agc_ps5_alloc(agc_ps5_dcb_t *dcb, size_t count)
{
    if (!dcb || !dcb->cursor_up || !dcb->cursor_down || count == 0)
        return NULL;

    if ((size_t)(dcb->cursor_down - dcb->cursor_up) < count)
        return NULL;

    uint32_t *p = dcb->cursor_up;
    dcb->cursor_up += count;
    return p;
}

bool agc_ps5_dcb_init(agc_ps5_dcb_t *dcb, void *memory, size_t bytes)
{
    if (!dcb || !memory || bytes < 16 || (bytes & 3u) != 0)
        return false;

    memset(dcb, 0, sizeof(*dcb));
    dcb->bottom = (uint32_t *)memory;
    dcb->top = dcb->bottom + bytes / sizeof(uint32_t);
    dcb->cursor_up = dcb->bottom;
    dcb->cursor_down = dcb->top;
    dcb->reserved_dw = 0;
    return true;
}

size_t agc_ps5_dcb_used_dw(const agc_ps5_dcb_t *dcb)
{
    if (!dcb || !dcb->bottom || !dcb->cursor_up)
        return 0;
    return (size_t)(dcb->cursor_up - dcb->bottom);
}

size_t agc_ps5_dcb_free_dw(const agc_ps5_dcb_t *dcb)
{
    if (!dcb || !dcb->cursor_up || !dcb->cursor_down)
        return 0;
    return (size_t)(dcb->cursor_down - dcb->cursor_up);
}

bool agc_ps5_dcb_nop(agc_ps5_dcb_t *dcb, uint32_t count_dw)
{
    if (count_dw == 0)
        return false;

    uint32_t *p = agc_ps5_alloc(dcb, count_dw);
    if (!p)
        return false;

    p[0] = agc_ps5_pm4(count_dw, AGC_PS5_IT_NOP, 0);
    for (uint32_t i = 1; i < count_dw; ++i)
        p[i] = 0;
    return true;
}

bool agc_ps5_dcb_set_index_buffer(agc_ps5_dcb_t *dcb, uint64_t address)
{
    /* prosper/Kyty identifies this packet as a 3-dword custom NOP packet. */
    uint32_t *p = agc_ps5_alloc(dcb, 3);
    if (!p)
        return false;

    p[0] = agc_ps5_pm4(3, AGC_PS5_IT_NOP, AGC_PS5_R_SET_INDEX_BASE);
    p[1] = (uint32_t)(address & 0xffffffffu);
    p[2] = (uint32_t)(address >> 32);
    return true;
}

bool agc_ps5_dcb_set_index_count(agc_ps5_dcb_t *dcb, uint32_t count)
{
    uint32_t *p = agc_ps5_alloc(dcb, 2);
    if (!p)
        return false;

    p[0] = agc_ps5_pm4(2, AGC_PS5_IT_NOP, AGC_PS5_R_SET_INDEX_COUNT);
    p[1] = count;
    return true;
}

bool agc_ps5_dcb_draw_index(agc_ps5_dcb_t *dcb, uint32_t count)
{
    /* The Gen5 DrawIndex packet is 7 dwords in the current reference implementation. */
    uint32_t *p = agc_ps5_alloc(dcb, 7);
    if (!p)
        return false;

    p[0] = agc_ps5_pm4(7, AGC_PS5_IT_NOP, AGC_PS5_R_DRAW_INDEX);
    p[1] = count;
    p[2] = 0;
    p[3] = 0;
    p[4] = 0;
    p[5] = 0;
    p[6] = 0;
    return true;
}

bool agc_ps5_dcb_draw_index_offset(agc_ps5_dcb_t *dcb, uint32_t count, uint32_t offset)
{
    uint32_t *p = agc_ps5_alloc(dcb, 3);
    if (!p)
        return false;

    p[0] = agc_ps5_pm4(3, AGC_PS5_IT_NOP, AGC_PS5_R_DRAW_INDEX_OFFSET);
    p[1] = count;
    p[2] = offset;
    return true;
}

void agc_ps5_dcb_dump(const agc_ps5_dcb_t *dcb)
{
    if (!dcb || !dcb->bottom)
        return;

    size_t n = agc_ps5_dcb_used_dw(dcb);
    for (size_t i = 0; i < n; ++i)
        printf("DCB[%04zu] = 0x%08x\n", i, dcb->bottom[i]);
}
