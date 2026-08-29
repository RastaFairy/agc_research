#ifndef AGC_PS5_DCB_H
#define AGC_PS5_DCB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Reconstructed from Kyty/prosper's AGC Gen5 DCB layout. */
typedef struct agc_ps5_dcb {
    uint32_t *bottom;
    uint32_t *top;
    uint32_t *cursor_up;
    uint32_t *cursor_down;
    void *callback;       /* guest callback; opaque here */
    void *user_data;
    uint32_t reserved_dw;
} agc_ps5_dcb_t;

/* PM4/NOP sub-operations used by the Gen5 DCB frontend. */
enum {
    AGC_PS5_IT_NOP               = 0x10,
    AGC_PS5_R_DRAW_INDEX         = 0x03,
    AGC_PS5_R_DRAW_INDEX_AUTO    = 0x04,
    AGC_PS5_R_SET_INDEX_BASE     = 0x1b,
    AGC_PS5_R_SET_INDEX_COUNT    = 0x1c,
    AGC_PS5_R_DRAW_INDEX_OFFSET  = 0x1d,
};

/* Packet builder API. All functions return false on insufficient DCB space. */
bool agc_ps5_dcb_init(agc_ps5_dcb_t *dcb, void *memory, size_t bytes);
size_t agc_ps5_dcb_used_dw(const agc_ps5_dcb_t *dcb);
size_t agc_ps5_dcb_free_dw(const agc_ps5_dcb_t *dcb);

bool agc_ps5_dcb_nop(agc_ps5_dcb_t *dcb, uint32_t count_dw);
bool agc_ps5_dcb_set_index_buffer(agc_ps5_dcb_t *dcb, uint64_t address);
bool agc_ps5_dcb_set_index_count(agc_ps5_dcb_t *dcb, uint32_t count);
bool agc_ps5_dcb_draw_index(agc_ps5_dcb_t *dcb, uint32_t count);
bool agc_ps5_dcb_draw_index_offset(agc_ps5_dcb_t *dcb, uint32_t count, uint32_t offset);

/* Debug dump for bring-up; output is deterministic and has no platform calls. */
void agc_ps5_dcb_dump(const agc_ps5_dcb_t *dcb);

#ifdef __cplusplus
}
#endif

#endif
