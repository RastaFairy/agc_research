#ifndef AGC_PS5_ABI_SUBMIT_H
#define AGC_PS5_ABI_SUBMIT_H
#include <stdint.h>

typedef struct agc_submit_command_buffer_desc {
    const uint32_t *addr;
    uint32_t dw_num;
    uint8_t flags;
    uint8_t _pad[3];
} agc_submit_command_buffer_desc_t;

_Static_assert(sizeof(agc_submit_command_buffer_desc_t) == 16, "submit descriptor must be 16 bytes");
_Static_assert(__builtin_offsetof(agc_submit_command_buffer_desc_t, addr) == 0, "addr offset");
_Static_assert(__builtin_offsetof(agc_submit_command_buffer_desc_t, dw_num) == 8, "dw_num offset");
_Static_assert(__builtin_offsetof(agc_submit_command_buffer_desc_t, flags) == 12, "flags offset");

#endif
