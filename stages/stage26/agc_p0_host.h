#ifndef AGC_P0_HOST_H
#define AGC_P0_HOST_H

#include "agc_p0_decoder.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct agc_host_framebuffer {
    uint32_t width;
    uint32_t height;
    uint32_t *pixels;
} agc_host_framebuffer_t;

typedef struct agc_host_stats {
    uint32_t set_reg_ops;
    uint32_t draw_ops;
    uint32_t write_data_ops;
    uint32_t sync_ops;
    uint32_t present_ops;
    uint32_t unsupported_semantics;
} agc_host_stats_t;

typedef struct agc_host_executor {
    agc_host_framebuffer_t fb;
    agc_host_stats_t stats;
    uint32_t *memory;
    size_t memory_words;
    bool presented;
} agc_host_executor_t;

int agc_host_init(agc_host_executor_t *exec, uint32_t width, uint32_t height);
void agc_host_free(agc_host_executor_t *exec);
int agc_host_execute(agc_host_executor_t *exec, const agc_ir_program_t *program);
int agc_host_write_ppm(const agc_host_framebuffer_t *fb, const char *path);

#ifdef __cplusplus
}
#endif
#endif
