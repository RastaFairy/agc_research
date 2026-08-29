#include "agc_p0_host.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t mix32(uint32_t x)
{
    x ^= x >> 16;
    x *= 0x7feb352du;
    x ^= x >> 15;
    x *= 0x846ca68bu;
    x ^= x >> 16;
    return x;
}

static void clear_fb(agc_host_framebuffer_t *fb, uint32_t rgba)
{
    size_t n = (size_t)fb->width * fb->height;
    for (size_t i = 0; i < n; ++i)
        fb->pixels[i] = rgba;
}

static void draw_reference_rect(agc_host_framebuffer_t *fb, uint32_t seed)
{
    const uint32_t w = fb->width;
    const uint32_t h = fb->height;
    uint32_t mixed = mix32(seed);
    unsigned rw = w / 3u + (mixed & 31u);
    unsigned rh = h / 3u + ((mixed >> 5) & 31u);
    if (rw > w) rw = w;
    if (rh > h) rh = h;
    unsigned x0 = (w - rw) / 2u;
    unsigned y0 = (h - rh) / 2u;
    uint8_t r = (uint8_t)(mixed & 0xffu);
    uint8_t g = (uint8_t)((mixed >> 8) & 0xffu);
    uint8_t b = (uint8_t)((mixed >> 16) & 0xffu);
    uint32_t px = 0xff000000u | ((uint32_t)r << 24) | ((uint32_t)g << 16) | ((uint32_t)b << 8);
    /* The reference backend is deliberately not a claim about AGC rasterization.
       It gives the IR a deterministic visible result so the pipeline can be tested. */
    for (unsigned y = y0; y < y0 + rh; ++y)
        for (unsigned x = x0; x < x0 + rw; ++x)
            fb->pixels[(size_t)y * w + x] = px;
}

int agc_host_init(agc_host_executor_t *exec, uint32_t width, uint32_t height)
{
    if (!exec || width == 0 || height == 0)
        return -1;
    memset(exec, 0, sizeof(*exec));
    size_t pixels = (size_t)width * height;
    if (pixels > SIZE_MAX / sizeof(uint32_t))
        return -1;
    exec->fb.width = width;
    exec->fb.height = height;
    exec->fb.pixels = calloc(pixels, sizeof(uint32_t));
    if (!exec->fb.pixels)
        return -1;
    exec->memory_words = 1u << 20;
    exec->memory = calloc(exec->memory_words, sizeof(uint32_t));
    if (!exec->memory) {
        free(exec->fb.pixels);
        memset(exec, 0, sizeof(*exec));
        return -1;
    }
    clear_fb(&exec->fb, 0xff101010u);
    return 0;
}

void agc_host_free(agc_host_executor_t *exec)
{
    if (!exec) return;
    free(exec->fb.pixels);
    free(exec->memory);
    memset(exec, 0, sizeof(*exec));
}

int agc_host_execute(agc_host_executor_t *exec, const agc_ir_program_t *program)
{
    if (!exec || !program)
        return -1;
    uint32_t draw_serial = 0;
    for (size_t i = 0; i < program->count; ++i) {
        const agc_ir_op_t *op = &program->ops[i];
        switch (op->kind) {
        case AGC_IR_SET_REG:
            exec->stats.set_reg_ops++;
            break;
        case AGC_IR_DRAW:
            exec->stats.draw_ops++;
            draw_serial += op->u.draw.vertex_or_index_count ? op->u.draw.vertex_or_index_count : op->u.draw.index_count;
            draw_reference_rect(&exec->fb, draw_serial + (uint32_t)i);
            break;
        case AGC_IR_WRITE_DATA: {
            exec->stats.write_data_ops++;
            uint64_t word_addr = op->u.write_data.address / sizeof(uint32_t);
            if (word_addr >= exec->memory_words || op->u.write_data.data_count > exec->memory_words - (size_t)word_addr)
                return -2;
            memcpy(exec->memory + word_addr, op->u.write_data.data,
                   op->u.write_data.data_count * sizeof(uint32_t));
            break;
        }
        case AGC_IR_SYNC:
            exec->stats.sync_ops++;
            break;
        case AGC_IR_PRESENT:
            exec->stats.present_ops++;
            exec->presented = true;
            break;
        default:
            exec->stats.unsupported_semantics++;
            return -3;
        }
    }
    return 0;
}

int agc_host_write_ppm(const agc_host_framebuffer_t *fb, const char *path)
{
    if (!fb || !fb->pixels || !path)
        return -1;
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    fprintf(f, "P6\n%u %u\n255\n", fb->width, fb->height);
    for (size_t i = 0, n = (size_t)fb->width * fb->height; i < n; ++i) {
        uint32_t p = fb->pixels[i];
        unsigned char rgb[3] = { (unsigned char)(p >> 24), (unsigned char)(p >> 16), (unsigned char)(p >> 8) };
        if (fwrite(rgb, 1, 3, f) != 3) { fclose(f); return -1; }
    }
    fclose(f);
    return 0;
}
