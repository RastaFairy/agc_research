#include "agc_p0_decoder.h"
#include "agc_p0_host.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static uint32_t pkt3(uint8_t opcode, uint32_t payload_dwords)
{
    assert(payload_dwords > 0 && payload_dwords <= 0x4000);
    return 0xC0000000u | ((payload_dwords - 1u) << 16) | ((uint32_t)opcode << 8);
}

int main(void)
{
    const uint32_t stream[] = {
        pkt3(0x69, 3), 0x00028000u, 0x00000001u, 0x00000002u,
        pkt3(0x76, 2), 0x00000010u, 0x12345678u,
        pkt3(0x79, 2), 0x00000020u, 0xCAFEBABEu,
        pkt3(0x26, 2), 0x00100000u, 0x00000000u,
        pkt3(0x2D, 2), 3u, 0x00000010u,
        pkt3(0x37, 5), 0u, 0x00000000u, 0u, 0x11223344u, 0x55667788u,
        pkt3(0x46, 1), 0x00000001u,
        pkt3(0x3C, 5), 1u, 2u, 3u, 4u, 5u,
        pkt3(0x49, 6), 1u, 2u, 3u, 4u, 5u, 6u,
    };
    agc_ir_program_t p;
    agc_ir_program_init(&p);
    agc_decode_error_t e;
    memset(&e, 0, sizeof(e));
    assert(agc_decode_p0(stream, sizeof(stream)/sizeof(stream[0]), NULL, &p, &e) == 0);
    assert(agc_ir_append_present(&p, 0, 1) == 0);

    agc_host_executor_t host;
    assert(agc_host_init(&host, 320, 180) == 0);
    assert(agc_host_execute(&host, &p) == 0);
    assert(host.stats.set_reg_ops == 3);
    assert(host.stats.draw_ops == 2);
    assert(host.stats.write_data_ops == 1);
    assert(host.stats.sync_ops == 3);
    assert(host.stats.present_ops == 1);
    assert(host.presented);
    assert(host.memory[0] == 0x11223344u);
    assert(host.memory[1] == 0x55667788u);
    assert(agc_host_write_ppm(&host.fb, "stage26_reference.ppm") == 0);

    printf("AGC PS5 Stage 26 host backend: PASS\n");
    printf("framebuffer = %ux%u\n", host.fb.width, host.fb.height);
    printf("IR executed: setreg=%u draw=%u writedata=%u sync=%u present=%u\n",
           host.stats.set_reg_ops, host.stats.draw_ops, host.stats.write_data_ops,
           host.stats.sync_ops, host.stats.present_ops);
    printf("reference image: stage26_reference.ppm\n");

    agc_host_free(&host);
    agc_ir_program_free(&p);
    return 0;
}
