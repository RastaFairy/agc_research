#include "agc_p0_decoder.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static uint32_t pkt3(uint8_t opcode, uint32_t payload_dwords)
{
    assert(payload_dwords > 0 && payload_dwords <= 0x4000);
    return 0xC0000000u | ((payload_dwords - 1u) << 16) | ((uint32_t)opcode << 8);
}

static void test_golden(void)
{
    const uint32_t stream[] = {
        pkt3(0x69, 3), 0x00028000u, 0x00000001u, 0x00000002u,
        pkt3(0x76, 2), 0x00000010u, 0x12345678u,
        pkt3(0x79, 2), 0x00000020u, 0xCAFEBABEu,
        pkt3(0x26, 2), 0x00100000u, 0x00000000u,
        pkt3(0x2D, 2), 3u, 0x00000010u,
        pkt3(0x37, 5), 0u, 0x00200000u, 0u, 0x11223344u, 0x55667788u,
        pkt3(0x46, 1), 0x00000001u,
        pkt3(0x3C, 5), 1u, 2u, 3u, 4u, 5u,
        pkt3(0x49, 6), 1u, 2u, 3u, 4u, 5u, 6u,
    };

    agc_ir_program_t p;
    agc_ir_program_init(&p);
    agc_decode_error_t e;
    memset(&e, 0, sizeof(e));
    assert(agc_decode_p0(stream, sizeof(stream) / sizeof(stream[0]), NULL, &p, &e) == 0);
    assert(p.count == 9);
    assert(p.ops[0].kind == AGC_IR_SET_REG);
    assert(p.ops[0].u.set_reg.reg_class == AGC_REG_CONTEXT);
    assert(p.ops[3].kind == AGC_IR_DRAW);
    assert(p.ops[4].kind == AGC_IR_DRAW);
    assert(p.ops[5].kind == AGC_IR_WRITE_DATA);
    assert(p.ops[6].u.sync.sync_kind == AGC_SYNC_EVENT_WRITE);
    assert(p.ops[7].u.sync.sync_kind == AGC_SYNC_WAIT_REG_MEM);
    assert(p.ops[8].u.sync.sync_kind == AGC_SYNC_RELEASE_MEM);
    assert(agc_ir_append_present(&p, 1, 0) == 0);
    assert(p.ops[p.count - 1].kind == AGC_IR_PRESENT);
    agc_ir_program_free(&p);
}

static void test_reject_unknown(void)
{
    const uint32_t stream[] = { pkt3(0x24, 1), 0u }; /* DRAW_INDIRECT is P1 */
    agc_ir_program_t p;
    agc_ir_program_init(&p);
    agc_decode_error_t e;
    memset(&e, 0, sizeof(e));
    assert(agc_decode_p0(stream, 2, NULL, &p, &e) != 0);
    assert(e.opcode == 0x24u);
    assert(strstr(e.message, "unsupported P0 opcode") != NULL);
    agc_ir_program_free(&p);
}

static void test_reject_truncated(void)
{
    const uint32_t stream[] = { pkt3(0x2D, 2), 3u };
    agc_ir_program_t p;
    agc_ir_program_init(&p);
    agc_decode_error_t e;
    memset(&e, 0, sizeof(e));
    assert(agc_decode_p0(stream, 2, NULL, &p, &e) != 0);
    assert(strstr(e.message, "truncated") != NULL || strstr(e.message, "requires") != NULL);
    agc_ir_program_free(&p);
}

int main(void)
{
    test_golden();
    test_reject_unknown();
    test_reject_truncated();
    puts("AGC PS5 Stage 25 P0 decoder: PASS");
    puts("P0 IR: SetReg/Draw/WriteData/Sync/Present");
    puts("Unsupported opcodes: fail-closed");
    return 0;
}
