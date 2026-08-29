#include "agc_p0_decoder.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PM4_TYPE_MASK 0xC0000000u
#define PM4_TYPE3     0xC0000000u
#define PM4_TYPE2     0x80000000u
#define PM4_COUNT_MASK 0x3FFF0000u
#define PM4_OPCODE_MASK 0x0000FF00u

#define IT_INDEX_BASE      0x26u
#define IT_DRAW_INDEX      0x2Bu
#define IT_DRAW_INDEX_AUTO 0x2Du
#define IT_WRITE_DATA      0x37u
#define IT_WAIT_REG_MEM    0x3Cu
#define IT_EVENT_WRITE     0x46u
#define IT_RELEASE_MEM     0x49u
#define IT_SET_CONTEXT_REG 0x69u
#define IT_SET_SH_REG      0x76u
#define IT_SET_UCONFIG_REG 0x79u

typedef struct packet_view {
    uint8_t opcode;
    uint32_t count_field;
    const uint32_t *payload;
    size_t payload_count;
} packet_view_t;

static void error_set(agc_decode_error_t *error,
                      size_t offset,
                      uint8_t opcode,
                      const char *message)
{
    if (!error)
        return;
    error->dword_offset = offset;
    error->opcode = opcode;
    snprintf(error->message, sizeof(error->message), "%s", message ? message : "decode error");
}

void agc_ir_program_init(agc_ir_program_t *program)
{
    if (!program)
        return;
    memset(program, 0, sizeof(*program));
}

void agc_ir_program_free(agc_ir_program_t *program)
{
    if (!program)
        return;
    free(program->ops);
    free(program->owned_words);
    memset(program, 0, sizeof(*program));
}

static int reserve_ops(agc_ir_program_t *program, size_t extra)
{
    if (!program || extra > SIZE_MAX - program->count)
        return -1;
    if (program->count + extra <= program->capacity)
        return 0;

    size_t cap = program->capacity ? program->capacity * 2u : 16u;
    while (cap < program->count + extra) {
        if (cap > SIZE_MAX / 2u)
            return -1;
        cap *= 2u;
    }
    agc_ir_op_t *next = realloc(program->ops, cap * sizeof(*next));
    if (!next)
        return -1;
    program->ops = next;
    program->capacity = cap;
    return 0;
}

static const uint32_t *own_words(agc_ir_program_t *program,
                                 const uint32_t *src,
                                 size_t count)
{
    if (count == 0)
        return NULL;
    if (!program || count > SIZE_MAX / sizeof(uint32_t))
        return NULL;
    size_t old = program->owned_words_count;
    if (old > SIZE_MAX - count)
        return NULL;
    uint32_t *next = realloc(program->owned_words,
                             (old + count) * sizeof(uint32_t));
    if (!next)
        return NULL;
    memcpy(next + old, src, count * sizeof(uint32_t));
    program->owned_words = next;
    program->owned_words_count = old + count;
    return next + old;
}

static int push_op(agc_ir_program_t *program, const agc_ir_op_t *op)
{
    if (reserve_ops(program, 1) != 0)
        return -1;
    program->ops[program->count++] = *op;
    return 0;
}

void agc_decoder_config_default(agc_decoder_config_t *config)
{
    if (!config)
        return;
    config->allow_type2_nop = false;
}

static int parse_header(size_t offset,
                        const uint32_t *stream,
                        size_t remaining,
                        packet_view_t *packet,
                        agc_decode_error_t *error)
{
    uint32_t header = stream[0];
    if ((header & PM4_TYPE_MASK) != PM4_TYPE3) {
        error_set(error, offset, 0, "unsupported packet type: P0 decoder accepts Type-3 PM4 only");
        return -1;
    }

    uint32_t count_field = (header & PM4_COUNT_MASK) >> 16;
    size_t payload_count = (size_t)count_field + 1u;
    if (payload_count > remaining - 1u) {
        error_set(error, offset, (uint8_t)((header & PM4_OPCODE_MASK) >> 8),
                  "truncated Type-3 packet");
        return -1;
    }

    packet->opcode = (uint8_t)((header & PM4_OPCODE_MASK) >> 8);
    packet->count_field = count_field;
    packet->payload = stream + 1;
    packet->payload_count = payload_count;
    return 0;
}

static int decode_set_reg(size_t offset,
                          uint8_t opcode,
                          agc_reg_class_t cls,
                          const packet_view_t *p,
                          agc_ir_program_t *program,
                          agc_decode_error_t *error)
{
    if (p->payload_count < 2) {
        error_set(error, offset, opcode, "SET_*_REG requires start register and at least one value");
        return -1;
    }
    const uint32_t *vals = own_words(program, p->payload + 1, p->payload_count - 1);
    if (!vals) {
        error_set(error, offset, opcode, "out of memory copying register values");
        return -1;
    }
    agc_ir_op_t op;
    memset(&op, 0, sizeof(op));
    op.kind = AGC_IR_SET_REG;
    op.source_dword = offset;
    op.opcode = opcode;
    op.u.set_reg.reg_class = cls;
    op.u.set_reg.start_reg = p->payload[0];
    op.u.set_reg.values = vals;
    op.u.set_reg.value_count = p->payload_count - 1;
    return push_op(program, &op);
}

static int decode_index_base(size_t offset,
                             const packet_view_t *p,
                             agc_ir_program_t *program,
                             agc_decode_error_t *error)
{
    if (p->payload_count < 2) {
        error_set(error, offset, IT_INDEX_BASE, "INDEX_BASE requires low/high address words");
        return -1;
    }
    agc_ir_op_t op;
    memset(&op, 0, sizeof(op));
    op.kind = AGC_IR_DRAW;
    op.source_dword = offset;
    op.opcode = IT_INDEX_BASE;
    op.u.draw.indexed = true;
    op.u.draw.index_base = (uint64_t)p->payload[0] | ((uint64_t)p->payload[1] << 32);
    return push_op(program, &op);
}

static int decode_draw(size_t offset,
                       uint8_t opcode,
                       const packet_view_t *p,
                       agc_ir_program_t *program,
                       agc_decode_error_t *error)
{
    agc_ir_op_t op;
    memset(&op, 0, sizeof(op));
    op.kind = AGC_IR_DRAW;
    op.source_dword = offset;
    op.opcode = opcode;
    op.u.draw.indexed = (opcode == IT_DRAW_INDEX);

    if (opcode == IT_DRAW_INDEX_AUTO) {
        if (p->payload_count < 2) {
            error_set(error, offset, opcode, "DRAW_INDEX_AUTO requires count and initiator");
            return -1;
        }
        op.u.draw.vertex_or_index_count = p->payload[0];
        op.u.draw.initiator = p->payload[1];
    } else {
        if (p->payload_count < 4) {
            error_set(error, offset, opcode, "DRAW_INDEX minimal decoder expects four payload dwords");
            return -1;
        }
        op.u.draw.index_count = p->payload[0];
        op.u.draw.index_base = (uint64_t)p->payload[1] | ((uint64_t)p->payload[2] << 32);
        op.u.draw.initiator = p->payload[3];
    }
    return push_op(program, &op);
}

static int decode_write_data(size_t offset,
                             const packet_view_t *p,
                             agc_ir_program_t *program,
                             agc_decode_error_t *error)
{
    if (p->payload_count < 4) {
        error_set(error, offset, IT_WRITE_DATA, "WRITE_DATA requires control, address and data");
        return -1;
    }
    const uint32_t *data = own_words(program, p->payload + 3, p->payload_count - 3);
    if (p->payload_count > 3 && !data) {
        error_set(error, offset, IT_WRITE_DATA, "out of memory copying WRITE_DATA payload");
        return -1;
    }
    agc_ir_op_t op;
    memset(&op, 0, sizeof(op));
    op.kind = AGC_IR_WRITE_DATA;
    op.source_dword = offset;
    op.opcode = IT_WRITE_DATA;
    op.u.write_data.control = p->payload[0];
    op.u.write_data.address = (uint64_t)p->payload[1] | ((uint64_t)p->payload[2] << 32);
    op.u.write_data.data = data;
    op.u.write_data.data_count = p->payload_count - 3;
    return push_op(program, &op);
}

static int decode_sync(size_t offset,
                       uint8_t opcode,
                       agc_sync_kind_t kind,
                       const packet_view_t *p,
                       agc_ir_program_t *program,
                       agc_decode_error_t *error)
{
    const uint32_t *payload = own_words(program, p->payload, p->payload_count);
    if (p->payload_count && !payload) {
        error_set(error, offset, opcode, "out of memory copying sync payload");
        return -1;
    }
    agc_ir_op_t op;
    memset(&op, 0, sizeof(op));
    op.kind = AGC_IR_SYNC;
    op.source_dword = offset;
    op.opcode = opcode;
    op.u.sync.sync_kind = kind;
    op.u.sync.payload = payload;
    op.u.sync.payload_count = p->payload_count;
    return push_op(program, &op);
}

int agc_decode_p0(const uint32_t *stream,
                  size_t dword_count,
                  const agc_decoder_config_t *config_in,
                  agc_ir_program_t *program,
                  agc_decode_error_t *error)
{
    agc_decoder_config_t default_config;
    if (!config_in) {
        agc_decoder_config_default(&default_config);
        config_in = &default_config;
    }
    if (!stream || !program) {
        error_set(error, 0, 0, "invalid decoder arguments");
        return -1;
    }

    size_t i = 0;
    while (i < dword_count) {
        uint32_t header = stream[i];
        uint32_t type = header & PM4_TYPE_MASK;
        if (type == PM4_TYPE2) {
            if (!config_in->allow_type2_nop || header != PM4_TYPE2) {
                error_set(error, i, 0, "unsupported Type-2 packet");
                return -1;
            }
            i++;
            continue;
        }

        packet_view_t p;
        if (parse_header(i, stream + i, dword_count - i, &p, error) != 0)
            return -1;

        int rc = 0;
        switch (p.opcode) {
        case IT_INDEX_BASE:
            rc = decode_index_base(i, &p, program, error);
            break;
        case IT_DRAW_INDEX:
        case IT_DRAW_INDEX_AUTO:
            rc = decode_draw(i, p.opcode, &p, program, error);
            break;
        case IT_WRITE_DATA:
            rc = decode_write_data(i, &p, program, error);
            break;
        case IT_WAIT_REG_MEM:
            rc = decode_sync(i, p.opcode, AGC_SYNC_WAIT_REG_MEM, &p, program, error);
            break;
        case IT_EVENT_WRITE:
            rc = decode_sync(i, p.opcode, AGC_SYNC_EVENT_WRITE, &p, program, error);
            break;
        case IT_RELEASE_MEM:
            rc = decode_sync(i, p.opcode, AGC_SYNC_RELEASE_MEM, &p, program, error);
            break;
        case IT_SET_CONTEXT_REG:
            rc = decode_set_reg(i, p.opcode, AGC_REG_CONTEXT, &p, program, error);
            break;
        case IT_SET_SH_REG:
            rc = decode_set_reg(i, p.opcode, AGC_REG_SH, &p, program, error);
            break;
        case IT_SET_UCONFIG_REG:
            rc = decode_set_reg(i, p.opcode, AGC_REG_UCONFIG, &p, program, error);
            break;
        default:
            error_set(error, i, p.opcode, "unsupported P0 opcode");
            return -1;
        }
        if (rc != 0)
            return rc;
        i += 1u + p.payload_count;
    }

    return 0;
}

int agc_ir_append_present(agc_ir_program_t *program,
                          uint32_t buffer_index,
                          uint32_t flip_arg)
{
    agc_ir_op_t op;
    memset(&op, 0, sizeof(op));
    op.kind = AGC_IR_PRESENT;
    op.source_dword = SIZE_MAX;
    op.opcode = 0;
    op.u.present.buffer_index = buffer_index;
    op.u.present.flip_arg = flip_arg;
    return push_op(program, &op);
}

const char *agc_ir_kind_name(agc_ir_kind_t kind)
{
    switch (kind) {
    case AGC_IR_SET_REG:    return "SetReg";
    case AGC_IR_DRAW:       return "Draw";
    case AGC_IR_WRITE_DATA: return "WriteData";
    case AGC_IR_SYNC:       return "Sync";
    case AGC_IR_PRESENT:    return "Present";
    default:                return "Unknown";
    }
}

const char *agc_opcode_name(uint8_t opcode)
{
    switch (opcode) {
    case IT_INDEX_BASE:      return "INDEX_BASE";
    case IT_DRAW_INDEX:      return "DRAW_INDEX";
    case IT_DRAW_INDEX_AUTO: return "DRAW_INDEX_AUTO";
    case IT_WRITE_DATA:      return "WRITE_DATA";
    case IT_WAIT_REG_MEM:    return "WAIT_REG_MEM";
    case IT_EVENT_WRITE:     return "EVENT_WRITE";
    case IT_RELEASE_MEM:     return "RELEASE_MEM";
    case IT_SET_CONTEXT_REG: return "SET_CONTEXT_REG";
    case IT_SET_SH_REG:      return "SET_SH_REG";
    case IT_SET_UCONFIG_REG: return "SET_UCONFIG_REG";
    default:                 return "UNKNOWN";
    }
}
