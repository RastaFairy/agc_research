#ifndef AGC_P0_DECODER_H
#define AGC_P0_DECODER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum agc_ir_kind {
    AGC_IR_SET_REG = 0,
    AGC_IR_DRAW,
    AGC_IR_WRITE_DATA,
    AGC_IR_SYNC,
    AGC_IR_PRESENT
} agc_ir_kind_t;

typedef enum agc_reg_class {
    AGC_REG_CONTEXT = 0,
    AGC_REG_SH,
    AGC_REG_UCONFIG
} agc_reg_class_t;

typedef enum agc_sync_kind {
    AGC_SYNC_WAIT_REG_MEM = 0,
    AGC_SYNC_EVENT_WRITE,
    AGC_SYNC_RELEASE_MEM
} agc_sync_kind_t;

typedef struct agc_ir_op {
    agc_ir_kind_t kind;
    size_t source_dword;
    uint8_t opcode;
    union {
        struct {
            agc_reg_class_t reg_class;
            uint32_t start_reg;
            const uint32_t *values;
            size_t value_count;
        } set_reg;
        struct {
            bool indexed;
            uint32_t vertex_or_index_count;
            uint32_t initiator;
            uint64_t index_base;
            uint32_t index_count;
        } draw;
        struct {
            uint32_t control;
            uint64_t address;
            const uint32_t *data;
            size_t data_count;
        } write_data;
        struct {
            agc_sync_kind_t sync_kind;
            const uint32_t *payload;
            size_t payload_count;
        } sync;
        struct {
            uint32_t buffer_index;
            uint32_t flip_arg;
        } present;
    } u;
} agc_ir_op_t;

typedef struct agc_ir_program {
    agc_ir_op_t *ops;
    size_t count;
    size_t capacity;
    uint32_t *owned_words;
    size_t owned_words_count;
} agc_ir_program_t;

typedef struct agc_decode_error {
    size_t dword_offset;
    uint8_t opcode;
    char message[160];
} agc_decode_error_t;

typedef struct agc_decoder_config {
    bool allow_type2_nop;
} agc_decoder_config_t;

void agc_ir_program_init(agc_ir_program_t *program);
void agc_ir_program_free(agc_ir_program_t *program);

void agc_decoder_config_default(agc_decoder_config_t *config);

int agc_decode_p0(const uint32_t *stream,
                  size_t dword_count,
                  const agc_decoder_config_t *config,
                  agc_ir_program_t *program,
                  agc_decode_error_t *error);

/* Present is intentionally a semantic boundary, not a guessed PM4 opcode. */
int agc_ir_append_present(agc_ir_program_t *program,
                          uint32_t buffer_index,
                          uint32_t flip_arg);

const char *agc_ir_kind_name(agc_ir_kind_t kind);
const char *agc_opcode_name(uint8_t opcode);

#ifdef __cplusplus
}
#endif

#endif
