#ifndef HAX_CORE_EMULATE_H_
#define HAX_CORE_EMULATE_H_

#include "../include/hax.h"
#include "emulate_ops.h"

/* Access completed successfully */
#define EM_CONTINUE        0

typedef enum {
    EM_MODE_REAL,    /* Real mode */
    EM_MODE_PROT16,  /* Protected mode (16-bit) */
    EM_MODE_PROT32,  /* Protected mode (32-bit) */
    EM_MODE_PROT64,  /* Protected mode (64-bit) */
} em_mode_t;

typedef enum {
    OP_NONE,
    OP_REG,
    OP_MEM,
    OP_IMM,
    OP_ACC,
} em_operand_type_t;

typedef struct em_operand_t {
    uint32_t width;
    em_operand_type_t type;
    union {
        struct operand_mem_t {
            vaddr_t addr;
            uint32_t segment;
        } mem;
        uint32_t reg;
        uint64_t value;
    };
} em_operand_t;

typedef struct em_opcode_t {
    em_handler_t* handler;
    em_operand_type_t type_dst;
    em_operand_type_t type_src1;
    em_operand_type_t type_src2;
    uint64_t flags;
} em_opcode_t;

typedef struct em_context_t {
    int mode;
    int override_segment;
    int override_operand_size;
    int override_address_size;
    uint8_t *insn;

    uint8_t rex_r;
    uint8_t rex_w;
    const struct em_opcode_t *opcode;
    struct em_operand_t dst;
    struct em_operand_t src1;
    struct em_operand_t src2;
    uint32_t eflags;
} em_context_t;

int em_decode_insn(struct em_context_t *ctxt, uint8_t *insn);
int em_emulate_insn(struct em_context_t *ctxt);

#endif /* HAX_CORE_EMULATE_H_ */
