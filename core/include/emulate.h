#ifndef HAX_CORE_EMULATE_H_
#define HAX_CORE_EMULATE_H_

#include "../include/hax.h"
#include "emulate_ops.h"

/* Access completed successfully */
#define EM_CONTINUE        0

struct em_operand_t {
    unsigned int bytes;
    enum {
        OP_NONE,
        OP_REG,
        OP_MEM,
        OP_IMM,
    } type;
    struct segmented_addr_t {
        HAX_VADDR_T addr;
        unsigned segment;
    } mem;
    union {
        uint32_t val32;
        uint64_t val64;
    } value;
};

struct em_instruction_t {
    em_handler_t handler;
    uint64_t flags;
};

struct em_context_t {
    struct em_instruction_t *insn;
    struct em_operand_t dst;
    struct em_operand_t src1;
    struct em_operand_t src2;
    uint32_t eflags;
};

int decode_insn(struct em_context_t *ctxt);
int emulate_insn(struct em_context_t *ctxt);

#endif /* HAX_CORE_EMULATE_H_ */
