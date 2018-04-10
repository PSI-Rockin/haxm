#include "include/emulate.h"

/* Instruction flags */
#define INSN_MOV (1 << 20)

/* Emulate accesses to guest memory */
static int segmented_read(struct em_context_t *ctxt,
    struct segmented_addr_t *addr, void *data, unsigned size)
{
    return EM_CONTINUE;
}

static int segmented_write(struct em_context_t *ctxt,
    struct segmented_addr_t *addr, void *data, unsigned size)
{
    return EM_CONTINUE;
}

int decode_insn(struct em_context_t *ctxt)
{
    return 0;
}

int emulate_insn(struct em_context_t *ctxt)
{
    struct em_instruction_t *insn = ctxt->insn;
    int rc;

    // TODO: Permissions, exceptions, etc.

    // Input operands
    if (ctxt->src1.type == OP_MEM) {
        rc = segmented_read(ctxt,
            &ctxt->src1.mem, &ctxt->src1.value, ctxt->src1.bytes);
        if (rc != EM_CONTINUE)
            goto done;
    }
    if (ctxt->src2.type == OP_MEM) {
        rc = segmented_read(ctxt,
            &ctxt->src2.mem, &ctxt->src2.value, ctxt->src2.bytes);
        if (rc != EM_CONTINUE)
            goto done;
    }
    if (ctxt->dst.type == OP_MEM && !(insn->flags & INSN_MOV)) {
        rc = segmented_read(ctxt,
            &ctxt->dst.mem, &ctxt->dst.value, ctxt->dst.bytes);
        if (rc != EM_CONTINUE)
            goto done;
    }

    // Emulate instruction
    fastop_dispatch(insn->handler,
        &ctxt->src1.value,
        &ctxt->src2.value,
        &ctxt->dst.value,
        &ctxt->eflags);

    // Output operands
    if (ctxt->dst.type == OP_MEM) {
        rc = segmented_write(ctxt,
            &ctxt->dst.mem, &ctxt->dst.value, ctxt->dst.bytes);
        if (rc != EM_CONTINUE)
            goto done;
    }

done:
    return 0;
}
