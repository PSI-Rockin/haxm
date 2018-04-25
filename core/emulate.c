/*
 * Copyright (c) 2018 Alexandro Sanchez Bach <alexandro@phi.nz>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   1. Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 *   3. Neither the name of the copyright holder nor the names of its
 *      contributors may be used to endorse or promote products derived from
 *      this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "include/emulate.h"

/* Instruction flags */
#define INSN_MOV     ((uint64_t)1 <<  0)
#define INSN_MODRM   ((uint64_t)1 <<  1)
#define INSN_BYTEOP  ((uint64_t)1 <<  2)
#define INSN_GROUP   ((uint64_t)1 <<  3)
/* Implementation flags */
#define INSN_NOTIMPL ((uint64_t)1 << 32)
#define INSN_FASTOP  ((uint64_t)1 << 33)

#define PF_SEG_OVERRIDE_NONE        0
// Each of the following denotes the presence of a segment override prefix
//   http://wiki.osdev.org/X86-64_Instruction_Encoding
#define PF_SEG_OVERRIDE_CS          1  // 0x2e
#define PF_SEG_OVERRIDE_SS          2  // 0x36
#define PF_SEG_OVERRIDE_DS          3  // 0x3e
#define PF_SEG_OVERRIDE_ES          4  // 0x26
#define PF_SEG_OVERRIDE_FS          5  // 0x64
#define PF_SEG_OVERRIDE_GS          6  // 0x65

#define  X1(...)  __VA_ARGS__
#define  X2(...)  X1(__VA_ARGS__), X1(__VA_ARGS__)
#define  X3(...)  X2(__VA_ARGS__), X1(__VA_ARGS__)
#define  X4(...)  X2(__VA_ARGS__), X2(__VA_ARGS__)
#define  X5(...)  X4(__VA_ARGS__), X1(__VA_ARGS__)
#define  X6(...)  X4(__VA_ARGS__), X2(__VA_ARGS__)
#define  X7(...)  X4(__VA_ARGS__), X3(__VA_ARGS__)
#define  X8(...)  X4(__VA_ARGS__), X4(__VA_ARGS__)
#define X16(...)  X8(__VA_ARGS__), X8(__VA_ARGS__)

/* Emulator ops */
#define READ_GPR(idx) \
    ctxt->ops->read_gpr(ctxt->vcpu, idx)
#define WRITE_GPR(idx, value) \
    ctxt->ops->write_gpr(ctxt->vcpu, idx, value)

/* Operand decoders */
#define DECL_DECODER(name) \
    static void decode_##name(em_context_t*, em_operand_t*)
DECL_DECODER(op_none);
DECL_DECODER(op_modrm_reg);
DECL_DECODER(op_modrm_rm);
DECL_DECODER(op_imm);
DECL_DECODER(op_simm8);
DECL_DECODER(op_acc);

#define \
    N { \
        .flags      = INSN_NOTIMPL \
    }
#define \
    I(_handler, _dec_dst, _dec_src1, _dec_src2, _flags) { \
        .handler      = &_handler,            \
        .decode_dst   = &decode_##_dec_dst,   \
        .decode_src1  = &decode_##_dec_src1,  \
        .decode_src2  = &decode_##_dec_src2,  \
        .flags        = _flags                \
    }
#define \
    G(_group, _dec_dst, _dec_src1, _dec_src2, _flags) { \
        .group        = _group,               \
        .decode_dst   = &decode_##_dec_dst,   \
        .decode_src1  = &decode_##_dec_src1,  \
        .decode_src2  = &decode_##_dec_src2,  \
        .flags        = _flags | INSN_GROUP | INSN_MODRM \
    }

#define \
    F(_handler, _dec_dst, _dec_src1, _dec_src2, _flags) \
    I(_handler, _dec_dst, _dec_src1, _dec_src2, _flags | INSN_FASTOP)

#define I2_BV(_handler, _dec_dst, _dec_src1, _dec_src2, _flags) \
    I(_handler, _dec_dst, _dec_src1, _dec_src2, (_flags | INSN_BYTEOP)), \
    I(_handler, _dec_dst, _dec_src1, _dec_src2, (_flags))
#define F2_BV(_handler, _dec_dst, _dec_src1, _dec_src2, _flags) \
    F(_handler, _dec_dst, _dec_src1, _dec_src2, (_flags | INSN_BYTEOP)), \
    F(_handler, _dec_dst, _dec_src1, _dec_src2, (_flags))
    
#define F6_ALU(_handler, _flags) \
    F2_BV(_handler, op_modrm_rm, op_modrm_reg, op_none, (_flags | INSN_MODRM)), \
    F2_BV(_handler, op_modrm_reg, op_modrm_rm, op_none, (_flags | INSN_MODRM)), \
    F2_BV(_handler, op_acc, op_imm, op_none, (_flags))

static const struct em_opcode_t opcode_group1[8] = {
    F(em_add, op_none, op_none, op_none, 0),
    F(em_or,  op_none, op_none, op_none, 0),
    F(em_adc, op_none, op_none, op_none, 0),
    F(em_sbb, op_none, op_none, op_none, 0),
    F(em_and, op_none, op_none, op_none, 0),
    F(em_sub, op_none, op_none, op_none, 0),
    F(em_xor, op_none, op_none, op_none, 0),
    F(em_cmp, op_none, op_none, op_none, 0),
};

static const struct em_opcode_t opcode_table[256] = {
    /* 0x00 - 0x07 */
    F6_ALU(em_add, 0), X2(N),
    /* 0x08 - 0x0F */
    F6_ALU(em_or, 0),  X2(N),
    /* 0x10 - 0x17 */
    F6_ALU(em_adc, 0), X2(N),
    /* 0x18 - 0x1F */
    F6_ALU(em_sbb, 0), X2(N),
    /* 0x20 - 0x27 */
    F6_ALU(em_and, 0), X2(N),
    /* 0x28 - 0x2F */
    F6_ALU(em_sub, 0), X2(N),
    /* 0x30 - 0x37 */
    F6_ALU(em_xor, 0), X2(N),
    /* 0x38 - 0x3F */
    F6_ALU(em_cmp, 0), X2(N),
    /* 0x40 - 0x47 */
    X8(F(em_inc, op_modrm_reg, op_none, op_none, 0)),
    /* 0x48 - 0x4F */
    X8(F(em_dec, op_modrm_reg, op_none, op_none, 0)),
    /* 0x50 - 0x7F */
    X16(N), X16(N), X16(N),
    /* 0x80 - 0x8F */
    G(opcode_group1, op_modrm_rm, op_imm, op_none, INSN_BYTEOP),
    G(opcode_group1, op_modrm_rm, op_imm, op_none, 0),
    G(opcode_group1, op_modrm_rm, op_imm, op_none, INSN_BYTEOP),
    G(opcode_group1, op_modrm_rm, op_simm8, op_none, 0),
    X4(N), X8(N),
    /* 0x90 - 0x9F */
    X16(N), X16(N), X16(N), X16(N),
    X16(N), X16(N), X16(N)
};

static const struct em_opcode_t opcode_table_0F[256] = {
    /* 0x00 - 0xFF */
    X16(N), X16(N), X16(N), X16(N),
    X16(N), X16(N), X16(N), X16(N),
    X16(N), X16(N), X16(N), X16(N),
    X16(N), X16(N), X16(N), X16(N),
};

static const struct em_opcode_t opcode_table_0F38[256] = {
    /* 0x00 - 0xFF */
    X16(N), X16(N), X16(N), X16(N),
    X16(N), X16(N), X16(N), X16(N),
    X16(N), X16(N), X16(N), X16(N),
    X16(N), X16(N), X16(N), X16(N),
};

static const struct em_opcode_t opcode_table_0F3A[256] = {
    /* 0x00 - 0xFF */
    X16(N), X16(N), X16(N), X16(N),
    X16(N), X16(N), X16(N), X16(N),
    X16(N), X16(N), X16(N), X16(N),
    X16(N), X16(N), X16(N), X16(N),
};

/* Emulate accesses to guest memory */
static int segmented_read(struct em_context_t *ctxt,
                          struct operand_mem_t *mem,
                          void *data, unsigned size)
{
    ctxt->ops->read_mem(ctxt->vcpu, mem->ea, data, size);
    return EM_CONTINUE;
}

static int segmented_write(struct em_context_t *ctxt,
                           struct operand_mem_t *mem,
                           void *data, unsigned size)
{
    ctxt->ops->write_mem(ctxt->vcpu, mem->ea, data, size);
    return EM_CONTINUE;
}

static int operand_read(struct em_context_t *ctxt,
                        struct em_operand_t *op)
{
    switch (op->type) {
    case OP_NONE:
    case OP_IMM:
        return EM_CONTINUE;
    case OP_REG:
        op->value = READ_GPR(op->reg.index);
        return EM_CONTINUE;
    case OP_MEM:
        return segmented_read(ctxt, &op->mem, &op->value, op->size);
    default:
        return EM_ERROR;
    }
}

static int operand_write(struct em_context_t *ctxt,
                         struct em_operand_t *op)
{
    switch (op->type) {
    case OP_NONE:
    case OP_IMM:
        return EM_CONTINUE;
    case OP_REG:
        WRITE_GPR(op->reg.index, op->value);
        return EM_CONTINUE;
    case OP_MEM:
        return segmented_write(ctxt, &op->mem, &op->value, op->size);
    default:
        return EM_ERROR;
    }
}

static uint8_t insn_fetch_u8(struct em_context_t *ctxt)
{
    uint8_t result = *(uint8_t*)(&ctxt->insn[ctxt->len]);
    ctxt->len += 1;
    return result;
}

static uint16_t insn_fetch_u16(struct em_context_t *ctxt)
{
    uint16_t result = *(uint16_t*)(&ctxt->insn[ctxt->len]);
    ctxt->len += 2;
    return result;
}

static uint32_t insn_fetch_u32(struct em_context_t *ctxt)
{
    uint32_t result = *(uint32_t*)(&ctxt->insn[ctxt->len]);
    ctxt->len += 4;
    return result;
}

static uint64_t insn_fetch_u64(struct em_context_t *ctxt)
{
    uint64_t result = *(uint64_t*)(&ctxt->insn[ctxt->len]);
    ctxt->len += 8;
    return result;
}

static void decode_prefixes(struct em_context_t *ctxt)
{
    uint8_t b;

    /* Intel SDM Vol. 2A: 2.1.1 Instruction Prefixes  */
    while (true) {
        b = insn_fetch_u8(ctxt);
        switch (b) {
        /* Group 1: Lock and repeat prefixes */
        case 0xF0: // LOCK
            // Ignored (is it possible to emulate atomic operations?)
            break;
        case 0xF2: // REPNE/REPNZ
            // Unimplemented
            break;
        case 0xF3: // REP + REPE/REPZ
            // Unimplemented
            break;
        /* Group 2: Segment override prefixes */
        case 0x2E:
            ctxt->override_segment = PF_SEG_OVERRIDE_CS;
            break;
        case 0x36:
            ctxt->override_segment = PF_SEG_OVERRIDE_SS;
            break;
        case 0x3E:
            ctxt->override_segment = PF_SEG_OVERRIDE_DS;
            break;
        case 0x26:
            ctxt->override_segment = PF_SEG_OVERRIDE_ES;
            break;
        case 0x64:
            ctxt->override_segment = PF_SEG_OVERRIDE_FS;
            break;
        case 0x65:
            ctxt->override_segment = PF_SEG_OVERRIDE_GS;
            break;
        /* Group 3: Operand-size override prefix */
        case 0x66:
            ctxt->override_operand_size = 1;
            break;
        /* Group 4: Address-size override prefix */
        case 0x67:
            ctxt->override_address_size = 1;
            break;
        default:
            ctxt->len--;
            return;
        }
    }
}

static void decode_op_none(em_context_t *ctxt,
                           em_operand_t *op)
{
    op->type = OP_NONE;
}

static void decode_op_modrm_reg(em_context_t *ctxt,
                                em_operand_t *op)
{
    op->type = OP_REG;
    op->size = ctxt->operand_size;
    op->reg.index = ctxt->modrm.reg | (ctxt->rex.r << 3);
}

static void decode_op_modrm_rm(em_context_t *ctxt,
                               em_operand_t *op)
{
    uint64_t disp;
    uint32_t reg_base;
    uint32_t reg_index;
    uint8_t scale;

    // Register operand
    if (ctxt->modrm.mod == 3) {
        op->type = OP_REG;
        op->size = ctxt->operand_size;
        op->reg.index = ctxt->modrm.rm | (ctxt->rex.b << 3);
        return;
    }

    // Memory operand
    op->type = OP_MEM;
    op->size = ctxt->operand_size;
    op->mem.ea = 0;
    if (ctxt->address_size == 2) {
        /* Intel SDM Vol. 2A:
         * Table 2-1. 16-Bit Addressing Forms with the ModR/M Byte */
    }
    if (ctxt->address_size == 4 || ctxt->address_size == 8) {
        /* Intel SDM Vol. 2A:
         * Table 2-2. 32-Bit Addressing Forms with the ModR/M Byte */
        if (ctxt->modrm.rm == 4) {
            /* Intel SDM Vol. 2A:
             * Table 2-3. 32-Bit Addressing Forms with the SIB Byte */
            ctxt->sib.value = insn_fetch_u8(ctxt);
            reg_base  = ctxt->sib.base  | (ctxt->rex.b << 3);
            reg_index = ctxt->sib.index | (ctxt->rex.x << 3);
            op->mem.ea += READ_GPR(reg_base);
            op->mem.ea += READ_GPR(reg_index) * (1 << ctxt->sib.scale);
        }
        if (ctxt->modrm.mod == 0 && ctxt->modrm.rm == 5) {
            op->mem.ea += insn_fetch_u32(ctxt);
        }

        // Dislacement
        if (ctxt->modrm.mod == 1) {
            op->mem.ea += insn_fetch_u8(ctxt);
        }
        if (ctxt->modrm.mod == 2) {
            op->mem.ea += insn_fetch_u32(ctxt);
        }
    }
}

static void decode_op_imm(em_context_t *ctxt,
                          em_operand_t *op)
{
    op->type = OP_IMM;
    op->size = ctxt->operand_size;
    switch (op->size) {
    case 1:
        op->value = insn_fetch_u8(ctxt);
        break;
    case 2:
        op->value = insn_fetch_u16(ctxt);
        break;
    case 4:
        op->value = insn_fetch_u32(ctxt);
        break;
    case 8:
        op->value = insn_fetch_u32(ctxt);
        break;
    }
}

static void decode_op_simm8(em_context_t *ctxt,
    em_operand_t *op)
{
    op->type = OP_IMM;
    op->size = 1;
    op->value = (int64)((int8)insn_fetch_u8(ctxt));
}

static void decode_op_acc(struct em_context_t *ctxt,
    struct em_operand_t *op)
{
    op->type = OP_REG;
    op->reg.index = REG_RAX;
    op->value = READ_GPR(op->reg.index);
}

int em_decode_insn(struct em_context_t *ctxt, uint8_t *insn)
{
    uint8_t b;
    uint64_t flags;
    struct em_opcode_t *opcode;
    const struct em_opcode_t *opcode_group;

    switch (ctxt->mode) {
    case EM_MODE_PROT16:
        ctxt->operand_size = 2;
        ctxt->address_size = 2;
    case EM_MODE_PROT32:
        ctxt->operand_size = 4;
        ctxt->address_size = 4;
        break;
    case EM_MODE_PROT64:
        ctxt->operand_size = 4;
        ctxt->address_size = 8;
        break;
    default:
        return EM_ERROR;
    }
    ctxt->override_segment = PF_SEG_OVERRIDE_NONE;
    ctxt->override_operand_size = 0;
    ctxt->override_address_size = 0;
    ctxt->insn = insn;
    ctxt->len = 0;
    decode_prefixes(ctxt);

    /* Apply legacy prefixes */
    if (ctxt->override_operand_size) {
        ctxt->operand_size ^= (2 | 4);
    }
    if (ctxt->override_address_size) {
        ctxt->address_size ^= (ctxt->mode != EM_MODE_PROT64) ? (2 | 4) : (4 | 8);
    }

    /* Intel SDM Vol. 2A: 2.2.1 REX Prefixes */
    ctxt->rex.value = 0;
    b = insn_fetch_u8(ctxt);
    if (ctxt->mode == EM_MODE_PROT64 && b >= 0x40 && b <= 0x4F) {
        ctxt->rex.value = b;
        if (ctxt->rex.w) {
            ctxt->operand_size = 8;
        }
        b = insn_fetch_u8(ctxt);
    }

    /* Intel SDM Vol. 2A: 2.1.2 Opcodes */
    opcode = &ctxt->opcode;
    *opcode = opcode_table[b];
    if (b == 0x0F) {
        b = insn_fetch_u8(ctxt);
        switch (b) {
        case 0x38:
            b = insn_fetch_u8(ctxt);
            *opcode = opcode_table_0F38[b];
        case 0x3A:
            b = insn_fetch_u8(ctxt);
            *opcode = opcode_table_0F3A[b];

        default:
            *opcode = opcode_table_0F[b];
        }
    }

    /* Intel SDM Vol. 2A: 2.1.3 ModR/M and SIB Bytes */
    flags = opcode->flags;
    if (flags & INSN_MODRM) {
        ctxt->modrm.value = insn_fetch_u8(ctxt);
    }

    /* Apply flags */
    if (flags & INSN_BYTEOP) {
        ctxt->operand_size = 1;
    }
    if (flags & INSN_GROUP) {
        opcode_group = &opcode->group[ctxt->modrm.opc];
        opcode->handler = opcode_group->handler;
        opcode->flags |= opcode_group->flags;
    }

    /* Decoding operands */
    if (opcode->decode_dst) {
        opcode->decode_dst(ctxt, &ctxt->dst);
    }
    if (opcode->decode_src1) {
        opcode->decode_src1(ctxt, &ctxt->src1);
    }
    if (opcode->decode_src2) {
        opcode->decode_src2(ctxt, &ctxt->src2);
    }

    return 0;
}

int em_emulate_insn(struct em_context_t *ctxt)
{
    const struct em_opcode_t *opcode = &ctxt->opcode;
    void(*fast_handler)();
    void(*soft_handler)(em_context_t*);
    uint64_t eflags;
    int rc;

    // TODO: Permissions, exceptions, etc.

    // Input operands
    if (!(opcode->flags & INSN_MOV)) {
        rc = operand_read(ctxt, &ctxt->dst);
        if (rc != EM_CONTINUE)
            goto done;
    }
    rc = operand_read(ctxt, &ctxt->src1);
    if (rc != EM_CONTINUE)
        goto done;
    rc = operand_read(ctxt, &ctxt->src2);
    if (rc != EM_CONTINUE)
        goto done;

    // Emulate instruction
    if (opcode->flags & INSN_FASTOP) {
        eflags = ctxt->eflags & RFLAGS_MASK_OSZAPC;
        fast_handler = (em_handler_t *)((uintptr_t)opcode->handler
            + FASTOP_OFFSET(ctxt->dst.size));
        fastop_dispatch(fast_handler,
            &ctxt->dst.value,
            &ctxt->src1.value,
            &ctxt->src2.value,
            &eflags);
        ctxt->eflags &= ~RFLAGS_MASK_OSZAPC;
        ctxt->eflags |= eflags & RFLAGS_MASK_OSZAPC;
    } else {
        soft_handler = opcode->handler;
        soft_handler(ctxt);
    }
    
    // Output operands
    rc = operand_write(ctxt, &ctxt->dst);
    if (rc != EM_CONTINUE)
        goto done;

    rc = EM_CONTINUE;
done:
    return rc;
}
