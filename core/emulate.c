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
#define INSN_MOV     ((uint64_t)1 <<  0) /* Instruction ignores destination original value */
#define INSN_MODRM   ((uint64_t)1 <<  1) /* Instruction expects ModRM byte */
#define INSN_BYTEOP  ((uint64_t)1 <<  2) /* Instruction accesses 1-byte registers */
#define INSN_GROUP   ((uint64_t)1 <<  3) /* Instruction opcode is extended via ModRM byte */
#define INSN_REP     ((uint64_t)1 <<  4) /* Instruction supports REP prefixes */
#define INSN_NOFLAGS ((uint64_t)1 <<  5) /* Instruction ignores flags */
/* Implementation flags */
#define INSN_NOTIMPL ((uint64_t)1 << 32)
#define INSN_FASTOP  ((uint64_t)1 << 33)

/* Operand flags */
#define OP_READ_PENDING        (1 <<  0)
#define OP_READ_FINISHED       (1 <<  1)
#define OP_WRITE_PENDING       (1 <<  2)
#define OP_WRITE_FINISHED      (1 <<  3)

/* Prefixes */
#define PREFIX_LOCK   0xF0
#define PREFIX_REPNE  0xF2
#define PREFIX_REPE   0xF3

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
#define READ_GPR(idx, size) \
    ctxt->ops->read_gpr(ctxt->vcpu, idx, size)
#define WRITE_GPR(idx, value, size) \
    ctxt->ops->write_gpr(ctxt->vcpu, idx, value, size)

#define BX (uint16_t)(ctxt->ops->read_gpr(ctxt->vcpu, REG_RBX, 2))
#define BP (uint16_t)(ctxt->ops->read_gpr(ctxt->vcpu, REG_RBP, 2))
#define SI (uint16_t)(ctxt->ops->read_gpr(ctxt->vcpu, REG_RSI, 2))
#define DI (uint16_t)(ctxt->ops->read_gpr(ctxt->vcpu, REG_RDI, 2))

/* Operand decoders */
#define DECL_DECODER(name) \
    static void decode_##name(em_context_t*, em_operand_t*)
DECL_DECODER(op_none);
DECL_DECODER(op_modrm_reg);
DECL_DECODER(op_modrm_rm);
DECL_DECODER(op_moffs);
DECL_DECODER(op_imm);
DECL_DECODER(op_simm8);
DECL_DECODER(op_acc);
DECL_DECODER(op_di);
DECL_DECODER(op_si);

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

/* Soft-emulation */
static void em_mov(struct em_context_t *ctxt);
static void em_movzx(struct em_context_t *ctxt);
static void em_xchg(struct em_context_t *ctxt);

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

static const struct em_opcode_t opcode_group3[8] = {
    F(em_test, op_modrm_rm, op_imm, op_none, 0),
    F(em_test, op_modrm_rm, op_imm, op_none, 0),
    F(em_not, op_modrm_rm, op_none, op_none, 0),
    F(em_neg, op_modrm_rm, op_none, op_none, 0),
};

static const struct em_opcode_t opcode_group11[8] = {
    I(em_mov, op_none, op_none, op_none, INSN_MOV),
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
    X4(N),
    I2_BV(em_mov, op_modrm_rm, op_modrm_reg, op_none, INSN_MODRM | INSN_MOV),
    I2_BV(em_mov, op_modrm_reg, op_modrm_rm, op_none, INSN_MODRM | INSN_MOV),
    X4(N),
    /* 0x90 - 0x9F */
    X16(N),
    /* 0xA0 - 0xAF */
    I2_BV(em_mov, op_acc, op_moffs, op_none, INSN_MOV),
    I2_BV(em_mov, op_moffs, op_acc, op_none, INSN_MOV),
    I2_BV(em_mov, op_di, op_si, op_none, INSN_MOV | INSN_REP), /* movs{b,w,d,q} */
    X2(N),
    X2(N),
    I2_BV(em_mov, op_di, op_acc, op_none, INSN_MOV | INSN_REP), /* stos{b,w,d,q} */
    I2_BV(em_mov, op_acc, op_si, op_none, INSN_MOV | INSN_REP), /* lods{b,w,d,q} */
    X2(N),
    /* 0xB0 - 0xBF */
    X16(N),
    /* 0xC0 - 0xCF */
    X4(N),
    X2(N),
    G(opcode_group11, op_modrm_rm, op_imm, op_none, INSN_BYTEOP),
    G(opcode_group11, op_modrm_rm, op_imm, op_none, 0),
    X8(N),
    /* 0xD0 - 0xEF */
    X16(N), X16(N),
    /* 0xF0 - 0xFF */
    X4(N),
    X2(N),
    G(opcode_group3, op_none, op_none, op_none, INSN_BYTEOP),
    G(opcode_group3, op_none, op_none, op_none, 0),
    X8(N),
};

static const struct em_opcode_t opcode_table_0F[256] = {
    /* 0x00 - 0xAF */
    X16(N), X16(N), X16(N), X16(N),
    X16(N), X16(N), X16(N), X16(N),
    X16(N), X16(N), X16(N),
    /* 0xB0 - 0xBF */
    X4(N),
    X2(N),
    I2_BV(em_movzx, op_modrm_reg, op_modrm_rm, op_none, INSN_MODRM | INSN_MOV),
    X8(N),
    /* 0xC0 - 0xFF */
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
static uint64_t get_canonical_address(struct em_context_t *ctxt,
                                      uint64_t addr, uint vaddr_bits)
{
    return ((int64)addr << (64 - vaddr_bits)) >> (64 - vaddr_bits);
}

static em_status_t get_linear_address(struct em_context_t *ctxt,
                                      struct operand_mem_t *mem,
                                      uint64_t *la)
{
    if (ctxt->mode == EM_MODE_PROT64) {
        *la = get_canonical_address(ctxt, mem->ea, 48);
    } else {
        *la = ctxt->ops->get_segment_base(ctxt->vcpu, mem->seg) + mem->ea;
    }
    return EM_CONTINUE;
}

static em_status_t segmented_read(struct em_context_t *ctxt,
                                  struct operand_mem_t *mem,
                                  void *data, unsigned size)
{
    uint64_t la;
    em_status_t rc;

    rc = get_linear_address(ctxt, mem, &la);
    if (rc != EM_CONTINUE) {
        return rc;
    }
    return ctxt->ops->read_memory(ctxt->vcpu, la, data, size);
}

static em_status_t segmented_write(struct em_context_t *ctxt,
                                   struct operand_mem_t *mem,
                                   void *data, unsigned size)
{
    uint64_t la;
    em_status_t rc;

    rc = get_linear_address(ctxt, mem, &la);
    if (rc != EM_CONTINUE) {
        return rc;
    }
    return ctxt->ops->write_memory(ctxt->vcpu, la, data, size);
}

static em_status_t operand_read(struct em_context_t *ctxt,
                                struct em_operand_t *op)
{
    em_status_t rc;
    if (op->flags & OP_READ_FINISHED) {
        return EM_CONTINUE;
    }

    switch (op->type) {
    case OP_NONE:
    case OP_IMM:
        rc = EM_CONTINUE;
        break;
    case OP_REG:
        op->value = READ_GPR(op->reg.index, op->size);
        rc = EM_CONTINUE;
        break;
    case OP_MEM:
        if (op->flags & OP_READ_PENDING) {
            rc = ctxt->ops->read_memory_post(ctxt->vcpu, &op->value, op->size);
        } else {
            rc = segmented_read(ctxt, &op->mem, &op->value, op->size);
        }
        break;
    default:
        rc = EM_ERROR;
        break;
    }

    if (rc == EM_CONTINUE) {
        op->flags |= OP_READ_FINISHED;
    } else {
        op->flags |= OP_READ_PENDING;
    }
    return rc;
}

static em_status_t operand_write(struct em_context_t *ctxt,
                                 struct em_operand_t *op)
{
    em_status_t rc;
    if (op->flags & OP_WRITE_FINISHED) {
        return EM_CONTINUE;
    }

    switch (op->type) {
    case OP_NONE:
    case OP_IMM:
        rc = EM_CONTINUE;
        break;
    case OP_REG:
        WRITE_GPR(op->reg.index, op->value, op->size);
        rc = EM_CONTINUE;
        break;
    case OP_MEM:
        if (op->flags & OP_WRITE_PENDING) {
            rc = EM_CONTINUE;
        } else {
            rc = segmented_write(ctxt, &op->mem, &op->value, op->size);
        }
        break;
    default:
        rc = EM_ERROR;
        break;
    }

    if (rc == EM_CONTINUE) {
        op->flags |= OP_WRITE_FINISHED;
    } else {
        op->flags |= OP_WRITE_PENDING;
    }
    return rc;
}

static void register_add(struct em_context_t *ctxt,
                         int reg_index, uint64_t value)
{
    WRITE_GPR(reg_index, READ_GPR(reg_index, 8) + value, 8);
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
        case PREFIX_LOCK:
            // Ignored (is it possible to emulate atomic operations?)
            ctxt->lock = b;
            break;
        case PREFIX_REPNE:
        case PREFIX_REPE:
            ctxt->rep = b;
            break;
        /* Group 2: Segment override prefixes */
        case 0x2E:
            ctxt->override_segment = SEG_CS;
            break;
        case 0x36:
            ctxt->override_segment = SEG_SS;
            break;
        case 0x3E:
            ctxt->override_segment = SEG_DS;
            break;
        case 0x26:
            ctxt->override_segment = SEG_ES;
            break;
        case 0x64:
            ctxt->override_segment = SEG_FS;
            break;
        case 0x65:
            ctxt->override_segment = SEG_GS;
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

static void decode_operands(struct em_context_t *ctxt)
{
    const struct em_opcode_t *opcode = &ctxt->opcode;

    if (opcode->decode_dst) {
        ctxt->dst.flags = 0;
        opcode->decode_dst(ctxt, &ctxt->dst);
    }
    if (opcode->decode_src1) {
        ctxt->src1.flags = 0;
        opcode->decode_src1(ctxt, &ctxt->src1);
    }
    if (opcode->decode_src2) {
        ctxt->src2.flags = 0;
        opcode->decode_src2(ctxt, &ctxt->src2);
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
    op->mem.seg = SEG_DS;
    if (ctxt->override_segment) {
        op->mem.seg = ctxt->override_segment;
    }

    if (ctxt->address_size == 2) {
        /* Intel SDM Vol. 2A:
         * Table 2-1. 16-Bit Addressing Forms with the ModR/M Byte */
        switch (ctxt->modrm.rm) {
        case 0:
            op->mem.ea = BX + SI;
            break;
        case 1:
            op->mem.ea = BX + DI;
            break;
        case 2:
            op->mem.ea = BP + SI;
            break;
        case 3:
            op->mem.ea = BP + DI;
            break;
        case 4:
            op->mem.ea = SI;
            break;
        case 5:
            op->mem.ea = DI;
            break;
        case 6:
            if (ctxt->modrm.mod == 0) {
                op->mem.ea = insn_fetch_u16(ctxt);
            } else {
                op->mem.ea = BP;
            }
            break;
        case 7:
            op->mem.ea = BX;
            break;
        }

        // Displacement
        if (ctxt->modrm.mod == 1) {
            op->mem.ea += insn_fetch_u8(ctxt);
        }
        if (ctxt->modrm.mod == 2) {
            op->mem.ea += insn_fetch_u16(ctxt);
        }
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
            scale = 1 << ctxt->sib.scale;
            op->mem.ea += READ_GPR(reg_base, ctxt->address_size);
            op->mem.ea += READ_GPR(reg_index, ctxt->address_size) * scale;
        } else if (ctxt->modrm.mod == 0 && ctxt->modrm.rm == 5) {
            op->mem.ea += insn_fetch_u32(ctxt);
        } else {
            op->mem.ea += ctxt->ops->read_gpr(ctxt->vcpu, ctxt->modrm.rm, 4);
        }

        // Displacement
        if (ctxt->modrm.mod == 1) {
            op->mem.ea += insn_fetch_u8(ctxt);
        }
        if (ctxt->modrm.mod == 2) {
            op->mem.ea += insn_fetch_u32(ctxt);
        }
    }
}

static void decode_op_moffs(em_context_t *ctxt,
                            em_operand_t *op)
{
    op->type = OP_MEM;
    op->size = ctxt->operand_size;
    op->mem.ea = 0;
    op->mem.seg = SEG_DS;
    switch (op->size) {
    case 1:
        op->mem.ea = insn_fetch_u8(ctxt);
        break;
    case 2:
        op->mem.ea = insn_fetch_u16(ctxt);
        break;
    case 4:
        op->mem.ea = insn_fetch_u32(ctxt);
        break;
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

static void decode_op_acc(em_context_t *ctxt,
                          em_operand_t *op)
{
    op->type = OP_REG;
    op->size = ctxt->operand_size;
    op->reg.index = REG_RAX;
}

static void decode_op_di(em_context_t *ctxt,
                         em_operand_t *op)
{
    op->type = OP_MEM;
    op->size = ctxt->operand_size;
    op->mem.ea = READ_GPR(REG_RDI, ctxt->address_size);
    op->mem.seg = SEG_ES;
}

static void decode_op_si(em_context_t *ctxt,
                         em_operand_t *op)
{
    op->type = OP_MEM;
    op->size = ctxt->operand_size;
    op->mem.ea = READ_GPR(REG_RSI, ctxt->address_size);
    op->mem.seg = SEG_DS;
    if (ctxt->override_segment) {
        op->mem.seg = ctxt->override_segment;
    }
}

/* Soft-emulation */
static void em_mov(struct em_context_t *ctxt)
{
    memcpy(&ctxt->dst.value, &ctxt->src1.value, ctxt->operand_size);
}

static void em_movzx(struct em_context_t *ctxt)
{
    uint64_t value = 0;
    memcpy(&value, &ctxt->src1, ctxt->operand_size);
    ctxt->dst.value = value;
}

static void em_xchg(struct em_context_t *ctxt)
{
    uint64_t src1, src2;
    src1 = ctxt->src1.value;
    src2 = ctxt->src2.value;
    ctxt->src1.value = src2;
    ctxt->src2.value = src1;
    operand_write(ctxt, &ctxt->src1);
    operand_write(ctxt, &ctxt->src2);
}

em_status_t em_decode_insn(struct em_context_t *ctxt, const uint8_t *insn)
{
    uint8_t b;
    uint64_t flags;
    struct em_opcode_t *opcode;
    const struct em_opcode_t *opcode_group;

    switch (ctxt->mode) {
    case EM_MODE_REAL:
    case EM_MODE_PROT16:
        ctxt->operand_size = 2;
        ctxt->address_size = 2;
        break;
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
    ctxt->override_segment = SEG_NONE;
    ctxt->override_operand_size = 0;
    ctxt->override_address_size = 0;
    ctxt->insn = insn;
    ctxt->lock = 0;
    ctxt->rep = 0;
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
            break;
        case 0x3A:
            b = insn_fetch_u8(ctxt);
            *opcode = opcode_table_0F3A[b];
            break;

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
        if (!opcode_group->handler) {
            return EM_ERROR;
        }
        opcode->flags |= opcode_group->flags;
        if (opcode_group->decode_dst != decode_op_none) {
            opcode->decode_dst = opcode_group->decode_dst;
        }
        if (opcode_group->decode_src1 != decode_op_none) {
            opcode->decode_src1 = opcode_group->decode_src1;
        }
        if (opcode_group->decode_src2 != decode_op_none) {
            opcode->decode_src2 = opcode_group->decode_src2;
        }
    }

    decode_operands(ctxt);
    return EM_CONTINUE;
}

em_status_t em_emulate_insn(struct em_context_t *ctxt)
{
    const struct em_opcode_t *opcode = &ctxt->opcode;
    em_status_t rc;
    ctxt->finished = false;

restart:
    // TODO: Permissions, exceptions, etc.
    if ((opcode->flags & INSN_REP) && ctxt->rep) {
        if (READ_GPR(REG_RCX, 8) == 0) {
            goto done;
        }
    }

    // Input operands
    if (!(opcode->flags & INSN_NOFLAGS)) {
        ctxt->rflags = ctxt->ops->read_rflags(ctxt->vcpu);
    }
    if (!(opcode->flags & INSN_MOV)) {
        rc = operand_read(ctxt, &ctxt->dst);
        if (rc != EM_CONTINUE)
            goto exit;
    }
    rc = operand_read(ctxt, &ctxt->src1);
    if (rc != EM_CONTINUE)
        goto exit;
    rc = operand_read(ctxt, &ctxt->src2);
    if (rc != EM_CONTINUE)
        goto exit;

    // Emulate instruction
    if (opcode->flags & INSN_FASTOP) {
        void (*fast_handler)();
        uint64_t eflags = ctxt->rflags & RFLAGS_MASK_OSZAPC;
        fast_handler = (em_handler_t *)((uintptr_t)opcode->handler
            + FASTOP_OFFSET(ctxt->dst.size));
        fastop_dispatch(fast_handler,
            &ctxt->dst.value,
            &ctxt->src1.value,
            &ctxt->src2.value,
            &eflags);
        ctxt->rflags &= ~RFLAGS_MASK_OSZAPC;
        ctxt->rflags |= eflags & RFLAGS_MASK_OSZAPC;
    } else {
        void (*soft_handler)(em_context_t*);
        soft_handler = opcode->handler;
        soft_handler(ctxt);
    }

    // Output operands
    if (!(opcode->flags & INSN_NOFLAGS)) {
        ctxt->ops->write_rflags(ctxt->vcpu, ctxt->rflags);
    }
    rc = operand_write(ctxt, &ctxt->dst);
    if (rc != EM_CONTINUE)
        goto exit;

    if (opcode->decode_dst == decode_op_di) {
        register_add(ctxt, REG_RDI, ctxt->operand_size *
            ((ctxt->rflags & RFLAGS_DF) ? -1LL : +1LL));
    }
    if (opcode->decode_src1 == decode_op_si) {
        register_add(ctxt, REG_RSI, ctxt->operand_size *
            ((ctxt->rflags & RFLAGS_DF) ? -1LL : +1LL));
    }
    if ((opcode->flags & INSN_REP) && ctxt->rep) {
        register_add(ctxt, REG_RCX, -1LL);
        if ((ctxt->rep == PREFIX_REPNE && (ctxt->rflags & RFLAGS_ZF)) ||
            (ctxt->rep == PREFIX_REPE && !(ctxt->rflags & RFLAGS_ZF))) {
            decode_operands(ctxt);
            goto restart;
        }
    }

done:
    rc = EM_CONTINUE;
    ctxt->finished = true;
    ctxt->ops->advance_rip(ctxt->vcpu, ctxt->len);

exit:
    return rc;
}
