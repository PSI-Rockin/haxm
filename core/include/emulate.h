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
