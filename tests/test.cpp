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

#include "gtest/gtest.h"
#include "keystone/keystone.h"

extern "C" {
#include "../core/include/emulate.h"
}

/* Emulator operations */
struct test_cpu_t {
    uint64_t gpr[16];
    uint64_t rip;
    uint64_t flags;
};

static uint64_t test_read_gpr(void *obj, uint32_t reg_index)
{
    test_cpu_t *vcpu = reinterpret_cast<test_cpu_t*>(obj);
    if (reg_index >= 16)
        throw std::exception("Register index OOB");
    return vcpu->gpr[reg_index];
}

static void test_write_gpr(void *obj, uint32_t reg_index, uint64_t value)
{
    test_cpu_t *vcpu = reinterpret_cast<test_cpu_t*>(obj);
    if (reg_index >= 16)
        throw std::exception("Register index OOB");
    vcpu->gpr[reg_index] = value;
}

class EmulatorTest : public testing::Test {
private:
    ks_engine *ks;
    test_cpu_t vcpu;
    em_context_t em_ctxt;
    em_vcpu_ops_t em_ops;

protected:
    virtual void SetUp()
    {
        // Initialize assembler
        ks_err err;
        err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
        ASSERT_EQ(err, KS_ERR_OK);
        err = ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_INTEL);
        ASSERT_EQ(err, KS_ERR_OK);

        // Initialize emulator
        em_ops.read_gpr = test_read_gpr;
        em_ops.write_gpr = test_write_gpr;
        em_ctxt.ops = &em_ops;
        em_ctxt.mode = EM_MODE_PROT64;
        em_ctxt.vcpu = &vcpu;
    }

    void run(const char* insn,
        const test_cpu_t& initial_state,
        const test_cpu_t& expected_state)
    {
        uint8_t *code;
        size_t count;
        size_t size;
        int err;

        vcpu = initial_state;
        err = ks_asm(ks, insn, 0, &code, &size, &count);
        ASSERT_FALSE(err);
        em_decode_insn(&em_ctxt, code);
        em_emulate_insn(&em_ctxt);
        EXPECT_FALSE(memcmp(&vcpu, &expected_state, sizeof(test_cpu_t)));
        ks_free(code);
    }
};

TEST_F(EmulatorTest, and) {
    test_cpu_t s0 = {};
    s0.gpr[REG_R14] = 0xF0F0;
    s0.gpr[REG_R12] = 0xFF00;
    test_cpu_t s1 = s0;
    s1.gpr[REG_R14] = 0xF000;
    run("and r14, r12", s0, s1);
}

TEST_F(EmulatorTest, add) {
    test_cpu_t s0 = {};
    s0.gpr[REG_R10] = 3;
    s0.gpr[REG_R11] = 5;
    test_cpu_t s1 = s0;
    s1.gpr[REG_R10] = 8;
    run("add r10, r11", s0, s1);
}
