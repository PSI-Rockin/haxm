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

#include <vector>

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
    uint8_t mem[0x100];
};

uint64_t test_read_gpr(void* obj, uint32_t reg_index) {
    test_cpu_t* vcpu = reinterpret_cast<test_cpu_t*>(obj);
    if (reg_index >= 16) {
        throw std::exception("Register index OOB");
    }
    return vcpu->gpr[reg_index];
}

void test_write_gpr(void* obj, uint32_t reg_index, uint64_t value) {
    test_cpu_t* vcpu = reinterpret_cast<test_cpu_t*>(obj);
    if (reg_index >= 16) {
        throw std::exception("Register index OOB");
    }
    vcpu->gpr[reg_index] = value;
}

void test_read_mem(void* obj, uint64_t ea,
                   uint64_t* value, uint32_t size) {
    test_cpu_t* vcpu = reinterpret_cast<test_cpu_t*>(obj);
    if (ea + size >= 0x100) {
        throw std::exception("Effective address OOB");
    }
    switch (size) {
    case 1:
        *value = *(uint8_t*)(&vcpu->mem[ea]);
        break;
    case 2:
        *value = *(uint16_t*)(&vcpu->mem[ea]);
        break;
    case 4:
        *value = *(uint32_t*)(&vcpu->mem[ea]);
        break;
    case 8:
        *value = *(uint64_t*)(&vcpu->mem[ea]);
        break;
    default:
        throw std::exception("Unsupported access size");
    }
}
void test_write_mem(void* obj, uint64_t ea,
                    uint64_t* value, uint32_t size) {
    test_cpu_t* vcpu = reinterpret_cast<test_cpu_t*>(obj);
    if (ea + size > 0x100) {
        throw std::exception("Effective address OOB");
    }
    switch (size) {
    case 1:
        *(uint8_t*)(&vcpu->mem[ea]) = *value;
        break;
    case 2:
        *(uint16_t*)(&vcpu->mem[ea]) = *value;
        break;
    case 4:
        *(uint32_t*)(&vcpu->mem[ea]) = *value;
        break;
    case 8:
        *(uint64_t*)(&vcpu->mem[ea]) = *value;
        break;
    default:
        throw std::exception("Unsupported access size");
    }
}

/* Test class */
class EmulatorTest : public testing::Test {
private:
    ks_engine* ks;
    test_cpu_t vcpu;
    em_context_t em_ctxt;
    em_vcpu_ops_t em_ops;

protected:
    virtual void SetUp() {
        // Initialize assembler
        ks_err err;
        err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
        ASSERT_EQ(err, KS_ERR_OK);
        err = ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_INTEL);
        ASSERT_EQ(err, KS_ERR_OK);

        // Initialize emulator
        em_ops.read_gpr = test_read_gpr;
        em_ops.write_gpr = test_write_gpr;
        em_ops.read_mem = test_read_mem;
        em_ops.write_mem = test_write_mem;
        em_ctxt.ops = &em_ops;
        em_ctxt.mode = EM_MODE_PROT64;
        em_ctxt.vcpu = &vcpu;
    }

    void run(const char* insn,
        const test_cpu_t& initial_state,
        const test_cpu_t& expected_state) {
        uint8_t* code;
        size_t count;
        size_t size;
        int err;

        vcpu = initial_state;
        err = ks_asm(ks, insn, 0, &code, &size, &count);
        ASSERT_FALSE(err);
        em_ctxt.eflags = vcpu.flags;
        err = em_decode_insn(&em_ctxt, code);
        ASSERT_TRUE(err != EM_ERROR);
        err = em_emulate_insn(&em_ctxt);
        ASSERT_TRUE(err != EM_ERROR);
        vcpu.flags = em_ctxt.eflags;
        EXPECT_FALSE(memcmp(&vcpu, &expected_state, sizeof(test_cpu_t)));
        ks_free(code);
    }

    /* Test helpers */
    struct test_f6alu_t {
        uint64_t in_dst;
        uint64_t in_src;
        uint64_t in_flags;
        uint64_t out_dst;
        uint64_t out_flags;
    };

    void test_f6alu_i08(const char* insn_name,
                        const std::vector<test_f6alu_t>& tests) {
        char insn[256];
        test_cpu_t vcpu_original;
        test_cpu_t vcpu_expected;

        // Test: r8, r8
        for (const auto& test : tests) {
            snprintf(insn, sizeof(insn), "%s dl, cl", insn_name);
            vcpu_original = {};
            vcpu_original.gpr[REG_RDX] = test.in_dst;
            vcpu_original.gpr[REG_RCX] = test.in_src;
            vcpu_original.flags = test.in_flags;
            vcpu_expected = vcpu_original;
            vcpu_expected.gpr[REG_RDX] = test.out_dst;
            vcpu_expected.flags = test.out_flags;
            run(insn, vcpu_original, vcpu_expected);
        }
        // Test: r8, imm8
        for (const auto& test : tests) {
            snprintf(insn, sizeof(insn), "%s al, %d", insn_name, test.in_src);
            vcpu_original = {};
            vcpu_original.gpr[REG_RAX] = test.in_dst;
            vcpu_original.flags = test.in_flags;
            vcpu_expected = vcpu_original;
            vcpu_expected.gpr[REG_RAX] = test.out_dst;
            vcpu_expected.flags = test.out_flags;
            run(insn, vcpu_original, vcpu_expected);
        }
        // Test: m8, imm8
        for (const auto& test : tests) {
            snprintf(insn, sizeof(insn), "%s byte ptr [edx + 2*ecx + 0x10], %d", insn_name, test.in_src);
            vcpu_original = {};
            vcpu_original.gpr[REG_RDX] = 0x20;
            vcpu_original.gpr[REG_RCX] = 0x08;
            (uint8_t&)vcpu_original.mem[0x40] = test.in_dst;
            vcpu_original.flags = test.in_flags;
            vcpu_expected = vcpu_original;
            (uint8_t&)vcpu_expected.mem[0x40] = test.out_dst;
            vcpu_expected.flags = test.out_flags;
            run(insn, vcpu_original, vcpu_expected);
        }
        // Test: r8, m8 (TODO)
        // Test: m8, r8 (TODO)
    }

    void test_f6alu_i16(const char* insn_name,
                        const std::vector<test_f6alu_t>& tests) {
        char insn[256];
        test_cpu_t vcpu_original;
        test_cpu_t vcpu_expected;

        // Test: r16, r16
        for (const auto& test : tests) {
            snprintf(insn, sizeof(insn), "%s dx, cx", insn_name);
            vcpu_original = {};
            vcpu_original.gpr[REG_RDX] = test.in_dst;
            vcpu_original.gpr[REG_RCX] = test.in_src;
            vcpu_original.flags = test.in_flags;
            vcpu_expected = vcpu_original;
            vcpu_expected.gpr[REG_RDX] = test.out_dst;
            vcpu_expected.flags = test.out_flags;
            run(insn, vcpu_original, vcpu_expected);
        }
        // Test: r16, imm16
        for (const auto& test : tests) {
            snprintf(insn, sizeof(insn), "%s ax, %d", insn_name, test.in_src);
            vcpu_original = {};
            vcpu_original.gpr[REG_RAX] = test.in_dst;
            vcpu_original.flags = test.in_flags;
            vcpu_expected = vcpu_original;
            vcpu_expected.gpr[REG_RAX] = test.out_dst;
            vcpu_expected.flags = test.out_flags;
            run(insn, vcpu_original, vcpu_expected);
        }
        // Test: m16, imm16
        for (const auto& test : tests) {
            snprintf(insn, sizeof(insn), "%s word ptr [edx + 2*ecx + 0x10], %d", insn_name, test.in_src);
            vcpu_original = {};
            vcpu_original.gpr[REG_RDX] = 0x20;
            vcpu_original.gpr[REG_RCX] = 0x08;
            (uint16_t&)vcpu_original.mem[0x40] = test.in_dst;
            vcpu_original.flags = test.in_flags;
            vcpu_expected = vcpu_original;
            (uint16_t&)vcpu_expected.mem[0x40] = test.out_dst;
            vcpu_expected.flags = test.out_flags;
            run(insn, vcpu_original, vcpu_expected);
        }
        // Test: r16, m16 (TODO)
        // Test: m16, r16 (TODO)
    }

    void test_f6alu_i32(const char* insn_name,
                        const std::vector<test_f6alu_t>& tests) {
        char insn[256];
        test_cpu_t vcpu_original;
        test_cpu_t vcpu_expected;

        // Test: r32, r32
        for (const auto& test : tests) {
            snprintf(insn, sizeof(insn), "%s edx, ecx", insn_name);
            vcpu_original = {};
            vcpu_original.gpr[REG_RDX] = test.in_dst;
            vcpu_original.gpr[REG_RCX] = test.in_src;
            vcpu_original.flags = test.in_flags;
            vcpu_expected = vcpu_original;
            vcpu_expected.gpr[REG_RDX] = test.out_dst;
            vcpu_expected.flags = test.out_flags;
            run(insn, vcpu_original, vcpu_expected);
        }
        // Test: r32, imm32
        for (const auto& test : tests) {
            snprintf(insn, sizeof(insn), "%s eax, %d", insn_name, test.in_src);
            vcpu_original = {};
            vcpu_original.gpr[REG_RAX] = test.in_dst;
            vcpu_original.flags = test.in_flags;
            vcpu_expected = vcpu_original;
            vcpu_expected.gpr[REG_RAX] = test.out_dst;
            vcpu_expected.flags = test.out_flags;
            run(insn, vcpu_original, vcpu_expected);
        }
        // Test: m32, imm32
        for (const auto& test : tests) {
            snprintf(insn, sizeof(insn), "%s dword ptr [edx + 2*ecx + 0x10], %d", insn_name, test.in_src);
            vcpu_original = {};
            vcpu_original.gpr[REG_RDX] = 0x20;
            vcpu_original.gpr[REG_RCX] = 0x08;
            (uint32_t&)vcpu_original.mem[0x40] = test.in_dst;
            vcpu_original.flags = test.in_flags;
            vcpu_expected = vcpu_original;
            (uint32_t&)vcpu_expected.mem[0x40] = test.out_dst;
            vcpu_expected.flags = test.out_flags;
            run(insn, vcpu_original, vcpu_expected);
        }
        // Test: r32, m32 (TODO)
        // Test: m32, r32 (TODO)
    }

    void test_f6alu_i64(const char* insn_name,
                        const std::vector<test_f6alu_t>& tests) {
        char insn[256];
        test_cpu_t vcpu_original;
        test_cpu_t vcpu_expected;

        // Test: r64, r64
        for (const auto& test : tests) {
            snprintf(insn, sizeof(insn), "%s rdx, r12", insn_name);
            vcpu_original = {};
            vcpu_original.gpr[REG_RDX] = test.in_dst;
            vcpu_original.gpr[REG_R12] = test.in_src;
            vcpu_original.flags = test.in_flags;
            vcpu_expected = vcpu_original;
            vcpu_expected.gpr[REG_RDX] = test.out_dst;
            vcpu_expected.flags = test.out_flags;
            run(insn, vcpu_original, vcpu_expected);
        }
        // Test: r64, imm32
        for (const auto& test : tests) {
            snprintf(insn, sizeof(insn), "%s rax, %d", insn_name, test.in_src);
            vcpu_original = {};
            vcpu_original.gpr[REG_RAX] = test.in_dst;
            vcpu_original.flags = test.in_flags;
            vcpu_expected = vcpu_original;
            vcpu_expected.gpr[REG_RAX] = test.out_dst;
            vcpu_expected.flags = test.out_flags;
            run(insn, vcpu_original, vcpu_expected);
        }
        // Test: m64, imm32
        for (const auto& test : tests) {
            snprintf(insn, sizeof(insn), "%s qword ptr [edx + 2*ecx + 0x10], %d", insn_name, test.in_src);
            vcpu_original = {};
            vcpu_original.gpr[REG_RDX] = 0x20;
            vcpu_original.gpr[REG_RCX] = 0x08;
            (uint64_t&)vcpu_original.mem[0x40] = test.in_dst;
            vcpu_original.flags = test.in_flags;
            vcpu_expected = vcpu_original;
            (uint64_t&)vcpu_expected.mem[0x40] = test.out_dst;
            vcpu_expected.flags = test.out_flags;
            run(insn, vcpu_original, vcpu_expected);
        }
        // Test: r64, m64 (TODO)
        // Test: m64, r64 (TODO)
    }
};

TEST_F(EmulatorTest, insn_add) {
    test_f6alu_i08("add", {
        { 0x04, 0x05, 0,
          0x09, RFLAGS_PF },
        { 0xFF, 0x01, 0,
          0x00, RFLAGS_CF | RFLAGS_PF | RFLAGS_AF | RFLAGS_ZF },
    });
    test_f6alu_i16("add", {
        { 0x0001, 0x1234, 0,
          0x1235, RFLAGS_PF },
        { 0xF000, 0x1001, 0,
          0x0001, RFLAGS_CF },
    });
    test_f6alu_i32("add", {
        { 0x55555555, 0x11111111, RFLAGS_CF,
          0x66666666, RFLAGS_PF },
        { 0xF0000000, 0x10000000, 0,
          0x00000000, RFLAGS_CF | RFLAGS_PF | RFLAGS_ZF },
    });
    test_f6alu_i64("add", {
        { 0x2'000000FFULL, 0x0'01010002ULL, RFLAGS_CF,
          0x2'01010101ULL, RFLAGS_AF },
        { 0x0'F0000000ULL, 0x0'10000001ULL, 0,
          0x1'00000001ULL, 0 },
    });
}

TEST_F(EmulatorTest, insn_and) {
    test_f6alu_i08("and", {
        { 0x55, 0xF0, RFLAGS_CF,
          0x50, RFLAGS_PF },
        { 0xF0, 0x0F, RFLAGS_OF,
          0x00, RFLAGS_PF | RFLAGS_ZF },
    });
    test_f6alu_i16("and", {
        { 0x0001, 0xF00F, RFLAGS_CF | RFLAGS_OF,
          0x0001, 0 },
        { 0xFF00, 0xF0F0, 0,
          0xF000, RFLAGS_PF | RFLAGS_SF },
    });
    test_f6alu_i32("and", {
        { 0xFFFF0001, 0xFFFF0001, 0,
          0xFFFF0001, RFLAGS_SF },
    });
    test_f6alu_i64("and", {
        { 0xFFFF'F0F0FFFFULL, 0x0000'FFFF0000ULL, 0,
          0x0000'F0F00000ULL, RFLAGS_PF },
    });
}

TEST_F(EmulatorTest, insn_or) {
    test_f6alu_i08("or", {
        { 0x55, 0xF0, RFLAGS_CF,
          0xF5, RFLAGS_PF | RFLAGS_SF },
        { 0xF0, 0x0E, RFLAGS_OF,
          0xFE, RFLAGS_SF },
    });
}

TEST_F(EmulatorTest, insn_xor) {
    test_f6alu_i08("xor", {
        { 0x0F, 0xF0, RFLAGS_CF,
          0xFF, RFLAGS_PF| RFLAGS_SF },
        { 0xFF, 0xFF, RFLAGS_OF,
          0x00, RFLAGS_PF | RFLAGS_ZF },
    });
}
