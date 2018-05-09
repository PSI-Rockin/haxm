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
#include <type_traits>

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

uint64_t test_read_gpr(void* obj, uint32_t reg_index, uint32_t size) {
    test_cpu_t* vcpu = reinterpret_cast<test_cpu_t*>(obj);
    if (reg_index >= 16) {
        throw std::exception("Register index OOB");
    }
    uint64_t value = 0;
    memcpy(&value, &vcpu->gpr[reg_index], size);
    return value;
}

void test_write_gpr(void* obj, uint32_t reg_index,
                    uint64_t value, uint32_t size) {
    test_cpu_t* vcpu = reinterpret_cast<test_cpu_t*>(obj);
    if (reg_index >= 16) {
        throw std::exception("Register index OOB");
    }
    memcpy(&vcpu->gpr[reg_index], &value, size);
}

em_status_t test_read_memory(void* obj, uint64_t ea,
                             uint64_t* value, uint32_t size) {
    test_cpu_t* vcpu = reinterpret_cast<test_cpu_t*>(obj);
    if (ea + size >= 0x100) {
        return EM_ERROR;
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
        return EM_ERROR;
    }
    return EM_CONTINUE;
}

em_status_t test_write_memory(void* obj, uint64_t ea,
                              uint64_t* value, uint32_t size) {
    test_cpu_t* vcpu = reinterpret_cast<test_cpu_t*>(obj);
    if (ea + size > 0x100) {
        return EM_ERROR;
    }
    switch (size) {
    case 1:
        *(uint8_t*)(&vcpu->mem[ea]) = (uint8_t)*value;
        break;
    case 2:
        *(uint16_t*)(&vcpu->mem[ea]) = (uint16_t)*value;
        break;
    case 4:
        *(uint32_t*)(&vcpu->mem[ea]) = (uint32_t)*value;
        break;
    case 8:
        *(uint64_t*)(&vcpu->mem[ea]) = (uint64_t)*value;
        break;
    default:
        return EM_ERROR;
    }
    return EM_CONTINUE;
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
        em_ops.read_memory = test_read_memory;
        em_ops.write_memory = test_write_memory;
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
        em_ctxt.eflags = static_cast<uint32_t>(vcpu.flags);
        err = em_decode_insn(&em_ctxt, code);
        ASSERT_TRUE(err != EM_ERROR);
        err = em_emulate_insn(&em_ctxt);
        ASSERT_TRUE(err != EM_ERROR);
        vcpu.flags = em_ctxt.eflags;
        EXPECT_FALSE(memcmp(&vcpu, &expected_state, sizeof(test_cpu_t)));
        ks_free(code);
    }

    /* Test cases */
    struct test_f6alu_t {
        uint64_t in_dst;
        uint64_t in_src;
        uint64_t in_flags;
        uint64_t out_dst;
        uint64_t out_flags;
    };

    /* Test helpers */
    template <int N>
    const char* gpr(int reg) {
        size_t index = 0;
        switch (N) {
        case 8:   index = 0; break;
        case 16:  index = 1; break;
        case 32:  index = 2; break;
        case 64:  index = 3; break;
        default:
            break;
        }
        std::vector<char*> regs;
        switch (reg) {
        case REG_RAX:  regs = { "al",   "ax",   "eax",  "rax" }; break;
        case REG_RCX:  regs = { "cl",   "cx",   "ecx",  "rcx" }; break;
        case REG_RDX:  regs = { "dl",   "dx",   "edx",  "rdx" }; break;
        case REG_RBX:  regs = { "bl",   "bx",   "ebx",  "rbx" }; break;
        case REG_RSP:  regs = { "spl",  "sp",   "esp",  "rsp" }; break;
        case REG_RBP:  regs = { "bpl",  "bp",   "ebp",  "rbp" }; break;
        case REG_RSI:  regs = { "sil",  "si",   "esi",  "rsi" }; break;
        case REG_RDI:  regs = { "dil",  "di",   "edi",  "rdi" }; break;
        case REG_R8:   regs = { "r8b",  "r8w",  "r8d",  "r8"  }; break;
        case REG_R9:   regs = { "r9b",  "r9w",  "r9d",  "r9"  }; break;
        case REG_R10:  regs = { "r10b", "r10w", "r10d", "r10" }; break;
        case REG_R11:  regs = { "r11b", "r11w", "r11d", "r11" }; break;
        case REG_R12:  regs = { "r12b", "r12w", "r12d", "r12" }; break;
        case REG_R13:  regs = { "r13b", "r13w", "r13d", "r13" }; break;
        case REG_R14:  regs = { "r14b", "r14w", "r14d", "r14" }; break;
        case REG_R15:  regs = { "r15b", "r15w", "r15d", "r15" }; break;
        }
        return regs[index];
    }

    template <int N>
    const char* mem() {
        size_t index = 0;
        switch (N) {
        case 8:   return "byte";
        case 16:  return "word";
        case 32:  return "dword";
        case 64:  return "qword";
        default:
            break;
        }
    }

    template <int N>
    void test_insn_rN_rN(const char* insn_name,
                         const std::vector<test_f6alu_t>& tests) {
        char insn[256];
        test_cpu_t vcpu_original;
        test_cpu_t vcpu_expected;
        snprintf(insn, sizeof(insn), "%s %s,%s", insn_name,
            gpr<N>(REG_RDX), gpr<N>(REG_RCX));

        // Run tests
        for (const auto& test : tests) {
            vcpu_original = {};
            vcpu_original.gpr[REG_RDX] = test.in_dst;
            vcpu_original.gpr[REG_RCX] = test.in_src;
            vcpu_original.flags = test.in_flags;
            vcpu_expected = vcpu_original;
            vcpu_expected.gpr[REG_RDX] = test.out_dst;
            vcpu_expected.flags = test.out_flags;
            run(insn, vcpu_original, vcpu_expected);
        }
    }

    template <int N>
    void test_insn_rN_iN(const char* insn_name,
                         const std::vector<test_f6alu_t>& tests) {
        char insn[256];
        test_cpu_t vcpu_original;
        test_cpu_t vcpu_expected;

        // Run tests
        for (const auto& test : tests) {
            snprintf(insn, sizeof(insn), "%s %s,%d", insn_name,
                gpr<N>(REG_RAX), (uint32_t)test.in_src);
            vcpu_original = {};
            vcpu_original.gpr[REG_RAX] = test.in_dst;
            vcpu_original.flags = test.in_flags;
            vcpu_expected = vcpu_original;
            vcpu_expected.gpr[REG_RAX] = test.out_dst;
            vcpu_expected.flags = test.out_flags;
            run(insn, vcpu_original, vcpu_expected);
        }
    }

    template <int N>
    void test_insn_mN_iN(const char* insn_name,
                         const std::vector<test_f6alu_t>& tests) {
        char insn[256];
        test_cpu_t vcpu_original;
        test_cpu_t vcpu_expected;

        // Run tests
        for (const auto& test : tests) {
            snprintf(insn, sizeof(insn), "%s %s ptr [edx + 2*ecx + 0x10], %d",
                insn_name, mem<N>(), (uint32_t)test.in_src);
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
    }

    template <int N>
    void test_insn_rN_mN(const char* insn_name,
                         const std::vector<test_f6alu_t>& tests) {
        char insn[256];
        test_cpu_t vcpu_original;
        test_cpu_t vcpu_expected;

        // TODO
    }

    template <int N>
    void test_insn_mN_rN(const char* insn_name,
                         const std::vector<test_f6alu_t>& tests) {
        char insn[256];
        test_cpu_t vcpu_original;
        test_cpu_t vcpu_expected;

        // TODO
    }

    template <int N>
    void test_f6alu(const char* insn_name,
                    const std::vector<test_f6alu_t>& tests) {
        test_insn_rN_rN<N>(insn_name, tests);
        test_insn_rN_iN<N>(insn_name, tests);
        test_insn_mN_iN<N>(insn_name, tests);
        test_insn_rN_mN<N>(insn_name, tests);
        test_insn_mN_rN<N>(insn_name, tests);
    }
};

TEST_F(EmulatorTest, insn_add) {
    test_f6alu<8>("add", {
        { 0x04, 0x05, 0,
          0x09, RFLAGS_PF },
        { 0xFF, 0x01, 0,
          0x00, RFLAGS_CF | RFLAGS_PF | RFLAGS_AF | RFLAGS_ZF },
    });
    test_f6alu<16>("add", {
        { 0x0001, 0x1234, 0,
          0x1235, RFLAGS_PF },
        { 0xF000, 0x1001, 0,
          0x0001, RFLAGS_CF },
    });
    test_f6alu<32>("add", {
        { 0x55555555, 0x11111111, RFLAGS_CF,
          0x66666666, RFLAGS_PF },
        { 0xF0000000, 0x10000000, 0,
          0x00000000, RFLAGS_CF | RFLAGS_PF | RFLAGS_ZF },
    });
    test_f6alu<64>("add", {
        { 0x2'000000FFULL, 0x0'01010002ULL, RFLAGS_CF,
          0x2'01010101ULL, RFLAGS_AF },
        { 0x0'F0000000ULL, 0x0'10000001ULL, 0,
          0x1'00000001ULL, 0 },
    });
}

TEST_F(EmulatorTest, insn_and) {
    test_f6alu<8>("and", {
        { 0x55, 0xF0, RFLAGS_CF,
          0x50, RFLAGS_PF },
        { 0xF0, 0x0F, RFLAGS_OF,
          0x00, RFLAGS_PF | RFLAGS_ZF },
    });
    test_f6alu<16>("and", {
        { 0x0001, 0xF00F, RFLAGS_CF | RFLAGS_OF,
          0x0001, 0 },
        { 0xFF00, 0xF0F0, 0,
          0xF000, RFLAGS_PF | RFLAGS_SF },
    });
    test_f6alu<32>("and", {
        { 0xFFFF0001, 0xFFFF0001, 0,
          0xFFFF0001, RFLAGS_SF },
    });
    test_f6alu<64>("and", {
        { 0xFFFF'F0F0FFFFULL, 0x0000'FFFF0000ULL, 0,
          0x0000'F0F00000ULL, RFLAGS_PF },
    });
}

TEST_F(EmulatorTest, insn_or) {
    test_f6alu<8>("or", {
        { 0x55, 0xF0, RFLAGS_CF,
          0xF5, RFLAGS_PF | RFLAGS_SF },
        { 0xF0, 0x0E, RFLAGS_OF,
          0xFE, RFLAGS_SF },
    });
}

TEST_F(EmulatorTest, insn_xor) {
    test_f6alu<8>("xor", {
        { 0x0F, 0xF0, RFLAGS_CF,
          0xFF, RFLAGS_PF| RFLAGS_SF },
        { 0xFF, 0xFF, RFLAGS_OF,
          0x00, RFLAGS_PF | RFLAGS_ZF },
    });
}
