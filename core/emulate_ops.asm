; x86 instruction emulation
; eax/rax - dest value
; edx/rdx - src1 value
; ecx/rcx - src2 value

option casemap:none

fop_start macro name
    align 16
    @CatStr(em_, name) proc
endm
fop_end macro name
    @CatStr(em_, name) endp
endm

; Instruction variants
fop macro instruction
    align 16
    instruction
    ret
endm
fop32 macro instruction
    fop <instruction>
endm
fop64 macro instruction
    ifdef rax
        fop <instruction>
    endif
endm

; Calling convention
reg_dst macro width
    if width eq 8
        exitm <al>
    elseif width eq 16
        exitm <ax>
    elseif width eq 32
        exitm <eax>
    elseif width eq 64
        exitm <rax>
    endif
endm
reg_src1 macro width
    if width eq 8
        exitm <dl>
    elseif width eq 16
        exitm <dx>
    elseif width eq 32
        exitm <edx>
    elseif width eq 64
        exitm <rdx>
    endif
endm
reg_src2 macro width
    if width eq 8
        exitm <cl>
    elseif width eq 16
        exitm <cx>
    elseif width eq 32
        exitm <ecx>
    elseif width eq 64
        exitm <rcx>
    endif
endm

; 1-operand instructions
fastop1 macro name
    fop_start name
    fop32 <name reg_dst(08)>
    fop32 <name reg_dst(16)>
    fop32 <name reg_dst(32)>
    fop64 <name reg_dst(64)>
    fop_end name
endm

; 2-operand instructions
fastop2 macro name
    fop_start name
    fop32 <name reg_dst(08), reg_src1(08)>
    fop32 <name reg_dst(16), reg_src1(16)>
    fop32 <name reg_dst(32), reg_src1(32)>
    fop64 <name reg_dst(64), reg_src1(64)>
    fop_end name
endm
fastop2w macro name
    fop_start name
    fop32 <nop>
    fop32 <name reg_dst(16), reg_src1(16)>
    fop32 <name reg_dst(32), reg_src1(32)>
    fop64 <name reg_dst(64), reg_src1(64)>
    fop_end name
endm
fastop2cl macro name
    fop_start name
    fop32 <name reg_dst(08), cl>
    fop32 <name reg_dst(16), cl>
    fop32 <name reg_dst(32), cl>
    fop64 <name reg_dst(64), cl>
    fop_end name
endm

; 3-operand instructions
fastop3 macro name
    fop_start name
    fop32 <name reg_dst(08), reg_src1(08), reg_src2(08)>
    fop32 <name reg_dst(16), reg_src1(16), reg_src2(16)>
    fop32 <name reg_dst(32), reg_src1(32), reg_src2(32)>
    fop64 <name reg_dst(64), reg_src1(64), reg_src2(64)>
    fop_end name
endm
fastop3w macro name
    fop_start name
    fop32 <nop>
    fop32 <name reg_dst(16), reg_src1(16), reg_src2(16)>
    fop32 <name reg_dst(32), reg_src1(32), reg_src2(32)>
    fop64 <name reg_dst(64), reg_src1(64), reg_src2(64)>
    fop_end name
endm
fastop3d macro name
    fop_start name
    fop32 <nop>
    fop32 <nop>
    fop32 <name reg_dst(32), reg_src1(32), reg_src2(32)>
    fop64 <name reg_dst(64), reg_src1(64), reg_src2(64)>
    fop_end name
endm
fastop3cl macro name
    fop_start name
    fop32 <name reg_dst(08), reg_src1(08), cl>
    fop32 <name reg_dst(16), reg_src1(16), cl>
    fop32 <name reg_dst(32), reg_src1(32), cl>
    fop64 <name reg_dst(64), reg_src1(64), cl>
    fop_end name
endm

.code

fastop1 not
fastop1 neg
fastop1 inc
fastop1 dec

fastop2 add
fastop2 or
fastop2 adc
fastop2 sbb
fastop2 and
fastop2 sub
fastop2 xor
fastop2 cmp
fastop2 test
fastop2 xadd

fastop2w bsf
fastop2w bsr
fastop2w bt
fastop2w bts
fastop2w btr
fastop2w btc

fastop2cl rol
fastop2cl ror
fastop2cl rcl
fastop2cl rcr
fastop2cl shl
fastop2cl shr
fastop2cl sar

fastop3d bextr
fastop3d andn

end
