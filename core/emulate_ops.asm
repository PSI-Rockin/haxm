;
; Copyright (c) 2018 Alexandro Sanchez Bach <alexandro@phi.nz>
;
; Redistribution and use in source and binary forms, with or without
; modification, are permitted provided that the following conditions are met:
;
;   1. Redistributions of source code must retain the above copyright notice,
;      this list of conditions and the following disclaimer.
;
;   2. Redistributions in binary form must reproduce the above copyright
;      notice, this list of conditions and the following disclaimer in the
;      documentation and/or other materials provided with the distribution.
;
;   3. Neither the name of the copyright holder nor the names of its
;      contributors may be used to endorse or promote products derived from
;      this software without specific prior written permission.
;
; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
; AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
; IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
; ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
; LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
; CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
; SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
; INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
; CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
; ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
; POSSIBILITY OF SUCH DAMAGE.

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
    ifdef eax
        fop <instruction>
    endif
endm
fop64 macro instruction
    ifdef rax
        fop <instruction>
    endif
endm

; Calling convention
;  - eax/rax - dest value
;  - edx/rdx - src1 value
;  - ecx/rcx - src2 value
reg_dst macro width:=<0>
    ; Select based on width
    if width eq 8
        exitm <al>
    elseif width eq 16
        exitm <ax>
    elseif width eq 32
        exitm <eax>
    elseif width eq 64
        exitm <rax>
    endif
    ; Select based on arch
    ifdef rdx
        exitm <rax>
    else
        exitm <eax>
    endif
endm
reg_src1 macro width:=<0>
    ; Select based on width
    if width eq 8
        exitm <dl>
    elseif width eq 16
        exitm <dx>
    elseif width eq 32
        exitm <edx>
    elseif width eq 64
        exitm <rdx>
    endif
    ; Select based on arch
    ifdef rdx
        exitm <rdx>
    else
        exitm <edx>
    endif
endm
reg_src2 macro width:=<0>
    ; Select based on width
    if width eq 8
        exitm <cl>
    elseif width eq 16
        exitm <cx>
    elseif width eq 32
        exitm <ecx>
    elseif width eq 64
        exitm <rcx>
    endif
    ; Select based on arch
    ifdef rdx
        exitm <rcx>
    else
        exitm <ecx>
    endif
endm
reg_tmp macro
    ; Select based on arch
    ifdef rbx
        exitm <rbx>
    else
        exitm <ebx>
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
fastop3d macro name
    fop_start name
    fop32 <nop>
    fop32 <nop>
    fop32 <name reg_dst(32), reg_src1(32), reg_src2(32)>
    fop64 <name reg_dst(64), reg_src1(64), reg_src2(64)>
    fop_end name
endm
fastop3wcl macro name
    fop_start name
    fop32 <nop>
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
fastop2 test
fastop2 xadd
fastop2 cmp
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

fastop3wcl shld
fastop3wcl shrd
fastop3d bextr
fastop3d andn

fastop_dispatch proc public op:PTR, src1:PTR, src2:PTR, dst:PTR, flags:PTR
    push reg_tmp()
    push reg_src1()
    push reg_src2()
    push reg_dst()
    mov reg_tmp(), src1
    mov reg_src1(), [reg_tmp()]
    mov reg_tmp(), src2
    mov reg_src2(), [reg_tmp()]
    mov reg_tmp(), flags
    push [reg_tmp()]
    popf
    call op
    pushf
    mov reg_tmp(), flags
    pop [reg_tmp()]
    mov reg_tmp(), dst
    mov [reg_tmp()], reg_dst()
    pop reg_dst()
    pop reg_src2()
    pop reg_src1()
    pop reg_tmp()
    ret
fastop_dispatch endp

end
