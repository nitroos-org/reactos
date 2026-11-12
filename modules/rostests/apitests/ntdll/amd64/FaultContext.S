/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Helper for the FaultContext test
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <asm.inc>

.code64

/* ULONG_PTR FaultContextRun(ULONG_PTR Address, ULONG_PTR Seed, ULONG_PTR Mode):
 * loads values derived from Seed (rdx) into rbx, rbp, rsi, rdi, r12, r13, r15 and xmm6, the stack pointer into
 * r14, then faults: Mode 0 reads Address (rax = rcx = Address), Mode 1 divides by rcx = 0 (rax = 1). The test's
 * vectored handler checks the exception and the context and continues at FaultContextFaultResume or
 * FaultContextDivideResume. Returns a mask of the registers that changed across the fault. */
PUBLIC FaultContextRun
PUBLIC FaultContextLiveStart
PUBLIC FaultContextFaultIp
PUBLIC FaultContextFaultResume
PUBLIC FaultContextDivideIp
PUBLIC FaultContextDivideResume
PUBLIC FaultContextLiveEnd
.PROC FaultContextRun
    push rbx
    .pushreg rbx
    push rbp
    .pushreg rbp
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    sub rsp, 24
    .allocstack 24
    movaps [rsp], xmm6
    .savexmm128 xmm6, 0
    .endprolog

    mov r10, HEX(1111111111111111)
    mov rbx, rdx
    xor rbx, r10
    mov r10, HEX(2222222222222222)
    mov rbp, rdx
    xor rbp, r10
    mov r10, HEX(3333333333333333)
    mov rsi, rdx
    xor rsi, r10
    mov r10, HEX(4444444444444444)
    mov rdi, rdx
    xor rdi, r10
    mov r10, HEX(5555555555555555)
    mov r12, rdx
    xor r12, r10
    mov r10, HEX(6666666666666666)
    mov r13, rdx
    xor r13, r10
    mov r10, HEX(7777777777777777)
    mov r15, rdx
    xor r15, r10
    movq xmm6, rdx
    mov r14, rsp
FaultContextLiveStart:
    test r8, r8
    jnz FaultContextDivide
    mov rax, rcx
FaultContextFaultIp:
    mov rax, [rax]
FaultContextFaultResume:
    jmp FaultContextCheck
FaultContextDivide:
    mov eax, 1
FaultContextDivideIp:
    div rcx
FaultContextDivideResume:
FaultContextCheck:
    xor eax, eax
    mov r10, HEX(1111111111111111)
    xor r10, rdx
    cmp rbx, r10
    je FaultContextOk1
    or eax, 1
FaultContextOk1:
    mov r10, HEX(2222222222222222)
    xor r10, rdx
    cmp rbp, r10
    je FaultContextOk2
    or eax, 2
FaultContextOk2:
    mov r10, HEX(3333333333333333)
    xor r10, rdx
    cmp rsi, r10
    je FaultContextOk3
    or eax, 4
FaultContextOk3:
    mov r10, HEX(4444444444444444)
    xor r10, rdx
    cmp rdi, r10
    je FaultContextOk4
    or eax, 8
FaultContextOk4:
    mov r10, HEX(5555555555555555)
    xor r10, rdx
    cmp r12, r10
    je FaultContextOk5
    or eax, 16
FaultContextOk5:
    mov r10, HEX(6666666666666666)
    xor r10, rdx
    cmp r13, r10
    je FaultContextOk6
    or eax, 32
FaultContextOk6:
    mov r10, HEX(7777777777777777)
    xor r10, rdx
    cmp r15, r10
    je FaultContextOk7
    or eax, 64
FaultContextOk7:
    cmp r14, rsp
    je FaultContextOk8
    or eax, 128
FaultContextOk8:
    movq r10, xmm6
    cmp r10, rdx
    je FaultContextLiveEnd
    or eax, 256
FaultContextLiveEnd:
    movaps xmm6, [rsp]
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret
.ENDP

END
