/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Helper for the FaultContext test
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <asm.inc>

.code

/* ULONG_PTR __cdecl FaultContextRun(ULONG_PTR Address, ULONG_PTR Seed, ULONG_PTR Mode):
 * loads values derived from Seed (edx) into ebx, ebp, esi and edi, then faults: Mode 0 reads Address
 * (eax = ecx = Address), Mode 1 divides by ecx = 0 (eax = 1). The test's vectored handler checks the exception
 * and the context and continues at FaultContextFaultResume or FaultContextDivideResume. Returns a mask of the
 * registers that changed across the fault. */
PUBLIC _FaultContextRun
PUBLIC _FaultContextLiveStart
PUBLIC _FaultContextFaultIp
PUBLIC _FaultContextFaultResume
PUBLIC _FaultContextDivideIp
PUBLIC _FaultContextDivideResume
PUBLIC _FaultContextLiveEnd
_FaultContextRun:
    push ebx
    push esi
    push edi
    push ebp
    mov ecx, [esp + 20]
    mov edx, [esp + 24]
    mov eax, [esp + 28]
    mov ebx, edx
    xor ebx, HEX(11111111)
    mov ebp, edx
    xor ebp, HEX(22222222)
    mov esi, edx
    xor esi, HEX(33333333)
    mov edi, edx
    xor edi, HEX(44444444)
_FaultContextLiveStart:
    test eax, eax
    jnz FaultContextDivide
    mov eax, ecx
_FaultContextFaultIp:
    mov eax, [eax]
_FaultContextFaultResume:
    jmp FaultContextCheck
FaultContextDivide:
    mov eax, 1
_FaultContextDivideIp:
    div ecx
_FaultContextDivideResume:
FaultContextCheck:
    xor eax, eax
    mov ecx, edx
    xor ecx, HEX(11111111)
    cmp ebx, ecx
    je FaultContextOk1
    or eax, 1
FaultContextOk1:
    mov ecx, edx
    xor ecx, HEX(22222222)
    cmp ebp, ecx
    je FaultContextOk2
    or eax, 2
FaultContextOk2:
    mov ecx, edx
    xor ecx, HEX(33333333)
    cmp esi, ecx
    je FaultContextOk3
    or eax, 4
FaultContextOk3:
    mov ecx, edx
    xor ecx, HEX(44444444)
    cmp edi, ecx
    je _FaultContextLiveEnd
    or eax, 8
_FaultContextLiveEnd:
    pop ebp
    pop edi
    pop esi
    pop ebx
    ret

END
