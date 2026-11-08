/* ReactOS WoW64 mode transition. SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm.inc>
#include <ksamd64.inc>
EXTERN Wow64Service:QWORD

.code
PUBLIC Wow64CpuRun
.PROC Wow64CpuRun
    sub rsp, 88
    .allocstack 88
    .endprolog
    mov [rcx], rsp
    mov dword ptr [rcx + 52], 1
    mov gs:[TeTlsSlots + 8], rcx
    mov r11, rcx
    jmp Wow64CpuReturn
.ENDP

PUBLIC Wow64CpuDispatch
.PROC Wow64CpuDispatch
    .endprolog
    /* The low-address gate enters with the i386 stub's return on ESP.
     * No caller argument is read until we are on the native stack.
     * The guest's x87 and SSE registers are not saved here: Wow64SystemService saves them
     * (FpSaved, below) before it runs anything that could change them, and leaves them
     * alone for the services that cannot. Nothing before it touches them. */
    mov r11, gs:[TeTlsSlots + 8]
    mov [r11 + 44], ecx
    mov [r11 + 48], edx
    mov [r11 + 20], eax
    /* XMM0-XMM5 are volatile in the native ABI and the kernel and native ntdll use them; the rest of the
     * guest's x87/SSE state is not touched (see FpSaved in wow64.h) */
    movups [r11 + 224], xmm0
    movups [r11 + 240], xmm1
    movups [r11 + 256], xmm2
    movups [r11 + 272], xmm3
    movups [r11 + 288], xmm4
    movups [r11 + 304], xmm5
    mov [r11 + 8], esp
    mov rsp, [r11]
    mov [r11 + 24], ebx
    mov [r11 + 28], esi
    mov [r11 + 32], edi
    mov [r11 + 36], ebp
    pushfq
    pop rdx
    mov [r11 + 16], edx
    cld
    mov ecx, eax
    mov edx, [r11 + 8]
    /* Return to the stub, which pops its own arguments. */
    mov eax, [rdx]
    mov [r11 + 12], eax
    add dword ptr [r11 + 8], 4
    add edx, 8
    call qword ptr Wow64Service[rip]
    mov r11, gs:[TeTlsSlots + 8]
    /* The common return: a far jump back to the compatibility-mode code segment, as Windows'
     * wow64cpu does, where the general return below leaves with IRETQ. The data segments
     * are as the gate found them (nothing in the layer or a system call changes DS, ES or FS:
     * a context switch reloads FS, the kernel's entries restore DS and ES). SS is not: the
     * kernel's SYSRET leaves a stack segment whose hidden attributes the processor does not
     * accept for 32-bit code (without this load a thread returning here fails at random),
     * so it is loaded again. Interrupts are held off for the instruction after it. */
    cmp byte ptr [r11 + 57], 0
    jne .Lfullfp
    movups xmm0, [r11 + 224]
    movups xmm1, [r11 + 240]
    movups xmm2, [r11 + 256]
    movups xmm3, [r11 + 272]
    movups xmm4, [r11 + 288]
    movups xmm5, [r11 + 304]
    jmp .Lfpdone
.Lfullfp:
    fxrstor [r11 + 64]
    mov byte ptr [r11 + 57], 0
.Lfpdone:
    mov rsp, [r11]
    mov r12, gs:[HEX(30)]
    mov r13, r11
    mov r14, rsp
    /* The flags: TF, DF and AC are the guest's to keep; the status flags are clobbered by a call in
     * both ABIs, and every other flag the system call left as the guest had it. POPFQ is slow, so
     * it is only done when one of those three is set (the general return below always does it). */
    mov eax, [r11 + 16]
    test eax, HEX(40500)
    jz .Lflagsdone
    and eax, HEX(240fd7)
    push rax
    popfq
.Lflagsdone:
    mov ebx, [r11 + 24]
    mov esi, [r11 + 28]
    mov edi, [r11 + 32]
    mov ebp, [r11 + 36]
    mov ecx, [r11 + 44]
    mov edx, [r11 + 48]
    mov eax, [r11 + 12]
    mov [r11 + 58], eax
    mov word ptr [r11 + 62], HEX(23)
    mov eax, HEX(2b)
    mov ss, ax
    mov eax, [r11 + 20]
    mov esp, [r11 + 8]
    jmp fword ptr [r11 + 58]
Wow64CpuReturn:
    /* IRET in ring 3 switches only user selectors and restores the 32-bit
     * stack. Kernel transitions occur inside the native ntdll calls. */
    mov rsp, [r11]
    /* The guest runs with the TEB in R12, its CPU area in R13 and the native stack in R14,
     * as on Windows: 64-bit code a guest enters with a far transfer uses R14 as its stack */
    mov r12, gs:[HEX(30)]
    mov r13, r11
    mov r14, rsp
    mov qword ptr [rsp + 64], HEX(2b)
    mov eax, [r11 + 8]
    mov [rsp + 56], rax
    /* A running guest sees only the flags Windows lets it see: no NT (an IRETQ with
     * NT set faults), IOPL, RF, VM, VIF or VIP. AC and ID stay. */
    mov eax, [r11 + 16]
    and eax, HEX(240fd7)
    mov [rsp + 48], rax
    mov qword ptr [rsp + 40], HEX(23)
    mov eax, [r11 + 12]
    mov [rsp + 32], rax
    mov ebx, [r11 + 24]
    mov esi, [r11 + 28]
    mov edi, [r11 + 32]
    mov ebp, [r11 + 36]
    mov eax, HEX(53)
    mov fs, ax
    mov eax, HEX(2b)
    mov ds, ax
    mov es, ax
    fxrstor [r11 + 64]
    mov byte ptr [r11 + 57], 0
    mov ecx, [r11 + 44]
    mov edx, [r11 + 48]
    mov eax, [r11 + 20]
    add rsp, 32
    iretq
.ENDP
END
