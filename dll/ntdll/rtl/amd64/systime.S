/*
 * PROJECT:     ReactOS NT User Mode Library
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     NtQuerySystemTime without a system call, x64
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/* INCLUDES ******************************************************************/

#include <asm.inc>
#include <ksamd64.inc>

.code64

/*
 * NTSTATUS
 * NTAPI
 * RtlpQuerySystemTimeUser(
 *     _Out_ PLARGE_INTEGER SystemTime);
 *
 * Loads the system time of the shared user data page (KSYSTEM_TIME at offset 0x14 of
 * 0x7FFE0000: LowPart and High1Time are one aligned 64-bit value that the kernel
 * stores in one piece) and stores it through the pointer. A bad pointer faults in the
 * store: the function has no frame, so its exception handler only has to turn the fault
 * into the return value (see RtlpQuerySystemTimeHandler below).
 */
PUBLIC RtlpQuerySystemTimeUser
.PROC RtlpQuerySystemTimeUser
    .seh_handler RtlpQuerySystemTimeHandler, @except
    .seh_handlerdata
    .seh_code
    .ENDPROLOG

    mov rax, qword ptr ds:[HEX(7FFE0014)]
    mov [rcx], rax
    xor eax, eax

PUBLIC RtlpQuerySystemTimeReturn
RtlpQuerySystemTimeReturn:
    ret
.ENDP

/*
 * EXCEPTION_DISPOSITION
 * NTAPI
 * RtlpQuerySystemTimeHandler(
 *     _In_ PEXCEPTION_RECORD ExceptionRecord,    rcx
 *     _In_ PVOID EstablisherFrame,               rdx
 *     _Inout_ PCONTEXT ContextRecord,            r8
 *     _In_ PDISPATCHER_CONTEXT DispatcherContext r9);
 *
 * The handler of RtlpQuerySystemTimeUser: an exception makes the function continue at its
 * return with the exception code as the status (what the try block's except part returned).
 * An unwind (EXCEPTION_UNWIND bits, 0x66) passes through.
 */
PUBLIC RtlpQuerySystemTimeHandler
.PROC RtlpQuerySystemTimeHandler
    .ENDPROLOG

    test dword ptr [rcx + ErExceptionFlags], HEX(66)
    jnz Unwinding

    mov eax, [rcx + ErExceptionCode]
    mov [r8 + CxRax], rax
    lea rax, [rip + RtlpQuerySystemTimeReturn]
    mov [r8 + CxRip], rax
    xor eax, eax                    /* ExceptionContinueExecution */
    ret

Unwinding:
    mov eax, 1                      /* ExceptionContinueSearch */
    ret
.ENDP

END
