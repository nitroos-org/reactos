/*
 * COPYRIGHT:  See COPYING in the top level directory
 * PROJECT:    ReactOS system libraries
 * FILE:       dll/win32/kernel32/client/i386/thread.S
 * PURPOSE:    Thread Start Thunks
 * PROGRAMMER: Alex Ionescu (alex@relsoft.net)
 */

#include <asm.inc>
#include <ks386.inc>

.code

EXTERN _BaseThreadStartup@8:PROC
EXTERN _BaseProcessStartup@4:PROC

PUBLIC _BaseThreadStartupThunk@0
_BaseThreadStartupThunk@0:

    /* Start out fresh */
    xor ebp, ebp

    push ebx                  /* lpParameter */
    push eax                  /* lpStartAddress */
    push 0                    /* Return EIP */
    jmp _BaseThreadStartup@8


PUBLIC _BaseProcessStartThunk@0
_BaseProcessStartThunk@0:
    /* Start out fresh */
    xor ebp, ebp

    push eax                  /* lpStartAddress */
    push 0                    /* Return EIP */
    jmp _BaseProcessStartup@4


/* DWORD WINAPI BasepCallThreadStart(lpStartAddress, lpParameter): lpStartAddress(lpParameter) whatever
 * its convention (a thread routine pops its parameter, an image entry does not) */
PUBLIC _BasepCallThreadStart@8
_BasepCallThreadStart@8:
    /* A routine of any origin may return with EBX, ESI, EDI and EBP replaced (the Go runtime's thread
     * entry does), and its caller may keep state in them: save them in memory, and find the stack
     * again without EBP (the EBP frame stays for a stack walk). After the call ESP is at the
     * parameter slot (the routine left it) or one slot above (it popped it); the marker above the
     * slot holds its own address, which tells the two apart. */
    push ebp                            /* the frame a stack walk follows to the caller */
    mov ebp, esp
    push ebx
    push esi
    push edi
    mov eax, dword ptr [ebp + 8]        /* Routine */
    mov ecx, dword ptr [ebp + 12]       /* Parameter */
    lea edx, [esp - 4]
    push edx                            /* marker: its own address */
    push ecx
    call eax
    cmp esp, dword ptr [esp]
    je BasepCallThreadStartStackFound
    add esp, 4                          /* the routine left the parameter */
BasepCallThreadStartStackFound:
    add esp, 4                          /* the marker */
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret 8

END

/* EOF */
