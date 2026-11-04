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
    push ebp
    mov ebp, esp
    push dword ptr [ebp + 12]
    call dword ptr [ebp + 8]
    mov esp, ebp
    pop ebp
    ret 8

END

/* EOF */
