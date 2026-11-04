/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS NT Library
 * FILE:            dl/ntdll/dispatch/i386/dispatch.S
 * PURPOSE:         User-Mode NT Dispatchers
 * PROGRAMMERS:     Alex Ionescu (alex@relsoft.net)
 */

/* INCLUDES ******************************************************************/

#include <asm.inc>
#include <ks386.inc>

EXTERN _LdrpInit@12:PROC
EXTERN _NtTestAlert@0:PROC
EXTERN _RtlDispatchException@8:PROC
EXTERN _RtlRaiseException@4:PROC
EXTERN _RtlRaiseStatus@4:PROC
EXTERN _ZwCallbackReturn@12:PROC
EXTERN _ZwContinue@8:PROC
EXTERN _ZwRaiseException@12:PROC

/* FUNCTIONS ****************************************************************/
.code

PUBLIC _CsrWow64Call@8
_CsrWow64Call@8:
    mov eax, HEX(10000)
    call dword ptr fs:[HEX(c0)]
    ret 8

/* Private user-mode WoW64 services, sharing the NT argument-list ABI. */
PUBLIC _RtlpWow64GetNativeSystemInformation@16
_RtlpWow64GetNativeSystemInformation@16:
    mov eax, HEX(10001)
    call dword ptr fs:[HEX(c0)]
    ret 16

PUBLIC _RtlpWow64EnableFsRedirectionEx@8
_RtlpWow64EnableFsRedirectionEx@8:
    mov eax, HEX(10002)
    call dword ptr fs:[HEX(c0)]
    ret 8

#ifdef SYSWOW64_GUEST
PUBLIC _RtlWow64CreateProcess@4
_RtlWow64CreateProcess@4:
    mov eax, HEX(10003)
    call dword ptr fs:[HEX(c0)]
    ret 4

#endif

/* RtlUserThreadStart: a thread entered here runs the routine in EAX with the
 * parameter in EBX (as Windows starts threads) and does not return (ldrinit.c,
 * RtlpUserThreadStart). kernel32 starts every thread here. The
 * start context the kernel stages for a WoW64 process's main thread enters it
 * once the guest loader has run, with the image's entry and the PEB32, as on
 * Windows. LdrWow64ProcessStart names the same code: the kernel stages a start
 * context only with an ntdll that exports both (psmgr.c). */
EXTERN _RtlpUserThreadStart@8:PROC
PUBLIC _RtlUserThreadStart@0
#ifdef SYSWOW64_GUEST
PUBLIC _LdrWow64ProcessStart@0
#endif
_RtlUserThreadStart@0:
#ifdef SYSWOW64_GUEST
_LdrWow64ProcessStart@0:
#endif
    /* Start out fresh: the frame list of a stack walk ends here */
    xor ebp, ebp
    push ebx
    push eax
    call _RtlpUserThreadStart@8
    int 3

/* ULONG RtlpCallThreadStart(Routine, Parameter): Routine(Parameter) whatever
 * its convention (a thread routine pops its parameter, an image entry does not) */
PUBLIC _RtlpCallThreadStart@8
_RtlpCallThreadStart@8:
    push ebp
    mov ebp, esp
    push dword ptr [ebp + 12]
    call dword ptr [ebp + 8]
    mov esp, ebp
    pop ebp
    ret 8

PUBLIC _LdrInitializeThunk@16
_LdrInitializeThunk@16:

    /* Get the APC Context */
    lea eax, [esp+16]

    /* Send it as the first parameter */
    mov [esp+4], eax

    /* Terminate the frame list */
    xor ebp, ebp

    /* Jump into the C initialization routine */
    jmp _LdrpInit@12


_KiUserApcExceptionHandler:

    /* Put the exception record in ECX and check the Flags */
    mov ecx, [esp+4]
    test dword ptr [ecx+EXCEPTION_RECORD_EXCEPTION_FLAGS], EXCEPTION_EXIT_UNWIND + EXCEPTION_UNWINDING
    jz .return

    /* Test alert the thread */
    call _NtTestAlert@0

.return:
    /* We'll execute handler */
    mov eax, EXCEPTION_EXECUTE_HANDLER
    ret 16


PUBLIC _KiUserApcDispatcher@16
_KiUserApcDispatcher@16:

    /* Setup SEH stack */
    lea eax, [esp+CONTEXT_ALIGNED_SIZE+16]
    mov ecx, fs:[TEB_EXCEPTION_LIST]
    mov edx, offset _KiUserApcExceptionHandler
    mov [eax], ecx
    mov [eax+4], edx

    /* Enable SEH */
    mov fs:[TEB_EXCEPTION_LIST], eax

    /* Put the Context in EDI */
    pop eax
    lea edi, [esp+12]

    /* Call the APC Routine */
    call eax

    /* Restore exception list */
    mov ecx, [edi+CONTEXT_ALIGNED_SIZE]
    mov fs:[TEB_EXCEPTION_LIST], ecx

    /* Switch back to the context */
    push 1
    push edi
    call _ZwContinue@8

    /* Save callback return value */
    mov esi, eax

    /* Raise status */
StatusRaiseApc:
    push esi
    call _RtlRaiseStatus@4
    jmp StatusRaiseApc
    ret 16


_KiUserCallbackExceptionHandler:

    /* Put the exception record in ECX and check the Flags */
    mov ecx, [esp+4]
    test dword ptr [ecx+EXCEPTION_RECORD_EXCEPTION_FLAGS], EXCEPTION_EXIT_UNWIND + EXCEPTION_UNWINDING
    jz return

    /* Tell the kernel to invalidate the stack */
    push STATUS_CALLBACK_POP_STACK
    push 0
    push 0
    call _ZwCallbackReturn@12

return:
    /* We'll execute the handler */
    mov eax, EXCEPTION_EXECUTE_HANDLER
    ret 16


PUBLIC _KiUserCallbackDispatcher@12
_KiUserCallbackDispatcher@12:

    /* Setup SEH stack */
    mov ecx, fs:[TEB_EXCEPTION_LIST]
    mov edx, offset _KiUserCallbackExceptionHandler
    lea eax, [esp+16]
    mov [esp+16], ecx
    mov [esp+20], edx

    /* Enable SEH */
    mov fs:[TEB_EXCEPTION_LIST], eax

    /* Get the callback Index */
    add esp, 4
    pop edx

    /* Get the callback table */
    mov eax, [fs:TEB_PEB]
    mov eax, [eax+PEB_KERNEL_CALLBACK_TABLE]

    /* Call the routine */
    call dword ptr [eax+edx*4]

    /* Return from callback */
    push eax
    push 0
    push 0
    call _ZwCallbackReturn@12

    /* Save callback return value */
    mov esi, eax

    /* Raise status */
StatusRaise:
    push esi
    call _RtlRaiseStatus@4
    jmp StatusRaise
    ret 12


PUBLIC _KiRaiseUserExceptionDispatcher@0
_KiRaiseUserExceptionDispatcher@0:

    /* Setup stack for EXCEPTION_RECORD */
    push ebp
    mov ebp, esp
    sub esp, EXCEPTION_RECORD_LENGTH

    /* Fill out the record */
    mov [esp+EXCEPTION_RECORD_EXCEPTION_ADDRESS], eax
    mov eax, [fs:KPCR_TEB]
    mov eax, [eax+TEB_EXCEPTION_CODE]
    mov [esp+EXCEPTION_RECORD_EXCEPTION_CODE], eax
    mov dword ptr [esp+EXCEPTION_RECORD_EXCEPTION_FLAGS], 0
    mov dword ptr [esp+EXCEPTION_RECORD_EXCEPTION_RECORD], 0
    mov dword ptr [esp+EXCEPTION_RECORD_NUMBER_PARAMETERS], 0

    /* Raise the exception */
    push esp
    call _RtlRaiseException@4

    /* Return exception code */
    mov eax, [esp+EXCEPTION_RECORD_EXCEPTION_CODE]
    mov esp, ebp
    pop ebp
    ret


PUBLIC _KiUserExceptionDispatcher@8
.PROC _KiUserExceptionDispatcher@8
    FPO 0, 0, 0, 0, 0, FRAME_FPO

    /* Clear direction flag */
    cld

    /* Save the Context and Exception Records */
    mov ecx, [esp+4]
    mov ebx, [esp]

    /* Dispatch the exception */
    push ecx
    push ebx
    call _RtlDispatchException@8

    /* Check for success */
    or al, al
    jz RaiseException

    /* Pop off the records */
    pop ebx
    pop ecx

    /* We're fine, continue execution */
    push 0
    push ecx
    call _ZwContinue@8

    /* Exit */
    jmp Exit

RaiseException:
    /* Pop off the records */
    pop ebx
    pop ecx

    /* Raise the exception */
    push 0
    push ecx
    push ebx
    call _ZwRaiseException@12

Exit:
    /* Allocate space for the nested exception record */
    add esp, -SIZEOF_EXCEPTION_RECORD

    /* Set it up */
    mov [esp+EXCEPTION_RECORD_EXCEPTION_CODE], eax
    mov dword ptr [esp+EXCEPTION_RECORD_EXCEPTION_FLAGS], EXCEPTION_NONCONTINUABLE
    mov [esp+EXCEPTION_RECORD_EXCEPTION_RECORD], ebx
    mov dword ptr [esp+EXCEPTION_RECORD_NUMBER_PARAMETERS], 0

    /* Raise the exception */
    push esp
    call _RtlRaiseException@4
    ret 8

.ENDP

PUBLIC _KiIntSystemCall@0
.PROC _KiIntSystemCall@0
    FPO 0, 0, 0, 0, 0, FRAME_FPO

    /* Set stack in EDX and do the interrupt */
    lea edx, [esp+8]
    int HEX(2E)

    /* Return to caller */
    ret

.ENDP

PUBLIC _KiFastSystemCall@0
.PROC _KiFastSystemCall@0
    FPO 0, 0, 0, 0, 0, FRAME_FPO

    /* Put ESP in EDX and do the SYSENTER */
    mov edx, esp
    sysenter

.ENDP

PUBLIC _KiFastSystemCallRet@0
.PROC _KiFastSystemCallRet@0
    FPO 0, 0, 0, 0, 0, FRAME_FPO

    /* Just return to caller */
    ret

.ENDP

END
