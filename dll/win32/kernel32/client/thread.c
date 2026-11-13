/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            dll/win32/kernel32/client/thread.c
 * PURPOSE:         Thread functions
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 *                  Ariadne (ariadne@xs4all.nl)
 */

/* INCLUDES *******************************************************************/

#include <k32.h>

#define NDEBUG
#include <debug.h>

#define SXS_SUPPORT_FIXME

typedef NTSTATUS (NTAPI *PCSR_CREATE_REMOTE_THREAD)(IN HANDLE ThreadHandle, IN PCLIENT_ID ClientId);

#define THREAD_ALL_ACCESS_NT6 (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0xFFFF)

/* FUNCTIONS ******************************************************************/

NTSTATUS
WINAPI
BasepNotifyCsrOfThread(IN HANDLE ThreadHandle,
                       IN PCLIENT_ID ClientId)
{
    BASE_API_MESSAGE ApiMessage;
    PBASE_CREATE_THREAD CreateThreadRequest = &ApiMessage.Data.CreateThreadRequest;

    DPRINT("BasepNotifyCsrOfThread: Thread: %p, Handle %p\n",
            ClientId->UniqueThread, ThreadHandle);

    /* Fill out the request */
    CreateThreadRequest->ClientId = *ClientId;
    CreateThreadRequest->ThreadHandle = ThreadHandle;

    /* Call CSR */
    CsrClientCallServer((PCSR_API_MESSAGE)&ApiMessage,
                        NULL,
                        CSR_CREATE_API_NUMBER(BASESRV_SERVERDLL_INDEX, BasepCreateThread),
                        sizeof(*CreateThreadRequest));
    if (!NT_SUCCESS(ApiMessage.Status))
    {
        DPRINT1("Failed to tell CSRSS about new thread: %lx\n", ApiMessage.Status);
        return ApiMessage.Status;
    }

    /* Return Success */
    return STATUS_SUCCESS;
}

DECLSPEC_NORETURN
VOID
BASE_THREAD_INIT_THUNK_CALL
BaseThreadInitThunk(
    _In_ DWORD Unknown,
    _In_ LPTHREAD_START_ROUTINE lpStartAddress,
    _In_ LPVOID lpParameter)
{
    /* Attempt to call the Thread Start Address */
    _SEH2_TRY
    {
        /*
         * Legacy check which is still used today for Win32 threads. The first thread of a process
         * (its parameter is the PEB) is registered by BaseDllInitialize when kernel32 connects to CSRSS:
         * it enters here too now and must not register a second termination port.
         */
        if (NtCurrentTeb()->NtTib.Version == (30 << 8) && lpParameter != NtCurrentPeb()) // OS/2 V3.0 ("Cruiser")
        {
            /* This registers the termination port with CSRSS */
            if (!BaseRunningInServerProcess) CsrNewThread();
        }

        /* Get the exit code from the Thread Start */
        ExitThread(BasepCallThreadStart(lpStartAddress, lpParameter));
    }
    _SEH2_EXCEPT(UnhandledExceptionFilter(_SEH2_GetExceptionInformation()))
    {
        /* Get the Exit code from the SEH Handler */
        if (!BaseRunningInServerProcess)
        {
            /*
             * Kill the whole process, usually. Like Windows, end it at once:
             * a crashed process does not run DLL_PROCESS_DETACH or atexit
             * handlers, which may wait for threads that are already gone.
             */
            NtTerminateProcess(NtCurrentProcess(), _SEH2_GetExceptionCode());
        }
        else
        {
            /* If running inside CSRSS, kill just this thread */
            ExitThread(_SEH2_GetExceptionCode());
        }
    }
    _SEH2_END;

    /* Both paths end the thread */
    UNREACHABLE;
}

DECLSPEC_NORETURN
VOID
WINAPI
BaseThreadStartup(
    _In_ LPTHREAD_START_ROUTINE lpStartAddress,
    _In_ LPVOID lpParameter)
{
    /* Fibers and the console control thread enter here (not through RtlUserThreadStart) */
    BaseThreadInitThunk(0, lpStartAddress, lpParameter);
}

VOID
NTAPI
BaseDispatchApc(IN PAPCFUNC ApcRoutine,
                IN PVOID Data,
                IN PACTIVATION_CONTEXT ActivationContext)
{
    RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME ActivationFrame;

    /* Setup the activation context */
    ActivationFrame.Size = sizeof(ActivationFrame);
    ActivationFrame.Format = RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_FORMAT_WHISTLER;

    /* Check if caller wanted one */
    if (ActivationContext == INVALID_ACTIVATION_CONTEXT)
    {
        /* Do the APC directly */
        ApcRoutine((ULONG_PTR)Data);
        return;
    }

    /* Then activate it */
    RtlActivateActivationContextUnsafeFast(&ActivationFrame, ActivationContext);

    /* Call the routine under SEH */
    _SEH2_TRY
    {
        ApcRoutine((ULONG_PTR)Data);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {

    }
    _SEH2_END;

    /* Now de-activate and release the activation context */
    RtlDeactivateActivationContextUnsafeFast(&ActivationFrame);
    RtlReleaseActivationContext(ActivationContext);
}

/* PUBLIC FUNCTIONS ***********************************************************/

/*
 * @implemented
 */
HANDLE
WINAPI
DECLSPEC_HOTPATCH
CreateThread(IN LPSECURITY_ATTRIBUTES lpThreadAttributes,
             IN SIZE_T dwStackSize,
             IN LPTHREAD_START_ROUTINE lpStartAddress,
             IN LPVOID lpParameter,
             IN DWORD dwCreationFlags,
             OUT LPDWORD lpThreadId)
{
    /* Act as if we're going to create a remote thread in ourselves */
    return CreateRemoteThread(NtCurrentProcess(),
                              lpThreadAttributes,
                              dwStackSize,
                              lpStartAddress,
                              lpParameter,
                              dwCreationFlags,
                              lpThreadId);
}

/*
 * @implemented
 */
HANDLE
WINAPI
CreateRemoteThread(IN HANDLE hProcess,
                   IN LPSECURITY_ATTRIBUTES lpThreadAttributes,
                   IN SIZE_T dwStackSize,
                   IN LPTHREAD_START_ROUTINE lpStartAddress,
                   IN LPVOID lpParameter,
                   IN DWORD dwCreationFlags,
                   OUT LPDWORD lpThreadId)
{
    return CreateRemoteThreadEx(hProcess,
                                lpThreadAttributes,
                                dwStackSize,
                                lpStartAddress,
                                lpParameter,
                                dwCreationFlags,
                                NULL,
                                lpThreadId);
}

/*
 * @implemented
 */
HANDLE
WINAPI
CreateRemoteThreadEx(
    _In_ HANDLE hProcess,
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_ SIZE_T dwStackSize,
    _In_ LPTHREAD_START_ROUTINE lpStartAddress,
    _In_opt_ LPVOID lpParameter,
    _In_ DWORD dwCreationFlags,
    _In_opt_ LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
    _Out_opt_ LPDWORD lpThreadId)
{
    NTSTATUS Status;
    INITIAL_TEB InitialTeb;
    CONTEXT Context;
    CLIENT_ID ClientId;
    OBJECT_ATTRIBUTES LocalObjectAttributes;
    POBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE hThread;
    ULONG Dummy;
    PTEB Teb;
    THREAD_BASIC_INFORMATION ThreadBasicInfo;
    PACTIVATION_CONTEXT_STACK ActivationContextStack = NULL;
    ACTIVATION_CONTEXT_BASIC_INFORMATION ActCtxInfo;
    ULONG_PTR Cookie;
    ULONG ReturnLength;
    SIZE_T ReturnSize;
    PPROCESSOR_NUMBER IdealProcessor;

    DPRINT("CreateRemoteThreadEx: hProcess: %p dwStackSize: %Iu lpStartAddress"
           ": %p lpParameter: %p, dwCreationFlags: %lx\n", hProcess,
           dwStackSize, lpStartAddress, lpParameter, dwCreationFlags);

    IdealProcessor = NULL;
    if (lpAttributeList)
    {
        Status = BasepReadThreadAttributes(lpAttributeList, &IdealProcessor);
        if (NT_SUCCESS(Status) && IdealProcessor)
        {
            PROCESS_BASIC_INFORMATION ProcessInfo;

            /* See BasepSetIdealProcessor */
            Status = NtQueryInformationProcess(hProcess, ProcessBasicInformation,
                                               &ProcessInfo, sizeof(ProcessInfo), NULL);
            if (NT_SUCCESS(Status) &&
                ProcessInfo.UniqueProcessId != (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueProcess)
            {
                Status = STATUS_NOT_SUPPORTED;
            }
        }
        if (!NT_SUCCESS(Status))
        {
            BaseSetLastNTError(Status);
            return NULL;
        }
    }

    /* Clear the Context */
    RtlZeroMemory(&Context, sizeof(Context));

    /* Write PID */
    ClientId.UniqueProcess = hProcess;

    /* Create the Stack */
    Status = BaseCreateStack(hProcess,
                             (dwCreationFlags & STACK_SIZE_PARAM_IS_A_RESERVATION) ?
                                0 : dwStackSize,
                             (dwCreationFlags & STACK_SIZE_PARAM_IS_A_RESERVATION) ?
                                dwStackSize : 0,
                             &InitialTeb);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return NULL;
    }

    /* Create the Initial Context */
    BaseInitializeContext(&Context,
                          lpParameter,
                          lpStartAddress,
                          InitialTeb.StackBase,
                          1);

    /* Initialize the attributes for the thread object */
    ObjectAttributes = BaseFormatObjectAttributes(&LocalObjectAttributes,
                                                  lpThreadAttributes,
                                                  NULL);

    /* Create the Kernel Thread Object */
    Status = NtCreateThread(&hThread,
                            THREAD_ALL_ACCESS_NT6,
                            ObjectAttributes,
                            hProcess,
                            &ClientId,
                            &Context,
                            &InitialTeb,
                            TRUE);
    if (!NT_SUCCESS(Status))
    {
        /* Fail the kernel create */
        BaseFreeThreadStack(hProcess, &InitialTeb);
        BaseSetLastNTError(Status);
        return NULL;
    }

    if (IdealProcessor)
    {
        Status = BasepSetIdealProcessor(hThread, IdealProcessor);
        if (!NT_SUCCESS(Status))
            goto Quit;
    }

    /* Are we in the same process? */
    if (hProcess == NtCurrentProcess())
    {
        /* Get the TEB */
        Status = NtQueryInformationThread(hThread,
                                          ThreadBasicInformation,
                                          &ThreadBasicInfo,
                                          sizeof(ThreadBasicInfo),
                                          &ReturnLength);
        if (!NT_SUCCESS(Status))
        {
            /* Fail */
            DPRINT1("SXS: %s - Failing thread create because "
                    "NtQueryInformationThread() failed with status %08lx\n",
                    __FUNCTION__, Status);
            goto Quit;
        }

        /* Allocate the Activation Context Stack */
        Status = RtlAllocateActivationContextStack(&ActivationContextStack);
        if (!NT_SUCCESS(Status))
        {
            /* Fail */
            DPRINT1("SXS: %s - Failing thread create because "
                    "RtlAllocateActivationContextStack() failed with status %08lx\n",
                    __FUNCTION__, Status);
            goto Quit;
        }

        /* Save it */
        Teb = ThreadBasicInfo.TebBaseAddress;
        Teb->ActivationContextStackPointer = ActivationContextStack;

        /* Query the Context */
        Status = RtlQueryInformationActivationContext(RTL_QUERY_ACTIVATION_CONTEXT_FLAG_USE_ACTIVE_ACTIVATION_CONTEXT,
                                                      NULL,
                                                      0,
                                                      ActivationContextBasicInformation,
                                                      &ActCtxInfo,
                                                      sizeof(ActCtxInfo),
                                                      &ReturnSize);
        if (!NT_SUCCESS(Status))
        {
            /* Fail */
            DPRINT1("SXS: %s - Failing thread create because "
                    "RtlQueryInformationActivationContext() failed with status %08lx\n",
                    __FUNCTION__, Status);
            goto Quit;
        }

        /* Does it need to be activated? */
        if ((ActCtxInfo.hActCtx) && !(ActCtxInfo.dwFlags & 1))
        {
            /* Activate it */
            Status = RtlActivateActivationContextEx(RTL_ACTIVATE_ACTIVATION_CONTEXT_EX_FLAG_RELEASE_ON_STACK_DEALLOCATION,
                                                    Teb,
                                                    ActCtxInfo.hActCtx,
                                                    &Cookie);
            if (!NT_SUCCESS(Status))
            {
                /* Fail */
                DPRINT1("SXS: %s - Failing thread create because "
                        "RtlActivateActivationContextEx() failed with status %08lx\n",
                        __FUNCTION__, Status);
                goto Quit;
            }
        }

        /* Sync the service tag with the parent thread's one */
        Teb->SubProcessTag = NtCurrentTeb()->SubProcessTag;
    }

    /* Notify CSR */
    if (!BaseRunningInServerProcess)
    {
        Status = BasepNotifyCsrOfThread(hThread, &ClientId);
    }
    else
    {
        if (hProcess != NtCurrentProcess())
        {
            PCSR_CREATE_REMOTE_THREAD CsrCreateRemoteThread;

            /* Get the direct CSRSRV export */
            CsrCreateRemoteThread = (PCSR_CREATE_REMOTE_THREAD)
                                    GetProcAddress(GetModuleHandleA("csrsrv"),
                                                   "CsrCreateRemoteThread");
            if (CsrCreateRemoteThread)
            {
                /* Call it instead of going through LPC */
                Status = CsrCreateRemoteThread(hThread, &ClientId);
            }
        }
    }

Quit:
    if (!NT_SUCCESS(Status))
    {
        /* Failed to create the thread */

        /* Free the activation context stack */
        if (ActivationContextStack)
            RtlFreeActivationContextStack(ActivationContextStack);

        NtTerminateThread(hThread, Status);
#ifdef SYSWOW64_GUEST
        /* Guest thread rundown releases both stacks after successful create. */
        NtWaitForSingleObject(hThread, FALSE, NULL);
#else
        // FIXME: Wait for the thread to terminate?
        BaseFreeThreadStack(hProcess, &InitialTeb);
#endif
        NtClose(hThread);

        BaseSetLastNTError(Status);
        return NULL;
    }

    /* Success */
    if (lpThreadId)
        *lpThreadId = HandleToUlong(ClientId.UniqueThread);

    /* Resume the thread if asked */
    if (!(dwCreationFlags & CREATE_SUSPENDED))
        NtResumeThread(hThread, &Dummy);

    /* Return handle to thread */
    return hThread;
}

/*
 * @implemented
 */
VOID
WINAPI
ExitThread(IN DWORD uExitCode)
{
    NTSTATUS Status;
    ULONG LastThread;
    PRTL_CRITICAL_SECTION LoaderLock;

    /* Make sure loader lock isn't held */
    LoaderLock = NtCurrentPeb()->LoaderLock;
    if (LoaderLock) ASSERT(NtCurrentTeb()->ClientId.UniqueThread != LoaderLock->OwningThread);

    /*
     * Terminate process if this is the last thread
     * of the current process
     */
    Status = NtQueryInformationThread(NtCurrentThread(),
                                      ThreadAmILastThread,
                                      &LastThread,
                                      sizeof(LastThread),
                                      NULL);
    if ((NT_SUCCESS(Status)) && (LastThread)) ExitProcess(uExitCode);

    /* Notify DLLs and TLS Callbacks of termination */
    LdrShutdownThread();
#if (NTDDI_VERSION < NTDDI_LONGHORN)
    /* Tell the Kernel to free the Stack */
    NtCurrentTeb()->FreeStackOnTermination = TRUE;
#endif
    NtTerminateThread(NULL, uExitCode);

    /* We should never reach this place */
    ERROR_FATAL("It should not happen\n");
    while (TRUE); /* 'noreturn' function */
}

/*
 * @implemented
 */
HANDLE
WINAPI
OpenThread(IN DWORD dwDesiredAccess,
           IN BOOL bInheritHandle,
           IN DWORD dwThreadId)
{
    NTSTATUS Status;
    HANDLE ThreadHandle;
    OBJECT_ATTRIBUTES ObjectAttributes;
    CLIENT_ID ClientId;

    ClientId.UniqueProcess = 0;
    ClientId.UniqueThread = ULongToHandle(dwThreadId);

    InitializeObjectAttributes(&ObjectAttributes,
                               NULL,
                               (bInheritHandle ? OBJ_INHERIT : 0),
                               NULL,
                               NULL);

    Status = NtOpenThread(&ThreadHandle,
                          dwDesiredAccess,
                          &ObjectAttributes,
                          &ClientId);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return NULL;
    }

    return ThreadHandle;
}

/*
 * @implemented
 */
PTEB
GetTeb(VOID)
{
    return NtCurrentTeb();
}

/*
 * @implemented
 */
BOOL
WINAPI
SwitchToThread(VOID)
{
    return NtYieldExecution() != STATUS_NO_YIELD_PERFORMED;
}


/*
 * @implemented
 */
DWORD
WINAPI
GetCurrentThreadId(VOID)
{
    return HandleToUlong(NtCurrentTeb()->ClientId.UniqueThread);
}

/*
 * @implemented
 */
VOID
WINAPI
GetCurrentThreadStackLimits(OUT PULONG_PTR LowLimit,
                            OUT PULONG_PTR HighLimit)
{
    PTEB Teb = NtCurrentTeb();

    *LowLimit = (ULONG_PTR)Teb->DeallocationStack;
    *HighLimit = (ULONG_PTR)Teb->NtTib.StackBase;
}

/*
 * @implemented
 */
BOOL
NTAPI
GetThreadTimes(IN HANDLE hThread,
               OUT LPFILETIME lpCreationTime,
               OUT LPFILETIME lpExitTime,
               OUT LPFILETIME lpKernelTime,
               OUT LPFILETIME lpUserTime)
{
    KERNEL_USER_TIMES KernelUserTimes;
    NTSTATUS Status;

    Status = NtQueryInformationThread(hThread,
                                      ThreadTimes,
                                      &KernelUserTimes,
                                      sizeof(KERNEL_USER_TIMES),
                                      NULL);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    *lpCreationTime = *(LPFILETIME)&KernelUserTimes.CreateTime;
    *lpExitTime = *(LPFILETIME)&KernelUserTimes.ExitTime;
    *lpKernelTime = *(LPFILETIME)&KernelUserTimes.KernelTime;
    *lpUserTime = *(LPFILETIME)&KernelUserTimes.UserTime;
    return TRUE;
}

/*
 * @implemented
 */
BOOL
WINAPI
QueryThreadCycleTime(
    _In_ HANDLE ThreadHandle,
    _Out_ PULONG64 CycleTime)
{
    THREAD_CYCLE_TIME_INFORMATION CycleTimeInfo;
    NTSTATUS Status;

    Status = NtQueryInformationThread(ThreadHandle,
                                      ThreadCycleTime,
                                      &CycleTimeInfo,
                                      sizeof(CycleTimeInfo),
                                      NULL);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    *CycleTime = CycleTimeInfo.AccumulatedCycles;
    return TRUE;
}

/*
 * @implemented
 */
BOOL
WINAPI
GetThreadContext(IN HANDLE hThread,
                 OUT LPCONTEXT lpContext)
{
    NTSTATUS Status;

    Status = NtGetContextThread(hThread, lpContext);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    return TRUE;
}

/*
 * @implemented
 */
BOOL
WINAPI
SetThreadContext(IN HANDLE hThread,
                 IN CONST CONTEXT *lpContext)
{
    NTSTATUS Status;

    Status = NtSetContextThread(hThread, (PCONTEXT)lpContext);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    return TRUE;
}

/*
 * @implemented
 */
BOOL
WINAPI
GetExitCodeThread(IN HANDLE hThread,
                  OUT LPDWORD lpExitCode)
{
    THREAD_BASIC_INFORMATION ThreadBasic;
    NTSTATUS Status;

    Status = NtQueryInformationThread(hThread,
                                      ThreadBasicInformation,
                                      &ThreadBasic,
                                      sizeof(THREAD_BASIC_INFORMATION),
                                      NULL);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    *lpExitCode = ThreadBasic.ExitStatus;
    return TRUE;
}

/*
 * @implemented
 */
DWORD
WINAPI
ResumeThread(IN HANDLE hThread)
{
    ULONG PreviousResumeCount;
    NTSTATUS Status;

    Status = NtResumeThread(hThread, &PreviousResumeCount);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return -1;
    }

    return PreviousResumeCount;
}

/*
 * @implemented
 */
BOOL
WINAPI
TerminateThread(IN HANDLE hThread,
                IN DWORD dwExitCode)
{
    NTSTATUS Status;
#if DBG
    PRTL_CRITICAL_SECTION LoaderLock;
    THREAD_BASIC_INFORMATION ThreadInfo;
#endif /* DBG */

    /* Check for invalid thread handle */
    if (!hThread)
    {
        /* Fail if one was passed */
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

#if DBG
    /* Get the loader lock */
    LoaderLock = NtCurrentPeb()->LoaderLock;
    if (LoaderLock)
    {
        /* Get our TID */
        Status = NtQueryInformationThread(hThread,
                                          ThreadBasicInformation,
                                          &ThreadInfo,
                                          sizeof(ThreadInfo),
                                          NULL);
        if (NT_SUCCESS(Status))
        {
            /* If terminating the current thread, we must not hold the loader lock */
            if (NtCurrentTeb()->ClientId.UniqueThread == ThreadInfo.ClientId.UniqueThread)
                ASSERT(NtCurrentTeb()->ClientId.UniqueThread != LoaderLock->OwningThread);
        }
    }
#endif /* DBG */

    /* Now terminate the thread */
    Status = NtTerminateThread(hThread, dwExitCode);
    if (!NT_SUCCESS(Status))
    {
        /* Fail */
        BaseSetLastNTError(Status);
        return FALSE;
    }

    /* All done */
    return TRUE;
}

/*
 * @implemented
 */
DWORD
WINAPI
SuspendThread(IN HANDLE hThread)
{
    ULONG PreviousSuspendCount;
    NTSTATUS Status;

    Status = NtSuspendThread(hThread, &PreviousSuspendCount);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return -1;
    }

    return PreviousSuspendCount;
}

/*
 * @implemented
 */
DWORD_PTR
WINAPI
SetThreadAffinityMask(IN HANDLE hThread,
                      IN DWORD_PTR dwThreadAffinityMask)
{
    THREAD_BASIC_INFORMATION ThreadBasic;
    KAFFINITY AffinityMask;
    NTSTATUS Status;

    AffinityMask = (KAFFINITY)dwThreadAffinityMask;

    Status = NtQueryInformationThread(hThread,
                                      ThreadBasicInformation,
                                      &ThreadBasic,
                                      sizeof(THREAD_BASIC_INFORMATION),
                                      NULL);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return 0;
    }

    Status = NtSetInformationThread(hThread,
                                    ThreadAffinityMask,
                                    &AffinityMask,
                                    sizeof(KAFFINITY));
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        ThreadBasic.AffinityMask = 0;
    }

    return ThreadBasic.AffinityMask;
}

#define THEONLYGROUP 0 // Fake support for a single group

/*
 * @implemented
 */
BOOL
WINAPI
GetThreadGroupAffinity(IN HANDLE hThread,
                       OUT PGROUP_AFFINITY GroupAffinity)
{
    NTSTATUS Status;
    THREAD_BASIC_INFORMATION ThreadBasic;

    STUB; // FIXME: Real group support

    /* A NULL output is a parameter error, not something to write through */
    if (!GroupAffinity)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    Status = NtQueryInformationThread(hThread,
                                      ThreadBasicInformation,
                                      &ThreadBasic,
                                      sizeof(ThreadBasic),
                                      NULL);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }
    ZeroMemory(GroupAffinity, sizeof(*GroupAffinity)); // For Reserved
    GroupAffinity->Mask = ThreadBasic.AffinityMask;
    GroupAffinity->Group = THEONLYGROUP;
    return TRUE;
}

/*
 * @implemented
 */
BOOL
WINAPI
SetThreadGroupAffinity(IN HANDLE hThread,
                       IN const GROUP_AFFINITY *GroupAffinity,
                       OUT OPTIONAL PGROUP_AFFINITY PreviousGroupAffinity)
{
    DWORD_PTR OldMask;

    STUB; // FIXME: Real group support
    if (!GroupAffinity || GroupAffinity->Group != THEONLYGROUP)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    OldMask = SetThreadAffinityMask(hThread, GroupAffinity->Mask);
    if (OldMask && PreviousGroupAffinity)
    {
        ZeroMemory(PreviousGroupAffinity, sizeof(*PreviousGroupAffinity)); // For Reserved
        PreviousGroupAffinity->Mask = OldMask;
        PreviousGroupAffinity->Group = THEONLYGROUP;
    }
    return OldMask != 0;
}

/*
 * @implemented
 */
BOOL
WINAPI
SetThreadPriority(IN HANDLE hThread,
                  IN int nPriority)
{
    LONG Prio = nPriority;
    NTSTATUS Status;

    /* Check if values forcing saturation should be used */
    if (Prio == THREAD_PRIORITY_TIME_CRITICAL)
    {
        /* This is 16 */
        Prio = (HIGH_PRIORITY + 1) / 2;
    }
    else if (Prio == THREAD_PRIORITY_IDLE)
    {
        /* This is -16 */
        Prio = -((HIGH_PRIORITY + 1) / 2);
    }

    /* Set the Base Priority */
    Status = NtSetInformationThread(hThread,
                                    ThreadBasePriority,
                                    &Prio,
                                    sizeof(LONG));
    if (!NT_SUCCESS(Status))
    {
        /* Failure */
        BaseSetLastNTError(Status);
        return FALSE;
    }

    /* Return */
    return TRUE;
}

/*
 * @implemented
 */
int
WINAPI
GetThreadPriority(IN HANDLE hThread)
{
    THREAD_BASIC_INFORMATION ThreadBasic;
    NTSTATUS Status;

    /* Query the Base Priority Increment */
    Status = NtQueryInformationThread(hThread,
                                      ThreadBasicInformation,
                                      &ThreadBasic,
                                      sizeof(THREAD_BASIC_INFORMATION),
                                      NULL);
    if (!NT_SUCCESS(Status))
    {
        /* Failure */
        BaseSetLastNTError(Status);
        return THREAD_PRIORITY_ERROR_RETURN;
    }

    /* Do some conversions for saturation values */
    if (ThreadBasic.BasePriority == ((HIGH_PRIORITY + 1) / 2))
    {
        /* Win32 calls this "time critical" */
        ThreadBasic.BasePriority = THREAD_PRIORITY_TIME_CRITICAL;
    }
    else if (ThreadBasic.BasePriority == -((HIGH_PRIORITY + 1) / 2))
    {
        /* Win32 calls this "idle" */
        ThreadBasic.BasePriority = THREAD_PRIORITY_IDLE;
    }

    /* Return the final result */
    return ThreadBasic.BasePriority;
}

/*
 * @implemented
 */
BOOL
WINAPI
GetThreadPriorityBoost(IN HANDLE hThread,
                       OUT PBOOL pDisablePriorityBoost)
{
    ULONG PriorityBoost;
    NTSTATUS Status;

    Status = NtQueryInformationThread(hThread,
                                      ThreadPriorityBoost,
                                      &PriorityBoost,
                                      sizeof(ULONG),
                                      NULL);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    *pDisablePriorityBoost = PriorityBoost;
    return TRUE;
}

/*
 * @implemented
 */
BOOL
NTAPI
SetThreadPriorityBoost(IN HANDLE hThread,
                       IN BOOL bDisablePriorityBoost)
{
    ULONG PriorityBoost;
    NTSTATUS Status;

    PriorityBoost = bDisablePriorityBoost != FALSE;

    Status = NtSetInformationThread(hThread,
                                    ThreadPriorityBoost,
                                    &PriorityBoost,
                                    sizeof(ULONG));
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    return TRUE;
}

/*
 * @implemented
 */
BOOL
WINAPI
GetThreadSelectorEntry(IN HANDLE hThread,
                       IN DWORD dwSelector,
                       OUT LPLDT_ENTRY lpSelectorEntry)
{
#ifdef _M_IX86
    DESCRIPTOR_TABLE_ENTRY DescriptionTableEntry;
    NTSTATUS Status;

    /* Set the selector and do the query */
    DescriptionTableEntry.Selector = dwSelector;
    Status = NtQueryInformationThread(hThread,
                                      ThreadDescriptorTableEntry,
                                      &DescriptionTableEntry,
                                      sizeof(DESCRIPTOR_TABLE_ENTRY),
                                      NULL);
    if (!NT_SUCCESS(Status))
    {
        /* Fail */
        BaseSetLastNTError(Status);
        return FALSE;
    }

    /* Success, return the selector */
    *lpSelectorEntry = DescriptionTableEntry.Descriptor;
    return TRUE;
#else
    DPRINT1("Calling GetThreadSelectorEntry!\n");
    return FALSE;
#endif
}

/*
 * @implemented
 */
DWORD
WINAPI
SetThreadIdealProcessor(IN HANDLE hThread,
                        IN DWORD dwIdealProcessor)
{
    NTSTATUS Status;

    Status = NtSetInformationThread(hThread,
                                    ThreadIdealProcessor,
                                    &dwIdealProcessor,
                                    sizeof(ULONG));
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return -1;
    }

    return (DWORD)Status;
}

/*
 * @implemented
 */
DWORD
WINAPI
GetProcessIdOfThread(IN HANDLE Thread)
{
    THREAD_BASIC_INFORMATION ThreadBasic;
    NTSTATUS Status;

    Status = NtQueryInformationThread(Thread,
                                      ThreadBasicInformation,
                                      &ThreadBasic,
                                      sizeof(THREAD_BASIC_INFORMATION),
                                      NULL);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return 0;
    }

    return HandleToUlong(ThreadBasic.ClientId.UniqueProcess);
}

/*
 * @implemented
 */
DWORD
WINAPI
GetThreadId(IN HANDLE Thread)
{
    THREAD_BASIC_INFORMATION ThreadBasic;
    NTSTATUS Status;

    Status = NtQueryInformationThread(Thread,
                                      ThreadBasicInformation,
                                      &ThreadBasic,
                                      sizeof(THREAD_BASIC_INFORMATION),
                                      NULL);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return 0;
    }

    return HandleToUlong(ThreadBasic.ClientId.UniqueThread);
}

/*
 * @unimplemented
 */
LANGID
WINAPI
SetThreadUILanguage(IN LANGID LangId)
{
#if (NTDDI_VERSION < NTDDI_LONGHORN)
    /* We only support LangId == 0, for selecting a language
     * identifier that best supports the NT Console. */
    if (LangId != 0)
    {
        BaseSetLastNTError(STATUS_NOT_SUPPORTED);
        return 0;
    }
#endif

    UNIMPLEMENTED;

    return LANGIDFROMLCID(NtCurrentTeb()->CurrentLocale);
}

/*
 * @implemented
 */
DWORD
WINAPI
QueueUserAPC(IN PAPCFUNC pfnAPC,
             IN HANDLE hThread,
             IN ULONG_PTR dwData)
{
    NTSTATUS Status;
    ACTIVATION_CONTEXT_BASIC_INFORMATION ActCtxInfo;

    /* Zero the activation context and query information on it */
    RtlZeroMemory(&ActCtxInfo, sizeof(ActCtxInfo));
    Status = RtlQueryInformationActivationContext(RTL_QUERY_ACTIVATION_CONTEXT_FLAG_USE_ACTIVE_ACTIVATION_CONTEXT,
                                                  NULL,
                                                  0,
                                                  ActivationContextBasicInformation,
                                                  &ActCtxInfo,
                                                  sizeof(ActCtxInfo),
                                                  NULL);
    if (!NT_SUCCESS(Status))
    {
        /* Fail due to SxS */
        DbgPrint("SXS: %s failing because RtlQueryInformationActivationContext()"
                 "returned status %08lx\n", __FUNCTION__, Status);
        BaseSetLastNTError(Status);
        return FALSE;
    }

    /* Queue the APC */
    Status = NtQueueApcThread(hThread,
                              (PKNORMAL_ROUTINE)BaseDispatchApc,
                              pfnAPC,
                              (PVOID)dwData,
                              (ActCtxInfo.dwFlags & 1) ?
                              INVALID_ACTIVATION_CONTEXT : ActCtxInfo.hActCtx);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    /* All good */
    return TRUE;
}

/*
 * @implemented
 */
BOOL
WINAPI
SetThreadStackGuarantee(IN OUT PULONG StackSizeInBytes)
{
    PTEB Teb = NtCurrentTeb();
    ULONG GuaranteedStackBytes;
    ULONG AllocationSize;
    ULONG_PTR StackSize, RoundedSize;

    if (!StackSizeInBytes)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    AllocationSize = *StackSizeInBytes;

    /* Retrieve the current stack size */
    GuaranteedStackBytes = Teb->GuaranteedStackBytes;

    /* Return the size of the previous stack */
    *StackSizeInBytes = GuaranteedStackBytes;

    /*
     * If the new stack size is either zero or is less than the current size,
     * the previous stack size is returned and we return success.
     */
    if ((AllocationSize == 0) || (AllocationSize < GuaranteedStackBytes))
    {
        return TRUE;
    }

    /* It must fit in the stack reservation */
    StackSize = (ULONG_PTR)Teb->NtTib.StackBase - (ULONG_PTR)Teb->DeallocationStack;
    if (AllocationSize >= StackSize)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* The guarantee is kept in whole pages, at least two on 64-bit */
    RoundedSize = max(ALIGN_UP_BY(AllocationSize, PAGE_SIZE),
                      PAGE_SIZE * sizeof(PVOID) / sizeof(ULONG));
    if ((RoundedSize >= StackSize) || (RoundedSize > MAXULONG))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* The kernel reads it when the stack overflows */
    Teb->GuaranteedStackBytes = (ULONG)RoundedSize;
    return TRUE;
}

/*
 * @implemented
 */
BOOL
WINAPI
GetThreadIOPendingFlag(IN HANDLE hThread,
                       OUT PBOOL lpIOIsPending)
{
    ULONG IoPending;
    NTSTATUS Status;

    /* Query the flag */
    Status = NtQueryInformationThread(hThread,
                                      ThreadIsIoPending,
                                      &IoPending,
                                      sizeof(IoPending),
                                      NULL);
    if (NT_SUCCESS(Status))
    {
        /* Return the flag */
        *lpIOIsPending = IoPending ? TRUE : FALSE;
        return TRUE;
    }

    /* Fail */
    BaseSetLastNTError(Status);
    return FALSE;
}

/*
 * @implemented
 */
BOOL
WINAPI
QueueUserWorkItem(IN LPTHREAD_START_ROUTINE Function,
                  IN PVOID Context,
                  IN ULONG Flags)
{
    NTSTATUS Status;

    /* NOTE: Rtl needs to safely call the function using a trampoline */
    Status = RtlQueueWorkItem((WORKERCALLBACKFUNC)Function, Context, Flags);
    if (!NT_SUCCESS(Status))
    {
        /* Failed */
        BaseSetLastNTError(Status);
        return FALSE;
    }

    /* All good */
    return TRUE;
}

/*
 * @implemented
 */
DWORD
WINAPI
TlsAlloc(VOID)
{
    ULONG Index;
    PTEB Teb;
    PPEB Peb;

    /* Get the PEB and TEB, lock the PEB */
    Teb = NtCurrentTeb();
    Peb = Teb->ProcessEnvironmentBlock;
    RtlAcquirePebLock();

    /* Try to get regular TEB slot */
    Index = RtlFindClearBitsAndSet(Peb->TlsBitmap, 1, 0);
    if (Index != 0xFFFFFFFF)
    {
        /* Clear the value. */
        Teb->TlsSlots[Index] = 0;
        RtlReleasePebLock();
        return Index;
    }

    /* If it fails, try to find expansion TEB slot. */
    Index = RtlFindClearBitsAndSet(Peb->TlsExpansionBitmap, 1, 0);
    if (Index != 0xFFFFFFFF)
    {
        /* Is there no expansion slot yet? */
        if (!Teb->TlsExpansionSlots)
        {
            /* Allocate an array */
            Teb->TlsExpansionSlots = RtlAllocateHeap(RtlGetProcessHeap(),
                                                     HEAP_ZERO_MEMORY,
                                                     TLS_EXPANSION_SLOTS *
                                                     sizeof(PVOID));
        }

        /* Did we get an array? */
        if (!Teb->TlsExpansionSlots)
        {
            /* Fail */
            RtlClearBits(Peb->TlsExpansionBitmap, Index, 1);
            Index = 0xFFFFFFFF;
            BaseSetLastNTError(STATUS_NO_MEMORY);
        }
        else
        {
            /* Clear the value. */
            Teb->TlsExpansionSlots[Index] = 0;
            Index += TLS_MINIMUM_AVAILABLE;
        }
    }
    else
    {
        /* Fail */
        BaseSetLastNTError(STATUS_NO_MEMORY);
    }

    /* Release the lock and return */
    RtlReleasePebLock();
    return Index;
}

/*
 * @implemented
 */
BOOL
WINAPI
TlsFree(IN DWORD Index)
{
    BOOL BitSet;
    PPEB Peb;
    ULONG TlsIndex;
    PVOID TlsBitmap;
    NTSTATUS Status;

    /* Acquire the PEB lock and grab the PEB */
    Peb = NtCurrentPeb();
    RtlAcquirePebLock();

    /* Check if the index is too high */
    if (Index >= TLS_MINIMUM_AVAILABLE)
    {
        /* Check if it can fit in the expansion slots */
        TlsIndex = Index - TLS_MINIMUM_AVAILABLE;
        if (TlsIndex >= TLS_EXPANSION_SLOTS)
        {
            /* It's invalid */
            BaseSetLastNTError(STATUS_INVALID_PARAMETER);
            RtlReleasePebLock();
            return FALSE;
        }
        else
        {
            /* Use the expansion bitmap */
            TlsBitmap = Peb->TlsExpansionBitmap;
            Index = TlsIndex;
        }
    }
    else
    {
        /* Use the normal bitmap */
        TlsBitmap = Peb->TlsBitmap;
    }

    /* Check if the index was set */
    BitSet = RtlAreBitsSet(TlsBitmap, Index, 1);
    if (BitSet)
    {
        /* Tell the kernel to free the TLS cells */
        Status = NtSetInformationThread(NtCurrentThread(),
                                        ThreadZeroTlsCell,
                                        &Index,
                                        sizeof(DWORD));
        if (!NT_SUCCESS(Status))
        {
            BaseSetLastNTError(STATUS_INVALID_PARAMETER);
            RtlReleasePebLock();
            return FALSE;
        }

        /* Clear the bit */
        RtlClearBits(TlsBitmap, Index, 1);
    }
    else
    {
        /* Fail */
        BaseSetLastNTError(STATUS_INVALID_PARAMETER);
        RtlReleasePebLock();
        return FALSE;
    }

    /* Done! */
    RtlReleasePebLock();
    return TRUE;
}

/*
 * @implemented
 */
LPVOID
WINAPI
TlsGetValue(IN DWORD Index)
{
    PTEB Teb;

    /* Get the TEB and clear the last error */
    Teb = NtCurrentTeb();
    Teb->LastErrorValue = 0;

    /* Check for simple TLS index */
    if (Index < TLS_MINIMUM_AVAILABLE)
    {
        /* Return it */
        return Teb->TlsSlots[Index];
    }

    /* Check for valid index */
    if (Index >= TLS_EXPANSION_SLOTS + TLS_MINIMUM_AVAILABLE)
    {
        /* Fail */
        BaseSetLastNTError(STATUS_INVALID_PARAMETER);
        return NULL;
    }

    /* The expansion slots are allocated on demand, so check for it. */
    Teb->LastErrorValue = 0;
    if (!Teb->TlsExpansionSlots) return NULL;

    /* Return the value from the expansion slots */
    return Teb->TlsExpansionSlots[Index - TLS_MINIMUM_AVAILABLE];
}

/*
 * @implemented
 */
BOOL
WINAPI
TlsSetValue(IN DWORD Index,
            IN LPVOID Value)
{
    DWORD TlsIndex;
    PTEB Teb = NtCurrentTeb();

    /* Check for simple TLS index */
    if (Index < TLS_MINIMUM_AVAILABLE)
    {
        /* Return it */
        Teb->TlsSlots[Index] = Value;
        return TRUE;
    }

    /* Check if this is an expansion slot */
    TlsIndex = Index - TLS_MINIMUM_AVAILABLE;
    if (TlsIndex >= TLS_EXPANSION_SLOTS)
    {
        /* Fail */
        BaseSetLastNTError(STATUS_INVALID_PARAMETER);
        return FALSE;
    }

    /* Do we not have expansion slots? */
    if (!Teb->TlsExpansionSlots)
    {
        /* Get the PEB lock to see if we still need them */
        RtlAcquirePebLock();
        if (!Teb->TlsExpansionSlots)
        {
            /* Allocate them */
            Teb->TlsExpansionSlots = RtlAllocateHeap(RtlGetProcessHeap(),
                                                     HEAP_ZERO_MEMORY,
                                                     TLS_EXPANSION_SLOTS *
                                                     sizeof(PVOID));
            if (!Teb->TlsExpansionSlots)
            {
                /* Fail */
                RtlReleasePebLock();
                BaseSetLastNTError(STATUS_NO_MEMORY);
                return FALSE;
            }
        }

        /* Release the lock */
        RtlReleasePebLock();
    }

    /* Write the value */
    Teb->TlsExpansionSlots[TlsIndex] = Value;

    /* Success */
    return TRUE;
}

/*
 * Windows 8 thread information. The kernel has no page priority and no power throttling for threads, so
 * the memory priority a thread of this process asks for is remembered here, in a small table that is keyed
 * by thread id and creation time (an id that is used again by another thread never matches an old entry).
 * Nothing acts on it: both are hints about how pages and processor time should be spent.
 */
#define BASEP_MEMORY_PRIORITY_SLOTS     64
#define BASEP_MEMORY_PRIORITY_DEFAULT   MEMORY_PRIORITY_NORMAL

typedef struct _BASEP_MEMORY_PRIORITY
{
    HANDLE ThreadId;
    LONGLONG CreateTime;
    ULONG Priority;
} BASEP_MEMORY_PRIORITY;

static BASEP_MEMORY_PRIORITY BasepMemoryPriority[BASEP_MEMORY_PRIORITY_SLOTS];
static ULONG BasepMemoryPriorityNext;

/* The critical section for the data structures of kernel32: a thread that waits for it does not keep the owner off the processor */
#define BasepLockMemoryPriority()   RtlEnterCriticalSection(&BaseDllDirectoryLock)
#define BasepUnlockMemoryPriority() RtlLeaveCriticalSection(&BaseDllDirectoryLock)

/*
 * Handle checks of the thread information functions: the same errors as the kernel gives on Windows. The identity of
 * the thread (its id and creation time) is only read when the handle may query the thread: the kernel here takes
 * THREAD_QUERY_INFORMATION for that, Windows takes less, and a handle that Windows serves must be served.
 */
static
NTSTATUS
BasepCheckThreadHandle(
    _In_ HANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PTHREAD_BASIC_INFORMATION BasicInfo,
    _Out_ PLONGLONG CreateTime,
    _Out_ PBOOLEAN HaveIdentity)
{
    KERNEL_USER_TIMES Times;
    NTSTATUS Status;

    *HaveIdentity = FALSE;
    Status = BasepCheckHandleType(ThreadHandle, L"Thread", DesiredAccess);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = NtQueryInformationThread(ThreadHandle, ThreadBasicInformation, BasicInfo, sizeof(*BasicInfo), NULL);
    if (NT_SUCCESS(Status))
    {
        Status = NtQueryInformationThread(ThreadHandle, ThreadTimes, &Times, sizeof(Times), NULL);
        if (NT_SUCCESS(Status))
        {
            *CreateTime = Times.CreateTime.QuadPart;
            *HaveIdentity = TRUE;
        }
    }

    return STATUS_SUCCESS;
}

static
ULONG
BasepGetMemoryPriority(
    _In_ const CLIENT_ID *ClientId,
    _In_ LONGLONG CreateTime)
{
    ULONG Priority = BASEP_MEMORY_PRIORITY_DEFAULT, i;

    if (ClientId->UniqueProcess != NtCurrentTeb()->ClientId.UniqueProcess)
        return Priority;

    BasepLockMemoryPriority();
    for (i = 0; i < BASEP_MEMORY_PRIORITY_SLOTS; i++)
    {
        if (BasepMemoryPriority[i].ThreadId == ClientId->UniqueThread &&
            BasepMemoryPriority[i].CreateTime == CreateTime)
        {
            Priority = BasepMemoryPriority[i].Priority;
            break;
        }
    }
    BasepUnlockMemoryPriority();
    return Priority;
}

static
VOID
BasepSetMemoryPriority(
    _In_ const CLIENT_ID *ClientId,
    _In_ LONGLONG CreateTime,
    _In_ ULONG Priority)
{
    ULONG i, Slot = BASEP_MEMORY_PRIORITY_SLOTS;

    if (ClientId->UniqueProcess != NtCurrentTeb()->ClientId.UniqueProcess)
        return;

    BasepLockMemoryPriority();
    for (i = 0; i < BASEP_MEMORY_PRIORITY_SLOTS; i++)
    {
        if (BasepMemoryPriority[i].ThreadId == ClientId->UniqueThread)
        {
            /* The same id again: the same thread, or an old one that is gone */
            Slot = i;
            break;
        }
        if (Slot == BASEP_MEMORY_PRIORITY_SLOTS && BasepMemoryPriority[i].ThreadId == NULL)
            Slot = i;
    }
    if (Slot == BASEP_MEMORY_PRIORITY_SLOTS)
    {
        /* Full: the oldest entry goes */
        Slot = BasepMemoryPriorityNext++ % BASEP_MEMORY_PRIORITY_SLOTS;
    }

    BasepMemoryPriority[Slot].ThreadId = ClientId->UniqueThread;
    BasepMemoryPriority[Slot].CreateTime = CreateTime;
    BasepMemoryPriority[Slot].Priority = Priority;
    BasepUnlockMemoryPriority();
}

/* The base priority of the process of a thread: the thread priorities are increments of it */
static
NTSTATUS
BasepQueryProcessBasePriority(
    _In_ const CLIENT_ID *ClientId,
    _Out_ PLONG BasePriority)
{
    PROCESS_BASIC_INFORMATION BasicInfo;
    OBJECT_ATTRIBUTES ObjectAttributes;
    CLIENT_ID Process;
    HANDLE Handle = NtCurrentProcess();
    NTSTATUS Status;

    if (ClientId->UniqueProcess != NtCurrentTeb()->ClientId.UniqueProcess)
    {
        InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
        Process.UniqueProcess = ClientId->UniqueProcess;
        Process.UniqueThread = NULL;
        Status = NtOpenProcess(&Handle, PROCESS_QUERY_INFORMATION, &ObjectAttributes, &Process);
        if (!NT_SUCCESS(Status))
            return Status;
    }

    Status = NtQueryInformationProcess(Handle, ProcessBasicInformation, &BasicInfo, sizeof(BasicInfo), NULL);
    if (Handle != NtCurrentProcess())
        NtClose(Handle);
    if (NT_SUCCESS(Status))
        *BasePriority = BasicInfo.BasePriority;

    return Status;
}

/*
 * @implemented
 */
BOOL
WINAPI
GetThreadInformation(
    _In_ HANDLE hThread,
    _In_ THREAD_INFORMATION_CLASS ThreadInformationClass,
    _Out_writes_bytes_(ThreadInformationSize) LPVOID ThreadInformation,
    _In_ DWORD ThreadInformationSize)
{
    THREAD_BASIC_INFORMATION BasicInfo;
    LONGLONG CreateTime = 0;
    LONG ProcessBase, Priority;
    ULONG Value = 0;
    BOOLEAN HaveIdentity;
    NTSTATUS Status;

    switch (ThreadInformationClass)
    {
        case ThreadMemoryPriority:
        case ThreadAbsoluteCpuPriority:
        case ThreadDynamicCodePolicy:
            break;

        default:
            /* Windows 10 knows no other class that can be read; this includes the power throttling state */
            BaseSetLastNTError(STATUS_INVALID_PARAMETER);
            return FALSE;
    }

    /* The sizes and the pointer are checked before the handle, as the kernel does */
    if (ThreadInformationSize != sizeof(ULONG))
    {
        BaseSetLastNTError(STATUS_INFO_LENGTH_MISMATCH);
        return FALSE;
    }

    if (!ThreadInformation)
    {
        BaseSetLastNTError(STATUS_ACCESS_VIOLATION);
        return FALSE;
    }

    Status = BasepCheckThreadHandle(hThread,
                                    THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION,
                                    &BasicInfo,
                                    &CreateTime,
                                    &HaveIdentity);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    if (ThreadInformationClass == ThreadMemoryPriority)
    {
        Value = HaveIdentity ? BasepGetMemoryPriority(&BasicInfo.ClientId, CreateTime) : BASEP_MEMORY_PRIORITY_DEFAULT;
    }
    else if (ThreadInformationClass == ThreadAbsoluteCpuPriority)
    {
        /* The base priority comes from the thread, which this handle may not read */
        if (!HaveIdentity)
        {
            BaseSetLastNTError(STATUS_ACCESS_DENIED);
            return FALSE;
        }

        /* The priority that the thread has before the scheduler adds anything: the process base and the increment */
        Status = BasepQueryProcessBasePriority(&BasicInfo.ClientId, &ProcessBase);
        if (!NT_SUCCESS(Status))
        {
            BaseSetLastNTError(Status);
            return FALSE;
        }

        if (BasicInfo.BasePriority >= (HIGH_PRIORITY + 1) / 2)
            Priority = (ProcessBase >= LOW_REALTIME_PRIORITY) ? HIGH_PRIORITY : (LOW_REALTIME_PRIORITY - 1);
        else if (BasicInfo.BasePriority <= -(HIGH_PRIORITY + 1) / 2)
            Priority = (ProcessBase >= LOW_REALTIME_PRIORITY) ? LOW_REALTIME_PRIORITY : 1;
        else
            Priority = ProcessBase + BasicInfo.BasePriority;

        if (ProcessBase >= LOW_REALTIME_PRIORITY)
            Priority = min(max(Priority, LOW_REALTIME_PRIORITY), HIGH_PRIORITY);
        else
            Priority = min(max(Priority, 1), LOW_REALTIME_PRIORITY - 1);
        Value = Priority;
    }

    _SEH2_TRY
    {
        *(PULONG)ThreadInformation = Value;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = STATUS_ACCESS_VIOLATION;
    }
    _SEH2_END;

    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    return TRUE;
}

/*
 * @implemented
 */
BOOL
WINAPI
SetThreadInformation(
    _In_ HANDLE hThread,
    _In_ THREAD_INFORMATION_CLASS ThreadInformationClass,
    _In_reads_bytes_(ThreadInformationSize) LPVOID ThreadInformation,
    _In_ DWORD ThreadInformationSize)
{
    THREAD_BASIC_INFORMATION BasicInfo;
    LONGLONG CreateTime = 0;
    THREAD_POWER_THROTTLING_STATE Throttling;
    LONG ProcessBase, Increment;
    ULONG Value = 0;
    BOOLEAN HaveIdentity;
    NTSTATUS Status = STATUS_SUCCESS;

    switch (ThreadInformationClass)
    {
        case ThreadMemoryPriority:
        case ThreadAbsoluteCpuPriority:
        case ThreadDynamicCodePolicy:
            if (ThreadInformationSize != sizeof(ULONG))
                Status = STATUS_INFO_LENGTH_MISMATCH;
            break;

        case ThreadPowerThrottling:
            if (ThreadInformationSize < sizeof(THREAD_POWER_THROTTLING_STATE))
                Status = STATUS_INVALID_PARAMETER;
            break;

        default:
            Status = STATUS_INVALID_PARAMETER;
            break;
    }
    if (NT_SUCCESS(Status) && !ThreadInformation)
        Status = STATUS_ACCESS_VIOLATION;
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    _SEH2_TRY
    {
        if (ThreadInformationClass == ThreadPowerThrottling)
            Throttling = *(PTHREAD_POWER_THROTTLING_STATE)ThreadInformation;
        else
            Value = *(PULONG)ThreadInformation;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = STATUS_ACCESS_VIOLATION;
    }
    _SEH2_END;
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    /* The value is checked first, then the handle */
    switch (ThreadInformationClass)
    {
        case ThreadMemoryPriority:
            /* Windows takes the values from 1 (very low) to 5 (normal) */
            if (Value < MEMORY_PRIORITY_VERY_LOW || Value > MEMORY_PRIORITY_NORMAL)
                Status = STATUS_INVALID_PARAMETER;
            break;

        case ThreadAbsoluteCpuPriority:
            /* 1 to 15; the real-time priorities, 16 to 31, take a privilege that is not given here */
            if (Value == 0 || Value > HIGH_PRIORITY)
                Status = STATUS_INVALID_PARAMETER;
            else if (Value >= LOW_REALTIME_PRIORITY)
                Status = STATUS_PRIVILEGE_NOT_HELD;
            break;

        case ThreadDynamicCodePolicy:
            /* 0 and 1 are the values of the policy; Windows 10 gives no process the right to change it */
            Status = (Value > 1) ? STATUS_INVALID_PARAMETER : STATUS_ACCESS_DENIED;
            break;

        default:
            /* The version is 0 or 1; only the execution speed bit exists, and a state needs its control bit */
            if (Throttling.Version > THREAD_POWER_THROTTLING_CURRENT_VERSION ||
                (Throttling.ControlMask & ~THREAD_POWER_THROTTLING_VALID_FLAGS) ||
                (Throttling.StateMask & ~Throttling.ControlMask))
            {
                Status = STATUS_INVALID_PARAMETER;
            }
            break;
    }
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    Status = BasepCheckThreadHandle(hThread, THREAD_SET_INFORMATION, &BasicInfo, &CreateTime, &HaveIdentity);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    if (ThreadInformationClass == ThreadMemoryPriority)
    {
        /* A handle that may not query the thread cannot say which one it is: the hint is taken and not kept */
        if (HaveIdentity)
            BasepSetMemoryPriority(&BasicInfo.ClientId, CreateTime, Value);
    }
    else if (ThreadInformationClass == ThreadAbsoluteCpuPriority)
    {
        if (!HaveIdentity)
        {
            BaseSetLastNTError(STATUS_ACCESS_DENIED);
            return FALSE;
        }

        /*
         * The kernel sets the priority of a thread as an increment of the base priority of the process, 2 up or
         * down, or to the highest or lowest priority of the class; the others cannot be set.
         */
        Status = BasepQueryProcessBasePriority(&BasicInfo.ClientId, &ProcessBase);
        if (NT_SUCCESS(Status))
        {
            if ((LONG)Value >= ProcessBase + THREAD_BASE_PRIORITY_MIN && (LONG)Value <= ProcessBase + THREAD_BASE_PRIORITY_MAX)
                Increment = (LONG)Value - ProcessBase;
            else if (Value == LOW_REALTIME_PRIORITY - 1)
                Increment = (HIGH_PRIORITY + 1) / 2;
            else if (Value == 1)
                Increment = -((HIGH_PRIORITY + 1) / 2);
            else
                Status = STATUS_NOT_SUPPORTED;
        }
        if (NT_SUCCESS(Status))
            Status = NtSetInformationThread(hThread, ThreadBasePriority, &Increment, sizeof(Increment));
        if (!NT_SUCCESS(Status))
        {
            BaseSetLastNTError(Status);
            return FALSE;
        }
    }

    return TRUE;
}

/* EOF */

#if defined(_WIN64) || defined(BUILD_WOW64_ENABLED) || defined(SYSWOW64_GUEST)
BOOL WINAPI Wow64GetThreadContext(HANDLE Thread, PWOW64_CONTEXT Context)
{
#ifdef _WIN64
    NTSTATUS Status = NtQueryInformationThread(Thread, ThreadWow64Context, Context, sizeof(*Context), NULL);
    if (NT_SUCCESS(Status)) return TRUE;
    BaseSetLastNTError(Status);
    return FALSE;
#else
    return GetThreadContext(Thread, (PCONTEXT)Context);
#endif
}

BOOL WINAPI Wow64SetThreadContext(HANDLE Thread, const WOW64_CONTEXT *Context)
{
#ifdef _WIN64
    NTSTATUS Status = NtSetInformationThread(Thread, ThreadWow64Context, (PVOID)Context, sizeof(*Context));
    if (NT_SUCCESS(Status)) return TRUE;
    BaseSetLastNTError(Status);
    return FALSE;
#else
    return SetThreadContext(Thread, (const CONTEXT *)Context);
#endif
}

#endif
