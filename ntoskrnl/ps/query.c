/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/ps/query.c
 * PURPOSE:         Process Manager: Thread/Process Query/Set Information
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 *                  Thomas Weidenmueller (w3seek@reactos.org)
 *                  Eric Kohl
 */

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

/* Debugging Level */
ULONG PspTraceLevel = 0;

/* PRIVATE FUNCTIONS *********************************************************/

NTSTATUS
NTAPI
PsReferenceProcessFilePointer(
    _In_ PEPROCESS Process,
    _Outptr_ PFILE_OBJECT *FileObject)
{
    PSECTION Section;
    PAGED_CODE();

    /* Lock the process */
    if (!ExAcquireRundownProtection(&Process->RundownProtect))
    {
        return STATUS_PROCESS_IS_TERMINATING;
    }

    /* Get the section */
    Section = Process->SectionObject;
    if (Section)
    {
        /* Get the file object and reference it */
        *FileObject = MmGetFileObjectForSection((PVOID)Section);
        ObReferenceObject(*FileObject);
    }

    /* Release the protection */
    ExReleaseRundownProtection(&Process->RundownProtect);

    /* Return status */
    return Section ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

#if DBG
static
PCSTR
PspDumpProcessInfoClassName(
    _In_ PROCESSINFOCLASS ProcessInformationClass)
{
    static CHAR UnknownClassName[11];

#define DBG_PROCESS_INFO_CLASS(InfoClass)   [InfoClass] = #InfoClass
    static const PCSTR ProcessInfoClasses[] =
    {
        DBG_PROCESS_INFO_CLASS(ProcessBasicInformation),
        DBG_PROCESS_INFO_CLASS(ProcessQuotaLimits),
        DBG_PROCESS_INFO_CLASS(ProcessVmCounters),
        DBG_PROCESS_INFO_CLASS(ProcessTimes),
        DBG_PROCESS_INFO_CLASS(ProcessBasePriority),
        DBG_PROCESS_INFO_CLASS(ProcessRaisePriority),
        DBG_PROCESS_INFO_CLASS(ProcessDebugPort),
        DBG_PROCESS_INFO_CLASS(ProcessExceptionPort),
        DBG_PROCESS_INFO_CLASS(ProcessAccessToken),
        DBG_PROCESS_INFO_CLASS(ProcessLdtInformation),
        DBG_PROCESS_INFO_CLASS(ProcessLdtSize),
        DBG_PROCESS_INFO_CLASS(ProcessDefaultHardErrorMode),
        DBG_PROCESS_INFO_CLASS(ProcessIoPortHandlers),
        DBG_PROCESS_INFO_CLASS(ProcessPooledUsageAndLimits),
        DBG_PROCESS_INFO_CLASS(ProcessWorkingSetWatch),
        DBG_PROCESS_INFO_CLASS(ProcessUserModeIOPL),
        DBG_PROCESS_INFO_CLASS(ProcessEnableAlignmentFaultFixup),
        DBG_PROCESS_INFO_CLASS(ProcessPriorityClass),
        DBG_PROCESS_INFO_CLASS(ProcessWx86Information),
        DBG_PROCESS_INFO_CLASS(ProcessHandleCount),
        DBG_PROCESS_INFO_CLASS(ProcessAffinityMask),
        DBG_PROCESS_INFO_CLASS(ProcessPriorityBoost),
        DBG_PROCESS_INFO_CLASS(ProcessDeviceMap),
        DBG_PROCESS_INFO_CLASS(ProcessSessionInformation),
        DBG_PROCESS_INFO_CLASS(ProcessForegroundInformation),
        DBG_PROCESS_INFO_CLASS(ProcessWow64Information),
        DBG_PROCESS_INFO_CLASS(ProcessImageFileName),
        DBG_PROCESS_INFO_CLASS(ProcessLUIDDeviceMapsEnabled),
        DBG_PROCESS_INFO_CLASS(ProcessBreakOnTermination),
        DBG_PROCESS_INFO_CLASS(ProcessDebugObjectHandle),
        DBG_PROCESS_INFO_CLASS(ProcessDebugFlags),
        DBG_PROCESS_INFO_CLASS(ProcessHandleTracing),
        DBG_PROCESS_INFO_CLASS(ProcessIoPriority),
        DBG_PROCESS_INFO_CLASS(ProcessExecuteFlags),
        DBG_PROCESS_INFO_CLASS(ProcessTlsInformation),
        DBG_PROCESS_INFO_CLASS(ProcessCookie),
        DBG_PROCESS_INFO_CLASS(ProcessImageInformation),
        DBG_PROCESS_INFO_CLASS(ProcessCycleTime),
        DBG_PROCESS_INFO_CLASS(ProcessPagePriority),
        DBG_PROCESS_INFO_CLASS(ProcessInstrumentationCallback),
        DBG_PROCESS_INFO_CLASS(ProcessThreadStackAllocation),
        DBG_PROCESS_INFO_CLASS(ProcessWorkingSetWatchEx),
        DBG_PROCESS_INFO_CLASS(ProcessImageFileNameWin32),
        DBG_PROCESS_INFO_CLASS(ProcessImageFileMapping),
        DBG_PROCESS_INFO_CLASS(ProcessAffinityUpdateMode),
        DBG_PROCESS_INFO_CLASS(ProcessMemoryAllocationMode),
        DBG_PROCESS_INFO_CLASS(ProcessGroupInformation),
        DBG_PROCESS_INFO_CLASS(ProcessConsoleHostProcess),
        DBG_PROCESS_INFO_CLASS(ProcessWindowInformation),
        DBG_PROCESS_INFO_CLASS(ProcessCommandLineInformation),
    };
#undef DBG_PROCESS_INFO_CLASS

    if (ProcessInformationClass < RTL_NUMBER_OF(ProcessInfoClasses))
    {
        return ProcessInfoClasses[ProcessInformationClass];
    }

    sprintf(UnknownClassName, "%lu", ProcessInformationClass);
    return UnknownClassName;
}

static
PCSTR
PspDumpThreadInfoClassName(
    _In_ THREADINFOCLASS ThreadInformationClass)
{
    static CHAR UnknownClassName[11];

#define DBG_THREAD_INFO_CLASS(InfoClass)   [InfoClass] = #InfoClass
    static const PCSTR ThreadInfoClasses[] =
    {
        DBG_THREAD_INFO_CLASS(ThreadBasicInformation),
        DBG_THREAD_INFO_CLASS(ThreadTimes),
        DBG_THREAD_INFO_CLASS(ThreadPriority),
        DBG_THREAD_INFO_CLASS(ThreadBasePriority),
        DBG_THREAD_INFO_CLASS(ThreadAffinityMask),
        DBG_THREAD_INFO_CLASS(ThreadImpersonationToken),
        DBG_THREAD_INFO_CLASS(ThreadDescriptorTableEntry),
        DBG_THREAD_INFO_CLASS(ThreadEnableAlignmentFaultFixup),
        DBG_THREAD_INFO_CLASS(ThreadEventPair_Reusable),
        DBG_THREAD_INFO_CLASS(ThreadQuerySetWin32StartAddress),
        DBG_THREAD_INFO_CLASS(ThreadZeroTlsCell),
        DBG_THREAD_INFO_CLASS(ThreadPerformanceCount),
        DBG_THREAD_INFO_CLASS(ThreadAmILastThread),
        DBG_THREAD_INFO_CLASS(ThreadIdealProcessor),
        DBG_THREAD_INFO_CLASS(ThreadPriorityBoost),
        DBG_THREAD_INFO_CLASS(ThreadSetTlsArrayAddress),
        DBG_THREAD_INFO_CLASS(ThreadIsIoPending),
        DBG_THREAD_INFO_CLASS(ThreadHideFromDebugger),
        DBG_THREAD_INFO_CLASS(ThreadBreakOnTermination),
        DBG_THREAD_INFO_CLASS(ThreadSwitchLegacyState),
        DBG_THREAD_INFO_CLASS(ThreadIsTerminated),
        DBG_THREAD_INFO_CLASS(ThreadLastSystemCall),
        DBG_THREAD_INFO_CLASS(ThreadIoPriority),
        DBG_THREAD_INFO_CLASS(ThreadCycleTime),
        DBG_THREAD_INFO_CLASS(ThreadPagePriority),
        DBG_THREAD_INFO_CLASS(ThreadActualBasePriority),
        DBG_THREAD_INFO_CLASS(ThreadTebInformation),
        DBG_THREAD_INFO_CLASS(ThreadCSwitchMon),
        DBG_THREAD_INFO_CLASS(ThreadCSwitchPmu),
        DBG_THREAD_INFO_CLASS(ThreadWow64Context),
        DBG_THREAD_INFO_CLASS(ThreadGroupInformation),
        DBG_THREAD_INFO_CLASS(ThreadUmsInformation),
        DBG_THREAD_INFO_CLASS(ThreadCounterProfiling),
        DBG_THREAD_INFO_CLASS(ThreadIdealProcessorEx),
        DBG_THREAD_INFO_CLASS(ThreadCpuAccountingInformation),
        DBG_THREAD_INFO_CLASS(ThreadSuspendCount),
        DBG_THREAD_INFO_CLASS(ThreadHeterogeneousCpuPolicy),
        DBG_THREAD_INFO_CLASS(ThreadContainerId),
        DBG_THREAD_INFO_CLASS(ThreadNameInformation),
        DBG_THREAD_INFO_CLASS(ThreadSelectedCpuSets),
        DBG_THREAD_INFO_CLASS(ThreadSystemThreadInformation),
        DBG_THREAD_INFO_CLASS(ThreadActualGroupAffinity),
        DBG_THREAD_INFO_CLASS(ThreadDynamicCodePolicyInfo),
        DBG_THREAD_INFO_CLASS(ThreadExplicitCaseSensitivity),
        DBG_THREAD_INFO_CLASS(ThreadWorkOnBehalfTicket),
        DBG_THREAD_INFO_CLASS(ThreadSubsystemInformation),
        DBG_THREAD_INFO_CLASS(ThreadDbgkWerReportActive),
        DBG_THREAD_INFO_CLASS(ThreadAttachContainer),
        DBG_THREAD_INFO_CLASS(ThreadManageWritesToExecutableMemory),
        DBG_THREAD_INFO_CLASS(ThreadPowerThrottlingState),
        DBG_THREAD_INFO_CLASS(ThreadWorkloadClass),
        DBG_THREAD_INFO_CLASS(ThreadCreateStateChange),
        DBG_THREAD_INFO_CLASS(ThreadApplyStateChange),
        DBG_THREAD_INFO_CLASS(ThreadStrongerBadHandleChecks),
        DBG_THREAD_INFO_CLASS(ThreadEffectiveIoPriority),
        DBG_THREAD_INFO_CLASS(ThreadEffectivePagePriority),
    };
#undef DBG_THREAD_INFO_CLASS

    if (ThreadInformationClass < RTL_NUMBER_OF(ThreadInfoClasses))
    {
        return ThreadInfoClasses[ThreadInformationClass];
    }

    sprintf(UnknownClassName, "%lu", ThreadInformationClass);
    return UnknownClassName;
}
#endif // #if DBG


/**
 * @brief
 * Returns whether a thread information class exists at the NT version
 * currently reported by the kernel. Vista and later classes are rejected
 * with STATUS_INVALID_INFO_CLASS below the version that introduced them, so
 * that a 5.2 identity behaves exactly like Windows Server 2003.
 **/
static
BOOLEAN
PspIsThreadInfoClassAvailable(
    _In_ ULONG ThreadInformationClass,
    _In_ BOOLEAN IsSet)
{
    ULONG Version = (NtMajorVersion << 8) | NtMinorVersion;
    ULONG MinVersion;

    switch (ThreadInformationClass)
    {
        case ThreadHideFromDebugger:
            /* Set exists since XP, Query only since Vista */
            if (IsSet)
                return TRUE;
            MinVersion = 0x0600;
            break;

        case ThreadIoPriority:
        case ThreadPagePriority:
            MinVersion = 0x0600;
            break;

        case ThreadActualBasePriority:
        case ThreadCSwitchPmu:
#if !(defined(_M_AMD64) && defined(BUILD_WOW64_ENABLED))
        case ThreadWow64Context: /* only a Set-probe placeholder without WoW64 */
#endif
        case ThreadGroupInformation:
        case ThreadUmsInformation:
        case ThreadCounterProfiling:
        case ThreadIdealProcessorEx:
            MinVersion = 0x0601;
            break;

        case ThreadCpuAccountingInformation:
            MinVersion = 0x0602;
            break;

        case ThreadSuspendCount:
            MinVersion = 0x0603;
            break;

        case ThreadNameInformation: /* ReactOS supports it at all versions */
            return TRUE;

        default:
            if ((ThreadInformationClass >= ThreadHeterogeneousCpuPolicy) &&
                (ThreadInformationClass <= ThreadEffectivePagePriority))
            {
                MinVersion = 0x0A00;
                break;
            }
            return TRUE;
    }

    return (Version >= MinVersion);
}

/**
 * @brief
 * Queries one of the Vista+ thread information classes that need no
 * per-class kernel state. The buffer size was already validated against
 * PsThreadInfoClass by the caller.
 **/
static
NTSTATUS
PspQueryThreadInfoVista(
    _In_ HANDLE ThreadHandle,
    _In_ ULONG ThreadInformationClass,
    _Out_ PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength,
    _Out_ PULONG Length,
    _In_ KPROCESSOR_MODE PreviousMode)
{
    PETHREAD Thread;
    NTSTATUS Status;
    ACCESS_MASK Access = THREAD_QUERY_LIMITED_INFORMATION;
    union
    {
        ULONG Ulong;
        GUID Guid;
        GROUP_AFFINITY GroupAffinity;
        PROCESSOR_NUMBER ProcessorNumber;
        SYSTEM_THREAD_INFORMATION SystemThread;
    } Out;
    ULONG Size;

    RtlZeroMemory(&Out, sizeof(Out));

    switch (ThreadInformationClass)
    {
        case ThreadIoPriority:
            Size = sizeof(ULONG);
            break;
        case ThreadPagePriority:
            Size = sizeof(ULONG);
            break;
        case ThreadActualBasePriority:
        case ThreadSuspendCount:
        case ThreadHeterogeneousCpuPolicy:
        case ThreadDynamicCodePolicyInfo:
        case ThreadExplicitCaseSensitivity:
        case ThreadSubsystemInformation:
            Size = sizeof(ULONG);
            break;
        case ThreadCpuAccountingInformation:
            Access = THREAD_QUERY_INFORMATION;
            Size = sizeof(ULONG);
            break;
        case ThreadGroupInformation:
        case ThreadActualGroupAffinity:
            Size = sizeof(GROUP_AFFINITY);
            break;
        case ThreadIdealProcessorEx:
            Size = sizeof(PROCESSOR_NUMBER);
            break;
        case ThreadContainerId:
            Size = sizeof(GUID);
            break;
        case ThreadSystemThreadInformation:
            Size = sizeof(SYSTEM_THREAD_INFORMATION);
            break;
        case ThreadSelectedCpuSets:
            /* No CPU sets are ever selected: zero-length list */
            Size = 0;
            break;
        default:
            return STATUS_INVALID_INFO_CLASS;
    }

    *Length = Size;
    if ((ThreadInformationClass != ThreadSelectedCpuSets) &&
        (ThreadInformationLength != Size))
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    Status = ObReferenceObjectByHandle(ThreadHandle,
                                       Access,
                                       PsThreadType,
                                       PreviousMode,
                                       (PVOID*)&Thread,
                                       NULL);
    if (!NT_SUCCESS(Status))
        return Status;

    switch (ThreadInformationClass)
    {
        case ThreadIoPriority:
            /* I/O priorities are not tracked: every thread is Normal */
            Out.Ulong = IoPriorityNormal;
            break;
        case ThreadPagePriority:
            /* Page priorities are not tracked: MEMORY_PRIORITY_NORMAL */
            Out.Ulong = 5;
            break;
        case ThreadActualBasePriority:
            Out.Ulong = (ULONG)Thread->Tcb.BasePriority;
            break;
        case ThreadSuspendCount:
            Out.Ulong = (ULONG)Thread->Tcb.SuspendCount;
            break;
        case ThreadGroupInformation:
        case ThreadActualGroupAffinity:
            /* Only processor group 0 exists */
            Out.GroupAffinity.Mask = Thread->Tcb.Affinity;
            Out.GroupAffinity.Group = 0;
            break;
        case ThreadIdealProcessorEx:
            Out.ProcessorNumber.Group = 0;
            Out.ProcessorNumber.Number = (UCHAR)Thread->Tcb.IdealProcessor;
            break;
        case ThreadSystemThreadInformation:
            Out.SystemThread.KernelTime.QuadPart = UInt32x32To64(Thread->Tcb.KernelTime, KeMaximumIncrement);
            Out.SystemThread.UserTime.QuadPart = UInt32x32To64(Thread->Tcb.UserTime, KeMaximumIncrement);
            Out.SystemThread.CreateTime = Thread->CreateTime;
            Out.SystemThread.WaitTime = Thread->Tcb.WaitTime;
            Out.SystemThread.StartAddress = (PVOID)Thread->StartAddress;
            Out.SystemThread.ClientId = Thread->Cid;
            Out.SystemThread.Priority = Thread->Tcb.Priority;
            Out.SystemThread.BasePriority = Thread->Tcb.BasePriority;
            Out.SystemThread.ContextSwitches = Thread->Tcb.ContextSwitches;
            Out.SystemThread.ThreadState = Thread->Tcb.State;
            Out.SystemThread.WaitReason = Thread->Tcb.WaitReason;
            break;
        default:
            /* CpuAccounting, HeterogeneousCpuPolicy, ContainerId, CpuSets,
             * DynamicCodePolicy, ExplicitCaseSensitivity: all zero. Win32
             * subsystem (0) for SubsystemInformation. */
            break;
    }

    ObDereferenceObject(Thread);

    if (Size != 0)
    {
        _SEH2_TRY
        {
            RtlCopyMemory(ThreadInformation, &Out, Size);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = _SEH2_GetExceptionCode();
        }
        _SEH2_END;
    }

    return Status;
}

/**
 * @brief
 * Sets one of the Vista+ thread information classes. Buffer size and
 * alignment were already validated against PsThreadInfoClass by the caller.
 * The buffer is always touched first so that an invalid address reports
 * STATUS_ACCESS_VIOLATION before any class-specific status.
 **/
static
NTSTATUS
PspSetThreadInfoVista(
    _In_ HANDLE ThreadHandle,
    _In_ ULONG ThreadInformationClass,
    _In_ PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength,
    _In_ KPROCESSOR_MODE PreviousMode)
{
    PETHREAD Thread;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG Value = 0;
    PROCESSOR_NUMBER ProcNumber = {0};

    /* Variable-length list of ULONG CPU set IDs */
    if ((ThreadInformationClass == ThreadSelectedCpuSets) &&
        ((ThreadInformationLength % sizeof(ULONG)) != 0))
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    /* Capture (and thereby validate) the input */
    _SEH2_TRY
    {
        if (ThreadInformationClass == ThreadIdealProcessorEx)
            ProcNumber = *(volatile PROCESSOR_NUMBER*)ThreadInformation;
        else if (ThreadInformationLength >= sizeof(ULONG))
            Value = *(volatile ULONG*)ThreadInformation;
        else if (ThreadInformationLength != 0)
            Value = *(volatile UCHAR*)ThreadInformation;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        return _SEH2_GetExceptionCode();
    }
    _SEH2_END;

    switch (ThreadInformationClass)
    {
        case ThreadIoPriority:
        case ThreadPagePriority:
        {
            /* Valid ranges: IoPriorityVeryLow..IoPriorityCritical (0..4),
             * page priority 0..7. The value is validated and accepted, but
             * not stored: neither priority is honoured by the I/O or memory
             * managers. */
            if (Value > ((ThreadInformationClass == ThreadIoPriority) ? 4 : 7))
                return STATUS_INVALID_PARAMETER;

            Status = ObReferenceObjectByHandle(ThreadHandle,
                                               THREAD_SET_INFORMATION,
                                               PsThreadType,
                                               PreviousMode,
                                               (PVOID*)&Thread,
                                               NULL);
            if (NT_SUCCESS(Status))
                ObDereferenceObject(Thread);
            return Status;
        }

        case ThreadIdealProcessorEx:
        {
            /* Only processor group 0 exists */
            if ((ProcNumber.Group != 0) || (ProcNumber.Number > MAXIMUM_PROCESSORS))
                return STATUS_INVALID_PARAMETER;

            Status = ObReferenceObjectByHandle(ThreadHandle,
                                               THREAD_SET_INFORMATION,
                                               PsThreadType,
                                               PreviousMode,
                                               (PVOID*)&Thread,
                                               NULL);
            if (!NT_SUCCESS(Status))
                return Status;

            Status = KeSetIdealProcessorThread(&Thread->Tcb, (CCHAR)ProcNumber.Number);
            if (Thread->Tcb.Teb && ExAcquireRundownProtection(&Thread->RundownProtect))
            {
                Thread->Tcb.Teb->IdealProcessor = Thread->Tcb.IdealProcessor;
                ExReleaseRundownProtection(&Thread->RundownProtect);
            }
            ObDereferenceObject(Thread);
            return Status;
        }

        case ThreadCSwitchPmu:
            /* Not a Win10 class */
            return STATUS_INVALID_INFO_CLASS;

        default:
            /* Known to the table (so that probing works) but not implemented */
            return STATUS_NOT_IMPLEMENTED;
    }
}

/* PUBLIC FUNCTIONS **********************************************************/

/*
 * @implemented
 */
/*
 * Snapshot of a process handle table into a caller-sized ULONG[] buffer, used
 * to implement the ProcessHandleTable (58) query.
 */
typedef struct _PSP_HANDLE_SNAP
{
    PULONG Buffer;
    ULONG Capacity;
    ULONG Count;
} PSP_HANDLE_SNAP, *PPSP_HANDLE_SNAP;

static
BOOLEAN
NTAPI
PspHandleSnapCallback(
    _In_ PHANDLE_TABLE_ENTRY HandleTableEntry,
    _In_ HANDLE Handle,
    _In_ PVOID Context)
{
    PPSP_HANDLE_SNAP Snap = (PPSP_HANDLE_SNAP)Context;

    UNREFERENCED_PARAMETER(HandleTableEntry);

    /* Record the handle value while there is room; keep counting regardless so
     * the caller can be told the full size it needs. */
    if (Snap->Count < Snap->Capacity)
        Snap->Buffer[Snap->Count] = HandleToUlong(Handle);
    Snap->Count++;

    /* FALSE: keep walking every entry. */
    return FALSE;
}

/*
 * ProcessCommandLineInformation (60, Windows 8.1+): the command line of the
 * target as its loader sees it, PEB->ProcessParameters->CommandLine, read in
 * the target's address space. The result is a UNICODE_STRING whose Buffer
 * points just behind it, followed by the characters and a terminating NUL
 * (MaximumLength = Length + 2). A short buffer fails with
 * STATUS_INFO_LENGTH_MISMATCH and the needed size as the return length.
 * Measured on Windows 10 22H2: PROCESS_QUERY_LIMITED_INFORMATION is enough
 * (also for protected processes), a process without a PEB (System, Registry)
 * is STATUS_NOT_FOUND, a terminated one STATUS_PROCESS_IS_TERMINATING, and a
 * WoW64 process reports the command line of its native PEB.
 */
static
NTSTATUS
PspQueryProcessCommandLine(
    _In_ HANDLE ProcessHandle,
    _In_ KPROCESSOR_MODE PreviousMode,
    _Out_writes_bytes_opt_(BufferLength) PVOID Buffer,
    _In_ ULONG BufferLength,
    _Out_ PULONG RequiredLength)
{
    PEPROCESS Process;
    PPEB Peb;
    PRTL_USER_PROCESS_PARAMETERS Params;
    UNICODE_STRING CommandLine = {0};
    ULONG ParamsFlags = 0, ParamsMaximum = 0;
    PWCHAR Copy = NULL;
    KAPC_STATE ApcState;
    BOOLEAN Attached = FALSE;
    ULONG Needed;
    NTSTATUS Status;

    PAGED_CODE();

    *RequiredLength = 0;

    Status = ObReferenceObjectByHandle(ProcessHandle,
                                       PROCESS_QUERY_LIMITED_INFORMATION,
                                       PsProcessType,
                                       PreviousMode,
                                       (PVOID*)&Process,
                                       NULL);
    if (!NT_SUCCESS(Status)) return Status;

    /* Keep the address space alive while it is read */
    if (!ExAcquireRundownProtection(&Process->RundownProtect))
    {
        ObDereferenceObject(Process);
        return STATUS_PROCESS_IS_TERMINATING;
    }

    /* System, Idle and minimal processes have no PEB */
    Peb = Process->Peb;
    if (Peb == NULL)
    {
        Status = STATUS_NOT_FOUND;
        goto Quit;
    }

    if (PsGetCurrentProcess() != Process)
    {
        KeStackAttachProcess(&Process->Pcb, &ApcState);
        Attached = TRUE;
    }

    /* The target's user mode owns every byte read here: probe each pointer
     * (a kernel address is refused) and read under SEH */
    _SEH2_TRY
    {
        ProbeForRead(Peb, sizeof(*Peb), sizeof(PVOID));
        Params = Peb->ProcessParameters;
        if (Params == NULL)
        {
            Status = STATUS_NOT_FOUND;
        }
        else
        {
            ProbeForRead(Params, sizeof(*Params), sizeof(PVOID));
            CommandLine = Params->CommandLine;
            ParamsFlags = Params->Flags;
            ParamsMaximum = Params->MaximumLength;
            Status = STATUS_SUCCESS;
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = STATUS_NOT_FOUND;
    }
    _SEH2_END;

    if (NT_SUCCESS(Status))
    {
        /* Bounded by the USHORT length; whole characters only */
        CommandLine.Length &= ~(USHORT)(sizeof(WCHAR) - 1);
        if (CommandLine.Length > MAXUSHORT - sizeof(WCHAR))
            CommandLine.Length = MAXUSHORT - sizeof(WCHAR) - 1;
        if (!(ParamsFlags & RTL_USER_PROCESS_PARAMETERS_NORMALIZED))
        {
            /* A process that has not started yet still holds the block as its
             * creator built it: the string is an offset into the block */
            ULONG_PTR Offset = (ULONG_PTR)CommandLine.Buffer;

            if ((Offset > ParamsMaximum) ||
                (CommandLine.Length > ParamsMaximum - Offset))
            {
                Status = STATUS_NOT_FOUND;
            }
            else
            {
                CommandLine.Buffer = (PWSTR)((PUCHAR)Params + Offset);
            }
        }
        else if ((CommandLine.Length != 0) && (CommandLine.Buffer == NULL))
        {
            Status = STATUS_NOT_FOUND;
        }
    }

    if (NT_SUCCESS(Status))
    {
        Copy = ExAllocatePoolWithTag(PagedPool,
                                     CommandLine.Length + sizeof(WCHAR),
                                     TAG_PS_COMMANDLINE);
        if (Copy == NULL)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
        }
        else
        {
            _SEH2_TRY
            {
                if (CommandLine.Length != 0)
                {
                    ProbeForRead(CommandLine.Buffer, CommandLine.Length, sizeof(WCHAR));
                    RtlCopyMemory(Copy, CommandLine.Buffer, CommandLine.Length);
                }
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                Status = STATUS_NOT_FOUND;
            }
            _SEH2_END;
        }
    }

    if (Attached) KeUnstackDetachProcess(&ApcState);

    if (!NT_SUCCESS(Status)) goto Quit;

    /* Only the kernel copy, terminated, is handed to the caller */
    Copy[CommandLine.Length / sizeof(WCHAR)] = UNICODE_NULL;
    Needed = sizeof(UNICODE_STRING) + CommandLine.Length + sizeof(WCHAR);
    *RequiredLength = Needed;

    if (BufferLength < Needed)
    {
        Status = STATUS_INFO_LENGTH_MISMATCH;
        goto Quit;
    }

    _SEH2_TRY
    {
        PUNICODE_STRING Out = (PUNICODE_STRING)Buffer;

        if (PreviousMode != KernelMode)
            ProbeForWrite(Buffer, Needed, sizeof(ULONG));

        RtlCopyMemory(Out + 1, Copy, CommandLine.Length + sizeof(WCHAR));
        Out->Length = CommandLine.Length;
        Out->MaximumLength = CommandLine.Length + sizeof(WCHAR);
        Out->Buffer = (PWSTR)(Out + 1);
        Status = STATUS_SUCCESS;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;

Quit:
    if (Copy) ExFreePoolWithTag(Copy, TAG_PS_COMMANDLINE);
    ExReleaseRundownProtection(&Process->RundownProtect);
    ObDereferenceObject(Process);
    return Status;
}

NTSTATUS
NTAPI
NtQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_to_opt_(ProcessInformationLength, *ReturnLength)
        PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength)
{
    PEPROCESS Process;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    NTSTATUS Status;
    ULONG Length = 0;

    PAGED_CODE();

    /* ProcessTlsInformation has no query below Vista: a 5.2 identity must
     * behave like Windows Server 2003, where the class does not exist */
    if ((ProcessInformationClass == ProcessTlsInformation) &&
        (NtMajorVersion < 6))
    {
        return STATUS_INVALID_INFO_CLASS;
    }

    /* ProcessProtectionInformation (61), Windows 8.1 and later (this system presents Windows 10): one
     * PS_PROTECTION byte, PROCESS_QUERY_LIMITED_INFORMATION */
    if ((ULONG)ProcessInformationClass == 61)
    {
        UCHAR Protection;

        if (ProcessInformationLength != sizeof(UCHAR)) return STATUS_INFO_LENGTH_MISMATCH;
        Status = ObReferenceObjectByHandle(ProcessHandle,
                                           PROCESS_QUERY_LIMITED_INFORMATION,
                                           PsProcessType,
                                           PreviousMode,
                                           (PVOID*)&Process,
                                           NULL);
        if (!NT_SUCCESS(Status)) return Status;
        Protection = Process->Protection;
        ObDereferenceObject(Process);

        _SEH2_TRY
        {
            if (PreviousMode != KernelMode)
            {
                ProbeForWrite(ProcessInformation, sizeof(UCHAR), sizeof(UCHAR));
                if (ReturnLength) ProbeForWriteUlong(ReturnLength);
            }
            *(PUCHAR)ProcessInformation = Protection;
            if (ReturnLength) *ReturnLength = sizeof(UCHAR);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = _SEH2_GetExceptionCode();
        }
        _SEH2_END;
        return Status;
    }

    /* Validate the information class */
    Status = DefaultQueryInfoBufferCheck(ProcessInformationClass,
                                         PsProcessInfoClass,
                                         RTL_NUMBER_OF(PsProcessInfoClass),
                                         ICIF_PROBE_READ,
                                         ProcessInformation,
                                         ProcessInformationLength,
                                         ReturnLength,
                                         NULL,
                                         PreviousMode);
    if (!NT_SUCCESS(Status))
    {
#if DBG
        DPRINT1("NtQueryInformationProcess(ProcessInformationClass: %s): Class validation failed! (Status: 0x%lx)\n",
                PspDumpProcessInfoClassName(ProcessInformationClass), Status);
#endif
        return Status;
    }

    if ((ProcessInformationClass == ProcessCookie) &&
        (ProcessHandle != NtCurrentProcess()))
    {
        /*
         * Retrieving the process cookie is only allowed for the calling process
         * itself! XP only allows NtCurrentProcess() as process handles even if
         * a real handle actually represents the current process.
         */
        return STATUS_INVALID_PARAMETER;
    }

    /* Check the information class */
    switch (ProcessInformationClass)
    {
        /* Basic process information */
        case ProcessBasicInformation:
        {
            PPROCESS_BASIC_INFORMATION ProcessBasicInfo = (PPROCESS_BASIC_INFORMATION)ProcessInformation;

            if (ProcessInformationLength != sizeof(PROCESS_BASIC_INFORMATION))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Set the return length */
            Length = sizeof(PROCESS_BASIC_INFORMATION);

            /* Reference the process */
            Status = ObReferenceObjectByHandle(ProcessHandle,
                                               PROCESS_QUERY_LIMITED_INFORMATION,
                                               PsProcessType,
                                               PreviousMode,
                                               (PVOID*)&Process,
                                               NULL);
            if (!NT_SUCCESS(Status)) break;

            /* Protect writes with SEH */
            _SEH2_TRY
            {
                /* Write all the information from the EPROCESS/KPROCESS */
                ProcessBasicInfo->ExitStatus = Process->ExitStatus;
                ProcessBasicInfo->PebBaseAddress = Process->Peb;
                ProcessBasicInfo->AffinityMask = Process->Pcb.Affinity;
                ProcessBasicInfo->UniqueProcessId = (ULONG_PTR)Process->
                                                    UniqueProcessId;
                ProcessBasicInfo->InheritedFromUniqueProcessId =
                    (ULONG_PTR)Process->InheritedFromUniqueProcessId;
                ProcessBasicInfo->BasePriority = Process->Pcb.BasePriority;

            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get exception code */
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;

            /* Dereference the process */
            ObDereferenceObject(Process);
            break;
        }

        /* Process quota limits */
        case ProcessQuotaLimits:
        {
            QUOTA_LIMITS_EX QuotaLimits;
            BOOLEAN Extended;

            if (ProcessInformationLength != sizeof(QUOTA_LIMITS) &&
                ProcessInformationLength != sizeof(QUOTA_LIMITS_EX))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Set the return length */
            Length = ProcessInformationLength;
            Extended = (Length == sizeof(QUOTA_LIMITS_EX));

            /* Reference the process */
            Status = ObReferenceObjectByHandle(ProcessHandle,
                                               PROCESS_QUERY_LIMITED_INFORMATION,
                                               PsProcessType,
                                               PreviousMode,
                                               (PVOID*)&Process,
                                               NULL);
            if (!NT_SUCCESS(Status)) break;

            /* Indicate success */
            Status = STATUS_SUCCESS;

            RtlZeroMemory(&QuotaLimits, sizeof(QuotaLimits));

            /* Get max/min working set sizes */
            QuotaLimits.MaximumWorkingSetSize =
                (SIZE_T)Process->Vm.MaximumWorkingSetSize << PAGE_SHIFT;
            QuotaLimits.MinimumWorkingSetSize =
                (SIZE_T)Process->Vm.MinimumWorkingSetSize << PAGE_SHIFT;

            /* Get default time limits */
            QuotaLimits.TimeLimit.QuadPart = -1LL;

            /* Is quota block a default one? */
            if (Process->QuotaBlock == &PspDefaultQuotaBlock)
            {
                /* Get default pools and pagefile limits */
                QuotaLimits.PagedPoolLimit = (SIZE_T)-1;
                QuotaLimits.NonPagedPoolLimit = (SIZE_T)-1;
                QuotaLimits.PagefileLimit = (SIZE_T)-1;
            }
            else
            {
                /* Get limits from non-default quota block */
                QuotaLimits.PagedPoolLimit =
                    Process->QuotaBlock->QuotaEntry[PsPagedPool].Limit;
                QuotaLimits.NonPagedPoolLimit =
                    Process->QuotaBlock->QuotaEntry[PsNonPagedPool].Limit;
                QuotaLimits.PagefileLimit =
                    Process->QuotaBlock->QuotaEntry[PsPageFile].Limit;
            }

            /* Get additional information, if needed */
            if (Extended)
            {
                QuotaLimits.Flags |= (Process->Vm.Flags.MaximumWorkingSetHard ?
                    QUOTA_LIMITS_HARDWS_MAX_ENABLE : QUOTA_LIMITS_HARDWS_MAX_DISABLE);
                QuotaLimits.Flags |= (Process->Vm.Flags.MinimumWorkingSetHard ?
                    QUOTA_LIMITS_HARDWS_MIN_ENABLE : QUOTA_LIMITS_HARDWS_MIN_DISABLE);

                /* FIXME: Get the correct information */
                //QuotaLimits.WorkingSetLimit = (SIZE_T)-1; // Not used on Win2k3, it is set to 0
                QuotaLimits.CpuRateLimit.RateData = 0;
            }

            /* Protect writes with SEH */
            _SEH2_TRY
            {
                RtlCopyMemory(ProcessInformation, &QuotaLimits, Length);
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get exception code */
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;

            /* Dereference the process */
            ObDereferenceObject(Process);
            break;
        }

        case ProcessIoCounters:
        {
            PIO_COUNTERS IoCounters = (PIO_COUNTERS)ProcessInformation;
            PROCESS_VALUES ProcessValues;

            if (ProcessInformationLength != sizeof(IO_COUNTERS))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            Length = sizeof(IO_COUNTERS);

            /* Reference the process */
            Status = ObReferenceObjectByHandle(ProcessHandle,
                                               PROCESS_QUERY_LIMITED_INFORMATION,
                                               PsProcessType,
                                               PreviousMode,
                                               (PVOID*)&Process,
                                               NULL);
            if (!NT_SUCCESS(Status)) break;

            /* Query IO counters from the process */
            KeQueryValuesProcess(&Process->Pcb, &ProcessValues);

            _SEH2_TRY
            {
                RtlCopyMemory(IoCounters, &ProcessValues.IoInfo, sizeof(IO_COUNTERS));
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Ignore exception */
            }
            _SEH2_END;

            /* Set status to success in any case */
            Status = STATUS_SUCCESS;

            /* Dereference the process */
            ObDereferenceObject(Process);
            break;
        }

        /* Timing */
        case ProcessTimes:
        {
            PKERNEL_USER_TIMES ProcessTime = (PKERNEL_USER_TIMES)ProcessInformation;
            ULONG UserTime, KernelTime;

            /* Set the return length */
            if (ProcessInformationLength != sizeof(KERNEL_USER_TIMES))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            Length = sizeof(KERNEL_USER_TIMES);

            /* Reference the process */
            Status = ObReferenceObjectByHandle(ProcessHandle,
                                               PROCESS_QUERY_LIMITED_INFORMATION,
                                               PsProcessType,
                                               PreviousMode,
                                               (PVOID*)&Process,
                                               NULL);
            if (!NT_SUCCESS(Status)) break;

            /* Protect writes with SEH */
            _SEH2_TRY
            {
                /* Copy time information from EPROCESS/KPROCESS */
                KernelTime = KeQueryRuntimeProcess(&Process->Pcb, &UserTime);
                ProcessTime->CreateTime = Process->CreateTime;
                ProcessTime->UserTime.QuadPart = (LONGLONG)UserTime * KeMaximumIncrement;
                ProcessTime->KernelTime.QuadPart = (LONGLONG)KernelTime * KeMaximumIncrement;
                ProcessTime->ExitTime = Process->ExitTime;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get exception code */
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;

            /* Dereference the process */
            ObDereferenceObject(Process);
            break;
        }

        /* Process Debug Port */
        case ProcessDebugPort:

            if (ProcessInformationLength != sizeof(HANDLE))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Set the return length */
            Length = sizeof(HANDLE);

            /* Reference the process */
            Status = ObReferenceObjectByHandle(ProcessHandle,
                                               PROCESS_QUERY_INFORMATION,
                                               PsProcessType,
                                               PreviousMode,
                                               (PVOID*)&Process,
                                               NULL);
            if (!NT_SUCCESS(Status)) break;

            /* Protect write with SEH */
            _SEH2_TRY
            {
                /* Return whether or not we have a debug port */
                *(PHANDLE)ProcessInformation = (Process->DebugPort ?
                                                (HANDLE)-1 : NULL);
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get exception code */
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;

            /* Dereference the process */
            ObDereferenceObject(Process);
            break;

        case ProcessHandleCount:
        {
            ULONG HandleCount;

            if (ProcessInformationLength != sizeof(ULONG))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Set the return length*/
            Length = sizeof(ULONG);

            /* Reference the process */
            Status = ObReferenceObjectByHandle(ProcessHandle,
                                               PROCESS_QUERY_LIMITED_INFORMATION,
                                               PsProcessType,
                                               PreviousMode,
                                               (PVOID*)&Process,
                                               NULL);
            if (!NT_SUCCESS(Status)) break;

            /* Count the number of handles this process has */
            HandleCount = ObGetProcessHandleCount(Process);

            /* Protect write in SEH */
            _SEH2_TRY
            {
                /* Return the count of handles */
                *(PULONG)ProcessInformation = HandleCount;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get the exception code */
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;

            /* Dereference the process */
            ObDereferenceObject(Process);
            break;
        }

        /* Session ID for the process */
        case ProcessSessionInformation:
        {
            PPROCESS_SESSION_INFORMATION SessionInfo = (PPROCESS_SESSION_INFORMATION)ProcessInformation;

            if (ProcessInformationLength != sizeof(PROCESS_SESSION_INFORMATION))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Set the return length*/
            Length = sizeof(PROCESS_SESSION_INFORMATION);

            /* Reference the process */
            Status = ObReferenceObjectByHandle(ProcessHandle,
                                               PROCESS_QUERY_LIMITED_INFORMATION,
                                               PsProcessType,
                                               PreviousMode,
                                               (PVOID*)&Process,
                                               NULL);
            if (!NT_SUCCESS(Status)) break;

            /* Enter SEH for write safety */
            _SEH2_TRY
            {
                /* Write back the Session ID */
                SessionInfo->SessionId = PsGetProcessSessionId(Process);
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get the exception code */
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;

            /* Dereference the process */
            ObDereferenceObject(Process);
            break;
        }

        /* Virtual Memory Statistics */
        case ProcessVmCounters:
        {
            PVM_COUNTERS VmCounters = (PVM_COUNTERS)ProcessInformation;
            SIZE_T CommitCharge;

            /* Validate the input length */
            if ((ProcessInformationLength != sizeof(VM_COUNTERS)) &&
                (ProcessInformationLength != sizeof(VM_COUNTERS_EX)))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Reference the process */
            Status = ObReferenceObjectByHandle(ProcessHandle,
                                               PROCESS_QUERY_LIMITED_INFORMATION,
                                               PsProcessType,
                                               PreviousMode,
                                               (PVOID*)&Process,
                                               NULL);
            if (!NT_SUCCESS(Status)) break;

            /* Enter SEH for write safety */
            _SEH2_TRY
            {
                /* Return data from EPROCESS */
                VmCounters->PeakVirtualSize = Process->PeakVirtualSize;
                VmCounters->VirtualSize = Process->VirtualSize;
                VmCounters->PageFaultCount = Process->Vm.PageFaultCount;
                VmCounters->PeakWorkingSetSize = Process->Vm.PeakWorkingSetSize;
                VmCounters->WorkingSetSize = Process->Vm.WorkingSetSize;
                VmCounters->QuotaPeakPagedPoolUsage = Process->QuotaPeak[PsPagedPool];
                VmCounters->QuotaPagedPoolUsage = Process->QuotaUsage[PsPagedPool];
                VmCounters->QuotaPeakNonPagedPoolUsage = Process->QuotaPeak[PsNonPagedPool];
                VmCounters->QuotaNonPagedPoolUsage = Process->QuotaUsage[PsNonPagedPool];
                /* The private commit charge, also returned as PrivateUsage in VM_COUNTERS_EX */
                CommitCharge = Process->CommitCharge;
                VmCounters->PagefileUsage = CommitCharge << PAGE_SHIFT;
                VmCounters->PeakPagefileUsage = Process->CommitChargePeak << PAGE_SHIFT;
                if (ProcessInformationLength == sizeof(VM_COUNTERS_EX))
                {
                    ((PVM_COUNTERS_EX)VmCounters)->PrivateUsage = CommitCharge << PAGE_SHIFT;
                }

                /* Set the return length */
                Length = ProcessInformationLength;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get the exception code */
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;

            /* Dereference the process */
            ObDereferenceObject(Process);
            break;
        }

        /* Hard Error Processing Mode */
        case ProcessDefaultHardErrorMode:

            if (ProcessInformationLength != sizeof(ULONG))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Set the return length*/
            Length = sizeof(ULONG);

            /* Reference the process */
            Status = ObReferenceObjectByHandle(ProcessHandle,
                                               PROCESS_QUERY_LIMITED_INFORMATION,
                                               PsProcessType,
                                               PreviousMode,
                                               (PVOID*)&Process,
                                               NULL);
            if (!NT_SUCCESS(Status)) break;

            /* Enter SEH for writing back data */
            _SEH2_TRY
            {
                /* Write the current processing mode */
                *(PULONG)ProcessInformation = Process->
                                              DefaultHardErrorProcessing;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get the exception code */
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;

            /* Dereference the process */
            ObDereferenceObject(Process);
            break;

        /* Priority Boosting status */
        case ProcessPriorityBoost:

            if (ProcessInformationLength != sizeof(ULONG))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Set the return length */
            Length = sizeof(ULONG);

            /* Reference the process */
            Status = ObReferenceObjectByHandle(ProcessHandle,
                                               PROCESS_QUERY_LIMITED_INFORMATION,
                                               PsProcessType,
                                               PreviousMode,
                                               (PVOID*)&Process,
                                               NULL);
            if (!NT_SUCCESS(Status)) break;

            /* Enter SEH for writing back data */
            _SEH2_TRY
            {
                /* Return boost status */
                *(PULONG)ProcessInformation = Process->Pcb.DisableBoost ?
                                              TRUE : FALSE;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get the exception code */
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;

            /* Dereference the process */
            ObDereferenceObject(Process);
            break;

        /* DOS Device Map */
        case ProcessDeviceMap:
        {
            ULONG Flags;

            if (ProcessInformationLength == sizeof(PROCESS_DEVICEMAP_INFORMATION_EX))
            {
                /* Protect read in SEH */
                _SEH2_TRY
                {
                    PPROCESS_DEVICEMAP_INFORMATION_EX DeviceMapEx = ProcessInformation;

                    Flags = DeviceMapEx->Flags;
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    /* Get the exception code */
                    Status = _SEH2_GetExceptionCode();
                    _SEH2_YIELD(break);
                }
                _SEH2_END;

                /* Only one flag is supported and it needs LUID mappings */
                if ((Flags & ~PROCESS_LUID_DOSDEVICES_ONLY) != 0 ||
                    !ObIsLUIDDeviceMapsEnabled())
                {
                    Status = STATUS_INVALID_PARAMETER;
                    break;
                }
            }
            else
            {
                /* This has to be the size of the Query union field for x64 compatibility! */
                if (ProcessInformationLength != RTL_FIELD_SIZE(PROCESS_DEVICEMAP_INFORMATION, Query))
                {
                    Status = STATUS_INFO_LENGTH_MISMATCH;
                    break;
                }

                /* No flags for standard call */
                Flags = 0;
            }

            /* Set the return length */
            Length = ProcessInformationLength;

            /* Reference the process */
            Status = ObReferenceObjectByHandle(ProcessHandle,
                                               PROCESS_QUERY_INFORMATION,
                                               PsProcessType,
                                               PreviousMode,
                                               (PVOID*)&Process,
                                               NULL);
            if (!NT_SUCCESS(Status)) break;

            /* Query the device map information */
            Status = ObQueryDeviceMapInformation(Process,
                                                 ProcessInformation,
                                                 Flags);

            /* Dereference the process */
            ObDereferenceObject(Process);
            break;
        }

        /* Priority class */
        case ProcessPriorityClass:
        {
            PPROCESS_PRIORITY_CLASS PsPriorityClass = (PPROCESS_PRIORITY_CLASS)ProcessInformation;

            if (ProcessInformationLength != sizeof(PROCESS_PRIORITY_CLASS))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Set the return length*/
            Length = sizeof(PROCESS_PRIORITY_CLASS);

            /* Reference the process */
            Status = ObReferenceObjectByHandle(ProcessHandle,
                                               PROCESS_QUERY_LIMITED_INFORMATION,
                                               PsProcessType,
                                               PreviousMode,
                                               (PVOID*)&Process,
                                               NULL);
            if (!NT_SUCCESS(Status)) break;

            /* Enter SEH for writing back data */
            _SEH2_TRY
            {
                /* Return current priority class */
                PsPriorityClass->PriorityClass = Process->PriorityClass;
                PsPriorityClass->Foreground = FALSE;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get the exception code */
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;

            /* Dereference the process */
            ObDereferenceObject(Process);
            break;
        }

        case ProcessImageFileName:
        {
            PUNICODE_STRING ImageName;

            /* Reference the process */
            Status = ObReferenceObjectByHandle(ProcessHandle,
                                               PROCESS_QUERY_LIMITED_INFORMATION,
                                               PsProcessType,
                                               PreviousMode,
                                               (PVOID*)&Process,
                                               NULL);
            if (!NT_SUCCESS(Status)) break;

            /* Get the image path */
            Status = SeLocateProcessImageName(Process, &ImageName);
            if (NT_SUCCESS(Status))
            {
                /* Set the return length */
                Length = ImageName->MaximumLength +
                         sizeof(OBJECT_NAME_INFORMATION);

                /* Make sure it's large enough */
                if (Length <= ProcessInformationLength)
                {
                    /* Enter SEH to protect write */
                    _SEH2_TRY
                    {
                        /* Copy it */
                        RtlCopyMemory(ProcessInformation,
                                      ImageName,
                                      Length);

                        /* Update pointer */
                        ((PUNICODE_STRING)ProcessInformation)->Buffer =
                            (PWSTR)((PUNICODE_STRING)ProcessInformation + 1);
                    }
                    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                    {
                        /* Get the exception code */
                        Status = _SEH2_GetExceptionCode();
                    }
                    _SEH2_END;
                }
                else
                {
                    /* Buffer too small */
                    Status = STATUS_INFO_LENGTH_MISMATCH;
                }

                /* Free the image path */
                ExFreePoolWithTag(ImageName, TAG_SEPA);
            }
            /* Dereference the process */
            ObDereferenceObject(Process);
            break;
        }

#if (NTDDI_VERSION >= NTDDI_VISTA) || (DLL_EXPORT_VERSION >= _WIN32_WINNT_VISTA)
        case ProcessImageFileNameWin32:
        {
            PFILE_OBJECT FileObject;
            POBJECT_NAME_INFORMATION ObjectNameInformation;

            /* Reference the process */
            Status = ObReferenceObjectByHandle(ProcessHandle,
                                               PROCESS_QUERY_LIMITED_INFORMATION,
                                               PsProcessType,
                                               PreviousMode,
                                               (PVOID*)&Process,
                                               NULL);
            if (!NT_SUCCESS(Status))
            {
                break;
            }

            /* Get the image path */
            Status = PsReferenceProcessFilePointer(Process, &FileObject);
            ObDereferenceObject(Process);
            if (!NT_SUCCESS(Status))
            {
                break;
            }
            Status = IoQueryFileDosDeviceName(FileObject, &ObjectNameInformation);
            ObDereferenceObject(FileObject);
            if (!NT_SUCCESS(Status))
            {
                break;
            }

            /* Determine return length and output */
            Length = sizeof(UNICODE_STRING) + ObjectNameInformation->Name.MaximumLength;
            if (Length <= ProcessInformationLength)
            {
                _SEH2_TRY
                {
                    PUNICODE_STRING ImageName = (PUNICODE_STRING)ProcessInformation;
                    ImageName->Length = ObjectNameInformation->Name.Length;
                    ImageName->MaximumLength = ObjectNameInformation->Name.MaximumLength;
                    if (ObjectNameInformation->Name.MaximumLength)
                    {
                        ImageName->Buffer = (PWSTR)(ImageName + 1);
                        RtlCopyMemory(ImageName->Buffer,
                                      ObjectNameInformation->Name.Buffer,
                                      ObjectNameInformation->Name.MaximumLength);
                    }
                    else
                    {
                        ASSERT(ImageName->Length == 0);
                        ImageName->Buffer = NULL;
                    }
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    Status = _SEH2_GetExceptionCode();
                }
                _SEH2_END;
            }
            else
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
            }
            ExFreePool(ObjectNameInformation);

            break;
        }
#endif /* (NTDDI_VERSION >= NTDDI_VISTA) || (DLL_EXPORT_VERSION >= _WIN32_WINNT_VISTA) */

        case ProcessDebugFlags:

            if (ProcessInformationLength != sizeof(ULONG))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Set the return length*/
            Length = sizeof(ULONG);

            /* Reference the process */
            Status = ObReferenceObjectByHandle(ProcessHandle,
                                               PROCESS_QUERY_INFORMATION,
                                               PsProcessType,
                                               PreviousMode,
                                               (PVOID*)&Process,
                                               NULL);
            if (!NT_SUCCESS(Status)) break;

            /* Enter SEH for writing back data */
            _SEH2_TRY
            {
                /* Return the debug flag state */
                *(PULONG)ProcessInformation = Process->NoDebugInherit ? 0 : 1;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get the exception code */
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;

            /* Dereference the process */
            ObDereferenceObject(Process);
            break;

        case ProcessBreakOnTermination:

            if (ProcessInformationLength != sizeof(ULONG))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Set the return length */
            Length = sizeof(ULONG);

            /* Reference the process */
            Status = ObReferenceObjectByHandle(ProcessHandle,
                                               PROCESS_QUERY_INFORMATION,
                                               PsProcessType,
                                               PreviousMode,
                                               (PVOID*)&Process,
                                               NULL);
            if (!NT_SUCCESS(Status)) break;

            /* Enter SEH for writing back data */
            _SEH2_TRY
            {
                /* Return the BreakOnTermination state */
                *(PULONG)ProcessInformation = Process->BreakOnTermination;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get the exception code */
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;

            /* Dereference the process */
            ObDereferenceObject(Process);
            break;

        /* Per-process security cookie */
        case ProcessCookie:
        {
            ULONG Cookie;

            if (ProcessInformationLength != sizeof(ULONG))
            {
                /* Length size wrong, bail out */
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Get the current process and cookie */
            Process = PsGetCurrentProcess();
            Cookie = Process->Cookie;
            if (!Cookie)
            {
                LARGE_INTEGER SystemTime;
                ULONG NewCookie;
                PKPRCB Prcb;

                /* Generate a new cookie */
                KeQuerySystemTime(&SystemTime);
                Prcb = KeGetCurrentPrcb();
                NewCookie = Prcb->KeSystemCalls ^ Prcb->InterruptTime ^
                            SystemTime.u.LowPart ^ SystemTime.u.HighPart;

                /* Set the new cookie or return the current one */
                Cookie = InterlockedCompareExchange((LONG*)&Process->Cookie,
                                                    NewCookie,
                                                    Cookie);
                if (!Cookie) Cookie = NewCookie;

                /* Set the return length */
                Length = sizeof(ULONG);
            }

            /* Indicate success */
            Status = STATUS_SUCCESS;

            /* Enter SEH to protect write */
            _SEH2_TRY
            {
                /* Write back the cookie */
                *(PULONG)ProcessInformation = Cookie;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get the exception code */
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;
            break;
        }

        case ProcessImageInformation:
        {
            SECTION_IMAGE_INFORMATION ImageInformation;

            if (ProcessInformationLength != sizeof(SECTION_IMAGE_INFORMATION))
            {
                /* Break out */
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Set the length required and validate it */
            Length = sizeof(SECTION_IMAGE_INFORMATION);

            /* Other processes can be queried too (NT6+); check for the current one */
            if (ProcessHandle == NtCurrentProcess())
            {
                Process = PsGetCurrentProcess();
                ObReferenceObject(Process);
            }
            else
            {
                Status = ObReferenceObjectByHandle(ProcessHandle,
                                                   PROCESS_QUERY_INFORMATION,
                                                   PsProcessType,
                                                   PreviousMode,
                                                   (PVOID*)&Process,
                                                   NULL);
                if (!NT_SUCCESS(Status)) break;
            }

            /* Get the image information into a local, then copy it out under SEH */
            Status = MmGetProcessImageInformation(Process, &ImageInformation);
            ObDereferenceObject(Process);
            if (!NT_SUCCESS(Status)) break;

            _SEH2_TRY
            {
                *(PSECTION_IMAGE_INFORMATION)ProcessInformation = ImageInformation;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get the exception code */
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;
            break;
        }

        case ProcessCycleTime:
        {
            PPROCESS_CYCLE_TIME_INFORMATION CycleTimeInfo = ProcessInformation;
            ULONG64 CycleTime, CycleTimeStamp;

            if (ProcessInformationLength != sizeof(PROCESS_CYCLE_TIME_INFORMATION))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Set the return length */
            Length = sizeof(PROCESS_CYCLE_TIME_INFORMATION);

            /* Reference the process */
            Status = ObReferenceObjectByHandle(ProcessHandle,
                                               PROCESS_QUERY_LIMITED_INFORMATION,
                                               PsProcessType,
                                               PreviousMode,
                                               (PVOID*)&Process,
                                               NULL);
            if (!NT_SUCCESS(Status)) break;

            CycleTime = KeQueryTotalCycleTimeProcess(&Process->Pcb, &CycleTimeStamp);

            /* Dereference the process */
            ObDereferenceObject(Process);

            /* Protect writes with SEH */
            _SEH2_TRY
            {
                CycleTimeInfo->AccumulatedCycles = CycleTime;
                CycleTimeInfo->CurrentCycleCount = CycleTimeStamp;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get exception code */
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;
            break;
        }

        case ProcessDebugObjectHandle:
        {
            HANDLE DebugPort = NULL;

            if (ProcessInformationLength != sizeof(HANDLE))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Set the return length */
            Length = sizeof(HANDLE);

            /* Reference the process */
            Status = ObReferenceObjectByHandle(ProcessHandle,
                                               PROCESS_QUERY_INFORMATION,
                                               PsProcessType,
                                               PreviousMode,
                                               (PVOID*)&Process,
                                               NULL);
            if (!NT_SUCCESS(Status)) break;

            /* Get the debug port. Continue even if this fails. */
            Status = DbgkOpenProcessDebugPort(Process, PreviousMode, &DebugPort);

            /* Let go of the process */
            ObDereferenceObject(Process);

            /* Protect write in SEH */
            _SEH2_TRY
            {
                /* Return debug port's handle */
                *(PHANDLE)ProcessInformation = DebugPort;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                if (DebugPort)
                    ObCloseHandle(DebugPort, PreviousMode);

                /* Get the exception code.
                 * Note: This overwrites any previous failure status. */
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;
            break;
        }

        case ProcessHandleTracing:
            DPRINT1("Handle tracing not implemented: %lu\n", ProcessInformationClass);
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case ProcessLUIDDeviceMapsEnabled:

            if (ProcessInformationLength != sizeof(ULONG))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Set the return length */
            Length = sizeof(ULONG);

            /* Indicate success */
            Status = STATUS_SUCCESS;

            /* Protect write in SEH */
            _SEH2_TRY
            {
                /* Query Ob */
                *(PULONG)ProcessInformation = ObIsLUIDDeviceMapsEnabled();
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get the exception code */
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;
            break;

        case ProcessWx86Information:

            if (ProcessInformationLength != sizeof(ULONG))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Set the return length */
            Length = sizeof(ULONG);

            /* Reference the process */
            Status = ObReferenceObjectByHandle(ProcessHandle,
                                               PROCESS_QUERY_INFORMATION,
                                               PsProcessType,
                                               PreviousMode,
                                               (PVOID*)&Process,
                                               NULL);
            if (!NT_SUCCESS(Status)) break;

            /* Protect write in SEH */
            _SEH2_TRY
            {
                /* Return if the flag is set */
                *(PULONG)ProcessInformation = (ULONG)Process->VdmAllowed;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get the exception code */
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;

            /* Dereference the process */
            ObDereferenceObject(Process);
            break;

        case ProcessWow64Information:
        {
            ULONG_PTR Wow64 = 0;

            if (ProcessInformationLength != sizeof(ULONG_PTR))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Set the return length */
            Length = sizeof(ULONG_PTR);

            /* Reference the process */
            Status = ObReferenceObjectByHandle(ProcessHandle,
                                               PROCESS_QUERY_LIMITED_INFORMATION,
                                               PsProcessType,
                                               PreviousMode,
                                               (PVOID*)&Process,
                                               NULL);
            if (!NT_SUCCESS(Status)) break;

#if defined(_WIN64) && defined(BUILD_WOW64_ENABLED)
            /* Make sure the process isn't dying */
            if (ExAcquireRundownProtection(&Process->RundownProtect))
            {
                /* Process creation owns allocation; a query never changes state. */
                if (Process->Wow64Process)
                    Wow64 = (ULONG_PTR)Process->Wow64Process->Peb;

                /* Release the lock */
                ExReleaseRundownProtection(&Process->RundownProtect);
            }
#endif

            /* Dereference the process */
            ObDereferenceObject(Process);

            /* Protect write with SEH */
            _SEH2_TRY
            {
                /* Return the Wow64 process information */
                *(PULONG_PTR)ProcessInformation = Wow64;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get exception code */
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;
            break;
        }

        /* Mitigation policy: only the system call disable policy (Win32k lockdown) is kept here */
        case ProcessMitigationPolicy:
        {
            PS_MITIGATION_POLICY_REQUEST Request;

            /* Set the return length */
            Length = sizeof(Request);

            _SEH2_TRY
            {
                Request = *(PPS_MITIGATION_POLICY_REQUEST)ProcessInformation;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                Status = _SEH2_GetExceptionCode();
                _SEH2_YIELD(break);
            }
            _SEH2_END;

            if (Request.Policy != PS_MITIGATION_SYSTEM_CALL_DISABLE)
            {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            Status = ObReferenceObjectByHandle(ProcessHandle,
                                               PROCESS_QUERY_LIMITED_INFORMATION,
                                               PsProcessType,
                                               PreviousMode,
                                               (PVOID*)&Process,
                                               NULL);
            if (!NT_SUCCESS(Status)) break;

            Request.Flags = (Process->Flags & PSF_DISALLOW_WIN32K_BIT) ? PS_MITIGATION_DISALLOW_WIN32K : 0;
            ObDereferenceObject(Process);

            _SEH2_TRY
            {
                *(PPS_MITIGATION_POLICY_REQUEST)ProcessInformation = Request;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;
            break;
        }

        case ProcessExecuteFlags:
        {
            ULONG ExecuteOptions = 0;

            if (ProcessInformationLength != sizeof(ULONG))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Set the return length */
            Length = sizeof(ULONG);

            if (ProcessHandle != NtCurrentProcess())
            {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            /* Get the options */
            Status = MmGetExecuteOptions(&ExecuteOptions);
            if (NT_SUCCESS(Status))
            {
                /* Protect write with SEH */
                _SEH2_TRY
                {
                    /* Return them */
                    *(PULONG)ProcessInformation = ExecuteOptions;
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    /* Get exception code */
                    Status = _SEH2_GetExceptionCode();
                }
                _SEH2_END;
            }
            break;
        }

        case ProcessLdtInformation:
            DPRINT1("VDM/16-bit not implemented: %lu\n", ProcessInformationClass);
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case ProcessWorkingSetWatch:
            DPRINT1("WS Watch not implemented: %lu\n", ProcessInformationClass);
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case ProcessPooledUsageAndLimits:
            DPRINT1("Pool limits not implemented: %lu\n", ProcessInformationClass);
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        /* ProcessHandleTable (Windows 8.1+): the process open handle values as a
         * ULONG[]. Chromium win32 lockdown queries this on itself right after it
         * lowers its token, to confirm no unexpected handle leaked into the
         * sandboxed process; on an NT 6.3+ identity a failed query is fatal and
         * the child self-terminates (observed exit 0x1b62). A process always has
         * implicit access to its own handle table, as on Windows. */
        case ProcessHandleTable:
        {
            PSP_HANDLE_SNAP Snap;
            PVOID ObjectTable;
            ULONG HandleCount;

            Status = ObReferenceObjectByHandle(ProcessHandle,
                                               PROCESS_QUERY_INFORMATION,
                                               PsProcessType,
                                               PreviousMode,
                                               (PVOID*)&Process,
                                               NULL);
            if (!NT_SUCCESS(Status)) break;

            /* Size the result by the current handle count. */
            HandleCount = ObGetProcessHandleCount(Process);
            Length = HandleCount * sizeof(ULONG);

            /* Sizing probe or a buffer too small: report the needed size. */
            if (ProcessInformationLength < Length)
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                ObDereferenceObject(Process);
                break;
            }

            /* No handles: nothing to copy. */
            if (HandleCount == 0)
            {
                Status = STATUS_SUCCESS;
                ObDereferenceObject(Process);
                break;
            }

            /* Collect the handle values into a kernel buffer first: the enum
             * callback runs in a critical region with a table entry locked, so
             * it must not touch user memory. */
            /* The count above is only a hint: other threads of the process
             * create handles while we enumerate, and the walk may see a few
             * entries more than the counter. Leave room for them (and never
             * promise more than the caller's buffer can hold), so that a
             * concurrent handle does not turn into a spurious failure. */
            Snap.Capacity = HandleCount + 1024;
            if (Snap.Capacity > ProcessInformationLength / sizeof(ULONG))
                Snap.Capacity = ProcessInformationLength / sizeof(ULONG);
            Snap.Buffer = ExAllocatePoolWithTag(PagedPool,
                                                Snap.Capacity * sizeof(ULONG),
                                                'tHsP');
            if (!Snap.Buffer)
            {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                ObDereferenceObject(Process);
                break;
            }
            Snap.Count = 0;

            ObjectTable = ObReferenceProcessHandleTable(Process);
            if (ObjectTable)
            {
                ExEnumHandleTable((PHANDLE_TABLE)ObjectTable,
                                  PspHandleSnapCallback,
                                  &Snap,
                                  NULL);
                ObDereferenceProcessHandleTable(Process);
            }

            if (Snap.Count > Snap.Capacity)
            {
                /* More handles than the caller's buffer holds: ask for more. */
                Length = Snap.Count * sizeof(ULONG);
                Status = STATUS_INFO_LENGTH_MISMATCH;
            }
            else
            {
                Length = Snap.Count * sizeof(ULONG);
                _SEH2_TRY
                {
                    RtlCopyMemory(ProcessInformation, Snap.Buffer, Length);
                    Status = STATUS_SUCCESS;
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    Status = _SEH2_GetExceptionCode();
                }
                _SEH2_END;
            }

            ExFreePoolWithTag(Snap.Buffer, 'tHsP');
            ObDereferenceObject(Process);
            break;
        }

        /* ProcessCommandLineInformation (Windows 8.1+): PEB command line of the target */
        case ProcessCommandLineInformation:
        {
            Status = PspQueryProcessCommandLine(ProcessHandle,
                                                PreviousMode,
                                                ProcessInformation,
                                                ProcessInformationLength,
                                                &Length);
            break;
        }

        /* Known to the table (Vista+) so that probing matches, but there is
         * nothing to query: TLS replacement is a set-only operation here */
        case ProcessTlsInformation:
            Status = STATUS_INVALID_INFO_CLASS;

            /* The caller's buffer is still validated first, as on NT6+ */
            if (PreviousMode != KernelMode)
            {
                _SEH2_TRY
                {
                    ProbeForWrite(ProcessInformation,
                                  ProcessInformationLength,
                                  sizeof(ULONG));
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    Status = _SEH2_GetExceptionCode();
                }
                _SEH2_END;
            }
            break;

        /* Not supported by Server 2003 */
        default:
#if DBG
            DPRINT1("Unsupported info class: %s\n", PspDumpProcessInfoClassName(ProcessInformationClass));
#endif
            Status = STATUS_INVALID_INFO_CLASS;
    }

    /* Check if caller wants the return length and if there is one */
    if (ReturnLength != NULL && Length != 0)
    {
        /* Protect write with SEH */
        _SEH2_TRY
        {
            *ReturnLength = Length;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Get exception code.
             * Note: This overwrites any previous failure status. */
            Status = _SEH2_GetExceptionCode();
        }
        _SEH2_END;
    }

    return Status;
}

#if defined(_WIN64) && defined(BUILD_WOW64_ENABLED)
/*
 * ProcessTlsInformation with PROCESS_TLS_WOW64, for one thread: the same
 * change on the 32-bit TLS vector in the thread's TEB32, whose entries and
 * length (the ULONG before it) are ULONGs; the new data must be 32-bit
 * addresses. Entry is the request entry for the thread, or NULL past the
 * entries given. Raises on bad memory or a bad request; returns whether the
 * thread counts (it has a vector, and in pass 1 an entry).
 */
static
BOOLEAN
PspSetThreadTls32(
    _In_ PTEB Teb,
    _In_ PPROCESS_TLS_INFORMATION Header,
    _Inout_opt_ PTHREAD_TLS_INFORMATION Entry,
    _In_ ULONG Pass,
    _In_ HANDLE ThreadId,
    _In_ ULONG64 GuestLimit)
{
    PTEB32 Guest;
    PULONG Vector, NewVector;
    ULONG OldLength, NewLength, Old = 0, i;
    ULONG_PTR NewTlsData;

    /* A 32-bit vector, its length word before it included, stays in the guest's address space */
#define TLS32_IN_GUEST(v, n) ((ULONG_PTR)(v) >= sizeof(ULONG) && \
                              (ULONG64)(ULONG_PTR)(v) + (ULONG64)(n) * sizeof(ULONG) <= GuestLimit)

    if (!Teb)
        return FALSE;
    Guest = PS_GET_TEB32_FROM_TEB(Teb);
    ProbeForRead(&Guest->ThreadLocalStoragePointer, sizeof(ULONG), sizeof(ULONG));
    Vector = (PULONG)UlongToPtr(Guest->ThreadLocalStoragePointer);
    if (!Vector)
        return FALSE;

    /* The thread's vector and its length, as user memory; a pointer outside the guest is not touched */
    if (!TLS32_IN_GUEST(Vector, 0))
        ExRaiseStatus(STATUS_INVALID_PARAMETER);
    ProbeForWrite(Vector - 1, sizeof(ULONG), sizeof(ULONG));
    OldLength = Vector[-1];
    if (OldLength >= MAXLONG / sizeof(ULONG) || !TLS32_IN_GUEST(Vector, OldLength))
        ExRaiseStatus(STATUS_INVALID_PARAMETER);
    ProbeForWrite(Vector, OldLength * sizeof(ULONG), sizeof(ULONG));

    /* Pass 0 counts beyond the entries given; pass 1 never sees more threads (the loader lock) */
    if (!Entry)
        return (Pass == 0);

    NewTlsData = (ULONG_PTR)Entry->NewTlsData;
    if (NewTlsData > MAXULONG)
        ExRaiseStatus(STATUS_INVALID_PARAMETER);

    if (Header->OperationType == PROCESS_TLS_REPLACE_VECTOR)
    {
        /* The new vector: at least one entry longer than the index */
        NewVector = (PULONG)NewTlsData;
        if (!TLS32_IN_GUEST(NewVector, 0))
            ExRaiseStatus(STATUS_INVALID_PARAMETER);
        ProbeForWrite(NewVector - 1, sizeof(ULONG), sizeof(ULONG));
        NewLength = NewVector[-1];
        if (NewLength <= Header->TlsIndex || NewLength >= MAXLONG / sizeof(ULONG) ||
            !TLS32_IN_GUEST(NewVector, NewLength))
            ExRaiseStatus(STATUS_INVALID_PARAMETER);
        ProbeForWrite(NewVector, NewLength * sizeof(ULONG), sizeof(ULONG));

        if (Pass == 1)
        {
            Entry->Flags = 0;
            for (i = 0; i < Header->TlsIndex; i++)
                NewVector[i] = (i < OldLength) ? Vector[i] : 0;
            Old = (ULONG)InterlockedExchange((PLONG)&Guest->ThreadLocalStoragePointer, (LONG)NewTlsData);
        }
    }
    else
    {
        if (Header->TlsIndex >= OldLength)
            ExRaiseStatus(STATUS_INVALID_PARAMETER);
        if (Pass == 1)
        {
            Entry->Flags = 0;
            Old = (ULONG)InterlockedExchange((PLONG)&Vector[Header->TlsIndex], (LONG)NewTlsData);
        }
    }

    if (Pass == 1)
    {
        Entry->OldTlsData = UlongToPtr(Old);
        Entry->ThreadId = ThreadId;
        Entry->Flags = THREAD_TLS_INFORMATION_ASSIGNED;
    }
    return TRUE;
#undef TLS32_IN_GUEST
}
#endif

/*
 * ProcessTlsInformation: changes the TLS vectors of the threads of the current
 * process for the loader, which holds its lock, so no thread of the process
 * initializes or frees its TLS meanwhile. A thread without a TLS vector has
 * not initialized it yet (it will see the new module then) or has freed it on
 * its way out, and is left alone; so is a thread that is exiting. Rundown
 * protection keeps the TEB of a thread mapped while it is changed.
 *
 * Every TLS vector is user memory with its number of entries in the pointer
 * before it (ntdll allocates them so). Every vector and length is probed as
 * user memory before it is used, and each request entry is read once per
 * pass. Pass 0 checks all threads and writes nothing; pass 1 checks again and
 * makes the change. A failure in pass 1 (the process changing its request or
 * unmapping its own vectors meanwhile) stops the change, and the entries done
 * so far are marked THREAD_TLS_INFORMATION_ASSIGNED; the entry is written
 * once before a thread is changed, so a fault on the request cannot hide a
 * change already made, short of the process unmapping it in that moment.
 * With PROCESS_TLS_WOW64 (the WoW64 layer, for the 32-bit loader of a WoW64
 * process) the vectors changed are the 32-bit ones in the TEB32s.
 */
static
NTSTATUS
PspSetProcessTlsInformation(
    _In_ PEPROCESS Process,
    _In_ PPROCESS_TLS_INFORMATION TlsInformation,
    _In_ ULONG Length)
{
    PROCESS_TLS_INFORMATION Header;
    PTHREAD_TLS_INFORMATION ThreadData;
    PETHREAD Thread;
    PTEB Teb;
    PVOID *Vector, *NewVector, NewTlsData, OldTlsData = NULL;
    ULONG_PTR OldLength, NewLength;
    ULONG Pass, Count, i;
    BOOLEAN Counted;
#if defined(_WIN64) && defined(BUILD_WOW64_ENABLED)
    BOOLEAN Wow64 = FALSE;
    SECTION_IMAGE_INFORMATION ImageInformation;
    ULONG64 GuestLimit = 0;
#endif
    NTSTATUS Status = STATUS_SUCCESS;

    if (Process != PsGetCurrentProcess())
        return STATUS_INVALID_PARAMETER;
    if (Length < FIELD_OFFSET(PROCESS_TLS_INFORMATION, ThreadData))
        return STATUS_INFO_LENGTH_MISMATCH;

    _SEH2_TRY
    {
        /* Entries are written back */
        ProbeForWrite(TlsInformation, Length, sizeof(ULONG));
        /* The header only: a request may have no entries */
        RtlCopyMemory(&Header, TlsInformation, FIELD_OFFSET(PROCESS_TLS_INFORMATION, ThreadData));
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        _SEH2_YIELD(return _SEH2_GetExceptionCode());
    }
    _SEH2_END;

#if defined(_WIN64) && defined(BUILD_WOW64_ENABLED)
    if (Header.Flags & PROCESS_TLS_WOW64)
    {
        if (!Process->Wow64Process)
            return STATUS_INVALID_PARAMETER;
        Header.Flags &= ~PROCESS_TLS_WOW64;
        Wow64 = TRUE;
        /* The guest's address space ends at 2 GiB, or near 4 GiB for a large-address-aware
           image (as the WoW64 layer reserves it: MM_HIGHEST_USER_ADDRESS_WOW64 or 0xFFFEFFFF) */
        MmGetImageInformation(&ImageInformation);
        GuestLimit = (ImageInformation.ImageCharacteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) ?
                     0xFFFF0000ULL : (ULONG64)MM_HIGHEST_USER_ADDRESS_WOW64 + 1;
    }
#endif
    if (Header.Flags ||
        (Header.OperationType != PROCESS_TLS_REPLACE_VECTOR && Header.OperationType != PROCESS_TLS_REPLACE_INDEX) ||
        Header.ThreadDataCount > (Length - FIELD_OFFSET(PROCESS_TLS_INFORMATION, ThreadData)) / sizeof(THREAD_TLS_INFORMATION) ||
        Header.TlsIndex >= MAXLONG / sizeof(PVOID) - 1)
    {
        return STATUS_INVALID_PARAMETER;
    }
    ThreadData = TlsInformation->ThreadData;

    /* Pass 0 checks every thread and counts them; pass 1 makes the change */
    for (Pass = 0; Pass < 2; Pass++)
    {
        Count = 0;
        for (Thread = PsGetNextProcessThread(Process, NULL);
             Thread != NULL;
             Thread = PsGetNextProcessThread(Process, Thread))
        {
            if (!ExAcquireRundownProtection(&Thread->RundownProtect))
                continue;

            Vector = NULL;
            Counted = FALSE;
            Teb = Thread->Tcb.Teb;
            _SEH2_TRY
            {
#if defined(_WIN64) && defined(BUILD_WOW64_ENABLED)
                if (Wow64)
                {
                    Counted = PspSetThreadTls32(Teb, &Header,
                                                (Count < Header.ThreadDataCount) ? &ThreadData[Count] : NULL,
                                                Pass, Thread->Cid.UniqueThread, GuestLimit);
                }
                else
#endif
                {
                if (Teb)
                {
                    ProbeForRead(&Teb->ThreadLocalStoragePointer, sizeof(PVOID), sizeof(PVOID));
                    Vector = Teb->ThreadLocalStoragePointer;
                }
                if (Vector)
                {
                    /* The thread's vector and its length, as user memory */
                    ProbeForWrite(Vector - 1, sizeof(PVOID), sizeof(PVOID));
                    OldLength = ((PULONG_PTR)Vector)[-1];
                    if (OldLength >= MAXLONG / sizeof(PVOID))
                        ExRaiseStatus(STATUS_INVALID_PARAMETER);
                    ProbeForWrite(Vector, OldLength * sizeof(PVOID), sizeof(PVOID));

                    if (Count >= Header.ThreadDataCount)
                    {
                        /* Pass 0 counts beyond the entries given; pass 1 never sees more threads (the loader lock) */
                        if (Pass == 1)
                            Vector = NULL;
                    }
                    else
                    {
                        NewTlsData = ThreadData[Count].NewTlsData;

                        if (Header.OperationType == PROCESS_TLS_REPLACE_VECTOR)
                        {
                            /* The new vector: at least one entry longer than the index */
                            NewVector = NewTlsData;
                            ProbeForWrite((PULONG_PTR)NewVector - 1, sizeof(PVOID), sizeof(PVOID));
                            NewLength = ((PULONG_PTR)NewVector)[-1];
                            if (NewLength <= Header.TlsIndex || NewLength >= MAXLONG / sizeof(PVOID))
                                ExRaiseStatus(STATUS_INVALID_PARAMETER);
                            ProbeForWrite(NewVector, NewLength * sizeof(PVOID), sizeof(PVOID));

                            if (Pass == 1)
                            {
                                ThreadData[Count].Flags = 0;
                                for (i = 0; i < Header.TlsIndex; i++)
                                    NewVector[i] = (i < OldLength) ? Vector[i] : NULL;
                                OldTlsData = InterlockedExchangePointer((PVOID*)&Teb->ThreadLocalStoragePointer, NewVector);
                            }
                        }
                        else
                        {
                            if (Header.TlsIndex >= OldLength)
                                ExRaiseStatus(STATUS_INVALID_PARAMETER);
                            if (Pass == 1)
                            {
                                ThreadData[Count].Flags = 0;
                                OldTlsData = InterlockedExchangePointer(&Vector[Header.TlsIndex], NewTlsData);
                            }
                        }

                        if (Pass == 1)
                        {
                            ThreadData[Count].OldTlsData = OldTlsData;
                            ThreadData[Count].ThreadId = Thread->Cid.UniqueThread;
                            ThreadData[Count].Flags = THREAD_TLS_INFORMATION_ASSIGNED;
                        }
                    }
                }
                Counted = (Vector != NULL);
                }
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;

            ExReleaseRundownProtection(&Thread->RundownProtect);

            if (!NT_SUCCESS(Status))
            {
                ObDereferenceObject(Thread);
                goto Done;
            }

            if (Counted)
                Count++;
        }

        if (Pass == 0 && Count > Header.ThreadDataCount)
        {
            /* Nothing changed: say how many entries it takes */
            Status = STATUS_INFO_LENGTH_MISMATCH;
            goto Done;
        }
    }

Done:
    _SEH2_TRY
    {
        /* Entries used (also when a fault stopped the change part way), or needed; nothing if the checks failed */
        if (Pass >= 1 || Status == STATUS_INFO_LENGTH_MISMATCH)
            TlsInformation->ThreadDataCount = Count;
        else
            TlsInformation->ThreadDataCount = 0;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        if (NT_SUCCESS(Status))
            Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;

    return Status;
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
NtSetInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _In_reads_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength)
{
    PEPROCESS Process;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    ACCESS_MASK Access;
    NTSTATUS Status;
    HANDLE PortHandle = NULL;
    HANDLE TokenHandle = NULL;
    HANDLE DirectoryHandle = NULL;
    PROCESS_SESSION_INFORMATION SessionInfo = {0};
    PROCESS_PRIORITY_CLASS PriorityClass = {0};
    PROCESS_FOREGROUND_BACKGROUND Foreground = {0};
    PVOID ExceptionPort;
    ULONG Break;
    KAFFINITY ValidAffinity, Affinity = 0;
    KPRIORITY BasePriority = 0;
    UCHAR MemoryPriority = 0;
    BOOLEAN DisableBoost = 0;
    ULONG DefaultHardErrorMode = 0;
    ULONG DebugFlags = 0, EnableFixup = 0, Boost = 0;
    ULONG NoExecute = 0, VdmPower = 0;
    BOOLEAN HasPrivilege;
    PLIST_ENTRY Next;
    PETHREAD Thread;
    PAGED_CODE();

    /* Validate the information class */
    Status = DefaultSetInfoBufferCheck(ProcessInformationClass,
                                       PsProcessInfoClass,
                                       RTL_NUMBER_OF(PsProcessInfoClass),
                                       ProcessInformation,
                                       ProcessInformationLength,
                                       PreviousMode);
    if (!NT_SUCCESS(Status))
    {
#if DBG
        DPRINT1("NtSetInformationProcess(ProcessInformationClass: %s): Class validation failed! (Status: 0x%lx)\n",
                PspDumpProcessInfoClassName(ProcessInformationClass), Status);
#endif
        return Status;
    }

    /* Check what class this is */
    Access = PROCESS_SET_INFORMATION;
    if (ProcessInformationClass == ProcessSessionInformation)
    {
        /* Setting the Session ID needs a special mask */
        Access |= PROCESS_SET_SESSIONID;
    }
    else if (ProcessInformationClass == ProcessExceptionPort)
    {
        /* Setting the exception port needs a special mask */
        Access |= PROCESS_SUSPEND_RESUME;
    }

    /* Reference the process */
    Status = ObReferenceObjectByHandle(ProcessHandle,
                                       Access,
                                       PsProcessType,
                                       PreviousMode,
                                       (PVOID*)&Process,
                                       NULL);
    if (!NT_SUCCESS(Status)) return Status;

    /* Check what kind of information class this is */
    switch (ProcessInformationClass)
    {
        case ProcessWx86Information:

            /* Check buffer length */
            if (ProcessInformationLength != sizeof(ULONG))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Use SEH for capture */
            _SEH2_TRY
            {
                /* Capture the boolean */
                VdmPower = *(PULONG)ProcessInformation;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get the exception code */
                Status = _SEH2_GetExceptionCode();
                _SEH2_YIELD(break);
            }
            _SEH2_END;

            /* Getting VDM powers requires the SeTcbPrivilege */
            if (!SeSinglePrivilegeCheck(SeTcbPrivilege, PreviousMode))
            {
                /* We don't hold the privilege, bail out */
                Status = STATUS_PRIVILEGE_NOT_HELD;
                DPRINT1("Need TCB privilege\n");
                break;
            }

            /* Set or clear the flag */
            if (VdmPower)
            {
                PspSetProcessFlag(Process, PSF_VDM_ALLOWED_BIT);
            }
            else
            {
                PspClearProcessFlag(Process, PSF_VDM_ALLOWED_BIT);
            }
            break;

        /* Error/Exception Port */
        case ProcessExceptionPort:

            /* Check buffer length */
            if (ProcessInformationLength != sizeof(HANDLE))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Use SEH for capture */
            _SEH2_TRY
            {
                /* Capture the handle */
                PortHandle = *(PHANDLE)ProcessInformation;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get the exception code */
                Status = _SEH2_GetExceptionCode();
                _SEH2_YIELD(break);
            }
            _SEH2_END;

            /* Setting the error port requires the SeTcbPrivilege */
            if (!SeSinglePrivilegeCheck(SeTcbPrivilege, PreviousMode))
            {
                /* We don't hold the privilege, bail out */
                Status = STATUS_PRIVILEGE_NOT_HELD;
                break;
            }

            /* Get the LPC Port */
            Status = ObReferenceObjectByHandle(PortHandle,
                                               0,
                                               LpcPortObjectType,
                                               PreviousMode,
                                               (PVOID)&ExceptionPort,
                                               NULL);
            if (!NT_SUCCESS(Status)) break;

            /* Change the pointer */
            if (InterlockedCompareExchangePointer(&Process->ExceptionPort,
                                                  ExceptionPort,
                                                  NULL))
            {
                /* We already had one, fail */
                ObDereferenceObject(ExceptionPort);
                Status = STATUS_PORT_ALREADY_SET;
            }
            break;

        /* Security Token */
        case ProcessAccessToken:

            /* Check buffer length */
            if (ProcessInformationLength != sizeof(PROCESS_ACCESS_TOKEN))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Use SEH for capture */
            _SEH2_TRY
            {
                /* Save the token handle */
                TokenHandle = ((PPROCESS_ACCESS_TOKEN)ProcessInformation)->
                               Token;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get the exception code */
                Status = _SEH2_GetExceptionCode();
                _SEH2_YIELD(break);
            }
            _SEH2_END;

            /* Assign the actual token */
            Status = PspSetPrimaryToken(Process, TokenHandle, NULL);
            break;

        /* Hard error processing */
        case ProcessDefaultHardErrorMode:

            /* Check buffer length */
            if (ProcessInformationLength != sizeof(ULONG))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Enter SEH for direct buffer read */
            _SEH2_TRY
            {
                DefaultHardErrorMode = *(PULONG)ProcessInformation;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get exception code */
                Status = _SEH2_GetExceptionCode();
                _SEH2_YIELD(break);
            }
            _SEH2_END;

            /* Set the mode */
            Process->DefaultHardErrorProcessing = DefaultHardErrorMode;

            /* Call Ke for the update */
            if (DefaultHardErrorMode & SEM_NOALIGNMENTFAULTEXCEPT)
            {
                KeSetAutoAlignmentProcess(&Process->Pcb, TRUE);
            }
            else
            {
                KeSetAutoAlignmentProcess(&Process->Pcb, FALSE);
            }
            Status = STATUS_SUCCESS;
            break;

        /* Session ID */
        case ProcessSessionInformation:

            /* Check buffer length */
            if (ProcessInformationLength != sizeof(PROCESS_SESSION_INFORMATION))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Enter SEH for capture */
            _SEH2_TRY
            {
                /* Capture the caller's buffer */
                SessionInfo = *(PPROCESS_SESSION_INFORMATION)ProcessInformation;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get the exception code */
                Status = _SEH2_GetExceptionCode();
                _SEH2_YIELD(break);
            }
            _SEH2_END;

            /* Setting the session id requires the SeTcbPrivilege */
            if (!SeSinglePrivilegeCheck(SeTcbPrivilege, PreviousMode))
            {
                /* We don't hold the privilege, bail out */
                Status = STATUS_PRIVILEGE_NOT_HELD;
                break;
            }

            /*
             * Since we cannot change the session ID of the given
             * process anymore because it is set once and for all
             * at process creation time and because it is stored
             * inside the Process->Session structure managed by MM,
             * we fake changing it: we just return success if the
             * user-defined value is the same as the session ID of
             * the process, and otherwise we fail.
             */
            if (SessionInfo.SessionId == PsGetProcessSessionId(Process))
            {
                Status = STATUS_SUCCESS;
            }
            else
            {
                Status = STATUS_ACCESS_DENIED;
            }

            break;

        case ProcessPriorityClass:

            /* Check buffer length */
            if (ProcessInformationLength != sizeof(PROCESS_PRIORITY_CLASS))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Enter SEH for capture */
            _SEH2_TRY
            {
                /* Capture the caller's buffer */
                PriorityClass = *(PPROCESS_PRIORITY_CLASS)ProcessInformation;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Return the exception code */
                Status = _SEH2_GetExceptionCode();
                _SEH2_YIELD(break);
            }
            _SEH2_END;

            /* Check for invalid PriorityClass value */
            if (PriorityClass.PriorityClass > PROCESS_PRIORITY_CLASS_ABOVE_NORMAL)
            {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            if ((PriorityClass.PriorityClass != Process->PriorityClass) &&
                (PriorityClass.PriorityClass == PROCESS_PRIORITY_CLASS_REALTIME))
            {
                /* Check the privilege */
                HasPrivilege = SeCheckPrivilegedObject(SeIncreaseBasePriorityPrivilege,
                                                       ProcessHandle,
                                                       PROCESS_SET_INFORMATION,
                                                       PreviousMode);
                if (!HasPrivilege)
                {
                    ObDereferenceObject(Process);
                    DPRINT1("Privilege to change priority to realtime lacking\n");
                    return STATUS_PRIVILEGE_NOT_HELD;
                }
            }

            /* Check if we have a job */
            if (Process->Job)
            {
                DPRINT1("Jobs not yet supported\n");
            }

            /* Set process priority class */
            Process->PriorityClass = PriorityClass.PriorityClass;

            /* Set process priority mode (foreground or background) */
            PspApplyProcessPriorityMode(Process,
                                        PriorityClass.Foreground ?
                                        PsProcessPriorityForeground :
                                        PsProcessPriorityBackground);
            Status = STATUS_SUCCESS;
            break;

        case ProcessForegroundInformation:

            /* Check buffer length */
            if (ProcessInformationLength != sizeof(PROCESS_FOREGROUND_BACKGROUND))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Enter SEH for capture */
            _SEH2_TRY
            {
                /* Capture the caller's buffer */
                Foreground = *(PPROCESS_FOREGROUND_BACKGROUND)ProcessInformation;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Return the exception code */
                Status = _SEH2_GetExceptionCode();
                _SEH2_YIELD(break);
            }
            _SEH2_END;

            /*
             * Set process priority mode (foreground or background). The process that
             * owns the foreground window stays in the foreground mode whatever CSRSS
             * asks: the console of a console program that is in front with its own
             * window loses the focus, and that must not take the window's quantum away.
             */
            if (Foreground.Foreground || !PspIsForegroundWindowProcess(Process))
            {
                PspApplyProcessPriorityMode(Process,
                                            Foreground.Foreground ?
                                            PsProcessPriorityForeground :
                                            PsProcessPriorityBackground);
            }
            Status = STATUS_SUCCESS;
            break;

        case ProcessBasePriority:

            /* Validate input length */
            if (ProcessInformationLength != sizeof(KPRIORITY))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Enter SEH for direct buffer read */
            _SEH2_TRY
            {
                BasePriority = *(KPRIORITY*)ProcessInformation;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get exception code */
                Break = 0;
                Status = _SEH2_GetExceptionCode();
                _SEH2_YIELD(break);
            }
            _SEH2_END;

            /* Extract the memory priority out of there */
            if (BasePriority & 0x80000000)
            {
                MemoryPriority = MEMORY_PRIORITY_FOREGROUND;
                BasePriority &= ~0x80000000;
            }
            else
            {
                MemoryPriority = MEMORY_PRIORITY_BACKGROUND;
            }

            /* Validate the number */
            if ((BasePriority > HIGH_PRIORITY) || (BasePriority <= LOW_PRIORITY))
            {
                ObDereferenceObject(Process);
                return STATUS_INVALID_PARAMETER;
            }

            /* Check if the new base is higher */
            if (BasePriority > Process->Pcb.BasePriority)
            {
                HasPrivilege = SeCheckPrivilegedObject(SeIncreaseBasePriorityPrivilege,
                                                       ProcessHandle,
                                                       PROCESS_SET_INFORMATION,
                                                       PreviousMode);
                if (!HasPrivilege)
                {
                    ObDereferenceObject(Process);
                    DPRINT1("Privilege to change priority from %lx to %lx lacking\n", Process->Pcb.BasePriority, BasePriority);
                    return STATUS_PRIVILEGE_NOT_HELD;
                }
            }

            /* Call Ke */
            KeSetPriorityAndQuantumProcess(&Process->Pcb, BasePriority, 0);

            /* Now set the memory priority */
            MmSetMemoryPriorityProcess(Process, MemoryPriority);
            Status = STATUS_SUCCESS;
            break;

        case ProcessRaisePriority:

            /* Validate input length */
            if (ProcessInformationLength != sizeof(ULONG))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Enter SEH for direct buffer read */
            _SEH2_TRY
            {
                Boost = *(PULONG)ProcessInformation;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get exception code */
                Break = 0;
                Status = _SEH2_GetExceptionCode();
                _SEH2_YIELD(break);
            }
            _SEH2_END;

            /* Make sure the process isn't dying */
            if (ExAcquireRundownProtection(&Process->RundownProtect))
            {
                /* Lock it */
                KeEnterCriticalRegion();
                ExAcquirePushLockShared(&Process->ProcessLock);

                /* Loop the threads */
                for (Next = Process->ThreadListHead.Flink;
                     Next != &Process->ThreadListHead;
                     Next = Next->Flink)
                {
                    /* Call Ke for the thread */
                    Thread = CONTAINING_RECORD(Next, ETHREAD, ThreadListEntry);
                    KeBoostPriorityThread(&Thread->Tcb, Boost);
                }

                /* Release the lock and rundown */
                ExReleasePushLockShared(&Process->ProcessLock);
                KeLeaveCriticalRegion();
                ExReleaseRundownProtection(&Process->RundownProtect);

                /* Set success code */
                Status = STATUS_SUCCESS;
            }
            else
            {
                /* Avoid race conditions */
                Status = STATUS_PROCESS_IS_TERMINATING;
            }
            break;

        case ProcessBreakOnTermination:

            /* Check buffer length */
            if (ProcessInformationLength != sizeof(ULONG))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Enter SEH for direct buffer read */
            _SEH2_TRY
            {
                Break = *(PULONG)ProcessInformation;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get exception code */
                Break = 0;
                Status = _SEH2_GetExceptionCode();
                _SEH2_YIELD(break);
            }
            _SEH2_END;

            /* Setting 'break on termination' requires the SeDebugPrivilege */
            if (!SeSinglePrivilegeCheck(SeDebugPrivilege, PreviousMode))
            {
                /* We don't hold the privilege, bail out */
                Status = STATUS_PRIVILEGE_NOT_HELD;
                break;
            }

            /* Set or clear the flag */
            if (Break)
            {
                PspSetProcessFlag(Process, PSF_BREAK_ON_TERMINATION_BIT);
            }
            else
            {
                PspClearProcessFlag(Process, PSF_BREAK_ON_TERMINATION_BIT);
            }

            break;

        case ProcessAffinityMask:

            /* Check buffer length */
            if (ProcessInformationLength != sizeof(KAFFINITY))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Enter SEH for direct buffer read */
            _SEH2_TRY
            {
                Affinity = *(PKAFFINITY)ProcessInformation;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get exception code */
                Break = 0;
                Status = _SEH2_GetExceptionCode();
                _SEH2_YIELD(break);
            }
            _SEH2_END;

            /* Make sure it's valid for the CPUs present */
            ValidAffinity = Affinity & KeActiveProcessors;
            if (!Affinity || (ValidAffinity != Affinity))
            {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            /* Check if it's within job affinity limits */
            if (Process->Job)
            {
                /* Not yet implemented */
                UNIMPLEMENTED;
                Status = STATUS_NOT_IMPLEMENTED;
                break;
            }

            /* Make sure the process isn't dying */
            if (ExAcquireRundownProtection(&Process->RundownProtect))
            {
                /* Lock it */
                KeEnterCriticalRegion();
                ExAcquirePushLockShared(&Process->ProcessLock);

                /* Call Ke to do the work */
                KeSetAffinityProcess(&Process->Pcb, ValidAffinity);

                /* Release the lock and rundown */
                ExReleasePushLockShared(&Process->ProcessLock);
                KeLeaveCriticalRegion();
                ExReleaseRundownProtection(&Process->RundownProtect);

                /* Set success code */
                Status = STATUS_SUCCESS;
            }
            else
            {
                /* Avoid race conditions */
                Status = STATUS_PROCESS_IS_TERMINATING;
            }
            break;

        /* Priority Boosting status */
        case ProcessPriorityBoost:

            /* Validate input length */
            if (ProcessInformationLength != sizeof(ULONG))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Enter SEH for direct buffer read */
            _SEH2_TRY
            {
                DisableBoost = *(PBOOLEAN)ProcessInformation;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get exception code */
                Break = 0;
                Status = _SEH2_GetExceptionCode();
                _SEH2_YIELD(break);
            }
            _SEH2_END;

            /* Make sure the process isn't dying */
            if (ExAcquireRundownProtection(&Process->RundownProtect))
            {
                /* Lock it */
                KeEnterCriticalRegion();
                ExAcquirePushLockShared(&Process->ProcessLock);

                /* Call Ke to do the work */
                KeSetDisableBoostProcess(&Process->Pcb, DisableBoost);

                /* Loop the threads too */
                for (Next = Process->ThreadListHead.Flink;
                     Next != &Process->ThreadListHead;
                     Next = Next->Flink)
                {
                    /* Call Ke for the thread */
                    Thread = CONTAINING_RECORD(Next, ETHREAD, ThreadListEntry);
                    KeSetDisableBoostThread(&Thread->Tcb, DisableBoost);
                }

                /* Release the lock and rundown */
                ExReleasePushLockShared(&Process->ProcessLock);
                KeLeaveCriticalRegion();
                ExReleaseRundownProtection(&Process->RundownProtect);

                /* Set success code */
                Status = STATUS_SUCCESS;
            }
            else
            {
                /* Avoid race conditions */
                Status = STATUS_PROCESS_IS_TERMINATING;
            }
            break;

        case ProcessDebugFlags:

            /* Check buffer length */
            if (ProcessInformationLength != sizeof(ULONG))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Enter SEH for direct buffer read */
            _SEH2_TRY
            {
                DebugFlags = *(PULONG)ProcessInformation;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get exception code */
                Status = _SEH2_GetExceptionCode();
                _SEH2_YIELD(break);
            }
            _SEH2_END;

            /* Set the mode */
            if (DebugFlags & ~1)
            {
                Status = STATUS_INVALID_PARAMETER;
            }
            else
            {
                if (DebugFlags & 1)
                {
                    PspClearProcessFlag(Process, PSF_NO_DEBUG_INHERIT_BIT);
                }
                else
                {
                    PspSetProcessFlag(Process, PSF_NO_DEBUG_INHERIT_BIT);
                }
            }

            /* Done */
            Status = STATUS_SUCCESS;
            break;

        case ProcessEnableAlignmentFaultFixup:

            /* Check buffer length */
            if (ProcessInformationLength != sizeof(BOOLEAN))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Enter SEH for direct buffer read */
            _SEH2_TRY
            {
                EnableFixup = *(PULONG)ProcessInformation;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get exception code */
                Status = _SEH2_GetExceptionCode();
                _SEH2_YIELD(break);
            }
            _SEH2_END;

            /* Set the mode */
            if (EnableFixup)
            {
                Process->DefaultHardErrorProcessing |= SEM_NOALIGNMENTFAULTEXCEPT;
            }
            else
            {
                Process->DefaultHardErrorProcessing &= ~SEM_NOALIGNMENTFAULTEXCEPT;
            }

            /* Call Ke for the update */
            KeSetAutoAlignmentProcess(&Process->Pcb, FALSE);
            Status = STATUS_SUCCESS;
            break;

        case ProcessUserModeIOPL:

            /* Only TCB can do this */
            if (!SeSinglePrivilegeCheck(SeTcbPrivilege, PreviousMode))
            {
                /* We don't hold the privilege, bail out */
                DPRINT1("Need TCB to set IOPL\n");
                Status = STATUS_PRIVILEGE_NOT_HELD;
                break;
            }

            /* Only supported on x86 */
#if defined (_X86_)
            Ke386SetIOPL();
#elif defined(_M_AMD64)
            /* On x64 this function isn't implemented.
               On Windows 2003 it returns success.
               On Vista+ it returns STATUS_NOT_IMPLEMENTED. */
            if ((ExGetPreviousMode() != KernelMode) &&
                (RtlRosGetAppcompatVersion() > _WIN32_WINNT_WS03))
            {
                Status = STATUS_NOT_IMPLEMENTED;
            }
#else
            Status = STATUS_NOT_IMPLEMENTED;
#endif
            /* Done */
            break;

        /* Mitigation policy: the Win32k lockdown can be turned on, never off */
        case ProcessMitigationPolicy:
        {
            PS_MITIGATION_POLICY_REQUEST Request;

            _SEH2_TRY
            {
                Request = *(PPS_MITIGATION_POLICY_REQUEST)ProcessInformation;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                Status = _SEH2_GetExceptionCode();
                _SEH2_YIELD(break);
            }
            _SEH2_END;

            if (Request.Policy != PS_MITIGATION_SYSTEM_CALL_DISABLE ||
                (Request.Flags & ~0x3))
            {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            /*
             * Measured on Windows 10: the request is accepted by a process that has made no Win32k call yet, which
             * is the case of a child of the creator before it runs, and fails with ERROR_WRITE_PROTECT once the
             * process has used Win32k. Asking for what is already so is always accepted.
             */
            if ((Request.Flags & PS_MITIGATION_DISALLOW_WIN32K) == (Process->Flags & PSF_DISALLOW_WIN32K_BIT ? PS_MITIGATION_DISALLOW_WIN32K : 0) &&
                !(Request.Flags & 2))
            {
                break;
            }

            if (Process->Win32Process != NULL)
            {
                Status = STATUS_MEDIA_WRITE_PROTECTED;
                break;
            }

            if (Request.Flags & PS_MITIGATION_DISALLOW_WIN32K)
            {
                PspSetProcessFlag(Process, PSF_DISALLOW_WIN32K_BIT);
            }
            else if (Process->Flags & PSF_DISALLOW_WIN32K_BIT)
            {
                /* The lockdown cannot be taken back */
                Status = STATUS_ACCESS_DENIED;
            }
            break;
        }

        case ProcessExecuteFlags:

            /* Check buffer length */
            if (ProcessInformationLength != sizeof(ULONG))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            if (ProcessHandle != NtCurrentProcess())
            {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            /* Enter SEH for direct buffer read */
            _SEH2_TRY
            {
                NoExecute = *(PULONG)ProcessInformation;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get exception code */
                Status = _SEH2_GetExceptionCode();
                _SEH2_YIELD(break);
            }
            _SEH2_END;

            /* Call Mm for the update */
            Status = MmSetExecuteOptions(NoExecute);
            break;

        case ProcessDeviceMap:

            /* Check buffer length */
            if (ProcessInformationLength != sizeof(HANDLE))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Use SEH for capture */
            _SEH2_TRY
            {
                /* Capture the handle */
                DirectoryHandle = *(PHANDLE)ProcessInformation;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get the exception code */
                Status = _SEH2_GetExceptionCode();
                _SEH2_YIELD(break);
            }
            _SEH2_END;

            /* Call Ob to set the device map */
            Status = ObSetDeviceMap(Process, DirectoryHandle);
            break;


        /* We currently don't implement any of these */
        case ProcessLdtInformation:
        case ProcessLdtSize:
        case ProcessIoPortHandlers:
             DPRINT1("VDM/16-bit Request not implemented: %lu\n", ProcessInformationClass);
             Status = STATUS_NOT_IMPLEMENTED;
             break;

        case ProcessQuotaLimits:

            Status = PspSetQuotaLimits(Process,
                                     1,
                                     ProcessInformation,
                                     ProcessInformationLength,
                                     PreviousMode);
            break;

        case ProcessWorkingSetWatch:
            DPRINT1("WS watch not implemented\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case ProcessHandleTracing:
            DPRINT1("Handle tracing not implemented\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case ProcessTlsInformation:
            Status = PspSetProcessTlsInformation(Process, ProcessInformation, ProcessInformationLength);
            break;

        /* Anything else is invalid */
        default:
#if DBG
            DPRINT1("Invalid Server 2003 Info Class: %s\n", PspDumpProcessInfoClassName(ProcessInformationClass));
#endif
            Status = STATUS_INVALID_INFO_CLASS;
    }

    /* Dereference and return status */
    ObDereferenceObject(Process);
    return Status;
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
NtSetInformationThread(
    _In_ HANDLE ThreadHandle,
    _In_ THREADINFOCLASS ThreadInformationClass,
    _In_reads_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength)
{
    PETHREAD Thread;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    NTSTATUS Status;
    KPRIORITY Priority = 0;
    PEPROCESS Process;
    PTEB Teb;

    PAGED_CODE();

    /* Reject Vista+ classes on an older NT version identity */
    if (!PspIsThreadInfoClassAvailable(ThreadInformationClass, TRUE))
        return STATUS_INVALID_INFO_CLASS;

    /* Vista+ takes no buffer for ThreadHideFromDebugger: any length is
     * rejected before the buffer (and its alignment) is looked at. */
    if ((ThreadInformationClass == ThreadHideFromDebugger) &&
        (NtMajorVersion >= 6) && (ThreadInformationLength != 0))
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    /* Validate the information class */
    Status = DefaultSetInfoBufferCheck(ThreadInformationClass,
                                       PsThreadInfoClass,
                                       RTL_NUMBER_OF(PsThreadInfoClass),
                                       ThreadInformation,
                                       ThreadInformationLength,
                                       PreviousMode);
    if (!NT_SUCCESS(Status))
    {
#if DBG
        DPRINT1("NtSetInformationThread(ThreadInformationClass: %s): Class validation failed! (Status: 0x%lx)\n",
                PspDumpThreadInfoClassName(ThreadInformationClass), Status);
#endif
        return Status;
    }

    /* Check what kind of information class this is */
    switch (ThreadInformationClass)
    {
#if defined(_M_AMD64) && defined(BUILD_WOW64_ENABLED)
        case ThreadWow64Context:
            return PspWow64ContextThread(ThreadHandle, ThreadInformation,
                                         ThreadInformationLength, TRUE, PreviousMode);
#endif
        /* Thread priority */
        case ThreadPriority:
        {
            /* Check buffer length */
            if (ThreadInformationLength != sizeof(KPRIORITY))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Use SEH for capture */
            _SEH2_TRY
            {
                /* Get the priority */
                Priority = *(PLONG)ThreadInformation;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get the exception code */
                Status = _SEH2_GetExceptionCode();
                _SEH2_YIELD(break);
            }
            _SEH2_END;

            /* Validate it */
            if ((Priority > HIGH_PRIORITY) ||
                (Priority <= LOW_PRIORITY))
            {
                /* Fail */
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            /* Check for the required privilege */
            if (Priority >= LOW_REALTIME_PRIORITY)
            {
                BOOLEAN HasPrivilege;
                HasPrivilege = SeCheckPrivilegedObject(SeIncreaseBasePriorityPrivilege,
                                                       ThreadHandle,
                                                       THREAD_SET_INFORMATION,
                                                       PreviousMode);
                if (!HasPrivilege)
                {
                    DPRINT1("Privilege to change priority to %lx lacking\n", Priority);
                    return STATUS_PRIVILEGE_NOT_HELD;
                }
            }

            /* Reference the thread */
            Status = ObReferenceObjectByHandle(ThreadHandle,
                                               THREAD_SET_INFORMATION,
                                               PsThreadType,
                                               PreviousMode,
                                               (PVOID*)&Thread,
                                               NULL);
            if (!NT_SUCCESS(Status))
                break;

            /* Set the priority */
            KeSetPriorityThread(&Thread->Tcb, Priority);

            /* Dereference the thread */
            ObDereferenceObject(Thread);
            break;
        }

        case ThreadBasePriority:
        {
            /* Check buffer length */
            if (ThreadInformationLength != sizeof(LONG))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Use SEH for capture */
            _SEH2_TRY
            {
                /* Get the priority */
                Priority = *(PLONG)ThreadInformation;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get the exception code */
                Status = _SEH2_GetExceptionCode();
                _SEH2_YIELD(break);
            }
            _SEH2_END;

            /* Validate it */
            if ((Priority > THREAD_BASE_PRIORITY_MAX) ||
                (Priority < THREAD_BASE_PRIORITY_MIN))
            {
                /* These ones are OK */
                if ((Priority != THREAD_BASE_PRIORITY_LOWRT + 1) &&
                    (Priority != THREAD_BASE_PRIORITY_IDLE - 1))
                {
                    /* Check if the process is real time */
                    if (PsGetCurrentProcess()->PriorityClass !=
                        PROCESS_PRIORITY_CLASS_REALTIME)
                    {
                        /* It isn't, fail */
                        Status = STATUS_INVALID_PARAMETER;
                        break;
                    }
                }
            }

            /* Reference the thread */
            Status = ObReferenceObjectByHandle(ThreadHandle,
                                               THREAD_SET_INFORMATION,
                                               PsThreadType,
                                               PreviousMode,
                                               (PVOID*)&Thread,
                                               NULL);
            if (!NT_SUCCESS(Status))
                break;

            /* Set the base priority */
            KeSetBasePriorityThread(&Thread->Tcb, Priority);

            /* Dereference the thread */
            ObDereferenceObject(Thread);
            break;
        }

        case ThreadAffinityMask:
        {
            KAFFINITY Affinity = 0, CombinedAffinity;

            /* Check buffer length */
            if (ThreadInformationLength != sizeof(ULONG_PTR))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Use SEH for capture */
            _SEH2_TRY
            {
                /* Get the priority */
                Affinity = *(PULONG_PTR)ThreadInformation;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get the exception code */
                Status = _SEH2_GetExceptionCode();
                _SEH2_YIELD(break);
            }
            _SEH2_END;

            /* Validate it */
            if (!Affinity)
            {
                /* Fail */
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            /* Reference the thread */
            Status = ObReferenceObjectByHandle(ThreadHandle,
                                               THREAD_SET_INFORMATION,
                                               PsThreadType,
                                               PreviousMode,
                                               (PVOID*)&Thread,
                                               NULL);
            if (!NT_SUCCESS(Status))
                break;

            /* Get the process */
            Process = Thread->ThreadsProcess;

            /* Try to acquire rundown */
            if (ExAcquireRundownProtection(&Process->RundownProtect))
            {
                /* Lock it */
                KeEnterCriticalRegion();
                ExAcquirePushLockShared(&Process->ProcessLock);

                /* Combine masks */
                CombinedAffinity = Affinity & Process->Pcb.Affinity;
                if (CombinedAffinity != Affinity)
                {
                    /* Fail */
                    Status = STATUS_INVALID_PARAMETER;
                }
                else
                {
                    /* Set the affinity */
                    KeSetAffinityThread(&Thread->Tcb, CombinedAffinity);
                }

                /* Release the lock and rundown */
                ExReleasePushLockShared(&Process->ProcessLock);
                KeLeaveCriticalRegion();
                ExReleaseRundownProtection(&Process->RundownProtect);
            }
            else
            {
                /* Too late */
                Status = STATUS_PROCESS_IS_TERMINATING;
            }

            /* Dereference the thread */
            ObDereferenceObject(Thread);
            break;
        }

        case ThreadImpersonationToken:
        {
            HANDLE TokenHandle;

            /* Check buffer length */
            if (ThreadInformationLength != sizeof(HANDLE))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Use SEH for capture */
            _SEH2_TRY
            {
                /* Save the token handle */
                TokenHandle = *(PHANDLE)ThreadInformation;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get the exception code */
                Status = _SEH2_GetExceptionCode();
                _SEH2_YIELD(break);
            }
            _SEH2_END;

            /* Reference the thread */
            Status = ObReferenceObjectByHandle(ThreadHandle,
                                               THREAD_SET_THREAD_TOKEN,
                                               PsThreadType,
                                               PreviousMode,
                                               (PVOID*)&Thread,
                                               NULL);
            if (!NT_SUCCESS(Status))
                break;

            /* Assign the actual token */
            Status = PsAssignImpersonationToken(Thread, TokenHandle);

            /* Dereference the thread */
            ObDereferenceObject(Thread);
            break;
        }

        case ThreadQuerySetWin32StartAddress:
        {
            PVOID Address;

            /* Check buffer length */
            if (ThreadInformationLength != sizeof(ULONG_PTR))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Use SEH for capture */
            _SEH2_TRY
            {
                /* Get the priority */
                Address = *(PVOID*)ThreadInformation;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get the exception code */
                Status = _SEH2_GetExceptionCode();
                _SEH2_YIELD(break);
            }
            _SEH2_END;

            /* Reference the thread */
            Status = ObReferenceObjectByHandle(ThreadHandle,
                                               THREAD_SET_INFORMATION,
                                               PsThreadType,
                                               PreviousMode,
                                               (PVOID*)&Thread,
                                               NULL);
            if (!NT_SUCCESS(Status))
                break;

            /* Set the address */
            Thread->Win32StartAddress = Address;

            /* Dereference the thread */
            ObDereferenceObject(Thread);
            break;
        }

        case ThreadIdealProcessor:
        {
            ULONG IdealProcessor;

            /* Check buffer length: a ULONG on every architecture */
            if (ThreadInformationLength != sizeof(ULONG))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Use SEH for capture */
            _SEH2_TRY
            {
                /* Get the ideal processor */
                IdealProcessor = *(PULONG)ThreadInformation;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get the exception code */
                Status = _SEH2_GetExceptionCode();
                _SEH2_YIELD(break);
            }
            _SEH2_END;

            /* Validate it */
            if (IdealProcessor > MAXIMUM_PROCESSORS)
            {
                /* Fail */
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            /* Reference the thread */
            Status = ObReferenceObjectByHandle(ThreadHandle,
                                               THREAD_SET_INFORMATION,
                                               PsThreadType,
                                               PreviousMode,
                                               (PVOID*)&Thread,
                                               NULL);
            if (!NT_SUCCESS(Status))
                break;

            /* Set the ideal */
            Status = KeSetIdealProcessorThread(&Thread->Tcb,
                                               (CCHAR)IdealProcessor);

            /* Get the TEB and protect the thread */
            Teb = Thread->Tcb.Teb;
            if (Teb && ExAcquireRundownProtection(&Thread->RundownProtect))
            {
                /* Save the ideal processor */
                Teb->IdealProcessor = Thread->Tcb.IdealProcessor;

                /* Release rundown protection */
                ExReleaseRundownProtection(&Thread->RundownProtect);
            }

            /* Dereference the thread */
            ObDereferenceObject(Thread);
            break;
        }

        case ThreadPriorityBoost:
        {
            ULONG_PTR DisableBoost;

            /* Check buffer length */
            if (ThreadInformationLength != sizeof(ULONG_PTR))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Use SEH for capture */
            _SEH2_TRY
            {
                /* Get the priority */
                DisableBoost = *(PULONG_PTR)ThreadInformation;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get the exception code */
                Status = _SEH2_GetExceptionCode();
                _SEH2_YIELD(break);
            }
            _SEH2_END;

            /* Reference the thread */
            Status = ObReferenceObjectByHandle(ThreadHandle,
                                               THREAD_SET_INFORMATION,
                                               PsThreadType,
                                               PreviousMode,
                                               (PVOID*)&Thread,
                                               NULL);
            if (!NT_SUCCESS(Status))
                break;

            /* Call the kernel */
            KeSetDisableBoostThread(&Thread->Tcb, (BOOLEAN)DisableBoost);

            /* Dereference the thread */
            ObDereferenceObject(Thread);
            break;
        }

        case ThreadZeroTlsCell:
        {
            ULONG_PTR TlsIndex;
            PETHREAD ProcThread;
#if defined(_WIN64) && defined(BUILD_WOW64_ENABLED)
            BOOLEAN Wow64Tls;
#endif

            /* Check buffer length */
            if (ThreadInformationLength != sizeof(ULONG))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Use SEH for capture */
            _SEH2_TRY
            {
                /* Get the priority */
                TlsIndex = *(PULONG)ThreadInformation;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get the exception code */
                Status = _SEH2_GetExceptionCode();
                _SEH2_YIELD(break);
            }
            _SEH2_END;

            /* Reference the thread */
            Status = ObReferenceObjectByHandle(ThreadHandle,
                                               THREAD_SET_INFORMATION,
                                               PsThreadType,
                                               PreviousMode,
                                               (PVOID*)&Thread,
                                               NULL);
            if (!NT_SUCCESS(Status))
                break;

            /* This is only valid for the current thread */
            if (Thread != PsGetCurrentThread())
            {
                /* Fail */
                Status = STATUS_INVALID_PARAMETER;
                ObDereferenceObject(Thread);
                break;
            }

            /* Get the process */
            Process = Thread->ThreadsProcess;
#if defined(_WIN64) && defined(BUILD_WOW64_ENABLED)
            Wow64Tls = Process->Wow64Process && (TlsIndex & 0x80000000);
            if (Wow64Tls) TlsIndex &= ~0x80000000UL;
#endif

            /* Loop the threads */
            ProcThread = PsGetNextProcessThread(Process, NULL);
            while (ProcThread)
            {
                /* Acquire rundown */
                if (ExAcquireRundownProtection(&ProcThread->RundownProtect))
                {
                    /* Get the TEB */
                    Teb = ProcThread->Tcb.Teb;
                    if (Teb)
                    {
#if defined(_WIN64) && defined(BUILD_WOW64_ENABLED)
                        if (Wow64Tls)
                        {
                            PTEB32 Guest = PS_GET_TEB32_FROM_TEB(Teb);
                            _SEH2_TRY
                            {
                                if (TlsIndex < TLS_MINIMUM_AVAILABLE)
                                    Guest->TlsSlots[TlsIndex] = 0;
                                else if (TlsIndex < TLS_MINIMUM_AVAILABLE + TLS_EXPANSION_SLOTS &&
                                         Guest->TlsExpansionSlots)
                                    ((PULONG)UlongToPtr(Guest->TlsExpansionSlots))[TlsIndex - TLS_MINIMUM_AVAILABLE] = 0;
                            }
                            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) { Status = _SEH2_GetExceptionCode(); }
                            _SEH2_END;
                        }
                        else
#endif
                        {
                            PVOID *ExpansionSlots;
                            PVOID *Slot;

                            /* The TEB is user memory and TlsExpansionSlots is
                               user controlled: probe the selected slot and wrap
                               the writes in SEH so a bad pointer cannot fault in
                               the kernel or be used for a kernel write. */
                            _SEH2_TRY
                            {
                                /* Check if we're in the expansion range */
                                if (TlsIndex > TLS_MINIMUM_AVAILABLE - 1)
                                {
                                    if (TlsIndex < (TLS_MINIMUM_AVAILABLE +
                                                    TLS_EXPANSION_SLOTS) - 1)
                                    {
                                        /* Capture the expansion vector first */
                                        ExpansionSlots = Teb->TlsExpansionSlots;
                                        if (ExpansionSlots)
                                        {
                                            /* Probe and clear the index */
                                            Slot = &ExpansionSlots[TlsIndex - TLS_MINIMUM_AVAILABLE];
                                            ProbeForWrite(Slot, sizeof(PVOID), sizeof(PVOID));
                                            *Slot = NULL;
                                        }
                                    }
                                }
                                else
                                {
                                    /* Probe and clear the index */
                                    ProbeForWrite(&Teb->TlsSlots[TlsIndex],
                                                  sizeof(PVOID), sizeof(PVOID));
                                    Teb->TlsSlots[TlsIndex] = NULL;
                                }
                            }
                            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                            {
                                Status = _SEH2_GetExceptionCode();
                            }
                            _SEH2_END;
                        }
                    }

                    /* Release rundown */
                    ExReleaseRundownProtection(&ProcThread->RundownProtect);
                }

                /* Go to the next thread */
                ProcThread = PsGetNextProcessThread(Process, ProcThread);
            }

            /* Dereference the thread */
            ObDereferenceObject(Thread);
            break;
        }

        case ThreadBreakOnTermination:
        {
            ULONG Break;

            /* Check buffer length */
            if (ThreadInformationLength != sizeof(ULONG))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Enter SEH for direct buffer read */
            _SEH2_TRY
            {
                Break = *(PULONG)ThreadInformation;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get exception code */
                Break = 0;
                Status = _SEH2_GetExceptionCode();
                _SEH2_YIELD(break);
            }
            _SEH2_END;

            /* Setting 'break on termination' requires the SeDebugPrivilege */
            if (!SeSinglePrivilegeCheck(SeDebugPrivilege, PreviousMode))
            {
                /* We don't hold the privilege, bail out */
                Status = STATUS_PRIVILEGE_NOT_HELD;
                break;
            }

            /* Reference the thread */
            Status = ObReferenceObjectByHandle(ThreadHandle,
                                               THREAD_SET_INFORMATION,
                                               PsThreadType,
                                               PreviousMode,
                                               (PVOID*)&Thread,
                                               NULL);
            if (!NT_SUCCESS(Status))
                break;

            /* Set or clear the flag */
            if (Break)
            {
                PspSetCrossThreadFlag(Thread, CT_BREAK_ON_TERMINATION_BIT);
            }
            else
            {
                PspClearCrossThreadFlag(Thread, CT_BREAK_ON_TERMINATION_BIT);
            }

            /* Dereference the thread */
            ObDereferenceObject(Thread);
            break;
        }

        case ThreadHideFromDebugger:
        {
            /* Check buffer length */
            if (ThreadInformationLength != 0)
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Reference the thread */
            Status = ObReferenceObjectByHandle(ThreadHandle,
                                               THREAD_SET_INFORMATION,
                                               PsThreadType,
                                               PreviousMode,
                                               (PVOID*)&Thread,
                                               NULL);
            if (!NT_SUCCESS(Status))
                break;

            /* Set the flag */
            PspSetCrossThreadFlag(Thread, CT_HIDE_FROM_DEBUGGER_BIT);

            /* Dereference the thread */
            ObDereferenceObject(Thread);
            break;
        }

#if (NTDDI_VERSION >= NTDDI_WIN10_RS1) || defined(__REACTOS__)
        case ThreadNameInformation:
        {
            UNICODE_STRING CapturedThreadName;
            PUNICODE_STRING NewThreadName;

            /* Check buffer length */
            if (ThreadInformationLength != sizeof(UNICODE_STRING))
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Reference the thread.
             * NOTE: Win10+ uses THREAD_SET_LIMITED_INFORMATION instead;
             * however some tools misuse thread names to perform suspicious
             * operations; therefore we try to mess with these by requiring
             * a bit more of access rights. */
            Status = ObReferenceObjectByHandle(ThreadHandle,
                                               THREAD_SET_INFORMATION,
                                               PsThreadType,
                                               PreviousMode,
                                               (PVOID*)&Thread,
                                               NULL);
            if (!NT_SUCCESS(Status))
                break;

            /* Probe and capture the thread name */
            Status = ProbeAndCaptureUnicodeString(&CapturedThreadName,
                                                  PreviousMode,
                                                  (PUNICODE_STRING)ThreadInformation);
            if (!NT_SUCCESS(Status))
            {
                ObDereferenceObject(Thread);
                break;
            }

            /* Allocate a new buffer only if the thread name isn't empty
             * (REMARK: We only consider Length instead of MaximumLength).
             * If empty, just reset the thread name pointer to NULL instead
             * of allocating an empty UNICODE_STRING. */
            NewThreadName = NULL;
            if (CapturedThreadName.Length > 0)
            {
                ULONG Length = sizeof(UNICODE_STRING) + CapturedThreadName.Length;
                NewThreadName = ExAllocatePoolWithTag(NonPagedPool, // FIXME: NonPagedPoolNx
                                                      Length, TAG_THREAD_NAME);
                if (!NewThreadName)
                {
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                }
                else
                {
                    /* Copy the new thread name */
                    NewThreadName->Length =
                    NewThreadName->MaximumLength = CapturedThreadName.Length;
                    NewThreadName->Buffer = (PWCH)(NewThreadName + 1);
                    RtlCopyMemory(NewThreadName->Buffer,
                                  CapturedThreadName.Buffer,
                                  CapturedThreadName.Length);
                }
            }

            /* Free the captured string */
            ReleaseCapturedUnicodeString(&CapturedThreadName, PreviousMode);

            /* Replace the original thread name with the new one */
            if (NT_SUCCESS(Status))
            {
                PUNICODE_STRING OldThreadName;
                PspLockThreadSecurityExclusive(Thread);
                OldThreadName = Thread->ThreadName;
                Thread->ThreadName = NewThreadName;
                PspUnlockThreadSecurityExclusive(Thread);

                /* Free the old thread name */
                if (OldThreadName)
                    ExFreePoolWithTag(OldThreadName, TAG_THREAD_NAME);
            }

            /* Dereference the thread */
            ObDereferenceObject(Thread);
            break;
        }
#endif /* (NTDDI_VERSION >= NTDDI_WIN10_RS1) || defined(__REACTOS__) */

        /* Anything else */
        default:
            /* Vista+ classes known to PsThreadInfoClass */
            if (ThreadInformationClass >= ThreadIoPriority)
            {
                Status = PspSetThreadInfoVista(ThreadHandle,
                                               ThreadInformationClass,
                                               ThreadInformation,
                                               ThreadInformationLength,
                                               PreviousMode);
                break;
            }

            /* Not yet implemented */
#if DBG
            DPRINT1("Not implemented: %s\n", PspDumpThreadInfoClassName(ThreadInformationClass));
#endif
            Status = STATUS_NOT_IMPLEMENTED;
    }

    return Status;
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
NtQueryInformationThread(
    _In_ HANDLE ThreadHandle,
    _In_ THREADINFOCLASS ThreadInformationClass,
    _Out_writes_bytes_to_opt_(ThreadInformationLength, *ReturnLength)
        PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength)
{
    PETHREAD Thread;
    PEPROCESS Process;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    NTSTATUS Status;
    ULONG Length = 0;
    BOOLEAN DescriptorFailed = FALSE;

    PAGED_CODE();

    /* Reject Vista+ classes on an older NT version identity */
    if (!PspIsThreadInfoClassAvailable(ThreadInformationClass, FALSE))
        return STATUS_INVALID_INFO_CLASS;

    /* Validate the information class */
    Status = DefaultQueryInfoBufferCheck(ThreadInformationClass,
                                         PsThreadInfoClass,
                                         RTL_NUMBER_OF(PsThreadInfoClass),
                                         ICIF_PROBE_READ,
                                         ThreadInformation,
                                         ThreadInformationLength,
                                         ReturnLength,
                                         NULL,
                                         PreviousMode);
    if (!NT_SUCCESS(Status))
    {
#if DBG
        DPRINT1("NtQueryInformationThread(ThreadInformationClass: %s): Class validation failed! (Status: 0x%lx)\n",
                PspDumpThreadInfoClassName(ThreadInformationClass), Status);
#endif
        return Status;
    }

    /* Check what kind of information class this is */
    switch (ThreadInformationClass)
    {
#if defined(_M_AMD64) && defined(BUILD_WOW64_ENABLED)
        case ThreadWow64Context:
            Status = PspWow64ContextThread(ThreadHandle, ThreadInformation,
                                           ThreadInformationLength, FALSE, PreviousMode);
            if (NT_SUCCESS(Status)) Length = sizeof(WOW64_CONTEXT);
            break;
#endif
        /* Basic thread information */
        case ThreadBasicInformation:
        {
            PTHREAD_BASIC_INFORMATION ThreadBasicInfo =
                (PTHREAD_BASIC_INFORMATION)ThreadInformation;

            /* Set the return length */
            Length = sizeof(THREAD_BASIC_INFORMATION);

            if (ThreadInformationLength != Length)
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Reference the thread */
            Status = ObReferenceObjectByHandle(ThreadHandle,
                                               THREAD_QUERY_LIMITED_INFORMATION,
                                               PsThreadType,
                                               PreviousMode,
                                               (PVOID*)&Thread,
                                               NULL);
            if (!NT_SUCCESS(Status))
                break;

            /* Protect writes with SEH */
            _SEH2_TRY
            {
                /* Write all the information from the ETHREAD/KTHREAD */
                ThreadBasicInfo->ExitStatus = Thread->ExitStatus;
                ThreadBasicInfo->TebBaseAddress = (PVOID)Thread->Tcb.Teb;
                ThreadBasicInfo->ClientId = Thread->Cid;
                ThreadBasicInfo->AffinityMask = Thread->Tcb.Affinity;
                ThreadBasicInfo->Priority = Thread->Tcb.Priority;
                ThreadBasicInfo->BasePriority = KeQueryBasePriorityThread(&Thread->Tcb);
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get exception code */
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;

            /* Dereference the thread */
            ObDereferenceObject(Thread);
            break;
        }

        /* Thread time information */
        case ThreadTimes:
        {
            PKERNEL_USER_TIMES ThreadTime = (PKERNEL_USER_TIMES)ThreadInformation;

            /* Set the return length */
            Length = sizeof(KERNEL_USER_TIMES);

            if (ThreadInformationLength != Length)
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Reference the thread */
            Status = ObReferenceObjectByHandle(ThreadHandle,
                                               THREAD_QUERY_LIMITED_INFORMATION,
                                               PsThreadType,
                                               PreviousMode,
                                               (PVOID*)&Thread,
                                               NULL);
            if (!NT_SUCCESS(Status))
                break;

            /* Protect writes with SEH */
            _SEH2_TRY
            {
                /* Copy time information from ETHREAD/KTHREAD */
                ThreadTime->KernelTime.QuadPart = Thread->Tcb.KernelTime * KeMaximumIncrement;
                ThreadTime->UserTime.QuadPart = Thread->Tcb.UserTime * KeMaximumIncrement;
                ThreadTime->CreateTime = Thread->CreateTime;

                /* Exit time is in a union and only valid on actual exit! */
                if (KeReadStateThread(&Thread->Tcb))
                {
                    ThreadTime->ExitTime = Thread->ExitTime;
                }
                else
                {
                    ThreadTime->ExitTime.QuadPart = 0;
                }
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get exception code */
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;

            /* Dereference the thread */
            ObDereferenceObject(Thread);
            break;
        }

        case ThreadCycleTime:
        {
            PTHREAD_CYCLE_TIME_INFORMATION CycleTimeInfo = ThreadInformation;
            ULONG64 CycleTime, CycleTimeStamp;

            /* Set the return length */
            Length = sizeof(THREAD_CYCLE_TIME_INFORMATION);

            if (ThreadInformationLength != Length)
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Reference the thread */
            Status = ObReferenceObjectByHandle(ThreadHandle,
                                               THREAD_QUERY_LIMITED_INFORMATION,
                                               PsThreadType,
                                               PreviousMode,
                                               (PVOID*)&Thread,
                                               NULL);
            if (!NT_SUCCESS(Status))
                break;

            CycleTime = KeQueryTotalCycleTimeThread(&Thread->Tcb, &CycleTimeStamp);

            /* Dereference the thread */
            ObDereferenceObject(Thread);

            /* Protect writes with SEH */
            _SEH2_TRY
            {
                CycleTimeInfo->AccumulatedCycles = CycleTime;
                CycleTimeInfo->CurrentCycleCount = CycleTimeStamp;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get exception code */
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;
            break;
        }

        case ThreadQuerySetWin32StartAddress:
        {
            /* Set the return length*/
            Length = sizeof(PVOID);

            if (ThreadInformationLength != Length)
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Reference the thread */
            Status = ObReferenceObjectByHandle(ThreadHandle,
                                               THREAD_QUERY_INFORMATION,
                                               PsThreadType,
                                               PreviousMode,
                                               (PVOID*)&Thread,
                                               NULL);
            if (!NT_SUCCESS(Status))
                break;

            /* Protect write with SEH */
            _SEH2_TRY
            {
                /* Return the Win32 Start Address */
                *(PVOID*)ThreadInformation = Thread->Win32StartAddress;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get exception code */
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;

            /* Dereference the thread */
            ObDereferenceObject(Thread);
            break;
        }

        case ThreadPerformanceCount:
        {
            /* Set the return length*/
            Length = sizeof(LARGE_INTEGER);

            if (ThreadInformationLength != Length)
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Reference the thread */
            Status = ObReferenceObjectByHandle(ThreadHandle,
                                               THREAD_QUERY_INFORMATION,
                                               PsThreadType,
                                               PreviousMode,
                                               (PVOID*)&Thread,
                                               NULL);
            if (!NT_SUCCESS(Status))
                break;

            /* Protect write with SEH */
            _SEH2_TRY
            {
                /* FIXME */
                (*(PLARGE_INTEGER)ThreadInformation).QuadPart = 0;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get exception code */
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;

            /* Dereference the thread */
            ObDereferenceObject(Thread);
            break;
        }

        case ThreadAmILastThread:
        {
            /* Set the return length*/
            Length = sizeof(ULONG);

            if (ThreadInformationLength != Length)
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* This info class always refers to the current thread! */
            Thread = PsGetCurrentThread();
            Process = PsGetThreadProcess(Thread);

            /* Protect write with SEH */
            _SEH2_TRY
            {
                /* Return whether or not we are the last thread */
                *(PULONG)ThreadInformation = Process->ActiveThreads == 1;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get exception code */
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;

            break;
        }

        case ThreadIsIoPending:
        {
            KIRQL OldIrql;

            /* Set the return length*/
            Length = sizeof(ULONG);

            if (ThreadInformationLength != Length)
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Reference the thread */
            Status = ObReferenceObjectByHandle(ThreadHandle,
                                               THREAD_QUERY_INFORMATION,
                                               PsThreadType,
                                               PreviousMode,
                                               (PVOID*)&Thread,
                                               NULL);
            if (!NT_SUCCESS(Status))
                break;

            /* Raise the IRQL to protect the IRP list */
            KeRaiseIrql(APC_LEVEL, &OldIrql);

            /* Protect write with SEH */
            _SEH2_TRY
            {
                /* Check if the IRP list is empty or not */
                *(PULONG)ThreadInformation = !IsListEmpty(&Thread->IrpList);
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get exception code */
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;

            /* Lower IRQL back */
            KeLowerIrql(OldIrql);

            /* Dereference the thread */
            ObDereferenceObject(Thread);
            break;
        }

        /* LDT and GDT information */
        case ThreadDescriptorTableEntry:
        {
#if defined(_X86_)
            /* Reference the thread */
            Status = ObReferenceObjectByHandle(ThreadHandle,
                                               THREAD_QUERY_INFORMATION,
                                               PsThreadType,
                                               PreviousMode,
                                               (PVOID*)&Thread,
                                               NULL);
            if (!NT_SUCCESS(Status))
                break;

            /* Call the worker routine */
            Status = PspQueryDescriptorThread(Thread,
                                              ThreadInformation,
                                              ThreadInformationLength,
                                              ReturnLength);

            /* Dereference the thread */
            ObDereferenceObject(Thread);

            /* NT reports the size of the descriptor on success only */
            if (NT_SUCCESS(Status)) Length = sizeof(LDT_ENTRY);
            else DescriptorFailed = TRUE;
#else
            /* Only implemented on x86 */
            Status = STATUS_NOT_IMPLEMENTED;
#endif
            break;
        }

        case ThreadPriorityBoost:
        {
            /* Set the return length*/
            Length = sizeof(ULONG);

            if (ThreadInformationLength != Length)
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Reference the thread */
            Status = ObReferenceObjectByHandle(ThreadHandle,
                                               THREAD_QUERY_LIMITED_INFORMATION,
                                               PsThreadType,
                                               PreviousMode,
                                               (PVOID*)&Thread,
                                               NULL);
            if (!NT_SUCCESS(Status))
                break;

            _SEH2_TRY
            {
                *(PULONG)ThreadInformation = Thread->Tcb.DisableBoost ? 1 : 0;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;

            /* Dereference the thread */
            ObDereferenceObject(Thread);
            break;
        }

#if (NTDDI_VERSION >= NTDDI_VISTA) || defined(__REACTOS__)
        case ThreadHideFromDebugger:
        {
            /* Set the return length */
            Length = sizeof(BOOLEAN);

            if (ThreadInformationLength != Length)
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Reference the thread */
            Status = ObReferenceObjectByHandle(ThreadHandle,
                                               THREAD_QUERY_INFORMATION,
                                               PsThreadType,
                                               PreviousMode,
                                               (PVOID*)&Thread,
                                               NULL);
            if (!NT_SUCCESS(Status))
                break;

            /* Protect write with SEH */
            _SEH2_TRY
            {
                *(PBOOLEAN)ThreadInformation = Thread->HideFromDebugger;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get exception code */
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;

            /* Dereference the thread */
            ObDereferenceObject(Thread);
            break;
        }
#endif /* (NTDDI_VERSION >= NTDDI_VISTA) */

        case ThreadBreakOnTermination:
        {
            /* Set the return length */
            Length = sizeof(ULONG);

            if (ThreadInformationLength != Length)
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Reference the thread */
            Status = ObReferenceObjectByHandle(ThreadHandle,
                                               THREAD_QUERY_INFORMATION,
                                               PsThreadType,
                                               PreviousMode,
                                               (PVOID*)&Thread,
                                               NULL);
            if (!NT_SUCCESS(Status))
                break;

            _SEH2_TRY
            {
                *(PULONG)ThreadInformation = Thread->BreakOnTermination;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;

            /* Dereference the thread */
            ObDereferenceObject(Thread);
            break;
        }

        case ThreadIsTerminated:
        {
            ULONG ThreadTerminated;

            /* Set the return length*/
            Length = sizeof(ThreadTerminated);

            if (ThreadInformationLength != Length)
            {
                Status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            /* Reference the thread */
            Status = ObReferenceObjectByHandle(ThreadHandle,
                                               THREAD_QUERY_LIMITED_INFORMATION,
                                               PsThreadType,
                                               PreviousMode,
                                               (PVOID*)&Thread,
                                               NULL);
            if (!NT_SUCCESS(Status))
                break;

            ThreadTerminated = PsIsThreadTerminating(Thread);

            _SEH2_TRY
            {
                *(PULONG)ThreadInformation = ThreadTerminated ? 1 : 0;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;

            /* Dereference the thread */
            ObDereferenceObject(Thread);
            break;
        }

#if (NTDDI_VERSION >= NTDDI_WIN10_RS1) || defined(__REACTOS__)
        case ThreadNameInformation:
        {
            PUNICODE_STRING ThreadName;

            /* Reference the thread */
            Status = ObReferenceObjectByHandle(ThreadHandle,
                                               THREAD_QUERY_LIMITED_INFORMATION,
                                               PsThreadType,
                                               PreviousMode,
                                               (PVOID*)&Thread,
                                               NULL);
            if (!NT_SUCCESS(Status))
                break;

            PspLockThreadSecurityShared(Thread);

            ThreadName = Thread->ThreadName;

            /* Set the return length (REMARK: We only
             * consider Length instead of MaximumLength) */
            Length = sizeof(UNICODE_STRING);
            Length += (ThreadName ? ThreadName->Length : 0);
            if (ThreadInformationLength < Length)
            {
                PspUnlockThreadSecurityShared(Thread);
                ObDereferenceObject(Thread);
                Status = STATUS_BUFFER_TOO_SMALL;
                /* As on Windows, and *not* STATUS_INFO_LENGTH_MISMATCH */
                break;
            }

            /* Protect writes with SEH */
            _SEH2_TRY
            {
                PTHREAD_NAME_INFORMATION NameInfo =
                    (PTHREAD_NAME_INFORMATION)ThreadInformation;
                if (ThreadName && (ThreadName->Length > 0))
                {
                    NameInfo->ThreadName.Length =
                    NameInfo->ThreadName.MaximumLength = ThreadName->Length;
                    NameInfo->ThreadName.Buffer = (PWCH)(&NameInfo->ThreadName + 1);
                    RtlCopyMemory(NameInfo->ThreadName.Buffer,
                                  ThreadName->Buffer,
                                  ThreadName->Length);
                }
                else
                {
                    RtlInitEmptyUnicodeString(&NameInfo->ThreadName, NULL, 0);
                }
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Get exception code */
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;

            PspUnlockThreadSecurityShared(Thread);

            /* Dereference the thread */
            ObDereferenceObject(Thread);
            break;
        }
#endif /* (NTDDI_VERSION >= NTDDI_WIN10_RS1) || defined(__REACTOS__) */

        /* Anything else */
        default:
            /* Vista+ classes known to PsThreadInfoClass */
            if (ThreadInformationClass >= ThreadIoPriority)
            {
                Status = PspQueryThreadInfoVista(ThreadHandle,
                                                 ThreadInformationClass,
                                                 ThreadInformation,
                                                 ThreadInformationLength,
                                                 &Length,
                                                 PreviousMode);
                break;
            }

            /* Not yet implemented */
#if DBG
            DPRINT1("Not implemented: %s\n", PspDumpThreadInfoClassName(ThreadInformationClass));
#endif
            Status = STATUS_NOT_IMPLEMENTED;
    }

    /* Protect write with SEH */
    _SEH2_TRY
    {
        /* Check if caller wanted return length (ThreadDescriptorTableEntry leaves it alone on failure) */
        if (ReturnLength && !DescriptorFailed) *ReturnLength = Length;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        /* Get exception code */
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;

    return Status;
}

/* EOF */
