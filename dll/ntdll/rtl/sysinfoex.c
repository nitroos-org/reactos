/*
 * PROJECT:     ReactOS NT User Mode Library
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     NtQuerySystemInformationEx (Windows 7 and later)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The kernel has no such service, so this answers in user mode. The only class that has an answer is
 * SystemSupportedProcessorArchitectures, which is what IsWow64Process2 style callers and Wine's ntdll
 * wow64 test ask for. Every other class fails with STATUS_INVALID_INFO_CLASS, as Windows does for a
 * class it does not know, instead of the "success without touching the buffer" of the old export stub.
 */

#include <ntdll.h>

#define NDEBUG
#include <debug.h>

#define MAX_ARCHITECTURES 3

NTSYSAPI
NTSTATUS
NTAPI
RtlWow64GetProcessMachines(
    _In_ HANDLE ProcessHandle,
    _Out_ PUSHORT ProcessMachine,
    _Out_opt_ PUSHORT NativeMachine);

/* SystemSupportedProcessorArchitectures; the NDK declares it for Windows 10 headers only */
#define SYSTEM_INFO_CLASS_SUPPORTED_ARCHITECTURES 181

static
ULONG
RtlpAddArchitecture(
    _Inout_updates_(MAX_ARCHITECTURES) SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION* Machines,
    _In_ ULONG Count,
    _In_ USHORT Machine,
    _In_ BOOLEAN IsNative,
    _In_ BOOLEAN KernelMode,
    _In_ USHORT ProcessMachine)
{
    SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION* Entry = &Machines[Count];

    RtlZeroMemory(Entry, sizeof(*Entry));
    Entry->Machine = Machine;
    Entry->KernelMode = KernelMode;
    Entry->UserMode = TRUE;
    Entry->Native = IsNative;
    Entry->Process = (Machine == ProcessMachine);
    return Count + 1;
}

static
NTSTATUS
RtlpQuerySupportedArchitectures(
    _In_reads_bytes_(InputLength) PVOID Input,
    _In_ ULONG InputLength,
    _Out_writes_bytes_to_opt_(OutputLength, *ReturnLength) PVOID Output,
    _In_ ULONG OutputLength,
    _Out_opt_ PULONG ReturnLength)
{
    SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION Machines[MAX_ARCHITECTURES + 1];
    USHORT ProcessMachine = 0, NativeMachine;
    HANDLE ProcessHandle;
    NTSTATUS Status;
    ULONG Count = 0, Size;

    if ((Input == NULL) || (InputLength != sizeof(HANDLE)))
    {
        return STATUS_INVALID_PARAMETER;
    }

    _SEH2_TRY
    {
        ProcessHandle = *(HANDLE*)Input;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    _SEH2_END;

    /* A zero handle asks about no particular process: nothing gets the Process flag */
    if (ProcessHandle != NULL)
    {
        /* The query validates the handle and needs PROCESS_QUERY_LIMITED_INFORMATION */
        Status = RtlWow64GetProcessMachines(ProcessHandle, &ProcessMachine, &NativeMachine);
        if (!NT_SUCCESS(Status))
        {
            return Status;
        }

        /* A native process answers 0: it runs as the machine the kernel runs on */
        if (ProcessMachine == IMAGE_FILE_MACHINE_UNKNOWN)
        {
            ProcessMachine = NativeMachine;
        }
    }

    /* The kernel's own architecture is first */
    NativeMachine = SharedUserData->ImageNumberLow;
    Count = RtlpAddArchitecture(Machines, Count, NativeMachine, TRUE, TRUE, ProcessMachine);

    /* An AMD64 kernel also runs i386 code when WOW64 is there; a process that already is one proves it */
#ifdef BUILD_WOW64_ENABLED
    if (NativeMachine == IMAGE_FILE_MACHINE_AMD64)
#else
    if ((NativeMachine == IMAGE_FILE_MACHINE_AMD64) && (ProcessMachine == IMAGE_FILE_MACHINE_I386))
#endif
    {
        Count = RtlpAddArchitecture(Machines, Count, IMAGE_FILE_MACHINE_I386, FALSE, FALSE, ProcessMachine);
    }

    /* The list ends with a zero entry */
    RtlZeroMemory(&Machines[Count], sizeof(Machines[Count]));
    Size = (Count + 1) * sizeof(Machines[0]);

    _SEH2_TRY
    {
        if (ReturnLength != NULL)
        {
            *ReturnLength = Size;
        }

        if (OutputLength < Size)
        {
            _SEH2_YIELD(return STATUS_BUFFER_TOO_SMALL);
        }

        RtlCopyMemory(Output, Machines, Size);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    _SEH2_END;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
NtQuerySystemInformationEx(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _In_reads_bytes_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(SystemInformationLength, *ReturnLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength)
{
    switch ((ULONG)SystemInformationClass)
    {
        case SYSTEM_INFO_CLASS_SUPPORTED_ARCHITECTURES:
            return RtlpQuerySupportedArchitectures(InputBuffer,
                                                   InputBufferLength,
                                                   SystemInformation,
                                                   SystemInformationLength,
                                                   ReturnLength);

        default:
            DPRINT1("NtQuerySystemInformationEx: class %lu is not implemented\n", (ULONG)SystemInformationClass);
            return STATUS_INVALID_INFO_CLASS;
    }
}
