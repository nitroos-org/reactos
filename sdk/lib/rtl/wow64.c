/*
 * PROJECT:     ReactOS runtime library (RTL)
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Implementation of RtlWow64GetProcessMachines
 * COPYRIGHT:   Copyright 2026 Timo Kreuzer <timo.kreuzer@reactos.org>
 */

/* INCLUDES *****************************************************************/

#include <rtl.h>

#define NDEBUG
#include <debug.h>

NTSTATUS
NTAPI
RtlWow64GetProcessMachines(
    _In_ HANDLE ProcessHandle,
    _Out_ PUSHORT ProcessMachine,
    _Out_opt_ PUSHORT NativeMachine)
{
    NTSTATUS Status;
    ULONG_PTR Wow64Info = 0;

    /* A NULL handle is not rejected, it reads as a native process (Windows 10 does the same).
       Every other handle, the current process pseudo handle included, is validated by the
       query: a bad handle, a thread or other object handle and a handle without
       PROCESS_QUERY_LIMITED_INFORMATION fail, and nothing is written to the outputs then. */
    if (ProcessHandle != NULL)
    {
        Status = NtQueryInformationProcess(ProcessHandle,
                                           ProcessWow64Information,
                                           &Wow64Info,
                                           sizeof(Wow64Info),
                                           NULL);
        if (!NT_SUCCESS(Status))
        {
            return Status;
        }
    }

    /* The only guest machine is i386. A native process reports 0 (IMAGE_FILE_MACHINE_UNKNOWN) */
    *ProcessMachine = Wow64Info ? IMAGE_FILE_MACHINE_I386 : IMAGE_FILE_MACHINE_UNKNOWN;

    if (NativeMachine != NULL)
    {
        /* The kernel stores it's native architecture in this field */
        *NativeMachine = SharedUserData->ImageNumberLow;
    }

    return STATUS_SUCCESS;
}
