/*
 * PROJECT:     ReactOS system libraries
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     CompareObjectHandles, exported by kernelbase and not by kernel32, as on Windows
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <stdarg.h>
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winternl.h>

/*
 * TRUE when both handles refer to the same kernel object, whatever the access they were opened with. FALSE with
 * ERROR_NOT_SAME_OBJECT when they do not, with ERROR_INVALID_HANDLE when either is not a valid handle.
 */
BOOL
WINAPI
CompareObjectHandles(
    _In_ HANDLE hFirstObjectHandle,
    _In_ HANDLE hSecondObjectHandle)
{
    NTSTATUS Status;

    Status = NtCompareObjects(hFirstObjectHandle, hSecondObjectHandle);
    if (Status != STATUS_SUCCESS)
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}
