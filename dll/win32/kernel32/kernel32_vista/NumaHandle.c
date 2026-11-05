/*
 * PROJECT:     ReactOS system libraries
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     GetNumaNodeNumberFromHandle, GetNumaProximityNodeEx and GetNumaAvailableMemoryNodeEx
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows 10 22H2 (x64 and x86, one NUMA node):
 *  - GetNumaNodeNumberFromHandle: a file handle gives node 0; a handle of any other kind (event, I/O completion port,
 *    process) or no handle gives ERROR_INVALID_HANDLE and leaves the node alone.
 *  - GetNumaProximityNodeEx: the proximity domain 0 is node 0; every other one is ERROR_NOT_FOUND and leaves the node alone.
 *  - GetNumaAvailableMemoryNodeEx: node 0 gives the available bytes; any other node is ERROR_INVALID_PARAMETER.
 * The node and the byte count are written only on success. This system has one node.
 */

#include "k32_vista.h"

BOOL WINAPI GetNumaAvailableMemoryNode(_In_ UCHAR Node, _Out_ PULONGLONG AvailableBytes);

#define NDEBUG
#include <debug.h>

BOOL
WINAPI
GetNumaNodeNumberFromHandle(
    _In_ HANDLE hFile,
    _Out_ PUSHORT NodeNumber)
{
    IO_STATUS_BLOCK IoStatusBlock;
    FILE_MODE_INFORMATION ModeInformation;
    NTSTATUS Status;

    /* Only a file object answers a file query; the other kinds fail with a type mismatch, which maps to ERROR_INVALID_HANDLE */
    Status = NtQueryInformationFile(hFile, &IoStatusBlock, &ModeInformation, sizeof(ModeInformation), FileModeInformation);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    *NodeNumber = 0;
    return TRUE;
}

BOOL
WINAPI
GetNumaProximityNodeEx(
    _In_ ULONG ProximityId,
    _Out_ PUSHORT NodeNumber)
{
    if (ProximityId != 0)
    {
        SetLastError(ERROR_NOT_FOUND);
        return FALSE;
    }

    *NodeNumber = 0;
    return TRUE;
}

BOOL
WINAPI
GetNumaAvailableMemoryNodeEx(
    _In_ USHORT Node,
    _Out_ PULONGLONG AvailableBytes)
{
    if (Node > 0xFF)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    return GetNumaAvailableMemoryNode((UCHAR)Node, AvailableBytes);
}
