/*
 * PROJECT:     ReactOS SDK
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Random bytes from the system generator for native programs and static libraries
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Setup and the file system formatters are native programs without advapi32, so they cannot call
 * RtlGenRandom (SystemFunction036). This asks the system generator in ksecdd.sys the way advapi32 does
 * (IOCTL_KSEC_RANDOM_FILL_BUFFER = CTL_CODE(FILE_DEVICE_KSEC, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)).
 * The includer has the NDK (NtOpenFile, NtDeviceIoControlFile, NtClose).
 */

#pragma once

#define ROS_IOCTL_KSEC_RANDOM_FILL_BUFFER 0x00390008

/* TRUE when Buffer holds Length bytes of the system generator. FALSE leaves the buffer alone: the caller keeps its
   old source as the fall-back that cannot fail (the driver is not there in the very early boot or in a minimal PE). */
static __inline
BOOLEAN
RosSystemRandom(
    _Out_writes_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length)
{
    UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\KsecDD");
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    HANDLE Handle;
    NTSTATUS Status;

    if (Length == 0)
        return TRUE;

    InitializeObjectAttributes(&ObjectAttributes, &DeviceName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenFile(&Handle,
                        FILE_READ_DATA | SYNCHRONIZE,
                        &ObjectAttributes,
                        &IoStatusBlock,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(Status))
        return FALSE;

    Status = NtDeviceIoControlFile(Handle,
                                   NULL,
                                   NULL,
                                   NULL,
                                   &IoStatusBlock,
                                   ROS_IOCTL_KSEC_RANDOM_FILL_BUFFER,
                                   NULL,
                                   0,
                                   Buffer,
                                   Length);
    NtClose(Handle);
    return NT_SUCCESS(Status);
}
