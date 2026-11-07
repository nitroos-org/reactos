/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1+ (https://spdx.org/licenses/LGPL-2.1+)
 * PURPOSE:     Contract test: IOCTL_TCP_SET_INFORMATION_EX whose BufferSize names more option bytes than
 *              the input holds is refused with STATUS_INVALID_PARAMETER before any handler reads them.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */

#include "precomp.h"
#include <tdiinfo.h>

static
NTSTATUS
G7Ioctl(
    _In_ HANDLE File,
    _In_ ULONG Code,
    _In_opt_ PVOID In,
    _In_ ULONG InLen,
    _In_opt_ PVOID Out,
    _In_ ULONG OutLen,
    _Out_opt_ PULONG_PTR Information)
{
    NTSTATUS Status;
    IO_STATUS_BLOCK Iosb;
    HANDLE Event;
    LARGE_INTEGER Timeout;

    Status = NtCreateEvent(&Event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
    if (!NT_SUCCESS(Status))
        return Status;
    Iosb.Status = STATUS_PENDING;
    Iosb.Information = 0;
    Status = NtDeviceIoControlFile(File, Event, NULL, NULL, &Iosb, Code, In, InLen, Out, OutLen);
    if (Status == STATUS_PENDING)
    {
        Timeout.QuadPart = -10000000LL * 10;
        if (NtWaitForSingleObject(Event, FALSE, &Timeout) != STATUS_WAIT_0)
        {
            NtCancelIoFile(File, &Iosb);
            NtWaitForSingleObject(Event, FALSE, NULL);
        }
        Status = Iosb.Status;
    }
    if (Information)
        *Information = Iosb.Information;
    NtClose(Event);
    return Status;
}

static
NTSTATUS
G7OpenDevice(
    _In_ PCWSTR Name,
    _Out_ PHANDLE Handle)
{
    UNICODE_STRING Us;
    OBJECT_ATTRIBUTES Oa;
    IO_STATUS_BLOCK Iosb;

    RtlInitUnicodeString(&Us, Name);
    InitializeObjectAttributes(&Oa, &Us, OBJ_CASE_INSENSITIVE, NULL, NULL);
    return NtCreateFile(Handle, FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE, &Oa, &Iosb,
                        NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, NULL, 0);
}

START_TEST(g7setinfoex)
{
    HANDLE Tcp;
    NTSTATUS Status;
    PTCP_REQUEST_SET_INFORMATION_EX Req;
    ULONG Size = FIELD_OFFSET(TCP_REQUEST_SET_INFORMATION_EX, Buffer) + sizeof(ULONG);

    /* SET_INFORMATION_EX: the option bytes it names must be inside the input */
    Status = G7OpenDevice(L"\\Device\\Tcp", &Tcp);
    ok(Status == STATUS_SUCCESS, "open \\Device\\Tcp gave 0x%lx\n", Status);
    if (!NT_SUCCESS(Status))
        return;
    Req = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, Size);
    Req->ID.toi_class = INFO_CLASS_PROTOCOL;
    Req->ID.toi_type = INFO_TYPE_ADDRESS_OBJECT;
    Req->ID.toi_id = AO_OPTION_TTL;
    Req->BufferSize = 0x1000;
    Status = G7Ioctl(Tcp, IOCTL_TCP_SET_INFORMATION_EX, Req, Size, NULL, 0, NULL);
    ok(Status == STATUS_INVALID_PARAMETER, "SET_INFORMATION_EX with BufferSize 0x1000 in %lu bytes gave 0x%lx\n", Size, Status);
    Req->BufferSize = 0xffffffff;
    Status = G7Ioctl(Tcp, IOCTL_TCP_SET_INFORMATION_EX, Req, Size, NULL, 0, NULL);
    ok(Status == STATUS_INVALID_PARAMETER, "SET_INFORMATION_EX with BufferSize -1 gave 0x%lx\n", Status);
    Req->ID.toi_type = INFO_TYPE_CONNECTION;
    Req->BufferSize = Size;
    Status = G7Ioctl(Tcp, IOCTL_TCP_SET_INFORMATION_EX, Req, Size, NULL, 0, NULL);
    ok(Status == STATUS_INVALID_PARAMETER, "SET_INFORMATION_EX (connection) with BufferSize %lu gave 0x%lx\n", Size, Status);
    RtlFreeHeap(RtlGetProcessHeap(), 0, Req);
    NtClose(Tcp);
}
