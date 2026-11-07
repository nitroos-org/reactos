/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1+ (https://spdx.org/licenses/LGPL-2.1+)
 * PURPOSE:     Contract test: IOCTL_SET_IP_ADDRESS and IOCTL_DELETE_IP_ADDRESS with an input shorter than
 *              the request they read (none at all, or a few bytes) are refused with
 *              STATUS_INVALID_PARAMETER; a well-formed request for an interface that does not exist is
 *              read and answered with another status.
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

START_TEST(g7setip)
{
    HANDLE Ip;
    NTSTATUS Status;
    ULONG Zero[3] = { 0 };
    ULONG SetAddress[3];
    USHORT NteIndex = 0x7ffe;

    Status = G7OpenDevice(L"\\Device\\Ip", &Ip);
    ok(Status == STATUS_SUCCESS, "open \\Device\\Ip gave 0x%lx\n", Status);
    if (!NT_SUCCESS(Status))
        return;

    /* Address changes need an administrator: without one every request is denied first */
    SetAddress[0] = 0x7ffe;
    SetAddress[1] = SetAddress[2] = 0;
    Status = G7Ioctl(Ip, IOCTL_SET_IP_ADDRESS, SetAddress, sizeof(SetAddress), NULL, 0, NULL);
    if (Status == STATUS_ACCESS_DENIED)
    {
        skip("not an administrator\n");
        NtClose(Ip);
        return;
    }
    /* No such interface */
    ok(Status != STATUS_SUCCESS && Status != STATUS_INVALID_PARAMETER,
       "SET_IP_ADDRESS of a missing interface gave 0x%lx\n", Status);

    Status = G7Ioctl(Ip, IOCTL_SET_IP_ADDRESS, NULL, 0, NULL, 0, NULL);
    ok(Status == STATUS_INVALID_PARAMETER, "SET_IP_ADDRESS with no input gave 0x%lx\n", Status);
    Status = G7Ioctl(Ip, IOCTL_SET_IP_ADDRESS, Zero, 4, NULL, 0, NULL);
    ok(Status == STATUS_INVALID_PARAMETER, "SET_IP_ADDRESS with 4 bytes gave 0x%lx\n", Status);
    Status = G7Ioctl(Ip, IOCTL_SET_IP_ADDRESS, Zero, 11, NULL, 0, NULL);
    ok(Status == STATUS_INVALID_PARAMETER, "SET_IP_ADDRESS with 11 bytes gave 0x%lx\n", Status);

    Status = G7Ioctl(Ip, IOCTL_DELETE_IP_ADDRESS, NULL, 0, NULL, 0, NULL);
    ok(Status == STATUS_INVALID_PARAMETER, "DELETE_IP_ADDRESS with no input gave 0x%lx\n", Status);
    Status = G7Ioctl(Ip, IOCTL_DELETE_IP_ADDRESS, Zero, 1, NULL, 0, NULL);
    ok(Status == STATUS_INVALID_PARAMETER, "DELETE_IP_ADDRESS with 1 byte gave 0x%lx\n", Status);
    /* No such interface: the request is read, nothing is deleted */
    Status = G7Ioctl(Ip, IOCTL_DELETE_IP_ADDRESS, &NteIndex, sizeof(NteIndex), NULL, 0, NULL);
    ok(Status != STATUS_SUCCESS && Status != STATUS_INVALID_PARAMETER,
       "DELETE_IP_ADDRESS of a missing interface gave 0x%lx\n", Status);
    NtClose(Ip);
}
