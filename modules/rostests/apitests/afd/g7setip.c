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
#include <iphlpapi.h>

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

/* "a.b.c.d" to the address as it goes on the wire (first octet in the lowest byte) */
static
BOOLEAN
G7ParseIp(_In_ PCSTR Text, _Out_ PULONG Address)
{
    ULONG Octet[4] = { 0 }, i = 0;

    for (; *Text && i < 4; Text++)
    {
        if (*Text == '.')
            i++;
        else if (*Text >= '0' && *Text <= '9')
            Octet[i] = Octet[i] * 10 + (*Text - '0');
        else
            return FALSE;
    }
    if (i != 3)
        return FALSE;
    *Address = Octet[0] | (Octet[1] << 8) | (Octet[2] << 16) | (Octet[3] << 24);
    return TRUE;
}

/*
 * A request that succeeds returns the bytes of the answer: IoStatus.Information is a byte count, not the
 * interface index (the I/O manager copies that many bytes back, and a count may not exceed the output buffer).
 * Changes the address of the first adapter that has one, and puts it back.
 */
static
void
G7TestSetAddressSucceeds(_In_ HANDLE Ip)
{
    typedef ULONG (WINAPI *PGETADAPTERSINFO)(PIP_ADAPTER_INFO, PULONG);
    PGETADAPTERSINFO pGetAdaptersInfo;
    PIP_ADAPTER_INFO Adapters, Adapter;
    HMODULE Iphlpapi = LoadLibraryW(L"iphlpapi.dll");
    ULONG Size = 0, Index = 0, Old, Mask, New;
    NTSTATUS Status;
    ULONG_PTR Info;
    ULONG Set[3], Out[3];

    pGetAdaptersInfo = Iphlpapi ? (PGETADAPTERSINFO)GetProcAddress(Iphlpapi, "GetAdaptersInfo") : NULL;
    if (!pGetAdaptersInfo || pGetAdaptersInfo(NULL, &Size) != ERROR_BUFFER_OVERFLOW)
    {
        skip("no adapter list\n");
        return;
    }
    Adapters = HeapAlloc(GetProcessHeap(), 0, Size);
    if (!Adapters || pGetAdaptersInfo(Adapters, &Size) != ERROR_SUCCESS)
    {
        skip("no adapter list\n");
        HeapFree(GetProcessHeap(), 0, Adapters);
        return;
    }
    for (Adapter = Adapters; Adapter; Adapter = Adapter->Next)
    {
        if (G7ParseIp(Adapter->IpAddressList.IpAddress.String, &Old) && Old &&
            G7ParseIp(Adapter->IpAddressList.IpMask.String, &Mask) && Mask)
        {
            Index = Adapter->Index;
            break;
        }
    }
    HeapFree(GetProcessHeap(), 0, Adapters);
    if (!Index)
    {
        skip("no adapter with an address\n");
        return;
    }

    /* Another host address of the same network (the first octet is the lowest byte) */
    New = (Old & Mask) | (((Old >> 24) == 200 ? 201 : 200) << 24);
    if ((New & ~Mask) == 0 || New == Old)
    {
        skip("no free address to use\n");
        return;
    }

    Set[0] = Index;
    Set[1] = New;
    Set[2] = Mask;
    memset(Out, 0x77, sizeof(Out));
    Info = 0xdeadbeef;
    Status = G7Ioctl(Ip, IOCTL_SET_IP_ADDRESS, Set, sizeof(Set), Out, sizeof(Out), &Info);
    ok(Status == STATUS_SUCCESS, "SET_IP_ADDRESS of interface %lu gave 0x%lx\n", Index, Status);
    if (Status == STATUS_SUCCESS)
    {
        ok(Info == sizeof(Out), "SET_IP_ADDRESS returned %Iu bytes, not the %Iu of the answer\n", Info, sizeof(Out));
        ok(Out[0] == Index, "the answer names interface %lu, not %lu\n", Out[0], Index);
        ok(Out[1] == Index, "the context in the answer is %lu, not %lu\n", Out[1], Index);
    }

    /* Put the old address back; a smaller output buffer gets at most its length */
    Set[1] = Old;
    memset(Out, 0x77, sizeof(Out));
    Info = 0xdeadbeef;
    Status = G7Ioctl(Ip, IOCTL_SET_IP_ADDRESS, Set, sizeof(Set), Out, 4, &Info);
    ok(Status == STATUS_SUCCESS, "SET_IP_ADDRESS back to the old address gave 0x%lx\n", Status);
    ok(Info <= 4, "SET_IP_ADDRESS returned %Iu bytes for an output buffer of 4\n", Info);
    ok(Out[1] == 0x77777777 && Out[2] == 0x77777777, "SET_IP_ADDRESS wrote past an output buffer of 4: %lx %lx\n", Out[1], Out[2]);
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

    /* A failed request returns no bytes: IoStatus.Information is a byte count, and the I/O manager copies that
       many bytes of the system buffer to the caller's output buffer (once it held an interface index) */
    {
        ULONG Out[3] = { 0x11111111, 0x22222222, 0x33333333 };
        ULONG_PTR Info = 0xdeadbeef;

        Status = G7Ioctl(Ip, IOCTL_SET_IP_ADDRESS, SetAddress, sizeof(SetAddress), Out, sizeof(Out), &Info);
        ok(Status != STATUS_SUCCESS, "SET_IP_ADDRESS of a missing interface gave 0x%lx\n", Status);
        ok(Info == 0, "SET_IP_ADDRESS of a missing interface returned %Iu bytes\n", Info);
        ok(Out[0] == 0x11111111 && Out[1] == 0x22222222 && Out[2] == 0x33333333,
           "SET_IP_ADDRESS of a missing interface changed the output: %lx %lx %lx\n", Out[0], Out[1], Out[2]);
    }

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

    G7TestSetAddressSucceeds(Ip);
    NtClose(Ip);
}
