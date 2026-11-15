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

/* Is the address in the address list of the adapter (FirstOnly: is it the first one)? */
static
BOOLEAN
G7AddressListHas(
    _In_ ULONG (WINAPI *GetAdaptersInfoFn)(PIP_ADAPTER_INFO, PULONG),
    _In_ ULONG Index,
    _In_ ULONG Address,
    _In_ BOOLEAN FirstOnly)
{
    PIP_ADAPTER_INFO Adapters, Adapter;
    PIP_ADDR_STRING Entry;
    ULONG Size = 0, Found;
    BOOLEAN Has = FALSE;

    if (GetAdaptersInfoFn(NULL, &Size) != ERROR_BUFFER_OVERFLOW)
        return FALSE;
    Adapters = HeapAlloc(GetProcessHeap(), 0, Size);
    if (!Adapters || GetAdaptersInfoFn(Adapters, &Size) != ERROR_SUCCESS)
    {
        HeapFree(GetProcessHeap(), 0, Adapters);
        return FALSE;
    }
    for (Adapter = Adapters; Adapter; Adapter = Adapter->Next)
    {
        if (Adapter->Index != Index)
            continue;
        for (Entry = &Adapter->IpAddressList; Entry; Entry = FirstOnly ? NULL : Entry->Next)
        {
            if (G7ParseIp(Entry->IpAddress.String, &Found) && Found == Address)
                Has = TRUE;
        }
    }
    HeapFree(GetProcessHeap(), 0, Adapters);
    return Has;
}

/* The context of the address in the address list of the adapter (0: it is not there) */
static
USHORT
G7ContextOf(
    _In_ ULONG (WINAPI *GetAdaptersInfoFn)(PIP_ADAPTER_INFO, PULONG),
    _In_ ULONG Index,
    _In_ ULONG Address)
{
    PIP_ADAPTER_INFO Adapters, Adapter;
    PIP_ADDR_STRING Entry;
    ULONG Size = 0, Found;
    USHORT Context = 0;

    if (GetAdaptersInfoFn(NULL, &Size) != ERROR_BUFFER_OVERFLOW)
        return 0;
    Adapters = HeapAlloc(GetProcessHeap(), 0, Size);
    if (!Adapters || GetAdaptersInfoFn(Adapters, &Size) != ERROR_SUCCESS)
    {
        HeapFree(GetProcessHeap(), 0, Adapters);
        return 0;
    }
    for (Adapter = Adapters; Adapter; Adapter = Adapter->Next)
    {
        if (Adapter->Index != Index)
            continue;
        for (Entry = &Adapter->IpAddressList; Entry; Entry = Entry->Next)
        {
            if (G7ParseIp(Entry->IpAddress.String, &Found) && Found == Address)
                Context = (USHORT)Entry->Context;
        }
    }
    HeapFree(GetProcessHeap(), 0, Adapters);
    return Context;
}

/*
 * A request that succeeds returns the bytes of the answer: IoStatus.Information is a byte count, not the
 * interface index (the I/O manager copies that many bytes back, and a count may not exceed the output buffer).
 * Adds an address to the first adapter that has one, and deletes it again.
 */
static
void
G7TestSetAddressSucceeds(_In_ HANDLE Ip)
{
    typedef ULONG (WINAPI *PGETADAPTERSINFO)(PIP_ADAPTER_INFO, PULONG);
    PGETADAPTERSINFO pGetAdaptersInfo;
    PIP_ADAPTER_INFO Adapters, Adapter;
    HMODULE Iphlpapi = LoadLibraryW(L"iphlpapi.dll");
    ULONG Size = 0, Index = 0, Old, Mask, New, Context = 0;
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

    /* The adapter has an address: the new one is an additional address beside it, with a context of its own */
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
        ok(Out[1] >= 0x8000 && Out[1] <= 0xffff, "the context in the answer is %lu, not one of an additional address\n", Out[1]);
        Context = Out[1];
        ok(G7AddressListHas(pGetAdaptersInfo, Index, Old, TRUE), "the first address is not %lx any more\n", Old);
        ok(G7AddressListHas(pGetAdaptersInfo, Index, New, FALSE), "the added address %lx is not in the list\n", New);
    }

    /* The address is there once */
    Status = G7Ioctl(Ip, IOCTL_SET_IP_ADDRESS, Set, sizeof(Set), NULL, 0, NULL);
    ok(Status == STATUS_DUPLICATE_OBJECTID, "SET_IP_ADDRESS of an address that is in use gave 0x%lx\n", Status);
    Set[1] = Old;
    Status = G7Ioctl(Ip, IOCTL_SET_IP_ADDRESS, Set, sizeof(Set), NULL, 0, NULL);
    ok(Status == STATUS_DUPLICATE_OBJECTID, "SET_IP_ADDRESS of the first address again gave 0x%lx\n", Status);
    Set[1] = 0;
    Status = G7Ioctl(Ip, IOCTL_SET_IP_ADDRESS, Set, sizeof(Set), NULL, 0, NULL);
    ok(Status == STATUS_INVALID_PARAMETER, "SET_IP_ADDRESS of 0.0.0.0 gave 0x%lx\n", Status);

    /* DeleteIPAddress removes the added address only */
    if (Context)
    {
        USHORT Nte = (USHORT)Context;

        Status = G7Ioctl(Ip, IOCTL_DELETE_IP_ADDRESS, &Nte, sizeof(Nte), NULL, 0, NULL);
        ok(Status == STATUS_SUCCESS, "DELETE_IP_ADDRESS of the context %lu gave 0x%lx\n", Context, Status);
        ok(!G7AddressListHas(pGetAdaptersInfo, Index, New, FALSE), "the deleted address %lx is still in the list\n", New);
        ok(G7AddressListHas(pGetAdaptersInfo, Index, Old, TRUE), "the first address is gone with it\n");
        Status = G7Ioctl(Ip, IOCTL_DELETE_IP_ADDRESS, &Nte, sizeof(Nte), NULL, 0, NULL);
        ok(Status != STATUS_SUCCESS, "DELETE_IP_ADDRESS of the context %lu again gave 0x%lx\n", Context, Status);
    }

    /* A smaller output buffer gets at most its length */
    Set[1] = New;
    memset(Out, 0x77, sizeof(Out));
    Info = 0xdeadbeef;
    Status = G7Ioctl(Ip, IOCTL_SET_IP_ADDRESS, Set, sizeof(Set), Out, 4, &Info);
    ok(Status == STATUS_SUCCESS, "SET_IP_ADDRESS again gave 0x%lx\n", Status);
    ok(Info <= 4, "SET_IP_ADDRESS returned %Iu bytes for an output buffer of 4\n", Info);
    ok(Out[1] == 0x77777777 && Out[2] == 0x77777777, "SET_IP_ADDRESS wrote past an output buffer of 4: %lx %lx\n", Out[1], Out[2]);
    if (Status == STATUS_SUCCESS)
    {
        /* Its context is in the address list */
        USHORT Nte = G7ContextOf(pGetAdaptersInfo, Index, New);

        ok(Nte >= 0x8000, "the context of the added address is %u\n", Nte);
        Status = G7Ioctl(Ip, IOCTL_DELETE_IP_ADDRESS, &Nte, sizeof(Nte), NULL, 0, NULL);
        ok(Status == STATUS_SUCCESS, "DELETE_IP_ADDRESS of the context %u gave 0x%lx\n", Nte, Status);
    }
    ok(!G7AddressListHas(pGetAdaptersInfo, Index, New, FALSE), "the address %lx is still there\n", New);
    ok(G7AddressListHas(pGetAdaptersInfo, Index, Old, TRUE), "the first address %lx is not there\n", Old);
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
