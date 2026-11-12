/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for NtSetIoCompletionEx (packet taken from an IoCompletionReserve) and the full-width
 *              CompletionInformation of NtSetIoCompletion
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows 10 22H2 (19045), x64 and x86 (WOW64) with the same results:
 *  - A reserve is one packet. While its packet is queued, in any port, a second call with the reserve is
 *    STATUS_INVALID_PARAMETER_2 and queues nothing. A failed call does not use the reserve up. The reserve is free again
 *    after the packet was removed, or after the port holding it was closed. Closing the reserve handle while its packet is
 *    queued does not drop the packet.
 *  - The port handle is validated before the reserve handle: a handle of another type is STATUS_OBJECT_TYPE_MISMATCH, an
 *    invalid one STATUS_INVALID_HANDLE (a port that is an event with an invalid reserve is the type mismatch, an invalid
 *    port with a reserve of the wrong type is the invalid handle). The port needs IO_COMPLETION_MODIFY_STATE, the reserve
 *    the access bit 0x2 (access 0, 1 or DELETE only: STATUS_ACCESS_DENIED), both STATUS_ACCESS_DENIED otherwise.
 *  - A NULL, closed or invalid reserve handle is STATUS_INVALID_HANDLE (NULL is not "no reserve"), a UserApcReserve, an
 *    event, a port, a wait completion packet or a pseudo handle STATUS_OBJECT_TYPE_MISMATCH.
 *  - The packet carries key, context, status and the whole pointer-wide information (0x1122334455667788 on x64) for
 *    NtSetIoCompletionEx and NtSetIoCompletion alike (the old build cut it to 32 bits).
 */

#include "precomp.h"

typedef NTSTATUS (NTAPI *PFN_ALLOC)(PHANDLE, POBJECT_ATTRIBUTES, ULONG);
typedef NTSTATUS (NTAPI *PFN_SETEX)(HANDLE, HANDLE, PVOID, PVOID, NTSTATUS, ULONG_PTR);
typedef NTSTATUS (NTAPI *PFN_CREATEWAIT)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);

static PFN_ALLOC pAlloc;
static PFN_SETEX pSetEx;
static PFN_CREATEWAIT pCreateWait;

static NTSTATUS SetEx(HANDLE Port, HANDLE Reserve, ULONG_PTR Key, NTSTATUS Status, ULONG_PTR Info)
{
    return pSetEx(Port, Reserve, (PVOID)Key, (PVOID)(Key + 0x100), Status, Info);
}

static ULONG Depth(HANDLE Port)
{
    IO_COMPLETION_BASIC_INFORMATION Basic = { 0xDEAD };
    NTSTATUS Status = NtQueryIoCompletion(Port, IoCompletionBasicInformation, &Basic, sizeof(Basic), NULL);

    ok_hex(Status, STATUS_SUCCESS);
    return Basic.Depth;
}

static void Remove(HANDLE Port, ULONG_PTR Key, NTSTATUS ExpectedStatus, ULONG_PTR ExpectedInfo)
{
    PVOID RemovedKey = NULL, RemovedContext = NULL;
    IO_STATUS_BLOCK Iosb = { { 0x77777777 }, 0x66666666 };
    LARGE_INTEGER Timeout;
    NTSTATUS Status;

    Timeout.QuadPart = 0;
    Status = NtRemoveIoCompletion(Port, &RemovedKey, &RemovedContext, &Iosb, &Timeout);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status)) return;
    ok_ptr(RemovedKey, (PVOID)Key);
    ok_ptr(RemovedContext, (PVOID)(Key + 0x100));
    ok_hex(Iosb.Status, ExpectedStatus);
    ok(Iosb.Information == ExpectedInfo, "Information %Ix, expected %Ix\n", Iosb.Information, ExpectedInfo);
}

static void RemoveNone(HANDLE Port)
{
    PVOID RemovedKey, RemovedContext;
    IO_STATUS_BLOCK Iosb;
    LARGE_INTEGER Timeout;
    NTSTATUS Status;

    Timeout.QuadPart = 0;
    Status = NtRemoveIoCompletion(Port, &RemovedKey, &RemovedContext, &Iosb, &Timeout);
    ok_hex(Status, STATUS_TIMEOUT);
}

static HANDLE NewPort(void)
{
    HANDLE Port = NULL;
    NTSTATUS Status = NtCreateIoCompletion(&Port, IO_COMPLETION_ALL_ACCESS, NULL, 0);

    ok_hex(Status, STATUS_SUCCESS);
    return Port;
}

static HANDLE NewReserve(ULONG Type)
{
    HANDLE Reserve = NULL;
    NTSTATUS Status = pAlloc(&Reserve, NULL, Type);

    ok_hex(Status, STATUS_SUCCESS);
    return Reserve;
}

static HANDLE Duplicate(HANDLE Handle, ACCESS_MASK Access)
{
    HANDLE New = NULL;
    NTSTATUS Status = NtDuplicateObject(NtCurrentProcess(), Handle, NtCurrentProcess(), &New, Access, 0, 0);

    ok_hex(Status, STATUS_SUCCESS);
    return New;
}

static void Test_OnePacket(HANDLE Port, HANDLE Reserve)
{
    HANDLE Port2 = NewPort(), Port3 = NewPort(), Port4 = NewPort();

    /* the same reserve twice before the removal */
    ok_hex(SetEx(Port, Reserve, 0x11, 0x1111, 0x2222), STATUS_SUCCESS);
    ok_dec(Depth(Port), 1);
    ok_hex(SetEx(Port, Reserve, 0x22, 0x3333, 0x4444), STATUS_INVALID_PARAMETER_2);
    ok_dec(Depth(Port), 1);
    Remove(Port, 0x11, 0x1111, 0x2222);
    RemoveNone(Port);
    ok_dec(Depth(Port), 0);

    /* free again after the removal, every time */
    ok_hex(SetEx(Port, Reserve, 0x33, 0x5555, 0x6666), STATUS_SUCCESS);
    Remove(Port, 0x33, 0x5555, 0x6666);
    ok_hex(SetEx(Port, Reserve, 0x44, 0x7777, 0x8888), STATUS_SUCCESS);
    Remove(Port, 0x44, 0x7777, 0x8888);

    /* in use on one port: refused on another */
    ok_hex(SetEx(Port, Reserve, 0x55, 0, 0), STATUS_SUCCESS);
    ok_hex(SetEx(Port2, Reserve, 0x56, 0, 0), STATUS_INVALID_PARAMETER_2);
    Remove(Port, 0x55, 0, 0);
    RemoveNone(Port2);
    ok_hex(SetEx(Port2, Reserve, 0x57, 0, 0), STATUS_SUCCESS);
    Remove(Port2, 0x57, 0, 0);

    /* the port closed with the packet queued gives the reserve back */
    ok_hex(SetEx(Port4, Reserve, 0x61, 0, 0), STATUS_SUCCESS);
    ok_hex(NtClose(Port4), STATUS_SUCCESS);
    ok_hex(SetEx(Port3, Reserve, 0x62, 0, 0), STATUS_SUCCESS);
    Remove(Port3, 0x62, 0, 0);

    NtClose(Port2);
    NtClose(Port3);
}

static void Test_ReserveHandleClosed(HANDLE Port)
{
    HANDLE Reserve = NewReserve(1);

    /* the queued packet keeps the reserve alive */
    ok_hex(SetEx(Port, Reserve, 0x71, 0x9, 0xA), STATUS_SUCCESS);
    ok_hex(NtClose(Reserve), STATUS_SUCCESS);
    Remove(Port, 0x71, 0x9, 0xA);

    /* a closed handle */
    Reserve = NewReserve(1);
    NtClose(Reserve);
    ok_hex(SetEx(Port, Reserve, 0x81, 0, 0), STATUS_INVALID_HANDLE);
    ok_dec(Depth(Port), 0);
}

static void Test_Types(HANDLE Port, HANDLE Reserve)
{
    HANDLE ApcReserve = NewReserve(0), Event = NULL, Wait = NULL, Other;

    NtCreateEvent(&Event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
    pCreateWait(&Wait, 0x1F0003, NULL);

    ok_hex(SetEx(Port, ApcReserve, 0x91, 0, 0), STATUS_OBJECT_TYPE_MISMATCH);
    ok_hex(SetEx(Port, Event, 0x92, 0, 0), STATUS_OBJECT_TYPE_MISMATCH);
    ok_hex(SetEx(Port, Port, 0x93, 0, 0), STATUS_OBJECT_TYPE_MISMATCH);
    if (Wait) ok_hex(SetEx(Port, Wait, 0x94, 0, 0), STATUS_OBJECT_TYPE_MISMATCH);
    ok_hex(SetEx(Port, (HANDLE)(ULONG_PTR)0x7777C, 0x95, 0, 0), STATUS_INVALID_HANDLE);
    ok_hex(SetEx(Port, NtCurrentProcess(), 0x96, 0, 0), STATUS_OBJECT_TYPE_MISMATCH);
    ok_hex(SetEx(Port, NtCurrentThread(), 0x97, 0, 0), STATUS_OBJECT_TYPE_MISMATCH);
    ok_dec(Depth(Port), 0);

    /* NULL is not "no reserve" */
    ok_hex(SetEx(Port, NULL, 0xA1, 1, 2), STATUS_INVALID_HANDLE);
    RemoveNone(Port);

    /* the port is checked first; a failed call does not use the reserve up */
    ok_hex(SetEx(Event, Reserve, 0xB1, 0, 0), STATUS_OBJECT_TYPE_MISMATCH);
    ok_hex(SetEx((HANDLE)(ULONG_PTR)0x7777C, Reserve, 0xB2, 0, 0), STATUS_INVALID_HANDLE);
    ok_hex(SetEx(NULL, Reserve, 0xB3, 0, 0), STATUS_INVALID_HANDLE);
    ok_hex(SetEx(Port, Reserve, 0xB4, 0, 0), STATUS_SUCCESS);
    Remove(Port, 0xB4, 0, 0);
    ok_hex(SetEx(Event, ApcReserve, 0xB5, 0, 0), STATUS_OBJECT_TYPE_MISMATCH);
    ok_hex(SetEx((HANDLE)(ULONG_PTR)0x7777C, ApcReserve, 0xB6, 0, 0), STATUS_INVALID_HANDLE);
    ok_hex(SetEx(Event, (HANDLE)(ULONG_PTR)0x7777C, 0xB7, 0, 0), STATUS_OBJECT_TYPE_MISMATCH);

    /* access of the port handle */
    Other = Duplicate(Port, IO_COMPLETION_QUERY_STATE);
    ok_hex(SetEx(Other, Reserve, 0xC1, 0, 0), STATUS_ACCESS_DENIED);
    NtClose(Other);
    Other = Duplicate(Port, IO_COMPLETION_MODIFY_STATE);
    ok_hex(SetEx(Other, Reserve, 0xC2, 0, 0), STATUS_SUCCESS);
    Remove(Port, 0xC2, 0, 0);
    NtClose(Other);
    Other = Duplicate(Port, 0);
    ok_hex(SetEx(Other, Reserve, 0xC3, 0, 0), STATUS_ACCESS_DENIED);
    RemoveNone(Port);
    NtClose(Other);

    NtClose(ApcReserve);
    NtClose(Event);
    if (Wait) NtClose(Wait);
}

static void Test_ReserveAccess(HANDLE Port, HANDLE Reserve)
{
    static const struct { ACCESS_MASK Access; NTSTATUS Expected; } Cases[] =
    {
        { 0,        STATUS_ACCESS_DENIED },
        { 1,        STATUS_ACCESS_DENIED },
        { 2,        STATUS_SUCCESS },
        { 3,        STATUS_SUCCESS },
        { DELETE,   STATUS_ACCESS_DENIED },
        { 0xF0003,  STATUS_SUCCESS },
    };
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(Cases); i++)
    {
        HANDLE Dup = Duplicate(Reserve, Cases[i].Access);
        NTSTATUS Status = SetEx(Port, Dup, 0xC8 + i, 0, 0);

        ok(Status == Cases[i].Expected, "reserve access 0x%lx: 0x%lx, expected 0x%lx\n", Cases[i].Access, Status,
           Cases[i].Expected);
        if (NT_SUCCESS(Status))
            Remove(Port, 0xC8 + i, 0, 0);
        else
            RemoveNone(Port);
        NtClose(Dup);
    }
}

static void Test_Information(HANDLE Port, HANDLE Reserve)
{
    ULONG_PTR Info = (ULONG_PTR)0x1122334455667788ULL;

    ok_hex(SetEx(Port, Reserve, 0xD1, 0xC0001234, Info), STATUS_SUCCESS);
    Remove(Port, 0xD1, 0xC0001234, Info);

    ok_hex(NtSetIoCompletion(Port, (PVOID)0xD2, (PVOID)0xD3, 0xC0001234, Info), STATUS_SUCCESS);
    {
        PVOID Key, Context;
        IO_STATUS_BLOCK Iosb;
        LARGE_INTEGER Timeout;

        Timeout.QuadPart = 0;
        ok_hex(NtRemoveIoCompletion(Port, &Key, &Context, &Iosb, &Timeout), STATUS_SUCCESS);
        ok_ptr(Key, (PVOID)0xD2);
        ok_ptr(Context, (PVOID)0xD3);
        ok_hex(Iosb.Status, 0xC0001234);
        ok(Iosb.Information == Info, "NtSetIoCompletion Information %Ix, expected %Ix\n", Iosb.Information, Info);
    }
}

START_TEST(NtSetIoCompletionEx)
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    HANDLE Port, Reserve;

    pAlloc = (PFN_ALLOC)GetProcAddress(hNtdll, "NtAllocateReserveObject");
    pSetEx = (PFN_SETEX)GetProcAddress(hNtdll, "NtSetIoCompletionEx");
    pCreateWait = (PFN_CREATEWAIT)GetProcAddress(hNtdll, "NtCreateWaitCompletionPacket");
    ok(pAlloc != NULL, "NtAllocateReserveObject is not exported by ntdll\n");
    ok(pSetEx != NULL, "NtSetIoCompletionEx is not exported by ntdll\n");
    if (!pAlloc || !pSetEx) return;

    Port = NewPort();
    Reserve = NewReserve(1);
    if (!Port || !Reserve) return;

    Test_OnePacket(Port, Reserve);
    Test_ReserveHandleClosed(Port);
    Test_Types(Port, Reserve);
    Test_ReserveAccess(Port, Reserve);
    Test_Information(Port, Reserve);

    /* in use, again, and the depth stays 1 */
    ok_hex(SetEx(Port, Reserve, 0xE1, 0, 0), STATUS_SUCCESS);
    ok_hex(SetEx(Port, Reserve, 0xE2, 0, 0), STATUS_INVALID_PARAMETER_2);
    ok_dec(Depth(Port), 1);
    Remove(Port, 0xE1, 0, 0);
    ok_dec(Depth(Port), 0);

    NtClose(Reserve);
    NtClose(Port);
}
