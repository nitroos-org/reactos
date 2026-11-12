/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for NtAllocateReserveObject and the reserve handle of NtQueueApcThreadEx of ntdll
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows 10 22H2 (19045), x64 and x86 (WOW64) with the same results:
 *  - NtAllocateReserveObject(&h, NULL, 0) is STATUS_SUCCESS and makes an object of the type "UserApcReserve", type 1 an
 *    "IoCompletionReserve"; any other type (2, 3, 0xFFFFFFFF) is STATUS_INVALID_PARAMETER and the 64-bit caller's handle
 *    stays untouched. Both types: valid access mask 0xF0003, generic mapping 0x20001 / 0x20002 / 0x20000 / 0xF0003,
 *    invalid attributes 0xB0 (OBJ_PERMANENT, OBJ_EXCLUSIVE, OBJ_OPENIF), no security required, no handle count kept.
 *  - The handle has the access 0xF0003, one handle, no attributes; with OBJ_INHERIT in the attributes the handle is
 *    inheritable (and the attributes read 2). An attributes length of 3 is STATUS_INVALID_PARAMETER, an unwritable handle
 *    pointer STATUS_ACCESS_VIOLATION.
 *  - NtQueueApcThreadEx(thread, reserve, routine, ...) with a UserApcReserve handle queues the APC: it runs at the next
 *    alertable wait. A second queueing with the same reserve while the first is still queued is
 *    STATUS_INVALID_PARAMETER_2; after the APC ran the reserve can be used again. An IoCompletionReserve handle or an
 *    event handle is STATUS_OBJECT_TYPE_MISMATCH, a handle value that is not open STATUS_INVALID_HANDLE, a NULL reserve
 *    is an ordinary APC. Closing the reserve handle while its APC is queued does not stop the APC.
 */

#include "precomp.h"

typedef NTSTATUS (NTAPI *PFN_ALLOC)(HANDLE *, POBJECT_ATTRIBUTES, ULONG);
typedef NTSTATUS (NTAPI *PFN_APCEX)(HANDLE, HANDLE, PVOID, PVOID, PVOID, PVOID);

static PFN_ALLOC pAlloc;
static PFN_APCEX pApcEx;
static volatile LONG g_ApcRan;

static VOID NTAPI ApcRoutine(PVOID Context, PVOID Argument1, PVOID Argument2)
{
    InterlockedIncrement(&g_ApcRan);
}

static void Describe(HANDLE Handle, PCWSTR ExpectedType, BOOLEAN Inherit)
{
    OBJECT_BASIC_INFORMATION Basic;
    BYTE Buffer[512];
    POBJECT_TYPE_INFORMATION Type = (POBJECT_TYPE_INFORMATION)Buffer;
    OBJECT_HANDLE_FLAG_INFORMATION Flags;
    ULONG Length;
    NTSTATUS Status;

    Status = NtQueryObject(Handle, ObjectBasicInformation, &Basic, sizeof(Basic), &Length);
    ok_hex(Status, STATUS_SUCCESS);
    ok_hex(Basic.GrantedAccess, 0xF0003);
    ok_dec(Basic.HandleCount, 1);
    ok_hex(Basic.Attributes, Inherit ? OBJ_INHERIT : 0);

    RtlZeroMemory(Buffer, sizeof(Buffer));
    Status = NtQueryObject(Handle, ObjectTypeInformation, Buffer, sizeof(Buffer), &Length);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        ok(Type->TypeName.Length / sizeof(WCHAR) == wcslen(ExpectedType) &&
           !_wcsnicmp(Type->TypeName.Buffer, ExpectedType, wcslen(ExpectedType)),
           "type name %.*ls, expected %ls\n", (int)(Type->TypeName.Length / sizeof(WCHAR)), Type->TypeName.Buffer,
           ExpectedType);
        ok_hex(Type->ValidAccessMask, 0xF0003);
        ok_hex(Type->GenericMapping.GenericRead, 0x20001);
        ok_hex(Type->GenericMapping.GenericWrite, 0x20002);
        ok_hex(Type->GenericMapping.GenericExecute, 0x20000);
        ok_hex(Type->GenericMapping.GenericAll, 0xF0003);
        ok_hex(Type->InvalidAttributes, 0xB0);
        ok_int(Type->SecurityRequired, 0);
        ok_int(Type->MaintainHandleCount, 0);
        ok_int(Type->PoolType, 512);
    }

    Status = NtQueryObject(Handle, ObjectHandleFlagInformation, &Flags, sizeof(Flags), &Length);
    ok_hex(Status, STATUS_SUCCESS);
    ok_int(Flags.Inherit, Inherit);
    ok_int(Flags.ProtectFromClose, 0);
}

static void Test_Create(void)
{
    HANDLE Handle;
    OBJECT_ATTRIBUTES Attributes;
    NTSTATUS Status;
    ULONG Type;

    Handle = NULL;
    Status = pAlloc(&Handle, NULL, 0);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        Describe(Handle, L"UserApcReserve", FALSE);
        NtClose(Handle);
    }

    Handle = NULL;
    Status = pAlloc(&Handle, NULL, 1);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        Describe(Handle, L"IoCompletionReserve", FALSE);
        NtClose(Handle);
    }

    for (Type = 2; Type != 0; Type = (Type == 2) ? 3 : (Type == 3) ? 0xFFFFFFFF : 0)
    {
        Handle = NULL;
        Status = pAlloc(&Handle, NULL, Type);
        ok_hex(Status, STATUS_INVALID_PARAMETER);
        if (NT_SUCCESS(Status)) NtClose(Handle);
    }

    InitializeObjectAttributes(&Attributes, NULL, OBJ_INHERIT, NULL, NULL);
    Handle = NULL;
    Status = pAlloc(&Handle, &Attributes, 0);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        Describe(Handle, L"UserApcReserve", TRUE);
        NtClose(Handle);
    }

    RtlZeroMemory(&Attributes, sizeof(Attributes));
    Attributes.Length = 3;
    Handle = NULL;
    Status = pAlloc(&Handle, &Attributes, 0);
    ok_hex(Status, STATUS_INVALID_PARAMETER);
    if (NT_SUCCESS(Status)) NtClose(Handle);

    Status = pAlloc((HANDLE *)(ULONG_PTR)8, NULL, 0);
    ok_hex(Status, STATUS_ACCESS_VIOLATION);
}

static void Test_ApcReserve(void)
{
    HANDLE ApcReserve = NULL, IoReserve = NULL, Event, Reserve2 = NULL;
    NTSTATUS Status;

    Status = pAlloc(&ApcReserve, NULL, 0);
    ok_hex(Status, STATUS_SUCCESS);
    Status = pAlloc(&IoReserve, NULL, 1);
    ok_hex(Status, STATUS_SUCCESS);
    if (!ApcReserve || !IoReserve) return;

    g_ApcRan = 0;
    Status = pApcEx(NtCurrentThread(), ApcReserve, (PVOID)ApcRoutine, NULL, NULL, NULL);
    ok_hex(Status, STATUS_SUCCESS);
    Status = pApcEx(NtCurrentThread(), ApcReserve, (PVOID)ApcRoutine, NULL, NULL, NULL);
    ok_hex(Status, STATUS_INVALID_PARAMETER_2);
    ok(g_ApcRan == 0, "the APC ran before an alertable wait\n");
    SleepEx(0, TRUE);
    ok_dec(g_ApcRan, 1);

    /* after the delivery the reserve is free again */
    Status = pApcEx(NtCurrentThread(), ApcReserve, (PVOID)ApcRoutine, NULL, NULL, NULL);
    ok_hex(Status, STATUS_SUCCESS);
    SleepEx(0, TRUE);
    ok_dec(g_ApcRan, 2);

    Status = pApcEx(NtCurrentThread(), IoReserve, (PVOID)ApcRoutine, NULL, NULL, NULL);
    ok_hex(Status, STATUS_OBJECT_TYPE_MISMATCH);
    SleepEx(0, TRUE);
    ok_dec(g_ApcRan, 2);

    Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    Status = pApcEx(NtCurrentThread(), Event, (PVOID)ApcRoutine, NULL, NULL, NULL);
    ok_hex(Status, STATUS_OBJECT_TYPE_MISMATCH);
    CloseHandle(Event);

    Status = pApcEx(NtCurrentThread(), (HANDLE)(ULONG_PTR)0x7770, (PVOID)ApcRoutine, NULL, NULL, NULL);
    ok_hex(Status, STATUS_INVALID_HANDLE);

    Status = pApcEx(NtCurrentThread(), NULL, (PVOID)ApcRoutine, NULL, NULL, NULL);
    ok_hex(Status, STATUS_SUCCESS);
    SleepEx(0, TRUE);
    ok_dec(g_ApcRan, 3);

    /* the queued APC keeps its reserve alive when the handle is closed first */
    Status = pAlloc(&Reserve2, NULL, 0);
    ok_hex(Status, STATUS_SUCCESS);
    Status = pApcEx(NtCurrentThread(), Reserve2, (PVOID)ApcRoutine, NULL, NULL, NULL);
    ok_hex(Status, STATUS_SUCCESS);
    Status = NtClose(Reserve2);
    ok_hex(Status, STATUS_SUCCESS);
    SleepEx(0, TRUE);
    ok_dec(g_ApcRan, 4);

    NtClose(ApcReserve);
    NtClose(IoReserve);
}

START_TEST(NtAllocateReserveObject)
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");

    pAlloc = (PFN_ALLOC)GetProcAddress(hNtdll, "NtAllocateReserveObject");
    pApcEx = (PFN_APCEX)GetProcAddress(hNtdll, "NtQueueApcThreadEx");
    ok(pAlloc != NULL, "NtAllocateReserveObject is not exported by ntdll\n");
    ok(pApcEx != NULL, "NtQueueApcThreadEx is not exported by ntdll\n");
    if (!pAlloc || !pApcEx) return;

    Test_Create();
    Test_ApcReserve();
}
