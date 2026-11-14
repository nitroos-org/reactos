/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for ObjectHandleFlagInformation and the pool type of ObjectTypeInformation of NtQueryObject
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows 10 22H2 (19045), x64 and x86 (WOW64) with the same results, for the types IoCompletionReserve,
 * UserApcReserve, IoCompletion, WaitCompletionPacket, Event, Semaphore, Mutant, Timer, File and Key:
 *  - ObjectHandleFlagInformation: Inherit is a BOOLEAN, 1 (not the OBJ_INHERIT bit 2) for an inheritable handle, 0
 *    otherwise; ProtectFromClose 1 or 0; the information length is 2. ObjectBasicInformation.Attributes is 0 for a plain
 *    handle, 2 (OBJ_INHERIT) for an inheritable one, 3 once NtSetInformationObject also protected it from close.
 *    NtSetInformationObject with Inherit = 1 makes a plain handle inheritable (the flags then read Inherit 1, attributes 2);
 *    with Inherit = 1 and ProtectFromClose = 1 they read Inherit 1, Protect 1, attributes 3.
 *  - ObjectTypeInformation.PoolType is 512 (the no-execute non-paged pool) for every type that lives in non-paged pool
 *    and 1 (paged pool) for the paged ones: Directory, SymbolicLink, Token, Section, Key, KeyedEvent (the table of all
 *    types, ObjectTypesInformation, agrees).
 *  - GrantedAccess of ObjectBasicInformation (and of SystemHandleInformation) is the access the handle was opened with,
 *    protected from close or not: Event 0x001f0003 both ways, never the internal 0x02000000 bit. A protected handle
 *    shows HandleAttributes 1 (HANDLE_FLAG_PROTECT_FROM_CLOSE) in ObjectBasicInformation.
 */

#include "precomp.h"

#define NONPAGED_NX 512

typedef NTSTATUS (NTAPI *PFN_ALLOC)(PHANDLE, POBJECT_ATTRIBUTES, ULONG);
typedef NTSTATUS (NTAPI *PFN_CREATEWAIT)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);

#define INTERNAL_PROTECT_CLOSE_BIT 0x02000000

static ACCESS_MASK g_PlainAccess;
static PFN_ALLOC pAlloc;
static PFN_CREATEWAIT pCreateWait;

typedef enum { T_IORESERVE, T_APCRESERVE, T_PORT, T_WAITPACKET, T_EVENT, T_SEMAPHORE, T_MUTANT, T_TIMER, T_FILE, T_KEY,
               T_COUNT } TYPE_INDEX;

static const struct { PCWSTR Name; ULONG PoolType; } g_Types[T_COUNT] =
{
    { L"IoCompletionReserve", NONPAGED_NX }, { L"UserApcReserve", NONPAGED_NX }, { L"IoCompletion", NONPAGED_NX },
    { L"WaitCompletionPacket", NONPAGED_NX }, { L"Event", NONPAGED_NX }, { L"Semaphore", NONPAGED_NX },
    { L"Mutant", NONPAGED_NX }, { L"Timer", NONPAGED_NX }, { L"File", NONPAGED_NX }, { L"Key", 1 },
};

static HANDLE Create(TYPE_INDEX Type, BOOLEAN Inherit)
{
    OBJECT_ATTRIBUTES Attributes;
    UNICODE_STRING Name;
    IO_STATUS_BLOCK Iosb;
    WCHAR Path[MAX_PATH + 8] = L"\\??\\";
    HANDLE Handle = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    InitializeObjectAttributes(&Attributes, NULL, Inherit ? OBJ_INHERIT : 0, NULL, NULL);
    switch (Type)
    {
        case T_IORESERVE: Status = pAlloc(&Handle, &Attributes, 1); break;
        case T_APCRESERVE: Status = pAlloc(&Handle, &Attributes, 0); break;
        case T_PORT: Status = NtCreateIoCompletion(&Handle, IO_COMPLETION_ALL_ACCESS, &Attributes, 0); break;
        case T_WAITPACKET:
            if (!pCreateWait) return NULL;
            Status = pCreateWait(&Handle, 0x1F0003, &Attributes);
            break;
        case T_EVENT: Status = NtCreateEvent(&Handle, EVENT_ALL_ACCESS, &Attributes, NotificationEvent, FALSE); break;
        case T_SEMAPHORE: Status = NtCreateSemaphore(&Handle, SEMAPHORE_ALL_ACCESS, &Attributes, 0, 1); break;
        case T_MUTANT: Status = NtCreateMutant(&Handle, MUTANT_ALL_ACCESS, &Attributes, FALSE); break;
        case T_TIMER: Status = NtCreateTimer(&Handle, TIMER_ALL_ACCESS, &Attributes, NotificationTimer); break;
        case T_FILE:
            GetModuleFileNameW(GetModuleHandleW(L"ntdll.dll"), Path + 4, MAX_PATH);
            RtlInitUnicodeString(&Name, Path);
            Attributes.ObjectName = &Name;
            Status = NtOpenFile(&Handle, FILE_GENERIC_READ, &Attributes, &Iosb,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_NON_DIRECTORY_FILE);
            break;
        case T_KEY:
            RtlInitUnicodeString(&Name, L"\\Registry\\Machine\\System");
            Attributes.ObjectName = &Name;
            Attributes.Attributes |= OBJ_CASE_INSENSITIVE;
            Status = NtOpenKey(&Handle, KEY_READ, &Attributes);
            break;
        default: break;
    }
    ok(NT_SUCCESS(Status), "creating %ls: 0x%lx\n", g_Types[Type].Name, Status);
    return NT_SUCCESS(Status) ? Handle : NULL;
}

static void CheckFlags(HANDLE Handle, PCSTR Label, ULONG Inherit, ULONG Protect, ULONG Attributes)
{
    OBJECT_HANDLE_FLAG_INFORMATION Flags = { 0x77, 0x77 };
    OBJECT_BASIC_INFORMATION Basic;
    ULONG Length = 0;
    NTSTATUS Status;

    Status = NtQueryObject(Handle, ObjectHandleFlagInformation, &Flags, sizeof(Flags), &Length);
    ok(Status == STATUS_SUCCESS, "%s: flags 0x%lx\n", Label, Status);
    ok(Length == sizeof(Flags), "%s: length %lu\n", Label, Length);
    ok(Flags.Inherit == Inherit, "%s: Inherit %u, expected %lu\n", Label, Flags.Inherit, Inherit);
    ok(Flags.ProtectFromClose == Protect, "%s: ProtectFromClose %u, expected %lu\n", Label, Flags.ProtectFromClose,
       Protect);
    Status = NtQueryObject(Handle, ObjectBasicInformation, &Basic, sizeof(Basic), &Length);
    ok(Status == STATUS_SUCCESS, "%s: basic 0x%lx\n", Label, Status);
    ok(Basic.Attributes == Attributes, "%s: Attributes 0x%lx, expected 0x%lx\n", Label, Basic.Attributes, Attributes);
    ok(!(Basic.GrantedAccess & INTERNAL_PROTECT_CLOSE_BIT), "%s: GrantedAccess 0x%lx has the internal bit\n", Label,
       Basic.GrantedAccess);
    if (g_PlainAccess)
        ok(Basic.GrantedAccess == g_PlainAccess, "%s: GrantedAccess 0x%lx, expected 0x%lx\n", Label,
           Basic.GrantedAccess, g_PlainAccess);
    else
        g_PlainAccess = Basic.GrantedAccess;
}

/* Finds the handle of this process in SystemHandleInformation (class 16) and SystemExtendedHandleInformation (class 64) */
static void CheckSystemHandle(HANDLE Handle, PCSTR Label)
{
    static const ULONG Classes[2] = { SystemHandleInformation, SystemExtendedHandleInformation };
    ULONG c;

    for (c = 0; c < 2; c++)
    {
        ULONG Size = 0x100000, Length = 0, i;
        BYTE *Buffer;
        NTSTATUS Status;
        BOOLEAN Found = FALSE;

        for (;;)
        {
            Buffer = HeapAlloc(GetProcessHeap(), 0, Size);
            if (!Buffer) return;
            Status = NtQuerySystemInformation(Classes[c], Buffer, Size, &Length);
            if (Status != STATUS_INFO_LENGTH_MISMATCH) break;
            HeapFree(GetProcessHeap(), 0, Buffer);
            Size = Length + 0x10000;
        }
        if (!NT_SUCCESS(Status))
        {
            HeapFree(GetProcessHeap(), 0, Buffer);
            continue;
        }
        if (Classes[c] == SystemHandleInformation)
        {
            PSYSTEM_HANDLE_INFORMATION Info = (PSYSTEM_HANDLE_INFORMATION)Buffer;

            for (i = 0; i < Info->NumberOfHandles; i++)
            {
                PSYSTEM_HANDLE_TABLE_ENTRY_INFO Entry = &Info->Handles[i];

                if (Entry->UniqueProcessId != (USHORT)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueProcess ||
                    Entry->HandleValue != (USHORT)(ULONG_PTR)Handle)
                    continue;
                Found = TRUE;
                ok(Entry->GrantedAccess == g_PlainAccess, "%s: class 16 GrantedAccess 0x%lx, expected 0x%lx\n", Label,
                   Entry->GrantedAccess, g_PlainAccess);
            }
        }
        else
        {
            PSYSTEM_HANDLE_INFORMATION_EX Info = (PSYSTEM_HANDLE_INFORMATION_EX)Buffer;

            for (i = 0; i < Info->NumberOfHandles; i++)
            {
                PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Entry = &Info->Handles[i];

                if (Entry->UniqueProcessId != (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueProcess ||
                    Entry->HandleValue != (ULONG_PTR)Handle)
                    continue;
                Found = TRUE;
                ok(Entry->GrantedAccess == g_PlainAccess, "%s: class 64 GrantedAccess 0x%lx, expected 0x%lx\n", Label,
                   Entry->GrantedAccess, g_PlainAccess);
            }
        }
        ok(Found, "%s: class %lu: handle %p not listed\n", Label, Classes[c], Handle);
        HeapFree(GetProcessHeap(), 0, Buffer);
    }
}

static void Test_Type(TYPE_INDEX Type)
{
    char Label[96];
    HANDLE Handle;
    BYTE Buffer[512];
    POBJECT_TYPE_INFORMATION Info = (POBJECT_TYPE_INFORMATION)Buffer;
    OBJECT_HANDLE_FLAG_INFORMATION Flags;
    ULONG Length;
    NTSTATUS Status;

    sprintf(Label, "%ls plain", g_Types[Type].Name);
    Handle = Create(Type, FALSE);
    if (!Handle) return;
    g_PlainAccess = 0;

    RtlZeroMemory(Buffer, sizeof(Buffer));
    Status = NtQueryObject(Handle, ObjectTypeInformation, Buffer, sizeof(Buffer), &Length);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        ok(Info->PoolType == g_Types[Type].PoolType, "%ls: PoolType %lu, expected %lu\n", g_Types[Type].Name,
           Info->PoolType, g_Types[Type].PoolType);
    }

    CheckFlags(Handle, Label, 0, 0, 0);

    Flags.Inherit = 1;
    Flags.ProtectFromClose = 0;
    Status = NtSetInformationObject(Handle, ObjectHandleFlagInformation, &Flags, sizeof(Flags));
    ok(Status == STATUS_SUCCESS, "%ls: set Inherit 0x%lx\n", g_Types[Type].Name, Status);
    sprintf(Label, "%ls set Inherit", g_Types[Type].Name);
    CheckFlags(Handle, Label, 1, 0, OBJ_INHERIT);

    Flags.ProtectFromClose = 1;
    Status = NtSetInformationObject(Handle, ObjectHandleFlagInformation, &Flags, sizeof(Flags));
    ok(Status == STATUS_SUCCESS, "%ls: set Inherit+Protect 0x%lx\n", g_Types[Type].Name, Status);
    sprintf(Label, "%ls set Inherit+Protect", g_Types[Type].Name);
    CheckFlags(Handle, Label, 1, 1, OBJ_INHERIT | 1);
    CheckSystemHandle(Handle, Label);

    Flags.Inherit = 0;
    Flags.ProtectFromClose = 0;
    Status = NtSetInformationObject(Handle, ObjectHandleFlagInformation, &Flags, sizeof(Flags));
    ok(Status == STATUS_SUCCESS, "%ls: reset 0x%lx\n", g_Types[Type].Name, Status);
    sprintf(Label, "%ls reset", g_Types[Type].Name);
    CheckFlags(Handle, Label, 0, 0, 0);
    NtClose(Handle);

    sprintf(Label, "%ls inheritable", g_Types[Type].Name);
    Handle = Create(Type, TRUE);
    if (!Handle) return;
    CheckFlags(Handle, Label, 1, 0, OBJ_INHERIT);
    NtClose(Handle);
}

static void Test_AllTypes(void)
{
    static const struct { PCWSTR Name; ULONG PoolType; } Expected[] =
    {
        { L"Directory", 1 }, { L"SymbolicLink", 1 }, { L"Token", 1 }, { L"Section", 1 }, { L"Key", 1 },
        { L"KeyedEvent", 1 }, { L"Process", NONPAGED_NX }, { L"Thread", NONPAGED_NX }, { L"Job", NONPAGED_NX },
        { L"DebugObject", NONPAGED_NX }, { L"Event", NONPAGED_NX }, { L"Mutant", NONPAGED_NX },
        { L"Callback", NONPAGED_NX }, { L"Semaphore", NONPAGED_NX }, { L"Timer", NONPAGED_NX },
        { L"IRTimer", NONPAGED_NX }, { L"Profile", NONPAGED_NX }, { L"UserApcReserve", NONPAGED_NX },
        { L"IoCompletionReserve", NONPAGED_NX }, { L"WaitCompletionPacket", NONPAGED_NX },
        { L"WindowStation", NONPAGED_NX }, { L"Desktop", NONPAGED_NX }, { L"Adapter", NONPAGED_NX },
        { L"Controller", NONPAGED_NX }, { L"Device", NONPAGED_NX }, { L"Driver", NONPAGED_NX },
        { L"IoCompletion", NONPAGED_NX }, { L"File", NONPAGED_NX }, { L"WmiGuid", NONPAGED_NX },
    };
    ULONG Size = 0x20000, Length = 0, Count, i, j, Matched = 0;
    BYTE *Buffer = HeapAlloc(GetProcessHeap(), 0, Size);
    BYTE *Entry;
    NTSTATUS Status;

    if (!Buffer) return;
    Status = NtQueryObject(NULL, ObjectTypesInformation, Buffer, Size, &Length);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        Count = *(ULONG *)Buffer;
        Entry = Buffer + sizeof(ULONG_PTR);
        for (i = 0; i < Count; i++)
        {
            POBJECT_TYPE_INFORMATION Info = (POBJECT_TYPE_INFORMATION)Entry;

            for (j = 0; j < RTL_NUMBER_OF(Expected); j++)
            {
                if (Info->TypeName.Length / sizeof(WCHAR) == wcslen(Expected[j].Name) &&
                    !_wcsnicmp(Info->TypeName.Buffer, Expected[j].Name, wcslen(Expected[j].Name)))
                {
                    ok(Info->PoolType == Expected[j].PoolType, "%ls: PoolType %lu, expected %lu\n", Expected[j].Name,
                       Info->PoolType, Expected[j].PoolType);
                    Matched++;
                }
            }
            Entry = (BYTE *)(((ULONG_PTR)Info->TypeName.Buffer + Info->TypeName.MaximumLength + sizeof(ULONG_PTR) - 1) &
                             ~(ULONG_PTR)(sizeof(ULONG_PTR) - 1));
        }
        ok(Matched >= 20, "only %lu of the known types were found\n", Matched);
    }
    HeapFree(GetProcessHeap(), 0, Buffer);
}

START_TEST(NtQueryObjectHandleFlags)
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    ULONG i;

    pAlloc = (PFN_ALLOC)GetProcAddress(hNtdll, "NtAllocateReserveObject");
    pCreateWait = (PFN_CREATEWAIT)GetProcAddress(hNtdll, "NtCreateWaitCompletionPacket");
    if (!pAlloc)
    {
        skip("NtAllocateReserveObject is not exported by ntdll\n");
        return;
    }

    for (i = 0; i < T_COUNT; i++)
        Test_Type(i);
    Test_AllTypes();
}
