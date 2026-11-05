/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test for RtlQueryRegistryValues default values
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */

#include "precomp.h"
#include <winreg.h>
#include <pseh/pseh2.h>

#define KEY_PATH L"\\Registry\\Machine\\Software"
#define MISSING_VALUE L"ReactOS_apitest_RtlQueryRegistryValues_Missing"

typedef struct _QUERY_RESULT
{
    ULONG Calls;
    ULONG Type;
    ULONG Length;
    WCHAR Text[16];
} QUERY_RESULT, *PQUERY_RESULT;

static
NTSTATUS
NTAPI
QueryRoutine(
    _In_ PWSTR ValueName,
    _In_ ULONG ValueType,
    _In_ PVOID ValueData,
    _In_ ULONG ValueLength,
    _In_ PVOID Context,
    _In_ PVOID EntryContext)
{
    PQUERY_RESULT Result = EntryContext;

    Result->Calls++;
    Result->Type = ValueType;
    Result->Length = ValueLength;
    if (ValueData && ValueLength <= sizeof(Result->Text))
        RtlCopyMemory(Result->Text, ValueData, ValueLength);
    return STATUS_SUCCESS;
}

/* Query a value that does not exist, so that the table's default is used */
static
NTSTATUS
QueryDefault(
    _In_ ULONG Type,
    _In_opt_ PVOID DefaultData,
    _Out_ PBOOLEAN Faulted,
    _Out_ PQUERY_RESULT Result)
{
    RTL_QUERY_REGISTRY_TABLE Table[2];
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    RtlZeroMemory(Table, sizeof(Table));
    RtlZeroMemory(Result, sizeof(*Result));
    Table[0].QueryRoutine = QueryRoutine;
    Table[0].Name = MISSING_VALUE;
    Table[0].EntryContext = Result;
    Table[0].DefaultType = Type;
    Table[0].DefaultData = DefaultData;
    Table[0].DefaultLength = 0;

    *Faulted = FALSE;
    _SEH2_TRY
    {
        Status = RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, KEY_PATH, Table, NULL, NULL);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        *Faulted = TRUE;
    }
    _SEH2_END;

    return Status;
}

#define BOUNDS_KEY_PATH L"\\Registry\\Machine\\Software\\ReactOS_apitest_RtlQueryRegistryValues_Bounds"

typedef struct _COLLECT
{
    ULONG Calls;
    ULONG Type;
    ULONG MaxLength;
    PCWSTR Wanted;      /* only the value of this name is recorded */
    WCHAR First[8];
} COLLECT, *PCOLLECT;

static
NTSTATUS
NTAPI
CollectRoutine(
    _In_ PWSTR ValueName,
    _In_ ULONG ValueType,
    _In_ PVOID ValueData,
    _In_ ULONG ValueLength,
    _In_ PVOID Context,
    _In_ PVOID EntryContext)
{
    PCOLLECT Collect = EntryContext;

    if (Collect->Wanted && _wcsicmp(ValueName, Collect->Wanted))
        return STATUS_SUCCESS;

    if (!Collect->Calls)
    {
        Collect->Type = ValueType;
        RtlZeroMemory(Collect->First, sizeof(Collect->First));
        RtlCopyMemory(Collect->First, ValueData, min(ValueLength, sizeof(Collect->First) - sizeof(WCHAR)));
    }
    Collect->Calls++;
    Collect->MaxLength = max(Collect->MaxLength, ValueLength);
    return STATUS_SUCCESS;
}

static
VOID
SetBoundsValue(
    _In_ HANDLE Key,
    _In_ PCWSTR Name,
    _In_ ULONG Type,
    _In_ const VOID *Data,
    _In_ ULONG Size)
{
    UNICODE_STRING ValueName;
    NTSTATUS Status;

    RtlInitUnicodeString(&ValueName, Name);
    Status = NtSetValueKey(Key, &ValueName, 0, Type, (PVOID)Data, Size);
    ok_hex(Status, STATUS_SUCCESS);
}

/* One query of a value of the bounds key. Returns FALSE when it faulted */
static
BOOLEAN
QueryBounds(
    _In_ PCWSTR Name,
    _In_ ULONG Flags,
    _In_ PVOID EntryContext,
    _Out_ NTSTATUS *Status)
{
    RTL_QUERY_REGISTRY_TABLE Table[2];
    BOOLEAN Faulted = FALSE;

    RtlZeroMemory(Table, sizeof(Table));
    Table[0].Flags = Flags;
    Table[0].QueryRoutine = (Flags & RTL_QUERY_REGISTRY_DIRECT) ? NULL : CollectRoutine;
    Table[0].Name = (PWSTR)Name;
    Table[0].EntryContext = EntryContext;
    Table[0].DefaultType = REG_NONE;

    *Status = STATUS_UNSUCCESSFUL;
    _SEH2_TRY
    {
        *Status = RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, BOUNDS_KEY_PATH, Table, NULL, NULL);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Faulted = TRUE;
    }
    _SEH2_END;
    return !Faulted;
}

/*
 * Values the registry hands to a query that are short, odd-sized or not terminated must neither
 * wrap a length nor make the query read or write outside its buffers.
 */
static
VOID
TestValueBounds(VOID)
{
    static const WCHAR Hello[] = L"hello";
    static const UCHAR OneByte[1] = { 'x' };
    static const UCHAR OddExpand[5] = { 'A', 0, 'B', 0, 'C' };
    static const WCHAR NoTerminator[4] = { L'a', L'b', L'c', L'd' };
    static const UCHAR Binary[12] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING KeyName;
    HANDLE Key;
    NTSTATUS Status;
    ULONG Disposition;
    COLLECT Collect;
    PUNICODE_STRING Direct;
    PULONG Buffer;
    PVOID Guarded;
    ULONG Dword = 0x12345678;

    RtlInitUnicodeString(&KeyName, BOUNDS_KEY_PATH);
    InitializeObjectAttributes(&ObjectAttributes, &KeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtCreateKey(&Key, KEY_ALL_ACCESS, &ObjectAttributes, 0, NULL, REG_OPTION_VOLATILE, &Disposition);
    if (!NT_SUCCESS(Status))
    {
        skip("Cannot create the test key: 0x%08lx\n", Status);
        return;
    }

    SetBoundsValue(Key, L"Str", REG_SZ, Hello, sizeof(Hello));
    SetBoundsValue(Key, L"Empty", REG_SZ, NULL, 0);
    SetBoundsValue(Key, L"One", REG_SZ, OneByte, sizeof(OneByte));
    SetBoundsValue(Key, L"OddExpand", REG_EXPAND_SZ, OddExpand, sizeof(OddExpand));
    SetBoundsValue(Key, L"NoTerm", REG_MULTI_SZ, NoTerminator, sizeof(NoTerminator));
    SetBoundsValue(Key, L"Bin", REG_BINARY, Binary, sizeof(Binary));
    SetBoundsValue(Key, L"Dword", REG_DWORD, &Dword, sizeof(Dword));

    /* A normal string is returned in a string the call allocates */
    Direct = AllocateGuarded(sizeof(*Direct));
    RtlZeroMemory(Direct, sizeof(*Direct));
    ok(QueryBounds(L"Str", RTL_QUERY_REGISTRY_DIRECT, Direct, &Status), "Str faulted\n");
    ok_hex(Status, STATUS_SUCCESS);
    ok_int(Direct->Length, sizeof(L"hello") - sizeof(WCHAR));
    ok_int(Direct->MaximumLength, sizeof(Hello));
    ok(Direct->Buffer && !wcscmp(Direct->Buffer, L"hello"), "Str: got '%ls'\n", Direct->Buffer);
    RtlFreeUnicodeString(Direct);

    /* An empty value and a one-byte value have no characters: the length must not wrap */
    RtlZeroMemory(Direct, sizeof(*Direct));
    ok(QueryBounds(L"Empty", RTL_QUERY_REGISTRY_DIRECT, Direct, &Status), "Empty faulted\n");
    ok_hex(Status, STATUS_SUCCESS);
    ok_int(Direct->Length, 0);
    ok(Direct->Length <= Direct->MaximumLength, "Empty: Length %u, MaximumLength %u\n", Direct->Length, Direct->MaximumLength);
    if (Direct->Buffer) RtlFreeUnicodeString(Direct);

    RtlZeroMemory(Direct, sizeof(*Direct));
    ok(QueryBounds(L"One", RTL_QUERY_REGISTRY_DIRECT, Direct, &Status), "One faulted\n");
    ok_hex(Status, STATUS_SUCCESS);
    ok_int(Direct->Length, 0);
    ok(Direct->Length <= Direct->MaximumLength, "One: Length %u, MaximumLength %u\n", Direct->Length, Direct->MaximumLength);
    if (Direct->Buffer) RtlFreeUnicodeString(Direct);
    FreeGuarded(Direct);

    /* The same into a caller's string, which ends at the guard page */
    Guarded = AllocateGuarded(sizeof(WCHAR));
    Direct = AllocateGuarded(sizeof(*Direct));
    Direct->Buffer = Guarded;
    Direct->Length = 0x1234;
    Direct->MaximumLength = sizeof(WCHAR);
    ok(QueryBounds(L"Empty", RTL_QUERY_REGISTRY_DIRECT, Direct, &Status), "Empty (caller buffer) faulted\n");
    ok_hex(Status, STATUS_SUCCESS);
    ok(Direct->Length == 0 || Direct->Length == 0x1234, "Empty (caller buffer): Length %u\n", Direct->Length);
    Direct->Length = 0x1234;
    ok(QueryBounds(L"One", RTL_QUERY_REGISTRY_DIRECT, Direct, &Status), "One (caller buffer) faulted\n");
    ok_hex(Status, STATUS_SUCCESS);
    ok_int(Direct->Length, 0);
    FreeGuarded(Direct);
    FreeGuarded(Guarded);

    /* REG_BINARY: a caller size smaller than the data stops the copy, nothing lands behind the buffer */
    Buffer = AllocateGuarded(8);
    Buffer[0] = 8;
    Buffer[1] = 0xAAAAAAAA;
    ok(QueryBounds(L"Bin", RTL_QUERY_REGISTRY_DIRECT, Buffer, &Status), "Bin (small buffer) faulted\n");
    ok(Buffer[0] == 8 && Buffer[1] == 0xAAAAAAAA, "Bin: buffer changed: %08lx %08lx\n", Buffer[0], Buffer[1]);
    FreeGuarded(Buffer);

    Buffer = AllocateGuarded(16);
    RtlFillMemory(Buffer, 16, 0xAA);
    Buffer[0] = (ULONG)-8;      /* negative: the buffer holds only the data, 8 bytes are available */
    ok(QueryBounds(L"Bin", RTL_QUERY_REGISTRY_DIRECT, Buffer, &Status), "Bin (negative size) faulted\n");
    ok(Buffer[0] == (ULONG)-8 && Buffer[3] == 0xAAAAAAAA, "Bin: buffer changed with a negative size\n");
    Buffer[0] = (ULONG)-16;
    ok(QueryBounds(L"Bin", RTL_QUERY_REGISTRY_DIRECT, Buffer, &Status), "Bin (negative size, room) faulted\n");
    ok_hex(Status, STATUS_SUCCESS);
    ok(!memcmp(Buffer, Binary, sizeof(Binary)) && Buffer[3] == 0xAAAAAAAA, "Bin: wrong data\n");
    FreeGuarded(Buffer);

    /* REG_BINARY with room for the data keeps working */
    Buffer = AllocateGuarded(12);
    Buffer[0] = 12;
    ok(QueryBounds(L"Bin", RTL_QUERY_REGISTRY_DIRECT, Buffer, &Status), "Bin (exact buffer) faulted\n");
    ok_hex(Status, STATUS_SUCCESS);
    ok(!memcmp(Buffer, Binary, sizeof(Binary)), "Bin: wrong data in an exact buffer\n");
    FreeGuarded(Buffer);

    /* A DWORD into its slot */
    Buffer = AllocateGuarded(sizeof(ULONG));
    ok(QueryBounds(L"Dword", RTL_QUERY_REGISTRY_DIRECT, Buffer, &Status), "Dword faulted\n");
    ok_hex(Status, STATUS_SUCCESS);
    ok_hex(*Buffer, Dword);
    FreeGuarded(Buffer);

    /* REG_EXPAND_SZ of an odd size: the scan for '%' stops at the value */
    RtlZeroMemory(&Collect, sizeof(Collect));
    Collect.Wanted = L"OddExpand";
    ok(QueryBounds(L"OddExpand", 0, &Collect, &Status), "OddExpand faulted\n");
    ok_hex(Status, STATUS_SUCCESS);
    ok_int(Collect.Calls, 1);
    ok(Collect.MaxLength <= sizeof(OddExpand), "OddExpand: length %lu\n", Collect.MaxLength);

    /*
     * REG_MULTI_SZ whose strings run to the end of the value: no string reaches past the data.
     * A query by name appends one terminator to the value (as Windows does), so it may see one more
     * character; an enumeration of the key's values does not.
     */
    RtlZeroMemory(&Collect, sizeof(Collect));
    Collect.Wanted = L"NoTerm";
    ok(QueryBounds(L"NoTerm", 0, &Collect, &Status), "NoTerm faulted\n");
    ok_hex(Status, STATUS_SUCCESS);
    ok(Collect.MaxLength <= sizeof(NoTerminator) + sizeof(WCHAR),
       "NoTerm: a string of %lu bytes from a value of %u\n", Collect.MaxLength, (UINT)sizeof(NoTerminator));

    RtlZeroMemory(&Collect, sizeof(Collect));
    Collect.Wanted = L"NoTerm";
    ok(QueryBounds(NULL, 0, &Collect, &Status), "NoTerm (enumeration) faulted\n");
    ok_hex(Status, STATUS_SUCCESS);
    ok(Collect.MaxLength <= sizeof(NoTerminator),
       "NoTerm (enumeration): a string of %lu bytes from a value of %u\n", Collect.MaxLength, (UINT)sizeof(NoTerminator));

    NtDeleteKey(Key);
    NtClose(Key);
}

START_TEST(RtlQueryRegistryValues)
{
    static const ULONG Types[] = { REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ };
    static const WCHAR Default[] = L"Default\0";
    QUERY_RESULT Result;
    NTSTATUS Status;
    BOOLEAN Faulted;
    ULONG i;

    for (i = 0; i < _countof(Types); i++)
    {
        /* A string default with DefaultLength 0 is measured */
        Status = QueryDefault(Types[i], (PVOID)Default, &Faulted, &Result);
        ok(!Faulted, "Type %lu: valid default faulted\n", Types[i]);
        ok_hex(Status, STATUS_SUCCESS);
        ok(Result.Calls == 1, "Type %lu: %lu calls\n", Types[i], Result.Calls);
        ok(Result.Type == (Types[i] == REG_EXPAND_SZ ? REG_EXPAND_SZ : REG_SZ),
           "Type %lu: got type %lu\n", Types[i], Result.Type);
        ok(Result.Length == sizeof(L"Default"), "Type %lu: got length %lu\n", Types[i], Result.Length);
        ok(!wcscmp(Result.Text, L"Default"), "Type %lu: got '%ls'\n", Types[i], Result.Text);

        /* Without data there is nothing to measure: the query fails, no fault */
        Status = QueryDefault(Types[i], NULL, &Faulted, &Result);
        ok(!Faulted, "Type %lu: NULL default faulted\n", Types[i]);
        if (!Faulted)
            ok_hex(Status, STATUS_DATA_OVERRUN);
        ok(Result.Calls == 0, "Type %lu: %lu calls\n", Types[i], Result.Calls);
    }

    TestValueBounds();
}
