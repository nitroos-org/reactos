/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     NtQueryMultipleValueKey, NtCompactKeys, NtQueryOpenSubKeysEx, NtInitializeRegistry
 *              and NtLockProductActivationKeys. The same PE32 image runs natively on i386 and under
 *              WoW64: the results must be the same. A service the kernel does not implement
 *              (STATUS_NOT_IMPLEMENTED) is only checked for its arguments being passed through
 *              unchanged; one that is implemented is checked for its documented results.
 */

#include "precomp.h"

#ifndef REG_SZ
#define REG_SZ          1
#define REG_BINARY      3
#define REG_DWORD       4
#define REG_MULTI_SZ    7
#endif

#define TEST_ROOT   L"\\Registry\\Machine\\SOFTWARE"
#define TEST_KEY    L"\\Registry\\Machine\\SOFTWARE\\NtRegistryServices_apitest"
#define TEST_KEY2   L"\\Registry\\Machine\\SOFTWARE\\NtRegistryServices_apitest\\Sub"

/* Layout of the NtQueryOpenSubKeysEx output buffer */
typedef struct
{
    HANDLE ProcessId;
    UNICODE_STRING KeyName;
} TEST_KEY_PID;

typedef struct
{
    ULONG Count;
    TEST_KEY_PID KeyArray[1];
} TEST_OPEN_SUBKEYS;

static NTSTATUS CreateTestKey(PHANDLE Key, PCWSTR Path)
{
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES Attributes;
    RtlInitUnicodeString(&Name, Path);
    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    return NtCreateKey(Key, KEY_ALL_ACCESS, &Attributes, 0, NULL, REG_OPTION_VOLATILE, NULL);
}

static NTSTATUS OpenTestKey(PHANDLE Key, PCWSTR Path)
{
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES Attributes;
    RtlInitUnicodeString(&Name, Path);
    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    return NtOpenKey(Key, KEY_READ | KEY_WRITE, &Attributes);
}

static void SetValue(HANDLE Key, PCWSTR Name, ULONG Type, const void *Data, ULONG Size)
{
    UNICODE_STRING ValueName;
    NTSTATUS Status;
    RtlInitUnicodeString(&ValueName, Name);
    Status = NtSetValueKey(Key, &ValueName, 0, Type, (PVOID)Data, Size);
    ok_ntstatus(Status, STATUS_SUCCESS);
}

static void Test_QueryMultipleValueKey(HANDLE Key)
{
    static const WCHAR Text[] = L"hello";
    static const ULONG Number = 0x12345678;
    static const UCHAR Blob[5] = {1, 2, 3, 4, 5};
    static const WCHAR Multi[] = L"a\0b\0";
    static const WCHAR *Names[4] = {L"Text", L"Number", L"Blob", L"Multi"};
    UNICODE_STRING Strings[4], Missing;
    KEY_VALUE_ENTRY Entries[4];
    UCHAR Buffer[256];
    ULONG Length, Required, i, Total;
    ULONG Types[4] = {REG_SZ, REG_DWORD, REG_BINARY, REG_MULTI_SZ};
    ULONG Sizes[4] = {sizeof(Text), sizeof(Number), sizeof(Blob), sizeof(Multi)};
    const void *Data[4] = {Text, &Number, Blob, Multi};
    NTSTATUS Status;

    SetValue(Key, Names[0], REG_SZ, Text, sizeof(Text));
    SetValue(Key, Names[1], REG_DWORD, &Number, sizeof(Number));
    SetValue(Key, Names[2], REG_BINARY, Blob, sizeof(Blob));
    SetValue(Key, Names[3], REG_MULTI_SZ, Multi, sizeof(Multi));
    Total = sizeof(Text) + sizeof(Number) + sizeof(Blob) + sizeof(Multi);

    for (i = 0; i < 4; i++)
    {
        RtlInitUnicodeString(&Strings[i], Names[i]);
        Entries[i].ValueName = &Strings[i];
        Entries[i].DataLength = 0x55555555;
        Entries[i].DataOffset = 0x66666666;
        Entries[i].Type = 0x77777777;
    }

    /* A buffer that is large enough */
    RtlFillMemory(Buffer, sizeof(Buffer), 0xAA);
    Length = sizeof(Buffer);
    Required = 0x88888888;
    Status = NtQueryMultipleValueKey(Key, Entries, 4, Buffer, &Length, &Required);
    ok(Status != STATUS_INVALID_SYSTEM_SERVICE, "Status = 0x%lx\n", Status);
    if (Status == STATUS_NOT_IMPLEMENTED)
    {
        skip("NtQueryMultipleValueKey is not implemented, checking the pass-through only\n");
        for (i = 0; i < 4; i++)
        {
            ok(Entries[i].ValueName == &Strings[i], "[%lu] ValueName = %p\n", i, Entries[i].ValueName);
            ok(Entries[i].DataLength == 0x55555555, "[%lu] DataLength = 0x%lx\n", i, Entries[i].DataLength);
            ok(Entries[i].DataOffset == 0x66666666, "[%lu] DataOffset = 0x%lx\n", i, Entries[i].DataOffset);
            ok(Entries[i].Type == 0x77777777, "[%lu] Type = 0x%lx\n", i, Entries[i].Type);
        }
        ok(Length == sizeof(Buffer), "Length = %lu\n", Length);
        ok(Required == 0x88888888, "Required = 0x%lx\n", Required);
        return;
    }

    ok_ntstatus(Status, STATUS_SUCCESS);
    for (i = 0; i < 4; i++)
    {
        ok(Entries[i].Type == Types[i], "[%lu] Type = %lu\n", i, Entries[i].Type);
        ok(Entries[i].DataLength == Sizes[i], "[%lu] DataLength = %lu\n", i, Entries[i].DataLength);
        ok(Entries[i].DataOffset + Entries[i].DataLength <= sizeof(Buffer),
           "[%lu] DataOffset = %lu\n", i, Entries[i].DataOffset);
        if (Entries[i].DataOffset + Entries[i].DataLength <= sizeof(Buffer))
            ok(!memcmp(Buffer + Entries[i].DataOffset, Data[i], Sizes[i]), "[%lu] data differs\n", i);
    }
    ok(Length >= Total && Length <= sizeof(Buffer), "Length = %lu\n", Length);
    ok(Required >= Total, "Required = %lu\n", Required);

    /* Too small: the size that is needed comes back */
    Length = 8;
    Required = 0x88888888;
    Status = NtQueryMultipleValueKey(Key, Entries, 4, Buffer, &Length, &Required);
    ok_ntstatus(Status, STATUS_BUFFER_OVERFLOW);
    ok(Required >= Total, "Required = %lu\n", Required);

    /* A value that does not exist */
    RtlInitUnicodeString(&Missing, L"NoSuchValue");
    Entries[1].ValueName = &Missing;
    Length = sizeof(Buffer);
    Status = NtQueryMultipleValueKey(Key, Entries, 4, Buffer, &Length, &Required);
    ok_ntstatus(Status, STATUS_OBJECT_NAME_NOT_FOUND);
}

static void Test_CompactKeys(HANDLE Key1, HANDLE Key2)
{
    HANDLE Keys[2] = {Key1, Key2};
    NTSTATUS Status;

    Status = NtCompactKeys(2, Keys);
    ok(Status != STATUS_INVALID_SYSTEM_SERVICE, "Status = 0x%lx\n", Status);
    ok(Status == STATUS_NOT_IMPLEMENTED || Status == STATUS_SUCCESS ||
       Status == STATUS_PRIVILEGE_NOT_HELD || Status == STATUS_ACCESS_DENIED ||
       Status == STATUS_INVALID_PARAMETER, "Status = 0x%lx\n", Status);
    ok(Keys[0] == Key1 && Keys[1] == Key2, "the array changed\n");

    /* A handle that is not valid: never a success */
    Keys[1] = (HANDLE)(ULONG_PTR)-4;
    Status = NtCompactKeys(2, Keys);
    ok(Status != STATUS_SUCCESS && Status != STATUS_INVALID_SYSTEM_SERVICE, "Status = 0x%lx\n", Status);

    Status = NtCompactKeys(0, Keys);
    ok(Status != STATUS_INVALID_SYSTEM_SERVICE, "Status = 0x%lx\n", Status);
}

static void Test_QueryOpenSubKeysEx(void)
{
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES Attributes;
    HANDLE Sub1, Sub2;
    UCHAR Buffer[0x2000];
    TEST_OPEN_SUBKEYS *Info = (TEST_OPEN_SUBKEYS *)Buffer;
    ULONG Required, Count, i, Mine = 0;
    NTSTATUS Status;

    /* Open sub keys of a loaded hive root, from this process */
    Status = OpenTestKey(&Sub1, TEST_KEY);
    ok_ntstatus(Status, STATUS_SUCCESS);
    Status = OpenTestKey(&Sub2, TEST_KEY2);
    ok_ntstatus(Status, STATUS_SUCCESS);

    RtlInitUnicodeString(&Name, TEST_ROOT);
    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);

    RtlFillMemory(Buffer, sizeof(Buffer), 0xAA);
    Required = 0x88888888;
    Status = NtQueryOpenSubKeysEx(&Attributes, sizeof(Buffer), Buffer, &Required);
    ok(Status != STATUS_INVALID_SYSTEM_SERVICE, "Status = 0x%lx\n", Status);
    if (Status == STATUS_NOT_IMPLEMENTED)
    {
        skip("NtQueryOpenSubKeysEx is not implemented, checking the pass-through only\n");
        ok(Required == 0x88888888, "Required = 0x%lx\n", Required);
        ok(Buffer[0] == 0xAA && Buffer[sizeof(Buffer) - 1] == 0xAA, "the buffer was written\n");
    }
    else
    {
        ok_ntstatus(Status, STATUS_SUCCESS);
        Count = Info->Count;
        ok(Count >= 2 && Count < 1000, "Count = %lu\n", Count);
        ok(Required >= sizeof(ULONG) + Count * sizeof(TEST_KEY_PID), "Required = %lu\n", Required);
        ok(Required <= sizeof(Buffer), "Required = %lu\n", Required);
        for (i = 0; i < Count && i < 1000; i++)
        {
            const UCHAR *Text = (const UCHAR *)Info->KeyArray[i].KeyName.Buffer;
            ok(Text >= Buffer && Text + Info->KeyArray[i].KeyName.Length <= Buffer + sizeof(Buffer),
               "[%lu] name outside the buffer: %p\n", i, Text);
            if (Info->KeyArray[i].ProcessId == NtCurrentTeb()->ClientId.UniqueProcess)
                Mine++;
        }
        ok(Mine >= 2, "only %lu of the keys are this process's\n", Mine);

        /* Too small */
        Required = 0x88888888;
        Status = NtQueryOpenSubKeysEx(&Attributes, 0, Buffer, &Required);
        ok(Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW, "Status = 0x%lx\n", Status);
        ok(Required >= sizeof(ULONG), "Required = %lu\n", Required);
    }

    /* A key that is not a hive root */
    RtlInitUnicodeString(&Name, TEST_KEY);
    Status = NtQueryOpenSubKeysEx(&Attributes, sizeof(Buffer), Buffer, &Required);
    ok(Status != STATUS_INVALID_SYSTEM_SERVICE && Status != STATUS_SUCCESS, "Status = 0x%lx\n", Status);

    NtClose(Sub2);
    NtClose(Sub1);
}

static void Test_Others(void)
{
    ULONG Version = 0x55555555, SafeMode = 0x55555555;
    NTSTATUS Status;

    Status = NtLockProductActivationKeys(&Version, &SafeMode);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok(Version != 0x55555555, "Version unchanged\n");
    ok(SafeMode == 0 || SafeMode == 1 || SafeMode == 2, "SafeMode = %lu\n", SafeMode);

    Version = 0x55555555;
    Status = NtLockProductActivationKeys(&Version, NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok(Version != 0x55555555, "Version unchanged\n");

    Status = NtLockProductActivationKeys(NULL, NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);

    /* A pointer that cannot be written */
    Status = NtLockProductActivationKeys((PULONG)(ULONG_PTR)0x10, NULL);
    ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);

    /* The registry is initialized long ago: a flag out of range, then the first-boot one */
    Status = NtInitializeRegistry(0xFFFF);
    ok_ntstatus(Status, STATUS_INVALID_PARAMETER);
    Status = NtInitializeRegistry(0);
    ok_ntstatus(Status, STATUS_ACCESS_DENIED);
}

START_TEST(NtRegistryServices)
{
    HANDLE Key, Sub;
    NTSTATUS Status;

    Status = CreateTestKey(&Key, TEST_KEY);
    if (!NT_SUCCESS(Status))
    {
        skip("Cannot create the test key: 0x%lx\n", Status);
        return;
    }
    Status = CreateTestKey(&Sub, TEST_KEY2);
    ok_ntstatus(Status, STATUS_SUCCESS);

    Test_QueryMultipleValueKey(Key);
    Test_CompactKeys(Key, Sub);
    Test_QueryOpenSubKeysEx();
    Test_Others();

    NtDeleteKey(Sub);
    NtClose(Sub);
    NtDeleteKey(Key);
    NtClose(Key);
}
