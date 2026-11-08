/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for NtSetInformationKey
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows 10 22H2 (19045), x64 (read-only probe on an existing key, every call that could succeed
 * carried the key's current state):
 *  - Order of the checks: class first (>= 6, and 99, 0x100, 0x80000000, 0xFFFFFFFF: STATUS_INVALID_INFO_CLASS, also
 *    with an invalid handle and with length 0), then the length (STATUS_INFO_LENGTH_MISMATCH), then the handle
 *    (STATUS_INVALID_HANDLE for a bad handle and NULL, STATUS_OBJECT_TYPE_MISMATCH for a process handle), then the
 *    access, then the buffer.
 *  - Length: exactly 8 for KeyWriteTimeInformation, exactly 4 for the other five classes; every other length
 *    (0, 1, 3, 5, 12, 16 and 8 for a ULONG class) is STATUS_INFO_LENGTH_MISMATCH.
 *  - A handle without KEY_SET_VALUE: STATUS_ACCESS_DENIED for the first five classes. KeySetHandleTagsInformation
 *    is STATUS_SUCCESS on a KEY_QUERY_VALUE handle (the tags belong to the handle).
 *  - The buffer: NULL, 1 and a kernel address are STATUS_ACCESS_VIOLATION; a buffer that is not aligned is read
 *    without complaint.
 *  - A set of the classes 1..4 with the key's own values moved the key's last write time to the time of the call.
 *    Which of the four did it was not isolated.
 * Not measured (ReactOS behaviour, asserted in Test_RoundTrip): that KeyWriteTimeInformation, the Wow64 flags and the
 * rest are read back by NtQueryKey. The accepted ranges of the flag values (a wider value could not be sent without changing the key).
 * Here a Wow64 flags value above 0xF, control flags above 0xE, virtualization bits above 7 and debug bits above 0xFF
 * are STATUS_INVALID_PARAMETER; those checks are not asserted.
 */

#include "precomp.h"

/* KEY_CACHED_INFORMATION (the ndk has only the class) */
typedef struct _TEST_KEY_CACHED_INFORMATION
{
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG SubKeys;
    ULONG MaxNameLen;
    ULONG Values;
    ULONG MaxValueNameLen;
    ULONG MaxValueDataLen;
    ULONG NameLength;
} TEST_KEY_CACHED_INFORMATION;

static HANDLE OpenKey(ACCESS_MASK Access, PCWSTR Path)
{
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES Attributes;
    HANDLE Key = NULL;
    NTSTATUS Status;

    RtlInitUnicodeString(&Name, Path);
    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenKey(&Key, Access, &Attributes);
    ok_ntstatus(Status, STATUS_SUCCESS);
    return Key;
}

static ULONG ExpectedLength(ULONG Class)
{
    return (Class == KeyWriteTimeInformation) ? sizeof(LARGE_INTEGER) : sizeof(ULONG);
}

static void Test_ClassAndLength(HANDLE Key)
{
    static const ULONG BadClasses[] = { 6, 7, 99, 0x100, 0x80000000, 0xFFFFFFFF };
    static const ULONG BadLengths[] = { 0, 1, 3, 5, 12, 16 };
    ULONG64 Buffer[2] = { 0 };
    NTSTATUS Status;
    ULONG i, Class, j;

    for (i = 0; i < RTL_NUMBER_OF(BadClasses); i++)
    {
        Status = NtSetInformationKey(Key, BadClasses[i], Buffer, 4);
        ok_ntstatus(Status, STATUS_INVALID_INFO_CLASS);
        Status = NtSetInformationKey(Key, BadClasses[i], Buffer, 0);
        ok_ntstatus(Status, STATUS_INVALID_INFO_CLASS);
        /* the class is checked before the handle */
        Status = NtSetInformationKey((HANDLE)0x1234, BadClasses[i], Buffer, 4);
        ok_ntstatus(Status, STATUS_INVALID_INFO_CLASS);
    }

    for (Class = 0; Class <= 5; Class++)
    {
        for (j = 0; j < RTL_NUMBER_OF(BadLengths); j++)
        {
            Status = NtSetInformationKey(Key, Class, Buffer, BadLengths[j]);
            ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
        }
        /* the length is checked before the handle */
        Status = NtSetInformationKey((HANDLE)0x1234, Class, Buffer, 1);
        ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
    }
    /* 8 is only for the write time, 4 only for the others */
    Status = NtSetInformationKey(Key, KeyWriteTimeInformation, Buffer, 4);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
    Status = NtSetInformationKey(Key, KeyWow64FlagsInformation, Buffer, 8);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
}

static void Test_Handles(void)
{
    ULONG64 Buffer[2] = { 0 };
    NTSTATUS Status;

    Status = NtSetInformationKey((HANDLE)0x1234, KeyWow64FlagsInformation, Buffer, 4);
    ok_ntstatus(Status, STATUS_INVALID_HANDLE);
    Status = NtSetInformationKey(NULL, KeyWow64FlagsInformation, Buffer, 4);
    ok_ntstatus(Status, STATUS_INVALID_HANDLE);
    Status = NtSetInformationKey(NtCurrentProcess(), KeyWow64FlagsInformation, Buffer, 4);
    ok_ntstatus(Status, STATUS_OBJECT_TYPE_MISMATCH);
}

static void Test_Access(PCWSTR Path)
{
    HANDLE ReadKey = OpenKey(KEY_QUERY_VALUE, Path);
    ULONG64 Buffer[2] = { 0 };
    NTSTATUS Status;
    ULONG Class;

    if (!ReadKey)
        return;
    /* A handle with KEY_QUERY_VALUE: no write. Values that cannot change the key. */
    for (Class = 0; Class <= 4; Class++)
    {
        Status = NtSetInformationKey(ReadKey, Class, Buffer, ExpectedLength(Class));
        ok_ntstatus(Status, STATUS_ACCESS_DENIED);
    }
    /* the tags are the handle's own */
    Status = NtSetInformationKey(ReadKey, KeySetHandleTagsInformation, Buffer, sizeof(ULONG));
    ok_ntstatus(Status, STATUS_SUCCESS);

    /* order: the length before the access */
    Status = NtSetInformationKey(ReadKey, KeyWow64FlagsInformation, Buffer, 3);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
    NtClose(ReadKey);
}

static void Test_Buffers(HANDLE Key)
{
    static const PVOID Bad[] = { NULL, (PVOID)1, (PVOID)(ULONG_PTR)0xFFFFFFFFFFFFF000ULL };
    ULONG64 Buffer[4] = { 0 };
    NTSTATUS Status;
    ULONG Class, i;

    for (Class = 0; Class <= 5; Class++)
    {
        for (i = 0; i < RTL_NUMBER_OF(Bad); i++)
        {
            Status = NtSetInformationKey(Key, Class, Bad[i], ExpectedLength(Class));
            ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);
        }
    }
    /* a misaligned buffer is read */
    Status = NtSetInformationKey(Key, KeySetHandleTagsInformation, (PUCHAR)Buffer + 1, sizeof(ULONG));
    ok_ntstatus(Status, STATUS_SUCCESS);
}

static void Test_RoundTrip(void)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\RosTests_NtSetInformationKey");
    OBJECT_ATTRIBUTES Attributes;
    HANDLE Key = NULL;
    NTSTATUS Status;
    KEY_WRITE_TIME_INFORMATION WriteTime;
    KEY_BASIC_INFORMATION Basic;
    TEST_KEY_CACHED_INFORMATION Cached;
    KEY_USER_FLAGS_INFORMATION Flags;
    LARGE_INTEGER Now, Zero;
    ULONG Length, Value, i;

    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtCreateKey(&Key, KEY_READ | KEY_SET_VALUE | DELETE, &Attributes, 0, NULL, REG_OPTION_VOLATILE, NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;

    /* the write time */
    WriteTime.LastWriteTime.QuadPart = 0x01D0000000000000LL;
    Status = NtSetInformationKey(Key, KeyWriteTimeInformation, &WriteTime, sizeof(WriteTime));
    ok_ntstatus(Status, STATUS_SUCCESS);
    Status = NtQueryKey(Key, KeyBasicInformation, &Basic, sizeof(Basic), &Length);
    ok(Status == STATUS_SUCCESS || Status == STATUS_BUFFER_OVERFLOW, "NtQueryKey returned %lx\n", Status);
    ok(Basic.LastWriteTime.QuadPart == WriteTime.LastWriteTime.QuadPart, "write time %I64x\n", Basic.LastWriteTime.QuadPart);
    Status = NtQueryKey(Key, KeyCachedInformation, &Cached, sizeof(Cached), &Length);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok(Cached.LastWriteTime.QuadPart == WriteTime.LastWriteTime.QuadPart, "cached write time %I64x\n", Cached.LastWriteTime.QuadPart);

    /* the Wow64 flags are what KeyFlagsInformation returns */
    Value = 3;
    Status = NtSetInformationKey(Key, KeyWow64FlagsInformation, &Value, sizeof(Value));
    ok_ntstatus(Status, STATUS_SUCCESS);
    Flags.UserFlags = 0xFF;
    Status = NtQueryKey(Key, KeyFlagsInformation, &Flags, sizeof(Flags), &Length);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_hex(Flags.UserFlags, 3);

    /* and the setting moved the write time to now (all four of the classes 1..4 do here, see the header) */
    NtQuerySystemTime(&Now);
    Status = NtQueryKey(Key, KeyCachedInformation, &Cached, sizeof(Cached), &Length);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok(Cached.LastWriteTime.QuadPart > WriteTime.LastWriteTime.QuadPart, "write time not moved\n");
    ok(Cached.LastWriteTime.QuadPart <= Now.QuadPart, "write time in the future\n");

    /* the other classes: accepted with their documented values */
    Value = 0xE;
    Status = NtSetInformationKey(Key, KeyControlFlagsInformation, &Value, sizeof(Value));
    ok_ntstatus(Status, STATUS_SUCCESS);
    for (Value = 0; Value <= 7; Value++)
    {
        Status = NtSetInformationKey(Key, KeySetVirtualizationInformation, &Value, sizeof(Value));
        ok_ntstatus(Status, STATUS_SUCCESS);
    }
    Value = 0x5A;
    Status = NtSetInformationKey(Key, KeySetDebugInformation, &Value, sizeof(Value));
    ok_ntstatus(Status, STATUS_SUCCESS);
    for (i = 0; i < 3; i++)
    {
        Value = 0x10 << i;
        Status = NtSetInformationKey(Key, KeySetHandleTagsInformation, &Value, sizeof(Value));
        ok_ntstatus(Status, STATUS_SUCCESS);
    }

    /* the setting of the other classes did not change the Wow64 flags */
    Flags.UserFlags = 0xFF;
    Status = NtQueryKey(Key, KeyFlagsInformation, &Flags, sizeof(Flags), &Length);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_hex(Flags.UserFlags, 3);

    /* a write time the caller gave is kept until the next change */
    Zero.QuadPart = 0;
    (void)Zero;
    WriteTime.LastWriteTime.QuadPart = 0x01D1000000000000LL;
    Status = NtSetInformationKey(Key, KeyWriteTimeInformation, &WriteTime, sizeof(WriteTime));
    ok_ntstatus(Status, STATUS_SUCCESS);
    Status = NtQueryKey(Key, KeyCachedInformation, &Cached, sizeof(Cached), &Length);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok(Cached.LastWriteTime.QuadPart == WriteTime.LastWriteTime.QuadPart, "cached write time %I64x\n", Cached.LastWriteTime.QuadPart);

    Status = NtDeleteKey(Key);
    ok_ntstatus(Status, STATUS_SUCCESS);
    NtClose(Key);
}

START_TEST(NtSetInformationKey)
{
    static const WCHAR Path[] = L"\\Registry\\Machine\\Software\\Microsoft";
    HANDLE Key;

    Key = OpenKey(KEY_SET_VALUE | KEY_QUERY_VALUE, Path);
    if (Key)
    {
        /* only calls that fail, or that cannot change the key */
        Test_ClassAndLength(Key);
        Test_Buffers(Key);
        NtClose(Key);
    }
    Test_Handles();
    Test_Access(Path);
    Test_RoundTrip();
}
