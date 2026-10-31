/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Kernel-Mode Test Suite ZwRenameKey test
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <kmt_test.h>

/* The DDK headers declare it for Windows 7 and later only */
#if (NTDDI_VERSION < NTDDI_WIN7)
NTSYSAPI
NTSTATUS
NTAPI
ZwRenameKey(
    _In_ HANDLE KeyHandle,
    _In_ PUNICODE_STRING NewName);
#endif

#define TEST_PARENT L"\\Registry\\Machine\\Software\\ReactOS kmtest CmRename"

static
HANDLE
CreateKey(
    _In_opt_ HANDLE Root,
    _In_ PCWSTR Name,
    _In_ ULONG Options)
{
    UNICODE_STRING String;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE Key = NULL;
    NTSTATUS Status;

    RtlInitUnicodeString(&String, Name);
    InitializeObjectAttributes(&ObjectAttributes, &String, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, Root, NULL);
    Status = ZwCreateKey(&Key, KEY_ALL_ACCESS, &ObjectAttributes, 0, NULL, Options, NULL);
    ok_eq_hex(Status, STATUS_SUCCESS);
    return NT_SUCCESS(Status) ? Key : NULL;
}

static
NTSTATUS
OpenKey(
    _In_opt_ HANDLE Root,
    _In_ PCWSTR Name,
    _In_ ACCESS_MASK Access,
    _Out_ PHANDLE Key)
{
    UNICODE_STRING String;
    OBJECT_ATTRIBUTES ObjectAttributes;

    RtlInitUnicodeString(&String, Name);
    InitializeObjectAttributes(&ObjectAttributes, &String, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, Root, NULL);
    return ZwOpenKey(Key, Access, &ObjectAttributes);
}

static
NTSTATUS
RenameKey(
    _In_ HANDLE Key,
    _In_ PCWSTR NewName)
{
    UNICODE_STRING String;

    RtlInitUnicodeString(&String, NewName);
    return ZwRenameKey(Key, &String);
}

static
BOOLEAN
NameEndsWith(
    _In_ HANDLE Key,
    _In_ PCWSTR Tail)
{
    PKEY_NAME_INFORMATION Info;
    ULONG Length, TailLength = (ULONG)wcslen(Tail);
    NTSTATUS Status;
    BOOLEAN Result = FALSE;
    UNICODE_STRING Name, TailString;

    Info = ExAllocatePoolWithTag(PagedPool, 1024, 'nRmK');
    if (!Info)
        return FALSE;
    Info->NameLength = 0;
    Status = ZwQueryKey(Key, KeyNameInformation, Info, 1024, &Length);
    if (NT_SUCCESS(Status) && Info->NameLength >= TailLength * sizeof(WCHAR))
    {
        Name.Buffer = (PWCHAR)((PUCHAR)Info->Name + Info->NameLength) - TailLength;
        Name.Length = Name.MaximumLength = (USHORT)(TailLength * sizeof(WCHAR));
        RtlInitUnicodeString(&TailString, Tail);
        Result = RtlEqualUnicodeString(&Name, &TailString, TRUE);
    }
    if (!Result)
        trace("name 0x%lx %.*ls, expected it to end with %ls\n", Status,
              (int)(Info->NameLength / sizeof(WCHAR)), Info->Name, Tail);
    ExFreePoolWithTag(Info, 'nRmK');
    return Result;
}

static
VOID
DeleteTree(
    _In_ HANDLE Key)
{
    UCHAR Buffer[sizeof(KEY_BASIC_INFORMATION) + 512 * sizeof(WCHAR)];
    PKEY_BASIC_INFORMATION Info = (PKEY_BASIC_INFORMATION)Buffer;
    ULONG Length;
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE Child;

    while (NT_SUCCESS(ZwEnumerateKey(Key, 0, KeyBasicInformation, Info, sizeof(Buffer), &Length)))
    {
        Name.Buffer = Info->Name;
        Name.Length = Name.MaximumLength = (USHORT)Info->NameLength;
        InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, Key, NULL);
        if (!NT_SUCCESS(ZwOpenKey(&Child, KEY_ALL_ACCESS, &ObjectAttributes)))
            break;
        DeleteTree(Child);
        ZwClose(Child);
    }
    ZwDeleteKey(Key);
}

START_TEST(CmRename)
{
    HANDLE Parent, Key, Child, ReadOnly, Sibling, Check;
    UNICODE_STRING Name;
    NTSTATUS Status;

    /* Leftovers of an earlier run */
    if (NT_SUCCESS(OpenKey(NULL, TEST_PARENT, KEY_ALL_ACCESS, &Parent)))
    {
        DeleteTree(Parent);
        ZwClose(Parent);
    }

    Parent = CreateKey(NULL, TEST_PARENT, REG_OPTION_VOLATILE);
    if (skip(Parent != NULL, "No parent key\n"))
        return;
    Key = CreateKey(Parent, L"Key", REG_OPTION_VOLATILE);
    Child = CreateKey(Key, L"Child", REG_OPTION_VOLATILE);
    Sibling = CreateKey(Parent, L"Sibling", REG_OPTION_VOLATILE);
    if (skip(Key && Child && Sibling, "No keys\n"))
        goto Cleanup;

    /* Basic rename; the open handles follow */
    Status = RenameKey(Key, L"Renamed");
    ok_eq_hex(Status, STATUS_SUCCESS);
    ok(NameEndsWith(Key, L"\\ReactOS kmtest CmRename\\Renamed"), "key name\n");
    ok(NameEndsWith(Child, L"\\ReactOS kmtest CmRename\\Renamed\\Child"), "child name\n");
    Status = OpenKey(Parent, L"Key", KEY_READ, &Check);
    ok_eq_hex(Status, STATUS_OBJECT_NAME_NOT_FOUND);
    Status = OpenKey(Parent, L"Renamed\\Child", KEY_READ, &Check);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
        ZwClose(Check);

    /* Taken and invalid names */
    Status = RenameKey(Key, L"SIBLING");
    ok_eq_hex(Status, STATUS_CANNOT_DELETE);
    Status = RenameKey(Key, L"renamed");
    ok_eq_hex(Status, STATUS_CANNOT_DELETE);
    Status = RenameKey(Key, L"a\\b");
    ok_eq_hex(Status, STATUS_INVALID_PARAMETER);
    Status = RenameKey(Key, L"");
    ok_eq_hex(Status, STATUS_INVALID_PARAMETER);
    Name.Buffer = L"odd";
    Name.Length = 3;
    Name.MaximumLength = 8;
    Status = ZwRenameKey(Key, &Name);
    ok_eq_hex(Status, STATUS_INVALID_PARAMETER);

    /* A kernel-mode caller's handle is not access checked */
    Status = OpenKey(Parent, L"Renamed", KEY_READ, &ReadOnly);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        Status = RenameKey(ReadOnly, L"Again");
        ok_eq_hex(Status, STATUS_SUCCESS);
        ok(NameEndsWith(Child, L"\\Again\\Child"), "child name after the second rename\n");
        ZwClose(ReadOnly);
    }

    /* The hive root (\Registry\Machine\Software) cannot be renamed */
    Status = OpenKey(NULL, L"\\Registry\\Machine\\Software", KEY_READ, &Check);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        Status = RenameKey(Check, L"ReactOS kmtest CmRename root");
        ok_eq_hex(Status, STATUS_ACCESS_DENIED);
        ZwClose(Check);
    }

    /* The direct children of the master hive hold the hives up... */
    Status = OpenKey(NULL, L"\\Registry\\Machine", KEY_READ, &Check);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        Status = RenameKey(Check, L"ReactOS kmtest CmRename machine");
        ok_eq_hex(Status, STATUS_ACCESS_DENIED);
        ZwClose(Check);
    }
    Status = OpenKey(NULL, L"\\Registry\\User", KEY_READ, &Check);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        Status = RenameKey(Check, L"ReactOS kmtest CmRename user");
        ok_eq_hex(Status, STATUS_ACCESS_DENIED);
        ZwClose(Check);
    }

    /* ... the keys below are ordinary volatile keys of that hive (unmeasured on Windows) */
    Check = CreateKey(NULL, L"\\Registry\\Machine\\HARDWARE\\ReactOS kmtest CmRename", REG_OPTION_VOLATILE);
    if (Check)
    {
        Status = RenameKey(Check, L"ReactOS kmtest CmRename 2");
        ok_eq_hex(Status, STATUS_SUCCESS);
        ok(NameEndsWith(Check, L"\\HARDWARE\\ReactOS kmtest CmRename 2"), "master hive key name\n");
        Status = ZwDeleteKey(Check);
        ok_eq_hex(Status, STATUS_SUCCESS);
        ZwClose(Check);
    }

    /* A deleted key */
    Status = ZwDeleteKey(Sibling);
    ok_eq_hex(Status, STATUS_SUCCESS);
    Status = RenameKey(Sibling, L"Sibling2");
    ok_eq_hex(Status, STATUS_KEY_DELETED);

Cleanup:
    if (Sibling) ZwClose(Sibling);
    if (Child) ZwClose(Child);
    if (Key) ZwClose(Key);
    DeleteTree(Parent);
    ZwClose(Parent);
}
