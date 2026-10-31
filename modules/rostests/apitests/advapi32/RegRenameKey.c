/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test RegRenameKey / NtRenameKey
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <ndk/cmfuncs.h>
#include <ndk/obfuncs.h>

/*
 * Firefox renames registry keys with RegRenameKey. The expectations are what
 * Windows 10 22H2 returns: NtRenameKey needs all of KEY_WRITE on the key, the
 * new name is one key name of 1 to 256 characters without a backslash, a name
 * taken by any sibling (or the key itself, in any case) is STATUS_CANNOT_DELETE,
 * the root of a hive cannot be renamed, and the key keeps its values, class,
 * subkeys and open handles, which report the new path. Only keys under
 * TEST_ROOT (and an app hive in %TEMP%) are touched.
 *
 * RegRenameKeyStress renames a key in a loop while other threads enumerate and
 * open its parent. RegRenameKeyPersist checks that a flushed rename survives a
 * reboot: the first run renames and flushes, the next run (after the reboot)
 * checks and deletes; on Windows both runs can follow each other directly.
 */

#define TEST_ROOT L"Software\\ReactOS RegRenameKey"
#define PERSIST_ROOT L"Software\\ReactOS RegRenameKeyPersist"

static LSTATUS (WINAPI *pRegRenameKey)(HKEY, LPCWSTR, LPCWSTR);
static LSTATUS (WINAPI *pRegDeleteTreeW)(HKEY, LPCWSTR);
static LSTATUS (WINAPI *pRegLoadAppKeyW)(LPCWSTR, PHKEY, REGSAM, DWORD, DWORD);

static
BOOLEAN
InitFunctions(VOID)
{
    HMODULE Advapi32 = GetModuleHandleW(L"advapi32.dll");

    pRegRenameKey = (PVOID)GetProcAddress(Advapi32, "RegRenameKey");
    pRegDeleteTreeW = (PVOID)GetProcAddress(Advapi32, "RegDeleteTreeW");
    pRegLoadAppKeyW = (PVOID)GetProcAddress(Advapi32, "RegLoadAppKeyW");
    if (!pRegRenameKey || !pRegDeleteTreeW)
    {
        skip("RegRenameKey or RegDeleteTreeW is missing\n");
        return FALSE;
    }
    return TRUE;
}

static
VOID
FillChars(
    _Out_writes_(Count + 1) PWCHAR Buffer,
    _In_ WCHAR Char,
    _In_ ULONG Count)
{
    ULONG i;

    for (i = 0; i < Count; i++)
        Buffer[i] = Char;
    Buffer[Count] = UNICODE_NULL;
}

static
NTSTATUS
Rename(
    _In_ HKEY Key,
    _In_ PCWSTR NewName)
{
    UNICODE_STRING Name;

    RtlInitUnicodeString(&Name, NewName);
    return NtRenameKey(Key, &Name);
}

static
HKEY
Create(
    _In_ HKEY Parent,
    _In_ PCWSTR Name,
    _In_ DWORD Options)
{
    HKEY Key = NULL;
    LONG Error;

    Error = RegCreateKeyExW(Parent, Name, 0, NULL, Options, KEY_ALL_ACCESS, NULL, &Key, NULL);
    ok(Error == ERROR_SUCCESS, "RegCreateKeyExW(%ls) returned %ld\n", Name, Error);
    return Error ? NULL : Key;
}

static
HKEY
Open(
    _In_ HKEY Parent,
    _In_opt_ PCWSTR Name,
    _In_ REGSAM Access)
{
    HKEY Key = NULL;
    return RegOpenKeyExW(Parent, Name, 0, Access, &Key) ? NULL : Key;
}

static
BOOLEAN
Exists(
    _In_ HKEY Parent,
    _In_ PCWSTR Name)
{
    HKEY Key = Open(Parent, Name, KEY_READ);
    if (Key)
        RegCloseKey(Key);
    return Key != NULL;
}

/* Does the full name of the key end with Tail (case-insensitive)? */
static
BOOLEAN
NameEndsWith(
    _In_ HANDLE Key,
    _In_ PCWSTR Tail)
{
    ULONG Buffer[512];
    PKEY_NAME_INFORMATION Info = (PKEY_NAME_INFORMATION)Buffer;
    ULONG Length, TailLength = (ULONG)wcslen(Tail), NameLength;
    NTSTATUS Status;

    Status = NtQueryKey(Key, KeyNameInformation, Info, sizeof(Buffer), &Length);
    if (!NT_SUCCESS(Status))
    {
        trace("NtQueryKey(KeyNameInformation) returned 0x%lx\n", Status);
        return FALSE;
    }
    NameLength = Info->NameLength / sizeof(WCHAR);
    if (NameLength < TailLength ||
        _wcsnicmp(&Info->Name[NameLength - TailLength], Tail, TailLength))
    {
        trace("name is %.*ls, expected it to end with %ls\n", (int)NameLength, Info->Name, Tail);
        return FALSE;
    }
    return TRUE;
}

static
ULONGLONG
WriteTime(
    _In_ HKEY Key)
{
    FILETIME Time = { 0 };
    RegQueryInfoKeyW(Key, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &Time);
    return ((ULONGLONG)Time.dwHighDateTime << 32) | Time.dwLowDateTime;
}

static
VOID
TestAccess(
    _In_ HKEY Root)
{
    static const struct
    {
        REGSAM Access;
        NTSTATUS Status;
    } Tests[] =
    {
        { KEY_WRITE, STATUS_SUCCESS },
        { KEY_ALL_ACCESS, STATUS_SUCCESS },
        { GENERIC_WRITE, STATUS_SUCCESS },
        { MAXIMUM_ALLOWED, STATUS_SUCCESS },
        { KEY_SET_VALUE, STATUS_ACCESS_DENIED },
        { KEY_CREATE_SUB_KEY, STATUS_ACCESS_DENIED },
        { KEY_SET_VALUE | KEY_CREATE_SUB_KEY, STATUS_ACCESS_DENIED },
        { KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_CREATE_SUB_KEY, STATUS_ACCESS_DENIED },
        { KEY_READ, STATUS_ACCESS_DENIED },
        { READ_CONTROL, STATUS_ACCESS_DENIED },
        { DELETE, STATUS_ACCESS_DENIED },
    };
    HKEY Key;
    ULONG i;
    NTSTATUS Status;

    Key = Create(Root, L"acc", 0);
    RegCloseKey(Key);
    for (i = 0; i < RTL_NUMBER_OF(Tests); i++)
    {
        Key = Open(Root, L"acc", Tests[i].Access);
        ok(Key != NULL, "[%lu] open failed\n", i);
        if (!Key)
            continue;
        Status = Rename(Key, L"acc2");
        ok(Status == Tests[i].Status, "[%lu] access 0x%lx: 0x%lx, expected 0x%lx\n",
           i, Tests[i].Access, Status, Tests[i].Status);
        RegCloseKey(Key);
        ok(Exists(Root, Status ? L"acc" : L"acc2"), "[%lu] key not found under its name\n", i);
        if (NT_SUCCESS(Status))
        {
            Key = Open(Root, L"acc2", KEY_WRITE);
            ok_hex(Rename(Key, L"acc"), STATUS_SUCCESS);
            RegCloseKey(Key);
        }
    }
    ok_long(RegDeleteKeyW(Root, L"acc"), ERROR_SUCCESS);
}

static
VOID
TestRegRenameKeyForms(
    _In_ HKEY Root)
{
    HKEY Key, Parent;
    WCHAR Path[MAX_PATH];

    /* The caller's handle needs only the right to open the subkey */
    Key = Create(Root, L"p\\child", 0);
    RegCloseKey(Key);
    Parent = Open(Root, L"p", KEY_READ);
    ok_long(pRegRenameKey(Parent, L"child", L"child2"), ERROR_SUCCESS);
    ok(Exists(Parent, L"child2") && !Exists(Parent, L"child"), "child not renamed\n");
    RegCloseKey(Parent);
    Parent = Open(Root, L"p", KEY_ENUMERATE_SUB_KEYS);
    ok_long(pRegRenameKey(Parent, L"child2", L"child"), ERROR_SUCCESS);
    RegCloseKey(Parent);

    /* A path of several keys */
    ok_long(pRegRenameKey(Root, L"p\\child", L"child3"), ERROR_SUCCESS);
    ok(Exists(Root, L"p\\child3"), "p\\child3 missing\n");
    ok_long(pRegRenameKey(Root, L"p\\child3\\", L"child"), ERROR_SUCCESS);
    ok(Exists(Root, L"p\\child"), "p\\child missing\n");
    StringCbPrintfW(Path, sizeof(Path), L"%s\\p\\child", TEST_ROOT);
    ok_long(pRegRenameKey(HKEY_CURRENT_USER, Path, L"child4"), ERROR_SUCCESS);
    ok(Exists(Root, L"p\\child4"), "p\\child4 missing\n");
    ok_long(pRegRenameKey(Root, L"p\\nosuch", L"x"), ERROR_FILE_NOT_FOUND);

    /* Without a subkey name the handle itself is renamed and needs KEY_WRITE;
     * an empty subkey name opens the key again */
    Parent = Open(Root, L"p", KEY_READ);
    ok_long(pRegRenameKey(Parent, NULL, L"q"), ERROR_ACCESS_DENIED);
    ok_long(pRegRenameKey(Parent, L"", L"q"), ERROR_SUCCESS);
    ok(Exists(Root, L"q") && !Exists(Root, L"p"), "p not renamed to q\n");
    ok(NameEndsWith(Parent, L"\\ReactOS RegRenameKey\\q"), "handle name not updated\n");
    RegCloseKey(Parent);
    Parent = Open(Root, L"q", KEY_WRITE);
    ok_long(pRegRenameKey(Parent, NULL, L"p"), ERROR_SUCCESS);
    RegCloseKey(Parent);
    ok(Exists(Root, L"p\\child4"), "p\\child4 missing\n");

    /* Errors */
    Key = Create(Root, L"p\\other", 0);
    RegCloseKey(Key);
    ok_long(pRegRenameKey(Root, L"p\\child4", L"other"), ERROR_ACCESS_DENIED);
    ok_long(pRegRenameKey(Root, L"p\\child4", L"x\\y"), ERROR_INVALID_PARAMETER);
    ok_long(pRegRenameKey(Root, L"p\\child4", L""), ERROR_INVALID_PARAMETER);

    /* A predefined handle is not mapped to its key */
    ok_long(pRegRenameKey(HKEY_CURRENT_USER, NULL, L"ReactOS RegRenameKey HKCU"), ERROR_INVALID_HANDLE);
    ok_long(pRegRenameKey(HKEY_CURRENT_USER, L"", L"ReactOS RegRenameKey HKCU"), ERROR_INVALID_HANDLE);

    ok_long(pRegDeleteTreeW(Root, L"p"), ERROR_SUCCESS);
    RegDeleteKeyW(Root, L"p");
}

static
VOID
TestNames(
    _In_ HKEY Root)
{
    static WCHAR Long[40000];
    HKEY Alpha, Beta;
    UNICODE_STRING Name;
    NTSTATUS Status;
    ULONG Buffer[256];
    PKEY_BASIC_INFORMATION Basic = (PKEY_BASIC_INFORMATION)Buffer;
    ULONG Length, n;

    Alpha = Create(Root, L"Alpha", 0);
    Beta = Create(Root, L"Beta", 0);
    if (!Alpha || !Beta)
        return;

    /* Taken names, by a sibling or the key itself, in any case */
    ok_hex(Rename(Alpha, L"Beta"), STATUS_CANNOT_DELETE);
    ok_hex(Rename(Alpha, L"BETA"), STATUS_CANNOT_DELETE);
    ok_hex(Rename(Alpha, L"Alpha"), STATUS_CANNOT_DELETE);
    ok_hex(Rename(Alpha, L"ALPHA"), STATUS_CANNOT_DELETE);
    ok(NameEndsWith(Alpha, L"\\Alpha"), "Alpha changed\n");

    /* One key name */
    ok_hex(Rename(Alpha, L"x\\y"), STATUS_INVALID_PARAMETER);
    ok_hex(Rename(Alpha, L"\\lead"), STATUS_INVALID_PARAMETER);
    ok_hex(Rename(Alpha, L"trail\\"), STATUS_INVALID_PARAMETER);
    ok_hex(Rename(Alpha, L""), STATUS_INVALID_PARAMETER);
    Name.Buffer = L"oddname";
    Name.Length = 3;
    Name.MaximumLength = 16;
    ok_hex(NtRenameKey(Alpha, &Name), STATUS_INVALID_PARAMETER);
    Name.Buffer = NULL;
    Name.Length = Name.MaximumLength = 0;
    ok_hex(NtRenameKey(Alpha, &Name), STATUS_INVALID_PARAMETER);
    Name.Length = Name.MaximumLength = 4;
    ok_hex(NtRenameKey(Alpha, &Name), STATUS_ACCESS_VIOLATION);
    ok_hex(NtRenameKey(Alpha, NULL), STATUS_ACCESS_VIOLATION);
    ok(NameEndsWith(Alpha, L"\\Alpha"), "Alpha changed\n");

    /* Up to 256 characters */
    for (n = 254; n <= 257; n++)
    {
        FillChars(Long, L'L', n);
        Status = Rename(Alpha, Long);
        ok(Status == (n <= 256 ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER),
           "length %lu: 0x%lx\n", n, Status);
        if (NT_SUCCESS(Status))
        {
            ok(Exists(Root, Long), "length %lu: not found\n", n);
            ok_hex(Rename(Alpha, L"Alpha"), STATUS_SUCCESS);
        }
    }
    FillChars(Long, L'L', 32767);
    ok_hex(Rename(Alpha, Long), STATUS_INVALID_PARAMETER);

    /* Other characters */
    ok_hex(Rename(Alpha, L"fw/sl"), STATUS_SUCCESS);
    ok(Exists(Root, L"fw/sl"), "fw/sl missing\n");
    ok_hex(Rename(Alpha, L"\x0416\x0436name"), STATUS_SUCCESS);
    Status = NtQueryKey(Alpha, KeyBasicInformation, Basic, sizeof(Buffer), &Length);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        ok(Basic->NameLength == 6 * sizeof(WCHAR) &&
           !memcmp(Basic->Name, L"\x0416\x0436name", 6 * sizeof(WCHAR)), "unicode name\n");
    }
    ok(Exists(Root, L"\x0416\x0436name"), "unicode name not found\n");
    Name.Buffer = L"emb\0ed";
    Name.Length = 12;
    Name.MaximumLength = 14;
    ok_hex(NtRenameKey(Alpha, &Name), STATUS_SUCCESS);
    Status = NtQueryKey(Alpha, KeyBasicInformation, Basic, sizeof(Buffer), &Length);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
        ok_long(Basic->NameLength, 12);
    ok(!Exists(Root, L"emb"), "emb found\n");
    ok_hex(Rename(Alpha, L"Alpha"), STATUS_SUCCESS);
    ok(Exists(Root, L"Alpha"), "Alpha missing\n");

    RegCloseKey(Alpha);
    RegCloseKey(Beta);
    RegDeleteKeyW(Root, L"Alpha");
    RegDeleteKeyW(Root, L"Beta");
}

static
VOID
TestOrder(
    _In_ HKEY Root)
{
    HKEY Key, ReadOnly, Deleted, Deleted2;

    /* What is checked first */
    Key = Create(Root, L"ord", 0);
    Deleted = Create(Root, L"ordsib", 0);
    RegCloseKey(Deleted);
    ReadOnly = Open(Root, L"ord", KEY_READ);
    /* The name is checked before the handle */
    ok_hex(Rename(ReadOnly, L""), STATUS_INVALID_PARAMETER);
    ok_hex(NtRenameKey(ReadOnly, NULL), STATUS_ACCESS_VIOLATION);
    ok_hex(Rename(ReadOnly, L"x\\y"), STATUS_INVALID_PARAMETER);
    ok_hex(Rename(NULL, L""), STATUS_INVALID_PARAMETER);
    ok_hex(Rename(NULL, L"x\\y"), STATUS_INVALID_PARAMETER);
    ok_hex(Rename(NULL, L"name"), STATUS_INVALID_HANDLE);
    ok_hex(Rename(ReadOnly, L"ordsib"), STATUS_ACCESS_DENIED);
    ok_hex(Rename(ReadOnly, L"ord2"), STATUS_ACCESS_DENIED);
    RegCloseKey(ReadOnly);

    Deleted = Create(Root, L"del", 0);
    Deleted2 = Open(Root, L"del", KEY_ALL_ACCESS);
    ok_hex(NtDeleteKey(Deleted), STATUS_SUCCESS);
    ok_hex(Rename(Deleted2, L"del2"), STATUS_KEY_DELETED);
    ok_hex(Rename(Deleted2, L""), STATUS_INVALID_PARAMETER);
    ok_hex(Rename(Deleted2, L"ordsib"), STATUS_KEY_DELETED);
    ok(!Exists(Root, L"del2"), "del2 exists\n");
    RegCloseKey(Deleted);
    RegCloseKey(Deleted2);

    RegCloseKey(Key);
    RegDeleteKeyW(Root, L"ord");
    RegDeleteKeyW(Root, L"ordsib");
}

static
VOID
SameKcbCheck(
    _In_ HKEY Root,
    _In_ PCWSTR Path,
    _In_ HKEY Old)
{
    HKEY Fresh;
    DWORD Value, Size;

    Fresh = Open(Root, Path, KEY_QUERY_VALUE | KEY_SET_VALUE);
    ok(Fresh != NULL, "%ls does not open\n", Path);
    if (!Fresh)
        return;
    Size = sizeof(Value);
    ok_long(RegQueryValueExW(Fresh, L"late", NULL, NULL, (PBYTE)&Value, &Size), ERROR_FILE_NOT_FOUND);
    Value = 99;
    ok_long(RegSetValueExW(Old, L"late", 0, REG_DWORD, (PBYTE)&Value, sizeof(Value)), ERROR_SUCCESS);
    Value = 0;
    Size = sizeof(Value);
    ok_long(RegQueryValueExW(Fresh, L"late", NULL, NULL, (PBYTE)&Value, &Size), ERROR_SUCCESS);
    ok_long(Value, 99);
    ok_long(RegDeleteValueW(Fresh, L"late"), ERROR_SUCCESS);
    Size = sizeof(Value);
    ok_long(RegQueryValueExW(Old, L"late", NULL, NULL, (PBYTE)&Value, &Size), ERROR_FILE_NOT_FOUND);
    RegCloseKey(Fresh);
}

static
VOID
TestTree(
    _In_ HKEY Root)
{
    HKEY Key, Child, Grand, ChildRead, New, Sub;
    DWORD Value = 1234, Size, Count, MaxLength, Index;
    WCHAR Class[64], Name[64];
    ULONGLONG ParentTime, KeyTime;
    static const PCWSTR Sorted[] = { L"child", L"mmm", L"nnn", L"zzz" };

    ok_long(RegCreateKeyExW(Root, L"Tree", 0, L"MyClass", 0, KEY_ALL_ACCESS, NULL, &Key, NULL), ERROR_SUCCESS);
    Child = Create(Key, L"child", 0);
    Grand = Create(Child, L"grand", 0);
    ok_long(RegSetValueExW(Key, L"val", 0, REG_DWORD, (PBYTE)&Value, sizeof(Value)), ERROR_SUCCESS);
    ChildRead = Open(Root, L"Tree\\child", KEY_READ);
    if (!Key || !Child || !Grand || !ChildRead)
        return;

    ParentTime = WriteTime(Root);
    Sub = Open(Root, L"Tree", KEY_READ);
    KeyTime = WriteTime(Sub);
    RegCloseKey(Sub);
    Sleep(30);

    /* Open handles to the key and below it keep working, under the new path */
    ok_hex(Rename(Key, L"TreeRenamed"), STATUS_SUCCESS);
    ok(NameEndsWith(Key, L"\\ReactOS RegRenameKey\\TreeRenamed"), "key handle name\n");
    ok(NameEndsWith(Child, L"\\ReactOS RegRenameKey\\TreeRenamed\\child"), "child handle name\n");
    ok(NameEndsWith(Grand, L"\\ReactOS RegRenameKey\\TreeRenamed\\child\\grand"), "grand handle name\n");
    ok(NameEndsWith(ChildRead, L"\\ReactOS RegRenameKey\\TreeRenamed\\child"), "read handle name\n");
    ok(!Exists(Root, L"Tree"), "old name still opens\n");
    ok(!Exists(Root, L"Tree\\child"), "old path still opens\n");
    ok(Exists(Root, L"TreeRenamed\\child\\grand"), "new path does not open\n");

    /* The parent's write time changes, the key's does not */
    ok(WriteTime(Root) != ParentTime, "parent write time unchanged\n");
    Sub = Open(Root, L"TreeRenamed", KEY_READ);
    ok(Sub && WriteTime(Sub) == KeyTime, "key write time changed\n");

    /* Values, class and subkeys stay */
    Value = 0;
    Size = sizeof(Value);
    ok_long(RegQueryValueExW(Key, L"val", NULL, NULL, (PBYTE)&Value, &Size), ERROR_SUCCESS);
    ok_long(Value, 1234);
    Value = 0;
    Size = sizeof(Value);
    ok_long(RegQueryValueExW(Sub, L"val", NULL, NULL, (PBYTE)&Value, &Size), ERROR_SUCCESS);
    ok_long(Value, 1234);
    Size = RTL_NUMBER_OF(Class);
    Count = 0;
    ok_long(RegQueryInfoKeyW(Sub, Class, &Size, NULL, &Count, NULL, NULL, NULL, NULL, NULL, NULL, NULL), ERROR_SUCCESS);
    ok(!wcscmp(Class, L"MyClass"), "class %ls\n", Class);
    ok_long(Count, 1);
    RegCloseKey(Sub);

    /* Writing through the old handles lands in the renamed tree */
    ok_long(RegSetValueExW(Child, L"cv", 0, REG_DWORD, (PBYTE)&Value, sizeof(Value)), ERROR_SUCCESS);
    New = Create(Child, L"new2", 0);
    RegCloseKey(New);
    ok(Exists(Root, L"TreeRenamed\\child\\new2"), "new2 not under the new path\n");
    Sub = Open(Root, L"TreeRenamed\\child", KEY_READ);
    Size = sizeof(Value);
    ok_long(RegQueryValueExW(Sub, L"cv", NULL, NULL, (PBYTE)&Value, &Size), ERROR_SUCCESS);
    RegCloseKey(Sub);

    /* A new open below the renamed key finds the KCB the old handles use
     * (it was rehashed, not duplicated): changes show through both at once */
    SameKcbCheck(Root, L"TreeRenamed\\child", Child);
    SameKcbCheck(Root, L"TreeRenamed\\child\\grand", Grand);

    /* And back, with all the handles still open */
    ok_hex(Rename(Key, L"Tree"), STATUS_SUCCESS);
    ok(NameEndsWith(Grand, L"\\ReactOS RegRenameKey\\Tree\\child\\grand"), "grand handle name after renaming back\n");
    ok(Exists(Root, L"Tree\\child\\new2"), "Tree\\child\\new2 missing\n");

    /* The parent's index stays sorted */
    RegCloseKey(Create(Key, L"aaa", 0));
    RegCloseKey(Create(Key, L"mmm", 0));
    RegCloseKey(Create(Key, L"zzz", 0));
    ok_long(pRegRenameKey(Key, L"aaa", L"nnn"), ERROR_SUCCESS);
    for (Index = 0; ; Index++)
    {
        Size = RTL_NUMBER_OF(Name);
        if (RegEnumKeyExW(Key, Index, Name, &Size, NULL, NULL, NULL, NULL))
            break;
        if (Index < RTL_NUMBER_OF(Sorted))
            ok(!wcscmp(Name, Sorted[Index]), "[%lu] %ls, expected %ls\n", Index, Name, Sorted[Index]);
    }
    ok_long(Index, RTL_NUMBER_OF(Sorted));

    /* The longest subkey name only grows */
    ok_long(pRegRenameKey(Key, L"nnn", L"a-forty-character-name-xxxxxxxxxxxxxxxxx"), ERROR_SUCCESS);
    MaxLength = 0;
    RegQueryInfoKeyW(Key, NULL, NULL, NULL, NULL, &MaxLength, NULL, NULL, NULL, NULL, NULL, NULL);
    ok_long(MaxLength, 40);
    ok_long(pRegRenameKey(Key, L"a-forty-character-name-xxxxxxxxxxxxxxxxx", L"n"), ERROR_SUCCESS);
    MaxLength = 0;
    RegQueryInfoKeyW(Key, NULL, NULL, NULL, NULL, &MaxLength, NULL, NULL, NULL, NULL, NULL, NULL);
    ok_long(MaxLength, 40);

    RegCloseKey(ChildRead);
    RegCloseKey(Grand);
    RegCloseKey(Child);
    RegCloseKey(Key);
    ok_long(pRegDeleteTreeW(Root, L"Tree"), ERROR_SUCCESS);
    RegDeleteKeyW(Root, L"Tree");
}

/* Enough siblings for an index root over several leaves */
static
VOID
TestBigIndex(
    _In_ HKEY Root)
{
    HKEY Parent, Key;
    WCHAR Name[64], Previous[64];
    DWORD Size, Index, Count;
    ULONG i;
    static const struct
    {
        PCWSTR From;
        PCWSTR To;
    } Renames[] =
    {
        { L"k0000", L"zz-last" },
        { L"k0600", L"a-first" },
        { L"k1199", L"k0600x" },
        { L"k0300", L"k0900y-longer-name-than-the-others" },
        { L"zz-last", L"k0000" },
    };

    Parent = Create(Root, L"big", 0);
    if (!Parent)
        return;
    for (i = 0; i < 1200; i++)
    {
        StringCbPrintfW(Name, sizeof(Name), L"k%04lu", i);
        Key = Create(Parent, Name, 0);
        if (!Key)
            break;
        RegCloseKey(Key);
    }
    for (i = 0; i < RTL_NUMBER_OF(Renames); i++)
    {
        ok_long(pRegRenameKey(Parent, Renames[i].From, Renames[i].To), ERROR_SUCCESS);
        ok(Exists(Parent, Renames[i].To), "[%lu] %ls missing\n", i, Renames[i].To);
        ok(!Exists(Parent, Renames[i].From), "[%lu] %ls still there\n", i, Renames[i].From);
    }
    Count = 0;
    RegQueryInfoKeyW(Parent, NULL, NULL, NULL, &Count, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    ok_long(Count, 1200);
    Previous[0] = UNICODE_NULL;
    for (Index = 0; ; Index++)
    {
        Size = RTL_NUMBER_OF(Name);
        if (RegEnumKeyExW(Parent, Index, Name, &Size, NULL, NULL, NULL, NULL))
            break;
        ok(_wcsicmp(Previous, Name) < 0, "[%lu] %ls after %ls\n", Index, Name, Previous);
        StringCbCopyW(Previous, sizeof(Previous), Name);
    }
    ok_long(Index, 1200);
    RegCloseKey(Parent);
    ok_long(pRegDeleteTreeW(Root, L"big"), ERROR_SUCCESS);
    RegDeleteKeyW(Root, L"big");
}

static
VOID
TestVolatile(
    _In_ HKEY Root)
{
    HKEY Vol, VolChild, Stable, VolKid, StableKid, VolSibling;

    Vol = Create(Root, L"Vol", REG_OPTION_VOLATILE);
    VolChild = Create(Vol, L"vchild", REG_OPTION_VOLATILE);
    if (!Vol || !VolChild)
        return;
    ok_hex(Rename(Vol, L"Vol2"), STATUS_SUCCESS);
    ok_hex(Rename(VolChild, L"vchild2"), STATUS_SUCCESS);
    ok(NameEndsWith(VolChild, L"\\ReactOS RegRenameKey\\Vol2\\vchild2"), "volatile child name\n");
    ok(Exists(Root, L"Vol2\\vchild2"), "Vol2\\vchild2 missing\n");

    Stable = Create(Root, L"NonVol", 0);
    VolKid = Create(Stable, L"volkid", REG_OPTION_VOLATILE);
    StableKid = Create(Stable, L"stablekid", 0);
    ok_hex(Rename(Stable, L"NonVol2"), STATUS_SUCCESS);
    ok(Exists(Root, L"NonVol2\\volkid"), "volatile kid lost\n");
    ok(Exists(Root, L"NonVol2\\stablekid"), "stable kid lost\n");
    ok(NameEndsWith(VolKid, L"\\NonVol2\\volkid"), "volatile kid name\n");

    /* Stable and volatile siblings share one name space */
    ok_hex(Rename(VolKid, L"stablekid"), STATUS_CANNOT_DELETE);
    VolSibling = Create(Stable, L"STABLEKID2", REG_OPTION_VOLATILE);
    ok_hex(Rename(StableKid, L"stablekid2"), STATUS_CANNOT_DELETE);
    ok_hex(Rename(VolKid, L"volkid2"), STATUS_SUCCESS);
    ok(Exists(Root, L"NonVol2\\volkid2"), "volkid2 missing\n");

    RegCloseKey(VolSibling);
    RegCloseKey(StableKid);
    RegCloseKey(VolKid);
    RegCloseKey(Stable);
    RegCloseKey(VolChild);
    RegCloseKey(Vol);
    pRegDeleteTreeW(Root, L"Vol2");
    RegDeleteKeyW(Root, L"Vol2");
    pRegDeleteTreeW(Root, L"NonVol2");
    RegDeleteKeyW(Root, L"NonVol2");
}

static
VOID
TestNotify(
    _In_ HKEY Root)
{
    static const struct
    {
        PCWSTR Path;
        BOOL Subtree;
        DWORD Filter;
        BOOL Signaled;
    } Watches[] =
    {
        { L"NG", TRUE, REG_NOTIFY_CHANGE_NAME, TRUE },
        { L"NG", TRUE, REG_NOTIFY_CHANGE_LAST_SET, FALSE },
        { L"NG", FALSE, REG_NOTIFY_CHANGE_NAME, FALSE },
        { L"NG\\NP", FALSE, REG_NOTIFY_CHANGE_NAME, TRUE },
        { L"NG\\NP", FALSE, REG_NOTIFY_CHANGE_LAST_SET, FALSE },
        { L"NG\\NP", FALSE, REG_NOTIFY_CHANGE_ATTRIBUTES, FALSE },
        { L"NG\\NP\\NK", FALSE, REG_NOTIFY_CHANGE_NAME, TRUE },
        { L"NG\\NP\\NK", FALSE, REG_NOTIFY_CHANGE_LAST_SET, TRUE },
        { L"NG\\NP\\NK", FALSE, REG_NOTIFY_CHANGE_SECURITY, TRUE },
        { L"NG\\NP\\NK", TRUE, REG_NOTIFY_CHANGE_ATTRIBUTES, TRUE },
        { L"NG\\NP\\NK\\NC", FALSE, REG_NOTIFY_CHANGE_NAME, FALSE },
        { L"NG\\NP\\NK\\NC", FALSE, REG_NOTIFY_CHANGE_LAST_SET, FALSE },
        { L"NG\\NP\\NS", FALSE, REG_NOTIFY_CHANGE_NAME, FALSE },
    };
    HKEY Keys[RTL_NUMBER_OF(Watches)], Key;
    HANDLE Events[RTL_NUMBER_OF(Watches)];
    ULONG i;

    RegCloseKey(Create(Root, L"NG\\NP\\NK\\NC", 0));
    RegCloseKey(Create(Root, L"NG\\NP\\NS", 0));
    for (i = 0; i < RTL_NUMBER_OF(Watches); i++)
    {
        Keys[i] = Open(Root, Watches[i].Path, KEY_NOTIFY);
        Events[i] = CreateEventW(NULL, TRUE, FALSE, NULL);
        ok_long(RegNotifyChangeKeyValue(Keys[i], Watches[i].Subtree, Watches[i].Filter, Events[i], TRUE), ERROR_SUCCESS);
    }
    Key = Open(Root, L"NG\\NP\\NK", KEY_WRITE);
    ok_hex(Rename(Key, L"NK2"), STATUS_SUCCESS);
    RegCloseKey(Key);
    Sleep(300);
    for (i = 0; i < RTL_NUMBER_OF(Watches); i++)
    {
        ok((WaitForSingleObject(Events[i], 0) == WAIT_OBJECT_0) == Watches[i].Signaled,
           "[%lu] %ls subtree %d filter 0x%lx: expected %ssignaled\n",
           i, Watches[i].Path, Watches[i].Subtree, Watches[i].Filter, Watches[i].Signaled ? "" : "not ");
        RegCloseKey(Keys[i]);
        CloseHandle(Events[i]);
    }
    pRegDeleteTreeW(Root, L"NG");
    RegDeleteKeyW(Root, L"NG");
}

static
VOID
TestHiveRoot(VOID)
{
    WCHAR TempPath[MAX_PATH], File[MAX_PATH];
    HKEY App = NULL, Key;
    LONG Error = ERROR_CALL_NOT_IMPLEMENTED;

    /* The root of a hive is linked from the hive above it: ACCESS_DENIED */
    if (pRegLoadAppKeyW)
    {
        GetTempPathW(RTL_NUMBER_OF(TempPath), TempPath);
        StringCbPrintfW(File, sizeof(File), L"%sReactOS-RegRenameKey-%lu.hiv", TempPath, GetCurrentProcessId());
        Error = pRegLoadAppKeyW(File, &App, KEY_ALL_ACCESS, 0, 0);
    }
    if (Error == ERROR_SUCCESS && App)
    {
        ok_hex(Rename(App, L"approot2"), STATUS_ACCESS_DENIED);
        Key = Create(App, L"inapp", 0);
        ok_hex(Rename(Key, L"inapp2"), STATUS_SUCCESS);
        ok(Exists(App, L"inapp2"), "inapp2 missing\n");
        RegCloseKey(Key);
        RegCloseKey(App);
        DeleteFileW(File);
        StringCbCatW(File, sizeof(File), L".LOG1");
        DeleteFileW(File);
        File[wcslen(File) - 1] = L'2';
        DeleteFileW(File);
    }
    else
    {
        /* No app hives: the user's hive root instead (renaming it fails) */
        ok(RegOpenCurrentUser(KEY_WRITE, &Key) == ERROR_SUCCESS, "RegOpenCurrentUser failed\n");
        ok_hex(Rename(Key, L"ReactOS RegRenameKey root"), STATUS_ACCESS_DENIED);
        RegCloseKey(Key);
    }
}

START_TEST(RegRenameKey)
{
    HKEY Root;

    if (!InitFunctions())
        return;

    pRegDeleteTreeW(HKEY_CURRENT_USER, TEST_ROOT);
    RegDeleteKeyW(HKEY_CURRENT_USER, TEST_ROOT);
    Root = Create(HKEY_CURRENT_USER, TEST_ROOT, 0);
    if (!Root)
        return;

    TestAccess(Root);
    TestRegRenameKeyForms(Root);
    TestNames(Root);
    TestOrder(Root);
    TestTree(Root);
    TestBigIndex(Root);
    TestVolatile(Root);
    TestNotify(Root);
    TestHiveRoot();

    RegCloseKey(Root);
    ok_long(pRegDeleteTreeW(HKEY_CURRENT_USER, TEST_ROOT), ERROR_SUCCESS);
    RegDeleteKeyW(HKEY_CURRENT_USER, TEST_ROOT);
    ok(!Exists(HKEY_CURRENT_USER, TEST_ROOT), "test key left behind\n");
}

/* Stress: one thread renames, others enumerate, open and query */

#define STRESS_SIBLINGS 40
static const PCWSTR StressNames[] =
{
    L"a",
    L"middle-name",
    L"zzzz-a-much-longer-name-that-needs-a-bigger-key-node-cell-than-the-others-do",
    L"\x0416\x0436-not-compressed",
};
static volatile LONG StressStop;
static HKEY StressParent, StressKey, StressSub;
static LONG StressBadCount, StressBadName, StressOpens, StressEnums, StressFailures;

static
BOOLEAN
IsStressName(
    _In_ PCWSTR Name)
{
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(StressNames); i++)
    {
        if (!_wcsicmp(Name, StressNames[i]))
            return TRUE;
    }
    return FALSE;
}

static
DWORD
WINAPI
StressReader(
    _In_ PVOID Context)
{
    WCHAR Name[128], Path[160];
    DWORD Size, Count, Index, i;
    HKEY Key;
    LONG Error;

    while (!StressStop)
    {
        /* The parent always has the siblings plus the renamed key */
        Count = 0;
        RegQueryInfoKeyW(StressParent, NULL, NULL, NULL, &Count, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        if (Count != STRESS_SIBLINGS + 1)
            InterlockedIncrement(&StressBadCount);

        /* Every name it enumerates is a sibling's or one the key had */
        for (Index = 0; ; Index++)
        {
            Size = RTL_NUMBER_OF(Name);
            Error = RegEnumKeyExW(StressParent, Index, Name, &Size, NULL, NULL, NULL, NULL);
            if (Error)
                break;
            if (wcsncmp(Name, L"sib", 3) && !IsStressName(Name))
                InterlockedIncrement(&StressBadName);
        }
        if (Error != ERROR_NO_MORE_ITEMS)
            InterlockedIncrement(&StressFailures);
        InterlockedIncrement(&StressEnums);

        /* A fresh open of the parent, a sibling and the key under its names */
        Key = Open(HKEY_CURRENT_USER, TEST_ROOT L"\\stress", KEY_READ);
        if (!Key)
            InterlockedIncrement(&StressFailures);
        else
            RegCloseKey(Key);
        Key = Open(StressParent, L"sib17", KEY_READ);
        if (!Key)
            InterlockedIncrement(&StressFailures);
        else
            RegCloseKey(Key);
        for (i = 0; i < RTL_NUMBER_OF(StressNames); i++)
        {
            StringCbPrintfW(Path, sizeof(Path), L"%s\\sub", StressNames[i]);
            Key = Open(StressParent, Path, KEY_READ);
            if (Key)
            {
                InterlockedIncrement(&StressOpens);
                RegCloseKey(Key);
            }
        }

        /* The open handles report one of the key's names */
        if (!NameEndsWith(StressSub, L"\\sub"))
            InterlockedIncrement(&StressFailures);
    }
    return 0;
}

START_TEST(RegRenameKeyStress)
{
    HANDLE Threads[4];
    WCHAR Name[32];
    ULONG i, Iterations = 3000, Current = 0;
    DWORD Value = 77, Size;
    NTSTATUS Status;
    LONG RenameFailures = 0;

    if (!InitFunctions())
        return;

    pRegDeleteTreeW(HKEY_CURRENT_USER, TEST_ROOT);
    RegDeleteKeyW(HKEY_CURRENT_USER, TEST_ROOT);
    StressParent = Create(HKEY_CURRENT_USER, TEST_ROOT L"\\stress", 0);
    if (!StressParent)
        return;
    for (i = 0; i < STRESS_SIBLINGS; i++)
    {
        StringCbPrintfW(Name, sizeof(Name), L"sib%02lu", i);
        RegCloseKey(Create(StressParent, Name, (i & 1) ? REG_OPTION_VOLATILE : 0));
    }
    StressKey = Create(StressParent, StressNames[0], 0);
    StressSub = Create(StressKey, L"sub", 0);
    ok_long(RegSetValueExW(StressSub, L"v", 0, REG_DWORD, (PBYTE)&Value, sizeof(Value)), ERROR_SUCCESS);
    if (!StressKey || !StressSub)
        return;

    for (i = 0; i < RTL_NUMBER_OF(Threads); i++)
        Threads[i] = CreateThread(NULL, 0, StressReader, NULL, 0, NULL);

    for (i = 0; i < Iterations; i++)
    {
        Current = (i + 1) % RTL_NUMBER_OF(StressNames);
        Status = Rename(StressKey, StressNames[Current]);
        if (!NT_SUCCESS(Status))
        {
            if (RenameFailures++ < 5)
                trace("rename %lu to %ls: 0x%lx\n", i, StressNames[Current], Status);
            Current = (Current + RTL_NUMBER_OF(StressNames) - 1) % RTL_NUMBER_OF(StressNames);
        }
    }

    StressStop = TRUE;
    WaitForMultipleObjects(RTL_NUMBER_OF(Threads), Threads, TRUE, 60000);
    for (i = 0; i < RTL_NUMBER_OF(Threads); i++)
        CloseHandle(Threads[i]);

    ok_long(RenameFailures, 0);
    ok_long(StressBadCount, 0);
    ok_long(StressBadName, 0);
    ok_long(StressFailures, 0);
    ok(StressEnums > 0, "readers did not run\n");
    ok(StressOpens > 0, "the key never opened under a name\n");
    trace("%lu renames, %ld enumerations, %ld opens of the key\n", Iterations, StressEnums, StressOpens);

    /* The end state: the last name, everything under it intact */
    for (i = 0; i < RTL_NUMBER_OF(StressNames); i++)
        ok(Exists(StressParent, StressNames[i]) == (i == Current), "[%lu] %ls exists %d\n", i, StressNames[i], i == Current);
    Value = 0;
    Size = sizeof(Value);
    ok_long(RegQueryValueExW(StressSub, L"v", NULL, NULL, (PBYTE)&Value, &Size), ERROR_SUCCESS);
    ok_long(Value, 77);
    {
        WCHAR Tail[160];
        StringCbPrintfW(Tail, sizeof(Tail), L"\\stress\\%s\\sub", StressNames[Current]);
        ok(NameEndsWith(StressSub, Tail), "sub handle name is not under %ls\n", StressNames[Current]);
    }

    RegCloseKey(StressSub);
    RegCloseKey(StressKey);
    RegCloseKey(StressParent);
    ok_long(pRegDeleteTreeW(HKEY_CURRENT_USER, TEST_ROOT), ERROR_SUCCESS);
    RegDeleteKeyW(HKEY_CURRENT_USER, TEST_ROOT);
    ok(!Exists(HKEY_CURRENT_USER, TEST_ROOT), "test key left behind\n");
}

/* Persistence across a reboot: run once, reboot, run again */
START_TEST(RegRenameKeyPersist)
{
    HKEY Root, Key;
    DWORD Value = 4321, Size;
    WCHAR Class[32];

    if (!InitFunctions())
        return;

    Root = Open(HKEY_CURRENT_USER, PERSIST_ROOT, KEY_ALL_ACCESS);
    if (!Root)
    {
        /* First run: make a key with a value, a class and a subkey, rename it, flush */
        Root = Create(HKEY_CURRENT_USER, PERSIST_ROOT, 0);
        if (!Root)
            return;
        ok_long(RegCreateKeyExW(Root, L"Before", 0, L"PersistClass", 0, KEY_ALL_ACCESS, NULL, &Key, NULL), ERROR_SUCCESS);
        ok_long(RegSetValueExW(Key, L"v", 0, REG_DWORD, (PBYTE)&Value, sizeof(Value)), ERROR_SUCCESS);
        RegCloseKey(Create(Key, L"sub", 0));
        ok_long(RegFlushKey(Root), ERROR_SUCCESS);
        ok_hex(Rename(Key, L"After-a-longer-name"), STATUS_SUCCESS);
        RegCloseKey(Key);
        ok_long(RegFlushKey(Root), ERROR_SUCCESS);
        trace("RegRenameKeyPersist: renamed and flushed; run again after a reboot\n");
        RegCloseKey(Root);
        return;
    }

    /* Second run */
    ok(!Exists(Root, L"Before"), "Before is back\n");
    Key = Open(Root, L"After-a-longer-name", KEY_READ);
    ok(Key != NULL, "After-a-longer-name is missing\n");
    if (Key)
    {
        Value = 0;
        Size = sizeof(Value);
        ok_long(RegQueryValueExW(Key, L"v", NULL, NULL, (PBYTE)&Value, &Size), ERROR_SUCCESS);
        ok_long(Value, 4321);
        Size = RTL_NUMBER_OF(Class);
        ok_long(RegQueryInfoKeyW(Key, Class, &Size, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL), ERROR_SUCCESS);
        ok(!wcscmp(Class, L"PersistClass"), "class %ls\n", Class);
        ok(Exists(Key, L"sub"), "sub is missing\n");
        RegCloseKey(Key);
    }
    trace("RegRenameKeyPersist: checked\n");
    RegCloseKey(Root);
    ok_long(pRegDeleteTreeW(HKEY_CURRENT_USER, PERSIST_ROOT), ERROR_SUCCESS);
    RegDeleteKeyW(HKEY_CURRENT_USER, PERSIST_ROOT);
    ok(!Exists(HKEY_CURRENT_USER, PERSIST_ROOT), "persist key left behind\n");
}
