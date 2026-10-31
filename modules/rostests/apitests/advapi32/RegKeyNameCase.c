/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test the case of key names (NtQueryKey, NtQueryObject) and the
 *              case mapping of key names (RtlUpcaseUnicodeChar, case-insensitive opens)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <ndk/cmfuncs.h>
#include <ndk/obfuncs.h>
#include <ndk/rtlfuncs.h>

/*
 * The expectations are what Windows 10 22H2 returns (measured, read-only, on
 * own temporary HKCU keys):
 *  - KeyNameInformation, ObjectNameInformation, KeyBasicInformation and
 *    KeyNodeInformation all report the case a key was CREATED with, however it
 *    was opened (other case, relative to a parent, through HKCU) and whatever
 *    other key of the same name (upper-cased) exists elsewhere. Only the names
 *    of the root of a hive come from the hive's mount name (\REGISTRY\MACHINE\SOFTWARE).
 *  - a case-insensitive open maps case with the Windows upcase table; the table
 *    entries below are RtlUpcaseUnicodeChar of Windows 10 22H2 for U+0000-U+FFFF.
 */

#define TEST_ROOT L"Software\\cmfProbe-CASE-RegKeyNameCase"
#define ROOT_COMPONENT L"\\cmfProbe-CASE-RegKeyNameCase"

static LSTATUS (WINAPI *pRegRenameKey)(HKEY, LPCWSTR, LPCWSTR);
static LSTATUS (WINAPI *pRegDeleteTreeW)(HKEY, LPCWSTR);

static
BOOLEAN
IsWow64(VOID)
{
    BOOL Wow64 = FALSE;

    return IsWow64Process(GetCurrentProcess(), &Wow64) && Wow64;
}

/* Does the NT name end with Tail, spelled exactly like Tail? */
static
BOOLEAN
EndsWithExact(
    _In_reads_(Bytes / sizeof(WCHAR)) PCWCH Name,
    _In_ ULONG Bytes,
    _In_ PCWSTR Tail)
{
    ULONG Chars = Bytes / sizeof(WCHAR), TailChars = (ULONG)wcslen(Tail);

    return Chars >= TailChars && !wcsncmp(&Name[Chars - TailChars], Tail, TailChars);
}

/* All four ways of asking for the name must show Tail (full path) and Last (last component) */
static
VOID
CheckNames(
    _In_ HKEY Key,
    _In_ PCSTR What,
    _In_ PCWSTR Tail,
    _In_ PCWSTR Last)
{
    ULONG Buffer[512];
    ULONG Length;
    NTSTATUS Status;
    PKEY_NAME_INFORMATION NameInfo = (PKEY_NAME_INFORMATION)Buffer;
    PKEY_BASIC_INFORMATION BasicInfo = (PKEY_BASIC_INFORMATION)Buffer;
    PKEY_NODE_INFORMATION NodeInfo = (PKEY_NODE_INFORMATION)Buffer;
    POBJECT_NAME_INFORMATION ObjectInfo = (POBJECT_NAME_INFORMATION)Buffer;

    Status = NtQueryKey(Key, KeyNameInformation, Buffer, sizeof(Buffer), &Length);
    ok(Status == STATUS_SUCCESS, "%s: KeyNameInformation 0x%lx\n", What, Status);
    if (NT_SUCCESS(Status))
        ok(EndsWithExact(NameInfo->Name, NameInfo->NameLength, Tail),
           "%s: KeyNameInformation is %.*ls, expected ...%ls\n",
           What, (int)(NameInfo->NameLength / sizeof(WCHAR)), NameInfo->Name, Tail);

    Status = NtQueryObject(Key, ObjectNameInformation, Buffer, sizeof(Buffer), &Length);
    ok(Status == STATUS_SUCCESS, "%s: ObjectNameInformation 0x%lx\n", What, Status);
    if (NT_SUCCESS(Status))
        ok(EndsWithExact(ObjectInfo->Name.Buffer, ObjectInfo->Name.Length, Tail),
           "%s: ObjectNameInformation is %.*ls, expected ...%ls\n",
           What, (int)(ObjectInfo->Name.Length / sizeof(WCHAR)), ObjectInfo->Name.Buffer, Tail);

    Status = NtQueryKey(Key, KeyBasicInformation, Buffer, sizeof(Buffer), &Length);
    ok(Status == STATUS_SUCCESS, "%s: KeyBasicInformation 0x%lx\n", What, Status);
    if (NT_SUCCESS(Status))
        ok(BasicInfo->NameLength == wcslen(Last) * sizeof(WCHAR) &&
           !wcsncmp(BasicInfo->Name, Last, BasicInfo->NameLength / sizeof(WCHAR)),
           "%s: KeyBasicInformation is %.*ls, expected %ls\n",
           What, (int)(BasicInfo->NameLength / sizeof(WCHAR)), BasicInfo->Name, Last);

    Status = NtQueryKey(Key, KeyNodeInformation, Buffer, sizeof(Buffer), &Length);
    ok(Status == STATUS_SUCCESS, "%s: KeyNodeInformation 0x%lx\n", What, Status);
    if (NT_SUCCESS(Status))
        ok(NodeInfo->NameLength == wcslen(Last) * sizeof(WCHAR) &&
           !wcsncmp(NodeInfo->Name, Last, NodeInfo->NameLength / sizeof(WCHAR)),
           "%s: KeyNodeInformation is %.*ls, expected %ls\n",
           What, (int)(NodeInfo->NameLength / sizeof(WCHAR)), NodeInfo->Name, Last);
}

static
VOID
CheckNtName(
    _In_ PCWSTR Path,
    _In_ PCWSTR Expected)
{
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES Attributes;
    HANDLE Key;
    ULONG Buffer[512], Length;
    PKEY_NAME_INFORMATION NameInfo = (PKEY_NAME_INFORMATION)Buffer;
    NTSTATUS Status;

    RtlInitUnicodeString(&Name, Path);
    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenKey(&Key, KEY_READ, &Attributes);
    ok(Status == STATUS_SUCCESS, "NtOpenKey(%ls) 0x%lx\n", Path, Status);
    if (!NT_SUCCESS(Status))
        return;
    Status = NtQueryKey(Key, KeyNameInformation, Buffer, sizeof(Buffer), &Length);
    ok(Status == STATUS_SUCCESS, "%ls: KeyNameInformation 0x%lx\n", Path, Status);
    if (NT_SUCCESS(Status))
        ok(NameInfo->NameLength == wcslen(Expected) * sizeof(WCHAR) &&
           !wcsncmp(NameInfo->Name, Expected, NameInfo->NameLength / sizeof(WCHAR)),
           "%ls: name is %.*ls, expected %ls\n",
           Path, (int)(NameInfo->NameLength / sizeof(WCHAR)), NameInfo->Name, Expected);
    NtClose(Key);
}

static
VOID
TestKeyNameCase(VOID)
{
    HKEY Root, Key, Key2;
    LONG Error;
    WCHAR Cyrillic[] = { 0x0416, 0x0436, L'A', L'b', 0x0434, 0 };
    WCHAR Latin1[] = { 0x00c4, 0x00f6, 0x00dc, L'a', L'b', 0 };
    WCHAR Tail[128];

    Error = RegCreateKeyExW(HKEY_CURRENT_USER, TEST_ROOT, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Root, NULL);
    ok(Error == ERROR_SUCCESS, "create root %ld\n", Error);
    if (Error)
        return;
    CheckNames(Root, "root", ROOT_COMPONENT, L"cmfProbe-CASE-RegKeyNameCase");

    /* created in mixed case */
    Error = RegCreateKeyExW(Root, L"MiXeD\\SubKEY\\deepLower", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Key, NULL);
    ok(Error == ERROR_SUCCESS, "create %ld\n", Error);
    if (!Error)
    {
        CheckNames(Key, "created", ROOT_COMPONENT L"\\MiXeD\\SubKEY\\deepLower", L"deepLower");
        RegCloseKey(Key);
    }

    /* opened in other cases */
    Error = RegOpenKeyExW(Root, L"mixed\\subkey\\DEEPLOWER", 0, KEY_ALL_ACCESS, &Key);
    ok(Error == ERROR_SUCCESS, "open other case %ld\n", Error);
    if (!Error)
    {
        CheckNames(Key, "reopened lower/upper", ROOT_COMPONENT L"\\MiXeD\\SubKEY\\deepLower", L"deepLower");
        RegCloseKey(Key);
    }
    Error = RegOpenKeyExW(Root, L"MIXED", 0, KEY_ALL_ACCESS, &Key);
    ok(Error == ERROR_SUCCESS, "open MIXED %ld\n", Error);
    if (!Error)
    {
        CheckNames(Key, "opened MIXED", ROOT_COMPONENT L"\\MiXeD", L"MiXeD");
        RegCloseKey(Key);
    }
    Error = RegOpenKeyExW(HKEY_CURRENT_USER, L"software\\CMFPROBE-case-regkeynamecase\\mixed", 0, KEY_ALL_ACCESS, &Key);
    ok(Error == ERROR_SUCCESS, "open through HKCU %ld\n", Error);
    if (!Error)
    {
        CheckNames(Key, "opened through HKCU", ROOT_COMPONENT L"\\MiXeD", L"MiXeD");
        RegCloseKey(Key);
    }

    /* the first open after the creating handle was closed uses another case */
    Error = RegCreateKeyExW(Root, L"Fresh\\OnlyOnce", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Key, NULL);
    ok(Error == ERROR_SUCCESS, "create Fresh %ld\n", Error);
    if (!Error)
        RegCloseKey(Key);
    Error = RegOpenKeyExW(Root, L"FRESH\\ONLYONCE", 0, KEY_ALL_ACCESS, &Key);
    ok(Error == ERROR_SUCCESS, "open FRESH %ld\n", Error);
    if (!Error)
    {
        CheckNames(Key, "first open FRESH\\ONLYONCE", ROOT_COMPONENT L"\\Fresh\\OnlyOnce", L"OnlyOnce");
        RegCloseKey(Key);
    }

    /* the same name, differently spelled, under two parents */
    Key = Key2 = NULL;
    Error = RegCreateKeyExW(Root, L"P1\\NaMe", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Key, NULL);
    ok(Error == ERROR_SUCCESS, "create P1 %ld\n", Error);
    Error = RegCreateKeyExW(Root, L"P2\\nAmE", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Key2, NULL);
    ok(Error == ERROR_SUCCESS, "create P2 %ld\n", Error);
    if (Key && Key2)
    {
        CheckNames(Key, "P1\\NaMe", ROOT_COMPONENT L"\\P1\\NaMe", L"NaMe");
        CheckNames(Key2, "P2\\nAmE", ROOT_COMPONENT L"\\P2\\nAmE", L"nAmE");
    }
    if (Key) RegCloseKey(Key);
    if (Key2) RegCloseKey(Key2);

    /* names with non-ASCII characters */
    Error = RegCreateKeyExW(Root, Latin1, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Key, NULL);
    ok(Error == ERROR_SUCCESS, "create Latin1 %ld\n", Error);
    if (!Error)
    {
        wcscpy(Tail, ROOT_COMPONENT L"\\");
        wcscat(Tail, Latin1);
        CheckNames(Key, "Latin-1", Tail, Latin1);
        RegCloseKey(Key);
    }
    Error = RegCreateKeyExW(Root, Cyrillic, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Key, NULL);
    ok(Error == ERROR_SUCCESS, "create Cyrillic %ld\n", Error);
    if (!Error)
    {
        wcscpy(Tail, ROOT_COMPONENT L"\\");
        wcscat(Tail, Cyrillic);
        CheckNames(Key, "Cyrillic", Tail, Cyrillic);
        RegCloseKey(Key);
    }

    /* renamed */
    if (pRegRenameKey)
    {
        Error = RegCreateKeyExW(Root, L"BeforeRen", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Key, NULL);
        ok(Error == ERROR_SUCCESS, "create BeforeRen %ld\n", Error);
        if (!Error)
        {
            Error = pRegRenameKey(Key, NULL, L"AfterREN");
            ok(Error == ERROR_SUCCESS, "RegRenameKey %ld\n", Error);
            if (!Error)
                CheckNames(Key, "renamed AfterREN", ROOT_COMPONENT L"\\AfterREN", L"AfterREN");
            RegCloseKey(Key);
        }
    }

    /* the mount names of the hives are what they were linked as */
    /* a 32-bit process is shown the physical Wow6432Node */
    if (!IsWow64())
        CheckNtName(L"\\registry\\machine\\software", L"\\REGISTRY\\MACHINE\\SOFTWARE");
    CheckNtName(L"\\REGISTRY\\MACHINE", L"\\REGISTRY\\MACHINE");
    CheckNtName(L"\\Registry\\User", L"\\REGISTRY\\USER");

    RegCloseKey(Root);
}

/* RtlUpcaseUnicodeChar of Windows 10 22H2: every character that changes, as runs
 * { first, last, step, delta } */
static const struct
{
    WCHAR First, Last;
    SHORT Step, Delta;
} UpcaseRuns[] =
{
    { 0x0061, 0x007a, 1, -32 },
    { 0x00e0, 0x00f6, 1, -32 },
    { 0x00f8, 0x00fe, 1, -32 },
    { 0x00ff, 0x00ff, 1, 121 },
    { 0x0101, 0x012f, 2, -1 },
    { 0x0133, 0x0137, 2, -1 },
    { 0x013a, 0x0148, 2, -1 },
    { 0x014b, 0x0177, 2, -1 },
    { 0x017a, 0x017e, 2, -1 },
    { 0x0180, 0x0180, 1, 195 },
    { 0x0183, 0x0185, 2, -1 },
    { 0x0188, 0x0188, 1, -1 },
    { 0x018c, 0x018c, 1, -1 },
    { 0x0192, 0x0192, 1, -1 },
    { 0x0195, 0x0195, 1, 97 },
    { 0x0199, 0x0199, 1, -1 },
    { 0x019a, 0x019a, 1, 163 },
    { 0x019e, 0x019e, 1, 130 },
    { 0x01a1, 0x01a5, 2, -1 },
    { 0x01a8, 0x01a8, 1, -1 },
    { 0x01ad, 0x01ad, 1, -1 },
    { 0x01b0, 0x01b0, 1, -1 },
    { 0x01b4, 0x01b6, 2, -1 },
    { 0x01b9, 0x01b9, 1, -1 },
    { 0x01bd, 0x01bd, 1, -1 },
    { 0x01bf, 0x01bf, 1, 56 },
    { 0x01c6, 0x01c6, 1, -2 },
    { 0x01c9, 0x01c9, 1, -2 },
    { 0x01cc, 0x01cc, 1, -2 },
    { 0x01ce, 0x01dc, 2, -1 },
    { 0x01dd, 0x01dd, 1, -79 },
    { 0x01df, 0x01ef, 2, -1 },
    { 0x01f3, 0x01f3, 1, -2 },
    { 0x01f5, 0x01f5, 1, -1 },
    { 0x01f9, 0x021f, 2, -1 },
    { 0x0223, 0x0233, 2, -1 },
    { 0x023c, 0x023c, 1, -1 },
    { 0x0242, 0x0242, 1, -1 },
    { 0x0247, 0x024f, 2, -1 },
    { 0x0250, 0x0250, 1, 10783 },
    { 0x0251, 0x0251, 1, 10780 },
    { 0x0253, 0x0253, 1, -210 },
    { 0x0254, 0x0254, 1, -206 },
    { 0x0256, 0x0257, 1, -205 },
    { 0x0259, 0x0259, 1, -202 },
    { 0x025b, 0x025b, 1, -203 },
    { 0x0260, 0x0260, 1, -205 },
    { 0x0263, 0x0263, 1, -207 },
    { 0x0268, 0x0268, 1, -209 },
    { 0x0269, 0x0269, 1, -211 },
    { 0x026b, 0x026b, 1, 10743 },
    { 0x026f, 0x026f, 1, -211 },
    { 0x0271, 0x0271, 1, 10749 },
    { 0x0272, 0x0272, 1, -213 },
    { 0x0275, 0x0275, 1, -214 },
    { 0x027d, 0x027d, 1, 10727 },
    { 0x0280, 0x0280, 1, -218 },
    { 0x0283, 0x0283, 1, -218 },
    { 0x0288, 0x0288, 1, -218 },
    { 0x0289, 0x0289, 1, -69 },
    { 0x028a, 0x028b, 1, -217 },
    { 0x028c, 0x028c, 1, -71 },
    { 0x0292, 0x0292, 1, -219 },
    { 0x0371, 0x0373, 2, -1 },
    { 0x0377, 0x0377, 1, -1 },
    { 0x037b, 0x037d, 1, 130 },
    { 0x03ac, 0x03ac, 1, -38 },
    { 0x03ad, 0x03af, 1, -37 },
    { 0x03b1, 0x03c1, 1, -32 },
    { 0x03c3, 0x03cb, 1, -32 },
    { 0x03cc, 0x03cc, 1, -64 },
    { 0x03cd, 0x03ce, 1, -63 },
    { 0x03d7, 0x03d7, 1, -8 },
    { 0x03d9, 0x03ef, 2, -1 },
    { 0x03f2, 0x03f2, 1, 7 },
    { 0x03f8, 0x03f8, 1, -1 },
    { 0x03fb, 0x03fb, 1, -1 },
    { 0x0430, 0x044f, 1, -32 },
    { 0x0450, 0x045f, 1, -80 },
    { 0x0461, 0x0481, 2, -1 },
    { 0x048b, 0x04bf, 2, -1 },
    { 0x04c2, 0x04ce, 2, -1 },
    { 0x04cf, 0x04cf, 1, -15 },
    { 0x04d1, 0x0523, 2, -1 },
    { 0x0561, 0x0586, 1, -48 },
    { 0x1d79, 0x1d79, 1, 35332 },
    { 0x1d7d, 0x1d7d, 1, 3814 },
    { 0x1e01, 0x1e95, 2, -1 },
    { 0x1ea1, 0x1eff, 2, -1 },
    { 0x1f00, 0x1f07, 1, 8 },
    { 0x1f10, 0x1f15, 1, 8 },
    { 0x1f20, 0x1f27, 1, 8 },
    { 0x1f30, 0x1f37, 1, 8 },
    { 0x1f40, 0x1f45, 1, 8 },
    { 0x1f51, 0x1f57, 2, 8 },
    { 0x1f60, 0x1f67, 1, 8 },
    { 0x1f70, 0x1f71, 1, 74 },
    { 0x1f72, 0x1f75, 1, 86 },
    { 0x1f76, 0x1f77, 1, 100 },
    { 0x1f78, 0x1f79, 1, 128 },
    { 0x1f7a, 0x1f7b, 1, 112 },
    { 0x1f7c, 0x1f7d, 1, 126 },
    { 0x1f80, 0x1f87, 1, 8 },
    { 0x1f90, 0x1f97, 1, 8 },
    { 0x1fa0, 0x1fa7, 1, 8 },
    { 0x1fb0, 0x1fb1, 1, 8 },
    { 0x1fb3, 0x1fb3, 1, 9 },
    { 0x1fc3, 0x1fc3, 1, 9 },
    { 0x1fd0, 0x1fd1, 1, 8 },
    { 0x1fe0, 0x1fe1, 1, 8 },
    { 0x1fe5, 0x1fe5, 1, 7 },
    { 0x1ff3, 0x1ff3, 1, 9 },
    { 0x214e, 0x214e, 1, -28 },
    { 0x2170, 0x217f, 1, -16 },
    { 0x2184, 0x2184, 1, -1 },
    { 0x24d0, 0x24e9, 1, -26 },
    { 0x2c30, 0x2c5e, 1, -48 },
    { 0x2c61, 0x2c61, 1, -1 },
    { 0x2c65, 0x2c65, 1, -10795 },
    { 0x2c66, 0x2c66, 1, -10792 },
    { 0x2c68, 0x2c6c, 2, -1 },
    { 0x2c73, 0x2c73, 1, -1 },
    { 0x2c76, 0x2c76, 1, -1 },
    { 0x2c81, 0x2ce3, 2, -1 },
    { 0x2d00, 0x2d25, 1, -7264 },
    { 0xa641, 0xa65f, 2, -1 },
    { 0xa663, 0xa66d, 2, -1 },
    { 0xa681, 0xa697, 2, -1 },
    { 0xa723, 0xa72f, 2, -1 },
    { 0xa733, 0xa76f, 2, -1 },
    { 0xa77a, 0xa77c, 2, -1 },
    { 0xa77f, 0xa787, 2, -1 },
    { 0xa78c, 0xa78c, 1, -1 },
    { 0xff41, 0xff5a, 1, -32 },
};

/* Characters that do NOT change on Windows although other tables map them */
static const struct
{
    WCHAR Char, NotEqualTo;
} NoMapping[] =
{
    { 0x00b5, 0x039c }, /* micro sign */
    { 0x0131, L'I' },   /* dotless i */
    { 0x017f, L'S' },   /* long s */
    { 0x03c2, 0x03a3 }, /* final sigma */
};

static
BOOLEAN
OpensAs(
    _In_ HKEY Root,
    _In_ WCHAR Created,
    _In_ WCHAR Opened,
    _Out_ PLONG Error)
{
    WCHAR Name[2], Name2[2];
    HKEY Key, Key2;

    Name[0] = Created; Name[1] = 0;
    Name2[0] = Opened; Name2[1] = 0;
    *Error = RegCreateKeyExW(Root, Name, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Key, NULL);
    if (*Error)
        return FALSE;
    *Error = RegOpenKeyExW(Root, Name2, 0, KEY_READ, &Key2);
    if (!*Error)
        RegCloseKey(Key2);
    RegCloseKey(Key);
    return *Error == ERROR_SUCCESS;
}

static
VOID
TestUnicodeCase(VOID)
{
    HKEY Root, Key;
    LONG Error;
    ULONG i, Bad = 0, BadRtl = 0, Total = 0;
    ULONG c;
    WCHAR Upper;
    WCHAR Zhe[] = { 0x0436, 0 }, ZheUpper[] = { 0x0416, 0 };

    Error = RegCreateKeyExW(HKEY_CURRENT_USER, TEST_ROOT, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Root, NULL);
    ok(Error == ERROR_SUCCESS, "create root %ld\n", Error);
    if (Error)
        return;

    /* Cyrillic: opened in the other case */
    Error = RegCreateKeyExW(Root, Zhe, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Key, NULL);
    ok(Error == ERROR_SUCCESS, "create U+0436 %ld\n", Error);
    if (!Error)
        RegCloseKey(Key);
    Error = RegOpenKeyExW(Root, ZheUpper, 0, KEY_READ, &Key);
    ok(Error == ERROR_SUCCESS, "open U+0416 for U+0436: %ld\n", Error);
    if (!Error)
        RegCloseKey(Key);

    /* the whole table: user mode and the registry */
    for (i = 0; i < ARRAYSIZE(UpcaseRuns); i++)
    {
        for (c = UpcaseRuns[i].First; c <= UpcaseRuns[i].Last; c += UpcaseRuns[i].Step)
        {
            Upper = (WCHAR)(c + UpcaseRuns[i].Delta);
            Total++;
            if (RtlUpcaseUnicodeChar((WCHAR)c) != Upper)
            {
                if (BadRtl++ < 8)
                    trace("RtlUpcaseUnicodeChar(%04lx) = %04x, expected %04x\n",
                          c, RtlUpcaseUnicodeChar((WCHAR)c), Upper);
            }
            if (!OpensAs(Root, (WCHAR)c, Upper, &Error))
            {
                if (Bad++ < 8)
                    trace("key %04lx does not open as %04x: %ld\n", c, Upper, Error);
            }
        }
    }
    ok(BadRtl == 0, "RtlUpcaseUnicodeChar differs from Windows for %lu of %lu characters\n", BadRtl, Total);
    ok(Bad == 0, "case-insensitive key open differs from Windows for %lu of %lu characters\n", Bad, Total);

    /* characters Windows leaves alone (each in a parent of its own: the other
     * character would find the key of its own lower or upper case otherwise) */
    for (i = 0; i < ARRAYSIZE(NoMapping); i++)
    {
        WCHAR Sub[8];
        HKEY SubKey;
        BOOLEAN Same = TRUE;

        _snwprintf(Sub, ARRAYSIZE(Sub), L"Neg%lu", i);
        Error = RegCreateKeyExW(Root, Sub, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &SubKey, NULL);
        ok(Error == ERROR_SUCCESS, "create %ls %ld\n", Sub, Error);
        if (!Error)
        {
            Same = OpensAs(SubKey, NoMapping[i].Char, NoMapping[i].NotEqualTo, &Error);
            RegCloseKey(SubKey);
        }
        ok(!Same, "U+%04x opens as U+%04x\n", NoMapping[i].Char, NoMapping[i].NotEqualTo);
        ok(RtlUpcaseUnicodeChar(NoMapping[i].Char) == NoMapping[i].Char,
           "RtlUpcaseUnicodeChar(U+%04x) = U+%04x\n", NoMapping[i].Char, RtlUpcaseUnicodeChar(NoMapping[i].Char));
    }

    RegCloseKey(Root);
}

START_TEST(RegKeyNameCase)
{
    HMODULE Advapi32 = GetModuleHandleW(L"advapi32.dll");
    HKEY Key;

    pRegRenameKey = (PVOID)GetProcAddress(Advapi32, "RegRenameKey");
    pRegDeleteTreeW = (PVOID)GetProcAddress(Advapi32, "RegDeleteTreeW");
    if (!pRegDeleteTreeW)
    {
        skip("RegDeleteTreeW is missing\n");
        return;
    }
    pRegDeleteTreeW(HKEY_CURRENT_USER, TEST_ROOT);
    TestKeyNameCase();
    TestUnicodeCase();
    pRegDeleteTreeW(HKEY_CURRENT_USER, TEST_ROOT);
    ok(RegOpenKeyExW(HKEY_CURRENT_USER, TEST_ROOT, 0, KEY_READ, &Key) == ERROR_FILE_NOT_FOUND,
       "the test root is still there\n");
}
