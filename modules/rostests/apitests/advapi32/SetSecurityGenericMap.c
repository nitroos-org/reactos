/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests that a descriptor set on an object is stored with its generic rights mapped
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <sddl.h>

/*
 * Measured on Windows Server 2022 (x64 and x86 under WoW64, the same): what NtSetSecurityObject,
 * SetKernelObjectSecurity, RegSetKeySecurity, SetFileSecurity and SetPrivateObjectSecurity store,
 * read back. The generic rights of every ACE that is not inherit-only are mapped with the object
 * type's generic mapping (also in ACEs with inheritance flags, and in a deny ACE); an inherit-only
 * ACE keeps them; no ACE is merged, split or dropped, the flags stay.
 */

typedef struct
{
    ULONG Count;
    struct { UCHAR Type, Flags; ULONG Mask; } Aces[4];
} ROW;

/* Masks after mapping with an event's (0x20001 0x20002 0x120000 0x1F0003), a key's (0x20019 0x20006 0x20039 0xF003F), a file's
   (0x120089 0x120116 0x1200A0 0x1F01FF) and the private test mapping (0x20001 0x20002 0x20004 0x1F00FF) */
enum { M_EVENT, M_KEY, M_FILE, M_PRIVATE, M_COUNT };

static const WCHAR *Sddls[] =
{
    L"D:(A;;GA;;;WD)",
    L"D:(A;;0x80000001;;;BU)(D;;GX;;;AN)",
    L"D:(A;CI;GW;;;BA)(A;OI;GR;;;BU)(A;OICI;GA;;;SY)",
    L"D:(A;OICIIO;GA;;;CO)(A;CIIO;GR;;;BU)(A;;0x20000;;;SY)",
};

/* Per descriptor and mapping: the ACEs stored (type, flags, mask) */
static const ROW Expected[RTL_NUMBER_OF(Sddls)][M_COUNT] =
{
    {
        { 1, {{0, 0x00, 0x001F0003}} },
        { 1, {{0, 0x00, 0x000F003F}} },
        { 1, {{0, 0x00, 0x001F01FF}} },
        { 1, {{0, 0x00, 0x001F00FF}} },
    },
    {
        { 2, {{0, 0x00, 0x00020001}, {1, 0x00, 0x00120000}} },
        { 2, {{0, 0x00, 0x00020019}, {1, 0x00, 0x00020039}} },
        { 2, {{0, 0x00, 0x00120089}, {1, 0x00, 0x001200A0}} },
        { 2, {{0, 0x00, 0x00020001}, {1, 0x00, 0x00020004}} },
    },
    {
        { 3, {{0, 0x02, 0x00020002}, {0, 0x01, 0x00020001}, {0, 0x03, 0x001F0003}} },
        { 3, {{0, 0x02, 0x00020006}, {0, 0x01, 0x00020019}, {0, 0x03, 0x000F003F}} },
        { 3, {{0, 0x02, 0x00120116}, {0, 0x01, 0x00120089}, {0, 0x03, 0x001F01FF}} },
        { 3, {{0, 0x02, 0x00020002}, {0, 0x01, 0x00020001}, {0, 0x03, 0x001F00FF}} },
    },
    {
        { 3, {{0, 0x0B, 0x10000000}, {0, 0x0A, 0x80000000}, {0, 0x00, 0x00020000}} },
        { 3, {{0, 0x0B, 0x10000000}, {0, 0x0A, 0x80000000}, {0, 0x00, 0x00020000}} },
        { 3, {{0, 0x0B, 0x10000000}, {0, 0x0A, 0x80000000}, {0, 0x00, 0x00020000}} },
        { 3, {{0, 0x0B, 0x10000000}, {0, 0x0A, 0x80000000}, {0, 0x00, 0x00020000}} },
    },
};

static GENERIC_MAPPING PrivateMapping = {0x20001, 0x20002, 0x20004, 0x1F00FF};

static void CheckStored(PSECURITY_DESCRIPTOR Sd, ULONG Row, ULONG Map, const char *What)
{
    const ROW *Want = &Expected[Row][Map];
    BOOL Present = FALSE, Defaulted;
    PACL Dacl = NULL;
    ACCESS_ALLOWED_ACE *Ace;
    ULONG i;

    ok(GetSecurityDescriptorDacl(Sd, &Present, &Dacl, &Defaulted), "%s %lu: no DACL (%lu)\n", What, Row, GetLastError());
    if (!Present || !Dacl)
    {
        ok(0, "%s %lu: DACL absent or NULL\n", What, Row);
        return;
    }
    ok(Dacl->AceCount == Want->Count, "%s %lu: %u ACEs, expected %lu\n", What, Row, Dacl->AceCount, Want->Count);
    for (i = 0; i < Dacl->AceCount && i < Want->Count; i++)
    {
        if (!GetAce(Dacl, i, (PVOID *)&Ace))
            break;
        ok(Ace->Header.AceType == Want->Aces[i].Type && Ace->Header.AceFlags == Want->Aces[i].Flags &&
           Ace->Mask == Want->Aces[i].Mask,
           "%s %lu ACE %lu: (%u;%02x;%08lx), expected (%u;%02x;%08lx)\n", What, Row, i,
           Ace->Header.AceType, Ace->Header.AceFlags, Ace->Mask,
           Want->Aces[i].Type, Want->Aces[i].Flags, Want->Aces[i].Mask);
    }
}

static PSECURITY_DESCRIPTOR FromSddl(const WCHAR *Sddl)
{
    PSECURITY_DESCRIPTOR Sd = NULL;
    ok(ConvertStringSecurityDescriptorToSecurityDescriptorW(Sddl, SDDL_REVISION_1, &Sd, NULL), "SDDL %ls: %lu\n", Sddl, GetLastError());
    return Sd;
}

static void TestEvent(void)
{
    BYTE Buffer[1024];
    DWORD Needed;
    HANDLE Event;
    ULONG i;
    WCHAR Name[64];

    StringCchPrintfW(Name, RTL_NUMBER_OF(Name), L"Local\\SetSecGenericMap%lu", GetCurrentProcessId());
    Event = CreateEventW(NULL, TRUE, FALSE, Name);
    ok(Event != NULL, "CreateEvent: %lu\n", GetLastError());
    if (!Event)
        return;
    for (i = 0; i < RTL_NUMBER_OF(Sddls); i++)
    {
        PSECURITY_DESCRIPTOR Sd = FromSddl(Sddls[i]);
        if (!Sd)
            continue;
        ok(SetKernelObjectSecurity(Event, DACL_SECURITY_INFORMATION, Sd), "SetKernelObjectSecurity %lu: %lu\n", i, GetLastError());
        ok(GetKernelObjectSecurity(Event, DACL_SECURITY_INFORMATION, Buffer, sizeof(Buffer), &Needed), "GetKernelObjectSecurity %lu: %lu\n", i, GetLastError());
        CheckStored(Buffer, i, M_EVENT, "event");
        LocalFree(Sd);
    }
    CloseHandle(Event);
}

static void TestKey(void)
{
    BYTE Buffer[1024];
    DWORD Length;
    HKEY Key;
    LONG Error;
    ULONG i;

    Error = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\SetSecurityGenericMapTest", 0, NULL, REG_OPTION_VOLATILE,
                            READ_CONTROL | WRITE_DAC, NULL, &Key, NULL);
    ok(Error == ERROR_SUCCESS, "RegCreateKeyEx: %ld\n", Error);
    if (Error)
        return;
    for (i = 0; i < RTL_NUMBER_OF(Sddls); i++)
    {
        PSECURITY_DESCRIPTOR Sd = FromSddl(Sddls[i]);
        if (!Sd)
            continue;
        Error = RegSetKeySecurity(Key, DACL_SECURITY_INFORMATION, Sd);
        ok(Error == ERROR_SUCCESS, "RegSetKeySecurity %lu: %ld\n", i, Error);
        Length = sizeof(Buffer);
        Error = RegGetKeySecurity(Key, DACL_SECURITY_INFORMATION, Buffer, &Length);
        ok(Error == ERROR_SUCCESS, "RegGetKeySecurity %lu: %ld\n", i, Error);
        if (!Error)
            CheckStored(Buffer, i, M_KEY, "key");
        LocalFree(Sd);
    }
    /* Everyone all access again (the last DACL set gives nobody DELETE), then delete */
    {
        PSECURITY_DESCRIPTOR Sd = FromSddl(L"D:(A;;KA;;;WD)");
        if (Sd)
        {
            RegSetKeySecurity(Key, DACL_SECURITY_INFORMATION, Sd);
            LocalFree(Sd);
        }
    }
    RegCloseKey(Key);
    Error = RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\SetSecurityGenericMapTest");
    ok(Error == ERROR_SUCCESS, "RegDeleteKey: %ld\n", Error);
}

static void TestFile(void)
{
    BYTE Buffer[1024];
    DWORD Needed;
    WCHAR Dir[MAX_PATH], Path[MAX_PATH];
    HANDLE File;
    ULONG i;

    GetTempPathW(RTL_NUMBER_OF(Dir), Dir);
    StringCchPrintfW(Path, RTL_NUMBER_OF(Path), L"%lsSetSecGenericMap%lu.tmp", Dir, GetCurrentProcessId());
    File = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "CreateFile: %lu\n", GetLastError());
    if (File == INVALID_HANDLE_VALUE)
        return;
    CloseHandle(File);
    for (i = 0; i < RTL_NUMBER_OF(Sddls); i++)
    {
        PSECURITY_DESCRIPTOR Sd = FromSddl(Sddls[i]);
        if (!Sd)
            continue;
        if (!SetFileSecurityW(Path, DACL_SECURITY_INFORMATION, Sd))
        {
            /* A file system without security (FAT) */
            skip("SetFileSecurity %lu: %lu\n", i, GetLastError());
            LocalFree(Sd);
            break;
        }
        ok(GetFileSecurityW(Path, DACL_SECURITY_INFORMATION, Buffer, sizeof(Buffer), &Needed), "GetFileSecurity %lu: %lu\n", i, GetLastError());
        CheckStored(Buffer, i, M_FILE, "file");
        LocalFree(Sd);
    }
    /* Everyone all access again (the last DACL set keeps nobody but SYSTEM), then delete */
    {
        PSECURITY_DESCRIPTOR Sd = FromSddl(L"D:(A;;FA;;;WD)");
        if (Sd)
        {
            SetFileSecurityW(Path, DACL_SECURITY_INFORMATION, Sd);
            LocalFree(Sd);
        }
    }
    ok(DeleteFileW(Path), "DeleteFile: %lu\n", GetLastError());
}

static void TestPrivate(void)
{
    BYTE Buffer[1024];
    DWORD Needed;
    PSECURITY_DESCRIPTOR Creator, Object = NULL;
    HANDLE Token = NULL;
    ULONG i;

    ok(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token), "OpenProcessToken: %lu\n", GetLastError());
    Creator = FromSddl(L"O:SYG:SYD:(A;;GA;;;WD)");
    if (!Creator)
        return;
    ok(CreatePrivateObjectSecurity(NULL, Creator, &Object, FALSE, Token, &PrivateMapping), "CreatePrivateObjectSecurity: %lu\n", GetLastError());
    LocalFree(Creator);
    if (!Object)
        return;
    for (i = 0; i < RTL_NUMBER_OF(Sddls); i++)
    {
        PSECURITY_DESCRIPTOR Sd = FromSddl(Sddls[i]);
        if (!Sd)
            continue;
        ok(SetPrivateObjectSecurity(DACL_SECURITY_INFORMATION, Sd, &Object, &PrivateMapping, Token), "SetPrivateObjectSecurity %lu: %lu\n", i, GetLastError());
        ok(GetPrivateObjectSecurity(Object, DACL_SECURITY_INFORMATION, Buffer, sizeof(Buffer), &Needed), "GetPrivateObjectSecurity %lu: %lu\n", i, GetLastError());
        CheckStored(Buffer, i, M_PRIVATE, "private");
        LocalFree(Sd);
    }
    DestroyPrivateObjectSecurity(&Object);
    CloseHandle(Token);
}

START_TEST(SetSecurityGenericMap)
{
    TestEvent();
    TestKey();
    TestFile();
    TestPrivate();
}
