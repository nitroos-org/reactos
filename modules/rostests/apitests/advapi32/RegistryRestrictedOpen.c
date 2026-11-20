/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Opening registry keys, creating subkeys and setting values with restricted and write restricted tokens
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The rows were measured on Windows Server 2022 (10.0.20348) by an administrator who impersonates each token and opens
 * HKLM\SOFTWARE\<test key>\<key> (RegOpenKeyEx with every mask below, RegOpenKeyEx(KEY_CREATE_SUB_KEY) and RegCreateKeyEx,
 * RegOpenKeyEx(KEY_SET_VALUE) and RegSetValueEx). The keys have protected DACLs:
 *   P0  Administrators, SYSTEM: all             (the parent of the others)
 *   C1  Administrators and S-1-5-33: all
 *   C2  S-1-5-33 only (the account is not in it)
 *   C3  Administrators: all, Everyone: read
 *   C4  Administrators and S-1-5-33: all, then an ACE denying Everyone KEY_WRITE
 * Tokens (copies of the administrator's token, an impersonation token):
 *   N      no restrictions                      R33   restricting SID S-1-5-33
 *   RWD    restricting SID Everyone             RBA   restricting SID Administrators
 *   RMIX   restricting SIDs Everyone, S-1-5-33  W33   write restricted, S-1-5-33
 *   WWD    write restricted, Everyone           W0    write restricted, no restricting SIDs
 * A restricted token is decided by the key's own descriptor on Windows. A token without restrictions is decided by it too, but
 * where registry key access is not enforced (the default) this system grants it every key as it always did, so the rows of
 * the unrestricted token for keys that do not grant it (C2) are not compared.
 */

#include "precomp.h"
#include <sddl.h>
#include <ndk/obfuncs.h>

#ifndef WRITE_RESTRICTED
#define WRITE_RESTRICTED 0x8
#endif

#define TEST_KEY L"SOFTWARE\\RosRegRestrOpenTest"

enum { TOK_N, TOK_R33, TOK_RWD, TOK_RBA, TOK_RMIX, TOK_W33, TOK_WWD, TOK_W0, TOK_COUNT };
enum { KEY_P0, KEY_C1, KEY_C2, KEY_C3, KEY_C4, KEY_COUNT };

static const PCWSTR KeyNames[KEY_COUNT] = { NULL, L"c1", L"c2", L"c3", L"c4" };
static const PCWSTR KeySds[KEY_COUNT] =
{
    L"D:P(A;;GA;;;BA)(A;;GA;;;SY)",
    L"D:P(A;;GA;;;BA)(A;;GA;;;S-1-5-33)",
    L"D:P(A;;GA;;;S-1-5-33)",
    L"D:P(A;;GA;;;BA)(A;;GR;;;WD)",
    L"D:P(A;;GA;;;BA)(A;;GA;;;S-1-5-33)(D;;KW;;;WD)",
};

static const DWORD Masks[] =
{
    KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_CREATE_SUB_KEY, KEY_ENUMERATE_SUB_KEYS, KEY_NOTIFY, READ_CONTROL, DELETE, WRITE_DAC,
    GENERIC_READ, GENERIC_WRITE, KEY_ALL_ACCESS, MAXIMUM_ALLOWED,
};
#define MASK_COUNT ARRAYSIZE(Masks)

/* Granted: bit n is set when mask n opens; Maximum: the access of a MAXIMUM_ALLOWED handle; Create, SetValue: they work */
static const struct
{
    INT Token;
    INT Key;
    DWORD Granted;
    DWORD Maximum;
    BOOL Create;
    BOOL SetValue;
} Rows[] =
{
    { TOK_N, KEY_P0, 0xfff, 0x000f003f, 1, 1 },
    { TOK_N, KEY_C1, 0xfff, 0x000f003f, 1, 1 },
    { TOK_N, KEY_C2, 0x8a0, 0x00060000, 0, 0 },
    { TOK_N, KEY_C3, 0xfff, 0x000f003f, 1, 1 },
    { TOK_N, KEY_C4, 0xfff, 0x000f003f, 1, 1 },
    { TOK_R33, KEY_P0, 0x000, 0x00000000, 0, 0 },
    { TOK_R33, KEY_C1, 0xfff, 0x000f003f, 1, 1 },
    { TOK_R33, KEY_C2, 0x000, 0x00000000, 0, 0 },
    { TOK_R33, KEY_C3, 0x000, 0x00000000, 0, 0 },
    { TOK_R33, KEY_C4, 0xfff, 0x000f003f, 1, 1 },
    { TOK_RWD, KEY_P0, 0x000, 0x00000000, 0, 0 },
    { TOK_RWD, KEY_C1, 0x000, 0x00000000, 0, 0 },
    { TOK_RWD, KEY_C2, 0x000, 0x00000000, 0, 0 },
    { TOK_RWD, KEY_C3, 0x939, 0x00020019, 0, 0 },
    { TOK_RWD, KEY_C4, 0x000, 0x00000000, 0, 0 },
    { TOK_RBA, KEY_P0, 0xfff, 0x000f003f, 1, 1 },
    { TOK_RBA, KEY_C1, 0xfff, 0x000f003f, 1, 1 },
    { TOK_RBA, KEY_C2, 0x8a0, 0x00060000, 0, 0 },
    { TOK_RBA, KEY_C3, 0xfff, 0x000f003f, 1, 1 },
    { TOK_RBA, KEY_C4, 0xfff, 0x000f003f, 1, 1 },
    { TOK_RMIX, KEY_P0, 0x000, 0x00000000, 0, 0 },
    { TOK_RMIX, KEY_C1, 0xfff, 0x000f003f, 1, 1 },
    { TOK_RMIX, KEY_C2, 0x000, 0x00000000, 0, 0 },
    { TOK_RMIX, KEY_C3, 0x939, 0x00020019, 0, 0 },
    { TOK_RMIX, KEY_C4, 0xfff, 0x000f003f, 1, 1 },
    { TOK_W33, KEY_P0, 0x939, 0x00020039, 0, 0 },
    { TOK_W33, KEY_C1, 0xfff, 0x000f003f, 1, 1 },
    { TOK_W33, KEY_C2, 0x000, 0x00000000, 0, 0 },
    { TOK_W33, KEY_C3, 0x939, 0x00020039, 0, 0 },
    { TOK_W33, KEY_C4, 0xfff, 0x000f003f, 1, 1 },
    { TOK_WWD, KEY_P0, 0x939, 0x00020039, 0, 0 },
    { TOK_WWD, KEY_C1, 0x939, 0x00020039, 0, 0 },
    { TOK_WWD, KEY_C2, 0x000, 0x00000000, 0, 0 },
    { TOK_WWD, KEY_C3, 0x939, 0x00020039, 0, 0 },
    { TOK_WWD, KEY_C4, 0x939, 0x00020039, 0, 0 },
    { TOK_W0, KEY_P0, 0x9b9, 0x00060039, 0, 0 },
    { TOK_W0, KEY_C1, 0x9b9, 0x00060039, 0, 0 },
    { TOK_W0, KEY_C2, 0x8a0, 0x00060000, 0, 0 },
    { TOK_W0, KEY_C3, 0x9b9, 0x00060039, 0, 0 },
    { TOK_W0, KEY_C4, 0x9b9, 0x00060039, 0, 0 },
};

static HANDLE Tokens[TOK_COUNT];

static BOOL
MakeTokens(VOID)
{
    HANDLE hProcess = NULL, hImp = NULL;
    BYTE Sid33[SECURITY_MAX_SID_SIZE], SidWd[SECURITY_MAX_SID_SIZE], SidBa[SECURITY_MAX_SID_SIZE];
    DWORD cb;
    SID_AND_ATTRIBUTES Restrict[2];
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    PISID Sid = (PISID)Sid33;
    BOOL Ret;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hProcess))
        return FALSE;
    Ret = DuplicateTokenEx(hProcess, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &hImp);
    CloseHandle(hProcess);
    if (!Ret)
        return FALSE;
    Tokens[TOK_N] = hImp;

    RtlInitializeSid(Sid, &NtAuthority, 1);
    *RtlSubAuthoritySid(Sid, 0) = 33;
    cb = sizeof(SidWd);
    CreateWellKnownSid(WinWorldSid, NULL, SidWd, &cb);
    cb = sizeof(SidBa);
    CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, SidBa, &cb);
    Restrict[0].Attributes = Restrict[1].Attributes = 0;

    Restrict[0].Sid = Sid33;
    Ret = CreateRestrictedToken(hImp, 0, 0, NULL, 0, NULL, 1, Restrict, &Tokens[TOK_R33]);
    Restrict[0].Sid = SidWd;
    Ret = Ret && CreateRestrictedToken(hImp, 0, 0, NULL, 0, NULL, 1, Restrict, &Tokens[TOK_RWD]);
    Restrict[0].Sid = SidBa;
    Ret = Ret && CreateRestrictedToken(hImp, 0, 0, NULL, 0, NULL, 1, Restrict, &Tokens[TOK_RBA]);
    Restrict[0].Sid = SidWd;
    Restrict[1].Sid = Sid33;
    Ret = Ret && CreateRestrictedToken(hImp, 0, 0, NULL, 0, NULL, 2, Restrict, &Tokens[TOK_RMIX]);
    Restrict[0].Sid = Sid33;
    Ret = Ret && CreateRestrictedToken(hImp, WRITE_RESTRICTED, 0, NULL, 0, NULL, 1, Restrict, &Tokens[TOK_W33]);
    Restrict[0].Sid = SidWd;
    Ret = Ret && CreateRestrictedToken(hImp, WRITE_RESTRICTED, 0, NULL, 0, NULL, 1, Restrict, &Tokens[TOK_WWD]);
    Ret = Ret && CreateRestrictedToken(hImp, WRITE_RESTRICTED, 0, NULL, 0, NULL, 0, NULL, &Tokens[TOK_W0]);
    ok(Ret, "creating the tokens failed with %lu\n", GetLastError());
    return Ret;
}

static VOID
KeyPath(INT Key, PWSTR Buffer, SIZE_T Count)
{
    if (KeyNames[Key])
        StringCchPrintfW(Buffer, Count, TEST_KEY L"\\%s", KeyNames[Key]);
    else
        StringCchCopyW(Buffer, Count, TEST_KEY);
}

static BOOL
MakeKeys(VOID)
{
    INT Key;
    WCHAR Path[100];
    HKEY hKey;
    LONG Error;
    PSECURITY_DESCRIPTOR Sd;

    for (Key = KEY_COUNT - 1; Key >= 0; Key--)
    {
        KeyPath(Key, Path, ARRAYSIZE(Path));
        RegDeleteKeyW(HKEY_LOCAL_MACHINE, Path);
    }

    for (Key = 0; Key < KEY_COUNT; Key++)
    {
        KeyPath(Key, Path, ARRAYSIZE(Path));
        Error = RegCreateKeyExW(HKEY_LOCAL_MACHINE, Path, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hKey, NULL);
        ok(Error == ERROR_SUCCESS, "creating %ls failed with %ld\n", Path, Error);
        if (Error != ERROR_SUCCESS)
            return FALSE;
        /* The descriptor goes on last: the creator needs the key while it is made */
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(KeySds[Key], SDDL_REVISION_1, &Sd, NULL))
        {
            RegCloseKey(hKey);
            return FALSE;
        }
        Error = RegSetKeySecurity(hKey, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, Sd);
        ok(Error == ERROR_SUCCESS, "setting the descriptor of %ls failed with %ld\n", Path, Error);
        LocalFree(Sd);
        RegCloseKey(hKey);
    }
    return TRUE;
}

static VOID
DeleteKeys(VOID)
{
    INT Key;
    WCHAR Path[100];

    for (Key = KEY_COUNT - 1; Key >= 0; Key--)
    {
        KeyPath(Key, Path, ARRAYSIZE(Path));
        StringCchCatW(Path, ARRAYSIZE(Path), L"\\sub");
        RegDeleteKeyW(HKEY_LOCAL_MACHINE, Path);
        KeyPath(Key, Path, ARRAYSIZE(Path));
        RegDeleteKeyW(HKEY_LOCAL_MACHINE, Path);
    }
}

static BOOL
Impersonate(INT Token)
{
    return SetThreadToken(NULL, Tokens[Token]);
}

static VOID
TestOpens(VOID)
{
    ULONG i, m;
    WCHAR Path[100];
    HKEY hKey;
    LONG Error;
    BOOL Opened;
    OBJECT_BASIC_INFORMATION Info;
    NTSTATUS Status;

    for (i = 0; i < ARRAYSIZE(Rows); i++)
    {
        KeyPath(Rows[i].Key, Path, ARRAYSIZE(Path));
        if (Rows[i].Token == TOK_N && Rows[i].Key == KEY_C2)
            continue;
        ok(Impersonate(Rows[i].Token), "SetThreadToken failed with %lu\n", GetLastError());

        for (m = 0; m < MASK_COUNT; m++)
        {
            hKey = NULL;
            Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, Path, 0, Masks[m], &hKey);
            Opened = Error == ERROR_SUCCESS;
            ok(Opened == !!(Rows[i].Granted & (1 << m)),
               "token %d key %d mask 0x%08lx: open returned %ld, expected %s\n",
               Rows[i].Token, Rows[i].Key, Masks[m], Error, (Rows[i].Granted & (1 << m)) ? "success" : "access denied");
            ok(Opened || Error == ERROR_ACCESS_DENIED, "token %d key %d mask 0x%08lx: error %ld\n",
               Rows[i].Token, Rows[i].Key, Masks[m], Error);
            if (!Opened)
                continue;
            if (Masks[m] == MAXIMUM_ALLOWED)
            {
                Status = NtQueryObject(hKey, ObjectBasicInformation, &Info, sizeof(Info), NULL);
                ok(NT_SUCCESS(Status), "NtQueryObject failed with 0x%lx\n", Status);
                if (NT_SUCCESS(Status))
                    ok(Info.GrantedAccess == Rows[i].Maximum, "token %d key %d: MAXIMUM_ALLOWED granted 0x%08lx, expected 0x%08lx\n",
                       Rows[i].Token, Rows[i].Key, Info.GrantedAccess, Rows[i].Maximum);
            }
            RegCloseKey(hKey);
        }
        SetThreadToken(NULL, NULL);
    }
}

static VOID
TestCreateAndSet(VOID)
{
    ULONG i;
    WCHAR Path[100];
    HKEY hKey, hSub;
    LONG Error;
    DWORD Value = 1, Disposition;

    for (i = 0; i < ARRAYSIZE(Rows); i++)
    {
        if (Rows[i].Token == TOK_N && Rows[i].Key == KEY_C2)
            continue;
        KeyPath(Rows[i].Key, Path, ARRAYSIZE(Path));
        Impersonate(Rows[i].Token);

        hKey = NULL;
        Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, Path, 0, KEY_CREATE_SUB_KEY, &hKey);
        if (Error == ERROR_SUCCESS)
        {
            hSub = NULL;
            Error = RegCreateKeyExW(hKey, L"sub", 0, NULL, 0, KEY_READ, NULL, &hSub, &Disposition);
            ok(Error == ERROR_SUCCESS, "token %d key %d: creating a subkey failed with %ld\n", Rows[i].Token, Rows[i].Key, Error);
            if (hSub)
                RegCloseKey(hSub);
            RegCloseKey(hKey);
        }
        ok(Rows[i].Create == (Error == ERROR_SUCCESS), "token %d key %d: open for creating a subkey and the create gave %ld, expected %s\n",
           Rows[i].Token, Rows[i].Key, Error, Rows[i].Create ? "success" : "access denied");

        hKey = NULL;
        Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, Path, 0, KEY_SET_VALUE, &hKey);
        if (Error == ERROR_SUCCESS)
        {
            Error = RegSetValueExW(hKey, L"v", 0, REG_DWORD, (PBYTE)&Value, sizeof(Value));
            RegCloseKey(hKey);
        }
        ok(Rows[i].SetValue == (Error == ERROR_SUCCESS), "token %d key %d: open for setting a value and the write gave %ld, expected %s\n",
           Rows[i].Token, Rows[i].Key, Error, Rows[i].SetValue ? "success" : "access denied");

        SetThreadToken(NULL, NULL);

        /* the subkey made by the administrator's token below or by the token itself goes away again */
        {
            WCHAR Sub[110];

            StringCchPrintfW(Sub, ARRAYSIZE(Sub), L"%s\\sub", Path);
            RegDeleteKeyW(HKEY_LOCAL_MACHINE, Sub);
        }
    }
}

/*
 * A subkey made by its absolute path (RegCreateKeyEx on HKEY_LOCAL_MACHINE, no handle of the parent) needs the same right on the
 * parent as the create through a handle of it (measured on Windows Server 2022 for the keys P0, C1, C2 and C3: the rows of
 * Create above), and so for a restricted token it must not succeed where the open for creating a subkey does not
 */
static VOID
TestPathCreate(VOID)
{
    ULONG i;
    WCHAR Path[110];
    HKEY hSub;
    LONG Error;
    DWORD Disposition;

    for (i = 0; i < ARRAYSIZE(Rows); i++)
    {
        if (Rows[i].Key == KEY_C4 || (Rows[i].Token == TOK_N && Rows[i].Key == KEY_C2))
            continue;
        KeyPath(Rows[i].Key, Path, ARRAYSIZE(Path));
        StringCchCatW(Path, ARRAYSIZE(Path), L"\\pcsub");
        Impersonate(Rows[i].Token);
        hSub = NULL;
        Error = RegCreateKeyExW(HKEY_LOCAL_MACHINE, Path, 0, NULL, 0, KEY_READ, NULL, &hSub, &Disposition);
        SetThreadToken(NULL, NULL);
        if (hSub)
            RegCloseKey(hSub);
        ok(Rows[i].Create == (Error == ERROR_SUCCESS), "token %d key %d: creating a subkey by its path gave %ld, expected %s\n",
           Rows[i].Token, Rows[i].Key, Error, Rows[i].Create ? "success" : "access denied");
        RegDeleteKeyW(HKEY_LOCAL_MACHINE, Path);
    }
}

START_TEST(RegistryRestrictedOpen)
{
    ULONG i;

    if (!MakeTokens())
    {
        skip("no tokens\n");
        return;
    }
    if (!MakeKeys())
    {
        skip("no keys (the test needs an elevated administrator)\n");
        DeleteKeys();
        return;
    }

    TestOpens();
    TestCreateAndSet();
    TestPathCreate();

    DeleteKeys();
    for (i = 0; i < TOK_COUNT; i++)
        if (Tokens[i])
            CloseHandle(Tokens[i]);
}
