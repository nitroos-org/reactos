/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The AppContainer pass of the access check for a lowbox token
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A lowbox (AppContainer) token is granted only what both the normal pass (its user and groups) and the AppContainer
 * pass (its package SID, its enabled capabilities, ALL APPLICATION PACKAGES, ALL RESTRICTED APPLICATION PACKAGES)
 * grant. Measured on Windows Server 2022 (the rows of the ticket): nothing without such an ACE, also on a NULL DACL and
 * as the owner (READ_CONTROL), and the open of a process of its user (no such ACE in the process DACL) is refused.
 * The other rows (intersection, capabilities, the restricted packages group, a deny ACE) follow the documented rule
 * and are not measured. The plain token of the same user is checked on every row: its results are unchanged.
 * The descriptors carry a Low label (no write up), so the label of the Low lowbox token does not decide the rows.
 */

#include "precomp.h"
#include <sddl.h>

/* S-1-15-2-1-2-3-4-5-6-7 (the package), S-1-15-3-1 (a capability it holds), S-1-15-3-3 (one it does not) */
static struct { UCHAR Revision, Count, Authority[6]; ULONG Sub[8]; } AcPackage =
    { 1, 8, { 0, 0, 0, 0, 0, 15 }, { 2, 1, 2, 3, 4, 5, 6, 7 } };
static struct { UCHAR Revision, Count, Authority[6]; ULONG Sub[2]; } AcCapability =
    { 1, 2, { 0, 0, 0, 0, 0, 15 }, { 3, 1 } };

#define AC_PKG  L"S-1-15-2-1-2-3-4-5-6-7"
#define AC_CAP  L"S-1-15-3-1"
#define AC_CAP2 L"S-1-15-3-3"
#define AC_ALL  L"S-1-15-2-1"
#define AC_RES  L"S-1-15-2-2"

static GENERIC_MAPPING AcMapping = { 0x1, 0x2, 0x4, 0x7 };
#define AC_ANY 0xFFFFFFFF   /* granted, whatever the rights (the plain token on a NULL DACL) */
#define AC_OWN (READ_CONTROL | WRITE_DAC)   /* the owner's implicit rights (the user owns the descriptors) */
static WCHAR UserSid[128];

/* AccessCheck of a descriptor (O:user G:user, a Low label, the given DACL) for a token */
static BOOL AcCheck(HANDLE Token, PCWSTR Dacl, ACCESS_MASK Desired, PACCESS_MASK Granted)
{
    WCHAR Sddl[1024];
    PSECURITY_DESCRIPTOR Sd;
    UCHAR PrivBuffer[256];
    DWORD PrivLength = sizeof(PrivBuffer);
    BOOL Status = FALSE, Result;

    StringCbPrintfW(Sddl, sizeof(Sddl), L"O:%sG:%s%sS:(ML;;NW;;;LW)", UserSid, UserSid, Dacl);
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(Sddl, SDDL_REVISION_1, &Sd, NULL))
    {
        ok(0, "%S: SDDL error %lu\n", Sddl, GetLastError());
        *Granted = 0xdeadbeef;
        return FALSE;
    }
    *Granted = 0;
    Result = AccessCheck(Sd, Token, Desired, &AcMapping, (PPRIVILEGE_SET)PrivBuffer, &PrivLength, Granted, &Status);
    ok(Result, "AccessCheck failed: %lu\n", GetLastError());
    LocalFree(Sd);
    if (!Status)
        *Granted = 0;
    return Result && Status;
}

typedef struct _AC_ROW
{
    PCWSTR Dacl;            /* %s is the user's SID */
    ACCESS_MASK Desired;
    ACCESS_MASK Plain;      /* granted to the plain token, 0 = denied */
    ACCESS_MASK Lowbox;     /* granted to the lowbox token, 0 = denied */
} AC_ROW;

static const AC_ROW AcRows[] =
{
    /* no AppContainer ACE: nothing (measured) */
    { L"D:(A;;0x7;;;%s)", MAXIMUM_ALLOWED, 0x7 | AC_OWN, 0 },
    { L"D:(A;;0x7;;;%s)", 0x1, 0x1, 0 },
    /* ALL APPLICATION PACKAGES, the package, capabilities: the intersection with the normal pass */
    { L"D:(A;;0x7;;;%s)(A;;0x1;;;" AC_ALL L")", MAXIMUM_ALLOWED, 0x7 | AC_OWN, 0x1 },
    { L"D:(A;;0x7;;;%s)(A;;0x1;;;" AC_ALL L")", 0x1, 0x1, 0x1 },
    { L"D:(A;;0x7;;;%s)(A;;0x1;;;" AC_ALL L")", 0x2, 0x2, 0 },
    { L"D:(A;;0x3;;;%s)(A;;0x7;;;" AC_PKG L")", MAXIMUM_ALLOWED, 0x3 | AC_OWN, 0x3 },
    { L"D:(A;;0x3;;;%s)(A;;0x7;;;" AC_PKG L")", 0x4, 0, 0 },
    { L"D:(A;;0x7;;;%s)(A;;0x2;;;" AC_CAP L")", MAXIMUM_ALLOWED, 0x7 | AC_OWN, 0x2 },
    { L"D:(A;;0x7;;;%s)(A;;0x2;;;" AC_CAP2 L")", MAXIMUM_ALLOWED, 0x7 | AC_OWN, 0 },
    { L"D:(A;;0x7;;;%s)(A;;0x4;;;" AC_RES L")", MAXIMUM_ALLOWED, 0x7 | AC_OWN, 0x4 },
    /* an AppContainer ACE alone: the normal pass grants nothing */
    { L"D:(A;;0x7;;;" AC_ALL L")", MAXIMUM_ALLOWED, AC_OWN, 0 },
    /* a deny for the packages */
    { L"D:(D;;0x1;;;" AC_ALL L")(A;;0x7;;;%s)(A;;0x7;;;" AC_PKG L")", MAXIMUM_ALLOWED, 0x7 | AC_OWN, 0x6 },
    /* NULL DACL (measured: nothing) */
    { L"D:NO_ACCESS_CONTROL", MAXIMUM_ALLOWED, AC_ANY, 0 },
    /* the owner's implicit rights (measured: not without an AppContainer ACE) */
    { L"D:(A;;0x1;;;%s)", READ_CONTROL, READ_CONTROL, 0 },
    { L"D:(A;;0x1;;;%s)(A;;0x20000;;;" AC_ALL L")", READ_CONTROL, READ_CONTROL, READ_CONTROL },
};

static void TestAccessCheckRows(HANDLE Plain, HANDLE Lowbox)
{
    WCHAR Dacl[512];
    ACCESS_MASK Granted;
    BOOL Ok;
    ULONG i;

    for (i = 0; i < _countof(AcRows); i++)
    {
        StringCbPrintfW(Dacl, sizeof(Dacl), AcRows[i].Dacl, UserSid, UserSid);

        Ok = AcCheck(Plain, Dacl, AcRows[i].Desired, &Granted);
        ok(Ok == (AcRows[i].Plain != 0) && (AcRows[i].Plain == AC_ANY ? Granted != 0 : Granted == AcRows[i].Plain),
           "row %lu plain: %S desired %#lx: %d granted %#lx, expected %#lx\n", i, Dacl, AcRows[i].Desired, Ok, Granted,
           AcRows[i].Plain);

        Ok = AcCheck(Lowbox, Dacl, AcRows[i].Desired, &Granted);
        ok(Ok == (AcRows[i].Lowbox != 0) && Granted == AcRows[i].Lowbox,
           "row %lu lowbox: %S desired %#lx: %d granted %#lx, expected %#lx\n", i, Dacl, AcRows[i].Desired, Ok, Granted,
           AcRows[i].Lowbox);
    }
}

/* A descriptor from SDDL with the user's SID for %s */
static PSECURITY_DESCRIPTOR MakeSd(PCWSTR Format)
{
    WCHAR Sddl[512];
    PSECURITY_DESCRIPTOR Sd = NULL;

    StringCbPrintfW(Sddl, sizeof(Sddl), Format, UserSid, UserSid, UserSid);
    ok(ConvertStringSecurityDescriptorToSecurityDescriptorW(Sddl, SDDL_REVISION_1, &Sd, NULL),
       "%S: error %lu\n", Sddl, GetLastError());
    return Sd;
}

/* Object opens while the thread impersonates the lowbox token: with and without an ALL APPLICATION PACKAGES ACE */
static void TestOpens(HANDLE Lowbox, BOOL DebugEnabled)
{
    static const PCWSTR Formats[2] =
    {
        L"D:(A;;GA;;;%s)(A;;GA;;;SY)S:(ML;;NW;;;LW)",
        L"D:(A;;GA;;;%s)(A;;GA;;;SY)(A;;GR;;;" AC_ALL L")S:(ML;;NW;;;LW)",
    };
    static const PCWSTR KeyFormats[2] =
    {
        L"D:(A;;KA;;;%s)(A;;KA;;;SY)S:(ML;;NW;;;LW)",
        L"D:(A;;KA;;;%s)(A;;KA;;;SY)(A;;KR;;;" AC_ALL L")S:(ML;;NW;;;LW)",
    };
    WCHAR Name[MAX_PATH], Temp[MAX_PATH], KeyPath[256];
    SECURITY_ATTRIBUTES Sa = { sizeof(Sa), NULL, FALSE };
    HANDLE Objects[2][2] = {{NULL}}, h;
    HKEY Keys[2] = {NULL}, hKey, Software = NULL;
    LONG Error;
    int i;

    GetTempPathW(_countof(Temp), Temp);
    for (i = 0; i < 2; i++)
    {
        Sa.lpSecurityDescriptor = MakeSd(Formats[i]);
        StringCbPrintfW(Name, sizeof(Name), L"AcPassEvt%lu_%d", GetCurrentProcessId(), i);
        Objects[i][0] = CreateEventW(&Sa, TRUE, FALSE, Name);
        ok(Objects[i][0] != NULL, "CreateEventW: %lu\n", GetLastError());
        StringCbPrintfW(Name, sizeof(Name), L"%sAcPass%lu_%d.tmp", Temp, GetCurrentProcessId(), i);
        Objects[i][1] = CreateFileW(Name, GENERIC_WRITE, FILE_SHARE_READ, &Sa, CREATE_ALWAYS, FILE_FLAG_DELETE_ON_CLOSE, NULL);
        ok(Objects[i][1] != INVALID_HANDLE_VALUE, "CreateFileW %S: %lu\n", Name, GetLastError());
        LocalFree(Sa.lpSecurityDescriptor);

        /* the key with the masks of a key (the rows are about the AppContainer pass, not generic rights) */
        Sa.lpSecurityDescriptor = MakeSd(KeyFormats[i]);
        StringCbPrintfW(KeyPath, sizeof(KeyPath), L"%s\\Software\\AcPass%lu_%d", UserSid, GetCurrentProcessId(), i);
        Error = RegCreateKeyExW(HKEY_USERS, KeyPath, 0, NULL, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, &Sa, &Keys[i], NULL);
        ok(Error == ERROR_SUCCESS, "RegCreateKeyExW %S: %ld\n", KeyPath, Error);
        LocalFree(Sa.lpSecurityDescriptor);
        if (Error == ERROR_SUCCESS)
        {
            UCHAR Buffer[1024];
            DWORD Size = sizeof(Buffer);
            PWSTR String = NULL;

            if (RegGetKeySecurity(Keys[i], DACL_SECURITY_INFORMATION, Buffer, &Size) == ERROR_SUCCESS &&
                ConvertSecurityDescriptorToStringSecurityDescriptorW(Buffer, SDDL_REVISION_1, DACL_SECURITY_INFORMATION,
                                                                     &String, NULL))
            {
                trace("key %d: %S\n", i, String);
                LocalFree(String);
            }
        }
    }

    StringCbPrintfW(KeyPath, sizeof(KeyPath), L"%s\\Software", UserSid);
    Error = RegOpenKeyExW(HKEY_USERS, KeyPath, 0, KEY_ENUMERATE_SUB_KEYS, &Software);
    ok(Error == ERROR_SUCCESS, "RegOpenKeyExW %S: %ld\n", KeyPath, Error);
    ok(SetThreadToken(NULL, Lowbox), "SetThreadToken: %lu\n", GetLastError());
    for (i = 0; i < 2; i++)
    {
        StringCbPrintfW(Name, sizeof(Name), L"AcPassEvt%lu_%d", GetCurrentProcessId(), i);
        SetLastError(0xdeadbeef);
        h = OpenEventW(EVENT_QUERY_STATE, FALSE, Name);     /* in GENERIC_READ of an event (SYNCHRONIZE is not) */
        ok((h != NULL) == (i == 1), "event %d: %p, error %lu\n", i, h, GetLastError());
        if (h)
            CloseHandle(h);

        StringCbPrintfW(Name, sizeof(Name), L"%sAcPass%lu_%d.tmp", Temp, GetCurrentProcessId(), i);
        SetLastError(0xdeadbeef);
        h = CreateFileW(Name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
        ok((h != INVALID_HANDLE_VALUE) == (i == 1), "file %d: error %lu\n", i, GetLastError());
        if (h != INVALID_HANDLE_VALUE)
            CloseHandle(h);

        /* relative to a key opened before the impersonation: only the key itself is checked */
        StringCbPrintfW(KeyPath, sizeof(KeyPath), L"AcPass%lu_%d", GetCurrentProcessId(), i);
        Error = RegOpenKeyExW(Software, KeyPath, 0, KEY_QUERY_VALUE, &hKey);
        ok((Error == ERROR_SUCCESS) == (i == 1), "key %d: error %ld\n", i, Error);
        if (Error == ERROR_SUCCESS)
            RegCloseKey(hKey);
    }

    /* The process of its user (the ticket's row; a debug privilege the caller holds enabled grants it, as for any token) */
    SetLastError(0xdeadbeef);
    h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
    if (DebugEnabled)
        trace("SeDebugPrivilege is enabled: process open %p\n", h);
    else
        ok(h == NULL && GetLastError() == ERROR_ACCESS_DENIED, "process open: %p, error %lu\n", h, GetLastError());
    if (h)
        CloseHandle(h);
    RevertToSelf();

    /* The plain token still opens all of them */
    h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
    ok(h != NULL, "plain process open: %lu\n", GetLastError());
    if (h)
        CloseHandle(h);

    if (Software)
        RegCloseKey(Software);
    for (i = 0; i < 2; i++)
    {
        if (Objects[i][0])
            CloseHandle(Objects[i][0]);
        if (Objects[i][1] != INVALID_HANDLE_VALUE && Objects[i][1])
            CloseHandle(Objects[i][1]);
        if (Keys[i])
        {
            RegDeleteKeyW(Keys[i], L"");
            RegCloseKey(Keys[i]);
        }
    }
}

START_TEST(AccessCheckAppContainer)
{
    typedef NTSTATUS (NTAPI *PFN_CreateLowBox)(PHANDLE, HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PSID, ULONG,
                                               PSID_AND_ATTRIBUTES, ULONG, HANDLE *);
    PFN_CreateLowBox pNtCreateLowBoxToken =
        (PFN_CreateLowBox)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateLowBoxToken");
    UCHAR Buffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    SID_AND_ATTRIBUTES Capability = { (PSID)&AcCapability, SE_GROUP_ENABLED };
    PRIVILEGE_SET Debug = { 1, PRIVILEGE_SET_ALL_NECESSARY };
    HANDLE Process, Plain, Lowbox = NULL;
    PWSTR SidString;
    DWORD Length;
    BOOL DebugEnabled = FALSE;
    NTSTATUS Status;

    if (!pNtCreateLowBoxToken)
    {
        skip("NtCreateLowBoxToken is not available\n");
        return;
    }
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &Process) ||
        !DuplicateTokenEx(Process, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &Plain))
    {
        skip("no impersonation token: %lu\n", GetLastError());
        return;
    }
    GetTokenInformation(Process, TokenUser, Buffer, sizeof(Buffer), &Length);
    ConvertSidToStringSidW(((PTOKEN_USER)Buffer)->User.Sid, &SidString);
    StringCbCopyW(UserSid, sizeof(UserSid), SidString);
    LocalFree(SidString);

    LookupPrivilegeValueW(NULL, L"SeDebugPrivilege",&Debug.Privilege[0].Luid);
    PrivilegeCheck(Plain, &Debug, &DebugEnabled);

    Status = pNtCreateLowBoxToken(&Lowbox, Plain, TOKEN_ALL_ACCESS, NULL, (PSID)&AcPackage, 1, &Capability, 0, NULL);
    ok(Status == STATUS_SUCCESS, "NtCreateLowBoxToken returned %lx\n", Status);
    if (NT_SUCCESS(Status))
    {
        TestAccessCheckRows(Plain, Lowbox);
        TestOpens(Lowbox, DebugEnabled);
        CloseHandle(Lowbox);
    }
    CloseHandle(Plain);
    CloseHandle(Process);
}
