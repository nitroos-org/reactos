/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Registry key access as the kernel enforces it (registry ACL mode 2), for a standard
 *              user and for restricted tokens: the keys a standard user must not write, what it may
 *              read, HKCU, backup/restore opens, OWNER RIGHTS on a key
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Where an expected value was measured on Windows 10 22H2 (registry ACL design 2.2, the restricted-token
 * measurements of the CryptAcquireContext work) the row says "measured" and asserts that value. Every other
 * row asserts what the key's own descriptor says (AccessCheck of the token against the descriptor the key
 * reports, read as the process itself): it tests that the kernel enforces the stored descriptor, not what
 * Windows' descriptor for that key would be. The descriptor rows of the keys a standard user must not write
 * also assert that the descriptor does not let it write (a finding if it does).
 *
 * The NitroOS kernel enforces key descriptors only in registry ACL mode 2 (boot option /REGACL=ENFORCE or
 * Configuration Manager\RegistryAclMode). In mode 1 (audit) and 0 (legacy) every open the rows make
 * succeeds, and that is what the rows assert there, except the opens of the restricted tokens (restricting
 * SIDs): in mode 1 their opens are decided by the key's descriptor too, as on Windows. On Windows the rows
 * always use the enforced values.
 *
 * The "standard user" is the process itself when it does not run as an administrator; otherwise a thread
 * token made from the process token with Administrators deny-only and no privileges. The restricted tokens
 * are that standard token with restricting SIDs: Chromium's renderer list (Everyone, Users, Authenticated
 * Users, RESTRICTED, the logon SID) and Everyone alone. Nothing is written outside HKCU, except that the
 * administrator rows open keys (nothing is changed through those handles).
 */

#include "precomp.h"
#include <aclapi.h>
#include <sddl.h>
#include <ndk/obfuncs.h>
#include <ndk/cmfuncs.h>

#define KEY_R   0x20019     /* KEY_READ */

/* ------------------------------------------------------------------------ mode */

static BOOL Enforced;   /* the kernel enforces key descriptors (or this is Windows) */
static DWORD AclMode;   /* registry ACL mode of the kernel (this system): 0 legacy, 1 audit, 2 enforce */

static DWORD ReadAclMode(void)
{
    HKEY Key;
    DWORD Mode = MAXDWORD, Size = sizeof(Mode), Type;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\RegAcl\\AuditStats",
                      0, KEY_QUERY_VALUE, &Key) != ERROR_SUCCESS)
        return MAXDWORD;
    if (RegQueryValueExW(Key, L"Mode", NULL, &Type, (LPBYTE)&Mode, &Size) != ERROR_SUCCESS || Type != REG_DWORD)
        Mode = MAXDWORD;
    RegCloseKey(Key);
    return Mode;
}

/* ---------------------------------------------------------------------- tokens */

static BOOL ProcessIsAdmin;
static HANDLE StdToken;         /* impersonation token; the process token's duplicate when not an admin */
static HANDLE ChromeToken;      /* restricted: Everyone, Users, Authenticated Users, RESTRICTED, logon SID */
static HANDLE EveryoneToken;    /* restricted: Everyone only */

static PSID AllocWellKnown(WELL_KNOWN_SID_TYPE Type)
{
    DWORD Size = SECURITY_MAX_SID_SIZE;
    PSID Sid = LocalAlloc(LPTR, Size);

    if (Sid && !CreateWellKnownSid(Type, NULL, Sid, &Size))
    {
        LocalFree(Sid);
        Sid = NULL;
    }
    return Sid;
}

static BOOL IsAdminNow(void)
{
    PSID Admins = AllocWellKnown(WinBuiltinAdministratorsSid);
    BOOL Member = FALSE;

    if (Admins && !CheckTokenMembership(NULL, Admins, &Member))
        Member = FALSE;
    LocalFree(Admins);
    return Member;
}

/* The logon SID of a token (caller LocalFree()s), or NULL */
static PSID LogonSidOf(HANDLE Token)
{
    DWORD Length = 0, i;
    PTOKEN_GROUPS Groups;
    PSID Copy = NULL;

    GetTokenInformation(Token, TokenGroups, NULL, 0, &Length);
    Groups = LocalAlloc(LPTR, Length);
    if (Groups && GetTokenInformation(Token, TokenGroups, Groups, Length, &Length))
    {
        for (i = 0; i < Groups->GroupCount; i++)
        {
            if (Groups->Groups[i].Attributes & SE_GROUP_LOGON_ID)
            {
                Length = GetLengthSid(Groups->Groups[i].Sid);
                Copy = LocalAlloc(LPTR, Length);
                if (Copy)
                    CopySid(Length, Copy, Groups->Groups[i].Sid);
                break;
            }
        }
    }
    LocalFree(Groups);
    return Copy;
}

static HANDLE MakeImpersonation(HANDLE Primary, ULONG RestrictCount, PSID_AND_ATTRIBUTES Restrict)
{
    SID_AND_ATTRIBUTES Deny;
    HANDLE Filtered = NULL, Imp = NULL;
    PSID Admins = AllocWellKnown(WinBuiltinAdministratorsSid);

    Deny.Sid = Admins;
    Deny.Attributes = 0;
    if (!CreateRestrictedToken(Primary, DISABLE_MAX_PRIVILEGE, ProcessIsAdmin ? 1 : 0, ProcessIsAdmin ? &Deny : NULL,
                               0, NULL, RestrictCount, Restrict, &Filtered))
    {
        trace("CreateRestrictedToken failed: %lu\n", GetLastError());
        LocalFree(Admins);
        return NULL;
    }
    if (!DuplicateTokenEx(Filtered, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &Imp))
    {
        trace("DuplicateTokenEx failed: %lu\n", GetLastError());
        Imp = NULL;
    }
    CloseHandle(Filtered);
    LocalFree(Admins);
    return Imp;
}

static BOOL InitTokens(void)
{
    HANDLE Process;
    SID_AND_ATTRIBUTES Chrome[5], Everyone[1];
    PSID Sids[5];
    ULONG Count = 0, i;

    ProcessIsAdmin = IsAdminNow();
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &Process))
    {
        skip("OpenProcessToken failed: %lu\n", GetLastError());
        return FALSE;
    }

    StdToken = MakeImpersonation(Process, 0, NULL);

    Sids[0] = AllocWellKnown(WinWorldSid);
    Sids[1] = AllocWellKnown(WinBuiltinUsersSid);
    Sids[2] = AllocWellKnown(WinAuthenticatedUserSid);
    Sids[3] = AllocWellKnown(WinRestrictedCodeSid);
    Sids[4] = LogonSidOf(Process);
    for (i = 0; i < 5; i++)
    {
        if (Sids[i])
        {
            Chrome[Count].Sid = Sids[i];
            Chrome[Count].Attributes = 0;
            Count++;
        }
    }
    ChromeToken = MakeImpersonation(Process, Count, Chrome);
    Everyone[0].Sid = Sids[0];
    Everyone[0].Attributes = 0;
    EveryoneToken = MakeImpersonation(Process, 1, Everyone);
    for (i = 0; i < 5; i++)
        LocalFree(Sids[i]);
    CloseHandle(Process);

    ok(StdToken != NULL, "no standard-user token\n");
    return StdToken != NULL;
}

static void ExitTokens(void)
{
    if (StdToken) CloseHandle(StdToken);
    if (ChromeToken) CloseHandle(ChromeToken);
    if (EveryoneToken) CloseHandle(EveryoneToken);
    StdToken = ChromeToken = EveryoneToken = NULL;
}

/* -------------------------------------------------------------------- helpers */

static ACCESS_MASK GrantedAccessOf(HKEY Key)
{
    OBJECT_BASIC_INFORMATION Info;

    if (!NT_SUCCESS(NtQueryObject(Key, ObjectBasicInformation, &Info, sizeof(Info), NULL)))
        return 0xdeadbeef;
    return Info.GrantedAccess;
}

/* Open as the token (impersonated on this thread). Returns the Win32 error; *Granted gets the handle's access */
static LONG OpenAs(HANDLE Token, HKEY Root, PCWSTR Path, REGSAM Sam, ACCESS_MASK *Granted)
{
    HKEY Key;
    LONG Error;

    if (Granted)
        *Granted = 0;
    if (!SetThreadToken(NULL, Token))
        return ERROR_GEN_FAILURE;
    Error = RegOpenKeyExW(Root, Path, 0, Sam, &Key);
    SetThreadToken(NULL, NULL);
    if (Error == ERROR_SUCCESS)
    {
        if (Granted)
            *Granted = GrantedAccessOf(Key);
        RegCloseKey(Key);
    }
    return Error;
}

/* Does the key's own descriptor (read as the process) give Token the access? -1: the descriptor cannot be read */
static int DescriptorGrants(HANDLE Token, HKEY Root, PCWSTR Path, REGSAM Wow, ACCESS_MASK Desired)
{
    GENERIC_MAPPING Mapping = { KEY_READ, KEY_WRITE, KEY_EXECUTE | KEY_CREATE_LINK, KEY_ALL_ACCESS };
    PRIVILEGE_SET Privileges;
    DWORD PrivilegesLength = sizeof(Privileges), Length = 0;
    DWORD Granted = 0;
    BOOL Status = FALSE;
    PSECURITY_DESCRIPTOR Sd;
    HKEY Key;
    int Result = -1;

    if (RegOpenKeyExW(Root, Path, 0, READ_CONTROL | Wow, &Key) != ERROR_SUCCESS)
        return -1;
    RegGetKeySecurity(Key, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                      NULL, &Length);
    Sd = LocalAlloc(LPTR, Length ? Length : 1);
    if (Sd && RegGetKeySecurity(Key, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                                DACL_SECURITY_INFORMATION, Sd, &Length) == ERROR_SUCCESS)
    {
        MapGenericMask(&Desired, &Mapping);
        if (AccessCheck(Sd, Token, Desired, &Mapping, &Privileges, &PrivilegesLength, &Granted, &Status))
            Result = Status ? 1 : 0;
        else
            trace("AccessCheck failed: %lu\n", GetLastError());
    }
    LocalFree(Sd);
    RegCloseKey(Key);
    return Result;
}

/* A measured row: the open as Token gives Expected when enforced, success otherwise */
static void Measured(HANDLE Token, const char *Who, HKEY Root, PCWSTR Path, REGSAM Sam, LONG Expected)
{
    LONG Error = OpenAs(Token, Root, Path, Sam, NULL);

    if (Error == ERROR_FILE_NOT_FOUND)
    {
        skip("%s: %ls does not exist\n", Who, Path);
        return;
    }
    ok(Error == (Enforced ? Expected : ERROR_SUCCESS), "%s %ls 0x%lx: error %ld, expected %ld (measured)\n",
       Who, Path, (ULONG)Sam, Error, Enforced ? Expected : ERROR_SUCCESS);
}

/* A measured MAXIMUM_ALLOWED row: the granted access when enforced */
static void MeasuredMax(HANDLE Token, const char *Who, HKEY Root, PCWSTR Path, ACCESS_MASK Expected)
{
    ACCESS_MASK Granted;
    LONG Error = OpenAs(Token, Root, Path, MAXIMUM_ALLOWED, &Granted);

    if (Error == ERROR_FILE_NOT_FOUND)
    {
        skip("%s: %ls does not exist\n", Who, Path);
        return;
    }
    if (!Enforced)
    {
        ok(Error == ERROR_SUCCESS, "%s %ls MAXIMUM_ALLOWED: error %ld\n", Who, Path, Error);
        return;
    }
    if (Expected == 0)
    {
        ok(Error == ERROR_ACCESS_DENIED, "%s %ls MAXIMUM_ALLOWED: error %ld granted 0x%lx, expected 5 (measured)\n",
           Who, Path, Error, (ULONG)Granted);
        return;
    }
    ok(Error == ERROR_SUCCESS && Granted == Expected, "%s %ls MAXIMUM_ALLOWED: error %ld granted 0x%lx, expected 0x%lx (measured)\n",
       Who, Path, Error, (ULONG)Granted, (ULONG)Expected);
}

/*
 * A descriptor row: when enforced, the open as Token succeeds exactly when the key's descriptor grants it.
 * MustDeny: the descriptor must not grant it either (a write a standard user must not have).
 */
static void ByDescriptor(HANDLE Token, const char *Who, HKEY Root, PCWSTR Path, REGSAM Sam, BOOL MustDeny)
{
    REGSAM Wow = Sam & (KEY_WOW64_32KEY | KEY_WOW64_64KEY);
    int Grants = DescriptorGrants(Token, Root, Path, Wow, Sam & ~Wow);
    LONG Error;

    if (Grants < 0)
    {
        skip("%s: the descriptor of %ls cannot be read\n", Who, Path);
        return;
    }
    if (MustDeny)
        ok(Grants == 0, "%s: the descriptor of %ls grants 0x%lx (it must not)\n", Who, Path, (ULONG)Sam);
    Error = OpenAs(Token, Root, Path, Sam, NULL);
    if (!Enforced)
        ok(Error == ERROR_SUCCESS, "%s %ls 0x%lx: error %ld (not enforced)\n", Who, Path, (ULONG)Sam, Error);
    else
        ok(Error == (Grants ? ERROR_SUCCESS : ERROR_ACCESS_DENIED), "%s %ls 0x%lx: error %ld, the descriptor %s it\n",
           Who, Path, (ULONG)Sam, Error, Grants ? "grants" : "denies");
}

/* ------------------------------------------------------------- standard user */

static const WCHAR Services[] = L"SYSTEM\\CurrentControlSet\\Services";
static const WCHAR RunKey[] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
static const WCHAR TaskCache[] = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache";
static const WCHAR Winlogon[] = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
static const WCHAR Firewall[] = L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy";
static const WCHAR FirewallRules[] = L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules";
static const WCHAR ConfigManager[] = L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Configuration Manager";

static void TestStandardUser(void)
{
    WCHAR Name[256], Path[400];
    DWORD Index, Chars, Writable = 0, Checked = 0;
    HKEY Key;

    /* measured on Windows 10 22H2 (design 2.2): reads granted, writes denied */
    Measured(StdToken, "standard", HKEY_LOCAL_MACHINE, L"SOFTWARE", KEY_READ, ERROR_SUCCESS);
    Measured(StdToken, "standard", HKEY_LOCAL_MACHINE, L"SOFTWARE", KEY_SET_VALUE, ERROR_ACCESS_DENIED);
    Measured(StdToken, "standard", HKEY_LOCAL_MACHINE, RunKey, KEY_READ, ERROR_SUCCESS);
    Measured(StdToken, "standard", HKEY_LOCAL_MACHINE, RunKey, KEY_SET_VALUE, ERROR_ACCESS_DENIED);
    Measured(StdToken, "standard", HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Schedule", KEY_READ, ERROR_SUCCESS);
    Measured(StdToken, "standard", HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Schedule", KEY_SET_VALUE, ERROR_ACCESS_DENIED);
    MeasuredMax(StdToken, "standard", HKEY_LOCAL_MACHINE, L"SOFTWARE", KEY_R);
    MeasuredMax(StdToken, "standard", HKEY_LOCAL_MACHINE, L"SYSTEM", KEY_R);
    MeasuredMax(StdToken, "standard", HKEY_LOCAL_MACHINE, Services, KEY_R);
    MeasuredMax(StdToken, "standard", HKEY_LOCAL_MACHINE, RunKey, KEY_R);
    MeasuredMax(StdToken, "standard", HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies", KEY_R);
    MeasuredMax(StdToken, "standard", HKEY_LOCAL_MACHINE, L"HARDWARE", KEY_R);
    MeasuredMax(StdToken, "standard", HKEY_LOCAL_MACHINE, L"SAM", KEY_R);
    MeasuredMax(StdToken, "standard", HKEY_LOCAL_MACHINE, L"SAM\\SAM", 0);
    MeasuredMax(StdToken, "standard", HKEY_LOCAL_MACHINE, L"SECURITY", 0);
    MeasuredMax(StdToken, "standard", HKEY_LOCAL_MACHINE, TaskCache, 0);
    MeasuredMax(StdToken, "standard", HKEY_USERS, L".DEFAULT", KEY_R);

    /* the rest of the list: what the stored descriptor says, and that it keeps a standard user out */
    ByDescriptor(StdToken, "standard", HKEY_LOCAL_MACHINE, Services, KEY_CREATE_SUB_KEY, TRUE);
    ByDescriptor(StdToken, "standard", HKEY_LOCAL_MACHINE, Firewall, KEY_SET_VALUE, TRUE);
    ByDescriptor(StdToken, "standard", HKEY_LOCAL_MACHINE, Firewall, KEY_CREATE_SUB_KEY, TRUE);
    ByDescriptor(StdToken, "standard", HKEY_LOCAL_MACHINE, FirewallRules, KEY_SET_VALUE, TRUE);
    ByDescriptor(StdToken, "standard", HKEY_LOCAL_MACHINE, Winlogon, KEY_SET_VALUE, TRUE);
    ByDescriptor(StdToken, "standard", HKEY_LOCAL_MACHINE, RunKey, KEY_SET_VALUE | KEY_WOW64_32KEY, TRUE);
    ByDescriptor(StdToken, "standard", HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", KEY_SET_VALUE, TRUE);
    ByDescriptor(StdToken, "standard", HKEY_LOCAL_MACHINE, ConfigManager, KEY_SET_VALUE, TRUE);
    ByDescriptor(StdToken, "standard", HKEY_LOCAL_MACHINE, L"SAM", KEY_SET_VALUE, TRUE);
    ByDescriptor(StdToken, "standard", HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies", KEY_CREATE_SUB_KEY, TRUE);
    ByDescriptor(StdToken, "standard", HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", KEY_READ, FALSE);

    /* every service key: its ImagePath must not be writable by a standard user */
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, Services, 0, KEY_ENUMERATE_SUB_KEYS, &Key) == ERROR_SUCCESS)
    {
        for (Index = 0; ; Index++)
        {
            ACCESS_MASK Unused;
            LONG Error;
            int Grants;

            Chars = RTL_NUMBER_OF(Name);
            if (RegEnumKeyExW(Key, Index, Name, &Chars, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
                break;
            StringCchPrintfW(Path, RTL_NUMBER_OF(Path), L"%ls\\%ls", Services, Name);
            Grants = DescriptorGrants(StdToken, HKEY_LOCAL_MACHINE, Path, 0, KEY_SET_VALUE);
            if (Grants < 0)
                continue;
            Checked++;
            if (Grants)
            {
                Writable++;
                ok(0, "the descriptor of %ls lets a standard user set values (ImagePath)\n", Path);
            }
            Error = OpenAs(StdToken, HKEY_LOCAL_MACHINE, Path, KEY_SET_VALUE, &Unused);
            ok(Error == ((!Enforced || Grants) ? ERROR_SUCCESS : ERROR_ACCESS_DENIED),
               "standard %ls KEY_SET_VALUE: error %ld\n", Path, Error);
        }
        RegCloseKey(Key);
    }
    trace("service keys checked %lu, writable by a standard user %lu\n", Checked, Writable);
    ok(Checked > 10, "only %lu service keys checked\n", Checked);
}

/* HKCU: everything a user does with its own keys works in every mode */
static void TestCurrentUser(void)
{
    static const WCHAR Scratch[] = L"Software\\ReactOS-apitest-RegSecurityEnforce";
    HKEY Key = NULL, Child = NULL;
    HANDLE Event;
    WCHAR Name[64];
    DWORD Disp, Value = 1, Chars;
    LONG Error;

    if (!SetThreadToken(NULL, StdToken))
    {
        ok(0, "SetThreadToken failed: %lu\n", GetLastError());
        return;
    }
    RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\ReactOS-apitest-RegSecurityEnforce\\renamed");
    RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\ReactOS-apitest-RegSecurityEnforce\\child");
    RegDeleteKeyW(HKEY_CURRENT_USER, Scratch);

    Error = RegCreateKeyExW(HKEY_CURRENT_USER, Scratch, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Key, &Disp);
    ok(Error == ERROR_SUCCESS, "standard HKCU create: %ld\n", Error);
    if (Error)
        goto Done;
    ok(GrantedAccessOf(Key) == KEY_ALL_ACCESS, "HKCU scratch key granted 0x%lx\n", (ULONG)GrantedAccessOf(Key));
    Error = RegSetValueExW(Key, L"v", 0, REG_DWORD, (BYTE *)&Value, sizeof(Value));
    ok(Error == ERROR_SUCCESS, "standard HKCU set value: %ld\n", Error);
    Error = RegCreateKeyExW(Key, L"child", 0, NULL, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, NULL, &Child, &Disp);
    ok(Error == ERROR_SUCCESS, "standard HKCU create child: %ld\n", Error);
    Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    Error = RegNotifyChangeKeyValue(Key, TRUE, REG_NOTIFY_CHANGE_LAST_SET, Event, TRUE);
    ok(Error == ERROR_SUCCESS, "standard HKCU notify: %ld\n", Error);
    if (Child)
    {
        Error = RegSetValueExW(Child, L"w", 0, REG_DWORD, (BYTE *)&Value, sizeof(Value));
        ok(Error == ERROR_SUCCESS, "standard HKCU child set value: %ld\n", Error);
    }
    ok(WaitForSingleObject(Event, 5000) == WAIT_OBJECT_0, "no change notification\n");
    CloseHandle(Event);
    Chars = RTL_NUMBER_OF(Name);
    Error = RegEnumKeyExW(Key, 0, Name, &Chars, NULL, NULL, NULL, NULL);
    ok(Error == ERROR_SUCCESS, "standard HKCU enumerate: %ld\n", Error);
    Chars = sizeof(Value);
    Error = RegQueryValueExW(Key, L"v", NULL, NULL, (BYTE *)&Value, &Chars);
    ok(Error == ERROR_SUCCESS, "standard HKCU query value: %ld\n", Error);
    if (Child)
    {
        LSTATUS (WINAPI *pRegRenameKey)(HKEY, LPCWSTR, LPCWSTR);

        pRegRenameKey = (PVOID)GetProcAddress(GetModuleHandleW(L"advapi32.dll"), "RegRenameKey");
        if (pRegRenameKey)
        {
            Error = pRegRenameKey(Child, NULL, L"renamed");
            ok(Error == ERROR_SUCCESS, "standard HKCU rename: %ld\n", Error);
        }
        Error = RegDeleteValueW(Child, L"w");
        ok(Error == ERROR_SUCCESS, "standard HKCU delete value: %ld\n", Error);
        Error = RegDeleteKeyW(Child, L"");
        ok(Error == ERROR_SUCCESS, "standard HKCU delete child: %ld\n", Error);
        RegCloseKey(Child);
    }
    RegCloseKey(Key);
    Error = RegDeleteKeyW(HKEY_CURRENT_USER, Scratch);
    ok(Error == ERROR_SUCCESS, "standard HKCU delete: %ld\n", Error);

Done:
    SetThreadToken(NULL, NULL);
}

/* ---------------------------------------------------------- restricted tokens */

/*
 * The rows of the restricted tokens. Chromium's renderer list: what each key's descriptor gives both
 * passes. Everyone as the only restricting SID: Windows denies the registry reads of CryptAcquireContext
 * (measured on Windows 10 22H2 and Server 2022: a provider key below the one here, ERROR_ACCESS_DENIED)
 * and the opens of HKCU; these keys grant Users (HKLM) or the user (HKCU), not Everyone, so their
 * descriptors must deny the read (MustDeny).
 */
static const struct
{
    BOOL EveryoneOnly;
    HKEY Root;
    PCWSTR Path;
    REGSAM Sam;
    BOOL MustDeny;
} RRows[] =
{
    { FALSE, HKEY_LOCAL_MACHINE, L"SOFTWARE", KEY_READ, FALSE },
    { FALSE, HKEY_LOCAL_MACHINE, L"SYSTEM", KEY_READ, FALSE },
    { FALSE, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", KEY_READ, FALSE },
    { FALSE, HKEY_CURRENT_USER, L"Software", KEY_READ, FALSE },
    { FALSE, HKEY_CURRENT_USER, L"Software", KEY_SET_VALUE, TRUE },
    { FALSE, HKEY_LOCAL_MACHINE, L"SOFTWARE", KEY_SET_VALUE, TRUE },
    { TRUE, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider", KEY_READ, TRUE },
    { TRUE, HKEY_CURRENT_USER, L"Software", KEY_READ, TRUE },
    { TRUE, HKEY_LOCAL_MACHINE, L"SOFTWARE", KEY_READ, FALSE },
};

/*
 * The child's side (started with the restricted primary token): open each row's key with its own
 * token. Expect: one character per row from the parent, '1' the descriptor grants it, '0' it denies
 * it, '-' not known (skipped).
 */
static void RestrictedChild(const WCHAR *Kind, const WCHAR *Expect)
{
    BOOL EveryoneOnly = !wcscmp(Kind, L"everyone");
    WCHAR User[200], Path[300];
    LONG Error, Wanted;
    ULONG i;

    /*
     * The parent's HKCU is HKU\<its user SID>: the child opens that key by name. Its own
     * HKEY_CURRENT_USER is not used: when the restricted token cannot open the user's
     * hive root, advapi32 maps HKCU to HKU\.DEFAULT, a different key
     */
    if (!GetEnvironmentVariableW(L"REGACL_ENFORCE_USER", User, RTL_NUMBER_OF(User)))
        User[0] = UNICODE_NULL;
    for (i = 0; i < RTL_NUMBER_OF(RRows) && Expect[i]; i++)
    {
        HKEY Key;

        if (RRows[i].EveryoneOnly != EveryoneOnly || Expect[i] == L'-')
            continue;
        /* the token in force: the child's own, or the thread's impersonation token */
        if (RRows[i].Root == HKEY_CURRENT_USER)
        {
            if (!User[0])
            {
                skip("%ls child: no user SID for %ls\n", Kind, RRows[i].Path);
                continue;
            }
            StringCchPrintfW(Path, RTL_NUMBER_OF(Path), L"%ls\\%ls", User, RRows[i].Path);
            Error = RegOpenKeyExW(HKEY_USERS, Path, 0, RRows[i].Sam, &Key);
        }
        else
        {
            Error = RegOpenKeyExW(RRows[i].Root, RRows[i].Path, 0, RRows[i].Sam, &Key);
        }
        if (Error == ERROR_BAD_IMPERSONATION_LEVEL && is_reactos())
        {
            /*
             * A standard user's thread gets the restricted copy of its own token only at
             * identification level here (Windows not measured for a standard user): a token
             * question, not a registry one; the row cannot run
             */
            skip("%ls: the restricted token is not usable for impersonation by this caller\n", Kind);
            continue;
        }
        if (Error == ERROR_SUCCESS)
            RegCloseKey(Key);
        /* a restricted token is decided by the descriptor in audit mode too, not in legacy mode */
        Wanted = (((!Enforced && AclMode != 1) || Expect[i] == L'1')) ? ERROR_SUCCESS : ERROR_ACCESS_DENIED;
        ok(Error == Wanted, "%ls child: %ls 0x%lx: error %ld, expected %ld (the descriptor %s it)\n", Kind,
           RRows[i].Path, (ULONG)RRows[i].Sam, Error, Wanted, Expect[i] == L'1' ? "grants" : "denies");
    }
}

/*
 * The parent's side: work out what each row's descriptor gives the restricted token (AccessCheck with
 * the impersonation token; the rows a descriptor must deny are checked here), then start this test
 * again in a child process whose primary token is the restricted token (as Chromium starts its
 * renderers) to make the opens, and take its failures as one row. Without a child (CreateProcessAsUser
 * refused), the rows run on this thread with the impersonation token instead.
 */
static void RunRestrictedChild(HANDLE Impersonation, const WCHAR *Kind)
{
    STARTUPINFOW Si = { sizeof(Si) };
    PROCESS_INFORMATION Pi;
    WCHAR Exe[MAX_PATH], Cmd[MAX_PATH + 64], Expect[RTL_NUMBER_OF(RRows) + 1];
    BOOL EveryoneOnly = !wcscmp(Kind, L"everyone");
    HANDLE Primary = NULL;
    DWORD Exit = 0xdeadbeef;
    BOOL Started;
    ULONG i;
    int Grants;

    if (!Impersonation)
    {
        skip("no %ls token\n", Kind);
        return;
    }
    for (i = 0; i < RTL_NUMBER_OF(RRows); i++)
    {
        Expect[i] = L'-';
        if (RRows[i].EveryoneOnly != EveryoneOnly)
            continue;
        Grants = DescriptorGrants(Impersonation, RRows[i].Root, RRows[i].Path, 0, RRows[i].Sam);
        if (Grants < 0)
        {
            skip("%ls: the descriptor of %ls cannot be read\n", Kind, RRows[i].Path);
            continue;
        }
        if (RRows[i].MustDeny)
            ok(Grants == 0, "%ls: the descriptor of %ls grants 0x%lx (it must not)\n", Kind, RRows[i].Path,
               (ULONG)RRows[i].Sam);
        Expect[i] = Grants ? L'1' : L'0';
    }
    Expect[RTL_NUMBER_OF(RRows)] = UNICODE_NULL;

    GetModuleFileNameW(NULL, Exe, RTL_NUMBER_OF(Exe));
    StringCchPrintfW(Cmd, RTL_NUMBER_OF(Cmd), L"\"%ls\" RegSecurityEnforce", Exe);
    if (!DuplicateTokenEx(Impersonation, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &Primary))
        Primary = NULL;
    SetEnvironmentVariableW(L"REGACL_ENFORCE_EXPECT", Expect);
    SetEnvironmentVariableW(L"REGACL_ENFORCE_CHILD", Kind);
    {
        HANDLE Token;
        BYTE Buffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
        DWORD Length;
        PWSTR Text;

        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token))
        {
            if (GetTokenInformation(Token, TokenUser, Buffer, sizeof(Buffer), &Length) &&
                ConvertSidToStringSidW(((PTOKEN_USER)Buffer)->User.Sid, &Text))
            {
                SetEnvironmentVariableW(L"REGACL_ENFORCE_USER", Text);
                LocalFree(Text);
            }
            CloseHandle(Token);
        }
    }
    Si.dwFlags = STARTF_USESTDHANDLES;
    Si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    Si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    Si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    fflush(stdout);
    /*
     * Everyone alone cannot even start a process (the system DLLs grant Users, not Everyone; Windows
     * refuses that token CreateFile of a system DLL too, measured): those rows run on a thread, as the
     * Windows measurement did
     */
    Started = Primary && !EveryoneOnly &&
              CreateProcessAsUserW(Primary, Exe, Cmd, NULL, NULL, TRUE, 0, NULL, NULL, &Si, &Pi);
    SetEnvironmentVariableW(L"REGACL_ENFORCE_CHILD", NULL);
    SetEnvironmentVariableW(L"REGACL_ENFORCE_EXPECT", NULL);
    if (Primary)
        CloseHandle(Primary);
    if (!Started)
    {
        trace("%ls child not started (%lu): the rows run impersonated\n", Kind, GetLastError());
        if (SetThreadToken(NULL, Impersonation))
        {
            RestrictedChild(Kind, Expect);
            SetThreadToken(NULL, NULL);
        }
        return;
    }
    ok(WaitForSingleObject(Pi.hProcess, 120000) == WAIT_OBJECT_0, "%ls child did not finish\n", Kind);
    GetExitCodeProcess(Pi.hProcess, &Exit);
    ok(Exit == 0, "%ls child: %lu failures (above)\n", Kind, Exit);
    CloseHandle(Pi.hProcess);
    CloseHandle(Pi.hThread);
}

static void TestRestricted(void)
{
    RunRestrictedChild(ChromeToken, L"chrome");
    RunRestrictedChild(EveryoneToken, L"everyone");
}

/* -------------------------------------------------------- backup and restore */

static HANDLE AdminWithPrivileges(BOOL Backup, BOOL Restore)
{
    HANDLE Process, Imp = NULL;
    struct { DWORD Count; LUID_AND_ATTRIBUTES Privileges[2]; } Set;
    LUID BackupLuid, RestoreLuid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &Process))
        return NULL;
    if (!DuplicateTokenEx(Process, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &Imp))
        Imp = NULL;
    CloseHandle(Process);
    if (!Imp)
        return NULL;
    LookupPrivilegeValueW(NULL, L"SeBackupPrivilege", &BackupLuid);
    LookupPrivilegeValueW(NULL, L"SeRestorePrivilege", &RestoreLuid);
    Set.Count = 2;
    Set.Privileges[0].Luid = BackupLuid;
    Set.Privileges[0].Attributes = Backup ? SE_PRIVILEGE_ENABLED : 0;
    Set.Privileges[1].Luid = RestoreLuid;
    Set.Privileges[1].Attributes = Restore ? SE_PRIVILEGE_ENABLED : 0;
    if (!AdjustTokenPrivileges(Imp, FALSE, (PTOKEN_PRIVILEGES)&Set, 0, NULL, NULL))
    {
        CloseHandle(Imp);
        return NULL;
    }
    return Imp;
}

static NTSTATUS NtOpenAs(HANDLE Token, PCWSTR Path, ACCESS_MASK Desired, ULONG Options, ACCESS_MASK *Granted)
{
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES Attributes;
    HANDLE Key;
    NTSTATUS Status;

    *Granted = 0;
    RtlInitUnicodeString(&Name, Path);
    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    if (!SetThreadToken(NULL, Token))
        return STATUS_UNSUCCESSFUL;
    Status = NtOpenKeyEx(&Key, Desired, &Attributes, Options);
    SetThreadToken(NULL, NULL);
    if (NT_SUCCESS(Status))
    {
        *Granted = GrantedAccessOf((HKEY)Key);
        NtClose(Key);
    }
    return Status;
}

static void TestBackupRestore(void)
{
    static const WCHAR SamSam[] = L"\\Registry\\Machine\\SAM\\SAM";
    static const struct
    {
        BOOL Backup, Restore, Option;
        ACCESS_MASK Desired;
        NTSTATUS Status;
        ACCESS_MASK Granted;
    } Rows[] =
    {
        /* measured on Windows 10 22H2 on HKLM\SAM\SAM, whose DACL gives administrators RC|WD only (design 2.2) */
        { FALSE, FALSE, FALSE, KEY_READ,      STATUS_ACCESS_DENIED, 0 },
        { FALSE, FALSE, TRUE,  KEY_READ,      STATUS_ACCESS_DENIED, 0 },
        { TRUE,  FALSE, FALSE, KEY_READ,      STATUS_ACCESS_DENIED, 0 },
        { TRUE,  FALSE, TRUE,  KEY_READ,      STATUS_SUCCESS, 0x01020019 },
        { TRUE,  FALSE, TRUE,  KEY_SET_VALUE, STATUS_SUCCESS, 0x01020019 },
        { TRUE,  TRUE,  TRUE,  KEY_READ,      STATUS_SUCCESS, 0x010F001F },
        { FALSE, TRUE,  TRUE,  KEY_READ,      STATUS_SUCCESS, 0x010F0006 },
    };
    ACCESS_MASK Granted;
    NTSTATUS Status;
    HANDLE Token;
    ULONG i;

    if (!ProcessIsAdmin)
    {
        skip("not an administrator: no backup/restore rows\n");
        return;
    }
    if (!Enforced)
    {
        skip("key access is not enforced: the backup/restore rows need it\n");
        return;
    }
    for (i = 0; i < RTL_NUMBER_OF(Rows); i++)
    {
        Token = AdminWithPrivileges(Rows[i].Backup, Rows[i].Restore);
        if (!Token)
        {
            skip("row %lu: no token\n", i);
            continue;
        }
        Status = NtOpenAs(Token, SamSam, Rows[i].Desired, Rows[i].Option ? REG_OPTION_BACKUP_RESTORE : 0, &Granted);
        ok(Status == Rows[i].Status && Granted == Rows[i].Granted,
           "row %lu (backup %d restore %d option %d desired 0x%lx): status 0x%lx granted 0x%lx, expected 0x%lx 0x%lx (measured)\n",
           i, Rows[i].Backup, Rows[i].Restore, Rows[i].Option, (ULONG)Rows[i].Desired,
           Status, (ULONG)Granted, Rows[i].Status, (ULONG)Rows[i].Granted);
        CloseHandle(Token);
    }
}

/* --------------------------------------------------------------- owner rights */

/*
 * OWNER RIGHTS (S-1-3-4) in a key's DACL: an ACE for it is an ACE for the owner, and replaces the owner's
 * implicit READ_CONTROL | WRITE_DAC. (A;;KA;;;OW) gives the owner full control (the case the R4 audit
 * counted as a denial); (A;;KR;;;OW) leaves it without WRITE_DAC. Documented behaviour; the key rows
 * themselves were not measured on Windows.
 */
static void TestOwnerRights(void)
{
    static const WCHAR Parent[] = L"Software\\ReactOS-apitest-RegOwnerRights";
    static const WCHAR ChildPath[] = L"Software\\ReactOS-apitest-RegOwnerRights\\k";
    PSECURITY_DESCRIPTOR Sd;
    HKEY Key, Child;
    LONG Error;
    DWORD Disp;

    /* a volatile key: if a row leaves it shut, it goes at the next boot */
    RegDeleteKeyW(HKEY_CURRENT_USER, ChildPath);
    RegDeleteKeyW(HKEY_CURRENT_USER, Parent);
    Error = RegCreateKeyExW(HKEY_CURRENT_USER, Parent, 0, NULL, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, NULL, &Key, &Disp);
    ok(Error == ERROR_SUCCESS, "create %ls: %ld\n", Parent, Error);
    if (Error)
        return;

    /* the owner is the creator's token owner; OW: full control */
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;KA;;;OW)", SDDL_REVISION_1, &Sd, NULL))
    {
        SECURITY_ATTRIBUTES Sa = { sizeof(Sa), Sd, FALSE };

        Error = RegCreateKeyExW(Key, L"k", 0, NULL, REG_OPTION_VOLATILE, KEY_READ, &Sa, &Child, &Disp);
        ok(Error == ERROR_SUCCESS, "create k: %ld\n", Error);
        if (!Error)
            RegCloseKey(Child);
        LocalFree(Sd);
        Error = RegOpenKeyExW(HKEY_CURRENT_USER, ChildPath, 0, KEY_ALL_ACCESS, &Child);
        ok(Error == ERROR_SUCCESS, "owner with (A;;KA;;;OW): KEY_ALL_ACCESS open error %ld\n", Error);
        if (!Error)
        {
            /* OW: read only, no WRITE_DAC for the owner any more */
            if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;KR;;;OW)(A;;SD;;;WD)", SDDL_REVISION_1, &Sd, NULL))
            {
                Error = RegSetKeySecurity(Child, DACL_SECURITY_INFORMATION, Sd);
                ok(Error == ERROR_SUCCESS, "set (A;;KR;;;OW): %ld\n", Error);
                LocalFree(Sd);
            }
            RegCloseKey(Child);
            Error = RegOpenKeyExW(HKEY_CURRENT_USER, ChildPath, 0, KEY_READ, &Child);
            ok(Error == ERROR_SUCCESS, "owner with (A;;KR;;;OW): KEY_READ open error %ld\n", Error);
            if (!Error)
                RegCloseKey(Child);
            Error = RegOpenKeyExW(HKEY_CURRENT_USER, ChildPath, 0, WRITE_DAC, &Child);
            ok(Error == (Enforced ? ERROR_ACCESS_DENIED : ERROR_SUCCESS),
               "owner with (A;;KR;;;OW): WRITE_DAC open error %ld\n", Error);
            if (!Error)
                RegCloseKey(Child);
        }
        /* (A;;SD;;;WD) leaves DELETE to everyone, for the cleanup */
        Error = RegDeleteKeyW(HKEY_CURRENT_USER, ChildPath);
        ok(Error == ERROR_SUCCESS, "delete k: %ld\n", Error);
    }
    RegCloseKey(Key);
    RegDeleteKeyW(HKEY_CURRENT_USER, Parent);
}

/* ------------------------------------------------------------------- the test */

START_TEST(RegSecurityEnforce)
{
    DWORD Mode = ReadAclMode();
    WCHAR Child[16], Expect[32];

    AclMode = Mode;
    Enforced = !is_reactos() || Mode == 2;
    if (GetEnvironmentVariableW(L"REGACL_ENFORCE_CHILD", Child, RTL_NUMBER_OF(Child)) &&
        GetEnvironmentVariableW(L"REGACL_ENFORCE_EXPECT", Expect, RTL_NUMBER_OF(Expect)))
    {
        /* started by RunRestrictedChild with a restricted primary token */
        RestrictedChild(Child, Expect);
        return;
    }
    trace("registry ACL mode %ld: rows use the %s values\n", (LONG)Mode, Enforced ? "enforced" : "not-enforced");
    if (!InitTokens())
        return;
    if (!ProcessIsAdmin)
        trace("the process is a standard user\n");

    TestStandardUser();
    TestCurrentUser();
    TestRestricted();
    TestBackupRestore();
    TestOwnerRights();
    ExitTokens();
}
