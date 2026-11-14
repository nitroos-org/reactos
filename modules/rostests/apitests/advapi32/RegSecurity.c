/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Registry key security as Windows has it: RegGetKeySecurity/RegSetKeySecurity round
 *              trips, the default security descriptors of the hive roots, KEY_* access checks for an
 *              administrator and for a standard user, and the rights needed to create a subkey.
 *              Written for the registry ACL enforcement track: where the kernel does not yet store or
 *              enforce key security descriptors the checks are marked todo_ros, so the gap is
 *              documented without breaking runs.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The tests are split by what they touch:
 *   RegSecurityDump       read-only: prints the SDDL of the keys below (diagnostics, never fails)
 *   RegSecurityDefaultSd  read-only: default SDs of HKLM\SYSTEM, SOFTWARE, SAM, SECURITY, HKU, HKCU
 *   RegSecurityAccess     read-only (opens only, nothing is written): KEY_* access as admin / standard
 *   RegSecurityMapping    read-only: generic mapping of the granted access
 *   RegSecurityRoundTrip  writes a volatile key under HKCU only
 *   RegSecurityCreate     writes volatile keys under HKCU only: create-under-parent rights, inheritance
 *
 * "Standard user" is the process itself when it does not run as an administrator (the standard-user
 * golden), otherwise a thread token made from the process token with Administrators deny-only, no
 * privileges and no other change (the shape of a filtered / restricted renderer token).
 */

#include "precomp.h"
#include <aclapi.h>
#include <sddl.h>
#include <ndk/obfuncs.h>

#define KEY_R   0x20019     /* KEY_READ */
#define KEY_W   0x20006     /* KEY_WRITE */
#define KEY_X   0x20019     /* generic execute as the reactos object type maps it */
#define KEY_WIN10_X 0x20039 /* generic execute as Windows 10 maps it */
#define KEY_A   0xF003F     /* KEY_ALL_ACCESS */

/* CHK(gap, cond, fmt, ...): gap != 0 marks an assertion that fails on reactos today
 * (kernel does not store / enforce key security descriptors). Keyed on is_reactos() and not on
 * WINETEST_PLATFORM, so a plain run of the exe needs no environment. */
#define CHK(gap, cond, ...) do { todo_if((gap) && is_reactos()) ok(cond, __VA_ARGS__); } while (0)

/* ---------------------------------------------------------------------- tokens */

static HANDLE StdImpersonation;     /* NULL: use the process token as is */
static BOOL ProcessIsAdmin;

static BOOL IsAdminNow(void)
{
    SID_IDENTIFIER_AUTHORITY Nt = {SECURITY_NT_AUTHORITY};
    PSID Admins = NULL;
    BOOL Member = FALSE;

    if (!AllocateAndInitializeSid(&Nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                                  0, 0, 0, 0, 0, 0, &Admins))
        return FALSE;
    if (!CheckTokenMembership(NULL, Admins, &Member))
        Member = FALSE;
    FreeSid(Admins);
    return Member;
}

/* Builds StdImpersonation (see header). Returns FALSE when no token could be made. */
static BOOL InitTokens(void)
{
    SID_IDENTIFIER_AUTHORITY Nt = {SECURITY_NT_AUTHORITY};
    HANDLE Process, Filtered = NULL;
    PSID Admins = NULL;
    SID_AND_ATTRIBUTES Deny;
    BOOL Ok;

    ProcessIsAdmin = IsAdminNow();
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &Process))
    {
        skip("OpenProcessToken failed: %lu\n", GetLastError());
        return FALSE;
    }
    if (!ProcessIsAdmin)
    {
        /* the process is the standard user: no impersonation needed */
        CloseHandle(Process);
        StdImpersonation = NULL;
        return TRUE;
    }
    AllocateAndInitializeSid(&Nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                             0, 0, 0, 0, 0, 0, &Admins);
    Deny.Sid = Admins;
    Deny.Attributes = 0;
    Ok = CreateRestrictedToken(Process, DISABLE_MAX_PRIVILEGE, 1, &Deny, 0, NULL, 0, NULL, &Filtered);
    if (!Ok)
    {
        skip("CreateRestrictedToken failed: %lu\n", GetLastError());
    }
    else
    {
        Ok = DuplicateTokenEx(Filtered, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation,
                              TokenImpersonation, &StdImpersonation);
        if (!Ok)
            skip("DuplicateTokenEx failed: %lu\n", GetLastError());
        CloseHandle(Filtered);
    }
    FreeSid(Admins);
    CloseHandle(Process);
    return Ok;
}

static void ExitTokens(void)
{
    if (StdImpersonation)
        CloseHandle(StdImpersonation);
    StdImpersonation = NULL;
}

static BOOL BeStandard(void)
{
    if (!StdImpersonation)
        return TRUE;
    if (!ImpersonateLoggedOnUser(StdImpersonation))
    {
        ok(0, "ImpersonateLoggedOnUser failed: %lu\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

static void BeSelf(void)
{
    if (StdImpersonation)
        RevertToSelf();
}

/* The standard-user check of the helper itself: it must not be an administrator now */
static void CheckStandardIsStandard(void)
{
    if (!BeStandard())
        return;
    ok(!IsAdminNow(), "the standard-user token is an administrator\n");
    BeSelf();
}

/* ------------------------------------------------------------------------ sids */

static PSID WellKnown(WELL_KNOWN_SID_TYPE Type)
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

/* The user SID of the current process token (caller frees) */
static PSID ProcessUserSid(void)
{
    HANDLE Token;
    DWORD Length = 0;
    PTOKEN_USER User;
    PSID Copy = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token))
        return NULL;
    GetTokenInformation(Token, TokenUser, NULL, 0, &Length);
    User = LocalAlloc(LPTR, Length);
    if (User && GetTokenInformation(Token, TokenUser, User, Length, &Length))
    {
        Length = GetLengthSid(User->User.Sid);
        Copy = LocalAlloc(LPTR, Length);
        if (Copy)
            CopySid(Length, Copy, User->User.Sid);
    }
    LocalFree(User);
    CloseHandle(Token);
    return Copy;
}

/* The default owner of the process token (caller frees) */
static PSID ProcessOwnerSid(void)
{
    HANDLE Token;
    DWORD Length = 0;
    PTOKEN_OWNER Owner;
    PSID Copy = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token))
        return NULL;
    GetTokenInformation(Token, TokenOwner, NULL, 0, &Length);
    Owner = LocalAlloc(LPTR, Length);
    if (Owner && GetTokenInformation(Token, TokenOwner, Owner, Length, &Length))
    {
        Length = GetLengthSid(Owner->Owner);
        Copy = LocalAlloc(LPTR, Length);
        if (Copy)
            CopySid(Length, Copy, Owner->Owner);
    }
    LocalFree(Owner);
    CloseHandle(Token);
    return Copy;
}

/* --------------------------------------------------------------- security info */

/* RegGetKeySecurity with the size probe Windows documents. Caller LocalFree()s *Sd. */
static LONG GetKeySd(HKEY Key, SECURITY_INFORMATION Info, PSECURITY_DESCRIPTOR *Sd)
{
    DWORD Length = 0, Needed;
    LONG Error;
    PSECURITY_DESCRIPTOR Buffer;

    *Sd = NULL;
    Error = RegGetKeySecurity(Key, Info, NULL, &Length);
    if (Error != ERROR_INSUFFICIENT_BUFFER)
        return Error ? Error : ERROR_SUCCESS;
    Buffer = LocalAlloc(LPTR, Length);
    if (!Buffer)
        return ERROR_OUTOFMEMORY;
    Needed = Length;
    Error = RegGetKeySecurity(Key, Info, Buffer, &Needed);
    if (Error)
    {
        LocalFree(Buffer);
        return Error;
    }
    *Sd = Buffer;
    return ERROR_SUCCESS;
}

static PSID SdOwner(PSECURITY_DESCRIPTOR Sd)
{
    PSID Owner = NULL;
    BOOL Defaulted;

    GetSecurityDescriptorOwner(Sd, &Owner, &Defaulted);
    return Owner;
}

static PACL SdDacl(PSECURITY_DESCRIPTOR Sd, BOOL *Present)
{
    PACL Dacl = NULL;
    BOOL Defaulted;

    *Present = FALSE;
    GetSecurityDescriptorDacl(Sd, Present, &Dacl, &Defaulted);
    return Dacl;
}

/* Finds the first ACE of Type for Sid; returns its mask and flags (0 if there is none) */
static BOOL FindAce(PACL Dacl, PSID Sid, BYTE Type, ACCESS_MASK *Mask, BYTE *Flags)
{
    DWORD i;
    PVOID Ace;

    if (!Dacl)
        return FALSE;
    for (i = 0; i < Dacl->AceCount; i++)
    {
        PACCESS_ALLOWED_ACE A;

        if (!GetAce(Dacl, i, &Ace))
            continue;
        A = Ace;
        if (A->Header.AceType == Type && EqualSid((PSID)&A->SidStart, Sid))
        {
            if (Mask) *Mask = A->Mask;
            if (Flags) *Flags = A->Header.AceFlags;
            return TRUE;
        }
    }
    return FALSE;
}

/* Union of the allow-ACE masks that name Sid (no deny handling: the keys inspected have no deny ACEs) */
static ACCESS_MASK AllowedFor(PACL Dacl, PSID Sid)
{
    ACCESS_MASK Total = 0;
    DWORD i;
    PVOID Ace;

    if (!Dacl)
        return 0;
    for (i = 0; i < Dacl->AceCount; i++)
    {
        PACCESS_ALLOWED_ACE A;

        if (GetAce(Dacl, i, &Ace))
        {
            A = Ace;
            if (A->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && EqualSid((PSID)&A->SidStart, Sid))
                Total |= A->Mask;
        }
    }
    return Total;
}

static BOOL SidIs(PSID Sid, WELL_KNOWN_SID_TYPE Type)
{
    PSID Known = WellKnown(Type);
    BOOL Equal = Sid && Known && EqualSid(Sid, Known);

    LocalFree(Known);
    return Equal;
}

static void PrintKeySddl(const char *Label, HKEY Root, PCWSTR Path)
{
    HKEY Key;
    LONG Error;
    PSECURITY_DESCRIPTOR Sd;
    PWSTR Text = NULL;

    Error = RegOpenKeyExW(Root, Path, 0, READ_CONTROL, &Key);
    if (Error)
    {
        printf("SDDL %s: open READ_CONTROL error %ld\n", Label, Error);
        return;
    }
    Error = GetKeySd(Key, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &Sd);
    if (Error)
        printf("SDDL %s: RegGetKeySecurity error %ld\n", Label, Error);
    else
    {
        if (ConvertSecurityDescriptorToStringSecurityDescriptorW(Sd, SDDL_REVISION_1,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &Text, NULL))
        {
            printf("SDDL %s: %ls\n", Label, Text);
            LocalFree(Text);
        }
        else
            printf("SDDL %s: convert error %lu\n", Label, GetLastError());
        LocalFree(Sd);
    }
    RegCloseKey(Key);
}

/* ------------------------------------------------------------------ the tests */

static const struct
{
    const char *Label;
    HKEY Root;
    PCWSTR Path;
} DumpKeys[] =
{
    { "HKLM",                   HKEY_LOCAL_MACHINE, L"" },
    { "HKLM\\SYSTEM",           HKEY_LOCAL_MACHINE, L"SYSTEM" },
    { "HKLM\\SOFTWARE",         HKEY_LOCAL_MACHINE, L"SOFTWARE" },
    { "HKLM\\SAM",              HKEY_LOCAL_MACHINE, L"SAM" },
    { "HKLM\\SAM\\SAM",         HKEY_LOCAL_MACHINE, L"SAM\\SAM" },
    { "HKLM\\SECURITY",         HKEY_LOCAL_MACHINE, L"SECURITY" },
    { "HKLM\\HARDWARE",         HKEY_LOCAL_MACHINE, L"HARDWARE" },
    { "HKLM\\SYSTEM\\CCS\\Services", HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services" },
    { "HKLM\\SOFTWARE\\Microsoft", HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft" },
    { "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", HKEY_LOCAL_MACHINE,
      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" },
    { "HKU",                    HKEY_USERS, L"" },
    { "HKU\\.DEFAULT",          HKEY_USERS, L".DEFAULT" },
    { "HKCU",                   HKEY_CURRENT_USER, L"" },
    { "HKCU\\Software",         HKEY_CURRENT_USER, L"Software" },
    { "HKCU\\Software\\Microsoft", HKEY_CURRENT_USER, L"Software\\Microsoft" },
    { "HKCU\\Environment",      HKEY_CURRENT_USER, L"Environment" },
    { "HKCU\\Control Panel",    HKEY_CURRENT_USER, L"Control Panel" },
};

START_TEST(RegSecurityDump)
{
    SIZE_T i;

    for (i = 0; i < RTL_NUMBER_OF(DumpKeys); i++)
        PrintKeySddl(DumpKeys[i].Label, DumpKeys[i].Root, DumpKeys[i].Path);
}

/* The Windows rights of the principals on one of the HKLM hive roots */
static void CheckHiveRoot(const char *Label, PCWSTR Path, BOOL ExpectOwnerAdmins)
{
    HKEY Key;
    LONG Error;
    PSECURITY_DESCRIPTOR Sd;
    PACL Dacl;
    BOOL Present;
    PSID Admins = WellKnown(WinBuiltinAdministratorsSid);
    PSID System = WellKnown(WinLocalSystemSid);
    PSID Users = WellKnown(WinBuiltinUsersSid);
    PSID Everyone = WellKnown(WinWorldSid);
    ACCESS_MASK Mask;
    BYTE Flags;

    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, Path, 0, READ_CONTROL, &Key);
    ok_long(Error, ERROR_SUCCESS);
    if (Error)
        goto Done;
    Error = GetKeySd(Key, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &Sd);
    ok_long(Error, ERROR_SUCCESS);
    if (Error)
    {
        RegCloseKey(Key);
        goto Done;
    }
    Dacl = SdDacl(Sd, &Present);
    ok(Present && Dacl, "%s: no DACL\n", Label);

    if (ExpectOwnerAdmins)
        CHK(0, SidIs(SdOwner(Sd), WinBuiltinAdministratorsSid), "%s: owner is not Administrators\n", Label);

    /* SYSTEM and Administrators have full control, inherited by subkeys (CI) */
    Mask = 0;
    Flags = 0;
    CHK(0, FindAce(Dacl, System, ACCESS_ALLOWED_ACE_TYPE, &Mask, &Flags) && Mask == KEY_A,
        "%s: SYSTEM ACE mask 0x%lx\n", Label, (ULONG)Mask);
    Mask = 0;
    CHK(0, FindAce(Dacl, Admins, ACCESS_ALLOWED_ACE_TYPE, &Mask, &Flags) && Mask == KEY_A,
        "%s: Administrators ACE mask 0x%lx\n", Label, (ULONG)Mask);
    CHK(0, (Flags & CONTAINER_INHERIT_ACE), "%s: Administrators ACE does not inherit to subkeys (flags 0x%x)\n", Label, Flags);
    /* Users read only */
    Mask = 0;
    CHK(0, FindAce(Dacl, Users, ACCESS_ALLOWED_ACE_TYPE, &Mask, NULL) && Mask == KEY_R,
        "%s: Users ACE mask 0x%lx, expected 0x%x\n", Label, (ULONG)Mask, KEY_R);
    /* and nobody else (Everyone in particular) is granted anything */
    CHK(0, AllowedFor(Dacl, Everyone) == 0, "%s: Everyone is granted 0x%lx\n", Label, (ULONG)AllowedFor(Dacl, Everyone));
    LocalFree(Sd);
    RegCloseKey(Key);
Done:
    LocalFree(Admins);
    LocalFree(System);
    LocalFree(Users);
    LocalFree(Everyone);
}

/* HKLM\SAM\SAM and HKLM\SECURITY: SYSTEM only, Administrators may read and change the DACL only */
static void CheckSecret(const char *Label, PCWSTR Path)
{
    HKEY Key;
    LONG Error;
    PSECURITY_DESCRIPTOR Sd;
    PACL Dacl;
    BOOL Present;
    PSID Admins = WellKnown(WinBuiltinAdministratorsSid);
    PSID System = WellKnown(WinLocalSystemSid);
    PSID Users = WellKnown(WinBuiltinUsersSid);
    PSID Everyone = WellKnown(WinWorldSid);
    ACCESS_MASK Mask = 0;

    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, Path, 0, READ_CONTROL, &Key);
    if (Error == ERROR_FILE_NOT_FOUND)
    {
        skip("%s does not exist\n", Label);
        goto Done;
    }
    ok_long(Error, ERROR_SUCCESS);
    if (Error)
        goto Done;
    Error = GetKeySd(Key, DACL_SECURITY_INFORMATION, &Sd);
    ok_long(Error, ERROR_SUCCESS);
    if (!Error)
    {
        Dacl = SdDacl(Sd, &Present);
        ok(Present && Dacl, "%s: no DACL\n", Label);
        CHK(0, FindAce(Dacl, System, ACCESS_ALLOWED_ACE_TYPE, &Mask, NULL) && Mask == KEY_A,
            "%s: SYSTEM ACE mask 0x%lx\n", Label, (ULONG)Mask);
        Mask = 0;
        CHK(0, FindAce(Dacl, Admins, ACCESS_ALLOWED_ACE_TYPE, &Mask, NULL) &&
               Mask == (READ_CONTROL | WRITE_DAC),
            "%s: Administrators ACE mask 0x%lx, expected READ_CONTROL|WRITE_DAC\n", Label, (ULONG)Mask);
        /* holds vacuously on reactos today (the descriptor only names Everyone); a regression guard */
        ok(AllowedFor(Dacl, Users) == 0, "%s: Users are granted 0x%lx\n", Label, (ULONG)AllowedFor(Dacl, Users));
        CHK(0, AllowedFor(Dacl, Everyone) == 0, "%s: Everyone is granted 0x%lx\n", Label, (ULONG)AllowedFor(Dacl, Everyone));
        LocalFree(Sd);
    }
    RegCloseKey(Key);
Done:
    LocalFree(Admins);
    LocalFree(System);
    LocalFree(Users);
    LocalFree(Everyone);
}

/* The user's own hive root: the user and SYSTEM and Administrators have full control */
static void CheckUserRoot(const char *Label, PCWSTR Path)
{
    HKEY Key;
    LONG Error;
    PSECURITY_DESCRIPTOR Sd;
    PACL Dacl;
    BOOL Present;
    PSID User = ProcessUserSid();
    PSID System = WellKnown(WinLocalSystemSid);
    PSID Everyone = WellKnown(WinWorldSid);
    ACCESS_MASK Mask = 0;

    Error = RegOpenKeyExW(HKEY_CURRENT_USER, Path, 0, READ_CONTROL, &Key);
    ok_long(Error, ERROR_SUCCESS);
    if (Error)
        goto Done;
    Error = GetKeySd(Key, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &Sd);
    ok_long(Error, ERROR_SUCCESS);
    if (!Error)
    {
        Dacl = SdDacl(Sd, &Present);
        ok(Present && Dacl, "%s: no DACL\n", Label);
        CHK(0, FindAce(Dacl, User, ACCESS_ALLOWED_ACE_TYPE, &Mask, NULL) && Mask == KEY_A,
            "%s: the user's ACE mask 0x%lx\n", Label, (ULONG)Mask);
        Mask = 0;
        CHK(0, FindAce(Dacl, System, ACCESS_ALLOWED_ACE_TYPE, &Mask, NULL) && Mask == KEY_A,
            "%s: SYSTEM ACE mask 0x%lx\n", Label, (ULONG)Mask);
        CHK(0, AllowedFor(Dacl, Everyone) == 0, "%s: Everyone is granted 0x%lx\n", Label, (ULONG)AllowedFor(Dacl, Everyone));
        LocalFree(Sd);
    }
    RegCloseKey(Key);
Done:
    LocalFree(User);
    LocalFree(System);
    LocalFree(Everyone);
}

START_TEST(RegSecurityDefaultSd)
{
    CheckHiveRoot("HKLM\\SYSTEM", L"SYSTEM", TRUE);
    CheckHiveRoot("HKLM\\SOFTWARE", L"SOFTWARE", TRUE);
    CheckHiveRoot("HKLM\\SOFTWARE\\Microsoft", L"SOFTWARE\\Microsoft", FALSE);
    CheckHiveRoot("HKLM\\SYSTEM\\CurrentControlSet\\Services", L"SYSTEM\\CurrentControlSet\\Services", FALSE);
    CheckSecret("HKLM\\SAM\\SAM", L"SAM\\SAM");
    CheckSecret("HKLM\\SECURITY", L"SECURITY");
    CheckUserRoot("HKCU", L"");
    CheckUserRoot("HKCU\\Software", L"Software");
}

/* Opens only; every handle is closed at once. Nothing is written. */
static LONG OpenAs(BOOL Standard, HKEY Root, PCWSTR Path, REGSAM Sam, HKEY *Key)
{
    LONG Error;

    if (Standard && !BeStandard())
        return ERROR_GEN_FAILURE;
    Error = RegOpenKeyExW(Root, Path, 0, Sam, Key);
    if (Standard)
        BeSelf();
    return Error;
}

static void CheckOpen(BOOL Standard, BOOL Gap, const char *Label, HKEY Root, PCWSTR Path,
                      REGSAM Sam, LONG Expected)
{
    HKEY Key = NULL;
    LONG Error = OpenAs(Standard, Root, Path, Sam, &Key);

    CHK(Gap, Error == Expected, "%s open %s 0x%lx: error %ld, expected %ld\n",
        Standard ? "standard" : "admin", Label, (ULONG)Sam, Error, Expected);
    if (Error == ERROR_SUCCESS)
        RegCloseKey(Key);
}

static const WCHAR ServicesPath[] = L"SYSTEM\\CurrentControlSet\\Services";

START_TEST(RegSecurityAccess)
{
    HKEY Probe;

    if (!InitTokens())
        return;
    CheckStandardIsStandard();

    /* administrator: full control of HKLM\SOFTWARE and the services, but only READ_CONTROL / WRITE_DAC
     * on SAM\SAM and SECURITY (the famous "administrators cannot read SAM") */
    if (ProcessIsAdmin)
    {
        CheckOpen(FALSE, FALSE, "HKLM\\SOFTWARE", HKEY_LOCAL_MACHINE, L"SOFTWARE", KEY_ALL_ACCESS, ERROR_SUCCESS);
        CheckOpen(FALSE, FALSE, "HKLM\\SOFTWARE", HKEY_LOCAL_MACHINE, L"SOFTWARE", KEY_READ, ERROR_SUCCESS);
        CheckOpen(FALSE, FALSE, "Services", HKEY_LOCAL_MACHINE, ServicesPath, KEY_SET_VALUE, ERROR_SUCCESS);
        CheckOpen(FALSE, FALSE, "Services", HKEY_LOCAL_MACHINE, ServicesPath, KEY_CREATE_SUB_KEY, ERROR_SUCCESS);
        CheckOpen(FALSE, FALSE, "HKCU", HKEY_CURRENT_USER, L"Software", KEY_ALL_ACCESS, ERROR_SUCCESS);
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SAM\\SAM", 0, READ_CONTROL, &Probe) == ERROR_SUCCESS)
        {
            RegCloseKey(Probe);
            CheckOpen(FALSE, TRUE, "SAM\\SAM", HKEY_LOCAL_MACHINE, L"SAM\\SAM", KEY_READ, ERROR_ACCESS_DENIED);
            CheckOpen(FALSE, FALSE, "SAM\\SAM", HKEY_LOCAL_MACHINE, L"SAM\\SAM", READ_CONTROL | WRITE_DAC, ERROR_SUCCESS);
        }
        else
            skip("HKLM\\SAM\\SAM cannot be opened for READ_CONTROL\n");
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SECURITY", 0, READ_CONTROL, &Probe) == ERROR_SUCCESS)
        {
            RegCloseKey(Probe);
            CheckOpen(FALSE, TRUE, "SECURITY", HKEY_LOCAL_MACHINE, L"SECURITY", KEY_READ, ERROR_ACCESS_DENIED);
            CheckOpen(FALSE, FALSE, "SECURITY", HKEY_LOCAL_MACHINE, L"SECURITY", READ_CONTROL | WRITE_DAC, ERROR_SUCCESS);
        }
        else
            skip("HKLM\\SECURITY cannot be opened for READ_CONTROL\n");
    }
    else
        skip("the process is not an administrator: administrator checks skipped\n");

    /* standard user: reads HKLM, may not write it; owns HKCU; cannot even look at SAM / SECURITY */
    CheckOpen(TRUE, FALSE, "HKLM\\SOFTWARE", HKEY_LOCAL_MACHINE, L"SOFTWARE", KEY_READ, ERROR_SUCCESS);
    CheckOpen(TRUE, FALSE, "HKLM\\SYSTEM", HKEY_LOCAL_MACHINE, L"SYSTEM", KEY_READ, ERROR_SUCCESS);
    CheckOpen(TRUE, FALSE, "Services", HKEY_LOCAL_MACHINE, ServicesPath, KEY_READ, ERROR_SUCCESS);
    CheckOpen(TRUE, FALSE, "HKCU\\Software", HKEY_CURRENT_USER, L"Software", KEY_ALL_ACCESS, ERROR_SUCCESS);
    CheckOpen(TRUE, TRUE, "HKLM\\SOFTWARE", HKEY_LOCAL_MACHINE, L"SOFTWARE", KEY_SET_VALUE, ERROR_ACCESS_DENIED);
    CheckOpen(TRUE, TRUE, "HKLM\\SOFTWARE", HKEY_LOCAL_MACHINE, L"SOFTWARE", KEY_CREATE_SUB_KEY, ERROR_ACCESS_DENIED);
    CheckOpen(TRUE, TRUE, "HKLM\\SOFTWARE", HKEY_LOCAL_MACHINE, L"SOFTWARE", KEY_WRITE, ERROR_ACCESS_DENIED);
    CheckOpen(TRUE, TRUE, "HKLM\\SOFTWARE", HKEY_LOCAL_MACHINE, L"SOFTWARE", KEY_ALL_ACCESS, ERROR_ACCESS_DENIED);
    CheckOpen(TRUE, TRUE, "HKLM\\SOFTWARE", HKEY_LOCAL_MACHINE, L"SOFTWARE", WRITE_DAC, ERROR_ACCESS_DENIED);
    CheckOpen(TRUE, TRUE, "Services", HKEY_LOCAL_MACHINE, ServicesPath, KEY_SET_VALUE, ERROR_ACCESS_DENIED);
    CheckOpen(TRUE, TRUE, "Services", HKEY_LOCAL_MACHINE, ServicesPath, KEY_CREATE_SUB_KEY, ERROR_ACCESS_DENIED);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SAM\\SAM", 0, KEY_READ, &Probe) != ERROR_FILE_NOT_FOUND)
    {
        CheckOpen(TRUE, TRUE, "SAM\\SAM", HKEY_LOCAL_MACHINE, L"SAM\\SAM", READ_CONTROL, ERROR_ACCESS_DENIED);
        CheckOpen(TRUE, TRUE, "SAM\\SAM", HKEY_LOCAL_MACHINE, L"SAM\\SAM", KEY_READ, ERROR_ACCESS_DENIED);
    }
    CheckOpen(TRUE, TRUE, "SECURITY", HKEY_LOCAL_MACHINE, L"SECURITY", READ_CONTROL, ERROR_ACCESS_DENIED);
    CheckOpen(TRUE, TRUE, "SECURITY", HKEY_LOCAL_MACHINE, L"SECURITY", KEY_READ, ERROR_ACCESS_DENIED);
    ExitTokens();
}

static ACCESS_MASK GrantedAccessOf(HKEY Key)
{
    OBJECT_BASIC_INFORMATION Info;
    NTSTATUS Status = NtQueryObject(Key, ObjectBasicInformation, &Info, sizeof(Info), NULL);

    if (!NT_SUCCESS(Status))
        return 0xdeadbeef;
    return Info.GrantedAccess;
}

static void CheckGranted(BOOL Standard, BOOL Gap, const char *Label, HKEY Root, PCWSTR Path,
                         REGSAM Sam, ACCESS_MASK Expected)
{
    HKEY Key;
    LONG Error = OpenAs(Standard, Root, Path, Sam, &Key);
    ACCESS_MASK Granted;

    ok_long(Error == ERROR_SUCCESS || (Standard && Error == ERROR_ACCESS_DENIED), TRUE);
    if (Error)
        return;
    Granted = GrantedAccessOf(Key);
    CHK(Gap, Granted == Expected, "%s open %s 0x%lx: granted 0x%lx, expected 0x%lx\n",
        Standard ? "standard" : "admin", Label, (ULONG)Sam, (ULONG)Granted, (ULONG)Expected);
    RegCloseKey(Key);
}

START_TEST(RegSecurityMapping)
{
    HKEY Key;
    ACCESS_MASK Granted;
    LONG Error;

    if (!InitTokens())
        return;

    /* the generic mapping of the key object type, on a key where the caller has full control (HKCU) */
    Error = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software", 0, GENERIC_READ, &Key);
    ok_long(Error, ERROR_SUCCESS);
    if (!Error)
    {
        Granted = GrantedAccessOf(Key);
        ok(Granted == KEY_R, "GENERIC_READ granted 0x%lx, expected 0x%x\n", (ULONG)Granted, KEY_R);
        RegCloseKey(Key);
    }
    Error = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software", 0, GENERIC_WRITE, &Key);
    ok_long(Error, ERROR_SUCCESS);
    if (!Error)
    {
        Granted = GrantedAccessOf(Key);
        ok(Granted == KEY_W, "GENERIC_WRITE granted 0x%lx, expected 0x%x\n", (ULONG)Granted, KEY_W);
        RegCloseKey(Key);
    }
    Error = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software", 0, GENERIC_EXECUTE, &Key);
    ok_long(Error, ERROR_SUCCESS);
    if (!Error)
    {
        Granted = GrantedAccessOf(Key);
        /* Windows 10 maps GENERIC_EXECUTE of a key to KEY_READ | KEY_NOTIFY (0x20039 is KEY_EXECUTE
         * 0x20019 plus KEY_NOTIFY): the object type of the reactos kernel uses 0x20019 */
        CHK(1, Granted == KEY_WIN10_X, "GENERIC_EXECUTE granted 0x%lx, expected 0x%x\n", (ULONG)Granted, KEY_WIN10_X);
        RegCloseKey(Key);
    }
    Error = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software", 0, GENERIC_ALL, &Key);
    ok_long(Error, ERROR_SUCCESS);
    if (!Error)
    {
        Granted = GrantedAccessOf(Key);
        ok(Granted == KEY_A, "GENERIC_ALL granted 0x%lx, expected 0x%x\n", (ULONG)Granted, KEY_A);
        RegCloseKey(Key);
    }

    /* MAXIMUM_ALLOWED: what the DACL grants */
    if (ProcessIsAdmin)
        CheckGranted(FALSE, FALSE, "HKLM\\SOFTWARE", HKEY_LOCAL_MACHINE, L"SOFTWARE", MAXIMUM_ALLOWED, KEY_A);
    CheckGranted(TRUE, TRUE, "HKLM\\SOFTWARE", HKEY_LOCAL_MACHINE, L"SOFTWARE", MAXIMUM_ALLOWED, KEY_R);
    CheckGranted(TRUE, TRUE, "Services", HKEY_LOCAL_MACHINE, ServicesPath, MAXIMUM_ALLOWED, KEY_R);
    CheckGranted(TRUE, FALSE, "HKCU\\Software", HKEY_CURRENT_USER, L"Software", MAXIMUM_ALLOWED, KEY_A);
    ExitTokens();
}

/* ---------------------------------------------------------------- round trips */

static const WCHAR RoundTripKey[] = L"Software\\ReactOS-apitest-RegSecurity";

static void DeleteTestKey(HKEY Parent, PCWSTR Name)
{
    RegDeleteKeyW(Parent, Name);
}

START_TEST(RegSecurityRoundTrip)
{
    HKEY Key;
    LONG Error;
    DWORD Length, Needed;
    PSECURITY_DESCRIPTOR Sd = NULL, NewSd = NULL;
    PACL Dacl, NewDacl = NULL;
    BOOL Present;
    PSID Owner = ProcessOwnerSid();
    PSID Everyone = WellKnown(WinWorldSid);
    PSID System = WellKnown(WinLocalSystemSid);
    PSID Guests = WellKnown(WinBuiltinGuestsSid);
    EXPLICIT_ACCESSW Access;
    ACCESS_MASK Mask;
    DWORD AceCountBefore;
    SECURITY_DESCRIPTOR Absolute;

    RegDeleteKeyW(HKEY_CURRENT_USER, RoundTripKey);
    Error = RegCreateKeyExW(HKEY_CURRENT_USER, RoundTripKey, 0, NULL, REG_OPTION_VOLATILE,
                            KEY_ALL_ACCESS, NULL, &Key, NULL);
    ok_long(Error, ERROR_SUCCESS);
    if (Error)
        goto Done;

    /* the size probe: a NULL buffer gets ERROR_INSUFFICIENT_BUFFER and the needed length */
    Length = 0;
    Error = RegGetKeySecurity(Key, DACL_SECURITY_INFORMATION, NULL, &Length);
    ok_long(Error, ERROR_INSUFFICIENT_BUFFER);
    ok(Length >= sizeof(SECURITY_DESCRIPTOR_RELATIVE), "needed length %lu\n", Length);

    /* a buffer that is one byte too small is refused and reports the same length */
    if (Length > 1)
    {
        Sd = LocalAlloc(LPTR, Length);
        Needed = Length - 1;
        Error = RegGetKeySecurity(Key, DACL_SECURITY_INFORMATION, Sd, &Needed);
        ok_long(Error, ERROR_INSUFFICIENT_BUFFER);
        LocalFree(Sd);
        Sd = NULL;
    }

    /* a self-relative descriptor with owner, group and DACL */
    Error = GetKeySd(Key, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &Sd);
    ok_long(Error, ERROR_SUCCESS);
    if (Error)
        goto Close;
    ok(IsValidSecurityDescriptor(Sd), "the descriptor is not valid\n");
    ok(SdOwner(Sd) != NULL, "no owner\n");
    {
        SECURITY_DESCRIPTOR_CONTROL Control;
        DWORD Revision;

        ok(GetSecurityDescriptorControl(Sd, &Control, &Revision), "GetSecurityDescriptorControl failed\n");
        ok(Control & SE_SELF_RELATIVE, "descriptor is not self-relative (0x%x)\n", Control);
        ok(Control & SE_DACL_PRESENT, "no DACL present (0x%x)\n", Control);
    }
    /* the owner is the creating token's owner (Administrators for an admin, the user otherwise) */
    CHK(0, SdOwner(Sd) && Owner && EqualSid(SdOwner(Sd), Owner), "owner of a new key is not the token owner\n");
    /* Everyone is not granted full control of a new key under HKCU */
    Dacl = SdDacl(Sd, &Present);
    CHK(0, Present && Dacl && AllowedFor(Dacl, Everyone) == 0, "Everyone is granted 0x%lx on a new key\n",
        (ULONG)AllowedFor(Dacl, Everyone));
    CHK(0, FindAce(Dacl, System, ACCESS_ALLOWED_ACE_TYPE, &Mask, NULL), "a new key under HKCU has no SYSTEM ACE\n");
    AceCountBefore = Dacl ? Dacl->AceCount : 0;

    /* only the requested parts come back */
    LocalFree(Sd);
    Error = GetKeySd(Key, OWNER_SECURITY_INFORMATION, &Sd);
    ok_long(Error, ERROR_SUCCESS);
    if (!Error)
    {
        SECURITY_DESCRIPTOR_CONTROL Control;
        DWORD Revision;

        GetSecurityDescriptorControl(Sd, &Control, &Revision);
        ok(!(Control & SE_DACL_PRESENT), "owner-only query returned a DACL (0x%x)\n", Control);
        LocalFree(Sd);
    }
    Sd = NULL;

    /* set: add an ACE for Everyone (read), get it back */
    Error = GetKeySd(Key, DACL_SECURITY_INFORMATION, &Sd);
    ok_long(Error, ERROR_SUCCESS);
    if (Error)
        goto Close;
    Dacl = SdDacl(Sd, &Present);
    ZeroMemory(&Access, sizeof(Access));
    Access.grfAccessPermissions = KEY_R;
    Access.grfAccessMode = GRANT_ACCESS;
    Access.grfInheritance = NO_INHERITANCE;
    Access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    Access.Trustee.ptstrName = Everyone;
    Error = SetEntriesInAclW(1, &Access, Dacl, &NewDacl);
    ok_long(Error, ERROR_SUCCESS);
    if (Error)
        goto Close;
    InitializeSecurityDescriptor(&Absolute, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&Absolute, TRUE, NewDacl, FALSE);
    Error = RegSetKeySecurity(Key, DACL_SECURITY_INFORMATION, &Absolute);
    ok_long(Error, ERROR_SUCCESS);

    LocalFree(Sd);
    Sd = NULL;
    Error = GetKeySd(Key, DACL_SECURITY_INFORMATION, &Sd);
    ok_long(Error, ERROR_SUCCESS);
    if (!Error)
    {
        Dacl = SdDacl(Sd, &Present);
        Mask = 0;
        CHK(0, Dacl && FindAce(Dacl, Everyone, ACCESS_ALLOWED_ACE_TYPE, &Mask, NULL) && Mask == KEY_R,
            "the ACE set with RegSetKeySecurity did not come back (mask 0x%lx)\n", (ULONG)Mask);
        CHK(0, Dacl && Dacl->AceCount == AceCountBefore + 1, "ACE count %u, expected %lu\n",
            Dacl ? Dacl->AceCount : 0, AceCountBefore + 1);
    }

    /* set a protected DACL: only the owner's full control */
    {
        PACL Only = NULL;
        EXPLICIT_ACCESSW Own;

        ZeroMemory(&Own, sizeof(Own));
        Own.grfAccessPermissions = KEY_A;
        Own.grfAccessMode = SET_ACCESS;
        Own.grfInheritance = NO_INHERITANCE;
        Own.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        Own.Trustee.ptstrName = Owner;
        if (SetEntriesInAclW(1, &Own, NULL, &Only) == ERROR_SUCCESS)
        {
            SECURITY_DESCRIPTOR_CONTROL Control;
            DWORD Revision;

            SetSecurityDescriptorDacl(&Absolute, TRUE, Only, FALSE);
            Absolute.Control |= SE_DACL_PROTECTED;
            Error = RegSetKeySecurity(Key, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, &Absolute);
            ok_long(Error, ERROR_SUCCESS);
            LocalFree(Sd);
            Sd = NULL;
            Error = GetKeySd(Key, DACL_SECURITY_INFORMATION, &Sd);
            ok_long(Error, ERROR_SUCCESS);
            if (!Error)
            {
                Dacl = SdDacl(Sd, &Present);
                Mask = 0;
                CHK(0, Dacl && Dacl->AceCount == 1 && FindAce(Dacl, Owner, ACCESS_ALLOWED_ACE_TYPE, &Mask, NULL) &&
                    Mask == KEY_A, "protected DACL: %u ACEs, owner mask 0x%lx, expected 1 and 0xf003f\n",
                    Dacl ? Dacl->AceCount : 0, (ULONG)Mask);
                GetSecurityDescriptorControl(Sd, &Control, &Revision);
                CHK(0, Control & SE_DACL_PROTECTED, "the DACL is not protected (0x%x)\n", Control);
            }
            LocalFree(Only);
        }
    }

    /* a descriptor with a NULL DACL grants everyone everything; get returns present + NULL */
    LocalFree(Sd);
    Sd = NULL;
    SetSecurityDescriptorDacl(&Absolute, TRUE, NULL, FALSE);
    Absolute.Control &= ~SE_DACL_PROTECTED;
    Error = RegSetKeySecurity(Key, DACL_SECURITY_INFORMATION, &Absolute);
    ok_long(Error, ERROR_SUCCESS);
    Error = GetKeySd(Key, DACL_SECURITY_INFORMATION, &Sd);
    ok_long(Error, ERROR_SUCCESS);
    if (!Error)
    {
        Dacl = SdDacl(Sd, &Present);
        CHK(0, Present && Dacl == NULL, "NULL DACL did not round trip (present %d, dacl %p)\n", Present, Dacl);
    }

    /* a bad owner: a SID the token may not assign (Guests) fails without SeRestorePrivilege */
    if (Guests)
    {
        InitializeSecurityDescriptor(&Absolute, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorOwner(&Absolute, Guests, FALSE);
        Error = RegSetKeySecurity(Key, OWNER_SECURITY_INFORMATION, &Absolute);
        CHK(0, Error == ERROR_INVALID_OWNER, "setting a foreign owner: error %ld, expected %d\n", Error, ERROR_INVALID_OWNER);
        if (Error == ERROR_SUCCESS)
        {
            /* put it back so the key can be deleted whatever the kernel did */
            SetSecurityDescriptorOwner(&Absolute, Owner, FALSE);
            RegSetKeySecurity(Key, OWNER_SECURITY_INFORMATION, &Absolute);
        }
    }

    /* an invalid descriptor (not self-relative buffer of garbage) is refused */
    {
        BYTE Garbage[8] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

        Error = RegSetKeySecurity(Key, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)Garbage);
        ok(Error != ERROR_SUCCESS, "RegSetKeySecurity accepted a garbage descriptor\n");
    }

    /* a handle without WRITE_DAC cannot change the DACL; without READ_CONTROL cannot read it */
Close:
    RegCloseKey(Key);
    {
        HKEY Weak;

        /* the owner may always reopen for READ_CONTROL | WRITE_DAC to clean up */
        RegOpenKeyExW(HKEY_CURRENT_USER, RoundTripKey, 0, WRITE_DAC | READ_CONTROL, &Weak);
        if (Weak)
        {
            SECURITY_DESCRIPTOR Restore;
            PACL Full = NULL;
            EXPLICIT_ACCESSW E;

            ZeroMemory(&E, sizeof(E));
            E.grfAccessPermissions = KEY_A;
            E.grfAccessMode = SET_ACCESS;
            E.Trustee.TrusteeForm = TRUSTEE_IS_SID;
            E.Trustee.ptstrName = Owner;
            SetEntriesInAclW(1, &E, NULL, &Full);
            InitializeSecurityDescriptor(&Restore, SECURITY_DESCRIPTOR_REVISION);
            SetSecurityDescriptorDacl(&Restore, TRUE, Full, FALSE);
            RegSetKeySecurity(Weak, DACL_SECURITY_INFORMATION, &Restore);
            RegCloseKey(Weak);
            LocalFree(Full);
        }
    }
    DeleteTestKey(HKEY_CURRENT_USER, RoundTripKey);
Done:
    LocalFree(Sd);
    LocalFree(NewSd);
    LocalFree(NewDacl);
    LocalFree(Owner);
    LocalFree(Everyone);
    LocalFree(System);
    LocalFree(Guests);
}

/* --------------------------------------------------------------- create rights */

static const WCHAR CreateParent[] = L"Software\\ReactOS-apitest-RegSecurityCreate";

/* Applies a DACL given as SDDL to Key */
static LONG SetKeyDaclSddl(HKEY Key, PCWSTR Sddl)
{
    PSECURITY_DESCRIPTOR Sd;
    LONG Error;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(Sddl, SDDL_REVISION_1, &Sd, NULL))
        return GetLastError();
    Error = RegSetKeySecurity(Key, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, Sd);
    LocalFree(Sd);
    return Error;
}

START_TEST(RegSecurityCreate)
{
    HKEY Parent, Child, Deny;
    LONG Error;
    PSID User = ProcessUserSid();
    PSID Owner = ProcessOwnerSid();
    PWSTR UserText = NULL, OwnerText = NULL;
    WCHAR Sddl[512];
    PSECURITY_DESCRIPTOR Sd;
    PACL Dacl;
    BOOL Present;
    ACCESS_MASK Mask;
    BYTE Flags;
    DWORD Disp;

    if (!User || !Owner ||
        !ConvertSidToStringSidW(User, &UserText) || !ConvertSidToStringSidW(Owner, &OwnerText))
    {
        skip("no SID text\n");
        goto Done;
    }

    RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\ReactOS-apitest-RegSecurityCreate\\child");
    RegDeleteKeyW(HKEY_CURRENT_USER, CreateParent);
    Error = RegCreateKeyExW(HKEY_CURRENT_USER, CreateParent, 0, NULL, REG_OPTION_VOLATILE,
                            KEY_ALL_ACCESS, NULL, &Parent, NULL);
    ok_long(Error, ERROR_SUCCESS);
    if (Error)
        goto Done;

    /* the parent: the user may read it and change its DACL (owner), nothing else. The ACE inherits
     * to subkeys, a CREATOR OWNER ACE gives the creator full control of children */
    StringCchPrintfW(Sddl, RTL_NUMBER_OF(Sddl), L"O:%lsG:SYD:P(A;CI;0x20019;;;%ls)(A;CI;GA;;;CO)", OwnerText, UserText);
    Error = SetKeyDaclSddl(Parent, Sddl);
    ok_long(Error, ERROR_SUCCESS);

    /* no KEY_CREATE_SUB_KEY in the DACL: opening for it fails, and creating a subkey in the parent
     * through a handle that has KEY_READ only is refused (ERROR_ACCESS_DENIED) */
    Error = RegOpenKeyExW(HKEY_CURRENT_USER, CreateParent, 0, KEY_CREATE_SUB_KEY, &Deny);
    CHK(1, Error == ERROR_ACCESS_DENIED, "open parent for KEY_CREATE_SUB_KEY: error %ld, expected 5\n", Error);
    if (!Error)
        RegCloseKey(Deny);
    Error = RegOpenKeyExW(HKEY_CURRENT_USER, CreateParent, 0, KEY_SET_VALUE, &Deny);
    CHK(1, Error == ERROR_ACCESS_DENIED, "open parent for KEY_SET_VALUE: error %ld, expected 5\n", Error);
    if (!Error)
        RegCloseKey(Deny);
    Error = RegOpenKeyExW(HKEY_CURRENT_USER, CreateParent, 0, KEY_READ, &Deny);
    ok_long(Error, ERROR_SUCCESS);
    if (!Error)
    {
        Error = RegCreateKeyExW(Deny, L"child", 0, NULL, REG_OPTION_VOLATILE, KEY_READ, NULL, &Child, &Disp);
        CHK(1, Error == ERROR_ACCESS_DENIED, "create under a KEY_READ-only handle: error %ld, expected 5\n", Error);
        if (!Error)
        {
            RegCloseKey(Child);
            RegDeleteKeyW(Deny, L"child");
        }
        RegCloseKey(Deny);
    }

    /* add KEY_CREATE_SUB_KEY: now the open and the create work */
    StringCchPrintfW(Sddl, RTL_NUMBER_OF(Sddl), L"O:%lsG:SYD:P(A;CI;0x2001d;;;%ls)(A;CI;GA;;;CO)", OwnerText, UserText);
    Error = SetKeyDaclSddl(Parent, Sddl);
    ok_long(Error, ERROR_SUCCESS);
    Error = RegOpenKeyExW(HKEY_CURRENT_USER, CreateParent, 0, KEY_CREATE_SUB_KEY | KEY_READ, &Deny);
    ok_long(Error, ERROR_SUCCESS);
    if (!Error)
    {
        /* the creator gets what it asked for on the new handle even when the new DACL
         * (inherited from the parent) would not grant it: KEY_ALL_ACCESS here */
        Error = RegCreateKeyExW(Deny, L"child", 0, NULL, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, NULL, &Child, &Disp);
        ok_long(Error, ERROR_SUCCESS);
        if (!Error)
        {
            /* inheritance: the CI ACEs of the parent became ACEs of the child. The user's ACE is
             * explicit (no INHERITED_ACE bit: the kernel create path does not set it), the CREATOR
             * OWNER ACE became an ACE for the owner of the child */
            Error = GetKeySd(Child, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &Sd);
            ok_long(Error, ERROR_SUCCESS);
            if (!Error)
            {
                Dacl = SdDacl(Sd, &Present);
                Mask = 0;
                Flags = 0;
                CHK(0, Dacl && FindAce(Dacl, User, ACCESS_ALLOWED_ACE_TYPE, &Mask, &Flags) && Mask == 0x2001d &&
                    !(Flags & INHERITED_ACE),
                    "child: the inherited user ACE has mask 0x%lx flags 0x%x, expected 0x2001d without INHERITED_ACE\n",
                    (ULONG)Mask, Flags);
                Mask = 0;
                CHK(0, Dacl && FindAce(Dacl, Owner, ACCESS_ALLOWED_ACE_TYPE, &Mask, NULL) && (Mask & KEY_A) == KEY_A,
                    "child: the CREATOR OWNER ACE did not become an owner ACE (mask 0x%lx)\n", (ULONG)Mask);
                CHK(0, SdOwner(Sd) && EqualSid(SdOwner(Sd), Owner), "child: owner is not the token owner\n");
                LocalFree(Sd);
            }
            RegCloseKey(Child);
            RegDeleteKeyW(Deny, L"child");
        }
        RegCloseKey(Deny);
    }

    /* the parent's DACL is restored for the cleanup */
    StringCchPrintfW(Sddl, RTL_NUMBER_OF(Sddl), L"O:%lsG:SYD:P(A;CI;GA;;;%ls)", OwnerText, UserText);
    {
        HKEY Fix;

        if (RegOpenKeyExW(HKEY_CURRENT_USER, CreateParent, 0, WRITE_DAC | READ_CONTROL, &Fix) == ERROR_SUCCESS)
        {
            SetKeyDaclSddl(Fix, Sddl);
            RegCloseKey(Fix);
        }
    }
    RegCloseKey(Parent);
    RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\ReactOS-apitest-RegSecurityCreate\\child");
    RegDeleteKeyW(HKEY_CURRENT_USER, CreateParent);

Done:
    LocalFree(UserText);
    LocalFree(OwnerText);
    LocalFree(User);
    LocalFree(Owner);
}
