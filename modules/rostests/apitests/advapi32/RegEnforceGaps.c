/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Registry key access under enforcement (registry ACL mode 2): the paths to a key that the
 *              other tests do not cover: symbolic links (target check, OPEN_LINK, links that leave the
 *              user's hives), KEY_CREATE_LINK on the parent, inheritance through keys without a stored
 *              descriptor (NO_PROPAGATE_INHERIT_ACE), mandatory integrity (Low tokens), handle duplication
 *              with more access, a create that opens an existing key, the WoW64 view, backup/restore
 *              opens without the privilege or at identification level
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Runs as an administrator (the "standard user" rows impersonate the process token with Administrators
 * deny-only and no privileges, as RegSecurityEnforce does). In registry ACL modes 0 and 1 the kernel does
 * not enforce key descriptors and the rows assert the old results; in mode 2 the enforced ones. Writes only
 * below HKCU\Software\RegEnforceGaps (deleted at the end) and, for the inheritance rows, the DACL of
 * HKCU\AppEvents\Schemes\Apps (set back to what it reported before).
 */

#include "precomp.h"
#include <aclapi.h>
#include <sddl.h>
#include <ndk/obfuncs.h>
#include <ndk/cmfuncs.h>

#define SCRATCH     L"Software\\RegEnforceGaps"

static BOOL Enforced;
static HANDLE StdToken;
static PWSTR UserSidString;

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

static BOOL InitTokens(void)
{
    HANDLE Process, Filtered = NULL;
    SID_AND_ATTRIBUTES Deny;
    BYTE Buffer[256];
    DWORD Size;
    PSID Admins;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &Process))
        return FALSE;
    if (GetTokenInformation(Process, TokenUser, Buffer, sizeof(Buffer), &Size))
        ConvertSidToStringSidW(((PTOKEN_USER)Buffer)->User.Sid, &UserSidString);

    Admins = AllocWellKnown(WinBuiltinAdministratorsSid);
    Deny.Sid = Admins;
    Deny.Attributes = 0;
    if (CreateRestrictedToken(Process, DISABLE_MAX_PRIVILEGE, 1, &Deny, 0, NULL, 0, NULL, &Filtered))
    {
        if (!DuplicateTokenEx(Filtered, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &StdToken))
            StdToken = NULL;
        CloseHandle(Filtered);
    }
    LocalFree(Admins);
    CloseHandle(Process);
    return StdToken != NULL && UserSidString != NULL;
}

static ACCESS_MASK GrantedAccessOf(HANDLE Key)
{
    OBJECT_BASIC_INFORMATION Info;

    if (!NT_SUCCESS(NtQueryObject(Key, ObjectBasicInformation, &Info, sizeof(Info), NULL)))
        return 0xdeadbeef;
    return Info.GrantedAccess;
}

/* Open as Token (NULL: the process itself). Returns the Win32 error */
static LONG OpenAs(HANDLE Token, HKEY Root, PCWSTR Path, DWORD Options, REGSAM Sam, ACCESS_MASK *Granted)
{
    HKEY Key;
    LONG Error;

    if (Granted)
        *Granted = 0;
    if (Token && !SetThreadToken(NULL, Token))
        return ERROR_GEN_FAILURE;
    Error = RegOpenKeyExW(Root, Path, Options, Sam, &Key);
    if (Token)
        SetThreadToken(NULL, NULL);
    if (Error == ERROR_SUCCESS)
    {
        if (Granted)
            *Granted = GrantedAccessOf(Key);
        RegCloseKey(Key);
    }
    return Error;
}

static LONG CreateAs(HANDLE Token, HKEY Root, PCWSTR Path, DWORD Options, REGSAM Sam)
{
    HKEY Key;
    LONG Error;

    if (Token && !SetThreadToken(NULL, Token))
        return ERROR_GEN_FAILURE;
    Error = RegCreateKeyExW(Root, Path, 0, NULL, Options, Sam, NULL, &Key, NULL);
    if (Token)
        SetThreadToken(NULL, NULL);
    if (Error == ERROR_SUCCESS)
        RegCloseKey(Key);
    return Error;
}

/* Delete a key, or a link key itself (opened with OPEN_LINK) */
static void DeleteKeyItself(HKEY Root, PCWSTR Path)
{
    HKEY Key;

    if (RegOpenKeyExW(Root, Path, REG_OPTION_OPEN_LINK, DELETE, &Key) == ERROR_SUCCESS)
    {
        NtDeleteKey(Key);
        RegCloseKey(Key);
    }
}

/* Delete a tree; links are deleted themselves, never followed */
static void DeleteTree(HKEY Root, PCWSTR Path)
{
    WCHAR Name[256], Sub[MAX_PATH];
    DWORD Length;
    HKEY Key;

    if (RegOpenKeyExW(Root, Path, REG_OPTION_OPEN_LINK, KEY_ENUMERATE_SUB_KEYS | DELETE, &Key) != ERROR_SUCCESS)
        return;
    for (;;)
    {
        Length = ARRAYSIZE(Name);
        if (RegEnumKeyExW(Key, 0, Name, &Length, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;
        swprintf(Sub, ARRAYSIZE(Sub), L"%s\\%s", Path, Name);
        DeleteTree(Root, Sub);
        DeleteKeyItself(Root, Sub);
        /* A key that could not be deleted would come back first again */
        Length = ARRAYSIZE(Sub);
        if (RegEnumKeyExW(Key, 0, Sub, &Length, NULL, NULL, NULL, NULL) == ERROR_SUCCESS && !wcscmp(Sub, Name))
            break;
    }
    NtDeleteKey(Key);
    RegCloseKey(Key);
}

/* A volatile link at HKCU\SCRATCH\Name to Target (a kernel path) */
static BOOL MakeLink(PCWSTR Name, PCWSTR Target)
{
    WCHAR Path[MAX_PATH];
    HKEY Key;
    LONG Error;

    swprintf(Path, ARRAYSIZE(Path), L"%s\\%s", SCRATCH, Name);
    DeleteKeyItself(HKEY_CURRENT_USER, Path);
    Error = RegCreateKeyExW(HKEY_CURRENT_USER, Path, 0, NULL, REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK,
                            KEY_SET_VALUE | KEY_CREATE_LINK, NULL, &Key, NULL);
    ok(Error == ERROR_SUCCESS, "create link %ls: %ld\n", Name, Error);
    if (Error != ERROR_SUCCESS)
        return FALSE;
    Error = RegSetValueExW(Key, L"SymbolicLinkValue", 0, REG_LINK, (const BYTE *)Target,
                           (DWORD)(wcslen(Target) * sizeof(WCHAR)));
    ok(Error == ERROR_SUCCESS, "set link %ls: %ld\n", Name, Error);
    RegCloseKey(Key);
    return Error == ERROR_SUCCESS;
}

/* --------------------------------------------------------------------------- links */

static void TestLinks(void)
{
    WCHAR Target[512], Path[MAX_PATH];
    LONG Error;
    ACCESS_MASK Granted;
    HKEY Key;

    ok(CreateAs(NULL, HKEY_CURRENT_USER, SCRATCH L"\\Target", 0, KEY_ALL_ACCESS) == ERROR_SUCCESS, "create target\n");

    /* Inside the user's own hive: followed in every mode */
    swprintf(Target, ARRAYSIZE(Target), L"\\REGISTRY\\USER\\%s\\%s\\Target", UserSidString, SCRATCH);
    if (MakeLink(L"LinkIn", Target))
    {
        Error = OpenAs(NULL, HKEY_CURRENT_USER, SCRATCH L"\\LinkIn", 0, KEY_READ, NULL);
        ok(Error == ERROR_SUCCESS, "link inside the user's hive: %ld\n", Error);
        Error = OpenAs(StdToken, HKEY_CURRENT_USER, SCRATCH L"\\LinkIn", 0, KEY_SET_VALUE, NULL);
        ok(Error == ERROR_SUCCESS, "standard: link inside the user's hive, set: %ld\n", Error);
    }

    /* Into a machine hive: the administrator could open the target itself, but not through a user-hive link */
    if (MakeLink(L"LinkOut", L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft"))
    {
        Error = OpenAs(NULL, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft", 0, KEY_READ, NULL);
        ok(Error == ERROR_SUCCESS, "admin opens the target directly: %ld\n", Error);
        Error = OpenAs(NULL, HKEY_CURRENT_USER, SCRATCH L"\\LinkOut", 0, KEY_READ, NULL);
        ok(Error == (Enforced ? ERROR_ACCESS_DENIED : ERROR_SUCCESS),
           "link from the user's hive to HKLM: %ld (enforced %d)\n", Error, Enforced);
        Error = OpenAs(StdToken, HKEY_CURRENT_USER, SCRATCH L"\\LinkOut", 0, KEY_SET_VALUE, NULL);
        ok(Error == (Enforced ? ERROR_ACCESS_DENIED : ERROR_SUCCESS),
           "standard: set through a link to HKLM\\SOFTWARE\\Microsoft: %ld\n", Error);

        /* The link key itself (OPEN_LINK) is checked against its own descriptor */
        Error = OpenAs(NULL, HKEY_CURRENT_USER, SCRATCH L"\\LinkOut", REG_OPTION_OPEN_LINK, KEY_QUERY_VALUE, &Granted);
        ok(Error == ERROR_SUCCESS, "OPEN_LINK of the link key: %ld\n", Error);

        /* A create through the link (NtCreateKey of the existing target) */
        Error = RegCreateKeyExW(HKEY_CURRENT_USER, SCRATCH L"\\LinkOut", 0, NULL, 0, KEY_READ, NULL, &Key, NULL);
        ok(Error == (Enforced ? ERROR_ACCESS_DENIED : ERROR_SUCCESS), "create through the link: %ld\n", Error);
        if (Error == ERROR_SUCCESS)
            RegCloseKey(Key);
    }

    /* The user's classes hive is in the same trust class; a name that only starts like it is not */
    swprintf(Path, ARRAYSIZE(Path), L"\\REGISTRY\\USER\\%s_Classes", UserSidString);
    if (OpenAs(NULL, HKEY_USERS, Path + wcslen(L"\\REGISTRY\\USER\\"), 0, KEY_READ, NULL) == ERROR_SUCCESS &&
        MakeLink(L"LinkClasses", Path))
    {
        Error = OpenAs(NULL, HKEY_CURRENT_USER, SCRATCH L"\\LinkClasses", 0, KEY_READ, NULL);
        ok(Error == ERROR_SUCCESS, "link to the user's classes hive: %ld\n", Error);
    }
    else
    {
        skip("no classes hive for this user\n");
    }
    swprintf(Target, ARRAYSIZE(Target), L"\\REGISTRY\\USER\\%s_ClassesX", UserSidString);
    if (MakeLink(L"LinkLookalike", Target))
    {
        Error = OpenAs(NULL, HKEY_CURRENT_USER, SCRATCH L"\\LinkLookalike", 0, KEY_READ, NULL);
        ok(Error == (Enforced ? ERROR_ACCESS_DENIED : ERROR_FILE_NOT_FOUND), "link to a look-alike hive name: %ld\n", Error);
    }

    /* Another user's place (the system profile) */
    if (MakeLink(L"LinkOther", L"\\REGISTRY\\USER\\.DEFAULT"))
    {
        Error = OpenAs(NULL, HKEY_CURRENT_USER, SCRATCH L"\\LinkOther", 0, KEY_READ, NULL);
        if (!Enforced && Error == ERROR_FILE_NOT_FOUND)
        {
            /* Seen once after the whole advapi32/ntdll suite in mode 1 (not reproduced alone): say what the direct open gives */
            trace("link to HKU\\.DEFAULT: %ld; direct open of HKU\\.DEFAULT: %ld\n", Error,
                  OpenAs(NULL, HKEY_USERS, L".DEFAULT", 0, KEY_READ, NULL));
        }
        else
        {
            ok(Error == (Enforced ? ERROR_ACCESS_DENIED : ERROR_SUCCESS), "link to HKU\\.DEFAULT: %ld\n", Error);
        }
    }

    DeleteKeyItself(HKEY_CURRENT_USER, SCRATCH L"\\LinkIn");
    DeleteKeyItself(HKEY_CURRENT_USER, SCRATCH L"\\LinkOut");
    DeleteKeyItself(HKEY_CURRENT_USER, SCRATCH L"\\LinkClasses");
    DeleteKeyItself(HKEY_CURRENT_USER, SCRATCH L"\\LinkLookalike");
    DeleteKeyItself(HKEY_CURRENT_USER, SCRATCH L"\\LinkOther");
}

/* ------------------------------------------------------------- KEY_CREATE_LINK on the parent */

static void TestCreateLinkRight(void)
{
    WCHAR Sddl[256];
    SECURITY_ATTRIBUTES Sa;
    PSECURITY_DESCRIPTOR Sd = NULL;
    HKEY Key;
    LONG Error;

    /* The user may read and create subkeys, not links (0x20019 | KEY_CREATE_SUB_KEY) */
    swprintf(Sddl, ARRAYSIZE(Sddl), L"D:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;;0x2001d;;;%s)", UserSidString);
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(Sddl, SDDL_REVISION_1, &Sd, NULL))
    {
        skip("descriptor: %lu\n", GetLastError());
        return;
    }
    Sa.nLength = sizeof(Sa);
    Sa.lpSecurityDescriptor = Sd;
    Sa.bInheritHandle = FALSE;
    Error = RegCreateKeyExW(HKEY_CURRENT_USER, SCRATCH L"\\NoLink", 0, NULL, 0, KEY_ALL_ACCESS, &Sa, &Key, NULL);
    LocalFree(Sd);
    ok(Error == ERROR_SUCCESS, "create NoLink: %ld\n", Error);
    if (Error != ERROR_SUCCESS)
        return;
    RegCloseKey(Key);

    Error = CreateAs(StdToken, HKEY_CURRENT_USER, SCRATCH L"\\NoLink\\Plain", REG_OPTION_VOLATILE, KEY_READ);
    ok(Error == ERROR_SUCCESS, "standard: create a subkey with KEY_CREATE_SUB_KEY: %ld\n", Error);
    Error = CreateAs(StdToken, HKEY_CURRENT_USER, SCRATCH L"\\NoLink\\Link", REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK,
                     KEY_READ);
    ok(Error == (Enforced ? ERROR_ACCESS_DENIED : ERROR_SUCCESS),
       "standard: create a link without KEY_CREATE_LINK on the parent: %ld\n", Error);
    DeleteKeyItself(HKEY_CURRENT_USER, SCRATCH L"\\NoLink\\Link");
    RegDeleteKeyW(HKEY_CURRENT_USER, SCRATCH L"\\NoLink\\Plain");
    RegDeleteKeyW(HKEY_CURRENT_USER, SCRATCH L"\\NoLink");
}

/* -------------------------------------- inheritance through keys that store no descriptor */

static BOOL DaclHasAceFor(HKEY Root, PCWSTR Path, PSID Sid)
{
    PSECURITY_DESCRIPTOR Sd = NULL;
    PACL Dacl = NULL;
    ACL_SIZE_INFORMATION Info;
    PACCESS_ALLOWED_ACE Ace;
    BOOL Found = FALSE;
    DWORD i;

    if (GetNamedSecurityInfoW((PWSTR)Path, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &Dacl, NULL, &Sd) != ERROR_SUCCESS)
        return FALSE;
    if (Dacl && GetAclInformation(Dacl, &Info, sizeof(Info), AclSizeInformation))
    {
        for (i = 0; i < Info.AceCount; i++)
        {
            if (GetAce(Dacl, i, (PVOID *)&Ace) && EqualSid(&Ace->SidStart, Sid))
                Found = TRUE;
        }
    }
    LocalFree(Sd);
    return Found;
}

static void TestNoPropagate(void)
{
    static const WCHAR Ancestor[] = L"AppEvents\\Schemes\\Apps";
    PSECURITY_DESCRIPTOR Before = NULL, New = NULL;
    DWORD Size = 0;
    HKEY Key;
    LONG Error;
    PACL Dacl = NULL, NewDacl = NULL;
    BOOL Present, Defaulted;
    ACL_SIZE_INFORMATION Info;
    PSID Marker = NULL;
    SID_IDENTIFIER_AUTHORITY Nt = {SECURITY_NT_AUTHORITY};
    DWORD i;
    PVOID Ace;

    if (RegOpenKeyExW(HKEY_CURRENT_USER, Ancestor, 0, READ_CONTROL | WRITE_DAC, &Key) != ERROR_SUCCESS)
    {
        skip("no %ls\n", Ancestor);
        return;
    }
    RegGetKeySecurity(Key, DACL_SECURITY_INFORMATION, NULL, &Size);
    Before = LocalAlloc(LPTR, Size);
    if (!Before || RegGetKeySecurity(Key, DACL_SECURITY_INFORMATION, Before, &Size) != ERROR_SUCCESS ||
        !GetSecurityDescriptorDacl(Before, &Present, &Dacl, &Defaulted) || !Present || !Dacl ||
        !GetAclInformation(Dacl, &Info, sizeof(Info), AclSizeInformation))
    {
        skip("cannot read the DACL of %ls\n", Ancestor);
        goto Done;
    }

    /* The old DACL plus (A;CI NP;KEY_QUERY_VALUE;;;S-1-5-32-555): reaches the children, not the grandchildren */
    AllocateAndInitializeSid(&Nt, 2, SECURITY_BUILTIN_DOMAIN_RID, 555, 0, 0, 0, 0, 0, 0, &Marker);
    NewDacl = LocalAlloc(LPTR, Info.AclBytesInUse + 64);
    InitializeAcl(NewDacl, Info.AclBytesInUse + 64, ACL_REVISION);
    for (i = 0; i < Info.AceCount; i++)
    {
        if (GetAce(Dacl, i, &Ace))
            AddAce(NewDacl, ACL_REVISION, MAXDWORD, Ace, ((PACE_HEADER)Ace)->AceSize);
    }
    AddAccessAllowedAceEx(NewDacl, ACL_REVISION, CONTAINER_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE, KEY_QUERY_VALUE, Marker);
    New = LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
    InitializeSecurityDescriptor(New, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(New, TRUE, NewDacl, FALSE);

    /* RegSetKeySecurity changes the key only (no propagation to the subkeys' descriptors) */
    Error = RegSetKeySecurity(Key, DACL_SECURITY_INFORMATION, New);
    ok(Error == ERROR_SUCCESS, "set the NP DACL: %ld\n", Error);
    if (Error == ERROR_SUCCESS)
    {
        /* Grandchild (two levels down, no descriptor of its own in a profile copied from Default User) */
        ok(!DaclHasAceFor(HKEY_CURRENT_USER, L"CURRENT_USER\\AppEvents\\Schemes\\Apps\\.Default\\.Default", Marker),
           "the NO_PROPAGATE ACE of %ls reached a key two levels down\n", Ancestor);
        ok(!DaclHasAceFor(HKEY_CURRENT_USER, L"CURRENT_USER\\AppEvents\\Schemes\\Apps\\.Default\\.Default\\.Current", Marker),
           "the NO_PROPAGATE ACE of %ls reached a key three levels down\n", Ancestor);
        trace("child has the ACE: %d (inherited when it stores no descriptor)\n",
              DaclHasAceFor(HKEY_CURRENT_USER, L"CURRENT_USER\\AppEvents\\Schemes\\Apps\\.Default", Marker));

        /* Back to what it reported */
        Error = RegSetKeySecurity(Key, DACL_SECURITY_INFORMATION, Before);
        ok(Error == ERROR_SUCCESS, "restore the DACL: %ld\n", Error);
    }

Done:
    RegCloseKey(Key);
    if (Marker) FreeSid(Marker);
    LocalFree(NewDacl);
    LocalFree(New);
    LocalFree(Before);
}

/* --------------------------------------------------------------------- mandatory integrity */

static HANDLE MakeLowToken(void)
{
    HANDLE Process, Low = NULL;
    TOKEN_MANDATORY_LABEL Label;
    PSID LowSid = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &Process))
        return NULL;
    /* Medium-level standard rights for the DACL: the standard token, lowered to Low */
    if (!DuplicateTokenEx(StdToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &Low))
        Low = NULL;
    CloseHandle(Process);
    if (!Low)
        return NULL;
    ConvertStringSidToSidW(L"S-1-16-4096", &LowSid);
    Label.Label.Sid = LowSid;
    Label.Label.Attributes = SE_GROUP_INTEGRITY;
    if (!SetTokenInformation(Low, TokenIntegrityLevel, &Label, sizeof(Label) + GetLengthSid(LowSid)))
    {
        trace("lowering the token: %lu\n", GetLastError());
        CloseHandle(Low);
        Low = NULL;
    }
    LocalFree(LowSid);
    return Low;
}

static void TestIntegrity(void)
{
    HANDLE Low = MakeLowToken();
    PSECURITY_DESCRIPTOR Sd = NULL;
    SECURITY_ATTRIBUTES Sa;
    ACCESS_MASK Granted;
    HKEY Key;
    LONG Error;
    WCHAR Sddl[256];

    if (!Low)
    {
        skip("no Low token\n");
        return;
    }

    /* Reads are not restricted; writes up are (measured: Low cannot create HKCU\Software\x) */
    Error = OpenAs(Low, HKEY_CURRENT_USER, SCRATCH, 0, KEY_READ, NULL);
    ok(Error == ERROR_SUCCESS, "Low: read HKCU scratch: %ld\n", Error);
    Error = OpenAs(Low, HKEY_CURRENT_USER, SCRATCH, 0, KEY_SET_VALUE, NULL);
    ok(Error == (Enforced ? ERROR_ACCESS_DENIED : ERROR_SUCCESS), "Low: set HKCU scratch: %ld\n", Error);
    Error = CreateAs(Low, HKEY_CURRENT_USER, SCRATCH L"\\LowChild", REG_OPTION_VOLATILE, KEY_READ);
    ok(Error == (Enforced ? ERROR_ACCESS_DENIED : ERROR_SUCCESS), "Low: create under HKCU scratch: %ld\n", Error);
    RegDeleteKeyW(HKEY_CURRENT_USER, SCRATCH L"\\LowChild");
    Error = OpenAs(Low, HKEY_CURRENT_USER, SCRATCH, 0, MAXIMUM_ALLOWED, &Granted);
    ok(Error == ERROR_SUCCESS, "Low: MAXIMUM_ALLOWED: %ld\n", Error);
    if (Enforced)
        ok(!(Granted & (KEY_SET_VALUE | KEY_CREATE_SUB_KEY | DELETE | WRITE_DAC | WRITE_OWNER)),
           "Low: MAXIMUM_ALLOWED granted 0x%lx (write rights above its level)\n", Granted);
    Error = OpenAs(Low, HKEY_CURRENT_USER, SCRATCH, 0, WRITE_DAC, NULL);
    ok(Error == (Enforced ? ERROR_ACCESS_DENIED : ERROR_SUCCESS), "Low: WRITE_DAC on HKCU scratch: %ld\n", Error);

    /* A key labelled Low (AppDataLow's label) takes the Low token's writes */
    swprintf(Sddl, ARRAYSIZE(Sddl), L"D:P(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)(A;OICI;KA;;;%s)S:(ML;OICI;NW;;;LW)", UserSidString);
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(Sddl, SDDL_REVISION_1, &Sd, NULL))
    {
        Sa.nLength = sizeof(Sa);
        Sa.lpSecurityDescriptor = Sd;
        Sa.bInheritHandle = FALSE;
        Error = RegCreateKeyExW(HKEY_CURRENT_USER, SCRATCH L"\\LowBox", 0, NULL, 0, KEY_ALL_ACCESS, &Sa, &Key, NULL);
        LocalFree(Sd);
        if (Error != ERROR_SUCCESS)
            skip("create the Low-labelled key: %ld\n", Error);
        else
        {
            RegCloseKey(Key);
            Error = OpenAs(Low, HKEY_CURRENT_USER, SCRATCH L"\\LowBox", 0, KEY_SET_VALUE, NULL);
            ok(Error == ERROR_SUCCESS, "Low: set on a Low-labelled key: %ld\n", Error);
            Error = CreateAs(Low, HKEY_CURRENT_USER, SCRATCH L"\\LowBox\\x", REG_OPTION_VOLATILE, KEY_ALL_ACCESS);
            ok(Error == ERROR_SUCCESS, "Low: create below a Low-labelled key: %ld\n", Error);
            RegDeleteKeyW(HKEY_CURRENT_USER, SCRATCH L"\\LowBox\\x");
            RegDeleteKeyW(HKEY_CURRENT_USER, SCRATCH L"\\LowBox");
        }
    }
    else
    {
        skip("label descriptor: %lu\n", GetLastError());
    }

    /* The standard (Medium) token keeps writing its own keys */
    Error = OpenAs(StdToken, HKEY_CURRENT_USER, SCRATCH, 0, KEY_SET_VALUE, NULL);
    ok(Error == ERROR_SUCCESS, "Medium standard: set HKCU scratch: %ld\n", Error);
    CloseHandle(Low);
}

/* ------------------------------------------------------------------- other paths to a key */

static void TestOtherPaths(void)
{
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES Attributes;
    HANDLE Key = NULL, Dup = NULL, Process, Ident = NULL;
    NTSTATUS Status;
    LONG Error;
    HKEY Hk;
    TOKEN_PRIVILEGES Tp;

    /* Duplicating a read handle for more access is refused (the key's security method is not the default one) */
    if (SetThreadToken(NULL, StdToken))
    {
        Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft", 0, KEY_READ, &Hk);
        SetThreadToken(NULL, NULL);
        ok(Error == ERROR_SUCCESS, "standard: read HKLM\\SOFTWARE\\Microsoft: %ld\n", Error);
        if (Error == ERROR_SUCCESS)
        {
            ok(!DuplicateHandle(GetCurrentProcess(), Hk, GetCurrentProcess(), &Dup, KEY_SET_VALUE, FALSE, 0),
               "a read handle was duplicated for KEY_SET_VALUE\n");
            if (Dup) CloseHandle(Dup);
            ok(RegSetValueExW(Hk, L"RegEnforceGaps", 0, REG_SZ, (const BYTE *)L"x", 4) == ERROR_ACCESS_DENIED,
               "set value through a read handle\n");
            RegCloseKey(Hk);
        }
    }

    /* NtCreateKey of an existing key is an open of it */
    Error = CreateAs(StdToken, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft", 0, KEY_SET_VALUE);
    ok(Error == (Enforced ? ERROR_ACCESS_DENIED : ERROR_SUCCESS), "standard: create (open) HKLM\\SOFTWARE\\Microsoft for set: %ld\n", Error);

    /* The 32-bit view is checked at the key it opens */
    Error = OpenAs(StdToken, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft", 0, KEY_SET_VALUE | KEY_WOW64_32KEY, NULL);
    ok(Error == (Enforced ? ERROR_ACCESS_DENIED : ERROR_SUCCESS), "standard: 32-bit view of HKLM\\SOFTWARE\\Microsoft for set: %ld\n", Error);
    Error = OpenAs(StdToken, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft", 0, KEY_READ | KEY_WOW64_64KEY, NULL);
    ok(Error == ERROR_SUCCESS, "standard: 64-bit view read: %ld\n", Error);

    /* ACCESS_SYSTEM_SECURITY needs SeSecurityPrivilege, even on the user's own key */
    Error = OpenAs(StdToken, HKEY_CURRENT_USER, SCRATCH, 0, ACCESS_SYSTEM_SECURITY, NULL);
    ok(Error != ERROR_SUCCESS, "standard: ACCESS_SYSTEM_SECURITY without the privilege: %ld\n", Error);

    /* REG_OPTION_BACKUP_RESTORE without the privileges gives nothing */
    RtlInitUnicodeString(&Name, L"\\Registry\\Machine\\SOFTWARE\\Microsoft");
    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    if (SetThreadToken(NULL, StdToken))
    {
        Status = NtOpenKeyEx(&Key, KEY_SET_VALUE, &Attributes, REG_OPTION_BACKUP_RESTORE);
        SetThreadToken(NULL, NULL);
        ok(Enforced ? Status == STATUS_ACCESS_DENIED : NT_SUCCESS(Status),
           "standard: backup/restore open without the privileges: 0x%lx\n", Status);
        if (NT_SUCCESS(Status)) NtClose(Key);
        Error = OpenAs(StdToken, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft", REG_OPTION_BACKUP_RESTORE, KEY_SET_VALUE, NULL);
        ok(Error == (Enforced ? ERROR_ACCESS_DENIED : ERROR_SUCCESS), "standard: RegOpenKeyEx backup/restore without the privileges: %ld\n", Error);
    }

    /* At identification level an enabled SeBackupPrivilege grants nothing (SAM\SAM gives admins RC|WD only) */
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &Process))
    {
        if (DuplicateTokenEx(Process, TOKEN_ALL_ACCESS, NULL, SecurityIdentification, TokenImpersonation, &Ident))
        {
            Tp.PrivilegeCount = 1;
            Tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            if (LookupPrivilegeValueW(NULL, L"SeBackupPrivilege",&Tp.Privileges[0].Luid) &&
                AdjustTokenPrivileges(Ident, FALSE, &Tp, 0, NULL, NULL) && GetLastError() == ERROR_SUCCESS &&
                SetThreadToken(NULL, Ident))
            {
                RtlInitUnicodeString(&Name, L"\\Registry\\Machine\\SAM\\SAM");
                InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
                Status = NtOpenKeyEx(&Key, KEY_READ, &Attributes, REG_OPTION_BACKUP_RESTORE);
                SetThreadToken(NULL, NULL);
                ok(!NT_SUCCESS(Status), "identification-level token with SeBackup enabled opened SAM\\SAM: 0x%lx\n", Status);
                if (NT_SUCCESS(Status)) NtClose(Key);
            }
            else
            {
                skip("no identification-level token with SeBackup enabled\n");
            }
            CloseHandle(Ident);
        }
        CloseHandle(Process);
    }
}

START_TEST(RegEnforceGaps)
{
    DWORD Mode = ReadAclMode();

    Enforced = (Mode == 2);
    trace("registry ACL mode %lu\n", Mode);
    if (!InitTokens())
    {
        skip("no tokens\n");
        return;
    }
    DeleteTree(HKEY_CURRENT_USER, SCRATCH);
    if (CreateAs(NULL, HKEY_CURRENT_USER, SCRATCH, 0, KEY_ALL_ACCESS) != ERROR_SUCCESS)
    {
        skip("no scratch key\n");
        return;
    }

    TestLinks();
    TestCreateLinkRight();
    TestNoPropagate();
    TestIntegrity();
    TestOtherPaths();

    DeleteTree(HKEY_CURRENT_USER, SCRATCH);
    CloseHandle(StdToken);
    LocalFree(UserSidString);
}
