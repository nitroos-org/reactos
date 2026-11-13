/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Kernel-Mode Test Suite: the owner and SACL a user-mode caller
 *              may give a new registry key in its explicit descriptor
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * A key stores the descriptor it is created with, so the explicit one must be
 * one the caller may assign. The expected statuses are those of Windows 10
 * 22H2 for the same NtCreateKey calls (oracle probe of the registry ACL
 * follow-up, run as an administrator with the privileges set per token):
 *  - a SACL (present: with an audit ACE, NULL or empty) needs
 *    SeSecurityPrivilege enabled: STATUS_PRIVILEGE_NOT_HELD; a SACL with only
 *    mandatory label ACEs does not; the SACL is checked before the owner;
 *  - the owner must be the token user or a group with SE_GROUP_OWNER
 *    (Administrators in an administrator's token, not when it is deny-only),
 *    else SeRestorePrivilege enabled: STATUS_INVALID_OWNER;
 *    SeTakeOwnershipPrivilege and SeSecurityPrivilege do not help;
 *  - the primary group is not checked.
 * A create that fails leaves no key. (Windows created the key and still
 * returned STATUS_PRIVILEGE_NOT_HELD for a NULL SACL; this kernel creates
 * nothing.) In legacy mode (/REGACL=LEGACY) and while setup runs nothing is
 * stored and nothing is checked: every create succeeds, as before.
 */

#include <kmt_test.h>
#include <sddl.h>

#define STATS_KEY L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\RegAcl\\AuditStats"

enum { OK_ = 0, PRV, OWN };

static const struct
{
    PCSTR Name;
    PCWSTR Sddl;        /* %U: the token user */
    BOOLEAN NullSacl;
    UCHAR Expect[5];    /* T0 .. T4 */
} g_Cases[] =
{
    /*                                                                       T0   T1   T2   T3   T4 */
    { "dacl-only",       L"D:(A;;KA;;;WD)(A;;KA;;;BA)", FALSE,             { OK_, OK_, OK_, OK_, OK_ } },
    { "owner=user",      L"O:%UD:(A;;KA;;;WD)(A;;KA;;;BA)", FALSE,         { OK_, OK_, OK_, OK_, OK_ } },
    { "owner=BA",        L"O:BAD:(A;;KA;;;WD)(A;;KA;;;BA)", FALSE,         { OK_, OK_, OK_, OK_, OWN } },
    { "owner=SY",        L"O:SYD:(A;;KA;;;WD)(A;;KA;;;BA)", FALSE,         { OWN, OK_, OWN, OWN, OWN } },
    { "owner=BU",        L"O:BUD:(A;;KA;;;WD)(A;;KA;;;BA)", FALSE,         { OWN, OK_, OWN, OWN, OWN } },
    { "group=SY",        L"G:SYD:(A;;KA;;;WD)(A;;KA;;;BA)", FALSE,         { OK_, OK_, OK_, OK_, OK_ } },
    { "sacl-audit",      L"D:(A;;KA;;;WD)(A;;KA;;;BA)S:(AU;SA;KA;;;WD)", FALSE, { PRV, PRV, OK_, PRV, PRV } },
    { "sacl-null",       L"D:(A;;KA;;;WD)(A;;KA;;;BA)", TRUE,              { PRV, PRV, OK_, PRV, PRV } },
    { "sacl-empty",      L"D:(A;;KA;;;WD)(A;;KA;;;BA)S:", FALSE,           { PRV, PRV, OK_, PRV, PRV } },
    { "label-low",       L"D:(A;;KA;;;WD)(A;;KA;;;BA)S:(ML;;NW;;;LW)", FALSE, { OK_, OK_, OK_, OK_, OK_ } },
    { "owner=BU+audit",  L"O:BUD:(A;;KA;;;WD)(A;;KA;;;BA)S:(AU;SA;KA;;;WD)", FALSE, { PRV, PRV, OWN, PRV, PRV } },
    { "audit+label-low", L"D:(A;;KA;;;WD)(A;;KA;;;BA)S:(AU;SA;KA;;;WD)(ML;;NW;;;LW)", FALSE, { PRV, PRV, OK_, PRV, PRV } },
};

static const PCSTR g_TokenNames[5] = { "admin, privileges off", "+SeRestore", "+SeSecurity", "+SeTakeOwnership",
                                       "filtered (Administrators deny-only, no privileges)" };
static const PCWSTR g_Off[] = { L"SeRestorePrivilege", L"SeSecurityPrivilege", L"SeTakeOwnershipPrivilege",
                                L"SeRelabelPrivilege", L"SeBackupPrivilege" };

static
BOOLEAN
SetPrivilege(
    _In_ HANDLE Token,
    _In_ PCWSTR Name,
    _In_ DWORD Attributes)
{
    TOKEN_PRIVILEGES Tp;

    if (!LookupPrivilegeValueW(NULL, Name, &Tp.Privileges[0].Luid))
        return FALSE;
    Tp.PrivilegeCount = 1;
    Tp.Privileges[0].Attributes = Attributes;
    if (!AdjustTokenPrivileges(Token, FALSE, &Tp, 0, NULL, NULL))
        return FALSE;
    return GetLastError() == ERROR_SUCCESS;
}

/* Is Administrators an owner-capable group of the token (an elevated administrator) */
static
BOOLEAN
AdminOwner(
    _In_ HANDLE Token)
{
    UCHAR Buffer[4096];
    PTOKEN_GROUPS Groups = (PTOKEN_GROUPS)Buffer;
    UCHAR Sid[SECURITY_MAX_SID_SIZE];
    DWORD Length = sizeof(Sid), i;

    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, Sid, &Length) ||
        !GetTokenInformation(Token, TokenGroups, Buffer, sizeof(Buffer), &Length))
    {
        return FALSE;
    }
    for (i = 0; i < Groups->GroupCount; i++)
    {
        if (EqualSid(Groups->Groups[i].Sid, Sid))
            return (Groups->Groups[i].Attributes & SE_GROUP_OWNER) &&
                   !(Groups->Groups[i].Attributes & SE_GROUP_USE_FOR_DENY_ONLY);
    }
    return FALSE;
}

/* AuditStats\StoresDescriptors: 0 in legacy mode and while setup runs; missing on a kernel without it */
static
ULONG
StoresDescriptors(VOID)
{
    UNICODE_STRING Path = RTL_CONSTANT_STRING(STATS_KEY), Name = RTL_CONSTANT_STRING(L"StoresDescriptors");
    OBJECT_ATTRIBUTES ObjectAttributes;
    UCHAR Buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION Info = (PKEY_VALUE_PARTIAL_INFORMATION)Buffer;
    HANDLE Key;
    ULONG Length, Result = 1;

    InitializeObjectAttributes(&ObjectAttributes, &Path, OBJ_CASE_INSENSITIVE, NULL, NULL);
    if (NT_SUCCESS(NtOpenKey(&Key, KEY_QUERY_VALUE, &ObjectAttributes)))
    {
        if (NT_SUCCESS(NtQueryValueKey(Key, &Name, KeyValuePartialInformation, Info, sizeof(Buffer), &Length)) &&
            Info->Type == REG_DWORD && Info->DataLength == sizeof(ULONG))
        {
            Result = *(PULONG)Info->Data;
        }
        NtClose(Key);
    }
    return Result;
}

static
NTSTATUS
CreateKey(
    _In_ PCWSTR Path,
    _In_opt_ PSECURITY_DESCRIPTOR Sd,
    _Out_ PHANDLE Key)
{
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES ObjectAttributes;

    RtlInitUnicodeString(&Name, Path);
    InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_CASE_INSENSITIVE, NULL, Sd);
    *Key = NULL;
    return NtCreateKey(Key, KEY_ALL_ACCESS, &ObjectAttributes, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
}

static
BOOLEAN
KeyExists(
    _In_ PCWSTR Path)
{
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE Key;
    NTSTATUS Status;

    RtlInitUnicodeString(&Name, Path);
    InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenKey(&Key, KEY_READ, &ObjectAttributes);
    if (NT_SUCCESS(Status))
        NtClose(Key);
    return NT_SUCCESS(Status);
}

static
VOID
Expand(
    _In_ PCWSTR In,
    _In_ PCWSTR User,
    _Out_writes_(Chars) PWSTR Out,
    _In_ SIZE_T Chars)
{
    SIZE_T o = 0;

    for (; *In && o + 1 < Chars; In++)
    {
        if (In[0] == L'%' && In[1] == L'U')
        {
            SIZE_T n = wcslen(User);
            if (o + n + 1 >= Chars)
                break;
            wcscpy(Out + o, User);
            o += n;
            In++;
        }
        else
        {
            Out[o++] = *In;
        }
    }
    Out[o] = 0;
}

START_TEST(CmCreatorSd)
{
    static const NTSTATUS Statuses[] = { STATUS_SUCCESS, STATUS_PRIVILEGE_NOT_HELD, STATUS_INVALID_OWNER };
    HANDLE Process, Filtered, Token[5] = { NULL }, Root, Key;
    UCHAR Buffer[512], BaSid[SECURITY_MAX_SID_SIZE];
    SID_AND_ATTRIBUTES Disable;
    BOOLEAN Usable[5] = { TRUE, TRUE, TRUE, TRUE, TRUE }, Checked, Admin;
    WCHAR RootPath[300], Path[340], Sddl[400];
    PWSTR UserSid = NULL;
    DWORD Length, k;
    ULONG t, c;
    NTSTATUS Status, Want;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &Process))
    {
        skip(0, "no process token: %lu\n", GetLastError());
        return;
    }
    Length = sizeof(Buffer);
    ok(GetTokenInformation(Process, TokenUser, Buffer, sizeof(Buffer), &Length), "TokenUser\n");
    ok(ConvertSidToStringSidW(((PTOKEN_USER)Buffer)->User.Sid, &UserSid), "user SID\n");
    if (!UserSid)
        return;
    Admin = AdminOwner(Process);
    Checked = (StoresDescriptors() != 0);
    trace("user %S, Administrators owner-capable %d, descriptors stored (so checked) %d\n", UserSid, Admin, Checked);

    /* T0..T3: the process token with the privileges off, then one on; T4: filtered */
    for (t = 0; t < 4; t++)
    {
        if (!DuplicateTokenEx(Process, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &Token[t]))
        {
            Usable[t] = FALSE;
            continue;
        }
        for (k = 0; k < RTL_NUMBER_OF(g_Off); k++)
            SetPrivilege(Token[t], g_Off[k], 0);
    }
    if (Token[1] && !SetPrivilege(Token[1], L"SeRestorePrivilege", SE_PRIVILEGE_ENABLED))
        Usable[1] = FALSE;
    if (Token[2] && !SetPrivilege(Token[2], L"SeSecurityPrivilege", SE_PRIVILEGE_ENABLED))
        Usable[2] = FALSE;
    if (Token[3] && !SetPrivilege(Token[3], L"SeTakeOwnershipPrivilege", SE_PRIVILEGE_ENABLED))
        Usable[3] = FALSE;
    Length = sizeof(BaSid);
    CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, BaSid, &Length);
    Disable.Sid = BaSid;
    Disable.Attributes = 0;
    if (!CreateRestrictedToken(Process, DISABLE_MAX_PRIVILEGE, 1, &Disable, 0, NULL, 0, NULL, &Filtered) ||
        !DuplicateTokenEx(Filtered, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &Token[4]))
    {
        Usable[4] = FALSE;
    }
    else
    {
        CloseHandle(Filtered);
    }

    StringCchPrintfW(RootPath, RTL_NUMBER_OF(RootPath), L"\\Registry\\User\\%s\\Software\\KmtCmCreatorSd-%lu",
                     UserSid, GetCurrentProcessId());
    Status = CreateKey(RootPath, NULL, &Root);
    ok(Status == STATUS_SUCCESS, "root: 0x%08lx\n", Status);
    if (!NT_SUCCESS(Status))
        goto Cleanup;

    for (t = 0; t < 5; t++)
    {
        if (!Usable[t])
        {
            skip(0, "token %s: cannot be made here\n", g_TokenNames[t]);
            continue;
        }
        for (c = 0; c < RTL_NUMBER_OF(g_Cases); c++)
        {
            PSECURITY_DESCRIPTOR Sd = NULL;
            SECURITY_DESCRIPTOR Absolute;
            UCHAR Dacl[512], Sacl[128], Owner[SECURITY_MAX_SID_SIZE], Group[SECURITY_MAX_SID_SIZE];
            DWORD a = sizeof(Absolute), d = sizeof(Dacl), s = sizeof(Sacl), o = sizeof(Owner), g = sizeof(Group);
            PSECURITY_DESCRIPTOR Use;

            Expand(g_Cases[c].Sddl, UserSid, Sddl, RTL_NUMBER_OF(Sddl));
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(Sddl, SDDL_REVISION_1, &Sd, NULL))
            {
                ok(0, "%s: SDDL not converted: %lu\n", g_Cases[c].Name, GetLastError());
                continue;
            }
            Use = Sd;
            if (g_Cases[c].NullSacl)
            {
                ok(MakeAbsoluteSD(Sd, &Absolute, &a, (PACL)Dacl, &d, (PACL)Sacl, &s, Owner, &o, Group, &g),
                   "absolute\n");
                SetSecurityDescriptorSacl(&Absolute, TRUE, NULL, FALSE);
                Use = &Absolute;
            }

            StringCchPrintfW(Path, RTL_NUMBER_OF(Path), L"%s\\K%lu-%lu", RootPath, t, c);
            ok(SetThreadToken(NULL, Token[t]), "impersonate\n");
            Status = CreateKey(Path, Use, &Key);
            SetThreadToken(NULL, NULL);
            LocalFree(Sd);

            Want = STATUS_SUCCESS;
            if (Checked)
            {
                Want = Statuses[g_Cases[c].Expect[t]];
                /* An administrator that is not elevated owns nothing through Administrators */
                if (!Admin && t != 1 && t < 4 && Want == STATUS_SUCCESS && wcsstr(g_Cases[c].Sddl, L"O:BA"))
                    Want = STATUS_INVALID_OWNER;
            }
            ok(Status == Want, "token %s, %s: 0x%08lx, expected 0x%08lx\n",
               g_TokenNames[t], g_Cases[c].Name, Status, Want);
            if (NT_SUCCESS(Status))
            {
                ok(NT_SUCCESS(NtDeleteKey(Key)), "delete\n");
                NtClose(Key);
            }
            else
            {
                ok(!KeyExists(Path), "token %s, %s: the failed create left a key\n", g_TokenNames[t], g_Cases[c].Name);
            }
        }
    }

    ok(NT_SUCCESS(NtDeleteKey(Root)), "delete the root\n");
    NtClose(Root);
    ok(!KeyExists(RootPath), "the root is gone\n");

Cleanup:
    for (t = 0; t < 5; t++)
    {
        if (Token[t])
            CloseHandle(Token[t]);
    }
    CloseHandle(Process);
    LocalFree(UserSid);
}
