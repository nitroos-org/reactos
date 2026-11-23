/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Which tokens a process of Low or Untrusted integrity gets a changeable duplicate of
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <ndk/obfuncs.h>

/*
 * Measured on Windows Server 2022 (64 and 32 bit): a process of Low or Untrusted integrity that duplicates a token
 * is granted, on the duplicate, the requested access limited to ASSIGN_PRIMARY, DUPLICATE, IMPERSONATE, QUERY,
 * QUERY_SOURCE and READ_CONTROL (nothing for MAXIMUM_ALLOWED, 0x2001f for TOKEN_ALL_ACCESS) when the source token has
 * an enabled privilege other than SeChangeNotifyPrivilege, and the access it asks when it has none. It does not
 * matter what level or groups the source has: the elevated administrator's token with only SeImpersonatePrivilege,
 * SeCreateGlobalPrivilege, SeDebugPrivilege or SeTimeZonePrivilege enabled (each alone) is limited, the same token
 * with them disabled or deleted is not, and neither is a token with only SeChangeNotifyPrivilege or the caller's own
 * (lowered, so all its privileges are disabled). A Medium caller gets all the access it asks for every one of them.
 *
 * DELIBERATE DIFFERENCE: ours also limits a source token of High integrity or above that has no enabled privilege (the
 * "...disabled" rows and "only SeChangeNotifyPrivilege" below, when the test runs as an elevated administrator); Windows
 * gives the full access there (0xf01ff, measured), ours is deliberately stricter (operator decision).
 *
 * The parent (an elevated administrator or any token that holds the privileges) makes impersonation tokens of
 * itself with chosen privileges, inheritable; it starts itself with a duplicate of its token lowered to Medium, Low
 * and Untrusted, and the child duplicates each one and checks what the new handle is granted.
 */

typedef struct
{
    PCSTR Name;
    PCWSTR Privilege;       /* the privilege kept besides SeChangeNotifyPrivilege, NULL: only SeChangeNotifyPrivilege, (PCWSTR)1: all */
    int State;              /* 0 disabled, 1 enabled, -1 as it is in the token */
    BOOL Limited;           /* expected for a caller below Medium */
} VARIANT_ROW;

static const VARIANT_ROW Variants[] =
{
    {"all privileges as they are", (PCWSTR)1, -1, TRUE},
    {"SeImpersonatePrivilege enabled", L"SeImpersonatePrivilege", 1, TRUE},
    {"SeImpersonatePrivilege disabled", L"SeImpersonatePrivilege", 0, FALSE},
    {"SeCreateGlobalPrivilege enabled", L"SeCreateGlobalPrivilege", 1, TRUE},
    {"SeCreateGlobalPrivilege disabled", L"SeCreateGlobalPrivilege", 0, FALSE},
    {"SeDebugPrivilege enabled", L"SeDebugPrivilege", 1, TRUE},
    {"SeDebugPrivilege disabled", L"SeDebugPrivilege", 0, FALSE},
    {"SeTimeZonePrivilege enabled", L"SeTimeZonePrivilege", 1, TRUE},
    {"only SeChangeNotifyPrivilege", NULL, -1, FALSE},
};
#define NVARIANT ((ULONG)RTL_NUMBER_OF(Variants))

static const ACCESS_MASK LimitedMask = TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY |
                                       TOKEN_QUERY_SOURCE | READ_CONTROL;

static DWORD TokenLevel(HANDLE Token)
{
    BYTE Buffer[64];
    PTOKEN_MANDATORY_LABEL Label = (PTOKEN_MANDATORY_LABEL)Buffer;
    DWORD Length;

    if (!GetTokenInformation(Token, TokenIntegrityLevel, Buffer, sizeof(Buffer), &Length))
        return MAXDWORD;
    return *GetSidSubAuthority(Label->Label.Sid, *GetSidSubAuthorityCount(Label->Label.Sid) - 1);
}

static BOOL LoweredToken(DWORD Level, PHANDLE Out)
{
    SID_IDENTIFIER_AUTHORITY LabelAuth = {SECURITY_MANDATORY_LABEL_AUTHORITY};
    BYTE Sid[SECURITY_MAX_SID_SIZE];
    TOKEN_MANDATORY_LABEL Label;
    HANDLE Token;
    BOOL Ret;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &Token))
        return FALSE;
    Ret = DuplicateTokenEx(Token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, Out);
    CloseHandle(Token);
    ok(Ret, "DuplicateTokenEx: %lu\n", GetLastError());
    if (!Ret)
        return FALSE;
    InitializeSid((PSID)Sid, &LabelAuth, 1);
    *GetSidSubAuthority((PSID)Sid, 0) = Level;
    Label.Label.Sid = (PSID)Sid;
    Label.Label.Attributes = SE_GROUP_INTEGRITY;
    Ret = SetTokenInformation(*Out, TokenIntegrityLevel, &Label, sizeof(Label) + GetLengthSid((PSID)Sid));
    ok(Ret, "SetTokenInformation(%lx): %lu\n", Level, GetLastError());
    if (!Ret)
        CloseHandle(*Out);
    return Ret;
}

/* An inheritable impersonation token of the process with the privileges of the row; NULL if the process lacks it */
static HANDLE MakeVariant(const VARIANT_ROW *Row)
{
    SECURITY_ATTRIBUTES Inherit = {sizeof(Inherit), NULL, TRUE};
    BYTE Buffer[4096], Buffer2[4096];
    PTOKEN_PRIVILEGES Privileges = (PTOKEN_PRIVILEGES)Buffer, Kept = (PTOKEN_PRIVILEGES)Buffer2;
    LUID_AND_ATTRIBUTES Delete[64];
    HANDLE Token = NULL, Restricted = NULL, Result = NULL;
    DWORD Length, i, DeleteCount = 0;
    BOOL Found = (Row->Privilege == (PCWSTR)1);

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &Token))
        return NULL;
    if (!GetTokenInformation(Token, TokenPrivileges, Buffer, sizeof(Buffer), &Length))
        goto Done;
    if (Row->Privilege == (PCWSTR)1)
    {
        /* the process's own token as it is limits the duplicate only if it has an enabled privilege besides SeChangeNotifyPrivilege */
        Found = FALSE;
        for (i = 0; i < Privileges->PrivilegeCount; i++)
        {
            WCHAR Name[64];
            DWORD NameLength = _countof(Name);

            if ((Privileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) &&
                LookupPrivilegeNameW(NULL, &Privileges->Privileges[i].Luid, Name, &NameLength) &&
                wcscmp(Name, L"SeChangeNotifyPrivilege"))
                Found = TRUE;
        }
        if (!Found)
            goto Done;
    }
    else
    {
        for (i = 0; i < Privileges->PrivilegeCount; i++)
        {
            WCHAR Name[64];
            DWORD NameLength = _countof(Name);

            if (!LookupPrivilegeNameW(NULL, &Privileges->Privileges[i].Luid, Name, &NameLength))
                continue;
            if (!wcscmp(Name, L"SeChangeNotifyPrivilege"))
                continue;
            if (Row->Privilege && !wcscmp(Name, Row->Privilege))
            {
                Found = TRUE;
                continue;
            }
            Delete[DeleteCount].Luid = Privileges->Privileges[i].Luid;
            Delete[DeleteCount].Attributes = 0;
            DeleteCount++;
        }
        if (Row->Privilege && !Found)
            goto Done;
    }
    if (!CreateRestrictedToken(Token, 0, 0, NULL, DeleteCount, DeleteCount ? Delete : NULL, 0, NULL, &Restricted))
        goto Done;
    if (Row->State >= 0)
    {
        if (!GetTokenInformation(Restricted, TokenPrivileges, Buffer2, sizeof(Buffer2), &Length))
            goto Done;
        for (i = 0; i < Kept->PrivilegeCount; i++)
        {
            WCHAR Name[64];
            DWORD NameLength = _countof(Name);

            if (LookupPrivilegeNameW(NULL, &Kept->Privileges[i].Luid, Name, &NameLength) &&
                wcscmp(Name, L"SeChangeNotifyPrivilege"))
                Kept->Privileges[i].Attributes = Row->State ? SE_PRIVILEGE_ENABLED : 0;
        }
        AdjustTokenPrivileges(Restricted, FALSE, Kept, 0, NULL, NULL);
    }
    if (!DuplicateTokenEx(Restricted, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, &Inherit,
                          SecurityImpersonation, TokenImpersonation, &Result))
        Result = NULL;

Done:
    if (Restricted) CloseHandle(Restricted);
    if (Token) CloseHandle(Token);
    return Result;
}

static ACCESS_MASK Granted(HANDLE Source, ACCESS_MASK Asked)
{
    OBJECT_BASIC_INFORMATION Basic;
    HANDLE Dup = NULL;
    NTSTATUS Status;

    if (!DuplicateTokenEx(Source, Asked, NULL, SecurityImpersonation, TokenPrimary, &Dup))
        return 0xFFFFFFFF;
    Status = NtQueryObject(Dup, ObjectBasicInformation, &Basic, sizeof(Basic), NULL);
    CloseHandle(Dup);
    return NT_SUCCESS(Status) ? Basic.GrantedAccess : 0xFFFFFFFE;
}

static VOID Child(DWORD Level, int Argc, char **Argv)
{
    HANDLE Own;
    int i;
    BOOL Below = Level < SECURITY_MANDATORY_MEDIUM_RID;
    ACCESS_MASK Access;

    for (i = 0; i + 1 < Argc; i += 2)
    {
        HANDLE Source = (HANDLE)(ULONG_PTR)strtoull(Argv[i], NULL, 10);
        int Row = atoi(Argv[i + 1]);
        /* the deliberately stricter rows: Windows value Limited == FALSE, ours limited because the source is High or above */
        BOOL Deliberate = !Variants[Row].Limited && TokenLevel(Source) >= SECURITY_MANDATORY_HIGH_RID;
        BOOL Limited = (Variants[Row].Limited || Deliberate) && Below;

        if (Deliberate && Below)
            trace("level %lx, %s: deliberately limited (Windows: full access)\n", Level, Variants[Row].Name);
        Access = Granted(Source, MAXIMUM_ALLOWED);
        if (Limited)
            ok(Access == 0, "level %lx, %s: MAXIMUM_ALLOWED granted 0x%lx\n", Level, Variants[Row].Name, Access);
        else
            ok((Access & TOKEN_ALL_ACCESS) == TOKEN_ALL_ACCESS, "level %lx, %s: MAXIMUM_ALLOWED granted 0x%lx\n", Level, Variants[Row].Name, Access);

        Access = Granted(Source, TOKEN_ALL_ACCESS);
        if (Limited)
            ok(Access == (TOKEN_ALL_ACCESS & LimitedMask), "level %lx, %s: TOKEN_ALL_ACCESS granted 0x%lx\n", Level, Variants[Row].Name, Access);
        else
            ok(Access == TOKEN_ALL_ACCESS, "level %lx, %s: TOKEN_ALL_ACCESS granted 0x%lx\n", Level, Variants[Row].Name, Access);

        Access = Granted(Source, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT);
        if (Limited)
            ok(Access == (TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY), "level %lx, %s: QUERY|DUP|ASSIGN|ADJUST_DEFAULT granted 0x%lx\n", Level, Variants[Row].Name, Access);
        else
            ok(Access == (TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT), "level %lx, %s: QUERY|DUP|ASSIGN|ADJUST_DEFAULT granted 0x%lx\n", Level, Variants[Row].Name, Access);

        /* the rights that stay: IMPERSONATE and QUERY_SOURCE are granted, SYNCHRONIZE and WRITE_DAC are not */
        Access = Granted(Source, TOKEN_IMPERSONATE | TOKEN_QUERY_SOURCE | READ_CONTROL);
        ok(Access == (TOKEN_IMPERSONATE | TOKEN_QUERY_SOURCE | READ_CONTROL), "level %lx, %s: IMPERSONATE|QUERY_SOURCE|READ_CONTROL granted 0x%lx\n", Level, Variants[Row].Name, Access);
        Access = Granted(Source, WRITE_DAC | TOKEN_ADJUST_PRIVILEGES);
        ok(Access == (Limited ? 0 : (WRITE_DAC | TOKEN_ADJUST_PRIVILEGES)), "level %lx, %s: WRITE_DAC|ADJUST_PRIVILEGES granted 0x%lx\n", Level, Variants[Row].Name, Access);
    }

    /* the caller's own token: lowered, all its privileges are disabled: never limited */
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &Own))
    {
        Access = Granted(Own, TOKEN_ALL_ACCESS);
        ok(Access == TOKEN_ALL_ACCESS, "level %lx, own token: TOKEN_ALL_ACCESS granted 0x%lx\n", Level, Access);
        Access = Granted(Own, MAXIMUM_ALLOWED);
        ok((Access & TOKEN_ALL_ACCESS) == TOKEN_ALL_ACCESS, "level %lx, own token: MAXIMUM_ALLOWED granted 0x%lx\n", Level, Access);
        CloseHandle(Own);
    }
}

static VOID RunChild(DWORD Level, const HANDLE *Handles, const ULONG *Rows, ULONG Count)
{
    WCHAR Path[MAX_PATH], Command[1024];
    STARTUPINFOW Startup = {sizeof(Startup)};
    PROCESS_INFORMATION Pi;
    HANDLE Token;
    ULONG i;
    size_t Length;

    if (!LoweredToken(Level, &Token))
        return;
    GetModuleFileNameW(NULL, Path, _countof(Path));
    StringCchPrintfW(Command, _countof(Command), L"\"%s\" TokenDuplicateLimit child %lx", Path, Level);
    for (i = 0; i < Count; i++)
    {
        Length = wcslen(Command);
        StringCchPrintfW(Command + Length, _countof(Command) - Length, L" %I64u %lu", (ULONG64)(ULONG_PTR)Handles[i], Rows[i]);
    }
    Startup.dwFlags = STARTF_USESTDHANDLES;
    Startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    Startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    Startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    if (!CreateProcessAsUserW(Token, Path, Command, NULL, NULL, TRUE, 0, NULL, NULL, &Startup, &Pi))
    {
        ok(0, "CreateProcessAsUser(level %lx): %lu\n", Level, GetLastError());
        CloseHandle(Token);
        return;
    }
    CloseHandle(Token);
    winetest_wait_child_process(&Pi);
}

START_TEST(TokenDuplicateLimit)
{
    HANDLE Handles[NVARIANT], Token;
    ULONG Rows[NVARIANT], Count = 0, i;
    char **Argv;
    int Argc;
    DWORD Level;

    Argc = winetest_get_mainargs(&Argv);
    if (Argc >= 4 && !strcmp(Argv[2], "child"))
    {
        Child(strtoul(Argv[3], NULL, 16), Argc - 4, Argv + 4);
        return;
    }

    ok(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token), "OpenProcessToken: %lu\n", GetLastError());
    Level = TokenLevel(Token);
    CloseHandle(Token);
    if (Level < SECURITY_MANDATORY_MEDIUM_RID)
    {
        skip("the test needs a caller at Medium or above\n");
        return;
    }

    for (i = 0; i < NVARIANT; i++)
    {
        HANDLE Variant = MakeVariant(&Variants[i]);

        if (!Variant)
        {
            skip("%s: the token does not hold the privilege\n", Variants[i].Name);
            continue;
        }
        Handles[Count] = Variant;
        Rows[Count] = i;
        Count++;
    }
    if (!Count)
        return;

    RunChild(SECURITY_MANDATORY_MEDIUM_RID, Handles, Rows, Count);
    RunChild(SECURITY_MANDATORY_LOW_RID, Handles, Rows, Count);
    RunChild(SECURITY_MANDATORY_UNTRUSTED_RID, Handles, Rows, Count);

    for (i = 0; i < Count; i++)
        CloseHandle(Handles[i]);
}
