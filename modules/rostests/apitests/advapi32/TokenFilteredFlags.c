/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     TOKEN_IS_FILTERED and TOKEN_SANDBOX_INERT of tokens made by CreateRestrictedToken
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows Server 2022 (10.0.20348), as an administrator, as a standard user and as SYSTEM, on the flags of
 * TokenAccessInformation (0x800 filtered, 0x40 sandbox inert, 0x10 restricted, 0x8 write restricted), on TokenHasRestrictions
 * and on TokenSandBoxInert:
 *  - a token is filtered (0x800, HasRestrictions 1) when the call really took something from it: a group made deny-only that
 *    was enabled, a privilege that was deleted (DISABLE_MAX_PRIVILEGE removes all but SeChangeNotifyPrivilege), restricting SIDs
 *    added, or LUA_TOKEN that changed a group or a privilege. A call that changes nothing, a SID or a privilege the token does
 *    not have, SANDBOX_INERT alone and WRITE_RESTRICTED alone do not make a filtered token (a write restricted token reports
 *    HasRestrictions 1 because it is restricted: 0x18)
 *  - the flag of a filtered token stays in its copies and in the tokens made from it
 *  - SANDBOX_INERT is stored (0x40, TokenSandBoxInert 1) only when the calling process runs as SYSTEM, LocalService or
 *    NetworkService (also as the TrustedInstaller service, whose token is the SYSTEM user's, and with SeTcbPrivilege
 *    deleted, or when the thread impersonates somebody else); an administrator or a standard user gets a token
 *    without it, and no error
 */

#include "precomp.h"

#ifndef LUA_TOKEN
#define LUA_TOKEN 0x4
#endif
#ifndef WRITE_RESTRICTED
#define WRITE_RESTRICTED 0x8
#endif

#define FL_FILTERED 0x800
#define FL_INERT    0x40
#define FL_MASK     (FL_FILTERED | FL_INERT | 0x18)

/* The start of TOKEN_ACCESS_INFORMATION (the header of an older PSDK does not declare it) */
typedef struct _TF_TOKEN_ACCESS_INFORMATION
{
    PVOID SidHash;
    PVOID RestrictedSidHash;
    PVOID Privileges;
    LUID AuthenticationId;
    DWORD TokenType;
    DWORD ImpersonationLevel;
    DWORD MandatoryPolicy;
    DWORD Flags;
} TF_TOKEN_ACCESS_INFORMATION, *PTF_TOKEN_ACCESS_INFORMATION;

static BOOL RunsAsSystem;    /* the process runs as LocalSystem, LocalService or NetworkService */

static DWORD
FlagsOf(HANDLE hToken, DWORD *HasRestrictions, DWORD *Inert)
{
    BYTE Buffer[4096];
    DWORD Length = 0, Value = 0xCCCCCC00, Flags = 0xFFFFFFFF;

    if (GetTokenInformation(hToken, (TOKEN_INFORMATION_CLASS)22, Buffer, sizeof(Buffer), &Length))
        Flags = ((PTF_TOKEN_ACCESS_INFORMATION)Buffer)->Flags;
    else
        ok(0, "TokenAccessInformation failed with %lu\n", GetLastError());
    if (GetTokenInformation(hToken, (TOKEN_INFORMATION_CLASS)21, &Value, sizeof(Value), &Length))
        *HasRestrictions = Value & 0xFF;
    else
        *HasRestrictions = 0xDEAD;
    Value = 0xDEAD;
    if (GetTokenInformation(hToken, (TOKEN_INFORMATION_CLASS)15, &Value, sizeof(Value), &Length))
        *Inert = Value;
    else
        *Inert = 0xDEAD;
    return Flags;
}

static BOOL
HoldsGroup(HANDLE hToken, PSID Sid)
{
    BYTE Buffer[8192];
    PTOKEN_GROUPS Groups = (PTOKEN_GROUPS)Buffer;
    DWORD Length, i;

    if (!GetTokenInformation(hToken, TokenGroups, Buffer, sizeof(Buffer), &Length))
        return FALSE;
    for (i = 0; i < Groups->GroupCount; i++)
        if (EqualSid(Groups->Groups[i].Sid, Sid) && (Groups->Groups[i].Attributes & SE_GROUP_ENABLED))
            return TRUE;
    return FALSE;
}

static BOOL
HoldsPrivilege(HANDLE hToken, const LUID *Luid, BOOL AllButChangeNotify, const LUID *ChangeNotify)
{
    BYTE Buffer[4096];
    PTOKEN_PRIVILEGES Privileges = (PTOKEN_PRIVILEGES)Buffer;
    DWORD Length, i;

    if (!GetTokenInformation(hToken, TokenPrivileges, Buffer, sizeof(Buffer), &Length))
        return FALSE;
    for (i = 0; i < Privileges->PrivilegeCount; i++)
    {
        if (AllButChangeNotify)
        {
            if (memcmp(&Privileges->Privileges[i].Luid, ChangeNotify, sizeof(LUID)))
                return TRUE;
        }
        else if (!memcmp(&Privileges->Privileges[i].Luid, Luid, sizeof(LUID)))
            return TRUE;
    }
    return FALSE;
}

typedef enum { OP_NOTHING, OP_INERT, OP_DISABLE_MAX, OP_INERT_DISABLE_MAX, OP_DELETE_SHUTDOWN, OP_DELETE_CREATE_TOKEN,
               OP_DENY_USERS, OP_DENY_RDU, OP_LUA, OP_WRITE_RESTRICTED, OP_LIST, OP_WRITE_RESTRICTED_LIST, OP_INERT_LIST } OP;
static const PCSTR OpNames[] = { "nothing", "SANDBOX_INERT", "DISABLE_MAX_PRIVILEGE", "SANDBOX_INERT|DISABLE_MAX_PRIVILEGE",
                                 "delete SeShutdown", "delete SeCreateToken", "deny-only Users", "deny-only Remote Desktop Users",
                                 "LUA_TOKEN", "WRITE_RESTRICTED", "list {Everyone}", "WRITE_RESTRICTED + list", "SANDBOX_INERT + list" };

static HANDLE
Apply(HANDLE hSource, OP Op, PSID Users, PSID Rdu, PSID Everyone, const LUID *Shutdown, const LUID *CreateToken)
{
    DWORD Flags = 0, nDeny = 0, nDel = 0, nList = 0;
    SID_AND_ATTRIBUTES Deny, List;
    LUID_AND_ATTRIBUTES Del;
    HANDLE hNew = NULL;

    Deny.Attributes = List.Attributes = 0;
    Del.Attributes = 0;
    switch (Op)
    {
        case OP_INERT: Flags = SANDBOX_INERT; break;
        case OP_DISABLE_MAX: Flags = DISABLE_MAX_PRIVILEGE; break;
        case OP_INERT_DISABLE_MAX: Flags = SANDBOX_INERT | DISABLE_MAX_PRIVILEGE; break;
        case OP_DELETE_SHUTDOWN: Del.Luid = *Shutdown; nDel = 1; break;
        case OP_DELETE_CREATE_TOKEN: Del.Luid = *CreateToken; nDel = 1; break;
        case OP_DENY_USERS: Deny.Sid = Users; nDeny = 1; break;
        case OP_DENY_RDU: Deny.Sid = Rdu; nDeny = 1; break;
        case OP_LUA: Flags = LUA_TOKEN; break;
        case OP_WRITE_RESTRICTED: Flags = WRITE_RESTRICTED; break;
        case OP_LIST: List.Sid = Everyone; nList = 1; break;
        case OP_WRITE_RESTRICTED_LIST: Flags = WRITE_RESTRICTED; List.Sid = Everyone; nList = 1; break;
        case OP_INERT_LIST: Flags = SANDBOX_INERT; List.Sid = Everyone; nList = 1; break;
        default: break;
    }
    if (!CreateRestrictedToken(hSource, Flags, nDeny, nDeny ? &Deny : NULL, nDel, nDel ? &Del : NULL, nList, nList ? &List : NULL, &hNew))
        return NULL;
    return hNew;
}

static VOID
TestSource(PCSTR Name, HANDLE hSource, BOOL SourceFiltered, PSID Users, PSID Rdu, PSID Everyone,
           const LUID *Shutdown, const LUID *CreateToken, const LUID *ChangeNotify)
{
    static const OP Ops[] = { OP_NOTHING, OP_INERT, OP_DISABLE_MAX, OP_INERT_DISABLE_MAX, OP_DELETE_SHUTDOWN, OP_DELETE_CREATE_TOKEN,
                              OP_DENY_USERS, OP_DENY_RDU, OP_LUA, OP_WRITE_RESTRICTED, OP_LIST, OP_WRITE_RESTRICTED_LIST, OP_INERT_LIST };
    BYTE AdminsSid[SECURITY_MAX_SID_SIZE];
    DWORD cb = sizeof(AdminsSid), i, Flags, Has, Inert, Expected, ExpectedHas;
    BOOL Changes, Restricted, WriteRestricted, Filtered;
    HANDLE hNew;

    CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, AdminsSid, &cb);
    for (i = 0; i < ARRAYSIZE(Ops); i++)
    {
        OP Op = Ops[i];

        hNew = Apply(hSource, Op, Users, Rdu, Everyone, Shutdown, CreateToken);
        ok(hNew != NULL, "%s: %s failed with %lu\n", Name, OpNames[Op], GetLastError());
        if (!hNew)
            continue;

        /* What the call changes in this source token */
        switch (Op)
        {
            case OP_DISABLE_MAX: case OP_INERT_DISABLE_MAX: Changes = HoldsPrivilege(hSource, NULL, TRUE, ChangeNotify); break;
            case OP_DELETE_SHUTDOWN: Changes = HoldsPrivilege(hSource, Shutdown, FALSE, NULL); break;
            case OP_DELETE_CREATE_TOKEN: Changes = HoldsPrivilege(hSource, CreateToken, FALSE, NULL); break;
            case OP_DENY_USERS: Changes = HoldsGroup(hSource, Users); break;
            case OP_DENY_RDU: Changes = HoldsGroup(hSource, Rdu); break;
            case OP_LUA: Changes = HoldsGroup(hSource, AdminsSid) || HoldsPrivilege(hSource, NULL, TRUE, ChangeNotify); break;
            case OP_LIST: case OP_WRITE_RESTRICTED_LIST: case OP_INERT_LIST: Changes = TRUE; break;
            default: Changes = FALSE; break;
        }
        Restricted = Op == OP_LIST || Op == OP_WRITE_RESTRICTED_LIST || Op == OP_INERT_LIST;
        WriteRestricted = Op == OP_WRITE_RESTRICTED || Op == OP_WRITE_RESTRICTED_LIST;
        Filtered = SourceFiltered || Changes;
        if (Op == OP_LUA && !HoldsGroup(hSource, AdminsSid))
            Filtered = SourceFiltered;      /* not measured for a token whose privileges are all kept: skipped below */

        Flags = FlagsOf(hNew, &Has, &Inert);
        Expected = (Filtered ? FL_FILTERED : 0) | (Restricted || WriteRestricted ? 0x10 : 0) | (WriteRestricted ? 0x8 : 0) |
                   ((Op == OP_INERT || Op == OP_INERT_DISABLE_MAX || Op == OP_INERT_LIST) && RunsAsSystem ? FL_INERT : 0);
        ExpectedHas = (Filtered || Restricted || WriteRestricted) ? 1 : 0;
        if (Op == OP_LUA && !HoldsGroup(hSource, AdminsSid))
            goto Next;
        ok((Flags & FL_MASK) == Expected, "%s: %s: access information flags 0x%lx, expected 0x%lx in 0x%x\n",
           Name, OpNames[Op], Flags, Expected, FL_MASK);
        ok(Has == ExpectedHas, "%s: %s: TokenHasRestrictions %lu, expected %lu\n", Name, OpNames[Op], Has, ExpectedHas);
        ok(Inert == ((Expected & FL_INERT) ? 1UL : 0UL), "%s: %s: TokenSandBoxInert %lu, expected %lu\n",
           Name, OpNames[Op], Inert, (Expected & FL_INERT) ? 1UL : 0UL);
Next:
        CloseHandle(hNew);
    }
}

START_TEST(TokenFilteredFlags)
{
    HANDLE hProcess = NULL, hPrimary = NULL, hFiltered = NULL, hCopy = NULL;
    BYTE Users[SECURITY_MAX_SID_SIZE], Rdu[SECURITY_MAX_SID_SIZE], Everyone[SECURITY_MAX_SID_SIZE], SystemSid[SECURITY_MAX_SID_SIZE];
    BYTE LocalServiceSid[SECURITY_MAX_SID_SIZE], NetworkServiceSid[SECURITY_MAX_SID_SIZE];
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    LUID Shutdown, CreateToken, ChangeNotify;
    DWORD cb, Flags, Has, Inert;
    BYTE UserBuffer[256];

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hProcess) ||
        !DuplicateTokenEx(hProcess, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hPrimary))
    {
        skip("no process token\n");
        return;
    }
    cb = sizeof(Users);
    CreateWellKnownSid(WinBuiltinUsersSid, NULL, Users, &cb);
    cb = sizeof(Everyone);
    CreateWellKnownSid(WinWorldSid, NULL, Everyone, &cb);
    cb = sizeof(SystemSid);
    CreateWellKnownSid(WinLocalSystemSid, NULL, SystemSid, &cb);
    cb = sizeof(LocalServiceSid);
    CreateWellKnownSid(WinLocalServiceSid, NULL, LocalServiceSid, &cb);
    cb = sizeof(NetworkServiceSid);
    CreateWellKnownSid(WinNetworkServiceSid, NULL, NetworkServiceSid, &cb);
    RtlInitializeSid((PSID)Rdu, &NtAuthority, 2);
    *RtlSubAuthoritySid((PSID)Rdu, 0) = SECURITY_BUILTIN_DOMAIN_RID;
    *RtlSubAuthoritySid((PSID)Rdu, 1) = DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS;
    LookupPrivilegeValueA(NULL, SE_SHUTDOWN_NAME, &Shutdown);
    LookupPrivilegeValueA(NULL, SE_CREATE_TOKEN_NAME, &CreateToken);
    LookupPrivilegeValueA(NULL, SE_CHANGE_NOTIFY_NAME, &ChangeNotify);

    if (GetTokenInformation(hProcess, TokenUser, UserBuffer, sizeof(UserBuffer), &cb))
        RunsAsSystem = EqualSid(((PTOKEN_USER)UserBuffer)->User.Sid, SystemSid) ||
                       EqualSid(((PTOKEN_USER)UserBuffer)->User.Sid, LocalServiceSid) ||
                       EqualSid(((PTOKEN_USER)UserBuffer)->User.Sid, NetworkServiceSid);

    /* the process token itself is not filtered: the rows below start from that */
    Flags = FlagsOf(hPrimary, &Has, &Inert);
    if (Flags & FL_FILTERED)
    {
        skip("the token of the process is filtered already (flags 0x%lx)\n", Flags);
        return;
    }
    ok(Has == 0, "TokenHasRestrictions of the process token is %lu\n", Has);

    TestSource("N", hPrimary, FALSE, (PSID)Users, (PSID)Rdu, (PSID)Everyone, &Shutdown, &CreateToken, &ChangeNotify);

    /* a filtered token stays filtered through a call that changes nothing, through copies, and when it is filtered again */
    if (CreateRestrictedToken(hPrimary, DISABLE_MAX_PRIVILEGE, 0, NULL, 0, NULL, 0, NULL, &hFiltered))
    {
        Flags = FlagsOf(hFiltered, &Has, &Inert);
        ok((Flags & FL_FILTERED) && Has == 1, "DISABLE_MAX_PRIVILEGE: flags 0x%lx, HasRestrictions %lu\n", Flags, Has);
        if (DuplicateTokenEx(hFiltered, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &hCopy))
        {
            Flags = FlagsOf(hCopy, &Has, &Inert);
            ok((Flags & FL_FILTERED) && Has == 1, "copy of a filtered token: flags 0x%lx, HasRestrictions %lu\n", Flags, Has);
            CloseHandle(hCopy);
        }
        if (Flags & FL_FILTERED)
            TestSource("F1", hFiltered, TRUE, (PSID)Users, (PSID)Rdu, (PSID)Everyone, &Shutdown, &CreateToken, &ChangeNotify);
        CloseHandle(hFiltered);
    }
    else
        skip("DISABLE_MAX_PRIVILEGE failed with %lu\n", GetLastError());

    CloseHandle(hPrimary);
    CloseHandle(hProcess);
}
