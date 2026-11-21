/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The access check and audit alarm functions decide as the access check functions do
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * AccessCheckAndAuditAlarm, AccessCheckByTypeAndAuditAlarm, AccessCheckByTypeResultListAndAuditAlarm
 * and AccessCheckByTypeResultListAndAuditAlarmByHandle check the access of a client (the impersonation
 * token of the thread, or a token handle for the ByHandle form) to a security descriptor. They must
 * decide exactly as AccessCheck, AccessCheckByType and AccessCheckByTypeResultList decide for the same
 * descriptor, token, request, object type list and generic mapping.
 *
 * Part 1 runs in this process, an administrator, which does not hold SeAuditPrivilege (the default
 * rights give it to LocalService and NetworkService): the ByType forms with AUDIT_ALLOW_NO_PRIVILEGE,
 * which "performs the access check without generating audit messages when the privilege is not
 * enabled", and the rows for the missing privilege and the missing impersonation.
 *
 * Part 2 runs in a service of LocalSystem, which holds SeAuditPrivilege: AccessCheckAndAuditAlarm
 * (it has no Flags parameter, so it needs the privilege) and the ByType forms with Flags 0. The
 * service writes the failed checks into a file; this process reports them. With the argument "probe"
 * only part 1 runs and nothing is created (for a read-only run on Windows).
 *
 * Both parts run the same equality matrix: every DACL x owner x client token x request x object type
 * list, each AuditAlarm form against its AccessCheck form. On a denial the AuditAlarm forms with one
 * result succeed with AccessStatus FALSE and the reason in the last error, as AccessCheck does
 * (measured on Windows Server 2022).
 */

#include "precomp.h"
#include <stdio.h>

#ifndef ACL_REVISION_DS
#define ACL_REVISION_DS 4
#endif
#ifndef WRITE_RESTRICTED
#define WRITE_RESTRICTED 0x8
#endif

/* The rights of the test object: 1, 2, 4 and 8, with a generic mapping of their own */
#define R1 0x0001
#define R2 0x0002
#define R4 0x0004
#define R8 0x0008
#define R_ALL (R1 | R2 | R4 | R8)

static GENERIC_MAPPING Mapping = { R1 | READ_CONTROL, R2, R4, R_ALL | STANDARD_RIGHTS_REQUIRED };

static GUID Guids[] =
{
    {0},                                                                            /* G_NONE */
    {0x6a3e0001, 0x2b1c, 0x4f55, {0x91, 0x0e, 0x5d, 0x22, 0x13, 0x7a, 0xc4, 0x01}}, /* G_ROOT */
    {0x6a3e0002, 0x2b1c, 0x4f55, {0x91, 0x0e, 0x5d, 0x22, 0x13, 0x7a, 0xc4, 0x02}}, /* G_A */
    {0x6a3e0003, 0x2b1c, 0x4f55, {0x91, 0x0e, 0x5d, 0x22, 0x13, 0x7a, 0xc4, 0x03}}, /* G_B */
    {0x6a3e0004, 0x2b1c, 0x4f55, {0x91, 0x0e, 0x5d, 0x22, 0x13, 0x7a, 0xc4, 0x04}}, /* G_C */
    {0x6a3e0005, 0x2b1c, 0x4f55, {0x91, 0x0e, 0x5d, 0x22, 0x13, 0x7a, 0xc4, 0x05}}, /* G_X: never in a list */
};
enum { G_NONE, G_ROOT, G_A, G_B, G_C, G_X };

/* SIDs; S_NOBODY is a domain user that no test token holds (the owner of the descriptors of the named rows) */
enum { S_EVERYONE, S_ADMINS, S_USERS, S_SYSTEM, S_OWNER_RIGHTS, S_SELF, S_NOBODY, S_USER, S_COUNT };
static PSID Sids[S_COUNT];

/* A DACL: plain allow 'A' and deny 'D', object allow 'a' and object deny 'd' ACEs */
typedef struct
{
    char Type;
    int Sid;
    ACCESS_MASK Mask;
    int Guid;
} ACE_SPEC;

typedef struct
{
    const char *Name;
    BOOL NullDacl;
    int AceCount;
    ACE_SPEC Aces[4];
} DACL_SPEC;

static const DACL_SPEC Dacls[] =
{
    { "null", TRUE, 0 },
    { "empty", FALSE, 0 },
    { "allow-everyone-1", FALSE, 1, {{'A', S_EVERYONE, R1}} },
    { "allow-admins-7", FALSE, 1, {{'A', S_ADMINS, R1 | R2 | R4}} },
    { "deny-2-allow-7rc", FALSE, 2, {{'D', S_EVERYONE, R2}, {'A', S_EVERYONE, R1 | R2 | R4 | READ_CONTROL}} },
    { "everyone-3-users-4", FALSE, 2, {{'A', S_EVERYONE, R1 | R2}, {'A', S_USERS, R4}} },
    { "user-all", FALSE, 1, {{'A', S_USER, R_ALL | READ_CONTROL | WRITE_DAC | WRITE_OWNER}} },
    { "owner-rights-1", FALSE, 2, {{'A', S_OWNER_RIGHTS, R1}, {'A', S_EVERYONE, R2}} },
    { "self-4", FALSE, 2, {{'A', S_SELF, R4}, {'A', S_EVERYONE, R1}} },
    { "object-a2-deny-b4", FALSE, 3, {{'a', S_EVERYONE, R2, G_A}, {'d', S_EVERYONE, R4, G_B}, {'A', S_EVERYONE, R1 | R4}} },
    { "object-c4-x2", FALSE, 3, {{'a', S_EVERYONE, R4, G_C}, {'a', S_EVERYONE, R2, G_X}, {'A', S_ADMINS, R1}} },
    { "system-only", FALSE, 1, {{'A', S_SYSTEM, R1 | R2 | R4}} },
};

static const int Owners[] = { S_NOBODY, S_USER };

static const ACCESS_MASK Requests[] =
{
    0, R1, R2, R4, R1 | R2 | R4, R8, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
    MAXIMUM_ALLOWED, MAXIMUM_ALLOWED | R1, ACCESS_SYSTEM_SECURITY, ACCESS_SYSTEM_SECURITY | R1,
};

/* Object type lists: none, {root, A, B under A}, {root, A, C under A, B} */
typedef struct
{
    const char *Name;
    int Count;
    WORD Levels[4];
    int Guids[4];
} LIST_SPEC;

static const LIST_SPEC Lists[] =
{
    { "none", 0 },
    { "root-a-b", 3, {0, 1, 2}, {G_ROOT, G_A, G_B} },
    { "root-a-c-b", 4, {0, 1, 2, 1}, {G_ROOT, G_A, G_C, G_B} },
};

/* Client tokens, all impersonation tokens made from the token of this process */
enum { K_SELF, K_RESTRICTED, K_ADMINS_DENY_ONLY, K_WRITE_RESTRICTED, K_PRIVILEGED, K_IDENTIFICATION, K_COUNT };
static const char *TokenNames[K_COUNT] =
{
    "self", "restricted-everyone", "admins-deny-only", "write-restricted", "privileges-enabled", "identification",
};
static HANDLE Tokens[K_COUNT];

/* Reporting: ok() in this process; in the service, a line per failed check in the result file */
static BOOL InService;
static HANDLE ReportFile = INVALID_HANDLE_VALUE;
static LONG ServiceChecks, ServiceFailures;

static void Check(int Line, BOOL Condition, const char *Format, ...)
{
    char Text[600];
    va_list Args;

    va_start(Args, Format);
    _vsnprintf(Text, sizeof(Text) - 3, Format, Args);
    Text[sizeof(Text) - 3] = 0;
    va_end(Args);

    if (!InService)
    {
        ok_(__FILE__, Line)(Condition, "%s", Text);
        return;
    }

    ServiceChecks++;
    if (!Condition && ReportFile != INVALID_HANDLE_VALUE)
    {
        char Out[700];
        DWORD Written;

        ServiceFailures++;
        _snprintf(Out, sizeof(Out) - 1, "FAIL %d %s", Line, Text);
        Out[sizeof(Out) - 1] = 0;
        /* one line per failure */
        while (strlen(Out) && (Out[strlen(Out) - 1] == '\n' || Out[strlen(Out) - 1] == '\r'))
            Out[strlen(Out) - 1] = 0;
        strcat(Out, "\r\n");
        WriteFile(ReportFile, Out, (DWORD)strlen(Out), &Written, NULL);
    }
}
#define CHECK(Condition, ...) Check(__LINE__, (Condition), __VA_ARGS__)

static void Note(const char *Format, ...)
{
    char Text[300];
    va_list Args;
    DWORD Written;

    va_start(Args, Format);
    _vsnprintf(Text, sizeof(Text) - 3, Format, Args);
    Text[sizeof(Text) - 3] = 0;
    va_end(Args);

    if (!InService)
    {
        trace("%s", Text);
    }
    else if (ReportFile != INVALID_HANDLE_VALUE)
    {
        char Out[320];
        _snprintf(Out, sizeof(Out) - 1, "NOTE %s", Text);
        Out[sizeof(Out) - 1] = 0;
        WriteFile(ReportFile, Out, (DWORD)strlen(Out), &Written, NULL);
    }
}

/* SIDs, tokens and descriptors */

static BOOL MakeSids(void)
{
    SID_IDENTIFIER_AUTHORITY World = {SECURITY_WORLD_SID_AUTHORITY};
    SID_IDENTIFIER_AUTHORITY Nt = {SECURITY_NT_AUTHORITY};
    SID_IDENTIFIER_AUTHORITY Creator = {SECURITY_CREATOR_SID_AUTHORITY};
    HANDLE Token;
    BYTE Buffer[256];
    DWORD Length;
    PTOKEN_USER User = (PTOKEN_USER)Buffer;

    if (!AllocateAndInitializeSid(&World, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &Sids[S_EVERYONE]) ||
        !AllocateAndInitializeSid(&Nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                  &Sids[S_ADMINS]) ||
        !AllocateAndInitializeSid(&Nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_USERS, 0, 0, 0, 0, 0, 0,
                                  &Sids[S_USERS]) ||
        !AllocateAndInitializeSid(&Nt, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &Sids[S_SYSTEM]) ||
        !AllocateAndInitializeSid(&Creator, 1, 4 /* SECURITY_CREATOR_OWNER_RIGHTS_RID */, 0, 0, 0, 0, 0, 0, 0,
                                  &Sids[S_OWNER_RIGHTS]) ||
        !AllocateAndInitializeSid(&Nt, 1, SECURITY_PRINCIPAL_SELF_RID, 0, 0, 0, 0, 0, 0, 0, &Sids[S_SELF]) ||
        !AllocateAndInitializeSid(&Nt, 5, SECURITY_NT_NON_UNIQUE, 111, 222, 333, 1001, 0, 0, 0, &Sids[S_NOBODY]))
    {
        return FALSE;
    }

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token))
        return FALSE;
    if (!GetTokenInformation(Token, TokenUser, Buffer, sizeof(Buffer), &Length))
    {
        CloseHandle(Token);
        return FALSE;
    }
    CloseHandle(Token);

    Sids[S_USER] = HeapAlloc(GetProcessHeap(), 0, GetLengthSid(User->User.Sid));
    if (!Sids[S_USER])
        return FALSE;
    CopySid(GetLengthSid(User->User.Sid), Sids[S_USER], User->User.Sid);
    return TRUE;
}

static void FreeSids(void)
{
    int i;

    for (i = 0; i < S_COUNT; i++)
    {
        if (!Sids[i])
            continue;
        if (i == S_USER)
            HeapFree(GetProcessHeap(), 0, Sids[i]);
        else
            FreeSid(Sids[i]);
        Sids[i] = NULL;
    }
}

static HANDLE ImpersonationCopy(HANDLE Token, SECURITY_IMPERSONATION_LEVEL Level)
{
    HANDLE Copy = NULL;

    if (!DuplicateTokenEx(Token, TOKEN_ALL_ACCESS, NULL, Level, TokenImpersonation, &Copy))
        return NULL;
    return Copy;
}

static BOOL EnablePrivilege(HANDLE Token, LPCSTR Name)
{
    TOKEN_PRIVILEGES Privileges;

    Privileges.PrivilegeCount = 1;
    Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValueA(NULL, Name, &Privileges.Privileges[0].Luid))
        return FALSE;
    if (!AdjustTokenPrivileges(Token, FALSE, &Privileges, 0, NULL, NULL))
        return FALSE;
    return GetLastError() == ERROR_SUCCESS;
}

static BOOL MakeTokens(void)
{
    HANDLE Process, Restricted;
    SID_AND_ATTRIBUTES Sid;
    BOOL Result = FALSE;
    int i;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &Process))
        return FALSE;

    Tokens[K_SELF] = ImpersonationCopy(Process, SecurityImpersonation);
    Tokens[K_IDENTIFICATION] = ImpersonationCopy(Process, SecurityIdentification);

    Sid.Sid = Sids[S_EVERYONE];
    Sid.Attributes = 0;
    if (CreateRestrictedToken(Process, 0, 0, NULL, 0, NULL, 1, &Sid, &Restricted))
    {
        Tokens[K_RESTRICTED] = ImpersonationCopy(Restricted, SecurityImpersonation);
        CloseHandle(Restricted);
    }
    if (CreateRestrictedToken(Process, WRITE_RESTRICTED, 0, NULL, 0, NULL, 1, &Sid, &Restricted))
    {
        Tokens[K_WRITE_RESTRICTED] = ImpersonationCopy(Restricted, SecurityImpersonation);
        CloseHandle(Restricted);
    }
    Sid.Sid = Sids[S_ADMINS];
    if (CreateRestrictedToken(Process, 0, 1, &Sid, 0, NULL, 0, NULL, &Restricted))
    {
        Tokens[K_ADMINS_DENY_ONLY] = ImpersonationCopy(Restricted, SecurityImpersonation);
        CloseHandle(Restricted);
    }

    Tokens[K_PRIVILEGED] = ImpersonationCopy(Process, SecurityImpersonation);
    if (Tokens[K_PRIVILEGED])
    {
        EnablePrivilege(Tokens[K_PRIVILEGED], SE_SECURITY_NAME);
        EnablePrivilege(Tokens[K_PRIVILEGED], SE_TAKE_OWNERSHIP_NAME);
    }

    CloseHandle(Process);

    Result = TRUE;
    for (i = 0; i < K_COUNT; i++)
    {
        if (!Tokens[i])
        {
            Note("token %s could not be made (%lu)\n", TokenNames[i], GetLastError());
            Result = FALSE;
        }
    }
    return Result;
}

static void FreeTokens(void)
{
    int i;

    for (i = 0; i < K_COUNT; i++)
    {
        if (Tokens[i])
            CloseHandle(Tokens[i]);
        Tokens[i] = NULL;
    }
}

/* A self-relative descriptor with the owner, the group LocalSystem and the DACL */
static PSECURITY_DESCRIPTOR MakeDescriptor(const DACL_SPEC *Spec, int Owner)
{
    SECURITY_DESCRIPTOR Absolute;
    BYTE AclBuffer[1024];
    PACL Acl = (PACL)AclBuffer;
    PSECURITY_DESCRIPTOR Relative;
    DWORD Length = 0;
    int i;

    InitializeSecurityDescriptor(&Absolute, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorOwner(&Absolute, Sids[Owner], FALSE);
    SetSecurityDescriptorGroup(&Absolute, Sids[S_SYSTEM], FALSE);

    if (Spec->NullDacl)
    {
        SetSecurityDescriptorDacl(&Absolute, TRUE, NULL, FALSE);
    }
    else
    {
        if (!InitializeAcl(Acl, sizeof(AclBuffer), ACL_REVISION_DS))
            return NULL;
        for (i = 0; i < Spec->AceCount; i++)
        {
            const ACE_SPEC *Ace = &Spec->Aces[i];
            BOOL Added = FALSE;

            switch (Ace->Type)
            {
                case 'A':
                    Added = AddAccessAllowedAceEx(Acl, ACL_REVISION_DS, 0, Ace->Mask, Sids[Ace->Sid]);
                    break;
                case 'D':
                    Added = AddAccessDeniedAceEx(Acl, ACL_REVISION_DS, 0, Ace->Mask, Sids[Ace->Sid]);
                    break;
                case 'a':
                    Added = AddAccessAllowedObjectAce(Acl, ACL_REVISION_DS, 0, Ace->Mask, &Guids[Ace->Guid], NULL,
                                                      Sids[Ace->Sid]);
                    break;
                case 'd':
                    Added = AddAccessDeniedObjectAce(Acl, ACL_REVISION_DS, 0, Ace->Mask, &Guids[Ace->Guid], NULL,
                                                     Sids[Ace->Sid]);
                    break;
            }
            if (!Added)
                return NULL;
        }
        SetSecurityDescriptorDacl(&Absolute, TRUE, Acl, FALSE);
    }

    MakeSelfRelativeSD(&Absolute, NULL, &Length);
    Relative = HeapAlloc(GetProcessHeap(), 0, Length);
    if (Relative && !MakeSelfRelativeSD(&Absolute, Relative, &Length))
    {
        HeapFree(GetProcessHeap(), 0, Relative);
        Relative = NULL;
    }
    return Relative;
}

static void MakeList(const LIST_SPEC *Spec, OBJECT_TYPE_LIST *List)
{
    int i;

    for (i = 0; i < Spec->Count; i++)
    {
        List[i].Level = Spec->Levels[i];
        List[i].Sbz = 0;
        List[i].ObjectType = &Guids[Spec->Guids[i]];
    }
}

/* One outcome of a call */
#define SENTINEL 0xa5a5a5a5
typedef struct
{
    BOOL Return;
    DWORD Error;
    DWORD Granted[4];
    DWORD Status[4];
    BOOL GenerateOnClose;
} OUTCOME;

static void ResetOutcome(OUTCOME *Out)
{
    int i;

    Out->Return = 0x55;
    Out->Error = 0;
    for (i = 0; i < 4; i++)
    {
        Out->Granted[i] = SENTINEL;
        Out->Status[i] = SENTINEL;
    }
    Out->GenerateOnClose = 0x55;
}

/* The last error is kept also on success: AccessCheck reports the reason of a denial there */
static void Finish(OUTCOME *Out, BOOL Return)
{
    Out->Return = Return;
    Out->Error = GetLastError();
}

/* The AccessCheck forms */

static void CallAccessCheck(PSECURITY_DESCRIPTOR Sd, HANDLE Token, ACCESS_MASK Desired, OUTCOME *Out)
{
    BYTE PrivilegeBuffer[256];
    DWORD PrivilegeLength = sizeof(PrivilegeBuffer);

    ResetOutcome(Out);
    SetLastError(0xdeadbeef);
    Finish(Out, AccessCheck(Sd, Token, Desired, &Mapping, (PPRIVILEGE_SET)PrivilegeBuffer, &PrivilegeLength,
                            &Out->Granted[0], (LPBOOL)&Out->Status[0]));
}

static void CallAccessCheckByType(PSECURITY_DESCRIPTOR Sd, HANDLE Token, ACCESS_MASK Desired,
                                  OBJECT_TYPE_LIST *List, DWORD Count, OUTCOME *Out)
{
    BYTE PrivilegeBuffer[256];
    DWORD PrivilegeLength = sizeof(PrivilegeBuffer);

    ResetOutcome(Out);
    SetLastError(0xdeadbeef);
    Finish(Out, AccessCheckByType(Sd, Sids[S_USER], Token, Desired, Count ? List : NULL, Count, &Mapping,
                                  (PPRIVILEGE_SET)PrivilegeBuffer, &PrivilegeLength, &Out->Granted[0],
                                  (LPBOOL)&Out->Status[0]));
}

static void CallAccessCheckByTypeResultList(PSECURITY_DESCRIPTOR Sd, HANDLE Token, ACCESS_MASK Desired,
                                            OBJECT_TYPE_LIST *List, DWORD Count, OUTCOME *Out)
{
    BYTE PrivilegeBuffer[256];
    DWORD PrivilegeLength = sizeof(PrivilegeBuffer);

    ResetOutcome(Out);
    SetLastError(0xdeadbeef);
    Finish(Out, AccessCheckByTypeResultList(Sd, Sids[S_USER], Token, Desired, List, Count, &Mapping,
                                            (PPRIVILEGE_SET)PrivilegeBuffer, &PrivilegeLength, Out->Granted,
                                            (LPBOOL)Out->Status));
}

/* The AuditAlarm forms; the thread forms impersonate Token for the call (NULL: no impersonation) */

static BOOL Impersonate(HANDLE Token)
{
    if (!Token)
        return TRUE;
    return SetThreadToken(NULL, Token);
}

static void Revert(void)
{
    RevertToSelf();
}

static void CallAndAuditAlarm(PSECURITY_DESCRIPTOR Sd, HANDLE Token, ACCESS_MASK Desired, OUTCOME *Out)
{
    BOOL Return;

    ResetOutcome(Out);
    if (!Impersonate(Token))
    {
        Finish(Out, FALSE);
        return;
    }
    SetLastError(0xdeadbeef);
    Return = AccessCheckAndAuditAlarmW(L"AccessCheckAuditAlarm", (LPVOID)1, (LPWSTR)L"TestObject",
                                       (LPWSTR)L"Object", Sd, Desired, &Mapping, FALSE, &Out->Granted[0],
                                       (LPBOOL)&Out->Status[0], &Out->GenerateOnClose);
    Finish(Out, Return);
    Revert();
}

static void CallByTypeAndAuditAlarm(PSECURITY_DESCRIPTOR Sd, HANDLE Token, ACCESS_MASK Desired, DWORD Flags,
                                    OBJECT_TYPE_LIST *List, DWORD Count, OUTCOME *Out)
{
    BOOL Return;

    ResetOutcome(Out);
    if (!Impersonate(Token))
    {
        Finish(Out, FALSE);
        return;
    }
    SetLastError(0xdeadbeef);
    Return = AccessCheckByTypeAndAuditAlarmW(L"AccessCheckAuditAlarm", (LPVOID)1, L"TestObject", L"Object", Sd,
                                             Sids[S_USER], Desired, AuditEventObjectAccess, Flags,
                                             Count ? List : NULL, Count, &Mapping, FALSE, &Out->Granted[0],
                                             (LPBOOL)&Out->Status[0], &Out->GenerateOnClose);
    Finish(Out, Return);
    Revert();
}

static void CallResultListAndAuditAlarm(PSECURITY_DESCRIPTOR Sd, HANDLE Token, ACCESS_MASK Desired, DWORD Flags,
                                        OBJECT_TYPE_LIST *List, DWORD Count, OUTCOME *Out)
{
    BOOL Return;

    ResetOutcome(Out);
    if (!Impersonate(Token))
    {
        Finish(Out, FALSE);
        return;
    }
    SetLastError(0xdeadbeef);
    Return = AccessCheckByTypeResultListAndAuditAlarmW(L"AccessCheckAuditAlarm", (LPVOID)1, L"TestObject",
                                                       L"Object", Sd, Sids[S_USER], Desired, AuditEventObjectAccess,
                                                       Flags, List, Count, &Mapping, FALSE, Out->Granted, Out->Status,
                                                       &Out->GenerateOnClose);
    Finish(Out, Return);
    Revert();
}

/* The ByHandle form; the thread impersonates Impersonated during the call (NULL: no impersonation) */
static void CallByHandle(PSECURITY_DESCRIPTOR Sd, HANDLE Impersonated, HANDLE Client, ACCESS_MASK Desired,
                         DWORD Flags, OBJECT_TYPE_LIST *List, DWORD Count, OUTCOME *Out)
{
    BOOL Return;

    ResetOutcome(Out);
    if (!Impersonate(Impersonated))
    {
        Finish(Out, FALSE);
        return;
    }
    SetLastError(0xdeadbeef);
    Return = AccessCheckByTypeResultListAndAuditAlarmByHandleW(L"AccessCheckAuditAlarm", (LPVOID)1, Client,
                                                               L"TestObject", L"Object", Sd, Sids[S_USER], Desired,
                                                               AuditEventObjectAccess, Flags, List, Count, &Mapping,
                                                               FALSE, Out->Granted, Out->Status,
                                                               &Out->GenerateOnClose);
    Finish(Out, Return);
    Revert();
}

/* Comparisons */

/* One result: the decision (status), the granted rights and, for a denial, the reason are the same */
static BOOL SameSingle(const OUTCOME *Plain, const OUTCOME *Audit)
{
    if (!Plain->Return)
        return !Audit->Return && Audit->Error == Plain->Error;
    if (!Audit->Return || Audit->GenerateOnClose != FALSE)
        return FALSE;
    if (!!Plain->Status[0] != !!Audit->Status[0] || Plain->Granted[0] != Audit->Granted[0])
        return FALSE;
    return Plain->Status[0] || Audit->Error == Plain->Error;
}

static BOOL SameList(const OUTCOME *Plain, const OUTCOME *Audit, DWORD Count)
{
    DWORD i;

    if (!!Plain->Return != !!Audit->Return)
        return FALSE;
    if (!Plain->Return)
        return Audit->Error == Plain->Error;
    for (i = 0; i < Count; i++)
    {
        if (Plain->Granted[i] != Audit->Granted[i] || Plain->Status[i] != Audit->Status[i])
            return FALSE;
    }
    return Audit->GenerateOnClose == FALSE;
}

static void Describe(char *Text, size_t Size, const OUTCOME *Out, DWORD Count)
{
    DWORD i;
    int Used;

    Used = _snprintf(Text, Size, "ret %d err %lu", Out->Return, Out->Error);
    for (i = 0; i < (Count ? Count : 1) && Used > 0 && (size_t)Used < Size; i++)
        Used += _snprintf(Text + Used, Size - Used, " [0x%lx 0x%lx]", Out->Granted[i], Out->Status[i]);
    Text[Size - 1] = 0;
}

typedef struct
{
    ULONG Compared, Equal, Granted, Denied;
} MATRIX_STATS;

static void Matrix(DWORD Flags, BOOL WithAndAuditAlarm)
{
    MATRIX_STATS Stats[4] = {{0}};
    static const char *Forms[4] =
    {
        "AccessCheckAndAuditAlarm", "AccessCheckByTypeAndAuditAlarm",
        "AccessCheckByTypeResultListAndAuditAlarm", "AccessCheckByTypeResultListAndAuditAlarmByHandle",
    };
    OBJECT_TYPE_LIST List[4];
    OUTCOME Plain, Audit;
    char PlainText[200], AuditText[200];
    unsigned d, o, k, r, l;
    int f;

    for (d = 0; d < ARRAYSIZE(Dacls); d++)
    for (o = 0; o < ARRAYSIZE(Owners); o++)
    {
        PSECURITY_DESCRIPTOR Sd = MakeDescriptor(&Dacls[d], Owners[o]);

        if (!Sd)
        {
            CHECK(FALSE, "descriptor %s could not be made\n", Dacls[d].Name);
            continue;
        }

        for (k = 0; k < K_COUNT; k++)
        for (r = 0; r < ARRAYSIZE(Requests); r++)
        for (l = 0; l < ARRAYSIZE(Lists); l++)
        {
            DWORD Count = Lists[l].Count;
            BOOL Same;

            MakeList(&Lists[l], List);

            for (f = 0; f < 4; f++)
            {
                if (f == 0 && (!WithAndAuditAlarm || Count != 0))
                    continue;
                if (f >= 2 && Count == 0)
                    continue;

                switch (f)
                {
                    case 0:
                        CallAccessCheck(Sd, Tokens[k], Requests[r], &Plain);
                        CallAndAuditAlarm(Sd, Tokens[k], Requests[r], &Audit);
                        break;
                    case 1:
                        CallAccessCheckByType(Sd, Tokens[k], Requests[r], List, Count, &Plain);
                        CallByTypeAndAuditAlarm(Sd, Tokens[k], Requests[r], Flags, List, Count, &Audit);
                        break;
                    case 2:
                        CallAccessCheckByTypeResultList(Sd, Tokens[k], Requests[r], List, Count, &Plain);
                        CallResultListAndAuditAlarm(Sd, Tokens[k], Requests[r], Flags, List, Count, &Audit);
                        break;
                    case 3:
                        CallAccessCheckByTypeResultList(Sd, Tokens[k], Requests[r], List, Count, &Plain);
                        CallByHandle(Sd, Tokens[k], Tokens[k], Requests[r], Flags, List, Count, &Audit);
                        break;
                }

                Same = (f < 2) ? SameSingle(&Plain, &Audit) : SameList(&Plain, &Audit, Count);
                Stats[f].Compared++;
                if (Same)
                    Stats[f].Equal++;
                if (Plain.Return && Plain.Status[0] == ((f < 2) ? TRUE : ERROR_SUCCESS))
                    Stats[f].Granted++;
                else
                    Stats[f].Denied++;

                if (Same)
                {
                    /* every case is one check */
                    CHECK(TRUE, "equal\n");
                }
                else
                {
                    Describe(PlainText, sizeof(PlainText), &Plain, f < 2 ? 0 : Count);
                    Describe(AuditText, sizeof(AuditText), &Audit, f < 2 ? 0 : Count);
                    CHECK(FALSE, "%s dacl %s owner %d token %s request 0x%lx list %s: AccessCheck %s, AuditAlarm %s\n",
                          Forms[f], Dacls[d].Name, Owners[o], TokenNames[k], Requests[r], Lists[l].Name,
                          PlainText, AuditText);
                }
            }
        }

        HeapFree(GetProcessHeap(), 0, Sd);
    }

    for (f = 0; f < 4; f++)
    {
        if (!Stats[f].Compared)
            continue;
        CHECK(Stats[f].Equal == Stats[f].Compared, "%s: %lu of %lu cases differ\n", Forms[f],
              Stats[f].Compared - Stats[f].Equal, Stats[f].Compared);
        /* The matrix is not one-sided: it has granted and denied cases */
        CHECK(Stats[f].Granted > 0 && Stats[f].Denied > 0, "%s: %lu granted, %lu denied\n", Forms[f],
              Stats[f].Granted, Stats[f].Denied);
        Note("matrix flags %lu %s: %lu cases, %lu equal, first-entry granted %lu, denied %lu\n", Flags, Forms[f],
             Stats[f].Compared, Stats[f].Equal, Stats[f].Granted, Stats[f].Denied);
    }
}

/* Named rows */

static PSECURITY_DESCRIPTOR DescriptorByName(const char *Name, int Owner)
{
    unsigned i;

    for (i = 0; i < ARRAYSIZE(Dacls); i++)
    {
        if (!strcmp(Dacls[i].Name, Name))
            return MakeDescriptor(&Dacls[i], Owner);
    }
    return NULL;
}

static void CheckOutputsUntouched(int Line, const char *What, const OUTCOME *Out, DWORD Count)
{
    DWORD i;

    for (i = 0; i < (Count ? Count : 1); i++)
    {
        Check(Line, Out->Granted[i] == SENTINEL && Out->Status[i] == SENTINEL,
              "%s: entry %lu was written on failure (0x%lx 0x%lx)\n", What, i, Out->Granted[i], Out->Status[i]);
    }
}

/* Rows of the three ByType forms; Flags is AUDIT_ALLOW_NO_PRIVILEGE without the privilege, else 0 */
static void ByTypeRows(DWORD Flags)
{
    PSECURITY_DESCRIPTOR Sd, SdOwned, SdObject;
    OBJECT_TYPE_LIST List[4];
    OUTCOME Out;

    Sd = DescriptorByName("allow-everyone-1", S_NOBODY);
    SdOwned = DescriptorByName("allow-everyone-1", S_USER);
    SdObject = DescriptorByName("object-a2-deny-b4", S_NOBODY);
    if (!Sd || !SdOwned || !SdObject)
    {
        CHECK(FALSE, "descriptors could not be made\n");
        goto Done;
    }
    MakeList(&Lists[1], List);

    /* A denied request is denied */
    CallByTypeAndAuditAlarm(Sd, Tokens[K_SELF], R2, Flags, NULL, 0, &Out);
    CHECK(Out.Return && Out.Error == ERROR_ACCESS_DENIED, "ByType denied: ret %d err %lu\n", Out.Return, Out.Error);
    CHECK(Out.Status[0] == FALSE && Out.Granted[0] == 0, "ByType denied: status %lu granted 0x%lx\n",
          Out.Status[0], Out.Granted[0]);

    CallResultListAndAuditAlarm(Sd, Tokens[K_SELF], R2, Flags, List, 3, &Out);
    CHECK(Out.Return, "ResultList denied: ret %d err %lu\n", Out.Return, Out.Error);
    CHECK(Out.Status[0] == ERROR_ACCESS_DENIED && Out.Granted[0] == 0, "ResultList denied: [0x%lx 0x%lx]\n",
          Out.Granted[0], Out.Status[0]);

    CallByHandle(Sd, Tokens[K_SELF], Tokens[K_SELF], R2, Flags, List, 3, &Out);
    CHECK(Out.Return, "ByHandle denied: ret %d err %lu\n", Out.Return, Out.Error);
    CHECK(Out.Status[0] == ERROR_ACCESS_DENIED && Out.Granted[0] == 0, "ByHandle denied: [0x%lx 0x%lx]\n",
          Out.Granted[0], Out.Status[0]);

    /* A granted request is granted */
    CallByTypeAndAuditAlarm(Sd, Tokens[K_SELF], R1, Flags, NULL, 0, &Out);
    CHECK(Out.Return && Out.Status[0] == TRUE && Out.Granted[0] == R1,
          "ByType granted: ret %d err %lu status %lu granted 0x%lx\n", Out.Return, Out.Error, Out.Status[0],
          Out.Granted[0]);
    CHECK(Out.GenerateOnClose == FALSE, "ByType: GenerateOnClose %d\n", Out.GenerateOnClose);

    CallResultListAndAuditAlarm(Sd, Tokens[K_SELF], R1, Flags, List, 3, &Out);
    CHECK(Out.Return && Out.Status[0] == ERROR_SUCCESS && Out.Granted[0] == R1 &&
          Out.Status[2] == ERROR_SUCCESS && Out.Granted[2] == R1,
          "ResultList granted: ret %d [0x%lx 0x%lx] [0x%lx 0x%lx]\n", Out.Return, Out.Granted[0], Out.Status[0],
          Out.Granted[2], Out.Status[2]);
    CHECK(Out.Granted[3] == SENTINEL, "ResultList wrote past the list\n");

    CallByHandle(Sd, Tokens[K_SELF], Tokens[K_SELF], R1, Flags, List, 3, &Out);
    CHECK(Out.Return && Out.Status[0] == ERROR_SUCCESS && Out.Granted[0] == R1,
          "ByHandle granted: ret %d [0x%lx 0x%lx]\n", Out.Return, Out.Granted[0], Out.Status[0]);

    /* MAXIMUM_ALLOWED: the rights of the DACL, plus READ_CONTROL and WRITE_DAC for the owner */
    CallByTypeAndAuditAlarm(Sd, Tokens[K_SELF], MAXIMUM_ALLOWED, Flags, NULL, 0, &Out);
    CHECK(Out.Return && Out.Granted[0] == R1, "ByType MAXIMUM_ALLOWED: ret %d err %lu granted 0x%lx\n",
          Out.Return, Out.Error, Out.Granted[0]);
    CallByTypeAndAuditAlarm(SdOwned, Tokens[K_SELF], MAXIMUM_ALLOWED, Flags, NULL, 0, &Out);
    CHECK(Out.Return && Out.Granted[0] == (R1 | READ_CONTROL | WRITE_DAC),
          "ByType MAXIMUM_ALLOWED owner: ret %d err %lu granted 0x%lx\n", Out.Return, Out.Error, Out.Granted[0]);

    /*
     * A type list with a result per entry: {root, A, C under A, B}. DACL: allow R2 on A (object ACE),
     * deny R4 on B (object ACE), allow R1|R4 (plain). Asking R2: A and C (under A) are granted it;
     * B (not under A) and the root (B lacks it) are not.
     */
    MakeList(&Lists[2], List);
    CallResultListAndAuditAlarm(SdObject, Tokens[K_SELF], R2, Flags, List, 4, &Out);
    CHECK(Out.Return, "ResultList object ACEs: ret %d err %lu\n", Out.Return, Out.Error);
    CHECK(Out.Status[0] == ERROR_ACCESS_DENIED && Out.Granted[0] == 0, "root: [0x%lx 0x%lx]\n", Out.Granted[0],
          Out.Status[0]);
    CHECK(Out.Status[1] == ERROR_SUCCESS && Out.Granted[1] == R2, "A: [0x%lx 0x%lx]\n", Out.Granted[1],
          Out.Status[1]);
    CHECK(Out.Status[2] == ERROR_SUCCESS && Out.Granted[2] == R2, "C: [0x%lx 0x%lx]\n", Out.Granted[2],
          Out.Status[2]);
    CHECK(Out.Status[3] == ERROR_ACCESS_DENIED && Out.Granted[3] == 0, "B: [0x%lx 0x%lx]\n", Out.Granted[3],
          Out.Status[3]);
    /* Asking R4: B is denied it by its object ACE (before the plain allow); A and C have it */
    CallByHandle(SdObject, Tokens[K_SELF], Tokens[K_SELF], R4, Flags, List, 4, &Out);
    CHECK(Out.Return && Out.Status[1] == ERROR_SUCCESS && Out.Granted[1] == R4 && Out.Status[2] == ERROR_SUCCESS &&
          Out.Status[3] == ERROR_ACCESS_DENIED && Out.Granted[3] == 0,
          "ByHandle object ACEs R4: ret %d [0x%lx 0x%lx] [0x%lx 0x%lx] [0x%lx 0x%lx]\n", Out.Return,
          Out.Granted[1], Out.Status[1], Out.Granted[2], Out.Status[2], Out.Granted[3], Out.Status[3]);
    /* Without a result list the object is the root: R2 is denied (B, a child of the root, lacks it) */
    CallByTypeAndAuditAlarm(SdObject, Tokens[K_SELF], R2, Flags, List, 4, &Out);
    CHECK(Out.Return && Out.Status[0] == FALSE && Out.Error == ERROR_ACCESS_DENIED, "ByType object ACEs: ret %d err %lu\n", Out.Return,
          Out.Error);

    /* A restricted token: the DACL allows Administrators only, the restricting SID is Everyone */
    HeapFree(GetProcessHeap(), 0, Sd);
    Sd = DescriptorByName("allow-admins-7", S_NOBODY);
    if (Sd)
    {
        CallByTypeAndAuditAlarm(Sd, Tokens[K_RESTRICTED], R1, Flags, NULL, 0, &Out);
        CHECK(Out.Return && Out.Status[0] == FALSE && Out.Error == ERROR_ACCESS_DENIED, "restricted token: ret %d err %lu\n", Out.Return,
              Out.Error);
        CallByTypeAndAuditAlarm(Sd, Tokens[K_ADMINS_DENY_ONLY], R1, Flags, NULL, 0, &Out);
        CHECK(Out.Return && Out.Status[0] == FALSE && Out.Error == ERROR_ACCESS_DENIED, "deny-only Administrators: ret %d err %lu\n",
              Out.Return, Out.Error);
        if (Flags == AUDIT_ALLOW_NO_PRIVILEGE)
        {
            /* (an administrator) */
            CallByTypeAndAuditAlarm(Sd, Tokens[K_SELF], R1 | R2 | R4, Flags, NULL, 0, &Out);
            CHECK(Out.Return && Out.Granted[0] == (R1 | R2 | R4), "Administrators: ret %d err %lu granted 0x%lx\n",
                  Out.Return, Out.Error, Out.Granted[0]);
        }
    }

    /* An identification level client is enough */
    CallByTypeAndAuditAlarm(SdOwned, Tokens[K_IDENTIFICATION], R1, Flags, NULL, 0, &Out);
    CHECK(Out.Return && Out.Granted[0] == R1, "identification level: ret %d err %lu\n", Out.Return, Out.Error);

    /* Not impersonating: the thread forms fail */
    CallByTypeAndAuditAlarm(SdOwned, NULL, R1, Flags, NULL, 0, &Out);
    CHECK(!Out.Return && Out.Error == ERROR_NO_IMPERSONATION_TOKEN, "ByType not impersonating: ret %d err %lu\n",
          Out.Return, Out.Error);
    CheckOutputsUntouched(__LINE__, "ByType not impersonating", &Out, 0);
    CallResultListAndAuditAlarm(SdOwned, NULL, R1, Flags, List, 3, &Out);
    CHECK(!Out.Return && Out.Error == ERROR_NO_IMPERSONATION_TOKEN,
          "ResultList not impersonating: ret %d err %lu\n", Out.Return, Out.Error);
    CheckOutputsUntouched(__LINE__, "ResultList not impersonating", &Out, 3);

    /* Parameters: a request with generic rights, a bad audit type, no owner, an empty result list */
    CallByTypeAndAuditAlarm(SdOwned, Tokens[K_SELF], GENERIC_READ, Flags, NULL, 0, &Out);
    CHECK(!Out.Return && Out.Error == ERROR_GENERIC_NOT_MAPPED, "generic rights: ret %d err %lu\n", Out.Return,
          Out.Error);
    CallResultListAndAuditAlarm(SdOwned, Tokens[K_SELF], R1, Flags, List, 0, &Out);
    CHECK(!Out.Return && Out.Error == ERROR_INVALID_PARAMETER, "empty result list: ret %d err %lu\n", Out.Return,
          Out.Error);
    CheckOutputsUntouched(__LINE__, "empty result list", &Out, 1);
    {
        BOOL Return;
        DWORD Granted = SENTINEL, Status = SENTINEL;
        BOOL OnClose = 0x55;
        SECURITY_DESCRIPTOR NoOwner;

        Impersonate(Tokens[K_SELF]);
        SetLastError(0xdeadbeef);
        Return = AccessCheckByTypeAndAuditAlarmW(L"AccessCheckAuditAlarm", NULL, L"TestObject", L"Object", SdOwned,
                                                 NULL, R1, (AUDIT_EVENT_TYPE)7, Flags, NULL, 0, &Mapping, FALSE,
                                                 &Granted, (LPBOOL)&Status, &OnClose);
        CHECK(!Return && GetLastError() == ERROR_INVALID_PARAMETER, "bad audit type: ret %d err %lu\n", Return,
              GetLastError());

        InitializeSecurityDescriptor(&NoOwner, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorDacl(&NoOwner, TRUE, NULL, FALSE);
        SetLastError(0xdeadbeef);
        Return = AccessCheckByTypeAndAuditAlarmW(L"AccessCheckAuditAlarm", NULL, L"TestObject", L"Object", &NoOwner,
                                                 NULL, R1, AuditEventObjectAccess, Flags, NULL, 0, &Mapping, FALSE,
                                                 &Granted, (LPBOOL)&Status, &OnClose);
        CHECK(!Return && GetLastError() == ERROR_INVALID_SECURITY_DESCR, "no owner: ret %d err %lu\n", Return,
              GetLastError());
        CHECK(Granted == SENTINEL && Status == SENTINEL, "no owner: outputs written\n");
        CHECK(OnClose == FALSE, "no owner: on close %d (written FALSE on a failure, as on Windows)\n", OnClose);

        /* The ANSI forms */
        SetLastError(0xdeadbeef);
        Return = AccessCheckByTypeAndAuditAlarmA("AccessCheckAuditAlarm", NULL, "TestObject", NULL, SdOwned, NULL, R2,
                                                 AuditEventObjectAccess, Flags, NULL, 0, &Mapping, FALSE, &Granted,
                                                 (LPBOOL)&Status, &OnClose);
        CHECK(Return && GetLastError() == ERROR_ACCESS_DENIED && Status == FALSE && Granted == 0,
              "ByTypeA denied: ret %d err %lu\n", Return, GetLastError());
        Granted = Status = SENTINEL;
        Return = AccessCheckByTypeResultListAndAuditAlarmA("AccessCheckAuditAlarm", NULL, "TestObject", "Object",
                                                           SdOwned, NULL, R1, AuditEventObjectAccess, Flags, List, 1,
                                                           &Mapping, FALSE, &Granted, &Status, &OnClose);
        CHECK(Return && Status == ERROR_SUCCESS && Granted == R1, "ResultListA granted: ret %d [0x%lx 0x%lx]\n",
              Return, Granted, Status);
        Granted = Status = SENTINEL;
        Return = AccessCheckByTypeResultListAndAuditAlarmByHandleA("AccessCheckAuditAlarm", NULL, Tokens[K_SELF],
                                                                   "TestObject", "Object", SdOwned, NULL, R8,
                                                                   AuditEventObjectAccess, Flags, List, 1, &Mapping,
                                                                   FALSE, &Granted, &Status, &OnClose);
        CHECK(Return && Status == ERROR_ACCESS_DENIED && Granted == 0, "ByHandleA denied: ret %d [0x%lx 0x%lx]\n",
              Return, Granted, Status);
        Revert();
    }

Done:
    if (Sd)
        HeapFree(GetProcessHeap(), 0, Sd);
    if (SdOwned)
        HeapFree(GetProcessHeap(), 0, SdOwned);
    if (SdObject)
        HeapFree(GetProcessHeap(), 0, SdObject);
}

/* The token rows of the ByHandle form */
static void ByHandleTokenRows(DWORD Flags)
{
    PSECURITY_DESCRIPTOR Sd = DescriptorByName("allow-everyone-1", S_NOBODY);
    OBJECT_TYPE_LIST List[4];
    OUTCOME Out;
    HANDLE Process, NoQuery = NULL, Anonymous = NULL;

    if (!Sd)
        return;
    MakeList(&Lists[1], List);

    /* No TOKEN_QUERY access */
    if (DuplicateHandle(GetCurrentProcess(), Tokens[K_SELF], GetCurrentProcess(), &NoQuery, TOKEN_IMPERSONATE,
                        FALSE, 0))
    {
        CallByHandle(Sd, Tokens[K_SELF], NoQuery, R1, Flags, List, 3, &Out);
        CHECK(!Out.Return && Out.Error == ERROR_ACCESS_DENIED, "token without TOKEN_QUERY: ret %d err %lu\n",
              Out.Return, Out.Error);
        CheckOutputsUntouched(__LINE__, "token without TOKEN_QUERY", &Out, 3);
        CloseHandle(NoQuery);
    }

    /* Not a token */
    CallByHandle(Sd, Tokens[K_SELF], GetCurrentProcess(), R1, Flags, List, 3, &Out);
    CHECK(!Out.Return, "process handle as token: ret %d err %lu\n", Out.Return, Out.Error);
    CallByHandle(Sd, Tokens[K_SELF], (HANDLE)(ULONG_PTR)0x7ffc, R1, Flags, List, 3, &Out);
    CHECK(!Out.Return && Out.Error == ERROR_INVALID_HANDLE, "bad token handle: ret %d err %lu\n", Out.Return,
          Out.Error);
    CheckOutputsUntouched(__LINE__, "bad token handle", &Out, 3);

    /* The token pseudo handles name no token here (Windows Server 2022: ERROR_INVALID_HANDLE) */
    CallByHandle(Sd, Tokens[K_SELF], (HANDLE)(LONG_PTR)-4, R1, Flags, List, 3, &Out);
    CHECK(!Out.Return && Out.Error == ERROR_INVALID_HANDLE, "process token pseudo handle: ret %d err %lu\n",
          Out.Return, Out.Error);
    CheckOutputsUntouched(__LINE__, "process token pseudo handle", &Out, 3);
    CallByHandle(Sd, Tokens[K_SELF], (HANDLE)(LONG_PTR)-6, R1, Flags, List, 3, &Out);
    CHECK(!Out.Return && Out.Error == ERROR_INVALID_HANDLE, "effective token pseudo handle: ret %d err %lu\n",
          Out.Return, Out.Error);

    /*
     * As measured on Windows Server 2022: the ByHandle form works while the thread is not
     * impersonating and with a primary token; a result list of 0x1001 entries is refused.
     */
    CallByHandle(Sd, NULL, Tokens[K_SELF], R1, Flags, List, 3, &Out);
    CHECK(Out.Return && Out.Granted[0] == R1 && Out.Status[0] == ERROR_SUCCESS,
          "ByHandle not impersonating: ret %d err %lu [0x%lx 0x%lx]\n", Out.Return, Out.Error,
          Out.Granted[0], Out.Status[0]);
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Process))
    {
        CallByHandle(Sd, Tokens[K_SELF], Process, R1, Flags, List, 3, &Out);
        CHECK(Out.Return && Out.Granted[0] == R1 && Out.Status[0] == ERROR_SUCCESS,
              "ByHandle primary token: ret %d err %lu [0x%lx 0x%lx]\n", Out.Return, Out.Error,
              Out.Granted[0], Out.Status[0]);
        CloseHandle(Process);
    }
    {
        OBJECT_TYPE_LIST *Big = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x1001 * sizeof(*Big));
        GUID *BigGuids = HeapAlloc(GetProcessHeap(), 0, 0x1001 * sizeof(GUID));
        DWORD *Granted = HeapAlloc(GetProcessHeap(), 0, 0x1001 * sizeof(DWORD));
        DWORD *Status = HeapAlloc(GetProcessHeap(), 0, 0x1001 * sizeof(DWORD));
        BOOL OnClose, Return;
        DWORD i;

        if (Big && BigGuids && Granted && Status)
        {
            for (i = 0; i < 0x1001; i++)
            {
                BigGuids[i] = Guids[G_ROOT];
                BigGuids[i].Data1 += i;
                Big[i].Level = i ? ACCESS_PROPERTY_SET_GUID : ACCESS_OBJECT_GUID;
                Big[i].ObjectType = &BigGuids[i];
            }
            Impersonate(Tokens[K_SELF]);
            SetLastError(0xdeadbeef);
            Return = AccessCheckByTypeResultListAndAuditAlarmW(L"AccessCheckAuditAlarm", NULL, L"TestObject",
                                                               L"Object", Sd, NULL, R1, AuditEventObjectAccess, Flags,
                                                               Big, 0x1001, &Mapping, FALSE, Granted, Status,
                                                               &OnClose);
            CHECK(!Return && GetLastError() == ERROR_INVALID_PARAMETER, "ResultList of 0x1001 entries: ret %d err %lu\n",
                  Return, GetLastError());
            Revert();
        }
        HeapFree(GetProcessHeap(), 0, Big);
        HeapFree(GetProcessHeap(), 0, BigGuids);
        HeapFree(GetProcessHeap(), 0, Granted);
        HeapFree(GetProcessHeap(), 0, Status);
    }

    /*
     * An anonymous level token cannot identify the client. Windows Server 2022 evaluates such a token
     * given by handle (the thread forms refuse it there too); NtAccessCheck refuses it on both systems,
     * so this form refuses it as well rather than grant what the access check itself does not.
     */
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE, &Process))
    {
        Anonymous = ImpersonationCopy(Process, SecurityAnonymous);
        CloseHandle(Process);
    }
    if (Anonymous)
    {
        CallByHandle(Sd, Tokens[K_SELF], Anonymous, R1, Flags, List, 3, &Out);
        CHECK(!Out.Return && Out.Error == ERROR_BAD_IMPERSONATION_LEVEL, "anonymous token handle: ret %d err %lu\n",
              Out.Return, Out.Error);
        CheckOutputsUntouched(__LINE__, "anonymous token handle", &Out, 3);

        if (SetThreadToken(NULL, Anonymous))
        {
            OUTCOME Thread;
            BOOL Return;

            ResetOutcome(&Thread);
            SetLastError(0xdeadbeef);
            Return = AccessCheckByTypeAndAuditAlarmW(L"AccessCheckAuditAlarm", NULL, L"TestObject", L"Object", Sd,
                                                     NULL, R1, AuditEventObjectAccess, Flags, NULL, 0, &Mapping,
                                                     FALSE, &Thread.Granted[0], (LPBOOL)&Thread.Status[0],
                                                     &Thread.GenerateOnClose);
            Finish(&Thread, Return);
            RevertToSelf();
            CHECK(!Thread.Return && Thread.Error == ERROR_BAD_IMPERSONATION_LEVEL,
                  "anonymous impersonation: ret %d err %lu\n", Thread.Return, Thread.Error);
        }
        else
        {
            Note("SetThreadToken(anonymous) failed with %lu\n", GetLastError());
        }
        CloseHandle(Anonymous);
    }

    HeapFree(GetProcessHeap(), 0, Sd);
}

/* Part 1: an administrator without SeAuditPrivilege */
static void RunWithoutPrivilege(void)
{
    PSECURITY_DESCRIPTOR Sd = DescriptorByName("null", S_SYSTEM);
    OBJECT_TYPE_LIST List[4];
    OUTCOME Out;

    if (!Sd)
        return;
    MakeList(&Lists[1], List);

    /* Flags 0: the four forms need the privilege, and nothing is written */
    CallAndAuditAlarm(Sd, Tokens[K_SELF], R1, &Out);
    CHECK(!Out.Return && Out.Error == ERROR_PRIVILEGE_NOT_HELD, "AndAuditAlarm without privilege: ret %d err %lu\n",
          Out.Return, Out.Error);
    CheckOutputsUntouched(__LINE__, "AndAuditAlarm without privilege", &Out, 0);
    CallByTypeAndAuditAlarm(Sd, Tokens[K_SELF], R1, 0, NULL, 0, &Out);
    CHECK(!Out.Return && Out.Error == ERROR_PRIVILEGE_NOT_HELD, "ByType without privilege: ret %d err %lu\n",
          Out.Return, Out.Error);
    CheckOutputsUntouched(__LINE__, "ByType without privilege", &Out, 0);
    CallResultListAndAuditAlarm(Sd, Tokens[K_SELF], R1, 0, List, 3, &Out);
    CHECK(!Out.Return && Out.Error == ERROR_PRIVILEGE_NOT_HELD, "ResultList without privilege: ret %d err %lu\n",
          Out.Return, Out.Error);
    CheckOutputsUntouched(__LINE__, "ResultList without privilege", &Out, 3);
    CallByHandle(Sd, Tokens[K_SELF], Tokens[K_SELF], R1, 0, List, 3, &Out);
    CHECK(!Out.Return && Out.Error == ERROR_PRIVILEGE_NOT_HELD, "ByHandle without privilege: ret %d err %lu\n",
          Out.Return, Out.Error);
    CheckOutputsUntouched(__LINE__, "ByHandle without privilege", &Out, 3);

    /* The privilege of the client token does not count: the primary token of the process is checked */
    HeapFree(GetProcessHeap(), 0, Sd);

    ByTypeRows(AUDIT_ALLOW_NO_PRIVILEGE);
    ByHandleTokenRows(AUDIT_ALLOW_NO_PRIVILEGE);
    Matrix(AUDIT_ALLOW_NO_PRIVILEGE, FALSE);
}

/* Part 2: LocalSystem, SeAuditPrivilege enabled */
static void RunWithPrivilege(void)
{
    PSECURITY_DESCRIPTOR Sd = DescriptorByName("allow-everyone-1", S_NOBODY);
    PSECURITY_DESCRIPTOR SdOwned = DescriptorByName("allow-everyone-1", S_USER);
    OUTCOME Out;

    if (!Sd || !SdOwned)
    {
        CHECK(FALSE, "descriptors could not be made\n");
        goto Done;
    }

    /* AccessCheckAndAuditAlarm: denied, granted, MAXIMUM_ALLOWED */
    CallAndAuditAlarm(Sd, Tokens[K_SELF], R2, &Out);
    CHECK(Out.Return && Out.Error == ERROR_ACCESS_DENIED && Out.Status[0] == FALSE && Out.Granted[0] == 0,
          "AndAuditAlarm denied: ret %d err %lu status %lu granted 0x%lx\n", Out.Return, Out.Error, Out.Status[0],
          Out.Granted[0]);
    CallAndAuditAlarm(Sd, Tokens[K_SELF], R1, &Out);
    CHECK(Out.Return && Out.Status[0] == TRUE && Out.Granted[0] == R1 && Out.GenerateOnClose == FALSE,
          "AndAuditAlarm granted: ret %d err %lu status %lu granted 0x%lx\n", Out.Return, Out.Error, Out.Status[0],
          Out.Granted[0]);
    CallAndAuditAlarm(SdOwned, Tokens[K_SELF], MAXIMUM_ALLOWED, &Out);
    CHECK(Out.Return && Out.Granted[0] == (R1 | READ_CONTROL | WRITE_DAC),
          "AndAuditAlarm MAXIMUM_ALLOWED owner: ret %d err %lu granted 0x%lx\n", Out.Return, Out.Error,
          Out.Granted[0]);
    CallAndAuditAlarm(Sd, NULL, R1, &Out);
    CHECK(!Out.Return && Out.Error == ERROR_NO_IMPERSONATION_TOKEN, "AndAuditAlarm not impersonating: ret %d err %lu\n",
          Out.Return, Out.Error);
    CheckOutputsUntouched(__LINE__, "AndAuditAlarm not impersonating", &Out, 0);
    /* ACCESS_SYSTEM_SECURITY needs SeSecurityPrivilege in the client token */
    CallAndAuditAlarm(Sd, Tokens[K_PRIVILEGED], ACCESS_SYSTEM_SECURITY, &Out);
    CHECK(Out.Return && Out.Granted[0] == ACCESS_SYSTEM_SECURITY, "ACCESS_SYSTEM_SECURITY: ret %d err %lu granted 0x%lx\n",
          Out.Return, Out.Error, Out.Granted[0]);
    {
        BOOL Return;
        DWORD Granted = SENTINEL;
        BOOL Status = 0x55, OnClose = 0x55;

        Impersonate(Tokens[K_SELF]);
        Return = AccessCheckAndAuditAlarmA("AccessCheckAuditAlarm", NULL, "TestObject", NULL, Sd, R4, &Mapping, TRUE,
                                           &Granted, &Status, &OnClose);
        Revert();
        CHECK(Return && Status == FALSE && Granted == 0 && OnClose == FALSE,
              "AndAuditAlarmA denied: ret %d status %d granted 0x%lx on close %d\n", Return, Status, Granted, OnClose);
    }

    ByTypeRows(0);
    ByHandleTokenRows(0);
    Matrix(0, TRUE);

Done:
    if (Sd)
        HeapFree(GetProcessHeap(), 0, Sd);
    if (SdOwned)
        HeapFree(GetProcessHeap(), 0, SdOwned);
}

/* The service */

static WCHAR ServiceName[64];
static WCHAR ResultFileName[MAX_PATH];
static SERVICE_STATUS_HANDLE StatusHandle;

static void ServiceWork(void)
{
    HANDLE Process;
    char Line[64];
    DWORD Written;

    ReportFile = CreateFileW(ResultFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (ReportFile == INVALID_HANDLE_VALUE)
        return;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Process) ||
        !EnablePrivilege(Process, SE_AUDIT_NAME))
    {
        WriteFile(ReportFile, "NOPRIVILEGE\r\n", 13, &Written, NULL);
    }
    else if (!MakeSids() || !MakeTokens())
    {
        WriteFile(ReportFile, "NOSETUP\r\n", 9, &Written, NULL);
    }
    else
    {
        RunWithPrivilege();
        _snprintf(Line, sizeof(Line) - 1, "DONE %ld %ld\r\n", ServiceChecks, ServiceFailures);
        Line[sizeof(Line) - 1] = 0;
        WriteFile(ReportFile, Line, (DWORD)strlen(Line), &Written, NULL);
    }
    FreeTokens();
    FreeSids();
    CloseHandle(ReportFile);
    ReportFile = INVALID_HANDLE_VALUE;
}

static void ReportState(DWORD State)
{
    SERVICE_STATUS Status;

    RtlZeroMemory(&Status, sizeof(Status));
    Status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    Status.dwCurrentState = State;
    Status.dwControlsAccepted = 0;
    Status.dwWaitHint = (State == SERVICE_RUNNING || State == SERVICE_STOPPED) ? 0 : 5000;
    SetServiceStatus(StatusHandle, &Status);
}

static DWORD WINAPI ServiceHandler(DWORD Control, DWORD EventType, LPVOID EventData, LPVOID Context)
{
    return NO_ERROR;
}

static VOID WINAPI ServiceMain(DWORD argc, LPWSTR *argv)
{
    StatusHandle = RegisterServiceCtrlHandlerExW(ServiceName, ServiceHandler, NULL);
    if (!StatusHandle)
        return;
    ReportState(SERVICE_RUNNING);
    ServiceWork();
    ReportState(SERVICE_STOPPED);
}

static void ServiceProcess(PCSTR Name, PCSTR File)
{
    SERVICE_TABLE_ENTRYW Table[2];

    InService = TRUE;
    MultiByteToWideChar(CP_ACP, 0, Name, -1, ServiceName, _countof(ServiceName));
    MultiByteToWideChar(CP_ACP, 0, File, -1, ResultFileName, _countof(ResultFileName));
    Table[0].lpServiceName = ServiceName;
    Table[0].lpServiceProc = ServiceMain;
    Table[1].lpServiceName = NULL;
    Table[1].lpServiceProc = NULL;
    StartServiceCtrlDispatcherW(Table);
}

static BOOL WaitStopped(SC_HANDLE Service)
{
    SERVICE_STATUS_PROCESS Status;
    DWORD Needed, Waited;

    for (Waited = 0; Waited <= 600000; Waited += 200)
    {
        if (QueryServiceStatusEx(Service, SC_STATUS_PROCESS_INFO, (LPBYTE)&Status, sizeof(Status), &Needed) &&
            Status.dwCurrentState == SERVICE_STOPPED)
            return TRUE;
        Sleep(200);
    }
    return FALSE;
}

static void RunService(void)
{
    CHAR FileName[MAX_PATH], Command[2 * MAX_PATH + 128], Name[64], Result[MAX_PATH], Temp[MAX_PATH];
    WCHAR CommandW[2 * MAX_PATH + 128], NameW[64];
    SC_HANDLE Scm, Service;
    HANDLE File;
    char *Text, *Line, *Next;
    DWORD Size, Read = 0;
    BOOL Done = FALSE;

    Scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!Scm)
    {
        skip("OpenSCManager failed with %lu\n", GetLastError());
        return;
    }

    GetModuleFileNameA(NULL, FileName, _countof(FileName));
    GetTempPathA(_countof(Temp), Temp);
    StringCbPrintfA(Name, sizeof(Name), "RosAcAuditAlarm%lu", GetTickCount());
    StringCbPrintfA(Result, sizeof(Result), "%s%s.txt", Temp, Name);
    StringCbPrintfA(Command, sizeof(Command), "\"%s\" AccessCheckAuditAlarm service %s \"%s\"", FileName, Name,
                    Result);
    MultiByteToWideChar(CP_ACP, 0, Command, -1, CommandW, _countof(CommandW));
    MultiByteToWideChar(CP_ACP, 0, Name, -1, NameW, _countof(NameW));

    DeleteFileA(Result);
    Service = CreateServiceW(Scm, NameW, NameW, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                             SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, CommandW, NULL, NULL, NULL, NULL, NULL);
    if (!Service)
    {
        skip("CreateService failed with %lu\n", GetLastError());
        CloseServiceHandle(Scm);
        return;
    }

    ok(StartServiceW(Service, 0, NULL), "StartService failed with %lu\n", GetLastError());
    ok(WaitStopped(Service), "the service did not finish\n");
    DeleteService(Service);
    CloseServiceHandle(Service);
    CloseServiceHandle(Scm);

    File = CreateFileA(Result, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "the service wrote no result (%lu)\n", GetLastError());
    if (File == INVALID_HANDLE_VALUE)
        return;
    Size = GetFileSize(File, NULL);
    Text = HeapAlloc(GetProcessHeap(), 0, Size + 1);
    if (Text)
    {
        ReadFile(File, Text, Size, &Read, NULL);
        Text[Read] = 0;
    }
    CloseHandle(File);
    DeleteFileA(Result);
    if (!Text)
        return;

    for (Line = Text; Line && *Line; Line = Next)
    {
        Next = strchr(Line, '\n');
        if (Next)
            *Next++ = 0;
        if (strchr(Line, '\r'))
            *strchr(Line, '\r') = 0;

        if (!strncmp(Line, "FAIL ", 5))
        {
            ok(0, "service: %s\n", Line + 5);
        }
        else if (!strncmp(Line, "NOTE ", 5))
        {
            trace("service: %s\n", Line + 5);
        }
        else if (!strncmp(Line, "DONE ", 5))
        {
            long Checks = 0, Failures = -1;

            Done = TRUE;
            sscanf(Line + 5, "%ld %ld", &Checks, &Failures);
            ok(Failures == 0, "service: %ld of %ld checks failed\n", Failures, Checks);
            ok(Checks > 10000, "service: only %ld checks ran\n", Checks);
        }
        else if (!strncmp(Line, "NO", 2))
        {
            skip("the service could not run the rows: %s\n", Line);
            Done = TRUE;
        }
    }
    ok(Done, "the service did not finish its rows\n");
    HeapFree(GetProcessHeap(), 0, Text);
}

START_TEST(AccessCheckAuditAlarm)
{
    int argc;
    char **argv;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 5 && !strcmp(argv[2], "service"))
    {
        ServiceProcess(argv[3], argv[4]);
        return;
    }

    if (!MakeSids() || !MakeTokens())
    {
        skip("the SIDs and tokens could not be made\n");
        FreeTokens();
        FreeSids();
        return;
    }

    RunWithoutPrivilege();

    FreeTokens();
    FreeSids();

    /* "probe": part 1 only, nothing is created (a read-only run on Windows) */
    if (argc >= 3 && !strcmp(argv[2], "probe"))
        return;

    /* Part 2 */
    RunService();
}
