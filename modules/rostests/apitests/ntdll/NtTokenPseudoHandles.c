/*
 * PROJECT:         ReactOS API tests
 * LICENSE:         LGPLv2.1+ - See COPYING.LIB in the top level directory
 * PURPOSE:         Tests for the Windows 8+ token pseudo handles:
 *                  NtCurrentProcessToken() (-4), NtCurrentThreadToken() (-5)
 *                  and NtCurrentEffectiveToken() (-6)
 *
 * The expectations were measured on Windows 10 22H2 (build 19045), x64 native
 * and 32-bit under WOW64, which behave the same:
 *  - NtQueryInformationToken and the NtAccessCheck family accept the three
 *    values (for TOKEN_QUERY, and TOKEN_QUERY_SOURCE for TokenSource);
 *  - everything else that takes a token handle, or any other handle, fails
 *    with STATUS_INVALID_HANDLE;
 *  - -4 is the primary token, -5 the impersonation token of the thread
 *    (STATUS_NO_TOKEN without one), -6 the impersonation token or, without
 *    one, the primary token;
 *  - NtAccessCheck on a pseudo handle accepts the primary token, which a real
 *    handle to it does not (STATUS_NO_IMPERSONATION_TOKEN);
 *  - NtClose of -1 .. -6 succeeds and does nothing.
 */

#include "precomp.h"

#ifndef NtCurrentProcessToken
#define NtCurrentProcessToken()     ((HANDLE)(LONG_PTR)-4)
#define NtCurrentThreadToken()      ((HANDLE)(LONG_PTR)-5)
#define NtCurrentEffectiveToken()   ((HANDLE)(LONG_PTR)-6)
#endif
#define PSEUDO_PROCESS_TOKEN    ((HANDLE)(LONG_PTR)-4)
#define PSEUDO_THREAD_TOKEN     ((HANDLE)(LONG_PTR)-5)
#define PSEUDO_EFFECTIVE_TOKEN  ((HANDLE)(LONG_PTR)-6)

static
NTSTATUS
QueryClass(
    _In_ HANDLE Handle,
    _In_ TOKEN_INFORMATION_CLASS Class,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ ULONG Size)
{
    ULONG Length;

    return NtQueryInformationToken(Handle, Class, Buffer, Size, &Length);
}

static
VOID
GetTokenId(
    _In_ HANDLE Handle,
    _Out_ PLUID TokenId,
    _Out_ PNTSTATUS OutStatus)
{
    TOKEN_STATISTICS Statistics;

    RtlZeroMemory(&Statistics, sizeof(Statistics));
    *OutStatus = QueryClass(Handle, TokenStatistics, &Statistics, sizeof(Statistics));
    *TokenId = Statistics.TokenId;
}

static
ULONG
PrivilegeCount(
    _In_ HANDLE Handle)
{
    UCHAR Buffer[1024];
    NTSTATUS Status;

    Status = QueryClass(Handle, TokenPrivileges, Buffer, sizeof(Buffer));
    ok_hex(Status, STATUS_SUCCESS);
    return NT_SUCCESS(Status) ? ((PTOKEN_PRIVILEGES)Buffer)->PrivilegeCount : 0;
}

static
VOID
CheckType(
    _In_ PCSTR Name,
    _In_ HANDLE Handle,
    _In_ NTSTATUS ExpectedStatus,
    _In_ TOKEN_TYPE ExpectedType,
    _In_ SECURITY_IMPERSONATION_LEVEL ExpectedLevel)
{
    NTSTATUS Status;
    TOKEN_TYPE Type = 0xdead;
    SECURITY_IMPERSONATION_LEVEL Level = 0xdead;

    Status = QueryClass(Handle, TokenType, &Type, sizeof(Type));
    ok(Status == ExpectedStatus, "%s: TokenType Status = 0x%lx, expected 0x%lx\n", Name, Status, ExpectedStatus);
    if (!NT_SUCCESS(ExpectedStatus))
        return;

    ok(Type == ExpectedType, "%s: TokenType = %d, expected %d\n", Name, Type, ExpectedType);
    Status = QueryClass(Handle, TokenImpersonationLevel, &Level, sizeof(Level));
    if (ExpectedType == TokenPrimary)
    {
        ok(Status == STATUS_INVALID_INFO_CLASS, "%s: TokenImpersonationLevel Status = 0x%lx\n", Name, Status);
    }
    else
    {
        ok(Status == STATUS_SUCCESS, "%s: TokenImpersonationLevel Status = 0x%lx\n", Name, Status);
        ok(Level == ExpectedLevel, "%s: TokenImpersonationLevel = %d, expected %d\n", Name, Level, ExpectedLevel);
    }
}

/* Query classes, compared against a real handle to the same token */
static
VOID
CheckQueryAgainstRealToken(
    _In_ PCSTR Name,
    _In_ HANDLE Pseudo,
    _In_ HANDLE Real)
{
    static const TOKEN_INFORMATION_CLASS Classes[] =
    {
        TokenUser, TokenGroups, TokenPrivileges, TokenOwner, TokenPrimaryGroup, TokenDefaultDacl,
        TokenSource, TokenStatistics, TokenRestrictedSids, TokenSessionId, TokenGroupsAndPrivileges,
        TokenSandBoxInert, TokenOrigin, TokenElevationType, TokenLinkedToken, TokenHasRestrictions,
        TokenAccessInformation, TokenIntegrityLevel, TokenUIAccess, TokenMandatoryPolicy,
        TokenIsAppContainer,
    };
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(Classes); i++)
    {
        UCHAR PseudoBuffer[2048], RealBuffer[2048];
        ULONG PseudoLength = 0, RealLength = 0;
        NTSTATUS PseudoStatus, RealStatus;

        RtlFillMemory(PseudoBuffer, sizeof(PseudoBuffer), 0x11);
        RtlFillMemory(RealBuffer, sizeof(RealBuffer), 0x11);
        PseudoStatus = NtQueryInformationToken(Pseudo, Classes[i], PseudoBuffer, sizeof(PseudoBuffer), &PseudoLength);
        RealStatus = NtQueryInformationToken(Real, Classes[i], RealBuffer, sizeof(RealBuffer), &RealLength);
        ok(PseudoStatus == RealStatus, "%s: class %d: pseudo 0x%lx, real 0x%lx\n",
           Name, Classes[i], PseudoStatus, RealStatus);
        if (Classes[i] == TokenLinkedToken)
        {
            /* The linked token comes back as a new handle each time */
            if (NT_SUCCESS(PseudoStatus) && *(PHANDLE)PseudoBuffer != NULL)
                NtClose(*(PHANDLE)PseudoBuffer);
            if (NT_SUCCESS(RealStatus) && *(PHANDLE)RealBuffer != NULL)
                NtClose(*(PHANDLE)RealBuffer);
        }
        ok(PseudoLength == RealLength, "%s: class %d: length %lu, real %lu\n",
           Name, Classes[i], PseudoLength, RealLength);
    }

    /* TokenSource needs TOKEN_QUERY_SOURCE: the pseudo handle has it */
    {
        TOKEN_SOURCE Source;
        NTSTATUS Status = QueryClass(Pseudo, TokenSource, &Source, sizeof(Source));
        ok_hex(Status, STATUS_SUCCESS);
    }
}

/* Everything a pseudo handle must NOT be accepted by: STATUS_INVALID_HANDLE */
static
VOID
CheckRejected(
    _In_ PCSTR Name,
    _In_ HANDLE Handle,
    _In_ HANDLE RealToken)
{
    NTSTATUS Status;
    HANDLE NewHandle;
    OBJECT_ATTRIBUTES ObjectAttributes;
    ULONG i;
    UCHAR Buffer[512];
    ULONG Length;
    BOOLEAN Equal, Result;
    PRIVILEGE_SET Privileges;
    LARGE_INTEGER Zero;
    static const ACCESS_MASK Accesses[] =
    {
        0, TOKEN_QUERY, TOKEN_DUPLICATE, TOKEN_QUERY | TOKEN_DUPLICATE, MAXIMUM_ALLOWED, TOKEN_ALL_ACCESS
    };
    static const ULONG Types[] = { TokenPrimary, TokenImpersonation };
    ULONG t;

    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

    for (t = 0; t < RTL_NUMBER_OF(Types); t++)
    {
        for (i = 0; i < RTL_NUMBER_OF(Accesses); i++)
        {
            NewHandle = (HANDLE)0x55555555;
            Status = NtDuplicateToken(Handle, Accesses[i], &ObjectAttributes, FALSE, Types[t], &NewHandle);
            ok(Status == STATUS_INVALID_HANDLE, "%s: NtDuplicateToken(0x%lx, type %lu) = 0x%lx\n",
               Name, Accesses[i], Types[t], Status);
            if (NT_SUCCESS(Status))
                NtClose(NewHandle);
        }
    }

    /* A duplicated handle: the target is a real handle in the table, so these are not the same as NtDuplicateToken */
    NewHandle = (HANDLE)0x55555555;
    Status = NtDuplicateObject(NtCurrentProcess(), Handle, NtCurrentProcess(), &NewHandle, 0, 0, DUPLICATE_SAME_ACCESS);
    ok(Status == STATUS_INVALID_HANDLE, "%s: NtDuplicateObject(SAME_ACCESS) = 0x%lx\n", Name, Status);
    if (NT_SUCCESS(Status))
        NtClose(NewHandle);
    NewHandle = (HANDLE)0x55555555;
    Status = NtDuplicateObject(NtCurrentProcess(), Handle, NtCurrentProcess(), &NewHandle, TOKEN_QUERY, 0, 0);
    ok(Status == STATUS_INVALID_HANDLE, "%s: NtDuplicateObject(TOKEN_QUERY) = 0x%lx\n", Name, Status);
    if (NT_SUCCESS(Status))
        NtClose(NewHandle);
    Status = NtDuplicateObject(NtCurrentProcess(), Handle, NULL, NULL, 0, 0, 0);
    ok(Status == STATUS_INVALID_HANDLE, "%s: NtDuplicateObject(no target) = 0x%lx\n", Name, Status);

    /* Other token services */
    Privileges.PrivilegeCount = 0;
    Privileges.Control = 0;
    Status = NtPrivilegeCheck(Handle, &Privileges, &Result);
    ok(Status == STATUS_INVALID_HANDLE, "%s: NtPrivilegeCheck = 0x%lx\n", Name, Status);
    Status = NtCompareTokens(Handle, RealToken, &Equal);
    ok(Status == STATUS_INVALID_HANDLE, "%s: NtCompareTokens(pseudo, real) = 0x%lx\n", Name, Status);
    Status = NtCompareTokens(RealToken, Handle, &Equal);
    ok(Status == STATUS_INVALID_HANDLE, "%s: NtCompareTokens(real, pseudo) = 0x%lx\n", Name, Status);
    NewHandle = NULL;
    Status = NtFilterToken(Handle, 0, NULL, NULL, NULL, &NewHandle);
    ok(Status == STATUS_INVALID_HANDLE, "%s: NtFilterToken = 0x%lx\n", Name, Status);
    if (NT_SUCCESS(Status))
        NtClose(NewHandle);
    Status = NtAdjustPrivilegesToken(Handle, TRUE, NULL, 0, NULL, NULL);
    ok(Status == STATUS_INVALID_HANDLE, "%s: NtAdjustPrivilegesToken = 0x%lx\n", Name, Status);
    Status = NtAdjustGroupsToken(Handle, TRUE, NULL, 0, NULL, NULL);
    ok(Status == STATUS_INVALID_HANDLE, "%s: NtAdjustGroupsToken = 0x%lx\n", Name, Status);
    Length = 0;
    Status = NtQuerySecurityObject(Handle, DACL_SECURITY_INFORMATION, Buffer, sizeof(Buffer), &Length);
    ok(Status == STATUS_INVALID_HANDLE, "%s: NtQuerySecurityObject = 0x%lx\n", Name, Status);
    {
        /* Needs TOKEN_ADJUST_DEFAULT, which a pseudo handle never carries */
        PTOKEN_DEFAULT_DACL DefaultDacl = (PTOKEN_DEFAULT_DACL)Buffer;

        DefaultDacl->DefaultDacl = NULL;
        Status = NtSetInformationToken(Handle, TokenDefaultDacl, DefaultDacl, sizeof(*DefaultDacl));
        ok(Status == STATUS_INVALID_HANDLE, "%s: NtSetInformationToken = 0x%lx\n", Name, Status);
    }

    /* No other object type, and no handle-table operation, takes these values */
    {
        PROCESS_BASIC_INFORMATION ProcessInfo;
        THREAD_BASIC_INFORMATION ThreadInfo;
        OBJECT_BASIC_INFORMATION ObjectInfo;

        Status = NtQueryObject(Handle, ObjectBasicInformation, &ObjectInfo, sizeof(ObjectInfo), NULL);
        ok(Status == STATUS_INVALID_HANDLE, "%s: NtQueryObject = 0x%lx\n", Name, Status);
        Status = NtQueryInformationProcess(Handle, ProcessBasicInformation, &ProcessInfo, sizeof(ProcessInfo), NULL);
        ok(Status == STATUS_INVALID_HANDLE, "%s: NtQueryInformationProcess = 0x%lx\n", Name, Status);
        Status = NtQueryInformationThread(Handle, ThreadBasicInformation, &ThreadInfo, sizeof(ThreadInfo), NULL);
        ok(Status == STATUS_INVALID_HANDLE, "%s: NtQueryInformationThread = 0x%lx\n", Name, Status);
        NewHandle = NULL;
        Status = NtOpenProcessToken(Handle, TOKEN_QUERY, &NewHandle);
        ok(Status == STATUS_INVALID_HANDLE, "%s: NtOpenProcessToken = 0x%lx\n", Name, Status);
        Status = NtOpenThreadToken(Handle, TOKEN_QUERY, FALSE, &NewHandle);
        ok(Status == STATUS_INVALID_HANDLE, "%s: NtOpenThreadToken = 0x%lx\n", Name, Status);
        Zero.QuadPart = 0;
        Status = NtWaitForSingleObject(Handle, FALSE, &Zero);
        ok(Status == STATUS_INVALID_HANDLE, "%s: NtWaitForSingleObject = 0x%lx\n", Name, Status);
        Status = NtSetEvent(Handle, NULL);
        ok(Status == STATUS_INVALID_HANDLE, "%s: NtSetEvent = 0x%lx\n", Name, Status);
    }
}

/* One security descriptor that allows access 1 to the given SID, and one that allows nobody */
static
VOID
InitSd(
    _Out_ PSECURITY_DESCRIPTOR Sd,
    _Out_writes_bytes_(256) PACL Acl,
    _In_ PSID Sid)
{
    NTSTATUS Status;

    Status = RtlCreateSecurityDescriptor(Sd, SECURITY_DESCRIPTOR_REVISION);
    ok_hex(Status, STATUS_SUCCESS);
    Status = RtlCreateAcl(Acl, 256, ACL_REVISION);
    ok_hex(Status, STATUS_SUCCESS);
    Status = RtlAddAccessAllowedAce(Acl, ACL_REVISION, 1, Sid);
    ok_hex(Status, STATUS_SUCCESS);
    Status = RtlSetDaclSecurityDescriptor(Sd, TRUE, Acl, FALSE);
    ok_hex(Status, STATUS_SUCCESS);
    Status = RtlSetOwnerSecurityDescriptor(Sd, Sid, FALSE);
    ok_hex(Status, STATUS_SUCCESS);
    Status = RtlSetGroupSecurityDescriptor(Sd, Sid, FALSE);
    ok_hex(Status, STATUS_SUCCESS);
}

typedef struct
{
    NTSTATUS Status;
    NTSTATUS AccessStatus;
    ACCESS_MASK Granted;
} ACCESS_RESULT;

static
VOID
RunAccessChecks(
    _In_ HANDLE Handle,
    _In_ PSECURITY_DESCRIPTOR Sd,
    _Out_ ACCESS_RESULT *Plain,
    _Out_ ACCESS_RESULT *ByType,
    _Out_ ACCESS_RESULT *ResultList)
{
    GENERIC_MAPPING Mapping = { 1, 2, 4, 7 };
    UCHAR PrivBuffer[256];
    PPRIVILEGE_SET Priv = (PPRIVILEGE_SET)PrivBuffer;
    ULONG PrivLength = sizeof(PrivBuffer);
    ACCESS_MASK GrantedList[1] = { 0xdead };
    NTSTATUS StatusList[1] = { 0xdeadbeef };
    OBJECT_TYPE_LIST TypeList = { 0, 0, NULL };
    GUID Guid = { 0 };

    RtlZeroMemory(Plain, sizeof(*Plain));
    RtlZeroMemory(ByType, sizeof(*ByType));
    RtlZeroMemory(ResultList, sizeof(*ResultList));

    Plain->Status = NtAccessCheck(Sd, Handle, 1, &Mapping, Priv, &PrivLength, &Plain->Granted, &Plain->AccessStatus);

    TypeList.ObjectType = &Guid;
    PrivLength = sizeof(PrivBuffer);
    ByType->Status = NtAccessCheckByType(Sd, NULL, Handle, 1, NULL, 0, &Mapping,
                                         Priv, &PrivLength, &ByType->Granted, &ByType->AccessStatus);

    PrivLength = sizeof(PrivBuffer);
    ResultList->Status = NtAccessCheckByTypeResultList(Sd, NULL, Handle, 1, &TypeList, 1, &Mapping,
                                                       Priv, &PrivLength, GrantedList, StatusList);
    ResultList->Granted = GrantedList[0];
    ResultList->AccessStatus = StatusList[0];
}

/*
 * The status and result of the three access checks on a pseudo handle must be the
 * same as on a real handle to the token it stands for (ReferenceToken, a real
 * impersonation token). AccessMustBeGranted tells what the Sd is expected to do
 * with that token, so that the comparison cannot pass by both sides denying.
 */
static
VOID
CheckAccessSame(
    _In_ PCSTR Name,
    _In_ HANDLE Handle,
    _In_ PSECURITY_DESCRIPTOR Sd,
    _In_ HANDLE ReferenceToken,
    _In_ BOOLEAN AccessMustBeGranted)
{
    ACCESS_RESULT Pseudo[3], Real[3];
    static const PCSTR Names[3] = { "NtAccessCheck", "NtAccessCheckByType", "NtAccessCheckByTypeResultList" };
    ULONG i;

    RunAccessChecks(Handle, Sd, &Pseudo[0], &Pseudo[1], &Pseudo[2]);
    RunAccessChecks(ReferenceToken, Sd, &Real[0], &Real[1], &Real[2]);

    ok(Real[0].Status == STATUS_SUCCESS, "%s: reference NtAccessCheck Status = 0x%lx\n", Name, Real[0].Status);
    if (AccessMustBeGranted)
        ok(Real[0].AccessStatus == STATUS_SUCCESS && Real[0].Granted == 1, "%s: reference is not granted\n", Name);
    else
        ok(Real[0].AccessStatus == STATUS_ACCESS_DENIED && Real[0].Granted == 0, "%s: reference is not denied\n", Name);

    for (i = 0; i < 3; i++)
    {
        ok(Pseudo[i].Status == Real[i].Status, "%s: %s Status = 0x%lx, real handle 0x%lx\n",
           Name, Names[i], Pseudo[i].Status, Real[i].Status);
        ok(Pseudo[i].AccessStatus == Real[i].AccessStatus && Pseudo[i].Granted == Real[i].Granted,
           "%s: %s AccessStatus = 0x%lx, Granted = 0x%lx, real handle 0x%lx, 0x%lx\n",
           Name, Names[i], Pseudo[i].AccessStatus, Pseudo[i].Granted, Real[i].AccessStatus, Real[i].Granted);
    }
}

/* All three access checks fail with the same status, without a result */
static
VOID
CheckAccessFails(
    _In_ PCSTR Name,
    _In_ HANDLE Handle,
    _In_ PSECURITY_DESCRIPTOR Sd,
    _In_ NTSTATUS ExpectedStatus)
{
    ACCESS_RESULT Plain, ByType, ResultList;
    ACCESS_RESULT *All[3];
    static const PCSTR Names[3] = { "NtAccessCheck", "NtAccessCheckByType", "NtAccessCheckByTypeResultList" };
    ULONG i;

    RunAccessChecks(Handle, Sd, &Plain, &ByType, &ResultList);
    All[0] = &Plain;
    All[1] = &ByType;
    All[2] = &ResultList;
    for (i = 0; i < 3; i++)
    {
        ok(All[i]->Status == ExpectedStatus, "%s: %s Status = 0x%lx, expected 0x%lx\n",
           Name, Names[i], All[i]->Status, ExpectedStatus);
    }
}

static
HANDLE
MakeImpersonationToken(
    _In_ HANDLE Source,
    _In_ SECURITY_IMPERSONATION_LEVEL Level)
{
    NTSTATUS Status;
    HANDLE Duplicate = NULL;
    OBJECT_ATTRIBUTES ObjectAttributes;
    SECURITY_QUALITY_OF_SERVICE Sqos;

    Sqos.Length = sizeof(Sqos);
    Sqos.ImpersonationLevel = Level;
    Sqos.ContextTrackingMode = 0;
    Sqos.EffectiveOnly = FALSE;
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    ObjectAttributes.SecurityQualityOfService = &Sqos;
    Status = NtDuplicateToken(Source, TOKEN_ALL_ACCESS, &ObjectAttributes, FALSE, TokenImpersonation, &Duplicate);
    ok_hex(Status, STATUS_SUCCESS);
    return Duplicate;
}

static
NTSTATUS
SetImpersonation(
    _In_opt_ HANDLE Token)
{
    return NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &Token, sizeof(Token));
}

static
VOID
TestNotImpersonating(
    _In_ HANDLE RealToken,
    _In_ PSECURITY_DESCRIPTOR AllowSd)
{
    NTSTATUS Status;
    LUID RealId, Id;
    ULONG i;
    static const HANDLE Pseudo[3] = { PSEUDO_PROCESS_TOKEN, PSEUDO_THREAD_TOKEN, PSEUDO_EFFECTIVE_TOKEN };
    static const PCSTR Names[3] = { "-4", "-5", "-6" };

    trace("--- thread not impersonating\n");
    GetTokenId(RealToken, &RealId, &Status);
    ok_hex(Status, STATUS_SUCCESS);

    /* -4 and -6 (which falls back to the process token) are the primary token */
    CheckType("-4", PSEUDO_PROCESS_TOKEN, STATUS_SUCCESS, TokenPrimary, 0);
    CheckType("-6", PSEUDO_EFFECTIVE_TOKEN, STATUS_SUCCESS, TokenPrimary, 0);
    GetTokenId(PSEUDO_PROCESS_TOKEN, &Id, &Status);
    ok_hex(Status, STATUS_SUCCESS);
    ok(RtlEqualLuid(&Id, &RealId), "-4 is not the process token\n");
    GetTokenId(PSEUDO_EFFECTIVE_TOKEN, &Id, &Status);
    ok_hex(Status, STATUS_SUCCESS);
    ok(RtlEqualLuid(&Id, &RealId), "-6 is not the process token\n");
    CheckQueryAgainstRealToken("-4", PSEUDO_PROCESS_TOKEN, RealToken);
    CheckQueryAgainstRealToken("-6", PSEUDO_EFFECTIVE_TOKEN, RealToken);

    /* -5 has no token to return: same status as NtOpenThreadToken */
    {
        HANDLE ThreadToken = NULL;
        TOKEN_TYPE Type;

        Status = NtOpenThreadToken(NtCurrentThread(), TOKEN_QUERY, FALSE, &ThreadToken);
        ok_hex(Status, STATUS_NO_TOKEN);
        Status = QueryClass(PSEUDO_THREAD_TOKEN, TokenType, &Type, sizeof(Type));
        ok_hex(Status, STATUS_NO_TOKEN);
        Status = QueryClass(PSEUDO_THREAD_TOKEN, TokenUser, &Id, sizeof(Id));
        ok_hex(Status, STATUS_NO_TOKEN);
    }

    for (i = 0; i < 3; i++)
        CheckRejected(Names[i], Pseudo[i], RealToken);

    /* Access checks accept the primary token through a pseudo handle, not through a real one */
    {
        HANDLE Reference = MakeImpersonationToken(RealToken, SecurityImpersonation);

        if (Reference != NULL)
        {
            CheckAccessSame("-4", PSEUDO_PROCESS_TOKEN, AllowSd, Reference, TRUE);
            CheckAccessSame("-6", PSEUDO_EFFECTIVE_TOKEN, AllowSd, Reference, TRUE);
            NtClose(Reference);
        }
    }
    CheckAccessFails("-5", PSEUDO_THREAD_TOKEN, AllowSd, STATUS_NO_TOKEN);
    CheckAccessFails("real primary", RealToken, AllowSd, STATUS_NO_IMPERSONATION_TOKEN);
}

static
VOID
TestImpersonating(
    _In_ HANDLE RealToken,
    _In_ PSECURITY_DESCRIPTOR AllowSd,
    _In_ SECURITY_IMPERSONATION_LEVEL Level)
{
    NTSTATUS Status;
    HANDLE Impersonation;
    LUID RealId, ThreadId, Id;

    trace("--- thread impersonating at level %d\n", Level);
    Impersonation = MakeImpersonationToken(RealToken, Level);
    if (Impersonation == NULL)
        return;
    GetTokenId(RealToken, &RealId, &Status);
    GetTokenId(Impersonation, &ThreadId, &Status);
    ok(!RtlEqualLuid(&RealId, &ThreadId), "a duplicate has the id of its source\n");

    Status = SetImpersonation(Impersonation);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        CheckType("-4", PSEUDO_PROCESS_TOKEN, STATUS_SUCCESS, TokenPrimary, 0);
        CheckType("-5", PSEUDO_THREAD_TOKEN, STATUS_SUCCESS, TokenImpersonation, Level);
        CheckType("-6", PSEUDO_EFFECTIVE_TOKEN, STATUS_SUCCESS, TokenImpersonation, Level);

        GetTokenId(PSEUDO_PROCESS_TOKEN, &Id, &Status);
        ok_hex(Status, STATUS_SUCCESS);
        ok(RtlEqualLuid(&Id, &RealId), "-4 is not the process token\n");
        GetTokenId(PSEUDO_THREAD_TOKEN, &Id, &Status);
        ok_hex(Status, STATUS_SUCCESS);
        ok(RtlEqualLuid(&Id, &ThreadId), "-5 is not the thread token\n");
        GetTokenId(PSEUDO_EFFECTIVE_TOKEN, &Id, &Status);
        ok_hex(Status, STATUS_SUCCESS);
        ok(RtlEqualLuid(&Id, &ThreadId), "-6 is not the thread token\n");

        CheckAccessSame("-4", PSEUDO_PROCESS_TOKEN, AllowSd, Impersonation, TRUE);
        CheckAccessSame("-5", PSEUDO_THREAD_TOKEN, AllowSd, Impersonation, TRUE);
        CheckAccessSame("-6", PSEUDO_EFFECTIVE_TOKEN, AllowSd, Impersonation, TRUE);
        CheckRejected("-5 (impersonating)", PSEUDO_THREAD_TOKEN, RealToken);
        CheckRejected("-6 (impersonating)", PSEUDO_EFFECTIVE_TOKEN, RealToken);

        Status = SetImpersonation(NULL);
        ok_hex(Status, STATUS_SUCCESS);
    }

    /* Back to the primary token */
    CheckType("-5 after revert", PSEUDO_THREAD_TOKEN, STATUS_NO_TOKEN, 0, 0);
    CheckType("-6 after revert", PSEUDO_EFFECTIVE_TOKEN, STATUS_SUCCESS, TokenPrimary, 0);
    NtClose(Impersonation);
}

/* The thread token is a different token than the process token: the handles must pick the right one */
static
VOID
TestDistinctTokens(
    _In_ HANDLE RealToken,
    _In_opt_ PSECURITY_DESCRIPTOR AdminSd,
    _In_opt_ PSID AdminSid)
{
    NTSTATUS Status;
    HANDLE Filtered = NULL, Impersonation;
    TOKEN_GROUPS DisableAdmins;
    ULONG ProcessPrivileges, ThreadPrivileges;

    trace("--- thread token without the privileges (and without Administrators)\n");
    ProcessPrivileges = PrivilegeCount(PSEUDO_PROCESS_TOKEN);
    DisableAdmins.GroupCount = 1;
    DisableAdmins.Groups[0].Sid = AdminSid;
    DisableAdmins.Groups[0].Attributes = 0;
    Status = NtFilterToken(RealToken, DISABLE_MAX_PRIVILEGE, AdminSid ? &DisableAdmins : NULL, NULL, NULL, &Filtered);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;
    Impersonation = MakeImpersonationToken(Filtered, SecurityImpersonation);
    NtClose(Filtered);
    if (Impersonation == NULL)
        return;

    Status = SetImpersonation(Impersonation);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        ThreadPrivileges = PrivilegeCount(PSEUDO_THREAD_TOKEN);
        ok(PrivilegeCount(PSEUDO_PROCESS_TOKEN) == ProcessPrivileges, "-4 changed with the thread token\n");
        ok(PrivilegeCount(PSEUDO_EFFECTIVE_TOKEN) == ThreadPrivileges, "-6 is not the thread token\n");
        if (ProcessPrivileges <= 1)
            skip("The process token has too few privileges to tell the tokens apart\n");
        else
            ok(ThreadPrivileges < ProcessPrivileges, "thread %lu, process %lu privileges\n", ThreadPrivileges, ProcessPrivileges);

        /* AdminSd allows only the Administrators group, which only the process token has enabled */
        if (AdminSd)
        {
            HANDLE Full = MakeImpersonationToken(RealToken, SecurityImpersonation);

            /* -4 is the process token (granted), -5 and -6 the thread token (Administrators removed) */
            if (Full != NULL)
                CheckAccessSame("-4 (admin)", PSEUDO_PROCESS_TOKEN, AdminSd, Full, TRUE);
            CheckAccessSame("-5 (admin)", PSEUDO_THREAD_TOKEN, AdminSd, Impersonation, FALSE);
            CheckAccessSame("-6 (admin)", PSEUDO_EFFECTIVE_TOKEN, AdminSd, Impersonation, FALSE);
            if (Full != NULL)
                NtClose(Full);
        }
        SetImpersonation(NULL);
    }
    NtClose(Impersonation);
}

START_TEST(NtTokenPseudoHandles)
{
    NTSTATUS Status;
    HANDLE RealToken = NULL;
    UCHAR UserBuffer[256];
    PTOKEN_USER User = (PTOKEN_USER)UserBuffer;
    UCHAR SdBuffer[SECURITY_DESCRIPTOR_MIN_LENGTH], AclBuffer[256];
    ULONG i;
    static const HANDLE OtherValues[] =
    {
        (HANDLE)(LONG_PTR)-3, (HANDLE)(LONG_PTR)-7, (HANDLE)(LONG_PTR)-8, (HANDLE)(LONG_PTR)-9, (HANDLE)(LONG_PTR)-100
    };
    TOKEN_TYPE Type;
    HANDLE Handle;
    ULONG Length;

    Status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_ALL_ACCESS, &RealToken);
    if (!NT_SUCCESS(Status))
        Status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &RealToken);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;

    /* Before Windows 8 the values are just invalid handles */
    Status = QueryClass(PSEUDO_PROCESS_TOKEN, TokenType, &Type, sizeof(Type));
    if (Status == STATUS_INVALID_HANDLE && GetNTVersion() < _WIN32_WINNT_WIN8)
    {
        skip("Token pseudo handles need Windows 8 or newer\n");
        NtClose(RealToken);
        return;
    }
    ok_hex(Status, STATUS_SUCCESS);

    Status = NtQueryInformationToken(RealToken, TokenUser, User, sizeof(UserBuffer), &Length);
    ok_hex(Status, STATUS_SUCCESS);
    InitSd((PSECURITY_DESCRIPTOR)SdBuffer, (PACL)AclBuffer, User->User.Sid);

    TestNotImpersonating(RealToken, (PSECURITY_DESCRIPTOR)SdBuffer);
    TestImpersonating(RealToken, (PSECURITY_DESCRIPTOR)SdBuffer, SecurityImpersonation);
    TestImpersonating(RealToken, (PSECURITY_DESCRIPTOR)SdBuffer, SecurityIdentification);

    {
        /* Administrators only */
        static SID_IDENTIFIER_AUTHORITY NtAuthority = { SECURITY_NT_AUTHORITY };
        PSID AdminSid = NULL;
        UCHAR AdminSdBuffer[SECURITY_DESCRIPTOR_MIN_LENGTH], AdminAclBuffer[256];
        UCHAR GroupsBuffer[2048];
        PTOKEN_GROUPS Groups = (PTOKEN_GROUPS)GroupsBuffer;
        BOOLEAN IsAdmin = FALSE;

        Status = RtlAllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                             DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdminSid);
        ok_hex(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status))
        {
            Status = QueryClass(RealToken, TokenGroups, Groups, sizeof(GroupsBuffer));
            if (NT_SUCCESS(Status))
            {
                for (i = 0; i < Groups->GroupCount; i++)
                {
                    if ((Groups->Groups[i].Attributes & SE_GROUP_ENABLED) &&
                        RtlEqualSid(Groups->Groups[i].Sid, AdminSid))
                        IsAdmin = TRUE;
                }
            }
            if (IsAdmin)
            {
                InitSd((PSECURITY_DESCRIPTOR)AdminSdBuffer, (PACL)AdminAclBuffer, AdminSid);
                TestDistinctTokens(RealToken, (PSECURITY_DESCRIPTOR)AdminSdBuffer, AdminSid);
            }
            else
            {
                TestDistinctTokens(RealToken, NULL, NULL);
            }
            RtlFreeSid(AdminSid);
        }
    }

    /* Other special-looking values are invalid handles for the token services */
    for (i = 0; i < RTL_NUMBER_OF(OtherValues); i++)
    {
        Status = QueryClass(OtherValues[i], TokenType, &Type, sizeof(Type));
        ok(Status == STATUS_INVALID_HANDLE, "QueryInformationToken(%p) = 0x%lx\n", OtherValues[i], Status);
    }

    /* The process and thread pseudo handles are not tokens */
    Status = QueryClass(NtCurrentProcess(), TokenType, &Type, sizeof(Type));
    ok_hex(Status, STATUS_OBJECT_TYPE_MISMATCH);
    Status = QueryClass(NtCurrentThread(), TokenType, &Type, sizeof(Type));
    ok_hex(Status, STATUS_OBJECT_TYPE_MISMATCH);

#ifdef _WIN64
    /* Pseudo handles are sign-extended: a zero-extended 32-bit value is just another invalid handle */
    Status = QueryClass((HANDLE)(ULONG_PTR)0xFFFFFFFCUL, TokenType, &Type, sizeof(Type));
    ok_hex(Status, STATUS_INVALID_HANDLE);
    Status = QueryClass((HANDLE)(ULONG_PTR)0xFFFFFFFAUL, TokenType, &Type, sizeof(Type));
    ok_hex(Status, STATUS_INVALID_HANDLE);
#endif

    /* Closing them is a harmless success, repeatedly, and does not stop them from working */
    for (Handle = (HANDLE)(LONG_PTR)-1; (LONG_PTR)Handle >= -6; Handle = (HANDLE)((LONG_PTR)Handle - 1))
    {
        Status = NtClose(Handle);
        ok(Status == STATUS_SUCCESS, "NtClose(%p) = 0x%lx\n", Handle, Status);
    }
    Status = QueryClass(PSEUDO_PROCESS_TOKEN, TokenType, &Type, sizeof(Type));
    ok_hex(Status, STATUS_SUCCESS);
    Status = QueryClass(PSEUDO_EFFECTIVE_TOKEN, TokenType, &Type, sizeof(Type));
    ok_hex(Status, STATUS_SUCCESS);
    if (!NtCurrentPeb()->BeingDebugged)
    {
        /* (Closing an invalid handle raises an exception in a debugged process) */
        Status = NtClose((HANDLE)(LONG_PTR)-7);
        ok_hex(Status, STATUS_INVALID_HANDLE);
    }

    NtClose(RealToken);
}
