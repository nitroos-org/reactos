/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The access check and audit alarm system services reject bad pointers and sizes cleanly
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * NtAccessCheckAndAuditAlarm, NtAccessCheckByTypeAndAuditAlarm, NtAccessCheckByTypeResultListAndAuditAlarm
 * and NtAccessCheckByTypeResultListAndAuditAlarmByHandle are called with one bad argument at a time:
 * the call fails with an error status, writes none of its outputs, and leaks no handle and no pool.
 * The caller is an administrator without SeAuditPrivilege; the ByType forms pass AUDIT_ALLOW_NO_PRIVILEGE
 * so that every argument is examined, NtAccessCheckAndAuditAlarm (no Flags) is examined up to the
 * privilege check. The thread impersonates a copy of its own token.
 *
 * Bad memory is a page set to PAGE_NOACCESS right after a readable page: a buffer that ends at the
 * page boundary is valid, one byte more is not.
 */

#include "precomp.h"
#include <ndk/sefuncs.h>
#include <ndk/exfuncs.h>
#include <ndk/obfuncs.h>

#define R1 0x0001
#define R2 0x0002
#define SENTINEL 0xa5a5a5a5

static GENERIC_MAPPING Mapping = { R1 | READ_CONTROL, R2, 0x4, 0xf | STANDARD_RIGHTS_REQUIRED };
static GUID GuidRoot = {0x0f2b0001, 0x77a1, 0x4c3d, {0x8e, 0x11, 0x02, 0x9c, 0x5a, 0x33, 0x61, 0x01}};
static GUID GuidChild = {0x0f2b0002, 0x77a1, 0x4c3d, {0x8e, 0x11, 0x02, 0x9c, 0x5a, 0x33, 0x61, 0x02}};

enum { FORM_AND, FORM_BYTYPE, FORM_RESULTLIST, FORM_BYHANDLE, FORM_COUNT };
static const char *FormNames[FORM_COUNT] = { "AndAuditAlarm", "ByType", "ResultList", "ByHandle" };

/* The arguments of one call; a test changes one of them */
typedef struct
{
    PUNICODE_STRING Subsystem, TypeName, Name;
    PSECURITY_DESCRIPTOR Sd;
    PSID Self;
    ACCESS_MASK Desired;
    AUDIT_EVENT_TYPE AuditType;
    ULONG Flags;
    POBJECT_TYPE_LIST List;
    ULONG Count;
    PGENERIC_MAPPING Mapping;
    HANDLE Token;
    PACCESS_MASK Granted;
    PNTSTATUS Status;
    PBOOLEAN OnClose;
} ARGS;

static UNICODE_STRING Subsystem, TypeName, Name;
static SECURITY_DESCRIPTOR GoodSd;
static PSID Everyone;
static OBJECT_TYPE_LIST GoodList[2];
static ACCESS_MASK Granted[4];
static NTSTATUS Status[4];
static BOOLEAN OnClose;
static HANDLE ClientToken;
static PUCHAR Page;     /* a readable and writable page ... */
static PUCHAR NoAccess; /* ... followed by an inaccessible one */

static void Defaults(ARGS *Args)
{
    int i;

    Args->Subsystem = &Subsystem;
    Args->TypeName = &TypeName;
    Args->Name = &Name;
    Args->Sd = &GoodSd;
    Args->Self = NULL;
    Args->Desired = R1;
    Args->AuditType = AuditEventObjectAccess;
    Args->Flags = AUDIT_ALLOW_NO_PRIVILEGE;
    Args->List = GoodList;
    Args->Count = 2;
    Args->Mapping = &Mapping;
    Args->Token = ClientToken;
    Args->Granted = Granted;
    Args->Status = Status;
    Args->OnClose = &OnClose;
    for (i = 0; i < 4; i++)
    {
        Granted[i] = SENTINEL;
        Status[i] = SENTINEL;
    }
    OnClose = 0x55;
}

static NTSTATUS Call(int Form, const ARGS *Args)
{
    NTSTATUS Result;

    SetThreadToken(NULL, ClientToken);
    switch (Form)
    {
        case FORM_AND:
            Result = NtAccessCheckAndAuditAlarm(Args->Subsystem, (PVOID)1, Args->TypeName, Args->Name, Args->Sd,
                                                Args->Desired, Args->Mapping, FALSE, Args->Granted, Args->Status,
                                                Args->OnClose);
            break;
        case FORM_BYTYPE:
            Result = NtAccessCheckByTypeAndAuditAlarm(Args->Subsystem, (PVOID)1, Args->TypeName, Args->Name,
                                                      Args->Sd, Args->Self, Args->Desired, Args->AuditType,
                                                      Args->Flags, Args->List, Args->Count, Args->Mapping, FALSE,
                                                      Args->Granted, Args->Status, Args->OnClose);
            break;
        case FORM_RESULTLIST:
            Result = NtAccessCheckByTypeResultListAndAuditAlarm(Args->Subsystem, (PVOID)1, Args->TypeName, Args->Name,
                                                                Args->Sd, Args->Self, Args->Desired, Args->AuditType,
                                                                Args->Flags, Args->List, Args->Count, Args->Mapping,
                                                                FALSE, Args->Granted, Args->Status, Args->OnClose);
            break;
        default:
            Result = NtAccessCheckByTypeResultListAndAuditAlarmByHandle(Args->Subsystem, (PVOID)1, Args->Token,
                                                                        Args->TypeName, Args->Name, Args->Sd,
                                                                        Args->Self, Args->Desired, Args->AuditType,
                                                                        Args->Flags, Args->List, Args->Count,
                                                                        Args->Mapping, FALSE, Args->Granted,
                                                                        Args->Status, Args->OnClose);
            break;
    }
    RevertToSelf();
    return Result;
}

static BOOL Untouched(void)
{
    int i;

    for (i = 0; i < 4; i++)
    {
        if (Granted[i] != SENTINEL || Status[i] != SENTINEL)
            return FALSE;
    }
    return OnClose == 0x55;
}

/* One bad argument: the call must fail (with Expected when it is not 0) and write nothing */
static void ExpectFailure(int Line, int Form, const ARGS *Args, NTSTATUS Expected, const char *What)
{
    NTSTATUS Result = Call(Form, Args);

    if (Expected)
        ok_(__FILE__, Line)(Result == Expected, "%s %s: status 0x%08lx, expected 0x%08lx\n", FormNames[Form], What,
                            Result, Expected);
    else
        ok_(__FILE__, Line)(!NT_SUCCESS(Result), "%s %s: status 0x%08lx, expected a failure\n", FormNames[Form],
                            What, Result);
    ok_(__FILE__, Line)(Untouched(), "%s %s: outputs written on failure (0x%lx 0x%lx %u)\n", FormNames[Form], What,
                        Granted[0], Status[0], OnClose);
}
#define EXPECT_FAILURE(Form, Args, Expected, What) ExpectFailure(__LINE__, Form, Args, Expected, What)

static BOOL Setup(void)
{
    SID_IDENTIFIER_AUTHORITY World = {SECURITY_WORLD_SID_AUTHORITY};
    HANDLE Process;
    DWORD Old;

    RtlInitUnicodeString(&Subsystem, L"AccessCheckAuditAlarmArgs");
    RtlInitUnicodeString(&TypeName, L"TestObject");
    RtlInitUnicodeString(&Name, L"Object");

    if (!AllocateAndInitializeSid(&World, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &Everyone))
        return FALSE;
    InitializeSecurityDescriptor(&GoodSd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorOwner(&GoodSd, Everyone, FALSE);
    SetSecurityDescriptorGroup(&GoodSd, Everyone, FALSE);
    SetSecurityDescriptorDacl(&GoodSd, TRUE, NULL, FALSE);

    GoodList[0].Level = ACCESS_OBJECT_GUID;
    GoodList[0].Sbz = 0;
    GoodList[0].ObjectType = &GuidRoot;
    GoodList[1].Level = ACCESS_PROPERTY_SET_GUID;
    GoodList[1].Sbz = 0;
    GoodList[1].ObjectType = &GuidChild;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE, &Process))
        return FALSE;
    if (!DuplicateTokenEx(Process, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &ClientToken))
    {
        CloseHandle(Process);
        return FALSE;
    }
    CloseHandle(Process);

    Page = VirtualAlloc(NULL, 2 * 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!Page)
        return FALSE;
    NoAccess = Page + 4096;
    return VirtualProtect(NoAccess, 4096, PAGE_NOACCESS, &Old);
}

/* The rows */

static void GoodCalls(void)
{
    ARGS Args;
    int Form;

    /* The defaults are valid: with the NULL DACL, R1 is granted */
    for (Form = FORM_BYTYPE; Form < FORM_COUNT; Form++)
    {
        NTSTATUS Result;

        Defaults(&Args);
        Result = Call(Form, &Args);
        ok(Result == STATUS_SUCCESS, "%s valid call: 0x%08lx\n", FormNames[Form], Result);
        ok(Status[0] == STATUS_SUCCESS && Granted[0] == R1, "%s valid call: [0x%lx 0x%lx]\n", FormNames[Form],
           Granted[0], Status[0]);
        ok(OnClose == FALSE, "%s valid call: GenerateOnClose %u\n", FormNames[Form], OnClose);
        if (Form != FORM_BYTYPE)
            ok(Status[1] == STATUS_SUCCESS && Granted[2] == SENTINEL, "%s valid call: list [1] 0x%lx, [2] 0x%lx\n",
               FormNames[Form], Status[1], Granted[2]);
    }

    /* NtAccessCheckAndAuditAlarm has no Flags: without SeAuditPrivilege it stops there, writing nothing */
    Defaults(&Args);
    EXPECT_FAILURE(FORM_AND, &Args, STATUS_PRIVILEGE_NOT_HELD, "without SeAuditPrivilege");
}

static void OutputPointers(void)
{
    ARGS Args;
    int Form;
    SYSTEM_BASIC_INFORMATION Info;
    PVOID Boundary = NULL;

    if (NT_SUCCESS(NtQuerySystemInformation(SystemBasicInformation, &Info, sizeof(Info), NULL)))
        Boundary = (PVOID)((Info.MaximumUserModeAddress + 1) & ~(ULONG_PTR)0xfff);

    for (Form = 0; Form < FORM_COUNT; Form++)
    {
        Defaults(&Args);
        Args.Granted = NULL;
        EXPECT_FAILURE(Form, &Args, STATUS_ACCESS_VIOLATION, "NULL GrantedAccess");

        Defaults(&Args);
        Args.Status = NULL;
        EXPECT_FAILURE(Form, &Args, STATUS_ACCESS_VIOLATION, "NULL AccessStatus");

        Defaults(&Args);
        Args.Status = (PNTSTATUS)((PUCHAR)Status + 1);
        EXPECT_FAILURE(Form, &Args, 0, "misaligned AccessStatus");

        Defaults(&Args);
        Args.OnClose = NULL;
        EXPECT_FAILURE(Form, &Args, STATUS_ACCESS_VIOLATION, "NULL GenerateOnClose");

        /* GenerateOnClose outside user memory: refused by the probe, nothing is written there */
        if (Boundary)
        {
            Defaults(&Args);
            Args.OnClose = (PBOOLEAN)Boundary;
            EXPECT_FAILURE(Form, &Args, STATUS_ACCESS_VIOLATION, "GenerateOnClose at the end of user memory");
        }

        /* A list result that does not fit: the last entry lies in the inaccessible page */
        if (Form == FORM_RESULTLIST || Form == FORM_BYHANDLE)
        {
            PACCESS_MASK Short = (PACCESS_MASK)(NoAccess - sizeof(ACCESS_MASK));

            Defaults(&Args);
            *Short = SENTINEL;
            Args.Granted = Short;
            EXPECT_FAILURE(Form, &Args, STATUS_ACCESS_VIOLATION, "GrantedAccess list one entry short");
            ok(*Short == SENTINEL, "%s: the first entry of the short list was written\n", FormNames[Form]);
        }

        Defaults(&Args);
        Args.Mapping = NULL;
        EXPECT_FAILURE(Form, &Args, STATUS_ACCESS_VIOLATION, "NULL GenericMapping");

        Defaults(&Args);
        Args.Mapping = (PGENERIC_MAPPING)(NoAccess - 8);
        EXPECT_FAILURE(Form, &Args, STATUS_ACCESS_VIOLATION, "GenericMapping across the inaccessible page");
    }
}

static void InputArguments(void)
{
    ARGS Args;
    int Form;
    UNICODE_STRING BadString;
    PUCHAR SelfRelative;
    PISECURITY_DESCRIPTOR_RELATIVE Relative;
    OBJECT_TYPE_LIST BadList[3];

    for (Form = FORM_BYTYPE; Form < FORM_COUNT; Form++)
    {
        /* Descriptors */
        Defaults(&Args);
        Args.Sd = NULL;
        EXPECT_FAILURE(Form, &Args, STATUS_INVALID_SECURITY_DESCR, "NULL descriptor");

        Defaults(&Args);
        Args.Sd = (PSECURITY_DESCRIPTOR)(NoAccess - 2);
        EXPECT_FAILURE(Form, &Args, 0, "descriptor across the inaccessible page");

        /* A self-relative descriptor whose owner offset points past its end, into the inaccessible page */
        SelfRelative = NoAccess - sizeof(SECURITY_DESCRIPTOR_RELATIVE);
        Relative = (PISECURITY_DESCRIPTOR_RELATIVE)SelfRelative;
        RtlZeroMemory(Relative, sizeof(*Relative));
        Relative->Revision = SECURITY_DESCRIPTOR_REVISION;
        Relative->Control = SE_SELF_RELATIVE;
        Relative->Owner = sizeof(*Relative);
        Relative->Group = sizeof(*Relative);
        Defaults(&Args);
        Args.Sd = Relative;
        EXPECT_FAILURE(Form, &Args, 0, "self-relative descriptor with the owner outside");

        Relative->Owner = 0x7ffffff0;
        EXPECT_FAILURE(Form, &Args, 0, "self-relative descriptor with a huge owner offset");

        /* Strings */
        Defaults(&Args);
        Args.Subsystem = NULL;
        EXPECT_FAILURE(Form, &Args, STATUS_ACCESS_VIOLATION, "NULL subsystem name");

        BadString.Buffer = (PWSTR)(NoAccess - 4);
        BadString.Length = 8;
        BadString.MaximumLength = 8;
        Defaults(&Args);
        Args.Name = &BadString;
        EXPECT_FAILURE(Form, &Args, STATUS_ACCESS_VIOLATION, "object name across the inaccessible page");

        BadString.Buffer = (PWSTR)Page;
        BadString.Length = 0xfffe;
        BadString.MaximumLength = 2;
        Defaults(&Args);
        Args.TypeName = &BadString;
        EXPECT_FAILURE(Form, &Args, STATUS_ACCESS_VIOLATION, "type name longer than its buffer");

        Defaults(&Args);
        Args.Name = (PUNICODE_STRING)(NoAccess - 4);
        EXPECT_FAILURE(Form, &Args, 0, "UNICODE_STRING across the inaccessible page");

        /* The principal self SID: inaccessible, or a SID whose sub-authorities run into the inaccessible page */
        Defaults(&Args);
        Args.Self = (PSID)(NoAccess - 4);
        EXPECT_FAILURE(Form, &Args, 0, "principal self SID across the inaccessible page");
        {
            PSID_IDENTIFIER_AUTHORITY Authority;
            PUCHAR Sid = NoAccess - 8;

            Sid[0] = SID_REVISION;
            Sid[1] = 15;
            Authority = (PSID_IDENTIFIER_AUTHORITY)(Sid + 2);
            RtlZeroMemory(Authority, 6);
            Defaults(&Args);
            Args.Self = (PSID)Sid;
            EXPECT_FAILURE(Form, &Args, 0, "principal self SID with 15 sub-authorities at the page end");
        }

        /* The request and the audit type */
        Defaults(&Args);
        Args.Desired = GENERIC_WRITE;
        EXPECT_FAILURE(Form, &Args, STATUS_GENERIC_NOT_MAPPED, "generic rights");

        Defaults(&Args);
        Args.AuditType = (AUDIT_EVENT_TYPE)2;
        EXPECT_FAILURE(Form, &Args, STATUS_INVALID_PARAMETER, "audit type 2");
        Args.AuditType = (AUDIT_EVENT_TYPE)0x80000000;
        EXPECT_FAILURE(Form, &Args, STATUS_INVALID_PARAMETER, "audit type 0x80000000");

        /* Object type lists */
        Defaults(&Args);
        Args.List = NULL;
        EXPECT_FAILURE(Form, &Args, 0, "NULL list with a count");

        Defaults(&Args);
        Args.List = (POBJECT_TYPE_LIST)(NoAccess - sizeof(OBJECT_TYPE_LIST));
        Args.List->Level = ACCESS_OBJECT_GUID;
        Args.List->ObjectType = &GuidRoot;
        EXPECT_FAILURE(Form, &Args, STATUS_ACCESS_VIOLATION, "list whose second entry is inaccessible");

        Defaults(&Args);
        Args.Count = 0x40000000;
        EXPECT_FAILURE(Form, &Args, 0, "list count 0x40000000");
        Args.Count = 0xffffffff;
        EXPECT_FAILURE(Form, &Args, 0, "list count 0xffffffff");

        BadList[0] = GoodList[0];
        BadList[1] = GoodList[1];
        BadList[1].Level = ACCESS_PROPERTY_GUID; /* level 2 right under level 0 */
        Defaults(&Args);
        Args.List = BadList;
        EXPECT_FAILURE(Form, &Args, STATUS_INVALID_PARAMETER, "list levels out of order");

        BadList[1].Level = ACCESS_OBJECT_GUID; /* a second root */
        EXPECT_FAILURE(Form, &Args, STATUS_INVALID_PARAMETER, "two level 0 entries");

        BadList[1].Level = 5;
        EXPECT_FAILURE(Form, &Args, STATUS_INVALID_PARAMETER, "level 5");

        BadList[1] = GoodList[1];
        BadList[1].ObjectType = (GUID *)(NoAccess - 8);
        EXPECT_FAILURE(Form, &Args, STATUS_ACCESS_VIOLATION, "GUID across the inaccessible page");
    }

    /* Result list lengths */
    for (Form = FORM_RESULTLIST; Form < FORM_COUNT; Form++)
    {
        Defaults(&Args);
        Args.Count = 0;
        EXPECT_FAILURE(Form, &Args, STATUS_INVALID_PARAMETER, "empty result list");
        /* (a WoW64 caller may fail earlier, reading the 0x1001 entries of the two-entry list) */
        Args.Count = 0x1001;
        EXPECT_FAILURE(Form, &Args, 0, "result list of 0x1001 entries");
    }
}

static void TokenHandles(void)
{
    ARGS Args;
    HANDLE Event, NoQuery;

    Defaults(&Args);
    Args.Token = NULL;
    EXPECT_FAILURE(FORM_BYHANDLE, &Args, STATUS_INVALID_HANDLE, "NULL token handle");

    Args.Token = (HANDLE)(ULONG_PTR)0x7ffc;
    EXPECT_FAILURE(FORM_BYHANDLE, &Args, STATUS_INVALID_HANDLE, "invalid token handle");

    Event = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (Event)
    {
        Args.Token = Event;
        EXPECT_FAILURE(FORM_BYHANDLE, &Args, STATUS_OBJECT_TYPE_MISMATCH, "event handle");
        CloseHandle(Event);
    }

    if (DuplicateHandle(GetCurrentProcess(), ClientToken, GetCurrentProcess(), &NoQuery, TOKEN_IMPERSONATE, FALSE, 0))
    {
        Args.Token = NoQuery;
        EXPECT_FAILURE(FORM_BYHANDLE, &Args, STATUS_ACCESS_DENIED, "token handle without TOKEN_QUERY");
        CloseHandle(NoQuery);
    }
}

/* Thousands of failing and succeeding calls leak no handle and no paged pool */
static void NoLeaks(void)
{
    ARGS Args;
    DWORD HandlesBefore = 0, HandlesAfter = 0;
    ULONG Round;
    int Form;

    /* warm up */
    for (Form = 0; Form < FORM_COUNT; Form++)
    {
        Defaults(&Args);
        Call(Form, &Args);
    }

    GetProcessHandleCount(GetCurrentProcess(), &HandlesBefore);
    for (Round = 0; Round < 500; Round++)
    {
        for (Form = 0; Form < FORM_COUNT; Form++)
        {
            Defaults(&Args);
            Call(Form, &Args);
            Args.Sd = (PSECURITY_DESCRIPTOR)(NoAccess - 2);
            Call(Form, &Args);
            Defaults(&Args);
            Args.Name = (PUNICODE_STRING)(NoAccess - 4);
            Call(Form, &Args);
            Defaults(&Args);
            Args.List = NULL;
            Call(Form, &Args);
            Defaults(&Args);
            Args.OnClose = NULL;
            Call(Form, &Args);
            Defaults(&Args);
            Args.Token = (HANDLE)(ULONG_PTR)0x7ffc;
            Call(Form, &Args);
        }
    }
    GetProcessHandleCount(GetCurrentProcess(), &HandlesAfter);
    ok(HandlesAfter == HandlesBefore, "handle count %lu before, %lu after 12000 calls\n", HandlesBefore,
       HandlesAfter);
}

START_TEST(AccessCheckAuditAlarmArgs)
{
    if (!Setup())
    {
        skip("setup failed (%lu)\n", GetLastError());
        return;
    }

    GoodCalls();
    OutputPointers();
    InputArguments();
    TokenHandles();
    NoLeaks();

    VirtualFree(Page, 0, MEM_RELEASE);
    CloseHandle(ClientToken);
    FreeSid(Everyone);
}
