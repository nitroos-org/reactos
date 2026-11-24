/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Who may give a process a primary token: ProcessAccessToken, the ReactOS-private
 *              ProcessRosAccessTokenCopy and CreateProcessAsUser, for callers and targets of different kinds
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows Server 2022 (64 and 32 bit alike, as the administrator over a remote shell):
 * - ProcessAccessToken with an unused primary token: a child created suspended that never ran takes it; a child
 *   that runs, that ran and is suspended again, that has a second thread (created suspended, never run), and the
 *   caller's own process: STATUS_NOT_SUPPORTED. That comes after the handle (STATUS_ACCESS_DENIED without
 *   TOKEN_ASSIGN_PRIMARY), the level (STATUS_BAD_IMPERSONATION_LEVEL) and the privilege (STATUS_PRIVILEGE_NOT_HELD),
 *   before the type and the in-use check (an impersonation token or a token in use: STATUS_NOT_SUPPORTED).
 * - CreateProcessAsUser from a Low integrity caller with handles (TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY) it inherited:
 *   the parent's primary token, an impersonation copy of it, a Medium primary copy, a filtered copy (higher than
 *   the caller): ERROR_PRIVILEGE_NOT_HELD; a Low primary copy (a sibling at its level): success; a Low impersonation
 *   copy through a handle with TOKEN_ASSIGN_PRIMARY only: ERROR_ACCESS_DENIED.
 * - From a restricted caller (restricting SIDs) and a write-restricted caller: the parent's token and its copies,
 *   which are not siblings of the caller's token: ERROR_PRIVILEGE_NOT_HELD; a token filtered from the parent's
 *   (DISABLE_MAX_PRIVILEGE) and another restricted token of the parent's, siblings of the caller's: success; a Low
 *   impersonation copy through a handle with TOKEN_ASSIGN_PRIMARY only: ERROR_PRIVILEGE_NOT_HELD (before the right).
 * - The process of CreateProcessAsUser has a new token object with the token's integrity level, restricting SIDs and
 *   enabled privileges.
 * The private class has the rules of ProcessAccessToken (the rows above, the handle right, the level, the privilege)
 * and gives the process a copy; it is what CreateProcessAsUser uses for a handle without TOKEN_DUPLICATE.
 */

#include "precomp.h"
#include <sddl.h>
#include <ndk/psfuncs.h>

#ifndef WRITE_RESTRICTED
#define WRITE_RESTRICTED 0x8
#endif

static CHAR g_Exe[MAX_PATH];

/* the handles a derived caller inherits, in this order */
enum { H_PARENT, H_PARENT_IMP, H_LOW, H_MEDIUM, H_FILTERED, H_RESTRICTED_SIBLING, H_LOW_IMP_AP, H_COUNT };
static const PCSTR HandleName[H_COUNT] = { "parent's token", "parent's impersonation copy", "Low primary copy",
                                          "Medium primary copy", "filtered copy", "restricted sibling",
                                          "Low impersonation copy without TOKEN_QUERY" };

static BOOL StartChild(PCSTR Mode, DWORD Flags, PROCESS_INFORMATION *Pi)
{
    STARTUPINFOA Si = { sizeof(Si) };
    CHAR CommandLine[MAX_PATH + 64];

    StringCbPrintfA(CommandLine, sizeof(CommandLine), "\"%s\" ProcessTokenCopy %s", g_Exe, Mode);
    return CreateProcessA(g_Exe, CommandLine, NULL, NULL, FALSE, Flags, NULL, NULL, &Si, Pi);
}

static VOID EndChild(PROCESS_INFORMATION *Pi)
{
    TerminateProcess(Pi->hProcess, 0);
    WaitForSingleObject(Pi->hProcess, 10000);
    CloseHandle(Pi->hThread);
    CloseHandle(Pi->hProcess);
}

static NTSTATUS SetToken(HANDLE Process, PROCESSINFOCLASS Class, HANDLE Token)
{
    PROCESS_ACCESS_TOKEN Access;

    Access.Token = Token;
    Access.Thread = NULL;
    return NtSetInformationProcess(Process, Class, &Access, sizeof(Access));
}

static BOOL TokenId(HANDLE Token, LUID *Id)
{
    TOKEN_STATISTICS Stats;
    DWORD Length;

    if (!GetTokenInformation(Token, TokenStatistics, &Stats, sizeof(Stats), &Length))
        return FALSE;
    *Id = Stats.TokenId;
    return TRUE;
}

static BOOL ProcessTokenId(HANDLE Process, LUID *Id)
{
    HANDLE Token;
    BOOL Ret;

    if (!OpenProcessToken(Process, TOKEN_QUERY, &Token))
        return FALSE;
    Ret = TokenId(Token, Id);
    CloseHandle(Token);
    return Ret;
}

static DWORD IntegrityLevel(HANDLE Token)
{
    ULONG Buffer[32];
    DWORD Length;
    PTOKEN_MANDATORY_LABEL Label = (PVOID)Buffer;

    if (!GetTokenInformation(Token, TokenIntegrityLevel, Buffer, sizeof(Buffer), &Length))
        return 0xffffffff;
    return *GetSidSubAuthority(Label->Label.Sid, *GetSidSubAuthorityCount(Label->Label.Sid) - 1);
}

static BOOL PrivilegeEnabled(HANDLE Token, PCWSTR Name)
{
    PRIVILEGE_SET Set;
    BOOL Result = FALSE;

    Set.PrivilegeCount = 1;
    Set.Control = PRIVILEGE_SET_ALL_NECESSARY;
    Set.Privilege[0].Attributes = 0;
    if (!LookupPrivilegeValueW(NULL, Name, &Set.Privilege[0].Luid) || !PrivilegeCheck(Token, &Set, &Result))
        return FALSE;
    return Result;
}

static DWORD RestrictingSidCount(HANDLE Token)
{
    ULONG Buffer[256];
    DWORD Length;

    if (!GetTokenInformation(Token, TokenRestrictedSids, Buffer, sizeof(Buffer), &Length))
        return 0xffffffff;
    return ((PTOKEN_GROUPS)Buffer)->GroupCount;
}

static HANDLE Dup(HANDLE Token, SECURITY_IMPERSONATION_LEVEL Level, TOKEN_TYPE Type)
{
    HANDLE New = NULL;

    if (!DuplicateTokenEx(Token, MAXIMUM_ALLOWED, NULL, Level, Type, &New))
        return NULL;
    return New;
}

static HANDLE Narrow(HANDLE Handle, ACCESS_MASK Rights, BOOL Inherit)
{
    HANDLE New = NULL;

    if (!Handle || !DuplicateHandle(GetCurrentProcess(), Handle, GetCurrentProcess(), &New, Rights, Inherit, 0))
        return NULL;
    return New;
}

static BOOL SetLevel(HANDLE Token, PCWSTR SidText)
{
    TOKEN_MANDATORY_LABEL Label;
    PSID Sid;
    BOOL Ret;

    if (!ConvertStringSidToSidW(SidText, &Sid))
        return FALSE;
    Label.Label.Attributes = SE_GROUP_INTEGRITY;
    Label.Label.Sid = Sid;
    Ret = SetTokenInformation(Token, TokenIntegrityLevel, &Label, sizeof(Label) + GetLengthSid(Sid));
    LocalFree(Sid);
    return Ret;
}

/* restricting SIDs: the user, Everyone, Users, Authenticated Users, RESTRICTED */
static HANDLE Restricted(HANDLE Token, DWORD Flags)
{
    static const PCWSTR Names[] = { L"S-1-1-0", L"S-1-5-32-545", L"S-1-5-11", L"S-1-5-12" };
    ULONG UserBuffer[64];
    SID_AND_ATTRIBUTES Sids[5];
    DWORD Length, i;
    HANDLE New = NULL;

    if (!GetTokenInformation(Token, TokenUser, UserBuffer, sizeof(UserBuffer), &Length))
        return NULL;
    Sids[0].Sid = ((PTOKEN_USER)UserBuffer)->User.Sid;
    Sids[0].Attributes = 0;
    for (i = 0; i < _countof(Names); i++)
    {
        ConvertStringSidToSidW(Names[i], &Sids[i + 1].Sid);
        Sids[i + 1].Attributes = 0;
    }
    if (!CreateRestrictedToken(Token, Flags, 0, NULL, 0, NULL, _countof(Sids), Sids, &New))
        New = NULL;
    for (i = 1; i < _countof(Sids); i++)
        LocalFree(Sids[i].Sid);
    return New;
}

/* CreateProcessAsUser of a suspended child with Token; returns the error (0: started), the child is ended */
static DWORD Cpau(HANDLE Token, HANDLE Source, PCSTR What)
{
    STARTUPINFOA Si = { sizeof(Si) };
    PROCESS_INFORMATION Pi;
    CHAR CommandLine[MAX_PATH + 64];
    LUID Child, Original;

    StringCbPrintfA(CommandLine, sizeof(CommandLine), "\"%s\" ProcessTokenCopy nop", g_Exe);
    if (!CreateProcessAsUserA(Token, g_Exe, CommandLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &Si, &Pi))
        return GetLastError();
    if (Source && TokenId(Source, &Original) && ProcessTokenId(Pi.hProcess, &Child))
        ok(!RtlEqualLuid(&Child, &Original), "%s: the child has the token object itself\n", What);
    EndChild(&Pi);
    return ERROR_SUCCESS;
}

/* ProcessAccessToken and the private class on targets in each state */
static VOID TestTargetStates(VOID)
{
    static const PROCESSINFOCLASS Classes[] = { ProcessAccessToken, ProcessRosAccessTokenCopy };
    PROCESS_INFORMATION Pi;
    HANDLE Me, Token, Remote;
    LUID Before, After, Want;
    NTSTATUS Status;
    ULONG i;

    ok(OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &Me), "OpenProcessToken: %lu\n", GetLastError());
    for (i = 0; i < _countof(Classes); i++)
    {
        PCSTR Name = (i == 0) ? "ProcessAccessToken" : "ProcessRosAccessTokenCopy";

        /* never ran: takes it (the object itself, or a copy) */
        Token = Dup(Me, SecurityImpersonation, TokenPrimary);
        if (StartChild("nop", CREATE_SUSPENDED, &Pi))
        {
            Status = SetToken(Pi.hProcess, Classes[i], Token);
            ok(Status == STATUS_SUCCESS, "%s, never ran: 0x%lx\n", Name, Status);
            if (NT_SUCCESS(Status) && ProcessTokenId(Pi.hProcess, &After) && TokenId(Token, &Want))
                ok(RtlEqualLuid(&After, &Want) == (i == 0), "%s, never ran: object itself %d\n", Name, RtlEqualLuid(&After, &Want));
            EndChild(&Pi);
        }
        CloseHandle(Token);

        /* runs */
        Token = Dup(Me, SecurityImpersonation, TokenPrimary);
        if (StartChild("sleep", 0, &Pi))
        {
            Sleep(1500);
            ProcessTokenId(Pi.hProcess, &Before);
            Status = SetToken(Pi.hProcess, Classes[i], Token);
            ok(Status == STATUS_NOT_SUPPORTED, "%s, running: 0x%lx\n", Name, Status);
            ok(ProcessTokenId(Pi.hProcess, &After) && RtlEqualLuid(&Before, &After), "%s, running: token changed\n", Name);

            /* the order (Windows): the handle and the level come first, the type and the in-use check after */
            Remote = Narrow(Token, TOKEN_QUERY, FALSE);
            Status = SetToken(Pi.hProcess, Classes[i], Remote);
            ok(Status == STATUS_ACCESS_DENIED, "%s, running, no TOKEN_ASSIGN_PRIMARY: 0x%lx\n", Name, Status);
            CloseHandle(Remote);
            Remote = Dup(Me, SecurityIdentification, TokenImpersonation);
            Status = SetToken(Pi.hProcess, Classes[i], Remote);
            ok(Status == STATUS_BAD_IMPERSONATION_LEVEL, "%s, running, identification: 0x%lx\n", Name, Status);
            CloseHandle(Remote);
            Remote = Dup(Me, SecurityImpersonation, TokenImpersonation);
            Status = SetToken(Pi.hProcess, Classes[i], Remote);
            ok(Status == STATUS_NOT_SUPPORTED, "%s, running, impersonation: 0x%lx\n", Name, Status);
            CloseHandle(Remote);
            Status = SetToken(Pi.hProcess, Classes[i], Me);
            ok(Status == STATUS_NOT_SUPPORTED, "%s, running, in use: 0x%lx\n", Name, Status);
            EndChild(&Pi);
        }

        /* ran, suspended again */
        if (StartChild("sleep", 0, &Pi))
        {
            Sleep(1500);
            SuspendThread(Pi.hThread);
            Status = SetToken(Pi.hProcess, Classes[i], Token);
            ok(Status == STATUS_NOT_SUPPORTED, "%s, ran and suspended: 0x%lx\n", Name, Status);
            EndChild(&Pi);
        }

        /* never ran, a second thread created suspended */
        if (StartChild("nop", CREATE_SUSPENDED, &Pi))
        {
            Remote = CreateRemoteThread(Pi.hProcess, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitThread"),
                                        NULL, CREATE_SUSPENDED, NULL);
            ok(Remote != NULL, "CreateRemoteThread: %lu\n", GetLastError());
            Status = SetToken(Pi.hProcess, Classes[i], Token);
            ok(Status == STATUS_NOT_SUPPORTED, "%s, second thread: 0x%lx\n", Name, Status);
            if (Remote) CloseHandle(Remote);
            EndChild(&Pi);
        }

        /* the caller itself */
        ProcessTokenId(GetCurrentProcess(), &Before);
        Status = SetToken(NtCurrentProcess(), Classes[i], Token);
        ok(Status == STATUS_NOT_SUPPORTED, "%s, own process: 0x%lx\n", Name, Status);
        ok(ProcessTokenId(GetCurrentProcess(), &After) && RtlEqualLuid(&Before, &After), "%s, own process: token changed\n", Name);
        CloseHandle(Token);
    }
    CloseHandle(Me);
}

/* the input of the private class on a child that never ran */
static VOID TestInput(VOID)
{
    PROCESS_INFORMATION Pi;
    PROCESS_ACCESS_TOKEN Access = { 0 };
    HANDLE Me, Token, Event, Limited;
    NTSTATUS Status;

    ok(OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &Me), "OpenProcessToken: %lu\n", GetLastError());
    if (!StartChild("nop", CREATE_SUSPENDED, &Pi))
    {
        skip("no child: %lu\n", GetLastError());
        return;
    }

    Status = NtSetInformationProcess(Pi.hProcess, ProcessRosAccessTokenCopy, &Access, sizeof(Access) - 1);
    ok(Status == STATUS_INFO_LENGTH_MISMATCH, "short length: 0x%lx\n", Status);
    Status = NtSetInformationProcess(Pi.hProcess, ProcessRosAccessTokenCopy, &Access, sizeof(Access) + 1);
    ok(Status == STATUS_INFO_LENGTH_MISMATCH, "long length: 0x%lx\n", Status);
    Status = NtSetInformationProcess(Pi.hProcess, ProcessRosAccessTokenCopy, NULL, sizeof(Access));
    ok(Status == STATUS_ACCESS_VIOLATION, "no buffer: 0x%lx\n", Status);
    Status = NtSetInformationProcess(Pi.hProcess, ProcessRosAccessTokenCopy, (PVOID)(ULONG_PTR)0x10, sizeof(Access));
    ok(Status == STATUS_ACCESS_VIOLATION, "bad buffer: 0x%lx\n", Status);
    Status = SetToken(Pi.hProcess, ProcessRosAccessTokenCopy, NULL);
    ok(Status == STATUS_INVALID_HANDLE, "no token: 0x%lx\n", Status);
    Status = SetToken(Pi.hProcess, ProcessRosAccessTokenCopy, (HANDLE)(ULONG_PTR)0x7ffc);
    ok(Status == STATUS_INVALID_HANDLE, "invalid handle: 0x%lx\n", Status);

    Event = CreateEventA(NULL, FALSE, FALSE, NULL);
    Status = SetToken(Pi.hProcess, ProcessRosAccessTokenCopy, Event);
    ok(Status == STATUS_OBJECT_TYPE_MISMATCH, "an event: 0x%lx\n", Status);
    CloseHandle(Event);

    Token = Narrow(Me, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, FALSE);
    Status = SetToken(Pi.hProcess, ProcessRosAccessTokenCopy, Token);
    ok(Status == STATUS_ACCESS_DENIED, "no TOKEN_ASSIGN_PRIMARY: 0x%lx\n", Status);
    CloseHandle(Token);

    Token = Dup(Me, SecurityIdentification, TokenImpersonation);
    Status = SetToken(Pi.hProcess, ProcessRosAccessTokenCopy, Token);
    ok(Status == STATUS_BAD_IMPERSONATION_LEVEL, "identification: 0x%lx\n", Status);
    CloseHandle(Token);
    Token = Dup(Me, SecurityAnonymous, TokenImpersonation);
    Status = SetToken(Pi.hProcess, ProcessRosAccessTokenCopy, Token);
    ok(Status == STATUS_BAD_IMPERSONATION_LEVEL, "anonymous: 0x%lx\n", Status);
    CloseHandle(Token);

    /* the process handle needs PROCESS_SET_INFORMATION */
    Token = Dup(Me, SecurityImpersonation, TokenPrimary);
    Limited = Narrow(Pi.hProcess, PROCESS_ALL_ACCESS & ~PROCESS_SET_INFORMATION, FALSE);
    Status = SetToken(Limited, ProcessRosAccessTokenCopy, Token);
    ok(Status == STATUS_ACCESS_DENIED, "no PROCESS_SET_INFORMATION: 0x%lx\n", Status);
    CloseHandle(Limited);
    CloseHandle(Token);

    EndChild(&Pi);
    CloseHandle(Me);
}

/* what the copy carries: never more than the token */
static VOID TestCopyContent(VOID)
{
    PROCESS_INFORMATION Pi, Pi2;
    HANDLE Me, Source, Handle, ChildToken, InUse;
    LUID Want, Have;
    DWORD Session = 0, ChildSession = 0, Length;
    NTSTATUS Status;
    TOKEN_PRIVILEGES Tp;
    TOKEN_TYPE Type;

    ok(OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &Me), "OpenProcessToken: %lu\n", GetLastError());
    GetTokenInformation(Me, TokenSessionId, &Session, sizeof(Session), &Length);

    /* an impersonation copy at Low integrity with SeChangeNotify only enabled */
    Source = Dup(Me, SecurityImpersonation, TokenImpersonation);
    ok(SetLevel(Source, L"S-1-16-4096"), "lowering: %lu\n", GetLastError());
    if (Source && StartChild("nop", CREATE_SUSPENDED, &Pi))
    {
        Handle = Narrow(Source, TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, FALSE);
        Status = SetToken(Pi.hProcess, ProcessRosAccessTokenCopy, Handle);
        ok(Status == STATUS_SUCCESS, "Low impersonation copy: 0x%lx\n", Status);
        if (NT_SUCCESS(Status) && OpenProcessToken(Pi.hProcess, TOKEN_QUERY, &ChildToken))
        {
            ok(GetTokenInformation(ChildToken, TokenType, &Type, sizeof(Type), &Length) && Type == TokenPrimary, "type %d\n", Type);
            ok(IntegrityLevel(ChildToken) == SECURITY_MANDATORY_LOW_RID, "level 0x%lx\n", IntegrityLevel(ChildToken));
            ok(TokenId(ChildToken, &Have) && TokenId(Source, &Want) && !RtlEqualLuid(&Have, &Want), "not a new object\n");
            GetTokenInformation(ChildToken, TokenSessionId, &ChildSession, sizeof(ChildSession), &Length);
            ok(ChildSession == Session, "session %lu, caller's %lu\n", ChildSession, Session);
            ok(PrivilegeEnabled(ChildToken, L"SeBackupPrivilege") == PrivilegeEnabled(Source, L"SeBackupPrivilege"),
               "SeBackupPrivilege %d, source %d\n", PrivilegeEnabled(ChildToken, L"SeBackupPrivilege"),
               PrivilegeEnabled(Source, L"SeBackupPrivilege"));
            CloseHandle(ChildToken);
        }
        CloseHandle(Handle);
        EndChild(&Pi);
    }
    if (Source) CloseHandle(Source);

    /* a Medium primary copy: SeBackupPrivilege keeps the state the source has, the level stays */
    Source = Dup(Me, SecurityImpersonation, TokenPrimary);
    Tp.PrivilegeCount = 1;
    LookupPrivilegeValueW(NULL, L"SeBackupPrivilege", &Tp.Privileges[0].Luid);
    Tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(Source, FALSE, &Tp, sizeof(Tp), NULL, NULL);
    SetLevel(Source, L"S-1-16-8192");
    if (Source && StartChild("nop", CREATE_SUSPENDED, &Pi))
    {
        Handle = Narrow(Source, TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, FALSE);
        Status = SetToken(Pi.hProcess, ProcessRosAccessTokenCopy, Handle);
        ok(Status == STATUS_SUCCESS, "Medium copy: 0x%lx\n", Status);
        if (NT_SUCCESS(Status) && OpenProcessToken(Pi.hProcess, TOKEN_QUERY, &ChildToken))
        {
            ok(IntegrityLevel(ChildToken) == IntegrityLevel(Source), "level 0x%lx, source 0x%lx\n",
               IntegrityLevel(ChildToken), IntegrityLevel(Source));
            ok(PrivilegeEnabled(ChildToken, L"SeBackupPrivilege") == PrivilegeEnabled(Source, L"SeBackupPrivilege"),
               "SeBackupPrivilege %d, source %d\n", PrivilegeEnabled(ChildToken, L"SeBackupPrivilege"),
               PrivilegeEnabled(Source, L"SeBackupPrivilege"));
            CloseHandle(ChildToken);
        }
        CloseHandle(Handle);
        EndChild(&Pi);

        /* the source stays unused: ProcessAccessToken still takes the object itself */
        if (StartChild("nop", CREATE_SUSPENDED, &Pi2))
        {
            Status = SetToken(Pi2.hProcess, ProcessAccessToken, Source);
            ok(Status == STATUS_SUCCESS, "the source after the copy: 0x%lx\n", Status);
            EndChild(&Pi2);
        }
    }
    if (Source) CloseHandle(Source);

    /* a restricted source: the copy is restricted */
    Source = Restricted(Me, 0);
    if (Source && StartChild("nop", CREATE_SUSPENDED, &Pi))
    {
        Handle = Narrow(Source, TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, FALSE);
        Status = SetToken(Pi.hProcess, ProcessRosAccessTokenCopy, Handle);
        ok(Status == STATUS_SUCCESS, "restricted copy: 0x%lx\n", Status);
        if (NT_SUCCESS(Status) && OpenProcessToken(Pi.hProcess, TOKEN_QUERY, &ChildToken))
        {
            ok(RestrictingSidCount(ChildToken) == RestrictingSidCount(Source) && RestrictingSidCount(Source) > 0,
               "the copy has %lu restricting SIDs, the source %lu\n", RestrictingSidCount(ChildToken),
               RestrictingSidCount(Source));
            CloseHandle(ChildToken);
        }
        CloseHandle(Handle);
        EndChild(&Pi);
    }
    if (Source) CloseHandle(Source);

    /* the caller's own token, in use: a copy for the child; the token stays in use (ProcessAccessToken refuses it) */
    InUse = Narrow(Me, TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, FALSE);
    if (StartChild("nop", CREATE_SUSPENDED, &Pi))
    {
        Status = SetToken(Pi.hProcess, ProcessRosAccessTokenCopy, InUse);
        ok(Status == STATUS_SUCCESS, "own token in use: 0x%lx\n", Status);
        Status = SetToken(Pi.hProcess, ProcessAccessToken, InUse);
        ok(Status == STATUS_TOKEN_ALREADY_IN_USE, "own token in use, ProcessAccessToken: 0x%lx\n", Status);
        EndChild(&Pi);
    }
    CloseHandle(InUse);
    CloseHandle(Me);
}

/* a derived caller (Low, restricted, write-restricted): CreateProcessAsUser and the private class with inherited handles */
static VOID CallerRows(PCSTR Kind, int Count, char **Args)
{
    /*
     * ERROR_SUCCESS where the token is a sibling of the caller's at or below its level, else the privilege; a handle
     * without TOKEN_QUERY: the privilege first, then ERROR_ACCESS_DENIED (the kernel class does not need the right)
     */
    static const DWORD LowExpected[H_COUNT] = { ERROR_PRIVILEGE_NOT_HELD, ERROR_PRIVILEGE_NOT_HELD, ERROR_SUCCESS,
                                                ERROR_PRIVILEGE_NOT_HELD, ERROR_PRIVILEGE_NOT_HELD, ERROR_PRIVILEGE_NOT_HELD,
                                                ERROR_ACCESS_DENIED };
    static const DWORD RestrictedExpected[H_COUNT] = { ERROR_PRIVILEGE_NOT_HELD, ERROR_PRIVILEGE_NOT_HELD,
                                                       ERROR_PRIVILEGE_NOT_HELD, ERROR_PRIVILEGE_NOT_HELD,
                                                       ERROR_SUCCESS, ERROR_SUCCESS, ERROR_PRIVILEGE_NOT_HELD };
    const DWORD *Expected = strcmp(Kind, "low") ? RestrictedExpected : LowExpected;
    PROCESS_INFORMATION Pi;
    HANDLE Handle, Me;
    NTSTATUS Status;
    DWORD Error;
    int i;

    ok(Count == H_COUNT, "%s: %d handles\n", Kind, Count);
    for (i = 0; i < Count && i < H_COUNT; i++)
    {
        Handle = (HANDLE)(ULONG_PTR)strtoul(Args[i], NULL, 16);
        Error = Cpau(Handle, NULL, HandleName[i]);
        ok(Error == Expected[i], "%s caller, %s: CreateProcessAsUser %lu, expected %lu\n", Kind, HandleName[i], Error, Expected[i]);
        if (StartChild("nop", CREATE_SUSPENDED, &Pi))
        {
            Status = SetToken(Pi.hProcess, ProcessRosAccessTokenCopy, Handle);
            ok(Status == ((Expected[i] == ERROR_PRIVILEGE_NOT_HELD) ? STATUS_PRIVILEGE_NOT_HELD : STATUS_SUCCESS),
               "%s caller, %s: the private class 0x%lx\n", Kind, HandleName[i], Status);
            EndChild(&Pi);
        }
        else
        {
            skip("%s caller: no child %lu\n", Kind, GetLastError());
        }
    }

    /* the privilege comes before the state of the process (Windows: the parent's token on a running child) */
    if (StartChild("sleep", 0, &Pi))
    {
        Sleep(1500);
        Handle = (HANDLE)(ULONG_PTR)strtoul(Args[H_PARENT], NULL, 16);
        Status = SetToken(Pi.hProcess, ProcessAccessToken, Handle);
        ok(Status == STATUS_PRIVILEGE_NOT_HELD, "%s caller, parent's token, running child: ProcessAccessToken 0x%lx\n", Kind, Status);
        Status = SetToken(Pi.hProcess, ProcessRosAccessTokenCopy, Handle);
        ok(Status == STATUS_PRIVILEGE_NOT_HELD, "%s caller, parent's token, running child: the private class 0x%lx\n", Kind, Status);
        EndChild(&Pi);
    }

    /* the caller's own (started) process keeps its token */
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &Me))
    {
        /* with a sibling it may take (Low: the Low copy; restricted: the filtered copy), so the state decides */
        Handle = (HANDLE)(ULONG_PTR)strtoul(Args[Expected == LowExpected ? H_LOW : H_FILTERED], NULL, 16);
        Status = SetToken(NtCurrentProcess(), ProcessRosAccessTokenCopy, Handle);
        ok(Status == STATUS_NOT_SUPPORTED, "%s caller, own process: 0x%lx\n", Kind, Status);
        CloseHandle(Me);
    }
}

static VOID RunCaller(PCSTR Kind, HANDLE CallerToken, HANDLE *Handles)
{
    STARTUPINFOA Si = { sizeof(Si) };
    PROCESS_INFORMATION Pi;
    CHAR CommandLine[MAX_PATH + 256];
    size_t Used;
    int i;

    if (!CallerToken)
    {
        skip("%s caller: no token %lu\n", Kind, GetLastError());
        return;
    }

    /* whoever runs the test: the derived caller has no SeAssignPrimaryTokenPrivilege */
    {
        TOKEN_PRIVILEGES Tp;

        Tp.PrivilegeCount = 1;
        Tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;
        if (LookupPrivilegeValueW(NULL, L"SeAssignPrimaryTokenPrivilege",&Tp.Privileges[0].Luid))
            AdjustTokenPrivileges(CallerToken, FALSE, &Tp, sizeof(Tp), NULL, NULL);
    }
    StringCbPrintfA(CommandLine, sizeof(CommandLine), "\"%s\" ProcessTokenCopy caller %s", g_Exe, Kind);
    for (i = 0; i < H_COUNT; i++)
    {
        Used = strlen(CommandLine);
        StringCbPrintfA(CommandLine + Used, sizeof(CommandLine) - Used, " %lx", (ULONG)(ULONG_PTR)Handles[i]);
    }
    if (!CreateProcessAsUserA(CallerToken, g_Exe, CommandLine, NULL, NULL, TRUE, 0, NULL, NULL, &Si, &Pi))
    {
        ok(0, "%s caller: CreateProcessAsUser %lu\n", Kind, GetLastError());
        return;
    }
    winetest_wait_child_process(Pi.hProcess);
    CloseHandle(Pi.hThread);
    CloseHandle(Pi.hProcess);
}

static VOID TestCallers(VOID)
{
    HANDLE Me, Imp, Low, LowImp, Medium, Filtered = NULL, Sibling, Caller, Handles[H_COUNT];
    int i;

    ok(OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &Me), "OpenProcessToken: %lu\n", GetLastError());
    if (IntegrityLevel(Me) < SECURITY_MANDATORY_HIGH_RID)
    {
        /* the Medium and filtered copies must be above the Low caller and not the caller's own level */
        skip("the caller rows need a High integrity test process\n");
        CloseHandle(Me);
        return;
    }
    Imp = Dup(Me, SecurityImpersonation, TokenImpersonation);
    Low = Dup(Me, SecurityImpersonation, TokenPrimary);
    SetLevel(Low, L"S-1-16-4096");
    Medium = Dup(Me, SecurityImpersonation, TokenPrimary);
    SetLevel(Medium, L"S-1-16-8192");
    CreateRestrictedToken(Me, DISABLE_MAX_PRIVILEGE, 0, NULL, 0, NULL, 0, NULL, &Filtered);
    Sibling = Restricted(Me, 0);
    Handles[H_PARENT] = Narrow(Me, TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, TRUE);
    Handles[H_PARENT_IMP] = Narrow(Imp, TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, TRUE);
    Handles[H_LOW] = Narrow(Low, TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, TRUE);
    Handles[H_MEDIUM] = Narrow(Medium, TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, TRUE);
    Handles[H_FILTERED] = Narrow(Filtered, TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, TRUE);
    Handles[H_RESTRICTED_SIBLING] = Narrow(Sibling, TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, TRUE);
    LowImp = Dup(Me, SecurityImpersonation, TokenImpersonation);
    SetLevel(LowImp, L"S-1-16-4096");
    Handles[H_LOW_IMP_AP] = Narrow(LowImp, TOKEN_ASSIGN_PRIMARY, TRUE);

    Caller = Dup(Me, SecurityImpersonation, TokenPrimary);
    SetLevel(Caller, L"S-1-16-4096");
    RunCaller("low", Caller, Handles);
    CloseHandle(Caller);
    Caller = Restricted(Me, 0);
    RunCaller("restricted", Caller, Handles);
    if (Caller) CloseHandle(Caller);
    Caller = Restricted(Me, WRITE_RESTRICTED);
    RunCaller("write-restricted", Caller, Handles);
    if (Caller) CloseHandle(Caller);

    for (i = 0; i < H_COUNT; i++)
        if (Handles[i]) CloseHandle(Handles[i]);
    CloseHandle(Imp);
    CloseHandle(Low);
    CloseHandle(Medium);
    CloseHandle(LowImp);
    if (Filtered) CloseHandle(Filtered);
    if (Sibling) CloseHandle(Sibling);
    CloseHandle(Me);
}

START_TEST(ProcessTokenCopy)
{
    int argc;
    char **argv;

    GetModuleFileNameA(NULL, g_Exe, sizeof(g_Exe));
    argc = winetest_get_mainargs(&argv);
    if (argc >= 3 && !strcmp(argv[2], "nop"))
        return;
    if (argc >= 3 && !strcmp(argv[2], "sleep"))
    {
        Sleep(30000);
        return;
    }
    if (argc >= 4 && !strcmp(argv[2], "caller"))
    {
        CallerRows(argv[3], argc - 4, argv + 4);
        return;
    }

    TestTargetStates();
    TestInput();
    TestCopyContent();
    TestCallers();
}
