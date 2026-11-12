/*
 * PROJECT:     NitroOS Session Manager
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     NitroSessions feature flag (Windows-style sessions, phase P0)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

/* INCLUDES *******************************************************************/

#include "smss.h"

#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

/*
 * HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\NitroSessions (DWORD).
 * Absent or 0: today's single-session boot, nothing below runs.
 * 1: after session 0 is up, create a second Mm session and run the test
 *    command (NitroSessionsTestCommand, REG_SZ) in it. There is no csrss for
 *    session 1, so the test command must be a native image.
 * 4: after session 0 is up, create session 1 with its own csrss. That csrss
 *    loads basesrv only (no winsrv: win32k stays global until phase P3b),
 *    with its ports in \Sessions\1\Windows. Then:
 *    - NitroSessionsTestCommand runs in session 1. A Windows image is
 *      registered with session 1's csrss, like winlogon with session 0's;
 *    - once SMSS is detached again, NitroSessionsTestCommand0 (REG_SZ,
 *      optional) runs outside any session, a native image. It proves that a
 *      process created after the detach does not see session 1.
 *    - NitroSessionsTestKill (DWORD, optional, test only): terminate every
 *      process of session 1 (its csrss and the test command) and wait for
 *      them to be gone before SMSS detaches, so that SMSS holds the last
 *      reference to the session.
 */
ULONG SmpNitroSessions;
static ULONG SmpNitroSessionsTestKill;
ULONG SmpNitroSessionsTestForward;
ULONG SmpNitroSessionsTestForwardStall;
UNICODE_STRING SmpNitroSessionsTestCommand;
UNICODE_STRING SmpNitroSessionsTestCommand0;

/*
 * Serialises the creation of sessions after session 0 (design 3.1): SMSS is
 * the only session leader and is attached to the session it creates until
 * it detaches, so only one create may run at a time. Taken around the
 * NitroSessions creates and SmpStartCsr.
 */
RTL_CRITICAL_SECTION SmpMuSessionLock;

/* FUNCTIONS ******************************************************************/

/* A REG_SZ or REG_EXPAND_SZ value of the key, copied into the SMSS heap */
static
VOID
SmpReadNitroString(
    _In_ HANDLE KeyHandle,
    _In_ PCWSTR Name,
    _Out_ PUNICODE_STRING Result)
{
    NTSTATUS Status;
    UNICODE_STRING ValueName;
    ULONG ResultLength;
    PKEY_VALUE_PARTIAL_INFORMATION Info;
    UCHAR Buffer[FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + 512 * sizeof(WCHAR)];
    PWCHAR String;

    RtlInitEmptyUnicodeString(Result, NULL, 0);
    Info = (PKEY_VALUE_PARTIAL_INFORMATION)Buffer;

    RtlInitUnicodeString(&ValueName, Name);
    Status = NtQueryValueKey(KeyHandle,
                             &ValueName,
                             KeyValuePartialInformation,
                             Info,
                             sizeof(Buffer) - sizeof(UNICODE_NULL),
                             &ResultLength);
    if (!NT_SUCCESS(Status) ||
        ((Info->Type != REG_SZ) && (Info->Type != REG_EXPAND_SZ)) ||
        (Info->DataLength < sizeof(WCHAR)) ||
        (Info->DataLength > sizeof(Buffer) - sizeof(UNICODE_NULL) -
                            FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data)))
    {
        return;
    }

    String = RtlAllocateHeap(SmpHeap, SmBaseTag, Info->DataLength + sizeof(UNICODE_NULL));
    if (!String) return;

    RtlCopyMemory(String, Info->Data, Info->DataLength);
    String[Info->DataLength / sizeof(WCHAR)] = UNICODE_NULL;
    RtlInitUnicodeString(Result, String);
    DPRINT1("SMSS: %S = '%wZ'\n", Name, Result);
}

VOID
NTAPI
SmpReadNitroSessionsConfig(VOID)
{
    NTSTATUS Status;
    HANDLE KeyHandle;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING KeyName, ValueName;
    ULONG ResultLength;
    PKEY_VALUE_PARTIAL_INFORMATION Info;
    UCHAR Buffer[FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + sizeof(ULONG)];

    SmpNitroSessions = 0;
    SmpNitroSessionsTestKill = 0;
    SmpNitroSessionsTestForward = 0;
    SmpNitroSessionsTestForwardStall = 0;
    RtlInitEmptyUnicodeString(&SmpNitroSessionsTestCommand, NULL, 0);
    RtlInitEmptyUnicodeString(&SmpNitroSessionsTestCommand0, NULL, 0);

    RtlInitUnicodeString(&KeyName,
                         L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager");
    InitializeObjectAttributes(&ObjectAttributes,
                               &KeyName,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);
    Status = NtOpenKey(&KeyHandle, KEY_READ, &ObjectAttributes);
    if (!NT_SUCCESS(Status)) return;

    Info = (PKEY_VALUE_PARTIAL_INFORMATION)Buffer;

    /* The flag itself; anything but a DWORD counts as absent */
    RtlInitUnicodeString(&ValueName, L"NitroSessions");
    Status = NtQueryValueKey(KeyHandle,
                             &ValueName,
                             KeyValuePartialInformation,
                             Info,
                             sizeof(Buffer),
                             &ResultLength);
    if (NT_SUCCESS(Status) &&
        (Info->Type == REG_DWORD) &&
        (Info->DataLength == sizeof(ULONG)))
    {
        SmpNitroSessions = *(PULONG)Info->Data;
    }

    /* The test commands are only read when the flag is set */
    if (SmpNitroSessions != 0)
    {
        DPRINT1("SMSS: NitroSessions = %lu\n", SmpNitroSessions);
        SmpReadNitroString(KeyHandle, L"NitroSessionsTestCommand", &SmpNitroSessionsTestCommand);
        if (SMP_NITRO_SESSIONS_CSR_START(SmpNitroSessions))
        {
            SmpReadNitroString(KeyHandle, L"NitroSessionsTestCommand0", &SmpNitroSessionsTestCommand0);

            RtlInitUnicodeString(&ValueName, L"NitroSessionsTestKill");
            Status = NtQueryValueKey(KeyHandle,
                                     &ValueName,
                                     KeyValuePartialInformation,
                                     Info,
                                     sizeof(Buffer),
                                     &ResultLength);
            if (NT_SUCCESS(Status) &&
                (Info->Type == REG_DWORD) &&
                (Info->DataLength == sizeof(ULONG)))
            {
                SmpNitroSessionsTestKill = *(PULONG)Info->Data;
            }

            /* Test only: SMSS checks that session 1's csrss refuses bad SbCreateRemoteProcess requests */
            RtlInitUnicodeString(&ValueName, L"NitroSessionsTestForward");
            Status = NtQueryValueKey(KeyHandle,
                                     &ValueName,
                                     KeyValuePartialInformation,
                                     Info,
                                     sizeof(Buffer),
                                     &ResultLength);
            if (NT_SUCCESS(Status) &&
                (Info->Type == REG_DWORD) &&
                (Info->DataLength == sizeof(ULONG)))
            {
                SmpNitroSessionsTestForward = *(PULONG)Info->Data;
            }

            /* Test only: forwards wait this many seconds instead of the target csrss answering (a stuck target) */
            RtlInitUnicodeString(&ValueName, L"NitroSessionsTestForwardStall");
            Status = NtQueryValueKey(KeyHandle,
                                     &ValueName,
                                     KeyValuePartialInformation,
                                     Info,
                                     sizeof(Buffer),
                                     &ResultLength);
            if (NT_SUCCESS(Status) &&
                (Info->Type == REG_DWORD) &&
                (Info->DataLength == sizeof(ULONG)))
            {
                SmpNitroSessionsTestForwardStall = *(PULONG)Info->Data;
            }
        }
    }

    NtClose(KeyHandle);
}

/*
 * Flag 1: create a second Mm session and start the test command in it.
 * Runs once, from the main thread, after session 0's initial command is
 * started and SMSS has detached from session 0.
 */
NTSTATUS
NTAPI
SmpStartNitroTestSession(VOID)
{
    NTSTATUS Status, Status2;
    ULONG MuSessionId = 0;
    PVOID State;

    if (SmpNitroSessions != SMP_NITRO_SESSIONS_TEST) return STATUS_SUCCESS;

    if (!SmpNitroSessionsTestCommand.Length)
    {
        DPRINT1("SMSS: NitroSessions=1 but no NitroSessionsTestCommand, no test session\n");
        return STATUS_SUCCESS;
    }

    /* Single leader: SMSS must not be attached to any session now */
    ASSERT(AttachedSessionId == -1);

    Status = SmpAcquirePrivilege(SE_LOAD_DRIVER_PRIVILEGE, &State);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("SMSS: NitroSessions: no load-driver privilege, Status=%lx\n", Status);
        return Status;
    }

    DPRINT1("SMSS: NitroSessions: creating the test session\n");
    Status = NtSetSystemInformation(SystemSessionCreate,
                                    &MuSessionId,
                                    sizeof(MuSessionId));
    DPRINT1("SMSS: NitroSessions: SystemSessionCreate Status=%lx SessionId=%lu\n",
            Status, MuSessionId);
    if (!NT_SUCCESS(Status))
    {
        SmpReleasePrivilege(State);
        return Status;
    }
    AttachedSessionId = MuSessionId;

    /* Attached to the new session: the process joins it at creation */
    Status = SmpExecuteCommand(&SmpNitroSessionsTestCommand,
                               MuSessionId,
                               NULL,
                               SMP_ASYNC_FLAG);
    DPRINT1("SMSS: NitroSessions: test command '%wZ' in session %lu, Status=%lx\n",
            &SmpNitroSessionsTestCommand, MuSessionId, Status);

    /* Detach again; SMSS stays the leader of no session */
    Status2 = NtSetSystemInformation(SystemSessionDetach,
                                     &AttachedSessionId,
                                     sizeof(AttachedSessionId));
    DPRINT1("SMSS: NitroSessions: SystemSessionDetach Status=%lx\n", Status2);
    if (NT_SUCCESS(Status2)) AttachedSessionId = -1;

    SmpReleasePrivilege(State);
    return Status;
}

/*
 * The csrss command line of a headless session: the Windows subsystem's
 * command line from the registry (the "Required" Windows entry), with every
 * ServerDll except basesrv left out. win32k is not loaded in such a session,
 * so neither is winsrv (user and console servers).
 */
static
NTSTATUS
SmpBuildHeadlessCsrCommand(
    _Out_ PUNICODE_STRING Command)
{
    static const WCHAR ServerDllKey[] = L"ServerDll=";
    const SIZE_T KeyChars = RTL_NUMBER_OF(ServerDllKey) - 1;
    PLIST_ENTRY NextEntry;
    PSMP_REGISTRY_VALUE RegEntry, Windows = NULL;
    PCWSTR Source, End, Token, DllName;
    SIZE_T TokenChars, NameChars;
    PWCHAR Buffer, Out;
    BOOLEAN Keep;

    RtlInitEmptyUnicodeString(Command, NULL, 0);

    for (NextEntry = SmpSubSystemsToLoad.Flink;
         NextEntry != &SmpSubSystemsToLoad;
         NextEntry = NextEntry->Flink)
    {
        RegEntry = CONTAINING_RECORD(NextEntry, SMP_REGISTRY_VALUE, Entry);
        if (RegEntry->Name.Buffer && !_wcsicmp(RegEntry->Name.Buffer, L"Windows"))
        {
            Windows = RegEntry;
            break;
        }
    }
    if (!Windows || !Windows->Value.Length) return STATUS_OBJECT_NAME_NOT_FOUND;

    Buffer = RtlAllocateHeap(SmpHeap, SmBaseTag, Windows->Value.Length + sizeof(UNICODE_NULL));
    if (!Buffer) return STATUS_NO_MEMORY;

    Out = Buffer;
    Source = Windows->Value.Buffer;
    End = Source + Windows->Value.Length / sizeof(WCHAR);
    while (Source < End)
    {
        /* Skip blanks, then take one token */
        while ((Source < End) && ((*Source == L' ') || (*Source == L'\t'))) Source++;
        if (Source >= End || *Source == UNICODE_NULL) break;
        Token = Source;
        while ((Source < End) && (*Source != L' ') && (*Source != L'\t') &&
               (*Source != UNICODE_NULL)) Source++;
        TokenChars = Source - Token;

        /* ServerDll=<name>[:<entry>],<index>: keep basesrv only */
        Keep = TRUE;
        if ((TokenChars > KeyChars) && !_wcsnicmp(Token, ServerDllKey, KeyChars))
        {
            DllName = Token + KeyChars;
            NameChars = 0;
            while ((DllName + NameChars < Source) &&
                   (DllName[NameChars] != L':') && (DllName[NameChars] != L','))
            {
                NameChars++;
            }
            /* With a win32k of its own (flag 5), the session keeps every server */
            Keep = (SmpNitroSessions == SMP_NITRO_SESSIONS_WIN32K) ||
                   ((NameChars == 7) && !_wcsnicmp(DllName, L"basesrv", 7));
        }
        if (!Keep) continue;

        if (Out != Buffer) *Out++ = L' ';
        RtlCopyMemory(Out, Token, TokenChars * sizeof(WCHAR));
        Out += TokenChars;
    }
    *Out = UNICODE_NULL;

    if (Out == Buffer)
    {
        RtlFreeHeap(SmpHeap, 0, Buffer);
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    RtlInitUnicodeString(Command, Buffer);
    return STATUS_SUCCESS;
}

/*
 * Test only (NitroSessionsTestKill): terminate a process of the test session
 * and wait until it is gone. A process that is not waited for in full would
 * still hold its reference when SMSS detaches.
 */
static
VOID
SmpNitroKillAndWait(
    _In_ PCSTR What,
    _In_ HANDLE Process)
{
    NTSTATUS Status;
    LARGE_INTEGER Timeout;

    Status = NtTerminateProcess(Process, STATUS_UNSUCCESSFUL);
    if (NT_SUCCESS(Status))
    {
        Timeout.QuadPart = -10000000LL * 20;
        Status = NtWaitForSingleObject(Process, FALSE, &Timeout);
    }
    DPRINT1("SMSS: NitroSessions: test kill of %s, Status=%lx\n", What, Status);
}

/*
 * Detach SMSS from the session it is attached to, if any. Returns the failure
 * status when SMSS is still attached afterwards: the caller must not start
 * anything meant to be in no session then.
 */
NTSTATUS
NTAPI
SmpNitroDetach(VOID)
{
    NTSTATUS Status;
    PVOID State;

    if (AttachedSessionId == -1) return STATUS_SUCCESS;

    Status = SmpAcquirePrivilege(SE_LOAD_DRIVER_PRIVILEGE, &State);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("SMSS: NitroSessions: no privilege to detach from session %lu, Status=%lx\n",
                AttachedSessionId, Status);
        return Status;
    }

    Status = NtSetSystemInformation(SystemSessionDetach,
                                    &AttachedSessionId,
                                    sizeof(AttachedSessionId));
    DPRINT1("SMSS: NitroSessions: SystemSessionDetach(%lu) Status=%lx\n",
            AttachedSessionId, Status);
    if (NT_SUCCESS(Status)) AttachedSessionId = -1;

    SmpReleasePrivilege(State);
    return Status;
}

/*
 * Test only (NitroSessionsTestForward = 1 with NitroSessions 4 or 5): the
 * target csrss's own checks of SbCreateRemoteProcess. Only SMSS can send it,
 * so SMSS sends the bad requests that a correct basesrv never forwards:
 * - a process of another session (SMSS itself, which is in none);
 * - a thread that is not one of the process's;
 * - another session in the request than the csrss's;
 * - unknown flags;
 * - csrss itself;
 * - a process that is registered already (the test command).
 * Each must be refused with its own status, and nothing is registered.
 */

/* A thread of the process, from the system process list */
static
HANDLE
SmpNitroThreadOf(
    _In_ HANDLE ProcessId)
{
    NTSTATUS Status;
    ULONG Size = 0x20000;
    PUCHAR Buffer;
    PSYSTEM_PROCESS_INFORMATION Info;
    PSYSTEM_THREAD_INFORMATION Threads;
    HANDLE ThreadId = NULL;

    for (;;)
    {
        Buffer = RtlAllocateHeap(SmpHeap, 0, Size);
        if (!Buffer) return NULL;
        Status = NtQuerySystemInformation(SystemProcessInformation, Buffer, Size, NULL);
        if (Status != STATUS_INFO_LENGTH_MISMATCH) break;
        RtlFreeHeap(SmpHeap, 0, Buffer);
        Size *= 2;
        if (Size > 0x1000000) return NULL;
    }

    if (NT_SUCCESS(Status))
    {
        Info = (PSYSTEM_PROCESS_INFORMATION)Buffer;
        for (;;)
        {
            if ((Info->UniqueProcessId == ProcessId) && Info->NumberOfThreads)
            {
                Threads = (PSYSTEM_THREAD_INFORMATION)(Info + 1);
                ThreadId = Threads[0].ClientId.UniqueThread;
                break;
            }
            if (!Info->NextEntryOffset) break;
            Info = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)Info + Info->NextEntryOffset);
        }
    }
    RtlFreeHeap(SmpHeap, 0, Buffer);
    return ThreadId;
}

static
VOID
SmpNitroForwardCase(
    _In_ PCSTR Name,
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ ULONG TargetSessionId,
    _In_ ULONG MessageSessionId,
    _In_ ULONG Flags,
    _In_ NTSTATUS Expected)
{
    CLIENT_ID ClientId;
    NTSTATUS Status;

    ClientId.UniqueProcess = ProcessId;
    ClientId.UniqueThread = ThreadId;
    Status = SmpSbCreateRemoteProcessEx(&ClientId, TargetSessionId, MessageSessionId, Flags);
    DPRINT1("SMSS: NitroSessions: forward self-test %s (%p.%p) Status=%lx expect=%lx %s\n",
            Name, ProcessId, ThreadId, Status, Expected,
            (Status == Expected) ? "PASS" : "FAIL");
}

static
VOID
SmpNitroForwardSelfTest(
    _In_ ULONG MuSessionId,
    _In_ HANDLE CsrProcessId,
    _In_ HANDLE TestProcessId)
{
    HANDLE SmssProcessId = NtCurrentTeb()->ClientId.UniqueProcess;
    HANDLE SmssThreadId = NtCurrentTeb()->ClientId.UniqueThread;
    HANDLE TestThreadId = SmpNitroThreadOf(TestProcessId);
    HANDLE CsrThreadId = SmpNitroThreadOf(CsrProcessId);

    DPRINT1("SMSS: NitroSessions: forward self-test, session %lu, test command %p.%p, csrss %p.%p\n",
            MuSessionId, TestProcessId, TestThreadId, CsrProcessId, CsrThreadId);
    if (!TestThreadId || !CsrThreadId)
    {
        DPRINT1("SMSS: NitroSessions: forward self-test FAIL (no thread ids)\n");
        return;
    }

    SmpNitroForwardCase("process-of-another-session", SmssProcessId, SmssThreadId,
                        MuSessionId, MuSessionId, 0, STATUS_ACCESS_DENIED);
    SmpNitroForwardCase("thread-of-another-process", TestProcessId, SmssThreadId,
                        MuSessionId, MuSessionId, 0, STATUS_INVALID_CID);
    SmpNitroForwardCase("other-session-in-request", TestProcessId, TestThreadId,
                        MuSessionId, 0, 0, STATUS_INVALID_PARAMETER);
    SmpNitroForwardCase("unknown-flags", TestProcessId, TestThreadId,
                        MuSessionId, MuSessionId, 0x80, STATUS_INVALID_PARAMETER);
    SmpNitroForwardCase("csrss-itself", CsrProcessId, CsrThreadId,
                        MuSessionId, MuSessionId, 0, STATUS_ACCESS_DENIED);
    SmpNitroForwardCase("already-registered", TestProcessId, TestThreadId,
                        MuSessionId, MuSessionId, 0, STATUS_OBJECT_NAME_COLLISION);
}

/*

 * Flag 4 (phase P2): session 1 with its own csrss. Runs once, from the main
 * thread, after session 0's initial command is started and SMSS has detached
 * from session 0. Every step runs under SmpMuSessionLock.
 */
NTSTATUS
NTAPI
SmpStartNitroCsrSession(VOID)
{
    NTSTATUS Status, Status2;
    ULONG MuSessionId = 0;
    PVOID State;
    UNICODE_STRING CsrCommand;
    HANDLE CsrProcessId = NULL, TestProcess = NULL, TestProcessId = NULL;

    if (!SMP_NITRO_SESSIONS_CSR_START(SmpNitroSessions)) return STATUS_SUCCESS;

    Status = SmpBuildHeadlessCsrCommand(&CsrCommand);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("SMSS: NitroSessions: no Windows subsystem command line, Status=%lx\n", Status);
        return Status;
    }
    DPRINT1("SMSS: NitroSessions: session csrss '%wZ'\n", &CsrCommand);

    RtlEnterCriticalSection(&SmpMuSessionLock);

    /* Single leader: SMSS must not be attached to any session now */
    ASSERT(AttachedSessionId == -1);

    Status = SmpAcquirePrivilege(SE_LOAD_DRIVER_PRIVILEGE, &State);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("SMSS: NitroSessions: no load-driver privilege, Status=%lx\n", Status);
        goto Quit;
    }
    Status = NtSetSystemInformation(SystemSessionCreate,
                                    &MuSessionId,
                                    sizeof(MuSessionId));
    DPRINT1("SMSS: NitroSessions: SystemSessionCreate Status=%lx SessionId=%lu\n",
            Status, MuSessionId);
    if (!NT_SUCCESS(Status))
    {
        SmpReleasePrivilege(State);
        goto Quit;
    }
    AttachedSessionId = MuSessionId;

    /* Flag 5: the session's own win32k (a session image), loaded while SMSS is attached to it */
    if (SmpNitroSessions == SMP_NITRO_SESSIONS_WIN32K)
    {
        UNICODE_STRING Win32k = RTL_CONSTANT_STRING(L"\\SystemRoot\\System32\\win32k.sys");

        Status = NtSetSystemInformation(SystemExtendServiceTableInformation, &Win32k, sizeof(Win32k));
        DPRINT1("SMSS: NitroSessions: win32k of session %lu, Status=%lx\n", MuSessionId, Status);
    }
    SmpReleasePrivilege(State);
    if (!NT_SUCCESS(Status)) goto Quit;

    /* The session's csrss. SmpLoadSubSystem waits up to 60 s for it to
       connect, and on any failure detaches and terminates it */
    Status = SmpExecuteCommand(&CsrCommand, MuSessionId, &CsrProcessId, SMP_SUBSYSTEM_FLAG);
    DPRINT1("SMSS: NitroSessions: csrss of session %lu, pid %p, Status=%lx\n",
            MuSessionId, CsrProcessId, Status);

    /* The test command in the session, registered with its csrss */
    if (NT_SUCCESS(Status) && SmpNitroSessionsTestCommand.Length)
    {
        Status2 = SmpExecuteInitialCommand(MuSessionId,
                                           &SmpNitroSessionsTestCommand,
                                           &TestProcess,
                                           &TestProcessId);
        DPRINT1("SMSS: NitroSessions: test command '%wZ' in session %lu, pid %p, Status=%lx\n",
                &SmpNitroSessionsTestCommand, MuSessionId, TestProcessId, Status2);
        if (NT_SUCCESS(Status2) && TestProcess)
        {
            if (SmpNitroSessionsTestKill) SmpNitroKillAndWait("the test command", TestProcess);
            NtClose(TestProcess);
        }
    }

    /* Test only: nothing may be left in the session when SMSS detaches */
    if (NT_SUCCESS(Status) && SmpNitroSessionsTestKill && CsrProcessId)
    {
        OBJECT_ATTRIBUTES Attributes;
        CLIENT_ID ClientId;
        HANDLE CsrProcess;
        LARGE_INTEGER Delay;

        InitializeObjectAttributes(&Attributes, NULL, 0, NULL, NULL);
        ClientId.UniqueProcess = CsrProcessId;
        ClientId.UniqueThread = NULL;
        Status2 = NtOpenProcess(&CsrProcess,
                                PROCESS_TERMINATE | SYNCHRONIZE,
                                &Attributes,
                                &ClientId);
        if (NT_SUCCESS(Status2))
        {
            SmpNitroKillAndWait("csrss", CsrProcess);
            NtClose(CsrProcess);
        }
        else
        {
            DPRINT1("SMSS: NitroSessions: test kill: cannot open csrss, Status=%lx\n", Status2);
        }

        /* Let the exited processes finish dropping the session */
        Delay.QuadPart = -10000000LL;
        NtDelayExecution(FALSE, &Delay);
    }

    /* Detach again; SMSS stays the leader of no session */
    Status2 = SmpNitroDetach();
    ASSERT(NT_SUCCESS(Status2));

    /* Created after the detach: a process in no session. Not while SMSS is
       still attached: the process would join the session instead */
    if (!NT_SUCCESS(Status2))
    {
        DPRINT1("SMSS: NitroSessions: still attached to session %lu, no test command in no session\n",
                AttachedSessionId);
    }
    else if ((SmpNitroSessionsTestForward & SMP_NITRO_TEST_FORWARD_SELF) && !SmpNitroSessionsTestKill && TestProcessId && CsrProcessId)
    {
        /* SMSS is in no session again, so it is a process of another session */
        SmpNitroForwardSelfTest(MuSessionId, CsrProcessId, TestProcessId);
    }
    if (NT_SUCCESS(Status2) && SmpNitroSessionsTestCommand0.Length)
    {
        Status2 = SmpExecuteCommand(&SmpNitroSessionsTestCommand0, 0, NULL, SMP_ASYNC_FLAG);
        DPRINT1("SMSS: NitroSessions: test command '%wZ' in no session, Status=%lx\n",
                &SmpNitroSessionsTestCommand0, Status2);
    }

Quit:
    RtlLeaveCriticalSection(&SmpMuSessionLock);
    RtlFreeHeap(SmpHeap, 0, CsrCommand.Buffer);
    return Status;
}

/* EOF */
