/*
 * PROJECT:     NitroOS Session Manager
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The console session (session 1): the interactive logon
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

/* INCLUDES *******************************************************************/

#include "smss.h"

#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

/*
 * As on Windows, session 0 holds the services and the system processes, and the interactive logon is in
 * session 1, the console session (the kernel publishes it as KUSER_SHARED_DATA.ActiveConsoleId before
 * any win32k loads, so session 0's win32k draws into memory). Once session 0's csrss and Winlogon run,
 * the Session Manager creates session 1 with its own win32k (a session image), its own csrss with every
 * server of the Windows subsystem, and its own Winlogon, which logs the user on.
 */
static WCHAR SmpConsoleLogonCommand[] = L"winlogon.exe";

/*
 * Serialises the creation of sessions after session 0 (design 3.1): SMSS is
 * the only session leader and is attached to the session it creates until
 * it detaches, so only one create may run at a time. Taken around the
 * console session's create and SmpStartCsr.
 */
RTL_CRITICAL_SECTION SmpMuSessionLock;

/* FUNCTIONS ******************************************************************/

/* The command line of the Windows subsystem (the "Required" Windows entry of the registry) */
static
PUNICODE_STRING
SmpWindowsSubsystemCommand(VOID)
{
    PLIST_ENTRY NextEntry;
    PSMP_REGISTRY_VALUE RegEntry;

    for (NextEntry = SmpSubSystemsToLoad.Flink;
         NextEntry != &SmpSubSystemsToLoad;
         NextEntry = NextEntry->Flink)
    {
        RegEntry = CONTAINING_RECORD(NextEntry, SMP_REGISTRY_VALUE, Entry);
        if (RegEntry->Name.Buffer && !_wcsicmp(RegEntry->Name.Buffer, L"Windows"))
            return RegEntry->Value.Length ? &RegEntry->Value : NULL;
    }
    return NULL;
}

/*
 * Detach SMSS from the session it is attached to, if any. Returns the failure
 * status when SMSS is still attached afterwards: the caller must not start
 * anything meant to be in no session then.
 */
NTSTATUS
NTAPI
SmpDetachSession(VOID)
{
    NTSTATUS Status;
    PVOID State;

    if (AttachedSessionId == -1) return STATUS_SUCCESS;

    Status = SmpAcquirePrivilege(SE_LOAD_DRIVER_PRIVILEGE, &State);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("SMSS: no privilege to detach from session %lu, Status=%lx\n",
                AttachedSessionId, Status);
        return Status;
    }

    Status = NtSetSystemInformation(SystemSessionDetach,
                                    &AttachedSessionId,
                                    sizeof(AttachedSessionId));
    DPRINT1("SMSS: SystemSessionDetach(%lu) Status=%lx\n", AttachedSessionId, Status);
    if (NT_SUCCESS(Status)) AttachedSessionId = -1;

    SmpReleasePrivilege(State);
    return Status;
}

/*
 * One attempt to start the console session: create it, load its win32k, start its csrss and its
 * Winlogon. Runs under SmpMuSessionLock, with SMSS in no session. On return SMSS is in no session again.
 */
static
NTSTATUS
SmpStartConsoleSessionOnce(
    _In_ PUNICODE_STRING CsrCommand)
{
    NTSTATUS Status, Status2;
    ULONG MuSessionId = 0;
    PVOID State;
    UNICODE_STRING Win32k = RTL_CONSTANT_STRING(L"\\SystemRoot\\System32\\win32k.sys");
    UNICODE_STRING LogonCommand;
    HANDLE CsrProcessId = NULL, Winlogon = NULL, WinlogonId = NULL;

    /* Single leader: SMSS must not be attached to any session now */
    ASSERT(AttachedSessionId == -1);

    Status = SmpAcquirePrivilege(SE_LOAD_DRIVER_PRIVILEGE, &State);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("SMSS: console session: no load-driver privilege, Status=%lx\n", Status);
        return Status;
    }

    Status = NtSetSystemInformation(SystemSessionCreate, &MuSessionId, sizeof(MuSessionId));
    DPRINT1("SMSS: console session: SystemSessionCreate Status=%lx SessionId=%lu\n", Status, MuSessionId);
    if (!NT_SUCCESS(Status))
    {
        SmpReleasePrivilege(State);
        return Status;
    }
    AttachedSessionId = MuSessionId;

    /*
     * The kernel published session 1 as the console: a session with another id (the previous attempt's
     * session not gone yet) would get no display and no console logon.
     */
    if (MuSessionId != SMP_CONSOLE_SESSION_ID)
    {
        DPRINT1("SMSS: console session: got session %lu, not %lu\n", MuSessionId, SMP_CONSOLE_SESSION_ID);
        SmpReleasePrivilege(State);
        Status = STATUS_INVALID_SERVER_STATE;
        goto Quit;
    }

    /* The session's own win32k (a session image), loaded while SMSS is attached to it */
    Status = NtSetSystemInformation(SystemExtendServiceTableInformation, &Win32k, sizeof(Win32k));
    DPRINT1("SMSS: console session: win32k of session %lu, Status=%lx\n", MuSessionId, Status);
    SmpReleasePrivilege(State);
    if (!NT_SUCCESS(Status)) goto Quit;

    /* The session's csrss. SmpLoadSubSystem waits up to 60 s for it to
       connect, and on any failure detaches and terminates it */
    Status = SmpExecuteCommand(CsrCommand, MuSessionId, &CsrProcessId, SMP_SUBSYSTEM_FLAG);
    DPRINT1("SMSS: console session: csrss of session %lu, pid %p, Status=%lx\n",
            MuSessionId, CsrProcessId, Status);
    if (!NT_SUCCESS(Status)) goto Quit;

    /* The session's Winlogon, registered with its csrss */
    RtlInitUnicodeString(&LogonCommand, SmpConsoleLogonCommand);
    Status = SmpExecuteInitialCommand(MuSessionId, &LogonCommand, &Winlogon, &WinlogonId);
    DPRINT1("SMSS: console session: Winlogon in session %lu, pid %p, Status=%lx\n",
            MuSessionId, WinlogonId, Status);
    if (NT_SUCCESS(Status) && Winlogon) NtClose(Winlogon);

Quit:
    /* Detach again; SMSS stays the leader of no session */
    Status2 = SmpDetachSession();
    if (!NT_SUCCESS(Status2) && NT_SUCCESS(Status)) Status = Status2;
    return Status;
}

/*
 * Start the console session. Runs once, from the main thread, after session 0's csrss and Winlogon are
 * started and SMSS has detached from session 0. A failed attempt is tried once more (a csrss that did
 * not connect in time under load, a transient lack of memory); when the second fails too, the caller
 * stops the machine: without the console session there is no display and no logon, and a machine that
 * runs on dark, with its boot accepted, would leave no way back to a working configuration.
 */
NTSTATUS
NTAPI
SmpStartConsoleSession(VOID)
{
    NTSTATUS Status;
    PUNICODE_STRING CsrCommand;
    LARGE_INTEGER Delay;
    ULONG Attempt;

    CsrCommand = SmpWindowsSubsystemCommand();
    if (!CsrCommand)
    {
        DPRINT1("SMSS: console session: no Windows subsystem command line\n");
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    for (Attempt = 1; ; Attempt++)
    {
        RtlEnterCriticalSection(&SmpMuSessionLock);
        Status = SmpStartConsoleSessionOnce(CsrCommand);
        RtlLeaveCriticalSection(&SmpMuSessionLock);
        if (NT_SUCCESS(Status) || (Attempt == 2)) break;

        DPRINT1("SMSS: console session: attempt %lu failed, Status=%lx, trying again\n", Attempt, Status);

        /* Let the processes of the failed attempt finish leaving its session, so that it goes */
        Delay.QuadPart = -10000000LL * 2;
        NtDelayExecution(FALSE, &Delay);
    }

    if (!NT_SUCCESS(Status))
        DPRINT1("SMSS: console session: cannot be started, Status=%lx\n", Status);
    return Status;
}

/* EOF */
