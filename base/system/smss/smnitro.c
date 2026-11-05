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
 *    command (NitroSessionsTestCommand, REG_SZ) in it. P0 has no csrss for
 *    session 1, so the test command must be a native image.
 */
ULONG SmpNitroSessions;
UNICODE_STRING SmpNitroSessionsTestCommand;

/* FUNCTIONS ******************************************************************/

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
    UCHAR Buffer[FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + 512 * sizeof(WCHAR)];
    PWCHAR String;

    SmpNitroSessions = 0;
    RtlInitEmptyUnicodeString(&SmpNitroSessionsTestCommand, NULL, 0);

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

    /* The test command is only read when the flag is set */
    if (SmpNitroSessions != 0)
    {
        DPRINT1("SMSS: NitroSessions = %lu\n", SmpNitroSessions);

        RtlInitUnicodeString(&ValueName, L"NitroSessionsTestCommand");
        Status = NtQueryValueKey(KeyHandle,
                                 &ValueName,
                                 KeyValuePartialInformation,
                                 Info,
                                 sizeof(Buffer) - sizeof(UNICODE_NULL),
                                 &ResultLength);
        if (NT_SUCCESS(Status) &&
            ((Info->Type == REG_SZ) || (Info->Type == REG_EXPAND_SZ)) &&
            (Info->DataLength >= sizeof(WCHAR)) &&
            (Info->DataLength <= sizeof(Buffer) - sizeof(UNICODE_NULL) -
                                 FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data)))
        {
            String = RtlAllocateHeap(SmpHeap, SmBaseTag, Info->DataLength + sizeof(UNICODE_NULL));
            if (String)
            {
                RtlCopyMemory(String, Info->Data, Info->DataLength);
                String[Info->DataLength / sizeof(WCHAR)] = UNICODE_NULL;
                RtlInitUnicodeString(&SmpNitroSessionsTestCommand, String);
                DPRINT1("SMSS: NitroSessionsTestCommand = '%wZ'\n", &SmpNitroSessionsTestCommand);
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

    if (SmpNitroSessions != 1) return STATUS_SUCCESS;

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

/* EOF */
