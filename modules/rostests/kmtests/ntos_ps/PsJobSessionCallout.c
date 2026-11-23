/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Kernel mode test: the win32k job callouts of a job with UI restrictions run in the job's
 *              session, whatever thread makes them
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 *
 * win32k is a session image: its code and data are reachable only from a process of its session. A job
 * keeps the session of its creator; win32k keeps the job's UI state in that session. The last reference
 * to a job can be dropped anywhere: by a system worker thread (no session), by a process of another
 * session. Deleting the job then must still reach the win32k of the job's session (before the fix: a
 * page fault on session space in IntDestroyJobInfo from a thread in no session, a kernel stop).
 * Run from a process of a session that has win32k (the user's session).
 */

#include <kmt_test.h>
#include <ndk/pstypes.h>
#include <ndk/psfuncs.h>

/* Exported, not in the headers: -1 for a process in no session */
NTKERNELAPI
ULONG
NTAPI
PsGetProcessSessionIdEx(
    _In_ PEPROCESS Process);

/* Exported, not in the headers */
NTKERNELAPI
PCHAR
NTAPI
PsGetProcessImageFileName(
    _In_ PEPROCESS Process);

typedef struct _JS_DROP
{
    WORK_QUEUE_ITEM WorkItem;
    PVOID Job;
    KEVENT Done;
    ULONG SessionOfWorker;
} JS_DROP, *PJS_DROP;

/* A job made by the current process, with every UI limit; referenced, no handle left */
static
PVOID
MakeUiJob(VOID)
{
    OBJECT_ATTRIBUTES Attributes;
    JOBOBJECT_BASIC_UI_RESTRICTIONS Ui;
    HANDLE Handle;
    PVOID Job = NULL;
    NTSTATUS Status;

    InitializeObjectAttributes(&Attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = ZwCreateJobObject(&Handle, JOB_OBJECT_ALL_ACCESS, &Attributes);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return NULL;

    Ui.UIRestrictionsClass = JOB_OBJECT_UILIMIT_ALL;
    Status = ZwSetInformationJobObject(Handle, JobObjectBasicUIRestrictions, &Ui, sizeof(Ui));
    ok_eq_hex(Status, STATUS_SUCCESS);

    Status = ObReferenceObjectByHandle(Handle, 0, NULL, KernelMode, &Job, NULL);
    ok_eq_hex(Status, STATUS_SUCCESS);
    ZwClose(Handle);
    return NT_SUCCESS(Status) ? Job : NULL;
}

static
VOID
NTAPI
DropInWorker(
    _In_ PVOID Context)
{
    PJS_DROP Drop = Context;

    Drop->SessionOfWorker = PsGetProcessSessionIdEx(PsGetCurrentProcess());
    /* The last reference: the job is deleted here, in the System process */
    ObDereferenceObject(Drop->Job);
    KeSetEvent(&Drop->Done, IO_NO_INCREMENT, FALSE);
}

/* A referenced process of another session than Session, by image name; NULL when there is none */
static
PEPROCESS
FindProcessOfOtherSession(
    _In_ ULONG Session,
    _In_ PCSTR ImageName)
{
    ULONG_PTR Pid;
    PEPROCESS Process;
    ULONG Other;

    for (Pid = 4; Pid < 0x10000; Pid += 4)
    {
        if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)Pid, &Process)))
            continue;
        Other = PsGetProcessSessionIdEx(Process);
        if ((Other != MAXULONG) && (Other != Session) &&
            !_stricmp(PsGetProcessImageFileName(Process), ImageName))
        {
            return Process;
        }
        ObDereferenceObject(Process);
    }
    return NULL;
}

START_TEST(PsJobSessionCallout)
{
    PEPROCESS Other;
    ULONG Session = PsGetProcessSessionIdEx(PsGetCurrentProcess());
    KAPC_STATE ApcState;
    JS_DROP Drop;
    PVOID Job;
    NTSTATUS Status;

    ok(Session != MAXULONG, "The test process is in no session\n");
    if (Session == MAXULONG)
        return;
    trace("test process in session %lu\n", Session);

    /* 1. The last reference dropped by a system worker thread (no session) */
    Job = MakeUiJob();
    if (Job)
    {
        RtlZeroMemory(&Drop, sizeof(Drop));
        Drop.Job = Job;
        Drop.SessionOfWorker = 0x1234;
        KeInitializeEvent(&Drop.Done, NotificationEvent, FALSE);
        ExInitializeWorkItem(&Drop.WorkItem, DropInWorker, &Drop);
        ExQueueWorkItem(&Drop.WorkItem, DelayedWorkQueue);
        Status = KeWaitForSingleObject(&Drop.Done, Executive, KernelMode, FALSE, NULL);
        ok_eq_hex(Status, STATUS_SUCCESS);
        ok_eq_ulong(Drop.SessionOfWorker, MAXULONG);
    }

    /* 2. The last reference dropped by a thread attached to a process of another session */
    Other = FindProcessOfOtherSession(Session, "services.exe");
    if (!Other)
    {
        skip(FALSE, "No services.exe in another session than %lu\n", Session);
        return;
    }
    Job = MakeUiJob();
    if (Job)
    {
        KeStackAttachProcess((PKPROCESS)Other, &ApcState);
        ok_eq_ulong(PsGetProcessSessionIdEx(PsGetCurrentProcess()), PsGetProcessSessionIdEx(Other));
        ObDereferenceObject(Job);
        KeUnstackDetachProcess(&ApcState);
    }

    /* 3. UI limits changed and the job deleted by a thread attached to another session */
    Job = MakeUiJob();
    if (Job)
    {
        HANDLE Handle;
        JOBOBJECT_BASIC_UI_RESTRICTIONS Ui;

        KeStackAttachProcess((PKPROCESS)Other, &ApcState);
        Status = ObOpenObjectByPointer(Job, OBJ_KERNEL_HANDLE, NULL, JOB_OBJECT_ALL_ACCESS, NULL, KernelMode, &Handle);
        ok_eq_hex(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status))
        {
            Ui.UIRestrictionsClass = JOB_OBJECT_UILIMIT_DESKTOP | JOB_OBJECT_UILIMIT_GLOBALATOMS;
            Status = ZwSetInformationJobObject(Handle, JobObjectBasicUIRestrictions, &Ui, sizeof(Ui));
            ok_eq_hex(Status, STATUS_SUCCESS);
            Ui.UIRestrictionsClass = 0;
            Status = ZwQueryInformationJobObject(Handle, JobObjectBasicUIRestrictions, &Ui, sizeof(Ui), NULL);
            ok_eq_hex(Status, STATUS_SUCCESS);
            ok_eq_hex(Ui.UIRestrictionsClass, JOB_OBJECT_UILIMIT_DESKTOP | JOB_OBJECT_UILIMIT_GLOBALATOMS);
            ZwClose(Handle);
        }
        ObDereferenceObject(Job);
        KeUnstackDetachProcess(&ApcState);
    }

    ObDereferenceObject(Other);
}
