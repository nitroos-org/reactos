/*
 * PROJECT:     ReactOS Kernel
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Core functions for managing Job Objects, a kernel mechanism
 *              for managing multiple processes as a single unit.
 * COPYRIGHT:   Copyright 2004-2012 Alex Ionescu (alex@relsoft.net) (stubs)
 *              Copyright 2004-2005 Thomas Weidenmueller <w3seek@reactos.com>
 *              Copyright 2015-2016 Samuel Serapión Vega <encoded@reactos.org>
 *              Copyright 2017 Mark Jansen <mark.jansen@reactos.org>
 *              Copyright 2018 Pierre Schweitzer <pierre@reactos.org>
 *              Copyright 2022 Timo Kreuzer <timo.kreuzer@reactos.org>
 *              Copyright 2024-2026 Gleb Surikov <glebs.surikovs@gmail.com>
 */

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

POBJECT_TYPE PsJobType = NULL;

LIST_ENTRY PsJobListHead;
static FAST_MUTEX PsJobListLock;

BOOLEAN PspUseJobSchedulingClasses;

CHAR PspJobSchedulingClasses[PSP_JOB_SCHEDULING_CLASSES] =
{
    1 * 6,
    2 * 6,
    3 * 6,
    4 * 6,
    5 * 6,
    6 * 6,
    7 * 6,
    8 * 6,
    9 * 6,
    10 * 6
};

GENERIC_MAPPING PspJobMapping =
{
    STANDARD_RIGHTS_READ | JOB_OBJECT_QUERY,

    STANDARD_RIGHTS_WRITE | JOB_OBJECT_ASSIGN_PROCESS |
    JOB_OBJECT_SET_ATTRIBUTES | JOB_OBJECT_TERMINATE,

    STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE,

    JOB_OBJECT_ALL_ACCESS
};

ULONG PspJobInfoLengths[] =
{
    0x0,
    sizeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION),
    sizeof(JOBOBJECT_BASIC_LIMIT_INFORMATION),
    sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST),
    sizeof(JOBOBJECT_BASIC_UI_RESTRICTIONS),
    sizeof(JOBOBJECT_SECURITY_LIMIT_INFORMATION),
    sizeof(JOBOBJECT_END_OF_JOB_TIME_INFORMATION),
    sizeof(JOBOBJECT_ASSOCIATE_COMPLETION_PORT),
    sizeof(JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION),
    sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION),
    0x4
};

ULONG PspJobInfoAlign[] =
{
    0x0,
    sizeof(ULONG),
    sizeof(ULONG),
    sizeof(ULONG),
    sizeof(ULONG),
    sizeof(ULONG),
    sizeof(ULONG),
    sizeof(HANDLE),
    sizeof(ULONG),
    sizeof(ULONG),
    sizeof(ULONG)
};

/* Job information classes past JobObjectJobSetInformation that user mode asks for: the JVM queries its job's
   processor groups and CPU rate at startup and warns "Attempt to query job object information failed" when the
   query is rejected. Jobs here have no processor group assignment and no CPU rate control. */
#define PspJobObjectGroupInformation            11
#define PspJobObjectGroupInformationEx          14
#define PspJobObjectCpuRateControlInformation   15

typedef struct _PS_JOB_CPU_RATE_CONTROL_INFORMATION
{
    ULONG ControlFlags;
    ULONG Value; /* CpuRate, Weight, or MinRate/MaxRate according to the flags */
} PS_JOB_CPU_RATE_CONTROL_INFORMATION;

/* DATA TYPE DEFINITIONS *****************************************************/

/*!
 * Context structure used to pass the exit status to the process termination
 * callback.
 *
 * @param[in] ExitStatus
 *     The exit status to be used for all terminated processes.
 *
 * @param[out] SelfDeferred
 *     Set if the current process is in the job and must be terminated last.
 */
typedef struct PSP_TERMINATE_PROCESS_CONTEXT
{
    NTSTATUS ExitStatus;
    BOOLEAN SelfDeferred;
} PSP_TERMINATE_PROCESS_CONTEXT, *PPSP_TERMINATE_PROCESS_CONTEXT;

/*!
 * Context structure used to collect process IDs for a job object.
 *
 * @param[in, out] ProcessIdList
 *     A pointer to the output process identifier list.
 *
 * @param[in, out] NextProcessId
 *     A pointer to the next output array entry.
 *
 * @param[in, out] RemainingLength
 *     The number of bytes remaining in the output array.
 */
typedef struct PSP_QUERY_JOB_PROCESS_ID_CONTEXT
{
    PJOBOBJECT_BASIC_PROCESS_ID_LIST ProcessIdList;
    PULONG_PTR NextProcessId;
    SIZE_T RemainingLength;
} PSP_QUERY_JOB_PROCESS_ID_CONTEXT, *PPSP_QUERY_JOB_PROCESS_ID_CONTEXT;

/* FUNCTIONS *****************************************************************/

CODE_SEG("INIT")
VOID
NTAPI
PspInitializeJobStructures(VOID)
{
    InitializeListHead(&PsJobListHead);
    ExInitializeFastMutex(&PsJobListLock);
}

/*!
 * Returns the next process directly assigned to a job while the job lock is
 * held.
 *
 * @param[in] Job
 *     A pointer to the job object being enumerated.
 *
 * @param[in, optional] PreviousProcess
 *     A pointer to the process after which enumeration should
 *     continue, or NULL to return the first process.
 *
 * @return
 *     A pointer to the next assigned process, or NULL if enumeration has completed.
 *
 * @remarks
 *     The caller must hold the job lock shared or exclusive.
 *
 *     Neither PreviousProcess nor the returned process is referenced by this
 *     function. The caller must ensure that PreviousProcess remains linked to
 *     the job and that direct job membership isn't modified during the
 *     enumeration.
 */
static
PEPROCESS
PspGetNextProcessInJobLocked(
    _In_ PEJOB Job,
    _In_opt_ PEPROCESS PreviousProcess
)
{
    PLIST_ENTRY Entry;
    PEPROCESS Process;

    ASSERT(ExIsResourceAcquiredSharedLite(&Job->JobLock) != 0 ||
           ExIsResourceAcquiredExclusiveLite(&Job->JobLock) != 0);

    /* Check if we're already starting somewhere. A process can be nested into
       a child job while the lock is dropped between two steps; its links then
       belong to that job's list. Start over: processes already handled are
       inactive (or terminated) by now and are skipped by the callers. */
    if (PreviousProcess != NULL && PreviousProcess->Job == Job)
    {
        ASSERT(!IsListEmpty(&PreviousProcess->JobLinks));

        /* Start where we left off */
        Entry = PreviousProcess->JobLinks.Flink;
    }
    else
    {
        /* Start at the beginning */
        Entry = Job->ProcessListHead.Flink;
    }

    /* Check if enumeration has completed */
    if (Entry == &Job->ProcessListHead)
    {
        return NULL;
    }

    ASSERT(Entry->Flink != NULL);
    ASSERT(Entry->Blink != NULL);
    ASSERT(Entry->Flink->Blink == Entry);
    ASSERT(Entry->Blink->Flink == Entry);

    Process = CONTAINING_RECORD(Entry, EPROCESS, JobLinks);
    ASSERT(Process->Job == Job);
    return Process;
}

/*!
 * Returns the next referenced process directly assigned to a job.
 *
 * @param[in] Job
 *     A pointer to the job object being enumerated.
 *
 * @param[in, optional] PreviousProcess
 *     A referenced process returned by the previous call, or NULL to start
 *     enumeration. When non-NULL, its reference is consumed by this function,
 *     regardless of whether another process is returned.
 *
 * @return
 *     A referenced pointer to the next process, or NULL if enumeration has
 *     completed.
 *
 * @remarks
 *     The returned reference must either be passed to the next call or
 *     released with ObDereferenceObject().
 *
 *     The job lock is not held when this function returns.
 *
 *     This relies on job membership remaining fixed until process object deletion.
 *     The reference to PreviousProcess therefore keeps its JobLinks valid until
 *     the next process has been selected.
 */
static
PEPROCESS
PspGetNextProcessInJob(
    _In_ PEJOB Job,
    _In_opt_ PEPROCESS PreviousProcess
)
{
    PEPROCESS Candidate;
    PEPROCESS NextProcess = NULL;

    ExEnterCriticalRegionAndAcquireResourceShared(&Job->JobLock);

    Candidate = PreviousProcess;

    while ((Candidate = PspGetNextProcessInJobLocked(Job, Candidate)) != NULL)
    {
        /*
         * Skip processes whose deletion has begun. JobLinks remains valid
         * while the job lock is held, allowing enumeration to continue.
         */
        if (ObReferenceObjectSafe(Candidate))
        {
            NextProcess = Candidate;
            break;
        }
    }

    ExReleaseResourceAndLeaveCriticalRegion(&Job->JobLock);

    /*
     * This must occur after releasing the job lock. The dereference can invoke
     * the process delete procedure, which removes JobLinks under the same lock.
     */
    if (PreviousProcess != NULL)
    {
        ObDereferenceObject(PreviousProcess);
    }

    return NextProcess;
}

/*!
 * Enumerates all processes currently associated with the specified job object
 * and invokes a callback for each process.
 *
 * @param[in] Job
 *     A pointer to the job object whose processes are to be enumerated.
 *
 * @param[in] Callback
 *     A pointer to the callback invoked for each referenced process.
 *
 * @param[in, optional] Context
 *     An optional context pointer passed to the callback.
 *
 * @return
 *     STATUS_SUCCESS if every callback succeeds. Otherwise, the first
 *     unsuccessful callback status is returned.
 *
 * @remarks
 *     Enumeration stops when a callback returns an unsuccessful status.
 *
 *     The callback is invoked _without_ the job lock held.
 */
NTSTATUS
NTAPI
PspEnumerateProcessesInJob(
    _In_ PEJOB Job,
    _In_ PJOB_ENUMERATOR_CALLBACK Callback,
    _In_opt_ PVOID Context
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PEPROCESS Process;

    /* Iterate through all processes in the job */
    for (Process = PspGetNextProcessInJob(Job, NULL);
         Process != NULL;
         Process = PspGetNextProcessInJob(Job, Process))
    {
        Status = Callback(Process, Context);
        if (!NT_SUCCESS(Status))
        {
            /*
             * On successful iteration, PspGetNextProcessInJob consumes
             * this reference. On failure, it must be released explicitly.
             */
            ObDereferenceObject(Process);
            break;
        }
    }

    return Status;
}

/*!
 * Enumerates all assigned processes while the caller holds the job
 * lock and invokes a callback for each process.
 *
 * @param[in] Job
 *     A pointer to the job object whose processes are to be enumerated.
 *
 * @param[in] Callback
 *     A pointer to the callback invoked for each process.
 *
 * @param[in, optional] Context
 *     An optional context pointer passed to the callback.
 *
 * @return
 *     STATUS_SUCCESS if every callback succeeds. Otherwise, the first
 *     unsuccessful callback status is returned.
 *
 * @remarks
 *     Enumeration stops when a callback returns an unsuccessful status.
 *
 *     The caller must hold the job lock shared or exclusive.
 *
 *     The callback must not release or recursively acquire the job lock,
 *     modify job membership, dereference the process object, or retain
 *     the process pointer after returning.
 */
static
NTSTATUS
PspEnumerateProcessesInJobLocked(
    _In_ PEJOB Job,
    _In_ PJOB_ENUMERATOR_CALLBACK Callback,
    _In_opt_ PVOID Context
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PEPROCESS Process;

    ASSERT(ExIsResourceAcquiredSharedLite(&Job->JobLock) != 0 ||
           ExIsResourceAcquiredExclusiveLite(&Job->JobLock) != 0);

    /* Iterate through all processes in the job */
    for (Process = PspGetNextProcessInJobLocked(Job, NULL);
         Process != NULL;
         Process = PspGetNextProcessInJobLocked(Job, Process))
    {
        Status = Callback(Process, Context);
        if (!NT_SUCCESS(Status))
            break;
    }

    return Status;
}

/*!
 * Enumerates the processes of a job and of all of its descendants while the
 * caller holds the job lock, and invokes a callback for each process.
 *
 * @param[in] Job
 *     A pointer to the job object whose hierarchy is to be enumerated.
 *
 * @param[in] Callback
 *     A pointer to the callback invoked for each process.
 *
 * @param[in, optional] Context
 *     An optional context pointer passed to the callback.
 *
 * @return
 *     STATUS_SUCCESS if every callback succeeds. Otherwise, the first
 *     unsuccessful callback status is returned.
 *
 * @remarks
 *     The caller must hold the job lock shared or exclusive. The locks of the
 *     descendants are taken shared, parent first, while the parent's lock is
 *     still held: nesting a process or a job needs the parent's lock
 *     exclusively, so the hierarchy does not change underneath the walk.
 *
 *     Subject to the same restrictions on the callback as
 *     PspEnumerateProcessesInJobLocked().
 */
static
NTSTATUS
PspEnumerateProcessesInJobHierarchyLocked(
    _In_ PEJOB Job,
    _In_ PJOB_ENUMERATOR_CALLBACK Callback,
    _In_opt_ PVOID Context
)
{
    NTSTATUS Status;
    PLIST_ENTRY Entry;

    Status = PspEnumerateProcessesInJobLocked(Job, Callback, Context);

    for (Entry = Job->ChildJobsHead.Flink;
         NT_SUCCESS(Status) && Entry != &Job->ChildJobsHead;
         Entry = Entry->Flink)
    {
        PEJOB Child = CONTAINING_RECORD(Entry, EJOB, ChildJobsLinks);

        ExEnterCriticalRegionAndAcquireResourceShared(&Child->JobLock);
        Status = PspEnumerateProcessesInJobHierarchyLocked(Child, Callback, Context);
        ExReleaseResourceAndLeaveCriticalRegion(&Child->JobLock);
    }

    return Status;
}

/*!
 * Queues a message to a job's completion port.
 *
 * @param[in] Job
 *     A pointer to the job receiving the notification.
 *
 * @param[in] Message
 *     The job notification message (JOB_OBJECT_MSG_*).
 *
 * @param[in, optional] CompletionValue
 *     The message specific completion value.
 *
 * @param[in] Quota
 *     Specifies whether the completion packet is charged as quota.
 *
 * @return
 *     STATUS_SUCCESS if the message was queued successfully.
 *     Otherwise, an appropriate NTSTATUS error code.
 *
 * @remarks
 *     The caller must hold the job lock shared or exclusive.
 *     The caller must ensure that the job has an associated completion port.
 */
NTSTATUS
NTAPI
PspSendJobMessageLocked(
    _In_ PEJOB Job,
    _In_ ULONG Message,
    _In_opt_ PVOID CompletionValue,
    _In_ BOOLEAN Quota
)
{
    ASSERT(Job->CompletionPort != NULL);

    ASSERT(ExIsResourceAcquiredSharedLite(&Job->JobLock) != 0 ||
           ExIsResourceAcquiredExclusiveLite(&Job->JobLock) != 0);

    return IoSetIoCompletion(Job->CompletionPort,
                             Job->CompletionKey,
                             CompletionValue,
                             STATUS_SUCCESS,
                             Message,
                             Quota);
}

/*!
 * Collects the job hierarchy a job belongs to.
 *
 * @param[in] Job
 *     A pointer to the (leaf) job.
 *
 * @param[out] Chain
 *     Receives the job and all of its ancestors, root job first.
 *
 * @return
 *     The number of entries written, or 0 if the hierarchy is deeper than
 *     PSP_JOB_MAX_NESTING.
 *
 * @remarks
 *     ParentJob is written once, while the child is still empty, and the parent
 *     keeps the child alive, so no lock is needed to walk it. A job that is
 *     being given a parent concurrently is revalidated by the callers once
 *     they hold the job locks.
 */
static
ULONG
PspGetJobChain(
    _In_ PEJOB Job,
    _Out_writes_(PSP_JOB_MAX_NESTING) PEJOB *Chain
)
{
    PEJOB Walk, Parent;
    ULONG Count = 0, i;

    for (Walk = Job; Walk != NULL; Walk = Parent)
    {
        if (Count == PSP_JOB_MAX_NESTING)
        {
            return 0;
        }

        Chain[Count++] = Walk;
        Parent = Walk->ParentJob;
    }

    /* Collected leaf first, callers want the root first */
    for (i = 0; i < Count / 2; i++)
    {
        Walk = Chain[i];
        Chain[i] = Chain[Count - 1 - i];
        Chain[Count - 1 - i] = Walk;
    }

    return Count;
}

/*!
 * Checks whether a job is the given job or one of its ancestors.
 *
 * @param[in] Job
 *     The job a process is directly assigned to.
 *
 * @param[in] Candidate
 *     The job to look for.
 *
 * @return
 *     TRUE if Candidate is Job or an ancestor of Job.
 */
static
BOOLEAN
PspIsJobInHierarchy(
    _In_ PEJOB Job,
    _In_ PEJOB Candidate
)
{
    for (; Job != NULL; Job = Job->ParentJob)
    {
        if (Job == Candidate)
        {
            return TRUE;
        }
    }

    return FALSE;
}

/*!
 * Decides which job a new process created by a process of the given job
 * joins.
 *
 * @param[in] ParentJob
 *     The job the creating process is directly assigned to.
 *
 * @param[in] Breakaway
 *     TRUE if the creator asked for CREATE_BREAKAWAY_FROM_JOB.
 *
 * @param[out] TargetJob
 *     Receives the job the new process is assigned to (it joins that job and
 *     all of its ancestors), or NULL if it leaves the whole hierarchy.
 *
 * @return
 *     STATUS_SUCCESS, or STATUS_ACCESS_DENIED if breakaway was requested but
 *     the job does not allow it.
 *
 * @remarks
 *     Verified against Windows 10: starting at the job the creator is in, the
 *     child leaves every job that has SILENT_BREAKAWAY_OK (or, when breakaway
 *     is requested, BREAKAWAY_OK) and stops at the first one that does not,
 *     remaining a member of that job and of its ancestors. A requested
 *     breakaway fails if the innermost job does not allow it.
 */
NTSTATUS
NTAPI
PspSelectJobForNewProcess(
    _In_ PEJOB ParentJob,
    _In_ BOOLEAN Breakaway,
    _Out_ PEJOB *TargetJob
)
{
    PEJOB Job;
    ULONG AllowedFlags;

    AllowedFlags = JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;
    if (Breakaway)
    {
        AllowedFlags |= JOB_OBJECT_LIMIT_BREAKAWAY_OK;
        if (!FlagOn(ParentJob->LimitFlags, AllowedFlags))
        {
            *TargetJob = NULL;
            return STATUS_ACCESS_DENIED;
        }
    }

    for (Job = ParentJob; Job != NULL; Job = Job->ParentJob)
    {
        if (!FlagOn(Job->LimitFlags, AllowedFlags))
        {
            break;
        }
    }

    *TargetJob = Job;
    return STATUS_SUCCESS;
}

/*!
 * Assigns a process that is not in any job to a job and to all of that job's
 * ancestors.
 *
 * @param[in] Process
 *     Pointer to the process to be assigned.
 *
 * @param[in] Job
 *     Pointer to the job the process becomes a direct member of.
 *
 * @returns
 *     STATUS_SUCCESS, an error status, or STATUS_RETRY if the process joined a
 *     job concurrently or the hierarchy changed under us.
 */
static
NTSTATUS
PspAssignNewProcessToJob(
    _In_ PEPROCESS Process,
    _In_ PEJOB Job
)
{
    PEJOB Chain[PSP_JOB_MAX_NESTING];
    PEJOB UIJob = NULL;
    ULONG Count, i;
    NTSTATUS Status = STATUS_SUCCESS;
    NTSTATUS CalloutStatus = STATUS_SUCCESS;
    PVOID PreviousJob;

    if (!ExAcquireRundownProtection(&Process->RundownProtect))
    {
        return STATUS_PROCESS_IS_TERMINATING;
    }

    Count = PspGetJobChain(Job, Chain);
    if (Count == 0)
    {
        ExReleaseRundownProtection(&Process->RundownProtect);
        return STATUS_ACCESS_DENIED;
    }

    /* Ancestors before descendants, the same order nesting uses */
    for (i = 0; i < Count; i++)
    {
        ExEnterCriticalRegionAndAcquireResourceExclusive(&Chain[i]->JobLock);
    }

    /* Only an empty job without a parent can be given one, and that happens
       under its lock: if the root we found has gained a parent, start over */
    if (Chain[0]->ParentJob != NULL)
    {
        Status = STATUS_RETRY;
        goto Exit;
    }

    for (i = 0; i < Count; i++)
    {
        PEJOB Level = Chain[i];

        /* https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-assignprocesstojobobject:
           "If the job or any of its parent jobs in the job chain is terminating
           when AssignProcessToJob is called, the function fails" */
        if (FlagOn(Level->JobFlags, PSP_JOB_TERMINATING))
        {
            Status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }

        /* Prevent processes from being added to the job if it is flagged
           for closing and has a limit on process termination on closing */
        if (FlagOn(Level->LimitFlags, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) &&
            FlagOn(Level->JobFlags, PSP_JOB_CLOSE_DONE))
        {
            Status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }

        /* Check if the job has a limit on the number of active processes */
        if (FlagOn(Level->LimitFlags, JOB_OBJECT_LIMIT_ACTIVE_PROCESS) &&
            Level->ActiveProcesses >= Level->ActiveProcessLimit)
        {
            /* If the job has a completion port, notify the job that the
               limit on the number of active processes has been exceeded */
            if (Level->CompletionPort)
            {
                (VOID)PspSendJobMessageLocked(Level,
                                              JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT,
                                              NULL,
                                              TRUE);
            }

            Status = STATUS_QUOTA_EXCEEDED;
            goto Exit;
        }
    }

    /* Acquire the reference owned by Process->Job before publishing the pointer.
       This ensures that every observable non-NULL Process->Job is already
       backed by its lifetime reference. If another assignment wins the race,
       release the unused reference. */
    ObReferenceObject(Job);

    /* The job locks protect the hierarchy, but another caller may simultaneously
       hold a different job's lock while trying to assign the same process */
    PreviousJob = InterlockedCompareExchangePointer((PVOID)&Process->Job,
                                                    Job,
                                                    NULL);
    if (PreviousJob)
    {
        ObDereferenceObject(Job);
        Status = STATUS_RETRY;
        goto Exit;
    }

    /* Assignment is committed at this point. No subsequent structural
       operation may fail.

       Readers of the process lists are blocked by the job locks until the
       lists and counters are complete. */

    ASSERT(IsListEmpty(&Process->JobLinks));

    InsertTailList(&Job->ProcessListHead, &Process->JobLinks);

    for (i = 0; i < Count; i++)
    {
        PEJOB Level = Chain[i];

        Level->TotalProcesses++;
        Level->ActiveProcesses++;

        if (Level->CompletionPort && Process->UniqueProcessId)
        {
            /* If the job has a completion port and the process has a unique ID,
               notify the job of the new process */
            (VOID)PspSendJobMessageLocked(Level,
                                          JOB_OBJECT_MSG_NEW_PROCESS,
                                          Process->UniqueProcessId,
                                          FALSE);
        }

        /* The innermost job that restricts the UI is the one win32k enforces */
        if (Level->UIRestrictionsClass != 0)
        {
            UIJob = Level;
        }
    }

    /* Hand the process to win32k, which enforces the UI restrictions. One
       that has not connected to win32k yet is picked up when it does. */
    if (UIJob != NULL && Process->Win32Process != NULL)
    {
        CalloutStatus = PspInvokeW32JobCallout(UIJob,
                                               PsW32JobCalloutAddProcess,
                                               Process->Win32Process);
    }

Exit:
    for (i = Count; i > 0; i--)
    {
        ExReleaseResourceAndLeaveCriticalRegion(&Chain[i - 1]->JobLock);
    }
    ExReleaseRundownProtection(&Process->RundownProtect);

    /* The assignment is committed, but win32k will not be enforcing the UI
       restrictions, so the process must not run at all. The caller is told
       the assignment failed, since that is what it asked for. */
    if (!NT_SUCCESS(CalloutStatus))
    {
        DPRINT1("Failed to apply the UI restrictions of job %p to process %p: 0x%lx\n",
                UIJob, Process, CalloutStatus);

        (VOID)PsTerminateProcess(Process, CalloutStatus);
        Status = CalloutStatus;
    }

    /* TODO: Ensure that job limits are respected */

    return Status;
}

/*!
 * Assigns a process that already is in a job to another job, nesting the
 * jobs (Windows 8 and later).
 *
 * @param[in] Process
 *     Pointer to the process to be assigned.
 *
 * @param[in] Target
 *     Pointer to the job the process becomes a direct member of.
 *
 * @returns
 *     STATUS_SUCCESS if the process is in Target afterwards (including when it
 *     already was in it or in one of its ancestors, which Windows accepts),
 *     STATUS_ACCESS_DENIED if Target cannot be nested under the process's job,
 *     another error status otherwise, or STATUS_RETRY if the process was not
 *     in a job after all.
 *
 * @remarks
 *     As on Windows, the process stays a member of its current job and all of
 *     that job's ancestors; Target becomes a child of the process's current
 *     job, unless it already is one. A job can only be given a parent while it
 *     has no processes and no children, and Target must not have another
 *     parent. The process's direct job becomes Target. Accounting of the
 *     jobs above Target already includes the process.
 *
 *     Locks are taken parent first, then child, like everywhere else. When
 *     the jobs are not yet related there is no such order, and the second
 *     lock is only tried (see the loop below).
 */
static
NTSTATUS
PspNestProcessInJob(
    _In_ PEPROCESS Process,
    _In_ PEJOB Target
)
{
    PEJOB Leaf, Walk, Parent;
    NTSTATUS Status = STATUS_SUCCESS;
    NTSTATUS CalloutStatus = STATUS_SUCCESS;
    BOOLEAN Attach = FALSE, Moved = FALSE, UIAlreadyEnforced = FALSE;

    if (!ExAcquireRundownProtection(&Process->RundownProtect))
    {
        return STATUS_ACCESS_DENIED;
    }

    for (;;)
    {
        Leaf = Process->Job;
        if (Leaf == NULL)
        {
            ExReleaseRundownProtection(&Process->RundownProtect);
            return STATUS_RETRY;
        }

        /* Already a member through this job or one of its ancestors */
        if (PspIsJobInHierarchy(Leaf, Target))
        {
            /* A process that has exited cannot be assigned any more */
            if (FlagOn(Process->JobStatus, PSP_JOB_NOT_REALLY_ACTIVE))
            {
                Status = STATUS_ACCESS_DENIED;
            }

            ExReleaseRundownProtection(&Process->RundownProtect);
            return Status;
        }

        /* The relation of the two jobs decides how they may be locked, and
           ParentJob never changes once set, so look at it first. A target
           that belongs below some other job can never take the process; no
           lock is needed to say so. */
        Parent = Target->ParentJob;
        if (Parent != NULL && Parent != Leaf)
        {
            ExReleaseRundownProtection(&Process->RundownProtect);
            return STATUS_ACCESS_DENIED;
        }

        ExEnterCriticalRegionAndAcquireResourceExclusive(&Leaf->JobLock);

        if (Parent == Leaf)
        {
            /* Already a child: parent first, then child, as everywhere else */
            ExEnterCriticalRegionAndAcquireResourceExclusive(&Target->JobLock);
        }
        else
        {
            /* Target has no parent yet and may become a child of Leaf. Nothing
               orders the two locks for unrelated jobs: two threads assigning
               a process of X to Y and a process of Y to X would each hold one
               and wait for the other. So never wait for the second lock while
               holding the first; back off and start over instead. */
            KeEnterCriticalRegion();
            if (!ExAcquireResourceExclusiveLite(&Target->JobLock, FALSE))
            {
                LARGE_INTEGER Interval;

                KeLeaveCriticalRegion();
                ExReleaseResourceAndLeaveCriticalRegion(&Leaf->JobLock);

                Interval.QuadPart = -10000; /* 1 ms */
                KeDelayExecutionThread(KernelMode, FALSE, &Interval);
                continue;
            }
        }

        /* The process may have been nested further in the meantime */
        if (Process->Job == Leaf)
        {
            break;
        }

        ExReleaseResourceAndLeaveCriticalRegion(&Target->JobLock);
        ExReleaseResourceAndLeaveCriticalRegion(&Leaf->JobLock);
    }

    /* An exiting process takes its job accounting down with it. The flag is
       set before the accounting is touched, and it is checked here under the
       lock the accounting needs, so this cannot race with it. */
    if (FlagOn(Process->JobStatus, PSP_JOB_NOT_REALLY_ACTIVE))
    {
        Status = STATUS_ACCESS_DENIED;
        goto Exit;
    }

    if (FlagOn(Leaf->JobFlags, PSP_JOB_TERMINATING) ||
        FlagOn(Target->JobFlags, PSP_JOB_TERMINATING))
    {
        Status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    if (FlagOn(Target->LimitFlags, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) &&
        FlagOn(Target->JobFlags, PSP_JOB_CLOSE_DONE))
    {
        Status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    if (Target->ParentJob == Leaf)
    {
        /* Already nested directly under the process's job */
    }
    else if (Target->ParentJob == NULL &&
             IsListEmpty(&Target->ProcessListHead) &&
             IsListEmpty(&Target->ChildJobsHead) &&
             Leaf->MemberLevel + 1 < PSP_JOB_MAX_NESTING)
    {
        /* An empty job becomes a child of the process's job */
        Attach = TRUE;
    }
    else
    {
        /* Windows: ERROR_ACCESS_DENIED for a job that belongs elsewhere */
        Status = STATUS_ACCESS_DENIED;
        goto Exit;
    }

    if (FlagOn(Target->LimitFlags, JOB_OBJECT_LIMIT_ACTIVE_PROCESS) &&
        Target->ActiveProcesses >= Target->ActiveProcessLimit)
    {
        if (Target->CompletionPort)
        {
            (VOID)PspSendJobMessageLocked(Target,
                                          JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT,
                                          NULL,
                                          TRUE);
        }

        Status = STATUS_QUOTA_EXCEEDED;
        goto Exit;
    }

    /* Committed from here on. The child's reference on its parent replaces
       the one the process held on its old direct job. */
    if (Attach)
    {
        ObReferenceObject(Leaf);
        Target->ParentJob = Leaf;
        Target->MemberLevel = Leaf->MemberLevel + 1;
        InsertTailList(&Leaf->ChildJobsHead, &Target->ChildJobsLinks);
    }

    ObReferenceObject(Target);

    RemoveEntryList(&Process->JobLinks);
    InsertTailList(&Target->ProcessListHead, &Process->JobLinks);
    Process->Job = Target;
    Moved = TRUE;

    Target->TotalProcesses++;
    Target->ActiveProcesses++;

    if (Target->CompletionPort && Process->UniqueProcessId)
    {
        (VOID)PspSendJobMessageLocked(Target,
                                      JOB_OBJECT_MSG_NEW_PROCESS,
                                      Process->UniqueProcessId,
                                      FALSE);
    }

    /* A process already under UI restrictions of an outer job is enforced by
       win32k through that job. Combining the restrictions of several jobs is
       not implemented, so the outer ones win. */
    for (Walk = Leaf; Walk != NULL; Walk = Walk->ParentJob)
    {
        if (Walk->UIRestrictionsClass != 0)
        {
            UIAlreadyEnforced = TRUE;
            break;
        }
    }

    if (Target->UIRestrictionsClass != 0 &&
        !UIAlreadyEnforced &&
        Process->Win32Process != NULL)
    {
        CalloutStatus = PspInvokeW32JobCallout(Target,
                                               PsW32JobCalloutAddProcess,
                                               Process->Win32Process);
    }

Exit:
    ExReleaseResourceAndLeaveCriticalRegion(&Target->JobLock);
    ExReleaseResourceAndLeaveCriticalRegion(&Leaf->JobLock);
    ExReleaseRundownProtection(&Process->RundownProtect);

    if (Moved)
    {
        /* Leaf stays referenced by Target's reference on its parent */
        ObDereferenceObject(Leaf);
    }

    if (!NT_SUCCESS(CalloutStatus))
    {
        DPRINT1("Failed to apply the UI restrictions of job %p to process %p: 0x%lx\n",
                Target, Process, CalloutStatus);

        (VOID)PsTerminateProcess(Process, CalloutStatus);
        Status = CalloutStatus;
    }

    return Status;
}

/*!
 * Assigns a process to a job object.
 
 * @param[in] Process
 *     Pointer to the process to be assigned to the job.
 *
 * @param[in] Job
 *     Pointer to the job object to which the process is to be assigned.
 *
 * @returns
 *     STATUS_SUCCESS if the process is successfully assigned to the job.
 *     An appropriate NTSTATUS error code otherwise.
 *
 * @remarks
 *     A process that already is in a job is nested into the new job, see
 *     PspNestProcessInJob().
 */
NTSTATUS
NTAPI
PspAssignProcessToJob(
    _In_ PEPROCESS Process,
    _In_ PEJOB Job
)
{
    NTSTATUS Status;

    for (;;)
    {
        if (Process->Job != NULL)
        {
            Status = PspNestProcessInJob(Process, Job);
        }
        else
        {
            Status = PspAssignNewProcessToJob(Process, Job);
        }

        /* The process's job membership changed while we looked at it */
        if (Status != STATUS_RETRY)
        {
            return Status;
        }
    }
}

/*!
 * Marks a process inactive in its job and in all of the job's ancestors.
 *
 * @param[in] Process
 *     A pointer to the process being marked inactive.
 *
 * @param[in] Terminating
 *     TRUE if this is part of terminating the jobs: a job that ends up without
 *     active processes then also signals its event.
 *
 * @remarks
 *     The first caller for a process does the work, later ones do nothing.
 *     The flag is set before any job lock is taken. From then on the process
 *     cannot be nested any deeper (PspNestProcessInJob checks the flag under
 *     the locks), so the chain found below stays valid.
 *
 *     Job locks are taken one at a time, innermost job first, and never held
 *     across the step to the parent, so this cannot deadlock with the
 *     parent-first locking of assignment.
 */
static
VOID
PspDeactivateProcessInJobHierarchy(
    _In_ PEPROCESS Process,
    _In_ BOOLEAN Terminating
)
{
    PEJOB Job, Parent;
    BOOLEAN ActiveProcessZero;

    if (InterlockedOr((PLONG)&Process->JobStatus, PSP_JOB_NOT_REALLY_ACTIVE) &
        PSP_JOB_NOT_REALLY_ACTIVE)
    {
        return;
    }

    /* A nest in progress finishes before it releases the direct job's lock */
    for (;;)
    {
        Job = Process->Job;
        ASSERT(Job != NULL);

        ExEnterCriticalRegionAndAcquireResourceExclusive(&Job->JobLock);
        if (Process->Job == Job)
        {
            break;
        }
        ExReleaseResourceAndLeaveCriticalRegion(&Job->JobLock);
    }

    for (;;)
    {
        ASSERT(Job->ActiveProcesses != 0);
        Job->ActiveProcesses--;
        ActiveProcessZero = (Job->ActiveProcesses == 0);

        /* If there are no active processes left in the job, notify anyone
           waiting for the job object by signaling completion. It is intended
           that the event is set to a signaled state only in the termination
           path */
        if (ActiveProcessZero)
        {
            if (Terminating)
            {
                KeSetEvent(&Job->Event, IO_NO_INCREMENT, FALSE);
            }

            /* If no active processes remain, notify the job completion port */
            if (Job->CompletionPort)
            {
                (VOID)PspSendJobMessageLocked(Job,
                                              JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO,
                                              NULL,
                                              FALSE);
            }
        }

        /* ParentJob is immutable once the job holds this process */
        Parent = Job->ParentJob;

        ExReleaseResourceAndLeaveCriticalRegion(&Job->JobLock);

        if (Parent == NULL)
        {
            break;
        }

        Job = Parent;
        ExEnterCriticalRegionAndAcquireResourceExclusive(&Job->JobLock);
    }
}

/*!
 * Removes a process from its assigned job.
 *
 * @param[in] Process
 *     A pointer to the process being removed from its assigned job.
 *
 * @remarks
 *     This function is called from PspDeleteProcess() during process object
 *     deletion. The process must still be linked to its assigned job.
 */
VOID
NTAPI
PspRemoveProcessFromJob(
    _In_ PEPROCESS Process
)
{
    PEJOB Job;

    Job = Process->Job;
    ASSERT(Job != NULL);

    /* Decrement the active process count of the job and its ancestors if the
       process is still active, and notify their completion ports */
    PspDeactivateProcessInJobHierarchy(Process, FALSE);

    ExEnterCriticalRegionAndAcquireResourceExclusive(&Job->JobLock);

    ASSERT(Process->Job == Job);
    ASSERT(Process->JobLinks.Flink != NULL);
    ASSERT(Process->JobLinks.Blink != NULL);
    ASSERT(!IsListEmpty(&Process->JobLinks));

    /* Remove the process from the job's process list */
    RemoveEntryList(&Process->JobLinks);
    InitializeListHead(&Process->JobLinks);

    /* TODO: Ensure that job limits are respected */

    ExReleaseResourceAndLeaveCriticalRegion(&Job->JobLock);
}

/*!
 * Handles the exit of a process from the specified job object.
 *
 * @param[in] Process
 *     A pointer to the process that is exiting the job.
 *
 * @remark
 *     This function is called from PspExitThread() when the last thread exits.
 *     The process must be assigned to a job.
 */
VOID
NTAPI
PspExitProcessFromJob(
    _In_ PEPROCESS Process
)
{
    ASSERT(Process->Job != NULL);

    /* Decrement the active process count of the job and its ancestors if the
       process is still active, and notify their completion ports */
    PspDeactivateProcessInJobHierarchy(Process, FALSE);

    /* TODO: Ensure that job limits are respected */
}

/*!
 * Callback function to terminate a process and update the job's
 * active process counter.
 *
 * @param[in] Process
 *     A pointer to the process object to be terminated.
 *
 * @param[in] Context
 *     A pointer to a PSP_TERMINATE_PROCESS_CONTEXT structure.
 *
 * @returns
 *     STATUS_SUCCESS.
 *
 * @remark
 *     The callback is invoked _without_ any job lock held. Process carries the
 *     reference acquired by the job enumerator for the duration of the call.
 *     It may have been nested into a deeper job since the enumerator found it;
 *     that job is terminated after this one.
 */
static
NTSTATUS
NTAPI
PspTerminateProcessCallback(
    _In_ PEPROCESS Process,
    _In_ PVOID Context
)
{
    NTSTATUS Status;
    PPSP_TERMINATE_PROCESS_CONTEXT TerminateContext = (PPSP_TERMINATE_PROCESS_CONTEXT)Context;
    NTSTATUS ExitStatus = TerminateContext->ExitStatus;

    ASSERT(Process->Job != NULL);

    /* Defer termination of the current process: terminating ourselves ends in
       PspExitThread on the current thread, which must run at PASSIVE_LEVEL with
       APCs enabled. Doing it here, inside the job lock critical region, would
       exit the thread with CombinedApcDisable != 0 and bugcheck 0x20
       (KERNEL_APC_PENDING_DURING_EXIT); it also never returns, so the lock
       would never be released. PspTerminateJobObject terminates us last, once
       the rest of the job has been torn down and the lock has been dropped. The
       job accounting for our own process is still completed by its normal exit
       path (PspExitThread -> PspExitProcessFromJob). */
    if (Process == PsGetCurrentProcess())
    {
        TerminateContext->SelfDeferred = TRUE;
        return STATUS_SUCCESS;
    }

    /* Avoid entering process termination when the process has already
       completed its active job transition */
    if (FlagOn(Process->JobStatus, PSP_JOB_NOT_REALLY_ACTIVE))
    {
        return STATUS_SUCCESS;
    }

    /* Terminate the process */
    Status = PsTerminateProcess(Process, ExitStatus);

    /* PsTerminateProcess can return STATUS_NOTHING_TO_TERMINATE
       when it finds no threads (the ordinary process exit remains
       responsible for completing job accounting in that case),
       that should be treated as a no-op for job traversal */
    if (!NT_SUCCESS(Status))
    {
        return STATUS_SUCCESS;
    }

    /* Decrement the active process count of the job and its ancestors if the
       process is still active */
    PspDeactivateProcessInJobHierarchy(Process, TRUE);

    return STATUS_SUCCESS;
}

/*!
 * Returns the next child job of a job.
 *
 * @param[in] Parent
 *     A pointer to the job whose children are enumerated.
 *
 * @param[in, optional] PreviousChild
 *     A referenced child returned by the previous call, or NULL to start.
 *     Its reference is consumed by this function.
 *
 * @return
 *     A referenced pointer to the next child, or NULL when done.
 */
static
PEJOB
PspGetNextChildJob(
    _In_ PEJOB Parent,
    _In_opt_ PEJOB PreviousChild
)
{
    PLIST_ENTRY Entry;
    PEJOB Next = NULL;

    ExEnterCriticalRegionAndAcquireResourceShared(&Parent->JobLock);

    if (PreviousChild != NULL)
    {
        Entry = PreviousChild->ChildJobsLinks.Flink;
    }
    else
    {
        Entry = Parent->ChildJobsHead.Flink;
    }

    /* A child whose deletion has begun is skipped; it unlinks itself under
       the exclusive lock, which keeps the links valid while we hold it */
    for (; Entry != &Parent->ChildJobsHead; Entry = Entry->Flink)
    {
        PEJOB Child = CONTAINING_RECORD(Entry, EJOB, ChildJobsLinks);

        if (ObReferenceObjectSafe(Child))
        {
            Next = Child;
            break;
        }
    }

    ExReleaseResourceAndLeaveCriticalRegion(&Parent->JobLock);

    /* Releasing the reference can delete the job, which takes the parent's
       lock to unlink */
    if (PreviousChild != NULL)
    {
        ObDereferenceObject(PreviousChild);
    }

    return Next;
}

/*!
 * Terminates the processes of a job and, after them, of all its descendants.
 *
 * @param[in] Job
 *     A pointer to the job object to be terminated.
 *
 * @param[in, out] Context
 *     The termination context shared by the whole hierarchy.
 *
 * @remarks
 *     A job is flagged as terminating until its descendants are done, so
 *     nothing can be assigned to any of them meanwhile. Processes are
 *     only ever nested deeper, so one that moves while its job is
 *     enumerated is reached through the child job afterwards.
 */
static
VOID
PspTerminateJobHierarchy(
    _In_ PEJOB Job,
    _Inout_ PPSP_TERMINATE_PROCESS_CONTEXT Context
)
{
    NTSTATUS Status;
    LONG PreviousFlags;
    PEJOB Child;

    PreviousFlags = InterlockedOr((PLONG)&Job->JobFlags, PSP_JOB_TERMINATING);

    /* Termination is idempotent, another caller already owns the traversal */
    if (PreviousFlags & PSP_JOB_TERMINATING)
    {
        return;
    }

    Status = PspEnumerateProcessesInJob(Job,
                                        PspTerminateProcessCallback,
                                        Context);

    /* The termination callback always returns STATUS_SUCCESS because
       per-process termination failures are handled locally */
    ASSERT(NT_SUCCESS(Status));
    UNREFERENCED_PARAMETER(Status);

    for (Child = PspGetNextChildJob(Job, NULL);
         Child != NULL;
         Child = PspGetNextChildJob(Job, Child))
    {
        PspTerminateJobHierarchy(Child, Context);
    }

    InterlockedAnd((PLONG)&Job->JobFlags, ~PSP_JOB_TERMINATING);
}

/*!
 * Terminates all processes currently associated with the specified job object
 * and with its child jobs.
 *
 * @param[in] Job
 *     A pointer to the job object to be terminated.
 *
 * @param[in] ExitStatus
 *     The exit status to be used for all terminated processes.
 *
 * @returns
 *     STATUS_SUCCESS if the job object was successfully terminated.
 *     Otherwise, an appropriate NTSTATUS error code.
 */
NTSTATUS
NTAPI
PspTerminateJobObject(
    _In_ PEJOB Job,
    _In_ NTSTATUS ExitStatus
)
{
    PSP_TERMINATE_PROCESS_CONTEXT Context;

    Context.ExitStatus = ExitStatus;
    Context.SelfDeferred = FALSE;

    PspTerminateJobHierarchy(Job, &Context);

    /* If the current process is a member of this job, terminate it last. The
       object manager invokes job close inside ObpCloseHandle's critical
       region, so the current thread cannot be exited inline here (that
       bugchecks 0x20); PspTerminateCurrentProcessDeferred queues our own exit
       as a kernel APC that is delivered once that critical region unwinds. */
    if (Context.SelfDeferred)
    {
        (VOID)PspTerminateCurrentProcessDeferred(ExitStatus);
    }

    return STATUS_SUCCESS;
}

/*!
 * Handles the closing of a job object.
 *
 * @param[in] Process
 *     Unused.
 *
 * @param[in] ObjectBody
 *     A pointer to the job object being closed.
 *
 * @param[in] GrantedAccess
 *     Unused.
 *
 * @param[in] ProcessHandleCount
 *     Unused.
 *
 * @param[in] SystemHandleCount
 *     The number of system handles currently open for the job object.
 *
 * @remark
 *     This function terminates the job if the
 *     JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE flag is set.
 */
VOID
NTAPI
PspCloseJob(
    _In_ PEPROCESS Process,
    _In_ PVOID ObjectBody,
    _In_ ACCESS_MASK GrantedAccess,
    _In_ ULONG_PTR ProcessHandleCount,
    _In_ ULONG_PTR SystemHandleCount
)
{
    NTSTATUS Status;
    PEJOB Job = (PEJOB)ObjectBody;
    PVOID CompletionPort = NULL;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(GrantedAccess);
    UNREFERENCED_PARAMETER(ProcessHandleCount);

    /* Proceed only when the last handle is left */
    if (SystemHandleCount > 1)
    {
        DPRINT1("PspJobClose called with unexpected SystemHandleCount: %lu\n",
                SystemHandleCount);
        return;
    }

    /* Flag the job as closed */
    InterlockedOr((PLONG)&Job->JobFlags, PSP_JOB_CLOSE_DONE);

    ExEnterCriticalRegionAndAcquireResourceExclusive(&Job->JobLock);

    /* If the job is set to kill on close, terminate all associated processes */
    if (FlagOn(Job->LimitFlags, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE))
    {
        /* Keep the completion port associated during termination so that
           final job messages can still be delivered */
        ExReleaseResourceAndLeaveCriticalRegion(&Job->JobLock);

        Status = PspTerminateJobObject(Job, STATUS_SUCCESS);
        ASSERT(NT_SUCCESS(Status));

        ExEnterCriticalRegionAndAcquireResourceExclusive(&Job->JobLock);
    }

    CompletionPort = Job->CompletionPort;
    Job->CompletionPort = NULL;
    Job->CompletionKey = NULL;

    ExReleaseResourceAndLeaveCriticalRegion(&Job->JobLock);

    if (CompletionPort)
    {
        ObDereferenceObject(CompletionPort);
    }
}

/*!
 * Deletes the specified job object and cleans up associated resources.
 *
 * @param[in] ObjectBody
 *     A pointer to the job object to be deleted.
 */
VOID
NTAPI
PspDeleteJob(_In_ PVOID ObjectBody)
{
    PEJOB Job = (PEJOB)ObjectBody;

    PAGED_CODE();

    /* Let win32k tear down any per-job state it keeps for UI restrictions */
    if (Job->UIRestrictionsClass != 0)
    {
        (VOID)PspInvokeW32JobCallout(Job, PsW32JobCalloutTerminate, NULL);
        Job->UIRestrictionsClass = 0;
    }

    Job->LimitFlags = 0;

    /* Remove the reference to the completion port if associated */
    if (Job->CompletionPort)
    {
        ObDereferenceObject(Job->CompletionPort);
        Job->CompletionPort = NULL;
    }

    /* TODO: Ensure that job sets are respected */

    /* A job in a hierarchy leaves its parent's list of children and drops the
       reference it held on the parent. Its own children cannot exist any
       more: each of them holds a reference on this job. */
    ASSERT(IsListEmpty(&Job->ChildJobsHead));

    if (Job->ParentJob != NULL)
    {
        PEJOB Parent = Job->ParentJob;

        ExEnterCriticalRegionAndAcquireResourceExclusive(&Parent->JobLock);
        RemoveEntryList(&Job->ChildJobsLinks);
        ExReleaseResourceAndLeaveCriticalRegion(&Parent->JobLock);

        Job->ParentJob = NULL;
        ObDereferenceObject(Parent);
    }

    /* Unlink the job object under lock */
    ExAcquireFastMutex(&PsJobListLock);

    ASSERT(!IsListEmpty(&Job->JobLinks));
    RemoveEntryList(&Job->JobLinks);

    ExReleaseFastMutex(&PsJobListLock);

    /* TODO: Clean up security information */

    /* Delete the resource associated with the job object */
    ExDeleteResource(&Job->JobLock);
}

/*!
 * Helper function to set limit information for a job object,
 * either basic or extended limits.
 *
 * @param[in] Job
 *     The job object being modified.
 *
 * @param[in] ExtendedLimit
 *     A pointer to the structure containing the limit information to be set.
 *
 * @param[in] IsExtendedLimit
 *     A boolean value indicating whether the limit information is extended.
 *
 * @returns
 *     STATUS_SUCCESS if the job limits are successfully set.
 *     Otherwise, an appropriate NTSTATUS error code.
 */
static
NTSTATUS
PspSetJobLimitsBasicOrExtended(
    _In_ PEJOB Job,
    _In_ PJOBOBJECT_EXTENDED_LIMIT_INFORMATION ExtendedLimit,
    _In_ BOOLEAN IsExtendedLimit
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG AllowedFlags;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();

    ASSERT(KeAreAllApcsDisabled());

    AllowedFlags = IsExtendedLimit
                       ? PSP_JOB_EXTENDED_LIMIT_VALID_FLAGS
                       : PSP_JOB_BASIC_LIMIT_VALID_FLAGS;

    /* Validate flags */
    if (ExtendedLimit->BasicLimitInformation.LimitFlags & ~AllowedFlags)
    {
        DPRINT1("Invalid LimitFlags specified: 0x%08X\n",
                ExtendedLimit->BasicLimitInformation.LimitFlags & ~AllowedFlags);
        return STATUS_INVALID_PARAMETER;
    }

    if (ExtendedLimit->BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_PRESERVE_JOB_TIME &&
        ExtendedLimit->BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_JOB_TIME)
    {
        DPRINT1("Invalid LimitFlags combination specified "
                "(PRESERVE_JOB_TIME and JOB_TIME are mutually exclusive)\n");
        return STATUS_INVALID_PARAMETER;
    }

    /* Acquire the job lock */
    ExAcquireResourceExclusiveLite(&Job->JobLock, TRUE);

    /*
     * Basic Limits
     */

    if (ExtendedLimit->BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_WORKINGSET)
    {
        /* https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information:
           "If MaximumWorkingSetSize is nonzero, MinimumWorkingSetSize cannot be zero"
           "If MinimumWorkingSetSize is nonzero, MaximumWorkingSetSize cannot be zero"
           Also check that the minimum doesn't exceed the maximum or both aren't equal to zero. */
        if ((ExtendedLimit->BasicLimitInformation.MaximumWorkingSetSize > 0 &&
                ExtendedLimit->BasicLimitInformation.MinimumWorkingSetSize <= 0)
            ||
            (ExtendedLimit->BasicLimitInformation.MinimumWorkingSetSize > 0 &&
                ExtendedLimit->BasicLimitInformation.MaximumWorkingSetSize <= 0)
            ||
            ExtendedLimit->BasicLimitInformation.MaximumWorkingSetSize <
            ExtendedLimit->BasicLimitInformation.MinimumWorkingSetSize)
        {
            Status = STATUS_INVALID_PARAMETER;
            goto ExitFromBasicLimits;
        }

        Job->MinimumWorkingSetSize = ExtendedLimit->BasicLimitInformation.MinimumWorkingSetSize;
        Job->MaximumWorkingSetSize = ExtendedLimit->BasicLimitInformation.MaximumWorkingSetSize;
    }

    if (ExtendedLimit->BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_PROCESS_TIME)
    {
        Job->PerProcessUserTimeLimit.QuadPart =
            ExtendedLimit->BasicLimitInformation.PerProcessUserTimeLimit.QuadPart;
    }

    if (ExtendedLimit->BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_JOB_TIME)
    {
        Job->PerJobUserTimeLimit.QuadPart =
            ExtendedLimit->BasicLimitInformation.PerJobUserTimeLimit.QuadPart;
    }

    if (ExtendedLimit->BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS)
    {
        Job->ActiveProcessLimit = ExtendedLimit->BasicLimitInformation.ActiveProcessLimit;
    }

    if (ExtendedLimit->BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_AFFINITY)
    {
        /* https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information:
           "The affinity must be a subset of the system affinity mask obtained
           by calling the GetProcessAffinityMask function"
           The lpSystemAffinityMask obtained with GetProcessAffinityMask() corresponds
           to ActiveProcessorsAffinityMask, which in turn corresponds to KeActiveProcessors */
        if (ExtendedLimit->BasicLimitInformation.Affinity !=
            (ExtendedLimit->BasicLimitInformation.Affinity & KeActiveProcessors))
        {
            Status = STATUS_INVALID_PARAMETER;
            goto ExitFromBasicLimits;
        }

        Job->Affinity = ExtendedLimit->BasicLimitInformation.Affinity;
    }

    if (ExtendedLimit->BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_PRIORITY_CLASS)
    {
        if (ExtendedLimit->BasicLimitInformation.PriorityClass > PROCESS_PRIORITY_CLASS_ABOVE_NORMAL ||
            ExtendedLimit->BasicLimitInformation.PriorityClass <= PROCESS_PRIORITY_CLASS_INVALID)
        {
            Status = STATUS_INVALID_PARAMETER;
            goto ExitFromBasicLimits;
        }

        /* https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information:
           "The calling process must enable the SE_INC_BASE_PRIORITY_NAME
           privilege" */
        if (SeCheckPrivilegedObject(SeIncreaseBasePriorityPrivilege,
                                    Job,
                                    JOB_OBJECT_SET_ATTRIBUTES,
                                    PreviousMode))
        {
            Job->PriorityClass = ExtendedLimit->BasicLimitInformation.PriorityClass;
        }
        else
        {
            Status = STATUS_PRIVILEGE_NOT_HELD;
            goto ExitFromBasicLimits;
        }
    }

    if (ExtendedLimit->BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_SCHEDULING_CLASS)
    {
        if (ExtendedLimit->BasicLimitInformation.SchedulingClass >= PSP_JOB_SCHEDULING_CLASSES)
        {
            Status = STATUS_INVALID_PARAMETER;
            goto ExitFromBasicLimits;
        }

        /* https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information:
           "To use a scheduling class greater than 5, the calling process must
           enable the SE_INC_BASE_PRIORITY_NAME privilege" */
        if (ExtendedLimit->BasicLimitInformation.SchedulingClass > PSP_JOB_SCHEDULING_CLASS_DEFAULT)
        {
            if (SeCheckPrivilegedObject(SeIncreaseBasePriorityPrivilege,
                                        Job,
                                        JOB_OBJECT_SET_ATTRIBUTES,
                                        PreviousMode))
            {
                Job->SchedulingClass = ExtendedLimit->BasicLimitInformation.SchedulingClass;
            }
            else
            {
                Status = STATUS_PRIVILEGE_NOT_HELD;
                goto ExitFromBasicLimits;
            }
        }
        else
        {
            Job->SchedulingClass = ExtendedLimit->BasicLimitInformation.SchedulingClass;
        }
    }

    /*
     * Extended Memory Limits
     */

    /* Acquire the memory limits lock */
    KeAcquireGuardedMutexUnsafe(&Job->MemoryLimitsLock);

    if (ExtendedLimit->BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_PROCESS_MEMORY)
    {
        Job->ProcessMemoryLimit = ExtendedLimit->ProcessMemoryLimit >> PAGE_SHIFT;
    }

    if (ExtendedLimit->BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_JOB_MEMORY)
    {
        Job->JobMemoryLimit = ExtendedLimit->JobMemoryLimit >> PAGE_SHIFT;
    }

    /* Update the job's limit flags with the new ones. This includes dealing
       with those extended limits that only set some flag */
    Job->LimitFlags = ExtendedLimit->BasicLimitInformation.LimitFlags;


    /* Release locks */

    KeReleaseGuardedMutexUnsafe(&Job->MemoryLimitsLock);

ExitFromBasicLimits:

    ExReleaseResourceLite(&Job->JobLock);

    return Status;
}

/*!
 * Queues an initial new-process notification for a process already assigned
 * to a job.
 *
 * @param[in] Process
 *     A borrowed pointer to the process being notified.
 *
 * @param[in] Context
 *     A pointer to the job associated with the completion port.
 *
 * @return
 *     STATUS_SUCCESS.
 *
 * @remarks
 *     The callback is invoked while the job lock is held exclusively.
 *     Notification failures are recorded for diagnostic purposes and do not
 *     undo the completion port association.
 */
static
NTSTATUS
NTAPI
PspAssociateCompletionPortCallback(
    _In_ PEPROCESS Process,
    _In_ PVOID Context)
{
    PEJOB Job;

    Job = (PEJOB)Context;

    ASSERT(Process->Job == Job);
    ASSERT(Job->CompletionPort != NULL);

    ASSERT(ExIsResourceAcquiredExclusiveLite(&Job->JobLock) != 0);

    /* Ensure the process is active and has a valid unique process ID */
    if (!FlagOn(Process->JobStatus, PSP_JOB_NOT_REALLY_ACTIVE) &&
        Process->UniqueProcessId)
    {
        (VOID)PspSendJobMessageLocked(Job,
                                      JOB_OBJECT_MSG_NEW_PROCESS,
                                      Process->UniqueProcessId,
                                      FALSE);
    }

    return STATUS_SUCCESS;
}

/*!
 * Associates an I/O completion port with a job object and enumerates its
 * processes to propagate the association.
 *
 * @param[in] Job
 *     A pointer to the job object to which the I/O completion port will be
 *     associated.
 *
 * @param[in] AssociateCpInfo
 *     A structure containing information used to associate a completion port
 *     with a job (the handle of the I/O completion port and the key).
 *
 * @return
 *     STATUS_SUCCESS if the completion port was associated with the job.
 *     Otherwise, an appropriate NTSTATUS error code.
 *
 * @remarks
 *     Once the completion port is installed, failure to queue an initial
 *     process notification is recorded diagnostically and does not undo the
 *     association.
 */
static
NTSTATUS
PspAssociateCompletionPortWithJob(
    _In_ PEJOB Job,
    _In_ PJOBOBJECT_ASSOCIATE_COMPLETION_PORT AssociateCpInfo
)
{
    NTSTATUS Status;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    HANDLE IoCompletion;

    ASSERT(KeAreAllApcsDisabled());

    if (!AssociateCpInfo->CompletionPort)
    {
        return STATUS_INVALID_PARAMETER;
    }

    Status = ObReferenceObjectByHandle(AssociateCpInfo->CompletionPort,
                                       IO_COMPLETION_MODIFY_STATE,
                                       IoCompletionType,
                                       PreviousMode,
                                       &IoCompletion,
                                       NULL);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    ExAcquireResourceExclusiveLite(&Job->JobLock, TRUE);

    /* Check if the job already has a completion port or is in a final state */
    if (Job->CompletionPort || FlagOn(Job->JobFlags, PSP_JOB_CLOSE_DONE))
    {
        ExReleaseResourceLite(&Job->JobLock);
        ObDereferenceObject(IoCompletion);
        return STATUS_INVALID_PARAMETER;
    }

    Job->CompletionKey = AssociateCpInfo->CompletionKey;
    Job->CompletionPort = IoCompletion;

    /* Inform all processes in the job about the association
       N.B. Assignment is serialized by JobLock; a process is therefore covered
       either by this enumeration or by the normal assignment path */
    Status = PspEnumerateProcessesInJobLocked(Job,
                                              PspAssociateCompletionPortCallback,
                                              Job);

    ASSERT(NT_SUCCESS(Status));

    ExReleaseResourceLite(&Job->JobLock);

    /* The completion port association is committed at this point. Initial process
       notifications are best-effort and a failure to queue one must not turn
       a successful association into a failure. */
    return STATUS_SUCCESS;
}

/*!
 * Collects accounting information, such as total user time, kernel time, page
 * fault counts, and I/O operations, for the given job object.
 *
 * @param[in] Job
 *     Pointer to the job object whose accounting information is being queried.
 *
 * @param[out] BasicAndIo
 *     Pointer to a structure that will be filled with basic accounting and
 *     I/O information about the job.
 *
 * @return
 *     STATUS_SUCCESS on success.
 *     Otherwise, an appropriate NTSTATUS error code.
 */
static
VOID
PspAccumulateJobProcessAccountingLocked(
    _In_ PEJOB Job,
    _Inout_ PJOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION BasicAndIo
)
{
    PLIST_ENTRY NextEntry;
    PROCESS_VALUES Values;
    PLIST_ENTRY ChildEntry;

    /* Sum up accounting data for each active process in the job */
    for (NextEntry = Job->ProcessListHead.Flink;
         NextEntry != &Job->ProcessListHead;
         NextEntry = NextEntry->Flink)
    {
        PEPROCESS Process = CONTAINING_RECORD(NextEntry, EPROCESS, JobLinks);

        /* Skip folded accounting processes */
        if (!FlagOn(Process->JobStatus, PSP_JOB_ACCOUNTING_FOLDED))
        {
            KeQueryValuesProcess(&Process->Pcb, &Values);

            /* Accumulate user and kernel times, and I/O counts */
            BasicAndIo->BasicInfo.TotalUserTime.QuadPart += Values.TotalUserTime.QuadPart;
            BasicAndIo->BasicInfo.TotalKernelTime.QuadPart += Values.TotalKernelTime.QuadPart;
            BasicAndIo->IoInfo.ReadOperationCount += Values.IoInfo.ReadOperationCount;
            BasicAndIo->IoInfo.WriteOperationCount += Values.IoInfo.WriteOperationCount;
            BasicAndIo->IoInfo.OtherOperationCount += Values.IoInfo.OtherOperationCount;
            BasicAndIo->IoInfo.ReadTransferCount += Values.IoInfo.ReadTransferCount;
            BasicAndIo->IoInfo.WriteTransferCount += Values.IoInfo.WriteTransferCount;
            BasicAndIo->IoInfo.OtherTransferCount += Values.IoInfo.OtherTransferCount;
        }
    }

    /* A job's totals include those of its child jobs. The process counts of
       the job already do (members are counted in all of their jobs). */
    for (ChildEntry = Job->ChildJobsHead.Flink;
         ChildEntry != &Job->ChildJobsHead;
         ChildEntry = ChildEntry->Flink)
    {
        PEJOB Child = CONTAINING_RECORD(ChildEntry, EJOB, ChildJobsLinks);

        ExEnterCriticalRegionAndAcquireResourceShared(&Child->JobLock);

        BasicAndIo->BasicInfo.TotalUserTime.QuadPart += Child->TotalUserTime.QuadPart;
        BasicAndIo->BasicInfo.TotalKernelTime.QuadPart += Child->TotalKernelTime.QuadPart;
        BasicAndIo->BasicInfo.ThisPeriodTotalUserTime.QuadPart += Child->ThisPeriodTotalUserTime.QuadPart;
        BasicAndIo->BasicInfo.ThisPeriodTotalKernelTime.QuadPart += Child->ThisPeriodTotalKernelTime.QuadPart;
        BasicAndIo->BasicInfo.TotalPageFaultCount += Child->TotalPageFaultCount;
        BasicAndIo->BasicInfo.TotalTerminatedProcesses += Child->TotalTerminatedProcesses;
        BasicAndIo->IoInfo.ReadOperationCount += Child->ReadOperationCount;
        BasicAndIo->IoInfo.WriteOperationCount += Child->WriteOperationCount;
        BasicAndIo->IoInfo.OtherOperationCount += Child->OtherOperationCount;
        BasicAndIo->IoInfo.ReadTransferCount += Child->ReadTransferCount;
        BasicAndIo->IoInfo.WriteTransferCount += Child->WriteTransferCount;
        BasicAndIo->IoInfo.OtherTransferCount += Child->OtherTransferCount;

        PspAccumulateJobProcessAccountingLocked(Child, BasicAndIo);

        ExReleaseResourceAndLeaveCriticalRegion(&Child->JobLock);
    }
}

static
NTSTATUS
PspQueryJobBasicAccountingInfo(
    _In_ PEJOB Job,
    _Out_ PJOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION BasicAndIo
)
{
    /* Zero the basic accounting information */
    RtlZeroMemory(&BasicAndIo->BasicInfo, sizeof(BasicAndIo->BasicInfo));

    /* Lock the job object */
    ExEnterCriticalRegionAndAcquireResourceShared(&Job->JobLock);

    /* Initialize with job's accumulated accounting data */
    BasicAndIo->BasicInfo.TotalUserTime.QuadPart = Job->TotalUserTime.QuadPart;
    BasicAndIo->BasicInfo.TotalKernelTime.QuadPart = Job->TotalKernelTime.QuadPart;
    BasicAndIo->BasicInfo.ThisPeriodTotalUserTime.QuadPart = Job->ThisPeriodTotalUserTime.QuadPart;
    BasicAndIo->BasicInfo.ThisPeriodTotalKernelTime.QuadPart = Job->ThisPeriodTotalKernelTime.QuadPart;
    BasicAndIo->BasicInfo.TotalPageFaultCount = Job->TotalPageFaultCount;
    BasicAndIo->BasicInfo.TotalProcesses = Job->TotalProcesses;
    BasicAndIo->BasicInfo.ActiveProcesses = Job->ActiveProcesses;
    BasicAndIo->BasicInfo.TotalTerminatedProcesses = Job->TotalTerminatedProcesses;

    /* Set I/O info (even though it may not be returned in some cases) */
    BasicAndIo->IoInfo.ReadOperationCount = Job->ReadOperationCount;
    BasicAndIo->IoInfo.WriteOperationCount = Job->WriteOperationCount;
    BasicAndIo->IoInfo.OtherOperationCount = Job->OtherOperationCount;
    BasicAndIo->IoInfo.ReadTransferCount = Job->ReadTransferCount;
    BasicAndIo->IoInfo.WriteTransferCount = Job->WriteTransferCount;
    BasicAndIo->IoInfo.OtherTransferCount = Job->OtherTransferCount;

    /* Sum up accounting data for the processes of the job and its children */
    PspAccumulateJobProcessAccountingLocked(Job, BasicAndIo);

    /* Release the job lock */
    ExReleaseResourceAndLeaveCriticalRegion(&Job->JobLock);

    return STATUS_SUCCESS;
}

/*!
 * Retrieves basic or extended limit information for a job object.
 *
 * @param[in] Job
 *     Pointer to the job object whose limit information is being queried.
 *
 * @param[in] Extended
 *     A boolean value indicating whether extended limit information is being
 *     requested or only basic limit information.
 *
 * @param[out] ExtendedLimit
 *     Pointer to a structure that will be filled with basic or extended limit
 *     information about the job.
 *
 * @return
 *     STATUS_SUCCESS on success.
 *     Otherwise, an appropriate NTSTATUS error code.
 */
static
NTSTATUS
PspQueryJobLimitInformation(
    _In_ PEJOB Job,
    _In_ BOOLEAN Extended,
    _Out_ PJOBOBJECT_EXTENDED_LIMIT_INFORMATION ExtendedLimit
)
{
    PKTHREAD CurrentThread = KeGetCurrentThread();

    /* Lock the job object */
    KeEnterGuardedRegionThread(CurrentThread);
    ExAcquireResourceSharedLite(&Job->JobLock, TRUE);

    /* Copy basic limit information */
    ExtendedLimit->BasicLimitInformation.LimitFlags = Job->LimitFlags;
    ExtendedLimit->BasicLimitInformation.MinimumWorkingSetSize = Job->MinimumWorkingSetSize;
    ExtendedLimit->BasicLimitInformation.MaximumWorkingSetSize = Job->MaximumWorkingSetSize;
    ExtendedLimit->BasicLimitInformation.ActiveProcessLimit = Job->ActiveProcessLimit;
    ExtendedLimit->BasicLimitInformation.PriorityClass = Job->PriorityClass;
    ExtendedLimit->BasicLimitInformation.SchedulingClass = Job->SchedulingClass;
    ExtendedLimit->BasicLimitInformation.Affinity = Job->Affinity;
    ExtendedLimit->BasicLimitInformation.PerProcessUserTimeLimit.QuadPart = Job->PerProcessUserTimeLimit.QuadPart;
    ExtendedLimit->BasicLimitInformation.PerJobUserTimeLimit.QuadPart = Job->PerJobUserTimeLimit.QuadPart;

    /* If extended limits are requested, include memory limits */
    if (Extended)
    {
        KeAcquireGuardedMutexUnsafe(&Job->MemoryLimitsLock);

        ExtendedLimit->ProcessMemoryLimit = Job->ProcessMemoryLimit << PAGE_SHIFT;
        ExtendedLimit->JobMemoryLimit = Job->JobMemoryLimit << PAGE_SHIFT;
        ExtendedLimit->PeakProcessMemoryUsed = Job->PeakProcessMemoryUsed << PAGE_SHIFT;
        ExtendedLimit->PeakJobMemoryUsed = Job->PeakJobMemoryUsed << PAGE_SHIFT;

        KeReleaseGuardedMutexUnsafe(&Job->MemoryLimitsLock);

        /* Zero out IoInfo to avoid kernel memory leaks */
        RtlZeroMemory(&ExtendedLimit->IoInfo, sizeof(ExtendedLimit->IoInfo));
    }

    /* Release the job lock */
    ExReleaseResourceLite(&Job->JobLock);
    KeLeaveGuardedRegionThread(CurrentThread);

    return STATUS_SUCCESS;
}

/*!
 * Callback function used to collect the process IDs for all active processes
 * in a job object.
 *
 * @param[in] Process
 *     A pointer to the process whose ID is being added to the process list.
 *
 * @param[in, out] Context
 *     A pointer to the context structure that tracks the process ID collection.
 *     This context holds the list of process IDs, the length of the buffer,
 *     and the status of the collection operation.
 *
 * @return
 *     STATUS_SUCCESS on successful collection of the process ID.
 *     Otherwise, an appropriate NTSTATUS error code if the buffer is
 *     insufficient or another error occurs.
 */
static
NTSTATUS
NTAPI
PspQueryJobProcessIdListCallback(
    _In_ PEPROCESS Process,
    _Inout_ PVOID Context
)
{
    PPSP_QUERY_JOB_PROCESS_ID_CONTEXT QueryContext = (PPSP_QUERY_JOB_PROCESS_ID_CONTEXT)Context;

    /* Skip processes that are not really active */
    if (FlagOn(Process->JobStatus, PSP_JOB_NOT_REALLY_ACTIVE))
    {
        /* Continue to the next process */
        return STATUS_SUCCESS;
    }

    /* An active process may be linked before its process identifier has been
       assigned - such a process is not representable in this information class */
    if (Process->UniqueProcessId == NULL)
    {
        ASSERT(QueryContext->ProcessIdList->NumberOfAssignedProcesses != 0);

        QueryContext->ProcessIdList->NumberOfAssignedProcesses--;

        return STATUS_SUCCESS;
    }

    if (QueryContext->RemainingLength < sizeof(ULONG_PTR))
    {
        return STATUS_BUFFER_OVERFLOW;
    }

    *QueryContext->NextProcessId++ = (ULONG_PTR)Process->UniqueProcessId;

    QueryContext->RemainingLength -= sizeof(ULONG_PTR);

    QueryContext->ProcessIdList->NumberOfProcessIdsInList++;

    return STATUS_SUCCESS;
}

/*!
 * Collects a list of process IDs for all processes associated with a job.
 *
 * @param[in] Job
 *     Pointer to the job object whose process IDs are being queried.
 *
 * @param[out] ProcIdList
 *     Pointer to a structure that will be filled with the list of process IDs
 *     and information about the number of assigned and returned process IDs.
 *
 * @param[in] JobInformationLength
 *     Specifies the size, in bytes, of the buffer that will receive the process
 *     ID list.
 *
 * @param[out] ReturnRequiredLength
 *     Pointer to a variable that receives the size, in bytes, of the
 *     information written to the buffer. If there is a buffer overflow, the
 *     required size is returned.
 *
 * @return
 *     STATUS_SUCCESS on success.
 *     STATUS_BUFFER_OVERFLOW if the buffer is too small to hold all IDs.
 *     Otherwise, an appropriate NTSTATUS error code.
 */
static
NTSTATUS
PspQueryJobProcessIdList(
    _In_ PEJOB Job,
    _Out_writes_bytes_(JobInformationLength) PJOBOBJECT_BASIC_PROCESS_ID_LIST ProcIdList,
    _In_ ULONG JobInformationLength,
    _Out_ PULONG ReturnRequiredLength
)
{
    NTSTATUS Status;
    PSP_QUERY_JOB_PROCESS_ID_CONTEXT QueryContext;

    /* Check if the buffer provided is large enough to hold at least the
       fixed portion of JOBOBJECT_BASIC_PROCESS_ID_LIST */
    if (JobInformationLength < sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST))
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    QueryContext.ProcessIdList = ProcIdList;
    QueryContext.NextProcessId = &ProcIdList->ProcessIdList[0];
    QueryContext.RemainingLength = JobInformationLength - FIELD_OFFSET(JOBOBJECT_BASIC_PROCESS_ID_LIST,
                                                                       ProcessIdList);

    Status = STATUS_SUCCESS;

    ExEnterCriticalRegionAndAcquireResourceShared(&Job->JobLock);

    _SEH2_TRY
    {
        ProcIdList->NumberOfAssignedProcesses = Job->ActiveProcesses;
        ProcIdList->NumberOfProcessIdsInList = 0;

        Status = PspEnumerateProcessesInJobHierarchyLocked(Job,
                                                           PspQueryJobProcessIdListCallback,
                                                           &QueryContext);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;

    ExReleaseResourceAndLeaveCriticalRegion(&Job->JobLock);

    if (NT_SUCCESS(Status) || Status == STATUS_BUFFER_OVERFLOW)
    {
        /* Report the bytes actually written */
        *ReturnRequiredLength = (ULONG)(JobInformationLength - QueryContext.RemainingLength);
    }
    else
    {
        *ReturnRequiredLength = 0;
    }

    return Status;
}

/*
 * @implemented
 */
PVOID
NTAPI
PsGetJobLock(PEJOB Job)
{
    ASSERT(Job);
    return (PVOID)&Job->JobLock;
}

/*
 * @implemented
 */
ULONG
NTAPI
PsGetJobSessionId(PEJOB Job)
{
    ASSERT(Job);
    return Job->SessionId;
}

/*
 * @implemented
 */
ULONG
NTAPI
PsGetJobUIRestrictionsClass(PEJOB Job)
{
    ASSERT(Job);
    return Job->UIRestrictionsClass;
}

/*
 * @implemented
 */
VOID
NTAPI
PsSetJobUIRestrictionsClass(
    PEJOB Job,
    ULONG UIRestrictionsClass
)
{
    ASSERT(Job);
    (void)InterlockedExchangeUL(&Job->UIRestrictionsClass, UIRestrictionsClass);
}

/*!
 * Invokes the win32k job callout, if win32k has registered one.
 *
 * @param[in] Job
 *     A pointer to the job object the callout applies to.
 *
 * @param[in] CalloutType
 *     The operation win32k is being asked to perform.
 *
 * @param[in, optional] Data
 *     Class specific data. For PsW32JobCalloutSetInformation this is the new
 *     UI restrictions class, for PsW32JobCalloutAddProcess the W32PROCESS of
 *     the process being added to the job.
 *
 * @returns
 *     The status returned by win32k, or STATUS_SUCCESS when no callout has
 *     been registered (i.e. the win32 subsystem is not loaded yet).
 *
 * @remarks
 *     FIXME: TODO: We do not attach to the session of the job, as win32k is only ever
 *     loaded in one session.
 */
NTSTATUS
NTAPI
PspInvokeW32JobCallout(
    _In_ PEJOB Job,
    _In_ PSW32JOBCALLOUTTYPE CalloutType,
    _In_opt_ PVOID Data
)
{
    WIN32_JOBCALLOUT_PARAMETERS Parameters;

    /* Nothing to do if win32k has not registered a callout */
    if (PspW32JobCallout == NULL)
    {
        return STATUS_SUCCESS;
    }

    Parameters.Job = Job;
    Parameters.CalloutType = CalloutType;
    Parameters.Data = Data;

    return PspW32JobCallout(&Parameters);
}

/*!
 * Applies a new basic UI restrictions class to a job object.
 *
 * @param[in] Job
 *     A pointer to the job object being modified.
 *
 * @param[in] UIRestrictionsClass
 *     The new set of JOB_OBJECT_UILIMIT_* flags.
 *
 * @returns
 *     STATUS_SUCCESS if the restrictions were applied.
 *     STATUS_INVALID_PARAMETER if unknown restriction flags were given.
 *     An appropriate NTSTATUS error code otherwise.
 *
 * @remarks
 *     The restrictions are only stored once win32k has accepted them, as it
 *     may fail to allocate the per-job state it needs to enforce them.
 */
static
NTSTATUS
PspSetJobUIRestrictions(
    _In_ PEJOB Job,
    _In_ ULONG UIRestrictionsClass
)
{
    NTSTATUS Status = STATUS_SUCCESS;

    /* Reject restrictions we do not know about */
    if (UIRestrictionsClass & ~JOB_OBJECT_UILIMIT_ALL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    ExEnterCriticalRegionAndAcquireResourceExclusive(&Job->JobLock);

    /* Only bother win32k if something actually changes */
    if (Job->UIRestrictionsClass != UIRestrictionsClass)
    {
        Status = PspInvokeW32JobCallout(Job,
                                        PsW32JobCalloutSetInformation,
                                        UlongToPtr(UIRestrictionsClass));
        if (NT_SUCCESS(Status))
        {
            Job->UIRestrictionsClass = UIRestrictionsClass;
        }
    }

    ExReleaseResourceAndLeaveCriticalRegion(&Job->JobLock);

    return Status;
}

/*!
 * Creates a job object.
 *
 * @param[out] JobHandle
 *     A pointer to a handle that will receive the handle of the created job object.
 *
 * @param[in] DesiredAccess
 *     Specifies the desired access rights for the job object.
 *
 * @param[in, optional] ObjectAttributes
 *     An optional pointer to an object attributes block
 *
 * @returns
 *     STATUS_SUCCESS if the job object is successfully created.
 *     An appropriate NTSTATUS error code otherwise.
 */
NTSTATUS
NTAPI
NtCreateJobObject(
    _Out_ PHANDLE JobHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes
)
{
    HANDLE Handle;
    PEJOB Job;
    KPROCESSOR_MODE PreviousMode;
    PEPROCESS CurrentProcess;
    NTSTATUS Status;

    PAGED_CODE();

    PreviousMode = ExGetPreviousMode();
    CurrentProcess = PsGetCurrentProcess();

    /* Check for valid buffers */
    if (PreviousMode != KernelMode)
    {
        _SEH2_TRY
        {
            ProbeForWriteHandle(JobHandle);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            return _SEH2_GetExceptionCode();
        }
        _SEH2_END;
    }

    /* Create the job object */
    Status = ObCreateObject(PreviousMode,
                            PsJobType,
                            ObjectAttributes,
                            PreviousMode,
                            NULL,
                            sizeof(EJOB),
                            0,
                            0,
                            (PVOID *)&Job);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Failed to create job object, Status 0x%08lx\n", Status);

        /* Windows stores NULL in the caller's handle when the call fails; it was probed above */
        _SEH2_TRY
        {
            *JobHandle = NULL;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* The variable went away meanwhile; keep the failure status */
        }
        _SEH2_END;
        return Status;
    }

    /* Initialize the job object */

    RtlZeroMemory(Job, sizeof(*Job));

    InitializeListHead(&Job->JobSetLinks);
    InitializeListHead(&Job->ProcessListHead);
    InitializeListHead(&Job->ChildJobsHead);
    InitializeListHead(&Job->ChildJobsLinks);

    /* Make sure that early destruction doesn't attempt to remove
       the object from the list before it even gets added */
    InitializeListHead(&Job->JobLinks);

    /* Inherit the session ID from the caller */
    Job->SessionId = PsGetProcessSessionId(CurrentProcess);

    /* Initialize the job limits lock */
    KeInitializeGuardedMutex(&Job->MemoryLimitsLock);

    /* Initialize the job lock */
    (VOID)ExInitializeResource(&Job->JobLock);

    /* Initialize the event object within the job */
    KeInitializeEvent(&Job->Event, NotificationEvent, FALSE);

    /* Set the scheduling class */
    Job->SchedulingClass = PSP_JOB_SCHEDULING_CLASS_DEFAULT;

    /* Link the object into the global job list */
    ExAcquireFastMutex(&PsJobListLock);
    InsertTailList(&PsJobListHead, &Job->JobLinks);
    ExReleaseFastMutex(&PsJobListLock);

    /* Insert the job object into the object table  */
    Status = ObInsertObject(Job,
                            NULL,
                            DesiredAccess,
                            0,
                            NULL,
                            &Handle);

    if (NT_SUCCESS(Status))
    {
        /* Pass the handle back to the caller */
        _SEH2_TRY
        {
            *JobHandle = Handle;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = _SEH2_GetExceptionCode();
        }
        _SEH2_END;
    }
    else
    {

        /* Windows stores NULL in the caller's handle when the call fails; it was probed above */
        _SEH2_TRY
        {
            *JobHandle = NULL;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* The variable went away meanwhile; keep the failure status */
        }
        _SEH2_END;
    }

    return Status;
}

NTSTATUS
NTAPI
NtCreateJobSet(IN ULONG NumJob,
               IN PJOB_SET_ARRAY UserJobSet,
               IN ULONG Flags)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

/*!
 * Opens a handle to an existing job object.
 *
 * @param JobHandle
 *     A pointer to a handle that will receive the handle of the created job
 *     object.
 *
 * @param DesiredAccess
 *     Specifies the desired access rights for the job object.
 *
 * @param ObjectAttributes
 *     Pointer to the OBJECT_ATTRIBUTES structure specifying the object name and
 *     attributes.
 *
 * @returns
 *     STATUS_SUCCESS if the job object is successfully created.
 *     An appropriate NTSTATUS error code otherwise.
 */
NTSTATUS
NTAPI
NtOpenJobObject(
    _Out_ PHANDLE JobHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
)
{
    KPROCESSOR_MODE PreviousMode;
    HANDLE Handle;
    NTSTATUS Status;

    PAGED_CODE();

    PreviousMode = ExGetPreviousMode();

    /* Check for valid buffers */
    if (PreviousMode != KernelMode)
    {
        _SEH2_TRY
        {
            ProbeForWriteHandle(JobHandle);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }

    Status = ObOpenObjectByName(ObjectAttributes,
                                PsJobType,
                                PreviousMode,
                                NULL,
                                DesiredAccess,
                                NULL,
                                &Handle);
    if (NT_SUCCESS(Status))
    {
        _SEH2_TRY
        {
            *JobHandle = Handle;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = _SEH2_GetExceptionCode();
        }
        _SEH2_END;
    }

    return Status;
}

/*!
 * Assigns a process to a job object.
 *
 * @param[in] JobHandle
 *     Handle to the job object.
 *
 * @param[in] ProcessHandle
 *     Handle to the process to be assigned.
 *
 * @returns
 *     STATUS_SUCCESS if the process is successfully assigned to the job.
 *     An appropriate NTSTATUS error code otherwise.
 */
NTSTATUS
NTAPI
NtAssignProcessToJobObject(
    _In_ HANDLE JobHandle,
    _In_ HANDLE ProcessHandle
)
{
    PEPROCESS Process;
    PEJOB Job;
    KPROCESSOR_MODE PreviousMode;
    ULONG SessionId;
    NTSTATUS Status;
    BOOLEAN WasInJob;

    PAGED_CODE();

    PreviousMode = ExGetPreviousMode();

    /* Reference the job. JOB_OBJECT_ASSIGN_PROCESS rights are required
       for assignment */
    Status = ObReferenceObjectByHandle(JobHandle,
                                       JOB_OBJECT_ASSIGN_PROCESS,
                                       PsJobType,
                                       PreviousMode,
                                       (PVOID *)&Job,
                                       NULL);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    /* Reference the process. The handle must have the PROCESS_SET_QUOTA and 
       PROCESS_TERMINATE access rights. */
    Status = ObReferenceObjectByHandle(ProcessHandle,
                                       PROCESS_SET_QUOTA | PROCESS_TERMINATE,
                                       PsProcessType,
                                       PreviousMode,
                                       (PVOID *)&Process,
                                       NULL);
    if (!NT_SUCCESS(Status))
    {
        ObDereferenceObject(Job);
        return Status;
    }

    /* Get the session ID - it must match the process and the job creator */
    SessionId = PsGetProcessSessionId(Process);

    if (SessionId != Job->SessionId)
    {
        /* Return STATUS_ACCESS_DENIED if the session ID is different */
        ObDereferenceObject(Job);
        ObDereferenceObject(Process);
        return STATUS_ACCESS_DENIED;
    }

    /* A process that already is in a job is nested into the new job, which
       Windows accepts when the jobs form a hierarchy. A failure then leaves
       the process as it was (verified on Windows 10 for a full active process
       limit); only a process that has not been in a job is terminated. */
    WasInJob = (Process->Job != NULL);

    Status = PspAssignProcessToJob(Process, Job);

    if (Status == STATUS_QUOTA_EXCEEDED && !WasInJob)
    {
        /* Preserve the assignment failure */
        (VOID)PsTerminateProcess(Process, STATUS_QUOTA_EXCEEDED);
    }

    ObDereferenceObject(Job);
    ObDereferenceObject(Process);

    return Status;
}

/*!
 * Determines if a specified process is associated with a specified or any job.
 *
 * @param[in] ProcessHandle
 *     A handle to the process being queried.
 *
 * @param[in, optional] JobHandle
 *     An optional handle to the job object being compared. If NULL,
 *     the function checks if the process is associated with any job.
 *
 * @returns
 *     STATUS_PROCESS_IN_JOB if the process is in the job or any job (when
 *     JobHandle is NULL).
 *     STATUS_PROCESS_NOT_IN_JOB if the process is not in the job or any job.
 *     Otherwise, an appropriate NTSTATUS error code.
 */
NTSTATUS
NTAPI
NtIsProcessInJob(
    _In_ HANDLE ProcessHandle,
    _In_opt_ HANDLE JobHandle
)
{
    KPROCESSOR_MODE PreviousMode;
    PEPROCESS Process;
    PEJOB ProcessJob;
    PEJOB JobObjectFromHandle;
    NTSTATUS Status;

    PreviousMode = ExGetPreviousMode();

    PAGED_CODE();

    /* Check if the process handle is the current process */
    if (ProcessHandle == NtCurrentProcess())
    {
        /* If so, directly use the current process object */
        Process = PsGetCurrentProcess();
    }
    else
    {
        /* Reference the process object by handle */
        Status = ObReferenceObjectByHandle(ProcessHandle,
                                           PROCESS_QUERY_INFORMATION,
                                           PsProcessType,
                                           PreviousMode,
                                           (PVOID *)&Process,
                                           NULL);
        if (!NT_SUCCESS(Status))
        {
            return Status;
        }
    }

    /* Get the job object associated with the process */
    ProcessJob = Process->Job;

    if (ProcessJob != NULL)
    {
        /* If no specific job handle is provided,
           the process is assigned to a job */
        if (JobHandle == NULL)
        {
            Status = STATUS_PROCESS_IN_JOB;
        }
        else
        {
            /* Get the job object from the provided job handle
               and compare it with the process job */
            Status = ObReferenceObjectByHandle(JobHandle,
                                               JOB_OBJECT_QUERY,
                                               PsJobType,
                                               PreviousMode,
                                               (PVOID *)&JobObjectFromHandle,
                                               NULL);
            if (NT_SUCCESS(Status))
            {
                /* The process is in the job it is directly assigned to and in
                   all of that job's ancestors */
                if (PspIsJobInHierarchy(ProcessJob, JobObjectFromHandle))
                {
                    Status = STATUS_PROCESS_IN_JOB;
                }
                else
                {
                    Status = STATUS_PROCESS_NOT_IN_JOB;
                }

                /* Dereference the job object handle */
                ObDereferenceObject(JobObjectFromHandle);
            }
        }
    }
    else
    {
        /* The process is not assigned to any job */
        Status = STATUS_PROCESS_NOT_IN_JOB;
    }

    /* Dereference the process object if it was referenced */
    if (ProcessHandle != NtCurrentProcess())
    {
        ObDereferenceObject(Process);
    }

    return Status;
}

/*!
 * Terminates all processes currently associated with the specified job object.
 *
 * @param[in] JobHandle
 *     A handle to the job object to be terminated.
 *
 * @param[in] ExitStatus
 *     The exit status to be used for all terminated processes.
 *
 * @returns
 *     STATUS_SUCCESS if the job object was successfully terminated.
 *     Otherwise, an appropriate NTSTATUS error code.
 */
NTSTATUS
NTAPI
NtTerminateJobObject(
    _In_ HANDLE JobHandle,
    _In_ NTSTATUS ExitStatus
)
{
    KPROCESSOR_MODE PreviousMode;
    PEJOB Job;
    NTSTATUS Status;

    PAGED_CODE();

    PreviousMode = ExGetPreviousMode();

    Status = ObReferenceObjectByHandle(JobHandle,
                                       JOB_OBJECT_TERMINATE,
                                       PsJobType,
                                       PreviousMode,
                                       (PVOID *)&Job,
                                       NULL);
    if (NT_SUCCESS(Status))
    {
        Status = PspTerminateJobObject(Job, ExitStatus);
        ObDereferenceObject(Job);
    }

    return Status;
}

/*!
 * Retrieves information about a job object based on the requested information
 * class.
 *
 * @param[in, optional] JobHandle
 *     Handle to the job object for which information is being queried. The
 *     handle must have the JOB_OBJECT_QUERY access right. If NULL, the current
 *     process' job is used.
 *
 * @param[in] JobInformationClass
 *     Specifies the type of information to query.
 *
 * @param[out] JobInformation
 *     Pointer to a buffer that receives the requested job object information.
 *
 * @param[in] JobInformationLength
 *     Specifies the size, in bytes, of the JobInformation buffer.
 *
 * @param[out, optional] ReturnLength
 *     Pointer to a variable that receives the size, in bytes, of the
 *     information written to the JobInformation buffer. Specify NULL to not
 *     receive this information.
 *
 * @return
 *     STATUS_SUCCESS on success.
 *     Otherwise, an appropriate NTSTATUS error code.
 *
 * @remarks
 *     Not fully implemented. The function currently does not support all
 *     information classes.
 */
NTSTATUS
NTAPI
NtQueryInformationJobObject(
    _In_opt_ HANDLE JobHandle,
    _In_ JOBOBJECTINFOCLASS JobInformationClass,
    _Out_writes_bytes_(JobInformationLength) PVOID JobInformation,
    _In_ ULONG JobInformationLength,
    _Out_opt_ PULONG ReturnLength
)
{
    PEJOB Job;
    NTSTATUS Status;
    BOOLEAN NoOutput;
    PVOID JobInfoBuffer;
    PKTHREAD CurrentThread;
    KPROCESSOR_MODE PreviousMode;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION ExtendedLimit;
    JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION BasicAndIo;
    JOBOBJECT_BASIC_UI_RESTRICTIONS UiRestrictions;
    GROUP_AFFINITY GroupAffinity;
    PS_JOB_CPU_RATE_CONTROL_INFORMATION CpuRate;
    ULONG RequiredLength, RequiredAlign, ReturnRequiredLength;
    BOOLEAN ExtraClass;

    PAGED_CODE();

    CurrentThread  = KeGetCurrentThread();

    ExtraClass = (JobInformationClass == PspJobObjectGroupInformation ||
                  JobInformationClass == PspJobObjectGroupInformationEx ||
                  JobInformationClass == PspJobObjectCpuRateControlInformation);

    /* Validate that JobInformationClass is in the expected range */
    if (!ExtraClass &&
        (JobInformationClass > JobObjectJobSetInformation ||
         JobInformationClass < JobObjectBasicAccountingInformation))
    {
        return STATUS_INVALID_INFO_CLASS;
    }

    /* Determine the required length and alignment for the class */
    if (!ExtraClass)
    {
        RequiredLength = PspJobInfoLengths[JobInformationClass];
        RequiredAlign = PspJobInfoAlign[JobInformationClass];
    }
    else if (JobInformationClass == PspJobObjectGroupInformation)
    {
        /* An array of group numbers: empty without a group assignment, so any buffer that holds
           one number does, and none is written */
        RequiredLength = 0;
        RequiredAlign = sizeof(USHORT);
        if (JobInformationLength < sizeof(USHORT))
            return STATUS_INFO_LENGTH_MISMATCH;
    }
    else if (JobInformationClass == PspJobObjectGroupInformationEx)
    {
        /* An array of group affinities: one entry, the active processors of group 0. The length
           is a whole number of entries (checked after the probe, as it reports a length) */
        RequiredLength = sizeof(GROUP_AFFINITY);
        RequiredAlign = sizeof(ULONG);
    }
    else
    {
        RequiredLength = sizeof(CpuRate);
        RequiredAlign = sizeof(ULONG);
    }
    ReturnRequiredLength = RequiredLength;

    /* If length mismatch (needed versus provided) */
    if (JobInformationClass != PspJobObjectGroupInformation &&
        JobInformationClass != PspJobObjectGroupInformationEx &&
        JobInformationLength != RequiredLength)
    {
        /* This can only be accepted if the class is variable length
           (JobObjectBasicProcessIdList or JobObjectSecurityLimitInformation) or
           if size is bigger than needed */
        if ((JobInformationClass != JobObjectBasicProcessIdList &&
                JobInformationClass != JobObjectSecurityLimitInformation) ||
            JobInformationLength < RequiredLength)
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        /* Set what we need to copy out */
        RequiredLength = JobInformationLength;
    }

    PreviousMode = ExGetPreviousMode();

    /* If the request is coming from user mode, probe the user buffer */
    if (PreviousMode != KernelMode)
    {
        ASSERT(RequiredAlign == 1 ||
               RequiredAlign == 2 ||
               RequiredAlign == 4 ||
               RequiredAlign == 8 ||
               RequiredAlign == 16);

        _SEH2_TRY
        {
            /* Probe the buffer */
            if (JobInformation != NULL)
            {
                ProbeForWrite(JobInformation, JobInformationLength, RequiredAlign);
            }

            /* Probe the return length if required */
            if (ReturnLength != NULL)
            {
                ProbeForWriteUlong(ReturnLength);
            }
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }

    /* The length of a group affinity array is a whole number of entries. Windows answers a zero
       length with the size it needs (the callers size their buffer with it) and any other
       length that is not a multiple with an invalid parameter, reporting the length it saw */
    if (JobInformationClass == PspJobObjectGroupInformationEx &&
        (JobInformationLength == 0 || (JobInformationLength % sizeof(GROUP_AFFINITY)) != 0))
    {
        _SEH2_TRY
        {
            if (ReturnLength != NULL)
            {
                *ReturnLength = JobInformationLength ? JobInformationLength : sizeof(GROUP_AFFINITY);
            }
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;

        return JobInformationLength ? STATUS_INVALID_PARAMETER : STATUS_BUFFER_TOO_SMALL;
    }

    /* If a job handle was provided, use it */
    if (JobHandle != NULL)
    {
        Status = ObReferenceObjectByHandle(JobHandle,
                                           JOB_OBJECT_QUERY,
                                           PsJobType,
                                           PreviousMode,
                                           (PVOID *)&Job,
                                           NULL);
        if (!NT_SUCCESS(Status))
        {
            return Status;
        }
    }
    /* Otherwise, get our current process' job, if any */
    else
    {
        PEPROCESS CurrentProcess;

        CurrentProcess = (PEPROCESS)CurrentThread->ApcState.Process;
        Job = CurrentProcess->Job;
        if (Job == NULL)
        {
            return STATUS_ACCESS_DENIED;
        }

        ObReferenceObject(Job);
    }

    /* By default, assume we'll have to copy data */
    NoOutput = FALSE;

    switch ((ULONG)JobInformationClass)
    {
    case JobObjectBasicAccountingInformation:
    case JobObjectBasicAndIoAccountingInformation:
    {
        Status = PspQueryJobBasicAccountingInfo(Job, &BasicAndIo);
        JobInfoBuffer = &BasicAndIo;
        break;
    }
    case JobObjectBasicLimitInformation:
    case JobObjectExtendedLimitInformation:
    {
        Status = PspQueryJobLimitInformation(Job,
                                             JobInformationClass == JobObjectExtendedLimitInformation,
                                             &ExtendedLimit);
        JobInfoBuffer = &ExtendedLimit;
        break;
    }
    case JobObjectBasicProcessIdList:
    {
        Status = PspQueryJobProcessIdList(Job,
                                          (PJOBOBJECT_BASIC_PROCESS_ID_LIST)JobInformation,
                                          JobInformationLength,
                                          &ReturnRequiredLength);

        /* No need to copy data as it's directly filled in the helper */
        NoOutput = TRUE;
        break;
    }
    case JobObjectBasicUIRestrictions:
    {
        UiRestrictions.UIRestrictionsClass = Job->UIRestrictionsClass;
        JobInfoBuffer = &UiRestrictions;
        break;
    }
    case PspJobObjectGroupInformation:
    {
        /* No group assignment: an empty array */
        Status = STATUS_SUCCESS;
        ReturnRequiredLength = 0;
        NoOutput = TRUE;
        break;
    }
    case PspJobObjectGroupInformationEx:
    {
        RtlZeroMemory(&GroupAffinity, sizeof(GroupAffinity));
        GroupAffinity.Mask = KeActiveProcessors;
        GroupAffinity.Group = 0;
        Status = STATUS_SUCCESS;
        JobInfoBuffer = &GroupAffinity;
        break;
    }
    case PspJobObjectCpuRateControlInformation:
    {
        /* Rate control is not enabled on any job */
        RtlZeroMemory(&CpuRate, sizeof(CpuRate));
        Status = STATUS_SUCCESS;
        JobInfoBuffer = &CpuRate;
        break;
    }
    case JobObjectSecurityLimitInformation:
    case JobObjectEndOfJobTimeInformation:
    case JobObjectAssociateCompletionPortInformation:
    case JobObjectJobSetInformation:
        DPRINT1("Class %d not implemented\n", JobInformationClass);
        Status = STATUS_NOT_IMPLEMENTED;
        break;
    default:
        DPRINT1("Invalid class %d\n", JobInformationClass);
        Status = STATUS_NOT_IMPLEMENTED;
        break;
    }

    /* Job is no longer required */
    ObDereferenceObject(Job);

    /* If we succeeded, copy back data */
    if (NT_SUCCESS(Status))
    {
        _SEH2_TRY
        {
            /* If we have anything to copy, do it */
            if (!NoOutput)
            {
                RtlCopyMemory(JobInformation, JobInfoBuffer, RequiredLength);
            }

            /* And return length if asked */
            if (ReturnLength != NULL)
            {
                *ReturnLength = ReturnRequiredLength;
            }
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }

    return Status;
}

/*!
 * Sets the information for a job object, updating the specified job object
 * limits.
 *
 * This function is called to modify various job object limits, including basic
 * limits, extended limits, security limits, and other job-specific settings.
 *
 * @param[in] JobHandle
 *     A handle to the job object that is being modified. The handle must have
 *     the JOB_OBJECT_SET_ATTRIBUTES access right.
 *
 * @param[in] JobInformationClass
 *     The class of information to set. This determines the structure and
 *     content of the JobInformation parameter.
 *
 * @param[in] JobInformation
 *     A pointer to a buffer that contains the information to be set. The type
 *     and content of the buffer depend on the value of JobInformationClass.
 *
 * @param[in] JobInformationLength
 *     The size of the buffer pointed to by JobInformation, in bytes.
 *
 * @return
 *     STATUS_SUCCESS on success.
 *     Otherwise, an appropriate NTSTATUS error code.
 *
 * @remarks
 *     Not fully implemented. The function currently does not support all
 *     information classes.
 */
NTSTATUS
NTAPI
NtSetInformationJobObject(
    _In_ HANDLE JobHandle,
    _In_ JOBOBJECTINFOCLASS JobInformationClass,
    _In_reads_bytes_(JobInformationLength) PVOID JobInformation,
    _In_ ULONG JobInformationLength
)
{
    PEJOB Job;
    NTSTATUS Status;
    PKTHREAD CurrentThread;
    ACCESS_MASK DesiredAccess;
    KPROCESSOR_MODE PreviousMode;
    ULONG RequiredLength, RequiredAlign;

    PAGED_CODE();

    CurrentThread = KeGetCurrentThread();

    /* Validate that JobInformationClass is in the expected range */
    if (JobInformationClass > JobObjectJobSetInformation ||
        JobInformationClass < JobObjectBasicAccountingInformation)
    {
        return STATUS_INVALID_INFO_CLASS;
    }

    /* Determine the required length and alignment for the class */
    RequiredLength = PspJobInfoLengths[JobInformationClass];
    RequiredAlign = PspJobInfoAlign[JobInformationClass];

    PreviousMode = ExGetPreviousMode();

    /* If the request is coming from user mode, probe the user buffer */
    if (PreviousMode != KernelMode)
    {
        ASSERT(RequiredAlign == 1 ||
               RequiredAlign == 2 ||
               RequiredAlign == 4 ||
               RequiredAlign == 8 ||
               RequiredAlign == 16);

        _SEH2_TRY
        {
            /* Probe out buffer for read */
            if (JobInformationLength != 0)
            {
                ProbeForRead(JobInformation, JobInformationLength, RequiredAlign);
            }
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }

    /* Validate that the provided buffer length matches the expected size
       for the class */
    if (JobInformationLength != RequiredLength)
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    DesiredAccess = JOB_OBJECT_SET_ATTRIBUTES;

    /* If setting security limits, additional security access rights
       are required */
    if (JobInformationClass == JobObjectSecurityLimitInformation)
    {
        DesiredAccess |= JOB_OBJECT_SET_SECURITY_ATTRIBUTES;
    }

    Status = ObReferenceObjectByHandle(JobHandle,
                                       DesiredAccess,
                                       PsJobType,
                                       PreviousMode,
                                       (PVOID *)&Job,
                                       NULL);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    /* And set the information.
     *
     * N.B. Disable APC delivery for the set operation. The handlers below may
     * acquire locks using unsafe variants which expect the caller to have
     * already established this state.
     */

    KeEnterGuardedRegionThread(CurrentThread);

    switch (JobInformationClass)
    {
    case JobObjectBasicLimitInformation:
    case JobObjectExtendedLimitInformation:
    {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION ExtendedLimit;
        BOOLEAN IsExtendedLimit = JobInformationClass == JobObjectExtendedLimitInformation;

        _SEH2_TRY
        {
            /* If asking for extending limits */
            if (IsExtendedLimit)
            {
                ExtendedLimit = *(PJOBOBJECT_EXTENDED_LIMIT_INFORMATION)JobInformation;
            }
            else
            {
                RtlZeroMemory(&ExtendedLimit, sizeof(ExtendedLimit));
                ExtendedLimit.BasicLimitInformation =
                    *(PJOBOBJECT_BASIC_LIMIT_INFORMATION)JobInformation;
            }
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = _SEH2_GetExceptionCode();
            goto Exit;
        }
        _SEH2_END;

        Status = PspSetJobLimitsBasicOrExtended(Job,
                                                &ExtendedLimit,
                                                IsExtendedLimit);
        goto Exit;
    }
    case JobObjectAssociateCompletionPortInformation:
    {
        JOBOBJECT_ASSOCIATE_COMPLETION_PORT AssociateCpInfo;

        _SEH2_TRY
        {
            RtlCopyMemory(&AssociateCpInfo,
                          JobInformation,
                          sizeof(AssociateCpInfo));
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = _SEH2_GetExceptionCode();
            break;
        }
        _SEH2_END;

        Status = PspAssociateCompletionPortWithJob(Job, &AssociateCpInfo);
        break;
    }
    case JobObjectBasicUIRestrictions:
    {
        JOBOBJECT_BASIC_UI_RESTRICTIONS UiRestrictions;

        _SEH2_TRY
        {
            UiRestrictions = *(PJOBOBJECT_BASIC_UI_RESTRICTIONS)JobInformation;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = _SEH2_GetExceptionCode();
            goto Exit;
        }
        _SEH2_END;

        Status = PspSetJobUIRestrictions(Job, UiRestrictions.UIRestrictionsClass);
        break;
    }
    case JobObjectBasicAccountingInformation:
    case JobObjectBasicAndIoAccountingInformation:
    case JobObjectBasicProcessIdList:
    case JobObjectEndOfJobTimeInformation:
    case JobObjectJobSetInformation:
    case JobObjectSecurityLimitInformation:
        DPRINT1("Class %d not implemented\n", JobInformationClass);
        Status = STATUS_NOT_IMPLEMENTED;
        break;
    case MaxJobObjectInfoClass:
    default:
        DPRINT1("Invalid class %d\n", JobInformationClass);
        Status = STATUS_INVALID_PARAMETER;
        break;
    }

Exit:
    KeLeaveGuardedRegionThread(CurrentThread);

    ObDereferenceObject(Job);

    return Status;
}

/* EOF */
