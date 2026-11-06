/*
 * PROJECT:     ReactOS kernel tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Every process maps the session space of its own session and of
 *              no other one, whoever created it and when (NitroSessions)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#include <kmt_test.h>

/* Exported, not in the headers */
NTKERNELAPI
ULONG
NTAPI
PsGetProcessSessionIdEx(
    _In_ PEPROCESS Process);

NTKERNELAPI
PCHAR
NTAPI
PsGetProcessImageFileName(
    _In_ PEPROCESS Process);

#define MAX_SESSIONS   8
#define MAX_PROCESSES  256
#define PATTERN_BASE   0x53455300UL  /* 'SES' + session id */
/* One page, always touched: MiRemoveMappedPtes does not take untouched
   committed pages of a session view yet */
#define VIEW_SIZE      PAGE_SIZE

#if defined(_M_IX86) && !defined(_X86PAE_)
/*
 * i386: a view mapped now gets a new page table, which a process that copied
 * a stale view of the session at its creation does not have. The page
 * directory entries are compared too: from the view up to the end of session
 * space (PTE_BASE), every entry is private to a session.
 */
#define CHECK_PDES          1
#define TEST_PDE_BASE       0xC0300000UL
#define TEST_PTE_BASE       0xC0000000UL
#define TEST_PDE_SHIFT      22
#define MAX_SESSION_PDES    64
#define PDE_OF(Va)          ((volatile ULONG *)(TEST_PDE_BASE + (((ULONG_PTR)(Va) >> TEST_PDE_SHIFT) << 2)))
#endif

typedef struct _TEST_VIEW
{
    ULONG Session;
    PEPROCESS Member;   /* referenced; a process of the session, not smss */
    PVOID Section;
    PVOID Base;
    ULONG Pattern;
#ifdef CHECK_PDES
    ULONG_PTR PdeStart; /* first address of the compared range */
    ULONG PdeCount;
    ULONG Pdes[MAX_SESSION_PDES]; /* the member's entries, 0 if not valid */
#endif
} TEST_VIEW, *PTEST_VIEW;

#ifdef CHECK_PDES
/* Attached to a process: does it map a page table of View's session? */
static
BOOLEAN
MapsSessionPdes(
    _In_ PTEST_VIEW View)
{
    ULONG i, Pde;

    for (i = 0; i < View->PdeCount; i++)
    {
        Pde = *PDE_OF(View->PdeStart + ((ULONG_PTR)i << TEST_PDE_SHIFT));
        if ((Pde & 1) && View->Pdes[i] && ((Pde >> PAGE_SHIFT) == (View->Pdes[i] >> PAGE_SHIFT)))
            return TRUE;
    }
    return FALSE;
}
#endif

typedef struct _TEST_PROCESS
{
    PEPROCESS Process;  /* referenced */
    ULONG Session;      /* PsGetProcessSessionIdEx: MAXULONG for no session */
} TEST_PROCESS, *PTEST_PROCESS;

/* Every live process, referenced; returns the count */
static
ULONG
SnapshotProcesses(
    _Out_writes_(MAX_PROCESSES) PTEST_PROCESS Processes)
{
    PSYSTEM_PROCESS_INFORMATION Info = NULL, Entry;
    ULONG Size = 256 * 1024, Length, Offset, Try, Count = 0;
    PEPROCESS Process;
    NTSTATUS Status = STATUS_INFO_LENGTH_MISMATCH;

    for (Try = 0; Try < 4; Try++, Size *= 2)
    {
        Info = ExAllocatePoolWithTag(PagedPool, Size, 'tSmM');
        if (!Info)
            return 0;
        Status = ZwQuerySystemInformation(SystemProcessInformation, Info, Size, &Length);
        if (NT_SUCCESS(Status))
            break;
        ExFreePoolWithTag(Info, 'tSmM');
        Info = NULL;
        if (Status != STATUS_INFO_LENGTH_MISMATCH)
            break;
    }
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return 0;

    for (Offset = 0; Count < MAX_PROCESSES; )
    {
        Entry = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)Info + Offset);
        if (Entry->UniqueProcessId &&
            NT_SUCCESS(PsLookupProcessByProcessId(Entry->UniqueProcessId, &Process)))
        {
            if (PsGetProcessExitStatus(Process) == STATUS_PENDING)
            {
                Processes[Count].Process = Process;
                Processes[Count].Session = PsGetProcessSessionIdEx(Process);
                Count++;
            }
            else
            {
                ObDereferenceObject(Process);
            }
        }
        if (!Entry->NextEntryOffset)
            break;
        Offset += Entry->NextEntryOffset;
    }

    ExFreePoolWithTag(Info, 'tSmM');
    return Count;
}

static
BOOLEAN
IsSmss(
    _In_ PEPROCESS Process)
{
    return !_stricmp(PsGetProcessImageFileName(Process), "smss.exe");
}

/* Map one touched page in the session space of View->Member's session */
static
VOID
MapSessionView(
    _Inout_ PTEST_VIEW View)
{
    LARGE_INTEGER MaximumSize;
    KAPC_STATE ApcState;
    SIZE_T ViewSize = 0;
    NTSTATUS Status;

    MaximumSize.QuadPart = VIEW_SIZE;
    Status = MmCreateSection(&View->Section, SECTION_ALL_ACCESS, NULL, &MaximumSize,
                             PAGE_READWRITE, SEC_COMMIT, NULL, NULL);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
    {
        View->Section = NULL;
        return;
    }

    KeStackAttachProcess((PKPROCESS)View->Member, &ApcState);
    ok_eq_ulong(PsGetCurrentProcessSessionId(), View->Session);
    Status = MmMapViewInSessionSpace(View->Section, &View->Base, &ViewSize);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        *(volatile ULONG *)View->Base = View->Pattern;
#ifdef CHECK_PDES
        {
            ULONG i, Pde;

            View->PdeStart = (ULONG_PTR)View->Base & ~((1UL << TEST_PDE_SHIFT) - 1);
            View->PdeCount = (TEST_PTE_BASE - View->PdeStart) >> TEST_PDE_SHIFT;
            if (View->PdeCount > MAX_SESSION_PDES)
                View->PdeCount = MAX_SESSION_PDES;
            for (i = 0; i < View->PdeCount; i++)
            {
                Pde = *PDE_OF(View->PdeStart + ((ULONG_PTR)i << TEST_PDE_SHIFT));
                View->Pdes[i] = (Pde & 1) ? Pde : 0;
            }
        }
#endif
    }
    else
    {
        View->Base = NULL;
    }
    KeUnstackDetachProcess(&ApcState);
}

static
VOID
UnmapSessionView(
    _Inout_ PTEST_VIEW View)
{
    KAPC_STATE ApcState;
    NTSTATUS Status;

    if (View->Base)
    {
        KeStackAttachProcess((PKPROCESS)View->Member, &ApcState);
        Status = MmUnmapViewInSessionSpace(View->Base);
        ok_eq_hex(Status, STATUS_SUCCESS);
        KeUnstackDetachProcess(&ApcState);
    }
    if (View->Section)
        ObDereferenceObject(View->Section);
    ObDereferenceObject(View->Member);
}

START_TEST(MmSessionTables)
{
    PTEST_PROCESS Processes;
    TEST_VIEW Views[MAX_SESSIONS];
    ULONG ProcessCount, ViewCount = 0, i, v, Checked = 0, NoSession = 0;
    KAPC_STATE ApcState;
    BOOLEAN Sees, Member;

    Processes = ExAllocatePoolWithTag(NonPagedPool, MAX_PROCESSES * sizeof(*Processes), 'tSmM');
    if (skip(Processes != NULL, "No memory\n"))
        return;

    RtlZeroMemory(Views, sizeof(Views));
    ProcessCount = SnapshotProcesses(Processes);
    ok(ProcessCount > 2, "Only %lu processes\n", ProcessCount);

    /* One view per session, mapped through a member that is not smss */
    for (i = 0; i < ProcessCount; i++)
    {
        ULONG Session = Processes[i].Session;

        if (Session == MAXULONG || IsSmss(Processes[i].Process))
            continue;
        for (v = 0; v < ViewCount; v++)
        {
            if (Views[v].Session == Session)
                break;
        }
        if (v < ViewCount || ViewCount == MAX_SESSIONS)
            continue;

        ObReferenceObject(Processes[i].Process);
        Views[ViewCount].Session = Session;
        Views[ViewCount].Member = Processes[i].Process;
        Views[ViewCount].Pattern = PATTERN_BASE + Session;
        MapSessionView(&Views[ViewCount]);
        trace("Session %lu: view %p (member %s, pid %p)\n", Session, Views[ViewCount].Base,
              PsGetProcessImageFileName(Processes[i].Process),
              PsGetProcessId(Processes[i].Process));
        ViewCount++;
    }
    /* Needs a second session (NitroSessions 1 or 4): with one, nothing is
       compared and the test would pass for nothing */
    ok(ViewCount >= 2, "Only %lu session(s) with a member: no second session (NitroSessions 0?)\n",
       ViewCount);

    /*
     * Every process against every session's view:
     *  - a member of session S sees S's view (read directly: on i386 the
     *    PDE comes in through the session's page table list on a fault);
     *  - nobody else sees the view of a session other than 0. A process in
     *    no session may see session 0's (amd64 shares those tables), and the
     *    view of another session is only read after MmIsAddressValid.
     */
    for (i = 0; i < ProcessCount; i++)
    {
        PEPROCESS Process = Processes[i].Process;
        ULONG Session = Processes[i].Session;

        if (Session == MAXULONG)
            NoSession++;
        if (PsGetProcessExitStatus(Process) != STATUS_PENDING)
            continue;

        KeStackAttachProcess((PKPROCESS)Process, &ApcState);
        for (v = 0; v < ViewCount; v++)
        {
            if (!Views[v].Base)
                continue;
            /* smss is the leader: it reports session 0, but it is in no
               session once it has detached */
            Member = (Session == Views[v].Session) && !IsSmss(Process);
            if (Member)
            {
                ok(*(volatile ULONG *)Views[v].Base == Views[v].Pattern,
                   "%s (pid %p, session %lu) does not see its session's view\n",
                   PsGetProcessImageFileName(Process), PsGetProcessId(Process), Session);
            }
            else if (Views[v].Session != 0)
            {
                Sees = MmIsAddressValid(Views[v].Base) &&
                       (*(volatile ULONG *)Views[v].Base == Views[v].Pattern);
                ok(!Sees, "%s (pid %p, session %ld) sees session %lu's view\n",
                   PsGetProcessImageFileName(Process), PsGetProcessId(Process),
                   (LONG)Session, Views[v].Session);
#ifdef CHECK_PDES
                ok(!MapsSessionPdes(&Views[v]),
                   "%s (pid %p, session %ld) maps page tables of session %lu\n",
                   PsGetProcessImageFileName(Process), PsGetProcessId(Process),
                   (LONG)Session, Views[v].Session);
#endif
            }
            Checked++;
        }
        KeUnstackDetachProcess(&ApcState);
    }
    trace("%lu processes (%lu in no session), %lu sessions, %lu checks\n",
          ProcessCount, NoSession, ViewCount, Checked);

    for (v = 0; v < ViewCount; v++)
        UnmapSessionView(&Views[v]);
    for (i = 0; i < ProcessCount; i++)
        ObDereferenceObject(Processes[i].Process);
    ExFreePoolWithTag(Processes, 'tSmM');
}
