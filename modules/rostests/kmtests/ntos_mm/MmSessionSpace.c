/*
 * PROJECT:     ReactOS kernel tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Session space is private to each session (NitroSessions)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#include <kmt_test.h>

/* Exported, not in the headers: -1 for a process in no session */
NTKERNELAPI
ULONG
NTAPI
PsGetProcessSessionIdEx(
    _In_ PEPROCESS Process);

#define PATTERN_OWN   0x4F574E30UL
#define PATTERN_OTHER 0x4F544831UL
/* One page, always touched: MiRemoveMappedPtes does not take untouched
   committed pages of a system or session view yet */
#define VIEW_SIZE     PAGE_SIZE

/* Exported, not in the headers */
NTKERNELAPI
PCHAR
NTAPI
PsGetProcessImageFileName(
    _In_ PEPROCESS Process);

/*
 * A referenced live process, or NULL. SameSession: another process of
 * OwnSession that is a session member (not the session leader, smss, which
 * holds the view of the session it created last). Otherwise: a process of a
 * session other than OwnSession.
 */
static
PEPROCESS
FindProcess(
    _In_ ULONG OwnSession,
    _In_ BOOLEAN SameSession,
    _Out_ PULONG FoundSession)
{
    PSYSTEM_PROCESS_INFORMATION Info = NULL, Entry;
    ULONG Size = 256 * 1024, Length, Offset, Session, Try;
    PEPROCESS Process, Found = NULL;
    NTSTATUS Status = STATUS_INFO_LENGTH_MISMATCH;
    BOOLEAN Candidate;

    *FoundSession = MAXULONG;
    for (Try = 0; Try < 4; Try++, Size *= 2)
    {
        Info = ExAllocatePoolWithTag(PagedPool, Size, 'tSmM');
        if (!Info)
            return NULL;
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
        return NULL;

    for (Offset = 0; ; )
    {
        Entry = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)Info + Offset);
        if (SameSession)
            Candidate = (Entry->SessionId == OwnSession) &&
                        (Entry->UniqueProcessId != PsGetCurrentProcessId());
        else
            Candidate = (Entry->SessionId != OwnSession);

        if (Candidate &&
            NT_SUCCESS(PsLookupProcessByProcessId(Entry->UniqueProcessId, &Process)))
        {
            /* -1: in no session (System, Idle); smss reports 0 as the leader */
            Session = PsGetProcessSessionIdEx(Process);
            if (!SameSession)
            {
                /* The kernel's view must match what the entry reports */
                ok_eq_ulong(Session, Entry->SessionId);
            }
            if ((Session == Entry->SessionId) &&
                (PsGetProcessExitStatus(Process) == STATUS_PENDING) &&
                _stricmp(PsGetProcessImageFileName(Process), "smss.exe"))
            {
                Found = Process;
                *FoundSession = Session;
                break;
            }
            ObDereferenceObject(Process);
        }
        if (!Entry->NextEntryOffset)
            break;
        Offset += Entry->NextEntryOffset;
    }

    ExFreePoolWithTag(Info, 'tSmM');
    return Found;
}

static
PVOID
CreateTestSection(VOID)
{
    LARGE_INTEGER MaximumSize;
    PVOID Section = NULL;
    NTSTATUS Status;

    MaximumSize.QuadPart = VIEW_SIZE;
    Status = MmCreateSection(&Section, SECTION_ALL_ACCESS, NULL, &MaximumSize,
                             PAGE_READWRITE, SEC_COMMIT, NULL, NULL);
    ok_eq_hex(Status, STATUS_SUCCESS);
    return NT_SUCCESS(Status) ? Section : NULL;
}

START_TEST(MmSessionSpace)
{
    PEPROCESS Other, Peer;
    ULONG OwnSession, OtherSession, PeerSession;
    PVOID SectionOwn = NULL, SectionOther = NULL;
    PVOID BaseOwn = NULL, BaseOther = NULL;
    SIZE_T ViewSize;
    KAPC_STATE ApcState;
    NTSTATUS Status;

    /* The test runs in the context of kmtest.exe, a session process */
    OwnSession = PsGetProcessSessionIdEx(PsGetCurrentProcess());
    if (OwnSession == MAXULONG)
    {
        skip(FALSE, "The test process is not in a session\n");
        return;
    }
    ok_eq_ulong(PsGetCurrentProcessSessionId(), OwnSession);

    Other = FindProcess(OwnSession, FALSE, &OtherSession);
    if (!Other)
    {
        skip(FALSE, "No process in a second session (NitroSessions=0)\n");
        return;
    }
    trace("Own session %lu, other session %lu (pid %p)\n",
          OwnSession, OtherSession, PsGetProcessId(Other));

    SectionOwn = CreateTestSection();
    SectionOther = CreateTestSection();
    if (!SectionOwn || !SectionOther)
        goto Cleanup;

    /* 1. A session view in our own session */
    ViewSize = 0;
    Status = MmMapViewInSessionSpace(SectionOwn, &BaseOwn, &ViewSize);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
    {
        BaseOwn = NULL;
        goto Cleanup;
    }
    *(volatile ULONG *)BaseOwn = PATTERN_OWN;

    /* 2. In the other session, that view is not there */
    KeStackAttachProcess((PKPROCESS)Other, &ApcState);
    ok_eq_ulong(PsGetCurrentProcessSessionId(), OtherSession);
    if (MmIsAddressValid(BaseOwn))
        ok(*(volatile ULONG *)BaseOwn != PATTERN_OWN,
           "Session %lu sees session %lu's view at %p\n", OtherSession, OwnSession, BaseOwn);

    /* ... and a view of its own works, with fresh contents */
    ViewSize = 0;
    Status = MmMapViewInSessionSpace(SectionOther, &BaseOther, &ViewSize);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        ok_eq_hex(*(volatile ULONG *)BaseOther, 0UL);
        *(volatile ULONG *)BaseOther = PATTERN_OTHER;
        if (BaseOther == BaseOwn)
            trace("Both sessions map their view at %p\n", BaseOther);
    }
    else
    {
        BaseOther = NULL;
    }
    KeUnstackDetachProcess(&ApcState);

    /* 3. Back in our session: our view is intact, the other one is not here */
    ok_eq_hex(*(volatile ULONG *)BaseOwn, PATTERN_OWN);
    if (BaseOther && MmIsAddressValid(BaseOther))
        ok(*(volatile ULONG *)BaseOther != PATTERN_OTHER,
           "Session %lu sees session %lu's view at %p\n", OwnSession, OtherSession, BaseOther);

    /* 3b. Another process of our session sees our view: on i386 its page
       directory gets the session PDE from the session's page table list */
    Peer = FindProcess(OwnSession, TRUE, &PeerSession);
    if (Peer)
    {
        KeStackAttachProcess((PKPROCESS)Peer, &ApcState);
        ok_eq_ulong(PsGetCurrentProcessSessionId(), OwnSession);
        ok_eq_hex(*(volatile ULONG *)BaseOwn, PATTERN_OWN);
        KeUnstackDetachProcess(&ApcState);
        ObDereferenceObject(Peer);
    }
    else
    {
        skip(FALSE, "No other process in session %lu\n", OwnSession);
    }

    /* 4. The other session still has its data; unmap its view there */
    if (BaseOther)
    {
        KeStackAttachProcess((PKPROCESS)Other, &ApcState);
        ok_eq_hex(*(volatile ULONG *)BaseOther, PATTERN_OTHER);
        Status = MmUnmapViewInSessionSpace(BaseOther);
        ok_eq_hex(Status, STATUS_SUCCESS);
        KeUnstackDetachProcess(&ApcState);
    }

Cleanup:
    if (BaseOwn)
    {
        Status = MmUnmapViewInSessionSpace(BaseOwn);
        ok_eq_hex(Status, STATUS_SUCCESS);
    }
    if (SectionOther) ObDereferenceObject(SectionOther);
    if (SectionOwn) ObDereferenceObject(SectionOwn);
    ObDereferenceObject(Other);
}
