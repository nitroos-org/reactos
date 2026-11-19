/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     RDBSS tests: byte-range lock torture with a model of who holds
 *              what, shared by the RdbssLockTorture kmtest and its second
 *              process (rdbsshostile.exe lt ...)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 *
 * Model threads (6 per process) own their handles (2 per file) and lock,
 * unlock, cancel and close at random on overlapping ranges of 4 files, near
 * offset 0 and just below 2^63, with zero-length locks among them. Every
 * lock they are granted goes into a table in shared memory, checked against
 * the locks already in it (LockFileEx: an exclusive lock overlaps nothing;
 * a shared lock overlaps only shared locks, or an exclusive lock of the same
 * handle); it leaves the table before it is unlocked or its handle closed.
 * A lock that was not granted (refused, cancelled) must not be held: an
 * unlock of exactly its range on the same handle must fail. Ranges are
 * unique per thread (the length encodes the thread), so that such an unlock
 * can only find that thread's own lock.
 * Chaos threads (2 per process) take waiting locks on handles they duplicate
 * and close with the locks still waiting, cancel them, and are terminated by
 * the controlling thread; their locks are not in the model. A waiting lock
 * must end within 10 s of its cancel or of the cleanup of its handle.
 */

#ifndef _RDBSSLOCKTORTURE_H_
#define _RDBSSLOCKTORTURE_H_

#define LT_FILES        4
#define LT_ENTRIES      512
#define LT_SLOTS        60
#define LT_SLOT         64
#define LT_HIGH_BASE    0x7FFFFFFFFFFFF000LL
#define LT_NMODEL       6
#define LT_NCHAOS       2
#define LT_SHARED_NAME  L"Local\\RdbssLockTortureTable"

typedef struct _LT_ENTRY
{
    LONGLONG Offset;
    LONGLONG Length;
    LONG Owner;                 /* handle id, 0 = free */
    LONG Exclusive;
} LT_ENTRY;

typedef struct _LT_TABLE
{
    volatile LONG Busy;
    LONG Count;
    LT_ENTRY E[LT_ENTRIES];
} LT_TABLE;

typedef struct _LT_SHARED
{
    LT_TABLE F[LT_FILES];
    volatile LONG NextOwner;
    volatile LONG Problems;
} LT_SHARED;

typedef struct _LT_HELD
{
    ULONG File;
    ULONG Handle;
    LONGLONG Offset;
    LONGLONG Length;
    BOOL Exclusive;
} LT_HELD;

typedef struct _LT_RUN
{
    LT_SHARED *Shared;
    PCWSTR Root;
    ULONG Process;
    DWORD EndTick;
    volatile LONG Ops, Granted, Refused, Cancels, Closes, CancelledAtClose, MaxWait;
} LT_RUN;

typedef struct _LT_MODEL
{
    LT_RUN *Run;
    ULONG Index;                /* unique across processes: length tag */
    ULONG Seed;
    HANDLE H[LT_FILES][2];
    LONG Id[LT_FILES][2];
    LT_HELD Held[64];
    ULONG HeldCount;
} LT_MODEL;

typedef struct _LT_CHAOS
{
    LT_RUN *Run;
    ULONG Seed;
    HANDLE Thread;
    HANDLE volatile Handles[2];
    OVERLAPPED Ov[3];
} LT_CHAOS;

/* RDBSS_LT_OFF (hex, inherited by the other processes): 1 = no zero-length
 * locks, 2 = no shared locks, 4 = no locks near 2^63 (to tell which kind of
 * lock a failure needs) */
static ULONG LtOff;

static
ULONG
LtRand(
    _Inout_ PULONG Seed)
{
    *Seed = *Seed * 1103515245 + 12345;
    return (*Seed >> 8) & 0xFFFFFF;
}

static
VOID
LtProblem(
    _In_ LT_RUN *Run,
    _In_ PCSTR Text)
{
    InterlockedIncrement(&Run->Shared->Problems);
    OutputDebugStringA(Text);
    printf("%s", Text);
}

static
HANDLE
LtOpen(
    _In_ LT_RUN *Run,
    _In_ ULONG File)
{
    WCHAR Name[MAX_PATH];

    _snwprintf(Name, MAX_PATH, L"%s\\f%lu.bin", Run->Root, File);
    Name[MAX_PATH - 1] = 0;
    return CreateFileW(Name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
}

static
VOID
LtLockTable(
    _In_ LT_TABLE *T)
{
    while (InterlockedCompareExchange(&T->Busy, 1, 0) != 0)
        Sleep(0);
}

static
VOID
LtUnlockTable(
    _In_ LT_TABLE *T)
{
    InterlockedExchange(&T->Busy, 0);
}

static
BOOL
LtOverlap(
    _In_ LONGLONG O1, _In_ LONGLONG L1,
    _In_ LONGLONG O2, _In_ LONGLONG L2)
{
    if (L1 == 0 || L2 == 0)
        return FALSE;
    return (O1 < O2 + L2) && (O2 < O1 + L1);
}

/* A lock was granted: check it against the table, then record it */
static
VOID
LtRecord(
    _In_ LT_RUN *Run,
    _In_ ULONG File,
    _In_ LONG Owner,
    _In_ LONGLONG Offset,
    _In_ LONGLONG Length,
    _In_ BOOL Exclusive)
{
    LT_TABLE *T = &Run->Shared->F[File];
    ULONG i, Free = LT_ENTRIES;
    CHAR Msg[256];

    if (Length == 0)
        return;
    LtLockTable(T);
    for (i = 0; i < LT_ENTRIES; ++i)
    {
        LT_ENTRY *E = &T->E[i];

        if (E->Owner == 0)
        {
            if (Free == LT_ENTRIES)
                Free = i;
            continue;
        }
        if (!LtOverlap(E->Offset, E->Length, Offset, Length))
            continue;
        if (Exclusive || (E->Exclusive && E->Owner != Owner))
        {
            _snprintf(Msg, sizeof(Msg), "RdbssLockTorture: lock granted twice: file %lu, %s %I64x+%I64x of handle %ld "
                      "overlaps %s %I64x+%I64x of handle %ld\n", File, Exclusive ? "exclusive" : "shared",
                      Offset, Length, Owner, E->Exclusive ? "exclusive" : "shared", E->Offset, E->Length, E->Owner);
            Msg[sizeof(Msg) - 1] = 0;
            LtProblem(Run, Msg);
        }
    }
    if (Free < LT_ENTRIES)
    {
        T->E[Free].Offset = Offset;
        T->E[Free].Length = Length;
        T->E[Free].Exclusive = Exclusive;
        T->E[Free].Owner = Owner;
    }
    LtUnlockTable(T);
}

static
VOID
LtForget(
    _In_ LT_RUN *Run,
    _In_ ULONG File,
    _In_ LONG Owner,
    _In_ LONGLONG Offset,
    _In_ LONGLONG Length)
{
    LT_TABLE *T = &Run->Shared->F[File];
    ULONG i;

    if (Length == 0)
        return;
    LtLockTable(T);
    for (i = 0; i < LT_ENTRIES; ++i)
    {
        LT_ENTRY *E = &T->E[i];

        if (E->Owner == Owner && E->Offset == Offset && E->Length == Length)
        {
            E->Owner = 0;
            break;
        }
    }
    LtUnlockTable(T);
}

static
BOOL
LtUnlock(
    _In_ HANDLE File,
    _In_ LONGLONG Offset,
    _In_ LONGLONG Length)
{
    OVERLAPPED Ov;
    DWORD Done;
    BOOL Ok;

    RtlZeroMemory(&Ov, sizeof(Ov));
    Ov.Offset = (DWORD)Offset;
    Ov.OffsetHigh = (DWORD)(Offset >> 32);
    Ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    Ok = UnlockFileEx(File, 0, (DWORD)Length, (DWORD)(Length >> 32), &Ov);
    if (!Ok && GetLastError() == ERROR_IO_PENDING)
        Ok = GetOverlappedResult(File, &Ov, &Done, TRUE);
    CloseHandle(Ov.hEvent);
    return Ok;
}

static
VOID
LtCancel(
    _In_ HANDLE File,
    _In_ OVERLAPPED *Ov)
{
    typedef BOOL (WINAPI *PFN_CANCELIOEX)(HANDLE, LPOVERLAPPED);
    static PFN_CANCELIOEX pCancelIoEx;

    if (pCancelIoEx == NULL)
        pCancelIoEx = (PFN_CANCELIOEX)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CancelIoEx");
    if (pCancelIoEx != NULL)
        pCancelIoEx(File, Ov);
    else
        CancelIo(File);
}

static
VOID
LtCloseHandleOf(
    _In_ LT_MODEL *M,
    _In_ ULONG File,
    _In_ ULONG Which)
{
    ULONG i;

    /* Out of the model first: the locks are still held until the close */
    for (i = 0; i < M->HeldCount; )
    {
        LT_HELD *L = &M->Held[i];

        if (L->File == File && L->Handle == Which)
        {
            LtForget(M->Run, File, M->Id[File][Which], L->Offset, L->Length);
            M->Held[i] = M->Held[--M->HeldCount];
            continue;
        }
        ++i;
    }
    CloseHandle(M->H[File][Which]);
    InterlockedIncrement(&M->Run->Closes);
    M->H[File][Which] = LtOpen(M->Run, File);
    M->Id[File][Which] = InterlockedIncrement(&M->Run->Shared->NextOwner);
}

static
VOID
LtModelOneOp(
    _In_ LT_MODEL *M)
{
    LT_RUN *Run = M->Run;
    ULONG R = LtRand(&M->Seed) % 100;
    CHAR Msg[256];

    InterlockedIncrement(&Run->Ops);
    if (M->HeldCount > 0 && (R < 35 || M->HeldCount >= RTL_NUMBER_OF(M->Held)))
    {
        ULONG i = LtRand(&M->Seed) % M->HeldCount;
        LT_HELD L = M->Held[i];

        LtForget(Run, L.File, M->Id[L.File][L.Handle], L.Offset, L.Length);
        M->Held[i] = M->Held[--M->HeldCount];
        if (!LtUnlock(M->H[L.File][L.Handle], L.Offset, L.Length))
        {
            _snprintf(Msg, sizeof(Msg), "RdbssLockTorture: unlock of a granted lock failed: file %lu %I64x+%I64x, error %lu\n",
                      L.File, L.Offset, L.Length, GetLastError());
            Msg[sizeof(Msg) - 1] = 0;
            LtProblem(Run, Msg);
        }
    }
    else if (R >= 35 && R < 40)
    {
        LtCloseHandleOf(M, LtRand(&M->Seed) % LT_FILES, LtRand(&M->Seed) % 2);
    }
    else
    {
        ULONG File = LtRand(&M->Seed) % LT_FILES, Which = LtRand(&M->Seed) % 2, i;
        ULONG Slot = LtRand(&M->Seed) % LT_SLOTS, Slots = 1 + LtRand(&M->Seed) % 4;
        BOOL High = (LtRand(&M->Seed) % 10 == 0), Exclusive = LtRand(&M->Seed) & 1;
        BOOL FailImmediately = (M->HeldCount > 0) || (LtRand(&M->Seed) % 3 == 0);
        LONGLONG Offset, Length;
        HANDLE F = M->H[File][Which];
        OVERLAPPED Ov;
        DWORD Done, T0, Waited, Patience;
        BOOL Ok;
        NTSTATUS Status;

        if (F == INVALID_HANDLE_VALUE)
        {
            M->H[File][Which] = LtOpen(Run, File);
            return;
        }
        if (LtOff & 4)
            High = FALSE;
        if (LtOff & 2)
            Exclusive = TRUE;
        Offset = (High ? LT_HIGH_BASE : 0) + (LONGLONG)Slot * LT_SLOT;
        Length = (LONGLONG)Slots * LT_SLOT - (LONGLONG)M->Index;
        if (LtRand(&M->Seed) % 16 == 0 && !(LtOff & 1))
            Length = 0;
        for (i = 0; i < M->HeldCount; ++i)
        {
            if (M->Held[i].File == File && M->Held[i].Handle == Which &&
                M->Held[i].Offset == Offset && M->Held[i].Length == Length)
                return;
        }

        RtlZeroMemory(&Ov, sizeof(Ov));
        Ov.Offset = (DWORD)Offset;
        Ov.OffsetHigh = (DWORD)(Offset >> 32);
        Ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        T0 = GetTickCount();
        Ok = LockFileEx(F, (Exclusive ? LOCKFILE_EXCLUSIVE_LOCK : 0) | (FailImmediately ? LOCKFILE_FAIL_IMMEDIATELY : 0),
                        0, (DWORD)Length, (DWORD)(Length >> 32), &Ov);
        if (!Ok && GetLastError() == ERROR_IO_PENDING)
        {
            Patience = LtRand(&M->Seed) % 1500;
            if (WaitForSingleObject(Ov.hEvent, Patience) != WAIT_OBJECT_0)
            {
                LtCancel(F, &Ov);
                InterlockedIncrement(&Run->Cancels);
                if (WaitForSingleObject(Ov.hEvent, 10000) != WAIT_OBJECT_0)
                {
                    _snprintf(Msg, sizeof(Msg), "RdbssLockTorture: a cancelled lock did not end within 10 s (file %lu %I64x+%I64x)\n",
                              File, Offset, Length);
                    Msg[sizeof(Msg) - 1] = 0;
                    LtProblem(Run, Msg);
                    WaitForSingleObject(Ov.hEvent, INFINITE);
                }
            }
            Ok = GetOverlappedResult(F, &Ov, &Done, TRUE);
        }
        Status = (NTSTATUS)Ov.Internal;
        Waited = GetTickCount() - T0;
        CloseHandle(Ov.hEvent);
        if ((LONG)Waited > Run->MaxWait)
            InterlockedExchange(&Run->MaxWait, (LONG)Waited);
        if (Ok)
        {
            InterlockedIncrement(&Run->Granted);
            LtRecord(Run, File, M->Id[File][Which], Offset, Length, Exclusive);
            M->Held[M->HeldCount].File = File;
            M->Held[M->HeldCount].Handle = Which;
            M->Held[M->HeldCount].Offset = Offset;
            M->Held[M->HeldCount].Length = Length;
            M->Held[M->HeldCount].Exclusive = Exclusive;
            ++M->HeldCount;
        }
        else
        {
            InterlockedIncrement(&Run->Refused);
            /* Not granted: the handle must not hold it */
            if (LtUnlock(F, Offset, Length))
            {
                _snprintf(Msg, sizeof(Msg), "RdbssLockTorture: a lock reported as not granted (%lx) was held: file %lu "
                          "%I64x+%I64x\n", Status, File, Offset, Length);
                Msg[sizeof(Msg) - 1] = 0;
                LtProblem(Run, Msg);
            }
        }
    }
}

static
DWORD
WINAPI
LtModelThread(
    _In_ PVOID Parameter)
{
    LT_MODEL *M = Parameter;
    ULONG File, Which;

    for (File = 0; File < LT_FILES; ++File)
    {
        for (Which = 0; Which < 2; ++Which)
        {
            M->H[File][Which] = LtOpen(M->Run, File);
            M->Id[File][Which] = InterlockedIncrement(&M->Run->Shared->NextOwner);
        }
    }
    while ((LONG)(GetTickCount() - M->Run->EndTick) < 0)
        LtModelOneOp(M);
    for (File = 0; File < LT_FILES; ++File)
    {
        for (Which = 0; Which < 2; ++Which)
        {
            LtCloseHandleOf(M, File, Which);
            if (M->H[File][Which] != INVALID_HANDLE_VALUE)
                CloseHandle(M->H[File][Which]);
            M->H[File][Which] = INVALID_HANDLE_VALUE;
        }
    }
    return 0;
}

/* Waits for the chaos thread's overlapped locks after their cancel or the
 * cleanup of their handle */
static
VOID
LtChaosWait(
    _In_ LT_CHAOS *C,
    _In_ ULONG Count,
    _In_ PCSTR Why)
{
    ULONG i;
    CHAR Msg[160];

    for (i = 0; i < Count; ++i)
    {
        if (C->Ov[i].hEvent == NULL)
            continue;
        if (WaitForSingleObject(C->Ov[i].hEvent, 10000) != WAIT_OBJECT_0)
        {
            _snprintf(Msg, sizeof(Msg), "RdbssLockTorture: a waiting lock did not end within 10 s of %s\n", Why);
            Msg[sizeof(Msg) - 1] = 0;
            LtProblem(C->Run, Msg);
            WaitForSingleObject(C->Ov[i].hEvent, INFINITE);
        }
    }
}

static
VOID
LtChaosClose(
    _In_ LT_CHAOS *C,
    _In_ ULONG Which)
{
    HANDLE H = InterlockedExchangePointer((PVOID volatile *)&C->Handles[Which], NULL);

    if (H != NULL && H != INVALID_HANDLE_VALUE)
        CloseHandle(H);
}

static
DWORD
WINAPI
LtChaosThread(
    _In_ PVOID Parameter)
{
    LT_CHAOS *C = Parameter;
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(C->Ov); ++i)
        C->Ov[i].hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    while ((LONG)(GetTickCount() - C->Run->EndTick) < 0)
    {
        ULONG File = LtRand(&C->Seed) % LT_FILES, Count = 1 + LtRand(&C->Seed) % 3, How = LtRand(&C->Seed) % 3;
        HANDLE H, Dup = NULL;

        InterlockedIncrement(&C->Run->Ops);
        H = LtOpen(C->Run, File);
        if (H == INVALID_HANDLE_VALUE)
            continue;
        C->Handles[0] = H;
        if (LtRand(&C->Seed) & 1)
        {
            DuplicateHandle(GetCurrentProcess(), H, GetCurrentProcess(), &Dup, 0, FALSE, DUPLICATE_SAME_ACCESS);
            C->Handles[1] = Dup;
        }
        for (i = 0; i < Count; ++i)
        {
            LONGLONG Offset = (LONGLONG)(LtRand(&C->Seed) % LT_SLOTS) * LT_SLOT;
            LONGLONG Length = (LONGLONG)(1 + LtRand(&C->Seed) % 4) * LT_SLOT;

            ResetEvent(C->Ov[i].hEvent);
            C->Ov[i].Internal = C->Ov[i].InternalHigh = 0;
            C->Ov[i].Offset = (DWORD)Offset;
            C->Ov[i].OffsetHigh = 0;
            LockFileEx((i == 1 && Dup != NULL) ? Dup : H, LOCKFILE_EXCLUSIVE_LOCK, 0, (DWORD)Length, 0, &C->Ov[i]);
        }
        Sleep(LtRand(&C->Seed) % 30);
        if (How == 0)
        {
            /* Cancel them, then close */
            for (i = 0; i < Count; ++i)
                LtCancel(H, &C->Ov[i]);
            LtChaosWait(C, Count, "CancelIoEx");
            LtChaosClose(C, 1);
            LtChaosClose(C, 0);
        }
        else
        {
            /* Close with the locks still waiting (the duplicate first: no
             * cleanup yet) */
            LtChaosClose(C, 1);
            if (How == 2)
                Sleep(LtRand(&C->Seed) % 20);
            LtChaosClose(C, 0);
            InterlockedIncrement(&C->Run->CancelledAtClose);
            LtChaosWait(C, Count, "the cleanup of its handle");
        }
    }
    return 0;
}

/* Runs the torture in this process: model and chaos threads, the chaos
 * threads terminated and restarted at random. Returns the problems found by
 * this process */
static
ULONG
LtRun(
    _In_ PCWSTR Root,
    _In_ ULONG Process,
    _In_ ULONG Seconds,
    _In_ ULONG Seed,
    _In_ BOOL ModelThreads,
    _In_ BOOL Terminate)
{
    HANDLE Mapping, Threads[LT_NMODEL];
    LT_SHARED *Shared;
    LT_RUN Run;
    LT_MODEL *Models;
    LT_CHAOS *Chaos[LT_NCHAOS];
    ULONG i, Terminated = 0;
    LONG Problems;

    {
        WCHAR Env[16];

        if (GetEnvironmentVariableW(L"RDBSS_LT_OFF", Env, RTL_NUMBER_OF(Env)))
            LtOff = wcstoul(Env, NULL, 16);
    }
    Mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(LT_SHARED), LT_SHARED_NAME);
    if (Mapping == NULL)
        return 1;
    Shared = MapViewOfFile(Mapping, FILE_MAP_WRITE, 0, 0, 0);
    if (Shared == NULL)
        return 1;
    RtlZeroMemory(&Run, sizeof(Run));
    Run.Shared = Shared;
    Run.Root = Root;
    Run.Process = Process;
    Run.EndTick = GetTickCount() + Seconds * 1000;
    Problems = Shared->Problems;

    Models = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(LT_MODEL) * LT_NMODEL);
    for (i = 0; ModelThreads && i < LT_NMODEL; ++i)
    {
        Models[i].Run = &Run;
        Models[i].Index = 1 + Process * LT_NMODEL + i;
        Models[i].Seed = Seed * 7919 + i;
        Threads[i] = CreateThread(NULL, 0, LtModelThread, &Models[i], 0, NULL);
    }
    for (i = 0; i < LT_NCHAOS; ++i)
    {
        Chaos[i] = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(LT_CHAOS));
        Chaos[i]->Run = &Run;
        Chaos[i]->Seed = Seed * 104729 + i;
        Chaos[i]->Thread = CreateThread(NULL, 0, LtChaosThread, Chaos[i], 0, NULL);
    }

    /* Terminate a chaos thread now and then, in the middle of its locks */
    while ((LONG)(GetTickCount() - Run.EndTick) < 0)
    {
        ULONG Which = LtRand(&Seed) % LT_NCHAOS;

        Sleep(100 + LtRand(&Seed) % 300);
        /* (Only where a handle a terminated thread could not close dies
         * with the process: the second process) */
        if (Terminate && (LtRand(&Seed) & 1))
        {
            LT_CHAOS *Old = Chaos[Which];

            TerminateThread(Old->Thread, 1);
            WaitForSingleObject(Old->Thread, INFINITE);
            CloseHandle(Old->Thread);
            /* Its I/O was cancelled when it exited; the handles are left */
            LtChaosClose(Old, 1);
            LtChaosClose(Old, 0);
            ++Terminated;
            /* (Old and its OVERLAPPEDs stay allocated: late completions) */
            Chaos[Which] = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(LT_CHAOS));
            Chaos[Which]->Run = &Run;
            Chaos[Which]->Seed = Seed + Terminated;
            Chaos[Which]->Thread = CreateThread(NULL, 0, LtChaosThread, Chaos[Which], 0, NULL);
        }
    }

    for (i = 0; ModelThreads && i < LT_NMODEL; ++i)
    {
        if (WaitForSingleObject(Threads[i], 120000) != WAIT_OBJECT_0)
            LtProblem(&Run, "RdbssLockTorture: a model thread did not end\n");
        CloseHandle(Threads[i]);
    }
    for (i = 0; i < LT_NCHAOS; ++i)
    {
        if (WaitForSingleObject(Chaos[i]->Thread, 120000) != WAIT_OBJECT_0)
            LtProblem(&Run, "RdbssLockTorture: a chaos thread did not end\n");
        CloseHandle(Chaos[i]->Thread);
        LtChaosClose(Chaos[i], 1);
        LtChaosClose(Chaos[i], 0);
    }

    printf("RdbssLockTorture process %lu: %lu s, %ld operations, %ld granted, %ld not granted, %ld cancels, "
           "%ld handle closes, %ld closes with waiting locks, %lu chaos threads terminated, longest lock wait %ld ms\n",
           Process, Seconds, Run.Ops, Run.Granted, Run.Refused, Run.Cancels, Run.Closes, Run.CancelledAtClose,
           Terminated, Run.MaxWait);
    Problems = Shared->Problems - Problems;
    UnmapViewOfFile(Shared);
    CloseHandle(Mapping);
    return (ULONG)Problems;
}

#endif /* _RDBSSLOCKTORTURE_H_ */
