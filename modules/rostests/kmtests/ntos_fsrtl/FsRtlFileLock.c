/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for the FsRtl byte-range lock package
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <kmt_test.h>

typedef struct _TEST_RANGE
{
    LONGLONG Start;
    LONGLONG Length;
    PEPROCESS Process;
    ULONG Key;
    BOOLEAN Exclusive;
} TEST_RANGE, *PTEST_RANGE;

static PEPROCESS ProcessA;
static PEPROCESS ProcessB;

static
PFILE_OBJECT
AllocateFileObject(VOID)
{
    PFILE_OBJECT FileObject = ExAllocatePoolWithTag(NonPagedPool, sizeof(*FileObject), 'kLsF');
    if (FileObject)
    {
        RtlZeroMemory(FileObject, sizeof(*FileObject));
        FileObject->Type = IO_TYPE_FILE;
        FileObject->Size = sizeof(*FileObject);
    }
    return FileObject;
}

static
BOOLEAN
TakeLock(PFILE_LOCK FileLock, PFILE_OBJECT FileObject, PTEST_RANGE Range)
{
    LARGE_INTEGER Offset, Length;
    IO_STATUS_BLOCK IoStatus;
    BOOLEAN Result;

    Offset.QuadPart = Range->Start;
    Length.QuadPart = Range->Length;
    IoStatus.Status = STATUS_UNSUCCESSFUL;
    Result = FsRtlFastLock(FileLock, FileObject, &Offset, &Length, Range->Process,
                           Range->Key, TRUE, Range->Exclusive, &IoStatus, NULL, FALSE);
    return Result && IoStatus.Status == STATUS_SUCCESS;
}

static
BOOLEAN
CanWrite(PFILE_LOCK FileLock, PFILE_OBJECT FileObject, LONGLONG Start, LONGLONG Length, PEPROCESS Process, ULONG Key)
{
    LARGE_INTEGER Offset, Len;
    Offset.QuadPart = Start;
    Len.QuadPart = Length;
    return FsRtlFastCheckLockForWrite(FileLock, &Offset, &Len, Key, FileObject, Process);
}

static
BOOLEAN
CanRead(PFILE_LOCK FileLock, PFILE_OBJECT FileObject, LONGLONG Start, LONGLONG Length, PEPROCESS Process, ULONG Key)
{
    LARGE_INTEGER Offset, Len;
    Offset.QuadPart = Start;
    Len.QuadPart = Length;
    return FsRtlFastCheckLockForRead(FileLock, &Offset, &Len, Key, FileObject, Process);
}

static
ULONG
CountLocks(PFILE_LOCK FileLock, PEPROCESS Process, PULONG OfProcess)
{
    PFILE_LOCK_INFO Info;
    ULONG Count = 0;

    *OfProcess = 0;
    for (Info = FsRtlGetNextFileLock(FileLock, TRUE);
         Info && Count < 1000;
         Info = FsRtlGetNextFileLock(FileLock, FALSE))
    {
        Count++;
        if (Info->ProcessId == Process)
            (*OfProcess)++;
    }
    return Count;
}

/* Several locks of one process interleaved with another owner's: unlocking all
   of the first process must remove every one of its locks and no other */
static
VOID
TestUnlockAllInterleaved(PFILE_OBJECT FileObject)
{
    static TEST_RANGE Ranges[] =
    {
        {   0, 10, NULL, 0, TRUE },
        {  10, 10, NULL, 0, TRUE },
        {  20, 10, NULL, 0, TRUE },
        {  30, 10, NULL, 0, TRUE },
        {  40, 10, NULL, 0, TRUE },
        {  50, 10, NULL, 0, TRUE },
        {  60, 10, NULL, 0, TRUE },
        {  70, 10, NULL, 0, TRUE },
        {  80, 10, NULL, 0, TRUE },
        {  90, 10, NULL, 0, TRUE },
        { 100, 10, NULL, 0, FALSE },
        { 100, 10, NULL, 0, FALSE },
        { 200, 10, NULL, 0, FALSE },
    };
    /* Owner per range: A A B A B A A B A A, shared A + B, shared A */
    static const UCHAR Owner[] = { 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0 };
    FILE_LOCK FileLock;
    LARGE_INTEGER Offset, Length;
    ULONG i, Count, OfA;
    NTSTATUS Status;

    FsRtlInitializeFileLock(&FileLock, NULL, NULL);
    for (i = 0; i < RTL_NUMBER_OF(Ranges); i++)
    {
        Ranges[i].Process = Owner[i] ? ProcessB : ProcessA;
        ok(TakeLock(&FileLock, FileObject, &Ranges[i]), "Lock %lu not granted\n", i);
    }

    Status = FsRtlFastUnlockAll(&FileLock, FileObject, ProcessA, NULL);
    ok_eq_hex(Status, STATUS_SUCCESS);

    for (i = 0; i < 10; i++)
    {
        if (Owner[i])
            ok(!CanWrite(&FileLock, FileObject, Ranges[i].Start, Ranges[i].Length, ProcessA, 0),
               "Range %I64d of the other owner was unlocked\n", Ranges[i].Start);
        else
            ok(CanWrite(&FileLock, FileObject, Ranges[i].Start, Ranges[i].Length, ProcessB, 0),
               "Range %I64d is still locked after FsRtlFastUnlockAll\n", Ranges[i].Start);
    }
    ok(!CanWrite(&FileLock, FileObject, 100, 10, ProcessA, 0), "Shared range of the other owner was unlocked\n");
    ok(CanWrite(&FileLock, FileObject, 200, 10, ProcessB, 0), "Shared range is still locked after FsRtlFastUnlockAll\n");

    Count = CountLocks(&FileLock, ProcessA, &OfA);
    ok_eq_ulong(Count, 4UL);
    ok_eq_ulong(OfA, 0UL);

    for (i = 0; i < RTL_NUMBER_OF(Ranges); i++)
    {
        if (Owner[i]) continue;
        Offset.QuadPart = Ranges[i].Start;
        Length.QuadPart = Ranges[i].Length;
        Status = FsRtlFastUnlockSingle(&FileLock, FileObject, &Offset, &Length, ProcessA, 0, NULL, FALSE);
        ok(Status == STATUS_RANGE_NOT_LOCKED, "Unlock of range %I64d returned 0x%lx\n", Ranges[i].Start, Status);
    }

    Status = FsRtlFastUnlockAll(&FileLock, FileObject, ProcessB, NULL);
    ok_eq_hex(Status, STATUS_SUCCESS);
    Count = CountLocks(&FileLock, ProcessA, &OfA);
    ok_eq_ulong(Count, 0UL);
    FsRtlUninitializeFileLock(&FileLock);
}

static
VOID
TestUnlockAllByKey(PFILE_OBJECT FileObject)
{
    FILE_LOCK FileLock;
    TEST_RANGE Range;
    ULONG i, Count, OfA;
    NTSTATUS Status;

    FsRtlInitializeFileLock(&FileLock, NULL, NULL);
    for (i = 0; i < 12; i++)
    {
        Range.Start = i * 10;
        Range.Length = 10;
        Range.Process = (i % 4 == 3) ? ProcessB : ProcessA;
        Range.Key = (i % 2) ? 2 : 1;
        Range.Exclusive = TRUE;
        ok(TakeLock(&FileLock, FileObject, &Range), "Lock %lu not granted\n", i);
    }

    Status = FsRtlFastUnlockAllByKey(&FileLock, FileObject, ProcessA, 1, NULL);
    ok_eq_hex(Status, STATUS_SUCCESS);

    for (i = 0; i < 12; i++)
    {
        BOOLEAN Gone = (i % 4 != 3) && !(i % 2);
        ok(CanWrite(&FileLock, FileObject, i * 10, 10, ProcessB, 7) == Gone,
           "Range %lu: expected %s\n", i * 10, Gone ? "unlocked" : "locked");
    }
    Count = CountLocks(&FileLock, ProcessA, &OfA);
    ok_eq_ulong(Count, 6UL);
    ok_eq_ulong(OfA, 3UL);
    FsRtlUninitializeFileLock(&FileLock);
}

/* The first lock creates the package's state: a check right after it must see a complete table */
static
VOID
TestFirstLockVisible(PFILE_OBJECT FileObject)
{
    FILE_LOCK FileLock;
    TEST_RANGE Range = { 4096, 512, NULL, 5, TRUE };
    PFILE_LOCK_INFO Info;

    FsRtlInitializeFileLock(&FileLock, NULL, NULL);
    ok(FsRtlGetNextFileLock(&FileLock, TRUE) == NULL, "Fresh lock enumerates a range\n");
    ok(CanRead(&FileLock, FileObject, 4096, 512, ProcessB, 0), "Fresh lock denies a read\n");

    Range.Process = ProcessA;
    ok(TakeLock(&FileLock, FileObject, &Range), "First lock not granted\n");

    ok(!CanRead(&FileLock, FileObject, 4096, 1, ProcessB, 0), "First lock not visible to a read check\n");
    ok(!CanWrite(&FileLock, FileObject, 4607, 1, ProcessB, 0), "First lock not visible to a write check\n");
    ok(CanRead(&FileLock, FileObject, 4096, 512, ProcessA, 5), "Owner cannot read its own range\n");
    ok(CanWrite(&FileLock, FileObject, 0, 4096, ProcessB, 0), "Range before the lock is locked\n");
    ok(CanWrite(&FileLock, FileObject, 4608, 4096, ProcessB, 0), "Range after the lock is locked\n");

    Info = FsRtlGetNextFileLock(&FileLock, TRUE);
    ok(Info != NULL, "First lock not enumerated\n");
    if (Info)
    {
        ok_eq_longlong(Info->StartingByte.QuadPart, 4096LL);
        ok_eq_longlong(Info->EndingByte.QuadPart, 4608LL);
        ok_eq_bool(Info->ExclusiveLock, TRUE);
        ok_eq_ulong(Info->Key, 5UL);
        ok(Info->ProcessId == ProcessA, "ProcessId %p, expected %p\n", Info->ProcessId, ProcessA);
    }
    ok(FsRtlGetNextFileLock(&FileLock, FALSE) == NULL, "More than one range enumerated\n");
    FsRtlUninitializeFileLock(&FileLock);
}

/* Lock IRPs: a waiter is granted on unlock, a waiter is cancelled, and the
   completion callback runs without the package's lock held, so it may call back in */
typedef struct _COMPLETION_STATE
{
    PFILE_LOCK FileLock;
    LONG Calls;
    NTSTATUS LastStatus;
    PIRP LastIrp;
    KIRQL Irql;
    BOOLEAN Reentered;
    BOOLEAN ReentryResult;
} COMPLETION_STATE;

static COMPLETION_STATE Completion;
static LARGE_INTEGER IrpLength;

static
NTSTATUS
NTAPI
CompleteLockIrp(PVOID Context, PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);

    Completion.Calls++;
    Completion.LastStatus = Irp->IoStatus.Status;
    Completion.LastIrp = Irp;
    Completion.Irql = KeGetCurrentIrql();
    Completion.Reentered = FALSE;
    if (Completion.Irql < DISPATCH_LEVEL)
    {
        Completion.ReentryResult = CanWrite(Completion.FileLock, Stack->FileObject,
                                            0, 10, ProcessB, 0);
        Completion.Reentered = TRUE;
    }
    return Irp->IoStatus.Status;
}

static
PIRP
BuildLockIrp(PFILE_OBJECT FileObject, UCHAR Minor, LONGLONG Offset, UCHAR Flags)
{
    PIO_STACK_LOCATION Stack;
    PIRP Irp = IoAllocateIrp(1, FALSE);

    if (!Irp) return NULL;
    Irp->Tail.Overlay.Thread = PsGetCurrentThread();
    Irp->RequestorMode = KernelMode;
    IoSetNextIrpStackLocation(Irp);
    Stack = IoGetCurrentIrpStackLocation(Irp);
    Stack->MajorFunction = IRP_MJ_LOCK_CONTROL;
    Stack->MinorFunction = Minor;
    Stack->Flags = Flags;
    Stack->FileObject = FileObject;
    Stack->Parameters.LockControl.ByteOffset.QuadPart = Offset;
    Stack->Parameters.LockControl.Length = &IrpLength;
    Stack->Parameters.LockControl.Key = 0;
    return Irp;
}

static
VOID
TestLockIrps(PFILE_OBJECT FileObject)
{
    FILE_LOCK FileLock;
    TEST_RANGE Range = { 0, 10, NULL, 0, TRUE };
    LARGE_INTEGER Offset, Length;
    PIRP Waiter, Cancelled, PreCancelled, Unlock;
    NTSTATUS Status;
    BOOLEAN Result;

    IrpLength.QuadPart = 10;
    RtlZeroMemory(&Completion, sizeof(Completion));
    Completion.FileLock = &FileLock;
    FsRtlInitializeFileLock(&FileLock, CompleteLockIrp, NULL);

    Range.Process = ProcessB;
    ok(TakeLock(&FileLock, FileObject, &Range), "Lock not granted\n");

    Waiter = BuildLockIrp(FileObject, IRP_MN_LOCK, 0, SL_EXCLUSIVE_LOCK);
    Cancelled = BuildLockIrp(FileObject, IRP_MN_LOCK, 0, SL_EXCLUSIVE_LOCK);
    PreCancelled = BuildLockIrp(FileObject, IRP_MN_LOCK, 0, SL_EXCLUSIVE_LOCK);
    Unlock = BuildLockIrp(FileObject, IRP_MN_UNLOCK_SINGLE, 0, 0);
    if (!skip(Waiter && Cancelled && PreCancelled && Unlock, "No IRPs\n"))
    {
        Status = FsRtlProcessFileLock(&FileLock, Waiter, NULL);
        ok_eq_hex(Status, STATUS_PENDING);
        ok_eq_long(Completion.Calls, 0L);

        /* Unlocking grants the waiter */
        Offset.QuadPart = 0;
        Length.QuadPart = 10;
        Status = FsRtlFastUnlockSingle(&FileLock, FileObject, &Offset, &Length, ProcessB, 0, NULL, FALSE);
        ok_eq_hex(Status, STATUS_SUCCESS);
        ok_eq_long(Completion.Calls, 1L);
        ok(Completion.LastIrp == Waiter, "Completed IRP %p, expected %p\n", Completion.LastIrp, Waiter);
        ok_eq_hex(Completion.LastStatus, STATUS_SUCCESS);
        ok(Completion.Irql < DISPATCH_LEVEL, "Completion at IRQL %u\n", Completion.Irql);
        ok_eq_bool(Completion.Reentered, TRUE);
        ok_eq_bool(Completion.ReentryResult, FALSE);
        ok(!CanWrite(&FileLock, FileObject, 0, 10, ProcessB, 0), "Granted waiter does not hold the range\n");

        /* A waiter behind the granted one, then cancelled */
        Status = FsRtlProcessFileLock(&FileLock, Cancelled, NULL);
        ok_eq_hex(Status, STATUS_PENDING);
        ok_eq_long(Completion.Calls, 1L);
        Result = IoCancelIrp(Cancelled);
        ok_eq_bool(Result, TRUE);
        ok_eq_long(Completion.Calls, 2L);
        ok(Completion.LastIrp == Cancelled, "Completed IRP %p, expected %p\n", Completion.LastIrp, Cancelled);
        ok_eq_hex(Completion.LastStatus, STATUS_CANCELLED);
        ok(Completion.Irql < DISPATCH_LEVEL, "Cancel completion at IRQL %u\n", Completion.Irql);

        /* Cancelled before it is queued: the queue cancels it while FsRtl queues it */
        PreCancelled->Cancel = TRUE;
        Status = FsRtlProcessFileLock(&FileLock, PreCancelled, NULL);
        ok_eq_hex(Status, STATUS_PENDING);
        ok_eq_long(Completion.Calls, 3L);
        ok(Completion.LastIrp == PreCancelled, "Completed IRP %p, expected %p\n", Completion.LastIrp, PreCancelled);
        ok_eq_hex(Completion.LastStatus, STATUS_CANCELLED);
        ok(Completion.Irql < DISPATCH_LEVEL, "Inline cancel completion at IRQL %u\n", Completion.Irql);
        ok_eq_bool(Completion.Reentered, TRUE);

        /* Unlock through an IRP */
        Status = FsRtlProcessFileLock(&FileLock, Unlock, NULL);
        ok_eq_hex(Status, STATUS_SUCCESS);
        ok_eq_long(Completion.Calls, 4L);
        ok(Completion.LastIrp == Unlock, "Completed IRP %p, expected %p\n", Completion.LastIrp, Unlock);
        ok_eq_bool(Completion.Reentered, TRUE);
        ok_eq_bool(Completion.ReentryResult, TRUE);
        ok(CanWrite(&FileLock, FileObject, 0, 10, ProcessB, 0), "Range still locked after the unlock IRP\n");
    }
    if (Waiter) IoFreeIrp(Waiter);
    if (Cancelled) IoFreeIrp(Cancelled);
    if (PreCancelled) IoFreeIrp(PreCancelled);
    if (Unlock) IoFreeIrp(Unlock);
    FsRtlUninitializeFileLock(&FileLock);
}

/* FsRtlAllocateFileLock (paged): enumeration visits every range once and stays at the end until restarted */
static
VOID
TestEnumeration(PFILE_OBJECT FileObject)
{
    PFILE_LOCK FileLock = FsRtlAllocateFileLock(NULL, NULL);
    TEST_RANGE Range = { 0, 10, NULL, 0, TRUE };
    PFILE_LOCK_INFO Info;
    ULONG i, Count, OfA;
    LONGLONG First;

    if (skip(FileLock != NULL, "No file lock\n"))
        return;
    Range.Process = ProcessA;
    for (i = 0; i < 5; i++)
    {
        Range.Start = 1000 - i * 100;
        ok(TakeLock(FileLock, FileObject, &Range), "Lock %lu not granted\n", i);
    }
    Count = CountLocks(FileLock, ProcessA, &OfA);
    ok_eq_ulong(Count, 5UL);
    ok_eq_ulong(OfA, 5UL);
    ok(FsRtlGetNextFileLock(FileLock, FALSE) == NULL, "Enumeration continued after its end\n");
    Info = FsRtlGetNextFileLock(FileLock, TRUE);
    ok(Info != NULL, "Restart found no range\n");
    if (Info)
    {
        First = Info->StartingByte.QuadPart;
        /* A check between two enumeration calls must not move the enumeration */
        (void)CanRead(FileLock, FileObject, 1000, 1, ProcessB, 0);
        Count = 1;
        while ((Info = FsRtlGetNextFileLock(FileLock, FALSE)) != NULL && Count < 10)
        {
            ok(Info->StartingByte.QuadPart != First, "Range %I64d enumerated twice\n", First);
            Count++;
        }
        ok_eq_ulong(Count, 5UL);
    }
    FsRtlFreeFileLock(FileLock);
}

/* A shared lock inside an exclusive lock of the same owner is granted and can be unlocked by its exact range; it stays
   locked when the exclusive lock goes (measured on Windows Server 2022, NTFS: self-ES rows). Any other overlap with an
   exclusive lock conflicts. A range that wraps past the 64-bit offsets is STATUS_INVALID_LOCK_RANGE. */
static
VOID
TestSharedInsideOwnExclusive(PFILE_OBJECT FileObject)
{
    FILE_LOCK FileLock;
    TEST_RANGE Excl = { 100, 100, NULL, 0, TRUE };
    TEST_RANGE Inner = { 120, 10, NULL, 0, FALSE };
    TEST_RANGE InnerKey = { 120, 10, NULL, 1, FALSE };
    TEST_RANGE Partial = { 150, 100, NULL, 0, FALSE };
    TEST_RANGE OtherExcl = { 120, 10, NULL, 0, TRUE };
    LARGE_INTEGER Offset, Length;
    IO_STATUS_BLOCK IoStatus;
    NTSTATUS Status;

    FsRtlInitializeFileLock(&FileLock, NULL, NULL);
    Excl.Process = ProcessA;
    Inner.Process = ProcessA;
    InnerKey.Process = ProcessA;
    Partial.Process = ProcessA;
    OtherExcl.Process = ProcessB;

    ok(TakeLock(&FileLock, FileObject, &Excl), "Exclusive lock not granted\n");
    ok(TakeLock(&FileLock, FileObject, &Inner), "Shared lock inside the owner's exclusive lock not granted\n");
    ok(!TakeLock(&FileLock, FileObject, &InnerKey), "Shared lock of another key inside an exclusive lock granted\n");
    ok(!TakeLock(&FileLock, FileObject, &Partial), "Shared lock reaching out of the exclusive lock granted\n");
    Inner.Process = ProcessB;
    ok(!TakeLock(&FileLock, FileObject, &Inner), "Shared lock of another process inside an exclusive lock granted\n");
    Inner.Process = ProcessA;

    Offset.QuadPart = 120;
    Length.QuadPart = 10;
    Status = FsRtlFastUnlockSingle(&FileLock, FileObject, &Offset, &Length, ProcessA, 0, NULL, FALSE);
    ok_eq_hex(Status, STATUS_SUCCESS);
    Status = FsRtlFastUnlockSingle(&FileLock, FileObject, &Offset, &Length, ProcessA, 0, NULL, FALSE);
    ok_eq_hex(Status, STATUS_RANGE_NOT_LOCKED);

    /* the shared lock outlives the exclusive lock it was taken inside */
    ok(TakeLock(&FileLock, FileObject, &Inner), "Shared lock inside the owner's exclusive lock not granted again\n");
    Offset.QuadPart = 100;
    Length.QuadPart = 100;
    Status = FsRtlFastUnlockSingle(&FileLock, FileObject, &Offset, &Length, ProcessA, 0, NULL, FALSE);
    ok_eq_hex(Status, STATUS_SUCCESS);
    ok(!TakeLock(&FileLock, FileObject, &OtherExcl), "Exclusive lock over a shared lock that was inside an exclusive lock granted\n");
    ok(!CanWrite(&FileLock, FileObject, 125, 1, ProcessB, 0), "Write into the shared range allowed\n");
    ok(CanWrite(&FileLock, FileObject, 150, 1, ProcessB, 0), "Write outside the shared range refused\n");
    Offset.QuadPart = 120;
    Length.QuadPart = 10;
    Status = FsRtlFastUnlockSingle(&FileLock, FileObject, &Offset, &Length, ProcessA, 0, NULL, FALSE);
    ok_eq_hex(Status, STATUS_SUCCESS);
    ok(TakeLock(&FileLock, FileObject, &OtherExcl), "Exclusive lock refused after the shared lock was unlocked\n");

    /* the shared lock goes with its owner's other locks */
    FsRtlFastUnlockAll(&FileLock, FileObject, ProcessB, NULL);
    ok(TakeLock(&FileLock, FileObject, &Excl), "Exclusive lock not granted\n");
    ok(TakeLock(&FileLock, FileObject, &Inner), "Shared lock inside the owner's exclusive lock not granted\n");
    Status = FsRtlFastUnlockAll(&FileLock, FileObject, ProcessA, NULL);
    ok_eq_hex(Status, STATUS_SUCCESS);
    ok(CanWrite(&FileLock, FileObject, 120, 10, ProcessB, 0), "Range still locked after FsRtlFastUnlockAll\n");

    /* a range that wraps */
    Offset.QuadPart = (LONGLONG)0xFFFFFFFFFFFFFF00ULL;
    Length.QuadPart = 0x200;
    IoStatus.Status = STATUS_UNSUCCESSFUL;
    ok(!FsRtlFastLock(&FileLock, FileObject, &Offset, &Length, ProcessA, 0, TRUE, TRUE, &IoStatus, NULL, FALSE),
       "Wrapping lock granted\n");
    ok_eq_hex(IoStatus.Status, STATUS_INVALID_LOCK_RANGE);
    FsRtlUninitializeFileLock(&FileLock);
}

START_TEST(FsRtlFileLock)
{
    PFILE_OBJECT FileObject;

    ProcessA = PsGetCurrentProcess();
    ProcessB = PsInitialSystemProcess;
    ok(ProcessA != ProcessB, "Test needs two processes\n");

    FileObject = AllocateFileObject();
    if (skip(FileObject != NULL, "No file object\n"))
        return;

    TestFirstLockVisible(FileObject);
    TestUnlockAllInterleaved(FileObject);
    TestUnlockAllByKey(FileObject);
    TestEnumeration(FileObject);
    TestSharedInsideOwnExclusive(FileObject);

    ExFreePoolWithTag(FileObject, 'kLsF');
}

START_TEST(FsRtlFileLockIrp)
{
    PFILE_OBJECT FileObject;

    ProcessA = PsGetCurrentProcess();
    ProcessB = PsInitialSystemProcess;
    FileObject = AllocateFileObject();
    if (skip(FileObject != NULL, "No file object\n"))
        return;

    TestLockIrps(FileObject);

    ExFreePoolWithTag(FileObject, 'kLsF');
}

/* Concurrency: the package must serialize itself (callers may hold only a shared resource) */

#define STRESS_THREADS 4

/* Distinct lock owners for the locker threads; only compared, never dereferenced */
static UCHAR LockerIdentity[STRESS_THREADS];

typedef struct _STRESS_STATE
{
    PFILE_LOCK FileLock;
    PFILE_OBJECT FileObject;
    KEVENT Start;
    ULONG Rounds;
    LONG Failures;
    LONG Index;
} STRESS_STATE, *PSTRESS_STATE;

static
VOID
NTAPI
FirstLockThread(PVOID Context)
{
    PSTRESS_STATE State = Context;
    LONG Index = InterlockedIncrement(&State->Index) - 1;
    TEST_RANGE Range;

    KeWaitForSingleObject(&State->Start, Executive, KernelMode, FALSE, NULL);
    Range.Start = Index * 100;
    Range.Length = 100;
    Range.Process = ProcessA;
    Range.Key = 0;
    Range.Exclusive = TRUE;
    if (!TakeLock(State->FileLock, State->FileObject, &Range) ||
        CanWrite(State->FileLock, State->FileObject, Range.Start, Range.Length, ProcessB, 0))
    {
        InterlockedIncrement(&State->Failures);
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static
VOID
NTAPI
LockerThread(PVOID Context)
{
    PSTRESS_STATE State = Context;
    LONG Index = InterlockedIncrement(&State->Index) - 1;
    LARGE_INTEGER Offset, Length;
    TEST_RANGE Range;
    ULONG i;

    KeWaitForSingleObject(&State->Start, Executive, KernelMode, FALSE, NULL);
    for (i = 0; i < State->Rounds; i++)
    {
        Range.Start = Index * 1000 + (i % 16) * 50;
        Range.Length = 25;
        Range.Process = (PEPROCESS)&LockerIdentity[Index % STRESS_THREADS];
        Range.Key = Index;
        Range.Exclusive = (i % 3) != 0;
        if (!TakeLock(State->FileLock, State->FileObject, &Range))
        {
            InterlockedIncrement(&State->Failures);
            continue;
        }
        if (Range.Exclusive &&
            CanRead(State->FileLock, State->FileObject, Range.Start, 1, ProcessA, 0))
        {
            InterlockedIncrement(&State->Failures);
        }
        if (i % 7 == 6)
        {
            FsRtlFastUnlockAll(State->FileLock, State->FileObject, Range.Process, NULL);
            continue;
        }
        Offset.QuadPart = Range.Start;
        Length.QuadPart = Range.Length;
        if (FsRtlFastUnlockSingle(State->FileLock, State->FileObject, &Offset, &Length,
                                  Range.Process, Range.Key, NULL, FALSE) != STATUS_SUCCESS)
        {
            InterlockedIncrement(&State->Failures);
        }
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static
VOID
NTAPI
CheckerThread(PVOID Context)
{
    PSTRESS_STATE State = Context;
    ULONG i;

    KeWaitForSingleObject(&State->Start, Executive, KernelMode, FALSE, NULL);
    for (i = 0; i < State->Rounds * 4; i++)
    {
        (void)CanRead(State->FileLock, State->FileObject, (i * 37) % 4000, 30, ProcessA, 0);
        (void)CanWrite(State->FileLock, State->FileObject, (i * 53) % 4000, 30, ProcessB, 1);
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static
BOOLEAN
RunThreads(PSTRESS_STATE State, PKSTART_ROUTINE *Routines, ULONG Count)
{
    OBJECT_ATTRIBUTES Attributes;
    PVOID Threads[STRESS_THREADS * 2];
    HANDLE Handle;
    NTSTATUS Status;
    ULONG i, Started = 0;

    ASSERT(Count <= RTL_NUMBER_OF(Threads));
    KeInitializeEvent(&State->Start, NotificationEvent, FALSE);
    State->Index = 0;
    InitializeObjectAttributes(&Attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    for (i = 0; i < Count; i++)
    {
        Status = PsCreateSystemThread(&Handle, THREAD_ALL_ACCESS, &Attributes, NULL, NULL, Routines[i], State);
        if (!NT_SUCCESS(Status)) break;
        Status = ObReferenceObjectByHandle(Handle, SYNCHRONIZE, *PsThreadType, KernelMode, &Threads[Started], NULL);
        ZwClose(Handle);
        if (!NT_SUCCESS(Status)) break;
        Started++;
    }
    KeSetEvent(&State->Start, IO_NO_INCREMENT, FALSE);
    for (i = 0; i < Started; i++)
    {
        KeWaitForSingleObject(Threads[i], Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(Threads[i]);
    }
    return Started == Count;
}

START_TEST(FsRtlFileLockStress)
{
    PKSTART_ROUTINE Routines[STRESS_THREADS * 2];
    STRESS_STATE State;
    FILE_LOCK FileLock;
    ULONG Round, i, Count, OfA, Lost = 0;
    BOOLEAN Started;

    ProcessA = PsGetCurrentProcess();
    ProcessB = PsInitialSystemProcess;
    RtlZeroMemory(&State, sizeof(State));
    State.FileLock = &FileLock;
    State.FileObject = AllocateFileObject();
    if (skip(State.FileObject != NULL, "No file object\n"))
        return;

    /* Concurrent first callers must install one table and lose no lock */
    for (i = 0; i < STRESS_THREADS; i++)
        Routines[i] = FirstLockThread;
    for (Round = 0; Round < 100; Round++)
    {
        FsRtlInitializeFileLock(&FileLock, NULL, NULL);
        if (!RunThreads(&State, Routines, STRESS_THREADS))
        {
            ok(FALSE, "Could not start the threads\n");
            break;
        }
        Count = CountLocks(&FileLock, ProcessA, &OfA);
        if (Count != STRESS_THREADS) Lost++;
        FsRtlUninitializeFileLock(&FileLock);
    }
    ok_eq_long(State.Failures, 0L);
    ok_eq_ulong(Lost, 0UL);

    /* Lock, unlock and check on one file from several threads at once */
    State.Failures = 0;
    State.Rounds = 20000;
    for (i = 0; i < STRESS_THREADS; i++)
        Routines[i] = LockerThread;
    for (; i < STRESS_THREADS * 2; i++)
        Routines[i] = CheckerThread;
    FsRtlInitializeFileLock(&FileLock, NULL, NULL);
    Started = RunThreads(&State, Routines, STRESS_THREADS * 2);
    ok_eq_bool(Started, TRUE);
    ok_eq_long(State.Failures, 0L);
    Count = CountLocks(&FileLock, ProcessA, &OfA);
    ok_eq_ulong(Count, 0UL);
    FsRtlUninitializeFileLock(&FileLock);

    ExFreePoolWithTag(State.FileObject, 'kLsF');
}
