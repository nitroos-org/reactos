/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test driver for the lazy write of ranges pinned for writing
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <kmt_test.h>

#define NDEBUG
#include <debug.h>

#define IOCTL_RUN_TEST 1

/* One view: page 0 is pinned by the tests, page 1 is a control page in the same view */
#define TEST_PAGES (VACB_MAPPING_GRANULARITY / PAGE_SIZE)
#define HELD_PAGE 0
#define CONTROL_PAGE 1

typedef struct _TEST_FCB
{
    FSRTL_ADVANCED_FCB_HEADER Header;
    SECTION_OBJECT_POINTERS SectionObjectPointers;
    FAST_MUTEX HeaderMutex;
} TEST_FCB, *PTEST_FCB;

static KMT_IRP_HANDLER TestIrpHandler;
static KMT_MESSAGE_HANDLER TestMessageHandler;

static PTEST_FCB TestFcb;
static PFILE_OBJECT TestFileObject;

/* The "disk": the first ULONG of every page as last written, and how many times each page was written */
static volatile ULONG DiskValue[TEST_PAGES];
static volatile LONG WriteCount[TEST_PAGES];

NTSTATUS
TestEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PCUNICODE_STRING RegistryPath,
    _Out_ PCWSTR *DeviceName,
    _Inout_ INT *Flags)
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    *DeviceName = L"CcPinLazyWrite";
    *Flags = TESTENTRY_NO_EXCLUSIVE_DEVICE |
             TESTENTRY_BUFFERED_IO_DEVICE |
             TESTENTRY_NO_READONLY_DEVICE;

    KmtRegisterIrpHandler(IRP_MJ_READ, NULL, TestIrpHandler);
    KmtRegisterIrpHandler(IRP_MJ_WRITE, NULL, TestIrpHandler);
    KmtRegisterMessageHandler(0, NULL, TestMessageHandler);

    return STATUS_SUCCESS;
}

VOID
TestUnload(
    _In_ PDRIVER_OBJECT DriverObject)
{
    PAGED_CODE();
}

static
BOOLEAN
NTAPI
AcquireForLazyWrite(
    _In_ PVOID Context,
    _In_ BOOLEAN Wait)
{
    return TRUE;
}

static
VOID
NTAPI
ReleaseFromLazyWrite(
    _In_ PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
}

static
BOOLEAN
NTAPI
AcquireForReadAhead(
    _In_ PVOID Context,
    _In_ BOOLEAN Wait)
{
    return TRUE;
}

static
VOID
NTAPI
ReleaseFromReadAhead(
    _In_ PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
}

static CACHE_MANAGER_CALLBACKS Callbacks = {
    AcquireForLazyWrite,
    ReleaseFromLazyWrite,
    AcquireForReadAhead,
    ReleaseFromReadAhead,
};

static
BOOLEAN
SetupFile(
    _In_ PDEVICE_OBJECT DeviceObject)
{
    PTEST_FCB Fcb;
    PFILE_OBJECT FileObject;

    FileObject = IoCreateStreamFileObject(NULL, DeviceObject);
    if (skip(FileObject != NULL, "Failed to allocate FO\n"))
        return FALSE;

    Fcb = ExAllocatePoolWithTag(NonPagedPool, sizeof(TEST_FCB), 'WlpK');
    if (skip(Fcb != NULL, "Failed to allocate FCB\n"))
    {
        ObDereferenceObject(FileObject);
        return FALSE;
    }

    RtlZeroMemory(Fcb, sizeof(TEST_FCB));
    ExInitializeFastMutex(&Fcb->HeaderMutex);
    FsRtlSetupAdvancedHeader(&Fcb->Header, &Fcb->HeaderMutex);
    Fcb->Header.AllocationSize.QuadPart = VACB_MAPPING_GRANULARITY;
    Fcb->Header.FileSize.QuadPart = VACB_MAPPING_GRANULARITY;
    Fcb->Header.ValidDataLength.QuadPart = VACB_MAPPING_GRANULARITY;
    FileObject->FsContext = Fcb;
    FileObject->SectionObjectPointer = &Fcb->SectionObjectPointers;

    TestFcb = Fcb;
    TestFileObject = FileObject;

    KmtStartSeh();
    CcInitializeCacheMap(FileObject, (PCC_FILE_SIZES)&Fcb->Header.AllocationSize, TRUE, &Callbacks, Fcb);
    KmtEndSeh(STATUS_SUCCESS);

    return !skip(CcIsFileCached(FileObject) == TRUE, "CcInitializeCacheMap failed\n");
}

static
VOID
FreeFile(VOID)
{
    CACHE_UNINITIALIZE_EVENT UninitEvent;

    if (TestFileObject)
    {
        if (CcIsFileCached(TestFileObject))
        {
            KeInitializeEvent(&UninitEvent.Event, NotificationEvent, FALSE);
            CcUninitializeCacheMap(TestFileObject, NULL, &UninitEvent);
            KeWaitForSingleObject(&UninitEvent.Event, Executive, KernelMode, FALSE, NULL);
        }

        /* Drop the pages Mm still holds, so that its section lets the file object go */
        CcPurgeCacheSection(TestFileObject->SectionObjectPointer, NULL, 0, FALSE);
        TestFileObject->FsContext = NULL;
        TestFileObject->SectionObjectPointer = NULL;
        ObDereferenceObject(TestFileObject);
        TestFileObject = NULL;
    }
    if (TestFcb)
    {
        ExFreePoolWithTag(TestFcb, 'WlpK');
        TestFcb = NULL;
    }
}

static
PVOID
PinPage(
    _In_ ULONG Page,
    _In_ ULONG Flags,
    _Out_ PULONG *Buffer)
{
    LARGE_INTEGER Offset;
    PVOID Bcb = NULL;
    BOOLEAN Ret = FALSE;

    *Buffer = NULL;
    Offset.QuadPart = (LONGLONG)Page * PAGE_SIZE;
    KmtStartSeh();
    Ret = CcPinRead(TestFileObject, &Offset, PAGE_SIZE, Flags, &Bcb, (PVOID *)Buffer);
    KmtEndSeh(STATUS_SUCCESS);
    ok(Ret == TRUE, "CcPinRead of page %lu failed\n", Page);
    return Ret ? Bcb : NULL;
}

/* A page changed under a short pin and unpinned at once, as file systems do for most of their metadata */
static
VOID
DirtyPage(
    _In_ ULONG Page,
    _In_ ULONG Value)
{
    PULONG Buffer;
    PVOID Bcb = PinPage(Page, PIN_WAIT, &Buffer);

    if (Bcb)
    {
        Buffer[0] = Value;
        CcSetDirtyPinnedData(Bcb, NULL);
        CcUnpinData(Bcb);
    }
}

static
VOID
FlushFile(VOID)
{
    IO_STATUS_BLOCK Iosb;

    CcFlushCache(TestFileObject->SectionObjectPointer, NULL, 0, &Iosb);
    ok_eq_hex(Iosb.Status, STATUS_SUCCESS);
}

/*
 * Dirties the control page and waits (up to 30 s) until the lazy writer has written it: a lazy write of the view
 * that holds the pinned page has run.  FALSE if none came.
 */
static
BOOLEAN
WaitForLazyWrite(VOID)
{
    LARGE_INTEGER Interval;
    LONG Before = WriteCount[CONTROL_PAGE];
    ULONG i;

    DirtyPage(CONTROL_PAGE, 0xC0C0C0C0 + Before);

    Interval.QuadPart = -100 * 10000LL;
    for (i = 0; i < 300; i++)
    {
        if (WriteCount[CONTROL_PAGE] != Before)
            return TRUE;
        KeDelayExecutionThread(KernelMode, FALSE, &Interval);
    }

    return FALSE;
}

/*
 * fastfat's pattern: the pinned range is made dirty first, changed afterwards.  No lazy write may take it while it
 * is pinned, and what it holds at the unpin is what reaches the disk, without another CcSetDirtyPinnedData.
 */
static
VOID
TestDirtyThenChange(VOID)
{
    PULONG Buffer;
    PVOID Bcb;
    LONG Writes;

    Bcb = PinPage(HELD_PAGE, PIN_WAIT, &Buffer);
    if (!Bcb)
        return;

    CcSetDirtyPinnedData(Bcb, NULL);
    Buffer[0] = 0xA1A1A1A1;
    Writes = WriteCount[HELD_PAGE];

    ok(WaitForLazyWrite(), "No lazy write of the view within 30 s\n");
    ok_eq_long(WriteCount[HELD_PAGE], Writes);
    ok(DiskValue[HELD_PAGE] != 0xA1A1A1A1, "The lazy writer wrote a pinned range (0x%lx)\n", DiskValue[HELD_PAGE]);

    Buffer[0] = 0xF1F1F1F1;
    CcUnpinData(Bcb);

    FlushFile();
    ok_eq_hex(DiskValue[HELD_PAGE], 0xF1F1F1F1UL);
}

/* A range pinned exclusive is held back too, and written once dirty and unpinned */
static
VOID
TestExclusive(VOID)
{
    PULONG Buffer;
    PVOID Bcb;
    LONG Writes;

    /* Dirty already (from an earlier pin), then pinned exclusive and changed */
    DirtyPage(HELD_PAGE, 0xB0B0B0B0);
    Bcb = PinPage(HELD_PAGE, PIN_WAIT | PIN_EXCLUSIVE, &Buffer);
    if (!Bcb)
        return;

    Buffer[0] = 0xB1B1B1B1;
    Writes = WriteCount[HELD_PAGE];

    ok(WaitForLazyWrite(), "No lazy write of the view within 30 s\n");
    ok_eq_long(WriteCount[HELD_PAGE], Writes);

    Buffer[0] = 0xB2B2B2B2;
    CcSetDirtyPinnedData(Bcb, NULL);
    CcUnpinData(Bcb);

    /* Unpinned: the lazy writer takes it now */
    ok(WaitForLazyWrite(), "No lazy write of the view within 30 s\n");
    ok_eq_hex(DiskValue[HELD_PAGE], 0xB2B2B2B2UL);
}

/*
 * The file system flushes a range it holds pinned: the flush writes it (and does not wait for the unpin, which would
 * never come); a change made after that flush still reaches the disk once unpinned.
 */
static
VOID
TestFlushWhilePinned(VOID)
{
    LARGE_INTEGER Offset;
    IO_STATUS_BLOCK Iosb;
    PULONG Buffer;
    PVOID Bcb;

    Bcb = PinPage(HELD_PAGE, PIN_WAIT | PIN_EXCLUSIVE, &Buffer);
    if (!Bcb)
        return;

    CcSetDirtyPinnedData(Bcb, NULL);
    Buffer[0] = 0xD1D1D1D1;

    Offset.QuadPart = HELD_PAGE * PAGE_SIZE;
    CcFlushCache(TestFileObject->SectionObjectPointer, &Offset, PAGE_SIZE, &Iosb);
    ok_eq_hex(Iosb.Status, STATUS_SUCCESS);
    ok_eq_hex(DiskValue[HELD_PAGE], 0xD1D1D1D1UL);

    Buffer[0] = 0xD2D2D2D2;
    CcUnpinData(Bcb);

    FlushFile();
    ok_eq_hex(DiskValue[HELD_PAGE], 0xD2D2D2D2UL);
}

/* A repinned range stays held back after CcUnpinData, until CcUnpinRepinnedBcb */
static
VOID
TestRepinned(VOID)
{
    IO_STATUS_BLOCK Iosb;
    PULONG Buffer;
    PVOID Bcb;
    LONG Writes;

    Bcb = PinPage(HELD_PAGE, PIN_WAIT, &Buffer);
    if (!Bcb)
        return;

    CcSetDirtyPinnedData(Bcb, NULL);
    Buffer[0] = 0xE1E1E1E1;
    CcRepinBcb(Bcb);
    CcUnpinData(Bcb);
    Writes = WriteCount[HELD_PAGE];

    ok(WaitForLazyWrite(), "No lazy write of the view within 30 s\n");
    ok_eq_long(WriteCount[HELD_PAGE], Writes);

    Buffer[0] = 0xE2E2E2E2;
    CcUnpinRepinnedBcb(Bcb, FALSE, &Iosb);
    ok_eq_hex(Iosb.Status, STATUS_SUCCESS);

    FlushFile();
    ok_eq_hex(DiskValue[HELD_PAGE], 0xE2E2E2E2UL);
}

static KEVENT FlushDoneEvent;

static
VOID
NTAPI
FlushThread(
    _In_ PVOID Context)
{
    IO_STATUS_BLOCK Iosb;

    UNREFERENCED_PARAMETER(Context);

    CcFlushCache(TestFileObject->SectionObjectPointer, NULL, 0, &Iosb);
    KeSetEvent(&FlushDoneEvent, IO_NO_INCREMENT, FALSE);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

/* Another thread flushes the file while a range of it is pinned exclusive: it does not wait for the pin */
static
VOID
TestFlushFromOtherThread(VOID)
{
    LARGE_INTEGER Timeout;
    HANDLE Thread;
    PULONG Buffer;
    PVOID Bcb, ThreadObject = NULL;
    NTSTATUS Status;

    Bcb = PinPage(HELD_PAGE, PIN_WAIT | PIN_EXCLUSIVE, &Buffer);
    if (!Bcb)
        return;

    Buffer[0] = 0x0F0F0F0F;
    CcSetDirtyPinnedData(Bcb, NULL);

    KeInitializeEvent(&FlushDoneEvent, NotificationEvent, FALSE);
    Status = PsCreateSystemThread(&Thread, THREAD_ALL_ACCESS, NULL, NULL, NULL, FlushThread, NULL);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        ObReferenceObjectByHandle(Thread, SYNCHRONIZE, *PsThreadType, KernelMode, &ThreadObject, NULL);
        ZwClose(Thread);

        Timeout.QuadPart = -30 * 10000000LL;
        Status = KeWaitForSingleObject(&FlushDoneEvent, Executive, KernelMode, FALSE, &Timeout);
        ok_eq_hex(Status, STATUS_SUCCESS);
    }

    CcUnpinData(Bcb);

    if (ThreadObject)
    {
        KeWaitForSingleObject(ThreadObject, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(ThreadObject);
    }

    FlushFile();
    ok_eq_hex(DiskValue[HELD_PAGE], 0x0F0F0F0FUL);
}

static
VOID
RunTest(
    _In_ PDEVICE_OBJECT DeviceObject)
{
    RtlZeroMemory((PVOID)DiskValue, sizeof(DiskValue));
    RtlZeroMemory((PVOID)WriteCount, sizeof(WriteCount));

    if (SetupFile(DeviceObject))
    {
        TestDirtyThenChange();
        FlushFile();
        TestExclusive();
        FlushFile();
        TestFlushWhilePinned();
        FlushFile();
        TestRepinned();
        FlushFile();
        TestFlushFromOtherThread();
        FlushFile();
    }

    FreeFile();
}

static
NTSTATUS
TestMessageHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG ControlCode,
    _In_opt_ PVOID Buffer,
    _In_ SIZE_T InLength,
    _Inout_ PSIZE_T OutLength)
{
    NTSTATUS Status = STATUS_SUCCESS;

    switch (ControlCode)
    {
        case IOCTL_RUN_TEST:
            FsRtlEnterFileSystem();
            RunTest(DeviceObject);
            FsRtlExitFileSystem();
            break;

        default:
            Status = STATUS_NOT_IMPLEMENTED;
            break;
    }

    return Status;
}

static
NTSTATUS
TestIrpHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStack)
{
    NTSTATUS Status = STATUS_SUCCESS;
    LONGLONG Offset;
    ULONG Length, Page;
    PUCHAR Buffer;

    PAGED_CODE();

    ASSERT(IoStack->MajorFunction == IRP_MJ_READ ||
           IoStack->MajorFunction == IRP_MJ_WRITE);

    FsRtlEnterFileSystem();

    Buffer = Irp->MdlAddress ? MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority) : NULL;
    ok(Buffer != NULL, "No buffer for a paging request\n");

    if (IoStack->MajorFunction == IRP_MJ_READ)
    {
        Offset = IoStack->Parameters.Read.ByteOffset.QuadPart;
        Length = IoStack->Parameters.Read.Length;
    }
    else
    {
        Offset = IoStack->Parameters.Write.ByteOffset.QuadPart;
        Length = IoStack->Parameters.Write.Length;
    }

    if (!Buffer)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        Length = 0;
    }
    else if (IoStack->MajorFunction == IRP_MJ_READ)
    {
        /* What the disk holds: the first ULONG of each page as last written, zeros elsewhere */
        RtlZeroMemory(Buffer, Length);
        for (Page = 0; Page * PAGE_SIZE < Length; Page++)
        {
            if ((ULONGLONG)(Offset / PAGE_SIZE) + Page < TEST_PAGES)
                ((PULONG)(Buffer + Page * PAGE_SIZE))[0] = DiskValue[Offset / PAGE_SIZE + Page];
        }
    }
    else
    {
        for (Page = 0; Page * PAGE_SIZE < Length; Page++)
        {
            if ((ULONGLONG)(Offset / PAGE_SIZE) + Page < TEST_PAGES)
            {
                DiskValue[Offset / PAGE_SIZE + Page] = ((PULONG)(Buffer + Page * PAGE_SIZE))[0];
                InterlockedIncrement(&WriteCount[Offset / PAGE_SIZE + Page]);
            }
        }
    }

    Irp->IoStatus.Information = Length;
    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    FsRtlExitFileSystem();

    return Status;
}
