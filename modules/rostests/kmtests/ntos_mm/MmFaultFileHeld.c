/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     A page fault on a file view while the faulting thread holds the file
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 *
 * A file system reads through the cache with the file's main resource held
 * shared (CcCopyRead, FsRtlCopyRead). When Mm takes a page of the cache view
 * away after Cc made it resident, the copy faults, and the fault pages the data
 * in. That path used to take the file exclusively first, so the thread waited
 * for its own shared hold forever (dmastall, 2026-11-04).
 *
 * The test maps a freshly written file into system space, purges the pages of it
 * that Mm and Cc kept (the fault only takes the page-in path for a page the
 * segment does not hold: without the purge the pages were there and the test
 * passed on a kernel without the fix), and touches one page in each of six
 * 64 KB chunks from a system thread: holding nothing, holding the file's
 * resource exclusive, holding it shared (twice), and holding only the file's
 * paging I/O resource, shared and then exclusive, while another thread holds the
 * main resource exclusive and waits for the paging resource exclusive (the order
 * of a size change, main then paging). A fault that took the file exclusively
 * there would wait for that thread, which waits for the faulting one.
 * Mm pages a file in by 64 KB, so the first touch
 * of a chunk brings in the rest of it: every case needs a chunk of its own, or
 * only the first one takes the page-in path (touching pages 1, 3, 5 and 7 of one
 * chunk passed on a kernel without the fix). Every touch must return the file's
 * data. A thread that does not finish within the timeout is the deadlock. The test
 * then releases the file on behalf of the stuck thread, which lets the fault go on
 * (it takes the file exclusively, as it did on its own), so the failure is reported
 * and the test ends in order, with the driver able to unload. Without that the
 * thread would stay in the driver for good and the run would hang with it.
 *
 * Windows does not call the file system's section synchronization (the FsFilter
 * AcquireForSectionSynchronization callbacks and the fast I/O
 * AcquireFileForNtCreateSection) when a fault pages data in: that is for creating
 * a section. While the touches run, the test counts the calls of the file system's
 * AcquireFileForNtCreateSection for this file (it puts a counting routine in the
 * slot, which then does what the slot did: FsRtl calls the slot right after the
 * FsFilter callbacks). Creating a section must count; no page-in may. A file
 * system whose FsFilter callback completes the acquire (fastfat, cdfs, ext2)
 * never gets to the slot, so creating a section does not count there and the
 * check is skipped; the touches still run.
 */

#include <kmt_test.h>

#define CHUNK_PAGES     16
#define TEST_CHUNKS     6
#define TEST_PAGES      (TEST_CHUNKS * CHUNK_PAGES)
#define TEST_TAG        'hFmM'
#define TOUCH_TIMEOUT   (-20LL * 10 * 1000 * 1000) /* 20 s */

typedef enum _HOLD_MODE { HoldNone, HoldShared, HoldExclusive } HOLD_MODE;

typedef struct _CONTENDER
{
    PERESOURCE MainResource;
    PERESOURCE PagingResource;
    KEVENT MainHeld;
    KEVENT Done;
} CONTENDER, *PCONTENDER;

typedef struct _TOUCH_CONTEXT
{
    PUCHAR View;
    ULONG Page;
    PERESOURCE Resource;
    HOLD_MODE Hold;
    BOOLEAN WaitForGo;
    ULONG Value;
    NTSTATUS Status;
    ERESOURCE_THREAD ResourceThread;
    LONG Released; /* the hold was given up, by the thread or by the test on its behalf */
    KEVENT Held;
    KEVENT Go;
    KEVENT Done;
} TOUCH_CONTEXT, *PTOUCH_CONTEXT;

/* The counting routine in the file system's AcquireFileForNtCreateSection slot */
static PFAST_IO_DISPATCH HookDispatch;
static PFAST_IO_ACQUIRE_FILE HookOriginalAcquire;
static PFAST_IO_RELEASE_FILE HookOriginalRelease;
static PVOID HookFcb;
static volatile LONG HookCount;

static
VOID
NTAPI
HookAcquireFileForNtCreateSection(PFILE_OBJECT FileObject)
{
    PFSRTL_COMMON_FCB_HEADER FcbHeader = FileObject->FsContext;

    if (FcbHeader == HookFcb)
        InterlockedIncrement(&HookCount);

    /* What FsRtl does with the slot, or without it */
    if (HookOriginalAcquire)
        HookOriginalAcquire(FileObject);
    else if (FcbHeader && FcbHeader->Resource)
        ExAcquireResourceExclusiveLite(FcbHeader->Resource, TRUE);
}

static
VOID
NTAPI
HookReleaseFileForNtCreateSection(PFILE_OBJECT FileObject)
{
    PFSRTL_COMMON_FCB_HEADER FcbHeader = FileObject->FsContext;

    if (HookOriginalRelease)
        HookOriginalRelease(FileObject);
    else if (FcbHeader && FcbHeader->Resource)
        ExReleaseResourceLite(FcbHeader->Resource);
}

static
BOOLEAN
HookInstall(PFILE_OBJECT FileObject)
{
    PDEVICE_OBJECT DeviceObject = IoGetRelatedDeviceObject(FileObject);
    PFAST_IO_DISPATCH Dispatch = DeviceObject->DriverObject->FastIoDispatch;

    if (!Dispatch || Dispatch->SizeOfFastIoDispatch < RTL_SIZEOF_THROUGH_FIELD(FAST_IO_DISPATCH, ReleaseFileForNtCreateSection))
        return FALSE;

    HookDispatch = Dispatch;
    HookFcb = FileObject->FsContext;
    HookCount = 0;
    HookOriginalAcquire = Dispatch->AcquireFileForNtCreateSection;
    HookOriginalRelease = Dispatch->ReleaseFileForNtCreateSection;
    /* Each routine does what the slot did, so a caller that sees one new and one old slot pairs up all the same */
    InterlockedExchangePointer((PVOID *)&Dispatch->ReleaseFileForNtCreateSection, (PVOID)HookReleaseFileForNtCreateSection);
    InterlockedExchangePointer((PVOID *)&Dispatch->AcquireFileForNtCreateSection, (PVOID)HookAcquireFileForNtCreateSection);
    return TRUE;
}

static
VOID
HookRemove(VOID)
{
    LARGE_INTEGER Delay;

    if (!HookDispatch)
        return;
    InterlockedExchangePointer((PVOID *)&HookDispatch->AcquireFileForNtCreateSection, (PVOID)HookOriginalAcquire);
    InterlockedExchangePointer((PVOID *)&HookDispatch->ReleaseFileForNtCreateSection, (PVOID)HookOriginalRelease);
    HookDispatch = NULL;
    /* Let a caller that is still inside one of the routines leave it before the driver can unload */
    Delay.QuadPart = -500LL * 10 * 1000;
    KeDelayExecutionThread(KernelMode, FALSE, &Delay);
}

static ULONG
PageTag(ULONG Page, ULONG Index)
{
    return 0x4D460000UL ^ (Page << 8) ^ Index;
}

static KSTART_ROUTINE ContenderThread;
static
VOID
NTAPI
ContenderThread(PVOID Context)
{
    PCONTENDER Contender = Context;

    /* A size change: main resource, then paging resource, both exclusive */
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(Contender->MainResource, TRUE);
    KeSetEvent(&Contender->MainHeld, IO_NO_INCREMENT, FALSE);
    ExAcquireResourceExclusiveLite(Contender->PagingResource, TRUE);
    ExReleaseResourceLite(Contender->PagingResource);
    ExReleaseResourceLite(Contender->MainResource);
    KeLeaveCriticalRegion();

    KeSetEvent(&Contender->Done, IO_NO_INCREMENT, FALSE);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static KSTART_ROUTINE TouchThread;
static
VOID
NTAPI
TouchThread(PVOID Context)
{
    PTOUCH_CONTEXT Touch = Context;

    KeEnterCriticalRegion();
    Touch->ResourceThread = ExGetCurrentResourceThread();
    if (Touch->Hold == HoldShared)
        ExAcquireResourceSharedLite(Touch->Resource, TRUE);
    else if (Touch->Hold == HoldExclusive)
        ExAcquireResourceExclusiveLite(Touch->Resource, TRUE);
    KeSetEvent(&Touch->Held, IO_NO_INCREMENT, FALSE);
    if (Touch->WaitForGo)
        KeWaitForSingleObject(&Touch->Go, Executive, KernelMode, FALSE, NULL);

    _SEH2_TRY
    {
        Touch->Value = *(volatile ULONG *)(Touch->View + Touch->Page * PAGE_SIZE + sizeof(ULONG));
        Touch->Status = STATUS_SUCCESS;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Touch->Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;

    if (Touch->Hold != HoldNone && InterlockedCompareExchange(&Touch->Released, 1, 0) == 0)
        ExReleaseResourceLite(Touch->Resource);
    KeLeaveCriticalRegion();

    KeSetEvent(&Touch->Done, IO_NO_INCREMENT, FALSE);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

/* Start the contender and wait until it holds the main resource. FALSE if it could not be started */
static
BOOLEAN
StartContender(PCONTENDER Contender, PFSRTL_COMMON_FCB_HEADER FcbHeader)
{
    HANDLE Thread;
    NTSTATUS Status;
    LARGE_INTEGER Timeout;

    Contender->MainResource = FcbHeader->Resource;
    Contender->PagingResource = FcbHeader->PagingIoResource;
    KeInitializeEvent(&Contender->MainHeld, NotificationEvent, FALSE);
    KeInitializeEvent(&Contender->Done, NotificationEvent, FALSE);
    Status = PsCreateSystemThread(&Thread, THREAD_ALL_ACCESS, NULL, NULL, NULL, ContenderThread, Contender);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return FALSE;
    ZwClose(Thread);

    /* Nobody else holds the test file's main resource: this does not wait long */
    Timeout.QuadPart = TOUCH_TIMEOUT;
    Status = KeWaitForSingleObject(&Contender->MainHeld, Executive, KernelMode, FALSE, &Timeout);
    ok(Status == STATUS_SUCCESS, "The contender did not get the main resource\n");
    /* Give it the moment to queue for the paging resource */
    Timeout.QuadPart = -200LL * 10 * 1000;
    KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
    return TRUE;
}

/* FALSE when the touching thread was stuck. *Leaked is set when it still is after the test gave its hold up:
   its context is then left alone on purpose. With Contender, the touch holds Resource (the paging resource)
   before the contender takes the main resource and queues for the paging one, and faults after that */
static
BOOLEAN
TouchPage(PUCHAR View, ULONG Page, PERESOURCE Resource, HOLD_MODE Hold, PFSRTL_COMMON_FCB_HEADER Contended,
          PCSTR What, PBOOLEAN Leaked)
{
    PTOUCH_CONTEXT Touch;
    CONTENDER Contender;
    BOOLEAN ContenderRuns = FALSE;
    BOOLEAN Result = TRUE;
    HANDLE Thread;
    NTSTATUS Status;
    LARGE_INTEGER Timeout;

    /* The case only means something when the page has to be faulted in */
    ok(!MmIsAddressValid(View + Page * PAGE_SIZE), "%s: page %lu is already resident, the fault path is not exercised\n", What, Page);

    Touch = ExAllocatePoolZero(NonPagedPool, sizeof(*Touch), TEST_TAG);
    if (skip(Touch != NULL, "No memory\n"))
        return TRUE;

    Touch->View = View;
    Touch->Page = Page;
    Touch->Resource = Resource;
    Touch->Hold = Hold;
    Touch->WaitForGo = (Contended != NULL);
    Touch->Status = STATUS_PENDING;
    KeInitializeEvent(&Touch->Held, NotificationEvent, FALSE);
    KeInitializeEvent(&Touch->Go, NotificationEvent, FALSE);
    KeInitializeEvent(&Touch->Done, NotificationEvent, FALSE);

    Status = PsCreateSystemThread(&Thread, THREAD_ALL_ACCESS, NULL, NULL, NULL, TouchThread, Touch);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(Touch, TEST_TAG);
        return TRUE;
    }
    ZwClose(Thread);

    if (Contended)
    {
        KeWaitForSingleObject(&Touch->Held, Executive, KernelMode, FALSE, NULL);
        ContenderRuns = StartContender(&Contender, Contended);
        KeSetEvent(&Touch->Go, IO_NO_INCREMENT, FALSE);
    }

    Timeout.QuadPart = TOUCH_TIMEOUT;
    Status = KeWaitForSingleObject(&Touch->Done, Executive, KernelMode, FALSE, &Timeout);
    ok(Status == STATUS_SUCCESS, "%s: the fault on page %lu did not finish in 20 s (the thread waits for its own hold of the file)\n", What, Page);
    if (Status != STATUS_SUCCESS)
    {
        /* Give the hold up for the thread: its wait for the file goes on, and the fault ends */
        if (Hold != HoldNone && InterlockedCompareExchange(&Touch->Released, 1, 0) == 0)
            ExReleaseResourceForThreadLite(Resource, Touch->ResourceThread);
        Timeout.QuadPart = TOUCH_TIMEOUT / 2;
        Status = KeWaitForSingleObject(&Touch->Done, Executive, KernelMode, FALSE, &Timeout);
        ok(Status == STATUS_SUCCESS, "%s: the fault on page %lu did not finish after the hold was given up\n", What, Page);
        if (Status != STATUS_SUCCESS)
        {
            *Leaked = TRUE;
            return FALSE;
        }
        Result = FALSE;
    }
    else
    {
        ok(Touch->Status == STATUS_SUCCESS, "%s: touching page %lu raised %lx\n", What, Page, Touch->Status);
        ok(Touch->Value == PageTag(Page, 1), "%s: page %lu reads %lx, expected %lx\n", What, Page, Touch->Value, PageTag(Page, 1));
    }

    if (ContenderRuns)
    {
        /* With the touch's hold gone, the contender gets the paging resource and leaves */
        Timeout.QuadPart = TOUCH_TIMEOUT;
        Status = KeWaitForSingleObject(&Contender.Done, Executive, KernelMode, FALSE, &Timeout);
        ok(Status == STATUS_SUCCESS, "%s: the contender did not finish\n", What);
        if (Status != STATUS_SUCCESS)
        {
            /* It still uses Contender, on our stack: do not return */
            KeWaitForSingleObject(&Contender.Done, Executive, KernelMode, FALSE, NULL);
        }
    }

    /* The thread signals before it terminates; give it the moment to leave */
    Timeout.QuadPart = -100LL * 10 * 1000;
    KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
    ExFreePoolWithTag(Touch, TEST_TAG);
    return Result;
}

START_TEST(MmFaultFileHeld)
{
    UNICODE_STRING FileName = RTL_CONSTANT_STRING(L"\\SystemRoot\\kmtest-mmfaultheld.bin");
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK IoStatus;
    HANDLE File = NULL, Section = NULL, Section2 = NULL;
    PFILE_OBJECT FileObject = NULL;
    PVOID SectionObject = NULL;
    PFSRTL_COMMON_FCB_HEADER FcbHeader;
    PUCHAR Buffer, View = NULL;
    SIZE_T ViewSize = 0;
    LARGE_INTEGER Offset;
    NTSTATUS Status;
    ULONG Page, Chunk, i;
    BOOLEAN Stuck = FALSE, Purged, Hooked, HavePaging;
    LONG Count;

    Buffer = ExAllocatePoolWithTag(NonPagedPool, CHUNK_PAGES * PAGE_SIZE, TEST_TAG);
    if (skip(Buffer != NULL, "No memory\n"))
        return;

    /* Non-cached writes */
    InitializeObjectAttributes(&Attributes, &FileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = ZwCreateFile(&File, GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE, &Attributes, &IoStatus, NULL,
                          FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OVERWRITE_IF,
                          FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_NO_INTERMEDIATE_BUFFERING,
                          NULL, 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (skip(NT_SUCCESS(Status), "Cannot create %wZ\n", &FileName))
        goto Free;

    {
        FILE_END_OF_FILE_INFORMATION Eof;
        Eof.EndOfFile.QuadPart = TEST_PAGES * PAGE_SIZE;
        Status = ZwSetInformationFile(File, &IoStatus, &Eof, sizeof(Eof), FileEndOfFileInformation);
        ok_eq_hex(Status, STATUS_SUCCESS);
        if (skip(NT_SUCCESS(Status), "Cannot size the file\n"))
            goto Close;
    }

    Status = ObReferenceObjectByHandle(File, FILE_READ_DATA, *IoFileObjectType, KernelMode, (PVOID *)&FileObject, NULL);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (skip(NT_SUCCESS(Status), "No file object\n"))
        goto Close;
    FcbHeader = FileObject->FsContext;
    if (skip(FcbHeader != NULL && FcbHeader->Resource != NULL, "The file system keeps no FCB resource\n"))
        goto Deref;
    HavePaging = (FcbHeader->PagingIoResource != NULL);

    InitializeObjectAttributes(&Attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = ZwCreateSection(&Section, SECTION_MAP_READ | SECTION_QUERY, &Attributes, NULL, PAGE_READONLY, SEC_COMMIT, File);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (skip(NT_SUCCESS(Status), "Cannot create the section\n"))
        goto Deref;
    Status = ObReferenceObjectByHandle(Section, SECTION_MAP_READ, MmSectionObjectType, KernelMode, &SectionObject, NULL);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (skip(NT_SUCCESS(Status), "No section object\n"))
        goto CloseSection;
    Status = MmMapViewInSystemSpace(SectionObject, (PVOID *)&View, &ViewSize);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (skip(NT_SUCCESS(Status), "Cannot map the view\n"))
        goto DerefSection;
    ok(ViewSize >= TEST_PAGES * PAGE_SIZE, "View size %Iu\n", ViewSize);

    /* Non-cached writes with the section in place */
    Status = STATUS_SUCCESS;
    for (Chunk = 0; Chunk < TEST_CHUNKS && NT_SUCCESS(Status); Chunk++)
    {
        for (Page = 0; Page < CHUNK_PAGES; Page++)
            for (i = 0; i < PAGE_SIZE / sizeof(ULONG); i++)
                ((PULONG)(Buffer + Page * PAGE_SIZE))[i] = PageTag(Chunk * CHUNK_PAGES + Page, i);
        Offset.QuadPart = (LONGLONG)Chunk * CHUNK_PAGES * PAGE_SIZE;
        Status = ZwWriteFile(File, NULL, NULL, NULL, &IoStatus, Buffer, CHUNK_PAGES * PAGE_SIZE, &Offset, NULL);
    }
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (skip(NT_SUCCESS(Status), "Cannot write the file\n"))
    {
        MmUnmapViewInSystemSpace(View);
        goto DerefSection;
    }

    /* Count the file system's section synchronization for this file from here on. The control: creating a
       section calls it */
    Hooked = HookInstall(FileObject);
    if (!skip(Hooked, "The file system has no fast I/O dispatch to count section synchronization in\n"))
    {
        InitializeObjectAttributes(&Attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
        Status = ZwCreateSection(&Section2, SECTION_MAP_READ | SECTION_QUERY, &Attributes, NULL, PAGE_READONLY, SEC_COMMIT, File);
        ok_eq_hex(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status))
            ZwClose(Section2);
        Count = InterlockedExchange(&HookCount, 0);
        /* A file system that synchronizes section creation in an FsFilter callback (fastfat, cdfs, ext2) completes
           it there, and FsRtl does not call the slot: the count shows nothing on it */
        Hooked = (Count != 0);
        skip(Hooked, "Creating a section did not call the file system's AcquireFileForNtCreateSection (synchronized in an FsFilter callback): no count\n");
    }

    /* The write and the view leave pages of the file in the segment (Cc keeps its own views of the same
       section), and a fault on one of those never takes the page-in path. Take them out. */
    Purged = CcPurgeCacheSection(FileObject->SectionObjectPointer, NULL, 0, FALSE);
    ok(Purged, "CcPurgeCacheSection did not purge the file\n");

    /* Each case touches one page of a chunk nobody touched before, so each one faults a cluster in. A case that
       fails does not stop the others; a thread that is stuck for good (it still holds a reference to the view)
       stops everything, and everything is left */
    TouchPage(View, 0 * CHUNK_PAGES + 1, FcbHeader->Resource, HoldNone, NULL, "No hold", &Stuck);
    if (!Stuck)
        TouchPage(View, 1 * CHUNK_PAGES + 1, FcbHeader->Resource, HoldExclusive, NULL, "Exclusive hold", &Stuck);
    if (!Stuck)
        TouchPage(View, 2 * CHUNK_PAGES + 1, FcbHeader->Resource, HoldShared, NULL, "Shared hold", &Stuck);
    if (!Stuck)
        TouchPage(View, 3 * CHUNK_PAGES + 1, FcbHeader->Resource, HoldShared, NULL, "Shared hold again", &Stuck);

    /* Only the paging resource, with a size change queued behind it */
    if (!Stuck && !skip(HavePaging, "The file system keeps no paging I/O resource\n"))
    {
        TouchPage(View, 4 * CHUNK_PAGES + 1, FcbHeader->PagingIoResource, HoldShared, FcbHeader,
                  "Paging resource shared, size change waiting", &Stuck);
        if (!Stuck)
            TouchPage(View, 5 * CHUNK_PAGES + 1, FcbHeader->PagingIoResource, HoldExclusive, FcbHeader,
                      "Paging resource exclusive, size change waiting", &Stuck);
    }
    if (Stuck)
        goto Unhook;

    if (Hooked)
    {
        Count = InterlockedExchange(&HookCount, 0);
        ok(Count == 0, "The page-ins called the file system's section synchronization (AcquireFileForNtCreateSection) %ld times\n", Count);
    }

Unhook:
    HookRemove();
    if (Stuck)
        goto Free;

    MmUnmapViewInSystemSpace(View);
DerefSection:
    ObDereferenceObject(SectionObject);
CloseSection:
    ZwClose(Section);
Deref:
    ObDereferenceObject(FileObject);
Close:
    {
        FILE_DISPOSITION_INFORMATION Disposition = { TRUE };
        ZwSetInformationFile(File, &IoStatus, &Disposition, sizeof(Disposition), FileDispositionInformation);
    }
    ZwClose(File);
Free:
    if (!Stuck)
        ExFreePoolWithTag(Buffer, TEST_TAG);
}
