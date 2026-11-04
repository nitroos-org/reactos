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
 * The test maps a freshly written file (non-cached writes, so no page of it is
 * resident) into system space and touches one new page per case from a system
 * thread: holding nothing, holding the file's resource shared, and holding it
 * exclusive. Every touch must return the file's data. A thread that does not
 * finish within the timeout is the deadlock; it is left behind (it cannot be
 * unblocked) and the test does not clean up after it.
 */

#include <kmt_test.h>

#define TEST_PAGES      16
#define TEST_TAG        'hFmM'
#define TOUCH_TIMEOUT   (-20LL * 10 * 1000 * 1000) /* 20 s */

typedef enum _HOLD_MODE { HoldNone, HoldShared, HoldExclusive } HOLD_MODE;

typedef struct _TOUCH_CONTEXT
{
    PUCHAR View;
    ULONG Page;
    PERESOURCE Resource;
    HOLD_MODE Hold;
    ULONG Value;
    NTSTATUS Status;
    KEVENT Done;
} TOUCH_CONTEXT, *PTOUCH_CONTEXT;

static ULONG
PageTag(ULONG Page, ULONG Index)
{
    return 0x4D460000UL ^ (Page << 8) ^ Index;
}

static KSTART_ROUTINE TouchThread;
static
VOID
NTAPI
TouchThread(PVOID Context)
{
    PTOUCH_CONTEXT Touch = Context;

    KeEnterCriticalRegion();
    if (Touch->Hold == HoldShared)
        ExAcquireResourceSharedLite(Touch->Resource, TRUE);
    else if (Touch->Hold == HoldExclusive)
        ExAcquireResourceExclusiveLite(Touch->Resource, TRUE);

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

    if (Touch->Hold != HoldNone)
        ExReleaseResourceLite(Touch->Resource);
    KeLeaveCriticalRegion();

    KeSetEvent(&Touch->Done, IO_NO_INCREMENT, FALSE);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

/* FALSE when the touching thread is stuck: its context is then leaked on purpose */
static
BOOLEAN
TouchPage(PUCHAR View, ULONG Page, PERESOURCE Resource, HOLD_MODE Hold, PCSTR What)
{
    PTOUCH_CONTEXT Touch;
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
    Touch->Status = STATUS_PENDING;
    KeInitializeEvent(&Touch->Done, NotificationEvent, FALSE);

    Status = PsCreateSystemThread(&Thread, THREAD_ALL_ACCESS, NULL, NULL, NULL, TouchThread, Touch);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(Touch, TEST_TAG);
        return TRUE;
    }
    ZwClose(Thread);

    Timeout.QuadPart = TOUCH_TIMEOUT;
    Status = KeWaitForSingleObject(&Touch->Done, Executive, KernelMode, FALSE, &Timeout);
    ok(Status == STATUS_SUCCESS, "%s: the fault on page %lu did not finish in 20 s (the thread waits for its own hold of the file)\n", What, Page);
    if (Status != STATUS_SUCCESS)
        return FALSE;

    ok(Touch->Status == STATUS_SUCCESS, "%s: touching page %lu raised %lx\n", What, Page, Touch->Status);
    ok(Touch->Value == PageTag(Page, 1), "%s: page %lu reads %lx, expected %lx\n", What, Page, Touch->Value, PageTag(Page, 1));

    /* The thread signals before it terminates; give it the moment to leave */
    Timeout.QuadPart = -100LL * 10 * 1000;
    KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
    ExFreePoolWithTag(Touch, TEST_TAG);
    return TRUE;
}

START_TEST(MmFaultFileHeld)
{
    UNICODE_STRING FileName = RTL_CONSTANT_STRING(L"\\SystemRoot\\kmtest-mmfaultheld.bin");
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK IoStatus;
    HANDLE File = NULL, Section = NULL;
    PFILE_OBJECT FileObject = NULL;
    PVOID SectionObject = NULL;
    PFSRTL_COMMON_FCB_HEADER FcbHeader;
    PUCHAR Buffer, View = NULL;
    SIZE_T ViewSize = 0;
    LARGE_INTEGER Offset;
    NTSTATUS Status;
    ULONG Page, i;
    BOOLEAN Stuck = FALSE;

    Buffer = ExAllocatePoolWithTag(NonPagedPool, TEST_PAGES * PAGE_SIZE, TEST_TAG);
    if (skip(Buffer != NULL, "No memory\n"))
        return;
    for (Page = 0; Page < TEST_PAGES; Page++)
        for (i = 0; i < PAGE_SIZE / sizeof(ULONG); i++)
            ((PULONG)(Buffer + Page * PAGE_SIZE))[i] = PageTag(Page, i);

    /* Non-cached writes: no page of the file is resident when the view is touched */
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

    /* A non-cached write with the section in place: the file system purges what it covers, so the
       segment holds no page of the file and every touch below takes the page-in path */
    Offset.QuadPart = 0;
    Status = ZwWriteFile(File, NULL, NULL, NULL, &IoStatus, Buffer, TEST_PAGES * PAGE_SIZE, &Offset, NULL);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (skip(NT_SUCCESS(Status), "Cannot write the file\n"))
    {
        MmUnmapViewInSystemSpace(View);
        goto DerefSection;
    }

    /* Each case touches a page nobody touched before, so each one faults the data in */
    if (!TouchPage(View, 1, FcbHeader->Resource, HoldNone, "No hold") ||
        !TouchPage(View, 3, FcbHeader->Resource, HoldExclusive, "Exclusive hold") ||
        !TouchPage(View, 5, FcbHeader->Resource, HoldShared, "Shared hold") ||
        !TouchPage(View, 7, FcbHeader->Resource, HoldShared, "Shared hold again"))
    {
        /* A stuck thread holds the file and a reference to the view: leave everything */
        Stuck = TRUE;
        goto Free;
    }

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
