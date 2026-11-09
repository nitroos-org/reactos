/*
 * PROJECT:     ReactOS Kernel
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Paging file functions
 * COPYRIGHT:   Copyright 1998-2003 David Welch <welch@mcmail.com>
 *              Copyright 2010-2018 Pierre Schweitzer <pierre@reactos.org>
 */

/* INCLUDES *****************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

/* Minimum pagefile size is 256 pages (1 MB) */
#define MINIMUM_PAGEFILE_SIZE       (256ULL * PAGE_SIZE)

/* Maximum pagefile sizes for different architectures */
#if defined(_M_IX86) && !defined(_X86PAE_)
/* Around 4 GB */
    #define MAXIMUM_PAGEFILE_SIZE   ((1ULL * 1024 * 1024 - 1) * PAGE_SIZE)
                                 // PAGE_ROUND_DOWN(4ULL * GIGABYTE - 1)
/* PAE uses the same size as x64 */
#elif (defined(_M_IX86) && defined(_X86PAE_)) || defined (_M_AMD64) || defined(_M_ARM64)
/* Around 16 TB */
    #if (NTDDI_VERSION >= NTDDI_WIN10)
    #define MAXIMUM_PAGEFILE_SIZE   ((4ULL * 1024 * 1024 * 1024 - 2) * PAGE_SIZE)
                                 // PAGE_ROUND_DOWN(16ULL * TERABYTE - PAGE_SIZE - 1)
    #else
    #define MAXIMUM_PAGEFILE_SIZE   ((4ULL * 1024 * 1024 * 1024 - 1) * PAGE_SIZE)
                                 // PAGE_ROUND_DOWN(16ULL * TERABYTE - 1)
    #endif
#elif defined (_M_IA64)
/* Around 32 TB */
    #define MAXIMUM_PAGEFILE_SIZE   ((8ULL * 1024 * 1024 * 1024 - 1) * PAGE_SIZE)
                                 // PAGE_ROUND_DOWN(32ULL * TERABYTE - 1)
#elif defined(_M_ARM)
/* Around 2 GB */
    #if (NTDDI_VERSION >= NTDDI_WIN10)
    #define MAXIMUM_PAGEFILE_SIZE   ((512ULL * 1024 - 2) * PAGE_SIZE)
                                 // PAGE_ROUND_DOWN(2ULL * GIGABYTE - PAGE_SIZE - 1)
    #elif (NTDDI_VERSION >= NTDDI_WINBLUE) // NTDDI_WIN81
    #define MAXIMUM_PAGEFILE_SIZE   ((512ULL * 1024 - 1) * PAGE_SIZE)
                                 // PAGE_ROUND_DOWN(2ULL * GIGABYTE - 1)
    #else
/* Around 4 GB */
    #define MAXIMUM_PAGEFILE_SIZE   ((1ULL * 1024 * 1024 - 1) * PAGE_SIZE)
                                 // PAGE_ROUND_DOWN(4ULL * GIGABYTE - 1)
    #endif
#else
#error Unknown architecture
#endif

/* List of paging files, both used and free */
PMMPAGING_FILE MmPagingFile[MAX_PAGING_FILES];

/* Lock for examining the list of paging files */
KGUARDED_MUTEX MmPageFileCreationLock;

/*
 * Slot bitmaps, their counters and the owner tags of every paging file. A
 * leaf spin lock: nothing is acquired while it is held, and it may be taken
 * at <= DISPATCH_LEVEL, also inside the PFN lock (NitroPager). Creation and
 * growth publish new slots under both this lock and MmPageFileCreationLock.
 */
KSPIN_LOCK MiPagingFileSlotLock;

/* Number of paging files */
ULONG MmNumberOfPagingFiles;

/* Number of pages that are available for swapping */
PFN_COUNT MiFreeSwapPages;

/* Number of pages that have been allocated for swapping */
PFN_COUNT MiUsedSwapPages;

BOOLEAN MmZeroPageFile;

/*
 * Number of pages that have been reserved for swapping but not yet allocated
 */
static PFN_COUNT MiReservedSwapPages;

/*
 * Ratio between reserved and available swap pages, e.g. setting this to five
 * forces one swap page to be available for every five swap pages that are
 * reserved. Setting this to zero turns off commit checking altogether.
 */
#define MM_PAGEFILE_COMMIT_RATIO      (1)

/*
 * Number of pages that can be used for potentially swapable memory without
 * pagefile space being reserved. The intention is that this allows smss
 * to start up and create page files while ordinarily having a commit
 * ratio of one.
 */
#define MM_PAGEFILE_COMMIT_GRACE      (256)

/*
 * Translate between a swap entry and a file and offset pair.
 */
#define FILE_FROM_ENTRY(i) ((i) & 0x0f)
#define OFFSET_FROM_ENTRY(i) ((i) >> 11)
#define ENTRY_FROM_FILE_OFFSET(i, j) ((i) | ((j) << 11) | 0x400)

/* PageFileHigh (slot + 1) of an ARM3 page-file PTE stays below MI_PTE_LOOKUP_NEEDED */
#ifdef _WIN64
#define MI_PAGEFILE_HIGH_LIMIT 0xffffffffULL
#else
#define MI_PAGEFILE_HIGH_LIMIT 0xFFFFF
#endif

/* Make sure there can be only 16 paging files */
C_ASSERT(FILE_FROM_ENTRY(0xffffffff) < MAX_PAGING_FILES);

static BOOLEAN MmSwapSpaceMessage = FALSE;

static BOOLEAN MmSystemPageFileLocated = FALSE;

/* FUNCTIONS *****************************************************************/

VOID
NTAPI
MmBuildMdlFromPages(PMDL Mdl, PPFN_NUMBER Pages)
{
    memcpy(Mdl + 1, Pages, sizeof(PFN_NUMBER) * (PAGE_ROUND_UP(Mdl->ByteOffset+Mdl->ByteCount)/PAGE_SIZE));
}


BOOLEAN
NTAPI
MmIsFileObjectAPagingFile(PFILE_OBJECT FileObject)
{
    ULONG i;

    /* Loop through all the paging files */
    for (i = 0; i < MmNumberOfPagingFiles; i++)
    {
        /* Check if this is one of them */
        if (MmPagingFile[i]->FileObject == FileObject) return TRUE;
    }

    /* Nothing found */
    return FALSE;
}

VOID
NTAPI
MmShowOutOfSpaceMessagePagingFile(VOID)
{
    if (!MmSwapSpaceMessage)
    {
        DPRINT1("MM: Out of swap space.\n");
        MmSwapSpaceMessage = TRUE;
    }
}

NTSTATUS
NTAPI
MmWriteToSwapPage(SWAPENTRY SwapEntry, PFN_NUMBER Page)
{
    ULONG i;
    ULONG_PTR offset;
    LARGE_INTEGER file_offset;
    IO_STATUS_BLOCK Iosb;
    NTSTATUS Status;
    KEVENT Event;
    UCHAR MdlBase[sizeof(MDL) + sizeof(PFN_NUMBER)];
    PMDL Mdl = (PMDL)MdlBase;

    DPRINT("MmWriteToSwapPage\n");

    if (SwapEntry == 0)
    {
        KeBugCheck(MEMORY_MANAGEMENT);
        return(STATUS_UNSUCCESSFUL);
    }

    i = FILE_FROM_ENTRY(SwapEntry);
    offset = OFFSET_FROM_ENTRY(SwapEntry) - 1;

    if (MmPagingFile[i]->FileObject == NULL ||
            MmPagingFile[i]->FileObject->DeviceObject == NULL)
    {
        DPRINT1("Bad paging file 0x%.8X\n", SwapEntry);
        KeBugCheck(MEMORY_MANAGEMENT);
    }

    MmInitializeMdl(Mdl, NULL, PAGE_SIZE);
    MmBuildMdlFromPages(Mdl, &Page);
    Mdl->MdlFlags |= MDL_PAGES_LOCKED;

    file_offset.QuadPart = offset * PAGE_SIZE;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    Status = IoSynchronousPageWrite(MmPagingFile[i]->FileObject,
                                    Mdl,
                                    &file_offset,
                                    &Event,
                                    &Iosb);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = Iosb.Status;
    }

    if (Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA)
    {
        MmUnmapLockedPages (Mdl->MappedSystemVa, Mdl);
    }
    if (NT_SUCCESS(Status))
    {
        MI_PRCB_COUNT_ADD(MmDirtyPagesWriteCount, 1);
        MI_PRCB_COUNT_ADD(MmDirtyWriteIoCount, 1);
    }
    return(Status);
}


NTSTATUS
NTAPI
MmReadFromSwapPage(SWAPENTRY SwapEntry, PFN_NUMBER Page)
{
    return MiReadPageFile(Page, FILE_FROM_ENTRY(SwapEntry), OFFSET_FROM_ENTRY(SwapEntry));
}

NTSTATUS
NTAPI
MiReadPageFile(
    _In_ PFN_NUMBER Page,
    _In_ ULONG PageFileIndex,
    _In_ ULONG_PTR PageFileOffset)
{
    LARGE_INTEGER file_offset;
    IO_STATUS_BLOCK Iosb;
    NTSTATUS Status;
    KEVENT Event;
    DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) UCHAR MdlBase[sizeof(MDL) + sizeof(PFN_NUMBER)];
    PMDL Mdl = (PMDL)MdlBase;
    PMMPAGING_FILE PagingFile;

    DPRINT("MiReadSwapFile\n");

    if (PageFileOffset == 0)
    {
        KeBugCheck(MEMORY_MANAGEMENT);
        return(STATUS_UNSUCCESSFUL);
    }

    /* Normalize offset. */
    PageFileOffset--;

    ASSERT(PageFileIndex < MAX_PAGING_FILES);

    PagingFile = MmPagingFile[PageFileIndex];

    if (PagingFile->FileObject == NULL || PagingFile->FileObject->DeviceObject == NULL)
    {
        DPRINT1("Bad paging file %u\n", PageFileIndex);
        KeBugCheck(MEMORY_MANAGEMENT);
    }

    MmInitializeMdl(Mdl, NULL, PAGE_SIZE);
    MmBuildMdlFromPages(Mdl, &Page);
    Mdl->MdlFlags |= MDL_PAGES_LOCKED | MDL_IO_PAGE_READ;

    file_offset.QuadPart = PageFileOffset * PAGE_SIZE;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    Status = IoPageRead(PagingFile->FileObject,
                        Mdl,
                        &file_offset,
                        &Event,
                        &Iosb);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = Iosb.Status;
    }
    if (Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA)
    {
        MmUnmapLockedPages (Mdl->MappedSystemVa, Mdl);
    }
    if (NT_SUCCESS(Status) && (MiNitroPagerMode != 0) && (Iosb.Information != PAGE_SIZE))
    {
        /*
         * A short transfer leaves the rest of a page that came unzeroed from the free
         * list, i.e. another process's old data: never hand that to the faulting
         * process, it is an in-page error. (Flag 0 keeps the old behaviour.)
         */
        DPRINT1("Paging file read of slot %Iu: %Iu of %lu bytes\n",
                PageFileOffset + 1, (SIZE_T)Iosb.Information, (ULONG)PAGE_SIZE);
        Status = STATUS_IN_PAGE_ERROR;
    }
    if (NT_SUCCESS(Status))
        MI_COUNT_PAGE_READ(1);
    return(Status);
}

/* Paging file growth (see MiWaitForPagingFileGrowth) */
static KEVENT MiPagingFileGrowthRequestEvent;
static KEVENT MiPagingFileGrowthDoneEvent;
static volatile SIZE_T MiPagingFileGrowthShortfall;
static volatile LONG MiPagingFileGrowthGeneration;
static volatile LONG MiPagingFileGrowthActive;
/* 0: no thread, 1: being created, 2: running */
static volatile LONG MiPagingFileGrowthThreadState;
/* Page the growth thread certifies new paging file space with, taken when it starts */
static PFN_NUMBER MiPagingFileCertifyPage;

/* At least this much is added at a time */
#define MI_PAGING_FILE_GROWTH_MINIMUM ((64 * 1024 * 1024) >> PAGE_SHIFT)

CODE_SEG("INIT")
VOID
NTAPI
MmInitPagingFile(VOID)
{
    ULONG i;

    KeInitializeGuardedMutex(&MmPageFileCreationLock);
    KeInitializeSpinLock(&MiPagingFileSlotLock);
    KeInitializeEvent(&MiPagingFileGrowthRequestEvent, SynchronizationEvent, FALSE);
    KeInitializeEvent(&MiPagingFileGrowthDoneEvent, NotificationEvent, FALSE);

    MiFreeSwapPages = 0;
    MiUsedSwapPages = 0;
    MiReservedSwapPages = 0;

    for (i = 0; i < MAX_PAGING_FILES; i++)
    {
        MmPagingFile[i] = NULL;
    }
    MmNumberOfPagingFiles = 0;
}

/* Set a slot's owner tag. MiPagingFileSlotLock held, Slot < SlotTagCount, SlotTags not NULL */
FORCEINLINE
VOID
MiStoreSlotTag(
    _In_ PMMPAGING_FILE PagingFile,
    _In_ ULONG_PTR Slot,
    _In_ ULONG Tag)
{
    PagingFile->SlotTags[Slot] = Tag;
    if (PagingFile->SlotTagsMirror != NULL)
        PagingFile->SlotTagsMirror[Slot] = Tag;
}


VOID
NTAPI
MmFreeSwapPage(SWAPENTRY Entry)
{
    ULONG i;
    ULONG_PTR off;
    PMMPAGING_FILE PagingFile;
    KIRQL OldIrql;

    i = FILE_FROM_ENTRY(Entry);
    off = OFFSET_FROM_ENTRY(Entry) - 1;

    KeAcquireSpinLock(&MiPagingFileSlotLock, &OldIrql);

    PagingFile = MmPagingFile[i];
    if (PagingFile == NULL)
    {
        KeBugCheck(MEMORY_MANAGEMENT);
    }

    /* Refuse an entry that cannot be in use: MM_WAIT_ENTRY, the header, outside the bitmap, bit clear */
    if ((Entry == MM_WAIT_ENTRY) ||
        (off == 0) ||
        (off >= PagingFile->Bitmap->SizeOfBitMap) ||
        !RtlTestBit(PagingFile->Bitmap, (ULONG)off))
    {
        KeReleaseSpinLock(&MiPagingFileSlotLock, OldIrql);
        DPRINT1("MmFreeSwapPage: entry %Ix is not in use\n", Entry);
        ASSERT(FALSE);
        return;
    }
    RtlClearBit(PagingFile->Bitmap, (ULONG)off);

    /* A legacy slot never has an owner tag; keep it that way for the next ARM3 user */
    if ((PagingFile->SlotTags != NULL) && (off < PagingFile->SlotTagCount))
        MiStoreSlotTag(PagingFile, off, 0);

    PagingFile->FreeSpace++;
    PagingFile->CurrentUsage--;

    MiFreeSwapPages++;
    MiUsedSwapPages--;

    KeReleaseSpinLock(&MiPagingFileSlotLock, OldIrql);
}

/*
 * The commit limit as Windows reports it: physical memory plus the size of
 * every paging file (the header page included, so that it is the sum of the
 * TotalSize values of SystemPageFileInformation). Applications compute with
 * it: GlobalMemoryStatusEx().ullTotalPageFile minus ullTotalPhys is the paging
 * file size (btop), and it is never below physical memory. This is the
 * reporting figure only; what commitment may actually charge is the lower
 * MiGetCommitLimit().
 */
SIZE_T
NTAPI
MiGetReportedCommitLimit(VOID)
{
    SIZE_T Limit = MmNumberOfPhysicalPages;
    ULONG i;

    KeAcquireGuardedMutex(&MmPageFileCreationLock);
    for (i = 0; i < MAX_PAGING_FILES; i++)
    {
        if (MmPagingFile[i] != NULL)
            Limit += MmPagingFile[i]->Size;
    }
    KeReleaseGuardedMutex(&MmPageFileCreationLock);

    return Limit;
}

/*
 * Fill SYSTEM_PAGEFILE_INFORMATION entries for SystemPageFileInformation. As
 * on Windows there is one entry per paging file, each followed by its
 * NUL-terminated NT name (\??\C:\pagefile.sys); the sizes are in pages.
 *
 * The image is built in a pool buffer under the paging file lock and copied to
 * the caller's buffer after the lock is released (the image is nonpaged and zeroed): a fault on the caller's
 * buffer (decommitted by another thread, or a view of a paging file backed
 * section whose swap-in takes the lock again) must not happen with the lock held.
 */
static
ULONG
MiPagingFileEntrySize(
    _In_ PMMPAGING_FILE PagingFile)
{
    return ALIGN_UP_BY(sizeof(SYSTEM_PAGEFILE_INFORMATION) +
                       PagingFile->PageFileName.Length + sizeof(WCHAR),
                       sizeof(PVOID));
}

NTSTATUS
NTAPI
MmQueryPagingFileInformation(
    _Out_writes_bytes_opt_(Size) PSYSTEM_PAGEFILE_INFORMATION Buffer,
    _In_ ULONG Size,
    _Out_ PULONG ReqSize)
{
    PSYSTEM_PAGEFILE_INFORMATION Entry, Previous, Image = NULL;
    ULONG i, Needed, ImageSize = 0, Tries;
    PMMPAGING_FILE PagingFile;
    PWCHAR Name;

    PAGED_CODE();

    if (Size < sizeof(SYSTEM_PAGEFILE_INFORMATION))
    {
        *ReqSize = sizeof(SYSTEM_PAGEFILE_INFORMATION);
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    for (Tries = 0; ; Tries++)
    {
        KeAcquireGuardedMutex(&MmPageFileCreationLock);

        Needed = 0;
        for (i = 0; i < MAX_PAGING_FILES; i++)
        {
            if (MmPagingFile[i] != NULL)
                Needed += MiPagingFileEntrySize(MmPagingFile[i]);
        }

        if (Needed > Size)
        {
            KeReleaseGuardedMutex(&MmPageFileCreationLock);
            if (Image != NULL)
                ExFreePoolWithTag(Image, TAG_MM);
            *ReqSize = Needed;
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        if (Needed == 0 || (Image != NULL && Needed <= ImageSize))
            break;

        /* A paging file appeared meanwhile or the first pass: allocate outside of the lock */
        KeReleaseGuardedMutex(&MmPageFileCreationLock);
        if (Image != NULL)
            ExFreePoolWithTag(Image, TAG_MM);
        /* Nonpaged and zeroed: a paged-out image would fault under the lock, and the padding goes to the caller */
        Image = ExAllocatePoolZero(NonPagedPool, Needed, TAG_MM);
        if (Image == NULL)
            return STATUS_INSUFFICIENT_RESOURCES;
        ImageSize = Needed;
    }

    /* The lock is held; the image has room for every entry */
    Entry = Image;
    Previous = NULL;
    for (i = 0; i < MAX_PAGING_FILES; i++)
    {
        PagingFile = MmPagingFile[i];
        if (PagingFile == NULL)
            continue;

        Name = (PWCHAR)(Entry + 1);
        RtlCopyMemory(Name, PagingFile->PageFileName.Buffer, PagingFile->PageFileName.Length);
        Name[PagingFile->PageFileName.Length / sizeof(WCHAR)] = UNICODE_NULL;

        Entry->NextEntryOffset = 0;
        Entry->TotalSize = (ULONG)PagingFile->Size;
        Entry->TotalInUse = (ULONG)PagingFile->CurrentUsage;
        Entry->PeakUsage = (ULONG)PagingFile->PeakUsage;
        Entry->PageFileName.Length = PagingFile->PageFileName.Length;
        Entry->PageFileName.MaximumLength = PagingFile->PageFileName.Length + sizeof(WCHAR);
        /* The name as the caller's buffer will see it */
        Entry->PageFileName.Buffer = (PWCHAR)((PUCHAR)Buffer + ((PUCHAR)Name - (PUCHAR)Image));

        if (Previous != NULL)
            Previous->NextEntryOffset = (ULONG)((PUCHAR)Entry - (PUCHAR)Previous);
        Previous = Entry;
        Entry = (PSYSTEM_PAGEFILE_INFORMATION)((PUCHAR)Entry + MiPagingFileEntrySize(PagingFile));
    }
    KeReleaseGuardedMutex(&MmPageFileCreationLock);

    *ReqSize = Needed;
    if (Image != NULL)
    {
        /* May fault; the exception unwinds in the caller with nothing held but the image */
        _SEH2_TRY
        {
            RtlCopyMemory(Buffer, Image, Needed);
        }
        _SEH2_FINALLY
        {
            ExFreePoolWithTag(Image, TAG_MM);
        }
        _SEH2_END;
    }
    return STATUS_SUCCESS;
}

/* Write and read back one page of the paging file: proves the file system can do paging I/O there */
static
NTSTATUS
MiCertifyPagingFilePage(
    _In_ PMMPAGING_FILE PagingFile,
    _In_ PFN_NUMBER FilePage)
{
    UCHAR MdlBase[sizeof(MDL) + sizeof(PFN_NUMBER)];
    PMDL Mdl = (PMDL)MdlBase;
    LARGE_INTEGER FileOffset;
    IO_STATUS_BLOCK Iosb;
    PFN_NUMBER Page = MiPagingFileCertifyPage;
    KEVENT Event;
    NTSTATUS Status;

    FileOffset.QuadPart = (LONGLONG)FilePage * PAGE_SIZE;

    MmInitializeMdl(Mdl, NULL, PAGE_SIZE);
    MmBuildMdlFromPages(Mdl, &Page);
    Mdl->MdlFlags |= MDL_PAGES_LOCKED;
    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    Status = IoSynchronousPageWrite(PagingFile->FileObject, Mdl, &FileOffset, &Event, &Iosb);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = Iosb.Status;
    }
    if (Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA)
        MmUnmapLockedPages(Mdl->MappedSystemVa, Mdl);

    if (NT_SUCCESS(Status))
    {
        MmInitializeMdl(Mdl, NULL, PAGE_SIZE);
        MmBuildMdlFromPages(Mdl, &Page);
        Mdl->MdlFlags |= MDL_PAGES_LOCKED;
        KeInitializeEvent(&Event, NotificationEvent, FALSE);
        Status = IoPageRead(PagingFile->FileObject, Mdl, &FileOffset, &Event, &Iosb);
        if (Status == STATUS_PENDING)
        {
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
            Status = Iosb.Status;
        }
        if (Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA)
            MmUnmapLockedPages(Mdl->MappedSystemVa, Mdl);
    }

    return Status;
}

/* Grow paging files by at least Shortfall pages, as far as their maximum allows */
static
VOID
MiGrowPagingFiles(
    _In_ SIZE_T Shortfall)
{
    PMMPAGING_FILE PagingFile;
    FILE_END_OF_FILE_INFORMATION EndOfFile;
    IO_STATUS_BLOCK Iosb;
    PFN_NUMBER OldSize, Growth;
    NTSTATUS Status;
    ULONG i;
    PULONG NewTags, OldTags;
    KIRQL OldIrql;

    for (i = 0; (i < MAX_PAGING_FILES) && (Shortfall > 0); i++)
    {
        KeAcquireGuardedMutex(&MmPageFileCreationLock);
        PagingFile = MmPagingFile[i];
        if ((PagingFile == NULL) || PagingFile->CannotGrow || (PagingFile->Size >= PagingFile->MaximumSize))
        {
            KeReleaseGuardedMutex(&MmPageFileCreationLock);
            continue;
        }
        OldSize = PagingFile->Size;
        Growth = max(max((PFN_NUMBER)Shortfall, MI_PAGING_FILE_GROWTH_MINIMUM), OldSize / 8);
        Growth = min(Growth, PagingFile->MaximumSize - OldSize);
        KeReleaseGuardedMutex(&MmPageFileCreationLock);

        /*
         * NitroPager only: the owner tags grow with the file (nonpaged, one per slot);
         * without the pool for them the file does not grow yet. Flag 0 has no tags and
         * grows as it always did.
         */
        NewTags = NULL;
        if ((MiNitroPagerMode != 0) && (PagingFile->SlotTags != NULL))
        {
            NewTags = ExAllocatePoolZero(NonPagedPool, (OldSize + Growth) * sizeof(ULONG), TAG_MM);
            if (NewTags == NULL)
            {
                DPRINT1("Paging file %wZ: no pool for %Iu slot tags, not growing now\n",
                        &PagingFile->PageFileName, OldSize + Growth);
                continue;
            }
        }

        /* Only this thread changes a paging file's size: no lock across the I/O */
        EndOfFile.EndOfFile.QuadPart = (LONGLONG)(OldSize + Growth) * PAGE_SIZE;
        Status = ZwSetInformationFile(PagingFile->FileHandle,
                                      &Iosb,
                                      &EndOfFile,
                                      sizeof(EndOfFile),
                                      FileEndOfFileInformation);
        if (NT_SUCCESS(Status))
            Status = MiCertifyPagingFilePage(PagingFile, OldSize + Growth - 1);

        if (!NT_SUCCESS(Status))
        {
            /* A shortage (an IRP, pool) may pass; anything else is the file system's answer */
            DPRINT1("Paging file %wZ cannot grow from %Iu to %Iu pages: 0x%lx\n",
                    &PagingFile->PageFileName, OldSize, OldSize + Growth, Status);
            if ((Status != STATUS_INSUFFICIENT_RESOURCES) && (Status != STATUS_NO_MEMORY))
                PagingFile->CannotGrow = TRUE;
            if (NewTags != NULL)
                ExFreePoolWithTag(NewTags, TAG_MM);
            continue;
        }

        /*
         * Copy the tags in short pieces, each under the slot lock, with every tag
         * write mirrored into the new array from before the first piece: no write is
         * lost and the lock is never held for the whole array (1 MB per GB of file).
         * Only this thread (one at a time) replaces the array.
         */
        OldTags = PagingFile->SlotTags;
        if (NewTags != NULL)
        {
            PFN_NUMBER Done, Piece, Count = PagingFile->SlotTagCount;

            KeAcquireSpinLock(&MiPagingFileSlotLock, &OldIrql);
            PagingFile->SlotTagsMirror = NewTags;
            KeReleaseSpinLock(&MiPagingFileSlotLock, OldIrql);

            for (Done = 0; Done < Count; Done += Piece)
            {
                Piece = min(Count - Done, (PFN_NUMBER)1024);
                KeAcquireSpinLock(&MiPagingFileSlotLock, &OldIrql);
                RtlCopyMemory(NewTags + Done, OldTags + Done, Piece * sizeof(ULONG));
                KeReleaseSpinLock(&MiPagingFileSlotLock, OldIrql);
            }
        }

        /* The new slots exist: they back committed memory from now on */
        KeAcquireGuardedMutex(&MmPageFileCreationLock);
        KeAcquireSpinLock(&MiPagingFileSlotLock, &OldIrql);
        if (NewTags != NULL)
        {
            PagingFile->SlotTags = NewTags;
            PagingFile->SlotTagsMirror = NULL;
            PagingFile->SlotTagCount = OldSize + Growth;
        }
        /* The slots beyond the old size were kept set: hand them out from now on */
        RtlClearBits(PagingFile->Bitmap, (ULONG)OldSize, (ULONG)Growth);
        PagingFile->Size += Growth;
        PagingFile->FreeSpace += Growth;
        MiFreeSwapPages += Growth;
        KeReleaseSpinLock(&MiPagingFileSlotLock, OldIrql);
        InterlockedExchangeAddSizeT(&MmTotalCommitLimit, Growth);
        KeReleaseGuardedMutex(&MmPageFileCreationLock);
        if ((NewTags != NULL) && (OldTags != NULL))
            ExFreePoolWithTag(OldTags, TAG_MM);

        DPRINT1("Paging file %wZ grew from %Iu to %Iu pages\n",
                &PagingFile->PageFileName, OldSize, OldSize + Growth);
        Shortfall = (Growth >= Shortfall) ? 0 : (Shortfall - Growth);
    }
}

static
VOID
NTAPI
MiPagingFileGrowthThread(
    _In_ PVOID Context)
{
    SIZE_T Shortfall;

    UNREFERENCED_PARAMETER(Context);

    for (;;)
    {
        KeWaitForSingleObject(&MiPagingFileGrowthRequestEvent, Executive, KernelMode, FALSE, NULL);

        InterlockedExchange(&MiPagingFileGrowthActive, 1);
        Shortfall = InterlockedExchangeSizeT(&MiPagingFileGrowthShortfall, 0);
        if (Shortfall != 0)
            MiGrowPagingFiles(Shortfall);

        InterlockedIncrement(&MiPagingFileGrowthGeneration);
        InterlockedExchange(&MiPagingFileGrowthActive, 0);
        KePulseEvent(&MiPagingFileGrowthDoneEvent, IO_NO_INCREMENT, FALSE);
    }
}

/* Start the one thread that grows paging files; a failed start is retried by the next caller */
static
VOID
MiStartPagingFileGrowthThread(VOID)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE ThreadHandle;
    NTSTATUS Status;

    if (InterlockedCompareExchange(&MiPagingFileGrowthThreadState, 1, 0) != 0)
        return;

    /* A retry can run in any process: the handle must not land in its handle table */
    InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = STATUS_NO_MEMORY;
    if ((MiPagingFileCertifyPage != 0) ||
        NT_SUCCESS(MmRequestPageMemoryConsumer(MC_SYSTEM, TRUE, &MiPagingFileCertifyPage)))
    {
        /* A retry runs when user commitment is exhausted: the stack may use the kernel reserve */
        MiKernelTierStackCreator = KeGetCurrentThread();
        Status = PsCreateSystemThread(&ThreadHandle, THREAD_ALL_ACCESS, &ObjectAttributes, NULL, NULL,
                                      MiPagingFileGrowthThread, NULL);
        MiKernelTierStackCreator = NULL;
    }

    if (NT_SUCCESS(Status))
    {
        ZwClose(ThreadHandle);
        InterlockedExchange(&MiPagingFileGrowthThreadState, 2);
    }
    else
    {
        InterlockedExchange(&MiPagingFileGrowthThreadState, 0);
    }
}

/*
 * Ask the growth thread to grow paging files by Shortfall pages and wait
 * for it. Returns TRUE when the commit limit grew. Takes no commitment:
 * the caller charges again. Call it with no lock held: the growth thread
 * waits for file system I/O.
 */
BOOLEAN
NTAPI
MiWaitForPagingFileGrowth(
    _In_ SIZE_T Shortfall)
{
    SIZE_T Remaining = 0, Requested, LimitBefore;
    LARGE_INTEGER Timeout;
    LONG Generation;
    ULONG i, Waits;

    /*
     * A thread inside a critical or guarded region may hold a resource that
     * the file system needs to grow the file: it does not wait.
     */
    if ((MmNumberOfPagingFiles == 0) ||
        (KeGetCurrentIrql() != PASSIVE_LEVEL) ||
        (KeGetCurrentThread()->CombinedApcDisable != 0))
    {
        return FALSE;
    }

    /* Its start may have failed when the paging file was created */
    if (MiPagingFileGrowthThreadState != 2)
    {
        MiStartPagingFileGrowthThread();
        if (MiPagingFileGrowthThreadState != 2)
            return FALSE;
    }

    /* A request that cannot fit even at the maximum fails at once and changes nothing */
    KeAcquireGuardedMutex(&MmPageFileCreationLock);
    for (i = 0; i < MAX_PAGING_FILES; i++)
    {
        if ((MmPagingFile[i] != NULL) && !MmPagingFile[i]->CannotGrow)
            Remaining += MmPagingFile[i]->MaximumSize - MmPagingFile[i]->Size;
    }
    KeReleaseGuardedMutex(&MmPageFileCreationLock);
    if (Shortfall > Remaining)
        return FALSE;

    LimitBefore = MmTotalCommitLimit;
    Generation = MiPagingFileGrowthGeneration;

    /* Keep the largest request that is waiting */
    Requested = MiPagingFileGrowthShortfall;
    while ((Shortfall > Requested) &&
           (InterlockedCompareExchangeSizeT(&MiPagingFileGrowthShortfall, Shortfall, Requested) != Requested))
    {
        Requested = MiPagingFileGrowthShortfall;
    }
    KeSetEvent(&MiPagingFileGrowthRequestEvent, IO_NO_INCREMENT, FALSE);

    /*
     * Wait, up to 30 s, until a round has finished since then, no round is
     * running and no request is left: then a round that started after our
     * request has taken it and is done.
     */
    Timeout.QuadPart = -100 * 10000LL;
    for (Waits = 0; Waits < 300; Waits++)
    {
        KeWaitForSingleObject(&MiPagingFileGrowthDoneEvent, Executive, KernelMode, FALSE, &Timeout);
        if ((MiPagingFileGrowthGeneration != Generation) &&
            !MiPagingFileGrowthActive &&
            (MiPagingFileGrowthShortfall == 0))
        {
            break;
        }
    }

    return (MmTotalCommitLimit > LimitBefore);
}

/*
 * Ask the growth thread for room without waiting. For a charge that failed on
 * a path that cannot block (kernel tier, any IRQL <= DISPATCH_LEVEL): the next
 * allocation then finds the room. Does not start the thread, take locks or
 * wait; the thread itself skips files that cannot grow.
 */
VOID
NTAPI
MiRequestPagingFileGrowth(
    _In_ SIZE_T Shortfall)
{
    SIZE_T Requested;

    if ((MmNumberOfPagingFiles == 0) || (MiPagingFileGrowthThreadState != 2) || (Shortfall == 0))
        return;

    Requested = MiPagingFileGrowthShortfall;
    while ((Shortfall > Requested) &&
           (InterlockedCompareExchangeSizeT(&MiPagingFileGrowthShortfall, Shortfall, Requested) != Requested))
    {
        Requested = MiPagingFileGrowthShortfall;
    }
    KeSetEvent(&MiPagingFileGrowthRequestEvent, IO_NO_INCREMENT, FALSE);
}

SWAPENTRY
NTAPI
MmAllocSwapPage(VOID)
{
    ULONG i;
    ULONG off;
    SWAPENTRY entry;
    KIRQL OldIrql;

    KeAcquireSpinLock(&MiPagingFileSlotLock, &OldIrql);

    if (MiFreeSwapPages == 0)
    {
        KeReleaseSpinLock(&MiPagingFileSlotLock, OldIrql);
        return(0);
    }

    for (i = 0; i < MAX_PAGING_FILES; i++)
    {
        if (MmPagingFile[i] != NULL &&
                MmPagingFile[i]->FreeSpace >= 1)
        {
            off = RtlFindClearBitsAndSet(MmPagingFile[i]->Bitmap, 1, 0);
            if (off == 0xFFFFFFFF)
            {
                KeBugCheck(MEMORY_MANAGEMENT);
                KeReleaseSpinLock(&MiPagingFileSlotLock, OldIrql);
                return(STATUS_UNSUCCESSFUL);
            }
            MmPagingFile[i]->FreeSpace--;
            MmPagingFile[i]->CurrentUsage++;
            if (MmPagingFile[i]->CurrentUsage > MmPagingFile[i]->PeakUsage)
                MmPagingFile[i]->PeakUsage = MmPagingFile[i]->CurrentUsage;
            MiUsedSwapPages++;
            MiFreeSwapPages--;

            KeReleaseSpinLock(&MiPagingFileSlotLock, OldIrql);

            entry = ENTRY_FROM_FILE_OFFSET((SWAPENTRY)i, (SWAPENTRY)off + 1);
            return(entry);
        }
    }

    KeReleaseSpinLock(&MiPagingFileSlotLock, OldIrql);
    KeBugCheck(MEMORY_MANAGEMENT);
    return(0);
}

NTSTATUS
NTAPI
NtCreatePagingFile(
    _In_ PUNICODE_STRING FileName,
    _In_ PLARGE_INTEGER MinimumSize,
    _In_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG Reserved)
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE FileHandle;
    IO_STATUS_BLOCK IoStatus;
    PFILE_OBJECT FileObject;
    PMMPAGING_FILE PagingFile;
    SIZE_T AllocMapSize;
    ULONG Count;
    KPROCESSOR_MODE PreviousMode;
    UNICODE_STRING PageFileName;
    LARGE_INTEGER SafeMinimumSize, SafeMaximumSize, AllocationSize;
    FILE_FS_DEVICE_INFORMATION FsDeviceInfo;
    SECURITY_DESCRIPTOR SecurityDescriptor;
    PACL Dacl;
    PWSTR Buffer;
    DEVICE_TYPE DeviceType;
    KIRQL OldIrql;

    PAGED_CODE();

    DPRINT("NtCreatePagingFile(FileName: '%wZ', MinimumSize: %I64d, MaximumSize: %I64d)\n",
           FileName, MinimumSize->QuadPart, MaximumSize->QuadPart);

    if (MmNumberOfPagingFiles >= MAX_PAGING_FILES)
    {
        return STATUS_TOO_MANY_PAGING_FILES;
    }

    PreviousMode = ExGetPreviousMode();

    if (PreviousMode != KernelMode)
    {
        if (SeSinglePrivilegeCheck(SeCreatePagefilePrivilege, PreviousMode) != TRUE)
        {
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        _SEH2_TRY
        {
            SafeMinimumSize = ProbeForReadLargeInteger(MinimumSize);
            SafeMaximumSize = ProbeForReadLargeInteger(MaximumSize);
            PageFileName = ProbeForReadUnicodeString(FileName);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Return the exception code */
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }
    else
    {
        SafeMinimumSize = *MinimumSize;
        SafeMaximumSize = *MaximumSize;
        PageFileName = *FileName;
    }

    /*
     * Pagefiles cannot be larger than the platform-specific memory addressable
     * limits, and of course the minimum should be smaller than the maximum.
     */
    if (SafeMinimumSize.QuadPart < MINIMUM_PAGEFILE_SIZE ||
        SafeMinimumSize.QuadPart > MAXIMUM_PAGEFILE_SIZE)
    {
        return STATUS_INVALID_PARAMETER_2;
    }
    if (SafeMaximumSize.QuadPart < SafeMinimumSize.QuadPart ||
        SafeMaximumSize.QuadPart > MAXIMUM_PAGEFILE_SIZE)
    {
        return STATUS_INVALID_PARAMETER_3;
    }

    /* Validate the name length */
    if ((PageFileName.Length == 0) ||
        (PageFileName.Length > MAXIMUM_FILENAME_LENGTH))
    {
        return STATUS_OBJECT_NAME_INVALID;
    }

    /* Allocate a buffer to keep the name copy. Note that it is kept only
     * for information purposes, so it gets allocated in the paged pool,
     * even if it will be stored in the PagingFile structure, that is
     * allocated from non-paged pool (see below). */
    PageFileName.MaximumLength = PageFileName.Length;
    Buffer = ExAllocatePoolWithTag(PagedPool, PageFileName.Length, TAG_MM);
    if (Buffer == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Copy the name */
    if (PreviousMode != KernelMode)
    {
        _SEH2_TRY
        {
            ProbeForRead(PageFileName.Buffer, PageFileName.Length, sizeof(WCHAR));
            RtlCopyMemory(Buffer, PageFileName.Buffer, PageFileName.Length);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            ExFreePoolWithTag(Buffer, TAG_MM);

            /* Return the exception code */
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }
    else
    {
        RtlCopyMemory(Buffer, PageFileName.Buffer, PageFileName.Length);
    }

    /* Replace caller's buffer with ours */
    PageFileName.Buffer = Buffer;

    /* Create the security descriptor for the page file */
    Status = RtlCreateSecurityDescriptor(&SecurityDescriptor, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(Buffer, TAG_MM);
        return Status;
    }

    /* Create the DACL: we will only allow two SIDs */
    Count = sizeof(ACL) + (sizeof(ACE) + RtlLengthSid(SeLocalSystemSid)) +
                          (sizeof(ACE) + RtlLengthSid(SeAliasAdminsSid));
    Dacl = ExAllocatePoolWithTag(PagedPool, Count, TAG_DACL);
    if (Dacl == NULL)
    {
        ExFreePoolWithTag(Buffer, TAG_MM);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Initialize the DACL */
    Status = RtlCreateAcl(Dacl, Count, ACL_REVISION);
    if (!NT_SUCCESS(Status))
        goto EarlyQuit;

    /* Grant full access to admins */
    Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, FILE_ALL_ACCESS, SeAliasAdminsSid);
    if (!NT_SUCCESS(Status))
        goto EarlyQuit;

    /* Grant full access to SYSTEM */
    Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, FILE_ALL_ACCESS, SeLocalSystemSid);
    if (!NT_SUCCESS(Status))
        goto EarlyQuit;

    /* Attach the DACL to the security descriptor */
    Status = RtlSetDaclSecurityDescriptor(&SecurityDescriptor, TRUE, Dacl, FALSE);
    if (!NT_SUCCESS(Status))
        goto EarlyQuit;

    InitializeObjectAttributes(&ObjectAttributes,
                               &PageFileName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               &SecurityDescriptor);

    /* Make sure we can at least store a complete page:
     * If we have 2048 BytesPerAllocationUnit (FAT16 < 128MB) there is
     * a problem if the paging file is fragmented. Suppose the first cluster
     * of the paging file is cluster 3042 but cluster 3043 is NOT part of the
     * paging file but of another file. We can't write a complete page (4096
     * bytes) to the physical location of cluster 3042 then. */
    AllocationSize.QuadPart = SafeMinimumSize.QuadPart + PAGE_SIZE;

    /* First, attempt to replace the page file, if existing */
    Status = IoCreateFile(&FileHandle,
                          SYNCHRONIZE | WRITE_DAC | FILE_READ_DATA | FILE_WRITE_DATA,
                          &ObjectAttributes,
                          &IoStatus,
                          &AllocationSize,
                          FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN,
                          FILE_SHARE_WRITE,
                          FILE_SUPERSEDE,
                          FILE_DELETE_ON_CLOSE | FILE_NO_COMPRESSION | FILE_NO_INTERMEDIATE_BUFFERING,
                          NULL,
                          0,
                          CreateFileTypeNone,
                          NULL,
                          IO_OPEN_PAGING_FILE | IO_NO_PARAMETER_CHECKING);
    /* If we failed, relax a bit constraints, someone may be already holding the
     * the file, so share write, don't attempt to replace and don't delete on close
     * (basically, don't do anything conflicting).
     * This can happen if the caller attempts to extend a page file.
     */
    if (!NT_SUCCESS(Status))
    {
        ULONG i;

        Status = IoCreateFile(&FileHandle,
                              SYNCHRONIZE | FILE_WRITE_DATA,
                              &ObjectAttributes,
                              &IoStatus,
                              &AllocationSize,
                              FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN,
                              FILE_SHARE_WRITE | FILE_SHARE_READ,
                              FILE_OPEN,
                              FILE_NO_COMPRESSION | FILE_NO_INTERMEDIATE_BUFFERING,
                              NULL,
                              0,
                              CreateFileTypeNone,
                              NULL,
                              IO_OPEN_PAGING_FILE | IO_NO_PARAMETER_CHECKING);
        if (!NT_SUCCESS(Status))
            goto EarlyQuit;

        /* We opened it! Check we are that "someone" ;-)
         * First, get the opened file object.
         */
        Status = ObReferenceObjectByHandle(FileHandle,
                                           FILE_READ_DATA | FILE_WRITE_DATA,
                                           IoFileObjectType,
                                           KernelMode,
                                           (PVOID*)&FileObject,
                                           NULL);
        if (!NT_SUCCESS(Status))
        {
            ZwClose(FileHandle);
            goto EarlyQuit;
        }

        /* Find if it matches a previous page file */
        PagingFile = NULL;

        KeAcquireGuardedMutex(&MmPageFileCreationLock);

        for (i = 0; i < MmNumberOfPagingFiles; ++i)
        {
            if (MmPagingFile[i]->FileObject->SectionObjectPointer == FileObject->SectionObjectPointer)
            {
                /* Same object pointer: this is the matching page file */
                PagingFile = MmPagingFile[i];
                break;
            }
        }

        /* If we didn't find the page file, fail */
        if (PagingFile == NULL)
        {
            KeReleaseGuardedMutex(&MmPageFileCreationLock);
            ObDereferenceObject(FileObject);
            ZwClose(FileHandle);
            Status = STATUS_NOT_FOUND;
            goto EarlyQuit;
        }

        /* Don't allow page file shrinking */
        if (PagingFile->MinimumSize > (SafeMinimumSize.QuadPart >> PAGE_SHIFT))
        {
            KeReleaseGuardedMutex(&MmPageFileCreationLock);
            ObDereferenceObject(FileObject);
            ZwClose(FileHandle);
            Status = STATUS_INVALID_PARAMETER_2;
            goto EarlyQuit;
        }

        if ((SafeMaximumSize.QuadPart >> PAGE_SHIFT) < PagingFile->MaximumSize)
        {
            KeReleaseGuardedMutex(&MmPageFileCreationLock);
            ObDereferenceObject(FileObject);
            ZwClose(FileHandle);
            Status = STATUS_INVALID_PARAMETER_3;
            goto EarlyQuit;
        }

        /* FIXME: implement parameters checking and page file extension */
        UNIMPLEMENTED;

        KeReleaseGuardedMutex(&MmPageFileCreationLock);
        ObDereferenceObject(FileObject);
        ZwClose(FileHandle);
        Status = STATUS_NOT_IMPLEMENTED;
        goto EarlyQuit;
    }

    if (!NT_SUCCESS(Status))
    {
EarlyQuit:
        DPRINT1("Failed creating page file: %lx\n", Status);
        ExFreePoolWithTag(Dacl, TAG_DACL);
        ExFreePoolWithTag(Buffer, TAG_MM);
        return Status;
    }

    /* Set the security descriptor */
    if (NT_SUCCESS(IoStatus.Status))
    {
        Status = ZwSetSecurityObject(FileHandle, DACL_SECURITY_INFORMATION, &SecurityDescriptor);
        if (!NT_SUCCESS(Status))
        {
            ZwClose(FileHandle);
            ExFreePoolWithTag(Dacl, TAG_DACL);
            ExFreePoolWithTag(Buffer, TAG_MM);
            return Status;
        }
    }

    /* DACL is no longer needed, free it */
    ExFreePoolWithTag(Dacl, TAG_DACL);

    /* FIXME: To enable once page file management is moved to ARM3 */
#if 0
    /* Check we won't overflow commit limit with the page file */
    if (MmTotalCommitLimitMaximum + (SafeMaximumSize.QuadPart >> PAGE_SHIFT) <= MmTotalCommitLimitMaximum)
    {
        ZwClose(FileHandle);
        ExFreePoolWithTag(Buffer, TAG_MM);
        return STATUS_INVALID_PARAMETER_3;
    }
#endif

    /* Set its end of file to minimal size */
    Status = ZwSetInformationFile(FileHandle,
                                  &IoStatus,
                                  &SafeMinimumSize,
                                  sizeof(LARGE_INTEGER),
                                  FileEndOfFileInformation);
    if (!NT_SUCCESS(Status) || !NT_SUCCESS(IoStatus.Status))
    {
        ZwClose(FileHandle);
        ExFreePoolWithTag(Buffer, TAG_MM);
        return Status;
    }

    Status = ObReferenceObjectByHandle(FileHandle,
                                       FILE_READ_DATA | FILE_WRITE_DATA,
                                       IoFileObjectType,
                                       KernelMode,
                                       (PVOID*)&FileObject,
                                       NULL);
    if (!NT_SUCCESS(Status))
    {
        ZwClose(FileHandle);
        ExFreePoolWithTag(Buffer, TAG_MM);
        return Status;
    }

    /* Only allow page file on a few device types */
    DeviceType = IoGetRelatedDeviceObject(FileObject)->DeviceType;
    if (DeviceType != FILE_DEVICE_DISK_FILE_SYSTEM &&
        DeviceType != FILE_DEVICE_NETWORK_FILE_SYSTEM &&
        DeviceType != FILE_DEVICE_DFS_VOLUME &&
        DeviceType != FILE_DEVICE_DFS_FILE_SYSTEM)
    {
        ObDereferenceObject(FileObject);
        ZwClose(FileHandle);
        ExFreePoolWithTag(Buffer, TAG_MM);
        return Status;
    }

    /* Deny page file creation on a floppy disk */
    FsDeviceInfo.Characteristics = 0;
    IoQueryVolumeInformation(FileObject, FileFsDeviceInformation,
                             sizeof(FsDeviceInfo), &FsDeviceInfo, &Count);
    if (BooleanFlagOn(FsDeviceInfo.Characteristics, FILE_FLOPPY_DISKETTE))
    {
        ObDereferenceObject(FileObject);
        ZwClose(FileHandle);
        ExFreePoolWithTag(Buffer, TAG_MM);
        return STATUS_FLOPPY_VOLUME;
    }

    /*
     * Missing validation steps TODO:
     * (see https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/mm/modwrite/create.htm )
     *
     * - Verify that no file system driver or any filter driver has done file
     *   I/O while opening the file.
     *   Verify that nothing of the paging file is yet in memory. Specifically,
     *   the file object must either have no SectionObjectPointer or the latter
     *   must have neither a DataSectionObject nor an ImageSectionObject.
     *   Otherwise, we should fail, returning STATUS_INCOMPATIBLE_FILE_MAP.
     *
     * - Inform all the applicable drivers to prepare for the possibility of
     *   paging I/O. Much of the point to paging I/O is to resolve page faults.
     *   Especially important is that drivers that handle paging I/O do not
     *   cause more page faults. All the code and data that each driver might
     *   ever use for access to the paging file must be locked into physical
     *   memory. This can’t be left until paging I/O actually occurs.
     *   It must be done in advance.
     */

    PagingFile = ExAllocatePoolZero(NonPagedPool, sizeof(*PagingFile), TAG_MM);
    if (PagingFile == NULL)
    {
        ObDereferenceObject(FileObject);
        ZwClose(FileHandle);
        ExFreePoolWithTag(Buffer, TAG_MM);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PagingFile->FileHandle = FileHandle;
    PagingFile->FileObject = FileObject;
    PagingFile->Size = (SafeMinimumSize.QuadPart >> PAGE_SHIFT);
    PagingFile->MinimumSize = PagingFile->Size;
    PagingFile->MaximumSize = (SafeMaximumSize.QuadPart >> PAGE_SHIFT);
    /* First page is never used: it's the header
     * TODO: write it
     */
    PagingFile->FreeSpace = PagingFile->Size - 1;
    PagingFile->CurrentUsage = 0;
    PagingFile->PageFileName = PageFileName;
    ASSERT(PagingFile->Size == PagingFile->FreeSpace + PagingFile->CurrentUsage + 1);

    AllocMapSize = sizeof(RTL_BITMAP) + (((PagingFile->MaximumSize + 31) / 32) * sizeof(ULONG));
    PagingFile->Bitmap = ExAllocatePoolWithTag(NonPagedPool,
                                               AllocMapSize,
                                               TAG_MM);
    if (PagingFile->Bitmap == NULL)
    {
        ExFreePoolWithTag(PagingFile, TAG_MM);
        ObDereferenceObject(FileObject);
        ZwClose(FileHandle);
        ExFreePoolWithTag(Buffer, TAG_MM);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlInitializeBitMap(PagingFile->Bitmap,
                        (PULONG)(PagingFile->Bitmap + 1),
                        (ULONG)(PagingFile->MaximumSize));
    RtlClearAllBits(PagingFile->Bitmap);

    /* The header is never a slot, and nothing beyond the current size is one until growth clears it */
    RtlSetBit(PagingFile->Bitmap, 0);
    if (PagingFile->MaximumSize > PagingFile->Size)
    {
        RtlSetBits(PagingFile->Bitmap,
                   (ULONG)PagingFile->Size,
                   (ULONG)(PagingFile->MaximumSize - PagingFile->Size));
    }

    /*
     * NitroPager owner tags (1 MB per GB of file); without them ARM3 does not page to this
     * file. Flag 0: no tags, nothing allocated (the pager is not used).
     */
    if (MiNitroPagerMode != 0)
    {
        PagingFile->SlotTags = ExAllocatePoolZero(NonPagedPool, PagingFile->Size * sizeof(ULONG), TAG_MM);
        PagingFile->SlotTagCount = (PagingFile->SlotTags != NULL) ? PagingFile->Size : 0;
    }
    PagingFile->SlotHint = 1;

    /* Insert the new paging file information into the list */
    KeAcquireGuardedMutex(&MmPageFileCreationLock);
    KeAcquireSpinLock(&MiPagingFileSlotLock, &OldIrql);
    /* Ensure the corresponding slot is empty yet */
    ASSERT(MmPagingFile[MmNumberOfPagingFiles] == NULL);
    MmPagingFile[MmNumberOfPagingFiles] = PagingFile;
    MmNumberOfPagingFiles++;
    MiFreeSwapPages = MiFreeSwapPages + PagingFile->FreeSpace;
    KeReleaseSpinLock(&MiPagingFileSlotLock, OldIrql);

    /* Its slots back committed memory from now on */
    InterlockedExchangeAddSizeT(&MmTotalCommitLimit, PagingFile->FreeSpace);
    InterlockedExchangeAddSizeT(&MmTotalCommitLimitMaximum, PagingFile->MaximumSize - 1);
    KeReleaseGuardedMutex(&MmPageFileCreationLock);

    MmSwapSpaceMessage = FALSE;

    /* The registry value is read, but nothing clears the file yet (separate ticket): say so once */
    if (MmZeroPageFile && (MmNumberOfPagingFiles == 1))
        DPRINT1("MM: ClearPageFileAtShutdown is set, but paging files are not cleared at shutdown\n");

    /* The thread that grows paging files toward their maximum */
    MiStartPagingFileGrowthThread();

    /* NitroPager: the modified page writer thread, once there is a file to write to */
    if (MiNitroPagerMode != 0)
        MiPagerStartWriter();

    if (!MmSystemPageFileLocated && BooleanFlagOn(FileObject->DeviceObject->Flags, DO_SYSTEM_BOOT_PARTITION))
    {
        MmSystemPageFileLocated = IoInitializeCrashDump(FileHandle);
    }

    return STATUS_SUCCESS;
}

/*
 * NitroPager slot layer (ARM3 private pages). A slot is a page of a paging
 * file, the bitmap index (the file offset in pages; index 0 is the header).
 * The ARM3 page-file PTE holds PageFileHigh = slot + 1.
 *
 * Every slot has an owner tag: a hash of the physical address of the PTE that
 * owns the data (see MiPagerOwnerTag). Tag 0 means "not written": the writer
 * stores the tag only when its write completed, so a read of a slot with tag 0
 * or with another owner's tag never returns data, and a free with another
 * owner's tag is refused. Legacy (RosMm) slots never have a tag.
 */
/*
 * Allocate a run of up to Wanted consecutive ARM3 slots in one paging file
 * (one cluster write covers them). Tries Wanted, then halves the run down to
 * one slot. Returns the number of slots, 0 if no file has a free slot.
 * Callable at <= DISPATCH_LEVEL, also inside the PFN lock (slot lock = leaf).
 */
static BOOLEAN MiPagerFileTakesSlots(_Inout_ PMMPAGING_FILE PagingFile);
static BOOLEAN MiPagerRetiredFileDue(_In_ PMMPAGING_FILE PagingFile);

/*
 * F8: a run size that failed is not searched for again (a full bitmap scan under
 * the slot lock, inside the writer's PFN lock hold) until this many more slots
 * are free in that file than when it failed
 */
#define MI_PAGER_RUN_RETRY_FREE 64

ULONG
NTAPI
MiAllocatePageFileSlots(
    _In_ ULONG Wanted,
    _Out_ PULONG FileIndex,
    _Out_ PULONG_PTR Slot)
{
    PMMPAGING_FILE PagingFile;
    KIRQL OldIrql;
    ULONG i, Offset, Run, j;

    ASSERT(Wanted != 0);
    KeAcquireSpinLock(&MiPagingFileSlotLock, &OldIrql);
    for (Run = Wanted; Run != 0; Run /= 2)
    {
        for (i = 0; i < MAX_PAGING_FILES; i++)
        {
            PagingFile = MmPagingFile[i];
            if ((PagingFile == NULL) || (PagingFile->SlotTags == NULL) ||
                (PagingFile->FreeSpace < Run) || !MiPagerFileTakesSlots(PagingFile))
            {
                continue;
            }

            /* A run this long was not there lately (F8) */
            if ((Run > 1) && (PagingFile->NoRunOf != 0) && (Run >= PagingFile->NoRunOf) &&
                (PagingFile->FreeSpace < PagingFile->NoRunFree + MI_PAGER_RUN_RETRY_FREE))
            {
                continue;
            }

            Offset = RtlFindClearBitsAndSet(PagingFile->Bitmap, Run, PagingFile->SlotHint);
            if (Offset == 0xFFFFFFFF)
            {
                if ((Run > 1) && ((PagingFile->NoRunOf == 0) || (Run <= PagingFile->NoRunOf)))
                {
                    PagingFile->NoRunOf = Run;
                    PagingFile->NoRunFree = PagingFile->FreeSpace;
                }
                continue;
            }
            if ((PagingFile->NoRunOf != 0) && (Run >= PagingFile->NoRunOf))
                PagingFile->NoRunOf = 0;

            /* Beyond the tags (cannot be: those bits stay set) or the PTE's lookup marker: not usable */
            if ((Offset == 0) ||
                ((ULONG_PTR)Offset + Run > PagingFile->SlotTagCount) ||
                ((ULONG_PTR)Offset + Run >= MI_PAGEFILE_HIGH_LIMIT))
            {
                for (j = 0; j < Run; j++)
                {
                    if (Offset + j != 0)
                        RtlClearBit(PagingFile->Bitmap, Offset + j);
                }
                continue;
            }

            PagingFile->SlotHint = Offset + Run;
            PagingFile->FreeSpace -= Run;
            PagingFile->CurrentUsage += Run;
            if (PagingFile->CurrentUsage > PagingFile->PeakUsage)
                PagingFile->PeakUsage = PagingFile->CurrentUsage;
            MiUsedSwapPages += Run;
            MiFreeSwapPages -= Run;
            for (j = 0; j < Run; j++)
            {
                ASSERT(PagingFile->SlotTags[Offset + j] == 0);
                MiStoreSlotTag(PagingFile, Offset + j, 0);
            }

            KeReleaseSpinLock(&MiPagingFileSlotLock, OldIrql);
            *FileIndex = i;
            *Slot = Offset;
            return Run;
        }
    }
    KeReleaseSpinLock(&MiPagingFileSlotLock, OldIrql);
    return 0;
}

BOOLEAN
NTAPI
MiAllocatePageFileSlot(
    _Out_ PULONG FileIndex,
    _Out_ PULONG_PTR Slot)
{
    return MiAllocatePageFileSlots(1, FileIndex, Slot) == 1;
}

/* A paging file takes ARM3 slots and is not retired for good (P4: private commitment may use the paging files) */
BOOLEAN
NTAPI
MiPagerHasSlotFile(VOID)
{
    ULONG i;

    /* Unlocked: files are never removed, SlotTags and RetiredForGood only change once */
    for (i = 0; i < MAX_PAGING_FILES; i++)
    {
        PMMPAGING_FILE PagingFile = MmPagingFile[i];

        if ((PagingFile != NULL) && (PagingFile->SlotTags != NULL) && !PagingFile->RetiredForGood)
            return TRUE;
    }
    return FALSE;
}

/* Free ARM3 slots in the files that still take new ones (a snapshot) */
PFN_NUMBER
NTAPI
MiPagerFreeSlotCount(VOID)
{
    PFN_NUMBER Count = 0;
    KIRQL OldIrql;
    ULONG i;

    KeAcquireSpinLock(&MiPagingFileSlotLock, &OldIrql);
    for (i = 0; i < MAX_PAGING_FILES; i++)
    {
        /*
         * A retired file due for its probe counts (N2): otherwise, with no modified page
         * left to probe it with, slots stay "short", trimming stays clean-only and the
         * file never comes back although the disk recovered
         */
        if ((MmPagingFile[i] != NULL) && (MmPagingFile[i]->SlotTags != NULL) &&
            (!MmPagingFile[i]->Retired || MiPagerRetiredFileDue(MmPagingFile[i])))
        {
            Count += MmPagingFile[i]->FreeSpace;
        }
    }
    KeReleaseSpinLock(&MiPagingFileSlotLock, OldIrql);
    return Count;
}

/*
 * The writer's cluster write to a file ended with Status. A file the volume
 * refuses (STATUS_FILE_INVALID: wrong media, a volume that went away) takes no
 * new slots for the rest of the boot. Other errors retire it only when they
 * persist: MI_PAGER_RETIRE_FAILURES failed writes in a row spread over at
 * least MI_PAGER_RETIRE_SPAN (the writer backs off between them), because
 * storport and atapi report a memory shortage on the paging path as a plain
 * device error. Such a file is tried again MI_PAGER_RETRY_RETIRED after it was
 * retired (MiAllocatePageFileSlots); one more failure retires it again.
 * Shortage statuses never count. Slots that hold data are always read.
 * Returns TRUE when this call retired the file.
 */
#define MI_PAGER_RETIRE_FAILURES 8
#define MI_PAGER_RETIRE_SPAN (10ULL * 10 * 1000 * 1000)
#define MI_PAGER_RETRY_RETIRED (60ULL * 10 * 1000 * 1000)
BOOLEAN
NTAPI
MiPagerPagingFileWriteResult(
    _In_ ULONG FileIndex,
    _In_ NTSTATUS Status)
{
    PMMPAGING_FILE PagingFile;
    BOOLEAN Retired = FALSE;
    ULONGLONG Now = KeQueryInterruptTime();
    KIRQL OldIrql;

    KeAcquireSpinLock(&MiPagingFileSlotLock, &OldIrql);
    PagingFile = (FileIndex < MAX_PAGING_FILES) ? MmPagingFile[FileIndex] : NULL;
    if ((PagingFile != NULL) && !PagingFile->Retired)
    {
        if (NT_SUCCESS(Status))
        {
            PagingFile->WriteFailuresInARow = 0;
        }
        else if ((Status == STATUS_INSUFFICIENT_RESOURCES) || (Status == STATUS_NO_MEMORY))
        {
            /* A shortage (an IRP, pool) says nothing about the file: it passes */
        }
        else if (Status == STATUS_FILE_INVALID)
        {
            PagingFile->Retired = TRUE;
            PagingFile->RetiredForGood = TRUE;
            Retired = TRUE;
        }
        else
        {
            if (PagingFile->WriteFailuresInARow++ == 0)
                PagingFile->FirstFailure = Now;
            if ((PagingFile->WriteFailuresInARow >= MI_PAGER_RETIRE_FAILURES) &&
                ((Now - PagingFile->FirstFailure) >= MI_PAGER_RETIRE_SPAN))
            {
                PagingFile->Retired = TRUE;
                PagingFile->RetiredAt = Now;
                Retired = TRUE;
            }
        }
    }
    KeReleaseSpinLock(&MiPagingFileSlotLock, OldIrql);

    if (Retired)
    {
        DPRINT1("NitroPager: paging file %lu retired after failed writes (0x%lx): no new pages go to it%s\n",
                FileIndex, Status, (Status == STATUS_FILE_INVALID) ? "" : " for 60 s");
    }
    return Retired;
}

/* Slot lock held: a file retired for its errors (not for good) whose probe is due */
static
BOOLEAN
MiPagerRetiredFileDue(
    _In_ PMMPAGING_FILE PagingFile)
{
    return PagingFile->Retired && !PagingFile->RetiredForGood &&
           ((KeQueryInterruptTime() - PagingFile->RetiredAt) >= MI_PAGER_RETRY_RETIRED);
}

/* Slot lock held: a file retired for its errors (not for good) is tried again after a while */
static
BOOLEAN
MiPagerFileTakesSlots(
    _Inout_ PMMPAGING_FILE PagingFile)
{
    if (!PagingFile->Retired)
        return TRUE;
    if (!MiPagerRetiredFileDue(PagingFile))
        return FALSE;

    /* One more failure retires it again at once (the streak and its start stay) */
    PagingFile->Retired = FALSE;
    PagingFile->WriteFailuresInARow = MI_PAGER_RETIRE_FAILURES - 1;
    return TRUE;
}

/*
 * Release an ARM3 slot. Owner is the releasing PTE's tag: the slot's tag must
 * be that or 0 (never written). Anything else is refused and counted, the
 * slot stays allocated: a leak, never a slot handed to two owners.
 */
BOOLEAN
NTAPI
MiReleasePageFileSlot(
    _In_ ULONG FileIndex,
    _In_ ULONG_PTR Slot,
    _In_ ULONG Owner)
{
    PMMPAGING_FILE PagingFile;
    KIRQL OldIrql;
    ULONG Tag;

    KeAcquireSpinLock(&MiPagingFileSlotLock, &OldIrql);
    PagingFile = (FileIndex < MAX_PAGING_FILES) ? MmPagingFile[FileIndex] : NULL;
    if ((PagingFile == NULL) ||
        (PagingFile->SlotTags == NULL) ||
        (Slot == 0) ||
        (Slot >= PagingFile->SlotTagCount) ||
        !RtlTestBit(PagingFile->Bitmap, (ULONG)Slot))
    {
        KeReleaseSpinLock(&MiPagingFileSlotLock, OldIrql);
        MiPagerSlotProblem(MI_PAGER_BAD_SLOT_FREE, FileIndex, Slot, Owner, 0);
        return FALSE;
    }

    Tag = PagingFile->SlotTags[Slot];
    if ((Tag != 0) && (Tag != Owner))
    {
        KeReleaseSpinLock(&MiPagingFileSlotLock, OldIrql);
        MiPagerSlotProblem(MI_PAGER_TAG_MISMATCH_FREE, FileIndex, Slot, Owner, Tag);
        return FALSE;
    }

    MiStoreSlotTag(PagingFile, Slot, 0);
    RtlClearBit(PagingFile->Bitmap, (ULONG)Slot);
    if (Slot < PagingFile->SlotHint)
        PagingFile->SlotHint = (ULONG)Slot;
    PagingFile->FreeSpace++;
    PagingFile->CurrentUsage--;
    MiFreeSwapPages++;
    MiUsedSwapPages--;
    KeReleaseSpinLock(&MiPagingFileSlotLock, OldIrql);
    return TRUE;
}

/* The writer's write completed: the slot now holds Owner's data */
VOID
NTAPI
MiSetPageFileSlotTag(
    _In_ ULONG FileIndex,
    _In_ ULONG_PTR Slot,
    _In_ ULONG Owner)
{
    PMMPAGING_FILE PagingFile;
    KIRQL OldIrql;

    ASSERT(Owner != 0);
    KeAcquireSpinLock(&MiPagingFileSlotLock, &OldIrql);
    PagingFile = MmPagingFile[FileIndex];
    ASSERT((PagingFile != NULL) && (Slot < PagingFile->SlotTagCount));
    ASSERT(RtlTestBit(PagingFile->Bitmap, (ULONG)Slot));
    ASSERT(PagingFile->SlotTags[Slot] == 0);
    MiStoreSlotTag(PagingFile, Slot, Owner);
    KeReleaseSpinLock(&MiPagingFileSlotLock, OldIrql);
}

/* Does the slot hold Owner's data? Returns the tag found in *Found */
BOOLEAN
NTAPI
MiCheckPageFileSlotTag(
    _In_ ULONG FileIndex,
    _In_ ULONG_PTR Slot,
    _In_ ULONG Owner,
    _Out_ PULONG Found)
{
    PMMPAGING_FILE PagingFile;
    KIRQL OldIrql;
    BOOLEAN Match = FALSE;

    *Found = 0;
    KeAcquireSpinLock(&MiPagingFileSlotLock, &OldIrql);
    PagingFile = (FileIndex < MAX_PAGING_FILES) ? MmPagingFile[FileIndex] : NULL;
    if ((PagingFile != NULL) &&
        (PagingFile->SlotTags != NULL) &&
        (Slot != 0) &&
        (Slot < PagingFile->SlotTagCount) &&
        RtlTestBit(PagingFile->Bitmap, (ULONG)Slot))
    {
        *Found = PagingFile->SlotTags[Slot];
        Match = (*Found != 0) && (*Found == Owner);
    }
    KeReleaseSpinLock(&MiPagingFileSlotLock, OldIrql);
    return Match;
}

/*
 * Write Count pages (at most MI_PAGER_CLUSTER_MAX) to Count consecutive ARM3
 * slots from FirstSlot, one paging write. Fails, never bugchecks, on a file
 * that went away. The MDL lives on the stack: no pool on the writer's path
 * above the I/O manager (whose IRP falls back to the reserve IRPs).
 */
NTSTATUS
NTAPI
MiWritePageFileCluster(
    _In_reads_(Count) PPFN_NUMBER Pages,
    _In_ ULONG Count,
    _In_ ULONG FileIndex,
    _In_ ULONG_PTR FirstSlot)
{
    DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) UCHAR MdlBase[sizeof(MDL) + MI_PAGER_CLUSTER_MAX * sizeof(PFN_NUMBER)];
    PMDL Mdl = (PMDL)MdlBase;
    LARGE_INTEGER FileOffset;
    IO_STATUS_BLOCK Iosb;
    PMMPAGING_FILE PagingFile;
    KEVENT Event;
    NTSTATUS Status;

    ASSERT((Count != 0) && (Count <= MI_PAGER_CLUSTER_MAX));
    PagingFile = (FileIndex < MAX_PAGING_FILES) ? MmPagingFile[FileIndex] : NULL;
    if ((PagingFile == NULL) || (PagingFile->FileObject == NULL) || (PagingFile->FileObject->DeviceObject == NULL))
        return STATUS_FILE_INVALID;

    MmInitializeMdl(Mdl, NULL, Count * PAGE_SIZE);
    RtlCopyMemory(MmGetMdlPfnArray(Mdl), Pages, Count * sizeof(PFN_NUMBER));
    Mdl->MdlFlags |= MDL_PAGES_LOCKED;

    FileOffset.QuadPart = (LONGLONG)FirstSlot * PAGE_SIZE;
    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    Status = IoSynchronousPageWrite(PagingFile->FileObject, Mdl, &FileOffset, &Event, &Iosb);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = Iosb.Status;
    }
    if (Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA)
        MmUnmapLockedPages(Mdl->MappedSystemVa, Mdl);

    /* A short write is a failed write: no slot may be tagged as holding its page */
    if (NT_SUCCESS(Status) && (Iosb.Information != (ULONG_PTR)Count * PAGE_SIZE))
        Status = STATUS_UNEXPECTED_IO_ERROR;

    if (NT_SUCCESS(Status))
    {
        MI_PRCB_COUNT_ADD(MmDirtyPagesWriteCount, Count);
        MI_PRCB_COUNT_ADD(MmDirtyWriteIoCount, 1);
    }
    return Status;
}

/* Write one page to an ARM3 slot */
NTSTATUS
NTAPI
MiWritePageFileSlot(
    _In_ PFN_NUMBER Page,
    _In_ ULONG FileIndex,
    _In_ ULONG_PTR Slot)
{
    return MiWritePageFileCluster(&Page, 1, FileIndex, Slot);
}

/* EOF */
