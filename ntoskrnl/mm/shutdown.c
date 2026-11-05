/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/mm/shutdown.c
 * PURPOSE:         Memory Manager Shutdown
 * PROGRAMMERS:
 */

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

#define MODULE_INVOLVED_IN_ARM3
#include "ARM3/miarm.h"

/* GLOBALS *******************************************************************/

/*
 * A dirty page whose write fails is tried again until it has failed this many times in a row, over at least
 * this long (a transient failure, a device that is busy or a lock that is held for a moment, still gets its
 * retries); after that shutdown gives the page up: the data is lost, as with the delayed write that Windows
 * gives up ("{Delayed Write Failed}"), and the system goes on to power off instead of looping for ever.
 */
#define MI_SHUTDOWN_GIVEUP_FAILURES 8
#define MI_SHUTDOWN_GIVEUP_TIME (5ULL * 1000 * 1000 * 10)
/* Pause after a pass in which a write failed, so that the retries are spread over the time above */
#define MI_SHUTDOWN_RETRY_PAUSE (-10 * 1000 * 10)
/* Pages tracked at once; more failing pages than this are judged together (MiShutdownOverflowSince) */
#define MI_SHUTDOWN_FAILED_PAGES 128

typedef struct _MI_SHUTDOWN_FAILED_PAGE
{
    PMM_SECTION_SEGMENT Segment;
    LONGLONG Offset;
    PFN_NUMBER Page;
    ULONG Failures;
    BOOLEAN GivenUp;
    ULONGLONG FirstFailure;
} MI_SHUTDOWN_FAILED_PAGE;

/*
 * A device whose writes fail this many times in a row (any pages, no write succeeding in between), over at
 * least the time above, is dead (a disk that is gone, not one bad file): paying the retries of every page
 * would take for ever, as each write may take the device's timeout.  The dirty pages of such a device are given
 * up without another write.
 */
#define MI_SHUTDOWN_BAD_DEVICE_FAILURES 8
#define MI_SHUTDOWN_DEVICES 8
/* Messages and event log entries for given-up pages are limited, the summary at the end counts them all */
#define MI_SHUTDOWN_MAX_REPORTS 32

typedef struct _MI_SHUTDOWN_DEVICE
{
    PDEVICE_OBJECT Device;
    ULONG FailuresInARow;
    BOOLEAN Bad;
    ULONGLONG FirstFailure;
} MI_SHUTDOWN_DEVICE;

/* Only MmShutdownSystem(0) uses these, once, from the shutdown thread */
static MI_SHUTDOWN_FAILED_PAGE MiShutdownFailedPages[MI_SHUTDOWN_FAILED_PAGES];
static ULONGLONG MiShutdownOverflowSince;
static MI_SHUTDOWN_DEVICE MiShutdownDevices[MI_SHUTDOWN_DEVICES];
static ULONG MiShutdownGivenUpPages, MiShutdownReports;

/* PRIVATE FUNCTIONS *********************************************************/

static
MI_SHUTDOWN_FAILED_PAGE*
MiShutdownFindFailedPage(
    _In_ PMM_SECTION_SEGMENT Segment,
    _In_ LONGLONG Offset,
    _In_ PFN_NUMBER Page,
    _In_ BOOLEAN Create)
{
    MI_SHUTDOWN_FAILED_PAGE *Free = NULL;
    ULONG i;

    for (i = 0; i < MI_SHUTDOWN_FAILED_PAGES; i++)
    {
        MI_SHUTDOWN_FAILED_PAGE *Slot = &MiShutdownFailedPages[i];

        if (Slot->Segment == NULL)
        {
            if (Free == NULL)
                Free = Slot;
        }
        else if (Slot->Segment == Segment && Slot->Offset == Offset)
        {
            if (Slot->Page == Page)
                return Slot;
            /* The page of that place was released and another one took its place: a new page */
            RtlZeroMemory(Slot, sizeof(*Slot));
            if (Free == NULL)
                Free = Slot;
        }
    }

    if (Free != NULL && Create)
    {
        Free->Segment = Segment;
        Free->Offset = Offset;
        Free->Page = Page;
        return Free;
    }
    return NULL;
}

/* TRUE if the page was given up before: it is not written again */
static
BOOLEAN
MiShutdownPageGivenUp(
    _In_ PMM_SECTION_SEGMENT Segment,
    _In_ LONGLONG Offset,
    _In_ PFN_NUMBER Page)
{
    MI_SHUTDOWN_FAILED_PAGE *Slot = MiShutdownFindFailedPage(Segment, Offset, Page, FALSE);

    return Slot != NULL && Slot->GivenUp;
}

/* The write of the page worked: forget its failures */
static
VOID
MiShutdownPageWritten(
    _In_ PMM_SECTION_SEGMENT Segment,
    _In_ LONGLONG Offset,
    _In_ PFN_NUMBER Page)
{
    MI_SHUTDOWN_FAILED_PAGE *Slot = MiShutdownFindFailedPage(Segment, Offset, Page, FALSE);

    if (Slot != NULL)
        RtlZeroMemory(Slot, sizeof(*Slot));
}

/* The write of the page failed. Returns TRUE when shutdown gives the page up now. */
static
BOOLEAN
MiShutdownPageWriteFailed(
    _In_ PMM_SECTION_SEGMENT Segment,
    _In_ LONGLONG Offset,
    _In_ PFN_NUMBER Page)
{
    MI_SHUTDOWN_FAILED_PAGE *Slot = MiShutdownFindFailedPage(Segment, Offset, Page, TRUE);
    ULONGLONG Now = KeQueryInterruptTime();

    if (Slot == NULL)
    {
        /* Table full: the pages that are not tracked are given up once the first of them failed long enough ago */
        if (MiShutdownOverflowSince == 0)
            MiShutdownOverflowSince = Now;
        return (Now - MiShutdownOverflowSince) >= MI_SHUTDOWN_GIVEUP_TIME;
    }

    if (Slot->Failures++ == 0)
        Slot->FirstFailure = Now;

    if (Slot->Failures >= MI_SHUTDOWN_GIVEUP_FAILURES &&
        (Now - Slot->FirstFailure) >= MI_SHUTDOWN_GIVEUP_TIME)
    {
        Slot->GivenUp = TRUE;
        return TRUE;
    }
    return FALSE;
}

static
MI_SHUTDOWN_DEVICE*
MiShutdownFindDevice(
    _In_ PDEVICE_OBJECT Device,
    _In_ BOOLEAN Create)
{
    MI_SHUTDOWN_DEVICE *Free = NULL;
    ULONG i;

    if (Device == NULL)
        return NULL;

    for (i = 0; i < MI_SHUTDOWN_DEVICES; i++)
    {
        if (MiShutdownDevices[i].Device == Device)
            return &MiShutdownDevices[i];
        if (MiShutdownDevices[i].Device == NULL && Free == NULL)
            Free = &MiShutdownDevices[i];
    }

    if (Free != NULL && Create)
    {
        Free->Device = Device;
        return Free;
    }
    return NULL;
}

/* TRUE if the device was found dead: its pages are not written */
static
BOOLEAN
MiShutdownDeviceBad(
    _In_ PDEVICE_OBJECT Device)
{
    MI_SHUTDOWN_DEVICE *Slot = MiShutdownFindDevice(Device, FALSE);

    return Slot != NULL && Slot->Bad;
}

/* A write to the device worked: its failures in a row start again */
static
VOID
MiShutdownDeviceWritten(
    _In_ PDEVICE_OBJECT Device)
{
    MI_SHUTDOWN_DEVICE *Slot = MiShutdownFindDevice(Device, FALSE);

    if (Slot != NULL)
        RtlZeroMemory(Slot, sizeof(*Slot));
}

/* A write to the device failed */
static
VOID
MiShutdownDeviceFailed(
    _In_ PDEVICE_OBJECT Device)
{
    MI_SHUTDOWN_DEVICE *Slot = MiShutdownFindDevice(Device, TRUE);
    ULONGLONG Now = KeQueryInterruptTime();

    if (Slot == NULL)
        return;

    if (Slot->FailuresInARow++ == 0)
        Slot->FirstFailure = Now;

    if (!Slot->Bad && Slot->FailuresInARow >= MI_SHUTDOWN_BAD_DEVICE_FAILURES &&
        (Now - Slot->FirstFailure) >= MI_SHUTDOWN_GIVEUP_TIME)
    {
        Slot->Bad = TRUE;
        DPRINT1("MM: shutdown: device %p fails its writes (%lu in a row), its pages are given up without another write\n",
                Device, Slot->FailuresInARow);
    }
}

/*
 * Tells that the write of a page is given up: the debugger port, and an event log entry like Windows' lost
 * delayed write (IO_LOST_DELAYED_WRITE, event 50) with the file name, against the file system's device.
 * The event log service may be gone this late in shutdown, then the entry stays queued in the I/O manager.
 * PASSIVE_LEVEL, no lock held, the segment (and so its file object) referenced.
 */
static
VOID
MiShutdownLogLostWrite(
    _In_ PMM_SECTION_SEGMENT Segment,
    _In_ LONGLONG Offset,
    _In_ NTSTATUS Status)
{
    PFILE_OBJECT FileObject = Segment->FileObject;
    PIO_ERROR_LOG_PACKET Packet;
    PDEVICE_OBJECT LogDevice;
    ULONG NameChars = 0, Size;
    PWCHAR Name = NULL;
    const ULONG MaxChars = 100;

    if (FileObject != NULL && FileObject->FileName.Buffer != NULL)
    {
        Name = FileObject->FileName.Buffer;
        NameChars = FileObject->FileName.Length / sizeof(WCHAR);
        /* Names that are too long show their tail, the part that tells the file apart */
        if (NameChars > MaxChars)
        {
            Name += NameChars - MaxChars;
            NameChars = MaxChars;
        }
    }

    if (MiShutdownReports++ >= MI_SHUTDOWN_MAX_REPORTS)
        return;

    DPRINT1("MM: shutdown gives up the write of the page at 0x%I64x of '%wZ' (status 0x%08lx): not written\n",
            Offset, FileObject ? &FileObject->FileName : NULL, Status);

    /* The file system's volume device, not the storage device below it (which FileObject->DeviceObject is) */
    if (FileObject == NULL)
        return;
    LogDevice = (FileObject->Vpb != NULL && FileObject->Vpb->DeviceObject != NULL) ?
                FileObject->Vpb->DeviceObject : FileObject->DeviceObject;
    if (LogDevice == NULL)
        return;

    Size = FIELD_OFFSET(IO_ERROR_LOG_PACKET, DumpData) + (NameChars + 1) * sizeof(WCHAR);
    Packet = IoAllocateErrorLogEntry(LogDevice, (UCHAR)Size);
    if (Packet == NULL)
        return;

    Packet->ErrorCode = IO_LOST_DELAYED_WRITE;
    Packet->FinalStatus = Status;
    Packet->MajorFunctionCode = IRP_MJ_WRITE;
    Packet->DeviceOffset.QuadPart = Offset;
    Packet->DumpDataSize = 0;
    Packet->NumberOfStrings = 1;
    Packet->StringOffset = FIELD_OFFSET(IO_ERROR_LOG_PACKET, DumpData);
    if (NameChars != 0)
        RtlCopyMemory((PUCHAR)Packet + Packet->StringOffset, Name, NameChars * sizeof(WCHAR));
    ((PWCHAR)((PUCHAR)Packet + Packet->StringOffset))[NameChars] = UNICODE_NULL;
    IoWriteErrorLogEntry(Packet);
}

VOID
MiShutdownSystem(VOID)
{
    ULONG i;
    PFN_NUMBER Page;
    BOOLEAN Dirty, Failed;

    /* Loop through all the paging files */
    for (i = 0; i < MmNumberOfPagingFiles; i++)
    {
        /* Free page file name */
        ASSERT(MmPagingFile[i]->PageFileName.Buffer != NULL);
        ExFreePoolWithTag(MmPagingFile[i]->PageFileName.Buffer, TAG_MM);
        MmPagingFile[i]->PageFileName.Buffer = NULL;

        /* And close them */
        ZwClose(MmPagingFile[i]->FileHandle);
    }

    /* Loop through all the pages owned by the legacy Mm and page them out, if needed. */
    /* We do it as long as there are dirty pages, since flushing can cause the FS to dirtify new ones. */
    /* A page that cannot be written is tried again a limited number of times, then given up (see above). */
    do
    {
        Dirty = FALSE;
        Failed = FALSE;

        Page = MmGetLRUFirstUserPage();
        while (Page)
        {
            LARGE_INTEGER SegmentOffset;
            PMM_SECTION_SEGMENT Segment = MmGetSectionAssociation(Page, &SegmentOffset);

            if (Segment)
            {
                BOOLEAN GiveUp = FALSE, Skipped = FALSE;
                NTSTATUS WriteStatus = STATUS_SUCCESS;
                PDEVICE_OBJECT Device = Segment->FileObject ? Segment->FileObject->DeviceObject : NULL;

                if ((*Segment->Flags) & MM_DATAFILE_SEGMENT)
                {
                    MmLockSectionSegment(Segment);

                    ULONG_PTR Entry = MmGetPageEntrySectionSegment(Segment, &SegmentOffset);

                    if (!IS_SWAP_FROM_SSE(Entry) && IS_DIRTY_SSE(Entry) &&
                        !MiShutdownPageGivenUp(Segment, SegmentOffset.QuadPart, PFN_FROM_SSE(Entry)))
                    {
                        PFN_NUMBER DirtyPage = PFN_FROM_SSE(Entry);

                        if (MiShutdownDeviceBad(Device))
                        {
                            GiveUp = Skipped = TRUE;
                        }
                        else
                        {
                            MmCheckDirtySegmentEx(Segment, &SegmentOffset, FALSE, TRUE, &WriteStatus);
                            if (NT_SUCCESS(WriteStatus))
                            {
                                MiShutdownPageWritten(Segment, SegmentOffset.QuadPart, DirtyPage);
                                MiShutdownDeviceWritten(Device);
                                Dirty = TRUE;
                            }
                            else
                            {
                                MiShutdownDeviceFailed(Device);
                                if (MiShutdownPageWriteFailed(Segment, SegmentOffset.QuadPart, DirtyPage))
                                {
                                    /* Given up: it does not keep the loop going */
                                    GiveUp = TRUE;
                                }
                                else
                                {
                                    Dirty = TRUE;
                                    Failed = TRUE;
                                }
                            }
                        }
                    }

                    MmUnlockSectionSegment(Segment);

                    if (GiveUp)
                    {
                        MiShutdownGivenUpPages++;
                        if (!Skipped)
                            MiShutdownLogLostWrite(Segment, SegmentOffset.QuadPart, WriteStatus);
                    }
                }

                MmDereferenceSegment(Segment);
            }

            Page = MmGetLRUNextUserPage(Page, FALSE);
        }

        if (Failed)
        {
            /* The next pass is the retry of the failed writes: not at once */
            LARGE_INTEGER Pause;

            Pause.QuadPart = MI_SHUTDOWN_RETRY_PAUSE;
            KeDelayExecutionThread(KernelMode, FALSE, &Pause);
        }
    } while (Dirty);

    if (MiShutdownGivenUpPages != 0)
    {
        DPRINT1("MM: shutdown gave up %lu page writes (the pages stay dirty, the file systems' own shutdown flush still tries them once)\n",
                MiShutdownGivenUpPages);
    }
}

VOID
MmShutdownSystem(IN ULONG Phase)
{
    if (Phase == 0)
    {
        MiShutdownSystem();
    }
    else if (Phase == 1)
    {
        ULONG i;

        /* Loop through all the paging files */
        for (i = 0; i < MmNumberOfPagingFiles; i++)
        {
            /* And dereference them */
            ObDereferenceObject(MmPagingFile[i]->FileObject);
        }
    }
    else
    {
        ASSERT(Phase == 2);

        UNIMPLEMENTED;
    }
}
