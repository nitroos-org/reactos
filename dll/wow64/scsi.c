/*
 * PROJECT:     ReactOS WoW64
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     SCSI and ATA pass-through requests of 32-bit callers
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 *
 * IOCTL_SCSI_PASS_THROUGH, IOCTL_SCSI_PASS_THROUGH_DIRECT, IOCTL_ATA_PASS_THROUGH and
 * IOCTL_ATA_PASS_THROUGH_DIRECT carry a header with a ULONG_PTR (the data buffer offset) or a PVOID (the
 * data buffer of the _DIRECT forms), so the 32-bit header is smaller and the sense and data areas behind it,
 * and the offsets to them, move:
 *
 *   field                       SCSI 32-bit  native     ATA 32-bit  native
 *   Length                      0            0          0           0
 *   DataTransferLength          12           12         8           8
 *   DataBufferOffset/DataBuffer 20           24         20          24
 *   SenseInfoOffset             24           32         -           -
 *   Cdb / PreviousTaskFile      28           36         24          32
 *   CurrentTaskFile             -            -          32          40
 *   sizeof                      44           56         40          48
 *
 * The storage drivers of this tree (sptilib, classpnp, cdrom) read the 32-bit layout themselves, as on
 * Windows, when IoIs32bitProcess() is true for the request, which it is for every request of a WoW64
 * process (it depends on the process, not on the request's IO_STATUS_BLOCK or event). Translating the
 * header to the native layout therefore does not work (measured: every request fails with
 * STATUS_REVISION_MISMATCH, because the drivers expect Length 44).
 * What the drivers cannot do for a 32-bit caller is these three things, done here:
 *
 *  - the request is sent with a private event and a private IO_STATUS_BLOCK, and the guest's event and
 *    IO_STATUS_BLOCK are set only after the result is in the guest's buffers: the kernel would set them as
 *    soon as the driver completes the request, before the copy-out below. The private event is also how a
 *    request that pends on an overlapped handle is waited for, and how the code knows the request reached
 *    the driver. They do not make the driver see a 32-bit request: NtDeviceIoControlFile hands the
 *    IO_STATUS_BLOCK it is given to the driver whatever the handle, and IoIs32bitProcess() looks at the
 *    process only;
 *  - the request is copied in, validated on the copy and sent from the copy (so the guest cannot change the
 *    header after the check), and the result is copied out: the data pointer of a _DIRECT request is the
 *    one the driver locks, and a range outside the guest address space must not reach it. The offsets and
 *    lengths in the header are checked by the driver against the lengths of the buffers, which are the guest's;
 *  - the request runs to completion here: the buffers are native copies that must outlive it.
 */

#include "wow64p.h"
#include <winioctl.h>
#include <ntddscsi.h>

/* The 32-bit layouts (ntddscsi.h defines SCSI_PASS_THROUGH32 and the others only for some compilers:
 * POINTER_32 is empty with GCC), spelled out with their sizes asserted. */
typedef struct
{
    USHORT Length;
    UCHAR ScsiStatus, PathId, TargetId, Lun, CdbLength, SenseInfoLength, DataIn;
    ULONG DataTransferLength, TimeOutValue;
    ULONG DataBufferOffset; /* DataBuffer in the _DIRECT form */
    ULONG SenseInfoOffset;
    UCHAR Cdb[16];
} WOW64_SCSI_PASS_THROUGH;

typedef struct
{
    USHORT Length, AtaFlags;
    UCHAR PathId, TargetId, Lun, ReservedAsUchar;
    ULONG DataTransferLength, TimeOutValue, ReservedAsUlong;
    ULONG DataBufferOffset; /* DataBuffer in the _DIRECT form */
    UCHAR PreviousTaskFile[8], CurrentTaskFile[8];
} WOW64_ATA_PASS_THROUGH;

C_ASSERT(sizeof(WOW64_SCSI_PASS_THROUGH) == 44);
C_ASSERT(FIELD_OFFSET(WOW64_SCSI_PASS_THROUGH, DataTransferLength) == 12);
C_ASSERT(FIELD_OFFSET(WOW64_SCSI_PASS_THROUGH, TimeOutValue) == 16);
C_ASSERT(FIELD_OFFSET(WOW64_SCSI_PASS_THROUGH, DataBufferOffset) == 20);
C_ASSERT(FIELD_OFFSET(WOW64_SCSI_PASS_THROUGH, SenseInfoOffset) == 24);
C_ASSERT(FIELD_OFFSET(WOW64_SCSI_PASS_THROUGH, Cdb) == 28);
C_ASSERT(sizeof(WOW64_ATA_PASS_THROUGH) == 40);
C_ASSERT(FIELD_OFFSET(WOW64_ATA_PASS_THROUGH, DataTransferLength) == 8);
C_ASSERT(FIELD_OFFSET(WOW64_ATA_PASS_THROUGH, DataBufferOffset) == 20);
C_ASSERT(FIELD_OFFSET(WOW64_ATA_PASS_THROUGH, PreviousTaskFile) == 24);
C_ASSERT(FIELD_OFFSET(WOW64_ATA_PASS_THROUGH, CurrentTaskFile) == 32);

/* The native layouts, for comparison */
C_ASSERT(sizeof(SCSI_PASS_THROUGH) == 56);
C_ASSERT(sizeof(SCSI_PASS_THROUGH_DIRECT) == 56);
C_ASSERT(FIELD_OFFSET(SCSI_PASS_THROUGH, DataBufferOffset) == 24);
C_ASSERT(FIELD_OFFSET(SCSI_PASS_THROUGH, SenseInfoOffset) == 32);
C_ASSERT(FIELD_OFFSET(SCSI_PASS_THROUGH, Cdb) == 36);
C_ASSERT(sizeof(ATA_PASS_THROUGH_EX) == 48);
C_ASSERT(sizeof(ATA_PASS_THROUGH_DIRECT) == 48);
C_ASSERT(FIELD_OFFSET(ATA_PASS_THROUGH_EX, DataBufferOffset) == 24);
C_ASSERT(FIELD_OFFSET(ATA_PASS_THROUGH_EX, PreviousTaskFile) == 32);
C_ASSERT(FIELD_OFFSET(ATA_PASS_THROUGH_EX, CurrentTaskFile) == 40);

/* Largest buffer copied for a request. Real transfers are a few megabytes at most (the drivers cap them far
 * lower); a larger one fails like a pool allocation of that size does. */
#define WOW64_MAX_PASS_THROUGH 0x4000000UL

NTSTATUS Wow64ScsiPassThrough(const ULONG *a)
{
    const ULONG Code = a[5];
    const ULONG InLength = a[7], OutLength = a[9];
    const BOOLEAN Ata = Code == IOCTL_ATA_PASS_THROUGH || Code == IOCTL_ATA_PASS_THROUGH_DIRECT;
    const BOOLEAN Direct = Code == IOCTL_SCSI_PASS_THROUGH_DIRECT || Code == IOCTL_ATA_PASS_THROUGH_DIRECT;
    const ULONG Header = Ata ? sizeof(WOW64_ATA_PASS_THROUGH) : sizeof(WOW64_SCSI_PASS_THROUGH);
    UCHAR *Buffer;
    ULONG Size, Information = 0;
    IO_STATUS_BLOCK Io, *Guest;
    HANDLE Event = NULL;
    LARGE_INTEGER NoWait = {{0}};
    BOOLEAN Started = FALSE;
    NTSTATUS Status;

    /* Both buffers must be guest memory before the request is built: a buffer the guest gets wrong is an
     * access violation here, not a fault of the kernel on the copy */
    if (a[6] && !GuestSpan(a[6], InLength)) return STATUS_ACCESS_VIOLATION;
    if (a[8] && !GuestSpan(a[8], OutLength)) return STATUS_ACCESS_VIOLATION;
    if (InLength > WOW64_MAX_PASS_THROUGH || OutLength > WOW64_MAX_PASS_THROUGH) return STATUS_INSUFFICIENT_RESOURCES;
    /* a NULL buffer with a length goes on as it is: the kernel gives the error it gives a 64-bit caller */
    if (a[6]) ProbeInput(a[6], InLength);
    if (a[8]) ProbeOutput(a[8], OutLength);
    Guest = IoBegin(a[4], &Io); /* probes the guest block */
    if (!Guest) return STATUS_ACCESS_VIOLATION;

    Size = max(max(InLength, OutLength), 1);
    Buffer = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, Size);
    if (!Buffer) return STATUS_NO_MEMORY;

    _SEH2_TRY
    {
        BOOLEAN Send = TRUE;

        /* The request is read from the guest once; everything below works on the copy */
        if (a[6]) RtlCopyMemory(Buffer, PTR32(a[6]), InLength);

        if (Direct && a[6] && InLength >= Header)
        {
            /* The data pointer is zero-extended by the driver and locked as it is: the range it names
             * must lie in the guest address space, or the kernel would lock whatever the native space
             * holds there. A bad range inside the guest space is the driver's to judge. */
            ULONG Pointer, Transfer;
            if (Ata)
            {
                const WOW64_ATA_PASS_THROUGH *Apt = (PVOID)Buffer;
                Pointer = Apt->DataBufferOffset;
                Transfer = Apt->DataTransferLength;
            }
            else
            {
                const WOW64_SCSI_PASS_THROUGH *Spt = (PVOID)Buffer;
                Pointer = Spt->DataBufferOffset;
                Transfer = Spt->DataTransferLength;
            }
            if (Pointer && Transfer && !GuestSpan(Pointer, Transfer)) Send = FALSE;
        }

        if (!Send)
        {
            /* what the driver answers for a range it cannot lock (also what Windows answers) */
            Status = STATUS_INSUFFICIENT_RESOURCES;
        }
        else
        {
            /* The private event and block keep the guest's own from being set before the result is copied out */
            Status = NtCreateEvent(&Event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
            if (NT_SUCCESS(Status))
            {
                RtlZeroMemory(&Io, sizeof(Io));
                Status = NtDeviceIoControlFile(HANDLE32(a[0]), Event, NULL, NULL, &Io, Code,
                                               a[6] ? Buffer : NULL, InLength, a[8] ? Buffer : NULL, OutLength);
                if (Status == STATUS_PENDING)
                {
                    Status = NtWaitForSingleObject(Event, FALSE, NULL);
                    if (NT_SUCCESS(Status)) Status = Io.Status;
                }
                /* the event is signalled for every request that reached the driver, and only for those */
                Started = NtWaitForSingleObject(Event, FALSE, &NoWait) == STATUS_SUCCESS;

                if (Started)
                {
                    /* Copy the result out as the kernel does for a buffered request: the bytes the
                     * driver reports, unless the request failed */
                    Information = (ULONG)min(Io.Information, (ULONG_PTR)OutLength);
                    if (!NT_ERROR(Status) && Information && a[8])
                        RtlCopyMemory(PTR32(a[8]), Buffer, Information);
                    Io.Information = Information;
                    IoEnd(a[4], &Io);
                    if (a[1]) NtSetEvent(HANDLE32(a[1]), NULL);
                }
            }
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;

    if (Event) NtClose(Event);
    RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
    return Status;
}
