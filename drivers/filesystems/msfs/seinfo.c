/*
 * PROJECT:     ReactOS Mailslot FileSystem
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Query and set the security descriptor of a mailslot
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "msfs.h"

#define NDEBUG
#include <debug.h>

NTSTATUS DEFAULTAPI
MsfsQuerySecurity(PDEVICE_OBJECT DeviceObject,
                  PIRP Irp)
{
    PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
    PMSFS_DEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;
    PMSFS_FCB Fcb = IoStack->FileObject->FsContext;
    NTSTATUS Status;

    Irp->IoStatus.Information = 0;

    KeLockMutex(&DeviceExtension->FcbListLock);
    if (Fcb == NULL || Fcb->SecurityDescriptor == NULL)
    {
        Status = STATUS_INVALID_DEVICE_REQUEST;
    }
    else
    {
        Status = SeQuerySecurityDescriptorInfo(&IoStack->Parameters.QuerySecurity.SecurityInformation,
                                               Irp->UserBuffer,
                                               &IoStack->Parameters.QuerySecurity.Length,
                                               &Fcb->SecurityDescriptor);
        if (Status == STATUS_BUFFER_TOO_SMALL)
        {
            Irp->IoStatus.Information = IoStack->Parameters.QuerySecurity.Length;
            Status = STATUS_BUFFER_OVERFLOW;
        }
        else if (NT_SUCCESS(Status))
        {
            Irp->IoStatus.Information = IoStack->Parameters.QuerySecurity.Length;
        }
    }
    KeUnlockMutex(&DeviceExtension->FcbListLock);

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

NTSTATUS DEFAULTAPI
MsfsSetSecurity(PDEVICE_OBJECT DeviceObject,
                PIRP Irp)
{
    PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
    PMSFS_DEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;
    PMSFS_FCB Fcb = IoStack->FileObject->FsContext;
    PSECURITY_DESCRIPTOR Old, Temp, New;
    NTSTATUS Status;

    Irp->IoStatus.Information = 0;

    KeLockMutex(&DeviceExtension->FcbListLock);
    if (Fcb == NULL || Fcb->SecurityDescriptor == NULL)
    {
        Status = STATUS_INVALID_DEVICE_REQUEST;
    }
    else
    {
        Old = Temp = Fcb->SecurityDescriptor;
        Status = SeSetSecurityDescriptorInfo(NULL,
                                             &IoStack->Parameters.SetSecurity.SecurityInformation,
                                             IoStack->Parameters.SetSecurity.SecurityDescriptor,
                                             &Temp,
                                             PagedPool,
                                             IoGetFileObjectGenericMapping());
        if (NT_SUCCESS(Status))
        {
            Status = ObLogSecurityDescriptor(Temp, &New, 1);
            ExFreePoolWithTag(Temp, 0);
            if (NT_SUCCESS(Status))
            {
                Fcb->SecurityDescriptor = New;
                ObDereferenceSecurityDescriptor(Old, 1);
            }
        }
    }
    KeUnlockMutex(&DeviceExtension->FcbListLock);

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}
