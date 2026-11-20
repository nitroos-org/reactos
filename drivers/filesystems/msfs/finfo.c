/*
 * COPYRIGHT:  See COPYING in the top level directory
 * PROJECT:    ReactOS kernel
 * FILE:       drivers/filesystems/msfs/finfo.c
 * PURPOSE:    Mailslot filesystem
 * PROGRAMMER: Eric Kohl
 */

/* INCLUDES ******************************************************************/

#include "msfs.h"

#define NDEBUG
#include <debug.h>

#undef MAILSLOT_NO_MESSAGE
#undef MAILSLOT_WAIT_FOREVER
#define MAILSLOT_NO_MESSAGE   MAXULONG
#define MAILSLOT_WAIT_FOREVER MAXULONG

/* FUNCTIONS *****************************************************************/

static NTSTATUS
MsfsQueryMailslotInformation(PMSFS_FCB Fcb,
                             PFILE_MAILSLOT_QUERY_INFORMATION Buffer,
                             PULONG BufferLength)
{
    KIRQL oldIrql;

    if (*BufferLength < sizeof(FILE_MAILSLOT_QUERY_INFORMATION))
        return STATUS_BUFFER_OVERFLOW;

    Buffer->MaximumMessageSize = Fcb->MaxMessageSize;
    Buffer->ReadTimeout = Fcb->TimeOut;

    KeAcquireSpinLock(&Fcb->MessageListLock, &oldIrql);
    Buffer->MessagesAvailable = Fcb->MessageCount;
    if (Fcb->MessageCount == 0)
    {
        Buffer->NextMessageSize = MAILSLOT_NO_MESSAGE;
    }
    else
    {
        PMSFS_MESSAGE Message = CONTAINING_RECORD(Fcb->MessageListHead.Flink,
                                                  MSFS_MESSAGE,
                                                  MessageListEntry);
        Buffer->NextMessageSize = Message->Size;
    }
    KeReleaseSpinLock(&Fcb->MessageListLock, oldIrql);

    *BufferLength -= sizeof(FILE_MAILSLOT_QUERY_INFORMATION);

    return STATUS_SUCCESS;
}


static NTSTATUS
MsfsQueryNameInformation(PMSFS_FCB Fcb,
                         PFILE_NAME_INFORMATION Buffer,
                         PULONG BufferLength)
{
    ULONG HeaderLength = FIELD_OFFSET(FILE_NAME_INFORMATION, FileName);
    ULONG CopyLength;

    if (*BufferLength < HeaderLength)
        return STATUS_INFO_LENGTH_MISMATCH;

    /* Report the mailslot name (including the leading backslash) and
     * copy as much of it as fits */
    Buffer->FileNameLength = Fcb->Name.Length;
    CopyLength = min((ULONG)Fcb->Name.Length, *BufferLength - HeaderLength);
    CopyLength &= ~(sizeof(WCHAR) - 1);
    RtlCopyMemory(Buffer->FileName, Fcb->Name.Buffer, CopyLength);

    *BufferLength -= HeaderLength + CopyLength;

    return (CopyLength < Fcb->Name.Length) ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
}


static NTSTATUS
MsfsSetMailslotInformation(PMSFS_FCB Fcb,
                           PFILE_MAILSLOT_SET_INFORMATION Buffer,
                           PULONG BufferLength,
                           KPROCESSOR_MODE RequestorMode)
{
    LARGE_INTEGER ReadTimeout;

    if (*BufferLength < sizeof(FILE_MAILSLOT_SET_INFORMATION))
        return STATUS_BUFFER_OVERFLOW;

    /* ReadTimeout is a caller-supplied pointer embedded in the buffered
     * data: the I/O manager does not copy or probe what it points to. */
    _SEH2_TRY
    {
        if (RequestorMode != KernelMode)
        {
            ProbeForRead(Buffer->ReadTimeout,
                         sizeof(ReadTimeout),
                         sizeof(UCHAR));
        }
        ReadTimeout = *Buffer->ReadTimeout;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        _SEH2_YIELD(return _SEH2_GetExceptionCode());
    }
    _SEH2_END;

    Fcb->TimeOut = ReadTimeout;

    return STATUS_SUCCESS;
}


NTSTATUS DEFAULTAPI
MsfsQueryInformation(PDEVICE_OBJECT DeviceObject,
                     PIRP Irp)
{
    PIO_STACK_LOCATION IoStack;
    FILE_INFORMATION_CLASS FileInformationClass;
    PFILE_OBJECT FileObject;
    PMSFS_FCB Fcb;
    PMSFS_CCB Ccb;
    PVOID SystemBuffer;
    ULONG BufferLength;
    NTSTATUS Status;

    DPRINT("MsfsQueryInformation(DeviceObject %p Irp %p)\n",
           DeviceObject, Irp);

    IoStack = IoGetCurrentIrpStackLocation (Irp);
    FileInformationClass = IoStack->Parameters.QueryFile.FileInformationClass;
    FileObject = IoStack->FileObject;
    Fcb = (PMSFS_FCB)FileObject->FsContext;
    Ccb = (PMSFS_CCB)FileObject->FsContext2;

    DPRINT("Mailslot name: %wZ\n", &Fcb->Name);

    /* the file name can be queried on both the server and the client side */
    if (FileInformationClass == FileNameInformation)
    {
        ULONG NameBufferLength = IoStack->Parameters.QueryFile.Length;

        Status = MsfsQueryNameInformation(Fcb,
                                          Irp->AssociatedIrp.SystemBuffer,
                                          &NameBufferLength);
        Irp->IoStatus.Status = Status;
        if (NT_SUCCESS(Status) || (Status == STATUS_BUFFER_OVERFLOW))
            Irp->IoStatus.Information = IoStack->Parameters.QueryFile.Length - NameBufferLength;
        else
            Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        return Status;
    }

    /* querying information is not permitted on client side */
    if (Fcb->ServerCcb != Ccb)
    {
        Status = STATUS_ACCESS_DENIED;

        Irp->IoStatus.Status = Status;
        Irp->IoStatus.Information = 0;

        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        return Status;
    }

    SystemBuffer = Irp->AssociatedIrp.SystemBuffer;
    BufferLength = IoStack->Parameters.QueryFile.Length;

    switch (FileInformationClass)
    {
    case FileMailslotQueryInformation:
        Status = MsfsQueryMailslotInformation(Fcb,
                                              SystemBuffer,
                                              &BufferLength);
        break;

    default:
        /* an unsupported class is a bad parameter, as on Windows (also the Vista class 48 that now reaches this driver) */
        Status = STATUS_INVALID_PARAMETER;
    }

    Irp->IoStatus.Status = Status;
    if (NT_SUCCESS(Status))
        Irp->IoStatus.Information =
             IoStack->Parameters.QueryFile.Length - BufferLength;
    else
        Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}


NTSTATUS DEFAULTAPI
MsfsSetInformation(PDEVICE_OBJECT DeviceObject,
                   PIRP Irp)
{
    PIO_STACK_LOCATION IoStack;
    FILE_INFORMATION_CLASS FileInformationClass;
    PFILE_OBJECT FileObject;
    PMSFS_FCB Fcb;
    PMSFS_CCB Ccb;
    PVOID SystemBuffer;
    ULONG BufferLength;
    NTSTATUS Status;

    DPRINT("MsfsSetInformation(DeviceObject %p Irp %p)\n", DeviceObject, Irp);

    IoStack = IoGetCurrentIrpStackLocation (Irp);
    FileInformationClass = IoStack->Parameters.QueryFile.FileInformationClass;
    FileObject = IoStack->FileObject;
    Fcb = (PMSFS_FCB)FileObject->FsContext;
    Ccb = (PMSFS_CCB)FileObject->FsContext2;

    DPRINT("Mailslot name: %wZ\n", &Fcb->Name);

    /* setting information is not permitted on client side */
    if (Fcb->ServerCcb != Ccb)
    {
        Status = STATUS_ACCESS_DENIED;

        Irp->IoStatus.Status = Status;
        Irp->IoStatus.Information = 0;

        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        return Status;
    }

    SystemBuffer = Irp->AssociatedIrp.SystemBuffer;
    BufferLength = IoStack->Parameters.QueryFile.Length;

    DPRINT("FileInformationClass %d\n", FileInformationClass);
    DPRINT("SystemBuffer %p\n", SystemBuffer);

    switch (FileInformationClass)
    {
    case FileMailslotSetInformation:
        Status = MsfsSetMailslotInformation(Fcb,
                                            SystemBuffer,
                                            &BufferLength,
                                            Irp->RequestorMode);
        break;

     default:
        Status = STATUS_NOT_IMPLEMENTED;
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

/* EOF */
