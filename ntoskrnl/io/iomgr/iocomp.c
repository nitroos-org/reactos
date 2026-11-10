/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/io/iomgr/iocomp.c
 * PURPOSE:         I/O Wrappers (called Completion Ports) for Kernel Queues
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 *                  Thomas Weidenmueller (w3seek@reactos.org)
 */

/* INCLUDES *****************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

POBJECT_TYPE IoCompletionType;

GENERAL_LOOKASIDE IoCompletionPacketLookaside;

GENERIC_MAPPING IopCompletionMapping =
{
    STANDARD_RIGHTS_READ | IO_COMPLETION_QUERY_STATE,
    STANDARD_RIGHTS_WRITE | IO_COMPLETION_MODIFY_STATE,
    STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE,
    IO_COMPLETION_ALL_ACCESS
};

static const INFORMATION_CLASS_INFO IoCompletionInfoClass[] =
{
     /* IoCompletionBasicInformation */
    IQS_SAME(IO_COMPLETION_BASIC_INFORMATION, ULONG, ICIF_QUERY),
};

/* PRIVATE FUNCTIONS *********************************************************/

NTSTATUS
NTAPI
IopUnloadSafeCompletion(IN PDEVICE_OBJECT DeviceObject,
                        IN PIRP Irp,
                        IN PVOID Context)
{
    NTSTATUS Status;
    PIO_UNLOAD_SAFE_COMPLETION_CONTEXT UnsafeContext = Context;

    /* Reference the device object */
    ObReferenceObject(UnsafeContext->DeviceObject);

    /* Call the completion routine */
    Status= UnsafeContext->CompletionRoutine(DeviceObject,
                                             Irp,
                                             UnsafeContext->Context);

    /* Dereference the device object */
    ObDereferenceObject(UnsafeContext->DeviceObject);

    /* Free our context */
    ExFreePool(UnsafeContext);
    return Status;
}

VOID
NTAPI
IopFreeMiniPacket(PIOP_MINI_COMPLETION_PACKET Packet)
{
    PKPRCB Prcb = KeGetCurrentPrcb();
    PNPAGED_LOOKASIDE_LIST List;

    /* Use the P List */
    List = (PNPAGED_LOOKASIDE_LIST)Prcb->
            PPLookasideList[LookasideCompletionList].P;
    List->L.TotalFrees++;

    /* Check if the Free was within the Depth or not */
    if (ExQueryDepthSList(&List->L.ListHead) >= List->L.Depth)
    {
        /* Let the balancer know */
        List->L.FreeMisses++;

        /* Use the L List */
        List = (PNPAGED_LOOKASIDE_LIST)Prcb->
                PPLookasideList[LookasideCompletionList].L;
        List->L.TotalFrees++;

        /* Check if the Free was within the Depth or not */
        if (ExQueryDepthSList(&List->L.ListHead) >= List->L.Depth)
        {
            /* All lists failed, use the pool */
            List->L.FreeMisses++;
            ExFreePool(Packet);
            return;
        }
    }

    /* The free was within dhe Depth */
    InterlockedPushEntrySList(&List->L.ListHead, (PSLIST_ENTRY)Packet);
}

/* Copies a dequeued completion out and frees the packet or IRP that carried it */
static
VOID
IopUnpackCompletionEntry(IN PLIST_ENTRY ListEntry,
                         OUT PFILE_IO_COMPLETION_INFORMATION Entry)
{
    PIOP_MINI_COMPLETION_PACKET Packet;
    PIRP Irp;

    /* Get the Packet Data */
    Packet = CONTAINING_RECORD(ListEntry,
                               IOP_MINI_COMPLETION_PACKET,
                               ListEntry);

    /* Check if this is piggybacked on an IRP */
    if (Packet->PacketType == IopCompletionPacketIrp)
    {
        /* Get the IRP */
        Irp = CONTAINING_RECORD(ListEntry,
                                IRP,
                                Tail.Overlay.ListEntry);

        /* Save values */
        Entry->KeyContext = Irp->Tail.CompletionKey;
        Entry->ApcContext = Irp->Overlay.AsynchronousParameters.UserApcContext;
        Entry->IoStatusBlock = Irp->IoStatus;

        /* Write the IOSB the completion left to the removal */
        IopWriteDeferredPortIosb(Irp);

        /* Free the IRP */
        IoFreeIrp(Irp);
    }
    else
    {
        /* Save values */
        Entry->KeyContext = Packet->KeyContext;
        Entry->ApcContext = Packet->ApcContext;
        /* All of it: Status fills only part of the union on 64-bit */
        RtlZeroMemory(&Entry->IoStatusBlock, sizeof(Entry->IoStatusBlock));
        Entry->IoStatusBlock.Status = Packet->IoStatus;
        Entry->IoStatusBlock.Information = Packet->IoStatusInformation;

        /* Free the packet */
        IopFreeMiniPacket(Packet);
    }
}

/* Tells a dequeued entry from the wait status KeRemoveQueue(Ex) stores in its place */
static
BOOLEAN
IopIsQueueWaitStatus(IN PLIST_ENTRY ListEntry)
{
    NTSTATUS Status = (NTSTATUS)(ULONG_PTR)ListEntry;

    return ((Status == STATUS_TIMEOUT) ||
            (Status == STATUS_USER_APC) ||
            (Status == STATUS_ALERTED));
}

VOID
NTAPI
IopDeleteIoCompletion(PVOID ObjectBody)
{
    PKQUEUE Queue = ObjectBody;
    PLIST_ENTRY FirstEntry;
    PLIST_ENTRY CurrentEntry;
    PIRP Irp;
    PIOP_MINI_COMPLETION_PACKET Packet;

    /* Rundown the Queue */
    FirstEntry = KeRundownQueue(Queue);
    if (FirstEntry)
    {
        /* Loop the packets */
        CurrentEntry = FirstEntry;
        do
        {
            /* Get the Packet */
            Packet = CONTAINING_RECORD(CurrentEntry,
                                       IOP_MINI_COMPLETION_PACKET,
                                       ListEntry);

            /* Go to next Entry */
            CurrentEntry = CurrentEntry->Flink;

            /* Check if it's part of an IRP, or a separate packet */
            if (Packet->PacketType == IopCompletionPacketIrp)
            {
                /* Get the IRP and free it; nobody removes it, so no IOSB is written */
                Irp = CONTAINING_RECORD(Packet, IRP, Tail.Overlay.ListEntry);
                if (Irp->Tail.Overlay.Thread)
                    ObDereferenceObject(Irp->Tail.Overlay.Thread);
                IoFreeIrp(Irp);
            }
            else
            {
                /* Use common routine */
                IopFreeMiniPacket(Packet);
            }
        } while (FirstEntry != CurrentEntry);
    }
}

/* PUBLIC FUNCTIONS **********************************************************/

/*
 * @implemented
 */
NTSTATUS
NTAPI
IoSetIoCompletion(IN PVOID IoCompletion,
                  IN PVOID KeyContext,
                  IN PVOID ApcContext,
                  IN NTSTATUS IoStatus,
                  IN ULONG_PTR IoStatusInformation,
                  IN BOOLEAN Quota)
{
    PKQUEUE Queue = (PKQUEUE)IoCompletion;
    PNPAGED_LOOKASIDE_LIST List;
    PKPRCB Prcb = KeGetCurrentPrcb();
    PIOP_MINI_COMPLETION_PACKET Packet;

    /* Get the P List */
    List = (PNPAGED_LOOKASIDE_LIST)Prcb->
            PPLookasideList[LookasideCompletionList].P;

    /* Try to allocate the Packet */
    List->L.TotalAllocates++;
    Packet = (PVOID)InterlockedPopEntrySList(&List->L.ListHead);

    /* Check if that failed, use the L list if it did */
    if (!Packet)
    {
        /* Let the balancer know */
        List->L.AllocateMisses++;

        /* Get L List */
        List = (PNPAGED_LOOKASIDE_LIST)Prcb->
                PPLookasideList[LookasideCompletionList].L;

        /* Try to allocate the Packet */
        List->L.TotalAllocates++;
        Packet = (PVOID)InterlockedPopEntrySList(&List->L.ListHead);
    }

    /* Still failed, use pool */
    if (!Packet)
    {
        /* Let the balancer know */
        List->L.AllocateMisses++;

        /* Allocate from Nonpaged Pool */
        Packet = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Packet), IOC_TAG);
    }

    /* Make sure we have one by now... */
    if (Packet)
    {
        /* Set up the Packet */
        Packet->PacketType = IopCompletionPacketMini;
        Packet->KeyContext = KeyContext;
        Packet->ApcContext = ApcContext;
        Packet->IoStatus = IoStatus;
        Packet->IoStatusInformation = IoStatusInformation;

        /* Insert the Queue */
        KeInsertQueue(Queue, &Packet->ListEntry);
    }
    else
    {
        /* Out of memory, fail */
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Return Success */
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
IoSetCompletionRoutineEx(IN PDEVICE_OBJECT DeviceObject,
                         IN PIRP Irp,
                         IN PIO_COMPLETION_ROUTINE CompletionRoutine,
                         IN PVOID Context,
                         IN BOOLEAN InvokeOnSuccess,
                         IN BOOLEAN InvokeOnError,
                         IN BOOLEAN InvokeOnCancel)
{
    PIO_UNLOAD_SAFE_COMPLETION_CONTEXT UnloadContext;

    /* Allocate the context */
    UnloadContext = ExAllocatePoolWithTag(NonPagedPool,
                                          sizeof(*UnloadContext),
                                          'sUoI');
    if (!UnloadContext) return STATUS_INSUFFICIENT_RESOURCES;

    /* Set up the context */
    UnloadContext->DeviceObject = DeviceObject;
    UnloadContext->Context = Context;
    UnloadContext->CompletionRoutine = CompletionRoutine;

    /* Now set the completion routine */
    IoSetCompletionRoutine(Irp,
                           IopUnloadSafeCompletion,
                           UnloadContext,
                           InvokeOnSuccess,
                           InvokeOnError,
                           InvokeOnCancel);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
NtCreateIoCompletion(OUT PHANDLE IoCompletionHandle,
                     IN ACCESS_MASK DesiredAccess,
                     IN POBJECT_ATTRIBUTES ObjectAttributes,
                     IN ULONG NumberOfConcurrentThreads)
{
    PKQUEUE Queue;
    HANDLE hIoCompletionHandle;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    NTSTATUS Status;
    PAGED_CODE();

    /* Check if this was a user-mode call */
    if (PreviousMode != KernelMode)
    {
        /* Wrap probing in SEH */
        _SEH2_TRY
        {
            /* Probe the handle */
            ProbeForWriteHandle(IoCompletionHandle);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Return the exception code */
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }

    /* Create the Object */
    Status = ObCreateObject(PreviousMode,
                            IoCompletionType,
                            ObjectAttributes,
                            PreviousMode,
                            NULL,
                            sizeof(KQUEUE),
                            0,
                            0,
                            (PVOID*)&Queue);
    if (NT_SUCCESS(Status))
    {
        /* Initialize the Queue */
        KeInitializeQueue(Queue, NumberOfConcurrentThreads);

        /* Insert it */
        Status = ObInsertObject(Queue,
                                NULL,
                                DesiredAccess,
                                0,
                                NULL,
                                &hIoCompletionHandle);
        if (NT_SUCCESS(Status))
        {
            /* Protect writing the handle in SEH */
            _SEH2_TRY
            {
                /* Write the handle back */
                *IoCompletionHandle = hIoCompletionHandle;
            }
            _SEH2_EXCEPT(ExSystemExceptionFilter())
            {
                /* Get the exception code */
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;
        }
   }

   /* Return Status */
   return Status;
}

NTSTATUS
NTAPI
NtOpenIoCompletion(OUT PHANDLE IoCompletionHandle,
                   IN ACCESS_MASK DesiredAccess,
                   IN POBJECT_ATTRIBUTES ObjectAttributes)
{
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    HANDLE hIoCompletionHandle;
    NTSTATUS Status;
    PAGED_CODE();

    /* Check if this was a user-mode call */
    if (PreviousMode != KernelMode)
    {
        /* Wrap probing in SEH */
        _SEH2_TRY
        {
            /* Probe the handle */
            ProbeForWriteHandle(IoCompletionHandle);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Return the exception code */
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }

    /* Open the Object */
    Status = ObOpenObjectByName(ObjectAttributes,
                                IoCompletionType,
                                PreviousMode,
                                NULL,
                                DesiredAccess,
                                NULL,
                                &hIoCompletionHandle);
    if (NT_SUCCESS(Status))
    {
        /* Protect writing the handle in SEH */
        _SEH2_TRY
        {
            /* Write the handle back */
            *IoCompletionHandle = hIoCompletionHandle;
        }
        _SEH2_EXCEPT(ExSystemExceptionFilter())
        {
            /* Get the exception code */
            Status = _SEH2_GetExceptionCode();
        }
        _SEH2_END;
    }

    /* Return Status */
    return Status;
}

NTSTATUS
NTAPI
NtQueryIoCompletion(IN  HANDLE IoCompletionHandle,
                    IN  IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass,
                    OUT PVOID IoCompletionInformation,
                    IN  ULONG IoCompletionInformationLength,
                    OUT PULONG ResultLength OPTIONAL)
{
    PKQUEUE Queue;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    NTSTATUS Status;
    PAGED_CODE();

    /* Check buffers and parameters */
    Status = DefaultQueryInfoBufferCheck(IoCompletionInformationClass,
                                         IoCompletionInfoClass,
                                         sizeof(IoCompletionInfoClass) /
                                         sizeof(IoCompletionInfoClass[0]),
                                         ICIF_PROBE_READ_WRITE,
                                         IoCompletionInformation,
                                         IoCompletionInformationLength,
                                         ResultLength,
                                         NULL,
                                         PreviousMode);
    if (!NT_SUCCESS(Status)) return Status;

    /* Get the Object */
    Status = ObReferenceObjectByHandle(IoCompletionHandle,
                                       IO_COMPLETION_QUERY_STATE,
                                       IoCompletionType,
                                       PreviousMode,
                                       (PVOID*)&Queue,
                                       NULL);
    if (NT_SUCCESS(Status))
    {
        /* Protect write in SEH */
        _SEH2_TRY
        {
            /* Return Info */
            ((PIO_COMPLETION_BASIC_INFORMATION)IoCompletionInformation)->
                Depth = KeReadStateQueue(Queue);

            /* Return Result Length if needed */
            if (ResultLength)
            {
                *ResultLength = sizeof(IO_COMPLETION_BASIC_INFORMATION);
            }
        }
        _SEH2_EXCEPT(ExSystemExceptionFilter())
        {
            /* Get exception code */
            Status = _SEH2_GetExceptionCode();
        }
        _SEH2_END;

        /* Dereference the queue */
        ObDereferenceObject(Queue);
    }

    /* Return Status */
    return Status;
}

NTSTATUS
NTAPI
NtRemoveIoCompletion(IN HANDLE IoCompletionHandle,
                     OUT PVOID *KeyContext,
                     OUT PVOID *ApcContext,
                     OUT PIO_STATUS_BLOCK IoStatusBlock,
                     IN PLARGE_INTEGER Timeout OPTIONAL)
{
    LARGE_INTEGER SafeTimeout;
    PKQUEUE Queue;
    PLIST_ENTRY ListEntry;
    FILE_IO_COMPLETION_INFORMATION Entry;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    NTSTATUS Status;
    PAGED_CODE();

    /* Check if the call was from user mode */
    if (PreviousMode != KernelMode)
    {
        /* Protect probes in SEH */
        _SEH2_TRY
        {
            /* Probe the pointers */
            ProbeForWritePointer(KeyContext);
            ProbeForWritePointer(ApcContext);

            /* Probe the I/O Status Block */
            ProbeForWriteIoStatusBlock(IoStatusBlock);
            if (Timeout)
            {
                /* Probe and capture the timeout */
                SafeTimeout = ProbeForReadLargeInteger(Timeout);
                Timeout = &SafeTimeout;
            }
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Return the exception code */
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }

    /* Open the Object */
    Status = ObReferenceObjectByHandle(IoCompletionHandle,
                                       IO_COMPLETION_MODIFY_STATE,
                                       IoCompletionType,
                                       PreviousMode,
                                       (PVOID*)&Queue,
                                       NULL);
    if (NT_SUCCESS(Status))
    {
        /* Remove queue */
        ListEntry = KeRemoveQueue(Queue, PreviousMode, Timeout);

        /* If we got a timeout or user_apc back, return the status */
        if (IopIsQueueWaitStatus(ListEntry))
        {
            /* Set this as the status */
            Status = (NTSTATUS)(ULONG_PTR)ListEntry;
        }
        else
        {
            /* Get the completion and free its packet */
            IopUnpackCompletionEntry(ListEntry, &Entry);

            /* Enter SEH to write back the values */
            _SEH2_TRY
            {
                /* Write the values to caller */
                *ApcContext = Entry.ApcContext;
                *KeyContext = Entry.KeyContext;
                *IoStatusBlock = Entry.IoStatusBlock;
            }
            _SEH2_EXCEPT(ExSystemExceptionFilter())
            {
                /* Get the exception code */
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;
        }

        /* Dereference the Object */
        ObDereferenceObject(Queue);
    }

    /* Return status */
    return Status;
}

/* Upper bound on completions taken per call, so the batch lives on the kernel stack */
#define IOP_MAX_COMPLETION_BATCH 16

/*
 * @implemented
 */
NTSTATUS
NTAPI
NtRemoveIoCompletionEx(IN HANDLE IoCompletionHandle,
                       OUT PFILE_IO_COMPLETION_INFORMATION IoCompletionInformation,
                       IN ULONG Count,
                       OUT PULONG NumEntriesRemoved,
                       IN PLARGE_INTEGER Timeout OPTIONAL,
                       IN BOOLEAN Alertable)
{
    LARGE_INTEGER SafeTimeout;
    PKQUEUE Queue;
    PLIST_ENTRY ListEntries[IOP_MAX_COMPLETION_BATCH];
    FILE_IO_COMPLETION_INFORMATION Entries[IOP_MAX_COMPLETION_BATCH];
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    NTSTATUS Status;
    ULONG Removed, i;
    PAGED_CODE();

    /* There must be room for at least one completion */
    if (Count == 0) return STATUS_INVALID_PARAMETER;

    /* The call returns up to Count completions, take at most one batch */
    Count = min(Count, IOP_MAX_COMPLETION_BATCH);

    /* Check if the call was from user mode */
    if (PreviousMode != KernelMode)
    {
        /* Protect probes in SEH */
        _SEH2_TRY
        {
            /* Probe the part of the output array that can be written */
            ProbeForWrite(IoCompletionInformation,
                          Count * sizeof(FILE_IO_COMPLETION_INFORMATION),
                          TYPE_ALIGNMENT(FILE_IO_COMPLETION_INFORMATION));
            ProbeForWriteUlong(NumEntriesRemoved);
            if (Timeout)
            {
                /* Probe and capture the timeout */
                SafeTimeout = ProbeForReadLargeInteger(Timeout);
                Timeout = &SafeTimeout;
            }
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Return the exception code */
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }

    /* Open the Object */
    Status = ObReferenceObjectByHandle(IoCompletionHandle,
                                       IO_COMPLETION_MODIFY_STATE,
                                       IoCompletionType,
                                       PreviousMode,
                                       (PVOID*)&Queue,
                                       NULL);
    if (!NT_SUCCESS(Status)) return Status;

    /* Wait for the first completion and take whatever else is queued */
    Removed = KeRemoveQueueEx(Queue,
                              PreviousMode,
                              Alertable,
                              Timeout,
                              ListEntries,
                              Count);
    if ((Removed == 1) && IopIsQueueWaitStatus(ListEntries[0]))
    {
        /* The wait ended without a completion */
        Status = (NTSTATUS)(ULONG_PTR)ListEntries[0];
        Removed = 0;
    }
    else
    {
        /* Get the completions and free their packets */
        for (i = 0; i < Removed; i++)
        {
            IopUnpackCompletionEntry(ListEntries[i], &Entries[i]);
        }
        Status = STATUS_SUCCESS;
    }

    /* Dereference the Object */
    ObDereferenceObject(Queue);

    /* Enter SEH to write back the values */
    _SEH2_TRY
    {
        RtlCopyMemory(IoCompletionInformation,
                      Entries,
                      Removed * sizeof(FILE_IO_COMPLETION_INFORMATION));
        *NumEntriesRemoved = Removed;
    }
    _SEH2_EXCEPT(ExSystemExceptionFilter())
    {
        /* Get the exception code */
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;

    /* Return status */
    return Status;
}

NTSTATUS
NTAPI
NtSetIoCompletion(IN HANDLE IoCompletionPortHandle,
                  IN PVOID CompletionKey,
                  IN PVOID CompletionContext,
                  IN NTSTATUS CompletionStatus,
                  IN ULONG CompletionInformation)
{
    NTSTATUS Status;
    PKQUEUE Queue;
    PAGED_CODE();

    /* Get the Object */
    Status = ObReferenceObjectByHandle(IoCompletionPortHandle,
                                       IO_COMPLETION_MODIFY_STATE,
                                       IoCompletionType,
                                       ExGetPreviousMode(),
                                       (PVOID*)&Queue,
                                       NULL);
    if (NT_SUCCESS(Status))
    {
        /* Set the Completion */
        Status = IoSetIoCompletion(Queue,
                                   CompletionKey,
                                   CompletionContext,
                                   CompletionStatus,
                                   CompletionInformation,
                                   TRUE);

        /* Dereference the object */
        ObDereferenceObject(Queue);
    }

    /* Return status */
    return Status;
}

/*
 * @name NtSetIoCompletionEx
 *
 *    Windows 7 and later: NtSetIoCompletion with the storage of the packet taken from an IoCompletionReserve object
 *    (NtAllocateReserveObject type 1). Not measured against Windows yet: a handle of another type is rejected, the
 *    reserve is otherwise only checked, never marked in use, and the packet is allocated as for NtSetIoCompletion.
 */
NTSTATUS
NTAPI
NtSetIoCompletionEx(IN HANDLE IoCompletionPortHandle,
                    IN HANDLE IoCompletionPacketHandle OPTIONAL,
                    IN PVOID CompletionKey,
                    IN PVOID CompletionContext,
                    IN NTSTATUS CompletionStatus,
                    IN ULONG_PTR CompletionInformation)
{
    NTSTATUS Status;
    PVOID Reserve;
    PAGED_CODE();

    if (IoCompletionPacketHandle)
    {
        Status = ObReferenceObjectByHandle(IoCompletionPacketHandle,
                                           0,
                                           ExIoCompletionReserveObjectType,
                                           ExGetPreviousMode(),
                                           &Reserve,
                                           NULL);
        if (!NT_SUCCESS(Status)) return Status;
        ObDereferenceObject(Reserve);
    }

    return NtSetIoCompletion(IoCompletionPortHandle,
                             CompletionKey,
                             CompletionContext,
                             CompletionStatus,
                             (ULONG)CompletionInformation);
}
