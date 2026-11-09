/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/io/iomgr/irq.c
 * PURPOSE:         I/O Wrappers (called Completion Ports) for Kernel Queues
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 */

/* INCLUDES *****************************************************************/

#include <ntoskrnl.h>

#define NDEBUG
#include <debug.h>

/* FUNCTIONS *****************************************************************/

/*
 * @implemented
 */
NTSTATUS
NTAPI
IoConnectInterrupt(OUT PKINTERRUPT *InterruptObject,
                   IN PKSERVICE_ROUTINE ServiceRoutine,
                   IN PVOID ServiceContext,
                   IN PKSPIN_LOCK SpinLock,
                   IN ULONG Vector,
                   IN KIRQL Irql,
                   IN KIRQL SynchronizeIrql,
                   IN KINTERRUPT_MODE InterruptMode,
                   IN BOOLEAN ShareVector,
                   IN KAFFINITY ProcessorEnableMask,
                   IN BOOLEAN FloatingSave)
{
    PKINTERRUPT Interrupt;
    PKINTERRUPT InterruptUsed;
    PIO_INTERRUPT IoInterrupt;
    BOOLEAN FirstRun;
    CCHAR Count = 0;
    KAFFINITY Affinity;

    PAGED_CODE();

    /* Assume failure */
    *InterruptObject = NULL;

    /* Get the affinity */
    Affinity = ProcessorEnableMask & KeActiveProcessors;
    while (Affinity)
    {
        /* Increase count */
        if (Affinity & 1) Count++;
        Affinity >>= 1;
    }

    /* Make sure we have a valid CPU count */
    if (!Count) return STATUS_INVALID_PARAMETER;

    /* Allocate the array of I/O interrupts */
    IoInterrupt = ExAllocatePoolZero(NonPagedPool,
                                     (Count - 1) * sizeof(KINTERRUPT) +
                                     sizeof(IO_INTERRUPT),
                                     TAG_IO_INTERRUPT);
    if (!IoInterrupt) return STATUS_INSUFFICIENT_RESOURCES;

    /* Use the structure's spinlock, if none was provided */
    if (!SpinLock)
    {
        SpinLock = &IoInterrupt->SpinLock;
        KeInitializeSpinLock(SpinLock);
    }

    /* We first start with a built-in interrupt inside the I/O structure */
    Interrupt = (PKINTERRUPT)(IoInterrupt + 1);
    FirstRun = TRUE;

    /* Now create all the interrupts */
    Affinity = ProcessorEnableMask & KeActiveProcessors;
    for (Count = 0; Affinity; Count++, Affinity >>= 1)
    {
        /* Check if it's enabled for this CPU */
        if (!(Affinity & 1))
            continue;

        /* Check which one we will use */
        InterruptUsed = FirstRun ? &IoInterrupt->FirstInterrupt : Interrupt;

        /* Initialize it */
        KeInitializeInterrupt(InterruptUsed,
                              ServiceRoutine,
                              ServiceContext,
                              SpinLock,
                              Vector,
                              Irql,
                              SynchronizeIrql,
                              InterruptMode,
                              ShareVector,
                              Count,
                              FloatingSave);

        /* Connect it */
        if (!KeConnectInterrupt(InterruptUsed))
        {
            /* Check how far we got */
            if (FirstRun)
            {
                /* We failed early so just free this */
                ExFreePoolWithTag(IoInterrupt, TAG_IO_INTERRUPT);
            }
            else
            {
                /* Far enough, so disconnect everything */
                IoDisconnectInterrupt(&IoInterrupt->FirstInterrupt);
            }

            /* And fail */
            return STATUS_INVALID_PARAMETER;
        }

        /* Now we've used up our First Run */
        if (FirstRun)
        {
            FirstRun = FALSE;
        }
        else
        {
            /* Move on to the next one */
            IoInterrupt->Interrupt[(UCHAR)Count] = Interrupt++;
        }
    }

    /* Return success */
    *InterruptObject = &IoInterrupt->FirstInterrupt;
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
VOID
NTAPI
IoDisconnectInterrupt(PKINTERRUPT InterruptObject)
{
    PIO_INTERRUPT IoInterrupt;
    ULONG i;

    PAGED_CODE();

    /* Get the I/O interrupt */
    IoInterrupt = CONTAINING_RECORD(InterruptObject,
                                    IO_INTERRUPT,
                                    FirstInterrupt);

    /* Disconnect the first one */
    KeDisconnectInterrupt(&IoInterrupt->FirstInterrupt);

    /* Now disconnect the others */
    for (i = 0; i < KeNumberProcessors; i++)
    {
        /* Make sure one was registered */
        if (!IoInterrupt->Interrupt[i])
            continue;

        /* Disconnect it */
        KeDisconnectInterrupt(IoInterrupt->Interrupt[i]);
    }

    /* Free the I/O interrupt */
    ExFreePoolWithTag(IoInterrupt, TAG_IO_INTERRUPT);
}

NTSTATUS
IopConnectInterruptExFullySpecific(
    _Inout_ PIO_CONNECT_INTERRUPT_PARAMETERS Parameters)
{
    NTSTATUS Status;

    PAGED_CODE();

    /* Fallback to standard IoConnectInterrupt */
    Status = IoConnectInterrupt(Parameters->FullySpecified.InterruptObject,
                                Parameters->FullySpecified.ServiceRoutine,
                                Parameters->FullySpecified.ServiceContext,
                                Parameters->FullySpecified.SpinLock,
                                Parameters->FullySpecified.Vector,
                                Parameters->FullySpecified.Irql,
                                Parameters->FullySpecified.SynchronizeIrql,
                                Parameters->FullySpecified.InterruptMode,
                                Parameters->FullySpecified.ShareVector,
                                Parameters->FullySpecified.ProcessorEnableMask,
                                Parameters->FullySpecified.FloatingSave);
    if (!NT_SUCCESS(Status))
        DPRINT1("IopConnectInterruptExFullySpecific() failed: 0x%lx\n", Status);
    return Status;
}

/*
 * Scan the translated resources allocated to a device for its interrupts.
 * Returns the number of line-based descriptors in *LineCount, the number of
 * message-signaled ones in *MessageCount and, when there is at least one
 * line-based descriptor, a copy of the first one in *FirstLine.
 */
static
NTSTATUS
IopScanTranslatedInterrupts(
    _In_ PDEVICE_OBJECT PhysicalDeviceObject,
    _Out_ PULONG LineCount,
    _Out_ PULONG MessageCount,
    _Out_ PCM_PARTIAL_RESOURCE_DESCRIPTOR FirstLine)
{
    PDEVICE_NODE DeviceNode;
    PCM_RESOURCE_LIST List;
    PCM_FULL_RESOURCE_DESCRIPTOR Full;
    ULONG i, j;

    PAGED_CODE();

    *LineCount = 0;
    *MessageCount = 0;

    if (!PhysicalDeviceObject || !PhysicalDeviceObject->DeviceObjectExtension)
        return STATUS_INVALID_PARAMETER;

    DeviceNode = IopGetDeviceNode(PhysicalDeviceObject);
    if (!DeviceNode)
        return STATUS_INVALID_PARAMETER;

    /* No resources assigned (not started or none needed): nothing to connect */
    List = DeviceNode->ResourceListTranslated;
    if (!List)
        return STATUS_SUCCESS;

    Full = &List->List[0];
    for (i = 0; i < List->Count; i++)
    {
        PCM_PARTIAL_RESOURCE_DESCRIPTOR Desc = Full->PartialResourceList.PartialDescriptors;

        for (j = 0; j < Full->PartialResourceList.Count; j++)
        {
            if (Desc->Type == CmResourceTypeInterrupt)
            {
                if (Desc->Flags & CM_RESOURCE_INTERRUPT_MESSAGE)
                {
                    (*MessageCount)++;
                }
                else
                {
                    if (*LineCount == 0)
                        *FirstLine = *Desc;
                    (*LineCount)++;
                }
            }

            /* Descriptors are variable-sized only when they carry device data */
            if (Desc->Type == CmResourceTypeDeviceSpecific)
                Desc = (PCM_PARTIAL_RESOURCE_DESCRIPTOR)
                       ((ULONG_PTR)(Desc + 1) + Desc->u.DeviceSpecificData.DataSize);
            else
                Desc++;
        }

        Full = (PCM_FULL_RESOURCE_DESCRIPTOR)Desc;
    }

    return STATUS_SUCCESS;
}

/*
 * Connect the (single) line-based translated interrupt of a device.
 * Windows behaviour not covered here, to be verified on the oracle: devices
 * with more than one line-based interrupt, and the exact status for a device
 * without any (we return STATUS_NOT_FOUND / STATUS_NOT_SUPPORTED).
 */
static
NTSTATUS
IopConnectInterruptLineBased(
    _In_ PDEVICE_OBJECT PhysicalDeviceObject,
    _Out_ PKINTERRUPT *InterruptObject,
    _In_ PKSERVICE_ROUTINE ServiceRoutine,
    _In_ PVOID ServiceContext,
    _In_opt_ PKSPIN_LOCK SpinLock,
    _In_ KIRQL SynchronizeIrql,
    _In_ BOOLEAN FloatingSave)
{
    CM_PARTIAL_RESOURCE_DESCRIPTOR Desc;
    ULONG LineCount, MessageCount;
    KIRQL Irql;
    KAFFINITY Affinity;
    NTSTATUS Status;

    PAGED_CODE();

    *InterruptObject = NULL;

    if (!ServiceRoutine)
        return STATUS_INVALID_PARAMETER;

    Status = IopScanTranslatedInterrupts(PhysicalDeviceObject, &LineCount, &MessageCount, &Desc);
    if (!NT_SUCCESS(Status))
        return Status;

    if (LineCount == 0)
    {
        DPRINT1("IoConnectInterruptEx: device has no line-based interrupt resource (%lu message)\n",
                MessageCount);
        return STATUS_NOT_FOUND;
    }

    if (LineCount > 1)
    {
        /* Multiple line interrupts are not supported yet: refuse rather than guess */
        DPRINT1("IoConnectInterruptEx: %lu line-based interrupts, only one is supported\n", LineCount);
        return STATUS_NOT_SUPPORTED;
    }

    Irql = (KIRQL)Desc.u.Interrupt.Level;
    if (SynchronizeIrql < Irql)
        SynchronizeIrql = Irql;

    Affinity = Desc.u.Interrupt.Affinity;
    if (!Affinity)
        Affinity = (KAFFINITY)-1;

    Status = IoConnectInterrupt(InterruptObject,
                                ServiceRoutine,
                                ServiceContext,
                                SpinLock,
                                Desc.u.Interrupt.Vector,
                                Irql,
                                SynchronizeIrql,
                                (Desc.Flags & CM_RESOURCE_INTERRUPT_LATCHED) ? Latched : LevelSensitive,
                                Desc.ShareDisposition == CmResourceShareShared,
                                Affinity,
                                FloatingSave);
    if (!NT_SUCCESS(Status))
        DPRINT1("IoConnectInterruptEx: line-based IoConnectInterrupt failed 0x%lx\n", Status);
    return Status;
}

static
NTSTATUS
IopConnectInterruptExMessageBased(
    _Inout_ PIO_CONNECT_INTERRUPT_PARAMETERS Parameters)
{
    PDEVICE_OBJECT Pdo = Parameters->MessageBased.PhysicalDeviceObject;
    PKSERVICE_ROUTINE Fallback = Parameters->MessageBased.FallBackServiceRoutine;
    PVOID Context = Parameters->MessageBased.ServiceContext;
    PKSPIN_LOCK SpinLock = Parameters->MessageBased.SpinLock;
    KIRQL SyncIrql = Parameters->MessageBased.SynchronizeIrql;
    BOOLEAN Floating = Parameters->MessageBased.FloatingSave;
    PVOID *Out = Parameters->MessageBased.ConnectionContext.Generic;
    PKINTERRUPT Interrupt;
    CM_PARTIAL_RESOURCE_DESCRIPTOR Desc;
    ULONG LineCount, MessageCount;
    NTSTATUS Status;

    PAGED_CODE();

    if (!Out || !Parameters->MessageBased.MessageServiceRoutine)
        return STATUS_INVALID_PARAMETER;

    *Out = NULL;

    Status = IopScanTranslatedInterrupts(Pdo, &LineCount, &MessageCount, &Desc);
    if (!NT_SUCCESS(Status))
        return Status;

    if (MessageCount != 0)
    {
        /*
         * The device was given message-signaled interrupts. Connecting them
         * (IO_INTERRUPT_MESSAGE_INFO table, per-message vectors) is not
         * implemented: report that instead of claiming a connection.
         */
        DPRINT1("IoConnectInterruptEx: message-based connection is not implemented\n");
        return STATUS_NOT_SUPPORTED;
    }

    /* No message resources: documented fallback to the line-based interrupt */
    if (!Fallback)
    {
        DPRINT1("IoConnectInterruptEx: no message resources and no fallback routine\n");
        return STATUS_NOT_SUPPORTED;
    }

    Status = IopConnectInterruptLineBased(Pdo,
                                          &Interrupt,
                                          Fallback,
                                          Context,
                                          SpinLock,
                                          SyncIrql,
                                          Floating);
    if (!NT_SUCCESS(Status))
        return Status;

    /* ConnectionContext shares its offset with LineBased.InterruptObject */
    Parameters->Version = CONNECT_LINE_BASED;
    *Out = Interrupt;
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
IoConnectInterruptEx(
    _Inout_ PIO_CONNECT_INTERRUPT_PARAMETERS Parameters)
{
    PAGED_CODE();

    switch (Parameters->Version)
    {
        case CONNECT_FULLY_SPECIFIED:
            return IopConnectInterruptExFullySpecific(Parameters);
        case CONNECT_FULLY_SPECIFIED_GROUP:
            //TODO: We don't do anything for the group type
            return IopConnectInterruptExFullySpecific(Parameters);
        case CONNECT_MESSAGE_BASED:
            return IopConnectInterruptExMessageBased(Parameters);
        case CONNECT_LINE_BASED:
            if (!Parameters->LineBased.InterruptObject)
                return STATUS_INVALID_PARAMETER;
            return IopConnectInterruptLineBased(Parameters->LineBased.PhysicalDeviceObject,
                                                Parameters->LineBased.InterruptObject,
                                                Parameters->LineBased.ServiceRoutine,
                                                Parameters->LineBased.ServiceContext,
                                                Parameters->LineBased.SpinLock,
                                                Parameters->LineBased.SynchronizeIrql,
                                                Parameters->LineBased.FloatingSave);
    }

    DPRINT1("IoConnectInterruptEx: unknown Version %lu\n", Parameters->Version);
    return STATUS_INVALID_PARAMETER;
}

VOID
NTAPI
IoDisconnectInterruptEx(
    _In_ PIO_DISCONNECT_INTERRUPT_PARAMETERS Parameters)
{
    PAGED_CODE();

    switch (Parameters->Version)
    {
        case CONNECT_FULLY_SPECIFIED:
        case CONNECT_FULLY_SPECIFIED_GROUP:
        case CONNECT_LINE_BASED:
            /* All three are plain KINTERRUPT connections made by IoConnectInterrupt */
            if (Parameters->ConnectionContext.InterruptObject)
                IoDisconnectInterrupt(Parameters->ConnectionContext.InterruptObject);
            break;

        case CONNECT_MESSAGE_BASED:
            /*
             * IoConnectInterruptEx never hands out a message table yet, so
             * ConnectionContext.InterruptMessageTable (which aliases
             * InterruptObject) cannot be one of ours: do not misread it as a
             * KINTERRUPT.
             */
            DPRINT1("IoDisconnectInterruptEx: message-based disconnect without a connection\n");
            break;

        default:
            DPRINT1("IoDisconnectInterruptEx: unknown Version %lu\n", Parameters->Version);
            break;
    }
}

/* EOF */
