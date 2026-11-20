/*
 * PROJECT:     ReactOS Storport Driver
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Storport driver main file
 * COPYRIGHT:   Copyright 2017 Eric Kohl (eric.kohl@reactos.org)
 */

/* INCLUDES *******************************************************************/

#include "precomp.h"
#include "inline.h"
#include "wdm.h"

#define NDEBUG
#include <debug.h>
#include <stdarg.h>


/* GLOBALS ********************************************************************/

ULONG PortNumber = 0;


/* FUNCTIONS ******************************************************************/

static
NTSTATUS
PortAddDriverInitData(
    PDRIVER_OBJECT_EXTENSION DriverExtension,
    PHW_INITIALIZATION_DATA HwInitializationData)
{
    PDRIVER_INIT_DATA InitData;
    ULONG Length;

    DPRINT1("PortAddDriverInitData()\n");

    InitData = ExAllocatePoolWithTag(NonPagedPool,
                                     sizeof(DRIVER_INIT_DATA),
                                     TAG_INIT_DATA);
    if (InitData == NULL)
        return STATUS_NO_MEMORY;

    /* Copy only what both interface revisions share, absent members stay zero */
    Length = min(HwInitializationData->HwInitializationDataSize,
                 sizeof(InitData->HwInitData));

    RtlZeroMemory(&InitData->HwInitData, sizeof(InitData->HwInitData));
    RtlCopyMemory(&InitData->HwInitData,
                  HwInitializationData,
                  Length);

    InsertHeadList(&DriverExtension->InitDataListHead,
                   &InitData->Entry);

    return STATUS_SUCCESS;
}


static
VOID
PortDeleteDriverInitData(
    PDRIVER_OBJECT_EXTENSION DriverExtension)
{
    PDRIVER_INIT_DATA InitData;
    PLIST_ENTRY ListEntry;

    DPRINT1("PortDeleteDriverInitData()\n");

    ListEntry = DriverExtension->InitDataListHead.Flink;
    while (ListEntry != &DriverExtension->InitDataListHead)
    {
        InitData = CONTAINING_RECORD(ListEntry,
                                     DRIVER_INIT_DATA,
                                     Entry);

        RemoveEntryList(&InitData->Entry);

        ExFreePoolWithTag(InitData,
                          TAG_INIT_DATA);

        ListEntry = DriverExtension->InitDataListHead.Flink;
    }
}


PHW_INITIALIZATION_DATA
PortGetDriverInitData(
    PDRIVER_OBJECT_EXTENSION DriverExtension,
    INTERFACE_TYPE InterfaceType)
{
    PDRIVER_INIT_DATA InitData;
    PLIST_ENTRY ListEntry;

    DPRINT1("PortGetDriverInitData()\n");

    ListEntry = DriverExtension->InitDataListHead.Flink;
    while (ListEntry != &DriverExtension->InitDataListHead)
    {
        InitData = CONTAINING_RECORD(ListEntry,
                                     DRIVER_INIT_DATA,
                                     Entry);
        if (InitData->HwInitData.AdapterInterfaceType == InterfaceType)
            return &InitData->HwInitData;

        ListEntry = ListEntry->Flink;
    }

    return NULL;
}


static
VOID
PortAcquireSpinLock(
    PFDO_DEVICE_EXTENSION DeviceExtension,
    STOR_SPINLOCK SpinLock,
    PVOID LockContext,
    PSTOR_LOCK_HANDLE LockHandle)
{
    DPRINT("PortAcquireSpinLock(%p %lu %p %p)\n",
            DeviceExtension, SpinLock, LockContext, LockHandle);

    LockHandle->Lock = SpinLock;

    switch (SpinLock)
    {
        case DpcLock: /* 1, */
            DPRINT("DpcLock\n");
            break;

        case StartIoLock: /* 2 */
            DPRINT("StartIoLock\n");
            break;

        case InterruptLock: /* 3 */
            DPRINT("InterruptLock\n");
            if (DeviceExtension->Interrupt == NULL)
                LockHandle->Context.OldIrql = 0;
            else
                LockHandle->Context.OldIrql = KeAcquireInterruptSpinLock(DeviceExtension->Interrupt);
            break;

        /* FIXME: The Win8 lock types are not implemented yet */
        case ThreadedDpcLock: /* 4 */
        case DpcLevelLock: /* 5 */
            DPRINT1("Unimplemented lock type %lu\n", SpinLock);
            break;

        case InvalidLock:
            NT_ASSERT(FALSE);
            break;
    }
}


static
VOID
PortReleaseSpinLock(
    PFDO_DEVICE_EXTENSION DeviceExtension,
    PSTOR_LOCK_HANDLE LockHandle)
{
    DPRINT("PortReleaseSpinLock(%p %p)\n",
            DeviceExtension, LockHandle);

    switch (LockHandle->Lock)
    {
        case DpcLock: /* 1, */
            DPRINT("DpcLock\n");
            break;

        case StartIoLock: /* 2 */
            DPRINT("StartIoLock\n");
            break;

        case InterruptLock: /* 3 */
            DPRINT("InterruptLock\n");
            if (DeviceExtension->Interrupt != NULL)
                KeReleaseInterruptSpinLock(DeviceExtension->Interrupt,
                                           LockHandle->Context.OldIrql);
            break;

        /* FIXME: The Win8 lock types are not implemented yet */
        case ThreadedDpcLock: /* 4 */
        case DpcLevelLock: /* 5 */
            DPRINT1("Unimplemented lock type %lu\n", LockHandle->Lock);
            break;

        case InvalidLock:
            NT_ASSERT(FALSE);
            break;
    }
}


static
NTSTATUS
NTAPI
PortAddDevice(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT PhysicalDeviceObject)
{
    PDRIVER_OBJECT_EXTENSION DriverObjectExtension;
    PFDO_DEVICE_EXTENSION DeviceExtension = NULL;
    WCHAR NameBuffer[sizeof("\\Device\\RaidPort4294967295")];
    UNICODE_STRING DeviceName;
    PDEVICE_OBJECT Fdo = NULL;
    NTSTATUS Status;

    DPRINT1("PortAddDevice(%p %p)\n",
            DriverObject, PhysicalDeviceObject);

    ASSERT(DriverObject);
    ASSERT(PhysicalDeviceObject);

    Status = RtlStringCbPrintfW(NameBuffer,
                                sizeof(NameBuffer),
                                L"\\Device\\RaidPort%lu",
                                PortNumber);
    ASSERT(NT_SUCCESS(Status));
    RtlInitUnicodeString(&DeviceName, NameBuffer);
    PortNumber++;

    DPRINT1("Creating device: %wZ\n", &DeviceName);

    /* Create the port device */
    Status = IoCreateDevice(DriverObject,
                            sizeof(FDO_DEVICE_EXTENSION),
                            &DeviceName,
                            FILE_DEVICE_CONTROLLER,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &Fdo);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("IoCreateDevice() failed (Status 0x%08lx)\n", Status);
        return Status;
    }

    DPRINT1("Created device: %wZ (%p)\n", &DeviceName, Fdo);

    /* Initialize the device */
    Fdo->Flags |= DO_DIRECT_IO;
    Fdo->Flags |= DO_POWER_PAGABLE;

    /* Initialize the device extension */
    DeviceExtension = (PFDO_DEVICE_EXTENSION)Fdo->DeviceExtension;
    RtlZeroMemory(DeviceExtension, sizeof(FDO_DEVICE_EXTENSION));

    DeviceExtension->ExtensionType = FdoExtension;

    DeviceExtension->Device = Fdo;
    DeviceExtension->PhysicalDevice = PhysicalDeviceObject;

    DeviceExtension->PnpState = dsStopped;

    DeviceExtension->ScsiPortNumber = -1;

    KeInitializeSpinLock(&DeviceExtension->PdoListLock);
    InitializeListHead(&DeviceExtension->PdoListHead);

    KeInitializeDpc(&DeviceExtension->BusChangeDpc, PortFdoBusChangeDpc, DeviceExtension);

    KeInitializeSpinLock(&DeviceExtension->TimerListLock);
    InitializeListHead(&DeviceExtension->TimerListHead);

    /* Initialize simple timer for StorPortNotification */
    KeInitializeTimer(&DeviceExtension->Timer);
    KeInitializeDpc(&DeviceExtension->TimerDpc, SimpleTimerCallbackDpcRoutine, DeviceExtension);

    /* Initialize FDO Device DPC for delayed completion */
    KeInitializeDpc(&Fdo->Dpc, PortCompletionDpc, DeviceExtension);

    /* Initialize completion list header */
    InitializeSListHead(&DeviceExtension->CompletionList);

    /* Request timeouts */
    PortInitializeTimeouts(DeviceExtension);

    /* Initialize the queue for requests waiting on memory */
    PortInitializeStarvedRequestQueue(&DeviceExtension->StarvedRequests);

    /* Initialize FDO flow control structure */
    KeInitializeSpinLock(&DeviceExtension->FlowControl.Lock);
    DeviceExtension->FlowControl.IsBusy = FALSE;
    DeviceExtension->FlowControl.IsPaused = FALSE;
    DeviceExtension->FlowControl.RemainingBusyRequests = 0;
    DeviceExtension->FlowControl.RemainingPauseTime = 0;
    DeviceExtension->FlowControl.OutstandingRequestCount = 0;
    DeviceExtension->FlowControl.KickNeeded = 0;
    InitializeListHead(&DeviceExtension->FlowControl.FdoBlockedRequestsListHead);
    KeInitializeDpc(&DeviceExtension->FlowKickDpc, PortFdoFlowKickDpc, DeviceExtension);

    /* Physically contiguous SRB extensions, sized once the miniport is up */
    InitializeSListHead(&DeviceExtension->SrbExtensionFreeList);

    /* Attach the FDO to the device stack */
    Status = IoAttachDeviceToDeviceStackSafe(Fdo,
                                             PhysicalDeviceObject,
                                             &DeviceExtension->LowerDevice);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("IoAttachDeviceToDeviceStackSafe() failed (Status 0x%08lx)\n", Status);
        IoDeleteDevice(Fdo);
        return Status;
    }

    /* Insert the FDO to the drivers FDO list */
    DriverObjectExtension = IoGetDriverObjectExtension(DriverObject,
                                                       (PVOID)DriverEntry);
    ASSERT(DriverObjectExtension->ExtensionType == DriverExtension);

    DeviceExtension->DriverExtension = DriverObjectExtension;

    StorpInterlockedInsertHeadListCounted(&DriverObjectExtension->AdapterListLock,
                                          &DriverObjectExtension->AdapterListHead,
                                          &DeviceExtension->AdapterListEntry,
                                          &DriverObjectExtension->AdapterCount);

    /* The device has been initialized */
    Fdo->Flags &= ~DO_DEVICE_INITIALIZING;

    DPRINT1("PortAddDevice() done (Status 0x%08lx)\n", Status);

    return Status;
}


static
VOID
NTAPI
PortUnload(
    _In_ PDRIVER_OBJECT DriverObject)
{
    PDRIVER_OBJECT_EXTENSION DriverExtension;

    DPRINT1("PortUnload(%p)\n",
            DriverObject);

    DriverExtension = IoGetDriverObjectExtension(DriverObject,
                                                 (PVOID)DriverEntry);
    if (DriverExtension != NULL)
    {
        PortDeleteDriverInitData(DriverExtension);
    }
}


static
NTSTATUS
NTAPI
PortDispatchCreate(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    DPRINT("PortDispatchCreate(%p %p)\n",
            DeviceObject, Irp);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = FILE_OPENED;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}


static
NTSTATUS
NTAPI
PortDispatchClose(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    DPRINT("PortDispatchClose(%p %p)\n",
            DeviceObject, Irp);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}


static
NTSTATUS
NTAPI
PortDispatchDeviceControl(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    PFDO_DEVICE_EXTENSION DeviceExtension;

    DPRINT("PortDispatchDeviceControl(%p %p)\n",
            DeviceObject, Irp);

    DeviceExtension = (PFDO_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    DPRINT("ExtensionType: %u\n", DeviceExtension->ExtensionType);

    switch (DeviceExtension->ExtensionType)
    {
        case FdoExtension:
            return PortFdoDeviceControl(DeviceObject,
                                        Irp);

        case PdoExtension:
            return PortPdoDeviceControl(DeviceObject,
                                        Irp);

        default:
            Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}


static
NTSTATUS
NTAPI
PortDispatchScsi(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    PFDO_DEVICE_EXTENSION DeviceExtension;

    DPRINT("PortDispatchScsi(%p %p)\n",
            DeviceObject, Irp);

    DeviceExtension = (PFDO_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    DPRINT("ExtensionType: %u\n", DeviceExtension->ExtensionType);

    switch (DeviceExtension->ExtensionType)
    {
        case FdoExtension:
            return PortFdoScsi(DeviceObject,
                               Irp);

        case PdoExtension:
            return PortPdoScsi(DeviceObject,
                               Irp);

        default:
            Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}


static
NTSTATUS
NTAPI
PortDispatchSystemControl(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    DPRINT1("PortDispatchSystemControl(%p %p)\n",
            DeviceObject, Irp);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}


static
NTSTATUS
NTAPI
PortDispatchPnp(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    PFDO_DEVICE_EXTENSION DeviceExtension;

    DPRINT1("PortDispatchPnp(%p %p)\n",
            DeviceObject, Irp);

    DeviceExtension = (PFDO_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    DPRINT("ExtensionType: %u\n", DeviceExtension->ExtensionType);

    switch (DeviceExtension->ExtensionType)
    {
        case FdoExtension:
            return PortFdoPnp(DeviceObject,
                              Irp);

        case PdoExtension:
            return PortPdoPnp(DeviceObject,
                              Irp);

        default:
            Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_UNSUCCESSFUL;
    }
}


static
NTSTATUS
NTAPI
PortDispatchPower(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    DPRINT1("PortDispatchPower(%p %p)\n",
            DeviceObject, Irp);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}


/* PUBLIC FUNCTIONS ***********************************************************/

/*
 * @implemented
 */
NTSTATUS
NTAPI
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    DPRINT1("DriverEntry(%p %p)\n", DriverObject, RegistryPath);
    return STATUS_SUCCESS;
}


/*
 * @implemented
 */
STORPORT_API
PUCHAR
NTAPI
StorPortAllocateRegistryBuffer(
    _In_ PVOID HwDeviceExtension,
    _In_ PULONG Length)
{
    PFDO_DEVICE_EXTENSION FdoExtension;
    PVOID Buffer;

    DPRINT("StorPortAllocateRegistryBuffer()\n");

    if (HwDeviceExtension == NULL || Length == NULL || *Length == 0)
        return NULL;

    FdoExtension = StorpGetMiniportFdo(HwDeviceExtension);

    Buffer = ExAllocatePoolWithTag(NonPagedPool, *Length, TAG_REGISTRY_BUFFER);
    if (Buffer == NULL)
        return NULL;
    RtlZeroMemory(Buffer, *Length);

    /* One buffer at a time for each adapter */
    if (InterlockedCompareExchangePointer(&FdoExtension->RegistryBuffer, Buffer, NULL) != NULL)
    {
        ExFreePoolWithTag(Buffer, TAG_REGISTRY_BUFFER);
        return NULL;
    }

    return Buffer;
}


/*
 * @implemented
 */
STORPORT_API
BOOLEAN
NTAPI
StorPortBusy(
    _In_ PVOID HwDeviceExtension,
    _In_ ULONG RequestsToComplete)
{
    PFDO_DEVICE_EXTENSION FdoExtension;

    DPRINT("StorPortBusy(%p %lu)\n", HwDeviceExtension, RequestsToComplete);

    if (HwDeviceExtension == NULL)
        return FALSE;

    FdoExtension = StorpGetMiniportFdo(HwDeviceExtension);

    /*
     * Not under the flow control lock: a miniport calls this from HwStartIo, which Storport can
     * run with that lock held. The scheduler reads the flags under the lock; a request that slips
     * past a flag being set is harmless, one that is held is issued when the flag clears.
     * Nothing outstanding means nothing to wait for.
     */
    if (RequestsToComplete == 0 || FdoExtension->FlowControl.OutstandingRequestCount == 0)
        return TRUE;

    FdoExtension->FlowControl.RemainingBusyRequests = RequestsToComplete;
    KeMemoryBarrier();
    FdoExtension->FlowControl.IsBusy = TRUE;

    return TRUE;
}


/*
 * @unimplemented
 */
STORPORT_API
VOID
NTAPI
StorPortCompleteRequest(
    _In_ PVOID HwDeviceExtension,
    _In_ UCHAR PathId,
    _In_ UCHAR TargetId,
    _In_ UCHAR Lun,
    _In_ UCHAR SrbStatus)
{
    DPRINT1("StorPortCompleteRequest()\n");
    UNIMPLEMENTED;
}


/*
 * @implemented
 */
STORPORT_API
ULONG
NTAPI
StorPortConvertPhysicalAddressToUlong(
    _In_ STOR_PHYSICAL_ADDRESS Address)
{
    DPRINT("StorPortConvertPhysicalAddressToUlong()\n");

    return Address.u.LowPart;
}


/*
 * @implemented
 */
STORPORT_API
STOR_PHYSICAL_ADDRESS
NTAPI
StorPortConvertUlongToPhysicalAddress(
    _In_ ULONG_PTR UlongAddress)
{
    STOR_PHYSICAL_ADDRESS Address;

    DPRINT("StorPortConvertUlongToPhysicalAddress()\n");

    Address.QuadPart = UlongAddress;
    return Address;
}


/*
 * @implemented
 */
STORPORT_API
VOID
StorPortDebugPrint(
    _In_ ULONG DebugPrintLevel,
    _In_ PCHAR DebugMessage,
    ...)
{
    va_list ap;

    va_start(ap, DebugMessage);
    vDbgPrintExWithPrefix("STORMINI: ",
                          -1,
                          DPFLTR_ERROR_LEVEL,
                          DebugMessage,
                          ap);
    va_end(ap);
}


/*
 * @implemented
 */
STORPORT_API
BOOLEAN
NTAPI
StorPortDeviceBusy(
    _In_ PVOID HwDeviceExtension,
    _In_ UCHAR PathId,
    _In_ UCHAR TargetId,
    _In_ UCHAR Lun,
    _In_ ULONG RequestsToComplete)
{
    /* TODO: Need coverage test */
    PFDO_DEVICE_EXTENSION FdoExtension;
    PPDO_DEVICE_EXTENSION PdoExtension;
    KLOCK_QUEUE_HANDLE LockHandle;

    DPRINT1("StorPortDeviceBusy(%p %d %d %d %d)\n",
            HwDeviceExtension, PathId, TargetId, Lun, RequestsToComplete);

    FdoExtension = StorpGetMiniportFdo(HwDeviceExtension);
    PdoExtension = FdoFindLun(FdoExtension, PathId, TargetId, Lun);

    KeAcquireInStackQueuedSpinLock(&FdoExtension->FlowControl.Lock, &LockHandle);
    NT_ASSERT(!PdoExtension->FlowControl.IsBusy);
    PdoExtension->FlowControl.IsBusy = TRUE;
    PdoExtension->FlowControl.RemainingBusyRequests = RequestsToComplete;
    KeReleaseInStackQueuedSpinLock(&LockHandle);

    return FALSE;
}


/*
 * @unimplemented
 */
STORPORT_API
BOOLEAN
NTAPI
StorPortDeviceReady(
    _In_ PVOID HwDeviceExtension,
    _In_ UCHAR PathId,
    _In_ UCHAR TargetId,
    _In_ UCHAR Lun)
{
    /* TODO: Need coverage test */
    PFDO_DEVICE_EXTENSION FdoExtension;
    PPDO_DEVICE_EXTENSION PdoExtension;
    KLOCK_QUEUE_HANDLE LockHandle;

    DPRINT1("StorPortDeviceReady(%p %d %d %d %d)\n",
            HwDeviceExtension, PathId, TargetId, Lun);

    FdoExtension = StorpGetMiniportFdo(HwDeviceExtension);
    PdoExtension = FdoFindLun(FdoExtension, PathId, TargetId, Lun);

    KeAcquireInStackQueuedSpinLock(&FdoExtension->FlowControl.Lock, &LockHandle);
    NT_ASSERT(!PdoExtension->FlowControl.IsBusy);
    PdoExtension->FlowControl.IsBusy = FALSE;
    KeReleaseInStackQueuedSpinLock(&LockHandle);

    return FALSE;
}


/*
 * @unimplemented
 */
STORPORT_API
ULONG
StorPortExtendedFunction(
    _In_ STORPORT_FUNCTION_CODE FunctionCode,
    _In_ PVOID HwDeviceExtension,
    ...)
{
    va_list va;
    ULONG Status = STOR_STATUS_NOT_IMPLEMENTED;
    PMINIPORT_DEVICE_EXTENSION MiniportExtension = NULL;
    PFDO_DEVICE_EXTENSION DeviceExtension = NULL;
    ULONG AllocatePoolSize;
    ULONG PoolTag;
    PVOID* AllocatedPoolPointer;
    PVOID PoolPointer;

    DPRINT("StorPortExtendedFunction(%d %p ...)\n",
           FunctionCode, HwDeviceExtension);

    va_start(va, HwDeviceExtension);

    switch (FunctionCode) {
        case ExtFunctionAllocatePool:
        {
            /* Allocate a non paged pool for miniport */
            AllocatePoolSize = va_arg(va, ULONG);
            PoolTag = va_arg(va, ULONG);
            AllocatedPoolPointer = va_arg(va, PVOID*);

            if (AllocatedPoolPointer == NULL) {
                Status = STOR_STATUS_INVALID_PARAMETER;
                break;
            }

            /* Documented for <= DISPATCH_LEVEL with STOR_STATUS_INVALID_IRQL above it: a miniport
               that allocates from its interrupt routine or under its interrupt lock (vioscsi saves the
               serial number of the first VPD 0x80 INQUIRY it completes) gets that, not a bugcheck */
            if (KeGetCurrentIrql() > DISPATCH_LEVEL) {
                *AllocatedPoolPointer = NULL;
                Status = STOR_STATUS_INVALID_IRQL;
                break;
            }

            PoolPointer = ExAllocatePoolWithTag(NonPagedPool, AllocatePoolSize, PoolTag);

            if (PoolPointer == NULL) {
                *AllocatedPoolPointer = NULL;
                Status = STOR_STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            *AllocatedPoolPointer = PoolPointer;
            Status = STOR_STATUS_SUCCESS;
            break;
        }

        case ExtFunctionFreePool:
        {
            /* Free a pool allocated with ExtFunctionAllocatePool */
            PoolPointer = va_arg(va, PVOID);

            if (PoolPointer == NULL) {
                Status =  STOR_STATUS_INVALID_PARAMETER;
                break;
            }

            if (KeGetCurrentIrql() > DISPATCH_LEVEL) {
                Status = STOR_STATUS_INVALID_IRQL;
                break;
            }

            ExFreePool(PoolPointer);
            Status = STOR_STATUS_SUCCESS;
            break;
        }

        case ExtFunctionInitializeTimer:
        {
            /* Allocate a timer for an HBA */
            PTIMER_ENTRY TimerEntry;
            PVOID* TimerHandle = va_arg(va, PVOID*);

            if (TimerHandle == NULL) {
                Status = STOR_STATUS_INVALID_PARAMETER;
                break;
            }

            TimerEntry = (PTIMER_ENTRY)ExAllocatePoolWithTag(NonPagedPool,
                                                             sizeof(TIMER_ENTRY),
                                                             TAG_MINIPORT_DATA);
            RtlZeroMemory(TimerEntry, sizeof(TIMER_ENTRY));

            if (TimerEntry == NULL) {
                Status = STOR_STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            /* Initialize internal timer object; Win8.1+ EX_TIMER may be used too if we had it */
            /* FIXME: IRQL > DISPATCH_LEVEL will bugcheck; queue a DPC to do this */
            KeInitializeTimer(&TimerEntry->Timer);

            MiniportExtension = CONTAINING_RECORD(HwDeviceExtension,
                                                  MINIPORT_DEVICE_EXTENSION,
                                                  HwDeviceExtension);
            DeviceExtension = MiniportExtension->Miniport->DeviceExtension;

            /* Insert into timer list and increment counter */
            StorpInterlockedInsertHeadListCounted(&DeviceExtension->TimerListLock,
                                                  &DeviceExtension->TimerListHead,
                                                  &TimerEntry->ListEntry,
                                                  &DeviceExtension->TimerCount);

            /* Return list entry of the timer as its handle */
            *TimerHandle = (PVOID)&TimerEntry->ListEntry;
            Status = STOR_STATUS_SUCCESS;

            break;
        }

        case ExtFunctionRequestTimer:
        {
            /* Schedule a single shot timer event */
            PVOID TimerHandle = va_arg(va, PVOID);
            PHW_TIMER_EX TimerCallback = va_arg(va, PHW_TIMER_EX);
            PVOID CallbackContext = va_arg(va, PVOID);
            ULONGLONG TimerValue = va_arg(va, ULONGLONG);
            ULONGLONG TolerableDelay = va_arg(va, ULONGLONG);
            PTIMER_ENTRY TimerEntry;
            ULONG IsTimerAlreadySet;
            LARGE_INTEGER TimerDueTime;
            NTSTATUS MultiplyResult;

            /* FIXME: I actually don't know how to deal with tolerable delay */
            UNREFERENCED_PARAMETER(TolerableDelay);

            if (HwDeviceExtension == NULL || TimerHandle == NULL || TimerCallback == NULL) {
                Status = STOR_STATUS_INVALID_PARAMETER;
                break;
            }

            TimerEntry = CONTAINING_RECORD(TimerHandle, TIMER_ENTRY, ListEntry);

            /* A timeout of zero cancels a pending timer; a cancelled timer can be set again */
            if (TimerValue == 0ull) {
                if (KeCancelTimer(&TimerEntry->Timer))
                    InterlockedExchange(&TimerEntry->TimerAlreadySet, 0);
                Status = STOR_STATUS_SUCCESS;
                break;
            }

            /* This API uses microseconds, KTIMER operate on 100 nanoseconds, multiply by 10
               to get the correct timer due time */
            MultiplyResult = RtlULongLongMult(TimerValue, 10ull, (PULONGLONG)&TimerDueTime.QuadPart);
            if (!NT_SUCCESS(MultiplyResult) || TimerDueTime.QuadPart < 0) {
                Status = STOR_STATUS_INVALID_PARAMETER;
                break;
            }

            /* Check if timer is already set. If so, don't try to reactivate timer. */
            IsTimerAlreadySet = InterlockedCompareExchange(&TimerEntry->TimerAlreadySet, 1, 0);
            if (IsTimerAlreadySet == 1) {
                Status = STOR_STATUS_BUSY;
                break;
            }

            /* Negative: relative to now. A positive due time is an absolute date */
            TimerDueTime.QuadPart = -TimerDueTime.QuadPart;

            /* Initialize the DPC, context and set timer accordingly */
            TimerEntry->HwDeviceExtension = HwDeviceExtension;
            TimerEntry->TimerCallback = TimerCallback;
            TimerEntry->Context = CallbackContext;
            KeInitializeDpc(&TimerEntry->TimerCallbackDpc,
                            TimerCallbackDpcRoutine,
                            (PVOID)TimerEntry);
            KeSetTimer(&TimerEntry->Timer,
                       TimerDueTime,
                       &TimerEntry->TimerCallbackDpc);
            Status = STOR_STATUS_SUCCESS;
            break;
        }

        case ExtFunctionGetMessageInterruptInformation:
        {
            /* Describe one of the message interrupts connected for the adapter */
            ULONG MessageId = va_arg(va, ULONG);
            PMESSAGE_INTERRUPT_INFORMATION InterruptInfo;
            PIO_INTERRUPT_MESSAGE_INFO_ENTRY Entry;
            PFDO_DEVICE_EXTENSION FdoExtension;

            InterruptInfo = va_arg(va, PMESSAGE_INTERRUPT_INFORMATION);
            if (InterruptInfo == NULL)
            {
                Status = STOR_STATUS_INVALID_PARAMETER;
                break;
            }

            FdoExtension = StorpGetMiniportFdo(HwDeviceExtension);
            if (!FdoExtension->MessageInterrupts)
            {
                Status = STOR_STATUS_UNSUCCESSFUL;
                break;
            }

            if (MessageId >= FdoExtension->MessageInfo->MessageCount)
            {
                Status = STOR_STATUS_INVALID_PARAMETER;
                break;
            }

            Entry = &FdoExtension->MessageInfo->MessageInfo[MessageId];

            InterruptInfo->MessageId = MessageId;
            InterruptInfo->MessageData = Entry->MessageData;
            InterruptInfo->MessageAddress = Entry->MessageAddress;
            InterruptInfo->InterruptVector = Entry->Vector;
            InterruptInfo->InterruptLevel = FdoExtension->MessageInfo->UnifiedIrql;
            InterruptInfo->InterruptMode = Entry->Mode;

            Status = STOR_STATUS_SUCCESS;
            break;
        }

        case ExtFunctionGetSystemAddress:
        {
            /* Hand back a kernel address the miniport can touch the buffer through */
            PSCSI_REQUEST_BLOCK Srb = va_arg(va, PSCSI_REQUEST_BLOCK);
            PVOID *SystemAddress = va_arg(va, PVOID *);
            PQUEUED_REQUEST_REFERENCE RequestReference;
            PVOID Address;

            if (Srb == NULL || SystemAddress == NULL)
            {
                Status = STOR_STATUS_INVALID_PARAMETER;
                break;
            }

            *SystemAddress = NULL;

            RequestReference = StorpRequestReference(Srb);
            if (RequestReference->Irp == NULL || RequestReference->Irp->MdlAddress == NULL)
            {
                /* No buffer was described, so whatever the request carries is it */
                *SystemAddress = StorpSrbDataBuffer(Srb);
                Status = (*SystemAddress != NULL) ? STOR_STATUS_SUCCESS : STOR_STATUS_INVALID_PARAMETER;
                break;
            }

            Address = MmGetSystemAddressForMdlSafe(RequestReference->Irp->MdlAddress,
                                                   NormalPagePriority);
            if (Address == NULL)
            {
                Status = STOR_STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            *SystemAddress = Address;
            Status = STOR_STATUS_SUCCESS;
            break;
        }

        case ExtFunctionGetOriginalMdl:
        {
            /* The MDL the IO manager built for the request, if there is one */
            PSCSI_REQUEST_BLOCK Srb = va_arg(va, PSCSI_REQUEST_BLOCK);
            PMDL *Mdl = va_arg(va, PMDL *);
            PQUEUED_REQUEST_REFERENCE RequestReference;

            if (Srb == NULL || Mdl == NULL)
            {
                Status = STOR_STATUS_INVALID_PARAMETER;
                break;
            }

            *Mdl = NULL;

            RequestReference = StorpRequestReference(Srb);
            if (RequestReference->Irp == NULL || RequestReference->Irp->MdlAddress == NULL)
            {
                Status = STOR_STATUS_INVALID_PARAMETER;
                break;
            }

            *Mdl = RequestReference->Irp->MdlAddress;
            Status = STOR_STATUS_SUCCESS;
            break;
        }

        case ExtFunctionGetDeviceObjects:
        {
            /* Where the miniport sits in the device stack */
            PDEVICE_OBJECT *AdapterDeviceObject = va_arg(va, PDEVICE_OBJECT *);
            PDEVICE_OBJECT *PhysicalDeviceObject = va_arg(va, PDEVICE_OBJECT *);
            PDEVICE_OBJECT *LowerDeviceObject = va_arg(va, PDEVICE_OBJECT *);

            DeviceExtension = StorpGetMiniportFdo(HwDeviceExtension);

            if (AdapterDeviceObject != NULL)
                *AdapterDeviceObject = DeviceExtension->Device;

            if (PhysicalDeviceObject != NULL)
                *PhysicalDeviceObject = DeviceExtension->PhysicalDevice;

            if (LowerDeviceObject != NULL)
                *LowerDeviceObject = DeviceExtension->LowerDevice;

            Status = STOR_STATUS_SUCCESS;
            break;
        }

        case ExtFunctionInitializePerformanceOptimizations:
        {
            /* Completions are not spread over processors yet, accept and ignore */
            Status = STOR_STATUS_SUCCESS;
            break;
        }

        case ExtFunctionQueryPerformanceCounter:
        {
            PLARGE_INTEGER PerformanceFrequency = va_arg(va, PLARGE_INTEGER);
            PLARGE_INTEGER PerformanceCounter = va_arg(va, PLARGE_INTEGER);

            if (PerformanceCounter == NULL)
            {
                Status = STOR_STATUS_INVALID_PARAMETER;
                break;
            }

            *PerformanceCounter = KeQueryPerformanceCounter(PerformanceFrequency);
            Status = STOR_STATUS_SUCCESS;
            break;
        }

        case ExtFunctionGetStartIoPerformanceParameters:
        {
            PSCSI_REQUEST_BLOCK Srb = va_arg(va, PSCSI_REQUEST_BLOCK);
            PSTARTIO_PERFORMANCE_PARAMETERS Parameters = va_arg(va, PSTARTIO_PERFORMANCE_PARAMETERS);

            if (HwDeviceExtension == NULL || Srb == NULL || Parameters == NULL ||
                Parameters->Size < sizeof(STARTIO_PERFORMANCE_PARAMETERS))
            {
                Status = STOR_STATUS_INVALID_PARAMETER;
                break;
            }

            /* No completion steering: every request is on the first channel and message */
            Parameters->Version = STOR_PERF_VERSION;
            Parameters->MessageNumber = 0;
            Parameters->ChannelNumber = 0;
            Status = STOR_STATUS_SUCCESS;
            break;
        }

        case ExtFunctionLogSystemEvent:
        {
            PSTOR_LOG_EVENT_DETAILS LogDetails = va_arg(va, PSTOR_LOG_EVENT_DETAILS);
            PULONG MaximumSize = va_arg(va, PULONG);

            UNREFERENCED_PARAMETER(MaximumSize);

            if (HwDeviceExtension == NULL || LogDetails == NULL)
            {
                Status = STOR_STATUS_INVALID_PARAMETER;
                break;
            }

            if (KeGetCurrentIrql() > DISPATCH_LEVEL)
            {
                Status = STOR_STATUS_INVALID_IRQL;
                break;
            }

            /* Only the three high bytes of the revision are compared */
            if ((LogDetails->InterfaceRevision >> 8) != (STOR_CURRENT_LOG_INTERFACE_REVISION >> 8))
            {
                LogDetails->InterfaceRevision = STOR_CURRENT_LOG_INTERFACE_REVISION;
                Status = STOR_STATUS_UNSUPPORTED_VERSION;
                break;
            }

            /* There is no system event log entry yet: the code is visible on the debug port only */
            DPRINT("StorPortLogSystemEvent: %u:%u:%u code 0x%lx\n",
                   LogDetails->PathId, LogDetails->TargetId, LogDetails->LunId, LogDetails->ErrorCode);
            Status = STOR_STATUS_SUCCESS;
            break;
        }

        case ExtFunctionSetUnitAttributes:
        {
            PSTOR_ADDRESS Address = va_arg(va, PSTOR_ADDRESS);
            STOR_UNIT_ATTRIBUTES Attributes = va_arg(va, STOR_UNIT_ATTRIBUTES);
            PSTOR_ADDR_BTL8 Btl8 = (PSTOR_ADDR_BTL8)Address;
            PPDO_DEVICE_EXTENSION PdoExtension;

            if (HwDeviceExtension == NULL || Address == NULL ||
                Address->Type != STOR_ADDRESS_TYPE_BTL8 ||
                Address->AddressLength != STOR_ADDR_BTL8_ADDRESS_LENGTH ||
                Attributes.Reserved != 0)
            {
                Status = STOR_STATUS_INVALID_PARAMETER;
                break;
            }

            PdoExtension = FdoFindLunAboveDispatch(StorpGetMiniportFdo(HwDeviceExtension),
                                                   Btl8->Path, Btl8->Target, Btl8->Lun);
            if (PdoExtension == NULL)
            {
                Status = STOR_STATUS_INVALID_PARAMETER;
                break;
            }

            PdoExtension->UnitAttributes = Attributes;
            Status = STOR_STATUS_SUCCESS;
            break;
        }

        case ExtFunctionAcquireMSISpinLock:
        {
            ULONG MessageId = va_arg(va, ULONG);
            PULONG OldIrql = va_arg(va, PULONG);
            PFDO_DEVICE_EXTENSION FdoExtension;

            if (HwDeviceExtension == NULL || OldIrql == NULL)
            {
                Status = STOR_STATUS_INVALID_PARAMETER;
                break;
            }

            FdoExtension = StorpGetMiniportFdo(HwDeviceExtension);
            if (!FdoExtension->MessageInterrupts || MessageId >= FdoExtension->MessageInfo->MessageCount)
            {
                Status = STOR_STATUS_INVALID_PARAMETER;
                break;
            }

            *OldIrql = KeAcquireInterruptSpinLock(FdoExtension->MessageInfo->MessageInfo[MessageId].InterruptObject);
            Status = STOR_STATUS_SUCCESS;
            break;
        }

        case ExtFunctionReleaseMSISpinLock:
        {
            ULONG MessageId = va_arg(va, ULONG);
            ULONG OldIrql = va_arg(va, ULONG);
            PFDO_DEVICE_EXTENSION FdoExtension;

            if (HwDeviceExtension == NULL)
            {
                Status = STOR_STATUS_INVALID_PARAMETER;
                break;
            }

            FdoExtension = StorpGetMiniportFdo(HwDeviceExtension);
            if (!FdoExtension->MessageInterrupts || MessageId >= FdoExtension->MessageInfo->MessageCount)
            {
                Status = STOR_STATUS_INVALID_PARAMETER;
                break;
            }

            KeReleaseInterruptSpinLock(FdoExtension->MessageInfo->MessageInfo[MessageId].InterruptObject,
                                       (KIRQL)OldIrql);
            Status = STOR_STATUS_SUCCESS;
            break;
        }

        default:
        {
            UNIMPLEMENTED;
            // __debugbreak();
        }
    }

    va_end(va);

    return Status;
}


/*
 * @implemented
 */
STORPORT_API
VOID
NTAPI
StorPortFreeDeviceBase(
    _In_ PVOID HwDeviceExtension,
    _In_ PVOID MappedAddress)
{
    DPRINT1("StorPortFreeDeviceBase(%p %p)\n",
            HwDeviceExtension, MappedAddress);
}


/*
 * @implemented
 */
STORPORT_API
VOID
NTAPI
StorPortFreeRegistryBuffer(
    _In_ PVOID HwDeviceExtension,
    _In_ PUCHAR Buffer)
{
    PFDO_DEVICE_EXTENSION FdoExtension;

    DPRINT("StorPortFreeRegistryBuffer()\n");

    if (HwDeviceExtension == NULL || Buffer == NULL)
        return;

    FdoExtension = StorpGetMiniportFdo(HwDeviceExtension);

    /* Only the buffer this adapter holds is freed */
    if (InterlockedCompareExchangePointer(&FdoExtension->RegistryBuffer, NULL, Buffer) == Buffer)
        ExFreePoolWithTag(Buffer, TAG_REGISTRY_BUFFER);
}


/*
 * @implemented
 */
STORPORT_API
ULONG
NTAPI
StorPortGetBusData(
    _In_ PVOID DeviceExtension,
    _In_ ULONG BusDataType,
    _In_ ULONG SystemIoBusNumber,
    _In_ ULONG SlotNumber,
    _Out_ _When_(Length != 0, _Out_writes_bytes_(Length)) PVOID Buffer,
    _In_ ULONG Length)
{
    PMINIPORT_DEVICE_EXTENSION MiniportExtension;
    PBUS_INTERFACE_STANDARD Interface;
    ULONG ReturnLength;

    DPRINT1("StorPortGetBusData(%p %lu %lu %lu %p %lu)\n",
            DeviceExtension, BusDataType, SystemIoBusNumber, SlotNumber, Buffer, Length);

    /* Get the miniport extension */
    MiniportExtension = CONTAINING_RECORD(DeviceExtension,
                                          MINIPORT_DEVICE_EXTENSION,
                                          HwDeviceExtension);
    DPRINT1("DeviceExtension %p  MiniportExtension %p\n",
            DeviceExtension, MiniportExtension);

    Interface = &MiniportExtension->Miniport->DeviceExtension->BusInterface;

    ReturnLength = Interface->GetBusData(Interface->Context,
                                         BusDataType,
                                         Buffer,
                                         0,
                                         Length);
    DPRINT1("ReturnLength: %lu\n", ReturnLength);

    return ReturnLength;
}


/*
 * @implemented
 */
STORPORT_API
PVOID
NTAPI
StorPortGetDeviceBase(
    _In_ PVOID HwDeviceExtension,
    _In_ INTERFACE_TYPE BusType,
    _In_ ULONG SystemIoBusNumber,
    _In_ STOR_PHYSICAL_ADDRESS IoAddress,
    _In_ ULONG NumberOfBytes,
    _In_ BOOLEAN InIoSpace)
{
    PMINIPORT_DEVICE_EXTENSION MiniportExtension;
    PHYSICAL_ADDRESS TranslatedAddress;
    PVOID MappedAddress;
    NTSTATUS Status;

    DPRINT1("StorPortGetDeviceBase(%p %lu %lu 0x%I64x %lu %u)\n",
            HwDeviceExtension, BusType, SystemIoBusNumber, IoAddress.QuadPart, NumberOfBytes, InIoSpace);

    /* Get the miniport extension */
    MiniportExtension = CONTAINING_RECORD(HwDeviceExtension,
                                          MINIPORT_DEVICE_EXTENSION,
                                          HwDeviceExtension);
    DPRINT1("HwDeviceExtension %p  MiniportExtension %p\n",
            HwDeviceExtension, MiniportExtension);

    if (!TranslateResourceListAddress(MiniportExtension->Miniport->DeviceExtension,
                                      BusType,
                                      SystemIoBusNumber,
                                      IoAddress,
                                      NumberOfBytes,
                                      InIoSpace,
                                      &TranslatedAddress))
    {
        DPRINT1("Checkpoint!\n");
        return NULL;
    }

    DPRINT1("Translated Address: 0x%I64x\n", TranslatedAddress.QuadPart);

    /* In I/O space */
    if (InIoSpace)
    {
        DPRINT1("Translated Address: %p\n", (PVOID)(ULONG_PTR)TranslatedAddress.QuadPart);
        return (PVOID)(ULONG_PTR)TranslatedAddress.QuadPart;
    }

    /* In memory space */
    MappedAddress = MmMapIoSpace(TranslatedAddress,
                                 NumberOfBytes,
                                 FALSE);
    DPRINT1("Mapped Address: %p\n", MappedAddress);

    Status = AllocateAddressMapping(&MiniportExtension->Miniport->DeviceExtension->MappedAddressList,
                                    IoAddress,
                                    MappedAddress,
                                    NumberOfBytes,
                                    SystemIoBusNumber);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Checkpoint!\n");
        MappedAddress = NULL;
    }

    DPRINT1("Mapped Address: %p\n", MappedAddress);
    return MappedAddress;
}


/*
 * @implemented
 */
STORPORT_API
PVOID
NTAPI
StorPortGetLogicalUnit(
    _In_ PVOID HwDeviceExtension,
    _In_ UCHAR PathId,
    _In_ UCHAR TargetId,
    _In_ UCHAR Lun)
{
    PMINIPORT_DEVICE_EXTENSION MiniportExtension;
    PFDO_DEVICE_EXTENSION FdoExtension;
    PPDO_DEVICE_EXTENSION PdoExtension;

    DPRINT("StorPortGetLogicalUnit(%p %u %u %u)\n",
           HwDeviceExtension, PathId, TargetId, Lun);

    if (HwDeviceExtension == NULL)
        return NULL;

    MiniportExtension = CONTAINING_RECORD(HwDeviceExtension,
                                          MINIPORT_DEVICE_EXTENSION,
                                          HwDeviceExtension);
    FdoExtension = MiniportExtension->Miniport->DeviceExtension;

    /* Miniports call this from HwInterrupt too, where the list lock cannot be taken */
    if (KeGetCurrentIrql() > DISPATCH_LEVEL)
        PdoExtension = FdoFindLunAboveDispatch(FdoExtension, PathId, TargetId, Lun);
    else
        PdoExtension = FdoFindLun(FdoExtension, PathId, TargetId, Lun);

    /* A unit nothing ever found has nothing kept about it */
    if (PdoExtension == NULL)
        return NULL;

    return PdoExtension->LunExtension;
}


/*
 * @implemented
 */
STORPORT_API
STOR_PHYSICAL_ADDRESS
NTAPI
StorPortGetPhysicalAddress(
    _In_ PVOID HwDeviceExtension,
    _In_opt_ PSCSI_REQUEST_BLOCK Srb,
    _In_ PVOID VirtualAddress,
    _Out_ ULONG *Length)
{
    PMINIPORT_DEVICE_EXTENSION MiniportExtension;
    PFDO_DEVICE_EXTENSION DeviceExtension;
    STOR_PHYSICAL_ADDRESS PhysicalAddress;
    ULONG_PTR Offset;

    DPRINT("StorPortGetPhysicalAddress(%p %p %p %p)\n",
            HwDeviceExtension, Srb, VirtualAddress, Length);

    /* Get the miniport extension */
    MiniportExtension = CONTAINING_RECORD(HwDeviceExtension,
                                          MINIPORT_DEVICE_EXTENSION,
                                          HwDeviceExtension);
    DPRINT("HwDeviceExtension %p  MiniportExtension %p\n",
            HwDeviceExtension, MiniportExtension);

    DeviceExtension = MiniportExtension->Miniport->DeviceExtension;

    /* Inside of the uncached extension? */
    if (((ULONG_PTR)VirtualAddress >= (ULONG_PTR)DeviceExtension->UncachedExtensionVirtualBase) &&
        ((ULONG_PTR)VirtualAddress < (ULONG_PTR)DeviceExtension->UncachedExtensionVirtualBase + DeviceExtension->UncachedExtensionSize))
    {
        Offset = (ULONG_PTR)VirtualAddress - (ULONG_PTR)DeviceExtension->UncachedExtensionVirtualBase;

        PhysicalAddress.QuadPart = DeviceExtension->UncachedExtensionPhysicalBase.QuadPart + Offset;
        *Length = DeviceExtension->UncachedExtensionSize - Offset;

        return PhysicalAddress;
    }

    PhysicalAddress = MmGetPhysicalAddress(VirtualAddress);
    if (PhysicalAddress.QuadPart == 0)
    {
        *Length = 0;
        return PhysicalAddress;
    }

    /* Outside the uncached extension only the rest of this page is known contiguous */
    *Length = PAGE_SIZE - BYTE_OFFSET(VirtualAddress);

    return PhysicalAddress;
}


/*
 * @implemented
 */
STORPORT_API
PSTOR_SCATTER_GATHER_LIST
NTAPI
StorPortGetScatterGatherList(
    _In_ PVOID HwDeviceExtension,
    _In_ PSCSI_REQUEST_BLOCK Srb)
{
    UNREFERENCED_PARAMETER(HwDeviceExtension);
    PQUEUED_REQUEST_REFERENCE RequestReference;

    DPRINT("StorPortGetScatterGatherList(%p %p)\n", HwDeviceExtension, Srb);
    RequestReference = StorpRequestReference(Srb);

    return RequestReference->ScatterGatherList;
}


/*
 * @implemented
 */
STORPORT_API
PSCSI_REQUEST_BLOCK
NTAPI
StorPortGetSrb(
    _In_ PVOID DeviceExtension,
    _In_ UCHAR PathId,
    _In_ UCHAR TargetId,
    _In_ UCHAR Lun,
    _In_ LONG QueueTag)
{
    DPRINT("StorPortGetSrb()\n");
    return NULL;
}


/*
 * @implemented
 */
STORPORT_API
PVOID
NTAPI
StorPortGetUncachedExtension(
    _In_ PVOID HwDeviceExtension,
    _In_ PPORT_CONFIGURATION_INFORMATION ConfigInfo,
    _In_ ULONG NumberOfBytes)
{
    PMINIPORT_DEVICE_EXTENSION MiniportExtension;
    PFDO_DEVICE_EXTENSION DeviceExtension;
    PHYSICAL_ADDRESS LowestAddress, HighestAddress, Alignment;
    DEVICE_DESCRIPTION DeviceDescription;
    ULONG NumberOfMapRegisters;

    DPRINT1("StorPortGetUncachedExtension(%p %p %lu)\n",
            HwDeviceExtension, ConfigInfo, NumberOfBytes);

    /* Get the miniport extension */
    MiniportExtension = CONTAINING_RECORD(HwDeviceExtension,
                                          MINIPORT_DEVICE_EXTENSION,
                                          HwDeviceExtension);
    DPRINT1("HwDeviceExtension %p  MiniportExtension %p\n",
            HwDeviceExtension, MiniportExtension);

    DeviceExtension = MiniportExtension->Miniport->DeviceExtension;

    /* Return the uncached extension base address if we already have one */
    if (DeviceExtension->UncachedExtensionVirtualBase != NULL)
        return DeviceExtension->UncachedExtensionVirtualBase;

    // FIXME: Set DMA stuff here?
    RtlZeroMemory(&DeviceDescription, sizeof(DeviceDescription));
    DeviceDescription.Version = DEVICE_DESCRIPTION_VERSION;
    DeviceDescription.Master = ConfigInfo->Master;
    DeviceDescription.ScatterGather = ConfigInfo->ScatterGather;
    DeviceDescription.DemandMode = ConfigInfo->DemandMode;
    DeviceDescription.Dma32BitAddresses = ConfigInfo->Dma32BitAddresses;
    /* Any flag but SCSI_DMA64_SYSTEM_SUPPORTED (which Storport sets itself) is the miniport saying it handles 64-bit
       addresses: MINIPORT_SUPPORTED, or one of the FULL64BIT and 4 GB region values */
    DeviceDescription.Dma64BitAddresses = (ConfigInfo->Dma64BitAddresses & ~SCSI_DMA64_SYSTEM_SUPPORTED) ? TRUE : FALSE;
    DeviceDescription.BusNumber = ConfigInfo->SystemIoBusNumber;
    DeviceDescription.DmaChannel = ConfigInfo->DmaChannel;
    DeviceDescription.InterfaceType = ConfigInfo->AdapterInterfaceType;
    DeviceDescription.DmaWidth = ConfigInfo->DmaWidth;
    DeviceDescription.DmaSpeed = ConfigInfo->DmaSpeed;
    DeviceDescription.MaximumLength = ConfigInfo->MaximumTransferLength;
    DeviceDescription.DmaPort = ConfigInfo->DmaPort;

    DeviceExtension->DmaAdapter =
        IoGetDmaAdapter(DeviceExtension->PhysicalDevice, &DeviceDescription, &NumberOfMapRegisters);

    NT_ASSERT(DeviceExtension->DmaAdapter);
    /* Fewer map registers than pages of the longest transfer: the HAL capped them (a device
       that needs map registers), and they limit the transfer length (PortFdoStartMiniport) */
    DeviceExtension->NumberOfMapRegisters = 0;
    if (DeviceExtension->DmaAdapter != NULL &&
        NumberOfMapRegisters < BYTES_TO_PAGES(DeviceDescription.MaximumLength & MAXLONG) + 1)
    {
        DeviceExtension->NumberOfMapRegisters = NumberOfMapRegisters;
    }

    /* FIXME: AdapterInterfaceType is exposed here and I think it's convenient to initialize
       HwInitData in FDO extension right here. Needs review. */
    DeviceExtension->HwInitData = PortGetDriverInitData(DeviceExtension->DriverExtension,
        DeviceDescription.InterfaceType);
    NT_ASSERT(DeviceExtension->HwInitData);

    /* Allocate the uncached extension */
    Alignment.QuadPart = 0;
    LowestAddress.QuadPart = 0;
    HighestAddress.QuadPart = 0x00000000FFFFFFFF;
    DeviceExtension->UncachedExtensionVirtualBase = MmAllocateContiguousMemorySpecifyCache(NumberOfBytes,
                                                                                           LowestAddress,
                                                                                           HighestAddress,
                                                                                           Alignment,
                                                                                           MmCached);
    if (DeviceExtension->UncachedExtensionVirtualBase == NULL)
        return NULL;

    DeviceExtension->UncachedExtensionPhysicalBase = MmGetPhysicalAddress(DeviceExtension->UncachedExtensionVirtualBase);
    DeviceExtension->UncachedExtensionSize = NumberOfBytes;

    return DeviceExtension->UncachedExtensionVirtualBase;
}


/*
 * @unimplemented
 */
STORPORT_API
PVOID
NTAPI
StorPortGetVirtualAddress(
    _In_ PVOID HwDeviceExtension,
    _In_ STOR_PHYSICAL_ADDRESS PhysicalAddress)
{
    DPRINT1("StorPortGetVirtualAddress(%p %I64x)\n",
            HwDeviceExtension, PhysicalAddress.QuadPart);
    UNIMPLEMENTED;
    return NULL;
}


/*
 * @implemented
 */
STORPORT_API
ULONG
NTAPI
StorPortInitialize(
    _In_ PVOID Argument1,
    _In_ PVOID Argument2,
    _In_ struct _HW_INITIALIZATION_DATA *HwInitializationData,
    _In_opt_ PVOID HwContext)
{
    PDRIVER_OBJECT DriverObject = (PDRIVER_OBJECT)Argument1;
    PUNICODE_STRING RegistryPath = (PUNICODE_STRING)Argument2;
    PDRIVER_OBJECT_EXTENSION DriverObjectExtension;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT1("StorPortInitialize(%p %p %p %p)\n",
            Argument1, Argument2, HwInitializationData, HwContext);

    DPRINT1("HwInitializationDataSize: %lu\n", HwInitializationData->HwInitializationDataSize);
    DPRINT1("AdapterInterfaceType: %u\n", HwInitializationData->AdapterInterfaceType);
    DPRINT1("HwInitialize: %p\n", HwInitializationData->HwInitialize);
    DPRINT1("HwStartIo: %p\n", HwInitializationData->HwStartIo);
    DPRINT1("HwInterrupt: %p\n", HwInitializationData->HwInterrupt);
    DPRINT1("HwFindAdapter: %p\n", HwInitializationData->HwFindAdapter);
    DPRINT1("HwResetBus: %p\n", HwInitializationData->HwResetBus);
    DPRINT1("HwDmaStarted: %p\n", HwInitializationData->HwDmaStarted);
    DPRINT1("HwAdapterState: %p\n", HwInitializationData->HwAdapterState);
    DPRINT1("DeviceExtensionSize: %lu\n", HwInitializationData->DeviceExtensionSize);
    DPRINT1("SpecificLuExtensionSize: %lu\n", HwInitializationData->SpecificLuExtensionSize);
    DPRINT1("SrbExtensionSize: %lu\n", HwInitializationData->SrbExtensionSize);
    DPRINT1("NumberOfAccessRanges: %lu\n", HwInitializationData->NumberOfAccessRanges);

    /* Check parameters */
    if ((DriverObject == NULL) ||
        (RegistryPath == NULL) ||
        (HwInitializationData == NULL))
    {
        DPRINT1("Invalid parameter!\n");
        return STATUS_INVALID_PARAMETER;
    }

    /* Check initialization data, any interface revision from the original onwards is fine */
    if ((HwInitializationData->HwInitializationDataSize < HW_INIT_DATA_SIZE_PHYSICAL) ||
        (HwInitializationData->HwInitialize == NULL) ||
        (HwInitializationData->HwStartIo == NULL) ||
        (HwInitializationData->HwFindAdapter == NULL) ||
        (HwInitializationData->HwResetBus == NULL))
    {
        DPRINT1("Revision mismatch!\n");
        return STATUS_REVISION_MISMATCH;
    }

    DriverObjectExtension = IoGetDriverObjectExtension(DriverObject,
                                                       (PVOID)DriverEntry);
    if (DriverObjectExtension == NULL)
    {
        DPRINT1("No driver object extension!\n");

        Status = IoAllocateDriverObjectExtension(DriverObject,
                                                 (PVOID)DriverEntry,
                                                 sizeof(DRIVER_OBJECT_EXTENSION),
                                                 (PVOID *)&DriverObjectExtension);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("IoAllocateDriverObjectExtension() failed (Status 0x%08lx)\n", Status);
            return Status;
        }

        DPRINT1("Driver object extension created!\n");

        /* Initialize the driver object extension */
        RtlZeroMemory(DriverObjectExtension,
                      sizeof(DRIVER_OBJECT_EXTENSION));

        DriverObjectExtension->ExtensionType = DriverExtension;
        DriverObjectExtension->DriverObject = DriverObject;

        InitializeListHead(&DriverObjectExtension->AdapterListHead);
        KeInitializeSpinLock(&DriverObjectExtension->AdapterListLock);

        InitializeListHead(&DriverObjectExtension->InitDataListHead);

        /* Set handlers */
        DriverObject->DriverExtension->AddDevice = PortAddDevice;
//        DriverObject->DriverStartIo = PortStartIo;
        DriverObject->DriverUnload = PortUnload;
        DriverObject->MajorFunction[IRP_MJ_CREATE] = PortDispatchCreate;
        DriverObject->MajorFunction[IRP_MJ_CLOSE] = PortDispatchClose;
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = PortDispatchDeviceControl;
        DriverObject->MajorFunction[IRP_MJ_SCSI] = PortDispatchScsi;
        DriverObject->MajorFunction[IRP_MJ_POWER] = PortDispatchPower;
        DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = PortDispatchSystemControl;
        DriverObject->MajorFunction[IRP_MJ_PNP] = PortDispatchPnp;
    }

    /* Add the initialzation data to the driver extension */
    Status = PortAddDriverInitData(DriverObjectExtension,
                                   HwInitializationData);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PortAddDriverInitData() failed (Status 0x%08lx)\n", Status);
        return Status;
    }

    DPRINT1("StorPortInitialize() done (Status 0x%08lx)\n", Status);

    return Status;
}


/*
 * @unimplemented
 */
STORPORT_API
VOID
NTAPI
StorPortLogError(
    _In_ PVOID HwDeviceExtension,
    _In_opt_ PSCSI_REQUEST_BLOCK Srb,
    _In_ UCHAR PathId,
    _In_ UCHAR TargetId,
    _In_ UCHAR Lun,
    _In_ ULONG ErrorCode,
    _In_ ULONG UniqueId)
{
    DPRINT1("ScsiPortLogError() called\n");
    DPRINT1("PathId: 0x%02x  TargetId: 0x%02x  Lun: 0x%02x  ErrorCode: 0x%08lx  UniqueId: 0x%08lx\n",
            PathId, TargetId, Lun, ErrorCode, UniqueId);

    DPRINT1("ScsiPortLogError() done\n");
}


/*
 * @implemented
 */
STORPORT_API
VOID
NTAPI
StorPortMoveMemory(
    _Out_writes_bytes_(Length) PVOID Destination,
    _In_reads_bytes_(Length) PVOID Source,
    _In_ ULONG Length)
{
    RtlMoveMemory(Destination, Source, Length);
}


/*
 * @unimplemented
 */
STORPORT_API
VOID
StorPortNotification(
    _In_ SCSI_NOTIFICATION_TYPE NotificationType,
    _In_ PVOID HwDeviceExtension,
    ...)
{
    PMINIPORT_DEVICE_EXTENSION MiniportExtension = NULL;
    PFDO_DEVICE_EXTENSION FdoExtension = NULL;
    PHW_PASSIVE_INITIALIZE_ROUTINE HwPassiveInitRoutine;
    PSTORPORT_EXTENDED_FUNCTIONS *ppExtendedFunctions;
    PQUEUED_REQUEST_REFERENCE RequestReference;
    PBOOLEAN Result;
    PSTOR_DPC Dpc;
    PHW_DPC_ROUTINE HwDpcRoutine;
    PVOID DpcArgument1;
    PVOID DpcArgument2;

    STOR_SPINLOCK SpinLock;
    PVOID LockContext;
    PSTOR_LOCK_HANDLE LockHandle;
    PSCSI_REQUEST_BLOCK Srb;

    va_list ap;

    DPRINT("StorPortNotification(%x %p)\n",
            NotificationType, HwDeviceExtension);

    /* Get the miniport extension */
    if (HwDeviceExtension != NULL)
    {
        MiniportExtension = CONTAINING_RECORD(HwDeviceExtension,
                                              MINIPORT_DEVICE_EXTENSION,
                                              HwDeviceExtension);
        DPRINT("HwDeviceExtension %p  MiniportExtension %p\n",
                HwDeviceExtension, MiniportExtension);

        FdoExtension = MiniportExtension->Miniport->DeviceExtension;
    }

    va_start(ap, HwDeviceExtension);

    switch (NotificationType)
    {
        case RequestComplete:
            DPRINT("RequestComplete\n");
            Srb = (PSCSI_REQUEST_BLOCK)va_arg(ap, PSCSI_REQUEST_BLOCK);
            DPRINT("Complete Notify - Srb %p\n", Srb);

            /*
             * Storport may have completed this SRB itself after restarting the adapter; its
             * packet is gone then and Srb->OriginalRequest is the IRP. That is recognised from
             * the SRB alone. The restart waits for calls counted here before it frees packets.
             */
            InterlockedIncrement(&FdoExtension->CompletionsInFlight);
            if (PortIsSweptSrb(FdoExtension, Srb))
            {
                DPRINT1("Late completion of Srb %p (completed by storport after a restart) ignored\n", Srb);
            }
            else
            {
                RequestReference = StorpRequestReference(Srb);
                NT_ASSERT(RequestReference);

                if (!PortClaimRequestCompletion(RequestReference))
                {
                    DPRINT1("Late completion of Srb %p ignored\n", Srb);
                }
                else
                {
                    /* Carry the miniport's answer back to the original request */
                    if (StorpIsExtendedSrb(Srb))
                    {
                        StorpCompleteExtendedSrb(RequestReference->Srb,
                                                 RequestReference->ExtendedRequest);
                    }

                    /* Queue for completion */
                    InterlockedPushEntrySList(&FdoExtension->CompletionList,
                                              &RequestReference->CompletionEntry);

                    /* Insert DPC for delayed completion */
                    KeInsertQueueDpc(&FdoExtension->Device->Dpc, NULL, NULL);
                }
            }
            InterlockedDecrement(&FdoExtension->CompletionsInFlight);
            break;

        case BusChangeDetected:
            DPRINT1("BusChangeDetected\n");

            /* Have PnP query bus relations again so the scan runs, once below device IRQL */
            if (FdoExtension != NULL && FdoExtension->PhysicalDevice != NULL)
                KeInsertQueueDpc(&FdoExtension->BusChangeDpc, NULL, NULL);
            break;

        case StateChangeDetectedCall:
        {
            ULONG ChangedEntity = va_arg(ap, ULONG);
            PSTOR_ADDRESS Address = va_arg(ap, PSTOR_ADDRESS);
            ULONG Attributes = va_arg(ap, ULONG);
            PHW_STATE_CHANGE StateChangeRoutine = va_arg(ap, PHW_STATE_CHANGE);
            PVOID StateChangeContext = va_arg(ap, PVOID);
            PULONG StateChangeStatus = va_arg(ap, PULONG);
            ULONG Result;

            UNREFERENCED_PARAMETER(Attributes);

            if (FdoExtension == NULL ||
                ChangedEntity == 0 ||
                (ChangedEntity & ~(STATE_CHANGE_LUN | STATE_CHANGE_TARGET | STATE_CHANGE_BUS)) != 0 ||
                (ChangedEntity != STATE_CHANGE_BUS &&
                 (Address == NULL ||
                  Address->Type != STOR_ADDRESS_TYPE_BTL8 ||
                  Address->AddressLength != STOR_ADDR_BTL8_ADDRESS_LENGTH)))
            {
                Result = STOR_STATUS_INVALID_PARAMETER;
            }
            else if (InterlockedCompareExchange(&FdoExtension->StateChangePending, 1, 0) != 0)
            {
                /* One state change at a time, the next one after the callback */
                Result = STOR_STATUS_UNSUCCESSFUL;
            }
            else
            {
                RtlZeroMemory(&FdoExtension->StateChangeAddress, sizeof(FdoExtension->StateChangeAddress));
                if (Address != NULL && Address->Type == STOR_ADDRESS_TYPE_BTL8)
                    RtlCopyMemory(&FdoExtension->StateChangeAddress, Address, sizeof(STOR_ADDR_BTL8));
                FdoExtension->StateChangeRoutine = StateChangeRoutine;
                FdoExtension->StateChangeContext = StateChangeContext;

                /* The whole bus is scanned again whatever the entity: the same path as BusChangeDetected */
                if (FdoExtension->PhysicalDevice != NULL)
                    KeInsertQueueDpc(&FdoExtension->BusChangeDpc, NULL, NULL);
                Result = STOR_STATUS_SUCCESS;
            }

            if (StateChangeStatus != NULL)
                *StateChangeStatus = Result;
            break;
        }

        case GetExtendedFunctionTable:
            DPRINT1("GetExtendedFunctionTable\n");
            ppExtendedFunctions = (PSTORPORT_EXTENDED_FUNCTIONS*)va_arg(ap, PSTORPORT_EXTENDED_FUNCTIONS*);
            if (ppExtendedFunctions != NULL)
                *ppExtendedFunctions = NULL; /* FIXME: */
            break;

        case EnablePassiveInitialization:
            DPRINT1("EnablePassiveInitialization\n");
            HwPassiveInitRoutine = (PHW_PASSIVE_INITIALIZE_ROUTINE)va_arg(ap, PHW_PASSIVE_INITIALIZE_ROUTINE);
            DPRINT1("HwPassiveInitRoutine %p\n", HwPassiveInitRoutine);
            Result = (PBOOLEAN)va_arg(ap, PBOOLEAN);

            // FIXME: It is not guaranteed that enabling passive initialization will fail and return
            // FALSE when not called in driver's HwStorInitialize routine.
            // Docs: Remarks of https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/storport/nf-storport-storportenablepassiveinitialization
            *Result = FALSE;

            if ((FdoExtension != NULL) &&
                (FdoExtension->HwPassiveInitRoutine == NULL))
            {
                FdoExtension->HwPassiveInitRoutine = HwPassiveInitRoutine;
                *Result = TRUE;
            }
            break;

        case InitializeDpc:
            DPRINT("InitializeDpc\n");
            Dpc = (PSTOR_DPC)va_arg(ap, PSTOR_DPC);
            DPRINT("Dpc %p\n", Dpc);
            HwDpcRoutine = (PHW_DPC_ROUTINE)va_arg(ap, PHW_DPC_ROUTINE);
            DPRINT("HwDpcRoutine %p\n", HwDpcRoutine);

            KeInitializeDpc((PRKDPC)&Dpc->Dpc,
                            (PKDEFERRED_ROUTINE)HwDpcRoutine,
                            (PVOID)(FdoExtension->Miniport.MiniportExtension->HwDeviceExtension));
            KeInitializeSpinLock(&Dpc->Lock);
            break;

        case IssueDpc:
            DPRINT("IssueDpc\n");
            Dpc = (PSTOR_DPC)va_arg(ap, PSTOR_DPC);
            DpcArgument1 = (PVOID)va_arg(ap, PVOID);
            DpcArgument2 = (PVOID)va_arg(ap, PVOID);
            DPRINT("Dpc %p Arg1 %p Arg2 %p\n", Dpc, DpcArgument1, DpcArgument2);
            Result = (PBOOLEAN)va_arg(ap, PBOOLEAN);

            *Result = KeInsertQueueDpc((PKDPC)Dpc, DpcArgument1, DpcArgument2);
            break;

        case AcquireSpinLock:
            DPRINT("AcquireSpinLock\n");
            SpinLock = (STOR_SPINLOCK)va_arg(ap, STOR_SPINLOCK);
            DPRINT("SpinLock %lu\n", SpinLock);
            LockContext = (PVOID)va_arg(ap, PVOID);
            DPRINT("LockContext %p\n", LockContext);
            LockHandle = (PSTOR_LOCK_HANDLE)va_arg(ap, PSTOR_LOCK_HANDLE);
            DPRINT("LockHandle %p\n", LockHandle);
            PortAcquireSpinLock(FdoExtension,
                                SpinLock,
                                LockContext,
                                LockHandle);
            break;

        case ReleaseSpinLock:
            DPRINT("ReleaseSpinLock\n");
            LockHandle = (PSTOR_LOCK_HANDLE)va_arg(ap, PSTOR_LOCK_HANDLE);
            DPRINT("LockHandle %p\n", LockHandle);
            PortReleaseSpinLock(FdoExtension,
                                LockHandle);
            break;

        case RequestTimerCall:
        {
            PHW_TIMER TimerRoutine;
            ULONG TimerValue;
            LARGE_INTEGER TimerDueTime;
            NTSTATUS MultiplyResult;

            TimerRoutine = (PHW_TIMER)va_arg(ap, PHW_TIMER);
            TimerValue = (ULONG)va_arg(ap, ULONG);
            NT_ASSERT(TimerRoutine != NULL);

            /* Set timer if timer value != 0. Logic is exactly same as StorPortRequestTimer */
            if (TimerValue != 0)
            {
                MultiplyResult = RtlULongLongMult(TimerValue, 10ull, (PULONGLONG)&TimerDueTime.QuadPart);
                if (!NT_SUCCESS(MultiplyResult)) {
                    break;
                }

                /* Negative: relative to now. A positive due time is an absolute date */
                TimerDueTime.QuadPart = -TimerDueTime.QuadPart;

                FdoExtension->TimerCallback = TimerRoutine;
                KeSetTimer(&FdoExtension->Timer, TimerDueTime, &FdoExtension->TimerDpc);
            }
            else
            {
                /* Otherwise cancel the timer. */
                KeCancelTimer(&FdoExtension->Timer);
            }
            break;
        }

        default:
            DPRINT1("Unsupported Notification %lx\n", NotificationType);
            break;
    }

    va_end(ap);
}


/*
 * @implemented
 */
STORPORT_API
BOOLEAN
NTAPI
StorPortPause(
    _In_ PVOID HwDeviceExtension,
    _In_ ULONG TimeOut)
{
    PFDO_DEVICE_EXTENSION FdoExtension;

    DPRINT("StorPortPause(%p %lu)\n", HwDeviceExtension, TimeOut);

    if (HwDeviceExtension == NULL)
        return FALSE;

    FdoExtension = StorpGetMiniportFdo(HwDeviceExtension);

    /* TimeOut is in seconds; the one second timer of the adapter counts it down, and its first tick comes
       less than a second from now, so one more tick makes the pause last at least TimeOut. 0 = until resumed */
    FdoExtension->FlowControl.RemainingPauseTime = (TimeOut != 0) ? TimeOut + 1 : 0;
    KeMemoryBarrier();
    FdoExtension->FlowControl.IsPaused = TRUE;

    return TRUE;
}


/*
 * @unimplemented
 */
STORPORT_API
BOOLEAN
NTAPI
StorPortPauseDevice(
    _In_ PVOID HwDeviceExtension,
    _In_ UCHAR PathId,
    _In_ UCHAR TargetId,
    _In_ UCHAR Lun,
    _In_ ULONG TimeOut)
{
    DPRINT1("StorPortPauseDevice()\n");
    UNIMPLEMENTED;
    return FALSE;
}


#if defined(_M_AMD64)
/*
 * @implemented
 */
/* KeQuerySystemTime is an inline function,
   so we cannot forward the export to ntoskrnl */
STORPORT_API
VOID
NTAPI
StorPortQuerySystemTime(
    _Out_ PLARGE_INTEGER CurrentTime)
{
    DPRINT1("StorPortQuerySystemTime(%p)\n", CurrentTime);

    KeQuerySystemTime(CurrentTime);
}
#endif /* defined(_M_AMD64) */


/*
 * @implemented
 */
STORPORT_API
BOOLEAN
NTAPI
StorPortReady(
    _In_ PVOID HwDeviceExtension)
{
    PFDO_DEVICE_EXTENSION FdoExtension;

    DPRINT("StorPortReady(%p)\n", HwDeviceExtension);

    if (HwDeviceExtension == NULL)
        return FALSE;

    FdoExtension = StorpGetMiniportFdo(HwDeviceExtension);

    FdoExtension->FlowControl.IsBusy = FALSE;
    FdoExtension->FlowControl.RemainingBusyRequests = 0;
    InterlockedExchange(&FdoExtension->FlowControl.KickNeeded, 1);
    KeInsertQueueDpc(&FdoExtension->FlowKickDpc, NULL, NULL);

    return TRUE;
}


/*
 * @implemented
 */
STORPORT_API
BOOLEAN
NTAPI
StorPortRegistryRead(
    _In_ PVOID HwDeviceExtension,
    _In_ PUCHAR ValueName,
    _In_ ULONG Global,
    _In_ ULONG Type,
    _In_ PUCHAR Buffer,
    _In_ PULONG BufferLength)
{
    DPRINT("StorPortRegistryRead()\n");

    if (HwDeviceExtension == NULL || BufferLength == NULL)
        return FALSE;

    return PortReadMiniportRegistryValue(StorpGetMiniportFdo(HwDeviceExtension),
                                         (PCSTR)ValueName,
                                         Global,
                                         Type,
                                         Buffer,
                                         BufferLength);
}


/*
 * @unimplemented
 */
STORPORT_API
BOOLEAN
NTAPI
StorPortRegistryWrite(
    _In_ PVOID HwDeviceExtension,
    _In_ PUCHAR ValueName,
    _In_ ULONG Global,
    _In_ ULONG Type,
    _In_ PUCHAR Buffer,
    _In_ ULONG BufferLength)
{
    DPRINT1("StorPortRegistryWrite()\n");
    UNIMPLEMENTED;
    return FALSE;
}


/*
 * @implemented
 */
STORPORT_API
BOOLEAN
NTAPI
StorPortResume(
    _In_ PVOID HwDeviceExtension)
{
    PFDO_DEVICE_EXTENSION FdoExtension;

    DPRINT("StorPortResume(%p)\n", HwDeviceExtension);

    if (HwDeviceExtension == NULL)
        return FALSE;

    FdoExtension = StorpGetMiniportFdo(HwDeviceExtension);

    FdoExtension->FlowControl.IsPaused = FALSE;
    FdoExtension->FlowControl.RemainingPauseTime = 0;
    InterlockedExchange(&FdoExtension->FlowControl.KickNeeded, 1);

    /* May be called from an interrupt routine or with the flow control lock held: issue from a DPC */
    KeInsertQueueDpc(&FdoExtension->FlowKickDpc, NULL, NULL);

    return TRUE;
}


/*
 * @unimplemented
 */
STORPORT_API
BOOLEAN
NTAPI
StorPortResumeDevice(
    _In_ PVOID HwDeviceExtension,
    _In_ UCHAR PathId,
    _In_ UCHAR TargetId,
    _In_ UCHAR Lun)
{
    DPRINT1("StorPortResumeDevice()\n");
    UNIMPLEMENTED;
    return FALSE;
}


/*
 * @implemented
 */
STORPORT_API
ULONG
NTAPI
StorPortSetBusDataByOffset(
    _In_ PVOID DeviceExtension,
    _In_ ULONG BusDataType,
    _In_ ULONG SystemIoBusNumber,
    _In_ ULONG SlotNumber,
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Offset,
    _In_ ULONG Length)
{
    PMINIPORT_DEVICE_EXTENSION MiniportExtension;
    PBUS_INTERFACE_STANDARD Interface;
    ULONG ReturnLength;

    DPRINT1("StorPortSetBusData(%p %lu %lu %lu %p %lu %lu)\n",
            DeviceExtension, BusDataType, SystemIoBusNumber, SlotNumber, Buffer, Offset, Length);

    MiniportExtension = CONTAINING_RECORD(DeviceExtension,
                                          MINIPORT_DEVICE_EXTENSION,
                                          HwDeviceExtension);
    DPRINT1("DeviceExtension %p  MiniportExtension %p\n",
            DeviceExtension, MiniportExtension);

    Interface = &MiniportExtension->Miniport->DeviceExtension->BusInterface;

    ReturnLength = Interface->SetBusData(Interface->Context,
                                         BusDataType,
                                         Buffer,
                                         Offset,
                                         Length);
    DPRINT1("ReturnLength: %lu\n", ReturnLength);

    return ReturnLength;
}


/*
 * @implemented
 */
STORPORT_API
BOOLEAN
NTAPI
StorPortSetDeviceQueueDepth(
    _In_ PVOID HwDeviceExtension,
    _In_ UCHAR PathId,
    _In_ UCHAR TargetId,
    _In_ UCHAR Lun,
    _In_ ULONG Depth)
{
    PFDO_DEVICE_EXTENSION FdoExtension;
    PPDO_DEVICE_EXTENSION PdoExtension;

    DPRINT("StorPortSetDeviceQueueDepth(%p %d %d %d %d)\n",
           HwDeviceExtension, PathId, TargetId, Lun, Depth);

    FdoExtension = StorpGetMiniportFdo(HwDeviceExtension);

    /* A miniport calls this when it completes an INQUIRY, from its interrupt routine too */
    PdoExtension = FdoFindLunAboveDispatch(FdoExtension, PathId, TargetId, Lun);

    /* A depth of 0 would let no request start, and the tag is taken modulo the depth */
    if (PdoExtension == NULL || Depth == 0)
    {
        return FALSE;
    }

    /* 254 is pre-Windows-8 per LUN queue limit; a larger request (a miniport asks for its ring size) gets the limit */
    if (Depth > 254)
        Depth = 254;

    /*
     * Never under the flow control lock: besides the interrupt routine, a miniport calls this from
     * HwBuildIo or HwStartIo (viostor answers INQUIRY there), and storport issues a request it held
     * back from the completion of another one with that lock held: a second acquire on the same
     * processor never returns. The limit is one aligned ULONG; the scheduler compares against it
     * with >=, so a limit lowered below what is outstanding only holds new requests back.
     */
    InterlockedExchange((PLONG)&PdoExtension->OutstandingRequestMax, (LONG)Depth);

    DPRINT("Set Path %d Target %d Lun %d Queue depth to %d\n", PathId, TargetId, Lun, Depth);

    return TRUE;
}


/*
 * @implemented
 */
STORPORT_API
VOID
NTAPI
StorPortStallExecution(
    _In_ ULONG Delay)
{
    KeStallExecutionProcessor(Delay);
}


/*
 * @implemented
 */
STORPORT_API
BOOLEAN
NTAPI
StorPortSynchronizeAccess(
    _In_ PVOID HwDeviceExtension,
    _In_ PSTOR_SYNCHRONIZED_ACCESS SynchronizedAccessRoutine,
    _In_opt_ PVOID Context)
{
    PFDO_DEVICE_EXTENSION FdoExtension;
    KIRQL OldIrql;
    BOOLEAN Result;

    DPRINT("StorPortSynchronizeAccess()\n");

    if (HwDeviceExtension == NULL || SynchronizedAccessRoutine == NULL)
        return FALSE;

    FdoExtension = StorpGetMiniportFdo(HwDeviceExtension);

    if (FdoExtension->Interrupt == NULL)
    {
        /* No interrupt (a virtual miniport): nothing to exclude, keep the routine at DISPATCH_LEVEL */
        KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);
        Result = SynchronizedAccessRoutine(HwDeviceExtension, Context);
        KeLowerIrql(OldIrql);
        return Result;
    }

    /* Every interrupt service routine of the adapter is held off, one lock for each message */
    OldIrql = PortFdoAcquireInterruptLocks(FdoExtension);
    Result = SynchronizedAccessRoutine(HwDeviceExtension, Context);
    PortFdoReleaseInterruptLocks(FdoExtension, OldIrql);

    return Result;
}


/*
 * @implemented
 */
STORPORT_API
BOOLEAN
NTAPI
StorPortValidateRange(
    _In_ PVOID HwDeviceExtension,
    _In_ INTERFACE_TYPE BusType,
    _In_ ULONG SystemIoBusNumber,
    _In_ STOR_PHYSICAL_ADDRESS IoAddress,
    _In_ ULONG NumberOfBytes,
    _In_ BOOLEAN InIoSpace)
{
    DPRINT1("StorPortValidateRange()\n");
    return TRUE;
}

/* EOF */
