/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/io/iomgr/iothread.c
 * PURPOSE:         IoCreateSystemThread: system thread that keeps its driver loaded
 *
 * Implemented from the public WDK documentation of IoCreateSystemThread:
 * like PsCreateSystemThread, but the I/O manager holds a reference on the
 * driver (given as a DEVICE_OBJECT or DRIVER_OBJECT) until the thread ends,
 * so the driver image cannot be unloaded while its thread still runs driver
 * code.
 */

/* INCLUDES *****************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

/* GLOBALS ******************************************************************/

typedef struct _IOP_SYSTEM_THREAD
{
    LIST_ENTRY Link;
    PETHREAD Thread;            /* set by the thread itself when it starts */
    PVOID Object;               /* referenced device or driver object */
    PKSTART_ROUTINE StartRoutine;
    PVOID StartContext;
} IOP_SYSTEM_THREAD, *PIOP_SYSTEM_THREAD;

static KSPIN_LOCK IopSystemThreadLock;
static LIST_ENTRY IopSystemThreadList;
static BOOLEAN IopSystemThreadInit;
volatile LONG IopSystemThreadCount;

/* FUNCTIONS ****************************************************************/

static
VOID
IopSystemThreadRelease(
    _In_ PIOP_SYSTEM_THREAD Entry)
{
    ObDereferenceObject(Entry->Object);
    ExFreePoolWithTag(Entry, 'tSoI');
}

/* Called by the exiting thread (PspExitThread), after it has left driver code */
VOID
NTAPI
IopSystemThreadExit(
    _In_ PETHREAD Thread)
{
    PLIST_ENTRY ListEntry;
    PIOP_SYSTEM_THREAD Found = NULL;
    KIRQL OldIrql;

    KeAcquireSpinLock(&IopSystemThreadLock, &OldIrql);
    for (ListEntry = IopSystemThreadList.Flink;
         ListEntry != &IopSystemThreadList;
         ListEntry = ListEntry->Flink)
    {
        PIOP_SYSTEM_THREAD Entry = CONTAINING_RECORD(ListEntry, IOP_SYSTEM_THREAD, Link);

        if (Entry->Thread == Thread)
        {
            RemoveEntryList(&Entry->Link);
            InterlockedDecrement(&IopSystemThreadCount);
            Found = Entry;
            break;
        }
    }
    KeReleaseSpinLock(&IopSystemThreadLock, OldIrql);

    if (Found)
        IopSystemThreadRelease(Found);
}

static
VOID
NTAPI
IopSystemThreadStart(
    _In_ PVOID Context)
{
    PIOP_SYSTEM_THREAD Entry = Context;
    PKSTART_ROUTINE StartRoutine = Entry->StartRoutine;
    PVOID StartContext = Entry->StartContext;

    /* Only this thread writes its own entry's Thread, no lock needed: the
       entry is looked up only from this thread's exit */
    Entry->Thread = PsGetCurrentThread();

    StartRoutine(StartContext);

    /* The routine is documented to call PsTerminateSystemThread; if it
       returns, end the thread for it. Either path ends in IopSystemThreadExit. */
    PsTerminateSystemThread(STATUS_SUCCESS);
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
IoCreateSystemThread(
    _Inout_ PVOID IoObject,
    _Out_ PHANDLE ThreadHandle,
    _In_ ULONG DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ HANDLE ProcessHandle,
    _Out_opt_ PCLIENT_ID ClientId,
    _In_ PKSTART_ROUTINE StartRoutine,
    _In_opt_ PVOID StartContext)
{
    PIOP_SYSTEM_THREAD Entry;
    PDEVICE_OBJECT DeviceObject = IoObject;
    KIRQL OldIrql;
    NTSTATUS Status;
    HANDLE Handle;

    PAGED_CODE();

    if (IoObject == NULL || StartRoutine == NULL)
        return STATUS_INVALID_PARAMETER;

    /* The documented IoObject is a device object or a driver object */
    if (DeviceObject->Type != IO_TYPE_DEVICE && DeviceObject->Type != IO_TYPE_DRIVER)
        return STATUS_INVALID_PARAMETER;

    Entry = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Entry), 'tSoI');
    if (Entry == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    /* Reference the driver (a device's owner) so the image stays mapped.
       FIXME: VERIFY ON ORACLE: whether the device object is referenced too. */
    if (DeviceObject->Type == IO_TYPE_DEVICE)
        Entry->Object = DeviceObject->DriverObject;
    else
        Entry->Object = IoObject;
    ObReferenceObject(Entry->Object);

    Entry->Thread = NULL;
    Entry->StartRoutine = StartRoutine;
    Entry->StartContext = StartContext;

    KeAcquireSpinLock(&IopSystemThreadLock, &OldIrql);
    if (!IopSystemThreadInit)
    {
        InitializeListHead(&IopSystemThreadList);
        IopSystemThreadInit = TRUE;
    }
    InsertTailList(&IopSystemThreadList, &Entry->Link);
    InterlockedIncrement(&IopSystemThreadCount);
    KeReleaseSpinLock(&IopSystemThreadLock, OldIrql);

    Status = PsCreateSystemThread(&Handle,
                                  DesiredAccess,
                                  ObjectAttributes,
                                  ProcessHandle,
                                  ClientId,
                                  IopSystemThreadStart,
                                  Entry);
    if (!NT_SUCCESS(Status))
    {
        /* The thread never ran: undo */
        KeAcquireSpinLock(&IopSystemThreadLock, &OldIrql);
        RemoveEntryList(&Entry->Link);
        InterlockedDecrement(&IopSystemThreadCount);
        KeReleaseSpinLock(&IopSystemThreadLock, OldIrql);
        IopSystemThreadRelease(Entry);
        return Status;
    }

    *ThreadHandle = Handle;
    return STATUS_SUCCESS;
}
