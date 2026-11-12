/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/wmi/notify.c
 * PURPOSE:         WMI kernel notification callbacks (IoWMISetNotificationCallback)
 *
 * Implemented from the public WDK documentation of IoWMISetNotificationCallback
 * and IoWMIWriteEvent.
 */

/* INCLUDES *****************************************************************/

#include <ntoskrnl.h>
#include <wmistr.h>
#include <wmidata.h>

#include "wmip.h"

#define NDEBUG
#include <debug.h>

/* GLOBALS ******************************************************************/

/* All GUID objects that currently carry a callback. Callbacks are delivered
   from IoWMIWriteEvent, which may run at DISPATCH_LEVEL, so a spin lock. */
static KSPIN_LOCK WmipNotifyLock;
static LIST_ENTRY WmipNotifyList;

/* FUNCTIONS ****************************************************************/

VOID
NTAPI
WmipNotifyInitialize(
    VOID)
{
    KeInitializeSpinLock(&WmipNotifyLock);
    InitializeListHead(&WmipNotifyList);
}

/* Unlinks the object and waits for deliveries in progress (not when called
   from DISPATCH_LEVEL, where nobody can be waited for). */
VOID
NTAPI
WmipNotifyRemove(
    _In_ PWMIP_GUID_OBJECT GuidObject)
{
    LARGE_INTEGER Delay;
    KIRQL OldIrql;

    KeAcquireSpinLock(&WmipNotifyLock, &OldIrql);
    if (GuidObject->NotifyLinked)
    {
        RemoveEntryList(&GuidObject->NotifyLink);
        GuidObject->NotifyLinked = FALSE;
    }
    GuidObject->NotifyCallback = NULL;
    GuidObject->NotifyContext = NULL;
    KeReleaseSpinLock(&WmipNotifyLock, OldIrql);

    /* FIXME: a callback that removes itself from inside the callback would
       wait for itself here; with in-flight > 0 from the same thread we only
       wait at PASSIVE_LEVEL and give up after about 1 second. */
    if (KeGetCurrentIrql() == PASSIVE_LEVEL)
    {
        ULONG Tries = 0;

        Delay.QuadPart = -10 * 1000 * 10; /* 10 ms */
        while (GuidObject->NotifyInFlight != 0 && Tries++ < 100)
            KeDelayExecutionThread(KernelMode, FALSE, &Delay);
    }
}

NTSTATUS
NTAPI
WmipNotifySetCallback(
    _In_ PWMIP_GUID_OBJECT GuidObject,
    _In_opt_ WMI_NOTIFICATION_CALLBACK Callback,
    _In_opt_ PVOID Context)
{
    KIRQL OldIrql;

    if (Callback == NULL)
    {
        /* FIXME: VERIFY ON ORACLE: whether a NULL callback is documented as
           "remove"; the docs are silent, we treat it as removal. */
        WmipNotifyRemove(GuidObject);
        return STATUS_SUCCESS;
    }

    KeAcquireSpinLock(&WmipNotifyLock, &OldIrql);
    GuidObject->NotifyCallback = Callback;
    GuidObject->NotifyContext = Context;
    if (!GuidObject->NotifyLinked)
    {
        InsertTailList(&WmipNotifyList, &GuidObject->NotifyLink);
        GuidObject->NotifyLinked = TRUE;
    }
    KeReleaseSpinLock(&WmipNotifyLock, OldIrql);

    return STATUS_SUCCESS;
}

VOID
NTAPI
WmipNotifyDeliver(
    _In_ PWNODE_HEADER Wnode)
{
    PWMIP_GUID_OBJECT Candidates[8];
    WMI_NOTIFICATION_CALLBACK Callbacks[RTL_NUMBER_OF(Candidates)];
    PVOID Contexts[RTL_NUMBER_OF(Candidates)];
    PLIST_ENTRY Entry;
    KIRQL OldIrql;
    ULONG Count, i;
    GUID Guid = Wnode->Guid;

    Count = 0;
    KeAcquireSpinLock(&WmipNotifyLock, &OldIrql);
    for (Entry = WmipNotifyList.Flink;
         Entry != &WmipNotifyList && Count < RTL_NUMBER_OF(Candidates);
         Entry = Entry->Flink)
    {
        PWMIP_GUID_OBJECT Obj = CONTAINING_RECORD(Entry, WMIP_GUID_OBJECT, NotifyLink);

        if (!IsEqualGUID(&Obj->Guid, &Guid))
            continue;

        /* Pin the object for the duration of the call */
        ObReferenceObject(Obj);
        InterlockedIncrement(&Obj->NotifyInFlight);
        Candidates[Count] = Obj;
        Callbacks[Count] = Obj->NotifyCallback;
        Contexts[Count] = Obj->NotifyContext;
        Count++;
    }
    KeReleaseSpinLock(&WmipNotifyLock, OldIrql);

    /* FIXME: at most 8 callbacks per event GUID are served */
    for (i = 0; i < Count; i++)
    {
        if (Callbacks[i] != NULL)
            Callbacks[i](Wnode, Contexts[i]);
        InterlockedDecrement(&Candidates[i]->NotifyInFlight);
        ObDereferenceObject(Candidates[i]);
    }
}
