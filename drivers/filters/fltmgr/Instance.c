/*
* PROJECT:         Filesystem Filter Manager
* LICENSE:         GPL - See COPYING in the top level directory
* FILE:            drivers/filters/fltmgr/Instance.c
* PURPOSE:         Mini-filter instances: attach to and detach from a volume
*/

/* INCLUDES ******************************************************************/

#include "fltmgr.h"
#include "fltmgrint.h"
#include "fltmgrproto.h"

#define NDEBUG
#include <debug.h>


/* DATA *********************************************************************/


/* PRIVATE FUNCTIONS ********************************************************/

static
VOID
InitRelatedObjects(_Out_ PFLT_RELATED_OBJECTS Objects,
                   _In_ PFLT_INSTANCE Instance)
{
    RtlZeroMemory(Objects, sizeof(*Objects));
    *(PUSHORT)&Objects->Size = sizeof(FLT_RELATED_OBJECTS);
    *(PFLT_FILTER *)&Objects->Filter = Instance->Filter;
    *(PFLT_VOLUME *)&Objects->Volume = Instance->Volume;
    *(PFLT_INSTANCE *)&Objects->Instance = Instance;
}

/* Adds or removes the callbacks of the filter of an instance to the per volume counts */
static
VOID
UpdateVolumeCallbackCounts(_In_ PFLT_VOLUME Volume,
                           _In_ PFLT_FILTER Filter,
                           _In_ LONG Delta)
{
    ULONG i;

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
    {
        if (Filter->OperationTable[i])
            InterlockedAdd((PLONG)&Volume->CallbackCount[i], Delta);
    }

    /* Stream and stream handle contexts live as long as the file is open: someone has to count the opens */
    if (Filter->ContextDefs[FLTP_CTX_INDEX_STREAM].Registered ||
        Filter->ContextDefs[FLTP_CTX_INDEX_STREAMHANDLE].Registered)
    {
        InterlockedAdd((PLONG)&Volume->ContextTracking, Delta);
    }
}

/* An altitude is unique per volume, and so is the name of an instance of a filter. Volume lock held. */
static
NTSTATUS
CheckCollision(_In_ PFLT_VOLUME Volume,
               _In_ PFLT_FILTER Filter,
               _In_ PCUNICODE_STRING Altitude,
               _In_ PCUNICODE_STRING Name)
{
    PLIST_ENTRY Entry;
    PFLT_INSTANCE Other;

    for (Entry = Volume->InstanceList.rList.Flink;
         Entry != &Volume->InstanceList.rList;
         Entry = Entry->Flink)
    {
        Other = CONTAINING_RECORD(Entry, FLT_INSTANCE, VolumeLink);

        if (FltpCompareAltitudeStrings(Altitude, &Other->Altitude) == 0)
            return STATUS_FLT_INSTANCE_ALTITUDE_COLLISION;

        if (Other->Filter == Filter && RtlEqualUnicodeString(&Other->Name, Name, TRUE))
            return STATUS_FLT_INSTANCE_NAME_COLLISION;
    }

    return STATUS_SUCCESS;
}

/*
 * Puts the instance in the list of its volume, which is ordered by altitude, highest first, and in the
 * list of its filter, both at once. Lock order: the filter's list, then the volume's.
 *
 * FltUnregisterFilter marks the filter draining before it tears down the instances it finds in the
 * filter's list. The flag is checked here under the filter's list lock: either the unregister finds
 * the instance, or the instance isn't made. Without that an attach which had looked at the flag
 * before the unregister started (a mount, FltStartFiltering) left an instance of a freed filter on
 * the volume.
 */
static
NTSTATUS
InsertInstance(_In_ PFLT_VOLUME Volume,
               _In_ PFLT_INSTANCE Instance)
{
    PFLT_FILTER Filter = Instance->Filter;
    PLIST_ENTRY Entry;
    PFLT_INSTANCE Other;
    NTSTATUS Status;

    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&Filter->InstanceList.rLock, TRUE);
    ExAcquireResourceExclusiveLite(&Volume->InstanceList.rLock, TRUE);

    /* A filter which is being unloaded gets no new instances */
    if (Filter->Base.Flags & FLT_OBFL_DRAINING)
    {
        Status = STATUS_FLT_DELETING_OBJECT;
        goto Quit;
    }

    /* Nothing new gets attached to a volume which is going away */
    if (Volume->Dismounted || (Volume->Base.Flags & FLT_OBFL_DRAINING))
    {
        Status = STATUS_FLT_VOLUME_NOT_FOUND;
        goto Quit;
    }

    /* We looked before the filter had its say, somebody may have been quicker */
    Status = CheckCollision(Volume, Instance->Filter, &Instance->Altitude, &Instance->Name);
    if (!NT_SUCCESS(Status))
        goto Quit;

    /* The first instance of a lower altitude, or the list head */
    for (Entry = Volume->InstanceList.rList.Flink;
         Entry != &Volume->InstanceList.rList;
         Entry = Entry->Flink)
    {
        Other = CONTAINING_RECORD(Entry, FLT_INSTANCE, VolumeLink);
        if (FltpCompareAltitudeStrings(&Instance->Altitude, &Other->Altitude) > 0)
            break;
    }
    InsertTailList(Entry, &Instance->VolumeLink);
    Volume->InstanceList.rCount++;
    UpdateVolumeCallbackCounts(Volume, Filter, 1);

    InsertTailList(&Filter->InstanceList.rList, &Instance->FilterLink);
    Filter->InstanceList.rCount++;

    /* The instance is live from here on */
    InterlockedAnd((PLONG)&Instance->Flags, ~INSFL_INITING);
    InterlockedOr((PLONG)&Instance->Flags, INSFL_ACTIVE);

Quit:
    ExReleaseResourceLite(&Volume->InstanceList.rLock);
    ExReleaseResourceLite(&Filter->InstanceList.rLock);
    KeLeaveCriticalRegion();
    return Status;
}


/* INTERNAL FUNCTIONS *******************************************************/

NTSTATUS
FltpAttachInstance(_In_ PFLT_FILTER Filter,
                   _In_ PFLT_VOLUME Volume,
                   _In_opt_ PCUNICODE_STRING Altitude,
                   _In_opt_ PCUNICODE_STRING Name,
                   _In_ ULONG SetupFlags,
                   _Out_opt_ PFLT_INSTANCE *RetInstance)
{
    FLT_RELATED_OBJECTS Objects;
    PFLT_INSTANCE Instance;
    PCUNICODE_STRING UseAltitude = Altitude ? Altitude : &Filter->DefaultAltitude;
    PCUNICODE_STRING UseName = Name ? Name : &Filter->DefaultInstanceName;
    SIZE_T Size;
    NTSTATUS Status;

    PAGED_CODE();

    if (RetInstance)
        *RetInstance = NULL;

    /* No altitude, no place in the stack */
    if (UseAltitude->Length == 0)
        return STATUS_FLT_INSTANCE_ALTITUDE_COLLISION;

    /* A filter which isn't started or is being unloaded gets no instances */
    if (!(Filter->Flags & FLTFL_FILTERING_INITIATED) || (Filter->Base.Flags & FLT_OBFL_DRAINING))
        return STATUS_FLT_NOT_INITIALIZED;

    /* The altitude string and the name are copied behind the instance */
    Size = sizeof(FLT_INSTANCE) + UseAltitude->Length + UseName->Length + 2 * sizeof(WCHAR);
    Instance = ExAllocatePoolWithTag(NonPagedPool, Size, FM_TAG_INSTANCE);
    if (Instance == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(Instance, Size);

    Instance->Base.Flags = FLT_OBFL_TYPE_INSTANCE;
    Instance->Base.PointerCount = 1;
    FltpExInitializeRundownProtection(&Instance->Base.RundownRef);
    Instance->Flags = INSFL_INITING;
    Instance->SetupFlags = SetupFlags;
    Instance->Volume = Volume;
    Instance->Filter = Filter;
    InitializeListHead(&Instance->FilterLink);
    InitializeListHead(&Instance->VolumeLink);

    Instance->Altitude.Buffer = Instance->AltitudeBuffer;
    Instance->Altitude.MaximumLength = UseAltitude->Length + sizeof(WCHAR);
    RtlCopyUnicodeString(&Instance->Altitude, UseAltitude);
    Instance->Altitude.Buffer[Instance->Altitude.Length / sizeof(WCHAR)] = UNICODE_NULL;

    Instance->Name.Buffer = Instance->AltitudeBuffer + Instance->Altitude.MaximumLength / sizeof(WCHAR);
    Instance->Name.MaximumLength = UseName->Length + sizeof(WCHAR);
    RtlCopyUnicodeString(&Instance->Name, UseName);
    Instance->Name.Buffer[Instance->Name.Length / sizeof(WCHAR)] = UNICODE_NULL;

    /* No point in bothering the filter if the place is taken */
    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&Volume->InstanceList.rLock, TRUE);
    Status = CheckCollision(Volume, Filter, &Instance->Altitude, &Instance->Name);
    ExReleaseResourceLite(&Volume->InstanceList.rLock);
    KeLeaveCriticalRegion();
    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(Instance, FM_TAG_INSTANCE);
        return Status;
    }

    /* Let the filter decide whether it wants this volume */
    if (Filter->InstanceSetup)
    {
        InitRelatedObjects(&Objects, Instance);
        Status = Filter->InstanceSetup(&Objects,
                                       SetupFlags,
                                       Volume->DeviceObject->DeviceType,
                                       Volume->FileSystemType);
        if (!NT_SUCCESS(Status))
        {
            FltpTeardownInstanceContexts(Instance);
            ExFreePoolWithTag(Instance, FM_TAG_INSTANCE);

            /* The filter saying no isn't an error as such, but the caller needs to know */
            return Status;
        }
    }

    /* Wire it into the volume and the filter, this is where altitude collisions show up */
    Status = InsertInstance(Volume, Instance);
    if (!NT_SUCCESS(Status))
    {
        FltpTeardownInstanceContexts(Instance);
        ExFreePoolWithTag(Instance, FM_TAG_INSTANCE);
        return Status;
    }

    if (RetInstance)
    {
        /* The caller gets a reference */
        if (!NT_SUCCESS(FltObjectReference(Instance)))
            *RetInstance = NULL;
        else
            *RetInstance = Instance;
    }

    return STATUS_SUCCESS;
}

/*
 * Detaches an instance: no new operation reaches it, the filter is told, the operations
 * which are in flight are waited for, the filter is told again, and the instance is freed.
 * The caller passes in a reference on the instance (from FltObjectReference), which is
 * consumed here: the instance can't go away while the caller looks at it, and the wait
 * for the references mustn't wait for the caller.
 */
VOID
FltpTeardownInstance(_In_ PFLT_INSTANCE Instance,
                     _In_ ULONG Reason)
{
    FLT_RELATED_OBJECTS Objects;
    PFLT_VOLUME Volume = Instance->Volume;
    PFLT_FILTER Filter = Instance->Filter;

    PAGED_CODE();

    /* Whoever sets the flag first does the work */
    if (InterlockedOr((PLONG)&Instance->Flags, INSFL_DELETING) & INSFL_DELETING)
    {
        FltObjectDereference(Instance);
        return;
    }

    /* No new operation takes the instance from here on */
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&Volume->InstanceList.rLock, TRUE);
    if (!IsListEmpty(&Instance->VolumeLink))
    {
        RemoveEntryList(&Instance->VolumeLink);
        InitializeListHead(&Instance->VolumeLink);
        Volume->InstanceList.rCount--;
        UpdateVolumeCallbackCounts(Volume, Filter, -1);
    }
    ExReleaseResourceLite(&Volume->InstanceList.rLock);

    ExAcquireResourceExclusiveLite(&Filter->InstanceList.rLock, TRUE);
    if (!IsListEmpty(&Instance->FilterLink))
    {
        RemoveEntryList(&Instance->FilterLink);
        InitializeListHead(&Instance->FilterLink);
        Filter->InstanceList.rCount--;
    }
    ExReleaseResourceLite(&Filter->InstanceList.rLock);
    KeLeaveCriticalRegion();

    InitRelatedObjects(&Objects, Instance);
    if (Filter->InstanceTeardownStart)
        Filter->InstanceTeardownStart(&Objects, Reason);

    /* Wait for the operations and the references of the filter to go */
    FltObjectDereference(Instance);
    FltpObjectRundownWait(&Instance->Base.RundownRef);

    if (Filter->InstanceTeardownComplete)
        Filter->InstanceTeardownComplete(&Objects, Reason);

    /* Whatever the filter attached to the instance goes now */
    FltpTeardownInstanceContexts(Instance);

    FltpExRundownCompleted(&Instance->Base.RundownRef);
    ExFreePoolWithTag(Instance, FM_TAG_INSTANCE);
}

/* Takes every instance of a filter down. Used by FltUnregisterFilter. */
VOID
FltpTeardownFilterInstances(_In_ PFLT_FILTER Filter,
                            _In_ ULONG Reason)
{
    PFLT_INSTANCE Instance;
    PLIST_ENTRY Entry;

    PAGED_CODE();

    for (;;)
    {
        Instance = NULL;

        /* Find an instance which is still around. Teardown takes it off the list */
        KeEnterCriticalRegion();
        ExAcquireResourceSharedLite(&Filter->InstanceList.rLock, TRUE);
        for (Entry = Filter->InstanceList.rList.Flink;
             Entry != &Filter->InstanceList.rList;
             Entry = Entry->Flink)
        {
            PFLT_INSTANCE Candidate = CONTAINING_RECORD(Entry, FLT_INSTANCE, FilterLink);
            if (!(Candidate->Flags & INSFL_DELETING) && NT_SUCCESS(FltObjectReference(Candidate)))
            {
                Instance = Candidate;
                break;
            }
        }
        ExReleaseResourceLite(&Filter->InstanceList.rLock);
        KeLeaveCriticalRegion();

        if (Instance == NULL)
            break;

        FltpTeardownInstance(Instance, Reason);
    }

    /* Another teardown (volume dismount) may still be on its way out of the list */
    for (;;)
    {
        BOOLEAN Empty;

        KeEnterCriticalRegion();
        ExAcquireResourceSharedLite(&Filter->InstanceList.rLock, TRUE);
        Empty = IsListEmpty(&Filter->InstanceList.rList);
        ExReleaseResourceLite(&Filter->InstanceList.rLock);
        KeLeaveCriticalRegion();

        if (Empty)
            break;

        KeDelayExecutionThread(KernelMode, FALSE, &(LARGE_INTEGER){ .QuadPart = -100000 });
    }
}

VOID
FltpTeardownVolumeInstances(_In_ PFLT_VOLUME Volume,
                            _In_ ULONG Reason)
{
    PFLT_INSTANCE Instance;
    PLIST_ENTRY Entry;

    PAGED_CODE();

    for (;;)
    {
        Instance = NULL;

        KeEnterCriticalRegion();
        ExAcquireResourceSharedLite(&Volume->InstanceList.rLock, TRUE);
        for (Entry = Volume->InstanceList.rList.Flink;
             Entry != &Volume->InstanceList.rList;
             Entry = Entry->Flink)
        {
            PFLT_INSTANCE Candidate = CONTAINING_RECORD(Entry, FLT_INSTANCE, VolumeLink);
            if (!(Candidate->Flags & INSFL_DELETING) && NT_SUCCESS(FltObjectReference(Candidate)))
            {
                Instance = Candidate;
                break;
            }
        }
        ExReleaseResourceLite(&Volume->InstanceList.rLock);
        KeLeaveCriticalRegion();

        if (Instance == NULL)
            break;

        FltpTeardownInstance(Instance, Reason);
    }
}


/* EXPORTED FUNCTIONS *******************************************************/

NTSTATUS
FLTAPI
FltAttachVolume(_Inout_ PFLT_FILTER Filter,
                _Inout_ PFLT_VOLUME Volume,
                _In_opt_ PCUNICODE_STRING InstanceName,
                _Outptr_opt_result_maybenull_ PFLT_INSTANCE *RetInstance)
{
    NTSTATUS Status;

    PAGED_CODE();

    Status = FltpAttachInstance(Filter,
                                Volume,
                                NULL,
                                InstanceName,
                                FLTFL_INSTANCE_SETUP_MANUAL_ATTACHMENT,
                                RetInstance);
    return Status;
}

NTSTATUS
FLTAPI
FltDetachVolume(_Inout_ PFLT_FILTER Filter,
                _Inout_ PFLT_VOLUME Volume,
                _In_opt_ PCUNICODE_STRING InstanceName)
{
    FLT_RELATED_OBJECTS Objects;
    PFLT_INSTANCE Instance = NULL;
    PLIST_ENTRY Entry;
    NTSTATUS Status;

    PAGED_CODE();

    /* Look for the instance of this filter, by name if we got one */
    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&Volume->InstanceList.rLock, TRUE);
    for (Entry = Volume->InstanceList.rList.Flink;
         Entry != &Volume->InstanceList.rList;
         Entry = Entry->Flink)
    {
        PFLT_INSTANCE Candidate = CONTAINING_RECORD(Entry, FLT_INSTANCE, VolumeLink);

        if (Candidate->Filter != Filter)
            continue;

        if (InstanceName && !RtlEqualUnicodeString(&Candidate->Name, InstanceName, TRUE))
            continue;

        if (NT_SUCCESS(FltObjectReference(Candidate)))
            Instance = Candidate;
        break;
    }
    ExReleaseResourceLite(&Volume->InstanceList.rLock);
    KeLeaveCriticalRegion();

    if (Instance == NULL)
        return STATUS_FLT_INSTANCE_NOT_FOUND;

    /* A manual detach is a request the filter may refuse */
    if (Filter->InstanceQueryTeardown)
    {
        InitRelatedObjects(&Objects, Instance);
        Status = Filter->InstanceQueryTeardown(&Objects, 0);
        if (!NT_SUCCESS(Status))
        {
            FltObjectDereference(Instance);
            return Status;
        }
    }

    /* The teardown consumes our reference */
    FltpTeardownInstance(Instance, FLTFL_INSTANCE_TEARDOWN_MANUAL);
    return STATUS_SUCCESS;
}

NTSTATUS
FLTAPI
FltEnumerateInstances(_In_opt_ PFLT_VOLUME Volume,
                      _In_opt_ PFLT_FILTER Filter,
                      _Out_writes_to_opt_(InstanceListSize, *NumberInstancesReturned) PFLT_INSTANCE *InstanceList,
                      _In_ ULONG InstanceListSize,
                      _Out_ PULONG NumberInstancesReturned)
{
    PFLT_RESOURCE_LIST_HEAD Head;
    PLIST_ENTRY Entry;
    ULONG Total = 0, i;
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();

    /* One of the two at least selects the list. Without either we'd need the global instance list */
    if (Volume == NULL && Filter == NULL)
        return STATUS_INVALID_PARAMETER;

    Head = Volume ? &Volume->InstanceList : &Filter->InstanceList;

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&Head->rLock, TRUE);
    for (Entry = Head->rList.Flink; Entry != &Head->rList; Entry = Entry->Flink)
    {
        PFLT_INSTANCE Instance;

        Instance = Volume ? CONTAINING_RECORD(Entry, FLT_INSTANCE, VolumeLink) :
                            CONTAINING_RECORD(Entry, FLT_INSTANCE, FilterLink);

        if (Instance->Flags & INSFL_DELETING)
            continue;

        /* Both given: the instances of the filter on the volume */
        if ((Volume && Filter && Instance->Filter != Filter) ||
            (Volume && Filter == NULL && FALSE))
        {
            continue;
        }

        if (InstanceList && Total < InstanceListSize)
        {
            if (!NT_SUCCESS(FltObjectReference(Instance)))
                continue;
            InstanceList[Total] = Instance;
        }
        Total++;
    }
    ExReleaseResourceLite(&Head->rLock);
    KeLeaveCriticalRegion();

    if (Total > InstanceListSize)
    {
        /* Return nothing partial */
        for (i = 0; InstanceList && i < InstanceListSize; i++)
        {
            FltObjectDereference(InstanceList[i]);
            InstanceList[i] = NULL;
        }
        Status = STATUS_BUFFER_TOO_SMALL;
    }

    *NumberInstancesReturned = Total;
    return Status;
}

NTSTATUS
FLTAPI
FltGetFilterFromInstance(_In_ PFLT_INSTANCE Instance,
                         _Outptr_ PFLT_FILTER *RetFilter)
{
    NTSTATUS Status;

    *RetFilter = NULL;
    Status = FltObjectReference(Instance->Filter);
    if (NT_SUCCESS(Status))
        *RetFilter = Instance->Filter;
    return Status;
}

NTSTATUS
FLTAPI
FltGetVolumeFromInstance(_In_ PFLT_INSTANCE Instance,
                         _Outptr_ PFLT_VOLUME *RetVolume)
{
    NTSTATUS Status;

    *RetVolume = NULL;
    Status = FltObjectReference(Instance->Volume);
    if (NT_SUCCESS(Status))
        *RetVolume = Instance->Volume;
    return Status;
}

/* The instances above and below an instance on the same volume, by altitude */
static
NTSTATUS
GetNeighbour(_In_ PFLT_INSTANCE Instance,
             _In_ BOOLEAN Upper,
             _Outptr_ PFLT_INSTANCE *RetInstance)
{
    PFLT_VOLUME Volume = Instance->Volume;
    PLIST_ENTRY Entry;
    NTSTATUS Status = STATUS_NO_MORE_ENTRIES;

    *RetInstance = NULL;

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&Volume->InstanceList.rLock, TRUE);
    if (!IsListEmpty(&Instance->VolumeLink))
    {
        /* The list runs from high to low altitude */
        Entry = Upper ? Instance->VolumeLink.Blink : Instance->VolumeLink.Flink;
        if (Entry != &Volume->InstanceList.rList)
        {
            PFLT_INSTANCE Other = CONTAINING_RECORD(Entry, FLT_INSTANCE, VolumeLink);
            Status = FltObjectReference(Other);
            if (NT_SUCCESS(Status))
                *RetInstance = Other;
        }
    }
    ExReleaseResourceLite(&Volume->InstanceList.rLock);
    KeLeaveCriticalRegion();

    return Status;
}

NTSTATUS
FLTAPI
FltGetUpperInstance(_In_ PFLT_INSTANCE CurrentInstance,
                    _Outptr_ PFLT_INSTANCE *RetInstance)
{
    return GetNeighbour(CurrentInstance, TRUE, RetInstance);
}

NTSTATUS
FLTAPI
FltGetLowerInstance(_In_ PFLT_INSTANCE CurrentInstance,
                    _Outptr_ PFLT_INSTANCE *RetInstance)
{
    return GetNeighbour(CurrentInstance, FALSE, RetInstance);
}

NTSTATUS
FLTAPI
FltGetTopInstance(_In_ PFLT_VOLUME Volume,
                  _Outptr_ PFLT_INSTANCE *RetInstance)
{
    NTSTATUS Status = STATUS_NO_MORE_ENTRIES;

    *RetInstance = NULL;

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&Volume->InstanceList.rLock, TRUE);
    if (!IsListEmpty(&Volume->InstanceList.rList))
    {
        PFLT_INSTANCE Instance = CONTAINING_RECORD(Volume->InstanceList.rList.Flink, FLT_INSTANCE, VolumeLink);
        Status = FltObjectReference(Instance);
        if (NT_SUCCESS(Status))
            *RetInstance = Instance;
    }
    ExReleaseResourceLite(&Volume->InstanceList.rLock);
    KeLeaveCriticalRegion();

    return Status;
}

NTSTATUS
FLTAPI
FltGetBottomInstance(_In_ PFLT_VOLUME Volume,
                     _Outptr_ PFLT_INSTANCE *RetInstance)
{
    NTSTATUS Status = STATUS_NO_MORE_ENTRIES;

    *RetInstance = NULL;

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&Volume->InstanceList.rLock, TRUE);
    if (!IsListEmpty(&Volume->InstanceList.rList))
    {
        PFLT_INSTANCE Instance = CONTAINING_RECORD(Volume->InstanceList.rList.Blink, FLT_INSTANCE, VolumeLink);
        Status = FltObjectReference(Instance);
        if (NT_SUCCESS(Status))
            *RetInstance = Instance;
    }
    ExReleaseResourceLite(&Volume->InstanceList.rLock);
    KeLeaveCriticalRegion();

    return Status;
}
