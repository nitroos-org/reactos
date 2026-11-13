/*
* PROJECT:         Filesystem Filter Manager
* LICENSE:         GPL - See COPYING in the top level directory
* FILE:            drivers/filters/fltmgr/Filter.c
* PURPOSE:         Handles registration of mini filters
* PROGRAMMERS:     Ged Murphy (gedmurphy@reactos.org)
*/

/* INCLUDES ******************************************************************/

#include "fltmgr.h"
#include "fltmgrint.h"
#include "fltmgrproto.h"
#include "Registry.h"

#define NDEBUG
#include <debug.h>


/* DATA *********************************************************************/

#define SERVICES_KEY L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\"
#define MAX_KEY_LENGTH  0x200

/* All registered mini-filters, ordered by altitude (highest first) */
LIST_ENTRY FilterList;
/* Protects FilterList and FltpVolumeList */
ERESOURCE FilterListLock;

/*
 * Per driver object data, allocated with IoAllocateDriverObjectExtension so the I/O manager
 * frees it when the driver object goes away. It remembers the DriverUnload routine the
 * mini-filter had before we hooked it.
 */
typedef struct _FLTP_DRIVER_EXTENSION
{
    PDRIVER_UNLOAD OldDriverUnload;

} FLTP_DRIVER_EXTENSION, *PFLTP_DRIVER_EXTENSION;

static CHAR FltpDriverExtensionKey;

static
VOID
NTAPI
FltpMiniFilterDriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
);

static
NTSTATUS
FltpStartingToDrainObject(
    _Inout_ PFLT_OBJECT Object
);

static
NTSTATUS
GetFilterAltitude(
    _In_ PFLT_FILTER Filter,
    _Inout_ PUNICODE_STRING AltitudeString,
    _Inout_ PUNICODE_STRING InstanceName
);


/* EXPORTED FUNCTIONS ******************************************************/

NTSTATUS
NTAPI
FltLoadFilter(_In_ PCUNICODE_STRING FilterName)
{
    UNICODE_STRING DriverServiceName;
    UNICODE_STRING ServicesKey;
    CHAR Buffer[MAX_KEY_LENGTH];

    /* Setup the base services key */
    RtlInitUnicodeString(&ServicesKey, SERVICES_KEY);

    /* Initialize the string data */
    DriverServiceName.Length = 0;
    DriverServiceName.Buffer = (PWCH)Buffer;
    DriverServiceName.MaximumLength = MAX_KEY_LENGTH;

    /* Create the full service key for this filter */
    RtlCopyUnicodeString(&DriverServiceName, &ServicesKey);
    RtlAppendUnicodeStringToString(&DriverServiceName, FilterName);

    /* Ask the kernel to load it for us */
    return ZwLoadDriver(&DriverServiceName);
}

NTSTATUS
NTAPI
FltUnloadFilter(_In_ PCUNICODE_STRING FilterName)
{
    UNICODE_STRING DriverServiceName;
    UNICODE_STRING ServicesKey;
    PFLT_FILTER_UNLOAD_CALLBACK UnloadCallback = NULL;
    PLIST_ENTRY Entry;
    PFLT_FILTER Filter;
    BOOLEAN Found = FALSE;
    CHAR Buffer[MAX_KEY_LENGTH];
    NTSTATUS Status;

    PAGED_CODE();

    /* Lookup the filter and take a copy of what we need. We must not hold a
     * reference across the callback, since it is going to unregister the filter */
    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&FilterListLock, TRUE);
    for (Entry = FilterList.Flink; Entry != &FilterList; Entry = Entry->Flink)
    {
        Filter = CONTAINING_RECORD(Entry, FLT_FILTER, GlobalLink);
        if (RtlEqualUnicodeString(&Filter->Name, FilterName, TRUE))
        {
            Found = TRUE;
            UnloadCallback = Filter->FilterUnload;
            break;
        }
    }
    ExReleaseResourceLite(&FilterListLock);
    KeLeaveCriticalRegion();

    if (Found)
    {
        /* A mini-filter without an unload callback can't be unloaded */
        if (UnloadCallback == NULL)
            return STATUS_INVALID_DEVICE_REQUEST;

        /* Ask the mini-filter if it agrees. On success it unregisters itself */
        Status = UnloadCallback(0);
        if (!NT_SUCCESS(Status))
            return Status;
    }

    /* Setup the base services key */
    RtlInitUnicodeString(&ServicesKey, SERVICES_KEY);

    /* Initialize the string data */
    DriverServiceName.Length = 0;
    DriverServiceName.Buffer = (PWCH)Buffer;
    DriverServiceName.MaximumLength = MAX_KEY_LENGTH;

    /* Create the full service key for this filter */
    RtlCopyUnicodeString(&DriverServiceName, &ServicesKey);
    RtlAppendUnicodeStringToString(&DriverServiceName, FilterName);
    return ZwUnloadDriver(&DriverServiceName);
}

NTSTATUS
NTAPI
FltRegisterFilter(_In_ PDRIVER_OBJECT DriverObject,
                  _In_ const FLT_REGISTRATION *Registration,
                  _Out_ PFLT_FILTER *RetFilter)
{
    PFLT_OPERATION_REGISTRATION Callbacks;
    PFLT_OPERATION_REGISTRATION Op;
    PFLTP_DRIVER_EXTENSION DriverExtension;
    PFLT_FILTER Filter;
    PFLT_FILTER Other;
    PLIST_ENTRY Entry;
    ULONG CallbackBufferSize;
    ULONG FilterBufferSize;
    ULONG Count = 0;
    PCHAR Ptr;
    NTSTATUS Status;

    PAGED_CODE();

    *RetFilter = NULL;

    /* Make sure we're targeting the correct major revision */
    if ((Registration->Version & 0xFF00) != FLT_MAJOR_VERSION)
    {
        return STATUS_INVALID_PARAMETER;
    }

    /* Make sure our namespace callbacks are valid */
    if ((!Registration->GenerateFileNameCallback && Registration->NormalizeNameComponentCallback) ||
        (!Registration->NormalizeNameComponentCallback && Registration->NormalizeContextCleanupCallback))
    {
        return STATUS_INVALID_PARAMETER;
    }

    /* Count the number of operations that were requested, including the terminator */
    Callbacks = (PFLT_OPERATION_REGISTRATION)Registration->OperationRegistration;
    while (Callbacks)
    {
        Count++;

        /* Bail when we find the last one */
        if (Callbacks->MajorFunction == IRP_MJ_OPERATION_END)
            break;

        /* A registration needs a pre or a post callback */
        if (Callbacks->PreOperation == NULL && Callbacks->PostOperation == NULL)
            return STATUS_INVALID_PARAMETER;

        /* Move to the next item */
        Callbacks++;
    }

    /* Calculate the buffer sizes */
    CallbackBufferSize = Count * sizeof(FLT_OPERATION_REGISTRATION);
    FilterBufferSize = sizeof(FLT_FILTER) +
                       CallbackBufferSize +
                       DriverObject->DriverExtension->ServiceKeyName.Length;

    /* Allocate a buffer to hold our filter data */
    Filter = ExAllocatePoolWithTag(NonPagedPool,
                                   FilterBufferSize,
                                   FM_TAG_FILTER);
    if (Filter == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(Filter, FilterBufferSize);

    /* Find the end of the fixed struct */
    Ptr = (PCHAR)(Filter + 1);

    /* Store a copy of the driver object of this filter */
    Filter->DriverObject = DriverObject;

    /* Initialize the base object data */
    Filter->Base.Flags = FLT_OBFL_TYPE_FILTER;
    Filter->Base.PointerCount = 1;
    FltpExInitializeRundownProtection(&Filter->Base.RundownRef);
    InitializeListHead(&Filter->GlobalLink);

    /* Set the callback addresses */
    Filter->RegistrationFlags = Registration->Flags;
    Filter->FilterUnload = Registration->FilterUnloadCallback;
    Filter->InstanceSetup = Registration->InstanceSetupCallback;
    Filter->InstanceQueryTeardown = Registration->InstanceQueryTeardownCallback;
    Filter->InstanceTeardownStart = Registration->InstanceTeardownStartCallback;
    Filter->InstanceTeardownComplete = Registration->InstanceTeardownCompleteCallback;
    Filter->GenerateFileName = Registration->GenerateFileNameCallback;
    Filter->NormalizeNameComponent = Registration->NormalizeNameComponentCallback;
    Filter->NormalizeContextCleanup = Registration->NormalizeContextCleanupCallback;

    /* Initialize the instance list */
    ExInitializeResourceLite(&Filter->InstanceList.rLock);
    InitializeListHead(&Filter->InstanceList.rList);
    Filter->InstanceList.rCount = 0;

    ExInitializeFastMutex(&Filter->ActiveOpens.mLock);
    InitializeListHead(&Filter->ActiveOpens.mList);
    Filter->ActiveOpens.mCount = 0;

    ExInitializeFastMutex(&Filter->ConnectionList.mLock);
    InitializeListHead(&Filter->ConnectionList.mList);
    Filter->ConnectionList.mCount = 0;

    /* Initialize the usermode port list */
    ExInitializeFastMutex(&Filter->PortList.mLock);
    InitializeListHead(&Filter->PortList.mList);
    Filter->PortList.mCount = 0;

    /* Check if the caller requested any context data */
    Status = STATUS_SUCCESS;
    if (Registration->ContextRegistration)
    {
        /* Register the contexts for this filter */
        Status = FltpRegisterContexts(Filter, Registration->ContextRegistration);
        if (!NT_SUCCESS(Status))
        {
            goto Quit;
        }
    }

    /* Add the filter name buffer onto the end of the data and fill in the string */
    Filter->Name.Length = 0;
    Filter->Name.MaximumLength = DriverObject->DriverExtension->ServiceKeyName.Length;
    Filter->Name.Buffer = (PWCH)(Ptr + CallbackBufferSize);
    RtlCopyUnicodeString(&Filter->Name, &DriverObject->DriverExtension->ServiceKeyName);

    /* Check if the caller is registering any callbacks */
    if (Registration->OperationRegistration)
    {
        /* The callback data comes after the fixed struct */
        Filter->Operations = (PFLT_OPERATION_REGISTRATION)Ptr;

        /* Tag the operation data onto the end of the filter data */
        RtlCopyMemory(Filter->Operations, Registration->OperationRegistration, CallbackBufferSize);

        /* walk through the requested callbacks */
        for (Op = Filter->Operations;
             Op->MajorFunction != IRP_MJ_OPERATION_END;
             Op++)
        {
            // http://fsfilters.blogspot.co.uk/2011/03/how-file-system-filters-attach-to_17.html
            /* Check if this is an attach to a volume */
            if (Op->MajorFunction == IRP_MJ_VOLUME_MOUNT)
            {
                Filter->PreVolumeMount = Op->PreOperation;
                Filter->PostVolumeMount = Op->PostOperation;
            }
            else if (Op->MajorFunction == IRP_MJ_SHUTDOWN)
            {
                /* There is no post-operation for shutdown */
                Op->PostOperation = NULL;
            }

            /* Index the operations we can dispatch IRPs for */
            if (Op->MajorFunction <= IRP_MJ_MAXIMUM_FUNCTION)
            {
                Filter->OperationTable[Op->MajorFunction] = Op;
            }
        }
    }

    /* Lookup the altitude of the mini-filter */
    Status = GetFilterAltitude(Filter,
                               &Filter->DefaultAltitude,
                               &Filter->DefaultInstanceName);
    if (!NT_SUCCESS(Status))
    {
        goto Quit;
    }

    /* Remember the original unload routine of this driver, we need it after the filter is gone */
    Filter->OldDriverUnload = (PFLT_FILTER_UNLOAD_CALLBACK)DriverObject->DriverUnload;
    if (DriverObject->DriverUnload != FltpMiniFilterDriverUnload)
    {
        Status = IoAllocateDriverObjectExtension(DriverObject,
                                                 &FltpDriverExtensionKey,
                                                 sizeof(FLTP_DRIVER_EXTENSION),
                                                 (PVOID *)&DriverExtension);
        if (Status == STATUS_OBJECT_NAME_COLLISION)
        {
            /* Registered before, and the driver has set a new DriverUnload since */
            DriverExtension = IoGetDriverObjectExtension(DriverObject, &FltpDriverExtensionKey);
            Status = STATUS_SUCCESS;
        }
        if (!NT_SUCCESS(Status))
        {
            goto Quit;
        }
        DriverExtension->OldDriverUnload = DriverObject->DriverUnload;
    }
    else
    {
        /* We hooked it already and the extension holds the original routine */
        DriverExtension = IoGetDriverObjectExtension(DriverObject, &FltpDriverExtensionKey);
        Filter->OldDriverUnload = DriverExtension ? (PFLT_FILTER_UNLOAD_CALLBACK)DriverExtension->OldDriverUnload : NULL;
    }

    /* Add the filter to the global list, sorted by altitude */
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&FilterListLock, TRUE);

    for (Entry = FilterList.Flink; Entry != &FilterList; Entry = Entry->Flink)
    {
        Other = CONTAINING_RECORD(Entry, FLT_FILTER, GlobalLink);

        /* The same driver can't register twice */
        if (Other->DriverObject == DriverObject ||
            RtlEqualUnicodeString(&Other->Name, &Filter->Name, TRUE))
        {
            Status = STATUS_FLT_INSTANCE_ALTITUDE_COLLISION;
            break;
        }
    }

    if (NT_SUCCESS(Status))
    {
        for (Entry = FilterList.Flink; Entry != &FilterList; Entry = Entry->Flink)
        {
            Other = CONTAINING_RECORD(Entry, FLT_FILTER, GlobalLink);
            if (FltpCompareAltitudeStrings(&Filter->DefaultAltitude, &Other->DefaultAltitude) > 0)
                break;
        }

        /* Insert before the first filter with a lower altitude, or at the tail */
        InsertTailList(Entry, &Filter->GlobalLink);
    }

    ExReleaseResourceLite(&FilterListLock);
    KeLeaveCriticalRegion();

    if (!NT_SUCCESS(Status))
    {
        goto Quit;
    }

    /* Check we opted not to have an unload routine, or if we want to stop the driver from being unloaded */
    if (Registration->FilterUnloadCallback && !FlagOn(Registration->Flags, FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP))
    {
        DriverObject->DriverUnload = FltpMiniFilterDriverUnload;
    }
    else
    {
        DriverObject->DriverUnload = NULL;
    }

Quit:

    if (NT_SUCCESS(Status))
    {
        DPRINT("Loaded FS mini-filter %wZ\n", &DriverObject->DriverExtension->ServiceKeyName);
        *RetFilter = Filter;
    }
    else
    {
        DPRINT1("Failed to load FS mini-filter %wZ : 0x%X\n", &DriverObject->DriverExtension->ServiceKeyName, Status);

        FltpFreeUnicodeString(&Filter->DefaultAltitude);
        FltpFreeUnicodeString(&Filter->DefaultInstanceName);
        ExDeleteResourceLite(&Filter->InstanceList.rLock);
        ExFreePoolWithTag(Filter, FM_TAG_FILTER);
    }

    return Status;
}

VOID
FLTAPI
FltUnregisterFilter(_In_ PFLT_FILTER Filter)
{
    NTSTATUS Status;

    PAGED_CODE();

    /* Set the draining flag */
    Status = FltpStartingToDrainObject(&Filter->Base);
    if (!NT_SUCCESS(Status))
    {
        /* Someone already unregistered us */
        return;
    }

    /* Stop new instances being created and sent operations by taking it off the list */
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&FilterListLock, TRUE);
    RemoveEntryList(&Filter->GlobalLink);
    InitializeListHead(&Filter->GlobalLink);
    ExReleaseResourceLite(&FilterListLock);
    KeLeaveCriticalRegion();

    /* Detach every instance, waiting for the operations in flight */
    FltpTeardownFilterInstances(Filter, FLTFL_INSTANCE_TEARDOWN_FILTER_UNLOAD);

    /* Wait until we're sure nothing else is using the filter (open ports) */
    FltpObjectRundownWait(&Filter->Base.RundownRef);

    /* We're finished cleaning up now */
    FltpExRundownCompleted(&Filter->Base.RundownRef);

    /* Hand the memory back */
    ExDeleteResourceLite(&Filter->InstanceList.rLock);
    FltpFreeUnicodeString(&Filter->DefaultAltitude);
    FltpFreeUnicodeString(&Filter->DefaultInstanceName);
    ExFreePoolWithTag(Filter, FM_TAG_FILTER);
}

NTSTATUS
NTAPI
FltStartFiltering(_In_ PFLT_FILTER Filter)
{
    PFLT_VOLUME *Volumes;
    ULONG Count, i;
    NTSTATUS Status;

    PAGED_CODE();

    /* Grab a ref to the filter */
    Status = FltObjectReference(&Filter->Base);
    if (!NT_SUCCESS(Status))
        return Status;

    /* Make sure we aren't already starting up */
    if (InterlockedOr((PLONG)&Filter->Flags, FLTFL_FILTERING_INITIATED) & FLTFL_FILTERING_INITIATED)
    {
        FltObjectDereference(&Filter->Base);
        return STATUS_INVALID_PARAMETER;
    }

    /* Create instances on the volumes we know about */
    Status = FltpSnapshotVolumes(&Volumes, &Count);
    if (NT_SUCCESS(Status))
    {
        for (i = 0; i < Count; i++)
        {
            /* A volume rejecting the filter is not an error of starting it */
            (VOID)FltpAttachFilterToVolume(Filter,
                                           Volumes[i],
                                           FLTFL_INSTANCE_SETUP_AUTOMATIC_ATTACHMENT);
        }

        FltpFreeVolumeSnapshot(Volumes, Count);
    }

    FltObjectDereference(&Filter->Base);
    return Status;
}

NTSTATUS
NTAPI
FltGetFilterFromName(_In_ PCUNICODE_STRING FilterName,
                     _Out_ PFLT_FILTER *RetFilter)
{
    PLIST_ENTRY Entry;
    PFLT_FILTER Filter;
    NTSTATUS Status = STATUS_FLT_FILTER_NOT_FOUND;

    PAGED_CODE();

    *RetFilter = NULL;

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&FilterListLock, TRUE);
    for (Entry = FilterList.Flink; Entry != &FilterList; Entry = Entry->Flink)
    {
        Filter = CONTAINING_RECORD(Entry, FLT_FILTER, GlobalLink);
        if (RtlEqualUnicodeString(&Filter->Name, FilterName, TRUE))
        {
            /* The caller owns a reference and must call FltObjectDereference */
            Status = FltObjectReference(Filter);
            if (NT_SUCCESS(Status))
                *RetFilter = Filter;
            break;
        }
    }
    ExReleaseResourceLite(&FilterListLock);
    KeLeaveCriticalRegion();

    return Status;
}

LONG
FLTAPI
FltCompareInstanceAltitudes(_In_ PFLT_INSTANCE Instance1,
                            _In_ PFLT_INSTANCE Instance2)
{
    return FltpCompareAltitudeStrings(&Instance1->Altitude, &Instance2->Altitude);
}


/* INTERNAL FUNCTIONS ******************************************************/

/*
 * Altitudes are strings of decimal digits with an optional fraction ("329998", "41200.5").
 * They compare as decimal numbers, not as strings: "9" is below "10", and "10.0" equals "10".
 */
LONG
FltpCompareAltitudeStrings(_In_ PCUNICODE_STRING Altitude1,
                           _In_ PCUNICODE_STRING Altitude2)
{
    PCWSTR A = Altitude1->Buffer, B = Altitude2->Buffer;
    ULONG LenA = Altitude1->Length / sizeof(WCHAR);
    ULONG LenB = Altitude2->Length / sizeof(WCHAR);
    ULONG IntA = 0, IntB = 0, FracA, FracB, i;

    /* Find the end of the integer parts */
    while (IntA < LenA && A[IntA] != L'.') IntA++;
    while (IntB < LenB && B[IntB] != L'.') IntB++;

    /* Skip the leading zeroes of the integer parts */
    i = 0;
    while (i < IntA && A[i] == L'0') i++;
    A += i; IntA -= i; LenA -= i;
    i = 0;
    while (i < IntB && B[i] == L'0') i++;
    B += i; IntB -= i; LenB -= i;

    /* More digits means a bigger number */
    if (IntA != IntB)
        return (IntA > IntB) ? 1 : -1;

    for (i = 0; i < IntA; i++)
    {
        if (A[i] != B[i])
            return (A[i] > B[i]) ? 1 : -1;
    }

    /* The fractions compare digit by digit, a missing digit is a zero */
    FracA = (IntA < LenA) ? IntA + 1 : LenA;
    FracB = (IntB < LenB) ? IntB + 1 : LenB;
    while (FracA < LenA || FracB < LenB)
    {
        WCHAR DigitA = (FracA < LenA) ? A[FracA++] : L'0';
        WCHAR DigitB = (FracB < LenB) ? B[FracB++] : L'0';

        if (DigitA != DigitB)
            return (DigitA > DigitB) ? 1 : -1;
    }

    return 0;
}

/* Takes a reference on every filter which is not going away, highest altitude first */
NTSTATUS
FltpSnapshotFilters(_Outptr_result_buffer_(*Count) PFLT_FILTER **Filters,
                    _Out_ PULONG Count)
{
    PFLT_FILTER *Array;
    PLIST_ENTRY Entry;
    ULONG Number = 0;
    PFLT_FILTER Filter;

    *Filters = NULL;
    *Count = 0;

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&FilterListLock, TRUE);

    for (Entry = FilterList.Flink; Entry != &FilterList; Entry = Entry->Flink)
        Number++;

    if (Number == 0)
    {
        ExReleaseResourceLite(&FilterListLock);
        KeLeaveCriticalRegion();
        return STATUS_SUCCESS;
    }

    Array = ExAllocatePoolWithTag(NonPagedPool, Number * sizeof(PFLT_FILTER), FM_TAG_FILTER);
    if (Array == NULL)
    {
        ExReleaseResourceLite(&FilterListLock);
        KeLeaveCriticalRegion();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Number = 0;
    for (Entry = FilterList.Flink; Entry != &FilterList; Entry = Entry->Flink)
    {
        Filter = CONTAINING_RECORD(Entry, FLT_FILTER, GlobalLink);
        if (NT_SUCCESS(FltObjectReference(Filter)))
            Array[Number++] = Filter;
    }

    ExReleaseResourceLite(&FilterListLock);
    KeLeaveCriticalRegion();

    *Filters = Array;
    *Count = Number;
    return STATUS_SUCCESS;
}

VOID
FltpFreeFilterSnapshot(_In_ PFLT_FILTER *Filters,
                       _In_ ULONG Count)
{
    ULONG i;

    if (Filters == NULL)
        return;

    for (i = 0; i < Count; i++)
        FltObjectDereference(Filters[i]);

    ExFreePoolWithTag(Filters, FM_TAG_FILTER);
}

static
NTSTATUS
FltpStartingToDrainObject(_Inout_ PFLT_OBJECT Object)
{
    /*
     * Set the draining flag for the filter. This let's us force
     * a post op callback for minifilters currently awaiting one.
     */
    if (InterlockedOr((PLONG)&Object->Flags, FLT_OBFL_DRAINING) & FLT_OBFL_DRAINING)
    {
        /* We've been called once, we're already being deleted */
        return STATUS_FLT_DELETING_OBJECT;
    }

    return STATUS_SUCCESS;
}

/*
 * The DriverUnload routine of an unloadable mini-filter. FltUnloadFilter normally asks the
 * filter first, but a plain service stop ends up here, with the filter possibly still registered.
 */
static
VOID
NTAPI
FltpMiniFilterDriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    PFLTP_DRIVER_EXTENSION DriverExtension;
    PFLT_FILTER_UNLOAD_CALLBACK UnloadCallback = NULL;
    PFLT_FILTER Filter = NULL, Current;
    PLIST_ENTRY Entry;
    PDRIVER_UNLOAD OldUnload = NULL;

    PAGED_CODE();

    DriverExtension = IoGetDriverObjectExtension(DriverObject, &FltpDriverExtensionKey);
    if (DriverExtension)
        OldUnload = DriverExtension->OldDriverUnload;

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&FilterListLock, TRUE);
    for (Entry = FilterList.Flink; Entry != &FilterList; Entry = Entry->Flink)
    {
        Current = CONTAINING_RECORD(Entry, FLT_FILTER, GlobalLink);
        if (Current->DriverObject == DriverObject)
        {
            Filter = Current;
            UnloadCallback = Current->FilterUnload;
            break;
        }
    }
    ExReleaseResourceLite(&FilterListLock);
    KeLeaveCriticalRegion();

    if (Filter)
    {
        /* Let the filter clean up, a mandatory unload can't be refused */
        if (UnloadCallback)
            (VOID)UnloadCallback(FLTFL_FILTER_UNLOAD_MANDATORY);

        /* Whatever it did, the filter must be gone now */
        KeEnterCriticalRegion();
        ExAcquireResourceSharedLite(&FilterListLock, TRUE);
        Filter = NULL;
        for (Entry = FilterList.Flink; Entry != &FilterList; Entry = Entry->Flink)
        {
            Current = CONTAINING_RECORD(Entry, FLT_FILTER, GlobalLink);
            if (Current->DriverObject == DriverObject)
            {
                Filter = Current;
                break;
            }
        }
        ExReleaseResourceLite(&FilterListLock);
        KeLeaveCriticalRegion();

        if (Filter)
            FltUnregisterFilter(Filter);
    }

    if (OldUnload)
        OldUnload(DriverObject);
}

/* PRIVATE FUNCTIONS ******************************************************/

/* Reads a REG_SZ value into a newly allocated unicode string without the terminator */
static
NTSTATUS
ReadStringValue(_In_ HANDLE Key,
                _In_ PUNICODE_STRING ValueName,
                _Inout_ PUNICODE_STRING String)
{
    ULONG BytesRequired = 0;
    PWCH Buffer;
    NTSTATUS Status;

    Status = FltpReadRegistryValue(Key, ValueName, REG_SZ, NULL, 0, &BytesRequired);
    if (Status != STATUS_BUFFER_TOO_SMALL)
        return NT_SUCCESS(Status) ? STATUS_OBJECT_NAME_NOT_FOUND : Status;

    Buffer = ExAllocatePoolWithTag(PagedPool, BytesRequired + sizeof(WCHAR), FM_TAG_UNICODE_STRING);
    if (Buffer == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    Status = FltpReadRegistryValue(Key, ValueName, REG_SZ, Buffer, BytesRequired, &BytesRequired);
    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(Buffer, FM_TAG_UNICODE_STRING);
        return Status;
    }

    /* Drop the terminators the registry value carries and make sure there is one anyway */
    BytesRequired &= ~(sizeof(WCHAR) - 1);
    Buffer[BytesRequired / sizeof(WCHAR)] = UNICODE_NULL;
    while (BytesRequired && Buffer[BytesRequired / sizeof(WCHAR) - 1] == UNICODE_NULL)
        BytesRequired -= sizeof(WCHAR);

    String->Buffer = Buffer;
    String->Length = (USHORT)BytesRequired;
    String->MaximumLength = (USHORT)(BytesRequired + sizeof(WCHAR));
    return STATUS_SUCCESS;
}

static
NTSTATUS
GetFilterAltitude(_In_ PFLT_FILTER Filter,
                  _Inout_ PUNICODE_STRING AltitudeString,
                  _Inout_ PUNICODE_STRING InstanceName)
{
    UNICODE_STRING InstancesKey = RTL_CONSTANT_STRING(L"Instances");
    UNICODE_STRING DefaultInstance = RTL_CONSTANT_STRING(L"DefaultInstance");
    UNICODE_STRING Altitude = RTL_CONSTANT_STRING(L"Altitude");
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE InstHandle = NULL;
    HANDLE RootHandle;
    NTSTATUS Status;

    /* Get a handle to the instances key in the filter's services key */
    Status = FltpOpenFilterServicesKey(Filter,
                                       KEY_QUERY_VALUE,
                                       &InstancesKey,
                                       &RootHandle);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    /* The 'default instance' string value names the key which holds the altitude */
    Status = ReadStringValue(RootHandle, &DefaultInstance, InstanceName);
    if (!NT_SUCCESS(Status))
    {
        goto Quit;
    }

    /* Setup the attributes using the root key handle */
    InitializeObjectAttributes(&ObjectAttributes,
                               InstanceName,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               RootHandle,
                               NULL);

    /* Now open the key name which was stored in the default instance */
    Status = ZwOpenKey(&InstHandle, KEY_QUERY_VALUE, &ObjectAttributes);
    if (NT_SUCCESS(Status))
    {
        Status = ReadStringValue(InstHandle, &Altitude, AltitudeString);
    }

Quit:
    if (!NT_SUCCESS(Status))
    {
        FltpFreeUnicodeString(AltitudeString);
        FltpFreeUnicodeString(InstanceName);
    }

    if (InstHandle)
    {
        ZwClose(InstHandle);
    }
    ZwClose(RootHandle);

    return Status;
}
