/*
* PROJECT:         Filesystem Filter Manager
* LICENSE:         GPL - See COPYING in the top level directory
* FILE:            drivers/filters/fltmgr/Context.c
* PURPOSE:         Contains context routines
* PROGRAMMERS:     Ged Murphy (gedmurphy@reactos.org)
*/

/* INCLUDES ******************************************************************/

#include "fltmgr.h"
#include "fltmgrint.h"
#include "fltmgrproto.h"

#define NDEBUG
#include <debug.h>


/* DATA *********************************************************************/

/*
 * A context is the filter's own memory, behind a header of ours. It has a reference count: the
 * allocation gives one to the filter, linking it to an object (instance, volume, stream, stream
 * handle) gives one to that object. The last reference runs the cleanup callback of the registration
 * and frees the memory.
 *
 * The contexts of a volume are all kept in one list on the volume, found by (type, filter or instance, key):
 * the key of a stream context is the FsContext of the file object, the one of a stream handle context
 * the file object. The file systems of this system have no per stream context support of their own
 * (FsRtlInsertPerStreamContext needs FSRTL_ADVANCED_FCB_HEADER), so the filter manager counts the opens
 * of every stream itself, and the stream contexts go when the last file object of the stream is closed.
 */
typedef struct _FLTP_CONTEXT
{
    LIST_ENTRY Link;
    volatile LONG RefCount;
    FLT_CONTEXT_TYPE Type;
    BOOLEAN Linked;
    PFLT_FILTER Filter;
    PFLT_INSTANCE Instance;
    PVOID Key;
    PVOID Pool;
    ULONG PoolTag;
    PFLT_CONTEXT_CLEANUP_CALLBACK CleanupCallback;
    PFLT_CONTEXT_FREE_CALLBACK FreeCallback;

} FLTP_CONTEXT, *PFLTP_CONTEXT;

#define CONTEXT_HEADER_SIZE ((sizeof(FLTP_CONTEXT) + 15) & ~(SIZE_T)15)
#define USER_TO_CONTEXT(p) ((PFLTP_CONTEXT)((PUCHAR)(p) - CONTEXT_HEADER_SIZE))
#define CONTEXT_TO_USER(c) ((PFLT_CONTEXT)((PUCHAR)(c) + CONTEXT_HEADER_SIZE))

/*
 * A stream (FsContext) with the file objects we have seen created for it. Only those count: a close
 * of a file object whose create we didn't see (opened before the instance came, a stream file object
 * the file system made itself) doesn't end anybody's open. A stream without a record has no stream
 * contexts (FltSetStreamContext refuses them), since we wouldn't know when it ends and the memory
 * of its FsContext could be another file's by then.
 */
typedef struct _FLTP_STREAM_OPEN
{
    LIST_ENTRY Link;
    PVOID Key;
    LONG Opens;
    LIST_ENTRY FileObjects;         /* FLTP_STREAM_FILE_OBJECT */

} FLTP_STREAM_OPEN, *PFLTP_STREAM_OPEN;

typedef struct _FLTP_STREAM_FILE_OBJECT
{
    LIST_ENTRY Link;
    PFILE_OBJECT FileObject;

} FLTP_STREAM_FILE_OBJECT, *PFLTP_STREAM_FILE_OBJECT;

/* The record of a stream. Volume->StreamListLock held. */
static
PFLTP_STREAM_OPEN
FindStreamOpen(_In_ PFLT_VOLUME Volume,
               _In_ PVOID Key)
{
    PLIST_ENTRY Entry;

    for (Entry = Volume->StreamList.Flink; Entry != &Volume->StreamList; Entry = Entry->Flink)
    {
        PFLTP_STREAM_OPEN Open = CONTAINING_RECORD(Entry, FLTP_STREAM_OPEN, Link);

        if (Open->Key == Key)
            return Open;
    }
    return NULL;
}

/* A stream's record goes, with whatever file objects are still listed. Volume->StreamListLock held. */
static
VOID
FreeStreamOpen(_In_ PFLTP_STREAM_OPEN Open)
{
    while (!IsListEmpty(&Open->FileObjects))
    {
        ExFreePoolWithTag(CONTAINING_RECORD(RemoveHeadList(&Open->FileObjects), FLTP_STREAM_FILE_OBJECT, Link),
                          FM_TAG_STREAMCTRL);
    }
    ExFreePoolWithTag(Open, FM_TAG_STREAMCTRL);
}

static
LONG
ContextTypeToIndex(
    _In_ FLT_CONTEXT_TYPE ContextType
)
{
    switch (ContextType)
    {
    case FLT_VOLUME_CONTEXT: return FLTP_CTX_INDEX_VOLUME;
    case FLT_INSTANCE_CONTEXT: return FLTP_CTX_INDEX_INSTANCE;
    case FLT_FILE_CONTEXT: return FLTP_CTX_INDEX_FILE;
    case FLT_STREAM_CONTEXT: return FLTP_CTX_INDEX_STREAM;
    case FLT_STREAMHANDLE_CONTEXT: return FLTP_CTX_INDEX_STREAMHANDLE;
    case FLT_TRANSACTION_CONTEXT: return FLTP_CTX_INDEX_TRANSACTION;
    }

    return -1;
}


/* INTERNAL FUNCTIONS ******************************************************/

NTSTATUS
FltpRegisterContexts(_In_ PFLT_FILTER Filter,
                     _In_ const FLT_CONTEXT_REGISTRATION *Context)
{
    PCFLT_CONTEXT_REGISTRATION ContextPtr;
    LONG Index;

    /* Loop through all entries in the context registration array */
    for (ContextPtr = Context; ContextPtr->ContextType != FLT_CONTEXT_END; ContextPtr++)
    {
        Index = ContextTypeToIndex(ContextPtr->ContextType);
        if (Index < 0 || Filter->ContextDefs[Index].Registered)
            return STATUS_FLT_INVALID_CONTEXT_REGISTRATION;

        /* Size and pooltag are only checked when ContextAllocateCallback is null */
        if (ContextPtr->ContextAllocateCallback == NULL &&
            (ContextPtr->PoolTag == 0 || ContextPtr->Size == 0))
        {
            return STATUS_FLT_INVALID_CONTEXT_REGISTRATION;
        }

        Filter->ContextDefs[Index].Registered = TRUE;
        Filter->ContextDefs[Index].Flags = ContextPtr->Flags;
        Filter->ContextDefs[Index].CleanupCallback = ContextPtr->ContextCleanupCallback;
        Filter->ContextDefs[Index].Size = ContextPtr->Size;
        Filter->ContextDefs[Index].PoolTag = ContextPtr->PoolTag;
        Filter->ContextDefs[Index].AllocateCallback = ContextPtr->ContextAllocateCallback;
        Filter->ContextDefs[Index].FreeCallback = ContextPtr->ContextFreeCallback;
    }

    return STATUS_SUCCESS;
}

static
VOID
FreeContext(_In_ PFLTP_CONTEXT Context)
{
    if (Context->CleanupCallback)
        Context->CleanupCallback(CONTEXT_TO_USER(Context), Context->Type);

    if (Context->FreeCallback)
        Context->FreeCallback(Context->Pool, Context->Type);
    else
        ExFreePoolWithTag(Context->Pool, Context->PoolTag);
}

typedef struct _FLTP_CONTEXT_FREE_ITEM
{
    WORK_QUEUE_ITEM WorkItem;
    PFLTP_CONTEXT Context;

} FLTP_CONTEXT_FREE_ITEM, *PFLTP_CONTEXT_FREE_ITEM;

static
VOID
NTAPI
FreeContextWorker(_In_ PVOID Parameter)
{
    PFLTP_CONTEXT_FREE_ITEM Item = Parameter;
    PFLT_FILTER Filter = Item->Context->Filter;

    FreeContext(Item->Context);
    FltObjectDereference(Filter);
    ExFreePoolWithTag(Item, FM_TAG_CONTEXT);
}

/*
 * The last reference went: cleanup callback and free. FltReleaseContext may be called at DISPATCH_LEVEL
 * (a post-operation in a completion routine), the cleanup callback is documented for IRQL <= APC_LEVEL
 * and the context memory may be paged: above APC_LEVEL a worker does it, with the filter kept until
 * then (its unregister waits for that). Only if that isn't possible (no memory for the work item, the
 * filter already past its rundown) it is done right here, as before.
 */
static
VOID
ReleaseContextHeader(_In_ PFLTP_CONTEXT Context)
{
    PFLTP_CONTEXT_FREE_ITEM Item;

    FLT_ASSERT(Context->RefCount > 0);

    if (InterlockedDecrement(&Context->RefCount) != 0)
        return;

    if (KeGetCurrentIrql() > APC_LEVEL)
    {
        Item = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Item), FM_TAG_CONTEXT);
        if (Item)
        {
            if (NT_SUCCESS(FltObjectReference(Context->Filter)))
            {
                Item->Context = Context;
                ExInitializeWorkItem(&Item->WorkItem, FreeContextWorker, Item);
                ExQueueWorkItem(&Item->WorkItem, DelayedWorkQueue);
                return;
            }
            ExFreePoolWithTag(Item, FM_TAG_CONTEXT);
        }
    }

    FreeContext(Context);
}

/* Does the context (type, owner, key) match? Volume contexts belong to the filter, the others to the instance. */
static
BOOLEAN
Matches(_In_ PFLTP_CONTEXT Context,
        _In_ FLT_CONTEXT_TYPE Type,
        _In_ PFLT_FILTER Filter,
        _In_opt_ PFLT_INSTANCE Instance,
        _In_opt_ PVOID Key)
{
    if (Context->Type != Type)
        return FALSE;

    if (Type == FLT_VOLUME_CONTEXT)
        return Context->Filter == Filter;

    return Context->Instance == Instance && Context->Key == Key;
}

static
PFLTP_CONTEXT
FindContext(_In_ PFLT_VOLUME Volume,
            _In_ FLT_CONTEXT_TYPE Type,
            _In_ PFLT_FILTER Filter,
            _In_opt_ PFLT_INSTANCE Instance,
            _In_opt_ PVOID Key)
{
    PLIST_ENTRY Entry;

    for (Entry = Volume->ContextList.Flink; Entry != &Volume->ContextList; Entry = Entry->Flink)
    {
        PFLTP_CONTEXT Context = CONTAINING_RECORD(Entry, FLTP_CONTEXT, Link);

        if (Matches(Context, Type, Filter, Instance, Key))
            return Context;
    }

    return NULL;
}

static
VOID
Unlink(_In_ PFLTP_CONTEXT Context)
{
    RemoveEntryList(&Context->Link);
    InitializeListHead(&Context->Link);
    Context->Linked = FALSE;
}

/* Puts a new context on the volume. Volume contexts are the filter's, the others belong to the instance. */
static
NTSTATUS
SetContext(_In_ PFLT_VOLUME Volume,
           _In_ FLT_CONTEXT_TYPE Type,
           _In_ PFLT_FILTER Filter,
           _In_opt_ PFLT_INSTANCE Instance,
           _In_opt_ PVOID Key,
           _In_ FLT_SET_CONTEXT_OPERATION Operation,
           _In_ PFLT_CONTEXT NewContext,
           _Outptr_opt_result_maybenull_ PFLT_CONTEXT *OldContext)
{
    PFLTP_CONTEXT New = USER_TO_CONTEXT(NewContext);
    PFLTP_CONTEXT Old;
    NTSTATUS Status = STATUS_SUCCESS;

    if (OldContext)
        *OldContext = NULL;

    if (New->Type != Type || New->Filter != Filter)
        return STATUS_FLT_INVALID_CONTEXT_REGISTRATION;

    ExAcquireFastMutex(&Volume->StreamListLock);

    /* A stream we don't know the opens of: we couldn't tell when its context has to go */
    if (Type == FLT_STREAM_CONTEXT && FindStreamOpen(Volume, Key) == NULL)
    {
        ExReleaseFastMutex(&Volume->StreamListLock);
        return STATUS_NOT_SUPPORTED;
    }

    Old = FindContext(Volume, Type, Filter, Instance, Key);
    if (Old == New)
    {
        /* Setting the same context again */
        if (OldContext)
        {
            InterlockedIncrement(&Old->RefCount);
            *OldContext = CONTEXT_TO_USER(Old);
        }
        ExReleaseFastMutex(&Volume->StreamListLock);
        return STATUS_FLT_CONTEXT_ALREADY_DEFINED;
    }

    if (Old && Operation == FLT_SET_CONTEXT_KEEP_IF_EXISTS)
    {
        if (OldContext)
        {
            InterlockedIncrement(&Old->RefCount);
            *OldContext = CONTEXT_TO_USER(Old);
        }
        ExReleaseFastMutex(&Volume->StreamListLock);
        return STATUS_FLT_CONTEXT_ALREADY_DEFINED;
    }

    if (New->Linked)
    {
        /* A context belongs to one object */
        ExReleaseFastMutex(&Volume->StreamListLock);
        return STATUS_FLT_CONTEXT_ALREADY_LINKED;
    }

    if (Old)
        Unlink(Old);

    New->Instance = Instance;
    New->Key = Key;
    InterlockedIncrement(&New->RefCount);
    InsertTailList(&Volume->ContextList, &New->Link);
    New->Linked = TRUE;
    ExReleaseFastMutex(&Volume->StreamListLock);

    if (Old)
    {
        /* The reference of the volume goes to the caller, or away */
        if (OldContext)
            *OldContext = CONTEXT_TO_USER(Old);
        else
            ReleaseContextHeader(Old);
    }

    return Status;
}

static
NTSTATUS
GetContext(_In_ PFLT_VOLUME Volume,
           _In_ FLT_CONTEXT_TYPE Type,
           _In_ PFLT_FILTER Filter,
           _In_opt_ PFLT_INSTANCE Instance,
           _In_opt_ PVOID Key,
           _Outptr_ PFLT_CONTEXT *Context)
{
    PFLTP_CONTEXT Found;

    *Context = NULL;

    ExAcquireFastMutex(&Volume->StreamListLock);
    Found = FindContext(Volume, Type, Filter, Instance, Key);
    if (Found)
        InterlockedIncrement(&Found->RefCount);
    ExReleaseFastMutex(&Volume->StreamListLock);

    if (Found == NULL)
        return STATUS_NOT_FOUND;

    *Context = CONTEXT_TO_USER(Found);
    return STATUS_SUCCESS;
}

static
NTSTATUS
DeleteContext(_In_ PFLT_VOLUME Volume,
              _In_ FLT_CONTEXT_TYPE Type,
              _In_ PFLT_FILTER Filter,
              _In_opt_ PFLT_INSTANCE Instance,
              _In_opt_ PVOID Key,
              _Outptr_opt_result_maybenull_ PFLT_CONTEXT *OldContext)
{
    PFLTP_CONTEXT Found;

    if (OldContext)
        *OldContext = NULL;

    ExAcquireFastMutex(&Volume->StreamListLock);
    Found = FindContext(Volume, Type, Filter, Instance, Key);
    if (Found)
        Unlink(Found);
    ExReleaseFastMutex(&Volume->StreamListLock);

    if (Found == NULL)
        return STATUS_NOT_FOUND;

    if (OldContext)
        *OldContext = CONTEXT_TO_USER(Found);
    else
        ReleaseContextHeader(Found);

    return STATUS_SUCCESS;
}

/* Takes the contexts out of the volume which are matched, and releases them. Owner NULL: all of them. */
static
VOID
PurgeContexts(_In_ PFLT_VOLUME Volume,
              _In_opt_ PFLT_FILTER Filter,
              _In_opt_ PFLT_INSTANCE Instance,
              _In_ FLT_CONTEXT_TYPE Types,
              _In_opt_ PVOID Key,
              _In_ BOOLEAN UseKey)
{
    LIST_ENTRY Removed;
    PLIST_ENTRY Entry, Next;

    InitializeListHead(&Removed);

    ExAcquireFastMutex(&Volume->StreamListLock);
    for (Entry = Volume->ContextList.Flink; Entry != &Volume->ContextList; Entry = Next)
    {
        PFLTP_CONTEXT Context = CONTAINING_RECORD(Entry, FLTP_CONTEXT, Link);

        Next = Entry->Flink;

        if (!(Context->Type & Types))
            continue;
        if (Filter && Context->Filter != Filter)
            continue;
        if (Instance && Context->Instance != Instance)
            continue;
        if (UseKey && Context->Key != Key)
            continue;

        Unlink(Context);
        InsertTailList(&Removed, &Context->Link);
    }
    ExReleaseFastMutex(&Volume->StreamListLock);

    /* The cleanup callbacks run without our lock */
    while (!IsListEmpty(&Removed))
    {
        PFLTP_CONTEXT Context = CONTAINING_RECORD(RemoveHeadList(&Removed), FLTP_CONTEXT, Link);

        InitializeListHead(&Context->Link);
        ReleaseContextHeader(Context);
    }
}

VOID
FltpTeardownInstanceContexts(_In_ PFLT_INSTANCE Instance)
{
    PFLT_VOLUME Volume = Instance->Volume;

    /* All that belonged to the instance, including the streams of the files it saw opened */
    PurgeContexts(Volume, NULL, Instance, FLT_ALL_CONTEXTS & ~FLT_VOLUME_CONTEXT, NULL, FALSE);
}

VOID
FltpTeardownVolumeContexts(_In_ PFLT_VOLUME Volume)
{
    PLIST_ENTRY Entry;

    PurgeContexts(Volume, NULL, NULL, FLT_ALL_CONTEXTS, NULL, FALSE);

    /* Nothing is open anymore */
    ExAcquireFastMutex(&Volume->StreamListLock);
    while (!IsListEmpty(&Volume->StreamList))
    {
        Entry = RemoveHeadList(&Volume->StreamList);
        FreeStreamOpen(CONTAINING_RECORD(Entry, FLTP_STREAM_OPEN, Link));
    }
    ExReleaseFastMutex(&Volume->StreamListLock);
}

/* The contexts a filter has on volumes which stay, when it unregisters */
VOID
FltpPurgeFilterContexts(_In_ PFLT_FILTER Filter)
{
    PFLT_VOLUME *Volumes;
    ULONG Count, i;

    if (NT_SUCCESS(FltpSnapshotVolumes(&Volumes, &Count)))
    {
        for (i = 0; i < Count; i++)
            PurgeContexts(Volumes[i], Filter, NULL, FLT_ALL_CONTEXTS, NULL, FALSE);

        FltpFreeVolumeSnapshot(Volumes, Count);
    }
}

/* A file object has been created on the volume for a stream: one more open */
VOID
FltpStreamOpened(_In_ PFLT_VOLUME Volume,
                 _In_ PFILE_OBJECT FileObject)
{
    PFLTP_STREAM_OPEN Open;
    PFLTP_STREAM_OPEN New = NULL;
    PFLTP_STREAM_FILE_OBJECT Fo;

    if (FileObject == NULL || FileObject->FsContext == NULL)
        return;

    /* Without its own record the file object doesn't count: its close then ends nothing */
    Fo = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Fo), FM_TAG_STREAMCTRL);
    if (Fo == NULL)
        return;
    Fo->FileObject = FileObject;

    New = ExAllocatePoolWithTag(NonPagedPool, sizeof(*New), FM_TAG_STREAMCTRL);

    ExAcquireFastMutex(&Volume->StreamListLock);
    Open = FindStreamOpen(Volume, FileObject->FsContext);
    if (Open == NULL && New)
    {
        Open = New;
        New = NULL;
        Open->Key = FileObject->FsContext;
        Open->Opens = 0;
        InitializeListHead(&Open->FileObjects);
        InsertTailList(&Volume->StreamList, &Open->Link);
    }
    if (Open)
    {
        InsertTailList(&Open->FileObjects, &Fo->Link);
        Open->Opens++;
        Fo = NULL;
    }
    ExReleaseFastMutex(&Volume->StreamListLock);

    if (New)
        ExFreePoolWithTag(New, FM_TAG_STREAMCTRL);
    if (Fo)
        ExFreePoolWithTag(Fo, FM_TAG_STREAMCTRL);
}

/* The file object goes: its handle contexts, and the stream contexts if it was the last open of the stream */
VOID
FltpFileObjectClosed(_In_ PFLT_VOLUME Volume,
                     _In_ PFILE_OBJECT FileObject)
{
    PFLTP_STREAM_OPEN Open;
    PFLTP_STREAM_FILE_OBJECT Fo = NULL;
    PLIST_ENTRY Entry;
    PVOID Stream = FileObject->FsContext;
    BOOLEAN Last = FALSE;

    PurgeContexts(Volume, NULL, NULL, FLT_STREAMHANDLE_CONTEXT, FileObject, TRUE);

    if (Stream == NULL)
        return;

    ExAcquireFastMutex(&Volume->StreamListLock);
    Open = FindStreamOpen(Volume, Stream);
    if (Open)
    {
        /* Only a file object whose create we saw ends an open */
        for (Entry = Open->FileObjects.Flink; Entry != &Open->FileObjects; Entry = Entry->Flink)
        {
            PFLTP_STREAM_FILE_OBJECT Candidate = CONTAINING_RECORD(Entry, FLTP_STREAM_FILE_OBJECT, Link);

            if (Candidate->FileObject == FileObject)
            {
                Fo = Candidate;
                RemoveEntryList(&Fo->Link);
                break;
            }
        }

        if (Fo && --Open->Opens <= 0)
        {
            RemoveEntryList(&Open->Link);
            FreeStreamOpen(Open);
            Last = TRUE;
        }
    }
    ExReleaseFastMutex(&Volume->StreamListLock);

    if (Fo)
        ExFreePoolWithTag(Fo, FM_TAG_STREAMCTRL);

    if (Last)
        PurgeContexts(Volume, NULL, NULL, FLT_STREAM_CONTEXT, Stream, TRUE);
}

/* The volume of a file object: the one of its device, or the one below it when something else is on top */
static
PFLT_VOLUME
VolumeOfFileObject(_In_ PFILE_OBJECT FileObject)
{
    PDEVICE_OBJECT Device;

    for (Device = FileObject->DeviceObject; Device; Device = Device->AttachedDevice)
    {
        if (Device->DriverObject == DriverData.DriverObject && Device->DeviceExtension)
            return ((PFLTMGR_DEVICE_EXTENSION)Device->DeviceExtension)->Volume;
    }

    return NULL;
}


/* EXPORTED FUNCTIONS ******************************************************/

BOOLEAN
FLTAPI
FltSupportsStreamContexts(_In_ PFILE_OBJECT FileObject)
{
    return FileObject->FsContext != NULL && VolumeOfFileObject(FileObject) != NULL;
}

BOOLEAN
FLTAPI
FltSupportsStreamHandleContexts(_In_ PFILE_OBJECT FileObject)
{
    return FltSupportsStreamContexts(FileObject);
}

NTSTATUS
FLTAPI
FltAllocateContext(_In_ PFLT_FILTER Filter,
                   _In_ FLT_CONTEXT_TYPE ContextType,
                   _In_ SIZE_T ContextSize,
                   _In_ POOL_TYPE PoolType,
                   _Outptr_result_bytebuffer_(ContextSize) PFLT_CONTEXT *ReturnedContext)
{
    PFLTP_CONTEXT_DEF Def;
    PFLTP_CONTEXT Context;
    SIZE_T Total;
    PVOID Pool;
    LONG Index;

    *ReturnedContext = NULL;

    Index = ContextTypeToIndex(ContextType);
    if (Index < 0)
        return STATUS_INVALID_PARAMETER;

    Def = &Filter->ContextDefs[Index];
    if (!Def->Registered)
        return STATUS_FLT_CONTEXT_ALLOCATION_NOT_FOUND;

    /* The size has to be the registered one, unless the registration allows anything bigger */
    if (Def->Size != FLT_VARIABLE_SIZED_CONTEXTS)
    {
        if (Def->Flags & FLTFL_CONTEXT_REGISTRATION_NO_EXACT_SIZE_MATCH)
        {
            if (ContextSize < Def->Size)
                return STATUS_FLT_INVALID_CONTEXT_REGISTRATION;
        }
        else if (ContextSize != Def->Size)
        {
            return STATUS_FLT_INVALID_CONTEXT_REGISTRATION;
        }
    }

    Total = CONTEXT_HEADER_SIZE + ContextSize;
    if (Def->AllocateCallback)
        Pool = Def->AllocateCallback(PoolType, Total, ContextType);
    else
        Pool = ExAllocatePoolWithTag(PoolType, Total, Def->PoolTag);
    if (Pool == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(Pool, Total);
    Context = Pool;
    InitializeListHead(&Context->Link);
    Context->RefCount = 1;
    Context->Type = ContextType;
    Context->Filter = Filter;
    Context->Pool = Pool;
    Context->PoolTag = Def->PoolTag;
    Context->CleanupCallback = Def->CleanupCallback;
    Context->FreeCallback = Def->FreeCallback;

    *ReturnedContext = CONTEXT_TO_USER(Context);
    return STATUS_SUCCESS;
}

VOID
FLTAPI
FltReferenceContext(_In_ PFLT_CONTEXT Context)
{
    InterlockedIncrement(&USER_TO_CONTEXT(Context)->RefCount);
}

VOID
FLTAPI
FltReleaseContext(_In_ PFLT_CONTEXT Context)
{
    ReleaseContextHeader(USER_TO_CONTEXT(Context));
}

/* Takes the context out of the object it is on; the references of the caller are not touched */
VOID
FLTAPI
FltDeleteContext(_In_ PFLT_CONTEXT Context)
{
    PFLTP_CONTEXT Header = USER_TO_CONTEXT(Context);
    PFLT_VOLUME Volume = NULL;
    PLIST_ENTRY Entry;
    BOOLEAN Release = FALSE;

    /* The volume it is on: look for the one which has it */
    PFLT_VOLUME *Volumes;
    ULONG Count, i;

    if (!NT_SUCCESS(FltpSnapshotVolumes(&Volumes, &Count)))
        return;

    for (i = 0; i < Count && !Release; i++)
    {
        Volume = Volumes[i];
        ExAcquireFastMutex(&Volume->StreamListLock);
        for (Entry = Volume->ContextList.Flink; Entry != &Volume->ContextList; Entry = Entry->Flink)
        {
            if (CONTAINING_RECORD(Entry, FLTP_CONTEXT, Link) == Header)
            {
                Unlink(Header);
                Release = TRUE;
                break;
            }
        }
        ExReleaseFastMutex(&Volume->StreamListLock);
    }
    FltpFreeVolumeSnapshot(Volumes, Count);

    if (Release)
        ReleaseContextHeader(Header);
}

NTSTATUS
FLTAPI
FltSetVolumeContext(_In_ PFLT_VOLUME Volume,
                    _In_ FLT_SET_CONTEXT_OPERATION Operation,
                    _In_ PFLT_CONTEXT NewContext,
                    _Outptr_opt_result_maybenull_ PFLT_CONTEXT *OldContext)
{
    return SetContext(Volume, FLT_VOLUME_CONTEXT, USER_TO_CONTEXT(NewContext)->Filter, NULL, NULL,
                      Operation, NewContext, OldContext);
}

NTSTATUS
FLTAPI
FltSetInstanceContext(_In_ PFLT_INSTANCE Instance,
                      _In_ FLT_SET_CONTEXT_OPERATION Operation,
                      _In_ PFLT_CONTEXT NewContext,
                      _Outptr_opt_result_maybenull_ PFLT_CONTEXT *OldContext)
{
    if (Instance->Flags & INSFL_DELETING)
        return STATUS_FLT_DELETING_OBJECT;

    return SetContext(Instance->Volume, FLT_INSTANCE_CONTEXT, Instance->Filter, Instance, NULL,
                      Operation, NewContext, OldContext);
}

NTSTATUS
FLTAPI
FltSetStreamContext(_In_ PFLT_INSTANCE Instance,
                    _In_ PFILE_OBJECT FileObject,
                    _In_ FLT_SET_CONTEXT_OPERATION Operation,
                    _In_ PFLT_CONTEXT NewContext,
                    _Outptr_opt_result_maybenull_ PFLT_CONTEXT *OldContext)
{
    if (FileObject->FsContext == NULL)
        return STATUS_NOT_SUPPORTED;
    if (Instance->Flags & INSFL_DELETING)
        return STATUS_FLT_DELETING_OBJECT;

    return SetContext(Instance->Volume, FLT_STREAM_CONTEXT, Instance->Filter, Instance, FileObject->FsContext,
                      Operation, NewContext, OldContext);
}

NTSTATUS
FLTAPI
FltSetStreamHandleContext(_In_ PFLT_INSTANCE Instance,
                          _In_ PFILE_OBJECT FileObject,
                          _In_ FLT_SET_CONTEXT_OPERATION Operation,
                          _In_ PFLT_CONTEXT NewContext,
                          _Outptr_opt_result_maybenull_ PFLT_CONTEXT *OldContext)
{
    if (FileObject->FsContext == NULL)
        return STATUS_NOT_SUPPORTED;
    if (Instance->Flags & INSFL_DELETING)
        return STATUS_FLT_DELETING_OBJECT;

    return SetContext(Instance->Volume, FLT_STREAMHANDLE_CONTEXT, Instance->Filter, Instance, FileObject,
                      Operation, NewContext, OldContext);
}

NTSTATUS
FLTAPI
FltGetVolumeContext(_In_ PFLT_FILTER Filter,
                    _In_ PFLT_VOLUME Volume,
                    _Outptr_ PFLT_CONTEXT *Context)
{
    return GetContext(Volume, FLT_VOLUME_CONTEXT, Filter, NULL, NULL, Context);
}

NTSTATUS
FLTAPI
FltGetInstanceContext(_In_ PFLT_INSTANCE Instance,
                      _Outptr_ PFLT_CONTEXT *Context)
{
    return GetContext(Instance->Volume, FLT_INSTANCE_CONTEXT, Instance->Filter, Instance, NULL, Context);
}

NTSTATUS
FLTAPI
FltGetStreamContext(_In_ PFLT_INSTANCE Instance,
                    _In_ PFILE_OBJECT FileObject,
                    _Outptr_ PFLT_CONTEXT *Context)
{
    *Context = NULL;
    if (FileObject->FsContext == NULL)
        return STATUS_NOT_SUPPORTED;

    return GetContext(Instance->Volume, FLT_STREAM_CONTEXT, Instance->Filter, Instance, FileObject->FsContext, Context);
}

NTSTATUS
FLTAPI
FltGetStreamHandleContext(_In_ PFLT_INSTANCE Instance,
                          _In_ PFILE_OBJECT FileObject,
                          _Outptr_ PFLT_CONTEXT *Context)
{
    *Context = NULL;
    if (FileObject->FsContext == NULL)
        return STATUS_NOT_SUPPORTED;

    return GetContext(Instance->Volume, FLT_STREAMHANDLE_CONTEXT, Instance->Filter, Instance, FileObject, Context);
}

NTSTATUS
FLTAPI
FltDeleteVolumeContext(_In_ PFLT_FILTER Filter,
                       _In_ PFLT_VOLUME Volume,
                       _Outptr_opt_result_maybenull_ PFLT_CONTEXT *OldContext)
{
    return DeleteContext(Volume, FLT_VOLUME_CONTEXT, Filter, NULL, NULL, OldContext);
}

NTSTATUS
FLTAPI
FltDeleteInstanceContext(_In_ PFLT_INSTANCE Instance,
                         _Outptr_opt_result_maybenull_ PFLT_CONTEXT *OldContext)
{
    return DeleteContext(Instance->Volume, FLT_INSTANCE_CONTEXT, Instance->Filter, Instance, NULL, OldContext);
}

NTSTATUS
FLTAPI
FltDeleteStreamContext(_In_ PFLT_INSTANCE Instance,
                       _In_ PFILE_OBJECT FileObject,
                       _Outptr_opt_result_maybenull_ PFLT_CONTEXT *OldContext)
{
    if (OldContext)
        *OldContext = NULL;
    if (FileObject->FsContext == NULL)
        return STATUS_NOT_SUPPORTED;

    return DeleteContext(Instance->Volume, FLT_STREAM_CONTEXT, Instance->Filter, Instance, FileObject->FsContext, OldContext);
}

NTSTATUS
FLTAPI
FltDeleteStreamHandleContext(_In_ PFLT_INSTANCE Instance,
                             _In_ PFILE_OBJECT FileObject,
                             _Outptr_opt_result_maybenull_ PFLT_CONTEXT *OldContext)
{
    if (OldContext)
        *OldContext = NULL;
    if (FileObject->FsContext == NULL)
        return STATUS_NOT_SUPPORTED;

    return DeleteContext(Instance->Volume, FLT_STREAMHANDLE_CONTEXT, Instance->Filter, Instance, FileObject, OldContext);
}

VOID
FLTAPI
FltGetContexts(_In_ PCFLT_RELATED_OBJECTS FltObjects,
               _In_ FLT_CONTEXT_TYPE DesiredContexts,
               _Out_ PFLT_RELATED_CONTEXTS Contexts)
{
    RtlZeroMemory(Contexts, sizeof(*Contexts));

    if ((DesiredContexts & FLT_VOLUME_CONTEXT) && FltObjects->Volume)
        (VOID)FltGetVolumeContext(FltObjects->Filter, FltObjects->Volume, &Contexts->VolumeContext);

    if (FltObjects->Instance)
    {
        if (DesiredContexts & FLT_INSTANCE_CONTEXT)
            (VOID)FltGetInstanceContext(FltObjects->Instance, &Contexts->InstanceContext);

        if (FltObjects->FileObject)
        {
            if (DesiredContexts & FLT_STREAM_CONTEXT)
                (VOID)FltGetStreamContext(FltObjects->Instance, FltObjects->FileObject, &Contexts->StreamContext);
            if (DesiredContexts & FLT_STREAMHANDLE_CONTEXT)
                (VOID)FltGetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, &Contexts->StreamHandleContext);
        }
    }
}

VOID
FLTAPI
FltReleaseContexts(_In_ PFLT_RELATED_CONTEXTS Contexts)
{
    if (Contexts->VolumeContext) FltReleaseContext(Contexts->VolumeContext);
    if (Contexts->InstanceContext) FltReleaseContext(Contexts->InstanceContext);
    if (Contexts->FileContext) FltReleaseContext(Contexts->FileContext);
    if (Contexts->StreamContext) FltReleaseContext(Contexts->StreamContext);
    if (Contexts->StreamHandleContext) FltReleaseContext(Contexts->StreamHandleContext);
    if (Contexts->TransactionContext) FltReleaseContext(Contexts->TransactionContext);
}
