/*
 * PROJECT:     ReactOS test suite
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Sample mini-filter driver: counts the operations it sees and changes some of them,
 *              for the tests of the filter manager. Written against the WDK documentation.
 *
 * One image can be loaded under several service names (copy the file), each with its own
 * altitude from the registry, to test several filters in one stack. The control device
 * \Device\<service name> (also \\.\<service name>) takes the FLTSAMPLE_IOCTL_* requests.
 */

#include <ntifs.h>
#include <fltkernel.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <pseh/pseh2.h>

#include "fltsample.h"

#define NDEBUG
#include <debug.h>

#define TAG_SAMPLE 'lSlF'

/* Minifilters written for the WDK use these members of FLT_PARAMETERS: they have to compile */
C_ASSERT(FIELD_OFFSET(FLT_PARAMETERS, DeviceIoControl.Common.IoControlCode) ==
         FIELD_OFFSET(FLT_PARAMETERS, FileSystemControl.Common.FsControlCode));
C_ASSERT(FIELD_OFFSET(FLT_PARAMETERS, DeviceIoControl.Buffered.SystemBuffer) ==
         FIELD_OFFSET(FLT_PARAMETERS, FileSystemControl.Neither.InputBuffer));
C_ASSERT(sizeof(((PFLT_PARAMETERS)0)->LockControl) != 0 &&
         sizeof(((PFLT_PARAMETERS)0)->QuerySecurity) != 0 &&
         sizeof(((PFLT_PARAMETERS)0)->SetSecurity) != 0 &&
         sizeof(((PFLT_PARAMETERS)0)->QueryQuota) != 0 &&
         sizeof(((PFLT_PARAMETERS)0)->Pnp) != 0 &&
         sizeof(((PFLT_PARAMETERS)0)->AcquireForSectionSynchronization) != 0 &&
         sizeof(((PFLT_PARAMETERS)0)->FastIoCheckIfPossible) != 0 &&
         sizeof(((PFLT_PARAMETERS)0)->MdlRead) != 0 &&
         sizeof(((PFLT_PARAMETERS)0)->MountVolume) != 0);
/* The anonymous union of SetFileInformation: the WDK names, and DUMMYUNIONNAME (NONAMELESSUNION builds) */
C_ASSERT(FIELD_OFFSET(FLT_PARAMETERS, SetFileInformation.ReplaceIfExists) ==
         FIELD_OFFSET(FLT_PARAMETERS, SetFileInformation.DeleteHandle));

#define MODE_NONE       0
#define MODE_BLK        1
#define MODE_NOWR       2
#define MODE_HALF       3
#define MODE_PEND       4
#define MODE_SYNC       5
#define MODE_SAFE       6
#define MODE_NODEL      7
#define MODE_MSG        8
#define MODE_NOSEC      9
#define MODE_SCTX       10
#define MODE_PDPC       11
#define MODE_DPCREAD    12
#define MODE_FSF        13

#define MAX_OPEN        256

typedef struct _OPEN_ENTRY
{
    PFILE_OBJECT FileObject;
    ULONG Mode;

} OPEN_ENTRY;

/*
 * Work of ours on a system worker thread. It goes through an IO_WORKITEM of the control device: that keeps
 * the device, and so the driver image, until the routine has returned. With a plain ExQueueWorkItem the
 * worker which wakes the unload (PendingWorkers) still had its own return to run, maybe after the image was
 * gone (seen as a bugcheck 0x50 executing in the unloaded image under the load/unload stress).
 */
typedef struct _SAMPLE_WORK
{
    WORK_QUEUE_ITEM WorkItem;       /* the routine and its parameter */
    PIO_WORKITEM IoWorkItem;

} SAMPLE_WORK, *PSAMPLE_WORK;

typedef struct _PEND_ITEM
{
    SAMPLE_WORK WorkItem;
    PFLT_CALLBACK_DATA Data;
    PEPROCESS Process;

} PEND_ITEM, *PPEND_ITEM;

static PDRIVER_OBJECT SampleDriver;
static PDEVICE_OBJECT ControlDevice;
static UNICODE_STRING SymLinkName;
static WCHAR SymLinkBuffer[80];
static PFLT_FILTER SampleFilter;
static PFLT_VOLUME HeldVolume;                  /* FLTSAMPLE_IOCTL_HOLD_VOLUME */
static FLTSAMPLE_VOLUME_PROPS HeldBefore;
#define LEAKED_VOLUMES_MAX 32
static PFLT_VOLUME LeakedVolumes[LEAKED_VOLUMES_MAX];   /* FLTSAMPLE_IOCTL_LEAK_VOLUME: references kept on purpose (test only) */
static ULONG LeakedCount;
static FLTSAMPLE_STATS Stats;
static ULONG AttachMask = 0xFFFF;
static ULONG PendDelayMs = 200;
static BOOLEAN RefuseDetach;
static BOOLEAN RefuseUnload;
static BOOLEAN VetoEnabled = TRUE;
static OPEN_ENTRY OpenFiles[MAX_OPEN];
static KSPIN_LOCK OpenLock;
static volatile LONG PendingWorkers;
static KEVENT WorkersDone;
static volatile ULONG RvFlags;
static ULONG RvDenyAllPort;    /* review test: the port gets a descriptor with an empty DACL */
static ULONG PortSecurity;     /* PORT_SECURITY_*: the descriptor the port is created with */
static WCHAR ServiceName[48];
static BOOLEAN UseContexts = TRUE;
static PFLT_PORT ServerPort;
static PFLT_PORT ClientPort;
static BOOLEAN ArmAsk;
static BOOLEAN InNestedAttach;

typedef struct _SAMPLE_CONTEXT
{
    ULONG Magic;
    ULONG Mode;

} SAMPLE_CONTEXT, *PSAMPLE_CONTEXT;

#define CONTEXT_MAGIC 0x43544658
static WCHAR RegistryPathBuffer[160];

DRIVER_INITIALIZE DriverEntry;
static DRIVER_DISPATCH ControlDispatch;
static BOOLEAN ClientRefuses(_In_ PCUNICODE_STRING Name);


/* HELPERS ****************************************************************/

static
ULONG
ModeFromName(_In_ PCUNICODE_STRING Name)
{
    static const struct { PCWSTR Extension; ULONG Mode; } Map[] =
    {
        { L".blk", MODE_BLK }, { L".nowr", MODE_NOWR }, { L".half", MODE_HALF }, { L".pend", MODE_PEND },
        { L".sync", MODE_SYNC }, { L".safe", MODE_SAFE }, { L".nodel", MODE_NODEL }, { L".msg", MODE_MSG },
        { L".nosec", MODE_NOSEC }, { L".sctx", MODE_SCTX }, { L".pdpc", MODE_PDPC },
        { L".dpc", MODE_DPCREAD }, { L".fsf", MODE_FSF },
    };
    ULONG i, Length;

    if (Name == NULL || Name->Buffer == NULL)
        return MODE_NONE;

    for (i = 0; i < RTL_NUMBER_OF(Map); i++)
    {
        UNICODE_STRING Extension;

        RtlInitUnicodeString(&Extension, Map[i].Extension);
        Length = Extension.Length;
        if (Name->Length >= Length)
        {
            UNICODE_STRING Tail;

            Tail.Buffer = (PWCHAR)((PCHAR)Name->Buffer + Name->Length - Length);
            Tail.Length = Tail.MaximumLength = (USHORT)Length;
            if (RtlEqualUnicodeString(&Tail, &Extension, TRUE))
                return Map[i].Mode;
        }
    }

    return MODE_NONE;
}

/* Only files under a directory named fltmgr_test are the business of the sample, the rest of the system is not counted */
static
BOOLEAN
IsTestName(_In_ PCUNICODE_STRING Name)
{
    static const WCHAR Pattern[] = L"fltmgr_test";
    ULONG i, j, Length;

    if (Name == NULL || Name->Buffer == NULL)
        return FALSE;

    Length = Name->Length / sizeof(WCHAR);
    for (i = 0; i + RTL_NUMBER_OF(Pattern) - 1 <= Length; i++)
    {
        for (j = 0; j < RTL_NUMBER_OF(Pattern) - 1; j++)
        {
            if (RtlUpcaseUnicodeChar(Name->Buffer[i + j]) != RtlUpcaseUnicodeChar(Pattern[j]))
                break;
        }
        if (j == RTL_NUMBER_OF(Pattern) - 1)
            return TRUE;
    }

    return FALSE;
}

static
BOOLEAN
IsTracked(_In_ PFILE_OBJECT FileObject)
{
    KIRQL OldIrql;
    ULONG i;
    BOOLEAN Found = FALSE;

    KeAcquireSpinLock(&OpenLock, &OldIrql);
    for (i = 0; i < MAX_OPEN && !Found; i++)
        Found = OpenFiles[i].FileObject == FileObject;
    KeReleaseSpinLock(&OpenLock, OldIrql);
    return Found;
}

static
VOID
AddOpen(_In_ PFILE_OBJECT FileObject,
        _In_ ULONG Mode)
{
    KIRQL OldIrql;
    ULONG i;

    KeAcquireSpinLock(&OpenLock, &OldIrql);
    for (i = 0; i < MAX_OPEN; i++)
    {
        if (OpenFiles[i].FileObject == NULL)
        {
            OpenFiles[i].FileObject = FileObject;
            OpenFiles[i].Mode = Mode;
            InterlockedIncrement((PLONG)&Stats.OpenFiles);
            break;
        }
    }
    KeReleaseSpinLock(&OpenLock, OldIrql);
}

static
ULONG
FindMode(_In_ PFILE_OBJECT FileObject)
{
    KIRQL OldIrql;
    ULONG i, Mode = MODE_NONE;

    KeAcquireSpinLock(&OpenLock, &OldIrql);
    for (i = 0; i < MAX_OPEN; i++)
    {
        if (OpenFiles[i].FileObject == FileObject)
        {
            Mode = OpenFiles[i].Mode;
            break;
        }
    }
    KeReleaseSpinLock(&OpenLock, OldIrql);
    return Mode;
}

static
VOID
RemoveOpen(_In_ PFILE_OBJECT FileObject)
{
    KIRQL OldIrql;
    ULONG i;

    KeAcquireSpinLock(&OpenLock, &OldIrql);
    for (i = 0; i < MAX_OPEN; i++)
    {
        if (OpenFiles[i].FileObject == FileObject)
        {
            OpenFiles[i].FileObject = NULL;
            InterlockedDecrement((PLONG)&Stats.OpenFiles);
            break;
        }
    }
    KeReleaseSpinLock(&OpenLock, OldIrql);
}

static
FLT_PREOP_CALLBACK_STATUS
Veto(_Inout_ PFLT_CALLBACK_DATA Data)
{
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    InterlockedIncrement((PLONG)&Stats.Vetoed);
    return FLT_PREOP_COMPLETE;
}


/* CONTEXTS ***************************************************************/

static
VOID
FLTAPI
ContextCleanup(_In_ PFLT_CONTEXT Context,
               _In_ FLT_CONTEXT_TYPE ContextType)
{
    PSAMPLE_CONTEXT Sample = Context;

    InterlockedIncrement((PLONG)&Stats.Contexts[FLTSAMPLE_CTX_CLEANED]);
    if (KeGetCurrentIrql() > APC_LEVEL)
        InterlockedIncrement((PLONG)&Stats.CleanupAboveApc);
    if (Sample->Magic != CONTEXT_MAGIC)
        InterlockedIncrement((PLONG)&Stats.ContextMismatch);

    switch (ContextType)
    {
        case FLT_INSTANCE_CONTEXT: InterlockedIncrement((PLONG)&Stats.CleanedByType[0]); break;
        case FLT_VOLUME_CONTEXT: InterlockedIncrement((PLONG)&Stats.CleanedByType[1]); break;
        case FLT_STREAM_CONTEXT: InterlockedIncrement((PLONG)&Stats.CleanedByType[2]); break;
        case FLT_STREAMHANDLE_CONTEXT: InterlockedIncrement((PLONG)&Stats.CleanedByType[3]); break;
        default: InterlockedIncrement((PLONG)&Stats.ContextMismatch); break;
    }
}

static
PSAMPLE_CONTEXT
NewContext(_In_ FLT_CONTEXT_TYPE Type,
           _In_ ULONG Mode)
{
    PFLT_CONTEXT Context;
    PSAMPLE_CONTEXT Sample;

    if (!NT_SUCCESS(FltAllocateContext(SampleFilter, Type, sizeof(SAMPLE_CONTEXT), NonPagedPool, &Context)))
        return NULL;

    InterlockedIncrement((PLONG)&Stats.Contexts[FLTSAMPLE_CTX_ALLOCATED]);
    Sample = Context;
    Sample->Magic = CONTEXT_MAGIC;
    Sample->Mode = Mode;
    return Sample;
}

/* What the operations see of the contexts the filter put on the objects around them */
static
VOID
LookAtContexts(_In_ PCFLT_RELATED_OBJECTS FltObjects,
               _In_ PFILE_OBJECT FileObject,
               _In_ ULONG Mode)
{
    PFLT_CONTEXT Context;
    PSAMPLE_CONTEXT Sample;
    NTSTATUS Status;

    if (NT_SUCCESS(FltGetInstanceContext(FltObjects->Instance, &Context)))
    {
        InterlockedIncrement((PLONG)&Stats.Contexts[FLTSAMPLE_CTX_INSTANCE_HITS]);
        FltReleaseContext(Context);
    }

    /* One volume context per volume, made when the first operation looks for it */
    Status = FltGetVolumeContext(FltObjects->Filter, FltObjects->Volume, &Context);
    if (NT_SUCCESS(Status))
    {
        InterlockedIncrement((PLONG)&Stats.Contexts[FLTSAMPLE_CTX_VOLUME_HITS]);
        FltReleaseContext(Context);
    }
    else if ((Sample = NewContext(FLT_VOLUME_CONTEXT, 0)) != NULL)
    {
        PFLT_CONTEXT Old = NULL;

        Status = FltSetVolumeContext(FltObjects->Volume, FLT_SET_CONTEXT_KEEP_IF_EXISTS, Sample, &Old);
        FltReleaseContext(Sample);
        if (Old)
            FltReleaseContext(Old);
    }

    if (NT_SUCCESS(FltGetStreamHandleContext(FltObjects->Instance, FileObject, &Context)))
    {
        InterlockedIncrement((PLONG)&Stats.Contexts[FLTSAMPLE_CTX_HANDLE_HITS]);
        if (((PSAMPLE_CONTEXT)Context)->Mode != Mode)
            InterlockedIncrement((PLONG)&Stats.ContextMismatch);
        FltReleaseContext(Context);
    }

    if (NT_SUCCESS(FltGetStreamContext(FltObjects->Instance, FileObject, &Context)))
    {
        InterlockedIncrement((PLONG)&Stats.Contexts[FLTSAMPLE_CTX_STREAM_HITS]);
        FltReleaseContext(Context);
    }
}

/* A new file object: its handle context, and the context of its stream if it is the first */
static
VOID
AttachContexts(_In_ PCFLT_RELATED_OBJECTS FltObjects,
               _In_ PFILE_OBJECT FileObject,
               _In_ ULONG Mode)
{
    PSAMPLE_CONTEXT Sample;
    PFLT_CONTEXT Old;
    NTSTATUS Status;

    if ((Sample = NewContext(FLT_STREAMHANDLE_CONTEXT, Mode)) != NULL)
    {
        Status = FltSetStreamHandleContext(FltObjects->Instance, FileObject, FLT_SET_CONTEXT_REPLACE_IF_EXISTS, Sample, NULL);
        if (NT_SUCCESS(Status))
            InterlockedIncrement((PLONG)&Stats.Contexts[FLTSAMPLE_CTX_HANDLE_NEW]);
        FltReleaseContext(Sample);
    }

    if ((Sample = NewContext(FLT_STREAM_CONTEXT, Mode)) != NULL)
    {
        Old = NULL;
        Status = FltSetStreamContext(FltObjects->Instance, FileObject, FLT_SET_CONTEXT_KEEP_IF_EXISTS, Sample, &Old);
        if (NT_SUCCESS(Status))
            InterlockedIncrement((PLONG)&Stats.Contexts[FLTSAMPLE_CTX_STREAM_NEW]);
        else if (Status == STATUS_FLT_CONTEXT_ALREADY_DEFINED)
            InterlockedIncrement((PLONG)&Stats.Contexts[FLTSAMPLE_CTX_STREAM_HITS]);
        FltReleaseContext(Sample);
        if (Old)
            FltReleaseContext(Old);
    }
}

static const FLT_CONTEXT_REGISTRATION ContextRegistration[] =
{
    { FLT_INSTANCE_CONTEXT, 0, ContextCleanup, sizeof(SAMPLE_CONTEXT), TAG_SAMPLE },
    { FLT_VOLUME_CONTEXT, 0, ContextCleanup, sizeof(SAMPLE_CONTEXT), TAG_SAMPLE },
    { FLT_STREAM_CONTEXT, 0, ContextCleanup, sizeof(SAMPLE_CONTEXT), TAG_SAMPLE },
    { FLT_STREAMHANDLE_CONTEXT, 0, ContextCleanup, sizeof(SAMPLE_CONTEXT), TAG_SAMPLE },
    { FLT_CONTEXT_END }
};

/* Calls of the context functions with known outcomes, on the instance of the first volume */
static
VOID
ContextSelfTest(_Out_writes_(16) PULONG Result)
{
    PFLT_VOLUME Volume = NULL;
    PFLT_VOLUME Volumes[4];
    PFLT_INSTANCE Instance = NULL;
    PFLT_INSTANCE Instances[4];
    PFLT_CONTEXT Ctx1 = NULL, Ctx2 = NULL, Old = NULL, Got = NULL, Bad = NULL;
    ULONG Count = 0, i, Cleaned;

    RtlZeroMemory(Result, 16 * sizeof(ULONG));

    if (!NT_SUCCESS(FltEnumerateVolumes(SampleFilter, Volumes, RTL_NUMBER_OF(Volumes), &Count)) || Count == 0)
        return;
    Volume = Volumes[0];
    for (i = 1; i < Count; i++)
        FltObjectDereference(Volumes[i]);

    if (!NT_SUCCESS(FltEnumerateInstances(Volume, SampleFilter, Instances, RTL_NUMBER_OF(Instances), &Count)) || Count == 0)
    {
        FltObjectDereference(Volume);
        return;
    }
    Instance = Instances[0];
    for (i = 1; i < Count; i++)
        FltObjectDereference(Instances[i]);

    /* A size other than the registered one is refused, and so is a type nobody registered */
    Result[0] = FltAllocateContext(SampleFilter, FLT_INSTANCE_CONTEXT, sizeof(SAMPLE_CONTEXT) + 1, NonPagedPool, &Bad);
    Result[13] = FltAllocateContext(SampleFilter, FLT_FILE_CONTEXT, sizeof(SAMPLE_CONTEXT), NonPagedPool, &Bad);

    /* Out of the way what the setup put there */
    (VOID)FltDeleteInstanceContext(Instance, NULL);

    Result[1] = FltAllocateContext(SampleFilter, FLT_INSTANCE_CONTEXT, sizeof(SAMPLE_CONTEXT), NonPagedPool, &Ctx1);
    Result[2] = FltSetInstanceContext(Instance, FLT_SET_CONTEXT_KEEP_IF_EXISTS, Ctx1, NULL);
    FltReleaseContext(Ctx1);
    InterlockedIncrement((PLONG)&Stats.Contexts[FLTSAMPLE_CTX_ALLOCATED]);

    FltAllocateContext(SampleFilter, FLT_INSTANCE_CONTEXT, sizeof(SAMPLE_CONTEXT), NonPagedPool, &Ctx2);
    InterlockedIncrement((PLONG)&Stats.Contexts[FLTSAMPLE_CTX_ALLOCATED]);
    ((PSAMPLE_CONTEXT)Ctx1)->Magic = ((PSAMPLE_CONTEXT)Ctx2)->Magic = CONTEXT_MAGIC;

    /* Keep: the one there stays, and is handed back */
    Result[3] = FltSetInstanceContext(Instance, FLT_SET_CONTEXT_KEEP_IF_EXISTS, Ctx2, &Old);
    Result[4] = (Old == Ctx1);
    if (Old)
        FltReleaseContext(Old);

    /* Replace: the new one is in, the old one comes back and is freed when we let go of it */
    Cleaned = Stats.Contexts[FLTSAMPLE_CTX_CLEANED];
    Old = NULL;
    Result[5] = FltSetInstanceContext(Instance, FLT_SET_CONTEXT_REPLACE_IF_EXISTS, Ctx2, &Old);
    Result[6] = (Old == Ctx1);
    Result[7] = (Stats.Contexts[FLTSAMPLE_CTX_CLEANED] == Cleaned);
    if (Old)
        FltReleaseContext(Old);
    Result[8] = (Stats.Contexts[FLTSAMPLE_CTX_CLEANED] == Cleaned + 1);

    if (NT_SUCCESS(FltGetInstanceContext(Instance, &Got)))
    {
        Result[9] = (Got == Ctx2);
        FltReleaseContext(Got);
    }

    /* The instance and we hold the second one; a third reference keeps it past the delete and our release */
    FltReferenceContext(Ctx2);
    Cleaned = Stats.Contexts[FLTSAMPLE_CTX_CLEANED];
    Result[10] = FltDeleteInstanceContext(Instance, NULL);
    FltReleaseContext(Ctx2);
    Result[11] = (Stats.Contexts[FLTSAMPLE_CTX_CLEANED] == Cleaned);
    FltReleaseContext(Ctx2);
    Result[12] = (Stats.Contexts[FLTSAMPLE_CTX_CLEANED] == Cleaned + 1);
    Result[14] = FltGetInstanceContext(Instance, &Got);

    FltObjectDereference(Instance);
    FltObjectDereference(Volume);
}

/* OPERATIONS *************************************************************/

static
VOID
NTAPI
SampleWorkThunk(_In_ PDEVICE_OBJECT DeviceObject,
                _In_opt_ PVOID Context)
{
    PSAMPLE_WORK Work = Context;
    PIO_WORKITEM IoWorkItem = Work->IoWorkItem;

    UNREFERENCED_PARAMETER(DeviceObject);

    /* The routine frees the item the work is in */
    Work->WorkItem.WorkerRoutine(Work->WorkItem.Parameter);
    IoFreeWorkItem(IoWorkItem);
}

static
VOID
QueueSampleWork(_Inout_ PSAMPLE_WORK Work,
                _In_ PWORKER_THREAD_ROUTINE Routine,
                _In_ PVOID Parameter)
{
    ExInitializeWorkItem(&Work->WorkItem, Routine, Parameter);
    Work->IoWorkItem = IoAllocateWorkItem(ControlDevice);
    if (Work->IoWorkItem)
        IoQueueWorkItem(Work->IoWorkItem, SampleWorkThunk, DelayedWorkQueue, Work);
    else
        ExQueueWorkItem(&Work->WorkItem, DelayedWorkQueue);
}

static
VOID
NTAPI
PendWorker(_In_ PVOID Parameter)
{
    PPEND_ITEM Item = Parameter;
    LARGE_INTEGER Delay;
    KAPC_STATE ApcState;

    Delay.QuadPart = -10000LL * (LONGLONG)PendDelayMs;
    KeDelayExecutionThread(KernelMode, FALSE, &Delay);

    InterlockedIncrement((PLONG)&Stats.PendCompleted);

    /* The file system reads the user's buffer: from here that is the address space of the requestor */
    KeStackAttachProcess((PKPROCESS)Item->Process, &ApcState);
    FltCompletePendedPreOperation(Item->Data, FLT_PREOP_SUCCESS_WITH_CALLBACK, NULL);
    KeUnstackDetachProcess(&ApcState);
    ObDereferenceObject(Item->Process);

    ExFreePoolWithTag(Item, TAG_SAMPLE);
    if (InterlockedDecrement(&PendingWorkers) == 0)
        KeSetEvent(&WorkersDone, IO_NO_INCREMENT, FALSE);
}

/*
 * A timer DPC: a DPC queued at PASSIVE_LEVEL runs at once on this processor, before the pre-operation
 * has even returned FLT_PREOP_PENDING, which is not the case to test.
 */
typedef struct _PEND_DPC_ITEM
{
    KTIMER Timer;
    KDPC Dpc;
    PFLT_CALLBACK_DATA Data;

} PEND_DPC_ITEM, *PPEND_DPC_ITEM;

/* .pdpc: the pended write is let go from a DPC, at DISPATCH_LEVEL, in whatever thread and process */
static
VOID
NTAPI
PendDpcRoutine(_In_ PKDPC Dpc,
               _In_opt_ PVOID Context,
               _In_opt_ PVOID Argument1,
               _In_opt_ PVOID Argument2)
{
    PPEND_DPC_ITEM Item = Context;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Argument1);
    UNREFERENCED_PARAMETER(Argument2);

    InterlockedIncrement((PLONG)&Stats.PendDpcCompleted);
    FltCompletePendedPreOperation(Item->Data, FLT_PREOP_SUCCESS_WITH_CALLBACK, NULL);
    ExFreePoolWithTag(Item, TAG_SAMPLE);
    if (InterlockedDecrement(&PendingWorkers) == 0)
        KeSetEvent(&WorkersDone, IO_NO_INCREMENT, FALSE);
}

typedef struct _RV_PARK_ITEM
{
    SAMPLE_WORK WorkItem;
    PFLT_CALLBACK_DATA Data;

} RV_PARK_ITEM, *PRV_PARK_ITEM;

/* Review test: a post-operation which took MORE_PROCESSING_REQUIRED is finished from a worker */
static
VOID
NTAPI
RvParkWorker(_In_ PVOID Parameter)
{
    PRV_PARK_ITEM Item = Parameter;
    LARGE_INTEGER Delay;

    Delay.QuadPart = -10000LL * 20;
    KeDelayExecutionThread(KernelMode, FALSE, &Delay);
    InterlockedIncrement((PLONG)&Stats.RvParkDone);
    FltCompletePendedPostOperation(Item->Data);

    ExFreePoolWithTag(Item, TAG_SAMPLE);
    if (InterlockedDecrement(&PendingWorkers) == 0)
        KeSetEvent(&WorkersDone, IO_NO_INCREMENT, FALSE);
}

static
FLT_PREOP_CALLBACK_STATUS
FLTAPI
PreOperation(_Inout_ PFLT_CALLBACK_DATA Data,
             _In_ PCFLT_RELATED_OBJECTS FltObjects,
             _Outptr_result_maybenull_ PVOID *CompletionContext)
{
    UCHAR Major = Data->Iopb->MajorFunction;
    PFILE_OBJECT FileObject = Data->Iopb->TargetFileObject;
    BOOLEAN Paging = (Data->Iopb->IrpFlags & IRP_PAGING_IO) != 0;
    ULONG Mode;

    *CompletionContext = NULL;

    /*
     * .sctx: a stream context for the file, whether we saw its create or not. The filter manager
     * only allows stream contexts for streams whose opens it followed.
     */
    if (Major == IRP_MJ_READ && !Paging && FileObject && ModeFromName(&FileObject->FileName) == MODE_SCTX)
    {
        PSAMPLE_CONTEXT Sample = NewContext(FLT_STREAM_CONTEXT, MODE_SCTX);
        PFLT_CONTEXT Old = NULL;

        if (Sample)
        {
            Stats.LastSctxStatus = FltSetStreamContext(FltObjects->Instance, FileObject,
                                                       FLT_SET_CONTEXT_KEEP_IF_EXISTS, Sample, &Old);
            InterlockedIncrement((PLONG)&Stats.SctxReads);
            if (Old)
                FltReleaseContext(Old);
            FltReleaseContext(Sample);
        }
    }

    /* Nothing but the test files counts */
    if (Major == IRP_MJ_CREATE)
    {
        if (!IsTestName(&FileObject->FileName))
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    else if (!IsTracked(FileObject))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* What needs to pend, or to change the length, wants an IRP: the fast I/O attempt isn't counted */
    if (FLT_IS_FASTIO_OPERATION(Data))
    {
        if (RvFlags & FLTSAMPLE_RV_DISALLOW_FASTIO)
        {
            InterlockedIncrement((PLONG)&Stats.RvFastIoDisallowed);
            return FLT_PREOP_DISALLOW_FASTIO;
        }

        ULONG FastMode = FindMode(FileObject);

        if (FastMode == MODE_PEND || FastMode == MODE_HALF || FastMode == MODE_PDPC)
            return FLT_PREOP_DISALLOW_FASTIO;
    }

    if (Major < FLTSAMPLE_MAX_MAJOR)
        InterlockedIncrement((PLONG)&Stats.Pre[Major]);

    /* A page of a .fsf file written by the modified page writer (which acquired the file for it before) */
    if (Major == IRP_MJ_WRITE && Paging && IoGetTopLevelIrp() == (PIRP)FSRTL_MOD_WRITE_TOP_LEVEL_IRP &&
        FindMode(FileObject) == MODE_FSF)
    {
        InterlockedIncrement((PLONG)&Stats.ModWriterWrites);
    }

    if (UseContexts && Major != IRP_MJ_CREATE)
        LookAtContexts(FltObjects, FileObject, FindMode(FileObject));

    switch (Major)
    {
        case IRP_MJ_CREATE:
            Stats.LastCreatePre = KeQueryPerformanceCounter(NULL).QuadPart;
            Mode = ModeFromName(&FileObject->FileName);
            RtlZeroMemory(Stats.LastCreate, sizeof(Stats.LastCreate));
            RtlCopyMemory(Stats.LastCreate, FileObject->FileName.Buffer,
                          min(FileObject->FileName.Length, sizeof(Stats.LastCreate) - sizeof(WCHAR)));
            if (Mode == MODE_MSG && ClientRefuses(&FileObject->FileName))
                return Veto(Data);
            if (VetoEnabled && Mode == MODE_BLK)
                return Veto(Data);
            if (VetoEnabled && Mode == MODE_NODEL && (Data->Iopb->Parameters.Create.Options & FILE_DELETE_ON_CLOSE))
                return Veto(Data);
            AddOpen(FileObject, Mode);
            /* The post-create must come in this thread (WDK) */
            *CompletionContext = PsGetCurrentThread();
            break;

        case IRP_MJ_CLOSE:
            RemoveOpen(FileObject);
            break;

        case IRP_MJ_WRITE:
            Stats.LastWritePre = KeQueryPerformanceCounter(NULL).QuadPart;
            if (Paging)
                break;
            Mode = FindMode(FileObject);
            if (VetoEnabled && Mode == MODE_NOWR)
                return Veto(Data);
            if (Mode == MODE_HALF && Data->Iopb->Parameters.Write.Length > 1)
            {
                Data->Iopb->Parameters.Write.Length /= 2;
                FltSetCallbackDataDirty(Data);
                InterlockedIncrement((PLONG)&Stats.Halved);
            }
            else if (Mode == MODE_PEND)
            {
                PPEND_ITEM Item = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Item), TAG_SAMPLE);

                PEPROCESS Process = FltGetRequestorProcess(Data);

                if (Item && Process)
                {
                    ObReferenceObject(Process);
                    Item->Process = Process;
                    Item->Data = Data;
                    InterlockedIncrement(&PendingWorkers);
                    KeResetEvent(&WorkersDone);
                    InterlockedIncrement((PLONG)&Stats.Pended);
                    QueueSampleWork(&Item->WorkItem, PendWorker, Item);
                    return FLT_PREOP_PENDING;
                }
                if (Item)
                    ExFreePoolWithTag(Item, TAG_SAMPLE);
            }
            else if (Mode == MODE_PDPC)
            {
                PPEND_DPC_ITEM Item = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Item), TAG_SAMPLE);

                if (Item)
                {
                    LARGE_INTEGER Due;

                    Item->Data = Data;
                    KeInitializeDpc(&Item->Dpc, PendDpcRoutine, Item);
                    KeInitializeTimer(&Item->Timer);
                    InterlockedIncrement(&PendingWorkers);
                    KeResetEvent(&WorkersDone);
                    InterlockedIncrement((PLONG)&Stats.PendDpc);
                    Due.QuadPart = -10000LL * 10;
                    KeSetTimer(&Item->Timer, Due, &Item->Dpc);
                    return FLT_PREOP_PENDING;
                }
            }
            break;

        case IRP_MJ_READ:
            if (Paging)
                break;
            Mode = FindMode(FileObject);
            if (Mode == MODE_DPCREAD)
            {
                /* A context of this read only: its last reference goes in the post-operation */
                PSAMPLE_CONTEXT Sample = NewContext(FLT_STREAMHANDLE_CONTEXT, Mode);

                if (Sample)
                {
                    *CompletionContext = Sample;
                    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
                }
                break;
            }
            if (Mode == MODE_SYNC)
            {
                InterlockedIncrement((PLONG)&Stats.Synchronized);
                *CompletionContext = PsGetCurrentThread();
                return FLT_PREOP_SYNCHRONIZE;
            }
            break;

        case IRP_MJ_SET_INFORMATION:
            if (VetoEnabled && FindMode(FileObject) == MODE_NODEL)
            {
                switch (Data->Iopb->Parameters.SetFileInformation.FileInformationClass)
                {
                    case FileDispositionInformation:
                    case FileRenameInformation:
                    case FileLinkInformation:
                        return Veto(Data);
                    default:
                        break;
                }
            }
            break;

        default:
            break;
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

static
FLT_POSTOP_CALLBACK_STATUS
FLTAPI
SafePostOperation(_Inout_ PFLT_CALLBACK_DATA Data,
                  _In_ PCFLT_RELATED_OBJECTS FltObjects,
                  _In_opt_ PVOID CompletionContext,
                  _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    InterlockedIncrement((PLONG)&Stats.SafePosts);
    if (KeGetCurrentIrql() < DISPATCH_LEVEL)
        InterlockedIncrement((PLONG)&Stats.SafeWorkerPassive);

    return FLT_POSTOP_FINISHED_PROCESSING;
}

static
FLT_POSTOP_CALLBACK_STATUS
FLTAPI
PostOperation(_Inout_ PFLT_CALLBACK_DATA Data,
              _In_ PCFLT_RELATED_OBJECTS FltObjects,
              _In_opt_ PVOID CompletionContext,
              _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    UCHAR Major = Data->Iopb->MajorFunction;
    PFILE_OBJECT FileObject = Data->Iopb->TargetFileObject;
    FLT_POSTOP_CALLBACK_STATUS Status;

    if (Major < FLTSAMPLE_MAX_MAJOR)
        InterlockedIncrement((PLONG)&Stats.Post[Major]);

    if (Flags & FLTFL_POST_OPERATION_DRAINING)
    {
        InterlockedIncrement((PLONG)&Stats.DrainingPosts);
        if (Major == IRP_MJ_READ && CompletionContext && FindMode(FileObject) == MODE_DPCREAD)
            FltReleaseContext(CompletionContext);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (!NT_SUCCESS(Data->IoStatus.Status))
        InterlockedIncrement((PLONG)&Stats.PostErrors);

    switch (Major)
    {
        case IRP_MJ_CREATE:
            Stats.LastCreatePost = KeQueryPerformanceCounter(NULL).QuadPart;
            /* Post-create callbacks run at PASSIVE_LEVEL in the thread which sent the create (WDK) */
            InterlockedIncrement((PLONG)&Stats.CreatePosts);
            if (KeGetCurrentIrql() != PASSIVE_LEVEL)
            {
                InterlockedIncrement((PLONG)&Stats.CreatePostNotPassive);
                break;
            }
            if (CompletionContext && CompletionContext != PsGetCurrentThread())
                InterlockedIncrement((PLONG)&Stats.CreatePostOtherThread);
            if (!NT_SUCCESS(Data->IoStatus.Status))
                RemoveOpen(FileObject);
            else if (UseContexts)
                AttachContexts(FltObjects, FileObject, FindMode(FileObject));
            break;

        case IRP_MJ_WRITE:
            Stats.LastWritePost = KeQueryPerformanceCounter(NULL).QuadPart;
            if ((RvFlags & FLTSAMPLE_RV_PARK_WRITE_POST) && FLT_IS_IRP_OPERATION(Data) &&
                !(Data->Iopb->IrpFlags & IRP_PAGING_IO))
            {
                PRV_PARK_ITEM Item = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Item), TAG_SAMPLE);

                if (Item)
                {
                    Item->Data = Data;
                    InterlockedIncrement(&PendingWorkers);
                    KeResetEvent(&WorkersDone);
                    InterlockedIncrement((PLONG)&Stats.RvParked);
                    QueueSampleWork(&Item->WorkItem, RvParkWorker, Item);
                    return FLT_POSTOP_MORE_PROCESSING_REQUIRED;
                }
            }
            break;

        case IRP_MJ_READ:
            if (CompletionContext && FindMode(FileObject) == MODE_DPCREAD)
            {
                /* Maybe DISPATCH_LEVEL: the cleanup callback must still come at APC_LEVEL or below */
                InterlockedIncrement((PLONG)&Stats.DpcReadPosts);
                if (KeGetCurrentIrql() == DISPATCH_LEVEL)
                    InterlockedIncrement((PLONG)&Stats.DpcReadPostsAtDispatch);
                FltReleaseContext(CompletionContext);
                break;
            }
            if ((RvFlags & FLTSAMPLE_RV_PARK_FASTIO_POST) && FLT_IS_FASTIO_OPERATION(Data))
            {
                PRV_PARK_ITEM Item = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Item), TAG_SAMPLE);

                /* A filter breaking the rule: it will call FltCompletePendedPostOperation later */
                if (Item)
                {
                    Item->Data = Data;
                    InterlockedIncrement(&PendingWorkers);
                    KeResetEvent(&WorkersDone);
                    InterlockedIncrement((PLONG)&Stats.RvParked);
                    QueueSampleWork(&Item->WorkItem, RvParkWorker, Item);
                    return FLT_POSTOP_MORE_PROCESSING_REQUIRED;
                }
            }
            if ((RvFlags & FLTSAMPLE_RV_PARK_READ_POST) && FLT_IS_IRP_OPERATION(Data) &&
                !(Data->Iopb->IrpFlags & IRP_PAGING_IO) && CompletionContext == NULL)
            {
                PRV_PARK_ITEM Item = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Item), TAG_SAMPLE);

                if (Item)
                {
                    Item->Data = Data;
                    InterlockedIncrement(&PendingWorkers);
                    KeResetEvent(&WorkersDone);
                    InterlockedIncrement((PLONG)&Stats.RvParked);
                    QueueSampleWork(&Item->WorkItem, RvParkWorker, Item);
                    return FLT_POSTOP_MORE_PROCESSING_REQUIRED;
                }
            }
            if (CompletionContext)
            {
                /* The pre-operation asked for FLT_PREOP_SYNCHRONIZE */
                if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
                    InterlockedIncrement((PLONG)&Stats.SyncPostNotPassive);
                if (CompletionContext == PsGetCurrentThread())
                    InterlockedIncrement((PLONG)&Stats.SyncSameThread);
            }
            else if (FindMode(FileObject) == MODE_SAFE)
            {
                BOOLEAN PagingRead = FLT_IS_IRP_OPERATION(Data) && (Data->Iopb->IrpFlags & IRP_PAGING_IO);
                BOOLEAN Done = FltDoCompletionProcessingWhenSafe(Data,
                                                                 FltObjects,
                                                                 CompletionContext,
                                                                 Flags,
                                                                 SafePostOperation,
                                                                 &Status);

                /* Paging I/O is never posted to a worker (WDK): run right here, or FALSE */
                if (PagingRead)
                {
                    InterlockedIncrement((PLONG)&Stats.SafePagingCalls);
                    if (!Done)
                        InterlockedIncrement((PLONG)&Stats.SafePagingRefused);
                    else if (Status == FLT_POSTOP_MORE_PROCESSING_REQUIRED)
                        InterlockedIncrement((PLONG)&Stats.SafePagingPosted);
                }
                if (Done)
                    return Status;
            }
            break;

        default:
            break;
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}


/* A section for a file is about to be created: the anti-virus pattern refuses it for some files */
static
FLT_PREOP_CALLBACK_STATUS
FLTAPI
PreSectionSync(_Inout_ PFLT_CALLBACK_DATA Data,
               _In_ PCFLT_RELATED_OBJECTS FltObjects,
               _Outptr_result_maybenull_ PVOID *CompletionContext)
{
    PFILE_OBJECT FileObject = Data->Iopb->TargetFileObject;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    if (FileObject == NULL || !IsTracked(FileObject))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    InterlockedIncrement((PLONG)&Stats.SectionSyncPre);
    if (!FLT_IS_FS_FILTER_OPERATION(Data))
        InterlockedIncrement((PLONG)&Stats.SectionSyncBadData);

    if (FindMode(FileObject) == MODE_NOSEC &&
        Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType == SyncTypeCreateSection)
    {
        InterlockedIncrement((PLONG)&Stats.SectionSyncDenied);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

static
FLT_POSTOP_CALLBACK_STATUS
FLTAPI
PostSectionSync(_Inout_ PFLT_CALLBACK_DATA Data,
                _In_ PCFLT_RELATED_OBJECTS FltObjects,
                _In_opt_ PVOID CompletionContext,
                _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    InterlockedIncrement((PLONG)&Stats.SectionSyncPost);
    /* What the file system's own callback (below the filter manager) said, if it has one */
    if (Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType == SyncTypeCreateSection)
        Stats.LastSectionSyncPostStatus = Data->IoStatus.Status;
    return FLT_POSTOP_FINISHED_PROCESSING;
}

/*
 * The other FsFilter operations: the release of a section synchronization, the modified page writer's
 * acquire and release, the cache flush's acquire and release. Counted for .fsf files, by operation
 * (FLTSAMPLE_FSF_INDEX), with the thread (an acquire and its release come from the same thread).
 */
static
FLT_PREOP_CALLBACK_STATUS
FLTAPI
PreFsFilter(_Inout_ PFLT_CALLBACK_DATA Data,
            _In_ PCFLT_RELATED_OBJECTS FltObjects,
            _Outptr_result_maybenull_ PVOID *CompletionContext)
{
    PFILE_OBJECT FileObject = Data->Iopb->TargetFileObject;
    ULONG Index = FLTSAMPLE_FSF_INDEX(Data->Iopb->MajorFunction);

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    if (FileObject == NULL || Index >= FLTSAMPLE_FSF_OPS || FindMode(FileObject) != MODE_FSF)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    InterlockedIncrement((PLONG)&Stats.FsFilterPre[Index]);
    if (!FLT_IS_FS_FILTER_OPERATION(Data))
        InterlockedIncrement((PLONG)&Stats.SectionSyncBadData);
    *CompletionContext = PsGetCurrentThread();
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

static
FLT_POSTOP_CALLBACK_STATUS
FLTAPI
PostFsFilter(_Inout_ PFLT_CALLBACK_DATA Data,
             _In_ PCFLT_RELATED_OBJECTS FltObjects,
             _In_opt_ PVOID CompletionContext,
             _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    ULONG Index = FLTSAMPLE_FSF_INDEX(Data->Iopb->MajorFunction);

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    if (Index < FLTSAMPLE_FSF_OPS)
    {
        InterlockedIncrement((PLONG)&Stats.FsFilterPost[Index]);
        if (CompletionContext != PsGetCurrentThread())
            InterlockedIncrement((PLONG)&Stats.FsFilterOtherThread);
        if (!NT_SUCCESS(Data->IoStatus.Status))
            InterlockedIncrement((PLONG)&Stats.FsFilterFailed[Index]);
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}


/* INSTANCES **************************************************************/

static
NTSTATUS
FLTAPI
InstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects,
              _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
              _In_ DEVICE_TYPE VolumeDeviceType,
              _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(VolumeDeviceType);

    if ((ULONG)VolumeFilesystemType >= FLTSAMPLE_FSTYPES ||
        !(AttachMask & (1UL << VolumeFilesystemType)))
    {
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    InterlockedIncrement((PLONG)&Stats.InstanceSetups);
    InterlockedIncrement((PLONG)&Stats.SetupsByFsType[VolumeFilesystemType]);
    InterlockedIncrement((PLONG)&Stats.LiveInstances);
    if (UseContexts)
    {
        PSAMPLE_CONTEXT Sample = NewContext(FLT_INSTANCE_CONTEXT, 0);

        if (Sample)
        {
            (VOID)FltSetInstanceContext(FltObjects->Instance, FLT_SET_CONTEXT_REPLACE_IF_EXISTS, Sample, NULL);
            FltReleaseContext(Sample);
        }
    }
    if ((RvFlags & FLTSAMPLE_RV_NESTED_ATTACH) && !InNestedAttach)
    {
        PFLT_INSTANCE Inner = NULL;

        /* Review test: one instance per volume and name, so ours will be refused once we said yes */
        InNestedAttach = TRUE;
        if (NT_SUCCESS(FltAttachVolume(SampleFilter, FltObjects->Volume, NULL, &Inner)) && Inner)
            FltObjectDereference(Inner);
        InNestedAttach = FALSE;
    }
    if (Flags & FLTFL_INSTANCE_SETUP_MANUAL_ATTACHMENT)
        InterlockedIncrement((PLONG)&Stats.ManualSetups);
    if (Flags & FLTFL_INSTANCE_SETUP_NEWLY_MOUNTED_VOLUME)
        InterlockedIncrement((PLONG)&Stats.NewlyMountedSetups);

    return STATUS_SUCCESS;
}

static
NTSTATUS
FLTAPI
InstanceQueryTeardown(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                      _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    InterlockedIncrement((PLONG)&Stats.QueryTeardowns);
    return RefuseDetach ? STATUS_FLT_DO_NOT_DETACH : STATUS_SUCCESS;
}

static
VOID
FLTAPI
InstanceTeardownStart(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                      _In_ FLT_INSTANCE_TEARDOWN_FLAGS Reason)
{
    UNREFERENCED_PARAMETER(FltObjects);

    Stats.LastTeardownReason = Reason;
    InterlockedIncrement((PLONG)&Stats.InstanceTeardownStarts);
}

static
VOID
FLTAPI
InstanceTeardownComplete(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                         _In_ FLT_INSTANCE_TEARDOWN_FLAGS Reason)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Reason);

    InterlockedIncrement((PLONG)&Stats.InstanceTeardownCompletes);
    InterlockedDecrement((PLONG)&Stats.LiveInstances);
}

static
VOID
ReportRun(_In_ PCWSTR Name,
          _In_ ULONG Value)
{
    RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, RegistryPathBuffer, Name, REG_DWORD, &Value, sizeof(Value));
}

static
NTSTATUS
FLTAPI
FilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    if (RefuseUnload && !(Flags & FLTFL_FILTER_UNLOAD_MANDATORY))
        return STATUS_FLT_DO_NOT_DETACH;

    /* No new clients; the connected ones are disconnected by the unregistering */
    if (ServerPort)
    {
        FltCloseCommunicationPort(ServerPort);
        ServerPort = NULL;
    }

    /* A volume we still hold (FLTSAMPLE_IOCTL_HOLD_VOLUME) */
    if (HeldVolume)
    {
        FltObjectDereference(HeldVolume);
        HeldVolume = NULL;
    }
    while (LeakedCount)
        FltObjectDereference(LeakedVolumes[--LeakedCount]);

    /* Pended operations need their worker, which needs our code, so wait for those */
    FltUnregisterFilter(SampleFilter);
    SampleFilter = NULL;
    while (PendingWorkers)
        KeWaitForSingleObject(&WorkersDone, Executive, KernelMode, FALSE, NULL);
    /* A DPC which woke us may still be on its way out of our code */
    KeFlushQueuedDpcs();

    /* Leave a report in the service key: all instances must be gone by now */
    ReportRun(L"LastRunSetups", Stats.InstanceSetups);
    ReportRun(L"LastRunTeardownStarts", Stats.InstanceTeardownStarts);
    ReportRun(L"LastRunTeardownCompletes", Stats.InstanceTeardownCompletes);
    ReportRun(L"LastRunLive", Stats.LiveInstances);
    ReportRun(L"LastRunWorkers", PendingWorkers);
    ReportRun(L"LastRunCtxAlloc", Stats.Contexts[FLTSAMPLE_CTX_ALLOCATED]);
    ReportRun(L"LastRunCtxCleaned", Stats.Contexts[FLTSAMPLE_CTX_CLEANED]);
    /* Every connection the filter accepted has had its DisconnectNotify by the end of FltUnregisterFilter */
    ReportRun(L"LastRunPortConnects", Stats.PortConnects);
    ReportRun(L"LastRunPortDisconnects", Stats.PortDisconnects);

    IoDeleteSymbolicLink(&SymLinkName);
    if (ControlDevice)
    {
        IoDeleteDevice(ControlDevice);
        ControlDevice = NULL;
    }

    return STATUS_SUCCESS;
}


/* CONTROL DEVICE *********************************************************/

typedef struct _ATTACH_RESULT
{
    ULONG Done;
    ULONG Failed;
    NTSTATUS LastStatus;

} ATTACH_RESULT, *PATTACH_RESULT;

static
NTSTATUS
ForEachVolume(_In_ BOOLEAN Attach,
              _Out_ PATTACH_RESULT Result)
{
    PFLT_VOLUME *Volumes = NULL;
    ULONG Count = 0, i;
    NTSTATUS Status;

    RtlZeroMemory(Result, sizeof(*Result));

    Status = FltEnumerateVolumes(SampleFilter, NULL, 0, &Count);
    if (Status != STATUS_BUFFER_TOO_SMALL || Count == 0)
        return Status == STATUS_BUFFER_TOO_SMALL ? STATUS_SUCCESS : Status;

    Volumes = ExAllocatePoolWithTag(NonPagedPool, (Count + 4) * sizeof(PFLT_VOLUME), TAG_SAMPLE);
    if (Volumes == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    Status = FltEnumerateVolumes(SampleFilter, Volumes, Count + 4, &Count);
    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(Volumes, TAG_SAMPLE);
        return Status;
    }

    for (i = 0; i < Count; i++)
    {
        PFLT_INSTANCE Instance = NULL;

        if (Attach)
            Status = FltAttachVolume(SampleFilter, Volumes[i], NULL, &Instance);
        else
            Status = FltDetachVolume(SampleFilter, Volumes[i], NULL);

        if (NT_SUCCESS(Status))
            Result->Done++;
        else
            Result->Failed++;
        Result->LastStatus = Status;

        if (Instance)
            FltObjectDereference(Instance);
        FltObjectDereference(Volumes[i]);
    }

    ExFreePoolWithTag(Volumes, TAG_SAMPLE);
    return STATUS_SUCCESS;
}

/* What FltGetVolumeProperties and FltGetVolumeName say about a volume */
static
VOID
GetVolumeProps(_In_ PFLT_VOLUME Volume,
               _Out_ FLTSAMPLE_VOLUME_PROPS *Props)
{
    ULONG Buffer[128];
    PFLT_VOLUME_PROPERTIES Properties = (PFLT_VOLUME_PROPERTIES)Buffer;
    UNICODE_STRING Name;
    ULONG Length = 0;

    RtlZeroMemory(Props, sizeof(*Props));
    Props->Status = FltGetVolumeProperties(Volume, Properties, sizeof(Buffer), &Length);
    if (NT_SUCCESS(Props->Status))
    {
        Props->DeviceType = Properties->DeviceType;
        Props->DeviceCharacteristics = Properties->DeviceCharacteristics;
        Props->DeviceObjectFlags = Properties->DeviceObjectFlags;
        Props->AlignmentRequirement = Properties->AlignmentRequirement;
        Props->SectorSize = Properties->SectorSize;
        RtlCopyMemory(Props->DriverName, Properties->FileSystemDriverName.Buffer,
                      min(Properties->FileSystemDriverName.Length, sizeof(Props->DriverName) - sizeof(WCHAR)));
    }
    RtlInitEmptyUnicodeString(&Name, Props->VolumeName, sizeof(Props->VolumeName) - sizeof(WCHAR));
    (VOID)FltGetVolumeName(Volume, &Name, NULL);
}

typedef struct _DELAYED_PING
{
    WORK_QUEUE_ITEM Item;
    KEVENT Event;
    volatile LONG Refs;
} DELAYED_PING, *PDELAYED_PING;

static
VOID
NTAPI
DelayedPingWorker(_In_ PVOID Parameter)
{
    PDELAYED_PING Ping = Parameter;

    KeSetEvent(&Ping->Event, IO_NO_INCREMENT, FALSE);
    if (InterlockedDecrement(&Ping->Refs) == 0)
        ExFreePoolWithTag(Ping, TAG_SAMPLE);
}

/* Takes a reference to the volume of that name, as a filter which keeps volumes around does */
static
NTSTATUS
HoldVolume(_In_reads_bytes_(Length) PCWSTR Wanted,
           _In_ ULONG Length,
           _In_ BOOLEAN Leak)
{
    PFLT_VOLUME *Volumes;
    ULONG Count = 0, i;
    UNICODE_STRING WantedName;
    NTSTATUS Status;
    BOOLEAN Taken = FALSE;

    if ((!Leak && HeldVolume) || (Leak && LeakedCount >= LEAKED_VOLUMES_MAX) || SampleFilter == NULL)
        return STATUS_INVALID_DEVICE_STATE;
    WantedName.Buffer = (PWCH)Wanted;
    WantedName.Length = WantedName.MaximumLength = (USHORT)min(Length & ~1, 0xFFFE);

    Status = FltEnumerateVolumes(SampleFilter, NULL, 0, &Count);
    if (Status != STATUS_BUFFER_TOO_SMALL || Count == 0)
        return STATUS_NOT_FOUND;
    Volumes = ExAllocatePoolWithTag(NonPagedPool, (Count + 4) * sizeof(PFLT_VOLUME), TAG_SAMPLE);
    if (Volumes == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    Status = FltEnumerateVolumes(SampleFilter, Volumes, Count + 4, &Count);
    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(Volumes, TAG_SAMPLE);
        return Status;
    }

    Status = STATUS_NOT_FOUND;
    for (i = 0; i < Count; i++)
    {
        FLTSAMPLE_VOLUME_PROPS Props;
        UNICODE_STRING Name;

        GetVolumeProps(Volumes[i], &Props);
        RtlInitUnicodeString(&Name, Props.VolumeName);
        if (!Taken && RtlEqualUnicodeString(&Name, &WantedName, TRUE))
        {
            /* This reference stays */
            if (Leak)
            {
                LeakedVolumes[LeakedCount++] = Volumes[i];
            }
            else
            {
                HeldVolume = Volumes[i];
                HeldBefore = Props;
            }
            Taken = TRUE;
            Status = STATUS_SUCCESS;
            continue;
        }
        FltObjectDereference(Volumes[i]);
    }

    ExFreePoolWithTag(Volumes, TAG_SAMPLE);
    return Status;
}

static
NTSTATUS
NTAPI
ControlDispatch(_In_ PDEVICE_OBJECT DeviceObject,
                _Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG InLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG OutLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID Buffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG Information = 0;
    NTSTATUS Status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Stack->MajorFunction == IRP_MJ_DEVICE_CONTROL)
    {
        switch (Stack->Parameters.DeviceIoControl.IoControlCode)
        {
            case FLTSAMPLE_IOCTL_GET_STATS:
            {
                PFLTSAMPLE_STATS Out = Buffer;
                ULONG Count = 0;

                if (OutLength < sizeof(*Out))
                {
                    Status = STATUS_BUFFER_TOO_SMALL;
                    break;
                }
                RtlCopyMemory(Out, &Stats, sizeof(*Out));
                Out->Size = sizeof(*Out);
                if (SampleFilter)
                    (VOID)FltEnumerateVolumes(SampleFilter, NULL, 0, &Count);
                Out->VolumeCount = Count;
                Information = sizeof(*Out);
                break;
            }

            case FLTSAMPLE_IOCTL_RESET:
            {
                LONG Setups = Stats.InstanceSetups, Starts = Stats.InstanceTeardownStarts,
                     Completes = Stats.InstanceTeardownCompletes, Live = Stats.LiveInstances,
                     Queries = Stats.QueryTeardowns, Manual = Stats.ManualSetups, Open = Stats.OpenFiles,
                     CtxAlloc = Stats.Contexts[FLTSAMPLE_CTX_ALLOCATED], CtxCleaned = Stats.Contexts[FLTSAMPLE_CTX_CLEANED];

                RtlZeroMemory(&Stats, sizeof(Stats));
                Stats.InstanceSetups = Setups;
                Stats.InstanceTeardownStarts = Starts;
                Stats.InstanceTeardownCompletes = Completes;
                Stats.LiveInstances = Live;
                Stats.QueryTeardowns = Queries;
                Stats.ManualSetups = Manual;
                Stats.OpenFiles = Open;
                Stats.Contexts[FLTSAMPLE_CTX_ALLOCATED] = CtxAlloc;
                Stats.Contexts[FLTSAMPLE_CTX_CLEANED] = CtxCleaned;
                break;
            }

            case FLTSAMPLE_IOCTL_ATTACH_ALL:
            case FLTSAMPLE_IOCTL_DETACH_ALL:
                if (OutLength < sizeof(ATTACH_RESULT) || SampleFilter == NULL)
                {
                    Status = STATUS_BUFFER_TOO_SMALL;
                    break;
                }
                Status = ForEachVolume(Stack->Parameters.DeviceIoControl.IoControlCode == FLTSAMPLE_IOCTL_ATTACH_ALL,
                                       Buffer);
                Information = sizeof(ATTACH_RESULT);
                break;

            case FLTSAMPLE_IOCTL_SET_PEND_DELAY:
                if (InLength < sizeof(ULONG)) { Status = STATUS_INVALID_PARAMETER; break; }
                PendDelayMs = *(PULONG)Buffer;
                break;

            case FLTSAMPLE_IOCTL_REFUSE_DETACH:
                if (InLength < sizeof(ULONG)) { Status = STATUS_INVALID_PARAMETER; break; }
                RefuseDetach = *(PULONG)Buffer != 0;
                break;

            case FLTSAMPLE_IOCTL_USE_CONTEXTS:
                if (InLength < sizeof(ULONG)) { Status = STATUS_INVALID_PARAMETER; break; }
                UseContexts = *(PULONG)Buffer != 0;
                break;

            case FLTSAMPLE_IOCTL_CONTEXT_SELFTEST:
                if (OutLength < sizeof(Stats.SelfTest) || SampleFilter == NULL)
                {
                    Status = STATUS_BUFFER_TOO_SMALL;
                    break;
                }
                ContextSelfTest(Buffer);
                Information = sizeof(Stats.SelfTest);
                break;

            case FLTSAMPLE_IOCTL_SET_VETO:
                if (InLength < sizeof(ULONG)) { Status = STATUS_INVALID_PARAMETER; break; }
                VetoEnabled = *(PULONG)Buffer != 0;
                break;

            case FLTSAMPLE_IOCTL_RV_FLAGS:
                if (InLength < sizeof(ULONG)) { Status = STATUS_INVALID_PARAMETER; break; }
                RvFlags = *(PULONG)Buffer;
                break;

            case FLTSAMPLE_IOCTL_CLOSE_CLIENT:
                /* The filter lets go of its client, whatever it is doing with it */
                if (SampleFilter)
                    FltCloseClientPort(SampleFilter, &ClientPort);
                break;

            case FLTSAMPLE_IOCTL_REFUSE_UNLOAD:
                if (InLength < sizeof(ULONG)) { Status = STATUS_INVALID_PARAMETER; break; }
                RefuseUnload = *(PULONG)Buffer != 0;
                break;

            case FLTSAMPLE_IOCTL_HOLD_VOLUME:
                if (InLength < sizeof(WCHAR)) { Status = STATUS_INVALID_PARAMETER; break; }
                Status = HoldVolume(Buffer, InLength, FALSE);
                break;

            case FLTSAMPLE_IOCTL_LEAK_VOLUME:
                /* Test only: a filter which never drops a volume reference, one more volume each time */
                if (InLength < sizeof(WCHAR)) { Status = STATUS_INVALID_PARAMETER; break; }
                Status = HoldVolume(Buffer, InLength, TRUE);
                break;

            case FLTSAMPLE_IOCTL_DELAYED_PING:
            {
                /* In: milliseconds to wait (ULONG). Out: ULONG, 1 if a work item of the delayed queue ran in time */
                PDELAYED_PING Ping;
                LARGE_INTEGER Timeout;

                if (InLength < sizeof(ULONG) || OutLength < sizeof(ULONG)) { Status = STATUS_BUFFER_TOO_SMALL; break; }
                Ping = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Ping), TAG_SAMPLE);
                if (Ping == NULL) { Status = STATUS_INSUFFICIENT_RESOURCES; break; }
                Ping->Refs = 2;
                KeInitializeEvent(&Ping->Event, NotificationEvent, FALSE);
                ExInitializeWorkItem(&Ping->Item, DelayedPingWorker, Ping);
                Timeout.QuadPart = -(LONGLONG)(*(PULONG)Buffer) * 10000;
                ExQueueWorkItem(&Ping->Item, DelayedWorkQueue);
                Status = KeWaitForSingleObject(&Ping->Event, Executive, KernelMode, FALSE, &Timeout);
                *(PULONG)Buffer = (Status == STATUS_SUCCESS);
                Status = STATUS_SUCCESS;
                Information = sizeof(ULONG);
                /* The worker may still come: it frees the item then */
                if (InterlockedDecrement(&Ping->Refs) == 0)
                    ExFreePoolWithTag(Ping, TAG_SAMPLE);
                break;
            }

            case FLTSAMPLE_IOCTL_DROP_LEAKED:
            {
                ULONG Dropped = LeakedCount;

                if (OutLength < sizeof(ULONG)) { Status = STATUS_BUFFER_TOO_SMALL; break; }
                while (LeakedCount)
                    FltObjectDereference(LeakedVolumes[--LeakedCount]);
                *(PULONG)Buffer = Dropped;
                Information = sizeof(ULONG);
                break;
            }

            case FLTSAMPLE_IOCTL_RELEASE_VOLUME:
            {
                FLTSAMPLE_HELD_VOLUME *Out = Buffer;

                if (OutLength < sizeof(*Out)) { Status = STATUS_BUFFER_TOO_SMALL; break; }
                RtlZeroMemory(Out, sizeof(*Out));
                if (HeldVolume)
                {
                    Out->Held = 1;
                    Out->Before = HeldBefore;
                    GetVolumeProps(HeldVolume, &Out->After);
                    FltObjectDereference(HeldVolume);
                    HeldVolume = NULL;
                }
                Information = sizeof(*Out);
                break;
            }

            default:
                Status = STATUS_INVALID_DEVICE_REQUEST;
                break;
        }
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = NT_SUCCESS(Status) ? Information : 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}


/* PORT *******************************************************************/

static
NTSTATUS
FLTAPI
PortConnect(_In_ PFLT_PORT Client,
            _In_opt_ PVOID ServerPortCookie,
            _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
            _In_ ULONG SizeOfContext,
            _Outptr_result_maybenull_ PVOID *ConnectionPortCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);

    /* A client which says "refuse" in its connection context is turned away */
    if (SizeOfContext == 6 && RtlCompareMemory(ConnectionContext, "refuse", 6) == 6)
        return STATUS_ACCESS_DENIED;

    ClientPort = Client;
    *ConnectionPortCookie = (PVOID)(ULONG_PTR)0x4C4F4B43;
    InterlockedIncrement((PLONG)&Stats.PortConnects);
    return STATUS_SUCCESS;
}

static
VOID
FLTAPI
PortDisconnect(_In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    InterlockedIncrement((PLONG)&Stats.PortDisconnects);
    FltCloseClientPort(SampleFilter, &ClientPort);
}

/* Review test: where the message buffers are, and whether they are the client's (FLTSAMPLE_MSG_WHERE) */
static
NTSTATUS
WhereAreTheBuffers(_In_ PFLTSAMPLE_MSG Message,
                   _In_ ULONG InputBufferLength,
                   _In_opt_ PVOID OutputBuffer,
                   _In_ ULONG OutputBufferLength,
                   _Out_ PULONG ReturnOutputBufferLength)
{
    FLTSAMPLE_WHERE_RESULT Result = { 0 };
    ULONG64 Where[2];

    if (InputBufferLength < FIELD_OFFSET(FLTSAMPLE_MSG, Data) + sizeof(Where) ||
        OutputBufferLength < sizeof(Result))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlCopyMemory(Where, Message->Data, sizeof(Where));
    Result.InputIsClients = Where[0] == (ULONG64)(ULONG_PTR)Message;
    Result.OutputIsClients = Where[1] == (ULONG64)(ULONG_PTR)OutputBuffer;
    Result.PreviousModeUser = ExGetPreviousMode() == UserMode;
    if (Result.PreviousModeUser)
    {
        /* What a filter ported from Windows does with them */
        _SEH2_TRY
        {
            ProbeForRead(Message, InputBufferLength, 1);
            ProbeForWrite(OutputBuffer, OutputBufferLength, 1);
            Result.ProbesOk = TRUE;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Result.ProbesOk = FALSE;
        }
        _SEH2_END;
    }

    RtlCopyMemory(OutputBuffer, &Result, sizeof(Result));
    *ReturnOutputBufferLength = sizeof(Result);
    return STATUS_SUCCESS;
}

static
NTSTATUS
PortMessageWork(_In_opt_ PVOID PortCookie,
                _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
                _In_ ULONG InputBufferLength,
                _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
                _In_ ULONG OutputBufferLength,
                _Out_ PULONG ReturnOutputBufferLength)
{
    PFLTSAMPLE_MSG Message = InputBuffer;
    NTSTATUS Status;
    ULONG Reply = 0;
    LARGE_INTEGER Timeout;

    *ReturnOutputBufferLength = 0;
    InterlockedIncrement((PLONG)&Stats.PortMessages);
    if ((InputBuffer == NULL && InputBufferLength != 0) || (OutputBuffer == NULL && OutputBufferLength != 0))
        InterlockedIncrement((PLONG)&Stats.MsgNullWithLength);

    if (PortCookie != (PVOID)(ULONG_PTR)0x4C4F4B43 || Message == NULL || InputBufferLength < FIELD_OFFSET(FLTSAMPLE_MSG, Data))
        return STATUS_INVALID_PARAMETER;

    switch (Message->Code)
    {
        case FLTSAMPLE_MSG_PING:
        {
            ULONG Length = InputBufferLength - FIELD_OFFSET(FLTSAMPLE_MSG, Data);

            if (Length > OutputBufferLength)
                Length = OutputBufferLength;
            if (Length)
                RtlCopyMemory(OutputBuffer, Message->Data, Length);
            *ReturnOutputBufferLength = Length;
            return STATUS_SUCCESS;
        }

        case FLTSAMPLE_MSG_GET_STATS:
            if (OutputBufferLength < sizeof(Stats))
                return STATUS_BUFFER_TOO_SMALL;
            RtlCopyMemory(OutputBuffer, &Stats, sizeof(Stats));
            *ReturnOutputBufferLength = sizeof(Stats);
            return STATUS_SUCCESS;

        case FLTSAMPLE_MSG_ARM:
            ArmAsk = Message->Arg != 0;
            return STATUS_SUCCESS;

        case FLTSAMPLE_MSG_WHERE:
            return WhereAreTheBuffers(Message, InputBufferLength, OutputBuffer, OutputBufferLength,
                                      ReturnOutputBufferLength);

        case FLTSAMPLE_MSG_OVERREPORT:
            /* A filter which claims more than it wrote: the client must not get bytes of ours */
            *ReturnOutputBufferLength = OutputBufferLength;
            return STATUS_SUCCESS;

        case FLTSAMPLE_MSG_NOTIFY:
        case FLTSAMPLE_MSG_ASK:
        {
            UCHAR Buffer[64];
            ULONG Length = min(Message->Arg, sizeof(Buffer));
            ULONG ReplyLength = Message->Code == FLTSAMPLE_MSG_ASK ? sizeof(Reply) : 0;
            BOOLEAN Forever;
            PFLTSAMPLE_ASK_RESULT Result = OutputBuffer;

            /* A message to the client; the first ULONG says what it is */
            *(PULONG)Buffer = Message->Code == FLTSAMPLE_MSG_ASK ? FLTSAMPLE_KIND_ASK : FLTSAMPLE_KIND_NOTIFY;
            if (Length > sizeof(ULONG))
                RtlFillMemory(Buffer + sizeof(ULONG), Length - sizeof(ULONG), 'k');
            else
                Length = sizeof(ULONG);

            /* The wait, in ms, comes after the message code: ULONG Data[0]. Zero is for ever. */
            if (InputBufferLength >= FIELD_OFFSET(FLTSAMPLE_MSG, Data) + sizeof(ULONG))
                Timeout.QuadPart = -10000LL * (LONGLONG)*(PULONG)Message->Data;
            else
                Timeout.QuadPart = -10000LL * 1000;
            Forever = Timeout.QuadPart == 0;

            Status = FltSendMessage(SampleFilter,
                                    &ClientPort,
                                    Buffer,
                                    Length,
                                    ReplyLength ? &Reply : NULL,
                                    ReplyLength ? &ReplyLength : NULL,
                                    Forever ? NULL : &Timeout);
            Stats.PortLastStatus = Status;
            InterlockedIncrement((PLONG)&Stats.PortSent);

            if (Result && OutputBufferLength >= sizeof(*Result))
            {
                RtlZeroMemory(Result, sizeof(*Result));
                Result->Status = Status;
                Result->ReplyLength = ReplyLength;
                RtlCopyMemory(Result->Reply, &Reply, min(ReplyLength, sizeof(Reply)));
                *ReturnOutputBufferLength = sizeof(*Result);
            }
            return STATUS_SUCCESS;
        }

        default:
            return STATUS_INVALID_DEVICE_REQUEST;
    }
}

/*
 * The message callback gets the client's own buffers, raw user mode memory (WDK, PFLT_MESSAGE_NOTIFY):
 * everything that touches them runs inside an exception handler.
 */
static
NTSTATUS
FLTAPI
PortMessage(_In_opt_ PVOID PortCookie,
            _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
            _In_ ULONG InputBufferLength,
            _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
            _In_ ULONG OutputBufferLength,
            _Out_ PULONG ReturnOutputBufferLength)
{
    NTSTATUS Status;

    _SEH2_TRY
    {
        Status = PortMessageWork(PortCookie, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength,
                                 ReturnOutputBufferLength);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        *ReturnOutputBufferLength = 0;
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;

    return Status;
}

/* A create the client has a say in: it gets the name, and a reply other than 0 refuses the create */
static
BOOLEAN
ClientRefuses(_In_ PCUNICODE_STRING Name)
{
    UCHAR Buffer[sizeof(ULONG) + 200];
    ULONG Length, Verdict = 0, VerdictLength = sizeof(Verdict);
    LARGE_INTEGER Timeout;
    NTSTATUS Status;

    if (!ArmAsk || ClientPort == NULL)
        return FALSE;

    *(PULONG)Buffer = FLTSAMPLE_KIND_CREATE;
    Length = min(Name->Length, sizeof(Buffer) - sizeof(ULONG));
    RtlCopyMemory(Buffer + sizeof(ULONG), Name->Buffer, Length);

    Timeout.QuadPart = -10000LL * 5000;
    InterlockedIncrement((PLONG)&Stats.PortAsked);
    Status = FltSendMessage(SampleFilter, &ClientPort, Buffer, sizeof(ULONG) + Length, &Verdict, &VerdictLength, &Timeout);
    if (!NT_SUCCESS(Status) || Status == STATUS_TIMEOUT)
    {
        InterlockedIncrement((PLONG)&Stats.PortAskFailed);
        return FALSE;
    }

    if (Verdict)
        InterlockedIncrement((PLONG)&Stats.PortDenied);
    return Verdict != 0;
}

/* ENTRY ******************************************************************/

static const FLT_OPERATION_REGISTRATION Operations[] =
{
    { IRP_MJ_CREATE, 0, PreOperation, PostOperation },
    { IRP_MJ_CLOSE, 0, PreOperation, PostOperation },
    { IRP_MJ_CLEANUP, 0, PreOperation, PostOperation },
    { IRP_MJ_READ, 0, PreOperation, PostOperation },
    { IRP_MJ_WRITE, 0, PreOperation, PostOperation },
    { IRP_MJ_QUERY_INFORMATION, 0, PreOperation, PostOperation },
    { IRP_MJ_SET_INFORMATION, 0, PreOperation, PostOperation },
    { IRP_MJ_DIRECTORY_CONTROL, 0, PreOperation, PostOperation },
    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION, 0, PreSectionSync, PostSectionSync },
    { IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION, 0, PreFsFilter, PostFsFilter },
    { IRP_MJ_ACQUIRE_FOR_MOD_WRITE, 0, PreFsFilter, PostFsFilter },
    { IRP_MJ_RELEASE_FOR_MOD_WRITE, 0, PreFsFilter, PostFsFilter },
    { IRP_MJ_ACQUIRE_FOR_CC_FLUSH, 0, PreFsFilter, PostFsFilter },
    { IRP_MJ_RELEASE_FOR_CC_FLUSH, 0, PreFsFilter, PostFsFilter },
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION Registration =
{
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    ContextRegistration,
    Operations,
    FilterUnload,
    InstanceSetup,
    InstanceQueryTeardown,
    InstanceTeardownStart,
    InstanceTeardownComplete,
    NULL,
    NULL,
    NULL,
};

static
VOID
ReadParameters(_In_ PUNICODE_STRING RegistryPath)
{
    RTL_QUERY_REGISTRY_TABLE Table[2];
    WCHAR Path[160];
    ULONG Mask = 0xFFFF;
    ULONG DefaultMask = 0xFFFF;

    if (RegistryPath->Length >= sizeof(Path) - sizeof(WCHAR))
        return;

    RtlCopyMemory(Path, RegistryPath->Buffer, RegistryPath->Length);
    Path[RegistryPath->Length / sizeof(WCHAR)] = UNICODE_NULL;
    RtlCopyMemory(RegistryPathBuffer, Path, sizeof(Path) < sizeof(RegistryPathBuffer) ? sizeof(Path) : sizeof(RegistryPathBuffer));

    RtlZeroMemory(Table, sizeof(Table));
    Table[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
    Table[0].Name = L"AttachMask";
    Table[0].EntryContext = &Mask;
    Table[0].DefaultType = REG_DWORD;
    Table[0].DefaultData = &DefaultMask;
    Table[0].DefaultLength = sizeof(ULONG);

    if (NT_SUCCESS(RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, Path, Table, NULL, NULL)))
        AttachMask = Mask;

    {
        ULONG Deny = 0, DefaultDeny = 0;

        RtlZeroMemory(Table, sizeof(Table));
        Table[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
        Table[0].Name = L"RvDenyAllPort";
        Table[0].EntryContext = &Deny;
        Table[0].DefaultType = REG_DWORD;
        Table[0].DefaultData = &DefaultDeny;
        Table[0].DefaultLength = sizeof(ULONG);
        if (NT_SUCCESS(RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, Path, Table, NULL, NULL)))
            RvDenyAllPort = Deny;
    }

    {
        ULONG Value = 0, DefaultValue = 0;

        RtlZeroMemory(Table, sizeof(Table));
        Table[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
        Table[0].Name = L"PortSecurity";
        Table[0].EntryContext = &Value;
        Table[0].DefaultType = REG_DWORD;
        Table[0].DefaultData = &DefaultValue;
        Table[0].DefaultLength = sizeof(ULONG);
        if (NT_SUCCESS(RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, Path, Table, NULL, NULL)))
            PortSecurity = Value;
    }
}

NTSTATUS
NTAPI
DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
            _In_ PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING DeviceName;
    WCHAR DeviceNameBuffer[80];
    PWCHAR Last;
    ULONG i;
    NTSTATUS Status;

    SampleDriver = DriverObject;
    KeInitializeSpinLock(&OpenLock);
    KeInitializeEvent(&WorkersDone, NotificationEvent, TRUE);
    Stats.Size = sizeof(Stats);

    /* The service name is the last part of the registry path */
    Last = RegistryPath->Buffer;
    for (i = 0; i < RegistryPath->Length / sizeof(WCHAR); i++)
    {
        if (RegistryPath->Buffer[i] == L'\\')
            Last = &RegistryPath->Buffer[i + 1];
    }
    for (i = 0; i < RTL_NUMBER_OF(ServiceName) - 1 &&
                &Last[i] < RegistryPath->Buffer + RegistryPath->Length / sizeof(WCHAR); i++)
    {
        ServiceName[i] = Last[i];
    }

    ReadParameters(RegistryPath);

    RtlStringCbPrintfW(DeviceNameBuffer, sizeof(DeviceNameBuffer), L"\\Device\\%ws", ServiceName);
    RtlInitUnicodeString(&DeviceName, DeviceNameBuffer);
    RtlStringCbPrintfW(SymLinkBuffer, sizeof(SymLinkBuffer), L"\\??\\%ws", ServiceName);
    RtlInitUnicodeString(&SymLinkName, SymLinkBuffer);

    Status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &ControlDevice);
    if (!NT_SUCCESS(Status))
        return Status;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = ControlDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = ControlDispatch;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ControlDispatch;

    Status = IoCreateSymbolicLink(&SymLinkName, &DeviceName);
    if (!NT_SUCCESS(Status))
        goto Fail;

    Status = FltRegisterFilter(DriverObject, &Registration, &SampleFilter);
    if (!NT_SUCCESS(Status))
        goto Fail;

    ControlDevice->Flags &= ~DO_DEVICE_INITIALIZING;

    {
        OBJECT_ATTRIBUTES PortAttributes;
        UNICODE_STRING PortName;
        WCHAR PortNameBuffer[80];
        PSECURITY_DESCRIPTOR BuiltDescriptor = NULL;

        RtlStringCbPrintfW(PortNameBuffer, sizeof(PortNameBuffer), L"\\%wsPort", ServiceName);
        RtlInitUnicodeString(&PortName, PortNameBuffer);
        InitializeObjectAttributes(&PortAttributes, &PortName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
        if (RvDenyAllPort)
        {
            /* Review test: a descriptor whose DACL is empty lets nobody connect */
            static SECURITY_DESCRIPTOR DenyAll;
            static ACL EmptyAcl;

            RtlCreateSecurityDescriptor(&DenyAll, SECURITY_DESCRIPTOR_REVISION);
            RtlCreateAcl(&EmptyAcl, sizeof(EmptyAcl), ACL_REVISION);
            RtlSetDaclSecurityDescriptor(&DenyAll, TRUE, &EmptyAcl, FALSE);
            PortAttributes.SecurityDescriptor = &DenyAll;
        }
        else if (PortSecurity == PORT_SECURITY_EVERYONE)
        {
            /* Everybody may connect */
            static SECURITY_DESCRIPTOR Everyone;
            static UCHAR AclBuffer[sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + SECURITY_MAX_SID_SIZE];
            PACL Acl = (PACL)AclBuffer;

            RtlCreateSecurityDescriptor(&Everyone, SECURITY_DESCRIPTOR_REVISION);
            RtlCreateAcl(Acl, sizeof(AclBuffer), ACL_REVISION);
            RtlAddAccessAllowedAce(Acl, ACL_REVISION, FLT_PORT_ALL_ACCESS, SeExports->SeWorldSid);
            RtlSetDaclSecurityDescriptor(&Everyone, TRUE, Acl, FALSE);
            PortAttributes.SecurityDescriptor = &Everyone;
        }
        else if (PortSecurity == PORT_SECURITY_BUILT_DEFAULT)
        {
            /* What the WDK samples do: the system and the administrators */
            Status = FltBuildDefaultSecurityDescriptor(&BuiltDescriptor, FLT_PORT_ALL_ACCESS);
            if (!NT_SUCCESS(Status))
            {
                FltUnregisterFilter(SampleFilter);
                SampleFilter = NULL;
                goto Fail;
            }
            PortAttributes.SecurityDescriptor = BuiltDescriptor;
        }
        Status = FltCreateCommunicationPort(SampleFilter, &ServerPort, &PortAttributes, NULL,
                                            PortConnect, PortDisconnect, PortMessage, 1);
        if (BuiltDescriptor)
        {
            /* The port has its own copy */
            FltFreeSecurityDescriptor(BuiltDescriptor);
            BuiltDescriptor = NULL;
        }
        if (!NT_SUCCESS(Status))
        {
            FltUnregisterFilter(SampleFilter);
            SampleFilter = NULL;
            goto Fail;
        }
    }

    Status = FltStartFiltering(SampleFilter);
    if (!NT_SUCCESS(Status))
    {
        FltCloseCommunicationPort(ServerPort);
        ServerPort = NULL;
        FltUnregisterFilter(SampleFilter);
        SampleFilter = NULL;
        goto Fail;
    }

    return STATUS_SUCCESS;

Fail:
    IoDeleteSymbolicLink(&SymLinkName);
    IoDeleteDevice(ControlDevice);
    ControlDevice = NULL;
    return Status;
}
