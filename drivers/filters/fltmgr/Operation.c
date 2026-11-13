/*
* PROJECT:         Filesystem Filter Manager
* LICENSE:         GPL - See COPYING in the top level directory
* FILE:            drivers/filters/fltmgr/Operation.c
* PURPOSE:         Runs the operations of a volume through the instances on it
*
* An IRP for a file system volume with filter instances on it goes through the pre-operation
* callbacks of the instances from the highest altitude to the lowest, is passed to the file system,
* and on completion through the post-operation callbacks of those instances which asked for one,
* from the lowest altitude to the highest. The state of one operation lives in an FLTP_IRPCTRL.
*
* The documentation for the callbacks is the Windows Driver Kit's for minifilter drivers:
* FLT_PREOP_CALLBACK_STATUS, FLT_POSTOP_CALLBACK_STATUS, FLT_CALLBACK_DATA, FLT_IO_PARAMETER_BLOCK.
*/

/* INCLUDES ******************************************************************/

#include "fltmgr.h"
#include "fltmgrint.h"
#include "fltmgrproto.h"

#define NDEBUG
#include <debug.h>


/* DATA *********************************************************************/

typedef struct _FLTP_NODE
{
    PFLT_INSTANCE Instance;         /* referenced until its callbacks are done with the operation */
    PVOID CompletionContext;
    BOOLEAN WantPost;

} FLTP_NODE, *PFLTP_NODE;

typedef struct _FLTP_IRPCTRL
{
    FLT_CALLBACK_DATA Data;         /* must be first: callbacks hand us this pointer back */
    FLT_IO_PARAMETER_BLOCK Iopb;
    PIRP Irp;
    PFLT_VOLUME Volume;
    PDEVICE_OBJECT LowerDevice;
    UCHAR MajorFunction;
    BOOLEAN Pended;                 /* the IRP is marked pending by us */
    BOOLEAN Synchronize;            /* a pre-operation asked for FLT_PREOP_SYNCHRONIZE */
    BOOLEAN SyncOwner;              /* the thread of the dispatch routine is running the post-operations */
    BOOLEAN ParkedSync;             /* a post-operation parked the operation inside the call to the file system */
    volatile LONG RefCount;         /* the dispatch routine keeps one while it looks at the block after sending the IRP */
    ULONG Count;
    ULONG Next;                     /* the next node to call the pre-operation of */
    ULONG CompleteIndex;            /* node of the pre-operation that completed the IRP */
    ULONG PostIndex;                /* nodes below this index still may need their post-operation */
    PFLTP_NODE Parked;              /* node whose post-operation returned MORE_PROCESSING_REQUIRED */
    volatile LONG PendState;        /* 0: running, 1: parked, 2: filter finished before we parked */
    volatile LONG PostState;
    FLT_PREOP_CALLBACK_STATUS PendedStatus;
    PVOID PendedContext;
    KEVENT SyncEvent;
    WORK_QUEUE_ITEM WorkItem;
    PFLT_POST_OPERATION_CALLBACK SafeCallback;
    PVOID SafeContext;
    FLT_POST_OPERATION_FLAGS SafeFlags;
    PFLTP_NODE SafeNode;
    FLTP_NODE Nodes[1];

} FLTP_IRPCTRL, *PFLTP_IRPCTRL;

typedef enum _FLTP_PRE_RESULT
{
    PreDown,
    PreComplete,
    PreParked

} FLTP_PRE_RESULT;


/* PRIVATE FUNCTIONS ********************************************************/

static
VOID
InitRelatedObjects(_Out_ PFLT_RELATED_OBJECTS Objects,
                   _In_ PFLTP_IRPCTRL Ctrl,
                   _In_ PFLT_INSTANCE Instance)
{
    RtlZeroMemory(Objects, sizeof(*Objects));
    *(PUSHORT)&Objects->Size = sizeof(FLT_RELATED_OBJECTS);
    *(PFLT_FILTER *)&Objects->Filter = Instance->Filter;
    *(PFLT_VOLUME *)&Objects->Volume = Ctrl->Volume;
    *(PFLT_INSTANCE *)&Objects->Instance = Instance;
    *(PFILE_OBJECT *)&Objects->FileObject = Ctrl->Iopb.TargetFileObject;
}

/* The buffer of a read or a write: the system buffer for buffered I/O, the user's for neither */
static
PVOID
GetTransferBuffer(_In_ PIRP Irp)
{
    if ((Irp->Flags & IRP_BUFFERED_IO) && Irp->AssociatedIrp.SystemBuffer)
        return Irp->AssociatedIrp.SystemBuffer;

    return Irp->UserBuffer;
}

/* Fills in the FLT_IO_PARAMETER_BLOCK, from the IRP and its current stack location */
static
VOID
FillParameters(_Inout_ PFLTP_IRPCTRL Ctrl,
               _In_ PIRP Irp,
               _In_ PIO_STACK_LOCATION Stack)
{
    PFLT_IO_PARAMETER_BLOCK Iopb = &Ctrl->Iopb;

    Iopb->IrpFlags = Irp->Flags;
    Iopb->MajorFunction = Stack->MajorFunction;
    Iopb->MinorFunction = Stack->MinorFunction;
    Iopb->OperationFlags = Stack->Flags;
    Iopb->TargetFileObject = Stack->FileObject;
    RtlZeroMemory(&Iopb->Parameters, sizeof(Iopb->Parameters));

    switch (Stack->MajorFunction)
    {
        case IRP_MJ_CREATE:
            Iopb->Parameters.Create.SecurityContext = Stack->Parameters.Create.SecurityContext;
            Iopb->Parameters.Create.Options = Stack->Parameters.Create.Options;
            Iopb->Parameters.Create.FileAttributes = Stack->Parameters.Create.FileAttributes;
            Iopb->Parameters.Create.ShareAccess = Stack->Parameters.Create.ShareAccess;
            Iopb->Parameters.Create.EaLength = Stack->Parameters.Create.EaLength;
            Iopb->Parameters.Create.EaBuffer = Irp->AssociatedIrp.SystemBuffer;
            Iopb->Parameters.Create.AllocationSize = Irp->Overlay.AllocationSize;
            break;

        case IRP_MJ_READ:
            Iopb->Parameters.Read.Length = Stack->Parameters.Read.Length;
            Iopb->Parameters.Read.Key = Stack->Parameters.Read.Key;
            Iopb->Parameters.Read.ByteOffset = Stack->Parameters.Read.ByteOffset;
            Iopb->Parameters.Read.ReadBuffer = GetTransferBuffer(Irp);
            Iopb->Parameters.Read.MdlAddress = Irp->MdlAddress;
            break;

        case IRP_MJ_WRITE:
            Iopb->Parameters.Write.Length = Stack->Parameters.Write.Length;
            Iopb->Parameters.Write.Key = Stack->Parameters.Write.Key;
            Iopb->Parameters.Write.ByteOffset = Stack->Parameters.Write.ByteOffset;
            Iopb->Parameters.Write.WriteBuffer = GetTransferBuffer(Irp);
            Iopb->Parameters.Write.MdlAddress = Irp->MdlAddress;
            break;

        case IRP_MJ_QUERY_INFORMATION:
            Iopb->Parameters.QueryFileInformation.Length = Stack->Parameters.QueryFile.Length;
            Iopb->Parameters.QueryFileInformation.FileInformationClass = Stack->Parameters.QueryFile.FileInformationClass;
            Iopb->Parameters.QueryFileInformation.InfoBuffer = Irp->AssociatedIrp.SystemBuffer;
            break;

        case IRP_MJ_SET_INFORMATION:
            Iopb->Parameters.SetFileInformation.Length = Stack->Parameters.SetFile.Length;
            Iopb->Parameters.SetFileInformation.FileInformationClass = Stack->Parameters.SetFile.FileInformationClass;
            Iopb->Parameters.SetFileInformation.ParentOfTarget = Stack->Parameters.SetFile.FileObject;
            Iopb->Parameters.SetFileInformation.DeleteHandle = Stack->Parameters.SetFile.DeleteHandle;
            Iopb->Parameters.SetFileInformation.InfoBuffer = Irp->AssociatedIrp.SystemBuffer;
            break;

        case IRP_MJ_DIRECTORY_CONTROL:
            if (Stack->MinorFunction == IRP_MN_QUERY_DIRECTORY)
            {
                Iopb->Parameters.DirectoryControl.QueryDirectory.Length = Stack->Parameters.QueryDirectory.Length;
                Iopb->Parameters.DirectoryControl.QueryDirectory.FileName = Stack->Parameters.QueryDirectory.FileName;
                Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass = Stack->Parameters.QueryDirectory.FileInformationClass;
                Iopb->Parameters.DirectoryControl.QueryDirectory.FileIndex = Stack->Parameters.QueryDirectory.FileIndex;
                Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer = Irp->UserBuffer;
                Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress = Irp->MdlAddress;
            }
            else
            {
                Iopb->Parameters.DirectoryControl.NotifyDirectory.Length = Stack->Parameters.NotifyDirectory.Length;
                Iopb->Parameters.DirectoryControl.NotifyDirectory.CompletionFilter = Stack->Parameters.NotifyDirectory.CompletionFilter;
                Iopb->Parameters.DirectoryControl.NotifyDirectory.DirectoryBuffer = Irp->UserBuffer;
                Iopb->Parameters.DirectoryControl.NotifyDirectory.MdlAddress = Irp->MdlAddress;
            }
            break;

        case IRP_MJ_QUERY_VOLUME_INFORMATION:
            Iopb->Parameters.QueryVolumeInformation.Length = Stack->Parameters.QueryVolume.Length;
            Iopb->Parameters.QueryVolumeInformation.FsInformationClass = Stack->Parameters.QueryVolume.FsInformationClass;
            Iopb->Parameters.QueryVolumeInformation.VolumeBuffer = Irp->AssociatedIrp.SystemBuffer;
            break;

        case IRP_MJ_SET_VOLUME_INFORMATION:
            Iopb->Parameters.SetVolumeInformation.Length = Stack->Parameters.SetVolume.Length;
            Iopb->Parameters.SetVolumeInformation.FsInformationClass = Stack->Parameters.SetVolume.FsInformationClass;
            Iopb->Parameters.SetVolumeInformation.VolumeBuffer = Irp->AssociatedIrp.SystemBuffer;
            break;

        default:
            /* The arguments of the remaining operations are handed over as they are */
            RtlCopyMemory(&Iopb->Parameters, &Stack->Parameters, sizeof(Stack->Parameters));
            break;
    }
}

/* A filter changed the callback data: put the parameters back in the IRP */
static
VOID
WriteBackParameters(_In_ PFLTP_IRPCTRL Ctrl,
                    _In_ PIRP Irp,
                    _In_ PIO_STACK_LOCATION Stack)
{
    PFLT_IO_PARAMETER_BLOCK Iopb = &Ctrl->Iopb;

    Irp->Flags = Iopb->IrpFlags;
    Stack->Flags = Iopb->OperationFlags;
    Stack->FileObject = Iopb->TargetFileObject;

    switch (Stack->MajorFunction)
    {
        case IRP_MJ_CREATE:
            Stack->Parameters.Create.SecurityContext = Iopb->Parameters.Create.SecurityContext;
            Stack->Parameters.Create.Options = Iopb->Parameters.Create.Options;
            Stack->Parameters.Create.FileAttributes = Iopb->Parameters.Create.FileAttributes;
            Stack->Parameters.Create.ShareAccess = Iopb->Parameters.Create.ShareAccess;
            Stack->Parameters.Create.EaLength = Iopb->Parameters.Create.EaLength;
            Irp->AssociatedIrp.SystemBuffer = Iopb->Parameters.Create.EaBuffer;
            Irp->Overlay.AllocationSize = Iopb->Parameters.Create.AllocationSize;
            break;

        case IRP_MJ_READ:
            Stack->Parameters.Read.Length = Iopb->Parameters.Read.Length;
            Stack->Parameters.Read.Key = Iopb->Parameters.Read.Key;
            Stack->Parameters.Read.ByteOffset = Iopb->Parameters.Read.ByteOffset;
            if ((Irp->Flags & IRP_BUFFERED_IO) && Irp->AssociatedIrp.SystemBuffer)
                Irp->AssociatedIrp.SystemBuffer = Iopb->Parameters.Read.ReadBuffer;
            else
                Irp->UserBuffer = Iopb->Parameters.Read.ReadBuffer;
            Irp->MdlAddress = Iopb->Parameters.Read.MdlAddress;
            break;

        case IRP_MJ_WRITE:
            Stack->Parameters.Write.Length = Iopb->Parameters.Write.Length;
            Stack->Parameters.Write.Key = Iopb->Parameters.Write.Key;
            Stack->Parameters.Write.ByteOffset = Iopb->Parameters.Write.ByteOffset;
            if ((Irp->Flags & IRP_BUFFERED_IO) && Irp->AssociatedIrp.SystemBuffer)
                Irp->AssociatedIrp.SystemBuffer = Iopb->Parameters.Write.WriteBuffer;
            else
                Irp->UserBuffer = Iopb->Parameters.Write.WriteBuffer;
            Irp->MdlAddress = Iopb->Parameters.Write.MdlAddress;
            break;

        case IRP_MJ_QUERY_INFORMATION:
            Stack->Parameters.QueryFile.Length = Iopb->Parameters.QueryFileInformation.Length;
            Stack->Parameters.QueryFile.FileInformationClass = Iopb->Parameters.QueryFileInformation.FileInformationClass;
            Irp->AssociatedIrp.SystemBuffer = Iopb->Parameters.QueryFileInformation.InfoBuffer;
            break;

        case IRP_MJ_SET_INFORMATION:
            Stack->Parameters.SetFile.Length = Iopb->Parameters.SetFileInformation.Length;
            Stack->Parameters.SetFile.FileInformationClass = Iopb->Parameters.SetFileInformation.FileInformationClass;
            Stack->Parameters.SetFile.FileObject = Iopb->Parameters.SetFileInformation.ParentOfTarget;
            Stack->Parameters.SetFile.DeleteHandle = Iopb->Parameters.SetFileInformation.DeleteHandle;
            Irp->AssociatedIrp.SystemBuffer = Iopb->Parameters.SetFileInformation.InfoBuffer;
            break;

        case IRP_MJ_DIRECTORY_CONTROL:
            if (Stack->MinorFunction == IRP_MN_QUERY_DIRECTORY)
            {
                Stack->Parameters.QueryDirectory.Length = Iopb->Parameters.DirectoryControl.QueryDirectory.Length;
                Stack->Parameters.QueryDirectory.FileName = Iopb->Parameters.DirectoryControl.QueryDirectory.FileName;
                Stack->Parameters.QueryDirectory.FileInformationClass = Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass;
                Stack->Parameters.QueryDirectory.FileIndex = Iopb->Parameters.DirectoryControl.QueryDirectory.FileIndex;
                Irp->UserBuffer = Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
                Irp->MdlAddress = Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress;
            }
            else
            {
                Stack->Parameters.NotifyDirectory.Length = Iopb->Parameters.DirectoryControl.NotifyDirectory.Length;
                Stack->Parameters.NotifyDirectory.CompletionFilter = Iopb->Parameters.DirectoryControl.NotifyDirectory.CompletionFilter;
                Irp->UserBuffer = Iopb->Parameters.DirectoryControl.NotifyDirectory.DirectoryBuffer;
                Irp->MdlAddress = Iopb->Parameters.DirectoryControl.NotifyDirectory.MdlAddress;
            }
            break;

        case IRP_MJ_QUERY_VOLUME_INFORMATION:
            Stack->Parameters.QueryVolume.Length = Iopb->Parameters.QueryVolumeInformation.Length;
            Stack->Parameters.QueryVolume.FsInformationClass = Iopb->Parameters.QueryVolumeInformation.FsInformationClass;
            Irp->AssociatedIrp.SystemBuffer = Iopb->Parameters.QueryVolumeInformation.VolumeBuffer;
            break;

        case IRP_MJ_SET_VOLUME_INFORMATION:
            Stack->Parameters.SetVolume.Length = Iopb->Parameters.SetVolumeInformation.Length;
            Stack->Parameters.SetVolume.FsInformationClass = Iopb->Parameters.SetVolumeInformation.FsInformationClass;
            Irp->AssociatedIrp.SystemBuffer = Iopb->Parameters.SetVolumeInformation.VolumeBuffer;
            break;

        default:
            RtlCopyMemory(&Stack->Parameters, &Iopb->Parameters, sizeof(Stack->Parameters));
            break;
    }
}

/* Does a registered operation want to see this IRP? */
static
BOOLEAN
OperationWantsIrp(_In_ PFLT_OPERATION_REGISTRATION Op,
                  _In_ PIRP Irp,
                  _In_ PIO_STACK_LOCATION Stack)
{
    if ((Op->Flags & FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO) && (Irp->Flags & IRP_PAGING_IO))
        return FALSE;

    if ((Op->Flags & FLTFL_OPERATION_REGISTRATION_SKIP_CACHED_IO) &&
        (Stack->MajorFunction == IRP_MJ_READ || Stack->MajorFunction == IRP_MJ_WRITE) &&
        !(Irp->Flags & (IRP_NOCACHE | IRP_PAGING_IO)))
    {
        return FALSE;
    }

#ifdef FO_VOLUME_OPEN
    if ((Op->Flags & FLTFL_OPERATION_REGISTRATION_SKIP_NON_DASD_IO) &&
        Stack->FileObject && !(Stack->FileObject->Flags & FO_VOLUME_OPEN))
    {
        return FALSE;
    }
#endif

    return TRUE;
}

static
VOID
ReleaseCtrl(_In_ PFLTP_IRPCTRL Ctrl)
{
    if (InterlockedDecrement(&Ctrl->RefCount) == 0)
        ExFreePoolWithTag(Ctrl, FM_TAG_IRPCTRL);
}

/* The operation is over for the filters: the instances are released, the block is freed with the last user */
static
VOID
FreeCtrl(_In_ PFLTP_IRPCTRL Ctrl)
{
    ULONG i;

    /* Whatever reference is left goes now */
    for (i = 0; i < Ctrl->Count; i++)
    {
        if (Ctrl->Nodes[i].Instance)
        {
            FltObjectDereference(Ctrl->Nodes[i].Instance);
            Ctrl->Nodes[i].Instance = NULL;
        }
    }

    ReleaseCtrl(Ctrl);
}

/* Takes the rest of the pre-operations, from Ctrl->Next on */
static
FLTP_PRE_RESULT
RunPreOperations(_Inout_ PFLTP_IRPCTRL Ctrl,
                 _In_ BOOLEAN HavePended)
{
    FLT_PREOP_CALLBACK_STATUS PreStatus;
    FLT_RELATED_OBJECTS Related;
    PFLT_OPERATION_REGISTRATION Op;
    PFLTP_NODE Node;
    PVOID Context;

    for (;;)
    {
        if (HavePended)
        {
            /* The pre-operation of the last node pended and has now come to a verdict */
            Node = &Ctrl->Nodes[Ctrl->Next - 1];
            Op = Node->Instance->Filter->OperationTable[Ctrl->MajorFunction];
            PreStatus = Ctrl->PendedStatus;
            Context = Ctrl->PendedContext;
            HavePended = FALSE;
        }
        else
        {
            if (Ctrl->Next >= Ctrl->Count)
                return PreDown;

            Node = &Ctrl->Nodes[Ctrl->Next++];
            Op = Node->Instance->Filter->OperationTable[Ctrl->MajorFunction];

            /* A filter without a pre-operation still sees the post-operation */
            if (Op->PreOperation == NULL)
            {
                Node->WantPost = (Op->PostOperation != NULL);
                continue;
            }

            Ctrl->Iopb.TargetInstance = Node->Instance;
            InitRelatedObjects(&Related, Ctrl, Node->Instance);
            Context = NULL;
            Ctrl->PendState = 0;
            PreStatus = Op->PreOperation(&Ctrl->Data, &Related, &Context);

            if (PreStatus == FLT_PREOP_PENDING)
            {
                /*
                 * The filter keeps the operation and completes it with FltCompletePendedPreOperation,
                 * maybe from another thread, maybe before we are back from the callback. Either we
                 * park the operation here, or the filter already has its verdict ready.
                 */
                Ctrl->Pended = TRUE;
                IoMarkIrpPending(Ctrl->Irp);
                if (InterlockedCompareExchange(&Ctrl->PendState, 1, 0) == 0)
                    return PreParked;

                PreStatus = Ctrl->PendedStatus;
                Context = Ctrl->PendedContext;
            }
        }

        switch (PreStatus)
        {
            case FLT_PREOP_SUCCESS_WITH_CALLBACK:
                Node->WantPost = (Op->PostOperation != NULL);
                Node->CompletionContext = Context;
                break;

            case FLT_PREOP_SYNCHRONIZE:
                Node->WantPost = (Op->PostOperation != NULL);
                Node->CompletionContext = Context;
                if (Node->WantPost)
                    Ctrl->Synchronize = TRUE;
                break;

            case FLT_PREOP_COMPLETE:
                Ctrl->CompleteIndex = (ULONG)(Node - Ctrl->Nodes);
                return PreComplete;

            case FLT_PREOP_SUCCESS_NO_CALLBACK:
            case FLT_PREOP_DISALLOW_FASTIO:
            default:
                break;
        }
    }
}

/*
 * Runs the post-operations from Ctrl->PostIndex downwards. Returns FALSE when a post-operation
 * has returned FLT_POSTOP_MORE_PROCESSING_REQUIRED, the completion then continues when the filter
 * calls FltCompletePendedPostOperation.
 */
static
BOOLEAN
RunPostOperations(_Inout_ PFLTP_IRPCTRL Ctrl)
{
    FLT_POSTOP_CALLBACK_STATUS PostStatus;
    FLT_POST_OPERATION_FLAGS Flags;
    FLT_RELATED_OBJECTS Related;
    PFLT_OPERATION_REGISTRATION Op;
    PFLTP_NODE Node;

    while (Ctrl->PostIndex > 0)
    {
        Node = &Ctrl->Nodes[--Ctrl->PostIndex];
        if (Node->Instance == NULL)
            continue;

        if (!Node->WantPost)
        {
            FltObjectDereference(Node->Instance);
            Node->Instance = NULL;
            continue;
        }

        Op = Node->Instance->Filter->OperationTable[Ctrl->MajorFunction];

        /* An instance which is being torn down must not rely on anything but the operation itself */
        Flags = (Node->Instance->Flags & INSFL_DELETING) ? FLTFL_POST_OPERATION_DRAINING : 0;
        if (Flags)
            Ctrl->Data.Flags |= FLTFL_CALLBACK_DATA_DRAINING_IO;

        Ctrl->Data.Flags |= FLTFL_CALLBACK_DATA_POST_OPERATION;
        Ctrl->Iopb.TargetInstance = Node->Instance;
        InitRelatedObjects(&Related, Ctrl, Node->Instance);

        Ctrl->Parked = Node;
        Ctrl->PostState = 0;
        PostStatus = Op->PostOperation(&Ctrl->Data, &Related, Node->CompletionContext, Flags);

        if (PostStatus == FLT_POSTOP_MORE_PROCESSING_REQUIRED)
        {
            /* Either the filter is yet to finish, or it did already */
            if (InterlockedCompareExchange(&Ctrl->PostState, 1, 0) == 0)
                return FALSE;
        }

        FltObjectDereference(Node->Instance);
        Node->Instance = NULL;
    }

    return TRUE;
}

/* The IRP is done: its status is whatever the post-operations left in the callback data */
static
NTSTATUS
FinishIrp(_In_ PFLTP_IRPCTRL Ctrl,
          _In_ BOOLEAN FromCompletionRoutine)
{
    PIRP Irp = Ctrl->Irp;
    NTSTATUS Status;

    Irp->IoStatus = Ctrl->Data.IoStatus;
    Status = Irp->IoStatus.Status;
    FreeCtrl(Ctrl);

    if (FromCompletionRoutine)
    {
        /* The I/O manager goes on completing it */
        if (Irp->PendingReturned)
            IoMarkIrpPending(Irp);
        return STATUS_SUCCESS;
    }

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static
NTSTATUS
NTAPI
IrpCompletion(_In_ PDEVICE_OBJECT DeviceObject,
              _In_ PIRP Irp,
              _In_ PVOID Context)
{
    PFLTP_IRPCTRL Ctrl = Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    Ctrl->Data.IoStatus = Irp->IoStatus;
    Ctrl->Data.Flags |= FLTFL_CALLBACK_DATA_POST_OPERATION;

    /* The contexts of the stream live as long as it is open, so before the filters see the new file */
    if (Ctrl->MajorFunction == IRP_MJ_CREATE && Ctrl->Volume->ContextTracking && NT_SUCCESS(Irp->IoStatus.Status))
        FltpStreamOpened(Ctrl->Volume, Ctrl->Iopb.TargetFileObject);

    if (Ctrl->Synchronize)
    {
        /* The post-operations run in the thread of the dispatch routine, which is waiting */
        KeSetEvent(&Ctrl->SyncEvent, IO_NO_INCREMENT, FALSE);
        return STATUS_MORE_PROCESSING_REQUIRED;
    }

    if (!RunPostOperations(Ctrl))
    {
        /*
         * The filter takes its time. If the file system has completed the IRP before returning
         * to our dispatch routine, that one has to answer STATUS_PENDING and the IRP gets marked.
         */
        if (!Irp->PendingReturned)
        {
            Ctrl->ParkedSync = TRUE;
            IoMarkIrpPending(Irp);
        }
        return STATUS_MORE_PROCESSING_REQUIRED;
    }

    return FinishIrp(Ctrl, TRUE);
}

/* The pre-operation of a filter completed the IRP: the filters above it get their post-operation */
static
NTSTATUS
CompleteInPreOperation(_In_ PFLTP_IRPCTRL Ctrl)
{
    PFLTP_NODE Node;
    BOOLEAN Pended;
    NTSTATUS Status;
    ULONG i;

    /* The nodes from the one which completed are done */
    for (i = Ctrl->CompleteIndex; i < Ctrl->Count; i++)
    {
        Node = &Ctrl->Nodes[i];
        Node->WantPost = FALSE;
    }

    Ctrl->Data.Flags |= FLTFL_CALLBACK_DATA_POST_OPERATION;
    Ctrl->PostIndex = Ctrl->CompleteIndex;

    /* A post-operation may take its time, in which case the dispatch routine has to answer STATUS_PENDING */
    for (i = 0; i < Ctrl->CompleteIndex; i++)
    {
        if (Ctrl->Nodes[i].WantPost && !Ctrl->Pended)
        {
            Ctrl->Pended = TRUE;
            IoMarkIrpPending(Ctrl->Irp);
            break;
        }
    }

    /* Nodes which never ran their pre-operation don't take part */
    for (i = Ctrl->CompleteIndex; i < Ctrl->Count; i++)
    {
        if (Ctrl->Nodes[i].Instance)
        {
            FltObjectDereference(Ctrl->Nodes[i].Instance);
            Ctrl->Nodes[i].Instance = NULL;
        }
    }

    if (!RunPostOperations(Ctrl))
    {
        /* The completion goes on in FltCompletePendedPostOperation */
        return STATUS_PENDING;
    }

    Pended = Ctrl->Pended;
    Status = FinishIrp(Ctrl, FALSE);
    return Pended ? STATUS_PENDING : Status;
}

/* All the pre-operations are done and none completed the IRP: down it goes */
static
NTSTATUS
SendDown(_In_ PFLTP_IRPCTRL Ctrl)
{
    PIRP Irp = Ctrl->Irp;
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PDEVICE_OBJECT Lower = Ctrl->LowerDevice;
    BOOLEAN Pended = Ctrl->Pended;
    BOOLEAN Synchronize = Ctrl->Synchronize;
    BOOLEAN AnyPost = FALSE;
    NTSTATUS Status;
    ULONG i;

    if (Ctrl->Data.Flags & FLTFL_CALLBACK_DATA_DIRTY)
    {
        WriteBackParameters(Ctrl, Irp, Stack);
        Ctrl->Data.Flags &= ~FLTFL_CALLBACK_DATA_DIRTY;
    }

    if (Ctrl->Volume->ContextTracking)
    {
        /* The close is the end of the handle contexts, the create needs a completion routine for the opens */
        if (Stack->MajorFunction == IRP_MJ_CLOSE && Stack->FileObject)
            FltpFileObjectClosed(Ctrl->Volume, Stack->FileObject);
        else if (Stack->MajorFunction == IRP_MJ_CREATE)
            AnyPost = TRUE;
    }

    /* The instances which don't want the post-operation are done with the operation now */
    for (i = 0; i < Ctrl->Count; i++)
    {
        if (Ctrl->Nodes[i].WantPost)
        {
            AnyPost = TRUE;
        }
        else if (Ctrl->Nodes[i].Instance)
        {
            FltObjectDereference(Ctrl->Nodes[i].Instance);
            Ctrl->Nodes[i].Instance = NULL;
        }
    }

    if (!AnyPost)
    {
        ReleaseCtrl(Ctrl);

        IoSkipCurrentIrpStackLocation(Irp);
        Status = IoCallDriver(Lower, Irp);
        return Pended ? STATUS_PENDING : Status;
    }

    Ctrl->PostIndex = Ctrl->Count;
    if (Synchronize)
        KeInitializeEvent(&Ctrl->SyncEvent, NotificationEvent, FALSE);

    /* We look at the block once more after the call */
    InterlockedIncrement(&Ctrl->RefCount);

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, IrpCompletion, Ctrl, TRUE, TRUE, TRUE);
    Status = IoCallDriver(Lower, Irp);

    if (!Synchronize)
    {
        /* Everything about the IRP may be gone by now, the block is still ours */
        if (Ctrl->ParkedSync)
            Status = STATUS_PENDING;
        ReleaseCtrl(Ctrl);
        return Pended ? STATUS_PENDING : Status;
    }

    ReleaseCtrl(Ctrl);

    /* FLT_PREOP_SYNCHRONIZE: we are still in the thread which sent the IRP, and it stays so */
    KeWaitForSingleObject(&Ctrl->SyncEvent, Executive, KernelMode, FALSE, NULL);
    Ctrl->SyncOwner = TRUE;
    for (;;)
    {
        KeClearEvent(&Ctrl->SyncEvent);
        if (RunPostOperations(Ctrl))
            break;

        /* A post-operation went into MORE_PROCESSING_REQUIRED, wait until it is done */
        KeWaitForSingleObject(&Ctrl->SyncEvent, Executive, KernelMode, FALSE, NULL);
        FltObjectDereference(Ctrl->Parked->Instance);
        Ctrl->Parked->Instance = NULL;
    }

    Status = FinishIrp(Ctrl, FALSE);
    return Pended ? STATUS_PENDING : Status;
}

static
NTSTATUS
ContinueAfterPre(_In_ PFLTP_IRPCTRL Ctrl,
                 _In_ FLTP_PRE_RESULT Result)
{
    BOOLEAN Pended = Ctrl->Pended;
    NTSTATUS Status;

    switch (Result)
    {
        case PreParked:
            /* The control block belongs to whoever completes the operation */
            return STATUS_PENDING;

        case PreComplete:
            Status = CompleteInPreOperation(Ctrl);
            break;

        default:
            Status = SendDown(Ctrl);
            break;
    }

    return Pended ? STATUS_PENDING : Status;
}

/* A file object which has been created: the stream gets one more open */
static
NTSTATUS
NTAPI
TrackCreateCompletion(_In_ PDEVICE_OBJECT DeviceObject,
                      _In_ PIRP Irp,
                      _In_ PVOID Context)
{
    PFLT_VOLUME Volume = Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (NT_SUCCESS(Irp->IoStatus.Status))
        FltpStreamOpened(Volume, IoGetCurrentIrpStackLocation(Irp)->FileObject);

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    return STATUS_SUCCESS;
}

/* Hands the IRP to the volume's file system as if we weren't here, but for the contexts of the streams */
static
NTSTATUS
PassThrough(_In_ PDEVICE_OBJECT DeviceObject,
            _Inout_ PIRP Irp)
{
    PFLTMGR_DEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;
    PFLT_VOLUME Volume = DeviceExtension->Volume;
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);

    if (Volume && Volume->ContextTracking)
    {
        if (Stack->MajorFunction == IRP_MJ_CLOSE && Stack->FileObject)
        {
            FltpFileObjectClosed(Volume, Stack->FileObject);
        }
        else if (Stack->MajorFunction == IRP_MJ_CREATE)
        {
            IoCopyCurrentIrpStackLocationToNext(Irp);
            IoSetCompletionRoutine(Irp, TrackCreateCompletion, Volume, TRUE, TRUE, TRUE);
            return IoCallDriver(DeviceExtension->AttachedToDeviceObject, Irp);
        }
    }

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(DeviceExtension->AttachedToDeviceObject, Irp);
}


/* INTERNAL FUNCTIONS ******************************************************/

NTSTATUS
FltpPerformIrp(_In_ PDEVICE_OBJECT DeviceObject,
               _Inout_ PIRP Irp)
{
    PFLTMGR_DEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PFLT_VOLUME Volume = DeviceExtension->Volume;
    PFLTP_IRPCTRL Ctrl;
    PLIST_ENTRY Entry;
    ULONG Count = 0;
    UCHAR Major = Stack->MajorFunction;
    FLTP_PRE_RESULT Result;

    /* The common case: nobody on this volume is interested */
    if (Volume == NULL ||
        Major > IRP_MJ_MAXIMUM_FUNCTION ||
        Volume->CallbackCount[Major] == 0 ||
        KeGetCurrentIrql() > APC_LEVEL)
    {
        return PassThrough(DeviceObject, Irp);
    }

    /* Count the instances for this operation and reference them, highest altitude first */
    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&Volume->InstanceList.rLock, TRUE);

    for (Entry = Volume->InstanceList.rList.Flink;
         Entry != &Volume->InstanceList.rList;
         Entry = Entry->Flink)
    {
        PFLT_INSTANCE Instance = CONTAINING_RECORD(Entry, FLT_INSTANCE, VolumeLink);
        PFLT_OPERATION_REGISTRATION Op = Instance->Filter->OperationTable[Major];

        if (Op && !(Instance->Flags & INSFL_DELETING) && OperationWantsIrp(Op, Irp, Stack))
            Count++;
    }

    Ctrl = NULL;
    if (Count)
    {
        Ctrl = ExAllocatePoolWithTag(NonPagedPool,
                                     sizeof(FLTP_IRPCTRL) + (Count - 1) * sizeof(FLTP_NODE),
                                     FM_TAG_IRPCTRL);
    }

    if (Ctrl)
    {
        RtlZeroMemory(Ctrl, sizeof(FLTP_IRPCTRL) + (Count - 1) * sizeof(FLTP_NODE));

        for (Entry = Volume->InstanceList.rList.Flink;
             Entry != &Volume->InstanceList.rList && Ctrl->Count < Count;
             Entry = Entry->Flink)
        {
            PFLT_INSTANCE Instance = CONTAINING_RECORD(Entry, FLT_INSTANCE, VolumeLink);
            PFLT_OPERATION_REGISTRATION Op = Instance->Filter->OperationTable[Major];

            if (Op && !(Instance->Flags & INSFL_DELETING) && OperationWantsIrp(Op, Irp, Stack) &&
                NT_SUCCESS(FltObjectReference(Instance)))
            {
                Ctrl->Nodes[Ctrl->Count++].Instance = Instance;
            }
        }
    }

    ExReleaseResourceLite(&Volume->InstanceList.rLock);
    KeLeaveCriticalRegion();

    if (Ctrl == NULL)
        return PassThrough(DeviceObject, Irp);

    if (Ctrl->Count == 0)
    {
        ExFreePoolWithTag(Ctrl, FM_TAG_IRPCTRL);
        return PassThrough(DeviceObject, Irp);
    }

    /* The callback data: the filters see the operation through it */
    Ctrl->RefCount = 1;
    Ctrl->Irp = Irp;
    Ctrl->Volume = Volume;
    Ctrl->LowerDevice = DeviceExtension->AttachedToDeviceObject;
    Ctrl->MajorFunction = Major;
    FillParameters(Ctrl, Irp, Stack);
    *(PFLT_IO_PARAMETER_BLOCK *)&Ctrl->Data.Iopb = &Ctrl->Iopb;
    *(PETHREAD *)&Ctrl->Data.Thread = Irp->Tail.Overlay.Thread;
    Ctrl->Data.RequestorMode = Irp->RequestorMode;
    Ctrl->Data.Flags = FLTFL_CALLBACK_DATA_IRP_OPERATION;
    if (Irp->AssociatedIrp.SystemBuffer && (Irp->Flags & IRP_BUFFERED_IO))
        Ctrl->Data.Flags |= FLTFL_CALLBACK_DATA_SYSTEM_BUFFER;

    Result = RunPreOperations(Ctrl, FALSE);
    return ContinueAfterPre(Ctrl, Result);
}

/*
 * A filter which sees an operation as an IRP only: the fast I/O entry points in
 * front of a volume with callbacks for the operation say no, so the caller falls back to an IRP.
 */
BOOLEAN
FltpFastIoDisallowed(_In_ PDEVICE_OBJECT DeviceObject,
                     _In_ UCHAR MajorFunction)
{
    PFLTMGR_DEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;

    return DeviceExtension && DeviceExtension->Volume &&
           DeviceExtension->Volume->CallbackCount[MajorFunction] != 0;
}


/* EXPORTED FUNCTIONS *******************************************************/

VOID
FLTAPI
FltCompletePendedPreOperation(_In_ PFLT_CALLBACK_DATA CallbackData,
                              _In_ FLT_PREOP_CALLBACK_STATUS CallbackStatus,
                              _In_opt_ PVOID Context)
{
    PFLTP_IRPCTRL Ctrl = CONTAINING_RECORD(CallbackData, FLTP_IRPCTRL, Data);
    FLTP_PRE_RESULT Result;

    Ctrl->PendedStatus = CallbackStatus;
    Ctrl->PendedContext = Context;

    /* If the callback is still on its way out, the dispatch routine picks the verdict up */
    if (InterlockedCompareExchange(&Ctrl->PendState, 2, 0) == 0)
        return;

    /* The operation is parked, we carry on with it in this thread */
    Result = RunPreOperations(Ctrl, TRUE);
    (VOID)ContinueAfterPre(Ctrl, Result);
}

VOID
FLTAPI
FltCompletePendedPostOperation(_In_ PFLT_CALLBACK_DATA CallbackData)
{
    PFLTP_IRPCTRL Ctrl = CONTAINING_RECORD(CallbackData, FLTP_IRPCTRL, Data);
    PFLTP_NODE Node;

    /* If the post-operation is still on its way out, the loop goes on by itself */
    if (InterlockedCompareExchange(&Ctrl->PostState, 2, 0) == 0)
        return;

    if (Ctrl->SyncOwner)
    {
        /* The thread of the dispatch routine is waiting for this */
        KeSetEvent(&Ctrl->SyncEvent, IO_NO_INCREMENT, FALSE);
        return;
    }

    Node = Ctrl->Parked;
    FltObjectDereference(Node->Instance);
    Node->Instance = NULL;

    if (!RunPostOperations(Ctrl))
        return;

    (VOID)FinishIrp(Ctrl, FALSE);
}

static
VOID
NTAPI
SafePostWorker(_In_ PVOID Parameter)
{
    PFLTP_IRPCTRL Ctrl = Parameter;
    FLT_RELATED_OBJECTS Related;
    FLT_POSTOP_CALLBACK_STATUS Status;

    InitRelatedObjects(&Related, Ctrl, Ctrl->SafeNode->Instance);
    Status = Ctrl->SafeCallback(&Ctrl->Data, &Related, Ctrl->SafeContext, Ctrl->SafeFlags);

    /* The filter has its own say when it wants more time, otherwise this is the end of it */
    if (Status == FLT_POSTOP_FINISHED_PROCESSING)
        FltCompletePendedPostOperation(&Ctrl->Data);
}

BOOLEAN
FLTAPI
FltDoCompletionProcessingWhenSafe(_In_ PFLT_CALLBACK_DATA Data,
                                  _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                  _In_opt_ PVOID CompletionContext,
                                  _In_ FLT_POST_OPERATION_FLAGS Flags,
                                  _In_ PFLT_POST_OPERATION_CALLBACK SafePostCallback,
                                  _Out_ PFLT_POSTOP_CALLBACK_STATUS RetPostOperationStatus)
{
    PFLTP_IRPCTRL Ctrl = CONTAINING_RECORD(Data, FLTP_IRPCTRL, Data);

    /* In an IRP's thread, below DISPATCH_LEVEL and not paging, it's safe to go on right now */
    if (KeGetCurrentIrql() <= APC_LEVEL && !(Ctrl->Iopb.IrpFlags & IRP_PAGING_IO))
    {
        *RetPostOperationStatus = SafePostCallback(Data, FltObjects, CompletionContext, Flags);
        return TRUE;
    }

    /* Otherwise a worker thread does it, and the post-operation returns for now */
    Ctrl->SafeCallback = SafePostCallback;
    Ctrl->SafeContext = CompletionContext;
    Ctrl->SafeFlags = Flags;
    Ctrl->SafeNode = Ctrl->Parked;
    ExInitializeWorkItem(&Ctrl->WorkItem, SafePostWorker, Ctrl);
    ExQueueWorkItem(&Ctrl->WorkItem, DelayedWorkQueue);

    *RetPostOperationStatus = FLT_POSTOP_MORE_PROCESSING_REQUIRED;
    return TRUE;
}

VOID
FLTAPI
FltSetCallbackDataDirty(_Inout_ PFLT_CALLBACK_DATA Data)
{
    Data->Flags |= FLTFL_CALLBACK_DATA_DIRTY;
}

VOID
FLTAPI
FltClearCallbackDataDirty(_Inout_ PFLT_CALLBACK_DATA Data)
{
    Data->Flags &= ~FLTFL_CALLBACK_DATA_DIRTY;
}

BOOLEAN
FLTAPI
FltIsCallbackDataDirty(_In_ PFLT_CALLBACK_DATA Data)
{
    return (Data->Flags & FLTFL_CALLBACK_DATA_DIRTY) != 0;
}

PEPROCESS
FLTAPI
FltGetRequestorProcess(_In_ PFLT_CALLBACK_DATA CallbackData)
{
    if (CallbackData->Thread == NULL)
        return NULL;

    return IoThreadToProcess(CallbackData->Thread);
}

ULONG
FLTAPI
FltGetRequestorProcessId(_In_ PFLT_CALLBACK_DATA CallbackData)
{
    PEPROCESS Process = FltGetRequestorProcess(CallbackData);

    return Process ? HandleToUlong(PsGetProcessId(Process)) : 0;
}

BOOLEAN
FLTAPI
FltIsOperationSynchronous(_In_ PFLT_CALLBACK_DATA Data)
{
    PFLTP_IRPCTRL Ctrl = CONTAINING_RECORD(Data, FLTP_IRPCTRL, Data);
    PFILE_OBJECT FileObject = Data->Iopb->TargetFileObject;

    if (!FLT_IS_IRP_OPERATION(Data))
        return TRUE;

    return (Ctrl->Irp->Flags & IRP_SYNCHRONOUS_API) ||
           (FileObject && (FileObject->Flags & FO_SYNCHRONOUS_IO));
}
