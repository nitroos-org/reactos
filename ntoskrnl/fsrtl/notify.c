/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/fsrtl/notify.c
 * PURPOSE:         Change Notifications and Sync for File System Drivers
 * PROGRAMMERS:     Pierre Schweitzer
 */

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

/* INLINED FUNCTIONS *********************************************************/

/*
 * @implemented
 */
FORCEINLINE
VOID
FsRtlNotifyAcquireFastMutex(IN PREAL_NOTIFY_SYNC RealNotifySync)
{
    ULONG_PTR CurrentThread = (ULONG_PTR)KeGetCurrentThread();

    /* Only acquire fast mutex if it's not already acquired by the current thread */
    if (RealNotifySync->OwningThread != CurrentThread)
    {
        ExAcquireFastMutexUnsafe(&(RealNotifySync->FastMutex));
        RealNotifySync->OwningThread = CurrentThread;
    }
    /* Whatever the case, keep trace of the attempt to acquire fast mutex */
    RealNotifySync->OwnerCount++;
}

/*
 * @implemented
 */
FORCEINLINE
VOID
FsRtlNotifyReleaseFastMutex(IN PREAL_NOTIFY_SYNC RealNotifySync)
{
    RealNotifySync->OwnerCount--;
    /* Release the fast mutex only if no other instance needs it */
    if (!RealNotifySync->OwnerCount)
    {
        ExReleaseFastMutexUnsafe(&(RealNotifySync->FastMutex));
        RealNotifySync->OwningThread = (ULONG_PTR)0;
    }
}

#define FsRtlNotifyGetLastPartOffset(FullLen, TargLen, Type, Chr)                 \
    for (FullPosition = 0; FullPosition < FullLen; ++FullPosition)                \
        if (((Type)NotifyChange->FullDirectoryName->Buffer)[FullPosition] == Chr) \
            ++FullNumberOfParts;                                                  \
    for (LastPartOffset = 0; LastPartOffset < TargLen; ++LastPartOffset) {        \
        if ( ((Type)TargetDirectory.Buffer)[LastPartOffset] == Chr) {             \
            ++TargetNumberOfParts;                                                \
        if (TargetNumberOfParts == FullNumberOfParts)                             \
            break;                                                                \
        }                                                                         \
    }

/* PRIVATE FUNCTIONS *********************************************************/

VOID
FsRtlNotifyCompleteIrpList(IN PNOTIFY_CHANGE NotifyChange,
                           IN NTSTATUS Status);

BOOLEAN
FsRtlNotifySetCancelRoutine(IN PIRP Irp,
                            IN PNOTIFY_CHANGE NotifyChange OPTIONAL);

/*
 * Take a notification off the FSD's NotifyList, once. Must be called with the
 * notify mutex held, by whoever drops the last reference (cleanup or cancel).
 * Both used to differ here: cancel freed the structure while it was still linked.
 */
static
VOID
FsRtlNotifyUnlinkChange(IN PNOTIFY_CHANGE NotifyChange)
{
    if (NotifyChange->NotifyList.Flink != NULL && NotifyChange->NotifyList.Blink != NULL)
    {
        RemoveEntryList(&NotifyChange->NotifyList);
    }
    NotifyChange->NotifyList.Flink = NULL;
    NotifyChange->NotifyList.Blink = NULL;
}

/*
 * Is the change buffer the one belonging to this (about to complete) IRP?
 */
static
BOOLEAN
FsRtlNotifyBufferBelongsToIrp(IN PIRP Irp,
                              IN PVOID Buffer)
{
    PVOID MdlBuffer;

    if (Buffer == Irp->AssociatedIrp.SystemBuffer)
    {
        return TRUE;
    }

    if (Irp->MdlAddress != NULL)
    {
        MdlBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
        return (MdlBuffer == Buffer);
    }

    return FALSE;
}

/*
 * The system address of the buffer an IRP returns its data in, if it has one.
 */
static
PVOID
FsRtlNotifyGetIrpBuffer(IN PIRP Irp)
{
    if (Irp->AssociatedIrp.SystemBuffer != NULL)
    {
        return Irp->AssociatedIrp.SystemBuffer;
    }

    if (Irp->MdlAddress != NULL)
    {
        return MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
    }

    return NULL;
}

/*
 * @implemented
 */
VOID
NTAPI
FsRtlCancelNotify(IN PDEVICE_OBJECT DeviceObject,
                  IN PIRP Irp)
{
    PVOID Buffer;
    PVOID _SEH2_VOLATILE Allocated;
    PIRP NotifyIrp;
    ULONG BufferLength;
    PIO_STACK_LOCATION Stack;
    PNOTIFY_CHANGE NotifyChange;
    PREAL_NOTIFY_SYNC RealNotifySync;
    BOOLEAN _SEH2_VOLATILE PoolQuotaCharged;
    PSECURITY_SUBJECT_CONTEXT _SEH2_VOLATILE SubjectContext = NULL;

    /* Get the NOTIFY_CHANGE struct and reset it */
    NotifyChange = (PNOTIFY_CHANGE)Irp->IoStatus.Information;
    Irp->IoStatus.Information = 0;
    /* Reset the cancel routine */
    IoSetCancelRoutine(Irp, NULL);
    /* And release lock */
    IoReleaseCancelSpinLock(Irp->CancelIrql);
    /* Get REAL_NOTIFY_SYNC struct */
    RealNotifySync = NotifyChange->NotifySync;

    FsRtlNotifyAcquireFastMutex(RealNotifySync);

   _SEH2_TRY
   {
       /* Remove the IRP from the notifications list and mark it pending.
        * FsRtlNotifyCompleteIrpList detaches (self-links) every IRP it takes off
        * the list, including one whose cancel routine had already been taken by
        * us: unlinking such an entry again would corrupt its former neighbours. */
       if (!IsListEmpty(&Irp->Tail.Overlay.ListEntry))
       {
           RemoveEntryList(&(Irp->Tail.Overlay.ListEntry));
           InitializeListHead(&(Irp->Tail.Overlay.ListEntry));
       }
       IoMarkIrpPending(Irp);

       /* Now, the tricky part - let's find a buffer big enough to hold the return data */
       if (NotifyChange->Buffer && NotifyChange->AllocatedBuffer == NULL &&
           FsRtlNotifyBufferBelongsToIrp(Irp, NotifyChange->Buffer))
       {
           /* Assume we didn't find any */
           Buffer = NULL;
           BufferLength = 0;

           /* If we don't have IRPs, check if current buffer is big enough */
           if (IsListEmpty(&NotifyChange->NotifyIrps))
           {
               if (NotifyChange->BufferLength >= NotifyChange->DataLength)
               {
                   BufferLength = NotifyChange->BufferLength;
               }
           }
           else
           {
               /* Otherwise, try to look at next IRP available */
               NotifyIrp = CONTAINING_RECORD(NotifyChange->NotifyIrps.Flink, IRP, Tail.Overlay.ListEntry);
               Stack = IoGetCurrentIrpStackLocation(NotifyIrp);

               /* If its buffer is big enough, get it */
               if (Stack->Parameters.NotifyDirectory.Length >= NotifyChange->BufferLength)
               {
                   /* Is it MDL? */
                   if (NotifyIrp->AssociatedIrp.SystemBuffer == NULL)
                   {
                       if (NotifyIrp->MdlAddress != NULL)
                       {
                           Buffer = MmGetSystemAddressForMdlSafe(NotifyIrp->MdlAddress, NormalPagePriority);
                       }
                   }
                   else
                   {
                       Buffer = NotifyIrp->AssociatedIrp.SystemBuffer;
                   }

                   /* Backup our accepted buffer length */
                   BufferLength = Stack->Parameters.NotifyDirectory.Length;
                   if (Buffer == NULL && BufferLength > NotifyChange->BufferLength)
                   {
                       BufferLength = NotifyChange->BufferLength;
                   }
               }
           }

           /* At that point, we *may* have a buffer. The pending data has to fit. */
           if (BufferLength < NotifyChange->DataLength)
           {
               BufferLength = 0;
           }

           /* If it has null length, then note that we won't use it */
           if (BufferLength == 0)
           {
               NotifyChange->Flags |= NOTIFY_IMMEDIATELY;
           }
           else if (Buffer != NULL)
           {
               /* The next IRP's buffer takes over: carry the pending data across, and
                * stop pointing at the buffer of the IRP we are about to complete */
               RtlCopyMemory(Buffer, NotifyChange->Buffer, NotifyChange->DataLength);
               NotifyChange->Buffer = Buffer;
               NotifyChange->ThisBufferLength = BufferLength;
           }
           else
           {
               /* We have a buffer length, but no buffer, so allocate one */
               Allocated = NULL;
               PoolQuotaCharged = FALSE;

               _SEH2_TRY
               {
                   /* Charge quotas */
                   PsChargePoolQuota(NotifyChange->OwningProcess, PagedPool, BufferLength);
                   PoolQuotaCharged = TRUE;

                   /* Allocate buffer */
                   Allocated = ExAllocatePoolWithTag(PagedPool | POOL_RAISE_IF_ALLOCATION_FAILURE, BufferLength, TAG_FS_NOTIFICATIONS);

                   /* Copy data in that buffer */
                   RtlCopyMemory(Allocated, NotifyChange->Buffer, NotifyChange->DataLength);
                   NotifyChange->AllocatedBuffer = Allocated;
                   NotifyChange->ThisBufferLength = BufferLength;
                   NotifyChange->Buffer = Allocated;
               }
               _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
               {
                   /* Something went wrong, have we allocated or charged quotas? */
                   if (Allocated != NULL)
                   {
                       ExFreePoolWithTag(Allocated, TAG_FS_NOTIFICATIONS);
                   }
                   if (PoolQuotaCharged)
                   {
                       /* We did, return quotas */
                       PsReturnProcessPagedPoolQuota(NotifyChange->OwningProcess, BufferLength);
                   }

                   /* And notify immediately */
                   NotifyChange->Flags |= NOTIFY_IMMEDIATELY;
               }
               _SEH2_END;
           }

           /* If we have to notify immediately, ensure that any buffer is 0-ed out */
           if (NotifyChange->Flags & NOTIFY_IMMEDIATELY)
           {
               NotifyChange->Buffer = 0;
               NotifyChange->AllocatedBuffer = 0;
               NotifyChange->LastEntry = 0;
               NotifyChange->DataLength = 0;
               NotifyChange->ThisBufferLength = 0;
           }
       }

       /* It's now time to complete - data are ready */

       /* Set appropriate status and complete */
       Irp->IoStatus.Status = STATUS_CANCELLED;
       IoCompleteRequest(Irp, IO_DISK_INCREMENT);

       /* If that notification isn't referenced any longer, drop it */
       if (!InterlockedDecrement((PLONG)&(NotifyChange->ReferenceCount)))
       {
           /* Always leave the FSD's list before the memory goes away: a cleanup that
            * found our reference still held did not unlink it */
           FsRtlNotifyUnlinkChange(NotifyChange);

           /* If it had an allocated buffer, delete */
           if (NotifyChange->AllocatedBuffer)
           {
               PsReturnProcessPagedPoolQuota(NotifyChange->OwningProcess, NotifyChange->ThisBufferLength);
               ExFreePoolWithTag(NotifyChange->AllocatedBuffer, TAG_FS_NOTIFICATIONS);
           }

           /* In case of full name, remember subject context for later deletion */
           if (NotifyChange->FullDirectoryName)
           {
               SubjectContext = NotifyChange->SubjectContext;
           }

           ExFreePoolWithTag(NotifyChange, 'NrSF');
       }
    }
    _SEH2_FINALLY
    {
        FsRtlNotifyReleaseFastMutex(RealNotifySync);

        /* If the subject security context was captured, release and free it */
        if (SubjectContext)
        {
            SeReleaseSubjectContext(SubjectContext);
            ExFreePool(SubjectContext);
        }
    }
    _SEH2_END;
}

/*
 * @implemented
 */
VOID
FsRtlCheckNotifyForDelete(IN PLIST_ENTRY NotifyList,
                          IN PVOID FsContext)
{
    PLIST_ENTRY NextEntry;
    PNOTIFY_CHANGE NotifyChange;

    if (!IsListEmpty(NotifyList))
    {
        /* Browse the notifications list to find the matching entry */
        for (NextEntry = NotifyList->Flink;
             NextEntry != NotifyList;
             NextEntry = NextEntry->Flink)
        {
            NotifyChange = CONTAINING_RECORD(NextEntry, NOTIFY_CHANGE, NotifyList);
            /* The FSD identifies the deleted directory by its stream context,
             * saved as StreamID, or by the context the watcher registered with */
            if ((NotifyChange->StreamID == FsContext || NotifyChange->FsContext == FsContext) &&
                !(NotifyChange->Flags & CLEANUP_IN_PROCESS) &&
                !IsListEmpty(&(NotifyChange->NotifyIrps)))
            {
                FsRtlNotifyCompleteIrpList(NotifyChange, STATUS_DELETE_PENDING);
            }
        }
    }
}

/*
 *@implemented
 */
PNOTIFY_CHANGE
FsRtlIsNotifyOnList(IN PLIST_ENTRY NotifyList,
                    IN PVOID FsContext)
{
    PLIST_ENTRY NextEntry;
    PNOTIFY_CHANGE NotifyChange;

    if (!IsListEmpty(NotifyList))
    {
        /* Browse the notifications list to find the matching entry */
        for (NextEntry = NotifyList->Flink;
             NextEntry != NotifyList;
             NextEntry = NextEntry->Flink)
        {
            NotifyChange = CONTAINING_RECORD(NextEntry, NOTIFY_CHANGE, NotifyList);
            /* If the current record matches with the given context, it's the good one.
             * A notification that was cleaned up and only waits for a cancel in flight to
             * free it belongs to a context the FSD has released: that address may have
             * been reused for a new handle, which must not find (and clean up) it */
            if (NotifyChange->FsContext == FsContext &&
                !(NotifyChange->Flags & CLEANUP_IN_PROCESS))
            {
                return NotifyChange;
            }
        }
    }
    return NULL;
}

/*
 * @implemented
 */
BOOLEAN
FsRtlNotifyCompleteIrp(IN PIRP Irp,
                       IN PNOTIFY_CHANGE NotifyChange,
                       IN ULONG DataLength,
                       IN NTSTATUS Status,
                       IN BOOLEAN SkipCompletion)
{
    PVOID Buffer, Target;
    PIO_STACK_LOCATION Stack;

    PAGED_CODE();

    /* Check if we need to complete: an IRP whose cancel routine is already gone is being
     * cancelled, and that cancel completes it. Tell the caller it did not take it. */
    if (!FsRtlNotifySetCancelRoutine(Irp, NotifyChange) && SkipCompletion)
    {
        return FALSE;
    }

    /* No succes => no data to return just complete */
    if (Status != STATUS_SUCCESS)
    {
        goto Completion;
    }

    /* Ensure there's something to return */
    Stack = IoGetCurrentIrpStackLocation(Irp);
    if (!DataLength || Stack->Parameters.NotifyDirectory.Length < DataLength)
    {
        /* The watcher re-enumerates, so a pending overflow has been reported */
        NotifyChange->Flags &= ~NOTIFY_IMMEDIATELY;
        Status = STATUS_NOTIFY_ENUM_DIR;
        /* Buffered data is dropped; a buffer borrowed from a pending IRP must not be
         * kept, that IRP is about to complete */
        if (!NotifyChange->AllocatedBuffer)
        {
            NotifyChange->Buffer = NULL;
            NotifyChange->ThisBufferLength = 0;
        }
        goto Completion;
    }

    /* Ensture there's a buffer where to find data */
    if (!NotifyChange->AllocatedBuffer)
    {
        /* The data sit in the buffer of the IRP that was queued first. If that IRP is
         * being cancelled (it is off the list, its cancel waits for us) they are not in
         * this IRP's buffer: carry them over, the change is not lost with the cancel */
        Buffer = NotifyChange->Buffer;
        if (Buffer != NULL && !FsRtlNotifyBufferBelongsToIrp(Irp, Buffer))
        {
            Target = FsRtlNotifyGetIrpBuffer(Irp);
            if (Target == NULL)
            {
                /* Nowhere to put them: the watcher re-enumerates */
                NotifyChange->Flags &= ~NOTIFY_IMMEDIATELY;
                NotifyChange->Buffer = NULL;
                NotifyChange->ThisBufferLength = 0;
                Status = STATUS_NOTIFY_ENUM_DIR;
                goto Completion;
            }
            RtlCopyMemory(Target, Buffer, DataLength);
        }
        Irp->IoStatus.Information = DataLength;
        NotifyChange->Buffer = NULL;
        NotifyChange->ThisBufferLength = 0;
        goto Completion;
    }

    /* Now, browse all the way to return data
     * and find the one that will work. We will
     * return data whatever happens
     */
    if (Irp->AssociatedIrp.SystemBuffer)
    {
        Buffer = Irp->AssociatedIrp.SystemBuffer;
        goto CopyAndComplete;
    }

    if (Irp->MdlAddress)
    {
        Buffer = MmGetSystemAddressForMdl(Irp->MdlAddress);
        goto CopyAndComplete;
    }

    if (!(Stack->Control & SL_PENDING_RETURNED))
    {
        Buffer = Irp->UserBuffer;
        goto CopyAndComplete;
    }

    Irp->Flags |= (IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | IRP_SYNCHRONOUS_PAGING_IO);
    Irp->AssociatedIrp.SystemBuffer = NotifyChange->AllocatedBuffer;
    /* Nothing to copy */
    goto ReleaseAndComplete;

CopyAndComplete:
    _SEH2_TRY
    {
        RtlCopyMemory(Buffer, NotifyChange->AllocatedBuffer, DataLength);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        /* Do nothing */
    }
    _SEH2_END;

ReleaseAndComplete:
    PsReturnProcessPagedPoolQuota(NotifyChange->OwningProcess, NotifyChange->ThisBufferLength);

    /* Release buffer UNLESS it's used */
    if (NotifyChange->AllocatedBuffer != Irp->AssociatedIrp.SystemBuffer &&
        NotifyChange->AllocatedBuffer)
    {
        ExFreePoolWithTag(NotifyChange->AllocatedBuffer, 0);
    }

    /* Prepare for return */
    NotifyChange->AllocatedBuffer = 0;
    NotifyChange->ThisBufferLength = 0;
    Irp->IoStatus.Information = DataLength;
    NotifyChange->Buffer = NULL;

    /* Finally complete */
Completion:
    IoMarkIrpPending(Irp);
    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_DISK_INCREMENT);
    return TRUE;
}

/*
 * @implemented
 */
VOID
FsRtlNotifyCompleteIrpList(IN PNOTIFY_CHANGE NotifyChange,
                           IN NTSTATUS Status)
{
    PIRP Irp;
    ULONG DataLength, LastEntry;
    PLIST_ENTRY NextEntry;
    BOOLEAN Completed = FALSE;

    DataLength = NotifyChange->DataLength;
    LastEntry = NotifyChange->LastEntry;

    /* The cleanup and delete marks stay: they tell later requests, and reports, that
     * this notification is finished, whatever the completions below did to it */
    NotifyChange->Flags &= (NOTIFY_IMMEDIATELY | WATCH_TREE | WATCH_ROOT |
                            CLEANUP_IN_PROCESS | DELETE_IN_PROCESS);
    NotifyChange->DataLength = 0;
    NotifyChange->LastEntry = 0;

    while (!IsListEmpty(&(NotifyChange->NotifyIrps)))
    {
        /* We take the first entry */
        NextEntry = RemoveHeadList(&(NotifyChange->NotifyIrps));
        /* Mark the IRP as no longer queued: its cancel routine may already be running
         * (and waiting for our mutex), and must not unlink it a second time */
        InitializeListHead(NextEntry);
        Irp = CONTAINING_RECORD(NextEntry, IRP, Tail.Overlay.ListEntry);
        /* We complete it */
        if (!FsRtlNotifyCompleteIrp(Irp, NotifyChange, DataLength, Status, TRUE))
        {
            /* Its cancel is in flight and completes it, with nothing to return. That
             * must not swallow a success: try the next queued IRP with the same data */
            continue;
        }
        Completed = TRUE;
        /* If we're notifying success, just notify first one */
        if (Status == STATUS_SUCCESS)
            break;
    }

    /* Nobody took the change (every queued IRP is being cancelled): it stays pending
     * for the next request. The buffer it sits in is the cancelled IRP's, which the
     * cancel routine hands on, so it must not be forgotten here. */
    if (Status == STATUS_SUCCESS && !Completed)
    {
        NotifyChange->DataLength = DataLength;
        NotifyChange->LastEntry = LastEntry;
        return;
    }

    /* A buffer borrowed from a completed IRP is gone with it */
    if (!NotifyChange->AllocatedBuffer)
    {
        NotifyChange->Buffer = NULL;
        NotifyChange->ThisBufferLength = 0;
    }
}

/*
 * @implemented
 */
BOOLEAN
FsRtlNotifySetCancelRoutine(IN PIRP Irp,
                            IN PNOTIFY_CHANGE NotifyChange OPTIONAL)
{
    PDRIVER_CANCEL CancelRoutine;

    /* Acquire cancel lock */
    IoAcquireCancelSpinLock(&Irp->CancelIrql);

    /* If NotifyChange was given */
    if (NotifyChange)
    {
        /* First get cancel routine */
        CancelRoutine = IoSetCancelRoutine(Irp, NULL);
        Irp->IoStatus.Information = 0;
        /* Release cancel lock */
        IoReleaseCancelSpinLock(Irp->CancelIrql);
        /* If there was a cancel routine */
        if (CancelRoutine)
        {
            /* Decrease reference count */
            InterlockedDecrement((PLONG)&NotifyChange->ReferenceCount);
            /* Notify that we removed cancel routine */
            return TRUE;
        }
    }
    else
    {
        /* If IRP is cancel, call FsRtl cancel routine */
        if (Irp->Cancel)
        {
             FsRtlCancelNotify(NULL, Irp);
        }
        else
        {
            /* Otherwise, define FsRtl cancel routine as IRP cancel routine */
            IoSetCancelRoutine(Irp, FsRtlCancelNotify);
            /* Release lock */
            IoReleaseCancelSpinLock(Irp->CancelIrql);
        }
    }

    /* Return that we didn't removed cancel routine */
    return FALSE;
}

/*
 * @implemented
 */
BOOLEAN
FsRtlNotifyUpdateBuffer(OUT PFILE_NOTIFY_INFORMATION OutputBuffer,
                        IN ULONG Action,
                        IN PSTRING ParentName,
                        IN PSTRING TargetName,
                        IN PSTRING StreamName,
                        IN BOOLEAN IsUnicode,
                        IN ULONG DataLength)
{
    /* Unless there's an issue with buffers, there's no reason to fail */
    BOOLEAN Succeed = TRUE;
    ULONG Capacity, Written = 0, Needed, ResultSize;
    PSTRING Names[3];
    ULONG i;

    PAGED_CODE();

    /* Update user buffer with the change that occured
     * First copy parent name if any
     * Then copy target name, there's always one
     * And finally, copy stream name if any
     * If these names aren't unicode, then convert first
     * Every write is checked against the space DataLength accounted for,
     * so a wrong length computed by the caller can't run past the entry
     */
    if (DataLength < FIELD_OFFSET(FILE_NOTIFY_INFORMATION, FileName))
    {
        return FALSE;
    }
    Capacity = DataLength - FIELD_OFFSET(FILE_NOTIFY_INFORMATION, FileName);

    Names[0] = ParentName;
    Names[1] = TargetName;
    Names[2] = StreamName;

    _SEH2_TRY
    {
        OutputBuffer->NextEntryOffset = 0;
        OutputBuffer->Action = Action;

        for (i = 0; i < 3; ++i)
        {
            PSTRING Name = Names[i];
            WCHAR Separator = (i == 0) ? L'\\' : L':';

            /* Absent names, and an empty parent (with its separator), write nothing */
            if (Name == NULL || (i == 0 && Name->Length == 0))
            {
                continue;
            }
            if (Name->Length != 0 && Name->Buffer == NULL)
            {
                Succeed = FALSE;
                break;
            }

            /* The separator goes after the parent and before the stream name */
            if (i == 2)
            {
                if (Written + sizeof(WCHAR) > Capacity)
                {
                    Succeed = FALSE;
                    break;
                }
                OutputBuffer->FileName[Written / sizeof(WCHAR)] = Separator;
                Written += sizeof(WCHAR);
            }

            if (Name->Length != 0)
            {
                if (IsUnicode)
                {
                    Needed = Name->Length;
                }
                else
                {
                    Needed = RtlOemStringToCountedUnicodeSize(Name);
                }
                if (Needed > Capacity - Written)
                {
                    Succeed = FALSE;
                    break;
                }

                if (IsUnicode)
                {
                    RtlCopyMemory((PVOID)((ULONG_PTR)OutputBuffer->FileName + Written),
                                  Name->Buffer, Name->Length);
                    ResultSize = Name->Length;
                }
                else
                {
                    RtlOemToUnicodeN((PWCHAR)((ULONG_PTR)OutputBuffer->FileName + Written),
                                     Capacity - Written, &ResultSize,
                                     Name->Buffer, Name->Length);
                }
                Written += ResultSize;
            }

            if (i == 0)
            {
                if (Written + sizeof(WCHAR) > Capacity)
                {
                    Succeed = FALSE;
                    break;
                }
                OutputBuffer->FileName[Written / sizeof(WCHAR)] = Separator;
                Written += sizeof(WCHAR);
            }
        }

        OutputBuffer->FileNameLength = Written;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Succeed = FALSE;
    }
    _SEH2_END;

    return Succeed;
}

/* PUBLIC FUNCTIONS **********************************************************/

/*++
 * @name FsRtlNotifyChangeDirectory
 * @implemented
 *
 * Lets FSD know if changes occures in the specified directory.
 * Directory will be reenumerated.
 *
 * @param NotifySync
 *        Synchronization object pointer
 *
 * @param FsContext
 *        Used to identify the notify structure
 *
 * @param FullDirectoryName
 *        String (A or W) containing the full directory name
 *
 * @param NotifyList
 *        Notify list pointer (to head)
 *
 * @param WatchTree
 *        True to notify changes in subdirectories too
 *
 * @param CompletionFilter
 *        Used to define types of changes to notify
 *
 * @param NotifyIrp
 *        IRP pointer to complete notify operation. It can be null
 *
 * @return None
 *
 * @remarks This function only redirects to FsRtlNotifyFilterChangeDirectory.
 *
 *--*/
VOID
NTAPI
FsRtlNotifyChangeDirectory(IN PNOTIFY_SYNC NotifySync,
                           IN PVOID FsContext,
                           IN PSTRING FullDirectoryName,
                           IN PLIST_ENTRY NotifyList,
                           IN BOOLEAN WatchTree,
                           IN ULONG CompletionFilter,
                           IN PIRP NotifyIrp)
{
    FsRtlNotifyFilterChangeDirectory(NotifySync,
                                     NotifyList,
                                     FsContext,
                                     FullDirectoryName,
                                     WatchTree,
                                     TRUE,
                                     CompletionFilter,
                                     NotifyIrp,
                                     NULL,
                                     NULL,
                                     NULL);
}

/*++
 * @name FsRtlNotifyCleanup
 * @implemented
 *
 * Called by FSD when all handles to FileObject (identified by FsContext) are closed
 *
 * @param NotifySync
 *        Synchronization object pointer
 *
 * @param NotifyList
 *        Notify list pointer (to head)
 *
 * @param FsContext
 *        Used to identify the notify structure
 *
 * @return None
 *
 * @remarks None
 *
 *--*/
VOID
NTAPI
FsRtlNotifyCleanup(IN PNOTIFY_SYNC NotifySync,
                   IN PLIST_ENTRY NotifyList,
                   IN PVOID FsContext)
{
    PNOTIFY_CHANGE NotifyChange;
    PREAL_NOTIFY_SYNC RealNotifySync;
    PSECURITY_SUBJECT_CONTEXT _SEH2_VOLATILE SubjectContext = NULL;

    /* Get real structure hidden behind the opaque pointer */
    RealNotifySync = (PREAL_NOTIFY_SYNC)NotifySync;

    /* Acquire the fast mutex */
    FsRtlNotifyAcquireFastMutex(RealNotifySync);

    _SEH2_TRY
    {
        /* Find if there's a matching notification with the FsContext */
        NotifyChange = FsRtlIsNotifyOnList(NotifyList, FsContext);
        if (NotifyChange)
        {
            /* Mark it as to know that cleanup is in process */
            NotifyChange->Flags |= CLEANUP_IN_PROCESS;

            /* If there are pending IRPs, complete them using the STATUS_NOTIFY_CLEANUP status */
            if (!IsListEmpty(&NotifyChange->NotifyIrps))
            {
                FsRtlNotifyCompleteIrpList(NotifyChange, STATUS_NOTIFY_CLEANUP);
            }

            /* Decrease reference number and if 0 is reached, it's time to do complete cleanup */
            if (!InterlockedDecrement((PLONG)&(NotifyChange->ReferenceCount)))
            {
                /* Remove it from the notifications list */
                FsRtlNotifyUnlinkChange(NotifyChange);

                /* In case there was an allocated buffer, free it */
                if (NotifyChange->AllocatedBuffer)
                {
                    PsReturnProcessPagedPoolQuota(NotifyChange->OwningProcess, NotifyChange->ThisBufferLength);
                    ExFreePool(NotifyChange->AllocatedBuffer);
                }

                /* In case there the string was set, get the captured subject security context */
                if (NotifyChange->FullDirectoryName)
                {
                    SubjectContext = NotifyChange->SubjectContext;
                }

                /* Finally, free the notification, as it's not needed anymore */
                ExFreePoolWithTag(NotifyChange, 'NrSF');
            }
            else
            {
                /* A cancel in flight still references the notification, and will free it;
                 * until then the entry stays on the list, flagged as cleaned up. The FSD is
                 * done with FsContext (it frees it after we return), so nothing may call
                 * back with it any more. */
                NotifyChange->TraverseCallback = NULL;
                NotifyChange->FilterCallback = NULL;
            }
        }
    }
    _SEH2_FINALLY
    {
        /* Release fast mutex */
        FsRtlNotifyReleaseFastMutex(RealNotifySync);

        /* If the subject security context was captured, release and free it */
        if (SubjectContext)
        {
            SeReleaseSubjectContext(SubjectContext);
            ExFreePool(SubjectContext);
        }
    }
    _SEH2_END;
}

/*++
 * @name FsRtlNotifyFilterChangeDirectory
 * @implemented
 *
 * FILLME
 *
 * @param NotifySync
 *        FILLME
 *
 * @param NotifyList
 *        FILLME
 *
 * @param FsContext
 *        FILLME
 *
 * @param FullDirectoryName
 *        FILLME
 *
 * @param WatchTree
 *        FILLME
 *
 * @param IgnoreBuffer
 *        FILLME
 *
 * @param CompletionFilter
 *        FILLME
 *
 * @param NotifyIrp
 *        FILLME
 *
 * @param TraverseCallback
 *        FILLME
 *
 * @param SubjectContext
 *        FILLME
 *
 * @param FilterCallback
 *        FILLME
 *
 * @return None
 *
 * @remarks None
 *
 *--*/
VOID
NTAPI
FsRtlNotifyFilterChangeDirectory(IN PNOTIFY_SYNC NotifySync,
                                 IN PLIST_ENTRY NotifyList,
                                 IN PVOID FsContext,
                                 IN PSTRING FullDirectoryName,
                                 IN BOOLEAN WatchTree,
                                 IN BOOLEAN IgnoreBuffer,
                                 IN ULONG CompletionFilter,
                                 IN PIRP NotifyIrp,
                                 IN PCHECK_FOR_TRAVERSE_ACCESS TraverseCallback OPTIONAL,
                                 IN PSECURITY_SUBJECT_CONTEXT SubjectContext OPTIONAL,
                                 IN PFILTER_REPORT_CHANGE FilterCallback OPTIONAL)
{
    ULONG SavedLength;
    PIO_STACK_LOCATION Stack;
    PNOTIFY_CHANGE NotifyChange = NULL;
    PREAL_NOTIFY_SYNC RealNotifySync;

    PAGED_CODE();

    DPRINT("FsRtlNotifyFilterChangeDirectory(): %p, %p, %p, %wZ, %u, %u, %u, %p, %p, %p, %p\n",
    NotifySync, NotifyList, FsContext, FullDirectoryName, WatchTree, IgnoreBuffer, CompletionFilter, NotifyIrp,
    TraverseCallback, SubjectContext, FilterCallback);

    /* Get real structure hidden behind the opaque pointer */
    RealNotifySync = (PREAL_NOTIFY_SYNC)NotifySync;

    /* Acquire the fast mutex */
    FsRtlNotifyAcquireFastMutex(RealNotifySync);

    _SEH2_TRY
    {
        /* If we have no IRP, FSD is performing a cleanup */
        if (!NotifyIrp)
        {
            /* So, we delete */
            FsRtlCheckNotifyForDelete(NotifyList, FsContext);
            _SEH2_LEAVE;
        }

        NotifyIrp->IoStatus.Status = STATUS_SUCCESS;
        NotifyIrp->IoStatus.Information = (ULONG_PTR)NULL;

        Stack = IoGetCurrentIrpStackLocation(NotifyIrp);
        /* If FileObject's been cleaned up, just return */
        if (Stack->FileObject->Flags & FO_CLEANUP_COMPLETE)
        {
            IoMarkIrpPending(NotifyIrp);
            NotifyIrp->IoStatus.Status = STATUS_NOTIFY_CLEANUP;
            IoCompleteRequest(NotifyIrp, IO_DISK_INCREMENT);
            _SEH2_LEAVE;
        }

        /* Try to find a matching notification has been already registered */
        NotifyChange = FsRtlIsNotifyOnList(NotifyList, FsContext);
        if (NotifyChange)
        {
            /* If it's been found, and is cleaned up, immediatly complete */
            if (NotifyChange->Flags & CLEANUP_IN_PROCESS)
            {
                IoMarkIrpPending(NotifyIrp);
                NotifyIrp->IoStatus.Status = STATUS_NOTIFY_CLEANUP;
                IoCompleteRequest(NotifyIrp, IO_DISK_INCREMENT);
                /* The IRP is completed: it must not be completed or queued again */
                _SEH2_LEAVE;
            }
            /* Or if it's about to be deleted, complete */
            else if (NotifyChange->Flags & DELETE_IN_PROCESS)
            {
                IoMarkIrpPending(NotifyIrp);
                NotifyIrp->IoStatus.Status = STATUS_DELETE_PENDING;
                IoCompleteRequest(NotifyIrp, IO_DISK_INCREMENT);
                _SEH2_LEAVE;
            }
            /* Complete now if asked to (and not asked to notify later on) */
            if ((NotifyChange->Flags & NOTIFY_IMMEDIATELY) && !(NotifyChange->Flags & NOTIFY_LATER))
            {
                NotifyChange->Flags &= ~NOTIFY_IMMEDIATELY;
                IoMarkIrpPending(NotifyIrp);
                NotifyIrp->IoStatus.Status = STATUS_NOTIFY_ENUM_DIR;
                IoCompleteRequest(NotifyIrp, IO_DISK_INCREMENT);
            }
            /* If no data yet, or asked to notify later on, handle */
            else if (NotifyChange->DataLength == 0 || (NotifyChange->Flags & NOTIFY_LATER))
            {
                goto HandleIRP;
            }
            /* Else, just complete with we have */
            else
            {
                SavedLength = NotifyChange->DataLength;
                NotifyChange->DataLength = 0;
                /* The records are handed over: the next change starts a new chain. LastEntry is the offset
                 * of the last record of the chain being built, so a stale one made the next change set the
                 * link of a record that does not exist and left the real first record unlinked: the reader
                 * saw one record of a read that held many (and a rename lost its NEW_NAME record). */
                NotifyChange->LastEntry = 0;
                FsRtlNotifyCompleteIrp(NotifyIrp, NotifyChange, SavedLength, STATUS_SUCCESS, FALSE);
            }

            _SEH2_LEAVE;
        }

        /* Allocate new notification */
        NotifyChange = ExAllocatePoolWithTag(PagedPool | POOL_RAISE_IF_ALLOCATION_FAILURE,
                                             sizeof(NOTIFY_CHANGE), 'NrSF');
        RtlZeroMemory(NotifyChange, sizeof(NOTIFY_CHANGE));

        /* Set basic information */
        NotifyChange->NotifySync = NotifySync;
        NotifyChange->FsContext = FsContext;
        NotifyChange->StreamID = Stack->FileObject->FsContext;
        NotifyChange->TraverseCallback = TraverseCallback;
        NotifyChange->SubjectContext = SubjectContext;
        NotifyChange->FullDirectoryName = FullDirectoryName;
        NotifyChange->FilterCallback = FilterCallback;
        InitializeListHead(&(NotifyChange->NotifyIrps));

        /* Keep trace of WatchTree */
        if (WatchTree)
        {
            NotifyChange->Flags |= WATCH_TREE;
        }

        /* If string is empty, faulty to ANSI */
        if (FullDirectoryName->Length == 0)
        {
            NotifyChange->CharacterSize = sizeof(CHAR);
        }
        else
        {
            /* If it can't contain WCHAR, it's ANSI */
            if (FullDirectoryName->Length < sizeof(WCHAR) || ((CHAR*)FullDirectoryName->Buffer)[1] != 0)
            {
                NotifyChange->CharacterSize = sizeof(CHAR);
            }
            else
            {
                NotifyChange->CharacterSize = sizeof(WCHAR);
            }

            /* Now, check is user is willing to watch root */
            if (FullDirectoryName->Length == NotifyChange->CharacterSize)
            {
                NotifyChange->Flags |= WATCH_ROOT;
            }
        }

        NotifyChange->CompletionFilter = CompletionFilter;

        /* In case we have not to ignore buffer , keep its length */
        if (!IgnoreBuffer)
        {
            NotifyChange->BufferLength = Stack->Parameters.NotifyDirectory.Length;
        }

        NotifyChange->OwningProcess = NotifyIrp->Tail.Overlay.Thread->ThreadsProcess;

        /* Insert the notification into the notification list */
        InsertTailList(NotifyList, &(NotifyChange->NotifyList));

        NotifyChange->ReferenceCount = 1;

HandleIRP:
        /* Associate the notification to the IRP */
        NotifyIrp->IoStatus.Information = (ULONG_PTR)NotifyChange;
        /* The IRP is pending */
        IoMarkIrpPending(NotifyIrp);
        /* Insert the IRP in the IRP list */
        InsertTailList(&(NotifyChange->NotifyIrps), &(NotifyIrp->Tail.Overlay.ListEntry));
        /* Increment reference count */
        InterlockedIncrement((PLONG)&(NotifyChange->ReferenceCount));
        /* Set cancel routine to FsRtl one */
        FsRtlNotifySetCancelRoutine(NotifyIrp, NULL);
    }
    _SEH2_FINALLY
    {
        /* Release fast mutex */
        FsRtlNotifyReleaseFastMutex(RealNotifySync);

        /* If the subject security context was captured and there's no notify */
        if (SubjectContext && (!NotifyChange || NotifyChange->FullDirectoryName))
        {
            SeReleaseSubjectContext(SubjectContext);
            ExFreePool(SubjectContext);
        }
    }
    _SEH2_END;
}

/*++
 * @name FsRtlNotifyFilterReportChange
 * @implemented
 *
 * FILLME
 *
 * @param NotifySync
 *        FILLME
 *
 * @param NotifyList
 *        FILLME
 *
 * @param FullTargetName
 *        FILLME
 *
 * @param TargetNameOffset
 *        FILLME
 *
 * @param StreamName
 *        FILLME
 *
 * @param NormalizedParentName
 *        FILLME
 *
 * @param FilterMatch
 *        FILLME
 *
 * @param Action
 *        FILLME
 *
 * @param TargetContext
 *        FILLME
 *
 * @param FilterContext
 *        FILLME
 *
 * @return None
 *
 * @remarks None
 *
 *--*/
VOID
NTAPI
FsRtlNotifyFilterReportChange(IN PNOTIFY_SYNC NotifySync,
                              IN PLIST_ENTRY NotifyList,
                              IN PSTRING FullTargetName,
                              IN USHORT TargetNameOffset,
                              IN PSTRING StreamName OPTIONAL,
                              IN PSTRING NormalizedParentName OPTIONAL,
                              IN ULONG FilterMatch,
                              IN ULONG Action,
                              IN PVOID TargetContext,
                              IN PVOID FilterContext)
{
    PIRP Irp;
    PVOID OutputBuffer;
    USHORT FullPosition;
    PLIST_ENTRY NextEntry;
    PIO_STACK_LOCATION Stack;
    PNOTIFY_CHANGE NotifyChange;
    PREAL_NOTIFY_SYNC RealNotifySync;
    PFILE_NOTIFY_INFORMATION FileNotifyInfo;
    BOOLEAN IsStream, IsParent, PoolQuotaCharged;
    STRING TargetDirectory, TargetName, ParentName, IntNormalizedParentName;
    ULONG NumberOfBytes, TargetNumberOfParts, FullNumberOfParts, LastPartOffset, ParentNameOffset, ParentNameLength;
    ULONG DataLength, AlignedDataLength;

    TargetDirectory.Length = 0;
    TargetDirectory.MaximumLength = 0;
    TargetDirectory.Buffer = NULL;
    TargetName.Length = 0;
    TargetName.MaximumLength = 0;
    TargetName.Buffer = NULL;
    ParentName.Length = 0;
    ParentName.MaximumLength = 0;
    ParentName.Buffer = NULL;
    IsStream = FALSE;

    PAGED_CODE();

    DPRINT("FsRtlNotifyFilterReportChange(%p, %p, %p, %u, %p, %p, %p, %x, %x, %p, %p)\n",
           NotifySync, NotifyList, FullTargetName, TargetNameOffset, StreamName, NormalizedParentName,
           FilterMatch, Action, TargetContext, FilterContext);

    /* We need offset in name */
    if (!TargetNameOffset && FullTargetName)
    {
        return;
    }

    /* The offset of the last component has to lie inside the name the FSD gave us */
    if (FullTargetName && TargetNameOffset > FullTargetName->Length)
    {
        return;
    }

    /* Get real structure hidden behind the opaque pointer */
    RealNotifySync = (PREAL_NOTIFY_SYNC)NotifySync;
    /* Acquire lock - will be released in finally block */
    FsRtlNotifyAcquireFastMutex(RealNotifySync);
    _SEH2_TRY
    {
        /* Browse all the registered notifications we have */
        for (NextEntry = NotifyList->Flink; NextEntry != NotifyList;
             NextEntry = NextEntry->Flink)
        {
            /* Try to find an entry matching our change */
            NotifyChange = CONTAINING_RECORD(NextEntry, NOTIFY_CHANGE, NotifyList);

            /* A watcher whose handle is closed only lingers until its last cancel ran */
            if (NotifyChange->Flags & CLEANUP_IN_PROCESS)
            {
                continue;
            }

            if (FullTargetName != NULL)
            {
                ASSERT(NotifyChange->FullDirectoryName != NULL);
                if (!NotifyChange->FullDirectoryName->Length)
                {
                    continue;
                }

                /* The offset has to cover the leading separator we are going to strip */
                if (TargetNameOffset < NotifyChange->CharacterSize)
                {
                    continue;
                }

                if (!(FilterMatch & NotifyChange->CompletionFilter))
                {
                    continue;
                }

                /* If no normalized name provided, construct it from full target name */
                if (NormalizedParentName == NULL)
                {
                    IntNormalizedParentName.Buffer = FullTargetName->Buffer;
                    if (TargetNameOffset != NotifyChange->CharacterSize)
                    {
                        IntNormalizedParentName.MaximumLength =
                        IntNormalizedParentName.Length = TargetNameOffset - NotifyChange->CharacterSize;
                    }
                    else
                    {
                        IntNormalizedParentName.MaximumLength =
                        IntNormalizedParentName.Length = TargetNameOffset;
                    }
                    NormalizedParentName = &IntNormalizedParentName;
                }

                /* heh? Watched directory bigger than changed file? */
                if (NormalizedParentName->Length < NotifyChange->FullDirectoryName->Length)
                {
                    continue;
                }

                /* Same len => parent */
                if (NormalizedParentName->Length == NotifyChange->FullDirectoryName->Length)
                {
                    IsParent = TRUE;
                }
                /* If not, then, we have to be watching the tree, otherwise we don't have to report such changes */
                else if (!(NotifyChange->Flags & WATCH_TREE))
                {
                    continue;
                }
                /* And finally, we've to check we're properly \-terminated */
                else
                {
                    if (!(NotifyChange->Flags & WATCH_ROOT))
                    {
                        if (NotifyChange->CharacterSize == sizeof(CHAR))
                        {
                            if (((PSTR)NormalizedParentName->Buffer)[NotifyChange->FullDirectoryName->Length] != '\\')
                            {
                                continue;
                            }
                        }
                        else
                        {
                            if (((PWSTR)NormalizedParentName->Buffer)[NotifyChange->FullDirectoryName->Length / sizeof (WCHAR)] != L'\\')
                            {
                                continue;
                            }
                        }
                    }

                    IsParent = FALSE;
                }

                /* If len matches, then check that both name are equal */
                if (!RtlEqualMemory(NormalizedParentName->Buffer, NotifyChange->FullDirectoryName->Buffer,
                                    NotifyChange->FullDirectoryName->Length))
                {
                    continue;
                }

                /* Call traverse callback (only if we have to traverse ;-)) */
                if (!IsParent
                    && NotifyChange->TraverseCallback != NULL
                    && !NotifyChange->TraverseCallback(NotifyChange->FsContext,
                                                       TargetContext,
                                                       NotifyChange->SubjectContext))
                {
                    continue;
                }

                /* And then, filter callback if provided */
                if (NotifyChange->FilterCallback != NULL
                    && FilterContext != NULL
                    && !NotifyChange->FilterCallback(NotifyChange->FsContext, FilterContext))
                {
                    continue;
                }
            }
            /* We have a stream! */
            else
            {
                ASSERT(NotifyChange->FullDirectoryName == NULL);
                if (TargetContext != NotifyChange->SubjectContext)
                {
                    continue;
                }

                ParentName.Buffer = NULL;
                ParentName.Length = 0;
                IsStream = TRUE;
                IsParent = FALSE;
            }

            /* If we don't have to notify immediately, prepare for output */
            if (!(NotifyChange->Flags & NOTIFY_IMMEDIATELY))
            {
                /* If we have something to output... */
                if (NotifyChange->BufferLength)
                {
                    /* Get size of the output */
                    NumberOfBytes = 0;
                    Irp = NULL;
                    if (!NotifyChange->ThisBufferLength)
                    {
                        if (IsListEmpty(&NotifyChange->NotifyIrps))
                        {
                            NumberOfBytes = NotifyChange->BufferLength;
                        }
                        else
                        {
                            Irp = CONTAINING_RECORD(NotifyChange->NotifyIrps.Flink, IRP, Tail.Overlay.ListEntry);
                            Stack = IoGetCurrentIrpStackLocation(Irp);
                            NumberOfBytes = Stack->Parameters.NotifyDirectory.Length;
                        }
                    }
                    else
                    {
                        NumberOfBytes = NotifyChange->ThisBufferLength;
                    }

                    /* If we're matching parent, we don't care about parent (redundant) */
                    if (IsParent)
                    {
                        ParentName.Length = 0;
                    }
                    else
                    {
                        /* If we don't deal with streams, some more work is required */
                        if (!IsStream)
                        {
                            if (NotifyChange->Flags & WATCH_ROOT ||
                                (NormalizedParentName->Buffer != FullTargetName->Buffer))
                            {
                                /* Construct TargetDirectory if we don't have it yet */
                                if (TargetDirectory.Buffer == NULL)
                                {
                                    TargetDirectory.Buffer = FullTargetName->Buffer;
                                    TargetDirectory.Length = TargetNameOffset;
                                    if (TargetNameOffset != NotifyChange->CharacterSize)
                                    {
                                        TargetDirectory.Length = TargetNameOffset - NotifyChange->CharacterSize;
                                    }
                                    TargetDirectory.MaximumLength = TargetDirectory.Length;
                                }
                                /* Now, we start looking for matching parts (unless we watch root) */
                                TargetNumberOfParts = 0;
                                LastPartOffset = 0;
                                if (!(NotifyChange->Flags & WATCH_ROOT))
                                {
                                    FullNumberOfParts = 1;
                                    if (NotifyChange->CharacterSize == sizeof(CHAR))
                                    {
                                        FsRtlNotifyGetLastPartOffset(NotifyChange->FullDirectoryName->Length,
                                                                     TargetDirectory.Length, PSTR, '\\');
                                    }
                                    else
                                    {
                                        FsRtlNotifyGetLastPartOffset(NotifyChange->FullDirectoryName->Length / sizeof(WCHAR),
                                                                     TargetDirectory.Length / sizeof(WCHAR), PWSTR, L'\\');
                                        LastPartOffset *= NotifyChange->CharacterSize;
                                    }
                                }

                                /* Then, we can construct proper parent name */
                                ParentNameOffset = NotifyChange->CharacterSize + LastPartOffset;
                                if (ParentNameOffset > TargetDirectory.Length)
                                {
                                    continue;
                                }
                                ParentName.Buffer = &TargetDirectory.Buffer[ParentNameOffset];
                                ParentNameLength = TargetDirectory.Length;
                            }
                            else
                            {
                                /* Construct parent name even for streams */
                                ParentName.Buffer = &NormalizedParentName->Buffer[NotifyChange->FullDirectoryName->Length] + NotifyChange->CharacterSize;
                                ParentNameLength = NormalizedParentName->Length - NotifyChange->FullDirectoryName->Length;
                                ParentNameOffset = NotifyChange->CharacterSize;
                                if (ParentNameOffset > ParentNameLength)
                                {
                                    continue;
                                }
                            }
                            ParentNameLength -= ParentNameOffset;
                            ParentName.Length = ParentNameLength;
                            ParentName.MaximumLength = ParentNameLength;
                        }
                    }

                    /* Start to count amount of data to write, we've first the structure itself */
                    DataLength = FIELD_OFFSET(FILE_NOTIFY_INFORMATION, FileName);

                    /* If stream, we'll just append stream name */
                    if (IsStream)
                    {
                        ASSERT(StreamName != NULL);
                        /* The name is the stream's, preceded by the ':' separator */
                        if (NotifyChange->CharacterSize == sizeof(WCHAR))
                        {
                            DataLength += StreamName->Length;
                        }
                        else
                        {
                            DataLength += RtlOemStringToCountedUnicodeSize(StreamName);
                        }
                        DataLength += sizeof(WCHAR);
                    }
                    else
                    {
                        /* If not parent, we've to append parent name */
                        if (!IsParent)
                        {
                            if (NotifyChange->CharacterSize == sizeof(CHAR))
                            {
                                DataLength += RtlOemStringToCountedUnicodeSize(&ParentName);
                            }
                            else
                            {
                                DataLength += ParentName.Length;
                            }
                            DataLength += sizeof(WCHAR);
                        }

                        /* Look for target name & construct it, if required */
                        if (TargetName.Buffer == NULL)
                        {
                            TargetName.Buffer = &FullTargetName->Buffer[TargetNameOffset];
                            TargetName.Length =
                            TargetName.MaximumLength = FullTargetName->Length - TargetNameOffset;
                        }

                        /* Then, we will append it as well */
                        if (NotifyChange->CharacterSize == sizeof(CHAR))
                        {
                            DataLength += RtlOemStringToCountedUnicodeSize(&TargetName);
                        }
                        else
                        {
                            DataLength += TargetName.Length;
                        }

                        /* If we also had a stream name, then we can append it as well */
                        if (StreamName != NULL)
                        {
                            if (NotifyChange->CharacterSize == sizeof(WCHAR))
                            {
                                DataLength += StreamName->Length + sizeof(WCHAR);
                            }
                            else
                            {
                                DataLength = DataLength + RtlOemStringToCountedUnicodeSize(StreamName) + sizeof(WCHAR);
                            }
                        }
                    }

                    /* Get the position where we can put our data (aligned!) */
                    AlignedDataLength = ROUND_UP(NotifyChange->DataLength, sizeof(ULONG));
                    /* If it's higher than buffer length, then, bail out without outputing */
                    if (DataLength > NumberOfBytes || AlignedDataLength + DataLength > NumberOfBytes)
                    {
                        NotifyChange->Flags |= NOTIFY_IMMEDIATELY;
                    }
                    else
                    {
                        OutputBuffer = NULL;
                        FileNotifyInfo = NULL;
                        /* If we already had a buffer, update last entry position */
                        if (NotifyChange->Buffer != NULL)
                        {
                            FileNotifyInfo = (PVOID)((ULONG_PTR)NotifyChange->Buffer + NotifyChange->LastEntry);
                            FileNotifyInfo->NextEntryOffset = AlignedDataLength - NotifyChange->LastEntry;
                            NotifyChange->LastEntry = AlignedDataLength;
                            /* And get our output buffer */
                            OutputBuffer = (PVOID)((ULONG_PTR)NotifyChange->Buffer + AlignedDataLength);
                        }
                        /* If we hadn't buffer, try to find one */
                        else if (Irp != NULL)
                        {
                            if (Irp->AssociatedIrp.SystemBuffer != NULL)
                            {
                                OutputBuffer = Irp->AssociatedIrp.SystemBuffer;
                            }
                            else if (Irp->MdlAddress != NULL)
                            {
                                OutputBuffer = MmGetSystemAddressForMdl(Irp->MdlAddress);
                            }

                            NotifyChange->Buffer = OutputBuffer;
                            NotifyChange->ThisBufferLength = NumberOfBytes;
                        }

                        /* If we couldn't find one, then allocate one */
                        if (NotifyChange->Buffer == NULL)
                        {
                            /* Assign the length buffer */
                            NotifyChange->ThisBufferLength = NumberOfBytes;

                            /* Assume we have not charged quotas */
                            PoolQuotaCharged = FALSE;
                            _SEH2_TRY
                            {
                                /* And charge quotas */
                                PsChargePoolQuota(NotifyChange->OwningProcess, PagedPool, NotifyChange->ThisBufferLength);
                                PoolQuotaCharged = TRUE;
                                OutputBuffer = ExAllocatePoolWithTag(PagedPool | POOL_RAISE_IF_ALLOCATION_FAILURE,
                                                                     NumberOfBytes, TAG_FS_NOTIFICATIONS);
                                NotifyChange->Buffer = OutputBuffer;
                                NotifyChange->AllocatedBuffer = OutputBuffer;
                            }
                            /* If something went wrong during allocation, notify immediately instead of outputing */
                            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                            {
                                if (PoolQuotaCharged)
                                {
                                    PsReturnProcessPagedPoolQuota(NotifyChange->OwningProcess, NotifyChange->ThisBufferLength);
                                }
                                /* There is no buffer, so there is no size either */
                                NotifyChange->ThisBufferLength = 0;
                                NotifyChange->Buffer = NULL;
                                NotifyChange->AllocatedBuffer = NULL;
                                NotifyChange->Flags |= NOTIFY_IMMEDIATELY;
                            }
                            _SEH2_END;
                        }

                        /* Finally, if we have a buffer, fill it in! */
                        if (OutputBuffer != NULL)
                        {
                            if (FsRtlNotifyUpdateBuffer((FILE_NOTIFY_INFORMATION *)OutputBuffer,
                                                         Action, &ParentName, &TargetName,
                                                         StreamName, NotifyChange->CharacterSize == sizeof(WCHAR),
                                                         DataLength))
                            {
                                NotifyChange->DataLength = DataLength + AlignedDataLength;
                            }
                            /* If it failed, notify immediately */
                            else
                            {
                                NotifyChange->Flags |= NOTIFY_IMMEDIATELY;
                            }
                        }
                    }

                    /* If we have to notify right now (something went wrong?) */
                    if (NotifyChange->Flags & NOTIFY_IMMEDIATELY)
                    {
                        /* Ensure that all our buffers are NULL */
                        if (NotifyChange->Buffer != NULL)
                        {
                            if (NotifyChange->AllocatedBuffer != NULL)
                            {
                                PsReturnProcessPagedPoolQuota(NotifyChange->OwningProcess, NotifyChange->ThisBufferLength);
                                ExFreePoolWithTag(NotifyChange->AllocatedBuffer, TAG_FS_NOTIFICATIONS);
                            }

                            NotifyChange->Buffer = NULL;
                            NotifyChange->AllocatedBuffer = NULL;
                            NotifyChange->LastEntry = 0;
                            NotifyChange->DataLength = 0;
                            NotifyChange->ThisBufferLength = 0;
                        }
                    }
                }
                else
                {
                    /* No buffer to record the change in: the watcher must re-enumerate */
                    NotifyChange->Flags |= NOTIFY_IMMEDIATELY;
                }
            }

            /* If asking for old name in case of a rename, notify later on,
             * so that we can wait for new name.
             * https://learn.microsoft.com/en-us/openspecs/main/ms-openspeclp/3589baea-5b22-48f2-9d43-f5bea4960ddb
             */
            if (Action == FILE_ACTION_RENAMED_OLD_NAME)
            {
                NotifyChange->Flags |= NOTIFY_LATER;
            }
            else
            {
                NotifyChange->Flags &= ~NOTIFY_LATER;
                if (!IsListEmpty(&NotifyChange->NotifyIrps))
                {
                    FsRtlNotifyCompleteIrpList(NotifyChange, STATUS_SUCCESS);
                }
            }
        }
    }
    _SEH2_FINALLY
    {
        FsRtlNotifyReleaseFastMutex(RealNotifySync);
    }
    _SEH2_END;
}

/*++
 * @name FsRtlNotifyFullChangeDirectory
 * @implemented
 *
 * Lets FSD know if changes occures in the specified directory.
 *
 * @param NotifySync
 *        Synchronization object pointer
 *
 * @param NotifyList
 *        Notify list pointer (to head)
 *
 * @param FsContext
 *        Used to identify the notify structure
 *
 * @param FullDirectoryName
 *        String (A or W) containing the full directory name
 *
 * @param WatchTree
 *        True to notify changes in subdirectories too
 *
 * @param IgnoreBuffer
 *        True to reenumerate directory. It's ignored it NotifyIrp is null
 *
 * @param CompletionFilter
 *        Used to define types of changes to notify
 *
 * @param NotifyIrp
 *        IRP pointer to complete notify operation. It can be null
 *
 * @param TraverseCallback
 *        Pointer to a callback function. It's called each time a change is
 *        done in a subdirectory of the main directory. It's ignored it NotifyIrp
 *        is null
 *
 * @param SubjectContext
 *        Pointer to pass to SubjectContext member of TraverseCallback.
 *        It's freed after use. It's ignored it NotifyIrp is null
 *
 * @return None
 *
 * @remarks This function only redirects to FsRtlNotifyFilterChangeDirectory.
 *
 *--*/
VOID
NTAPI
FsRtlNotifyFullChangeDirectory(IN PNOTIFY_SYNC NotifySync,
                               IN PLIST_ENTRY NotifyList,
                               IN PVOID FsContext,
                               IN PSTRING FullDirectoryName,
                               IN BOOLEAN WatchTree,
                               IN BOOLEAN IgnoreBuffer,
                               IN ULONG CompletionFilter,
                               IN PIRP NotifyIrp,
                               IN PCHECK_FOR_TRAVERSE_ACCESS TraverseCallback OPTIONAL,
                               IN PSECURITY_SUBJECT_CONTEXT SubjectContext OPTIONAL)
{
    FsRtlNotifyFilterChangeDirectory(NotifySync,
                                     NotifyList,
                                     FsContext,
                                     FullDirectoryName,
                                     WatchTree,
                                     IgnoreBuffer,
                                     CompletionFilter,
                                     NotifyIrp,
                                     TraverseCallback,
                                     SubjectContext,
                                     NULL);
}

/*++
 * @name FsRtlNotifyFullReportChange
 * @implemented
 *
 * Complets the pending notify IRPs.
 *
 * @param NotifySync
 *        Synchronization object pointer
 *
 * @param NotifyList
 *        Notify list pointer (to head)
 *
 * @param FullTargetName
 *        String (A or W) containing the full directory name that changed
 *
 * @param TargetNameOffset
 *        Offset, in FullTargetName, of the final component that is in the changed directory
 *
 * @param StreamName
 *        String (A or W) containing a stream name
 *
 * @param NormalizedParentName
 *        String (A or W) containing the full directory name that changed with long names
 *
 * @param FilterMatch
 *        Flags that will be compared to the completion filter
 *
 * @param Action
 *        Action code to store in user's buffer
 *
 * @param TargetContext
 *        Pointer to a callback function. It's called each time a change is
 *        done in a subdirectory of the main directory.
 *
 * @return None
 *
 * @remarks This function only redirects to FsRtlNotifyFilterReportChange.
 *
 *--*/
VOID
NTAPI
FsRtlNotifyFullReportChange(IN PNOTIFY_SYNC NotifySync,
                            IN PLIST_ENTRY NotifyList,
                            IN PSTRING FullTargetName,
                            IN USHORT TargetNameOffset,
                            IN PSTRING StreamName OPTIONAL,
                            IN PSTRING NormalizedParentName OPTIONAL,
                            IN ULONG FilterMatch,
                            IN ULONG Action,
                            IN PVOID TargetContext)
{
    FsRtlNotifyFilterReportChange(NotifySync,
                                  NotifyList,
                                  FullTargetName,
                                  TargetNameOffset,
                                  StreamName,
                                  NormalizedParentName,
                                  FilterMatch,
                                  Action,
                                  TargetContext,
                                  NULL);
}

/*++
 * @name FsRtlNotifyInitializeSync
 * @implemented
 *
 * Allocates the internal structure associated with notifications.
 *
 * @param NotifySync
 *        Opaque pointer. It will receive the address of the allocated internal structure.
 *
 * @return None
 *
 * @remarks This function raise an exception in case of a failure.
 *
 *--*/
VOID
NTAPI
FsRtlNotifyInitializeSync(IN PNOTIFY_SYNC *NotifySync)
{
    PREAL_NOTIFY_SYNC RealNotifySync;

    *NotifySync = NULL;

    RealNotifySync = ExAllocatePoolWithTag(NonPagedPool | POOL_RAISE_IF_ALLOCATION_FAILURE,
                                           sizeof(REAL_NOTIFY_SYNC), 'SNSF');
    ExInitializeFastMutex(&(RealNotifySync->FastMutex));
    RealNotifySync->OwningThread = 0;
    RealNotifySync->OwnerCount = 0;

    *NotifySync = RealNotifySync;
}

/*++
 * @name FsRtlNotifyReportChange
 * @implemented
 *
 * Complets the pending notify IRPs.
 *
 * @param NotifySync
 *        Synchronization object pointer
 *
 * @param NotifyList
 *        Notify list pointer (to head)
 *
 * @param FullTargetName
 *        String (A or W) containing the full directory name that changed
 *
 * @param FileNamePartLength
 *        Length of the final component that is in the changed directory
 *
 * @param FilterMatch
 *        Flags that will be compared to the completion filter
 *
 * @return None
 *
 * @remarks This function only redirects to FsRtlNotifyFilterReportChange.
 *
 *--*/
VOID
NTAPI
FsRtlNotifyReportChange(IN PNOTIFY_SYNC NotifySync,
                        IN PLIST_ENTRY NotifyList,
                        IN PSTRING FullTargetName,
                        IN PUSHORT FileNamePartLength,
                        IN ULONG FilterMatch)
{
      /* The final component can't be longer than the name it belongs to */
      if (*FileNamePartLength > FullTargetName->Length)
      {
          return;
      }

      FsRtlNotifyFilterReportChange(NotifySync,
                                    NotifyList,
                                    FullTargetName,
                                    FullTargetName->Length - *FileNamePartLength,
                                    NULL,
                                    NULL,
                                    FilterMatch,
                                    0,
                                    NULL,
                                    NULL);
}

/*++
 * @name FsRtlNotifyUninitializeSync
 * @implemented
 *
 * Uninitialize a NOTIFY_SYNC object
 *
 * @param NotifySync
 *        Address of a pointer to a PNOTIFY_SYNC object previously
 *        initialized by FsRtlNotifyInitializeSync()
 *
 * @return None
 *
 * @remarks None
 *
 *--*/
VOID
NTAPI
FsRtlNotifyUninitializeSync(IN PNOTIFY_SYNC *NotifySync)
{
    if (*NotifySync)
    {
        ExFreePoolWithTag(*NotifySync, 'SNSF');
        *NotifySync = NULL;
    }
}


/*++
 * @name FsRtlNotifyCleanupAll
 * @implemented
 *
 * Cleans up every notification of a list, as FsRtlNotifyCleanup does for one handle.
 *
 * @param NotifySync
 *        Synchronization object pointer
 *
 * @param NotifyList
 *        Notify list pointer (to head)
 *
 * @return None
 *
 *--*/
VOID
NTAPI
FsRtlNotifyCleanupAll(IN PNOTIFY_SYNC NotifySync,
                      IN PLIST_ENTRY NotifyList)
{
    PREAL_NOTIFY_SYNC RealNotifySync = (PREAL_NOTIFY_SYNC)NotifySync;
    PLIST_ENTRY NextEntry;
    PNOTIFY_CHANGE NotifyChange;
    PVOID FsContext;
    BOOLEAN Found;

    for (;;)
    {
        Found = FALSE;
        FsContext = NULL;

        /* The first notification not cleaned up yet; one waiting for a cancel in flight is skipped */
        FsRtlNotifyAcquireFastMutex(RealNotifySync);
        for (NextEntry = NotifyList->Flink; NextEntry != NotifyList; NextEntry = NextEntry->Flink)
        {
            NotifyChange = CONTAINING_RECORD(NextEntry, NOTIFY_CHANGE, NotifyList);
            if (!(NotifyChange->Flags & CLEANUP_IN_PROCESS))
            {
                FsContext = NotifyChange->FsContext;
                Found = TRUE;
                break;
            }
        }
        FsRtlNotifyReleaseFastMutex(RealNotifySync);

        if (!Found)
            break;

        FsRtlNotifyCleanup(NotifySync, NotifyList, FsContext);
    }
}
