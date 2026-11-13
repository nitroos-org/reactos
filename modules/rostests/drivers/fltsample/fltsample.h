/*
 * PROJECT:     ReactOS test suite
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Sample mini-filter, interface shared with the tests which drive it
 */

#ifndef _FLTSAMPLE_H
#define _FLTSAMPLE_H

#ifndef CTL_CODE
#error include winioctl.h or ntddk.h first
#endif

/* The tests are user mode programs, the operation numbers are the documented IRP_MJ_* values */
#ifndef IRP_MJ_CREATE
#define IRP_MJ_CREATE                   0x00
#define IRP_MJ_CLOSE                    0x02
#define IRP_MJ_READ                     0x03
#define IRP_MJ_WRITE                    0x04
#define IRP_MJ_QUERY_INFORMATION        0x05
#define IRP_MJ_SET_INFORMATION          0x06
#define IRP_MJ_DIRECTORY_CONTROL        0x0c
#define IRP_MJ_CLEANUP                  0x12
#endif
#ifndef FLTFL_INSTANCE_TEARDOWN_MANUAL
#define FLTFL_INSTANCE_TEARDOWN_MANUAL  0x00000001
#endif

#define FLTSAMPLE_MAX_MAJOR     28      /* IRP_MJ_MAXIMUM_FUNCTION + 1 */
#define FLTSAMPLE_FSTYPES       16

/*
 * What the filter does to a file depends on the extension of the name it is opened with:
 *   .blk   the create is refused (STATUS_ACCESS_DENIED), by the pre-operation
 *   .nowr  writes are refused
 *   .half  writes are cut to half their length
 *   .pend  writes are pended by the pre-operation and completed by a worker thread
 *   .sync  reads ask for FLT_PREOP_SYNCHRONIZE, the post-operation checks it is the same thread
 *   .safe  the post-operation of reads goes through FltDoCompletionProcessingWhenSafe
 *   .nodel the file can't be deleted or renamed (set information is refused)
 * Anything else is counted and let through.
 */

typedef struct _FLTSAMPLE_STATS
{
    ULONG Size;
    ULONG InstanceSetups;
    ULONG InstanceTeardownStarts;
    ULONG InstanceTeardownCompletes;
    ULONG QueryTeardowns;
    ULONG LiveInstances;
    ULONG ManualSetups;
    ULONG NewlyMountedSetups;
    ULONG SetupsByFsType[FLTSAMPLE_FSTYPES];
    ULONG LastTeardownReason;
    ULONG Pre[FLTSAMPLE_MAX_MAJOR];
    ULONG Post[FLTSAMPLE_MAX_MAJOR];
    ULONG Vetoed;
    ULONG Halved;
    ULONG Pended;
    ULONG PendCompleted;
    ULONG Synchronized;
    ULONG SyncSameThread;
    ULONG SyncPostNotPassive;
    ULONG SafePosts;
    ULONG SafePostsDeferred;
    ULONG SafeWorkerPassive;
    ULONG DrainingPosts;
    ULONG PostErrors;               /* post-operations seen with a failure status */
    ULONG FilterUnloads;
    LONGLONG LastCreatePre;         /* KeQueryPerformanceCounter at the last create */
    LONGLONG LastCreatePost;
    LONGLONG LastWritePre;
    LONGLONG LastWritePost;
    ULONG Contexts[8];              /* see the FLTSAMPLE_CTX_* indexes */
    ULONG OpenFiles;                /* file objects the filter has seen opened and not yet closed */
    ULONG VolumeCount;
    WCHAR LastCreate[64];           /* name of the last create the filter looked at */
    WCHAR Altitude[16];
    WCHAR InstanceName[32];

} FLTSAMPLE_STATS, *PFLTSAMPLE_STATS;

#define FLTSAMPLE_CTX_ALLOCATED         0
#define FLTSAMPLE_CTX_CLEANED           1
#define FLTSAMPLE_CTX_STREAM_HITS       2   /* a stream context was found by a later operation */
#define FLTSAMPLE_CTX_STREAM_NEW        3
#define FLTSAMPLE_CTX_HANDLE_HITS       4
#define FLTSAMPLE_CTX_HANDLE_NEW        5
#define FLTSAMPLE_CTX_INSTANCE_HITS     6
#define FLTSAMPLE_CTX_VOLUME_HITS       7

#define FLTSAMPLE_IOCTL_GET_STATS       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FLTSAMPLE_IOCTL_RESET           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FLTSAMPLE_IOCTL_ATTACH_ALL      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FLTSAMPLE_IOCTL_DETACH_ALL      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FLTSAMPLE_IOCTL_SET_PEND_DELAY  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FLTSAMPLE_IOCTL_REFUSE_DETACH   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FLTSAMPLE_IOCTL_REFUSE_UNLOAD   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FLTSAMPLE_IOCTL_SET_VETO        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FLTSAMPLE_IOCTL_USE_CONTEXTS    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)

#endif /* _FLTSAMPLE_H */
