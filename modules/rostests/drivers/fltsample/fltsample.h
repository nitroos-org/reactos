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
 *   .nosec no section can be created for the file (IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION is refused)
 *   .pdpc  writes are pended by the pre-operation and completed from a DPC, at DISPATCH_LEVEL
 *   .dpc   (on fltfakefs, which completes their reads at DISPATCH_LEVEL) a read carries a context of its
 *          own from the pre- to the post-operation, which releases its last reference there
 *   .sctx  a read tries FltSetStreamContext, even on a file object the filter didn't see created
 *          (SctxReads, LastSctxStatus)
 *   .fsf   the FsFilter operations other than a section's acquire (its release, the modified page
 *          writer's and the cache flush's acquire and release) are counted (FsFilterPre/Post), and so are
 *          the modified page writer's paging writes (ModWriterWrites)
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
    ULONG CleanedByType[4];         /* instance, volume, stream, stream handle contexts freed */
    ULONG ContextMismatch;          /* handle contexts which didn't say what the file table did */
    ULONG SelfTest[16];             /* results of FLTSAMPLE_IOCTL_CONTEXT_SELFTEST */
    ULONG OpenFiles;                /* file objects the filter has seen opened and not yet closed */
    ULONG VolumeCount;
    ULONG PortConnects;
    ULONG PortDisconnects;
    ULONG PortMessages;             /* messages from the client (FilterSendMessage) */
    ULONG PortSent;                 /* messages to the client (FltSendMessage) */
    ULONG PortAsked;                /* creates the client was asked about */
    ULONG PortDenied;               /* ... and said no to */
    ULONG PortAskFailed;            /* ... and couldn't be asked, or didn't answer */
    ULONG PortLastStatus;           /* what the last FltSendMessage returned */
    WCHAR LastCreate[64];           /* name of the last create the filter looked at */
    WCHAR Altitude[16];
    WCHAR InstanceName[32];
    ULONG RvFastIoDisallowed;       /* review tests: fast I/O refused because of FLTSAMPLE_IOCTL_RV_FLAGS */
    ULONG RvParked;                 /* review tests: read post-operations parked (MORE_PROCESSING_REQUIRED) */
    ULONG RvParkDone;               /* ... and completed by the worker */
    ULONG CreatePosts;              /* post-creates of test files */
    ULONG CreatePostNotPassive;     /* ... not at PASSIVE_LEVEL */
    ULONG CreatePostOtherThread;    /* ... not in the thread of the pre-create */
    ULONG SafePagingCalls;          /* FltDoCompletionProcessingWhenSafe for paging reads of .safe files */
    ULONG SafePagingPosted;         /* ... which said it posted the paging read to a worker */
    ULONG SafePagingRefused;        /* ... which returned FALSE */
    ULONG SectionSyncPre;           /* IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION pre-operations on test files */
    ULONG SectionSyncPost;
    ULONG SectionSyncDenied;        /* ... refused (.nosec files, a section for them is created) */
    ULONG SectionSyncBadData;       /* ... whose callback data didn't say FLTFL_CALLBACK_DATA_FS_FILTER_OPERATION */
    ULONG SctxReads;                /* reads of .sctx files, opened with or without the filter seeing it */
    LONG LastSctxStatus;            /* ... what FltSetStreamContext (keep if exists) said for the last one */
    ULONG PendDpc;                  /* .pdpc writes pended */
    ULONG PendDpcCompleted;         /* ... and completed from a DPC */
    ULONG DpcReadPosts;             /* post-reads of .dpc files (fltfakefs completes them from a DPC) */
    ULONG DpcReadPostsAtDispatch;   /* ... at DISPATCH_LEVEL, where the last reference of a context was released */
    ULONG CleanupAboveApc;          /* context cleanup callbacks called above APC_LEVEL (never, WDK) */
    LONG LastSectionSyncPostStatus; /* the status the last post-operation of a section's acquire saw */
    ULONG FsFilterPre[5];           /* the other FsFilter operations on .fsf files, FLTSAMPLE_FSF_* */
    ULONG FsFilterPost[5];
    ULONG FsFilterFailed[5];        /* ... post-operations which saw a failure */
    ULONG FsFilterOtherThread;      /* ... post-operations not in the thread of their pre-operation */
    ULONG ModWriterWrites;          /* paging writes of .fsf files by the modified page writer */
    ULONG MsgNullWithLength;        /* messages whose input or output buffer was NULL with a length */

} FLTSAMPLE_STATS, *PFLTSAMPLE_STATS;

/* FsFilter "major functions" (IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION ((UCHAR)-2) ... IRP_MJ_RELEASE_FOR_CC_FLUSH ((UCHAR)-6)) */
#define FLTSAMPLE_FSF_OPS               5
#define FLTSAMPLE_FSF_INDEX(Major)      ((ULONG)(UCHAR)(0x100 - (Major)) - 2)
#define FLTSAMPLE_FSF_RELEASE_SECTION   0
#define FLTSAMPLE_FSF_ACQUIRE_MODWRITE  1
#define FLTSAMPLE_FSF_RELEASE_MODWRITE  2
#define FLTSAMPLE_FSF_ACQUIRE_CCFLUSH   3
#define FLTSAMPLE_FSF_RELEASE_CCFLUSH   4

#define FLTSAMPLE_CTX_ALLOCATED         0
#define FLTSAMPLE_CTX_CLEANED           1
#define FLTSAMPLE_CTX_STREAM_HITS       2   /* a stream context was found by a later operation */
#define FLTSAMPLE_CTX_STREAM_NEW        3
#define FLTSAMPLE_CTX_HANDLE_HITS       4
#define FLTSAMPLE_CTX_HANDLE_NEW        5
#define FLTSAMPLE_CTX_INSTANCE_HITS     6
#define FLTSAMPLE_CTX_VOLUME_HITS       7

/* The messages the client sends through the port, and the ones it gets */
typedef struct _FLTSAMPLE_MSG
{
    ULONG Code;
    ULONG Arg;
    UCHAR Data[1];

} FLTSAMPLE_MSG, *PFLTSAMPLE_MSG;

#define FLTSAMPLE_MSG_PING          1   /* the data comes back */
#define FLTSAMPLE_MSG_GET_STATS     2   /* the statistics come back */
#define FLTSAMPLE_MSG_NOTIFY        3   /* the driver sends Arg bytes of data to the client, without a reply; the status comes back */
#define FLTSAMPLE_MSG_ASK           4   /* the same with a reply, waiting Arg ms (0: forever); { status, reply length, reply } comes back */
#define FLTSAMPLE_MSG_ARM           5   /* Arg = 1: the creates of .msg files are put to the client, which can refuse them */
#define FLTSAMPLE_MSG_WHERE         6   /* Data: the addresses of the client's input and output buffers (2 ULONG64);
                                           the answer: FLTSAMPLE_WHERE_RESULT */
#define FLTSAMPLE_MSG_OVERREPORT    7   /* the filter says it returned the whole output buffer, writing nothing */

typedef struct _FLTSAMPLE_WHERE_RESULT
{
    ULONG InputIsClients;       /* the filter got the client's own buffers */
    ULONG OutputIsClients;
    ULONG ProbesOk;             /* ProbeForRead / ProbeForWrite of them worked (previous mode user) */
    ULONG PreviousModeUser;

} FLTSAMPLE_WHERE_RESULT, *PFLTSAMPLE_WHERE_RESULT;

/* The messages of the driver to the client (after the FILTER_MESSAGE_HEADER) */
#define FLTSAMPLE_KIND_CREATE       1   /* followed by the name of the file; the reply is a ULONG, not 0 for no */
#define FLTSAMPLE_KIND_NOTIFY       2
#define FLTSAMPLE_KIND_ASK          3   /* the reply is the data of the message */

typedef struct _FLTSAMPLE_ASK_RESULT
{
    LONG Status;
    ULONG ReplyLength;
    UCHAR Reply[16];

} FLTSAMPLE_ASK_RESULT, *PFLTSAMPLE_ASK_RESULT;

#define FLTSAMPLE_IOCTL_GET_STATS       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FLTSAMPLE_IOCTL_RESET           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FLTSAMPLE_IOCTL_ATTACH_ALL      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FLTSAMPLE_IOCTL_DETACH_ALL      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FLTSAMPLE_IOCTL_SET_PEND_DELAY  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FLTSAMPLE_IOCTL_REFUSE_DETACH   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FLTSAMPLE_IOCTL_REFUSE_UNLOAD   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FLTSAMPLE_IOCTL_SET_VETO        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FLTSAMPLE_IOCTL_USE_CONTEXTS    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FLTSAMPLE_IOCTL_RV_FLAGS        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FLTSAMPLE_RV_DISALLOW_FASTIO    0x1 /* every fast I/O operation on a test file: FLT_PREOP_DISALLOW_FASTIO */
#define FLTSAMPLE_RV_PARK_READ_POST     0x2 /* the post-operation of a non paging IRP read parks, a worker completes it */
#define FLTSAMPLE_RV_PARK_WRITE_POST    0x4 /* the same for writes */
#define FLTSAMPLE_RV_PARK_FASTIO_POST   0x8 /* the post-operation of a fast I/O read parks (the WDK forbids it), a worker completes it */
#define FLTSAMPLE_RV_NESTED_ATTACH      0x10 /* InstanceSetup attaches another instance of the filter to the volume first,
                                                so the instance being set up collides with it after saying yes */
#define FLTSAMPLE_IOCTL_CONTEXT_SELFTEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FLTSAMPLE_IOCTL_CLOSE_CLIENT    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS) /* FltCloseClientPort */
/* In: the volume's name (WCHAR, no NUL needed). The filter keeps a reference to that volume and its properties */
#define FLTSAMPLE_IOCTL_HOLD_VOLUME     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80C, METHOD_BUFFERED, FILE_ANY_ACCESS)
/* Out: FLTSAMPLE_HELD_VOLUME: the properties of the held volume now, then the reference goes */
#define FLTSAMPLE_IOCTL_RELEASE_VOLUME  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80D, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _FLTSAMPLE_VOLUME_PROPS
{
    LONG Status;                    /* of FltGetVolumeProperties */
    ULONG DeviceType;
    ULONG DeviceCharacteristics;
    ULONG DeviceObjectFlags;
    ULONG AlignmentRequirement;
    ULONG SectorSize;
    WCHAR DriverName[32];
    WCHAR VolumeName[48];           /* FltGetVolumeName */

} FLTSAMPLE_VOLUME_PROPS;

typedef struct _FLTSAMPLE_HELD_VOLUME
{
    ULONG Held;                     /* a volume was held */
    FLTSAMPLE_VOLUME_PROPS Before;  /* when it was taken */
    FLTSAMPLE_VOLUME_PROPS After;   /* when it was let go */

} FLTSAMPLE_HELD_VOLUME;

/* Service key value PortSecurity (REG_DWORD): the descriptor the sample gives its port */
#define PORT_SECURITY_NONE              0   /* none: the filter manager's default */
#define PORT_SECURITY_EVERYONE          1   /* a DACL that lets everybody connect */
#define PORT_SECURITY_BUILT_DEFAULT     2   /* FltBuildDefaultSecurityDescriptor(FLT_PORT_ALL_ACCESS) */

#endif /* _FLTSAMPLE_H */
