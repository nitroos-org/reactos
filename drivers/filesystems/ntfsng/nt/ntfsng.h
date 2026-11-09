/*
 * PROJECT:     ReactOS NTFS-NG file system driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     NT glue around the vendored Linux fs/ntfs core
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#pragma once

#include <ntifs.h>
#include <ntdddisk.h>
#include <pseh/pseh2.h>
#include "../core/ngapi.h"

#define NDEBUG
#include <debug.h>

#define TAG_NTFSNG      'GNTN'
#define TAG_NTFSNG_CORE 'cNTN'

#define NG_WRITE_ACCESS (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | \
                         FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL)

#define NG_NODE_VCB 0x4e47
#define NG_NODE_FCB 0x4e48
/* Idle FCBs with cached data kept per volume before the oldest is purged (registry "FcbCacheMax" overrides). */
#define NG_FCB_CACHE_DEFAULT 1024

/*
 * CoreLock statistics per request type: the IRP major function of the top-level IRP, paging
 * reads and writes, and requests without an IRP (lazy writer, flusher, fast I/O).  Updated by the
 * lock holder only; read through FSCTL_NG_LOCK_STATS and printed at shutdown.
 */
#define NG_LOCK_PAGING_READ (IRP_MJ_MAXIMUM_FUNCTION + 1)
#define NG_LOCK_PAGING_WRITE (IRP_MJ_MAXIMUM_FUNCTION + 2)
#define NG_LOCK_NO_IRP (IRP_MJ_MAXIMUM_FUNCTION + 3)
#define NG_LOCK_CATEGORIES (IRP_MJ_MAXIMUM_FUNCTION + 4)
typedef struct _NG_LOCK_STAT
{
    ULONG Acquired;                 /* outermost acquisitions */
    ULONG Contended;                /* of those, the ones that had to wait */
    ULONGLONG WaitUs;               /* time spent waiting */
    ULONGLONG HeldUs;               /* time the lock was held */
} NG_LOCK_STAT;
typedef struct _NG_LOCK_STATS
{
    ULONG Version;                  /* 1 */
    ULONG Categories;               /* NG_LOCK_CATEGORIES */
    NG_LOCK_STAT Stat[NG_LOCK_CATEGORIES];
} NG_LOCK_STATS;
/* Diagnostic, debug builds only; FILE_WRITE_ACCESS needs an administrator write-opened volume handle. */
#if DBG
#define FSCTL_NG_LOCK_STATS CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 0xA41, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#endif

/* Time per stage (shim/include/ngos.h NGP_*): calls, ticks and bytes, read through FSCTL_NG_PROFILE. */
#define NG_PROFILE_STAGES 64
typedef struct _NG_PROF_STAT
{
    ULONGLONG Count;
    ULONGLONG Ticks;
    ULONGLONG Bytes;
} NG_PROF_STAT;
typedef struct _NG_PROFILE
{
    ULONG Version;                  /* 1 */
    ULONG Stages;                   /* NG_PROFILE_STAGES */
    ULONGLONG TicksPerSecond;
    NG_PROF_STAT Stage[NG_PROFILE_STAGES];
} NG_PROFILE;
#if DBG
#define FSCTL_NG_PROFILE CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 0xA42, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#endif
extern NG_PROFILE NgProfile;

#if DBG
/*
 * Time inside the core during the current CoreLock hold (zeroed when the outermost holder gets the lock, added to by
 * ngos_prof for the stages that run under it): the commit (writeback, journal write and flushes), the size change
 * (cluster allocation, run list and MFT record updates, the commit it may start) and the locked write.  At the end
 * of the hold NgNoteHold files it in a histogram by its main reason (NgPrintLockStats prints them).
 */
enum { NG_HT_COMMIT, NG_HT_SET_SIZE, NG_HT_WRITE, NG_HT_WRITEBACK, NG_HT_JNL, NG_HT_COUNT };
extern ULONGLONG NgHoldTicks[NG_HT_COUNT];
#endif

/* Volume control block: the device extension of the volume device object. */
typedef struct _NG_VCB
{
    USHORT NodeType;
    PDEVICE_OBJECT VolumeDevice;
    PDEVICE_OBJECT StorageDevice;   /* target of the mount, receives our reads */
    PVPB Vpb;
    ngc_vol *Core;
    ERESOURCE CoreLock;             /* serialises every call into the fs/ntfs core */
    /*
     * Paging writes run their data transfer without CoreLock (write.c, NgPagingWrite).  DataIoGate is held
     * shared by each such transfer, acquired under CoreLock and released before CoreLock is taken again;
     * it is taken exclusive only under CoreLock, to wait for the transfers in flight (NgDrainDataIoCallback: before
     * clusters are freed and before the device stops being this mount's).  DioActive counts the unlocked
     * writes from their start to their end under CoreLock (they pin a core node); DioIdle is set while it
     * is 0, and a dismount waits for it before it frees the core.  Both change under CoreLock only.
     */
    ERESOURCE DataIoGate;
    LONG DioActive;
    KEVENT DioIdle;
    NPAGED_LOOKASIDE_LIST DioBounce;    /* NG_DIO_BOUNCE buffers for those transfers */
    ULONG DioWrites, DioFallbacks, DioRedone, DioZeroPieces;   /* DioZeroPieces: gap zero-fill pieces written without CoreLock */
    ULONG DioReads, DioReadFallbacks;   /* paging and non-cached reads with / without the transfer outside CoreLock */
    FAST_MUTEX FcbListLock;
    LIST_ENTRY FcbList;
    /* The same FCBs by MFT record number (NgFcbBucket): every lookup by record walks one short chain, not the whole list
     * (thousands of FCBs linger after a create or delete storm).  Both are changed under FcbListLock. */
#define NG_FCB_HASH 1024
    LIST_ENTRY FcbHash[NG_FCB_HASH];
    /* FCBs without a handle whose data section still holds cached pages, oldest first (NgFcbIdle; FcbListLock).  Mm keeps
     * such a section, and with it the file object and the FCB, until the pages go: the idle list is trimmed to
     * NgGlobal.FcbCacheMax entries by flushing and purging the oldest, which lets the last close free them. */
    LIST_ENTRY IdleList;
    LONG IdleCount;
    struct _NG_FCB *VolumeFcb;
    struct ngc_volinfo Info;
    ULONG SectorSize;
    ULONG ClusterSize;              /* immutable cluster size, cached at mount; the paging path reads this,
                                       never the refreshable Info whose ngc_volinfo() zeroes it mid-update */
    UCHAR MajorVersion;             /* NTFS major version, cached at mount for the same reason */
    ULONGLONG Serial;               /* 64-bit volume serial, cached at mount (FileIdInformation) */
    BOOLEAN ReadOnly;               /* mounted read-only: policy, registry or request */
    BOOLEAN WritesLost;             /* a resize failed half way: changes made before it never reach the disk,
                                       so a flush fails (ReadOnly is set too) */
    BOOLEAN Damaged;                /* read-only because the mount-time check found damage: write opens are
                                       granted and every modification refused, so a damaged system volume boots */
    BOOLEAN WriteThrough;           /* after IRP_MJ_SHUTDOWN: every change ends with a full sync */
    BOOLEAN Removable;              /* removable media: mounted read-only */
    BOOLEAN WrongMedia;             /* a verify found another medium: every request but close fails */
    ULONGLONG BootSectors;          /* boot sector's sector count, compared again at verify */
    PFILE_OBJECT ShrinkOwner;       /* FSCTL_SHRINK_VOLUME: the handle with a prepared request (CoreLock), or NULL */
    ULONGLONG ShrinkSectors;        /* the volume size that request asked for, in sectors without the boot copy */
    ULONGLONG DeletedMftNo;         /* $Extend\$Deleted once looked up or created (CoreLock), 0 before */
    LONG OrphanSeq;                 /* makes the names of POSIX-deleted files in $Deleted unique */
    LIST_ENTRY GlobalLinks;         /* NgGlobal.VcbList */
    PKTHREAD Flusher;               /* writes back core metadata every NG_FLUSH_PERIOD_MS */
    PNOTIFY_SYNC NotifySync;        /* directory change notification (FsRtl) */
    TUNNEL Tunnel;                  /* creation times of names that just went away (FsRtl tunnel cache) */
    PFILE_OBJECT LockedBy;          /* FSCTL_LOCK_VOLUME holder: no other open while set */
    ERESOURCE CreateGate;           /* creates and cleanups shared; volume lock and dismount exclusive */
    ERESOURCE NotifyPathLock;       /* a change report to FsRtl and a rewrite of a Ccb's NotifyPath exclude each other: FsRtl
                                       reads a watcher's name (length, then bytes) several times under its own NotifySync
                                       and takes the length as stable.  Recursive; taken before FsRtl's mutex, and after
                                       FcbListLock (NgRetitleCcb), never the other way round */
    BOOLEAN RawWritten;             /* the lock holder wrote the disk directly: no core device I/O, dismounted when the lock ends */
    BOOLEAN LockEnding;             /* the holder's unlock or cleanup runs: its direct writes not yet started are refused (CoreLock) */
    LONG DroppedPagingWrites;       /* page writes of files not written: after RawWritten, or dismounted */
    LONG PagingFiles;               /* FCBs that are paging files, listed or not, until freed (FcbListLock) */
    BOOLEAN LabelStale;             /* the VPB label is empty because reading it at mount ran out of memory */
    BOOLEAN Dismounted;             /* FSCTL_DISMOUNT_VOLUME done: no core, the storage device has a new VPB */
    BOOLEAN RemovePending;          /* IRP_MN_QUERY_REMOVE_DEVICE granted: no new open until the removal or its cancel (CreateGate) */
    LIST_ENTRY DirNotifyList;
    KEVENT FlusherStop;
    KEVENT CommitKick;              /* the core asks the flusher to commit now (overlay past its threshold); auto-reset */
    ULONG Syncs;
    ULONG NonCachedViaCache;            /* non-cached writes sent through Cc: a view could not be purged */
    LONG PagingFileReads, PagingFileWrites;
    /* For a paging transfer when pool is gone: one device IRP and one partial MDL, set up when a paging
       file is first mapped, never freed (the volume holds the paging file until shutdown) */
    PIRP PagingReserveIrp;
    PMDL PagingReserveMdl;
    KEVENT PagingReserveFree;       /* signalled while the reserve is not in use; auto-reset */
    BOOLEAN PagingReserveReady;
    LONG PagingReserveUses;
    ULONG CoreDepth;                /* recursion depth of CoreLock held by its owner */
    UCHAR CoreCategory;             /* NG_LOCK_* of the outermost holder */
    LARGE_INTEGER CoreSince;        /* performance counter when the outermost holder got it */
    NG_LOCK_STATS LockStats;
} NG_VCB, *PNG_VCB;

#define NG_FLUSH_PERIOD_MS 2000
/* Over the System process base (8): 13, the critical work queue (EX_CRITICAL_QUEUE_PRIORITY_INCREMENT). */
#define NG_FLUSHER_PRIORITY_INCREMENT 5

/* One run of a paging file: VCN, LCN (negative for a hole) and length, in clusters. */
typedef struct _NG_RUN
{
    LONGLONG Vcn, Lcn, Len;
} NG_RUN, *PNG_RUN;

/* File control block: one per (MFT record, stream) open on a volume. */
typedef struct _NG_FCB
{
    FSRTL_COMMON_FCB_HEADER Header; /* must be first: FsContext */
    SECTION_OBJECT_POINTERS SectionObjectPointers;
    LONGLONG CachedEnd;             /* highest AllocationSize the header has had: bounds Mm's pages */
    LONGLONG LogicalVdl;            /* valid data length as SetFileValidData sees it (writes raise it) */
    LONGLONG TailZeroFrom;          /* every resident page of the data segment lying wholly at or past this offset is zero (MAXLONGLONG: unknown); NgSetFileSize.
                                       The part of the last page past the end can be written through a mapped view: not covered */
    ERESOURCE MainResource;
    ERESOURCE PagingIoResource;
    ERESOURCE PagingWriteLock;      /* exclusive around every paging and non-cached data write of the stream (write.c) */
    LIST_ENTRY VcbLinks;
    LIST_ENTRY HashLinks;           /* in Vcb->FcbHash[NgFcbBucket(MftNo)] while listed (VcbLinks.Flink is not NULL) */
    LIST_ENTRY IdleLinks;           /* in Vcb->IdleList while Flink is not NULL (FcbListLock) */
    PNG_VCB Vcb;
    LONG RefCount;                  /* file objects not yet closed */
    LONG OpenHandles;               /* file objects not yet cleaned up */
    LONG Opening;                   /* creates between finding this FCB and counting their handle (FcbListLock) */
    SHARE_ACCESS ShareAccess;
    ngc_node *Node;                 /* referenced core inode while handles are open; NULL when parked */
    BOOLEAN HasNode;                /* a regular FCB (not the volume) that can re-acquire its node */
    struct ngc_stat Stat;
    BOOLEAN IsVolume;
    BOOLEAN IsDirectory;
    BOOLEAN IsRoot;
    BOOLEAN Modified;               /* data changed since the last time update (cleanup/flush) */
    BOOLEAN Grown;                  /* the size grew since the core node was loaded: the last close trims the allocation ahead of it */
    BOOLEAN UserSetWriteTime;       /* LastWriteTime set through FileBasicInformation: keep it */
    BOOLEAN DeletePending;          /* unlink at the last cleanup */
    BOOLEAN Deleted;                /* unlinked: paging writes are dropped */
    BOOLEAN Orphan;                 /* POSIX delete (FileDispositionInformationEx) of the last name while other handles
                                       stay open: the name moved to $Extend\$Deleted, data and cache stay for those
                                       handles, DeletePending stays set; the last cleanup removes it there and frees the
                                       file, a mount removes what a crash left there (ngc_purge_deleted) */
    ULONGLONG DelParentMftNo;       /* the name the delete removes (from the handle that asked) */
    USHORT DelNameLength;           /* in WCHARs */
    WCHAR DelName[256];
    UNICODE_STRING DelPath;         /* full path for the change notification */
    FILE_LOCK FileLock;             /* byte-range locks (FsRtl) */
    ULONGLONG MftNo;
    BOOLEAN IsPagingFile;           /* opened with SL_OPEN_PAGING_FILE: paging I/O goes through Runs */
    KSPIN_LOCK RunLock;
    PNG_RUN Runs;                   /* cluster map of a paging file (nonpaged) */
    ULONG RunCount;
    UNICODE_STRING Stream;          /* empty for the unnamed $DATA */
    WCHAR StreamBuffer[256];
    LIST_ENTRY CcbList;             /* CCBs of the opens that succeeded, until close (FcbListLock) */
} NG_FCB, *PNG_FCB;

/* Directory snapshot storage: entries are carved from 64 KB chunks freed together. */
typedef struct _NG_ARENA
{
    struct _NG_ARENA *Next;
    ULONG Used, Size;
    ULONGLONG Data[ANYSIZE_ARRAY];
} NG_ARENA, *PNG_ARENA;

typedef struct _NG_DIRENT
{
    struct ngc_stat Stat;           /* not filled for "." and ".." */
    ULONG Tag;                      /* reparse tag, 0 if none */
    USHORT NameLength;              /* bytes */
    USHORT ShortChars;
    BOOLEAN IsDot;
    WCHAR Short[12];
    WCHAR Name[ANYSIZE_ARRAY];
} NG_DIRENT, *PNG_DIRENT;

/*
 * Context control block: one per file object.  Path, ParentMftNo, NameLength and Name change when
 * the file is renamed through any of its handles: the rename holds CreateGate and the FCB's main
 * resource exclusive and FcbListLock, so a reader holds one of them.  None of them locates the
 * file: a relative open starts at the related FCB's MFT record.
 */
typedef struct _NG_CCB
{
    UNICODE_STRING Path;            /* "\\dir\\file[:stream]" from the volume root, for names and notifications */
    ULONGLONG ParentMftNo;          /* directory holding the name this handle was opened by */
    USHORT NameLength;              /* that name as stored on disk, in WCHARs (0 for the root) */
    WCHAR Name[256];
    LIST_ENTRY FcbLinks;            /* NG_FCB.CcbList */
    BOOLEAN DeleteOnClose;
    BOOLEAN OpenedDeleteOnClose;    /* opened with FILE_DELETE_ON_CLOSE: FILE_DISPOSITION_ON_CLOSE may change DeleteOnClose */
    BOOLEAN PosixOnClose;           /* FILE_DISPOSITION_ON_CLOSE | FILE_DISPOSITION_POSIX_SEMANTICS: DeleteOnClose is a POSIX delete */
    BOOLEAN PosixDelete;            /* FileDispositionInformationEx DELETE | POSIX_SEMANTICS through this handle: at its cleanup,
                                       a delete still pending removes the name at once, whatever handles stay open */
    BOOLEAN Orphaned;               /* the name this handle was opened by was removed by a POSIX delete while it stayed open:
                                       Path names the file in $Extend\$Deleted; a rename or disposition is refused */
    BOOLEAN AppendOnly;             /* opened with FILE_APPEND_DATA but not FILE_WRITE_DATA */
    PNG_DIRENT *Entries;            /* directory snapshot taken at the first query */
    PNG_ARENA Arena;                /* storage of the snapshot's entries */
    ULONG EntryCount;
    ULONG EntryCapacity;
    ULONG NextIndex;
    UNICODE_STRING Pattern;         /* upcased search expression */
    BOOLEAN PatternIsStar;
    BOOLEAN Enumerated;
    BOOLEAN AnyReturned;
    LONG QueryBusy;                 /* a directory query of this handle is running (dirctl.c) */
    ACCESS_MASK Granted;            /* access of the handle, generic rights mapped */
    BOOLEAN ManageVolume;           /* a volume open that may lock, unlock, dismount the volume and read its bitmap (create.c) */
    BOOLEAN ManageVolumeMutate;     /* a volume open that may resize (shrink/extend) the volume: needs write access or the privilege */
    BOOLEAN CleanedUp;              /* a volume handle's cleanup ran (set under FcbListLock) */
    PVOID RetiredPaths;             /* earlier Path buffers of a renamed file (the diagnostic log may still print one) */
    UNICODE_STRING NotifyPath;      /* the name a change-notify registration watches: it shares the buffer of Path (no
                                       allocation of its own; a retired Path buffer lives until close), and a rename
                                       replaces buffer and length together under NotifyPathLock, which FsRtl's reads
                                       (NgNotify, the registration) hold too */
} NG_CCB, *PNG_CCB;

typedef struct _NG_GLOBAL
{
    PDRIVER_OBJECT DriverObject;
    PDEVICE_OBJECT ControlDevice;
    CACHE_MANAGER_CALLBACKS CacheCallbacks;
    ULONG MaxStackUsed;             /* fill-pattern measurement, whole thread stack */
    ULONG MaxStackAtIo;             /* stack depth when the core issues a device read */
    UCHAR MaxStackMajor;
    LONG FcbLive;
    ULONG FcbCacheMax;              /* idle FCBs with cached data kept per volume; MAXULONG = no trimming ("FcbCacheMax", "NoFcbTrim") */
    LONG Opens;
    ULONG PermissiveOpen;           /* diagnostic: grant write access at open, refuse the modification itself */
    ULONG ForceReadOnly;            /* "ReadOnly" DWORD in the service key: mount every volume read-only */
    ULONG Verbose;                  /* "Verbose" DWORD: request log (NGDIAG) and periodic core dumps on the debug port */
    BOOLEAN Disable8dot3;           /* NtfsDisable8dot3NameCreation == 1: no short names for new names */
    FAST_MUTEX VcbListLock;
    LIST_ENTRY VcbList;
} NG_GLOBAL;

extern NG_GLOBAL NgGlobal;

/* ntoskrnl (ReactOS): the last close of a file may leave its dirty data to the lazy writer.  Safe here: the
 * FCB (SectionObjectPointers, lazy write context) lives until the cached file object is closed, which the
 * cache map's reference delays until the map is deleted. */
NTKERNELAPI VOID NTAPI CcRosAllowLazyClose(_In_ PFILE_OBJECT FileObject);

/* ntfsng.c */
ULONG NgReadDword(PUNICODE_STRING KeyPath, PCWSTR Name);
NTSTATUS NgCleanupDismounted(PNG_VCB Vcb, PIRP Irp);
NTSTATUS NgErrnoToStatus(int Err);
VOID NgAcquireCore(PNG_VCB Vcb);
VOID NgReleaseCore(PNG_VCB Vcb);
VOID NgReleaseCoreNoTrim(PNG_VCB Vcb);
typedef struct _NG_SHARED_HOLD
{
    ULONGLONG Since;
    UCHAR Category;
    BOOLEAN Nested;                 /* inside the thread's own exclusive hold */
} NG_SHARED_HOLD;
VOID NgAcquireCoreShared(PNG_VCB Vcb, NG_SHARED_HOLD *Hold);
VOID NgReleaseCoreShared(PNG_VCB Vcb, NG_SHARED_HOLD *Hold);
VOID NgStackSample(VOID);
PNG_FCB NgAllocateFcb(PNG_VCB Vcb);
VOID NgDereferenceFcb(PNG_FCB Fcb);
VOID NgFillStat(PNG_FCB Fcb);
int NgEnsureNode(PNG_FCB Fcb);
VOID NgParkNode(PNG_FCB Fcb);

/* diag.c */
VOID NgDiagLogRequest(PDEVICE_OBJECT DeviceObject, PIRP Irp, NTSTATUS Status);

/* fsctl.c */
NTSTATUS NgFileSystemControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

/* ntfsng.c */
VOID NgPrintLockStats(PNG_VCB Vcb);

/* create.c */
NTSTATUS NgCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp);
PNG_FCB NgFindFcb(PNG_VCB Vcb, ULONGLONG MftNo);
VOID NgUnlistFcb(PNG_FCB Fcb);
BOOLEAN NgRetireStreams(PNG_VCB Vcb, ULONGLONG MftNo, PNG_FCB Self, BOOLEAN Retire);
VOID NgDeleteStreams(PNG_VCB Vcb, ULONGLONG MftNo, PNG_FCB Self);
VOID NgFcbRemoveLocked(PNG_FCB Fcb);
VOID NgFcbIdle(PNG_FCB Fcb);
BOOLEAN NgMarkDeletePending(PNG_VCB Vcb, PNG_FCB Fcb, BOOLEAN CheckStreams);
BOOLEAN NgNodeGone(ngc_node *Node);
VOID NgSetDeletePending(PNG_FCB Fcb, PNG_CCB Ccb);
NTSTATUS NgDeleteNow(PNG_FCB Fcb, BOOLEAN KeepOpen);
VOID NgPosixUnlink(PNG_FCB Fcb);

/* FileDispositionInformationEx (class 64; the class number is not in every DDK header) and its flags. */
#define NG_FILE_DISPOSITION_INFORMATION_EX  ((FILE_INFORMATION_CLASS)64)
#define NG_DISP_DELETE                      0x00000001
#define NG_DISP_POSIX_SEMANTICS             0x00000002
#define NG_DISP_FORCE_IMAGE_SECTION_CHECK   0x00000004
#define NG_DISP_ON_CLOSE                    0x00000008
#define NG_DISP_IGNORE_READONLY_ATTRIBUTE   0x00000010
#define NG_DISP_VALID_MASK                  0x0000001f
BOOLEAN NgValidName(PCUNICODE_STRING Name);
VOID NgNotify(PNG_VCB Vcb, PCUNICODE_STRING Path, ULONG Filter, ULONG Action);
VOID NgLockNotifyPath(PNG_VCB Vcb);
VOID NgUnlockNotifyPath(PNG_VCB Vcb);
VOID NgNotifyCcb(PNG_VCB Vcb, PNG_CCB Ccb, ULONG Filter, ULONG Action);
NTSTATUS NgCleanup(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NgClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);

/* read.c */
NTSTATUS NgRead(PDEVICE_OBJECT DeviceObject, PIRP Irp);

/* write.c */
NTSTATUS NgWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NgFlushBuffers(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NgShutdown(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NgSetFileSize(PNG_FCB Fcb, PFILE_OBJECT FileObject, LONGLONG NewSize);
int NgFlushVolume(PNG_VCB Vcb);
VOID NgFlushStream(PNG_FCB Fcb, PIO_STATUS_BLOCK Iosb);
NTSTATUS NgDropPagingWrite(PNG_VCB Vcb, PNG_FCB Fcb, PIRP Irp, ULONG Length);
#define NG_DIO_BOUNCE (64 * 1024)
VOID NgInitDataIo(PNG_VCB Vcb);
VOID NgDrainDataIoCallback(PVOID Context);
VOID NgWaitDataIoIdle(PNG_VCB Vcb);
int NgCommit(PNG_VCB Vcb);
VOID NgCommitKickCallback(PVOID Context);
VOID NgDataIoBegin(PNG_VCB Vcb);
VOID NgDataIoTransferred(PNG_VCB Vcb);
VOID NgDataIoDone(PNG_VCB Vcb);
BOOLEAN NgDropIfDiscardable(PNG_VCB Vcb, PIRP Irp, PNTSTATUS Status);
BOOLEAN NgPurgeFrom(PNG_FCB Fcb, LONGLONG Start);

/* create.c */
VOID NgMakeShortName(PNG_VCB Vcb, ngc_node *Parent, ngc_node *Node, PCWSTR Name, USHORT NameChars);
VOID NgTunnelAdd(PNG_VCB Vcb, ULONGLONG DirMftNo, PCWSTR Name, USHORT NameChars, LONGLONG CreationTime);
VOID NgTunnelApply(PNG_VCB Vcb, ngc_node *Parent, ngc_node *Node, PUNICODE_STRING Name);

/* fsctl.c */
BOOLEAN NgEndLock(PNG_VCB Vcb, PFILE_OBJECT FileObject, BOOLEAN Cleanup);
NTSTATUS NgDismountForRemoval(PNG_VCB Vcb, BOOLEAN Surprise);
NTSTATUS NgQueryRemove(PNG_VCB Vcb);
VOID NgCancelRemove(PNG_VCB Vcb);

/* security.c */
NTSTATUS NgQuerySecurity(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NgSetSecurity(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NgReadSecurity(PNG_VCB Vcb, ngc_node *Node, PSECURITY_DESCRIPTOR *Out);
int NgAssignNewSecurity(PNG_VCB Vcb, ngc_node *Node, PSECURITY_DESCRIPTOR ParentSd, PACCESS_STATE As, BOOLEAN IsDir,
                        NTSTATUS *Rejected);

/* access.c */
BOOLEAN NgCreateChecksAccess(PIRP Irp, PIO_STACK_LOCATION Stack);
NTSTATUS NgCheckExistingAccess(PACCESS_STATE As, PSECURITY_DESCRIPTOR Sd, PSECURITY_DESCRIPTOR ParentSd, ACCESS_MASK Implied);
NTSTATUS NgCheckAccessRight(PACCESS_STATE As, PSECURITY_DESCRIPTOR Sd, ACCESS_MASK Right);
NTSTATUS NgCheckCreateAccess(PACCESS_STATE As, PSECURITY_DESCRIPTOR ParentSd, BOOLEAN IsDir);
VOID NgGrantNewFile(PACCESS_STATE As);
NTSTATUS NgCheckDeleteEntry(PSECURITY_DESCRIPTOR Sd, PSECURITY_DESCRIPTOR DirSd);

/* pagefile.c */
NTSTATUS NgPagingFileMap(PNG_FCB Fcb);
/* NitroPager test knob (kernel decides: NitroPagerDebug 0x80 and, on free builds, /NITROPAGERDEBUG): this paging
   IRP/MDL allocation for FileObject (a paging file) is to fail */
NTKERNELAPI BOOLEAN NTAPI MmPagerInjectPagingAllocationFailure(PFILE_OBJECT FileObject);
NTSTATUS NgPagingFileIo(PNG_VCB Vcb, PNG_FCB Fcb, PIRP Irp, BOOLEAN Write, LONGLONG Offset, ULONG Length);
VOID NgAfterChange(PNG_VCB Vcb);
NTSTATUS NgCheckMedium(PNG_VCB Vcb);
VOID NgSetFlushOptional(PDEVICE_OBJECT Device);
#define NG_DEV_NOT_SENT (-2)          /* NgDevWriteDurable: no request reached the device */
int NgDevWriteDurable(PDEVICE_OBJECT Device, unsigned long long off, void *buf, unsigned int len);
int NgDevFlushDurable(PDEVICE_OBJECT Device);
VOID NgApplyModified(PNG_FCB Fcb);
NTSTATUS NgStartFlusher(PNG_VCB Vcb);
BOOLEAN NTAPI NgAcquireForLazyWrite(PVOID Context, BOOLEAN Wait);
VOID NTAPI NgReleaseFromLazyWrite(PVOID Context);
BOOLEAN NTAPI NgAcquireForReadAhead(PVOID Context, BOOLEAN Wait);
VOID NTAPI NgReleaseFromReadAhead(PVOID Context);

/* dirctl.c */
NTSTATUS NgDirectoryControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
VOID NgFreeDirSnapshot(PNG_CCB Ccb);

/* lock control */
NTSTATUS NgLockControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

/* info.c */
NTSTATUS NgQueryInformation(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NgSetInformation(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NgQueryVolumeInformation(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NgSetVolumeInformation(PDEVICE_OBJECT DeviceObject, PIRP Irp);
ULONG NgFileAttributes(PNG_FCB Fcb, const struct ngc_stat *St);
