/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Loopback mini-redirector for the RDBSS tests: shared definitions
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#ifndef _RDBSSLOOP_H_
#define _RDBSSLOOP_H_

/*
 * The loopback mini-redirector registers \Device\NitroLoopRdr with RDBSS and
 * claims the UNC server name "looprdr". \\looprdr\share\... maps onto a local
 * directory chosen with IOCTL_LOOPRDR_SET_ROOT. It is a test driver only: it
 * is built with the kernel-mode tests and never installed by setup.
 */

#define LOOPRDR_DEVICE_NAME     L"\\Device\\NitroLoopRdr"
#define LOOPRDR_DOS_NAME        L"\\DosDevices\\NitroLoopRdr"
#define LOOPRDR_USER_PATH       L"\\\\.\\NitroLoopRdr"
#define LOOPRDR_SERVER          L"looprdr"
#define LOOPRDR_SHARE           L"share"
#define LOOPRDR_IPC_SHARE       L"ipc$"

/* Device-level controls, sent to the device FCB (\\.\NitroLoopRdr) */
#define LOOPRDR_CTL(n, m) CTL_CODE(FILE_DEVICE_NETWORK_FILE_SYSTEM, 0x900 + (n), (m), FILE_ANY_ACCESS)
#define IOCTL_LOOPRDR_START         LOOPRDR_CTL(0, METHOD_BUFFERED)
#define IOCTL_LOOPRDR_STOP          LOOPRDR_CTL(1, METHOD_BUFFERED)
#define IOCTL_LOOPRDR_SET_ROOT      LOOPRDR_CTL(2, METHOD_BUFFERED)
#define IOCTL_LOOPRDR_GET_COUNTERS  LOOPRDR_CTL(3, METHOD_BUFFERED)
#define IOCTL_LOOPRDR_BREAK         LOOPRDR_CTL(4, METHOD_BUFFERED)
#define IOCTL_LOOPRDR_SET_OPTIONS   LOOPRDR_CTL(5, METHOD_BUFFERED)

/* File-level controls, sent to an open file on the share: they go through
 * RDBSS's FSCTL and IOCTL low-I/O paths and the mini-redirector answers them
 * itself (an echo that reverses the input), which proves the buffer plumbing */
#define FSCTL_LOOPRDR_ECHO          LOOPRDR_CTL(0x40, METHOD_BUFFERED)
#define FSCTL_LOOPRDR_ECHO_DIRECT   LOOPRDR_CTL(0x41, METHOD_OUT_DIRECT)
#define IOCTL_LOOPRDR_FILE_ECHO     LOOPRDR_CTL(0x42, METHOD_BUFFERED)

/* IOCTL_LOOPRDR_BREAK input: a handle (of the calling process) to a file
 * opened on the share; the driver asks RDBSS to drop all caching for its
 * SRV_OPEN, as an SMB oplock or lease break would */
typedef struct _LOOPRDR_BREAK
{
    ULONGLONG FileHandle;
    ULONG NewBufferingState;
    ULONG Flags;
} LOOPRDR_BREAK, *PLOOPRDR_BREAK;

#define LOOPRDR_BREAK_WAIT          0x1 /* wait until RDBSS acknowledged */
#define LOOPRDR_BREAK_FOR_SRVOPEN   0x2 /* use RxIndicateChangeOfBufferingStateForSrvOpen */

/* IOCTL_LOOPRDR_SET_OPTIONS input */
typedef struct _LOOPRDR_OPTIONS
{
    ULONG BufferingFlags;   /* FCB_STATE_* buffering bits granted on open */
    ULONG Flags;
} LOOPRDR_OPTIONS, *PLOOPRDR_OPTIONS;

#define LOOPRDR_OPT_ASYNC_LOWIO     0x1 /* complete reads/writes from a worker */

/* IOCTL_LOOPRDR_GET_COUNTERS output: live objects as seen by the
 * mini-redirector (created minus finalized) and operation counts */
typedef struct _LOOPRDR_COUNTERS
{
    LONG SrvCalls;
    LONG NetRoots;
    LONG VNetRoots;
    LONG Fcbs;
    LONG SrvOpens;
    LONG Fobxs;
    LONG BackingHandles;
    LONG PendingAsync;
    LONG Reads;
    LONG Writes;
    LONG PagingReads;
    LONG PagingWrites;
    LONG Locks;
    LONG Unlocks;
    LONG UnlockMultiple;
    LONG Flushes;
    LONG FsCtls;
    LONG IoCtls;
    LONG ComputeBufferingState;
    LONG CompleteBufferingState;
    LONG SetEndOfFile;
    LONG SetAllocation;
    LONG QuerySd;
    LONG SetSd;
    LONG QueryEa;
    LONG SetEa;
    LONG ExtendForCache;
    LONG ExtendForNonCache;
    LONG AsyncCompletions;
    LONG Started;
    LONG PipeNetRoots;      /* ipc$ net roots RDBSS classified as pipes */
} LOOPRDR_COUNTERS, *PLOOPRDR_COUNTERS;

#endif /* _RDBSSLOOP_H_ */
