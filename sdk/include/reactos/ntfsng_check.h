/*
 * PROJECT:     NTFS-NG file system driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     FSCTL_NG_CHECK: the consistency check (and its safe repairs) of a mounted NTFS-NG volume.
 *              Used by ntfslib's NtfsChkdsk (chkdsk, autochk).
 *
 * Include <winioctl.h> (user mode) or the NT headers (kernel) before this header: it needs CTL_CODE.
 *
 * The call is made on a volume handle (\\.\X:) of a caller with SeManageVolumePrivilege (administrators), as for
 * locking.  It runs the same check the driver runs at mount (ngfsck.c) under the volume lock, after the dirty
 * metadata was written back, so it works on the system volume and on a volume with open files.
 *   NG_CHECK_QUERY  only the state flags (no check): what autochk's dirty query asks.
 *   NG_CHECK_FIX    when the check finds no damage, leaked clusters and leaked MFT records are freed (they can
 *                   never cause a double allocation), the changes are committed and VOLUME_IS_DIRTY is cleared.
 *                   When it finds damage, nothing is repaired: the volume goes read-only and stays dirty.
 */
#ifndef _NTFSNG_CHECK_H
#define _NTFSNG_CHECK_H

#define FSCTL_NG_CHECK CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 0xA43, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define NG_CHECK_VERSION 1
#define NG_CHECK_FIX     0x1
#define NG_CHECK_QUERY   0x2

/* NG_CHECK_RESULT.Flags: the state before the check */
#define NG_CHK_READONLY       0x001   /* mounted read-only */
#define NG_CHK_DAMAGED        0x002   /* read-only because damage was found */
#define NG_CHK_DIRTY          0x004   /* VOLUME_IS_DIRTY on disk (also set while changes are in flight) */
#define NG_CHK_NEEDS_CHECK    0x008   /* dirty for a reason only a check settles: kept dirty, read-only, damaged, errors */
/* what the check did */
#define NG_CHK_RAN            0x010
#define NG_CHK_REPAIRED       0x020   /* leaks were freed */
#define NG_CHK_DIRTY_CLEARED  0x040
#define NG_CHK_NOW_READONLY   0x080   /* damage found with NG_CHECK_FIX: the volume was made read-only */
#define NG_CHK_REFUSED        0x100   /* a repair was asked for and not done */

typedef struct _NG_CHECK_REQUEST
{
    ULONG Version;                    /* NG_CHECK_VERSION */
    ULONG Flags;                      /* NG_CHECK_* */
} NG_CHECK_REQUEST, *PNG_CHECK_REQUEST;

typedef struct _NG_CHECK_RESULT
{
    ULONG Version;
    ULONG Flags;                      /* NG_CHK_* */
    ULONG ClusterSize;
    ULONG Fatal;                      /* findings that damage the volume */
    ULONG Leaks;                      /* leaked clusters runs + records (findings that are not damage) */
    ULONG LeakedRecords, FixedRecords;
    ULONG DirsSkipped, ClustersSkipped, Ms, RepairErrors, JournalReplayed;
    ULONG PassMs[3];                  /* time of the check's passes: sequence numbers, records, directory indexes */
    ULONG Reserved0;                  /* keeps the 64-bit fields at the same offsets in 32-bit and 64-bit callers */
    ULONGLONG Records, InUse, Dirs, IndexEntries, Clusters, LeakedClusters, FixedClusters, TotalClusters, FreeClusters;
    ULONGLONG ExtRecords, Reparse, SysClusters, LogClusters, IndexClusters;
    CHAR Why[128];                    /* the first finding that damages the volume */
} NG_CHECK_RESULT, *PNG_CHECK_RESULT;

#endif
