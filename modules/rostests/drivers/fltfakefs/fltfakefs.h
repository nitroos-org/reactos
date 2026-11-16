/*
 * PROJECT:     ReactOS test suite
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     A minimal file system for the tests of the filter manager, interface shared with the tests
 */

#ifndef _FLTFAKEFS_H
#define _FLTFAKEFS_H

#ifndef CTL_CODE
#error include winioctl.h or ntddk.h first
#endif

/*
 * The driver makes a disk device \Device\FltFakeDisk and registers a disk file system which mounts
 * only that disk. Its files have no data: reads return zeros, writes are swallowed. The opens, reads
 * and writes of a file whose name ends in ".dpc" are completed from a DPC, at DISPATCH_LEVEL, after
 * the dispatch routine returned STATUS_PENDING: what a file system on a real disk may do, and none
 * of this tree's do. The control device \\.\FltFakeFsCtl takes the FLTFAKEFS_IOCTL_* requests.
 */
#define FLTFAKEFS_DISK_NAME             L"\\Device\\FltFakeDisk"

typedef struct _FLTFAKEFS_STATS
{
    ULONG Size;
    ULONG Mounts;
    ULONG Creates;
    ULONG DpcCompletions;
    ULONG VolumesDeleted;
    ULONG Mounted;              /* a volume device exists now */

} FLTFAKEFS_STATS, *PFLTFAKEFS_STATS;

#define FLTFAKEFS_IOCTL_GET_STATS       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
/* The volume goes as when its medium is gone: the file system deletes its volume device, without a dismount */
#define FLTFAKEFS_IOCTL_DELETE_VOLUME   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)

#endif /* _FLTFAKEFS_H */
