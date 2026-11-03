/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS NTFS filesystem library
 * FILE:        include/reactos/libs/fslib/ntfslib.h
 * PURPOSE:     Public definitions for NTFS filesystem library
 */

#ifndef __NTFSLIB_H
#define __NTFSLIB_H

#include <fmifs/fmifs.h>

/*
 * NtfsChkdsk's ExitStatus besides NTSTATUS failures (chkdsk.exe turns them into its exit codes 1 and 3):
 * the check found and fixed errors (success), or found errors it did not fix (failure; the text is printed).
 * A dirty-only query (CheckOnlyIfDirty without FixErrors) returns TRUE with STATUS_DISK_CORRUPT_ERROR when
 * the volume needs a check, as autochk expects.
 */
#define NTFSCHK_STATUS_CORRECTED ((NTSTATUS)0x20000A01)
#define NTFSCHK_STATUS_ERRORS    ((NTSTATUS)0xE0000A03)

BOOLEAN
NTAPI
NtfsChkdsk(
    IN PUNICODE_STRING DriveRoot,
    IN PFMIFSCALLBACK Callback,
    IN BOOLEAN FixErrors,
    IN BOOLEAN Verbose,
    IN BOOLEAN CheckOnlyIfDirty,
    IN BOOLEAN ScanDrive,
    IN PVOID pUnknown1,
    IN PVOID pUnknown2,
    IN PVOID pUnknown3,
    IN PVOID pUnknown4,
    IN PULONG ExitStatus);

BOOLEAN
NTAPI
NtfsFormat(
    IN PUNICODE_STRING DriveRoot,
    IN PFMIFSCALLBACK Callback,
    IN BOOLEAN QuickFormat,
    IN BOOLEAN BackwardCompatible,
    IN MEDIA_TYPE MediaType,
    IN PUNICODE_STRING Label,
    IN ULONG ClusterSize);

#endif /* __NTFSLIB_H */
