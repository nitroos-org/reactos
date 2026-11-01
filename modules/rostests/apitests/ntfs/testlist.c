/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test list of the NTFS tests
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define STANDALONE
#include <apitest.h>

extern void func_NtfsAccess(void);
extern void func_NtfsAllInformation(void);
extern void func_NtfsBackup(void);
extern void func_NtfsCreate(void);
extern void func_NtfsCreateDeletePool(void);
extern void func_NtfsDelete(void);
extern void func_NtfsDeleteRunning(void);
extern void func_NtfsDirRename(void);
extern void func_NtfsHardLink(void);
extern void func_NtfsInherit(void);
extern void func_NtfsNotifyRename(void);
extern void func_NtfsNotifyScale(void);
extern void func_NtfsOpenById(void);
extern void func_NtfsPagingFile(void);
extern void func_NtfsRecordReuse(void);
extern void func_NtfsRelativeOpen(void);
extern void func_NtfsRelativeOpenJunctionAcl(void);
extern void func_NtfsRename(void);
extern void func_NtfsReparseRouting(void);
extern void func_NtfsSharing(void);
extern void func_NtfsSystemFiles(void);
extern void func_NtfsTraverse(void);
extern void func_NtfsVolumeAttributes(void);
extern void func_NtfsVolumeData(void);
extern void func_NtfsVolumeLabel(void);
extern void func_NtfsVolumeLabelReboot(void);
extern void func_NtfsVolumeLock(void);
extern void func_NtfsVolumeOpen(void);

const struct test winetest_testlist[] =
{
    { "NtfsAccess", func_NtfsAccess },
    { "NtfsAllInformation", func_NtfsAllInformation },
    { "NtfsBackup", func_NtfsBackup },
    { "NtfsCreate", func_NtfsCreate },
    { "NtfsCreateDeletePool", func_NtfsCreateDeletePool },
    { "NtfsDelete", func_NtfsDelete },
    { "NtfsDeleteRunning", func_NtfsDeleteRunning },
    { "NtfsDirRename", func_NtfsDirRename },
    { "NtfsHardLink", func_NtfsHardLink },
    { "NtfsInherit", func_NtfsInherit },
    { "NtfsNotifyRename", func_NtfsNotifyRename },
    { "NtfsNotifyScale", func_NtfsNotifyScale },
    { "NtfsOpenById", func_NtfsOpenById },
    { "NtfsPagingFile", func_NtfsPagingFile },
    { "NtfsRecordReuse", func_NtfsRecordReuse },
    { "NtfsRelativeOpen", func_NtfsRelativeOpen },
    { "NtfsRelativeOpenJunctionAcl", func_NtfsRelativeOpenJunctionAcl },
    { "NtfsRename", func_NtfsRename },
    { "NtfsReparseRouting", func_NtfsReparseRouting },
    { "NtfsSharing", func_NtfsSharing },
    { "NtfsSystemFiles", func_NtfsSystemFiles },
    { "NtfsTraverse", func_NtfsTraverse },
    { "NtfsVolumeAttributes", func_NtfsVolumeAttributes },
    { "NtfsVolumeData", func_NtfsVolumeData },
    { "NtfsVolumeLabel", func_NtfsVolumeLabel },
    { "NtfsVolumeLabelReboot", func_NtfsVolumeLabelReboot },
    { "NtfsVolumeLock", func_NtfsVolumeLock },
    { "NtfsVolumeOpen", func_NtfsVolumeOpen },
    { 0, 0 }
};
