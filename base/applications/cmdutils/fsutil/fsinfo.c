/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS FS utility tool
 * FILE:            base/applications/cmdutils/fsutil/fsinfo.c
 * PURPOSE:         FSutil file systems information
 * PROGRAMMERS:     Pierre Schweitzer <pierre@reactos.org>
 */

#include "fsutil.h"

#ifndef FILE_RETURNS_CLEANUP_RESULT_INFO
#define FILE_RETURNS_CLEANUP_RESULT_INFO    0x00000200
#endif
#ifndef FILE_SUPPORTS_POSIX_UNLINK_RENAME
#define FILE_SUPPORTS_POSIX_UNLINK_RENAME   0x00000400
#endif

/* Windows 10 layout of the extended NTFS volume data; older drivers return less */
typedef struct
{
    NTFS_VOLUME_DATA_BUFFER Base;
    ULONG ByteCount;
    USHORT MajorVersion;
    USHORT MinorVersion;
    ULONG BytesPerPhysicalSector;
    USHORT LfsMajorVersion;
    USHORT LfsMinorVersion;
    ULONG MaxDeviceTrimExtentCount;
    ULONG MaxDeviceTrimByteCount;
    ULONG MaxVolumeTrimExtentCount;
    ULONG MaxVolumeTrimByteCount;
} NTFS_VOLUME_DATA_WIN10;

int
FsInfoDrivesMain(int argc, const TCHAR *argv[])
{
    UINT i;
    DWORD Drives;

    if (argc > 1)
    {
        _tprintf(_T("Usage : fsutil fsInfo drives\n"));
        return 1;
    }

    /* Get the drives bitmap */
    Drives = GetLogicalDrives();
    if (Drives == 0)
    {
        PrintErrorMessage(GetLastError());
        return 1;
    }

    /* And output any found drive */
    _tprintf(_T("\nDrives: "));
    for (i = 0; i < 26; i++)
    {
        if (Drives & (1 << i))
        {
            _tprintf(_T("%c:\\ "), _T('A') + i);
        }
    }
    _tprintf(_T("\n"));

    return 0;
}

int
FsInfoDriveTypeMain(int argc, const TCHAR *argv[])
{
    UINT Type;
    const TCHAR * Desc;

    if (argc != 2)
    {
        _tprintf(_T("Usage : fsutil fsInfo driveType <volume pathname>\n"));
        _tprintf(_T("   Eg : fsutil fsInfo driveType C:\n"));
        return (argc < 2) ? 0 : 1;
    }

    /* Get its drive type and make it readable. Only "Fixed Drive" and "No such Root
     * Directory" were seen on the oracle, the other texts are TODO(oracle) (Windows docs) */
    Type = GetDriveType(argv[1]);
    switch (Type)
    {
        case DRIVE_NO_ROOT_DIR:
            Desc = _T("No such Root Directory");
            break;

        case DRIVE_REMOVABLE:
            Desc = _T("Removable Drive");
            break;

        case DRIVE_FIXED:
            Desc = _T("Fixed Drive");
            break;

        case DRIVE_REMOTE:
            Desc = _T("Remote/Network Drive");
            break;

        case DRIVE_CDROM:
            Desc = _T("CD-ROM Drive");
            break;

        case DRIVE_RAMDISK:
            Desc = _T("Ram Disk");
            break;

        case DRIVE_UNKNOWN:
        default:
            Desc = _T("Unknown Drive");
            break;
    }

    _tprintf(_T("%s - %s\n"), argv[1], Desc);

    return 0;
}

int
FsInfoVolumeInfoMain(int argc, const TCHAR *argv[])
{
    DWORD Serial, MaxComponentLen, Flags;
    TCHAR VolumeName[MAX_PATH + 1], FileSystem[MAX_PATH + 1];
    TCHAR Path[MAX_PATH + 2];

#define HANDLE_FLAG(Flag, Desc) \
    if (Flags & (Flag))         \
        _tprintf(_T(Desc "\n"))

    if (argc != 2)
    {
        _tprintf(_T("Usage : fsutil fsInfo volumeInfo <volume pathname>\n"));
        _tprintf(_T("   Eg : fsutil fsInfo volumeInfo C:\n"));
        return (argc < 2) ? 0 : 1;
    }

    /* Windows asks for the root of "<argument>\", so "C:" works, "C:\" does not */
    if (argv[1][0] == 0)
    {
        PrintErrorMessage(ERROR_INVALID_PARAMETER);
        return 1;
    }

    if (argv[1][_tcslen(argv[1]) - 1] == _T('\\'))
    {
        /* "<argument>\" would end in two separators */
        PrintErrorMessage(ERROR_PATH_NOT_FOUND);
        return 1;
    }

    _sntprintf(Path, RTL_NUMBER_OF(Path), _T("%s\\"), argv[1]);
    Path[RTL_NUMBER_OF(Path) - 1] = 0;

    /* Gather information */
    if (!GetVolumeInformation(Path, VolumeName, MAX_PATH + 1, &Serial,
                              &MaxComponentLen, &Flags, FileSystem, MAX_PATH + 1))
    {
        PrintErrorMessage(GetLastError());
        return 1;
    }

    /* Display general information */
    _tprintf(_T("Volume Name : %s\n"), VolumeName);
    _tprintf(_T("Volume Serial Number : 0x%x\n"), Serial);
    _tprintf(_T("Max Component Length : %u\n"), MaxComponentLen);
    _tprintf(_T("File System Name : %s\n"), FileSystem);

    /* "Is Read Only" is TODO(oracle) (the oracle volume is read-write); thin provisioning
     * cannot be queried here, so no volume is reported as thin */
    if (Flags & FILE_READ_ONLY_VOLUME)
        _tprintf(_T("Is Read Only\n"));
    else
        _tprintf(_T("Is ReadWrite\n"));
    _tprintf(_T("Not Thinly-Provisioned\n"));

    /* Display specific flags */
    HANDLE_FLAG(FILE_CASE_SENSITIVE_SEARCH, "Supports Case-sensitive filenames");
    HANDLE_FLAG(FILE_CASE_PRESERVED_NAMES, "Preserves Case of filenames");
    HANDLE_FLAG(FILE_UNICODE_ON_DISK, "Supports Unicode in filenames");
    HANDLE_FLAG(FILE_PERSISTENT_ACLS, "Preserves & Enforces ACL's");
    HANDLE_FLAG(FILE_FILE_COMPRESSION, "Supports file-based Compression");
    HANDLE_FLAG(FILE_VOLUME_QUOTAS, "Supports Disk Quotas");
    HANDLE_FLAG(FILE_SUPPORTS_SPARSE_FILES, "Supports Sparse files");
    HANDLE_FLAG(FILE_SUPPORTS_REPARSE_POINTS, "Supports Reparse Points");
    HANDLE_FLAG(FILE_RETURNS_CLEANUP_RESULT_INFO, "Returns Handle Close Result Information");
    HANDLE_FLAG(FILE_SUPPORTS_POSIX_UNLINK_RENAME, "Supports POSIX-style Unlink and Rename");
    HANDLE_FLAG(FILE_SUPPORTS_OBJECT_IDS, "Supports Object Identifiers");
    HANDLE_FLAG(FILE_SUPPORTS_ENCRYPTION, "Supports Encrypted File System");
    HANDLE_FLAG(FILE_NAMED_STREAMS, "Supports Named Streams");
    HANDLE_FLAG(FILE_SUPPORTS_TRANSACTIONS, "Supports Transactions");
    HANDLE_FLAG(FILE_SUPPORTS_HARD_LINKS, "Supports Hard Links");
    HANDLE_FLAG(FILE_SUPPORTS_EXTENDED_ATTRIBUTES, "Supports Extended Attributes");
    HANDLE_FLAG(FILE_SUPPORTS_OPEN_BY_FILE_ID, "Supports Open By FileID");
    HANDLE_FLAG(FILE_SUPPORTS_USN_JOURNAL, "Supports USN Journal");

#undef HANDLE_FLAG

    return 0;
}

/* Label padded to the value column, then the value */
#define NTFS_LABEL(Label) _tprintf(_T("%-35s"), _T(Label))

static void
PrintCount(const TCHAR * Label, ULONGLONG Count, ULONGLONG Bytes)
{
    TCHAR Number[40], Size[40];

    FormatNumber(Count, Number);
    FormatSize(Bytes, 1, 4, Size);
    _tprintf(_T("%-35s%11s  (%s)\n"), Label, Number, Size);
}

int
FsInfoNtfsInfoMain(int argc, const TCHAR *argv[])
{
    HANDLE Volume;
    DWORD BytesRead;
    NTFS_VOLUME_DATA_WIN10 Data;
    TCHAR Size[40];
    ULONGLONG BytesPerCluster, Zone;
    ULONG Physical, TrimExtDev, TrimBytesDev, TrimExtVol, TrimBytesVol;
    USHORT LfsMajor, LfsMinor;

    if (argc != 2)
    {
        _tprintf(_T("Usage : fsutil fsinfo ntfsInfo <volume pathname>\n"));
        _tprintf(_T("   Eg : fsutil fsinfo ntfsInfo C:\n"));
        return (argc < 2) ? 0 : 1;
    }

    /* Get a handle for the volume */
    Volume = OpenVolumeArg(argv[1], TRUE, GENERIC_READ, NOTE_LOCAL_NTFS_VOLUME, NULL);
    if (Volume == INVALID_HANDLE_VALUE)
    {
        return 1;
    }

    /* And query the NTFS data */
    ZeroMemory(&Data, sizeof(Data));
    if (DeviceIoControl(Volume, FSCTL_GET_NTFS_VOLUME_DATA, NULL, 0, &Data,
                        sizeof(Data), &BytesRead, NULL) == FALSE)
    {
        PrintErrorMessage(GetLastError());
        CloseHandle(Volume);
        return 1;
    }

    /* We no longer need the volume */
    CloseHandle(Volume);

    /* Fields the driver does not report: the sector size, NTFS 3.x implies LFS 2.0, no trim data */
    BytesPerCluster = Data.Base.BytesPerCluster;
    Physical = Data.Base.BytesPerSector;
    LfsMajor = 2;
    LfsMinor = 0;
    TrimExtDev = TrimBytesDev = TrimExtVol = TrimBytesVol = 0;
    if (BytesRead >= FIELD_OFFSET(NTFS_VOLUME_DATA_WIN10, BytesPerPhysicalSector) + sizeof(ULONG) &&
        Data.ByteCount >= FIELD_OFFSET(NTFS_VOLUME_DATA_WIN10, BytesPerPhysicalSector) - sizeof(NTFS_VOLUME_DATA_BUFFER) + sizeof(ULONG))
    {
        Physical = Data.BytesPerPhysicalSector;
    }
    if (BytesRead >= sizeof(NTFS_VOLUME_DATA_WIN10))
    {
        LfsMajor = Data.LfsMajorVersion;
        LfsMinor = Data.LfsMinorVersion;
        TrimExtDev = Data.MaxDeviceTrimExtentCount;
        TrimBytesDev = Data.MaxDeviceTrimByteCount;
        TrimExtVol = Data.MaxVolumeTrimExtentCount;
        TrimBytesVol = Data.MaxVolumeTrimByteCount;
    }

    /* Dump data */
    NTFS_LABEL("NTFS Volume Serial Number :");
    _tprintf(_T("0x%016I64x\n"), Data.Base.VolumeSerialNumber.QuadPart);
    if (BytesRead > sizeof(NTFS_VOLUME_DATA_BUFFER))
    {
        NTFS_LABEL("NTFS Version      :");
        _tprintf(_T("%u.%u\n"), Data.MajorVersion, Data.MinorVersion);
        NTFS_LABEL("LFS Version       :");
        _tprintf(_T("%u.%u\n"), LfsMajor, LfsMinor);
    }
    PrintCount(_T("Total Sectors     :"), Data.Base.NumberSectors.QuadPart, Data.Base.NumberSectors.QuadPart * Data.Base.BytesPerSector);
    PrintCount(_T("Total Clusters    :"), Data.Base.TotalClusters.QuadPart, Data.Base.TotalClusters.QuadPart * BytesPerCluster);
    PrintCount(_T("Free Clusters     :"), Data.Base.FreeClusters.QuadPart, Data.Base.FreeClusters.QuadPart * BytesPerCluster);
    PrintCount(_T("Total Reserved Clusters :"), Data.Base.TotalReserved.QuadPart, Data.Base.TotalReserved.QuadPart * BytesPerCluster);
    /* The driver has no storage reserve */
    PrintCount(_T("Reserved For Storage Reserve :"), 0, 0);
    NTFS_LABEL("Bytes Per Sector  :");
    _tprintf(_T("%lu\n"), Data.Base.BytesPerSector);
    NTFS_LABEL("Bytes Per Physical Sector :");
    _tprintf(_T("%lu\n"), Physical);
    NTFS_LABEL("Bytes Per Cluster :");
    _tprintf(_T("%lu\n"), Data.Base.BytesPerCluster);
    NTFS_LABEL("Bytes Per FileRecord Segment    :");
    _tprintf(_T("%lu\n"), Data.Base.BytesPerFileRecordSegment);
    NTFS_LABEL("Clusters Per FileRecord Segment :");
    _tprintf(_T("%lu\n"), Data.Base.ClustersPerFileRecordSegment);
    FormatSize(Data.Base.MftValidDataLength.QuadPart, 2, 0, Size);
    NTFS_LABEL("Mft Valid Data Length :");
    _tprintf(_T("%s\n"), Size);
    NTFS_LABEL("Mft Start Lcn  :");
    _tprintf(_T("0x%016I64x\n"), Data.Base.MftStartLcn.QuadPart);
    NTFS_LABEL("Mft2 Start Lcn :");
    _tprintf(_T("0x%016I64x\n"), Data.Base.Mft2StartLcn.QuadPart);
    NTFS_LABEL("Mft Zone Start :");
    _tprintf(_T("0x%016I64x\n"), Data.Base.MftZoneStart.QuadPart);
    NTFS_LABEL("Mft Zone End   :");
    _tprintf(_T("0x%016I64x\n"), Data.Base.MftZoneEnd.QuadPart);
    Zone = (Data.Base.MftZoneEnd.QuadPart - Data.Base.MftZoneStart.QuadPart) * BytesPerCluster;
    FormatSize(Zone, 2, 0, Size);
    NTFS_LABEL("MFT Zone Size  :");
    _tprintf(_T("%s\n"), Size);
    NTFS_LABEL("Max Device Trim Extent Count :");
    _tprintf(_T("%lu\n"), TrimExtDev);
    NTFS_LABEL("Max Device Trim Byte Count :");
    _tprintf(_T("0x%lx\n"), TrimBytesDev);
    NTFS_LABEL("Max Volume Trim Extent Count :");
    _tprintf(_T("%lu\n"), TrimExtVol);
    NTFS_LABEL("Max Volume Trim Byte Count :");
    _tprintf(_T("0x%lx\n"), TrimBytesVol);
    /* Windows also prints "Resource Manager Identifier" (TxF); this NTFS driver has none. */

    return 0;
}

#define DUMP_VALUE(stats, col, value) printf("%-*s%lu\n", col, #value " :", (unsigned long)stats->value)

static void
DumpBase(PFILESYSTEM_STATISTICS Base, TCHAR * Name)
{
    /* Print FS name */
    _tprintf(_T("%-23s%s\n\n"), _T("File System Type :"), Name);

    /* And then, dump any base stat */
    DUMP_VALUE(Base, 23, UserFileReads);
    DUMP_VALUE(Base, 23, UserFileReadBytes);
    DUMP_VALUE(Base, 23, UserDiskReads);
    DUMP_VALUE(Base, 23, UserFileWrites);
    DUMP_VALUE(Base, 23, UserFileWriteBytes);
    DUMP_VALUE(Base, 23, UserDiskWrites);
    DUMP_VALUE(Base, 23, MetaDataReads);
    DUMP_VALUE(Base, 23, MetaDataReadBytes);
    DUMP_VALUE(Base, 23, MetaDataDiskReads);
    DUMP_VALUE(Base, 23, MetaDataWrites);
    DUMP_VALUE(Base, 23, MetaDataWriteBytes);
    DUMP_VALUE(Base, 23, MetaDataDiskWrites);

    _tprintf(_T("\n"));
}

/* The FAT and EXFAT value columns were not seen on the oracle (TODO(oracle), same as NTFS) */
static void
DumpExFat(PVOID Statistics, PVOID Specific)
{
    PEXFAT_STATISTICS ExFat;
    PFILESYSTEM_STATISTICS Base;

    Base = Statistics;
    ExFat = Specific;

    /* First, display the generic stats */
    DumpBase(Base, _T("EXFAT"));

    /* Then, display the EXFAT specific ones */
    DUMP_VALUE(ExFat, 32, CreateHits);
    DUMP_VALUE(ExFat, 32, SuccessfulCreates);
    DUMP_VALUE(ExFat, 32, FailedCreates);
    DUMP_VALUE(ExFat, 32, NonCachedReads);
    DUMP_VALUE(ExFat, 32, NonCachedReadBytes);
    DUMP_VALUE(ExFat, 32, NonCachedWrites);
    DUMP_VALUE(ExFat, 32, NonCachedWriteBytes);
    DUMP_VALUE(ExFat, 32, NonCachedDiskReads);
    DUMP_VALUE(ExFat, 32, NonCachedDiskWrites);
}

static void
DumpFat(PVOID Statistics, PVOID Specific)
{
    PFAT_STATISTICS Fat;
    PFILESYSTEM_STATISTICS Base;

    Base = Statistics;
    Fat = Specific;

    /* First, display the generic stats */
    DumpBase(Base, _T("FAT"));

    /* Then, display the FAT specific ones */
    DUMP_VALUE(Fat, 32, CreateHits);
    DUMP_VALUE(Fat, 32, SuccessfulCreates);
    DUMP_VALUE(Fat, 32, FailedCreates);
    DUMP_VALUE(Fat, 32, NonCachedReads);
    DUMP_VALUE(Fat, 32, NonCachedReadBytes);
    DUMP_VALUE(Fat, 32, NonCachedWrites);
    DUMP_VALUE(Fat, 32, NonCachedWriteBytes);
    DUMP_VALUE(Fat, 32, NonCachedDiskReads);
    DUMP_VALUE(Fat, 32, NonCachedDiskWrites);
}

/* Windows prints a few more NTFS counters (LogFileFull, trim statistics...) after these;
 * the NTFS_STATISTICS structure of this tree does not carry them. */
static void
DumpNtfs(PVOID Statistics, PVOID Specific)
{
    PNTFS_STATISTICS Ntfs;
    PFILESYSTEM_STATISTICS Base;

    Base = Statistics;
    Ntfs = Specific;

    /* First, display the generic stats */
    DumpBase(Base, _T("NTFS"));

    /* Then, display the NTFS specific ones */
    DUMP_VALUE(Ntfs, 32, MftReads);
    DUMP_VALUE(Ntfs, 32, MftReadBytes);
    DUMP_VALUE(Ntfs, 32, MftWrites);
    DUMP_VALUE(Ntfs, 32, MftWriteBytes);
    DUMP_VALUE(Ntfs, 32, Mft2Writes);
    DUMP_VALUE(Ntfs, 32, Mft2WriteBytes);
    DUMP_VALUE(Ntfs, 32, RootIndexReads);
    DUMP_VALUE(Ntfs, 32, RootIndexReadBytes);
    DUMP_VALUE(Ntfs, 32, RootIndexWrites);
    DUMP_VALUE(Ntfs, 32, RootIndexWriteBytes);
    DUMP_VALUE(Ntfs, 32, BitmapReads);
    DUMP_VALUE(Ntfs, 32, BitmapReadBytes);
    DUMP_VALUE(Ntfs, 32, BitmapWrites);
    DUMP_VALUE(Ntfs, 32, BitmapWriteBytes);
    DUMP_VALUE(Ntfs, 32, MftBitmapReads);
    DUMP_VALUE(Ntfs, 32, MftBitmapReadBytes);
    DUMP_VALUE(Ntfs, 32, MftBitmapWrites);
    DUMP_VALUE(Ntfs, 32, MftBitmapWriteBytes);
    DUMP_VALUE(Ntfs, 32, UserIndexReads);
    DUMP_VALUE(Ntfs, 32, UserIndexReadBytes);
    DUMP_VALUE(Ntfs, 32, UserIndexWrites);
    DUMP_VALUE(Ntfs, 32, UserIndexWriteBytes);
    DUMP_VALUE(Ntfs, 32, LogFileReads);
    DUMP_VALUE(Ntfs, 32, LogFileReadBytes);
    DUMP_VALUE(Ntfs, 32, LogFileWrites);
    DUMP_VALUE(Ntfs, 32, LogFileWriteBytes);
}

#define GET_NEXT(stats, length, iter, type) (type)((ULONG_PTR)stats + (length * iter))
#define SUM_VALUE(stats, new, value) stats->value += new->value

static inline int
ValidateSizes(ULONG Length, DWORD ProcCount, DWORD BytesRead, DWORD SpecificSize)
{
    /* Check whether we could read our base length for every processor */
    if (Length * ProcCount > BytesRead)
    {
        _tprintf(_T("Only performed a partial read: %lu (expected: %lu)\n"), BytesRead, Length * ProcCount);
        return 1;
    }

    /* Check whether this covers a specific entry and a generic entry for every processor */
    if ((sizeof(FILESYSTEM_STATISTICS) + SpecificSize) * ProcCount > BytesRead)
    {
        _tprintf(_T("Only performed a partial read: %lu (expected: %Iu)\n"), BytesRead, (sizeof(FILESYSTEM_STATISTICS) + SpecificSize));
        return 1;
    }

    return 0;
}

static inline void
SumBase(PFILESYSTEM_STATISTICS Base, PFILESYSTEM_STATISTICS NextBase)
{
    /* Sum any entry in the generic structures */
    SUM_VALUE(Base, NextBase, UserFileReads);
    SUM_VALUE(Base, NextBase, UserFileReadBytes);
    SUM_VALUE(Base, NextBase, UserDiskReads);
    SUM_VALUE(Base, NextBase, UserFileWrites);
    SUM_VALUE(Base, NextBase, UserFileWriteBytes);
    SUM_VALUE(Base, NextBase, UserDiskWrites);
    SUM_VALUE(Base, NextBase, MetaDataReads);
    SUM_VALUE(Base, NextBase, MetaDataReadBytes);
    SUM_VALUE(Base, NextBase, MetaDataDiskReads);
    SUM_VALUE(Base, NextBase, MetaDataWrites);
    SUM_VALUE(Base, NextBase, MetaDataWriteBytes);
    SUM_VALUE(Base, NextBase, MetaDataDiskWrites);
}

static int
SumExFat(PVOID Statistics, PVOID Specific, ULONG Length, DWORD ProcCount, DWORD BytesRead)
{
    DWORD i;
    PEXFAT_STATISTICS ExFat;
    PFILESYSTEM_STATISTICS Base;

    /* First, validate we won't read beyond allocation */
    if (ValidateSizes(Length, ProcCount, BytesRead, sizeof(EXFAT_STATISTICS)))
    {
        return 1;
    }

    Base = Statistics;
    ExFat = Specific;

    /* And for every processor, sum every relevant value in first entry */
    for (i = 1; i < ProcCount; ++i)
    {
        PEXFAT_STATISTICS NextExFat;
        PFILESYSTEM_STATISTICS NextBase;

        NextBase = GET_NEXT(Base, Length, i, PFILESYSTEM_STATISTICS);
        NextExFat = GET_NEXT(ExFat, Length, i, PEXFAT_STATISTICS);

        /* Generic first */
        SumBase(Base, NextBase);
        /* Specific then */
        SUM_VALUE(ExFat, NextExFat, CreateHits);
        SUM_VALUE(ExFat, NextExFat, SuccessfulCreates);
        SUM_VALUE(ExFat, NextExFat, FailedCreates);
        SUM_VALUE(ExFat, NextExFat, NonCachedReads);
        SUM_VALUE(ExFat, NextExFat, NonCachedReadBytes);
        SUM_VALUE(ExFat, NextExFat, NonCachedWrites);
        SUM_VALUE(ExFat, NextExFat, NonCachedWriteBytes);
        SUM_VALUE(ExFat, NextExFat, NonCachedDiskReads);
        SUM_VALUE(ExFat, NextExFat, NonCachedDiskWrites);
    }

    return 0;
}

static int
SumFat(PVOID Statistics, PVOID Specific, ULONG Length, DWORD ProcCount, DWORD BytesRead)
{
    DWORD i;
    PFAT_STATISTICS Fat;
    PFILESYSTEM_STATISTICS Base;

    /* First, validate we won't read beyond allocation */
    if (ValidateSizes(Length, ProcCount, BytesRead, sizeof(FAT_STATISTICS)))
    {
        return 1;
    }

    Base = Statistics;
    Fat = Specific;

    /* And for every processor, sum every relevant value in first entry */
    for (i = 1; i < ProcCount; ++i)
    {
        PFAT_STATISTICS NextFat;
        PFILESYSTEM_STATISTICS NextBase;

        NextBase = GET_NEXT(Base, Length, i, PFILESYSTEM_STATISTICS);
        NextFat = GET_NEXT(Fat, Length, i, PFAT_STATISTICS);

        /* Generic first */
        SumBase(Base, NextBase);
        /* Specific then */
        SUM_VALUE(Fat, NextFat, CreateHits);
        SUM_VALUE(Fat, NextFat, SuccessfulCreates);
        SUM_VALUE(Fat, NextFat, FailedCreates);
        SUM_VALUE(Fat, NextFat, NonCachedReads);
        SUM_VALUE(Fat, NextFat, NonCachedReadBytes);
        SUM_VALUE(Fat, NextFat, NonCachedWrites);
        SUM_VALUE(Fat, NextFat, NonCachedWriteBytes);
        SUM_VALUE(Fat, NextFat, NonCachedDiskReads);
        SUM_VALUE(Fat, NextFat, NonCachedDiskWrites);
    }

    return 0;
}

static int
SumNtfs(PVOID Statistics, PVOID Specific, ULONG Length, DWORD ProcCount, DWORD BytesRead)
{
    DWORD i;
    PNTFS_STATISTICS Ntfs;
    PFILESYSTEM_STATISTICS Base;

    /* First, validate we won't read beyond allocation */
    if (ValidateSizes(Length, ProcCount, BytesRead, sizeof(NTFS_STATISTICS)))
    {
        return 1;
    }

    Base = Statistics;
    Ntfs = Specific;

    /* And for every processor, sum every relevant value in first entry */
    for (i = 1; i < ProcCount; ++i)
    {
        PNTFS_STATISTICS NextNtfs;
        PFILESYSTEM_STATISTICS NextBase;

        NextBase = GET_NEXT(Base, Length, i, PFILESYSTEM_STATISTICS);
        NextNtfs = GET_NEXT(Ntfs, Length, i, PNTFS_STATISTICS);

        /* Generic first */
        SumBase(Base, NextBase);
        /* Specific then */
        SUM_VALUE(Ntfs, NextNtfs, MftReads);
        SUM_VALUE(Ntfs, NextNtfs, MftReadBytes);
        SUM_VALUE(Ntfs, NextNtfs, MftWrites);
        SUM_VALUE(Ntfs, NextNtfs, MftWriteBytes);
        SUM_VALUE(Ntfs, NextNtfs, Mft2Writes);
        SUM_VALUE(Ntfs, NextNtfs, Mft2WriteBytes);
        SUM_VALUE(Ntfs, NextNtfs, RootIndexReads);
        SUM_VALUE(Ntfs, NextNtfs, RootIndexReadBytes);
        SUM_VALUE(Ntfs, NextNtfs, RootIndexWrites);
        SUM_VALUE(Ntfs, NextNtfs, RootIndexWriteBytes);
        SUM_VALUE(Ntfs, NextNtfs, BitmapReads);
        SUM_VALUE(Ntfs, NextNtfs, BitmapReadBytes);
        SUM_VALUE(Ntfs, NextNtfs, BitmapWrites);
        SUM_VALUE(Ntfs, NextNtfs, BitmapWriteBytes);
        SUM_VALUE(Ntfs, NextNtfs, MftBitmapReads);
        SUM_VALUE(Ntfs, NextNtfs, MftBitmapReadBytes);
        SUM_VALUE(Ntfs, NextNtfs, MftBitmapWrites);
        SUM_VALUE(Ntfs, NextNtfs, MftBitmapWriteBytes);
        SUM_VALUE(Ntfs, NextNtfs, UserIndexReads);
        SUM_VALUE(Ntfs, NextNtfs, UserIndexReadBytes);
        SUM_VALUE(Ntfs, NextNtfs, UserIndexWrites);
        SUM_VALUE(Ntfs, NextNtfs, UserIndexWriteBytes);
        SUM_VALUE(Ntfs, NextNtfs, LogFileReads);
        SUM_VALUE(Ntfs, NextNtfs, LogFileReadBytes);
        SUM_VALUE(Ntfs, NextNtfs, LogFileWrites);
        SUM_VALUE(Ntfs, NextNtfs, LogFileWriteBytes);
    }

    return 0;
}

int
FsInfoStatisticsMain(int argc, const TCHAR *argv[])
{
    HANDLE Volume;
    SYSTEM_INFO SystemInfo;
    FILESYSTEM_STATISTICS Buffer;
    PFILESYSTEM_STATISTICS Statistics;
    DWORD BytesRead, Length, ProcCount;
    /* +1 because 0 isn't assigned to a filesystem */
    void (*DumpFct[FILESYSTEM_STATISTICS_TYPE_EXFAT + 1])(PVOID, PVOID) = { NULL, DumpNtfs, DumpFat, DumpExFat };
    int (*SumFct[FILESYSTEM_STATISTICS_TYPE_EXFAT + 1])(PVOID, PVOID, ULONG, DWORD, DWORD) = { NULL, SumNtfs, SumFat, SumExFat };

    if (argc != 2)
    {
        _tprintf(_T("Usage : fsutil fsInfo statistics <volume pathname>\n"));
        _tprintf(_T("   Eg : fsutil fsInfo statistics C:\n"));
        return (argc < 2) ? 0 : 1;
    }

    /* Get a handle for the volume */
    Volume = OpenVolumeArg(argv[1], FALSE, GENERIC_READ, NOTE_LOCAL_ANY_FS, NULL);
    if (Volume == INVALID_HANDLE_VALUE)
    {
        return 1;
    }

    /* And query the statistics status - this call is expected to fail */
    Statistics = &Buffer;
    Length = sizeof(Buffer);
    /* Assume we have a single proc for now */
    ProcCount = 1;
    if (DeviceIoControl(Volume, FSCTL_FILESYSTEM_GET_STATISTICS, NULL, 0, Statistics,
                        Length, &BytesRead, NULL) == FALSE)
    {
        DWORD Error;

        /* Check we failed because we provided a too small buffer */
        Error = GetLastError();
        if (Error == ERROR_MORE_DATA)
        {
            /* Get proc count */
            GetSystemInfo(&SystemInfo);
            ProcCount = SystemInfo.dwNumberOfProcessors;
            /* Get the maximum size to allocate: it's the total size (generic + specific) for every proc */
            Length = Statistics->SizeOfCompleteStructure * ProcCount;

            Statistics = LocalAlloc(LPTR, Length);
            if (Statistics == NULL)
            {
                _tprintf(_T("Failed to allocate memory!\n"));
                CloseHandle(Volume);
                return 1;
            }

            /* Reissue the FSCTL, it's supposed to succeed now! */
            if (DeviceIoControl(Volume, FSCTL_FILESYSTEM_GET_STATISTICS, NULL, 0, Statistics,
                                Length, &BytesRead, NULL) == FALSE)
            {
                PrintErrorMessage(GetLastError());
                LocalFree(Statistics);
                CloseHandle(Volume);
                return 1;
            }
        }
        else
        {
            PrintErrorMessage(Error);
            CloseHandle(Volume);
            return 1;
        }
    }

    /* No need to deal with the volume any longer */
    CloseHandle(Volume);

    /* We only support FAT, EXFAT and NTFS for now */
    if (Statistics->FileSystemType > FILESYSTEM_STATISTICS_TYPE_EXFAT || Statistics->FileSystemType < FILESYSTEM_STATISTICS_TYPE_NTFS)
    {
        _tprintf(_T("Unrecognized file system type: %d\n"), Statistics->FileSystemType);
        if (Statistics != &Buffer)
        {
            LocalFree(Statistics);
        }

        return 1;
    }

    /* Sum all the statistics (both generic and specific) from all the processors in the first entry */
    if (SumFct[Statistics->FileSystemType](Statistics, (PVOID)((ULONG_PTR)Statistics + sizeof(FILESYSTEM_STATISTICS)),
                                           Statistics->SizeOfCompleteStructure, ProcCount, BytesRead))
    {
        if (Statistics != &Buffer)
        {
            LocalFree(Statistics);
        }

        return 1;
    }

    /* And finally, display the statistics (both generic and specific) */
    DumpFct[Statistics->FileSystemType](Statistics, (PVOID)((ULONG_PTR)Statistics + sizeof(FILESYSTEM_STATISTICS)));

    /* If we allocated memory, release it */
    if (Statistics != &Buffer)
    {
        LocalFree(Statistics);
    }

    return 0;
}
