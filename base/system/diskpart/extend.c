/*
 * PROJECT:         ReactOS DiskPart
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            base/system/diskpart/extend.c
 * PURPOSE:         Manages all the partitions of the OS in an interactive way.
 * PROGRAMMERS:     Lee Schroeder
 *                  Tomas Srnka (extend, 2026)
 */

#include "diskpart.h"

#define NDEBUG
#include <debug.h>

#ifndef FSCTL_EXTEND_VOLUME
#define FSCTL_EXTEND_VOLUME CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 60, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

/* The NTFS driver's limit: no partition of this size or more mounts. */
#define NTFS_MAX_BYTES (1ULL << 44)

/* WinBtrfs' own interface (drivers/filesystems/btrfs/btrfsioctl.h): its FSCTL_EXTEND_VOLUME is a stub. */
#define FSCTL_BTRFS_GET_DEVICES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x82e, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define FSCTL_BTRFS_RESIZE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x848, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

typedef struct _BTRFS_DEVICE
{
    UINT32 next_entry;
    UINT64 dev_id;
    UINT64 size;
    UINT64 max_size;
    BOOL readonly;
    BOOL missing;
    ULONG device_number;
    ULONG partition_number;
    UINT64 stats[5];
    USHORT namelen;
    WCHAR name[1];
} BTRFS_DEVICE, *PBTRFS_DEVICE;

typedef struct _BTRFS_RESIZE
{
    UINT64 device;
    UINT64 size;    /* 0: the size of the device */
} BTRFS_RESIZE;

/* The device of a one-device, writable Btrfs volume (checked before anything changes). */
static
NTSTATUS
GetBtrfsDevice(
    _In_ HANDLE hVolume,
    _Out_ PUINT64 pDeviceId)
{
    BYTE Buffer[1024];
    PBTRFS_DEVICE Device = (PBTRFS_DEVICE)Buffer;
    IO_STATUS_BLOCK Iosb;
    NTSTATUS Status;

    Status = NtFsControlFile(hVolume, NULL, NULL, NULL, &Iosb, FSCTL_BTRFS_GET_DEVICES, NULL, 0, Buffer, sizeof(Buffer));
    if (!NT_SUCCESS(Status))
        return Status;
    if (Device->next_entry != 0 || Device->readonly || Device->missing)
        return STATUS_NOT_SUPPORTED;
    *pDeviceId = Device->dev_id;
    return STATUS_SUCCESS;
}

/* The Btrfs volume takes its whole (grown) device. */
static
NTSTATUS
ExtendBtrfs(
    _In_ HANDLE hVolume,
    _In_ UINT64 DeviceId)
{
    BTRFS_RESIZE Resize;
    IO_STATUS_BLOCK Iosb;

    Resize.device = DeviceId;
    Resize.size = 0;
    return NtFsControlFile(hVolume, NULL, NULL, NULL, &Iosb, FSCTL_BTRFS_RESIZE, &Resize, sizeof(Resize), NULL, 0);
}

/*
 * A handle to the whole disk of the partition (bWholeDisk), or to the volume
 * on it, opened by the volume's own device name: a \Device\HarddiskN\PartitionM
 * link can name another partition once the layout changed in this session.
 * STATUS_OBJECT_NAME_NOT_FOUND when the partition has no volume.
 */
NTSTATUS
OpenPartitionDevice(
    _In_ PPARTENTRY PartEntry,
    _In_ BOOL bWholeDisk,
    _Out_ PHANDLE phDevice)
{
    WCHAR szName[MAX_PATH];
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK Iosb;
    PVOLENTRY VolumeEntry;

    *phDevice = NULL;
    if (bWholeDisk)
    {
        StringCchPrintfW(szName, ARRAYSIZE(szName), L"\\Device\\Harddisk%lu\\Partition0",
                         PartEntry->DiskEntry->DiskNumber);
    }
    else
    {
        VolumeEntry = GetVolumeFromPartition(PartEntry);
        if (VolumeEntry == NULL || VolumeEntry->DeviceName[0] == UNICODE_NULL)
            return STATUS_OBJECT_NAME_NOT_FOUND;
        StringCchCopyW(szName, ARRAYSIZE(szName), VolumeEntry->DeviceName);
    }
    RtlInitUnicodeString(&Name, szName);
    InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);

    return NtOpenFile(phDevice,
                      GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
                      &ObjectAttributes,
                      &Iosb,
                      FILE_SHARE_READ | FILE_SHARE_WRITE,
                      FILE_SYNCHRONOUS_IO_NONALERT);
}

/* The file system on the volume ("NTFS", "FAT32", "RAW", ...). */
NTSTATUS
GetPartitionFileSystem(
    _In_ HANDLE hVolume,
    _Out_writes_(cchFileSystem) PWSTR pszFileSystem,
    _In_ ULONG cchFileSystem)
{
    struct
    {
        FILE_FS_ATTRIBUTE_INFORMATION Info;
        WCHAR Buffer[32];
    } Attributes;
    IO_STATUS_BLOCK Iosb;
    NTSTATUS Status;

    pszFileSystem[0] = UNICODE_NULL;
    Status = NtQueryVolumeInformationFile(hVolume, &Iosb, &Attributes, sizeof(Attributes),
                                          FileFsAttributeInformation);
    if (NT_SUCCESS(Status))
    {
        StringCchCopyNW(pszFileSystem, cchFileSystem, Attributes.Info.FileSystemName,
                        Attributes.Info.FileSystemNameLength / sizeof(WCHAR));
    }
    return Status;
}

typedef enum _FAT_EXTEND_KIND
{
    FatExtendInPlace,       /* the FATs describe the new clusters: FSCTL_EXTEND_VOLUME */
    FatExtendOffline,       /* the FATs must grow: the FAT provider, on the locked volume */
    FatExtendTooBig,        /* more clusters than the FAT type allows */
    FatExtendUnknown        /* the boot sector cannot be read or makes no sense */
} FAT_EXTEND_KIND;

/*
 * The cluster count of a FAT volume of ullSectors sectors whose FATs are grown
 * by the fewest sectors (a whole number of clusters in all, as the FAT
 * provider grows them) that describe all of its clusters; *pulFatGrowth gets
 * that growth per FAT.
 */
static
ULONGLONG
PlanFatGrowth(
    _In_ ULONG ulBytesPerSector,
    _In_ ULONG ulSpc,
    _In_ ULONG ulFats,
    _In_ ULONG ulFatSectors,
    _In_ ULONG ulFirstData,
    _In_ ULONG ulBits,
    _In_ ULONGLONG ullSectors,
    _Out_ PULONG pulFatGrowth)
{
    ULONGLONG ullClusters, ullLowest, d;

    /* A lower bound of the FAT size, so the search starts close to the answer. */
    ullLowest = ((ullSectors - ulFirstData + (ULONGLONG)ulFats * ulFatSectors + 2ULL * ulSpc) * ulBits) /
                (8ULL * ulBytesPerSector * ulSpc + (ULONGLONG)ulFats * ulBits);
    d = (ullLowest > (ULONGLONG)ulFatSectors + ulSpc) ? ullLowest - ulFatSectors - ulSpc : 0;
    for (;; d++)
    {
        if (((ULONGLONG)ulFats * d) % ulSpc)
            continue;
        if (ullSectors <= ulFirstData + (ULONGLONG)ulFats * d)
        {
            *pulFatGrowth = (ULONG)d;
            return 0;
        }
        ullClusters = (ullSectors - ulFirstData - (ULONGLONG)ulFats * d) / ulSpc;
        if (((ULONGLONG)ulFatSectors + d) * ulBytesPerSector * 8 / ulBits >= ullClusters + 2)
        {
            *pulFatGrowth = (ULONG)d;
            return ullClusters;
        }
    }
}

/*
 * How the FAT volume on hVolume can grow to ullNewSectors sectors.  The FAT
 * type follows from the cluster count, which stays within the counts the
 * formatter writes, counted after the FATs grew.  *pullMaxSectors gets the
 * largest size the type allows.
 */
static
FAT_EXTEND_KIND
GetFatExtendKind(
    _In_ HANDLE hVolume,
    _In_ ULONG ulSectorSize,
    _In_ ULONGLONG ullNewSectors,
    _Out_ PULONGLONG pullMaxSectors)
{
    PBYTE Boot;
    IO_STATUS_BLOCK Iosb;
    LARGE_INTEGER Offset;
    ULONG ulBytesPerSector, ulReserved, ulFats, ulRootSectors, ulFatSectors, ulSpc;
    ULONG ulBits, ulOldClusters, ulOldSectors, ulFirstData, ulMaxClusters, ulGrowth;
    ULONGLONG ullNewClusters, ullFatMax, ullFirstData;
    FAT_EXTEND_KIND Kind = FatExtendUnknown;
    NTSTATUS Status;

    *pullMaxSectors = 0;
    if (ulSectorSize < 512)
        ulSectorSize = 512;

    /* One whole logical sector: the disk refuses shorter transfers. */
    Boot = RtlAllocateHeap(RtlGetProcessHeap(), 0, ulSectorSize);
    if (Boot == NULL)
        return FatExtendUnknown;
    Offset.QuadPart = 0;
    Status = NtReadFile(hVolume, NULL, NULL, NULL, &Iosb, Boot, ulSectorSize, &Offset, NULL);
    if (!NT_SUCCESS(Status) || Iosb.Information != ulSectorSize)
        goto done;

    ulBytesPerSector = *(PUSHORT)&Boot[0x0B];
    ulSpc = Boot[0x0D];
    ulReserved = *(PUSHORT)&Boot[0x0E];
    ulFats = Boot[0x10];
    ulRootSectors = ulBytesPerSector ? (*(PUSHORT)&Boot[0x11] * 32 + ulBytesPerSector - 1) / ulBytesPerSector : 0;
    ulFatSectors = *(PUSHORT)&Boot[0x16] ? *(PUSHORT)&Boot[0x16] : *(PULONG)&Boot[0x24];
    ulOldSectors = *(PUSHORT)&Boot[0x13] ? *(PUSHORT)&Boot[0x13] : *(PULONG)&Boot[0x20];
    /* The sum can exceed 32 bits in a damaged boot sector: wrapped, it would pass the size check below */
    ullFirstData = (ULONGLONG)ulReserved + (ULONGLONG)ulFats * ulFatSectors + ulRootSectors;
    if (ulBytesPerSector != ulSectorSize || !ulSpc || !ulFats || !ulFatSectors || ulOldSectors <= ullFirstData)
        goto done;
    ulFirstData = (ULONG)ullFirstData;

    /* The cluster counts the formatter writes: no cluster number reaches a reserved value. */
    ulOldClusters = (ulOldSectors - ulFirstData) / ulSpc;
    ulBits = (*(PUSHORT)&Boot[0x16] == 0) ? 32 : ((ulOldClusters < 4085) ? 12 : 16);

    /* 4079 to 4086 clusters: not every reader takes it for the same FAT type. */
    if (ulBits != 32 && ulOldClusters > 4078 && ulOldClusters < 4087)
        goto done;
    ulMaxClusters = (ulBits == 12) ? 4078 : ((ulBits == 16) ? 65518 : 0x0FFFFFEE);

    /* The largest volume: the type's most clusters, with the FATs they need. */
    ullFatMax = (((ULONGLONG)ulMaxClusters + 2) * ulBits + 8ULL * ulBytesPerSector - 1) / (8ULL * ulBytesPerSector);
    ulGrowth = (ullFatMax > ulFatSectors) ? (ULONG)(ullFatMax - ulFatSectors) : 0;
    while ((ulFats * ulGrowth) % ulSpc)
        ulGrowth++;
    *pullMaxSectors = min((ULONGLONG)ulFirstData + (ULONGLONG)ulFats * ulGrowth + (ULONGLONG)ulMaxClusters * ulSpc,
                          MAXULONG);

    if (ullNewSectors > MAXULONG || ullNewSectors <= ulFirstData)
    {
        Kind = FatExtendTooBig;
        goto done;
    }
    ullNewClusters = PlanFatGrowth(ulBytesPerSector, ulSpc, ulFats, ulFatSectors, ulFirstData, ulBits,
                                   ullNewSectors, &ulGrowth);
    if (ullNewClusters > ulMaxClusters || ullNewClusters < ulOldClusters)
        Kind = FatExtendTooBig;
    else
        Kind = ulGrowth ? FatExtendOffline : FatExtendInPlace;

done:
    RtlFreeHeap(RtlGetProcessHeap(), 0, Boot);
    return Kind;
}

typedef NTSTATUS (NTAPI *PULIB_EXTEND)(PUNICODE_STRING DriveRoot, ULONGLONG NewSectors);

/* The FAT provider's offline Extend, loaded (the caller frees *phModule), or NULL. */
static
PULIB_EXTEND
GetFatExtend(
    _Out_ HMODULE *phModule)
{
    PULIB_EXTEND pExtend;

    if (!GetFsModule(L"FAT", phModule))
        return NULL;
    pExtend = (PULIB_EXTEND)GetProcAddress(*phModule, "Extend");
    if (pExtend == NULL)
    {
        FreeLibrary(*phModule);
        *phModule = NULL;
    }
    return pExtend;
}

/*
 * Grows a FAT volume whose FATs are too small, offline: the FAT provider
 * (ufat) locks and dismounts the volume, grows the FATs and moves what is in
 * their way.  No handle of ours may be open on the volume.
 */
static
NTSTATUS
ExtendFatOffline(
    _In_ PCWSTR pszVolumeDevice,
    _In_ ULONGLONG ullNewSectors)
{
    UNICODE_STRING Name;
    HMODULE hModule;
    PULIB_EXTEND pExtend;
    NTSTATUS Status;

    pExtend = GetFatExtend(&hModule);
    if (pExtend == NULL)
        return STATUS_NOT_SUPPORTED;
    RtlInitUnicodeString(&Name, pszVolumeDevice);
    Status = pExtend(&Name, ullNewSectors);
    FreeLibrary(hModule);
    return Status;
}

/* Whether the volume can be locked now (nothing else open on it); hVolume stays unlocked. */
static
BOOL
CanLockVolume(
    _In_ HANDLE hVolume)
{
    IO_STATUS_BLOCK Iosb;

    if (!NT_SUCCESS(NtFsControlFile(hVolume, NULL, NULL, NULL, &Iosb, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0)))
        return FALSE;
    NtFsControlFile(hVolume, NULL, NULL, NULL, &Iosb, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0);
    return TRUE;
}

/*
 * The partition with the focus: the selected partition (selecting a volume
 * selects its partition, selecting a partition its volume), else the
 * partition of the selected volume when it agrees with the selected disk.
 */
PPARTENTRY
GetFocusPartition(VOID)
{
    PVOLENTRY VolumeEntry;

    if (CurrentPartition != NULL)
        return CurrentPartition;
    VolumeEntry = GetFocusVolume();
    if (VolumeEntry != NULL)
        return GetPartitionForVolume(VolumeEntry);
    return NULL;
}

/*
 * Reads the disks and volumes again after a partition changed size, and gives
 * the focus back to the same disk, partition and volume. A partition that had
 * no volume before gets none from a resize, so only a partition that had one
 * waits for its volume to come back.
 */
VOID
RefreshAfterResize(
    _In_ ULONG ulDiskNumber,
    _In_ ULONGLONG ullStartSector,
    _In_ BOOL bHadVolume)
{
    PLIST_ENTRY Entry, PartListEntry;
    PDISKENTRY DiskEntry;
    PPARTENTRY PartEntry, Found = NULL;

    CurrentDisk = NULL;
    CurrentPartition = NULL;
    CurrentVolume = NULL;

    DestroyPartitionList();
    CreatePartitionList();

    for (Entry = DiskListHead.Flink; Entry != &DiskListHead; Entry = Entry->Flink)
    {
        DiskEntry = CONTAINING_RECORD(Entry, DISKENTRY, ListEntry);
        if (DiskEntry->DiskNumber != ulDiskNumber)
            continue;

        CurrentDisk = DiskEntry;
        for (PartListEntry = DiskEntry->PrimaryPartListHead.Flink;
             PartListEntry != &DiskEntry->PrimaryPartListHead && !Found;
             PartListEntry = PartListEntry->Flink)
        {
            PartEntry = CONTAINING_RECORD(PartListEntry, PARTENTRY, ListEntry);
            if (PartEntry->IsPartitioned && PartEntry->StartSector.QuadPart == ullStartSector)
                Found = PartEntry;
        }
        for (PartListEntry = DiskEntry->LogicalPartListHead.Flink;
             PartListEntry != &DiskEntry->LogicalPartListHead && !Found;
             PartListEntry = PartListEntry->Flink)
        {
            PartEntry = CONTAINING_RECORD(PartListEntry, PARTENTRY, ListEntry);
            if (PartEntry->IsPartitioned && PartEntry->StartSector.QuadPart == ullStartSector)
                Found = PartEntry;
        }
        break;
    }

    CurrentPartition = Found;
    if (Found != NULL && bHadVolume)
    {
        /* The partition's volume gets the focus with it, as SELECT PARTITION gives it. */
        SelectVolumeOfNewPartition(Found);
    }
    else if (Found != NULL)
    {
        ReloadVolumeList();
    }
    else
    {
        DestroyVolumeList();
        CreateVolumeList();
    }
}

/* The unpartitioned space right after the partition, in its MBR container or after the container. */
static
PPARTENTRY
GetFreeSpaceAfter(
    _In_ PPARTENTRY PartEntry)
{
    PDISKENTRY DiskEntry = PartEntry->DiskEntry;
    PPARTENTRY Next = GetNextUnpartitionedEntry(PartEntry);

    /* The space is "after" the partition only if it starts where the partition ends */
    if (Next != NULL)
    {
        if (Next->StartSector.QuadPart == PartEntry->StartSector.QuadPart + PartEntry->SectorCount.QuadPart)
            return Next;
        return NULL;
    }

    /* The last logical partition grows past its container, which grows with it. */
    if (PartEntry->LogicalPartition && DiskEntry->ExtendedPartition != NULL &&
        PartEntry->ListEntry.Flink == &DiskEntry->LogicalPartListHead &&
        PartEntry->StartSector.QuadPart + PartEntry->SectorCount.QuadPart ==
        DiskEntry->ExtendedPartition->StartSector.QuadPart + DiskEntry->ExtendedPartition->SectorCount.QuadPart)
    {
        Next = GetNextUnpartitionedEntry(DiskEntry->ExtendedPartition);
        if (Next != NULL &&
            Next->StartSector.QuadPart == DiskEntry->ExtendedPartition->StartSector.QuadPart + DiskEntry->ExtendedPartition->SectorCount.QuadPart)
            return Next;
    }

    return NULL;
}

static
NTSTATUS
GrowPartition(
    _In_ PPARTENTRY PartEntry,
    _In_ LONGLONG llBytes)
{
    DISK_GROW_PARTITION Grow;
    IO_STATUS_BLOCK Iosb;
    HANDLE hDisk;
    NTSTATUS Status;

    Status = OpenPartitionDevice(PartEntry, TRUE, &hDisk);
    if (!NT_SUCCESS(Status))
        return Status;

    Grow.PartitionNumber = PartEntry->PartitionNumber;
    Grow.BytesToGrow.QuadPart = llBytes;
    Status = NtDeviceIoControlFile(hDisk, NULL, NULL, NULL, &Iosb, IOCTL_DISK_GROW_PARTITION,
                                   &Grow, sizeof(Grow), NULL, 0);
    NtClose(hDisk);
    return Status;
}

/*
 * The file system on the volume takes the whole partition (NTFS keeps the
 * last sector for its boot sector copy; FSCTL_EXTEND_VOLUME counts it).
 */
static
NTSTATUS
ExtendFileSystem(
    _In_ HANDLE hVolume,
    _In_ PCWSTR pszFileSystem,
    _In_ UINT64 BtrfsDevice)
{
    GET_LENGTH_INFORMATION Length;
    DISK_GEOMETRY Geometry;
    IO_STATUS_BLOCK Iosb;
    LONGLONG llSectors;
    NTSTATUS Status;

    if (_wcsicmp(pszFileSystem, L"Btrfs") == 0)
        return ExtendBtrfs(hVolume, BtrfsDevice);

    Status = NtDeviceIoControlFile(hVolume, NULL, NULL, NULL, &Iosb, IOCTL_DISK_GET_LENGTH_INFO,
                                   NULL, 0, &Length, sizeof(Length));
    if (!NT_SUCCESS(Status))
        return Status;
    Status = NtDeviceIoControlFile(hVolume, NULL, NULL, NULL, &Iosb, IOCTL_DISK_GET_DRIVE_GEOMETRY,
                                   NULL, 0, &Geometry, sizeof(Geometry));
    if (!NT_SUCCESS(Status) || Geometry.BytesPerSector == 0)
        Geometry.BytesPerSector = 512;

    llSectors = Length.Length.QuadPart / Geometry.BytesPerSector;
    return NtFsControlFile(hVolume, NULL, NULL, NULL, &Iosb, FSCTL_EXTEND_VOLUME,
                           &llSectors, sizeof(llSectors), NULL, 0);
}

static
BOOL
IsExtendableFileSystem(
    _In_ PCWSTR pszFileSystem)
{
    return (_wcsicmp(pszFileSystem, L"NTFS") == 0) ||
           (_wcsicmp(pszFileSystem, L"FAT") == 0) ||
           (_wcsicmp(pszFileSystem, L"FAT32") == 0) ||
           (_wcsicmp(pszFileSystem, L"Btrfs") == 0);
}

EXIT_CODE
extend_main(
    _In_ INT argc,
    _In_ PWSTR *argv)
{
    PPARTENTRY PartEntry, FreeEntry;
    PVOLENTRY VolumeEntry;
    PWSTR pszSuffix = NULL, pszEnd;
    WCHAR szFileSystem[32], szVolumeDevice[MAX_PATH];
    ULONGLONG ullSize = 0, ullFree, ullBytes, ullNewSectors, ullMaxSectors;
    ULONG ulDiskNumber, ulBytesPerSector;
    ULONGLONG ullStartSector;
    BOOL bFileSystemOnly = FALSE, bVolumeFocus, bHasFileSystem = FALSE, bOffline = FALSE;
    FAT_EXTEND_KIND Kind = FatExtendInPlace;
    UINT64 BtrfsDevice = 0;
    HANDLE hVolume = NULL;
    HMODULE hModule;
    NTSTATUS Status;
    INT i;

    for (i = 1; i < argc; i++)
    {
        if (HasPrefix(argv[i], L"size=", &pszSuffix))
        {
            /* size=<N> (MB), a whole decimal number that fits in a byte count */
            ullSize = _wcstoui64(pszSuffix, &pszEnd, 10);
            if (ullSize == 0 || *pszEnd != UNICODE_NULL || !iswdigit(*pszSuffix) ||
                ullSize > MAXLONGLONG / SIZE_1MB)
            {
                ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
                return EXIT_SUCCESS;
            }
        }
        else if (HasPrefix(argv[i], L"disk=", &pszSuffix))
        {
            /* disk=<N>: space on another disk makes a spanned volume (dynamic disks) */
            return RefuseUnsupportedOption(L"DISK");
        }
        else if (_wcsicmp(argv[i], L"filesystem") == 0)
        {
            bFileSystemOnly = TRUE;
        }
        else if (_wcsicmp(argv[i], L"noerr") == 0)
        {
            /* noerr */
        }
        else
        {
            ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
            return EXIT_SUCCESS;
        }
    }

    /* The file system takes the whole partition, so a size says something that cannot be done */
    if (bFileSystemOnly && ullSize != 0)
    {
        ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
        return EXIT_SUCCESS;
    }

    bVolumeFocus = (GetFocusVolume() != NULL);
    PartEntry = GetFocusPartition();
    if (PartEntry == NULL || !PartEntry->IsPartitioned)
    {
        ConResPuts(StdOut, bVolumeFocus ? IDS_EXTEND_NOT_PARTITION : IDS_SELECT_NO_VOLUME);
        return EXIT_SUCCESS;
    }
    ulDiskNumber = PartEntry->DiskEntry->DiskNumber;
    ullStartSector = PartEntry->StartSector.QuadPart;
    ulBytesPerSector = PartEntry->DiskEntry->BytesPerSector;

    /*
     * Everything that decides whether the file system can follow comes before
     * the partition changes: the volume and its file system, the FAT type
     * limit, a FAT volume that must be free to have its tables grown, the
     * provider that grows them, a one-device Btrfs volume and the privilege
     * WinBtrfs asks for.
     */
    VolumeEntry = GetVolumeFromPartition(PartEntry);
    szFileSystem[0] = UNICODE_NULL;
    szVolumeDevice[0] = UNICODE_NULL;
    if (VolumeEntry != NULL)
    {
        StringCchCopyW(szVolumeDevice, ARRAYSIZE(szVolumeDevice), VolumeEntry->DeviceName);
        Status = OpenPartitionDevice(PartEntry, FALSE, &hVolume);
        if (NT_SUCCESS(Status))
            Status = GetPartitionFileSystem(hVolume, szFileSystem, ARRAYSIZE(szFileSystem));
        if (!NT_SUCCESS(Status))
        {
            ConResPrintf(StdOut, IDS_EXTEND_FAIL, Status);
            goto done;
        }
        bHasFileSystem = (_wcsicmp(szFileSystem, L"RAW") != 0);
    }

    if (bHasFileSystem && !IsExtendableFileSystem(szFileSystem))
    {
        ConResPuts(StdOut, IDS_EXTEND_FS_UNSUPPORTED);
        goto done;
    }
    if (bFileSystemOnly && !bHasFileSystem)
    {
        /* A partition without a file system: nothing to extend (as Windows answers). */
        ConResPuts(StdOut, IDS_EXTEND_FS_SUCCESS);
        goto done;
    }

    if (bHasFileSystem && _wcsicmp(szFileSystem, L"Btrfs") == 0)
    {
        BOOLEAN bOldState;

        Status = RtlAdjustPrivilege(SE_MANAGE_VOLUME_PRIVILEGE, TRUE, FALSE, &bOldState);
        if (Status == STATUS_NOT_ALL_ASSIGNED)
            Status = STATUS_PRIVILEGE_NOT_HELD;
        if (NT_SUCCESS(Status))
            Status = GetBtrfsDevice(hVolume, &BtrfsDevice);
        if (!NT_SUCCESS(Status))
        {
            ConResPrintf(StdOut, IDS_EXTEND_FAIL, Status);
            goto done;
        }
    }

    if (bFileSystemOnly)
    {
        ullBytes = 0;
        ullNewSectors = PartEntry->SectorCount.QuadPart;
    }
    else
    {
        if (!CheckPartitionLayoutForChange(PartEntry->DiskEntry))
            goto done;

        FreeEntry = GetFreeSpaceAfter(PartEntry);
        ullFree = FreeEntry ? FreeEntry->SectorCount.QuadPart * ulBytesPerSector : 0;
        ullBytes = ullSize ? ullSize * SIZE_1MB : ullFree;
        if (ullFree == 0 || ullBytes > ullFree)
        {
            ConResPuts(StdOut, IDS_EXTEND_NO_SPACE);
            goto done;
        }
        ullNewSectors = PartEntry->SectorCount.QuadPart + ullBytes / ulBytesPerSector;
    }

    /*
     * The NTFS driver mounts no volume of 16 TiB or more (its page index is
     * 32 bits): the partition stays below that, so that it mounts again.
     */
    if (bHasFileSystem && _wcsicmp(szFileSystem, L"NTFS") == 0 &&
        ullNewSectors >= NTFS_MAX_BYTES / ulBytesPerSector)
    {
        ConResPrintf(StdOut, IDS_EXTEND_NTFS_TOO_BIG, (NTFS_MAX_BYTES - SIZE_1MB) / SIZE_1MB);
        goto done;
    }

    /*
     * A FAT volume extends in place while its FATs can describe the new
     * clusters; otherwise its FATs grow offline, which needs the volume to
     * itself and the FAT provider's Extend.
     */
    if (bHasFileSystem && _wcsnicmp(szFileSystem, L"FAT", 3) == 0)
    {
        Kind = GetFatExtendKind(hVolume, ulBytesPerSector, ullNewSectors, &ullMaxSectors);
        if (Kind == FatExtendTooBig)
        {
            ConResPrintf(StdOut, IDS_EXTEND_FAT_TOO_BIG, szFileSystem,
                         ullMaxSectors * ulBytesPerSector / SIZE_1MB);
            goto done;
        }
        if (Kind == FatExtendUnknown)
        {
            ConResPrintf(StdOut, IDS_EXTEND_FAIL, STATUS_FILE_CORRUPT_ERROR);
            goto done;
        }
        bOffline = (Kind == FatExtendOffline);
        if (bOffline)
        {
            /* Not crash-safe: never on the volume the system runs from. */
            if (VolumeEntry->IsBoot || VolumeEntry->IsSystem)
            {
                ConResPuts(StdOut, IDS_EXTEND_FAT_SYSTEM);
                goto done;
            }
            if (GetFatExtend(&hModule) == NULL)
            {
                ConResPuts(StdOut, IDS_EXTEND_FS_UNSUPPORTED);
                goto done;
            }
            FreeLibrary(hModule);
            if (!CanLockVolume(hVolume))
            {
                ConResPuts(StdOut, IDS_EXTEND_IN_USE);
                goto done;
            }
        }
    }

    /* The offline growth of the FATs is not crash-safe: said before anything is written. */
    if (bOffline)
        ConResPuts(StdOut, IDS_EXTEND_FAT_OFFLINE);

    if (!bFileSystemOnly)
    {
        Status = GrowPartition(PartEntry, (LONGLONG)ullBytes);
        if (!NT_SUCCESS(Status))
        {
            ConResPrintf(StdOut, IDS_EXTEND_FAIL, Status);
            goto done;
        }
    }

    if (bOffline)
    {
        NtClose(hVolume);
        hVolume = NULL;
        Status = ExtendFatOffline(szVolumeDevice, ullNewSectors);
    }
    else if (bHasFileSystem)
    {
        Status = ExtendFileSystem(hVolume, szFileSystem, BtrfsDevice);
    }
    else
    {
        Status = STATUS_SUCCESS;
    }

    if (bFileSystemOnly)
    {
        if (NT_SUCCESS(Status))
            ConResPuts(StdOut, IDS_EXTEND_FS_SUCCESS);
        else
            ConResPrintf(StdOut, IDS_EXTEND_FAIL, Status);
    }
    else if (NT_SUCCESS(Status))
    {
        ConResPuts(StdOut, IDS_EXTEND_SUCCESS);
    }
    else
    {
        /* The partition grew; EXTEND FILESYSTEM can finish the job later. */
        ConResPrintf(StdOut, IDS_EXTEND_FS_FAIL, Status);
    }

    if (hVolume != NULL)
    {
        NtClose(hVolume);
        hVolume = NULL;
    }
    RefreshAfterResize(ulDiskNumber, ullStartSector, VolumeEntry != NULL);

done:
    if (hVolume != NULL)
        NtClose(hVolume);

    return EXIT_SUCCESS;
}
