/*
 * PROJECT:         ReactOS DiskPart
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            base/system/diskpart/shrink.c
 * PURPOSE:         Manages all the partitions of the OS in an interactive way.
 * PROGRAMMERS:     Lee Schroeder
 *                  Tomas Srnka (shrink, 2026)
 */

#include "diskpart.h"

#define NDEBUG
#include <debug.h>

#ifndef FSCTL_SHRINK_VOLUME
#define FSCTL_SHRINK_VOLUME CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 108, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
typedef enum _SHRINK_VOLUME_REQUEST_TYPES
{
    ShrinkPrepare = 1,
    ShrinkCommit,
    ShrinkAbort
} SHRINK_VOLUME_REQUEST_TYPES, *PSHRINK_VOLUME_REQUEST_TYPES;
typedef struct _SHRINK_VOLUME_INFORMATION
{
    SHRINK_VOLUME_REQUEST_TYPES ShrinkRequestType;
    ULONGLONG Flags;
    LONGLONG NewNumberOfSectors;
} SHRINK_VOLUME_INFORMATION, *PSHRINK_VOLUME_INFORMATION;
#endif

#define BITMAP_CHUNK (64 * 1024)

/* The cluster after the last one in use (from the volume bitmap), or -1. */
static
LONGLONG
GetUsedEnd(
    _In_ HANDLE hVolume,
    _In_ LONGLONG llTotalClusters)
{
    PVOLUME_BITMAP_BUFFER Bitmap;
    STARTING_LCN_INPUT_BUFFER Start;
    IO_STATUS_BLOCK Iosb;
    LONGLONG llEnd = 0, llLcn, i;
    ULONG ulSize = FIELD_OFFSET(VOLUME_BITMAP_BUFFER, Buffer) + BITMAP_CHUNK;
    NTSTATUS Status;

    Bitmap = RtlAllocateHeap(RtlGetProcessHeap(), 0, ulSize);
    if (Bitmap == NULL)
        return -1;

    for (llLcn = 0; llLcn < llTotalClusters; )
    {
        Start.StartingLcn.QuadPart = llLcn;
        Status = NtFsControlFile(hVolume, NULL, NULL, NULL, &Iosb, FSCTL_GET_VOLUME_BITMAP,
                                 &Start, sizeof(Start), Bitmap, ulSize);
        if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_OVERFLOW)
        {
            llEnd = -1;
            break;
        }

        for (i = 0; i < (LONGLONG)BITMAP_CHUNK * 8 && Bitmap->StartingLcn.QuadPart + i < llTotalClusters &&
                    i < Bitmap->BitmapSize.QuadPart; i++)
        {
            if (Bitmap->Buffer[i / 8] & (1 << (i % 8)))
                llEnd = Bitmap->StartingLcn.QuadPart + i + 1;
        }

        if (Status != STATUS_BUFFER_OVERFLOW)
            break;
        llLcn = Bitmap->StartingLcn.QuadPart + (LONGLONG)BITMAP_CHUNK * 8;
    }

    RtlFreeHeap(RtlGetProcessHeap(), 0, Bitmap);
    return llEnd;
}

/*
 * How much smaller, in MB, the partition can get without moving data: the
 * volume keeps every cluster up to the last one in use, and its boot sector
 * copy after them.
 */
static
NTSTATUS
QueryReclaimable(
    _In_ HANDLE hVolume,
    _In_ PPARTENTRY PartEntry,
    _Out_ PULONGLONG pullMegabytes)
{
    NTFS_VOLUME_DATA_BUFFER Data;
    IO_STATUS_BLOCK Iosb;
    ULONGLONG ullLength, ullKeep;
    LONGLONG llUsedEnd;
    NTSTATUS Status;

    *pullMegabytes = 0;
    Status = NtFsControlFile(hVolume, NULL, NULL, NULL, &Iosb, FSCTL_GET_NTFS_VOLUME_DATA,
                             NULL, 0, &Data, sizeof(Data));
    if (!NT_SUCCESS(Status))
        return Status;

    llUsedEnd = GetUsedEnd(hVolume, Data.TotalClusters.QuadPart);
    if (llUsedEnd < 0)
        return STATUS_UNSUCCESSFUL;

    ullLength = PartEntry->SectorCount.QuadPart * PartEntry->DiskEntry->BytesPerSector;
    ullKeep = (ULONGLONG)llUsedEnd * Data.BytesPerCluster + Data.BytesPerSector;
    if (ullKeep < ullLength)
        *pullMegabytes = (ullLength - ullKeep) / SIZE_1MB;
    return STATUS_SUCCESS;
}

static
NTSTATUS
ShrinkRequest(
    _In_ HANDLE hVolume,
    _In_ SHRINK_VOLUME_REQUEST_TYPES Type,
    _In_ LONGLONG llSectors)
{
    SHRINK_VOLUME_INFORMATION Info;
    IO_STATUS_BLOCK Iosb;

    ZeroMemory(&Info, sizeof(Info));
    Info.ShrinkRequestType = Type;
    Info.NewNumberOfSectors = llSectors;
    return NtFsControlFile(hVolume, NULL, NULL, NULL, &Iosb, FSCTL_SHRINK_VOLUME,
                           &Info, sizeof(Info), NULL, 0);
}

EXIT_CODE
shrink_main(
    _In_ INT argc,
    _In_ PWSTR *argv)
{
    PPARTENTRY PartEntry;
    PWSTR pszSuffix = NULL, pszEnd;
    WCHAR szFileSystem[32];
    ULONGLONG ullDesired = 0, ullMinimum = 0, ullMax, ullShrink, ullLength;
    ULONG ulDiskNumber, ulBytesPerSector;
    ULONGLONG ullStartSector;
    BOOL bQueryMax = FALSE;
    HANDLE hVolume = NULL;
    DISK_GROW_PARTITION Grow;
    IO_STATUS_BLOCK Iosb;
    HANDLE hDisk;
    NTSTATUS Status;
    INT i;

    for (i = 1; i < argc; i++)
    {
        if (HasPrefix(argv[i], L"desired=", &pszSuffix))
        {
            ullDesired = _wcstoui64(pszSuffix, &pszEnd, 10);
            if (ullDesired == 0 || *pszEnd != UNICODE_NULL || !iswdigit(*pszSuffix) ||
                ullDesired > MAXLONGLONG / SIZE_1MB)
            {
                ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
                return EXIT_SUCCESS;
            }
        }
        else if (HasPrefix(argv[i], L"minimum=", &pszSuffix))
        {
            ullMinimum = _wcstoui64(pszSuffix, &pszEnd, 10);
            if (ullMinimum == 0 || *pszEnd != UNICODE_NULL || !iswdigit(*pszSuffix) ||
                ullMinimum > MAXLONGLONG / SIZE_1MB)
            {
                ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
                return EXIT_SUCCESS;
            }
        }
        else if (_wcsicmp(argv[i], L"querymax") == 0)
        {
            bQueryMax = TRUE;
        }
        else if (_wcsicmp(argv[i], L"nowait") == 0 || _wcsicmp(argv[i], L"noerr") == 0)
        {
            /* The shrink never waits for data to move: no data moves. */
        }
        else
        {
            ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
            return EXIT_SUCCESS;
        }
    }

    if (GetFocusVolume() == NULL)
    {
        ConResPuts(StdOut, IDS_SELECT_NO_VOLUME);
        return EXIT_SUCCESS;
    }

    PartEntry = GetFocusPartition();
    if (PartEntry == NULL || !PartEntry->IsPartitioned)
    {
        ConResPuts(StdOut, IDS_SHRINK_NOT_PARTITION);
        return EXIT_SUCCESS;
    }
    ulDiskNumber = PartEntry->DiskEntry->DiskNumber;
    ullStartSector = PartEntry->StartSector.QuadPart;
    ulBytesPerSector = PartEntry->DiskEntry->BytesPerSector;
    ullLength = PartEntry->SectorCount.QuadPart * ulBytesPerSector;

    Status = OpenPartitionDevice(PartEntry, FALSE, &hVolume);
    if (!NT_SUCCESS(Status))
    {
        ConResPrintf(StdOut, IDS_SHRINK_FAIL, Status);
        return EXIT_SUCCESS;
    }

    Status = GetPartitionFileSystem(hVolume, szFileSystem, ARRAYSIZE(szFileSystem));
    if (!NT_SUCCESS(Status))
    {
        ConResPrintf(StdOut, IDS_SHRINK_FAIL, Status);
        goto done;
    }
    if (_wcsicmp(szFileSystem, L"NTFS") != 0)
    {
        ConResPuts(StdOut, IDS_SHRINK_FS_UNSUPPORTED);
        goto done;
    }

    Status = QueryReclaimable(hVolume, PartEntry, &ullMax);
    if (!NT_SUCCESS(Status))
    {
        ConResPrintf(StdOut, IDS_SHRINK_FAIL, Status);
        goto done;
    }

    if (bQueryMax)
    {
        ConResPrintf(StdOut, IDS_SHRINK_QUERYMAX, ullMax);
        goto done;
    }

    /* As much as asked for (all there is, without DESIRED), but no less than MINIMUM. */
    ullShrink = ullDesired ? min(ullDesired, ullMax) : ullMax;
    if (ullShrink == 0 || (ullMinimum && ullShrink < ullMinimum) || (ullDesired && !ullMinimum && ullShrink < ullDesired))
    {
        ConResPuts(StdOut, IDS_SHRINK_TOO_BIG);
        goto done;
    }

    if (!CheckPartitionLayoutForChange(PartEntry->DiskEntry))
        goto done;

    /* The new partition's sectors: FSCTL_SHRINK_VOLUME counts the boot sector copy in the last one. */
    Status = ShrinkRequest(hVolume, ShrinkPrepare, (LONGLONG)((ullLength - ullShrink * SIZE_1MB) / ulBytesPerSector));
    if (NT_SUCCESS(Status))
    {
        Status = ShrinkRequest(hVolume, ShrinkCommit, 0);
        if (!NT_SUCCESS(Status))
            ShrinkRequest(hVolume, ShrinkAbort, 0);
    }
    if (!NT_SUCCESS(Status))
    {
        ConResPrintf(StdOut, IDS_SHRINK_FAIL, Status);
        goto done;
    }

    Status = OpenPartitionDevice(PartEntry, TRUE, &hDisk);
    if (NT_SUCCESS(Status))
    {
        Grow.PartitionNumber = PartEntry->PartitionNumber;
        Grow.BytesToGrow.QuadPart = -(LONGLONG)(ullShrink * SIZE_1MB);
        Status = NtDeviceIoControlFile(hDisk, NULL, NULL, NULL, &Iosb, IOCTL_DISK_GROW_PARTITION,
                                       &Grow, sizeof(Grow), NULL, 0);
        NtClose(hDisk);
    }
    if (!NT_SUCCESS(Status))
    {
        /* The file system is smaller already; the partition keeps its size. */
        ConResPrintf(StdOut, IDS_SHRINK_FAIL, Status);
    }
    else
    {
        ConResPrintf(StdOut, IDS_SHRINK_SUCCESS, ullShrink);
    }

    NtClose(hVolume);
    hVolume = NULL;
    RefreshAfterResize(ulDiskNumber, ullStartSector, TRUE);

done:
    if (hVolume != NULL)
        NtClose(hVolume);

    return EXIT_SUCCESS;
}
