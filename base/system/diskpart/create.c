/*
 * PROJECT:         ReactOS DiskPart
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            base/system/diskpart/create.c
 * PURPOSE:         Manages all the partitions of the OS in an interactive way.
 * PROGRAMMERS:     Lee Schroeder
 */

#include "diskpart.h"

#define NDEBUG
#include <debug.h>

/*
 * A size in MB as a count of sectors. A size that does not fit gives the largest number, which no
 * unpartitioned space has: the command fails and nothing is written (the product must not wrap
 * around to a small size, or to 0 which stands for "all of the space").
 */
static
ULONGLONG
MegabytesToSectors(
    _In_ ULONGLONG ullMegabytes,
    _In_ ULONG ulBytesPerSector)
{
    if (ullMegabytes > _UI64_MAX / (1024 * 1024))
        return _UI64_MAX;

    return (ullMegabytes * 1024 * 1024) / ulBytesPerSector;
}

/*
 * NOERR (for scripts): a command that fails does not stop the script, as on the Windows DiskPart (its level is 0). Read from the
 * command line before anything else is checked.
 */
static BOOLEAN g_bNoErr = FALSE;
#define CREATE_FAILED() (g_bNoErr ? EXIT_SUCCESS : EXIT_CMD_FAILED)
/* offset= that cannot be had (the range overlaps a partition or leaves the free space): the Windows DiskPart says "Virtual Disk Service error: There is not enough usable space" (0x8004240F) */
#define CREATE_NOSPACE() (g_bNoErr ? EXIT_SUCCESS : EXIT_CMD_NO_SPACE)

static
VOID
ScanNoErr(
    _In_ INT argc,
    _In_ PWSTR *argv)
{
    INT i;

    g_bNoErr = FALSE;
    for (i = 3; i < argc; i++)
    {
        if (_wcsicmp(argv[i], L"noerr") == 0)
            g_bNoErr = TRUE;
    }
}

/* An option that is not implemented: nothing is done, the error level says so (see RefuseUnsupportedOption) */

/*
 * size=<N> (MB): decimal digits only, more than 0, no overflow, given once. Anything else is "The arguments specified for this
 * command are not valid" on the Windows DiskPart (measured: size=abc, size=0, size=-5, size=16 size=32 all fail and nothing is
 * written); it was read as "all of the free space" here.
 */
static
BOOLEAN
ParseSizeMegabytes(
    _In_ PWSTR pszSize,
    _Out_ PULONGLONG pullSize,
    _Inout_ PBOOLEAN pbGiven)
{
    PWSTR pszEnd;
    ULONGLONG ullValue;

    if (*pbGiven || !iswdigit(*pszSize))
        return FALSE;

    errno = 0;
    ullValue = _wcstoui64(pszSize, &pszEnd, 10);
    if (*pszEnd != UNICODE_NULL || errno == ERANGE || ullValue == 0)
        return FALSE;

    *pbGiven = TRUE;
    *pullSize = ullValue;
    return TRUE;
}

/* offset=<N> is in KB: a whole number of sectors, strictly decimal, that does not overflow */
static
BOOLEAN
ParseOffsetKilobytes(
    _In_ PWSTR pszOffset,
    _In_ ULONG ulBytesPerSector,
    _Out_ PULONGLONG pullSectors)
{
    PWSTR pszEnd;
    ULONGLONG ullKilobytes;

    if (!iswdigit(*pszOffset))
        return FALSE;

    errno = 0;
    ullKilobytes = _wcstoui64(pszOffset, &pszEnd, 10);
    if (*pszEnd != UNICODE_NULL || errno == ERANGE || ullKilobytes > _UI64_MAX / 1024)
        return FALSE;

    if (((ullKilobytes * 1024) % ulBytesPerSector) != 0)
        return FALSE;

    *pullSectors = (ullKilobytes * 1024) / ulBytesPerSector;
    return TRUE;
}

/*
 * The unpartitioned entry of the list that holds the range [ullOffset, ullOffset + length) (length = ullSectors,
 * or all of the entry from the offset if ullSectors is 0). ullReserve sectors at the start of an entry are not
 * usable (the sector of the EBR of a logical drive). NULL if no entry holds the range: the range would overlap
 * a partition or leave the usable area.
 */
static
PPARTENTRY
FindFreeEntryFor(
    _In_ PLIST_ENTRY ListHead,
    _In_ ULONGLONG ullOffset,
    _In_ ULONGLONG ullSectors,
    _In_ BOOLEAN bReserveEbr,
    _Out_ PULONGLONG pullLength)
{
    PLIST_ENTRY ListEntry;
    PPARTENTRY PartEntry;
    ULONGLONG ullStart, ullEnd, ullLength;

    for (ListEntry = ListHead->Flink; ListEntry != ListHead; ListEntry = ListEntry->Flink)
    {
        PartEntry = CONTAINING_RECORD(ListEntry, PARTENTRY, ListEntry);
        if (PartEntry->IsPartitioned)
            continue;

        ullStart = PartEntry->StartSector.QuadPart;
        ullEnd = ullStart + PartEntry->SectorCount.QuadPart;
        if (bReserveEbr && ListEntry->Blink != ListHead)
            ullStart += PartEntry->DiskEntry->SectorAlignment;

        if (ullOffset < ullStart || ullOffset >= ullEnd)
            continue;

        ullLength = (ullSectors != 0) ? ullSectors : (ullEnd - ullOffset);
        if (ullLength == 0 || ullLength > ullEnd - ullOffset)
            return NULL;

        *pullLength = ullLength;
        return PartEntry;
    }

    return NULL;
}

/*
 * Makes the new (partitioned) entry [ullOffset, ullOffset + ullLength) out of the unpartitioned entry that holds it;
 * what is left in front of it and behind it stays unpartitioned entries (a rest smaller than the alignment is not
 * an entry, as the scan makes none).
 */
static
PPARTENTRY
SplitFreeEntry(
    _In_ PPARTENTRY FreeEntry,
    _In_ ULONGLONG ullOffset,
    _In_ ULONGLONG ullLength)
{
    PDISKENTRY DiskEntry = FreeEntry->DiskEntry;
    ULONGLONG ullStart = FreeEntry->StartSector.QuadPart;
    ULONGLONG ullEnd = ullStart + FreeEntry->SectorCount.QuadPart;
    ULONGLONG ullBefore = ullOffset - ullStart;
    ULONGLONG ullAfter = ullEnd - (ullOffset + ullLength);
    PPARTENTRY NewEntry, AfterEntry = NULL;

    NewEntry = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PARTENTRY));
    if (NewEntry == NULL)
        return NULL;

    if (ullAfter >= DiskEntry->SectorAlignment)
    {
        AfterEntry = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PARTENTRY));
        if (AfterEntry == NULL)
        {
            RtlFreeHeap(RtlGetProcessHeap(), 0, NewEntry);
            return NULL;
        }
    }

    NewEntry->DiskEntry = DiskEntry;
    NewEntry->StartSector.QuadPart = ullOffset;
    NewEntry->SectorCount.QuadPart = ullLength;
    NewEntry->LogicalPartition = FreeEntry->LogicalPartition;
    NewEntry->IsPartitioned = TRUE;
    NewEntry->New = TRUE;
    NewEntry->FormatState = Unformatted;
    NewEntry->FileSystemName[0] = L'\0';
    InsertHeadList(&FreeEntry->ListEntry, &NewEntry->ListEntry);

    if (AfterEntry != NULL)
    {
        AfterEntry->DiskEntry = DiskEntry;
        AfterEntry->StartSector.QuadPart = ullOffset + ullLength;
        AfterEntry->SectorCount.QuadPart = ullAfter;
        AfterEntry->LogicalPartition = FreeEntry->LogicalPartition;
        AfterEntry->FormatState = Unformatted;
        InsertHeadList(&NewEntry->ListEntry, &AfterEntry->ListEntry);
    }

    /* what is left in front: not the alignment area that is the EBR of a logical drive (nothing fits there) */
    if (ullBefore >= DiskEntry->SectorAlignment &&
        !(FreeEntry->LogicalPartition && ullBefore == DiskEntry->SectorAlignment))
    {
        FreeEntry->SectorCount.QuadPart = ullBefore;
    }
    else
    {
        RemoveEntryList(&FreeEntry->ListEntry);
        RtlFreeHeap(RtlGetProcessHeap(), 0, FreeEntry);
    }

    return NewEntry;
}

/*
 * Where a new partition goes when the user gives no offset: the largest unpartitioned entry that can hold it, the one
 * at the lowest offset among equals (measured on the Windows DiskPart). ullSectors is 0 for "all of it". For the logical
 * drives of an extended partition the first sector of every entry but the first is the EBR of the new drive (bLogical).
 */
static
PPARTENTRY
FindLargestFreeEntry(
    _In_ PLIST_ENTRY ListHead,
    _In_ ULONGLONG ullSectors,
    _In_ BOOLEAN bLogical)
{
    PLIST_ENTRY ListEntry;
    PPARTENTRY PartEntry, Best = NULL;
    ULONGLONG ullAvailable, ullBest = 0;

    for (ListEntry = ListHead->Flink; ListEntry != ListHead; ListEntry = ListEntry->Flink)
    {
        PartEntry = CONTAINING_RECORD(ListEntry, PARTENTRY, ListEntry);
        if (PartEntry->IsPartitioned)
            continue;

        ullAvailable = PartEntry->SectorCount.QuadPart;
        if (bLogical && ListEntry->Blink != ListHead)
        {
            if (ullAvailable <= PartEntry->DiskEntry->SectorAlignment)
                continue;
            ullAvailable -= PartEntry->DiskEntry->SectorAlignment;
        }

        if (ullSectors != 0 && ullSectors > ullAvailable)
            continue;

        if (Best == NULL || ullAvailable > ullBest)
        {
            Best = PartEntry;
            ullBest = ullAvailable;
        }
    }

    return Best;
}

/*
 * A disk the system found no partition table on (RAW) is initialised as MBR by the first CREATE PARTITION PRIMARY / EXTENDED, as the
 * Windows DiskPart does (measured: the disk gets an MBR, the partition is made at once).
 */
static
BOOLEAN
InitializeRawDiskAsMbr(VOID)
{
    CREATE_DISK DiskInfo;
    NTSTATUS Status;

    DiskInfo.PartitionStyle = PARTITION_STYLE_MBR;
    CreateSignature(&DiskInfo.Mbr.Signature);

    Status = CreateDisk(CurrentDisk->DiskNumber, &DiskInfo);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("CreateDisk() failed!\n");
        return FALSE;
    }

    CurrentDisk->StartSector.QuadPart = (ULONGLONG)CurrentDisk->SectorAlignment;
    CurrentDisk->EndSector.QuadPart = min(CurrentDisk->SectorCount.QuadPart, 0x100000000) - 1;

    ScanForUnpartitionedMbrDiskSpace(CurrentDisk);
    return TRUE;
}


static
PPARTENTRY
InsertGptPartition(
    _In_ PDISKENTRY pDisk,
    _In_ ULONGLONG ullSectorSize,
    _In_ const GUID *pPartitionType,
    _In_opt_ PULONGLONG pullOffset)
{
    PPARTENTRY PartEntry, NewPartEntry;
    ULONGLONG ullLength;
    GUID PartitionId;

    /* The identifier comes first: with no random data no partition is claimed */
    if (!CreateGUID(&PartitionId))
        return NULL;

    if (pullOffset != NULL)
    {
        /* offset=: exactly there, or nothing (the range must lie in unpartitioned space) */
        PartEntry = FindFreeEntryFor(&pDisk->PrimaryPartListHead, *pullOffset, ullSectorSize, FALSE, &ullLength);
        if (PartEntry == NULL)
            return NULL;

        NewPartEntry = SplitFreeEntry(PartEntry, *pullOffset, ullLength);
        if (NewPartEntry == NULL)
            return NULL;

        CopyMemory(&NewPartEntry->Gpt.PartitionType, pPartitionType, sizeof(GUID));
        NewPartEntry->Gpt.PartitionId = PartitionId;
        NewPartEntry->Gpt.Attributes = 0ULL;
        NewPartEntry->PartitionNumber = 0;
        return NewPartEntry;
    }

    PartEntry = FindLargestFreeEntry(&pDisk->PrimaryPartListHead, ullSectorSize, FALSE);
    if (PartEntry == NULL)
        return NULL;

    if (ullSectorSize == 0ULL || ullSectorSize == PartEntry->SectorCount.QuadPart)
    {
        DPRINT("Claim the whole unused space\n");
        NewPartEntry = PartEntry;
        NewPartEntry->IsPartitioned = TRUE;
        NewPartEntry->New = TRUE;
        NewPartEntry->DisplayNumber = 0;
        NewPartEntry->FormatState = Unformatted;
        NewPartEntry->FileSystemName[0] = L'\0';
    }
    else
    {
        DPRINT("Claim part of unused space\n");
        NewPartEntry = SplitFreeEntry(PartEntry, PartEntry->StartSector.QuadPart, ullSectorSize);
        if (NewPartEntry == NULL)
        {
            ConPuts(StdOut, L"Memory allocation failed!\n");
            return NULL;
        }
    }

    CopyMemory(&NewPartEntry->Gpt.PartitionType, pPartitionType, sizeof(GUID));
    NewPartEntry->Gpt.PartitionId = PartitionId;
    NewPartEntry->Gpt.Attributes = 0ULL;
    NewPartEntry->PartitionNumber = 0;
    return NewPartEntry;
}


EXIT_CODE
CreateEfiPartition(
    _In_ INT argc,
    _In_ PWSTR *argv)
{
    PPARTENTRY PartEntry;
    ULONGLONG ullSize = 0ULL;
    BOOLEAN bSizeGiven = FALSE;
    ULONGLONG ullSectorCount;
    ULONGLONG ullOffset = 0ULL;
    BOOLEAN bOffset = FALSE;
#if 0
    BOOL bNoErr = FALSE;
#endif
    INT i;
    PWSTR pszSuffix = NULL;
    NTSTATUS Status;

    DPRINT1("CreateEfiPartition()\n");

    ScanNoErr(argc, argv);

    if (CurrentDisk == NULL)
    {
        ConResPuts(StdOut, IDS_SELECT_NO_DISK);
        return CREATE_FAILED();
    }

    if (CurrentDisk->PartitionStyle != PARTITION_STYLE_GPT)
    {
        ConResPuts(StdOut, IDS_CREATE_PARTITION_INVALID_STYLE);
        return CREATE_FAILED();
    }

    if (!CheckPartitionLayoutForChange(CurrentDisk))
        return CREATE_FAILED();

    if (!HasFreeGptSlot(CurrentDisk))
    {
        ConResPuts(StdOut, IDS_CREATE_PARTITION_TABLE_FULL);
        return CREATE_FAILED();
    }

    for (i = 3; i < argc; i++)
    {
        if (HasPrefix(argv[i], L"size=", &pszSuffix))
        {
            /* size=<N> (MB) */
            DPRINT("Size : %s\n", pszSuffix);

            if (!ParseSizeMegabytes(pszSuffix, &ullSize, &bSizeGiven))
            {
                ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
                return CREATE_FAILED();
            }
        }
        else if (HasPrefix(argv[i], L"offset=", &pszSuffix))
        {
            /* offset=<N> (KB) */
            DPRINT("Offset : %s\n", pszSuffix);
            if (!ParseOffsetKilobytes(pszSuffix, CurrentDisk->BytesPerSector, &ullOffset))
            {
                ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
                return CREATE_FAILED();
            }
            bOffset = TRUE;
        }
        else if (_wcsicmp(argv[i], L"noerr") == 0)
        {
            /* noerr - Already handled above */
        }
        else
        {
            ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
            return CREATE_FAILED();
        }
    }

    DPRINT1("Size: %I64u\n", ullSize);
#if 0
    DPRINT1("Offset: %I64u\n", ullOffset);
#endif

    /* Size */
    if (ullSize != 0)
        ullSectorCount = MegabytesToSectors(ullSize, CurrentDisk->BytesPerSector);
    else
        ullSectorCount = 0;

    DPRINT1("SectorCount: %I64u\n", ullSectorCount);

#ifdef DUMP_PARTITION_LIST
    DumpPartitionList(CurrentDisk);
#endif

    PartEntry = InsertGptPartition(CurrentDisk,
                                   ullSectorCount,
                                   &PARTITION_SYSTEM_GUID,
                                   bOffset ? &ullOffset : NULL);
    if (PartEntry == FALSE)
    {
        ConResPuts(StdOut, IDS_CREATE_PARTITION_FAIL);
        CurrentPartition = NULL;
        return (bOffset ? CREATE_NOSPACE() : CREATE_FAILED());
    }

    CurrentPartition = PartEntry;
    CurrentDisk->Dirty = TRUE;

#ifdef DUMP_PARTITION_LIST
    DumpPartitionList(CurrentDisk);
#endif

    UpdateGptDiskLayout(CurrentDisk, FALSE);
    Status = WriteGptPartitions(CurrentDisk);
    if (!NT_SUCCESS(Status))
    {
        ConResPuts(StdOut, IDS_CREATE_PARTITION_FAIL);
        CurrentPartition = NULL;
        return CREATE_FAILED();
    }

    /* the number of the new partition is fixed now: the lowest that is free (a later LIST PARTITION must not renumber) */
    AssignPartitionNumbers(CurrentDisk);

    ConResPuts(StdOut, IDS_CREATE_PARTITION_SUCCESS);

    return EXIT_SUCCESS;
}


EXIT_CODE
CreateExtendedPartition(
    _In_ INT argc,
    _In_ PWSTR *argv)
{
    PPARTENTRY PartEntry, NewPartEntry;
    ULONGLONG ullSize = 0ULL;
    BOOLEAN bSizeGiven = FALSE;
    ULONGLONG ullSectorCount;
#if 0
    ULONGLONG ullOffset = 0ULL;
    BOOL bNoErr = FALSE;
#endif
    INT i;
    PWSTR pszSuffix = NULL;
    NTSTATUS Status;

    ScanNoErr(argc, argv);

    if (CurrentDisk == NULL)
    {
        ConResPuts(StdOut, IDS_SELECT_NO_DISK);
        return CREATE_FAILED();
    }

    if (CurrentDisk->PartitionStyle == PARTITION_STYLE_GPT)
    {
        ConResPuts(StdOut, IDS_CREATE_PARTITION_INVALID_STYLE);
        return CREATE_FAILED();
    }

    for (i = 3; i < argc; i++)
    {
        if (HasPrefix(argv[i], L"size=", &pszSuffix))
        {
            /* size=<N> (MB) */
            DPRINT("Size : %s\n", pszSuffix);

            if (!ParseSizeMegabytes(pszSuffix, &ullSize, &bSizeGiven))
            {
                ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
                return CREATE_FAILED();
            }
        }
        else if (HasPrefix(argv[i], L"offset=", &pszSuffix))
        {
            /* offset=<N> (KB) */
            DPRINT("Offset : %s\n", pszSuffix);
            return RefuseUnsupportedOption(L"OFFSET");
        }
        else if (HasPrefix(argv[i], L"align=", &pszSuffix))
        {
            /* align=<N> */
            DPRINT("Align : %s\n", pszSuffix);
            return RefuseUnsupportedOption(L"ALIGN");
        }
        else if (_wcsicmp(argv[i], L"noerr") == 0)
        {
            /* noerr - Already handled above */
        }
        else
        {
            ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
            return CREATE_FAILED();
        }
    }

    DPRINT1("Size: %I64u\n", ullSize);
#if 0
    DPRINT1("Offset: %I64u\n", ullOffset);
#endif

    if (CurrentDisk->PartitionStyle == PARTITION_STYLE_RAW && !InitializeRawDiskAsMbr())
    {
        ConResPuts(StdOut, IDS_CREATE_PARTITION_FAIL);
        return CREATE_FAILED();
    }

    if (GetPrimaryPartitionCount(CurrentDisk) >= 4)
    {
        ConPuts(StdOut, L"No space left for an extended partition!\n");
        return CREATE_FAILED();
    }

    if (!CheckPartitionLayoutForChange(CurrentDisk))
        return CREATE_FAILED();

    if (CurrentDisk->ExtendedPartition != NULL)
    {
        ConPuts(StdOut, L"We already have an extended partition on this disk!\n");
        return CREATE_FAILED();
    }

    if (ullSize != 0)
        ullSectorCount = MegabytesToSectors(ullSize, CurrentDisk->BytesPerSector);
    else
        ullSectorCount = 0;

    DPRINT1("SectorCount: %I64u\n", ullSectorCount);

    /* The largest free space that holds it (the lowest offset among equals), not only the space at the end of the disk */
    PartEntry = FindLargestFreeEntry(&CurrentDisk->PrimaryPartListHead, ullSectorCount, FALSE);
    if (PartEntry == NULL)
    {
        ConResPuts(StdOut, IDS_CREATE_PARTITION_FAIL);
        return CREATE_FAILED();
    }

    if (ullSectorCount == 0 || PartEntry->SectorCount.QuadPart == ullSectorCount)
    {
        PartEntry->IsPartitioned = TRUE;
        PartEntry->New = TRUE;
        PartEntry->DisplayNumber = 0;
        PartEntry->Mbr.PartitionType = PARTITION_EXTENDED;
        PartEntry->FormatState = Unformatted;
        PartEntry->FileSystemName[0] = L'\0';

        CurrentPartition = PartEntry;
        CurrentDisk->Dirty = TRUE;
    }
    else
    {
        NewPartEntry = SplitFreeEntry(PartEntry, PartEntry->StartSector.QuadPart, ullSectorCount);
        if (NewPartEntry == NULL)
        {
            ConPuts(StdOut, L"Memory allocation failed!\n");
            return CREATE_FAILED();
        }

        NewPartEntry->Mbr.PartitionType = PARTITION_EXTENDED;
        CurrentPartition = NewPartEntry;
        CurrentDisk->Dirty = TRUE;
    }

    UpdateMbrDiskLayout(CurrentDisk);
    Status = WriteMbrPartitions(CurrentDisk);
    if (!NT_SUCCESS(Status))
    {
        ConResPuts(StdOut, IDS_CREATE_PARTITION_FAIL);
        CurrentPartition = NULL;
        return CREATE_FAILED();
    }

    /* The new extended partition is the container of the logical partitions: make it known, with its free space, so
     * that "create partition logical" finds room in it without a rescan. */
    if (CurrentDisk->ExtendedPartition == NULL && CurrentPartition != NULL)
    {
        CurrentDisk->ExtendedPartition = CurrentPartition;
        if (IsListEmpty(&CurrentDisk->LogicalPartListHead))
            AddEmptyLogicalSpace(CurrentDisk);
    }

    /* the number of the new partition is fixed now: the lowest that is free (a later LIST PARTITION must not renumber) */
    AssignPartitionNumbers(CurrentDisk);

    ConResPuts(StdOut, IDS_CREATE_PARTITION_SUCCESS);

    return EXIT_SUCCESS;
}


EXIT_CODE
CreateLogicalPartition(
    _In_ INT argc,
    _In_ PWSTR *argv)
{
    PPARTENTRY PartEntry, NewPartEntry;
    ULONGLONG ullSize = 0ULL;
    BOOLEAN bSizeGiven = FALSE;
    ULONGLONG ullSectorCount;
    ULONGLONG ullOffset = 0ULL;
    BOOLEAN bOffset = FALSE;
#if 0
    BOOL bNoErr = FALSE;
#endif
    UCHAR PartitionType = PARTITION_HUGE;
    INT i, length;
    PWSTR pszSuffix = NULL;
    NTSTATUS Status;

    ScanNoErr(argc, argv);

    if (CurrentDisk == NULL)
    {
        ConResPuts(StdOut, IDS_SELECT_NO_DISK);
        return CREATE_FAILED();
    }

    if (CurrentDisk->PartitionStyle != PARTITION_STYLE_MBR)
    {
        ConResPuts(StdOut, IDS_CREATE_PARTITION_INVALID_STYLE);
        return CREATE_FAILED();
    }

    if (!CheckPartitionLayoutForChange(CurrentDisk))
        return CREATE_FAILED();

    for (i = 3; i < argc; i++)
    {
        if (HasPrefix(argv[i], L"size=", &pszSuffix))
        {
            /* size=<N> (MB) */
            DPRINT("Size : %s\n", pszSuffix);

            if (!ParseSizeMegabytes(pszSuffix, &ullSize, &bSizeGiven))
            {
                ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
                return CREATE_FAILED();
            }
        }
        else if (HasPrefix(argv[i], L"offset=", &pszSuffix))
        {
            /* offset=<N> (KB) */
            DPRINT("Offset : %s\n", pszSuffix);
            if (!ParseOffsetKilobytes(pszSuffix, CurrentDisk->BytesPerSector, &ullOffset))
            {
                ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
                return CREATE_FAILED();
            }
            bOffset = TRUE;
        }
        else if (HasPrefix(argv[i], L"id=", &pszSuffix))
        {
            /* id=<Byte> */
            DPRINT("Id : %s\n", pszSuffix);

            length = wcslen(pszSuffix);
            if ((length == 1) || (length == 2))
            {
                /* Byte */
                PartitionType = (UCHAR)wcstoul(pszSuffix, NULL, 16);
                if ((PartitionType == 0) && (errno == ERANGE))
                {
                    ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
                    return CREATE_FAILED();
                }
            }
            else
            {
                ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
                return CREATE_FAILED();
            }
        }
        else if (HasPrefix(argv[i], L"align=", &pszSuffix))
        {
            /* align=<N> */
            DPRINT("Align : %s\n", pszSuffix);
            return RefuseUnsupportedOption(L"ALIGN");
        }
        else if (_wcsicmp(argv[i], L"noerr") == 0)
        {
            /* noerr - Already handled above */
        }
        else
        {
            ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
            return CREATE_FAILED();
        }
    }

    DPRINT1("Size: %I64u\n", ullSize);
#if 0
    DPRINT1("Offset: %I64u\n", ullOffset);
#endif
    DPRINT1("Partition Type: %hx\n", PartitionType);

    if (ullSize != 0)
        ullSectorCount = MegabytesToSectors(ullSize, CurrentDisk->BytesPerSector);
    else
        ullSectorCount = 0;

    DPRINT1("SectorCount: %I64u\n", ullSectorCount);

    /* Only the partition created here and its volume get the focus */
    CurrentPartition = NULL;
    CurrentVolume = NULL;

    if (bOffset)
    {
        /* offset=: exactly there, or nothing (the range must lie in unpartitioned space of the extended partition) */
        ULONGLONG ullLength;

        PartEntry = FindFreeEntryFor(&CurrentDisk->LogicalPartListHead, ullOffset, ullSectorCount, TRUE, &ullLength);
        NewPartEntry = (PartEntry != NULL) ? SplitFreeEntry(PartEntry, ullOffset, ullLength) : NULL;
        if (NewPartEntry != NULL)
        {
            NewPartEntry->Mbr.PartitionType = PartitionType;
            CurrentPartition = NewPartEntry;
            CurrentDisk->Dirty = TRUE;
        }
    }

    /*
     * Every drive of the chain has its EBR in the alignment area in front of it. The unpartitioned entry at the start of
     * the extended partition begins behind the first EBR; any other entry begins where the drive in front of it ends, so
     * the new drive starts one alignment later (else its EBR lands in the end of that drive: it was written over its
     * data). The largest free space that holds the drive is used (the lowest offset among equals).
     */
    if (!bOffset)
    {
        PartEntry = FindLargestFreeEntry(&CurrentDisk->LogicalPartListHead, ullSectorCount, TRUE);
        if (PartEntry != NULL)
        {
            ULONGLONG ullReserve, ullAvailable, ullLength;

            ullReserve = (PartEntry->ListEntry.Blink != &CurrentDisk->LogicalPartListHead) ? CurrentDisk->SectorAlignment : 0;
            ullAvailable = PartEntry->SectorCount.QuadPart - ullReserve;
            ullLength = (ullSectorCount != 0) ? ullSectorCount : ullAvailable;

            NewPartEntry = SplitFreeEntry(PartEntry, PartEntry->StartSector.QuadPart + ullReserve, ullLength);
            if (NewPartEntry == NULL)
            {
                ConPuts(StdOut, L"Memory allocation failed!\n");
                return CREATE_FAILED();
            }

            NewPartEntry->Mbr.PartitionType = PartitionType;
            CurrentPartition = NewPartEntry;
            CurrentDisk->Dirty = TRUE;
        }
    }

    if (CurrentPartition == NULL)
    {
        /* No free space was large enough */
        ConResPuts(StdOut, IDS_CREATE_PARTITION_FAIL);
        return (bOffset ? CREATE_NOSPACE() : CREATE_FAILED());
    }

    UpdateMbrDiskLayout(CurrentDisk);
    Status = WriteMbrPartitions(CurrentDisk);
    if (!NT_SUCCESS(Status))
    {
        ConResPuts(StdOut, IDS_CREATE_PARTITION_FAIL);
        CurrentPartition = NULL;
        return CREATE_FAILED();
    }

    /* the number of the new partition is fixed now: the lowest that is free (a later LIST PARTITION must not renumber) */
    AssignPartitionNumbers(CurrentDisk);

    ConResPuts(StdOut, IDS_CREATE_PARTITION_SUCCESS);

    SelectVolumeOfNewPartition(CurrentPartition);

    return EXIT_SUCCESS;
}


EXIT_CODE
CreateMsrPartition(
    _In_ INT argc,
    _In_ PWSTR *argv)
{
    PPARTENTRY PartEntry;
    ULONGLONG ullSize = 0ULL;
    BOOLEAN bSizeGiven = FALSE;
    ULONGLONG ullSectorSize;
    ULONGLONG ullOffset = 0ULL;
    BOOLEAN bOffset = FALSE;
#if 0
    BOOL bNoErr = FALSE;
#endif
    INT i;
    PWSTR pszSuffix = NULL;
    NTSTATUS Status;

    DPRINT1("CreateMsrPartition()\n");

    ScanNoErr(argc, argv);

    if (CurrentDisk == NULL)
    {
        ConResPuts(StdOut, IDS_SELECT_NO_DISK);
        return CREATE_FAILED();
    }

    if (CurrentDisk->PartitionStyle != PARTITION_STYLE_GPT)
    {
        ConResPuts(StdOut, IDS_CREATE_PARTITION_INVALID_STYLE);
        return CREATE_FAILED();
    }

    if (!CheckPartitionLayoutForChange(CurrentDisk))
        return CREATE_FAILED();

    if (!HasFreeGptSlot(CurrentDisk))
    {
        ConResPuts(StdOut, IDS_CREATE_PARTITION_TABLE_FULL);
        return CREATE_FAILED();
    }

    for (i = 3; i < argc; i++)
    {
        if (HasPrefix(argv[i], L"size=", &pszSuffix))
        {
            /* size=<N> (MB) */
            DPRINT("Size : %s\n", pszSuffix);

            if (!ParseSizeMegabytes(pszSuffix, &ullSize, &bSizeGiven))
            {
                ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
                return CREATE_FAILED();
            }
        }
        else if (HasPrefix(argv[i], L"offset=", &pszSuffix))
        {
            /* offset=<N> (KB) */
            DPRINT("Offset : %s\n", pszSuffix);
            if (!ParseOffsetKilobytes(pszSuffix, CurrentDisk->BytesPerSector, &ullOffset))
            {
                ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
                return CREATE_FAILED();
            }
            bOffset = TRUE;
        }
        else if (_wcsicmp(argv[i], L"noerr") == 0)
        {
            /* noerr - Already handled above */
        }
        else
        {
            ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
            return CREATE_FAILED();
        }
    }

    DPRINT1("Size: %I64u\n", ullSize);
#if 0
    DPRINT1("Offset: %I64u\n", ullOffset);
#endif

    /* Size */
    if (ullSize != 0)
        ullSectorSize = MegabytesToSectors(ullSize, CurrentDisk->BytesPerSector);
    else
        ullSectorSize = 0;

    DPRINT1("SectorSize: %I64u\n", ullSectorSize);

#ifdef DUMP_PARTITION_LIST
    DumpPartitionList(CurrentDisk);
#endif

    PartEntry = InsertGptPartition(CurrentDisk,
                                   ullSectorSize,
                                   &PARTITION_MSFT_RESERVED_GUID,
                                   bOffset ? &ullOffset : NULL);
    if (PartEntry == FALSE)
    {
        ConResPuts(StdOut, IDS_CREATE_PARTITION_FAIL);
        CurrentPartition = NULL;
        return (bOffset ? CREATE_NOSPACE() : CREATE_FAILED());
    }

    CurrentPartition = PartEntry;
    CurrentDisk->Dirty = TRUE;

#ifdef DUMP_PARTITION_LIST
    DumpPartitionList(CurrentDisk);
#endif

    UpdateGptDiskLayout(CurrentDisk, FALSE);
    Status = WriteGptPartitions(CurrentDisk);
    if (!NT_SUCCESS(Status))
    {
        ConResPuts(StdOut, IDS_CREATE_PARTITION_FAIL);
        CurrentPartition = NULL;
        return CREATE_FAILED();
    }

    /* the number of the new partition is fixed now: the lowest that is free (a later LIST PARTITION must not renumber) */
    AssignPartitionNumbers(CurrentDisk);

    ConResPuts(StdOut, IDS_CREATE_PARTITION_SUCCESS);

    return EXIT_SUCCESS;
}


static
EXIT_CODE
CreatePrimaryMbrPartition(
    _In_ ULONGLONG ullSize,
    _In_ PWSTR pszPartitionType,
    _In_ BOOLEAN bOffset,
    _In_ ULONGLONG ullOffset)
{
    PPARTENTRY PartEntry, NewPartEntry;
    ULONGLONG ullSectorCount;
    UCHAR PartitionType;
    INT length;
    NTSTATUS Status;

    if (!CheckPartitionLayoutForChange(CurrentDisk))
        return CREATE_FAILED();

    if (pszPartitionType)
    {
        length = wcslen(pszPartitionType);
        if ((length != 1) && (length != 2))
        {
            ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
            return CREATE_FAILED();
        }

        PartitionType = (UCHAR)wcstoul(pszPartitionType, NULL, 16);
        if ((PartitionType == 0) && (errno == ERANGE))
        {
            ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
            return CREATE_FAILED();
        }
    }
    else
    {
        PartitionType = PARTITION_HUGE;
    }

    /* Only the partition created here and its volume get the focus */
    CurrentPartition = NULL;
    CurrentVolume = NULL;

    if (GetPrimaryPartitionCount(CurrentDisk) >= 4)
    {
        ConPuts(StdOut, L"No space left for another primary partition!\n");
        return CREATE_FAILED();
    }

    if (ullSize != 0)
        ullSectorCount = MegabytesToSectors(ullSize, CurrentDisk->BytesPerSector);
    else
        ullSectorCount = 0;

    DPRINT1("SectorCount: %I64u\n", ullSectorCount);

    if (bOffset)
    {
        /* offset=: exactly there, or nothing (the range must lie in unpartitioned space) */
        ULONGLONG ullLength;

        PartEntry = FindFreeEntryFor(&CurrentDisk->PrimaryPartListHead, ullOffset, ullSectorCount, FALSE, &ullLength);
        NewPartEntry = (PartEntry != NULL) ? SplitFreeEntry(PartEntry, ullOffset, ullLength) : NULL;
        if (NewPartEntry != NULL)
        {
            NewPartEntry->Mbr.PartitionType = PartitionType;
            CurrentPartition = NewPartEntry;
            CurrentDisk->Dirty = TRUE;
        }
    }

    if (!bOffset)
    {
        /* The largest free space that holds it (the lowest offset among equals) */
        PartEntry = FindLargestFreeEntry(&CurrentDisk->PrimaryPartListHead, ullSectorCount, FALSE);
        if (PartEntry != NULL)
        {
            if (ullSectorCount == 0 || PartEntry->SectorCount.QuadPart == ullSectorCount)
            {
                NewPartEntry = PartEntry;
                NewPartEntry->IsPartitioned = TRUE;
                NewPartEntry->New = TRUE;
                NewPartEntry->DisplayNumber = 0;
                NewPartEntry->FormatState = Unformatted;
                NewPartEntry->FileSystemName[0] = L'\0';
            }
            else
            {
                NewPartEntry = SplitFreeEntry(PartEntry, PartEntry->StartSector.QuadPart, ullSectorCount);
                if (NewPartEntry == NULL)
                {
                    ConPuts(StdOut, L"Memory allocation failed!\n");
                    return CREATE_FAILED();
                }
            }

            NewPartEntry->Mbr.PartitionType = PartitionType;
            CurrentPartition = NewPartEntry;
            CurrentDisk->Dirty = TRUE;
        }
    }

    if (CurrentPartition == NULL)
    {
        /* No free space was large enough */
        ConResPuts(StdOut, IDS_CREATE_PARTITION_FAIL);
        return (bOffset ? CREATE_NOSPACE() : CREATE_FAILED());
    }

    UpdateMbrDiskLayout(CurrentDisk);
    Status = WriteMbrPartitions(CurrentDisk);
    if (!NT_SUCCESS(Status))
    {
        ConResPuts(StdOut, IDS_CREATE_PARTITION_FAIL);
        CurrentPartition = NULL;
        return CREATE_FAILED();
    }

    /* the number of the new partition is fixed now: the lowest that is free (a later LIST PARTITION must not renumber) */
    AssignPartitionNumbers(CurrentDisk);

    ConResPuts(StdOut, IDS_CREATE_PARTITION_SUCCESS);

    SelectVolumeOfNewPartition(CurrentPartition);

    return EXIT_SUCCESS;
}


static
EXIT_CODE
CreatePrimaryGptPartition(
    _In_ ULONGLONG ullSize,
    _In_ PWSTR pszPartitionType,
    _In_ BOOLEAN bOffset,
    _In_ ULONGLONG ullOffset)
{
    PPARTENTRY PartEntry;
    ULONGLONG ullSectorCount;
    GUID guidPartitionType;
    NTSTATUS Status;

    if (!CheckPartitionLayoutForChange(CurrentDisk))
        return CREATE_FAILED();

    if (!HasFreeGptSlot(CurrentDisk))
    {
        ConResPuts(StdOut, IDS_CREATE_PARTITION_TABLE_FULL);
        return CREATE_FAILED();
    }

    /* Partition Type */
    if (pszPartitionType)
    {
        if (!StringToGUID(&guidPartitionType, pszPartitionType))
        {
            ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
            return CREATE_FAILED();
        }
    }
    else
    {
        CopyMemory(&guidPartitionType, &PARTITION_BASIC_DATA_GUID, sizeof(GUID));
    }

    /* Size */
    if (ullSize != 0)
        ullSectorCount = MegabytesToSectors(ullSize, CurrentDisk->BytesPerSector);
    else
        ullSectorCount = 0;

    DPRINT1("SectorCount: %I64u\n", ullSectorCount);

#ifdef DUMP_PARTITION_LIST
    DumpPartitionList(CurrentDisk);
#endif

    /* Only the partition created here and its volume get the focus */
    CurrentVolume = NULL;

    PartEntry = InsertGptPartition(CurrentDisk,
                                   ullSectorCount,
                                   &guidPartitionType,
                                   bOffset ? &ullOffset : NULL);
    if (PartEntry == FALSE)
    {
        ConResPuts(StdOut, IDS_CREATE_PARTITION_FAIL);
        CurrentPartition = NULL;
        return (bOffset ? CREATE_NOSPACE() : CREATE_FAILED());
    }

    CurrentPartition = PartEntry;
    CurrentDisk->Dirty = TRUE;

#ifdef DUMP_PARTITION_LIST
    DumpPartitionList(CurrentDisk);
#endif

    UpdateGptDiskLayout(CurrentDisk, FALSE);
    Status = WriteGptPartitions(CurrentDisk);
    if (!NT_SUCCESS(Status))
    {
        ConResPuts(StdOut, IDS_CREATE_PARTITION_FAIL);
        CurrentPartition = NULL;
        return CREATE_FAILED();
    }

    /* the number of the new partition is fixed now: the lowest that is free (a later LIST PARTITION must not renumber) */
    AssignPartitionNumbers(CurrentDisk);

    ConResPuts(StdOut, IDS_CREATE_PARTITION_SUCCESS);

    SelectVolumeOfNewPartition(CurrentPartition);

    return EXIT_SUCCESS;
}


EXIT_CODE
CreatePrimaryPartition(
    _In_ INT argc,
    _In_ PWSTR *argv)
{
    ULONGLONG ullSize = 0ULL;
    BOOLEAN bSizeGiven = FALSE;
    ULONGLONG ullOffset = 0ULL;
    BOOLEAN bOffset = FALSE;
#if 0
    BOOL bNoErr = FALSE;
#endif
    INT i;
    PWSTR pszSuffix = NULL;
    PWSTR pszPartitionType = NULL;

    ScanNoErr(argc, argv);

    if (CurrentDisk == NULL)
    {
        ConResPuts(StdOut, IDS_SELECT_NO_DISK);
        return CREATE_FAILED();
    }

    for (i = 3; i < argc; i++)
    {
        if (HasPrefix(argv[i], L"size=", &pszSuffix))
        {
            /* size=<N> (MB) */
            DPRINT("Size : %s\n", pszSuffix);

            if (!ParseSizeMegabytes(pszSuffix, &ullSize, &bSizeGiven))
            {
                ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
                return CREATE_FAILED();
            }
        }
        else if (HasPrefix(argv[i], L"offset=", &pszSuffix))
        {
            /* offset=<N> (KB) */
            DPRINT("Offset : %s\n", pszSuffix);
            if (!ParseOffsetKilobytes(pszSuffix, CurrentDisk->BytesPerSector, &ullOffset))
            {
                ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
                return CREATE_FAILED();
            }
            bOffset = TRUE;
        }
        else if (HasPrefix(argv[i], L"id=", &pszSuffix))
        {
            /* id=<Byte>|<GUID> */
            DPRINT("Id : %s\n", pszSuffix);
            pszPartitionType = pszSuffix;
        }
        else if (HasPrefix(argv[i], L"align=", &pszSuffix))
        {
            /* align=<N> */
            DPRINT("Align : %s\n", pszSuffix);
            return RefuseUnsupportedOption(L"ALIGN");
        }
        else if (_wcsicmp(argv[i], L"noerr") == 0)
        {
            /* noerr - Alread handled above */
        }
        else
        {
            ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
            return CREATE_FAILED();
        }
    }

    DPRINT("Size: %I64u\n", ullSize);
#if 0
    DPRINT1("Offset: %I64u\n", ullOffset);
#endif

    if (CurrentDisk->PartitionStyle == PARTITION_STYLE_RAW)
    {
        if (!InitializeRawDiskAsMbr())
        {
            ConResPuts(StdOut, IDS_CREATE_PARTITION_FAIL);
            return CREATE_FAILED();
        }
    }

    if (CurrentDisk->PartitionStyle == PARTITION_STYLE_MBR)
    {
        DPRINT("Partition Type: %s\n", pszPartitionType);
        return CreatePrimaryMbrPartition(ullSize, pszPartitionType, bOffset, ullOffset);
    }

    return CreatePrimaryGptPartition(ullSize, pszPartitionType, bOffset, ullOffset);
}
