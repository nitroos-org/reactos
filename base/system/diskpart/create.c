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

/* An option that is not implemented: nothing is done, the error level says so (see RefuseUnsupportedOption) */

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

static
PPARTENTRY
InsertGptPartition(
    _In_ PDISKENTRY pDisk,
    _In_ ULONGLONG ullSectorSize,
    _In_ const GUID *pPartitionType,
    _In_opt_ PULONGLONG pullOffset)
{
    PPARTENTRY PartEntry, NewPartEntry;
    PLIST_ENTRY ListEntry;
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

    for (ListEntry = pDisk->PrimaryPartListHead.Flink;
         ListEntry != &CurrentDisk->PrimaryPartListHead;
         ListEntry = ListEntry->Flink)
    {
        PartEntry = CONTAINING_RECORD(ListEntry, PARTENTRY, ListEntry);
        if (PartEntry->IsPartitioned)
            continue;

        if (ullSectorSize == 0ULL)
        {
            DPRINT("Claim whole unused space!\n");
            PartEntry->IsPartitioned = TRUE;
            PartEntry->New = TRUE;
            CopyMemory(&PartEntry->Gpt.PartitionType, pPartitionType, sizeof(GUID));
            PartEntry->Gpt.PartitionId = PartitionId;
            PartEntry->Gpt.Attributes = 0ULL;
            PartEntry->PartitionNumber = 0;
            PartEntry->FormatState = Unformatted;
            PartEntry->FileSystemName[0] = L'\0';

            return PartEntry;
        }
        else
        {
            if (ullSectorSize == PartEntry->SectorCount.QuadPart)
            {
                DPRINT("Claim matching unused space!\n");
                PartEntry->IsPartitioned = TRUE;
                PartEntry->New = TRUE;
                CopyMemory(&PartEntry->Gpt.PartitionType, pPartitionType, sizeof(GUID));
                PartEntry->Gpt.PartitionId = PartitionId;
                PartEntry->Gpt.Attributes = 0ULL;
                PartEntry->PartitionNumber = 0;
                PartEntry->FormatState = Unformatted;
                PartEntry->FileSystemName[0] = L'\0';

                return PartEntry;
            }
            else if (ullSectorSize < PartEntry->SectorCount.QuadPart)
            {
                DPRINT("Claim part of unused space\n");
                NewPartEntry = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PARTENTRY));
                if (NewPartEntry == NULL)
                {
                    ConPuts(StdOut, L"Memory allocation failed!\n");
                    return NULL;
                }

                NewPartEntry->DiskEntry = PartEntry->DiskEntry;

                NewPartEntry->StartSector.QuadPart = PartEntry->StartSector.QuadPart;
                NewPartEntry->SectorCount.QuadPart = ullSectorSize;

                NewPartEntry->LogicalPartition = FALSE;
                NewPartEntry->IsPartitioned = TRUE;
                NewPartEntry->New = TRUE;
                CopyMemory(&NewPartEntry->Gpt.PartitionType, pPartitionType, sizeof(GUID));
                NewPartEntry->Gpt.PartitionId = PartitionId;
                NewPartEntry->Gpt.Attributes = 0ULL;
                NewPartEntry->PartitionNumber = 0;
                NewPartEntry->FormatState = Unformatted;
                NewPartEntry->FileSystemName[0] = L'\0';

                PartEntry->StartSector.QuadPart += ullSectorSize;
                PartEntry->SectorCount.QuadPart -= ullSectorSize;

                InsertTailList(ListEntry, &NewPartEntry->ListEntry);

                return NewPartEntry;
            }
        }
    }

    return NULL;
}


EXIT_CODE
CreateEfiPartition(
    _In_ INT argc,
    _In_ PWSTR *argv)
{
    PPARTENTRY PartEntry;
    ULONGLONG ullSize = 0ULL;
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

    if (CurrentDisk == NULL)
    {
        ConResPuts(StdOut, IDS_SELECT_NO_DISK);
        return EXIT_SUCCESS;
    }

    if (CurrentDisk->PartitionStyle != PARTITION_STYLE_GPT)
    {
        ConResPuts(StdOut, IDS_CREATE_PARTITION_INVALID_STYLE);
        return EXIT_SUCCESS;
    }

    if (!CheckPartitionLayoutForChange(CurrentDisk))
        return EXIT_SUCCESS;

    if (!HasFreeGptSlot(CurrentDisk))
    {
        ConResPuts(StdOut, IDS_CREATE_PARTITION_TABLE_FULL);
        return EXIT_SUCCESS;
    }

    for (i = 3; i < argc; i++)
    {
        if (_wcsicmp(argv[i], L"noerr") == 0)
        {
            /* noerr */
            DPRINT("NoErr\n", pszSuffix);
            return RefuseUnsupportedOption(L"NOERR");
        }
    }

    for (i = 3; i < argc; i++)
    {
        if (HasPrefix(argv[i], L"size=", &pszSuffix))
        {
            /* size=<N> (MB) */
            DPRINT("Size : %s\n", pszSuffix);

            ullSize = _wcstoui64(pszSuffix, NULL, 10);
            if ((ullSize == 0) && (errno == ERANGE))
            {
                ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
                return EXIT_SUCCESS;
            }
        }
        else if (HasPrefix(argv[i], L"offset=", &pszSuffix))
        {
            /* offset=<N> (KB) */
            DPRINT("Offset : %s\n", pszSuffix);
            if (!ParseOffsetKilobytes(pszSuffix, CurrentDisk->BytesPerSector, &ullOffset))
            {
                ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
                return EXIT_SUCCESS;
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
            return EXIT_SUCCESS;
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
        return EXIT_SUCCESS;
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
        return EXIT_SUCCESS;
    }

    ConResPuts(StdOut, IDS_CREATE_PARTITION_SUCCESS);

    return EXIT_SUCCESS;
}


EXIT_CODE
CreateExtendedPartition(
    _In_ INT argc,
    _In_ PWSTR *argv)
{
    PPARTENTRY PartEntry, NewPartEntry;
    PLIST_ENTRY ListEntry;
    ULONGLONG ullSize = 0ULL;
    ULONGLONG ullSectorCount;
#if 0
    ULONGLONG ullOffset = 0ULL;
    BOOL bNoErr = FALSE;
#endif
    INT i;
    PWSTR pszSuffix = NULL;
    NTSTATUS Status;

    if (CurrentDisk == NULL)
    {
        ConResPuts(StdOut, IDS_SELECT_NO_DISK);
        return EXIT_SUCCESS;
    }

    if (CurrentDisk->PartitionStyle == PARTITION_STYLE_GPT)
    {
        ConResPuts(StdOut, IDS_CREATE_PARTITION_INVALID_STYLE);
        return EXIT_SUCCESS;
    }

    for (i = 3; i < argc; i++)
    {
        if (_wcsicmp(argv[i], L"noerr") == 0)
        {
            /* noerr */
            DPRINT("NoErr\n", pszSuffix);
            return RefuseUnsupportedOption(L"NOERR");
        }
    }

    for (i = 3; i < argc; i++)
    {
        if (HasPrefix(argv[i], L"size=", &pszSuffix))
        {
            /* size=<N> (MB) */
            DPRINT("Size : %s\n", pszSuffix);

            ullSize = _wcstoui64(pszSuffix, NULL, 10);
            if ((ullSize == 0) && (errno == ERANGE))
            {
                ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
                return EXIT_SUCCESS;
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
            return EXIT_SUCCESS;
        }
    }

    DPRINT1("Size: %I64u\n", ullSize);
#if 0
    DPRINT1("Offset: %I64u\n", ullOffset);
#endif

    if (GetPrimaryPartitionCount(CurrentDisk) >= 4)
    {
        ConPuts(StdOut, L"No space left for an extended partition!\n");
        return EXIT_SUCCESS;
    }

    if (!CheckPartitionLayoutForChange(CurrentDisk))
        return EXIT_SUCCESS;

    if (CurrentDisk->ExtendedPartition != NULL)
    {
        ConPuts(StdOut, L"We already have an extended partition on this disk!\n");
        return EXIT_SUCCESS;
    }

    if (ullSize != 0)
        ullSectorCount = MegabytesToSectors(ullSize, CurrentDisk->BytesPerSector);
    else
        ullSectorCount = 0;

    DPRINT1("SectorCount: %I64u\n", ullSectorCount);

    ListEntry = CurrentDisk->PrimaryPartListHead.Blink;

    PartEntry = CONTAINING_RECORD(ListEntry, PARTENTRY, ListEntry);
    if (PartEntry->IsPartitioned)
    {
        ConPuts(StdOut, L"No disk space left for an extended partition!\n");
        return EXIT_SUCCESS;
    }

    if (ullSectorCount == 0)
    {
        PartEntry->IsPartitioned = TRUE;
        PartEntry->New = TRUE;
        PartEntry->Mbr.PartitionType = PARTITION_EXTENDED;
        PartEntry->FormatState = Unformatted;
        PartEntry->FileSystemName[0] = L'\0';

        CurrentPartition = PartEntry;
        CurrentDisk->Dirty = TRUE;
    }
    else
    {
        if (PartEntry->SectorCount.QuadPart == ullSectorCount)
        {
            PartEntry->IsPartitioned = TRUE;
            PartEntry->New = TRUE;
            PartEntry->Mbr.PartitionType = PARTITION_EXTENDED;
            PartEntry->FormatState = Unformatted;
            PartEntry->FileSystemName[0] = L'\0';

            CurrentPartition = PartEntry;
            CurrentDisk->Dirty = TRUE;
        }
        else if (PartEntry->SectorCount.QuadPart > ullSectorCount)
        {
            NewPartEntry = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PARTENTRY));
            if (NewPartEntry == NULL)
            {
                ConPuts(StdOut, L"Memory allocation failed!\n");
                return TRUE;
            }

            NewPartEntry->DiskEntry = PartEntry->DiskEntry;

            NewPartEntry->StartSector.QuadPart = PartEntry->StartSector.QuadPart;
            NewPartEntry->SectorCount.QuadPart = ullSectorCount;

            NewPartEntry->LogicalPartition = FALSE;
            NewPartEntry->IsPartitioned = TRUE;
            NewPartEntry->New = TRUE;
            NewPartEntry->Mbr.PartitionType = PARTITION_EXTENDED;
            NewPartEntry->FormatState = Unformatted;
            NewPartEntry->FileSystemName[0] = L'\0';

            PartEntry->StartSector.QuadPart += ullSectorCount;
            PartEntry->SectorCount.QuadPart -= ullSectorCount;

            InsertTailList(ListEntry, &NewPartEntry->ListEntry);

            CurrentPartition = NewPartEntry;
            CurrentDisk->Dirty = TRUE;
        }
    }

    UpdateMbrDiskLayout(CurrentDisk);
    Status = WriteMbrPartitions(CurrentDisk);
    if (!NT_SUCCESS(Status))
    {
        ConResPuts(StdOut, IDS_CREATE_PARTITION_FAIL);
        CurrentPartition = NULL;
        return EXIT_SUCCESS;
    }

    /* The new extended partition is the container of the logical partitions: make it known, with its free space, so
     * that "create partition logical" finds room in it without a rescan. */
    if (CurrentDisk->ExtendedPartition == NULL && CurrentPartition != NULL)
    {
        CurrentDisk->ExtendedPartition = CurrentPartition;
        if (IsListEmpty(&CurrentDisk->LogicalPartListHead))
            AddEmptyLogicalSpace(CurrentDisk);
    }

    ConResPuts(StdOut, IDS_CREATE_PARTITION_SUCCESS);

    return EXIT_SUCCESS;
}


EXIT_CODE
CreateLogicalPartition(
    _In_ INT argc,
    _In_ PWSTR *argv)
{
    PPARTENTRY PartEntry, NewPartEntry;
    PLIST_ENTRY ListEntry;
    ULONGLONG ullSize = 0ULL;
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

    if (CurrentDisk == NULL)
    {
        ConResPuts(StdOut, IDS_SELECT_NO_DISK);
        return EXIT_SUCCESS;
    }

    if (CurrentDisk->PartitionStyle != PARTITION_STYLE_MBR)
    {
        ConResPuts(StdOut, IDS_CREATE_PARTITION_INVALID_STYLE);
        return EXIT_SUCCESS;
    }

    if (!CheckPartitionLayoutForChange(CurrentDisk))
        return EXIT_SUCCESS;

    for (i = 3; i < argc; i++)
    {
        if (_wcsicmp(argv[i], L"noerr") == 0)
        {
            /* noerr */
            DPRINT("NoErr\n", pszSuffix);
            return RefuseUnsupportedOption(L"NOERR");
        }
    }

    for (i = 3; i < argc; i++)
    {
        if (HasPrefix(argv[i], L"size=", &pszSuffix))
        {
            /* size=<N> (MB) */
            DPRINT("Size : %s\n", pszSuffix);

            ullSize = _wcstoui64(pszSuffix, NULL, 10);
            if ((ullSize == 0) && (errno == ERANGE))
            {
                ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
                return EXIT_SUCCESS;
            }
        }
        else if (HasPrefix(argv[i], L"offset=", &pszSuffix))
        {
            /* offset=<N> (KB) */
            DPRINT("Offset : %s\n", pszSuffix);
            if (!ParseOffsetKilobytes(pszSuffix, CurrentDisk->BytesPerSector, &ullOffset))
            {
                ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
                return EXIT_SUCCESS;
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
                    return EXIT_SUCCESS;
                }
            }
            else
            {
                ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
                return EXIT_SUCCESS;
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
            return EXIT_SUCCESS;
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
     * First fit: every drive of the chain has its EBR in the alignment area in front of it. The
     * unpartitioned entry at the start of the extended partition begins behind the first EBR; any
     * other entry begins where the drive in front of it ends, so the new drive starts one alignment
     * later (else its EBR lands in the end of that drive: it was written over its data).
     */
    for (ListEntry = bOffset ? &CurrentDisk->LogicalPartListHead : CurrentDisk->LogicalPartListHead.Flink;
         ListEntry != &CurrentDisk->LogicalPartListHead;
         ListEntry = ListEntry->Flink)
    {
        ULONGLONG ullReserve, ullAvailable, ullLength;

        PartEntry = CONTAINING_RECORD(ListEntry, PARTENTRY, ListEntry);
        if (PartEntry->IsPartitioned)
            continue;

        ullReserve = (ListEntry->Blink != &CurrentDisk->LogicalPartListHead) ? CurrentDisk->SectorAlignment : 0;
        if (PartEntry->SectorCount.QuadPart <= ullReserve)
            continue;

        ullAvailable = PartEntry->SectorCount.QuadPart - ullReserve;
        ullLength = (ullSectorCount != 0) ? ullSectorCount : ullAvailable;
        if (ullLength > ullAvailable)
            continue;

        NewPartEntry = SplitFreeEntry(PartEntry, PartEntry->StartSector.QuadPart + ullReserve, ullLength);
        if (NewPartEntry == NULL)
        {
            ConPuts(StdOut, L"Memory allocation failed!\n");
            return EXIT_SUCCESS;
        }

        NewPartEntry->Mbr.PartitionType = PartitionType;
        CurrentPartition = NewPartEntry;
        CurrentDisk->Dirty = TRUE;
        break;
    }

    if (CurrentPartition == NULL)
    {
        /* No free space was large enough */
        ConResPuts(StdOut, IDS_CREATE_PARTITION_FAIL);
        return EXIT_SUCCESS;
    }

    UpdateMbrDiskLayout(CurrentDisk);
    Status = WriteMbrPartitions(CurrentDisk);
    if (!NT_SUCCESS(Status))
    {
        ConResPuts(StdOut, IDS_CREATE_PARTITION_FAIL);
        CurrentPartition = NULL;
        return EXIT_SUCCESS;
    }

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

    if (CurrentDisk == NULL)
    {
        ConResPuts(StdOut, IDS_SELECT_NO_DISK);
        return EXIT_SUCCESS;
    }

    if (CurrentDisk->PartitionStyle != PARTITION_STYLE_GPT)
    {
        ConResPuts(StdOut, IDS_CREATE_PARTITION_INVALID_STYLE);
        return EXIT_SUCCESS;
    }

    if (!CheckPartitionLayoutForChange(CurrentDisk))
        return EXIT_SUCCESS;

    if (!HasFreeGptSlot(CurrentDisk))
    {
        ConResPuts(StdOut, IDS_CREATE_PARTITION_TABLE_FULL);
        return EXIT_SUCCESS;
    }

    for (i = 3; i < argc; i++)
    {
        if (_wcsicmp(argv[i], L"noerr") == 0)
        {
            /* noerr */
            DPRINT("NoErr\n", pszSuffix);
            return RefuseUnsupportedOption(L"NOERR");
        }
    }

    for (i = 3; i < argc; i++)
    {
        if (HasPrefix(argv[i], L"size=", &pszSuffix))
        {
            /* size=<N> (MB) */
            DPRINT("Size : %s\n", pszSuffix);

            ullSize = _wcstoui64(pszSuffix, NULL, 10);
            if ((ullSize == 0) && (errno == ERANGE))
            {
                ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
                return EXIT_SUCCESS;
            }
        }
        else if (HasPrefix(argv[i], L"offset=", &pszSuffix))
        {
            /* offset=<N> (KB) */
            DPRINT("Offset : %s\n", pszSuffix);
            if (!ParseOffsetKilobytes(pszSuffix, CurrentDisk->BytesPerSector, &ullOffset))
            {
                ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
                return EXIT_SUCCESS;
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
            return EXIT_SUCCESS;
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
        return EXIT_SUCCESS;
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
        return EXIT_SUCCESS;
    }

    ConResPuts(StdOut, IDS_CREATE_PARTITION_SUCCESS);

    return EXIT_SUCCESS;
}


static
VOID
CreatePrimaryMbrPartition(
    _In_ ULONGLONG ullSize,
    _In_ PWSTR pszPartitionType,
    _In_ BOOLEAN bOffset,
    _In_ ULONGLONG ullOffset)
{
    PPARTENTRY PartEntry, NewPartEntry;
    PLIST_ENTRY ListEntry;
    ULONGLONG ullSectorCount;
    UCHAR PartitionType;
    INT length;
    NTSTATUS Status;

    if (!CheckPartitionLayoutForChange(CurrentDisk))
        return;

    if (pszPartitionType)
    {
        length = wcslen(pszPartitionType);
        if ((length != 1) && (length != 2))
        {
            ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
            return;
        }

        PartitionType = (UCHAR)wcstoul(pszPartitionType, NULL, 16);
        if ((PartitionType == 0) && (errno == ERANGE))
        {
            ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
            return;
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
        return;
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

    for (ListEntry = bOffset ? &CurrentDisk->PrimaryPartListHead : CurrentDisk->PrimaryPartListHead.Flink;
         ListEntry != &CurrentDisk->PrimaryPartListHead;
         ListEntry = ListEntry->Flink)
    {
        PartEntry = CONTAINING_RECORD(ListEntry, PARTENTRY, ListEntry);
        if (PartEntry->IsPartitioned)
            continue;

        if (ullSectorCount == 0)
        {
            PartEntry->IsPartitioned = TRUE;
            PartEntry->New = TRUE;
            PartEntry->Mbr.PartitionType = PartitionType;
            PartEntry->FormatState = Unformatted;
            PartEntry->FileSystemName[0] = L'\0';

            CurrentPartition = PartEntry;
            CurrentDisk->Dirty = TRUE;
            break;
        }
        else
        {
            if (PartEntry->SectorCount.QuadPart == ullSectorCount)
            {
                PartEntry->IsPartitioned = TRUE;
                PartEntry->New = TRUE;
                PartEntry->Mbr.PartitionType = PartitionType;
                PartEntry->FormatState = Unformatted;
                PartEntry->FileSystemName[0] = L'\0';

                CurrentPartition = PartEntry;
                CurrentDisk->Dirty = TRUE;
                break;
            }
            else if (PartEntry->SectorCount.QuadPart > ullSectorCount)
            {
                NewPartEntry = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PARTENTRY));
                if (NewPartEntry == NULL)
                {
                    ConPuts(StdOut, L"Memory allocation failed!\n");
                    return;
                }

                NewPartEntry->DiskEntry = PartEntry->DiskEntry;

                NewPartEntry->StartSector.QuadPart = PartEntry->StartSector.QuadPart;
                NewPartEntry->SectorCount.QuadPart = ullSectorCount;

                NewPartEntry->LogicalPartition = FALSE;
                NewPartEntry->IsPartitioned = TRUE;
                NewPartEntry->New = TRUE;
                NewPartEntry->Mbr.PartitionType = PartitionType;
                NewPartEntry->FormatState = Unformatted;
                NewPartEntry->FileSystemName[0] = L'\0';

                PartEntry->StartSector.QuadPart += ullSectorCount;
                PartEntry->SectorCount.QuadPart -= ullSectorCount;

                InsertTailList(ListEntry, &NewPartEntry->ListEntry);

                CurrentPartition = NewPartEntry;
                CurrentDisk->Dirty = TRUE;
                break;
            }
        }
    }

    if (CurrentPartition == NULL)
    {
        /* No free space was large enough */
        ConResPuts(StdOut, IDS_CREATE_PARTITION_FAIL);
        return;
    }

    UpdateMbrDiskLayout(CurrentDisk);
    Status = WriteMbrPartitions(CurrentDisk);
    if (!NT_SUCCESS(Status))
    {
        ConResPuts(StdOut, IDS_CREATE_PARTITION_FAIL);
        CurrentPartition = NULL;
        return;
    }

    ConResPuts(StdOut, IDS_CREATE_PARTITION_SUCCESS);

    SelectVolumeOfNewPartition(CurrentPartition);
}


static
VOID
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
        return;

    if (!HasFreeGptSlot(CurrentDisk))
    {
        ConResPuts(StdOut, IDS_CREATE_PARTITION_TABLE_FULL);
        return;
    }

    /* Partition Type */
    if (pszPartitionType)
    {
        if (!StringToGUID(&guidPartitionType, pszPartitionType))
        {
            ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
            return;
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
        return;
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
        return;
    }

    ConResPuts(StdOut, IDS_CREATE_PARTITION_SUCCESS);

    SelectVolumeOfNewPartition(CurrentPartition);
}


EXIT_CODE
CreatePrimaryPartition(
    _In_ INT argc,
    _In_ PWSTR *argv)
{
    ULONGLONG ullSize = 0ULL;
    ULONGLONG ullOffset = 0ULL;
    BOOLEAN bOffset = FALSE;
#if 0
    BOOL bNoErr = FALSE;
#endif
    INT i;
    PWSTR pszSuffix = NULL;
    PWSTR pszPartitionType = NULL;

    if (CurrentDisk == NULL)
    {
        ConResPuts(StdOut, IDS_SELECT_NO_DISK);
        return EXIT_SUCCESS;
    }

    for (i = 3; i < argc; i++)
    {
        if (_wcsicmp(argv[i], L"noerr") == 0)
        {
            /* noerr */
            DPRINT("NoErr\n", pszSuffix);
            return RefuseUnsupportedOption(L"NOERR");
        }
    }

    for (i = 3; i < argc; i++)
    {
        if (HasPrefix(argv[i], L"size=", &pszSuffix))
        {
            /* size=<N> (MB) */
            DPRINT("Size : %s\n", pszSuffix);

            ullSize = _wcstoui64(pszSuffix, NULL, 10);
            if ((ullSize == 0) && (errno == ERANGE))
            {
                ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
                return EXIT_SUCCESS;
            }
        }
        else if (HasPrefix(argv[i], L"offset=", &pszSuffix))
        {
            /* offset=<N> (KB) */
            DPRINT("Offset : %s\n", pszSuffix);
            if (!ParseOffsetKilobytes(pszSuffix, CurrentDisk->BytesPerSector, &ullOffset))
            {
                ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
                return EXIT_SUCCESS;
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
            return EXIT_SUCCESS;
        }
    }

    DPRINT("Size: %I64u\n", ullSize);
#if 0
    DPRINT1("Offset: %I64u\n", ullOffset);
#endif

    if (CurrentDisk->PartitionStyle == PARTITION_STYLE_MBR)
    {
        DPRINT("Partition Type: %s\n", pszPartitionType);
        CreatePrimaryMbrPartition(ullSize, pszPartitionType, bOffset, ullOffset);
    }
    else if (CurrentDisk->PartitionStyle == PARTITION_STYLE_GPT)
    {
        CreatePrimaryGptPartition(ullSize, pszPartitionType, bOffset, ullOffset);
    }
    else
    {
        /* RAW: no partition table was found on the disk. It is not initialized here: CONVERT does that */
        CheckPartitionLayoutForChange(CurrentDisk);
    }

    return EXIT_SUCCESS;
}
