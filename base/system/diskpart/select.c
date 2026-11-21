/*
 * PROJECT:         ReactOS DiskPart
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            base/system/diskpart/select.c
 * PURPOSE:         Manages all the partitions of the OS in an interactive way.
 * PROGRAMMERS:     Lee Schroeder
 */

#include "diskpart.h"

#define NDEBUG
#include <debug.h>

/* FUNCTIONS ******************************************************************/

EXIT_CODE
SelectDisk(
    _In_ INT argc,
    _In_ PWSTR *argv)
{
    PLIST_ENTRY Entry;
    PDISKENTRY DiskEntry;
    ULONG ulValue;

    DPRINT("Select Disk()\n");

    if (argc > 3)
    {
        ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
        return EXIT_SUCCESS;
    }

    if (argc == 2)
    {
        if (CurrentDisk == NULL)
            ConResPuts(StdOut, IDS_SELECT_NO_DISK);
        else
            ConResPrintf(StdOut, IDS_SELECT_DISK, CurrentDisk->DiskNumber);
        return EXIT_SUCCESS;
    }

    if (!_wcsicmp(argv[2], L"system"))
    {
        CurrentDisk = NULL;

        Entry = DiskListHead.Flink;
        DiskEntry = CONTAINING_RECORD(Entry, DISKENTRY, ListEntry);

        CurrentDisk = DiskEntry;
        CurrentPartition = NULL;
        CurrentVolume = NULL;
        ConResPrintf(StdOut, IDS_SELECT_DISK, CurrentDisk->DiskNumber);
        return EXIT_SUCCESS;
    }
    else if (!_wcsicmp(argv[2], L"next"))
    {
        if (CurrentDisk == NULL)
        {
            CurrentPartition = NULL;
            CurrentVolume = NULL;
            ConResPuts(StdErr, IDS_SELECT_DISK_ENUM_NO_START);
            return EXIT_SUCCESS;
        }

        if (CurrentDisk->ListEntry.Flink == &DiskListHead)
        {
            CurrentDisk = NULL;
            CurrentPartition = NULL;
            CurrentVolume = NULL;
            ConResPuts(StdErr, IDS_SELECT_DISK_ENUM_FINISHED);
            return EXIT_SUCCESS;
        }

        Entry = CurrentDisk->ListEntry.Flink;

        DiskEntry = CONTAINING_RECORD(Entry, DISKENTRY, ListEntry);

        CurrentDisk = DiskEntry;
        CurrentPartition = NULL;
        CurrentVolume = NULL;
        ConResPrintf(StdOut, IDS_SELECT_DISK, CurrentDisk->DiskNumber);
        return EXIT_SUCCESS;
    }
    else if (IsDecString(argv[2]))
    {
        ulValue = wcstoul(argv[2], NULL, 10);
        if ((ulValue == 0) && (errno == ERANGE))
        {
            ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
            return EXIT_SUCCESS;
        }

        /* The partition and volume of the disk selected before lose the focus too. */
        CurrentDisk = NULL;
        CurrentPartition = NULL;
        CurrentVolume = NULL;

        Entry = DiskListHead.Flink;
        while (Entry != &DiskListHead)
        {
            DiskEntry = CONTAINING_RECORD(Entry, DISKENTRY, ListEntry);

            if (DiskEntry->DiskNumber == ulValue)
            {
                CurrentDisk = DiskEntry;
                CurrentPartition = NULL;
                CurrentVolume = NULL;
                ConResPrintf(StdOut, IDS_SELECT_DISK, CurrentDisk->DiskNumber);
                return EXIT_SUCCESS;
            }

            Entry = Entry->Flink;
        }
    }
    else
    {
        ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
        return EXIT_SUCCESS;
    }

    ConResPuts(StdErr, IDS_SELECT_DISK_INVALID);
    return EXIT_SUCCESS;
}


EXIT_CODE
SelectPartition(
    _In_ INT argc,
    _In_ PWSTR *argv)
{
    PLIST_ENTRY Entry;
    PPARTENTRY PartEntry;
    ULONG ulValue;

    DPRINT("Select Partition()\n");

    if (argc > 3)
    {
        ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
        return EXIT_SUCCESS;
    }

    if (CurrentDisk == NULL)
    {
        ConResPuts(StdOut, IDS_SELECT_PARTITION_NO_DISK);
        return EXIT_SUCCESS;
    }

    if (argc == 2)
    {
        if (CurrentPartition == NULL)
            ConResPuts(StdOut, IDS_SELECT_NO_PARTITION);
        else
            ConResPrintf(StdOut, IDS_SELECT_PARTITION, GetPartitionDisplayNumber(CurrentPartition));
        return EXIT_SUCCESS;
    }

    if (!IsDecString(argv[2]))
    {
        ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
        return EXIT_SUCCESS;
    }

    ulValue = wcstoul(argv[2], NULL, 10);
    if ((ulValue == 0) && (errno == ERANGE))
    {
        ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
        return EXIT_SUCCESS;
    }

    /* The number of a partition is the one LIST PARTITION shows (see AssignPartitionNumbers), not its place in the list */
    AssignPartitionNumbers(CurrentDisk);

    {
        PLIST_ENTRY Heads[2];
        ULONG Which;

        Heads[0] = &CurrentDisk->PrimaryPartListHead;
        Heads[1] = (CurrentDisk->PartitionStyle == PARTITION_STYLE_MBR) ? &CurrentDisk->LogicalPartListHead : NULL;

        for (Which = 0; Which < 2; Which++)
        {
            if (Heads[Which] == NULL)
                continue;

            for (Entry = Heads[Which]->Flink; Entry != Heads[Which]; Entry = Entry->Flink)
            {
                PartEntry = CONTAINING_RECORD(Entry, PARTENTRY, ListEntry);

                if (CurrentDisk->PartitionStyle == PARTITION_STYLE_GPT)
                {
                    if (IsEqualGUID(&PartEntry->Gpt.PartitionType, &PARTITION_ENTRY_UNUSED_GUID))
                        continue;
                }
                else
                {
                    if (PartEntry->Mbr.PartitionType == PARTITION_ENTRY_UNUSED || IsContainerPartition(PartEntry->Mbr.PartitionType))
                        continue;
                }

                if (PartEntry->DisplayNumber == ulValue)
                {
                    CurrentPartition = PartEntry;
                    /* The partition's volume, if any, gets the focus too. */
                    CurrentVolume = GetVolumeFromPartition(PartEntry);
                    ConResPrintf(StdOut, IDS_SELECT_PARTITION, ulValue);
                    return EXIT_SUCCESS;
                }
            }
        }
    }

    ConResPuts(StdErr, IDS_SELECT_PARTITION_INVALID);
    return EXIT_SUCCESS;
}


static
VOID
SetVolumeFocus(
    _In_ PVOLENTRY VolumeEntry)
{
    CurrentVolume = VolumeEntry;
    /*
     * The partition of a basic volume, and its disk, get the focus too;
     * a volume without one leaves no partition selected.
     */
    CurrentPartition = GetPartitionForVolume(VolumeEntry);
    if (CurrentPartition != NULL)
    {
        CurrentDisk = CurrentPartition->DiskEntry;
    }
    else if (VolumeEntry->pExtents != NULL && VolumeEntry->pExtents->NumberOfDiskExtents != 0)
    {
        /* A volume on a disk without a matching partition: its (first) disk. */
        PLIST_ENTRY DiskListEntry;

        for (DiskListEntry = DiskListHead.Flink; DiskListEntry != &DiskListHead; DiskListEntry = DiskListEntry->Flink)
        {
            PDISKENTRY DiskEntry = CONTAINING_RECORD(DiskListEntry, DISKENTRY, ListEntry);

            if (DiskEntry->DiskNumber == VolumeEntry->pExtents->Extents[0].DiskNumber)
            {
                CurrentDisk = DiskEntry;
                break;
            }
        }
    }
}


EXIT_CODE
SelectVolume(
    _In_ INT argc,
    _In_ PWSTR *argv)
{
    PLIST_ENTRY Entry;
    PVOLENTRY VolumeEntry;
    ULONG ulValue;
    WCHAR DriveLetter;

    DPRINT("SelectVolume()\n");

    if (argc > 3)
    {
        ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
        return EXIT_SUCCESS;
    }

    if (argc == 2)
    {
        if (CurrentVolume == NULL)
            ConResPuts(StdOut, IDS_SELECT_NO_VOLUME);
        else
            ConResPrintf(StdOut, IDS_SELECT_VOLUME, CurrentVolume->VolumeNumber);
        return EXIT_SUCCESS;
    }

    DriveLetter = IsDriveLetter(argv[2]);
    if (DriveLetter != UNICODE_NULL)
    {
        CurrentVolume = NULL;

        Entry = VolumeListHead.Flink;
        while (Entry != &VolumeListHead)
        {
            VolumeEntry = CONTAINING_RECORD(Entry, VOLENTRY, ListEntry);

            if (towupper(VolumeEntry->DriveLetter) == towupper(DriveLetter))
            {
                SetVolumeFocus(VolumeEntry);
                ConResPrintf(StdOut, IDS_SELECT_VOLUME, CurrentVolume->VolumeNumber);
                return EXIT_SUCCESS;
            }

            Entry = Entry->Flink;
        }

        ConResPuts(StdErr, IDS_SELECT_VOLUME_INVALID);
        return EXIT_SUCCESS;
    }

    if (IsDecString(argv[2]))
    {
        ulValue = wcstoul(argv[2], NULL, 10);
        if ((ulValue == 0) && (errno == ERANGE))
        {
            ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
            return EXIT_SUCCESS;
        }

        CurrentVolume = NULL;

        Entry = VolumeListHead.Flink;
        while (Entry != &VolumeListHead)
        {
            VolumeEntry = CONTAINING_RECORD(Entry, VOLENTRY, ListEntry);

            if (VolumeEntry->VolumeNumber == ulValue)
            {
                SetVolumeFocus(VolumeEntry);
                ConResPrintf(StdOut, IDS_SELECT_VOLUME, CurrentVolume->VolumeNumber);
                return EXIT_SUCCESS;
            }

            Entry = Entry->Flink;
        }

        ConResPuts(StdErr, IDS_SELECT_VOLUME_INVALID);
        return EXIT_SUCCESS;
    }

    ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
    return EXIT_SUCCESS;
}
