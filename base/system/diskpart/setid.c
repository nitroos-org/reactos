/*
 * PROJECT:         ReactOS DiskPart
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            base/system/diskpart/setid.c
 * PURPOSE:         Manages all the partitions of the OS in an interactive way.
 * PROGRAMMERS:     Lee Schroeder
 */

#include "diskpart.h"

#define NDEBUG
#include <debug.h>


EXIT_CODE
setid_main(
    _In_ INT argc,
    _In_ PWSTR *argv)
{
    INT i, length;
    PWSTR pszSuffix, pszId = NULL;
    NTSTATUS Status;
    BOOLEAN bNoErr = ArgsHaveNoErr(argc, argv);

    DPRINT("SetId()\n");

    /* the level of a failure in a script (Windows Server 2022): 0x80070057, which noerr does NOT hide when no partition is selected
       and does hide for an id that is not valid; 0x80042565 for a type that is a Virtual Disk Service error (set id=42), hidden */
    if (CurrentDisk == NULL)
    {
        ConResPuts(StdOut, IDS_SELECT_NO_DISK);
        return EXIT_CMD_FAILED;
    }

    if (CurrentPartition == NULL)
    {
        ConResPuts(StdOut, IDS_SELECT_NO_PARTITION);
        return EXIT_CMD_FAILED;
    }

    for (i = 1; i < argc; i++)
    {
        if (HasPrefix(argv[i], L"id=", &pszSuffix))
        {
            /* id=<Byte>|<GUID> */
            DPRINT("ID : %s\n", pszSuffix);
            pszId = pszSuffix;
        }
        else if (_wcsicmp(argv[i], L"noerr") == 0)
        {
            /* noerr: hides the failures that Windows hides (see FAIL_LEVEL) */
        }
        else if (_wcsicmp(argv[i], L"override") == 0)
        {
            /* override: the Windows DiskPart takes it and sets the id (measured: set id=07 override); no check of this program
               needs it overridden, so it changes nothing here */
            DPRINT("OVERRIDE\n");
        }
        else
        {
            ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
            return EXIT_CMD_FAILED;
        }
    }

    /* no id= : the arguments are not valid */
    if (pszId == NULL)
    {
        ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
        return EXIT_CMD_FAILED;
    }

    if (!CheckPartitionLayoutForChange(CurrentDisk))
        return EXIT_CMD_FAILED;

    if (CurrentDisk->PartitionStyle == PARTITION_STYLE_GPT)
    {
        if (!StringToGUID(&CurrentPartition->Gpt.PartitionType, pszId))
        {
            ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
            return FAIL_LEVEL(bNoErr, TRUE, EXIT_CMD_FAILED);
        }

        CurrentDisk->Dirty = TRUE;
        UpdateGptDiskLayout(CurrentDisk, FALSE);
        Status = WriteGptPartitions(CurrentDisk);
        if (!NT_SUCCESS(Status))
        {
            ConResPuts(StdOut, IDS_SETID_FAIL);
            return EXIT_SUCCESS;
        }
    }
    else if (CurrentDisk->PartitionStyle == PARTITION_STYLE_MBR)
    {
        UCHAR PartitionType = 0;

        length = wcslen(pszId);
        if (length == 0)
        {
            ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
            return EXIT_CMD_FAILED;
        }

        if (length > 2 || !IsHexString(pszId))
        {
            ConResPuts(StdErr, IDS_SETID_INVALID_FORMAT);
            return FAIL_LEVEL(bNoErr, TRUE, EXIT_CMD_FAILED);
        }

        PartitionType = (UCHAR)wcstoul(pszSuffix, NULL, 16);
        /* type 0 is the unused entry of the table: not a type (measured: 0 and 00 are refused as a format error) */
        if (PartitionType == 0)
        {
            ConResPuts(StdErr, IDS_SETID_INVALID_FORMAT);
            return FAIL_LEVEL(bNoErr, TRUE, EXIT_CMD_FAILED);
        }

        if (PartitionType == 0x42)
        {
            ConResPuts(StdErr, IDS_SETID_INVALID_TYPE);
            return FAIL_LEVEL(bNoErr, TRUE, EXIT_CMD_BAD_TYPE);
        }

        CurrentPartition->Mbr.PartitionType = PartitionType;
        CurrentDisk->Dirty = TRUE;
        UpdateMbrDiskLayout(CurrentDisk);
        Status = WriteMbrPartitions(CurrentDisk);
        if (!NT_SUCCESS(Status))
        {
            ConResPuts(StdOut, IDS_SETID_FAIL);
            return EXIT_SUCCESS;
        }
    }

    ConResPuts(StdOut, IDS_SETID_SUCCESS);

    return EXIT_SUCCESS;
}
