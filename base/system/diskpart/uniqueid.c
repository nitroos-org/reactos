/*
 * PROJECT:         ReactOS DiskPart
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            base/system/diskpart/uniqueid.c
 * PURPOSE:         Manages all the partitions of the OS in an interactive way.
 * PROGRAMMERS:     Lee Schroeder
 */

#include "diskpart.h"

#define NDEBUG
#include <debug.h>

/* FUNCTIONS ******************************************************************/

EXIT_CODE
UniqueIdDisk(
    _In_ INT argc,
    _In_ PWSTR *argv)
{
    WCHAR szBuffer[40];
    PWSTR pszSuffix, pszId = NULL;
    INT i;
    ULONG ulValue;
    BOOLEAN bNoErr = ArgsHaveNoErr(argc, argv);

    /* the level of a failure in a script (Windows Server 2022): 0x80070057 for an id that is not valid, which noerr hides */
    if (CurrentDisk == NULL)
    {
        ConResPuts(StdOut, IDS_SELECT_NO_DISK);
        return FAIL_LEVEL(bNoErr, TRUE, EXIT_CMD_FAILED);
    }

    if (argc == 2)
    {
        ConPuts(StdOut, L"\n");
        if (CurrentDisk->LayoutBuffer->PartitionStyle == PARTITION_STYLE_GPT)
            PrintGUID(szBuffer, &CurrentDisk->LayoutBuffer->Gpt.DiskId);
        else if (CurrentDisk->LayoutBuffer->PartitionStyle == PARTITION_STYLE_MBR)
            _swprintf(szBuffer, L"%08lx", CurrentDisk->LayoutBuffer->Mbr.Signature);
        else
            wcscpy(szBuffer, L"00000000");
        ConPrintf(StdOut, L"Disk ID: %s\n", szBuffer);
        ConPuts(StdOut, L"\n");
        return EXIT_SUCCESS;
    }

    /* "uniqueid disk id=<id>", with noerr after it */
    if (argc != 3 && !(argc == 4 && bNoErr))
    {
        ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
        return EXIT_CMD_FAILED;
    }

    for (i = 2; i < argc; i++)
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
        else
        {
            ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
            return EXIT_CMD_FAILED;
        }
    }

    if (pszId == NULL)
    {
        ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
        return EXIT_CMD_FAILED;
    }

    if (!CheckPartitionLayoutForChange(CurrentDisk))
        return EXIT_CMD_FAILED;

    if (CurrentDisk->PartitionStyle == PARTITION_STYLE_GPT)
    {
        if (!StringToGUID(&CurrentDisk->LayoutBuffer->Gpt.DiskId, pszId))
        {
            ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
            return FAIL_LEVEL(bNoErr, TRUE, EXIT_CMD_FAILED);
        }

        CurrentDisk->Dirty = TRUE;
        UpdateGptDiskLayout(CurrentDisk, FALSE);
        WriteGptPartitions(CurrentDisk);
    }
    else if (CurrentDisk->PartitionStyle == PARTITION_STYLE_MBR)
    {
        if ((pszId == NULL) ||
            (wcslen(pszId) != 8) ||
            (IsHexString(pszId) == FALSE))
        {
            ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
            return FAIL_LEVEL(bNoErr, TRUE, EXIT_CMD_FAILED);
        }

        ulValue = wcstoul(pszId, NULL, 16);
        if ((ulValue == 0) && (errno == ERANGE))
        {
            ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
            return FAIL_LEVEL(bNoErr, TRUE, EXIT_CMD_FAILED);
        }

        DPRINT("New Signature: 0x%08lx\n", ulValue);
        CurrentDisk->LayoutBuffer->Mbr.Signature = ulValue;
        CurrentDisk->Dirty = TRUE;
        UpdateMbrDiskLayout(CurrentDisk);
        WriteMbrPartitions(CurrentDisk);
    }
    else
    {
        ConResPuts(StdOut, IDS_UNIQUID_DISK_INVALID_STYLE);
    }

    return EXIT_SUCCESS;
}
