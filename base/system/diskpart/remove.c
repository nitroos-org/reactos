/*
 * PROJECT:         ReactOS DiskPart
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            base/system/diskpart/remove.c
 * PURPOSE:         Manages all the partitions of the OS in an interactive way.
 * PROGRAMMERS:     Lee Schroeder
 */

#include "diskpart.h"

#define NDEBUG
#include <debug.h>

EXIT_CODE
remove_main(
    _In_ INT argc,
    _In_ PWSTR *argv)
{
    PWSTR pszSuffix = NULL;
    WCHAR DriveLetter = UNICODE_NULL;
    INT i, nExclusive = 0;
    BOOL bResult;
    BOOLEAN bNoErr = ArgsHaveNoErr(argc, argv);

    DPRINT("remove_main()\n");

    /* the level of a failure in a script (Windows Server 2022): 0x80070057 for no volume (noerr hides it) and for invalid
       arguments (not hidden), 0x80042416 for a letter the volume does not have */
    if (GetFocusVolume() == NULL)
    {
        ConResPuts(StdOut, IDS_SELECT_NO_VOLUME);
        return FAIL_LEVEL(bNoErr, TRUE, EXIT_CMD_FAILED);
    }

    if (CurrentVolume->DriveLetter == UNICODE_NULL)
    {
        ConResPuts(StdOut, IDS_REMOVE_NO_LETTER);
        return EXIT_SUCCESS;
    }

    for (i = 1; i < argc; i++)
    {
        if (HasPrefix(argv[i], L"letter=", &pszSuffix))
        {
            if (wcslen(pszSuffix) == 1)
            {
                DriveLetter = towupper(*pszSuffix);
                nExclusive++;
            }
            else
            {
                ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
                return EXIT_CMD_FAILED;
            }
        }
        else if (HasPrefix(argv[i], L"mount=", &pszSuffix))
        {
            DPRINT("Mount\n", pszSuffix);
            return RefuseUnsupportedOption(L"MOUNT");
        }
        else if (_wcsicmp(argv[i], L"all") == 0)
        {
            /* all: every drive letter and mount point; this system has the drive letter only, the one that is removed below */
            nExclusive++;
        }
        else if (_wcsicmp(argv[i], L"dismount") == 0)
        {
            return RefuseUnsupportedOption(L"DISMOUNT");
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

    if (CurrentVolume->IsBoot || CurrentVolume->IsSystem)
    {
        ConResPuts(StdOut, IDS_ASSIGN_SYSTEM_VOLUME);
        return EXIT_SUCCESS;
    }

    if (nExclusive > 1)
    {
        ConResPuts(StdErr, IDS_ERROR_INVALID_ARGS);
        return EXIT_CMD_FAILED;
    }

    DPRINT("VolumeName: %S\n", CurrentVolume->VolumeName);
    DPRINT("DeviceName: %S\n", CurrentVolume->DeviceName);
    DPRINT("DriveLetter: %C\n", CurrentVolume->DriveLetter);

    if (DriveLetter != UNICODE_NULL)
    {
        DPRINT1("DriveLetter: %C\n", DriveLetter);

        if ((DriveLetter < L'C') || (DriveLetter > L'Z'))
        {
            ConResPuts(StdOut, IDS_ASSIGN_INVALID_LETTER);
            return EXIT_CMD_FAILED;
        }

        if (DriveLetter != CurrentVolume->DriveLetter)
        {
            ConResPuts(StdOut, IDS_REMOVE_WRONG_LETTER);
            return FAIL_LEVEL(bNoErr, TRUE, EXIT_CMD_NOT_FOUND);
        }
    }
    else
    {
        DriveLetter = CurrentVolume->DriveLetter;
    }

    bResult = DeleteDriveLetter(DriveLetter);
    if (bResult == FALSE)
    {
        ConResPuts(StdOut, IDS_REMOVE_FAIL);
        return EXIT_SUCCESS;
    }

    CurrentVolume->DriveLetter = UNICODE_NULL;
    ConResPuts(StdOut, IDS_REMOVE_SUCCESS);

    return EXIT_SUCCESS;
}
