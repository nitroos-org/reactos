/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS FS utility tool
 * FILE:            base/applications/cmdutils/fsutil/volume.c
 * PURPOSE:         FSutil volumes management
 * PROGRAMMERS:     Pierre Schweitzer <pierre@reactos.org>
 */

#include "fsutil.h"

static int
LockOrUnlockVolume(HANDLE Volume, BOOLEAN Lock)
{
    DWORD Operation;
    ULONG BytesRead;

    Operation = (Lock ? FSCTL_LOCK_VOLUME : FSCTL_UNLOCK_VOLUME);
    if (DeviceIoControl(Volume, Operation, NULL, 0, NULL, 0,
                        &BytesRead, NULL) == FALSE)
    {
        PrintErrorMessage(GetLastError());
        return 1;
    }

    return 0;
}

int
VolumeDismountMain(int argc, const TCHAR *argv[])
{
    HANDLE Volume;
    ULONG BytesRead;

    if (argc != 2)
    {
        _tprintf(_T("Usage : fsutil volume dismount <volume pathname>\n"));
        _tprintf(_T("   Eg : fsutil volume dismount C:\n"));
        return (argc < 2) ? 0 : 1;
    }

    /* Only a drive letter (or a \\.\ path) names a volume here */
    if (argv[1][0] != 0 && argv[1][1] != _T(':') && !(argv[1][0] == _T('\\') && argv[1][1] == _T('\\')))
    {
        PrintErrorMessage(ERROR_INVALID_NAME);
        return 1;
    }

    /* Get a handle for the volume */
    Volume = OpenVolumeArg(argv[1], TRUE, GENERIC_READ, NOTE_LOCAL_VOLUME, NULL);
    if (Volume == INVALID_HANDLE_VALUE)
    {
        return 1;
    }

    /* Attempt to lock the volume */
    if (LockOrUnlockVolume(Volume, TRUE))
    {
        CloseHandle(Volume);
        return 1;
    }

    /* Issue the dismount command */
    if (DeviceIoControl(Volume, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL,
                        0, &BytesRead, NULL) == FALSE)
    {
        PrintErrorMessage(GetLastError());
        LockOrUnlockVolume(Volume, FALSE);
        CloseHandle(Volume);
        return 1;
    }

    /* Unlock and quit */
    LockOrUnlockVolume(Volume, FALSE);
    CloseHandle(Volume);

    /* TODO(oracle): the success text is not probed, state-changing */
    _tprintf(_T("Volume %s is dismounted\n"), argv[1]);

    return 0;
}

static void
PrintSpace(const TCHAR * Label, ULONGLONG Bytes)
{
    TCHAR Number[40], Size[40];

    FormatNumber(Bytes, Number);
    FormatSize(Bytes, 1, 0, Size);
    _tprintf(_T("%-24s: %s (%s)\n"), Label, Number, Size);
}

int
VolumeDiskFreeMain(int argc, const TCHAR *argv[])
{
    HANDLE Volume;
    BOOLEAN NoteShown, Failed;
    ULARGE_INTEGER FreeAvail, TotalNumber, TotalNumberFree;
    const TCHAR * Path;
    TCHAR Root[4];

    if (argc != 2)
    {
        _tprintf(_T("Usage : fsutil volume diskFree <volume pathname>\n"));
        _tprintf(_T("   Eg : fsutil volume diskFree C:\n"));
        return (argc < 2) ? 0 : 1;
    }

    /* Windows reports a missing drive, then still tries the space query (which fails, or for an
     * empty name gives the current drive); the result stays a failure */
    Failed = FALSE;
    Volume = OpenVolumeArg(argv[1], TRUE, GENERIC_READ, NOTE_LOCAL_NTFS_VOLUME, &NoteShown);
    if (Volume == INVALID_HANDLE_VALUE)
    {
        Failed = TRUE;
        if (!NoteShown)
        {
            return 1;
        }
    }
    else
    {
        CloseHandle(Volume);
    }

    /* Space of the volume holding the name */
    Path = argv[1];
    if (Path[0] == 0)
    {
        Path = NULL;
    }
    else if (Path[1] == _T(':'))
    {
        Root[0] = Path[0];
        Root[1] = _T(':');
        Root[2] = _T('\\');
        Root[3] = 0;
        Path = Root;
    }
    else if (Path[0] == _T('\\') && Path[1] == _T('\\') && Path[2] == _T('.') && Path[3] == _T('\\') && Path[5] == _T(':'))
    {
        Root[0] = Path[4];
        Root[1] = _T(':');
        Root[2] = _T('\\');
        Root[3] = 0;
        Path = Root;
    }

    if (!GetDiskFreeSpaceEx(Path, &FreeAvail, &TotalNumber, &TotalNumberFree))
    {
        PrintErrorMessage(GetLastError());
        return 1;
    }

    PrintSpace(_T("Total free bytes"), TotalNumberFree.QuadPart);
    PrintSpace(_T("Total bytes"), TotalNumber.QuadPart);
    PrintSpace(_T("Total quota free bytes"), FreeAvail.QuadPart);

    return Failed ? 1 : 0;
}

int
VolumeListMain(int argc, const TCHAR *argv[])
{
    HANDLE Find;
    TCHAR Volume[MAX_PATH];
    TCHAR * Names;
    TCHAR * Name;
    DWORD Length;

    if (argc > 1)
    {
        _tprintf(_T("Usage : fsutil volume list\n"));
        return 1;
    }

    Find = FindFirstVolume(Volume, RTL_NUMBER_OF(Volume));
    if (Find == INVALID_HANDLE_VALUE)
    {
        PrintErrorMessage(GetLastError());
        return 1;
    }

    _tprintf(_T("Possible volumes and current mount points are:\n\n"));

    do
    {
        _tprintf(_T("%s\n"), Volume);

        /* Every mount point of the volume */
        Length = 0;
        GetVolumePathNamesForVolumeName(Volume, NULL, 0, &Length);
        if (Length > 1)
        {
            Names = LocalAlloc(LPTR, Length * sizeof(TCHAR));
            if (Names != NULL)
            {
                if (GetVolumePathNamesForVolumeName(Volume, Names, Length, &Length))
                {
                    for (Name = Names; *Name != 0; Name += _tcslen(Name) + 1)
                    {
                        _tprintf(_T("%s\n"), Name);
                    }
                }
                LocalFree(Names);
            }
        }

        _tprintf(_T("\n"));
    } while (FindNextVolume(Find, Volume, RTL_NUMBER_OF(Volume)));

    FindVolumeClose(Find);

    return 0;
}
