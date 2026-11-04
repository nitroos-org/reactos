/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS FS utility tool
 * FILE:            base/applications/cmdutils/fsutil/dirty.c
 * PURPOSE:         FSutil dirty bit handling
 * PROGRAMMERS:     Pierre Schweitzer <pierre@reactos.org>
 */

#include "fsutil.h"

int
DirtyQueryMain(int argc, const TCHAR *argv[])
{
    HANDLE Volume;
    ULONG VolumeStatus, BytesRead;

    /* We need exactly one volume: no argument is a plain usage, too many is a failure */
    if (argc != 2)
    {
        _tprintf(_T("Usage : fsutil dirty query <volume pathname>\n"));
        _tprintf(_T("   Eg : fsutil dirty query  C:\n"));
        return (argc < 2) ? 0 : 1;
    }

    /* Get a handle for the volume */
    Volume = OpenVolumeArg(argv[1], FALSE, GENERIC_READ, NOTE_LOCAL_VOLUME, NULL);
    if (Volume == INVALID_HANDLE_VALUE)
    {
        return 1;
    }

    /* And query the dirty status */
    if (DeviceIoControl(Volume, FSCTL_IS_VOLUME_DIRTY, NULL, 0, &VolumeStatus,
                        sizeof(ULONG), &BytesRead, NULL) == FALSE)
    {
        PrintErrorMessage(GetLastError());
        CloseHandle(Volume);
        return 1;
    }

    CloseHandle(Volume);

    /* Print the status */
    _tprintf(_T("Volume - %s is %s\n"), argv[1], ((VolumeStatus & VOLUME_IS_DIRTY) ? _T("Dirty") : _T("NOT Dirty")));

    return 0;
}

int
DirtySetMain(int argc, const TCHAR *argv[])
{
    HANDLE Volume;
    DWORD BytesRead;

    if (argc != 2)
    {
        _tprintf(_T("Usage : fsutil dirty set <volume pathname>\n"));
        _tprintf(_T("   Eg : fsutil dirty set C:\n"));
        return (argc < 2) ? 0 : 1;
    }

    /* Get a handle for the volume */
    Volume = OpenVolumeArg(argv[1], FALSE, GENERIC_READ, NOTE_LOCAL_VOLUME, NULL);
    if (Volume == INVALID_HANDLE_VALUE)
    {
        return 1;
    }

    /* And set the dirty bit */
    if (DeviceIoControl(Volume, FSCTL_MARK_VOLUME_DIRTY, NULL, 0, NULL, 0, &BytesRead, NULL) == FALSE)
    {
        PrintErrorMessage(GetLastError());
        CloseHandle(Volume);
        return 1;
    }

    CloseHandle(Volume);

    /* Print the status (TODO(oracle): the success text is not probed, state-changing) */
    _tprintf(_T("Volume - %s is now marked dirty\n"), argv[1]);

    return 0;
}
