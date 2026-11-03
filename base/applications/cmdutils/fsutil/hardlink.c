/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS FS utility tool
 * FILE:            base/applications/cmdutils/fsutil/hardlink.c
 * PURPOSE:         FSutil hard links handling
 * PROGRAMMERS:     Pierre Schweitzer <pierre@reactos.org>
 */

#include "fsutil.h"

int
HardLinkCreateMain(int argc, const TCHAR *argv[])
{
    /* We need a source and a destination */
    if (argc != 3)
    {
        _tprintf(_T("Usage : fsutil hardlink create <new filename> <existing filename>\n"));
        _tprintf(_T("   Eg : fsutil hardlink create c:\\foo.txt c:\\bar.txt\n"));
        return (argc < 2) ? 0 : 1;
    }

    /* Simply delegate to kernel32 */
    if (!CreateHardLink(argv[1], argv[2], NULL))
    {
        PrintErrorMessage(GetLastError());
        return 1;
    }

    /* Print the status (TODO(oracle): the success text is not probed, state-changing) */
    _tprintf(_T("Hardlink created for %s <<===>> %s\n"), argv[1], argv[2]);

    return 0;
}
