/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS FS utility tool
 * FILE:            base/applications/cmdutils/fsutil/fsutil.c
 * PURPOSE:         FSutil main
 * PROGRAMMERS:     Pierre Schweitzer <pierre@reactos.org>
 */

#include "fsutil.h"

int
__cdecl
_tmain(int argc, const TCHAR *argv[])
{
    int i;

    /* Without a command, list them */
    if (argc < 2)
    {
        _fputts(TopListing, stdout);
        return 0;
    }

    for (i = 0; i < TopItemCount; ++i)
    {
        if (_tcsicmp(argv[1], TopItems[i].Command) == 0)
        {
            return TopItems[i].Handler(argc - 1, &argv[1]);
        }
    }

    _tprintf(_T("%s is an invalid parameter.\n"), argv[1]);
    _fputts(TopListing, stdout);
    return 1;
}
