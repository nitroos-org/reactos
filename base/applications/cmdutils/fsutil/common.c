/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS FS utility tool
 * FILE:            base/applications/cmdutils/fsutil/common.c
 * PURPOSE:         FSutil common functions
 * PROGRAMMERS:     Pierre Schweitzer <pierre@reactos.org>
 */

#include "fsutil.h"

int
RunGroup(int argc,
         const TCHAR *argv[],
         const TCHAR * Listing,
         HandlerItem * List,
         int Count)
{
    int i;

    /* No command, or "help": list the commands */
    if (argc < 2 || _tcsicmp(argv[1], _T("help")) == 0)
    {
        _fputts(Listing, stdout);
        return 0;
    }

    for (i = 0; i < Count; ++i)
    {
        if (_tcsicmp(argv[1], List[i].Command) == 0)
        {
            if (List[i].Handler == NULL)
            {
                return NotImplementedMain(argv[0], argv[1]);
            }

            return List[i].Handler(argc - 1, &argv[1]);
        }
    }

    _tprintf(_T("%s is an invalid parameter.\n"), argv[1]);
    _fputts(Listing, stdout);
    return 1;
}

int
NotImplementedMain(const TCHAR * Group, const TCHAR * Command)
{
    if (Command != NULL)
    {
        _ftprintf(stderr, _T("fsutil %s %s is not implemented.\n"), Group, Command);
    }
    else
    {
        _ftprintf(stderr, _T("fsutil %s is not implemented.\n"), Group);
    }

    return 1;
}

static BOOLEAN
IsMissingDrive(const TCHAR * Arg)
{
    if (Arg[0] == 0)
    {
        return TRUE;
    }

    if (Arg[1] == _T(':'))
    {
        UINT Type;
        TCHAR Root[4];

        Root[0] = Arg[0];
        Root[1] = _T(':');
        Root[2] = _T('\\');
        Root[3] = 0;
        Type = GetDriveType(Root);
        return (Type == DRIVE_NO_ROOT_DIR || Type == DRIVE_UNKNOWN);
    }

    return FALSE;
}

HANDLE
OpenVolumeArg(const TCHAR * Volume,
              BOOLEAN Lenient,
              DWORD Access,
              const TCHAR * Note,
              BOOLEAN * NoteShown)
{
    HANDLE hVolume;
    DWORD Error;
    TCHAR VolumeID[MAX_PATH + 8];

    if (NoteShown != NULL)
    {
        *NoteShown = FALSE;
    }

    if (Volume[0] == _T('\\') && Volume[1] == _T('\\'))
    {
        _sntprintf(VolumeID, RTL_NUMBER_OF(VolumeID), _T("%s"), Volume);
    }
    else if (Lenient && Volume[0] != 0 && Volume[1] == _T(':'))
    {
        _sntprintf(VolumeID, RTL_NUMBER_OF(VolumeID), _T("\\\\.\\%c:"), Volume[0]);
    }
    else
    {
        _sntprintf(VolumeID, RTL_NUMBER_OF(VolumeID), _T("\\\\.\\%s"), Volume);
    }
    VolumeID[RTL_NUMBER_OF(VolumeID) - 1] = 0;

    /* A network drive is not acceptable (TODO(oracle): not testable on the oracle) */
    if (Note != NULL && Volume[0] != 0 && Volume[1] == _T(':'))
    {
        TCHAR Root[4] = { Volume[0], _T(':'), _T('\\'), 0 };

        if (GetDriveType(Root) == DRIVE_REMOTE)
        {
            _tprintf(_T("%s\n"), Note);
            if (NoteShown != NULL)
            {
                *NoteShown = TRUE;
            }
            SetLastError(ERROR_NOT_SUPPORTED);
            return INVALID_HANDLE_VALUE;
        }
    }

    hVolume = CreateFile(VolumeID, Access, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hVolume == INVALID_HANDLE_VALUE)
    {
        Error = GetLastError();
        /* \\.\Q:\ (trailing backslash) on a missing drive: Windows reports ERROR_FILE_NOT_FOUND,
         * the path form of the error is not what its fsutil prints */
        if (Error == ERROR_PATH_NOT_FOUND && IsMissingDrive(Volume))
        {
            Error = ERROR_FILE_NOT_FOUND;
        }
        PrintErrorMessage(Error);
        if (Note != NULL && IsMissingDrive(Volume))
        {
            _tprintf(_T("%s\n"), Note);
            if (NoteShown != NULL)
            {
                *NoteShown = TRUE;
            }
        }
        SetLastError(Error);
    }

    return hVolume;
}

int
PrintErrorMessage(DWORD Error)
{
    TCHAR * String;

    /* Try to get textual error */
    if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                      NULL, Error, 0, (TCHAR *)&String, 0, NULL) != 0)
    {
        size_t Len = _tcslen(String);

        /* The message ends with CRLF, we add our own line end */
        while (Len > 0 && (String[Len - 1] == _T('\r') || String[Len - 1] == _T('\n')))
        {
            String[--Len] = 0;
        }

        _tprintf(_T("Error:  %s\n"), String);
        LocalFree(String);
    }
    else
    {
        /* Otherwise, just print the error number */
        _tprintf(_T("Error:  %lu\n"), Error);
    }

    return Error;
}

void
FormatNumber(ULONGLONG Value, TCHAR * Buffer)
{
    TCHAR Digits[32];
    int Len, i, Pos;

    _sntprintf(Digits, RTL_NUMBER_OF(Digits), _T("%I64u"), Value);
    Len = (int)_tcslen(Digits);

    Pos = 0;
    for (i = 0; i < Len; ++i)
    {
        if (i > 0 && ((Len - i) % 3) == 0)
        {
            Buffer[Pos++] = _T(',');
        }
        Buffer[Pos++] = Digits[i];
    }
    Buffer[Pos] = 0;
}

void
FormatSize(ULONGLONG Bytes, int Decimals, int Width, TCHAR * Buffer)
{
    static const TCHAR * const Units[] = { _T("KB"), _T("MB"), _T("GB"), _T("TB"), _T("PB"), _T("EB") };
    double Value = (double)Bytes / 1024.0;
    int Unit = 0;

    while (Value >= 1024.0 && Unit < 5)
    {
        Value /= 1024.0;
        ++Unit;
    }

    _stprintf(Buffer, _T("%*.*f %s"), Width, Decimals, Value, Units[Unit]);
}
