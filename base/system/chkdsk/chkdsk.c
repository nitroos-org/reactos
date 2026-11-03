//======================================================================
//
// Chkdskx
//
// Copyright (c) 1998 Mark Russinovich
// Systems Internals
// http://www.sysinternals.com
//
// Chkdsk clone that demonstrates the use of the FMIFS file system
// utility library.
//
// --------------------------------------------------------------------
//
// This software is free software; you can redistribute it and/or
// modify it under the terms of the GNU Library General Public License as
// published by the Free Software Foundation; either version 2 of the
// License, or (at your option) any later version.
//
// This software is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Library General Public License for more details.
//
// You should have received a copy of the GNU Library General Public
// License along with this software; see the file COPYING.LIB. If
// not, write to the Free Software Foundation, Inc., 675 Mass Ave,
// Cambridge, MA 02139, USA.
//
// --------------------------------------------------------------------
//
// 1999 February (Emanuele Aliberti)
//      Adapted for ReactOS and lcc-win32.
//
// 1999 April (Emanuele Aliberti)
//      Adapted for ReactOS and egcs.
//
// 2008 July (Aleksey Bragin)
//      Cleanup, use ReactOS's fmifs.h
//
//======================================================================

#include <stdio.h>

/* PSDK/NDK Headers */
#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <wincon.h>
#include <winreg.h>
#include <winioctl.h>

#include <conutils.h>

/* Resource header */
#include "resource.h"

#define NTOS_MODE_USER
#include <ndk/ntndk.h>

/* FMIFS Public Header */
#include <fmifs/fmifs.h>

/* NtfsChkdsk's results besides failures (see ntfslib.h) */
#define NTFSCHK_STATUS_CORRECTED ((NTSTATUS)0x20000A01)
#define NTFSCHK_STATUS_ERRORS    ((NTSTATUS)0xE0000A03)

#define FMIFS_IMPORT_DLL

//
// Globals
//
BOOL    Error = FALSE;
BOOL    Corrected = FALSE;

// Switches
BOOL    FixErrors = FALSE;
BOOL    SkipClean = FALSE;
BOOL    ScanSectors = FALSE;
BOOL    Verbose = FALSE;
PWCHAR  Drive = NULL;
WCHAR   CurrentDirectory[1024];

#ifndef FMIFS_IMPORT_DLL
//
// Functions in FMIFS.DLL
//
PCHKDSK Chkdsk;
#endif


//----------------------------------------------------------------------
//
// PrintWin32Error
//
// Takes the win32 error code and prints the text version.
//
//----------------------------------------------------------------------
static VOID PrintWin32Error(UINT Message, DWORD ErrorCode)
{
    ConResPuts(StdErr, Message);
    ConMsgPuts(StdErr, FORMAT_MESSAGE_FROM_SYSTEM,
               NULL, ErrorCode, LANG_USER_DEFAULT);
    ConPuts(StdErr, L"\n");
}


//--------------------------------------------------------------------
//
// CtrlCIntercept
//
// Intercepts Ctrl-C's so that the program can't be quit with the
// disk in an inconsistent state.
//
//--------------------------------------------------------------------
BOOL
WINAPI
CtrlCIntercept(DWORD dwCtrlType)
{
    //
    // Handle the event so that the default handler doesn't
    //
    return TRUE;
}


//----------------------------------------------------------------------
//
// Usage
//
// Tell the user how to use the program
//
//----------------------------------------------------------------------
static VOID
Usage(PWCHAR ProgramName)
{
    ConResPrintf(StdOut, IDS_USAGE, ProgramName);
}


//----------------------------------------------------------------------
//
// ParseCommandLine
//
// Get the switches.
//
//----------------------------------------------------------------------
static int
ParseCommandLine(int argc, WCHAR *argv[])
{
    int i;
    BOOLEAN gotFix = FALSE;
    BOOLEAN gotVerbose = FALSE;
    BOOLEAN gotClean = FALSE;
    // BOOLEAN gotScan = FALSE;

    for (i = 1; i < argc; i++)
    {
        switch (argv[i][0])
        {
            case L'-': case L'/':

                switch (argv[i][1])
                {
                    case L'?':
                        return -1;

                    case L'F': case L'f':
                    {
                        if (gotFix) return i;
                        FixErrors = TRUE;
                        gotFix = TRUE;
                        break;
                    }

                    case L'V': case L'v':
                    {
                        if (gotVerbose) return i;
                        Verbose = TRUE;
                        gotVerbose = TRUE;
                        break;
                    }

                    case L'R': case L'r':
                    {
                        if (gotFix) return i;
                        ScanSectors = TRUE;
                        gotFix = TRUE;
                        break;
                    }

                    case L'C': case L'c':
                    {
                        if (gotClean) return i;
                        SkipClean = TRUE;
                        gotClean = TRUE;
                        break;
                    }

                    default:
                        return i;
                }
                break;

            default:
            {
                if (Drive) return i;
                if (argv[i][1] != L':') return i;

                Drive = argv[i];
                break;
            }
        }
    }
    return 0;
}



//----------------------------------------------------------------------
//
// ScheduleCheck
//
// As Windows, for a volume that cannot be locked (the system volume, or one with open
// files): ask whether to check it at the next restart.  Yes marks the volume dirty (the
// NTFS-NG driver keeps the flag until a check has run) and adds "autocheck autochk /r <volume>"
// to BootExecute, which autochk removes after the check.
//
//----------------------------------------------------------------------
static BOOL
ScheduleCheck(VOID)
{
    WCHAR vol[16], entry[64], *buf, *p;
    HANDLE h;
    HKEY key;
    DWORD type, size = 0, n, cb;
    BOOL ok = FALSE;

    swprintf(vol, L"\\\\.\\%C:", Drive[0]);
    h = CreateFileW(vol, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (h != INVALID_HANDLE_VALUE)
    {
        DeviceIoControl(h, FSCTL_MARK_VOLUME_DIRTY, NULL, 0, NULL, 0, &n, NULL);
        CloseHandle(h);
    }
    swprintf(entry, L"autocheck autochk /r \\??\\%C:", Drive[0]);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager", 0,
                      KEY_QUERY_VALUE | KEY_SET_VALUE, &key) != ERROR_SUCCESS)
        return FALSE;
    if (RegQueryValueExW(key, L"BootExecute", NULL, &type, NULL, &size) != ERROR_SUCCESS || type != REG_MULTI_SZ)
        size = sizeof(WCHAR);
    buf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size + (wcslen(entry) + 2) * sizeof(WCHAR));
    if (buf)
    {
        cb = size;
        if (RegQueryValueExW(key, L"BootExecute", NULL, &type, (LPBYTE)buf, &cb) != ERROR_SUCCESS || type != REG_MULTI_SZ)
            buf[0] = buf[1] = 0;
        for (p = buf; *p; p += wcslen(p) + 1)
            if (!_wcsicmp(p, entry))
                break;
        if (!*p)
        {
            /* p is at the final terminator: append the entry and a new terminator */
            wcscpy(p, entry);
            p += wcslen(entry) + 1;
            *p = 0;
        }
        ok = RegSetValueExW(key, L"BootExecute", 0, REG_MULTI_SZ, (LPBYTE)buf,
                            (DWORD)((p + 1 - buf) * sizeof(WCHAR))) == ERROR_SUCCESS;
        HeapFree(GetProcessHeap(), 0, buf);
    }
    RegCloseKey(key);
    return ok;
}

//----------------------------------------------------------------------
//
// ChkdskCallback
//
// The file system library will call us back with commands that we
// can interpret. If we wanted to halt the chkdsk we could return FALSE.
//
//----------------------------------------------------------------------
BOOLEAN
WINAPI
ChkdskCallback(
    CALLBACKCOMMAND Command,
    DWORD       Modifier,
    PVOID       Argument)
{
    BOOLEAN     Ret;
    PDWORD      percent;
    PBOOLEAN    status;
    PTEXTOUTPUT output;

    //
    // We get other types of commands,
    // but we don't have to pay attention to them
    //
    Ret = TRUE;
    switch (Command)
    {
        case UNKNOWN2:
            ConPuts(StdOut, L"UNKNOWN2\r");
            break;

        case UNKNOWN3:
            ConPuts(StdOut, L"UNKNOWN3\n");
            break;

        case UNKNOWN4:
            ConPuts(StdOut, L"UNKNOWN4\n");
            break;

        case UNKNOWN5:
            ConPuts(StdOut, L"UNKNOWN5\n");
            break;

        case FSNOTSUPPORTED:
            ConPuts(StdOut, L"FSNOTSUPPORTED\n");
            break;

        case VOLUMEINUSE:
            ConResPuts(StdOut, IDS_VOLUME_IN_USE);
            Ret = FALSE;
            break;

        case UNKNOWN9:
            ConPuts(StdOut, L"UNKNOWN9\n");
            break;

        case UNKNOWNA:
            ConPuts(StdOut, L"UNKNOWNA\n");
            break;

        case UNKNOWNC:
            ConPuts(StdOut, L"UNKNOWNC\n");
            break;

        case UNKNOWND:
            ConPuts(StdOut, L"UNKNOWND\n");
            break;

        case INSUFFICIENTRIGHTS:
            ConPuts(StdOut, L"INSUFFICIENTRIGHTS\n");
            break;

        case STRUCTUREPROGRESS:
            ConPuts(StdOut, L"STRUCTUREPROGRESS\n");
            break;

        case DONEWITHSTRUCTURE:
            ConPuts(StdOut, L"DONEWITHSTRUCTURE\n");
            break;

        case CLUSTERSIZETOOSMALL:
            ConPuts(StdOut, L"CLUSTERSIZETOOSMALL\n");
            break;

        case PROGRESS:
            percent = (PDWORD)Argument;
            ConResPrintf(StdOut, IDS_PERCENT_COMPL, *percent);
            break;

        case OUTPUT:
            output = (PTEXTOUTPUT)Argument;
            ConPrintf(StdOut, L"%S", output->Output);
            break;

        case DONE:
            status = (PBOOLEAN)Argument;
            if (*status && Modifier == NTFSCHK_STATUS_CORRECTED)
            {
                /* Errors were found and fixed: the text is printed, the exit code is 1. */
                Corrected = TRUE;
            }
            else if (*status == FALSE && Modifier == NTFSCHK_STATUS_ERRORS)
            {
                /* Errors were found and not fixed: the text is printed, the exit code is 3. */
                Error = TRUE;
            }
            else if (*status == FALSE)
            {
                ConResPrintf(StdOut, IDS_CHKDSK_FAIL, Modifier);
                if (Modifier == STATUS_DISK_CORRUPT_ERROR)
                    ConResPuts(StdOut, IDS_RUN_AGAIN);
                else
                    ConPrintf(StdOut, L"\n");
                Error = TRUE;
            }
            break;
    }
    return Ret;
}

#ifndef FMIFS_IMPORT_DLL
//----------------------------------------------------------------------
//
// LoadFMIFSEntryPoints
//
// Loads FMIFS.DLL and locates the entry point(s) we are going to use
//
//----------------------------------------------------------------------
static BOOLEAN
LoadFMIFSEntryPoints(VOID)
{
    HMODULE hFmifs = LoadLibraryW(L"fmifs.dll");
    if (hFmifs == NULL)
        return FALSE;

    Chkdsk = (PCHKDSK)GetProcAddress(hFmifs, "Chkdsk");
    if (!Chkdsk)
    {
        FreeLibrary(hFmifs);
        return FALSE;
    }

    return TRUE;
}
#endif


//----------------------------------------------------------------------
//
// WMain
//
// Engine. Just get command line switches and fire off a chkdsk. This
// could also be done in a GUI like Explorer does when you select a
// drive and run a check on it.
//
// We do this in UNICODE because the chkdsk command expects PWCHAR
// arguments.
//
//----------------------------------------------------------------------
int
wmain(int argc, WCHAR *argv[])
{
    int badArg;
    HANDLE volumeHandle;
    WCHAR  fileSystem[1024];
    WCHAR  volumeName[1024];
    DWORD  serialNumber;
    DWORD  flags, maxComponent;

    /* Initialize the Console Standard Streams */
    ConInitStdStreams();

    /* Windows' chkdsk prints no banner. */

#ifndef FMIFS_IMPORT_DLL
    //
    // Get function pointers
    //
    if (!LoadFMIFSEntryPoints())
    {
        ConResPuts(StdErr, IDS_NO_ENTRY_POINT);
        return -1;
    }
#endif

    //
    // Parse command line
    //
    badArg = ParseCommandLine(argc, argv);
    if (badArg == -1)
    {
        /* Windows chkdsk also exits with 3 after the help text */
        Usage(argv[0]);
        return 3;
    }
    if (badArg)
    {
        ConResPrintf(StdOut, IDS_BAD_ARGUMENT, argv[badArg]);
        Usage(argv[0]);
        return -1;
    }

    //
    // Get the drive's format
    //
    if (!Drive)
    {
        if (!GetCurrentDirectoryW(ARRAYSIZE(CurrentDirectory), CurrentDirectory))
        {
            PrintWin32Error(IDS_NO_CURRENT_DIR, GetLastError());
            return -1;
        }
    }
    else
    {
        wcscpy(CurrentDirectory, Drive);
    }
    CurrentDirectory[2] = L'\\';
    CurrentDirectory[3] = L'\0';
    Drive = CurrentDirectory;

    //
    // Determine the drive's file system format, which we need to
    // tell chkdsk
    //
    if (!GetVolumeInformationW(Drive,
                               volumeName,
                               ARRAYSIZE(volumeName),
                               &serialNumber,
                               &maxComponent,
                               &flags,
                               fileSystem,
                               ARRAYSIZE(fileSystem)))
    {
        PrintWin32Error(IDS_NO_QUERY_VOL, GetLastError());
        return -1;
    }

    //
    // If they want to fix, we need to have access to the drive
    //
    if (FixErrors)
    {
        swprintf(volumeName, L"\\\\.\\%C:", Drive[0]);
        /* As Windows: the volume must be lockable (no open files); the lock is only a test, the check
         * itself runs under the file system's own lock. */
        volumeHandle = CreateFileW(volumeName,
                                   GENERIC_READ | GENERIC_WRITE,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   NULL,
                                   OPEN_EXISTING,
                                   0,
                                   0);
        if (volumeHandle != INVALID_HANDLE_VALUE)
        {
            DWORD ret;
            if (!DeviceIoControl(volumeHandle, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &ret, NULL))
            {
                CloseHandle(volumeHandle);
                volumeHandle = INVALID_HANDLE_VALUE;
            }
            else
            {
                DeviceIoControl(volumeHandle, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &ret, NULL);
            }
        }
        if (volumeHandle == INVALID_HANDLE_VALUE)
        {
            /* Windows: cannot lock; offer to check at the next restart (Y/N). */
            WCHAR answer[16] = L"";
            ConResPuts(StdOut, IDS_CANNOT_LOCK);
            ConResPuts(StdOut, IDS_SCHEDULE_PROMPT);
            fflush(stdout);
            if (fgetws(answer, ARRAYSIZE(answer), stdin) && (answer[0] == L'Y' || answer[0] == L'y'))
            {
                DWORD mode;
                if (!GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode))
                    ConPuts(StdOut, L"Y\n");
                if (ScheduleCheck())
                    ConResPuts(StdOut, IDS_SCHEDULED);
                else
                    ConResPuts(StdErr, IDS_SCHEDULE_FAILED);
            }
            else if (answer[0])
            {
                DWORD mode;
                if (!GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode))
                    ConPuts(StdOut, L"N\n");
            }
            return 3;
        }
        CloseHandle(volumeHandle);

        //
        // Can't let the user break out of a chkdsk that can modify the drive
        //
        SetConsoleCtrlHandler(CtrlCIntercept, TRUE);
    }

    //
    // Just do it
    //
    ConResPrintf(StdOut, IDS_FILE_SYSTEM, fileSystem, Drive);
    Chkdsk(Drive,
           fileSystem,
           FixErrors,
           Verbose,
           SkipClean,
           ScanSectors,
           NULL,
           NULL,
           ChkdskCallback);

    /* As Windows: 0 no errors, 1 errors found and fixed, 3 errors not fixed or the check could not run. */
    if (Error) return 3;
    if (Corrected) return 1;
    return 0;
}

/* EOF */
