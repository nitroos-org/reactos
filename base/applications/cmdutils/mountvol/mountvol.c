/*
 * PROJECT:     ReactOS mountvol
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     List, create and delete volume mount points; mount manager auto-mount state
 * COPYRIGHT:   Copyright 2026 NitroOS contributors
 *
 * Written from the documented Win32 volume management functions and from
 * the output of the command on Windows (structure, exit codes, error
 * paths). Every error is the system message of the failing call.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windef.h>
#include <winbase.h>
#include <winioctl.h>
#include <winnls.h>
#include <winerror.h>
#include <mountmgr.h>

#include <conutils.h>

#define VOLUME_NAME_LENGTH  (MAX_PATH + 1)
#ifndef IOCTL_VOLUME_IS_OFFLINE
#define IOCTL_VOLUME_IS_OFFLINE   CTL_CODE(IOCTL_VOLUME_BASE, 4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

/* Print the system message of an error code, one line, to the standard output */
static VOID
PrintSystemError(DWORD Error)
{
    ConMsgPuts(StdOut,
               FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
               NULL,
               Error,
               LANG_USER_DEFAULT);
}

static VOID
PrintUsage(VOID)
{
    ConPuts(StdOut,
            L"Creates, deletes or lists a volume mount point.\n"
            L"\n"
            L"MOUNTVOL [drive:]path VolumeName\n"
            L"MOUNTVOL [drive:]path /D\n"
            L"MOUNTVOL [drive:]path /L\n"
            L"MOUNTVOL [drive:]path /P\n"
            L"MOUNTVOL /R\n"
            L"MOUNTVOL /N\n"
            L"MOUNTVOL /E\n"
            L"\n"
            L"    path        An existing, empty directory on an NTFS volume that is to\n"
            L"                hold the mount point.\n"
            L"    VolumeName  The name of the volume the mount point is to lead to.\n"
            L"    /D          Delete the mount point in the given directory.\n"
            L"    /L          Show the name of the volume the given mount point leads to.\n"
            L"    /P          Delete the mount point in the given directory, dismount the\n"
            L"                volume and take it out of use. A new mount point makes the\n"
            L"                volume available again.\n"
            L"    /R          Forget the mount points and settings kept for volumes that\n"
            L"                are not in the system any more.\n"
            L"    /N          Do not mount new volumes automatically.\n"
            L"    /E          Mount new volumes automatically again.\n"
            L"\n");
}

/* A volume is "not mountable" when its stack reports it as offline */
static BOOL
IsVolumeOffline(PCWSTR VolumeName)
{
    WCHAR Path[VOLUME_NAME_LENGTH];
    SIZE_T Length;
    HANDLE Volume;
    DWORD Returned;
    BOOL Offline;

    /* \\?\Volume{guid}\ -> \\.\Volume{guid} */
    Length = wcslen(VolumeName);
    if (Length < 5 || Length >= RTL_NUMBER_OF(Path))
        return FALSE;
    wcscpy(Path, VolumeName);
    if (Path[Length - 1] == L'\\')
        Path[Length - 1] = UNICODE_NULL;
    if (Path[0] == L'\\' && Path[1] == L'\\' && Path[2] == L'?')
        Path[2] = L'.';

    Volume = CreateFileW(Path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (Volume == INVALID_HANDLE_VALUE)
        return FALSE;
    Offline = DeviceIoControl(Volume, IOCTL_VOLUME_IS_OFFLINE, NULL, 0, NULL, 0, &Returned, NULL);
    CloseHandle(Volume);
    return Offline;
}

static VOID
PrintVolumeList(VOID)
{
    HANDLE Find;
    WCHAR Volume[VOLUME_NAME_LENGTH];
    PWCHAR Names, Name;
    DWORD Length;

    ConPuts(StdOut, L"Possible values for VolumeName along with current mount points are:\n\n");

    Find = FindFirstVolumeW(Volume, RTL_NUMBER_OF(Volume));
    if (Find == INVALID_HANDLE_VALUE)
        return;

    do
    {
        ConPrintf(StdOut, L"    %s\n", Volume);

        Names = NULL;
        Length = 0;
        GetVolumePathNamesForVolumeNameW(Volume, NULL, 0, &Length);
        if (Length > 1)
        {
            Names = HeapAlloc(GetProcessHeap(), 0, Length * sizeof(WCHAR));
            if (Names && !GetVolumePathNamesForVolumeNameW(Volume, Names, Length, &Length))
            {
                HeapFree(GetProcessHeap(), 0, Names);
                Names = NULL;
            }
        }

        if (Names && Names[0] != UNICODE_NULL)
        {
            for (Name = Names; *Name != UNICODE_NULL; Name += wcslen(Name) + 1)
                ConPrintf(StdOut, L"        %s\n", Name);
        }
        else if (IsVolumeOffline(Volume))
        {
            ConPuts(StdOut, L"        *** NOT MOUNTABLE UNTIL A VOLUME MOUNT POINT IS CREATED ***\n");
        }
        else
        {
            ConPuts(StdOut, L"        *** NO MOUNT POINTS ***\n");
        }
        ConPuts(StdOut, L"\n");

        if (Names)
            HeapFree(GetProcessHeap(), 0, Names);
    } while (FindNextVolumeW(Find, Volume, RTL_NUMBER_OF(Volume)));

    FindVolumeClose(Find);
}

/* Copy Arg into Out and make sure it ends in a backslash */
static BOOL
WithTrailingBackslash(PCWSTR Arg, PWSTR Out, SIZE_T OutCount)
{
    SIZE_T Length = wcslen(Arg);

    if (Length + 2 > OutCount)
        return FALSE;
    wcscpy(Out, Arg);
    if (Length == 0 || Out[Length - 1] != L'\\')
    {
        Out[Length++] = L'\\';
        Out[Length] = UNICODE_NULL;
    }
    return TRUE;
}

static HANDLE
OpenMountManager(DWORD Access)
{
    return CreateFileW(L"\\\\.\\MountPointManager",
                       Access,
                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL,
                       OPEN_EXISTING,
                       0,
                       NULL);
}

/* /N, /E and /R go to the mount manager */
static int
MountManagerCommand(WCHAR Switch)
{
    HANDLE Manager;
    MOUNTMGR_SET_AUTO_MOUNT SetState;
    DWORD Returned;
    BOOL Ok;

    Manager = OpenMountManager(GENERIC_READ | GENERIC_WRITE);
    if (Manager == INVALID_HANDLE_VALUE)
    {
        PrintSystemError(GetLastError());
        return 1;
    }

    if (Switch == L'R')
    {
        Ok = DeviceIoControl(Manager, IOCTL_MOUNTMGR_SCRUB_REGISTRY, NULL, 0, NULL, 0, &Returned, NULL);
    }
    else
    {
        SetState.NewState = (Switch == L'E') ? Enabled : Disabled;
        Ok = DeviceIoControl(Manager, IOCTL_MOUNTMGR_SET_AUTO_MOUNT,
                             &SetState, sizeof(SetState), NULL, 0, &Returned, NULL);
    }
    if (!Ok)
    {
        PrintSystemError(GetLastError());
        CloseHandle(Manager);
        return 1;
    }

    CloseHandle(Manager);
    return 0;
}

/* /P: the mount point must be the only one of its volume. The volume is
 * locked first so that a volume in use is left alone; then the mount point
 * goes away, the volume is dismounted and put offline. */
static int
RemoveAndDismount(PCWSTR MountPoint)
{
    WCHAR Volume[VOLUME_NAME_LENGTH];
    WCHAR Path[VOLUME_NAME_LENGTH];
    PWCHAR Names, Name;
    DWORD Length, Count, Returned, Error;
    HANDLE Handle;
    SIZE_T Len;

    if (!GetVolumeNameForVolumeMountPointW(MountPoint, Volume, RTL_NUMBER_OF(Volume)))
    {
        PrintSystemError(GetLastError());
        return 1;
    }

    Length = 0;
    Count = 0;
    GetVolumePathNamesForVolumeNameW(Volume, NULL, 0, &Length);
    if (Length > 1)
    {
        Names = HeapAlloc(GetProcessHeap(), 0, Length * sizeof(WCHAR));
        if (Names)
        {
            if (GetVolumePathNamesForVolumeNameW(Volume, Names, Length, &Length))
            {
                for (Name = Names; *Name != UNICODE_NULL; Name += wcslen(Name) + 1)
                    ++Count;
            }
            HeapFree(GetProcessHeap(), 0, Names);
        }
    }
    if (Count > 1)
    {
        ConPuts(StdOut,
                L"The /P option works only when the given mount point is the only mount point\n"
                L"of the volume.  Use /D instead.\n");
        return 1;
    }

    /* \\?\Volume{guid}\ -> \\.\Volume{guid} */
    Len = wcslen(Volume);
    wcscpy(Path, Volume);
    if (Len && Path[Len - 1] == L'\\')
        Path[Len - 1] = UNICODE_NULL;
    Path[2] = L'.';

    Handle = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL, OPEN_EXISTING, 0, NULL);
    if (Handle == INVALID_HANDLE_VALUE)
    {
        PrintSystemError(GetLastError());
        return 1;
    }
    if (!DeviceIoControl(Handle, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &Returned, NULL))
    {
        Error = GetLastError();
        CloseHandle(Handle);
        PrintSystemError(Error);
        return 1;
    }

    if (!DeleteVolumeMountPointW(MountPoint))
    {
        Error = GetLastError();
        DeviceIoControl(Handle, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &Returned, NULL);
        CloseHandle(Handle);
        PrintSystemError(Error);
        return 1;
    }

    if (!DeviceIoControl(Handle, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &Returned, NULL))
    {
        Error = GetLastError();
        CloseHandle(Handle);
        PrintSystemError(Error);
        return 1;
    }

    /* A stack without offline support just stays online: not an error */
    DeviceIoControl(Handle, IOCTL_VOLUME_OFFLINE, NULL, 0, NULL, 0, &Returned, NULL);
    CloseHandle(Handle);
    return 0;
}

int wmain(int argc, WCHAR *argv[])
{
    WCHAR MountPoint[VOLUME_NAME_LENGTH];
    WCHAR VolumeName[VOLUME_NAME_LENGTH];
    WCHAR Result[VOLUME_NAME_LENGTH];

    ConInitStdStreams();

    if (argc == 1)
    {
        PrintUsage();
        PrintVolumeList();
        return 0;
    }

    /* One argument: only /R, /N and /E mean something */
    if (argc == 2)
    {
        if (argv[1][0] == L'/' && argv[1][1] != UNICODE_NULL && argv[1][2] == UNICODE_NULL)
        {
            switch (argv[1][1])
            {
                case L'R': case L'r':
                    return MountManagerCommand(L'R');
                case L'N': case L'n':
                    return MountManagerCommand(L'N');
                case L'E': case L'e':
                    return MountManagerCommand(L'E');
            }
        }
        PrintUsage();
        PrintVolumeList();
        return 0;
    }

    if (argc != 3 || !WithTrailingBackslash(argv[1], MountPoint, RTL_NUMBER_OF(MountPoint)))
    {
        PrintUsage();
        PrintVolumeList();
        return 0;
    }

    /* [drive:]path /L, /D, /P */
    if (argv[2][0] == L'/' && argv[2][1] != UNICODE_NULL && argv[2][2] == UNICODE_NULL)
    {
        switch (argv[2][1])
        {
            case L'L': case L'l':
                if (!GetVolumeNameForVolumeMountPointW(MountPoint, Result, RTL_NUMBER_OF(Result)))
                {
                    PrintSystemError(GetLastError());
                    return 1;
                }
                ConPrintf(StdOut, L"    %s\n", Result);
                return 0;

            case L'D': case L'd':
                if (!DeleteVolumeMountPointW(MountPoint))
                {
                    PrintSystemError(GetLastError());
                    return 1;
                }
                return 0;

            case L'P': case L'p':
                return RemoveAndDismount(MountPoint);
        }
    }

    /* [drive:]path VolumeName */
    if (!WithTrailingBackslash(argv[2], VolumeName, RTL_NUMBER_OF(VolumeName)))
    {
        PrintUsage();
        PrintVolumeList();
        return 0;
    }
    if (!SetVolumeMountPointW(MountPoint, VolumeName))
    {
        PrintSystemError(GetLastError());
        return 1;
    }
    return 0;
}
