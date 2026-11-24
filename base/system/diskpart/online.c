/*
 * PROJECT:         ReactOS DiskPart
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            base/system/diskpart/online.c
 * PURPOSE:         ONLINE VOLUME and OFFLINE VOLUME: the volume's offline state in the partition manager
 */

#include "diskpart.h"
#include "diskpart_msg.h"
#include <ntddvol.h>

#define NDEBUG
#include <debug.h>

/* Opens the device of a volume given as "\\?\Volume{guid}\" for the volume IOCTLs (they need read and write access) */
static HANDLE
OpenVolumeDevice(
    _In_ PCWSTR pszVolumeName,
    _In_ DWORD dwAccess)
{
    WCHAR szDevice[MAX_PATH];
    SIZE_T Length = wcslen(pszVolumeName);

    if (Length < 5 || Length >= ARRAYSIZE(szDevice))
        return INVALID_HANDLE_VALUE;
    StringCchCopyW(szDevice, ARRAYSIZE(szDevice), pszVolumeName);
    if (szDevice[Length - 1] == L'\\')
        szDevice[Length - 1] = UNICODE_NULL;
    return CreateFileW(szDevice, dwAccess, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING, 0, NULL);
}

BOOL
IsVolumeOffline(
    _In_ PCWSTR pszVolumeName)
{
    HANDLE hVolume;
    DWORD dwBytes;
    BOOL bOffline;

    hVolume = OpenVolumeDevice(pszVolumeName, 0);
    if (hVolume == INVALID_HANDLE_VALUE)
        return FALSE;
    /* the IOCTL succeeds for an offline volume and fails (ERROR_NOT_READY... as Windows: 31) for an online one */
    bOffline = DeviceIoControl(hVolume, IOCTL_VOLUME_IS_OFFLINE, NULL, 0, NULL, 0, &dwBytes, NULL);
    CloseHandle(hVolume);
    return bOffline;
}

/* Whether the volume can be reached by any path: a drive letter or a mounted folder (the offline command refuses these) */
static BOOL
VolumeHasAccessPath(
    _In_ PCWSTR pszVolumeName)
{
    WCHAR szPaths[MAX_PATH];
    DWORD dwLength = 0;

    if (GetVolumePathNamesForVolumeNameW(pszVolumeName, szPaths, ARRAYSIZE(szPaths), &dwLength))
        return szPaths[0] != UNICODE_NULL;
    /* too small a buffer still says there are paths */
    return GetLastError() == ERROR_MORE_DATA;
}

/*
 * The error levels, the texts and the order of the checks are those of the Windows Server 2022 DiskPart
 * (measured): invalid arguments are not hidden by noerr, nor is a missing volume for ONLINE (OFFLINE hides it);
 * a volume that still has an access path is refused by OFFLINE (hidden by noerr).
 */
static EXIT_CODE
SetVolumeOffline(
    _In_ INT argc,
    _In_ PWSTR *argv,
    _In_ BOOL bOffline)
{
    BOOLEAN bNoErr = FALSE;
    HANDLE hVolume;
    DWORD dwBytes;
    INT i;

    for (i = 2; i < argc; i++)
    {
        if (_wcsicmp(argv[i], L"noerr") == 0 && !bNoErr)
        {
            bNoErr = TRUE;
        }
        else
        {
            ConResPuts(StdOut, bOffline ? IDS_OFFLINE_BAD_ARGS : IDS_ONLINE_BAD_ARGS);
            return EXIT_CMD_FAILED;
        }
    }

    if (GetFocusVolume() == NULL)
    {
        ConResPuts(StdOut, bOffline ? IDS_OFFLINE_NO_VOLUME : IDS_ONLINE_NO_VOLUME);
        ConPuts(StdOut, L"\n");
        ConMsgPuts(StdOut,
                   FORMAT_MESSAGE_FROM_HMODULE,
                   NULL,
                   bOffline ? MSG_COMMAND_OFFLINE_VOLUME : MSG_COMMAND_ONLINE_VOLUME,
                   LANG_USER_DEFAULT);
        return bOffline ? FAIL_LEVEL(bNoErr, TRUE, EXIT_CMD_FAILED) : EXIT_CMD_FAILED;
    }

    if (bOffline && VolumeHasAccessPath(CurrentVolume->VolumeName))
    {
        ConResPuts(StdOut, IDS_OFFLINE_HAS_PATH);
        return FAIL_LEVEL(bNoErr, TRUE, EXIT_CMD_HAS_PATH);
    }

    hVolume = OpenVolumeDevice(CurrentVolume->VolumeName, GENERIC_READ | GENERIC_WRITE);
    if (hVolume == INVALID_HANDLE_VALUE ||
        !DeviceIoControl(hVolume, bOffline ? IOCTL_VOLUME_OFFLINE : IOCTL_VOLUME_ONLINE,
                         NULL, 0, NULL, 0, &dwBytes, NULL))
    {
        ConResPrintf(StdOut, IDS_ONLINE_OFFLINE_FAILED, GetLastError());
        if (hVolume != INVALID_HANDLE_VALUE)
            CloseHandle(hVolume);
        return FAIL_LEVEL(bNoErr, TRUE, EXIT_CMD_FAILED);
    }
    CloseHandle(hVolume);

    ConResPuts(StdOut, bOffline ? IDS_OFFLINE_VOLUME_SUCCESS : IDS_ONLINE_VOLUME_SUCCESS);
    return EXIT_SUCCESS;
}

/* ONLINE or OFFLINE without a known object: the list of what can be brought online / offline, and a failing level (measured) */
static EXIT_CODE
ListObjects(
    _In_ PCWSTR pszCommand)
{
    PCOMMAND pCmd;

    for (pCmd = cmds; pCmd->cmd1; pCmd++)
    {
        if (_wcsicmp(pCmd->cmd1, pszCommand) == 0 && pCmd->cmd2 == NULL)
        {
            HelpCommand(pCmd);
            break;
        }
    }
    return EXIT_CMD_FAILED;
}

EXIT_CODE
OnlineObject(
    _In_ INT argc,
    _In_ PWSTR *argv)
{
    return ListObjects(L"ONLINE");
}

EXIT_CODE
OfflineObject(
    _In_ INT argc,
    _In_ PWSTR *argv)
{
    return ListObjects(L"OFFLINE");
}

EXIT_CODE
OnlineVolume(
    _In_ INT argc,
    _In_ PWSTR *argv)
{
    return SetVolumeOffline(argc, argv, FALSE);
}

EXIT_CODE
OfflineVolume(
    _In_ INT argc,
    _In_ PWSTR *argv)
{
    return SetVolumeOffline(argc, argv, TRUE);
}
