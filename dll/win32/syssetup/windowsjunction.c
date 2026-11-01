/*
 * PROJECT:     ReactOS system setup
 * LICENSE:     GPL-2.0-or-later
 * PURPOSE:     Directory junction \Windows -> system directory on NTFS installs
 *
 * Many installers and scripts hard-code C:\Windows\... New installs go to \Windows (the
 * default), where this is a no-op. When the user chose another directory (e.g. \ReactOS),
 * setup keeps SystemRoot there and makes \Windows a mount-point reparse point to it, as
 * "mklink /J C:\Windows C:\ReactOS" would.  Nothing existing is touched: if
 * \Windows is already there (another Windows on the same volume, or a previous run of this
 * step) it is left alone.  Volumes without reparse points (FAT) are skipped.
 */
#include "precomp.h"
#include <winioctl.h>
#define NDEBUG
#include <debug.h>

#ifndef IO_REPARSE_TAG_MOUNT_POINT
#define IO_REPARSE_TAG_MOUNT_POINT 0xA0000003
#endif

typedef struct _JUNCTION_BUFFER
{
    ULONG ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    USHORT SubstituteNameOffset;
    USHORT SubstituteNameLength;
    USHORT PrintNameOffset;
    USHORT PrintNameLength;
    WCHAR PathBuffer[2 * (MAX_PATH + 4)];
} JUNCTION_BUFFER;

#define JUNCTION_HEADER 8   /* tag, data length, reserved */
#define JUNCTION_FIXED  8   /* the four name offsets and lengths */

BOOL
InitializeWindowsJunction(VOID)
{
    static const WCHAR NtPrefix[] = L"\\??\\";
    WCHAR szSystem[MAX_PATH], szRoot[4], szLink[MAX_PATH], szFs[MAX_PATH];
    JUNCTION_BUFFER Reparse;
    DWORD dwFlags, dwAttr, cbReturned;
    SIZE_T cchSystem, cbSub, cbPrint;
    HANDLE hLink;
    BOOL ret;

    cchSystem = GetWindowsDirectoryW(szSystem, ARRAYSIZE(szSystem));
    if (cchSystem < 4 || cchSystem >= ARRAYSIZE(szSystem) ||
        szSystem[1] != L':' || szSystem[2] != L'\\')
    {
        LogItem(NULL, L"\\Windows junction: system directory is not a drive path, skipped");
        return FALSE;
    }

    szRoot[0] = szSystem[0];
    szRoot[1] = L':';
    szRoot[2] = L'\\';
    szRoot[3] = UNICODE_NULL;
    wcscpy(szLink, szRoot);
    wcscat(szLink, L"Windows");

    if (!_wcsicmp(szSystem, szLink))
    {
        LogItem(NULL, L"\\Windows junction: system directory is already %s, nothing to do", szLink);
        return TRUE;
    }

    if (!GetVolumeInformationW(szRoot, NULL, 0, NULL, NULL, &dwFlags, szFs, ARRAYSIZE(szFs)))
    {
        LogItem(NULL, L"\\Windows junction: cannot query %s (error %lu), skipped", szRoot, GetLastError());
        return FALSE;
    }
    if (!(dwFlags & FILE_SUPPORTS_REPARSE_POINTS))
    {
        LogItem(NULL, L"\\Windows junction: %s is %s, which has no reparse points, skipped", szRoot, szFs);
        return TRUE;
    }

    /* An atomic test for "does not exist yet": never open or modify what is there. */
    if (!CreateDirectoryW(szLink, NULL))
    {
        if (GetLastError() == ERROR_ALREADY_EXISTS)
        {
            dwAttr = GetFileAttributesW(szLink);
            LogItem(NULL, L"\\Windows junction: %s already exists (attributes 0x%lx), left untouched",
                    szLink, dwAttr);
            return TRUE;
        }
        LogItem(NULL, L"\\Windows junction: cannot create %s (error %lu)", szLink, GetLastError());
        return FALSE;
    }

    /* Substitute name \??\C:\ReactOS, print name C:\ReactOS, both NUL-terminated, like mklink /J */
    cbSub = (ARRAYSIZE(NtPrefix) - 1 + cchSystem) * sizeof(WCHAR);
    cbPrint = cchSystem * sizeof(WCHAR);
    RtlZeroMemory(&Reparse, sizeof(Reparse));
    Reparse.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    Reparse.SubstituteNameOffset = 0;
    Reparse.SubstituteNameLength = (USHORT)cbSub;
    Reparse.PrintNameOffset = (USHORT)(cbSub + sizeof(WCHAR));
    Reparse.PrintNameLength = (USHORT)cbPrint;
    wcscpy(Reparse.PathBuffer, NtPrefix);
    wcscat(Reparse.PathBuffer, szSystem);
    wcscpy((PWSTR)((PUCHAR)Reparse.PathBuffer + Reparse.PrintNameOffset), szSystem);
    Reparse.ReparseDataLength = (USHORT)(JUNCTION_FIXED + cbSub + cbPrint + 2 * sizeof(WCHAR));

    ret = FALSE;
    SetLastError(ERROR_SUCCESS);
    hLink = CreateFileW(szLink, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (hLink != INVALID_HANDLE_VALUE)
    {
        ret = DeviceIoControl(hLink, FSCTL_SET_REPARSE_POINT, &Reparse,
                              JUNCTION_HEADER + Reparse.ReparseDataLength, NULL, 0, &cbReturned, NULL);
        if (!ret)
            DPRINT1("FSCTL_SET_REPARSE_POINT failed (error %lu)\n", GetLastError());
        CloseHandle(hLink);
    }

    if (!ret)
    {
        DWORD dwError = GetLastError();
        /* We created it a moment ago and it is empty: do not leave a plain directory behind. */
        RemoveDirectoryW(szLink);
        LogItem(NULL, L"\\Windows junction: cannot make %s a junction to %s (error %lu)",
                szLink, szSystem, dwError);
        return FALSE;
    }

    LogItem(NULL, L"\\Windows junction: created %s -> %s", szLink, szSystem);
    return TRUE;
}
