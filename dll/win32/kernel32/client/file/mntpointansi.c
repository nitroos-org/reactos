/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            dll/win32/kernel32/client/file/mntpointansi.c
 * PURPOSE:         Volume mount point functions (ANSI)
 */

/* INCLUDES *****************************************************************/

#include <k32.h>

/* FUNCTIONS ****************************************************************/

/*
 * @implemented
 */
BOOL
WINAPI
GetVolumeNameForVolumeMountPointA(IN LPCSTR lpszVolumeMountPoint,
                                  IN LPSTR lpszVolumeName,
                                  IN DWORD cchBufferLength)
{
    BOOL Ret;
    ANSI_STRING VolumeName;
    UNICODE_STRING VolumeNameU;
    PUNICODE_STRING VolumeMountPointU;

    /* Convert mount point to unicode */
    VolumeMountPointU = Basep8BitStringToStaticUnicodeString(lpszVolumeMountPoint);
    if (VolumeMountPointU == NULL)
    {
        return FALSE;
    }

    /* Initialize the strings we'll use for convention */
    VolumeName.Buffer = lpszVolumeName;
    VolumeName.Length = 0;
    VolumeName.MaximumLength = cchBufferLength - 1;

    VolumeNameU.Length = 0;
    VolumeNameU.MaximumLength = (cchBufferLength - 1) * sizeof(WCHAR) + sizeof(UNICODE_NULL);
    /* Allocate a buffer big enough to contain the returned name */
    VolumeNameU.Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, VolumeNameU.MaximumLength);
    if (VolumeNameU.Buffer == NULL)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }

    /* Query -W */
    Ret = GetVolumeNameForVolumeMountPointW(VolumeMountPointU->Buffer, VolumeNameU.Buffer, cchBufferLength);
    /* If it succeed, perform -A conversion */
    if (Ret)
    {
        NTSTATUS Status;

        /* Reinit our string for length */
        RtlInitUnicodeString(&VolumeNameU, VolumeNameU.Buffer);
        /* Convert to ANSI */
        Status = RtlUnicodeStringToAnsiString(&VolumeName, &VolumeNameU, FALSE);
        /* If conversion failed, force failure, otherwise, just null terminate */
        if (!NT_SUCCESS(Status))
        {
            Ret = FALSE;
            BaseSetLastNTError(Status);
        }
        else
        {
            VolumeName.Buffer[VolumeName.Length] = ANSI_NULL;
        }
    }

    /* Internal buffer no longer needed */
    RtlFreeHeap(RtlGetProcessHeap(), 0, VolumeNameU.Buffer);

    return Ret;
}

/* EOF */

/*
 * @implemented
 */
BOOL
WINAPI
SetVolumeMountPointA(IN LPCSTR lpszVolumeMountPoint,
                     IN LPCSTR lpszVolumeName)
{
    BOOL Ret = FALSE;
    UNICODE_STRING MountPointU, VolumeNameU;

    if (lpszVolumeMountPoint == NULL || lpszVolumeName == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* the conversion follows SetFileApisToOEM, as in the other file functions */
    if (!Basep8BitStringToDynamicUnicodeString(&MountPointU, lpszVolumeMountPoint))
        return FALSE;
    if (Basep8BitStringToDynamicUnicodeString(&VolumeNameU, lpszVolumeName))
    {
        Ret = SetVolumeMountPointW(MountPointU.Buffer, VolumeNameU.Buffer);
        RtlFreeUnicodeString(&VolumeNameU);
    }
    RtlFreeUnicodeString(&MountPointU);
    return Ret;
}

/*
 * @implemented
 */
BOOL
WINAPI
DeleteVolumeMountPointA(IN LPCSTR lpszVolumeMountPoint)
{
    BOOL Ret;
    UNICODE_STRING MountPointU;

    /* the ANSI form names the missing path an invalid name, the wide form an invalid parameter */
    if (lpszVolumeMountPoint == NULL)
    {
        SetLastError(ERROR_INVALID_NAME);
        return FALSE;
    }

    if (!Basep8BitStringToDynamicUnicodeString(&MountPointU, lpszVolumeMountPoint))
        return FALSE;
    Ret = DeleteVolumeMountPointW(MountPointU.Buffer);
    RtlFreeUnicodeString(&MountPointU);
    return Ret;
}

/* The path found, converted for the ANSI caller; FALSE (and the last error) when it does not fit. */
static BOOL
BasepVolumeMountPointToAnsi(IN LPCWSTR Path, OUT LPSTR Buffer, IN DWORD cchBuffer)
{
    UNICODE_STRING PathU;
    ANSI_STRING PathA;
    NTSTATUS Status;

    RtlInitUnicodeString(&PathU, Path);
    PathA.Buffer = Buffer;
    PathA.Length = 0;
    PathA.MaximumLength = (USHORT)min(cchBuffer, MAXUSHORT);
    Status = RtlUnicodeStringToAnsiString(&PathA, &PathU, FALSE);
    if (!NT_SUCCESS(Status))
    {
        SetLastError(Status == STATUS_BUFFER_OVERFLOW ? ERROR_MORE_DATA : RtlNtStatusToDosError(Status));
        return FALSE;
    }
    Buffer[PathA.Length] = ANSI_NULL;
    return TRUE;
}

/*
 * @implemented
 */
HANDLE
WINAPI
FindFirstVolumeMountPointA(IN LPCSTR lpszRootPathName,
                           IN LPSTR lpszVolumeMountPoint,
                           IN DWORD cchBufferLength)
{
    UNICODE_STRING RootU;
    LPWSTR PathW;
    HANDLE Find = INVALID_HANDLE_VALUE;

    if (lpszRootPathName == NULL || lpszVolumeMountPoint == NULL || cchBufferLength == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }
    if (!Basep8BitStringToDynamicUnicodeString(&RootU, lpszRootPathName))
        return INVALID_HANDLE_VALUE;
    PathW = RtlAllocateHeap(RtlGetProcessHeap(), 0, cchBufferLength * sizeof(WCHAR));
    if (PathW == NULL)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    }
    else
    {
        Find = FindFirstVolumeMountPointW(RootU.Buffer, PathW, cchBufferLength);
        if (Find != INVALID_HANDLE_VALUE && !BasepVolumeMountPointToAnsi(PathW, lpszVolumeMountPoint, cchBufferLength))
        {
            FindVolumeMountPointClose(Find);
            Find = INVALID_HANDLE_VALUE;
        }
        RtlFreeHeap(RtlGetProcessHeap(), 0, PathW);
    }
    RtlFreeUnicodeString(&RootU);
    return Find;
}

/*
 * @implemented
 */
BOOL
WINAPI
FindNextVolumeMountPointA(IN HANDLE hFindVolumeMountPoint,
                          IN LPSTR lpszVolumeMountPoint,
                          DWORD cchBufferLength)
{
    LPWSTR PathW;
    BOOL Ret;

    if (hFindVolumeMountPoint == NULL || hFindVolumeMountPoint == INVALID_HANDLE_VALUE ||
        lpszVolumeMountPoint == NULL || cchBufferLength == 0)
        return FALSE;
    PathW = RtlAllocateHeap(RtlGetProcessHeap(), 0, cchBufferLength * sizeof(WCHAR));
    if (PathW == NULL)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    Ret = FindNextVolumeMountPointW(hFindVolumeMountPoint, PathW, cchBufferLength);
    if (Ret)
        Ret = BasepVolumeMountPointToAnsi(PathW, lpszVolumeMountPoint, cchBufferLength);
    RtlFreeHeap(RtlGetProcessHeap(), 0, PathW);
    return Ret;
}
