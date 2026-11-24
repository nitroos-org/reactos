/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            dll/win32/kernel32/client/file/mntpoint.c
 * PURPOSE:         File volume mount point functions
 * PROGRAMMER:      Pierre Schweitzer (pierre@reactos.org)
 */

#include <k32.h>
#define NDEBUG
#include <debug.h>

/*
 * @implemented
 */
static BOOL
GetVolumeNameForRoot(IN LPCWSTR lpszRootPath,
                     OUT LPWSTR lpszVolumeName,
                     IN DWORD cchBufferLength)
{
    BOOL Ret;
    NTSTATUS Status;
    PWSTR FoundVolume;
    DWORD BytesReturned;
    UNICODE_STRING NtPathName;
    IO_STATUS_BLOCK IoStatusBlock;
    PMOUNTMGR_MOUNT_POINT MountPoint;
    ULONG CurrentMntPt, FoundVolumeLen;
    PMOUNTMGR_MOUNT_POINTS MountPoints;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE VolumeHandle, MountMgrHandle;
    struct
    {
        MOUNTDEV_NAME;
        WCHAR Buffer[MAX_PATH];
    } MountDevName;

    /* It makes no sense on a non-local drive */
    if (GetDriveTypeW(lpszRootPath) == DRIVE_REMOTE)
    {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return FALSE;
    }

    /* Get the NT path */
    if (!RtlDosPathNameToNtPathName_U(lpszRootPath, &NtPathName, NULL, NULL))
    {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return FALSE;
    }

    /* If it's a root path - likely - drop backslash to open volume */
    if (NtPathName.Buffer[(NtPathName.Length / sizeof(WCHAR)) - 1] == L'\\')
    {
        NtPathName.Buffer[(NtPathName.Length / sizeof(WCHAR)) - 1] = UNICODE_NULL;
        NtPathName.Length -= sizeof(WCHAR);
    }

    /* If that's a DOS volume, upper case the letter */
    if (NtPathName.Length >= 2 * sizeof(WCHAR))
    {
        if (NtPathName.Buffer[(NtPathName.Length / sizeof(WCHAR)) - 1] == L':')
        {
            NtPathName.Buffer[(NtPathName.Length / sizeof(WCHAR)) - 2] = towupper(NtPathName.Buffer[(NtPathName.Length / sizeof(WCHAR)) - 2]);
        }
    }

    /* Attempt to open the volume */
    InitializeObjectAttributes(&ObjectAttributes, &NtPathName,
                               OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenFile(&VolumeHandle, SYNCHRONIZE | FILE_READ_ATTRIBUTES,
                        &ObjectAttributes, &IoStatusBlock,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        FILE_SYNCHRONOUS_IO_ALERT);
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, NtPathName.Buffer);
        BaseSetLastNTError(Status);
        return FALSE;
    }

    /* Query the device name - that's what we'll translate */
    if (!DeviceIoControl(VolumeHandle, IOCTL_MOUNTDEV_QUERY_DEVICE_NAME, NULL,
                         0, &MountDevName, sizeof(MountDevName), &BytesReturned,
                         NULL))
    {
        NtClose(VolumeHandle);
        RtlFreeHeap(RtlGetProcessHeap(), 0, NtPathName.Buffer);
        return FALSE;
    }

    /* No longer need the volume */
    NtClose(VolumeHandle);
    RtlFreeHeap(RtlGetProcessHeap(), 0, NtPathName.Buffer);

    /* We'll keep the device name for later usage */
    NtPathName.Length = MountDevName.NameLength;
    NtPathName.MaximumLength = MountDevName.NameLength + sizeof(UNICODE_NULL);
    NtPathName.Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, NtPathName.MaximumLength);
    if (NtPathName.Buffer == NULL)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }

    RtlCopyMemory(NtPathName.Buffer, MountDevName.Name, NtPathName.Length);
    NtPathName.Buffer[NtPathName.Length / sizeof(WCHAR)] = UNICODE_NULL;

    /* Allocate the structure for querying the mount mgr */
    MountPoint = RtlAllocateHeap(RtlGetProcessHeap(), 0,
                                 NtPathName.Length + sizeof(MOUNTMGR_MOUNT_POINT));
    if (MountPoint == NULL)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, NtPathName.Buffer);
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }

    /* 0 everything, we provide a device name */
    RtlZeroMemory(MountPoint, sizeof(MOUNTMGR_MOUNT_POINT));
    MountPoint->DeviceNameOffset = sizeof(MOUNTMGR_MOUNT_POINT);
    MountPoint->DeviceNameLength = NtPathName.Length;
    RtlCopyMemory((PVOID)((ULONG_PTR)MountPoint + sizeof(MOUNTMGR_MOUNT_POINT)), NtPathName.Buffer, NtPathName.Length);

    /* Allocate a dummy output buffer to probe for size */
    MountPoints = RtlAllocateHeap(RtlGetProcessHeap(), 0, sizeof(MOUNTMGR_MOUNT_POINTS));
    if (MountPoints == NULL)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, NtPathName.Buffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, MountPoint);
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }

    /* Open a handle to the mount manager */
    MountMgrHandle = CreateFileW(MOUNTMGR_DOS_DEVICE_NAME, 0,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                                 INVALID_HANDLE_VALUE);
    if (MountMgrHandle == INVALID_HANDLE_VALUE)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, NtPathName.Buffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, MountPoints);
        RtlFreeHeap(RtlGetProcessHeap(), 0, MountPoint);
        return FALSE;
    }

    /* Query the names associated to our device name */
    Ret = DeviceIoControl(MountMgrHandle, IOCTL_MOUNTMGR_QUERY_POINTS,
                          MountPoint, NtPathName.Length + sizeof(MOUNTMGR_MOUNT_POINT),
                          MountPoints, sizeof(MOUNTMGR_MOUNT_POINTS), &BytesReturned,
                          NULL);
    /* As long as the buffer is too small, keep looping */
    while (!Ret && GetLastError() == ERROR_MORE_DATA)
    {
        ULONG BufferSize;

        /* Get the size we've to allocate */
        BufferSize = MountPoints->Size;
        /* Reallocate the buffer with enough room */
        RtlFreeHeap(RtlGetProcessHeap(), 0, MountPoints);
        MountPoints = RtlAllocateHeap(RtlGetProcessHeap(), 0, BufferSize);
        if (MountPoints == NULL)
        {
            CloseHandle(MountMgrHandle);
            RtlFreeHeap(RtlGetProcessHeap(), 0, NtPathName.Buffer);
            RtlFreeHeap(RtlGetProcessHeap(), 0, MountPoint);
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return FALSE;
        }

        /* Reissue the request, it should work now! */
        Ret = DeviceIoControl(MountMgrHandle, IOCTL_MOUNTMGR_QUERY_POINTS,
                              MountPoint, NtPathName.Length + sizeof(MOUNTMGR_MOUNT_POINT),
                              MountPoints, BufferSize, &BytesReturned, NULL);
    }

    /* We're done, no longer need the mount manager */
    CloseHandle(MountMgrHandle);
    /* Nor our input buffer */
    RtlFreeHeap(RtlGetProcessHeap(), 0, MountPoint);

    /* If the mount manager failed, just quit */
    if (!Ret)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, NtPathName.Buffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, MountPoints);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    CurrentMntPt = 0;
    /* If there were no associated mount points, we'll return the device name */
    if (MountPoints->NumberOfMountPoints == 0)
    {
        FoundVolume = NtPathName.Buffer;
        FoundVolumeLen = NtPathName.Length;
    }
    /* Otherwise, find one which is matching */
    else
    {
        for (; CurrentMntPt < MountPoints->NumberOfMountPoints; ++CurrentMntPt)
        {
            UNICODE_STRING SymbolicLink;

            /* Make a string of it, to easy the checks */
            SymbolicLink.Length = MountPoints->MountPoints[CurrentMntPt].SymbolicLinkNameLength;
            SymbolicLink.MaximumLength = SymbolicLink.Length;
            SymbolicLink.Buffer = (PVOID)((ULONG_PTR)MountPoints + MountPoints->MountPoints[CurrentMntPt].SymbolicLinkNameOffset);
            /* If that's a NT volume name (GUID form), keep it! */
            if (MOUNTMGR_IS_NT_VOLUME_NAME(&SymbolicLink))
            {
                FoundVolume = SymbolicLink.Buffer;
                FoundVolumeLen = SymbolicLink.Length;

                break;
            }
        }
    }

    /* We couldn't find anything matching, return an error */
    if (CurrentMntPt == MountPoints->NumberOfMountPoints)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, NtPathName.Buffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, MountPoints);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* We found a matching volume, have we enough memory to return it? */
    if (cchBufferLength * sizeof(WCHAR) < FoundVolumeLen + 2 * sizeof(WCHAR))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, NtPathName.Buffer);
        RtlFreeHeap(RtlGetProcessHeap(), 0, MountPoints);
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
        return FALSE;
    }

    /* Copy it back! */
    RtlCopyMemory(lpszVolumeName, FoundVolume, FoundVolumeLen);
    /* Make it compliant */
    lpszVolumeName[1] = L'\\';
    /* And transform it as root path */
    lpszVolumeName[FoundVolumeLen / sizeof(WCHAR)] = L'\\';
    lpszVolumeName[FoundVolumeLen / sizeof(WCHAR) + 1] = UNICODE_NULL;

    /* We're done! */
    RtlFreeHeap(RtlGetProcessHeap(), 0, NtPathName.Buffer);
    RtlFreeHeap(RtlGetProcessHeap(), 0, MountPoints);
    return TRUE;
}

/*
 * @implemented
 */
BOOL
BasepGetVolumeNameFromReparsePoint(IN LPCWSTR lpszMountPoint,
                                   OUT LPWSTR lpszVolumeName,
                                   IN DWORD cchBufferLength,
                                   OUT LPBOOL IsAMountPoint)
{
    WCHAR Old;
    DWORD BytesReturned;
    HANDLE ReparseHandle;
    UNICODE_STRING SubstituteName;
    PREPARSE_DATA_BUFFER ReparseBuffer;

    /* Try to open the reparse point */
    ReparseHandle = CreateFileW(lpszMountPoint, 0,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                OPEN_EXISTING,
                                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_NORMAL,
                                INVALID_HANDLE_VALUE);
    /* It failed! */
    if (ReparseHandle == INVALID_HANDLE_VALUE)
    {
        /* Report it's not a mount point (it's not a reparse point) */
        if (IsAMountPoint != NULL)
        {
            *IsAMountPoint = FALSE;
        }

        /* And zero output */
        if (lpszVolumeName != NULL && cchBufferLength >= 1)
        {
            lpszVolumeName[0] = UNICODE_NULL;
        }

        return FALSE;
    }

    /* This is a mount point! */
    if (IsAMountPoint != NULL)
    {
        *IsAMountPoint = TRUE;
    }

    /* Prepare a buffer big enough to read its data */
    ReparseBuffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, MAXIMUM_REPARSE_DATA_BUFFER_SIZE);
    if (ReparseBuffer == NULL)
    {
        CloseHandle(ReparseHandle);
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);

        /* Zero output */
        if (lpszVolumeName != NULL && cchBufferLength >= 1)
        {
            lpszVolumeName[0] = UNICODE_NULL;
        }

        return FALSE;
    }

    /* Dump the reparse point data */
    if (!DeviceIoControl(ReparseHandle, FSCTL_GET_REPARSE_POINT, NULL, 0,
                         ReparseBuffer, MAXIMUM_REPARSE_DATA_BUFFER_SIZE, &BytesReturned,
                         NULL))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, ReparseBuffer);
        CloseHandle(ReparseHandle);

        /* Zero output */
        if (lpszVolumeName != NULL && cchBufferLength >= 1)
        {
            lpszVolumeName[0] = UNICODE_NULL;
        }

        return FALSE;
    }

    /* We no longer need the reparse point */
    CloseHandle(ReparseHandle);

    /* We only handle mount points */
    if (ReparseBuffer->ReparseTag != IO_REPARSE_TAG_MOUNT_POINT)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, ReparseBuffer);

        /* Zero output */
        if (lpszVolumeName != NULL && cchBufferLength >= 1)
        {
            lpszVolumeName[0] = UNICODE_NULL;
        }

        return FALSE;
    }

    /* Do we have enough room for copying substitue name? */
    if ((ReparseBuffer->MountPointReparseBuffer.SubstituteNameLength + sizeof(UNICODE_NULL)) > cchBufferLength * sizeof(WCHAR))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, ReparseBuffer);
        SetLastError(ERROR_FILENAME_EXCED_RANGE);

        /* Zero output */
        if (lpszVolumeName != NULL && cchBufferLength >= 1)
        {
            lpszVolumeName[0] = UNICODE_NULL;
        }

        return FALSE;
    }

    /* Copy the link target */
    RtlCopyMemory(lpszVolumeName,
                  &ReparseBuffer->MountPointReparseBuffer.PathBuffer[ReparseBuffer->MountPointReparseBuffer.SubstituteNameOffset / sizeof(WCHAR)],
                  ReparseBuffer->MountPointReparseBuffer.SubstituteNameLength);
    /* Make it DOS valid */
    Old = lpszVolumeName[1];
    /* We want a root path */
    lpszVolumeName[1] = L'\\';
    /* And null terminate obviously */
    lpszVolumeName[ReparseBuffer->MountPointReparseBuffer.SubstituteNameLength / sizeof(WCHAR)] = UNICODE_NULL;

    /* Make it a string to easily check it */
    SubstituteName.Length = ReparseBuffer->MountPointReparseBuffer.SubstituteNameLength;
    SubstituteName.MaximumLength = SubstituteName.Length;
    SubstituteName.Buffer = lpszVolumeName;

    /* No longer need the data? */
    RtlFreeHeap(RtlGetProcessHeap(), 0, ReparseBuffer);

    /* Is that a dos volume name with backslash? */
    if (MOUNTMGR_IS_DOS_VOLUME_NAME_WB(&SubstituteName))
    {
        return TRUE;
    }

    /* No, so restore previous name and return to the caller */
    lpszVolumeName[1] = Old;
    SetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
}

/*
 * @implemented
 */
BOOL
BasepGetVolumeNameForVolumeMountPoint(IN LPCWSTR lpszMountPoint,
                                      OUT LPWSTR lpszVolumeName,
                                      IN DWORD cchBufferLength,
                                      OUT LPBOOL IsAMountPoint)
{
    BOOL Ret;
    UNICODE_STRING MountPoint;

    /* Assume it's a mount point (likely for non reparse points) */
    if (IsAMountPoint != NULL)
    {
        *IsAMountPoint = 1;
    }

    /* Make a string with the mount point name */
    RtlInitUnicodeString(&MountPoint, lpszMountPoint);
    /* Not a root path? */
    if (MountPoint.Buffer[(MountPoint.Length / sizeof(WCHAR)) - 1] != L'\\')
    {
        BaseSetLastNTError(STATUS_OBJECT_NAME_INVALID);
        /* Zero output */
        if (lpszVolumeName != NULL && cchBufferLength >= 1)
        {
            lpszVolumeName[0] = UNICODE_NULL;
        }

        return FALSE;
    }

    /* Does it look like <letter>:\? */
    if (MountPoint.Length == 3 * sizeof(WCHAR))
    {
        /* Try to get volume name for root path */
        Ret = GetVolumeNameForRoot(lpszMountPoint, lpszVolumeName, cchBufferLength);
        /* It failed? */
        if (!Ret)
        {
            /* If wasn't a drive letter, so maybe a reparse point? */
            if (MountPoint.Buffer[1] != ':')
            {
                Ret = BasepGetVolumeNameFromReparsePoint(lpszMountPoint, lpszVolumeName, cchBufferLength, IsAMountPoint);
            }
            /* It was, so zero output */
            else if (lpszVolumeName != NULL && cchBufferLength >= 1)
            {
                lpszVolumeName[0] = UNICODE_NULL;
            }
        }
    }
    else
    {
        /* Try to get volume name for root path */
        Ret = GetVolumeNameForRoot(lpszMountPoint, lpszVolumeName, cchBufferLength);
        /* It failed? */
        if (!Ret)
        {
            /* It was a DOS volume as UNC name, so fail and zero output */
            if (MountPoint.Length == 14 && MountPoint.Buffer[0] == '\\' && MountPoint.Buffer[1] == '\\' &&
                (MountPoint.Buffer[2] == '.' || MountPoint.Buffer[2] == '?') && MountPoint.Buffer[3] == L'\\' &&
                MountPoint.Buffer[5] == ':')
            {
                if (lpszVolumeName != NULL && cchBufferLength >= 1)
                {
                    lpszVolumeName[0] = UNICODE_NULL;
                }
            }
            /* Maybe it's a reparse point? */
            else
            {
                Ret = BasepGetVolumeNameFromReparsePoint(lpszMountPoint, lpszVolumeName, cchBufferLength, IsAMountPoint);
            }
        }
    }

    return Ret;
}

/**
 * @name GetVolumeNameForVolumeMountPointW
 * @implemented
 *
 * Return an unique volume name for a drive root or mount point.
 *
 * @param VolumeMountPoint
 *        Pointer to string that contains either root drive name or
 *        mount point name.
 * @param VolumeName
 *        Pointer to buffer that is filled with resulting unique
 *        volume name on success.
 * @param VolumeNameLength
 *        Size of VolumeName buffer in TCHARs.
 *
 * @return
 *     TRUE when the function succeeds and the VolumeName buffer is filled,
 *     FALSE otherwise.
 */
BOOL
WINAPI
GetVolumeNameForVolumeMountPointW(IN LPCWSTR VolumeMountPoint,
                                  OUT LPWSTR VolumeName,
                                  IN DWORD VolumeNameLength)
{
    BOOL Ret;

    /* Just query our internal function */
    Ret = BasepGetVolumeNameForVolumeMountPoint(VolumeMountPoint, VolumeName,
                                                VolumeNameLength, NULL);
    if (!Ret && VolumeName != NULL && VolumeNameLength >= 1)
    {
        VolumeName[0] = UNICODE_NULL;
    }

    return Ret;
}

#ifndef REPARSE_DATA_BUFFER_HEADER_SIZE
#define REPARSE_DATA_BUFFER_HEADER_SIZE FIELD_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer)
#endif

/* Opens the mount manager so that it can be told to change mount points. */
static HANDLE
BasepOpenMountManagerForWrite(VOID)
{
    return CreateFileW(MOUNTMGR_DOS_DEVICE_NAME,
                       GENERIC_READ | GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL,
                       OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL,
                       INVALID_HANDLE_VALUE);
}

/* TRUE for "X:\", the only form that names a drive letter. */
static BOOL
BasepIsDriveLetterRoot(IN LPCWSTR MountPoint)
{
    return (((MountPoint[0] >= L'A' && MountPoint[0] <= L'Z') ||
             (MountPoint[0] >= L'a' && MountPoint[0] <= L'z')) &&
            MountPoint[1] == L':' && MountPoint[2] == L'\\' && MountPoint[3] == UNICODE_NULL);
}

/* Makes the "\??\Volume{GUID}" device name of a "\\?\Volume{GUID}\" volume name. */
static BOOL
BasepVolumeNameToNtName(IN LPCWSTR VolumeName, OUT PWSTR NtName, IN ULONG Count, IN BOOLEAN KeepBackslash)
{
    UNICODE_STRING Name;
    ULONG Length;

    RtlInitUnicodeString(&Name, VolumeName);
    if (!MOUNTMGR_IS_DOS_VOLUME_NAME_WB(&Name))
        return FALSE;

    Length = Name.Length / sizeof(WCHAR) - (KeepBackslash ? 0 : 1);
    if (Length + 1 > Count)
        return FALSE;
    RtlCopyMemory(NtName, Name.Buffer, Length * sizeof(WCHAR));
    NtName[Length] = UNICODE_NULL;
    NtName[1] = L'?';
    return TRUE;
}

/* TRUE when the volume of a "\\?\Volume{GUID}\" name can be opened. */
static BOOL
BasepVolumeExists(IN LPCWSTR VolumeName)
{
    WCHAR Device[64];
    HANDLE Volume;

    if (FAILED(RtlStringCchCopyW(Device, ARRAYSIZE(Device), VolumeName)))
        return FALSE;
    Device[wcslen(Device) - 1] = UNICODE_NULL;
    Volume = CreateFileW(Device, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                         OPEN_EXISTING, 0, NULL);
    if (Volume == INVALID_HANDLE_VALUE)
        return FALSE;
    CloseHandle(Volume);
    return TRUE;
}

static BOOL
BasepSetDriveLetter(IN WCHAR Letter, IN LPCWSTR VolumeName)
{
    WCHAR DosDevice[16];
    WCHAR NtName[64];
    PMOUNTMGR_CREATE_POINT_INPUT Input;
    ULONG DosDeviceLength, DeviceLength, InputLength;
    HANDLE MountMgr;
    DWORD Returned;
    BOOL Ret;

    /* a letter that is taken (by this volume or another) is refused first: Windows Server 2022 answers
     * "directory not empty" even when the volume name is not a volume name; then the volume has to exist */
    {
        WCHAR LetterName[3], Target[MAX_PATH];

        LetterName[0] = towupper(Letter);
        LetterName[1] = L':';
        LetterName[2] = UNICODE_NULL;
        if (QueryDosDeviceW(LetterName, Target, ARRAYSIZE(Target)) != 0)
        {
            SetLastError(ERROR_DIR_NOT_EMPTY);
            return FALSE;
        }

        if (!BasepVolumeNameToNtName(VolumeName, NtName, ARRAYSIZE(NtName), FALSE) ||
            !BasepVolumeExists(VolumeName))
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
    }

    RtlStringCchPrintfW(DosDevice, ARRAYSIZE(DosDevice), L"\\DosDevices\\%c:", towupper(Letter));
    DosDeviceLength = (ULONG)wcslen(DosDevice) * sizeof(WCHAR);
    DeviceLength = (ULONG)wcslen(NtName) * sizeof(WCHAR);

    InputLength = sizeof(MOUNTMGR_CREATE_POINT_INPUT) + DosDeviceLength + DeviceLength;
    Input = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, InputLength);
    if (Input == NULL)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    Input->SymbolicLinkNameOffset = sizeof(MOUNTMGR_CREATE_POINT_INPUT);
    Input->SymbolicLinkNameLength = (USHORT)DosDeviceLength;
    Input->DeviceNameOffset = (USHORT)(sizeof(MOUNTMGR_CREATE_POINT_INPUT) + DosDeviceLength);
    Input->DeviceNameLength = (USHORT)DeviceLength;
    RtlCopyMemory((PUCHAR)Input + Input->SymbolicLinkNameOffset, DosDevice, DosDeviceLength);
    RtlCopyMemory((PUCHAR)Input + Input->DeviceNameOffset, NtName, DeviceLength);

    MountMgr = BasepOpenMountManagerForWrite();
    if (MountMgr == INVALID_HANDLE_VALUE)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, Input);
        return FALSE;
    }
    Ret = DeviceIoControl(MountMgr, IOCTL_MOUNTMGR_CREATE_POINT, Input, InputLength, NULL, 0, &Returned, NULL);
    CloseHandle(MountMgr);
    RtlFreeHeap(RtlGetProcessHeap(), 0, Input);
    return Ret;
}

static BOOL
BasepDeleteDriveLetter(IN WCHAR Letter)
{
    WCHAR DosDevice[16];
    PMOUNTMGR_MOUNT_POINT Input;
    PMOUNTMGR_MOUNT_POINTS Output = NULL;
    ULONG DosDeviceLength, InputLength, OutputLength = 0x1000, Attempt;
    HANDLE MountMgr;
    DWORD Returned;
    BOOL Ret = FALSE;

    {
        WCHAR LetterName[3], Target[MAX_PATH];

        LetterName[0] = towupper(Letter);
        LetterName[1] = L':';
        LetterName[2] = UNICODE_NULL;
        if (QueryDosDeviceW(LetterName, Target, ARRAYSIZE(Target)) == 0)
        {
            SetLastError(ERROR_FILE_NOT_FOUND);
            return FALSE;
        }
    }

    RtlStringCchPrintfW(DosDevice, ARRAYSIZE(DosDevice), L"\\DosDevices\\%c:", towupper(Letter));
    DosDeviceLength = (ULONG)wcslen(DosDevice) * sizeof(WCHAR);

    InputLength = sizeof(MOUNTMGR_MOUNT_POINT) + DosDeviceLength;
    Input = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, InputLength);
    if (Input == NULL)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    Input->SymbolicLinkNameOffset = sizeof(MOUNTMGR_MOUNT_POINT);
    Input->SymbolicLinkNameLength = (USHORT)DosDeviceLength;
    RtlCopyMemory((PUCHAR)Input + Input->SymbolicLinkNameOffset, DosDevice, DosDeviceLength);

    MountMgr = BasepOpenMountManagerForWrite();
    if (MountMgr == INVALID_HANDLE_VALUE)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, Input);
        return FALSE;
    }

    /* the answer lists what the letter pointed at, and the mount manager refuses to delete into a buffer that
     * is too small: grow it by the size the mount manager gives and ask again */
    for (Attempt = 0; Attempt < 4; Attempt++)
    {
        Output = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, OutputLength);
        if (Output == NULL)
        {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            break;
        }
        Ret = DeviceIoControl(MountMgr, IOCTL_MOUNTMGR_DELETE_POINTS, Input, InputLength, Output, OutputLength, &Returned, NULL);
        if (Ret || GetLastError() != ERROR_MORE_DATA || Output->Size <= OutputLength)
            break;
        OutputLength = Output->Size;
        RtlFreeHeap(RtlGetProcessHeap(), 0, Output);
        Output = NULL;
    }
    CloseHandle(MountMgr);
    RtlFreeHeap(RtlGetProcessHeap(), 0, Input);
    if (Output)
        RtlFreeHeap(RtlGetProcessHeap(), 0, Output);
    return Ret;
}

/* Tells the mount manager that a folder became (or stopped being) a mount point, so that it lists the path. */
static VOID
BasepNotifyFolderMountPoint(IN ULONG IoControlCode, IN LPCWSTR Folder, IN LPCWSTR VolumeName)
{
    UNICODE_STRING NtFolder;
    WCHAR NtVolume[64];
    PMOUNTMGR_VOLUME_MOUNT_POINT Input;
    ULONG SourceLength, TargetLength, InputLength;
    HANDLE MountMgr;
    DWORD Returned;

    if (!RtlDosPathNameToNtPathName_U(Folder, &NtFolder, NULL, NULL))
        return;
    /* the target is the device of the volume, not its root directory: no closing backslash */
    if (!BasepVolumeNameToNtName(VolumeName, NtVolume, ARRAYSIZE(NtVolume), FALSE))
    {
        RtlFreeUnicodeString(&NtFolder);
        return;
    }
    SourceLength = NtFolder.Length;
    TargetLength = (ULONG)wcslen(NtVolume) * sizeof(WCHAR);
    InputLength = sizeof(MOUNTMGR_VOLUME_MOUNT_POINT) + TargetLength + SourceLength;

    /* the offsets are 16 bits wide: a path that does not fit gets no notice, the reparse point holds the mount */
    if (InputLength <= MAXUSHORT)
    {
        Input = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, InputLength);
        if (Input != NULL)
        {
            Input->TargetVolumeNameOffset = sizeof(MOUNTMGR_VOLUME_MOUNT_POINT);
            Input->TargetVolumeNameLength = (USHORT)TargetLength;
            Input->SourceVolumeNameOffset = (USHORT)(sizeof(MOUNTMGR_VOLUME_MOUNT_POINT) + TargetLength);
            Input->SourceVolumeNameLength = (USHORT)SourceLength;
            RtlCopyMemory((PUCHAR)Input + Input->TargetVolumeNameOffset, NtVolume, TargetLength);
            RtlCopyMemory((PUCHAR)Input + Input->SourceVolumeNameOffset, NtFolder.Buffer, SourceLength);

            MountMgr = BasepOpenMountManagerForWrite();
            if (MountMgr != INVALID_HANDLE_VALUE)
            {
                DeviceIoControl(MountMgr, IoControlCode, Input, InputLength, NULL, 0, &Returned, NULL);
                CloseHandle(MountMgr);
            }
            RtlFreeHeap(RtlGetProcessHeap(), 0, Input);
        }
    }
    RtlFreeUnicodeString(&NtFolder);
}

static BOOL
BasepSetFolderMountPoint(IN LPCWSTR Folder, IN LPCWSTR VolumeName)
{
    PREPARSE_DATA_BUFFER Reparse;
    WCHAR Substitute[64], Print[64];
    ULONG SubstituteLength, PrintLength, DataLength, BufferLength;
    HANDLE Directory;
    BY_HANDLE_FILE_INFORMATION Information;
    DWORD Returned;
    BOOL Ret;

    /* the print name is the substitute name again, as Windows writes it */
    if (!BasepVolumeNameToNtName(VolumeName, Substitute, ARRAYSIZE(Substitute), TRUE) ||
        FAILED(RtlStringCchCopyW(Print, ARRAYSIZE(Print), Substitute)))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    SubstituteLength = (ULONG)wcslen(Substitute) * sizeof(WCHAR);
    PrintLength = (ULONG)wcslen(Print) * sizeof(WCHAR);

    /* the substitute name, the print name and their two terminators follow the fixed part */
    DataLength = FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer) -
                 REPARSE_DATA_BUFFER_HEADER_SIZE + SubstituteLength + PrintLength + 2 * sizeof(WCHAR);
    BufferLength = REPARSE_DATA_BUFFER_HEADER_SIZE + DataLength;
    Reparse = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, BufferLength);
    if (Reparse == NULL)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    Reparse->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    Reparse->ReparseDataLength = (USHORT)DataLength;
    Reparse->MountPointReparseBuffer.SubstituteNameOffset = 0;
    Reparse->MountPointReparseBuffer.SubstituteNameLength = (USHORT)SubstituteLength;
    Reparse->MountPointReparseBuffer.PrintNameOffset = (USHORT)(SubstituteLength + sizeof(WCHAR));
    Reparse->MountPointReparseBuffer.PrintNameLength = (USHORT)PrintLength;
    RtlCopyMemory(Reparse->MountPointReparseBuffer.PathBuffer, Substitute, SubstituteLength);
    RtlCopyMemory((PUCHAR)Reparse->MountPointReparseBuffer.PathBuffer + SubstituteLength + sizeof(WCHAR), Print, PrintLength);

    /* the volume has to exist, as it has for a drive letter */
    if (!BasepVolumeExists(VolumeName))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, Reparse);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* no one else may write to the folder while it is checked and changed */
    Directory = CreateFileW(Folder, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (Directory == INVALID_HANDLE_VALUE)
    {
        DWORD Error = GetLastError();

        /* a folder that is not there: the error of opening it (Windows Server 2022: file not found) */
        RtlFreeHeap(RtlGetProcessHeap(), 0, Reparse);
        SetLastError(Error);
        return FALSE;
    }

    /* a folder that is a mount point already is not empty, as far as a mount is concerned */
    if (!GetFileInformationByHandle(Directory, &Information))
    {
        DWORD Error = GetLastError();

        CloseHandle(Directory);
        RtlFreeHeap(RtlGetProcessHeap(), 0, Reparse);
        SetLastError(Error);
        return FALSE;
    }
    if (Information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
    {
        CloseHandle(Directory);
        RtlFreeHeap(RtlGetProcessHeap(), 0, Reparse);
        SetLastError(ERROR_DIR_NOT_EMPTY);
        return FALSE;
    }
    Ret = DeviceIoControl(Directory, FSCTL_SET_REPARSE_POINT, Reparse, BufferLength, NULL, 0, &Returned, NULL);
    CloseHandle(Directory);
    RtlFreeHeap(RtlGetProcessHeap(), 0, Reparse);
    if (Ret)
        BasepNotifyFolderMountPoint(IOCTL_MOUNTMGR_VOLUME_MOUNT_POINT_CREATED, Folder, VolumeName);
    return Ret;
}

static BOOL
BasepDeleteFolderMountPoint(IN LPCWSTR Folder)
{
    PREPARSE_DATA_BUFFER Reparse;
    ULONG64 Header[2];
    UNICODE_STRING Substitute;
    WCHAR VolumeName[64];
    HANDLE Directory;
    DWORD Returned, Error;
    BOOL Ret = FALSE;

    Directory = CreateFileW(Folder, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (Directory == INVALID_HANDLE_VALUE)
        return FALSE;

    /* only a mount point of a volume may be removed, never another kind of reparse point: the same handle
     * reads what the folder is and removes it, so that nothing can be swapped in between */
    Reparse = RtlAllocateHeap(RtlGetProcessHeap(), 0, MAXIMUM_REPARSE_DATA_BUFFER_SIZE);
    if (Reparse == NULL)
    {
        CloseHandle(Directory);
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    if (!DeviceIoControl(Directory, FSCTL_GET_REPARSE_POINT, NULL, 0, Reparse, MAXIMUM_REPARSE_DATA_BUFFER_SIZE,
                         &Returned, NULL))
    {
        Error = GetLastError();
        goto Quit;
    }
    Error = ERROR_NOT_A_REPARSE_POINT;
    if (Reparse->ReparseTag != IO_REPARSE_TAG_MOUNT_POINT)
        goto Quit;
    Substitute.Length = Reparse->MountPointReparseBuffer.SubstituteNameLength;
    Substitute.MaximumLength = Substitute.Length;
    Substitute.Buffer = &Reparse->MountPointReparseBuffer.PathBuffer[Reparse->MountPointReparseBuffer.SubstituteNameOffset / sizeof(WCHAR)];
    if ((PUCHAR)Substitute.Buffer + Substitute.Length > (PUCHAR)Reparse + Returned || !MOUNTMGR_IS_NT_VOLUME_NAME_WB(&Substitute))
        goto Quit;
    RtlCopyMemory(VolumeName, Substitute.Buffer, Substitute.Length);
    VolumeName[Substitute.Length / sizeof(WCHAR)] = UNICODE_NULL;
    VolumeName[1] = L'\\';

    RtlZeroMemory(Header, sizeof(Header));
    ((PREPARSE_DATA_BUFFER)Header)->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    Ret = DeviceIoControl(Directory, FSCTL_DELETE_REPARSE_POINT, Header, REPARSE_DATA_BUFFER_HEADER_SIZE, NULL, 0, &Returned, NULL);
    Error = Ret ? ERROR_SUCCESS : GetLastError();

Quit:
    CloseHandle(Directory);
    RtlFreeHeap(RtlGetProcessHeap(), 0, Reparse);
    if (Ret)
        BasepNotifyFolderMountPoint(IOCTL_MOUNTMGR_VOLUME_MOUNT_POINT_DELETED, Folder, VolumeName);
    else
        SetLastError(Error);
    return Ret;
}

/**
 * @name SetVolumeMountPointW
 * @implemented
 *
 * Mounts a volume at a drive letter ("X:\") or at an empty folder of an NTFS volume.
 *
 * @param lpszVolumeMountPoint
 *        "X:\" or the path of the folder, ending with a backslash.
 * @param lpszVolumeName
 *        Volume name in the form returned by GetVolumeNameForVolumeMountPointW.
 *
 * @return TRUE when the volume is mounted there, FALSE otherwise (see GetLastError).
 */
BOOL
WINAPI
SetVolumeMountPointW(IN LPCWSTR lpszVolumeMountPoint,
                     IN LPCWSTR lpszVolumeName)
{
    SIZE_T Length;
    UNICODE_STRING VolumeName;

    if (lpszVolumeMountPoint == NULL || lpszVolumeName == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    Length = wcslen(lpszVolumeMountPoint);
    if (Length == 0 || lpszVolumeMountPoint[Length - 1] != L'\\')
    {
        SetLastError(ERROR_INVALID_NAME);
        return FALSE;
    }

    /* "\\?\Volume{GUID}" without the closing backslash is a name, but not one this function takes */
    RtlInitUnicodeString(&VolumeName, lpszVolumeName);
    if (VolumeName.Length == 96 && MOUNTMGR_IS_VOLUME_NAME(&VolumeName))
    {
        SetLastError(ERROR_INVALID_NAME);
        return FALSE;
    }

    if (BasepIsDriveLetterRoot(lpszVolumeMountPoint))
        return BasepSetDriveLetter(lpszVolumeMountPoint[0], lpszVolumeName);

    return BasepSetFolderMountPoint(lpszVolumeMountPoint, lpszVolumeName);
}

/**
 * @name DeleteVolumeMountPointW
 * @implemented
 *
 * Removes a drive letter ("X:\") or a mount point folder; the volume itself stays.
 */
BOOL
WINAPI
DeleteVolumeMountPointW(IN LPCWSTR lpszVolumeMountPoint)
{
    SIZE_T Length;

    if (lpszVolumeMountPoint == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    Length = wcslen(lpszVolumeMountPoint);
    if (Length == 0 || lpszVolumeMountPoint[Length - 1] != L'\\')
    {
        SetLastError(ERROR_INVALID_NAME);
        return FALSE;
    }

    if (BasepIsDriveLetterRoot(lpszVolumeMountPoint))
        return BasepDeleteDriveLetter(lpszVolumeMountPoint[0]);

    return BasepDeleteFolderMountPoint(lpszVolumeMountPoint);
}

/*
 * The state of a FindFirstVolumeMountPoint search: the root directory of the volume (the related file of the
 * opens by file ID) and the handle of its reparse point index, "$Extend\$Reparse:$R:$INDEX_ALLOCATION", whose
 * FileReparsePointInformation entries (reparse tag, file reference) are read in tag order: the mount point
 * tag comes first of the tags a folder mount point can have, so the search ends at the first other tag.
 */
#define VOLUME_MOUNT_POINT_FIND_MAGIC 0x504d5656   /* 'VVMP' */
#define VOLUME_MOUNT_POINT_INDEX_NAME L"$Extend\\$Reparse:$R:$INDEX_ALLOCATION"

typedef struct _VOLUME_MOUNT_POINT_FIND
{
    ULONG Magic;
    BOOLEAN Started;
    BOOLEAN Done;
    HANDLE Root;
    HANDLE Index;
} VOLUME_MOUNT_POINT_FIND, *PVOLUME_MOUNT_POINT_FIND;

static VOID
BasepFreeVolumeMountPointFind(IN PVOLUME_MOUNT_POINT_FIND Find)
{
    Find->Magic = 0;
    if (Find->Index != NULL)
        NtClose(Find->Index);
    if (Find->Root != NULL)
        NtClose(Find->Root);
    RtlFreeHeap(RtlGetProcessHeap(), 0, Find);
}

/*
 * Reads the mount points of the volume until one points at a volume (not a junction to a folder); copies its path
 * from the root, without the leading backslash and with a closing one ("dir\mnt\"), to the buffer.  Last error:
 * ERROR_NO_MORE_FILES at the end, ERROR_MORE_DATA when the path does not fit (the search is over then).
 */
static BOOL
BasepNextVolumeMountPoint(IN PVOLUME_MOUNT_POINT_FIND Find, OUT LPWSTR Buffer, IN DWORD cchBuffer)
{
    static const WCHAR VolumePrefix[] = L"\\??\\Volume{";
    ULONG Key[3] = { IO_REPARSE_TAG_MOUNT_POINT, 0, 0 };
    UNICODE_STRING KeyName, FileId;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    struct
    {
        LONGLONG FileReference;
        ULONG Tag;
    } Entry;   /* FILE_REPARSE_POINT_INFORMATION */
    PREPARSE_DATA_BUFFER Reparse;
    PFILE_NAME_INFORMATION NameInfo;
    NTSTATUS Status;
    HANDLE File;
    BOOL Ret = FALSE;

    Reparse = RtlAllocateHeap(RtlGetProcessHeap(), 0, MAXIMUM_REPARSE_DATA_BUFFER_SIZE);
    NameInfo = RtlAllocateHeap(RtlGetProcessHeap(), 0, sizeof(FILE_NAME_INFORMATION) + 0xFFFF);
    if (Reparse == NULL || NameInfo == NULL)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        goto Done;
    }
    KeyName.Buffer = (PWSTR)Key;
    KeyName.Length = KeyName.MaximumLength = sizeof(Key);

    for (;;)
    {
        BOOLEAN First = !Find->Started;

        Status = NtQueryDirectoryFile(Find->Index, NULL, NULL, NULL, &IoStatusBlock, &Entry, sizeof(Entry),
                                      FileReparsePointInformation, TRUE, First ? &KeyName : NULL, First);
        Find->Started = TRUE;
        if (!NT_SUCCESS(Status) || Entry.Tag != IO_REPARSE_TAG_MOUNT_POINT)
        {
            if (NT_SUCCESS(Status) || Status == STATUS_NO_MORE_FILES || Status == STATUS_NO_SUCH_FILE)
                SetLastError(ERROR_NO_MORE_FILES);
            else
                BaseSetLastNTError(Status);
            goto Done;
        }

        /* The file the entry names, opened by its reference below the root, as itself and not what it points to */
        FileId.Buffer = (PWSTR)&Entry.FileReference;
        FileId.Length = FileId.MaximumLength = sizeof(Entry.FileReference);
        InitializeObjectAttributes(&ObjectAttributes, &FileId, 0, Find->Root, NULL);
        Status = NtOpenFile(&File, SYNCHRONIZE | FILE_READ_ATTRIBUTES, &ObjectAttributes, &IoStatusBlock,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            FILE_OPEN_BY_FILE_ID | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT);
        if (!NT_SUCCESS(Status))
            continue;   /* removed since the index entry was read */

        Status = NtFsControlFile(File, NULL, NULL, NULL, &IoStatusBlock, FSCTL_GET_REPARSE_POINT, NULL, 0,
                                 Reparse, MAXIMUM_REPARSE_DATA_BUFFER_SIZE);
        if (NT_SUCCESS(Status) &&
            Reparse->ReparseTag == IO_REPARSE_TAG_MOUNT_POINT &&
            IoStatusBlock.Information >= FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer))
        {
            /* the data is read from the volume: its offsets are checked */
            ULONG Offset = Reparse->MountPointReparseBuffer.SubstituteNameOffset;
            ULONG Length = Reparse->MountPointReparseBuffer.SubstituteNameLength;
            ULONG Available = (ULONG)IoStatusBlock.Information -
                              FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer);
            BOOLEAN IsVolume = Offset <= Available && Length <= Available - Offset &&
                               Length >= sizeof(VolumePrefix) - sizeof(WCHAR) &&
                               !_wcsnicmp((PWSTR)((PUCHAR)Reparse->MountPointReparseBuffer.PathBuffer + Offset),
                                          VolumePrefix, (sizeof(VolumePrefix) - sizeof(WCHAR)) / sizeof(WCHAR));
            if (IsVolume)
            {
                Status = NtQueryInformationFile(File, &IoStatusBlock, NameInfo, sizeof(FILE_NAME_INFORMATION) + 0xFFFF,
                                                FileNameInformation);
                if (NT_SUCCESS(Status))
                {
                    PWSTR Name = NameInfo->FileName;
                    ULONG Chars = NameInfo->FileNameLength / sizeof(WCHAR);

                    if (Chars != 0 && Name[0] == L'\\')
                    {
                        Name++;
                        Chars--;
                    }
                    NtClose(File);
                    if (Chars + 2 > cchBuffer)
                    {
                        SetLastError(ERROR_MORE_DATA);
                        goto Done;
                    }
                    RtlCopyMemory(Buffer, Name, Chars * sizeof(WCHAR));
                    Buffer[Chars] = L'\\';
                    Buffer[Chars + 1] = UNICODE_NULL;
                    Ret = TRUE;
                    goto Done;
                }
            }
        }
        NtClose(File);
    }

Done:
    if (Reparse != NULL)
        RtlFreeHeap(RtlGetProcessHeap(), 0, Reparse);
    if (NameInfo != NULL)
        RtlFreeHeap(RtlGetProcessHeap(), 0, NameInfo);
    return Ret;
}

/**
 * @name FindFirstVolumeMountPointW
 * @implemented
 *
 * Starts the search for the folder mount points of the volume whose root is named ("X:\" or a volume name with
 * its closing backslash); the paths are given from that root.  Close the handle with FindVolumeMountPointClose.
 */
HANDLE
WINAPI
FindFirstVolumeMountPointW(IN LPCWSTR lpszRootPathName,
                           IN LPWSTR lpszVolumeMountPoint,
                           IN DWORD cchBufferLength)
{
    SIZE_T Length;
    ULONG NtLength;
    UNICODE_STRING NtRoot, NtIndex;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    PVOLUME_MOUNT_POINT_FIND Find;
    NTSTATUS Status;

    if (lpszRootPathName == NULL || lpszVolumeMountPoint == NULL || cchBufferLength == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }
    if (cchBufferLength == 1)
    {
        SetLastError(ERROR_BAD_LENGTH);
        return INVALID_HANDLE_VALUE;
    }

    /* the root is named with its closing backslash */
    Length = wcslen(lpszRootPathName);
    if (Length == 0 || lpszRootPathName[Length - 1] != L'\\')
    {
        SetLastError(ERROR_INVALID_NAME);
        return INVALID_HANDLE_VALUE;
    }
    if (!RtlDosPathNameToNtPathName_U(lpszRootPathName, &NtRoot, NULL, NULL))
    {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }

    Find = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Find));
    NtIndex.Buffer = NULL;
    NtLength = NtRoot.Length + sizeof(VOLUME_MOUNT_POINT_INDEX_NAME);
    if (Find != NULL && NtLength <= MAXUSHORT)
    {
        NtIndex.Length = 0;
        NtIndex.MaximumLength = (USHORT)NtLength;
        NtIndex.Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, NtLength);
    }
    if (Find == NULL || NtIndex.Buffer == NULL)
    {
        if (Find != NULL)
            RtlFreeHeap(RtlGetProcessHeap(), 0, Find);
        RtlFreeUnicodeString(&NtRoot);
        SetLastError(Find != NULL ? ERROR_FILENAME_EXCED_RANGE : ERROR_NOT_ENOUGH_MEMORY);
        return INVALID_HANDLE_VALUE;
    }
    Find->Magic = VOLUME_MOUNT_POINT_FIND_MAGIC;

    InitializeObjectAttributes(&ObjectAttributes, &NtRoot, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenFile(&Find->Root, SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY, &ObjectAttributes,
                        &IoStatusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    if (NT_SUCCESS(Status))
    {
        RtlCopyUnicodeString(&NtIndex, &NtRoot);
        RtlAppendUnicodeToString(&NtIndex, VOLUME_MOUNT_POINT_INDEX_NAME);
        InitializeObjectAttributes(&ObjectAttributes, &NtIndex, OBJ_CASE_INSENSITIVE, NULL, NULL);
        Status = NtOpenFile(&Find->Index, SYNCHRONIZE | FILE_GENERIC_READ, &ObjectAttributes, &IoStatusBlock,
                            FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT);
    }
    RtlFreeHeap(RtlGetProcessHeap(), 0, NtIndex.Buffer);
    RtlFreeUnicodeString(&NtRoot);
    if (!NT_SUCCESS(Status))
    {
        /* a file system without the index (FAT) or a name that is no root has no such path */
        if (Status == STATUS_OBJECT_NAME_INVALID || Status == STATUS_OBJECT_NAME_NOT_FOUND ||
            Status == STATUS_NOT_SUPPORTED || Status == STATUS_INVALID_PARAMETER)
            Status = STATUS_OBJECT_PATH_NOT_FOUND;
        BaseSetLastNTError(Status);
        BasepFreeVolumeMountPointFind(Find);
        return INVALID_HANDLE_VALUE;
    }

    if (!BasepNextVolumeMountPoint(Find, lpszVolumeMountPoint, cchBufferLength))
    {
        BasepFreeVolumeMountPointFind(Find);
        return INVALID_HANDLE_VALUE;
    }
    return Find;
}

/**
 * @name FindNextVolumeMountPointW
 * @implemented
 *
 * The next folder mount point of the search; ERROR_NO_MORE_FILES when there is none, ERROR_MORE_DATA when its path
 * does not fit the buffer (the search ends there).  A handle that is not a search is refused without an error code.
 */
BOOL
WINAPI
FindNextVolumeMountPointW(IN HANDLE hFindVolumeMountPoint,
                          IN LPWSTR lpszVolumeMountPoint,
                          DWORD cchBufferLength)
{
    PVOLUME_MOUNT_POINT_FIND Find = hFindVolumeMountPoint;
    BOOL Ret = FALSE;

    if (Find == NULL || Find == INVALID_HANDLE_VALUE)
        return FALSE;
    _SEH2_TRY
    {
        if (Find->Magic != VOLUME_MOUNT_POINT_FIND_MAGIC || Find->Done || lpszVolumeMountPoint == NULL)
            _SEH2_YIELD(return FALSE);
        Ret = BasepNextVolumeMountPoint(Find, lpszVolumeMountPoint, cchBufferLength);
        if (!Ret)
            Find->Done = TRUE;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        Ret = FALSE;
    }
    _SEH2_END;
    return Ret;
}

/**
 * @name FindVolumeMountPointClose
 * @implemented
 */
BOOL
WINAPI
FindVolumeMountPointClose(IN HANDLE hFindVolumeMountPoint)
{
    PVOLUME_MOUNT_POINT_FIND Find = hFindVolumeMountPoint;

    if (Find == NULL || Find == INVALID_HANDLE_VALUE)
        return FALSE;
    _SEH2_TRY
    {
        if (Find->Magic != VOLUME_MOUNT_POINT_FIND_MAGIC)
            _SEH2_YIELD(return FALSE);
        BasepFreeVolumeMountPointFind(Find);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
    _SEH2_END;
    return TRUE;
}

/* EOF */
