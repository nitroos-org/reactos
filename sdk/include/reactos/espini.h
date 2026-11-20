/*
 * PROJECT:     ReactOS SDK
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Find the loader configuration (freeldr.ini) of a UEFI installation
 *
 * On a UEFI computer the boot loader and its freeldr.ini are on the EFI system
 * partition (ESP) of the system disk. The ESP has no drive letter (it must not
 * get one), so it is reached through the volume GUID path of its volume.
 * Reading the partition type of a volume needs administrator rights.
 */

#pragma once

#include <winioctl.h>

/* C12A7328-F81F-11D2-BA4B-00A0C93EC93B: the EFI system partition (UEFI 2.10, 5.3.3 table 5.7) */
static const GUID EspIniEspTypeGuid =
    {0xc12a7328, 0xf81f, 0x11d2, {0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b}};

/* TRUE if the system was started by a UEFI loader (GetFirmwareType, FirmwareTypeUefi == 2) */
static inline BOOL
EspIniIsUefiBoot(VOID)
{
    typedef BOOL (WINAPI *PGETFIRMWARETYPE)(PDWORD);
    PGETFIRMWARETYPE pGetFirmwareType;
    HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
    DWORD Type = 0;

    pGetFirmwareType = hKernel ? (PGETFIRMWARETYPE)GetProcAddress(hKernel, "GetFirmwareType") : NULL;
    return (pGetFirmwareType && pGetFirmwareType(&Type) && Type == 2);
}

/* Number of the physical disk the volume lives on (its first extent) */
static inline BOOL
EspIniGetVolumeDisk(HANDLE hVolume, PDWORD DiskNumber)
{
    BYTE Buffer[sizeof(VOLUME_DISK_EXTENTS) + 3 * sizeof(DISK_EXTENT)];
    PVOLUME_DISK_EXTENTS Extents = (PVOLUME_DISK_EXTENTS)Buffer;
    DWORD Returned;

    if (!DeviceIoControl(hVolume, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, NULL, 0,
                         Buffer, sizeof(Buffer), &Returned, NULL) &&
        GetLastError() != ERROR_MORE_DATA)
    {
        return FALSE;
    }
    if (Extents->NumberOfDiskExtents == 0)
        return FALSE;
    *DiskNumber = Extents->Extents[0].DiskNumber;
    return TRUE;
}

/*
 * Finds the freeldr.ini on the EFI system partition of the disk the system drive is on.
 * On success returns ERROR_SUCCESS and Path holds the volume GUID path of the file
 * (\\?\Volume{...}\freeldr.ini). Otherwise a Win32 error: ERROR_ACCESS_DENIED when the
 * volumes could not be opened (not an administrator), ERROR_FILE_NOT_FOUND when the
 * system disk has no ESP with a freeldr.ini.
 */
static inline DWORD
EspIniFindFreeldrIni(PWCHAR Path, SIZE_T cchPath)
{
    WCHAR Drive[MAX_PATH], Volume[MAX_PATH + 16];
    HANDLE hFind, hVolume;
    DWORD SystemDisk, Disk, Returned, Length, Error = ERROR_FILE_NOT_FOUND;
    BOOL SawDenied = FALSE;
    PARTITION_INFORMATION_EX Info;

    /* The disk of the system drive: a query-only handle is enough */
    Length = GetEnvironmentVariableW(L"SystemDrive", Drive, ARRAYSIZE(Drive) - 8);
    if (Length == 0 || Length >= ARRAYSIZE(Drive) - 8)
        return ERROR_FILE_NOT_FOUND;
    memmove(Drive + 4, Drive, (Length + 1) * sizeof(WCHAR));
    Drive[0] = L'\\'; Drive[1] = L'\\'; Drive[2] = L'.'; Drive[3] = L'\\';
    hVolume = CreateFileW(Drive, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hVolume == INVALID_HANDLE_VALUE)
        return GetLastError();
    if (!EspIniGetVolumeDisk(hVolume, &SystemDisk))
        Error = GetLastError();
    CloseHandle(hVolume);
    if (Error != ERROR_FILE_NOT_FOUND)
        return Error;

    hFind = FindFirstVolumeW(Volume, ARRAYSIZE(Volume) - 16);
    if (hFind == INVALID_HANDLE_VALUE)
        return GetLastError();
    do
    {
        Length = wcslen(Volume);
        if (Length < 4 || Volume[Length - 1] != L'\\')
            continue;

        /* The volume without the trailing backslash is the volume device */
        Volume[Length - 1] = L'\0';
        hVolume = CreateFileW(Volume, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        Volume[Length - 1] = L'\\';
        if (hVolume == INVALID_HANDLE_VALUE)
        {
            if (GetLastError() == ERROR_ACCESS_DENIED)
                SawDenied = TRUE;
            continue;
        }

        if (EspIniGetVolumeDisk(hVolume, &Disk) && Disk == SystemDisk &&
            DeviceIoControl(hVolume, IOCTL_DISK_GET_PARTITION_INFO_EX, NULL, 0,
                            &Info, sizeof(Info), &Returned, NULL) &&
            Info.PartitionStyle == PARTITION_STYLE_GPT &&
            IsEqualGUID(&Info.Gpt.PartitionType, &EspIniEspTypeGuid) &&
            Length + 12 < cchPath)
        {
            wcscpy(Path, Volume);
            wcscat(Path, L"freeldr.ini");
            if (GetFileAttributesW(Path) != INVALID_FILE_ATTRIBUTES)
            {
                CloseHandle(hVolume);
                FindVolumeClose(hFind);
                return ERROR_SUCCESS;
            }
        }
        CloseHandle(hVolume);
    } while (FindNextVolumeW(hFind, Volume, ARRAYSIZE(Volume) - 16));
    FindVolumeClose(hFind);

    return SawDenied ? ERROR_ACCESS_DENIED : ERROR_FILE_NOT_FOUND;
}
