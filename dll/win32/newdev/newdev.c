/*
 * New device installer (newdev.dll)
 *
 * Copyright 2005-2006 Hervé Poussineau (hpoussin@reactos.org)
 *           2005 Christoph von Wittich (Christoph@ActiveVB.de)
 *           2009 Colin Finck (colin@reactos.org)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "newdev_private.h"

#include <stdio.h>
#include <winnls.h>
#include <cfgmgr32.h>

/* Global variables */
HINSTANCE hDllInstance;

static BOOL
SearchDriver(
    IN PDEVINSTDATA DevInstData,
    IN LPCWSTR Directory OPTIONAL,
    IN LPCWSTR InfFile OPTIONAL);

/* Does this thread act as SYSTEM? Then an install writes as SYSTEM anyway, and runs here */
static BOOL
IsSystemContext(VOID)
{
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    BYTE Buffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    PSID SystemSid;
    HANDLE hToken;
    DWORD Size;
    BOOL Result = FALSE;

    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken) &&
        !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        return FALSE;
    }

    if (GetTokenInformation(hToken, TokenUser, Buffer, sizeof(Buffer), &Size) &&
        AllocateAndInitializeSid(&NtAuthority, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &SystemSid))
    {
        Result = EqualSid(((PTOKEN_USER)Buffer)->User.Sid, SystemSid);
        FreeSid(SystemSid);
    }

    CloseHandle(hToken);
    return Result;
}

/*
 * Sends one install to the Plug and Play service (see PNP_INSTALL_REQUEST_PIPE) and waits
 * for its result. Returns a Win32 error code.
 */
static DWORD
SendInstallRequest(
    IN LPCWSTR DeviceId,
    IN LPCWSTR InfPath,
    IN DWORD Origin,
    OUT PBOOL NeedRestart)
{
    PNP_INSTALL_REQUEST Request;
    PNP_INSTALL_REPLY Reply;
    HANDLE hPipe;
    PBYTE Message;
    DWORD MessageSize, Done, Total, Error;
    ULONG Tries;

    *NeedRestart = FALSE;

    Request.Magic = PNP_INSTALL_REQUEST_MAGIC;
    Request.Version = PNP_INSTALL_REQUEST_VERSION;
    Request.Origin = Origin;
    Request.Flags = 0;
    Request.DeviceIdBytes = (wcslen(DeviceId) + 1) * sizeof(WCHAR);
    Request.InfPathBytes = (wcslen(InfPath) + 1) * sizeof(WCHAR);
    if (Request.DeviceIdBytes > (MAX_DEVICE_ID_LEN + 1) * sizeof(WCHAR) ||
        Request.InfPathBytes > MAX_PATH * sizeof(WCHAR))
    {
        return ERROR_INVALID_PARAMETER;
    }

    /* Identification only: whoever serves this pipe can see who we are, never act as us */
    for (Tries = 0; ; Tries++)
    {
        hPipe = CreateFileW(PNP_INSTALL_REQUEST_PIPE,
                            GENERIC_READ | GENERIC_WRITE,
                            0,
                            NULL,
                            OPEN_EXISTING,
                            SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                            NULL);
        if (hPipe != INVALID_HANDLE_VALUE)
            break;

        Error = GetLastError();
        if (Error == ERROR_PIPE_BUSY && Tries < 10)
        {
            WaitNamedPipeW(PNP_INSTALL_REQUEST_PIPE, 10000);
            continue;
        }
        ERR("Cannot open the install request pipe, error %lu\n", Error);
        /* Only administrators can open it */
        if (Error == ERROR_ACCESS_DENIED)
            return ERROR_ACCESS_DENIED;
        if (Error == ERROR_FILE_NOT_FOUND || Error == ERROR_PATH_NOT_FOUND)
            return ERROR_SERVICE_NOT_ACTIVE;
        return Error;
    }

    MessageSize = sizeof(Request) + Request.DeviceIdBytes + Request.InfPathBytes;
    Message = HeapAlloc(GetProcessHeap(), 0, MessageSize);
    if (!Message)
    {
        CloseHandle(hPipe);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    CopyMemory(Message, &Request, sizeof(Request));
    CopyMemory(Message + sizeof(Request), DeviceId, Request.DeviceIdBytes);
    CopyMemory(Message + sizeof(Request) + Request.DeviceIdBytes, InfPath, Request.InfPathBytes);

    Error = ERROR_SUCCESS;
    if (!WriteFile(hPipe, Message, MessageSize, &Done, NULL) || Done != MessageSize)
        Error = GetLastError() ? GetLastError() : ERROR_WRITE_FAULT;
    HeapFree(GetProcessHeap(), 0, Message);

    /* The service answers when drvinst.exe is done */
    for (Total = 0; Error == ERROR_SUCCESS && Total < sizeof(Reply); Total += Done)
    {
        if (!ReadFile(hPipe, (PBYTE)&Reply + Total, sizeof(Reply) - Total, &Done, NULL) || Done == 0)
            Error = ERROR_BROKEN_PIPE;
    }
    CloseHandle(hPipe);

    if (Error != ERROR_SUCCESS)
    {
        ERR("The install request failed, error %lu\n", Error);
        return Error;
    }
    if (Reply.Magic != PNP_INSTALL_REPLY_MAGIC)
        return ERROR_INVALID_DATA;

    *NeedRestart = (Error == ERROR_SUCCESS && Reply.Error == ERROR_SUCCESS && Reply.NeedRestart);
    return Reply.Error;
}

/*
 * The install of the driver the user picked (the best one of the driver list) goes to the
 * Plug and Play service, which runs it in drvinst.exe as SYSTEM: the driver package copy to
 * %SystemRoot%\inf, the class installers, and the Enum, Control\Class and Services writes.
 */
static BOOL
InstallDriverServiceSide(
    IN PDEVINSTDATA DevInstData,
    IN DWORD Origin)
{
    WCHAR DeviceId[MAX_DEVICE_ID_LEN + 1];
    WCHAR InfPath[MAX_PATH];
    SP_DRVINFO_DATA_W DrvInfoData;
    PSP_DRVINFO_DETAIL_DATA_W Detail = NULL;
    SP_DEVINSTALL_PARAMS_W InstallParams;
    DWORD Size = 0, Length, Error;
    BOOL NeedRestart = FALSE;

    if (!SetupDiGetDeviceInstanceIdW(DevInstData->hDevInfo, &DevInstData->devInfoData,
                                     DeviceId, ARRAYSIZE(DeviceId), NULL))
    {
        return FALSE;
    }

    /* The driver list is sorted by rank: the first entry is the one an install selects */
    DrvInfoData.cbSize = sizeof(DrvInfoData);
    if (!SetupDiEnumDriverInfoW(DevInstData->hDevInfo, &DevInstData->devInfoData,
                                SPDIT_COMPATDRIVER, 0, &DrvInfoData))
    {
        SetLastError(ERROR_NO_DRIVER_SELECTED);
        return FALSE;
    }
    SetupDiGetDriverInfoDetailW(DevInstData->hDevInfo, &DevInstData->devInfoData, &DrvInfoData, NULL, 0, &Size);
    if (Size < sizeof(SP_DRVINFO_DETAIL_DATA_W))
        Size = sizeof(SP_DRVINFO_DETAIL_DATA_W);
    Detail = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Size);
    if (!Detail)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    Detail->cbSize = sizeof(SP_DRVINFO_DETAIL_DATA_W);
    if (!SetupDiGetDriverInfoDetailW(DevInstData->hDevInfo, &DevInstData->devInfoData, &DrvInfoData, Detail, Size, NULL))
    {
        Error = GetLastError();
        HeapFree(GetProcessHeap(), 0, Detail);
        SetLastError(Error);
        return FALSE;
    }

    /* The service has another current directory: send the full path */
    Length = GetFullPathNameW(Detail->InfFileName, ARRAYSIZE(InfPath), InfPath, NULL);
    HeapFree(GetProcessHeap(), 0, Detail);
    if (Length == 0 || Length >= ARRAYSIZE(InfPath))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* The pages show the driver that is installed */
    DevInstData->drvInfoData = DrvInfoData;

    TRACE("Installing %s from %s service-side\n", debugstr_w(DeviceId), debugstr_w(InfPath));
    Error = SendInstallRequest(DeviceId, InfPath, Origin, &NeedRestart);
    if (Error != ERROR_SUCCESS)
    {
        SetLastError(Error);
        return FALSE;
    }

    /* The callers read a needed restart from the install parameters, as after an install here */
    if (NeedRestart)
    {
        InstallParams.cbSize = sizeof(InstallParams);
        if (SetupDiGetDeviceInstallParamsW(DevInstData->hDevInfo, &DevInstData->devInfoData, &InstallParams))
        {
            InstallParams.Flags |= DI_NEEDRESTART;
            SetupDiSetDeviceInstallParamsW(DevInstData->hDevInfo, &DevInstData->devInfoData, &InstallParams);
        }
    }

    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

/*
* @implemented
*/
BOOL WINAPI
UpdateDriverForPlugAndPlayDevicesW(
    IN HWND hwndParent,
    IN LPCWSTR HardwareId,
    IN LPCWSTR FullInfPath,
    IN DWORD InstallFlags,
    OUT PBOOL bRebootRequired OPTIONAL)
{
    DEVINSTDATA DevInstData;
    SP_DEVINSTALL_PARAMS InstallParams;
    DWORD i;
    LPWSTR Buffer = NULL;
    DWORD BufferSize;
    LPCWSTR CurrentHardwareId; /* Pointer into Buffer */
    DWORD Property;
    BOOL FoundHardwareId, FoundAtLeastOneDevice = FALSE;
    BOOL RebootRequired = FALSE;
    BOOL ret = FALSE;
    DWORD LastError;

    DevInstData.hDevInfo = INVALID_HANDLE_VALUE;

    TRACE("UpdateDriverForPlugAndPlayDevicesW(%p %s %s 0x%x %p)\n",
        hwndParent, debugstr_w(HardwareId), debugstr_w(FullInfPath), InstallFlags, bRebootRequired);

    /* Check flags */
    if (InstallFlags & ~(INSTALLFLAG_FORCE | INSTALLFLAG_READONLY | INSTALLFLAG_NONINTERACTIVE))
    {
        TRACE("Unknown flags: 0x%08lx\n", InstallFlags & ~(INSTALLFLAG_FORCE | INSTALLFLAG_READONLY | INSTALLFLAG_NONINTERACTIVE));
        SetLastError(ERROR_INVALID_FLAGS);
        goto cleanup;
    }

    if (!HardwareId || !FullInfPath)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        goto cleanup;
    }

    /* Installing a driver package needs an administrator (the Plug and Play service checks it
       again: only it installs, see InstallSelectedDriver) */
    if (!IsSystemContext() && !IsUserAdmin())
    {
        TRACE("The caller is not an administrator\n");
        SetLastError(ERROR_ACCESS_DENIED);
        goto cleanup;
    }

    /* Enumerate all devices of the system */
    DevInstData.hDevInfo = SetupDiGetClassDevsW(NULL, NULL, hwndParent, DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (DevInstData.hDevInfo == INVALID_HANDLE_VALUE)
        goto cleanup;
    DevInstData.devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
    for (i = 0; ; i++)
    {
        if (!SetupDiEnumDeviceInfo(DevInstData.hDevInfo, i, &DevInstData.devInfoData))
        {
            if (GetLastError() != ERROR_NO_MORE_ITEMS)
            {
                TRACE("SetupDiEnumDeviceInfo() failed with error 0x%x\n", GetLastError());
                goto cleanup;
            }
            /* This error was expected */
            break;
        }

        /* Match Hardware ID */
        FoundHardwareId = FALSE;
        Property = SPDRP_HARDWAREID;
        while (TRUE)
        {
            /* Get IDs data */
            Buffer = NULL;
            BufferSize = 0;
            while (!SetupDiGetDeviceRegistryPropertyW(DevInstData.hDevInfo,
                                                      &DevInstData.devInfoData,
                                                      Property,
                                                      NULL,
                                                      (PBYTE)Buffer,
                                                      BufferSize,
                                                      &BufferSize))
            {
                if (GetLastError() == ERROR_FILE_NOT_FOUND)
                {
                    break;
                }
                else if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
                {
                    TRACE("SetupDiGetDeviceRegistryPropertyW() failed with error 0x%x\n", GetLastError());
                    goto cleanup;
                }
                /* This error was expected */
                HeapFree(GetProcessHeap(), 0, Buffer);
                Buffer = HeapAlloc(GetProcessHeap(), 0, BufferSize);
                if (!Buffer)
                {
                    TRACE("HeapAlloc() failed\n", GetLastError());
                    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
                    goto cleanup;
                }
            }
            if (Buffer)
            {
                /* Check if we match the given hardware ID */
                for (CurrentHardwareId = Buffer; *CurrentHardwareId != UNICODE_NULL; CurrentHardwareId += wcslen(CurrentHardwareId) + 1)
                {
                    if (_wcsicmp(CurrentHardwareId, HardwareId) == 0)
                    {
                        FoundHardwareId = TRUE;
                        break;
                    }
                }
            }
            if (FoundHardwareId || Property == SPDRP_COMPATIBLEIDS)
            {
                break;
            }
            Property = SPDRP_COMPATIBLEIDS;
        }
        if (!FoundHardwareId)
            continue;

        /* We need to try to update the driver of this device */

        /* Get Instance ID */
        HeapFree(GetProcessHeap(), 0, Buffer);
        Buffer = NULL;
        if (SetupDiGetDeviceInstanceIdW(DevInstData.hDevInfo, &DevInstData.devInfoData, NULL, 0, &BufferSize))
        {
            /* Error, as the output buffer should be too small */
            SetLastError(ERROR_GEN_FAILURE);
            goto cleanup;
        }
        else if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            TRACE("SetupDiGetDeviceInstanceIdW() failed with error 0x%x\n", GetLastError());
            goto cleanup;
        }
        else if ((Buffer = HeapAlloc(GetProcessHeap(), 0, BufferSize * sizeof(WCHAR))) == NULL)
        {
            TRACE("HeapAlloc() failed\n", GetLastError());
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            goto cleanup;
        }
        else if (!SetupDiGetDeviceInstanceIdW(DevInstData.hDevInfo, &DevInstData.devInfoData, Buffer, BufferSize, NULL))
        {
            TRACE("SetupDiGetDeviceInstanceIdW() failed with error 0x%x\n", GetLastError());
            goto cleanup;
        }
        TRACE("Trying to update the driver of %s\n", debugstr_w(Buffer));

        /* Search driver in the specified .inf file */
        if (!SearchDriver(&DevInstData, NULL, FullInfPath))
        {
            TRACE("SearchDriver() failed with error 0x%x\n", GetLastError());
            continue;
        }

        /* FIXME: HACK! We shouldn't check of ERROR_PRIVILEGE_NOT_HELD */
        //if (!InstallSelectedDriver(&DevInstData, PNP_INSTALL_ORIGIN_UPDATEDRIVER))
        if (!InstallSelectedDriver(&DevInstData, PNP_INSTALL_ORIGIN_UPDATEDRIVER) && GetLastError() != ERROR_PRIVILEGE_NOT_HELD)
        {
            TRACE("InstallSelectedDriver() failed with error 0x%x\n", GetLastError());
            /* Not about this device: the other devices would fail the same way */
            if (GetLastError() == ERROR_ACCESS_DENIED || GetLastError() == ERROR_SERVICE_NOT_ACTIVE)
                goto cleanup;
            continue;
        }

        /* Do we need to reboot? */
        InstallParams.cbSize = sizeof(InstallParams);
        if (SetupDiGetDeviceInstallParams(DevInstData.hDevInfo,
                                          &DevInstData.devInfoData,
                                          &InstallParams))
        {
            if (InstallParams.Flags & (DI_NEEDRESTART | DI_NEEDREBOOT))
                RebootRequired = TRUE;
        }

        FoundAtLeastOneDevice = TRUE;
    }

    if (FoundAtLeastOneDevice)
    {
        if (bRebootRequired)
            *bRebootRequired = RebootRequired;

        SetLastError(NO_ERROR);
        ret = TRUE;
    }
    else
    {
        TRACE("No device found with HardwareID %s\n", debugstr_w(HardwareId));
        SetLastError(ERROR_NO_SUCH_DEVINST);
    }

cleanup:
    LastError = GetLastError();
    if (DevInstData.hDevInfo != INVALID_HANDLE_VALUE)
        SetupDiDestroyDeviceInfoList(DevInstData.hDevInfo);
    HeapFree(GetProcessHeap(), 0, Buffer);
    SetLastError(LastError);
    return ret;
}

/*
* @implemented
*/
BOOL WINAPI
UpdateDriverForPlugAndPlayDevicesA(
    IN HWND hwndParent,
    IN LPCSTR HardwareId,
    IN LPCSTR FullInfPath,
    IN DWORD InstallFlags,
    OUT PBOOL bRebootRequired OPTIONAL)
{
    BOOL Result;
    LPWSTR HardwareIdW = NULL;
    LPWSTR FullInfPathW = NULL;

    int len = MultiByteToWideChar(CP_ACP, 0, HardwareId, -1, NULL, 0);
    HardwareIdW = HeapAlloc(GetProcessHeap(), 0, len * sizeof(WCHAR));
    if (!HardwareIdW)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    MultiByteToWideChar(CP_ACP, 0, HardwareId, -1, HardwareIdW, len);

    len = MultiByteToWideChar(CP_ACP, 0, FullInfPath, -1, NULL, 0);
    FullInfPathW = HeapAlloc(GetProcessHeap(), 0, len * sizeof(WCHAR));
    if (!FullInfPathW)
    {
        HeapFree(GetProcessHeap(), 0, HardwareIdW);
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    MultiByteToWideChar(CP_ACP, 0, FullInfPath, -1, FullInfPathW, len);

    Result = UpdateDriverForPlugAndPlayDevicesW(
        hwndParent,
        HardwareIdW,
        FullInfPathW,
        InstallFlags,
        bRebootRequired);

    HeapFree(GetProcessHeap(), 0, HardwareIdW);
    HeapFree(GetProcessHeap(), 0, FullInfPathW);

    return Result;
}

/* Directory and InfFile MUST NOT be specified simultaneously */
static BOOL
SearchDriver(
    IN PDEVINSTDATA DevInstData,
    IN LPCWSTR Directory OPTIONAL,
    IN LPCWSTR InfFile OPTIONAL)
{
    SP_DEVINSTALL_PARAMS_W DevInstallParams = {0,};
    BOOL ret;

    DevInstallParams.cbSize = sizeof(SP_DEVINSTALL_PARAMS_W);
    if (!SetupDiGetDeviceInstallParamsW(DevInstData->hDevInfo, &DevInstData->devInfoData, &DevInstallParams))
    {
        TRACE("SetupDiGetDeviceInstallParams() failed with error 0x%x\n", GetLastError());
        return FALSE;
    }
    DevInstallParams.FlagsEx |= DI_FLAGSEX_ALLOWEXCLUDEDDRVS;

    if (InfFile)
    {
        DevInstallParams.Flags |= DI_ENUMSINGLEINF;
        wcsncpy(DevInstallParams.DriverPath, InfFile, MAX_PATH);
    }
    else if (Directory)
    {
        DevInstallParams.Flags &= ~DI_ENUMSINGLEINF;
        wcsncpy(DevInstallParams.DriverPath, Directory, MAX_PATH);
    }
    else
    {
        DevInstallParams.Flags &= ~DI_ENUMSINGLEINF;
        *DevInstallParams.DriverPath = '\0';
    }

    ret = SetupDiSetDeviceInstallParamsW(
        DevInstData->hDevInfo,
        &DevInstData->devInfoData,
        &DevInstallParams);
    if (!ret)
    {
        TRACE("SetupDiSetDeviceInstallParams() failed with error 0x%x\n", GetLastError());
        return FALSE;
    }

    ret = SetupDiBuildDriverInfoList(
        DevInstData->hDevInfo,
        &DevInstData->devInfoData,
        SPDIT_COMPATDRIVER);
    if (!ret)
    {
        TRACE("SetupDiBuildDriverInfoList() failed with error 0x%x\n", GetLastError());
        return FALSE;
    }

    DevInstData->drvInfoData.cbSize = sizeof(SP_DRVINFO_DATA);
    ret = SetupDiEnumDriverInfoW(
        DevInstData->hDevInfo,
        &DevInstData->devInfoData,
        SPDIT_COMPATDRIVER,
        0,
        &DevInstData->drvInfoData);
    if (!ret)
    {
        if (GetLastError() == ERROR_NO_MORE_ITEMS)
            return FALSE;
        TRACE("SetupDiEnumDriverInfo() failed with error 0x%x\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

static BOOL
IsDots(IN LPCWSTR str)
{
    if(wcscmp(str, L".") && wcscmp(str, L"..")) return FALSE;
    return TRUE;
}

static LPCWSTR
GetFileExt(IN LPWSTR FileName)
{
    LPCWSTR Dot;

    Dot = wcsrchr(FileName, '.');
    if (!Dot)
        return L"";

    return Dot;
}

static BOOL
SearchDriverRecursive(
    IN PDEVINSTDATA DevInstData,
    IN LPCWSTR Path)
{
    WIN32_FIND_DATAW wfd;
    WCHAR DirPath[MAX_PATH];
    WCHAR FileName[MAX_PATH];
    WCHAR FullPath[MAX_PATH];
    WCHAR LastDirPath[MAX_PATH] = L"";
    WCHAR PathWithPattern[MAX_PATH];
    BOOL ok = TRUE;
    BOOL retval = FALSE;
    HANDLE hFindFile = INVALID_HANDLE_VALUE;

    wcscpy(DirPath, Path);

    if (DirPath[wcslen(DirPath) - 1] != '\\')
        wcscat(DirPath, L"\\");

    wcscpy(PathWithPattern, DirPath);
    wcscat(PathWithPattern, L"*");

    for (hFindFile = FindFirstFileW(PathWithPattern, &wfd);
        ok && hFindFile != INVALID_HANDLE_VALUE;
        ok = FindNextFileW(hFindFile, &wfd))
    {

        wcscpy(FileName, wfd.cFileName);
        if (IsDots(FileName))
            continue;

        if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            /* Recursive search */
            wcscpy(FullPath, DirPath);
            wcscat(FullPath, FileName);
            if (SearchDriverRecursive(DevInstData, FullPath))
            {
                retval = TRUE;
                /* We continue the search for a better driver */
            }
        }
        else
        {
            LPCWSTR pszExtension = GetFileExt(FileName);

            if ((_wcsicmp(pszExtension, L".inf") == 0) && (wcscmp(LastDirPath, DirPath) != 0))
            {
                wcscpy(LastDirPath, DirPath);

                if (wcslen(DirPath) > MAX_PATH)
                    /* Path is too long to be searched */
                    continue;

                if (SearchDriver(DevInstData, DirPath, NULL))
                {
                    retval = TRUE;
                    /* We continue the search for a better driver */
                }

            }
        }
    }

    if (hFindFile != INVALID_HANDLE_VALUE)
        FindClose(hFindFile);
    return retval;
}

BOOL
CheckBestDriver(
    _In_ PDEVINSTDATA DevInstData,
    _In_ PCWSTR pszDir)
{
    return SearchDriverRecursive(DevInstData, pszDir);
}

BOOL
ScanFoldersForDriver(
    IN PDEVINSTDATA DevInstData)
{
    BOOL result;

    /* Search in default location */
    result = SearchDriver(DevInstData, NULL, NULL);

    if (DevInstData->CustomSearchPath)
    {
        /* Search only in specified paths */
        /* We need to check all specified directories to be
         * sure to find the best driver for the device.
         */
        LPCWSTR Path;
        for (Path = DevInstData->CustomSearchPath; *Path != '\0'; Path += wcslen(Path) + 1)
        {
            TRACE("Search driver in %s\n", debugstr_w(Path));
            if (wcslen(Path) == 2 && Path[1] == ':')
            {
                if (SearchDriverRecursive(DevInstData, Path))
                    result = TRUE;
            }
            else
            {
                if (SearchDriver(DevInstData, Path, NULL))
                    result = TRUE;
            }
        }
    }

    return result;
}

BOOL
PrepareFoldersToScan(
    IN PDEVINSTDATA DevInstData,
    IN BOOL IncludeRemovableDevices,
    IN BOOL IncludeCustomPath,
    IN HWND hwndCombo OPTIONAL)
{
    WCHAR drive[] = {'?',':',0};
    DWORD dwDrives = 0;
    DWORD i;
    UINT nType;
    DWORD CustomTextLength = 0;
    DWORD LengthNeeded = 0;
    LPWSTR Buffer;
    INT idx = (INT)SendMessageW(hwndCombo, CB_GETCURSEL, 0, 0);

    /* Calculate length needed to store the search paths */
    if (IncludeRemovableDevices)
    {
        dwDrives = GetLogicalDrives();
        for (drive[0] = 'A', i = 1; drive[0] <= 'Z'; drive[0]++, i <<= 1)
        {
            if (dwDrives & i)
            {
                nType = GetDriveTypeW(drive);
                if (nType == DRIVE_REMOVABLE || nType == DRIVE_CDROM)
                {
                    LengthNeeded += 3;
                }
            }
        }
    }
    if (IncludeCustomPath)
    {
        CustomTextLength = 1 + ((idx != CB_ERR) ?
        (INT)SendMessageW(hwndCombo, CB_GETLBTEXTLEN, idx, 0) : ComboBox_GetTextLength(hwndCombo));
        LengthNeeded += CustomTextLength;
    }

    /* Allocate space for search paths */
    HeapFree(GetProcessHeap(), 0, DevInstData->CustomSearchPath);
    DevInstData->CustomSearchPath = Buffer = HeapAlloc(
        GetProcessHeap(),
        0,
        (LengthNeeded + 1) * sizeof(WCHAR));
    if (!Buffer)
    {
        TRACE("HeapAlloc() failed\n");
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }

    /* Fill search paths */
    if (IncludeRemovableDevices)
    {
        for (drive[0] = 'A', i = 1; drive[0] <= 'Z'; drive[0]++, i <<= 1)
        {
            if (dwDrives & i)
            {
                nType = GetDriveTypeW(drive);
                if (nType == DRIVE_REMOVABLE || nType == DRIVE_CDROM)
                {
                    Buffer += 1 + _swprintf(Buffer, drive);
                }
            }
        }
    }
    if (IncludeCustomPath)
    {
        Buffer += 1 + ((idx != CB_ERR) ?
        SendMessageW(hwndCombo, CB_GETLBTEXT, idx, (LPARAM)Buffer) :
        GetWindowTextW(hwndCombo, Buffer, CustomTextLength));
    }
    *Buffer = '\0';

    return TRUE;
}

BOOL
InstallCurrentDriver(
    IN PDEVINSTDATA DevInstData)
{
    BOOL ret;

    TRACE("Installing driver %s: %s\n",
        debugstr_w(DevInstData->drvInfoData.MfgName),
        debugstr_w(DevInstData->drvInfoData.Description));

    ret = SetupDiCallClassInstaller(
        DIF_SELECTBESTCOMPATDRV,
        DevInstData->hDevInfo,
        &DevInstData->devInfoData);
    if (!ret)
    {
        TRACE("SetupDiCallClassInstaller(DIF_SELECTBESTCOMPATDRV) failed with error 0x%x\n", GetLastError());
        return FALSE;
    }

    ret = SetupDiCallClassInstaller(
        DIF_ALLOW_INSTALL,
        DevInstData->hDevInfo,
        &DevInstData->devInfoData);
    if (!ret)
    {
        TRACE("SetupDiCallClassInstaller(DIF_ALLOW_INSTALL) failed with error 0x%x\n", GetLastError());
        return FALSE;
    }

    ret = SetupDiCallClassInstaller(
        DIF_NEWDEVICEWIZARD_PREANALYZE,
        DevInstData->hDevInfo,
        &DevInstData->devInfoData);
    if (!ret)
    {
        TRACE("SetupDiCallClassInstaller(DIF_NEWDEVICEWIZARD_PREANALYZE) failed with error 0x%x\n", GetLastError());
        return FALSE;
    }

    ret = SetupDiCallClassInstaller(
        DIF_NEWDEVICEWIZARD_POSTANALYZE,
        DevInstData->hDevInfo,
        &DevInstData->devInfoData);
    if (!ret)
    {
        TRACE("SetupDiCallClassInstaller(DIF_NEWDEVICEWIZARD_POSTANALYZE) failed with error 0x%x\n", GetLastError());
        return FALSE;
    }

    ret = SetupDiCallClassInstaller(
        DIF_INSTALLDEVICEFILES,
        DevInstData->hDevInfo,
        &DevInstData->devInfoData);
    if (!ret)
    {
        TRACE("SetupDiCallClassInstaller(DIF_INSTALLDEVICEFILES) failed with error 0x%x\n", GetLastError());
        return FALSE;
    }

    ret = SetupDiCallClassInstaller(
        DIF_REGISTER_COINSTALLERS,
        DevInstData->hDevInfo,
        &DevInstData->devInfoData);
    if (!ret)
    {
        TRACE("SetupDiCallClassInstaller(DIF_REGISTER_COINSTALLERS) failed with error 0x%x\n", GetLastError());
        return FALSE;
    }

    ret = SetupDiCallClassInstaller(
        DIF_INSTALLINTERFACES,
        DevInstData->hDevInfo,
        &DevInstData->devInfoData);
    if (!ret)
    {
        TRACE("SetupDiCallClassInstaller(DIF_INSTALLINTERFACES) failed with error 0x%x\n", GetLastError());
        return FALSE;
    }

    ret = SetupDiCallClassInstaller(
        DIF_INSTALLDEVICE,
        DevInstData->hDevInfo,
        &DevInstData->devInfoData);
    if (!ret)
    {
        TRACE("SetupDiCallClassInstaller(DIF_INSTALLDEVICE) failed with error 0x%x\n", GetLastError());
        return FALSE;
    }

    ret = SetupDiCallClassInstaller(
        DIF_NEWDEVICEWIZARD_FINISHINSTALL,
        DevInstData->hDevInfo,
        &DevInstData->devInfoData);
    if (!ret)
    {
        TRACE("SetupDiCallClassInstaller(DIF_NEWDEVICEWIZARD_FINISHINSTALL) failed with error 0x%x\n", GetLastError());
        return FALSE;
    }

    ret = SetupDiCallClassInstaller(
        DIF_DESTROYPRIVATEDATA,
        DevInstData->hDevInfo,
        &DevInstData->devInfoData);
    if (!ret)
    {
        TRACE("SetupDiCallClassInstaller(DIF_DESTROYPRIVATEDATA) failed with error 0x%x\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

/*
 * Installs the best driver of the device's driver list. In a SYSTEM context (drvinst.exe,
 * setup) the install runs here. Anywhere else this process only picked the driver: the
 * Plug and Play service installs it as SYSTEM, for an administrator only, as on Windows.
 */
BOOL
InstallSelectedDriver(
    IN PDEVINSTDATA DevInstData,
    IN DWORD Origin)
{
    if (IsSystemContext())
        return InstallCurrentDriver(DevInstData);

    return InstallDriverServiceSide(DevInstData, Origin);
}

/*
* @implemented
*/
BOOL WINAPI
DevInstallW(
    IN HWND hWndParent,
    IN HINSTANCE hInstance,
    IN LPCWSTR InstanceId,
    IN INT Show)
{
    PDEVINSTDATA DevInstData = NULL;
    BOOL ret;
    DWORD config_flags;
    BOOL retval = FALSE;
    BOOL NeedRestart = FALSE;

    TRACE("(%p, %p, %s, %d)\n", hWndParent, hInstance, debugstr_w(InstanceId), Show);

    if (!IsUserAdmin())
    {
        /* XP kills the process... */
        ExitProcess(ERROR_ACCESS_DENIED);
    }

    DevInstData = HeapAlloc(GetProcessHeap(), 0, sizeof(DEVINSTDATA));
    if (!DevInstData)
    {
        TRACE("HeapAlloc() failed\n");
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        goto cleanup;
    }

    /* Clear devinst data */
    ZeroMemory(DevInstData, sizeof(DEVINSTDATA));
    DevInstData->devInfoData.cbSize = 0; /* Tell if the devInfoData is valid */

    /* Fill devinst data */
    DevInstData->hDevInfo = SetupDiCreateDeviceInfoListExW(NULL, NULL, NULL, NULL);
    if (DevInstData->hDevInfo == INVALID_HANDLE_VALUE)
    {
        TRACE("SetupDiCreateDeviceInfoListExW() failed with error 0x%x\n", GetLastError());
        goto cleanup;
    }

    DevInstData->devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
    ret = SetupDiOpenDeviceInfoW(
        DevInstData->hDevInfo,
        InstanceId,
        NULL,
        0, /* Open flags */
        &DevInstData->devInfoData);
    if (!ret)
    {
        TRACE("SetupDiOpenDeviceInfoW() failed with error 0x%x (InstanceId %s)\n",
            GetLastError(), debugstr_w(InstanceId));
        DevInstData->devInfoData.cbSize = 0;
        goto cleanup;
    }

    SetLastError(ERROR_GEN_FAILURE);
    ret = SetupDiGetDeviceRegistryProperty(
        DevInstData->hDevInfo,
        &DevInstData->devInfoData,
        SPDRP_DEVICEDESC,
        &DevInstData->regDataType,
        NULL, 0,
        &DevInstData->requiredSize);

    if (!ret && GetLastError() == ERROR_INSUFFICIENT_BUFFER && DevInstData->regDataType == REG_SZ)
    {
        DevInstData->buffer = HeapAlloc(GetProcessHeap(), 0, DevInstData->requiredSize);
        if (!DevInstData->buffer)
        {
            TRACE("HeapAlloc() failed\n");
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        }
        else
        {
            ret = SetupDiGetDeviceRegistryPropertyW(
                DevInstData->hDevInfo,
                &DevInstData->devInfoData,
                SPDRP_DEVICEDESC,
                &DevInstData->regDataType,
                DevInstData->buffer, DevInstData->requiredSize,
                &DevInstData->requiredSize);
        }
    }
    if (!ret)
    {
        TRACE("SetupDiGetDeviceRegistryProperty() failed with error 0x%x (InstanceId %s)\n",
            GetLastError(), debugstr_w(InstanceId));
        goto cleanup;
    }

    if (SetupDiGetDeviceRegistryPropertyW(
        DevInstData->hDevInfo,
        &DevInstData->devInfoData,
        SPDRP_CONFIGFLAGS,
        NULL,
        (BYTE *)&config_flags,
        sizeof(config_flags),
        NULL))
    {
        if (config_flags & CONFIGFLAG_FAILEDINSTALL)
        {
            /* The device is disabled */
            TRACE("Device is disabled\n");
            retval = TRUE;
            goto cleanup;
        }
    }

    TRACE("Installing %s (%s)\n", debugstr_w((PCWSTR)DevInstData->buffer), debugstr_w(InstanceId));

    /* Search driver in default location and removable devices */
    if (!PrepareFoldersToScan(DevInstData, FALSE, FALSE, NULL))
    {
        TRACE("PrepareFoldersToScan() failed with error 0x%lx\n", GetLastError());
        goto cleanup;
    }
    if (ScanFoldersForDriver(DevInstData))
    {
        /* Driver found ; install it */
        retval = InstallSelectedDriver(DevInstData, PNP_INSTALL_ORIGIN_DEVINSTALL);
        TRACE("InstallSelectedDriver() returned %d\n", retval);
        if (retval)
        {
            /* Should we display the 'Need to reboot' page? */
            SP_DEVINSTALL_PARAMS installParams;
            installParams.cbSize = sizeof(SP_DEVINSTALL_PARAMS);
            if (SetupDiGetDeviceInstallParams(
                DevInstData->hDevInfo,
                &DevInstData->devInfoData,
                &installParams))
            {
                if (installParams.Flags & (DI_NEEDRESTART | DI_NEEDREBOOT))
                {
                    if (Show != SW_HIDE)
                    {
                        TRACE("Displaying 'Reboot' wizard page\n");
                        retval = DisplayWizard(DevInstData, hWndParent, IDD_NEEDREBOOT);
                    }
                    else
                    {
                        /* No UI here: the caller (drvinst.exe) has the page shown in the user's session */
                        NeedRestart = TRUE;
                    }
                }
            }
        }
        goto cleanup;
    }
    else if (Show == SW_HIDE)
    {
        /* We can't show the wizard. Fail the install */
        TRACE("No wizard\n");
        goto cleanup;
    }

    /* Prepare the wizard, and display it */
    TRACE("Need to show install wizard\n");
    retval = DisplayWizard(DevInstData, hWndParent, IDD_WELCOMEPAGE);

cleanup:
    if (DevInstData)
    {
        if (DevInstData->devInfoData.cbSize != 0)
        {
            if (!SetupDiDestroyDriverInfoList(DevInstData->hDevInfo, &DevInstData->devInfoData, SPDIT_COMPATDRIVER))
                TRACE("SetupDiDestroyDriverInfoList() failed with error 0x%lx\n", GetLastError());
        }
        if (DevInstData->hDevInfo != INVALID_HANDLE_VALUE)
        {
            if (!SetupDiDestroyDeviceInfoList(DevInstData->hDevInfo))
                TRACE("SetupDiDestroyDeviceInfoList() failed with error 0x%lx\n", GetLastError());
        }
        HeapFree(GetProcessHeap(), 0, DevInstData->buffer);
        HeapFree(GetProcessHeap(), 0, DevInstData);
    }

    if (retval && NeedRestart)
        SetLastError(ERROR_SUCCESS_REBOOT_REQUIRED);

    return retval;
}


/*
 * drvinst.exe's half of an install an administrator asked for (the wizard, Update Driver,
 * UpdateDriverForPlugAndPlayDevices): the Plug and Play service checked the caller and the
 * INF path; this installs the best driver of that INF on the device, without UI. It runs
 * in a SYSTEM context only, so that it is never an install from the caller's process.
 */
BOOL
WINAPI
DevInstallFromInfW(
    IN LPCWSTR InstanceId,
    IN LPCWSTR InfPath,
    IN DWORD Flags)
{
    PDEVINSTDATA DevInstData = NULL;
    SP_DEVINSTALL_PARAMS_W InstallParams;
    BOOL retval = FALSE;
    BOOL NeedRestart = FALSE;
    DWORD Error = ERROR_GEN_FAILURE;

    TRACE("(%s, %s, 0x%lx)\n", debugstr_w(InstanceId), debugstr_w(InfPath), Flags);

    if (!InstanceId || !InfPath || Flags != 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!IsSystemContext())
    {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }

    DevInstData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(DEVINSTDATA));
    if (!DevInstData)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    DevInstData->bUpdate = TRUE;

    DevInstData->hDevInfo = SetupDiCreateDeviceInfoListExW(NULL, NULL, NULL, NULL);
    if (DevInstData->hDevInfo == INVALID_HANDLE_VALUE)
    {
        Error = GetLastError();
        goto cleanup;
    }

    DevInstData->devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
    if (!SetupDiOpenDeviceInfoW(DevInstData->hDevInfo, InstanceId, NULL, 0, &DevInstData->devInfoData))
    {
        Error = GetLastError();
        TRACE("SetupDiOpenDeviceInfoW() failed with error 0x%lx (InstanceId %s)\n", Error, debugstr_w(InstanceId));
        DevInstData->devInfoData.cbSize = 0;
        goto cleanup;
    }

    /* The drivers of this INF only, read from where it is, so that the install copies the
       driver files from there (setupapi stages the INF itself into %SystemRoot%\inf) */
    if (!SearchDriver(DevInstData, NULL, InfPath))
    {
        Error = ERROR_NO_COMPAT_DRIVERS;
        TRACE("No driver for %s in %s\n", debugstr_w(InstanceId), debugstr_w(InfPath));
        goto cleanup;
    }

    retval = InstallCurrentDriver(DevInstData);
    if (!retval)
    {
        Error = GetLastError();
        TRACE("InstallCurrentDriver() failed with error 0x%lx\n", Error);
        goto cleanup;
    }

    InstallParams.cbSize = sizeof(InstallParams);
    if (SetupDiGetDeviceInstallParamsW(DevInstData->hDevInfo, &DevInstData->devInfoData, &InstallParams) &&
        (InstallParams.Flags & (DI_NEEDRESTART | DI_NEEDREBOOT)))
    {
        NeedRestart = TRUE;
    }

cleanup:
    if (DevInstData->devInfoData.cbSize != 0)
        SetupDiDestroyDriverInfoList(DevInstData->hDevInfo, &DevInstData->devInfoData, SPDIT_COMPATDRIVER);
    if (DevInstData->hDevInfo != INVALID_HANDLE_VALUE && DevInstData->hDevInfo != NULL)
        SetupDiDestroyDeviceInfoList(DevInstData->hDevInfo);
    HeapFree(GetProcessHeap(), 0, DevInstData);

    if (retval)
        SetLastError(NeedRestart ? ERROR_SUCCESS_REBOOT_REQUIRED : ERROR_SUCCESS);
    else
        SetLastError(Error ? Error : ERROR_GEN_FAILURE);

    return retval;
}


/* The wizard's restart page alone, for a device the Plug and Play service
   installed in its own context (drvinst.exe) that needs a restart */
static BOOL
ShowRestartPage(
    IN LPCWSTR InstanceId)
{
    PDEVINSTDATA DevInstData;
    BOOL retval = FALSE;

    DevInstData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(DEVINSTDATA));
    if (!DevInstData)
        return FALSE;

    DevInstData->hDevInfo = SetupDiCreateDeviceInfoListExW(NULL, NULL, NULL, NULL);
    if (DevInstData->hDevInfo == INVALID_HANDLE_VALUE)
        goto cleanup;

    DevInstData->devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
    if (!SetupDiOpenDeviceInfoW(DevInstData->hDevInfo, InstanceId, NULL, 0, &DevInstData->devInfoData))
        goto cleanup;

    /* The page names the device by the description its driver gave it */
    if (!SetupDiGetDeviceRegistryPropertyW(DevInstData->hDevInfo,
                                           &DevInstData->devInfoData,
                                           SPDRP_DEVICEDESC,
                                           NULL,
                                           (PBYTE)DevInstData->drvInfoData.Description,
                                           sizeof(DevInstData->drvInfoData.Description) - sizeof(WCHAR),
                                           NULL))
    {
        lstrcpynW(DevInstData->drvInfoData.Description, InstanceId, LINE_LEN);
    }

    retval = DisplayWizard(DevInstData, NULL, IDD_NEEDREBOOT);

cleanup:
    if (DevInstData->hDevInfo != INVALID_HANDLE_VALUE && DevInstData->hDevInfo != NULL)
        SetupDiDestroyDeviceInfoList(DevInstData->hDevInfo);
    HeapFree(GetProcessHeap(), 0, DevInstData);
    return retval;
}


BOOL
WINAPI
InstallDevInstEx(
    IN HWND hWndParent,
    IN LPCWSTR InstanceId,
    IN BOOL bUpdate,
    OUT LPDWORD lpReboot,
    IN DWORD Unknown)
{
    PDEVINSTDATA DevInstData = NULL;
    BOOL ret;
    BOOL retval = FALSE;

    TRACE("InstllDevInstEx(%p, %s, %d, %p, %lx)\n",
          hWndParent, debugstr_w(InstanceId), bUpdate, lpReboot, Unknown);

    DevInstData = HeapAlloc(GetProcessHeap(), 0, sizeof(DEVINSTDATA));
    if (!DevInstData)
    {
        TRACE("HeapAlloc() failed\n");
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        goto cleanup;
    }

    /* Clear devinst data */
    ZeroMemory(DevInstData, sizeof(DEVINSTDATA));
    DevInstData->devInfoData.cbSize = 0; /* Tell if the devInfoData is valid */
    DevInstData->bUpdate = bUpdate;

    /* Fill devinst data */
    DevInstData->hDevInfo = SetupDiCreateDeviceInfoListExW(NULL, NULL, NULL, NULL);
    if (DevInstData->hDevInfo == INVALID_HANDLE_VALUE)
    {
        TRACE("SetupDiCreateDeviceInfoListExW() failed with error 0x%x\n", GetLastError());
        goto cleanup;
    }

    DevInstData->devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
    ret = SetupDiOpenDeviceInfoW(
        DevInstData->hDevInfo,
        InstanceId,
        NULL,
        0, /* Open flags */
        &DevInstData->devInfoData);
    if (!ret)
    {
        TRACE("SetupDiOpenDeviceInfoW() failed with error 0x%x (InstanceId %s)\n",
            GetLastError(), debugstr_w(InstanceId));
        DevInstData->devInfoData.cbSize = 0;
        goto cleanup;
    }

    SetLastError(ERROR_GEN_FAILURE);
    ret = SetupDiGetDeviceRegistryProperty(
        DevInstData->hDevInfo,
        &DevInstData->devInfoData,
        SPDRP_DEVICEDESC,
        &DevInstData->regDataType,
        NULL, 0,
        &DevInstData->requiredSize);

    if (!ret && GetLastError() == ERROR_INSUFFICIENT_BUFFER && DevInstData->regDataType == REG_SZ)
    {
        DevInstData->buffer = HeapAlloc(GetProcessHeap(), 0, DevInstData->requiredSize);
        if (!DevInstData->buffer)
        {
            TRACE("HeapAlloc() failed\n");
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        }
        else
        {
            ret = SetupDiGetDeviceRegistryPropertyW(
                DevInstData->hDevInfo,
                &DevInstData->devInfoData,
                SPDRP_DEVICEDESC,
                &DevInstData->regDataType,
                DevInstData->buffer, DevInstData->requiredSize,
                &DevInstData->requiredSize);
        }
    }

    if (!ret)
    {
        TRACE("SetupDiGetDeviceRegistryProperty() failed with error 0x%x (InstanceId %s)\n",
            GetLastError(), debugstr_w(InstanceId));
        goto cleanup;
    }

    /* Prepare the wizard, and display it */
    TRACE("Need to show install wizard\n");
    retval = DisplayWizard(DevInstData, hWndParent, IDD_WELCOMEPAGE);

cleanup:
    if (DevInstData)
    {
        if (DevInstData->devInfoData.cbSize != 0)
        {
            if (!SetupDiDestroyDriverInfoList(DevInstData->hDevInfo, &DevInstData->devInfoData, SPDIT_COMPATDRIVER))
                TRACE("SetupDiDestroyDriverInfoList() failed with error 0x%lx\n", GetLastError());
        }
        if (DevInstData->hDevInfo != INVALID_HANDLE_VALUE)
        {
            if (!SetupDiDestroyDeviceInfoList(DevInstData->hDevInfo))
                TRACE("SetupDiDestroyDeviceInfoList() failed with error 0x%lx\n", GetLastError());
        }
        HeapFree(GetProcessHeap(), 0, DevInstData->buffer);
        HeapFree(GetProcessHeap(), 0, DevInstData);
    }

    return retval;
}


/*
 * @implemented
 */
BOOL
WINAPI
InstallDevInst(
    IN HWND hWndParent,
    IN LPCWSTR InstanceId,
    IN BOOL bUpdate,
    OUT LPDWORD lpReboot)
{
    return InstallDevInstEx(hWndParent, InstanceId, bUpdate, lpReboot, 0);
}


/*
* @implemented
*/
BOOL WINAPI
ClientSideInstallW(
    IN HWND hWndOwner,
    IN HINSTANCE hInstance,
    IN LPWSTR lpNamedPipeName,
    IN INT Show)
{
    BOOL ReturnValue = FALSE;
    DWORD UiMode;
    DWORD BytesRead;
    DWORD Value;
    HANDLE hPipe = INVALID_HANDLE_VALUE;
    PWSTR DeviceInstance = NULL;
    PWSTR InstallEventName = NULL;
    HANDLE hInstallEvent;

    /* Open the pipe */
    hPipe = CreateFileW(lpNamedPipeName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if(hPipe == INVALID_HANDLE_VALUE)
    {
        ERR("CreateFileW failed with error %u\n", GetLastError());
        goto cleanup;
    }

    /* Read the data. Some is just included for compatibility with Windows right now and not yet used by ReactOS.
       See umpnpmgr for more details. */
    if(!ReadFile(hPipe, &Value, sizeof(Value), &BytesRead, NULL))
    {
        ERR("ReadFile failed with error %u\n", GetLastError());
        goto cleanup;
    }

    InstallEventName = (PWSTR)HeapAlloc(GetProcessHeap(), 0, Value);

    if(!ReadFile(hPipe, InstallEventName, Value, &BytesRead, NULL))
    {
        ERR("ReadFile failed with error %u\n", GetLastError());
        goto cleanup;
    }

    /* I couldn't figure out what the following value means under Windows XP.
       Therefore I used it in umpnpmgr to pass the UI mode (NEWDEV_UI_*). */
    if(!ReadFile(hPipe, &UiMode, sizeof(UiMode), &BytesRead, NULL))
    {
        ERR("ReadFile failed with error %u\n", GetLastError());
        goto cleanup;
    }

    /* Next one is again size in bytes of the following string */
    if(!ReadFile(hPipe, &Value, sizeof(Value), &BytesRead, NULL))
    {
        ERR("ReadFile failed with error %u\n", GetLastError());
        goto cleanup;
    }

    DeviceInstance = (PWSTR)HeapAlloc(GetProcessHeap(), 0, Value);

    if(!ReadFile(hPipe, DeviceInstance, Value, &BytesRead, NULL))
    {
        ERR("ReadFile failed with error %u\n", GetLastError());
        goto cleanup;
    }

    if (UiMode == NEWDEV_UI_RESTART_PAGE)
        ReturnValue = ShowRestartPage(DeviceInstance);
    else
        ReturnValue = DevInstallW(NULL, NULL, DeviceInstance, UiMode != NEWDEV_UI_HIDDEN ? SW_SHOWNOACTIVATE : SW_HIDE);
    if(!ReturnValue)
    {
        ERR("DevInstallW failed with error %lu\n", GetLastError());
        goto cleanup;
    }

    hInstallEvent = CreateEventW(NULL, TRUE, FALSE, InstallEventName);
    if(!hInstallEvent)
    {
        TRACE("CreateEventW('%ls') failed with error %lu\n", InstallEventName, GetLastError());
        goto cleanup;
    }

    SetEvent(hInstallEvent);
    CloseHandle(hInstallEvent);

cleanup:
    if(hPipe != INVALID_HANDLE_VALUE)
        CloseHandle(hPipe);

    if(InstallEventName)
        HeapFree(GetProcessHeap(), 0, InstallEventName);

    if(DeviceInstance)
        HeapFree(GetProcessHeap(), 0, DeviceInstance);

    return ReturnValue;
}

BOOL WINAPI
DllMain(
    IN HINSTANCE hInstance,
    IN DWORD dwReason,
    IN LPVOID lpReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        INITCOMMONCONTROLSEX InitControls;

        DisableThreadLibraryCalls(hInstance);

        InitControls.dwSize = sizeof(INITCOMMONCONTROLSEX);
        InitControls.dwICC = ICC_PROGRESS_CLASS;
        InitCommonControlsEx(&InitControls);
        hDllInstance = hInstance;
    }

    return TRUE;
}
