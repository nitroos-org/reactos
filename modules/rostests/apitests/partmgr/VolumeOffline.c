/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test for the offline state of a volume (IOCTL_VOLUME_OFFLINE, ONLINE, IS_OFFLINE)
 */

#include "precomp.h"
#include <winioctl.h>
#include <ntddvol.h>

#define FILE_SHARE_ALL (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)

/* A fixed volume that is not the one Windows runs from, has a drive letter and can be locked: a data disk of the test machine */
static BOOL
FindScratchVolume(_Out_writes_(cchName) PWSTR Name, _In_ DWORD cchName)
{
    WCHAR Candidate[MAX_PATH], Paths[MAX_PATH], SystemRoot[MAX_PATH];
    HANDLE Find = FindFirstVolumeW(Candidate, ARRAYSIZE(Candidate));
    BOOL Found = FALSE;
    DWORD Length;

    if (Find == INVALID_HANDLE_VALUE)
        return FALSE;
    GetWindowsDirectoryW(SystemRoot, ARRAYSIZE(SystemRoot));

    do
    {
        if (GetDriveTypeW(Candidate) != DRIVE_FIXED)
            continue;
        if (!GetVolumePathNamesForVolumeNameW(Candidate, Paths, ARRAYSIZE(Paths), &Length) || !Paths[0])
            continue;
        if ((Paths[0] | 0x20) == (SystemRoot[0] | 0x20))
            continue;
        lstrcpynW(Name, Candidate, cchName);
        Found = TRUE;
    } while (!Found && FindNextVolumeW(Find, Candidate, ARRAYSIZE(Candidate)));

    FindVolumeClose(Find);
    return Found;
}

START_TEST(VolumeOffline)
{
    WCHAR Volume[MAX_PATH], Device[MAX_PATH], Label[MAX_PATH], Fs[MAX_PATH];
    HANDLE Handle, Reader;
    DWORD Returned;
    BOOL Ret, Locked;
    CHAR Sector[512];

    if (!FindScratchVolume(Volume, ARRAYSIZE(Volume)))
    {
        skip("No fixed data volume besides the system volume\n");
        return;
    }

    /* \\?\Volume{guid}\ -> \\.\Volume{guid} */
    lstrcpynW(Device, Volume, ARRAYSIZE(Device));
    Device[1] = L'\\';
    Device[2] = L'.';
    Device[wcslen(Device) - 1] = UNICODE_NULL;

    Handle = CreateFileW(Device, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_ALL, NULL, OPEN_EXISTING, 0, NULL);
    if (Handle == INVALID_HANDLE_VALUE)
    {
        skip("Cannot open %ls (%lu)\n", Device, GetLastError());
        return;
    }

    /* online: IS_OFFLINE fails with 31, the other two succeed */
    SetLastError(0xdeadbeef);
    Ret = DeviceIoControl(Handle, IOCTL_VOLUME_IS_OFFLINE, NULL, 0, NULL, 0, &Returned, NULL);
    ok(!Ret, "IOCTL_VOLUME_IS_OFFLINE of an online volume succeeded\n");
    ok_dec(GetLastError(), ERROR_GEN_FAILURE);
    Ret = DeviceIoControl(Handle, IOCTL_VOLUME_IS_IO_CAPABLE, NULL, 0, NULL, 0, &Returned, NULL);
    ok(Ret, "IOCTL_VOLUME_IS_IO_CAPABLE failed (%lu)\n", GetLastError());
    Ret = DeviceIoControl(Handle, IOCTL_VOLUME_SUPPORTS_ONLINE_OFFLINE, NULL, 0, NULL, 0, &Returned, NULL);
    ok(Ret, "IOCTL_VOLUME_SUPPORTS_ONLINE_OFFLINE failed (%lu)\n", GetLastError());

    /* only a volume nobody uses is taken offline here */
    Locked = DeviceIoControl(Handle, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &Returned, NULL);
    if (!Locked)
    {
        skip("The volume is in use (%lu)\n", GetLastError());
        CloseHandle(Handle);
        return;
    }
    Ret = DeviceIoControl(Handle, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &Returned, NULL);
    ok(Ret, "FSCTL_DISMOUNT_VOLUME failed (%lu)\n", GetLastError());

    Ret = DeviceIoControl(Handle, IOCTL_VOLUME_OFFLINE, NULL, 0, NULL, 0, &Returned, NULL);
    ok(Ret, "IOCTL_VOLUME_OFFLINE failed (%lu)\n", GetLastError());
    Ret = DeviceIoControl(Handle, IOCTL_VOLUME_IS_OFFLINE, NULL, 0, NULL, 0, &Returned, NULL);
    ok(Ret, "IOCTL_VOLUME_IS_OFFLINE of an offline volume failed (%lu)\n", GetLastError());
    Ret = DeviceIoControl(Handle, IOCTL_VOLUME_IS_IO_CAPABLE, NULL, 0, NULL, 0, &Returned, NULL);
    ok(Ret, "IOCTL_VOLUME_IS_IO_CAPABLE of an offline volume failed (%lu)\n", GetLastError());

    /* a second handle sees the state, and cannot read the volume or reach its files */
    Reader = CreateFileW(Device, GENERIC_READ, FILE_SHARE_ALL, NULL, OPEN_EXISTING, 0, NULL);
    ok(Reader != INVALID_HANDLE_VALUE, "Opening an offline volume failed (%lu)\n", GetLastError());
    if (Reader != INVALID_HANDLE_VALUE)
    {
        Ret = DeviceIoControl(Reader, IOCTL_VOLUME_IS_OFFLINE, NULL, 0, NULL, 0, &Returned, NULL);
        ok(Ret, "IOCTL_VOLUME_IS_OFFLINE on a second handle failed (%lu)\n", GetLastError());
        SetLastError(0xdeadbeef);
        Ret = ReadFile(Reader, Sector, sizeof(Sector), &Returned, NULL);
        ok(!Ret, "Reading an offline volume succeeded\n");
        ok_dec(GetLastError(), ERROR_NOT_READY);
        CloseHandle(Reader);
    }
    Ret = GetVolumeInformationW(Volume, Label, ARRAYSIZE(Label), NULL, NULL, NULL, Fs, ARRAYSIZE(Fs));
    ok(!Ret, "GetVolumeInformationW of an offline volume succeeded\n");

    /* online again: everything is back */
    Ret = DeviceIoControl(Handle, IOCTL_VOLUME_ONLINE, NULL, 0, NULL, 0, &Returned, NULL);
    ok(Ret, "IOCTL_VOLUME_ONLINE failed (%lu)\n", GetLastError());
    SetLastError(0xdeadbeef);
    Ret = DeviceIoControl(Handle, IOCTL_VOLUME_IS_OFFLINE, NULL, 0, NULL, 0, &Returned, NULL);
    ok(!Ret, "IOCTL_VOLUME_IS_OFFLINE after IOCTL_VOLUME_ONLINE succeeded\n");
    ok_dec(GetLastError(), ERROR_GEN_FAILURE);
    DeviceIoControl(Handle, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &Returned, NULL);
    CloseHandle(Handle);

    Ret = GetVolumeInformationW(Volume, Label, ARRAYSIZE(Label), NULL, NULL, NULL, Fs, ARRAYSIZE(Fs));
    ok(Ret, "GetVolumeInformationW after IOCTL_VOLUME_ONLINE failed (%lu)\n", GetLastError());
}
