/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     IOCTL_DISK_SET_CACHE_INFORMATION on \\.\PhysicalDrive0: the write cache that the drive reports as
 *              changeable can be switched off and on again
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * classpnp reports StorageDeviceWriteCacheProperty's WriteCacheChangeable from MODE SENSE, so a drive that says
 * "changeable" has to accept the MODE SELECT behind IOCTL_DISK_SET_CACHE_INFORMATION. The cache is put back as it was.
 */

#include "precomp.h"

#include <winioctl.h>
#include <ntddstor.h>

static BOOL
GetCache(HANDLE Disk, DISK_CACHE_INFORMATION *Cache, DWORD *Error)
{
    DWORD Returned = 0;
    BOOL Ok;

    memset(Cache, 0, sizeof(*Cache));
    SetLastError(0xDEADBEEF);
    Ok = DeviceIoControl(Disk, IOCTL_DISK_GET_CACHE_INFORMATION, NULL, 0, Cache, sizeof(*Cache), &Returned, NULL);
    *Error = GetLastError();
    return Ok;
}

START_TEST(DiskCacheInformation)
{
    STORAGE_PROPERTY_QUERY Query = { StorageDeviceWriteCacheProperty, PropertyStandardQuery };
    STORAGE_WRITE_CACHE_PROPERTY Property;
    DISK_CACHE_INFORMATION Before, Now, Set;
    HANDLE Disk;
    DWORD Error, Returned = 0;
    BOOL Ok;

    Disk = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                       OPEN_EXISTING, 0, NULL);
    if (Disk == INVALID_HANDLE_VALUE)
    {
        skip("\\\\.\\PhysicalDrive0: %lu\n", GetLastError());
        return;
    }

    memset(&Property, 0, sizeof(Property));
    if (!DeviceIoControl(Disk, IOCTL_STORAGE_QUERY_PROPERTY, &Query, sizeof(Query), &Property, sizeof(Property), &Returned, NULL) ||
        Property.WriteCacheChangeable != WriteCacheChangeable)
    {
        skip("the drive does not report a write cache it can change (error %lu, changeable %d)\n", GetLastError(),
             (int)Property.WriteCacheChangeable);
        CloseHandle(Disk);
        return;
    }

    Ok = GetCache(Disk, &Before, &Error);
    ok(Ok, "IOCTL_DISK_GET_CACHE_INFORMATION failed %lu\n", Error);
    if (!Ok)
    {
        CloseHandle(Disk);
        return;
    }

    /* the other way round from what it is now, and back */
    Set = Before;
    Set.WriteCacheEnabled = !Before.WriteCacheEnabled;
    SetLastError(0xDEADBEEF);
    Ok = DeviceIoControl(Disk, IOCTL_DISK_SET_CACHE_INFORMATION, &Set, sizeof(Set), NULL, 0, &Returned, NULL);
    ok(Ok, "switching the write cache %s failed %lu\n", Set.WriteCacheEnabled ? "on" : "off", GetLastError());
    if (Ok)
    {
        ok(GetCache(Disk, &Now, &Error) && Now.WriteCacheEnabled == Set.WriteCacheEnabled,
           "the write cache is %d after it was set to %d (error %lu)\n", Now.WriteCacheEnabled, Set.WriteCacheEnabled, Error);
        ok(Now.ReadCacheEnabled == Before.ReadCacheEnabled, "the read cache went from %d to %d\n", Before.ReadCacheEnabled,
           Now.ReadCacheEnabled);

        SetLastError(0xDEADBEEF);
        Ok = DeviceIoControl(Disk, IOCTL_DISK_SET_CACHE_INFORMATION, &Before, sizeof(Before), NULL, 0, &Returned, NULL);
        ok(Ok, "restoring the write cache failed %lu\n", GetLastError());
        ok(GetCache(Disk, &Now, &Error) && Now.WriteCacheEnabled == Before.WriteCacheEnabled,
           "the write cache is %d, expected %d again (error %lu)\n", Now.WriteCacheEnabled, Before.WriteCacheEnabled, Error);
    }

    CloseHandle(Disk);
}
