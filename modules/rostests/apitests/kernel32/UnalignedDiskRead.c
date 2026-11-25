/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Reads of \\.\PhysicalDrive0 into buffers that start at any offset of a page give the same bytes and the full
 *              length as a read into an aligned buffer
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * classpnp splits a request into pieces when the port driver reports too little memory (InitLowMemRetry); a buffer
 * that does not start on a sector boundary of its page used to make a piece that is not a whole number of sectors and
 * a request that completed short. Nothing here makes the port driver fail: the test guards the plain path (the retry
 * path was driven by a port driver that fails every few requests, see the notes of the ticket).
 */

#include "precomp.h"

#include <winioctl.h>

#define READ_SIZE   0x10000
#define READ_COUNT  8

static const ULONG Offsets[] = { 0, 0x10, 0x200, 0x1F0, 0x210, 0x400, 0xE00, 0xFF0, 0x4 };

START_TEST(UnalignedDiskRead)
{
    PUCHAR Pages, Reference, Buffer;
    HANDLE Disk;
    DISK_GEOMETRY Geometry;
    LARGE_INTEGER Position;
    DWORD Returned, Read;
    ULONG i, n;
    BOOL Ok;

    Disk = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (Disk == INVALID_HANDLE_VALUE)
    {
        skip("\\\\.\\PhysicalDrive0: %lu\n", GetLastError());
        return;
    }
    if (!DeviceIoControl(Disk, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &Geometry, sizeof(Geometry), &Returned, NULL))
    {
        skip("no geometry: %lu\n", GetLastError());
        CloseHandle(Disk);
        return;
    }

    Pages = VirtualAlloc(NULL, 2 * (READ_SIZE + 2 * 0x1000), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ok(Pages != NULL, "VirtualAlloc failed %lu\n", GetLastError());
    if (!Pages)
    {
        CloseHandle(Disk);
        return;
    }
    Reference = Pages;
    Buffer = Pages + READ_SIZE + 2 * 0x1000;

    for (n = 0; n < READ_COUNT; n++)
    {
        Position.QuadPart = (LONGLONG)n * 0x23000;     /* whole sectors, not on a 64K boundary */
        Position.QuadPart -= Position.QuadPart % Geometry.BytesPerSector;

        ok(SetFilePointerEx(Disk, Position, NULL, FILE_BEGIN), "SetFilePointerEx failed %lu\n", GetLastError());
        Read = 0;
        Ok = ReadFile(Disk, Reference, READ_SIZE, &Read, NULL);
        ok(Ok && Read == READ_SIZE, "reference read at %I64d: %d, %lu bytes, error %lu\n", Position.QuadPart, Ok, Read, GetLastError());

        for (i = 0; i < _countof(Offsets); i++)
        {
            memset(Buffer, 0x5A, READ_SIZE + 0x1000);
            ok(SetFilePointerEx(Disk, Position, NULL, FILE_BEGIN), "SetFilePointerEx failed %lu\n", GetLastError());
            Read = 0;
            SetLastError(0xDEADBEEF);
            Ok = ReadFile(Disk, Buffer + Offsets[i], READ_SIZE, &Read, NULL);
            if (!Ok && (GetLastError() == ERROR_INVALID_PARAMETER || GetLastError() == ERROR_NOACCESS))
            {
                /* a buffer that is not aligned to the device is refused: nothing to check at this offset */
                continue;
            }
            ok(Ok && Read == READ_SIZE, "read at %I64d into offset %#lx: %d, %lu bytes, error %lu\n", Position.QuadPart, Offsets[i], Ok, Read, GetLastError());
            ok(Read != READ_SIZE || !memcmp(Buffer + Offsets[i], Reference, READ_SIZE),
               "read at %I64d into offset %#lx gives other bytes\n", Position.QuadPart, Offsets[i]);
        }
    }

    VirtualFree(Pages, 0, MEM_RELEASE);
    CloseHandle(Disk);
}
