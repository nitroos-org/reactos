/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Sends the KdHello driver its IOCTLs: kdhellotest [value] [count],
 *              kdhellotest crash (bug checks the machine)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IOCTL_KDHELLO_PING \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KDHELLO_BUGCHECK \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_ACCESS)

int main(int argc, char **argv)
{
    BOOL Crash = (argc > 1) && !strcmp(argv[1], "crash");
    ULONG Value = (argc > 1 && !Crash) ? strtoul(argv[1], NULL, 0) : 41;
    ULONG Count = (argc > 2) ? strtoul(argv[2], NULL, 0) : 1;
    ULONG Out, i;
    DWORD Returned;
    HANDLE Device;

    Device = CreateFileW(L"\\\\.\\KdHello", GENERIC_READ | GENERIC_WRITE, 0, NULL,
                         OPEN_EXISTING, 0, NULL);
    if (Device == INVALID_HANDLE_VALUE)
    {
        printf("kdhellotest: open failed, error %lu\n", GetLastError());
        return 1;
    }

    if (Crash)
    {
        printf("kdhellotest: asking the driver for a bug check\n");
        fflush(stdout);
        DeviceIoControl(Device, IOCTL_KDHELLO_BUGCHECK, NULL, 0, NULL, 0, &Returned, NULL);
        printf("kdhellotest: still running, error %lu\n", GetLastError());
        CloseHandle(Device);
        return 1;
    }

    for (i = 0; i < Count; i++)
    {
        Out = 0;
        if (!DeviceIoControl(Device, IOCTL_KDHELLO_PING, &Value, sizeof(Value),
                             &Out, sizeof(Out), &Returned, NULL))
        {
            printf("kdhellotest: IOCTL failed, error %lu\n", GetLastError());
            CloseHandle(Device);
            return 1;
        }
    }

    printf("kdhellotest: ping %lu -> %lu (%lu calls)\n", Value, Out, Count);
    CloseHandle(Device);
    return (Out == Value + 1) ? 0 : 1;
}
