/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     RDBSS tests: the second process of RdbssHostile (rdbsshostile.exe)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 *
 * Usage: rdbsshostile <root> <seconds> <seed>. Runs the hostile operations of
 * RdbssHostile.h on the same files as the kmtest process (mapped views,
 * truncation, locks, cancellation) and exits with the number of problems
 * found (0 when everything ended and nothing suspicious came back).
 */

#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winioctl.h>
#define NTOS_MODE_USER
#include <ndk/iofuncs.h>
#include <ndk/rtlfuncs.h>
#include <ntstatus.h>
#include <stdio.h>
#include <stdlib.h>
#include <pseh/pseh2.h>

#include "RdbssLoop.h"
#include "RdbssHostile.h"

int
wmain(
    int argc,
    WCHAR **argv)
{
    ULONG Seconds, Seed, Ops, Errors, Problems, Mask = 0xFFFFFFFF;

    if (argc < 4)
    {
        printf("usage: rdbsshostile <root> <seconds> <seed> [ops mask]\n");
        return 255;
    }
    Seconds = wcstoul(argv[2], NULL, 10);
    Seed = wcstoul(argv[3], NULL, 10);
    if (argc >= 5)
        Mask = wcstoul(argv[4], NULL, 16);

    Problems = HostileRun(argv[1], 4, Seconds, Seed, NULL, Mask, &Ops, &Errors);
    printf("rdbsshostile: %lu s, 4 threads, %lu operations, %lu failed, %lu problems\n", Seconds, Ops, Errors, Problems);
    return (int)Problems;
}
