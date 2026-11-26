/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test that the cached control blocks of closed registry keys are released within seconds
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <ndk/exfuncs.h>
#include <ndk/extypes.h>

#define KEY_COUNT       20000
#define SETTLE_MS       12000
/*
 * Pages that the keys must have cost: the key data of 20000 keys is about 650 pages, the control blocks that stay cached
 * for a few seconds after the close about 1200 more. A system that releases the blocks at once (nothing is held over a
 * table limit) shows only the key data: there is nothing to see, the test is skipped.
 */
#define MIN_GROWTH      1000

static LSTATUS (WINAPI *pRegDeleteTreeW)(HKEY, LPCWSTR);
#define RegDeleteTreeW pRegDeleteTreeW

static LONG GetPagedPoolPages(void)
{
    SYSTEM_PERFORMANCE_INFORMATION Info;
    NTSTATUS Status;

    Status = NtQuerySystemInformation(SystemPerformanceInformation, &Info, sizeof(Info), NULL);
    ok(Status == STATUS_SUCCESS, "NtQuerySystemInformation returned 0x%08lx\n", Status);
    return NT_SUCCESS(Status) ? (LONG)Info.PagedPoolPages : 0;
}

/*
 * The registry caches a control block for every key that was opened, and keeps the blocks of closed keys in a table of
 * a limited size: what is over the limit is released by a worker that a timer starts five seconds after the table
 * overflowed. A scan of many keys therefore leaves their blocks for a few seconds, then the worker frees all of them
 * (not a fixed small part per run: a table that only shrank by 512 entries every five seconds took minutes to empty).
 * The cost of a control block is paged pool: a good part of what the scan added must be gone after SETTLE_MS.
 */
START_TEST(RegClosedKeysDrain)
{
    HKEY Root, Key;
    LONG Error, Before, Peak, After;
    ULONG i;
    WCHAR Name[32];

    pRegDeleteTreeW = (PVOID)GetProcAddress(GetModuleHandleW(L"advapi32.dll"), "RegDeleteTreeW");
    if (!pRegDeleteTreeW)
    {
        skip("RegDeleteTreeW is not available\n");
        return;
    }

    Error = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\ReactOSTestClosedKeysDrain", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Root, NULL);
    ok(Error == ERROR_SUCCESS, "RegCreateKeyExW failed: %ld\n", Error);
    if (Error != ERROR_SUCCESS)
        return;

    Before = GetPagedPoolPages();
    for (i = 0; i < KEY_COUNT; i++)
    {
        _snwprintf(Name, _countof(Name), L"k%05lu", i);
        Error = RegCreateKeyExW(Root, Name, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Key, NULL);
        if (Error != ERROR_SUCCESS)
        {
            ok(0, "RegCreateKeyExW of key %lu failed: %ld\n", i, Error);
            goto Cleanup;
        }
        RegCloseKey(Key);
    }
    for (i = 0; i < KEY_COUNT; i++)
    {
        _snwprintf(Name, _countof(Name), L"k%05lu", i);
        if (RegOpenKeyExW(Root, Name, 0, KEY_READ, &Key) == ERROR_SUCCESS)
            RegCloseKey(Key);
    }
    Peak = GetPagedPoolPages();

    Sleep(SETTLE_MS);
    After = GetPagedPoolPages();
    trace("Paged pool pages: %ld before, %ld after %d keys, %ld after %d ms\n", Before, Peak, KEY_COUNT, After, SETTLE_MS);

    if (Peak - Before < MIN_GROWTH)
    {
        skip("The keys cost only %ld pages: no closed key control blocks are held\n", Peak - Before);
    }
    else
    {
        ok(Peak - After >= (Peak - Before) / 4,
           "Only %ld of the %ld pages that %d keys cost were released after %d ms\n",
           Peak - After, Peak - Before, KEY_COUNT, SETTLE_MS);
    }

Cleanup:
    RegCloseKey(Root);
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\ReactOSTestClosedKeysDrain");
}
