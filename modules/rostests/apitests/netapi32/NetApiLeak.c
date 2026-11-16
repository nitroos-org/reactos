/*
 * PROJECT:     ReactOS netapi32.dll API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     NetWkstaGetInfo and NetUserEnum return one buffer that NetApiBufferFree frees whole
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>

#define WIN32_NO_STATUS
#include <stdio.h>
#include <windef.h>
#include <winbase.h>
#include <lmcons.h>
#include <lmerr.h>
#include <lmapibuf.h>
#include <lmwksta.h>
#include <lmaccess.h>

#define CALL_ITERATIONS     10000
#define WARMUP_ITERATIONS   200

typedef struct _HEAP_TOTALS
{
    SIZE_T Blocks;
    SIZE_T Bytes;
} HEAP_TOTALS;

/* Busy blocks and bytes in every heap of the process */
static void SnapshotHeaps(HEAP_TOTALS *Totals)
{
    HANDLE Heaps[64];
    PROCESS_HEAP_ENTRY Entry;
    DWORD Count, i;

    Totals->Blocks = 0;
    Totals->Bytes = 0;
    Count = GetProcessHeaps(ARRAYSIZE(Heaps), Heaps);
    if (Count > ARRAYSIZE(Heaps))
        Count = ARRAYSIZE(Heaps);
    for (i = 0; i < Count; i++)
    {
        if (!HeapLock(Heaps[i]))
            continue;
        Entry.lpData = NULL;
        while (HeapWalk(Heaps[i], &Entry))
        {
            if ((Entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) && !(Entry.wFlags & PROCESS_HEAP_REGION))
            {
                Totals->Blocks++;
                Totals->Bytes += Entry.cbData;
            }
        }
        HeapUnlock(Heaps[i]);
    }
}

static BOOL InBuffer(PVOID Buffer, DWORD Size, LPCWSTR String)
{
    PUCHAR Start = Buffer, P = (PUCHAR)String;
    SIZE_T Length = (wcslen(String) + 1) * sizeof(WCHAR);

    return P >= Start && Length <= Size && (SIZE_T)(P - Start) <= Size - Length;
}

static void CheckStringInBuffer(PVOID Buffer, LPCWSTR String, PCSTR What)
{
    DWORD Size = 0;
    NET_API_STATUS Status;

    if (String == NULL)
        return;
    Status = NetApiBufferSize(Buffer, &Size);
    ok(Status == NERR_Success, "%s: NetApiBufferSize returned %lu\n", What, Status);
    ok(InBuffer(Buffer, Size, String), "%s: string %p is outside the %lu byte buffer at %p\n", What, String, Size, Buffer);
}

static BOOL WkstaOnce(DWORD Level, BOOL Check)
{
    LPBYTE Buffer = NULL;
    NET_API_STATUS Status;

    Status = NetWkstaGetInfo(NULL, Level, &Buffer);
    if (Status != NERR_Success)
        return FALSE;
    ok(Buffer != NULL, "NetWkstaGetInfo(%lu) returned no buffer\n", Level);

    if (Check && Buffer != NULL)
    {
        switch (Level)
        {
            case 100:
            {
                LPWKSTA_INFO_100 Info = (LPWKSTA_INFO_100)Buffer;
                CheckStringInBuffer(Buffer, Info->wki100_computername, "wksta 100 computer name");
                CheckStringInBuffer(Buffer, Info->wki100_langroup, "wksta 100 domain");
                break;
            }
            case 101:
            {
                LPWKSTA_INFO_101 Info = (LPWKSTA_INFO_101)Buffer;
                CheckStringInBuffer(Buffer, Info->wki101_computername, "wksta 101 computer name");
                CheckStringInBuffer(Buffer, Info->wki101_langroup, "wksta 101 domain");
                CheckStringInBuffer(Buffer, Info->wki101_lanroot, "wksta 101 lanroot");
                break;
            }
            case 102:
            {
                LPWKSTA_INFO_102 Info = (LPWKSTA_INFO_102)Buffer;
                CheckStringInBuffer(Buffer, Info->wki102_computername, "wksta 102 computer name");
                CheckStringInBuffer(Buffer, Info->wki102_langroup, "wksta 102 domain");
                CheckStringInBuffer(Buffer, Info->wki102_lanroot, "wksta 102 lanroot");
                break;
            }
        }
    }

    Status = NetApiBufferFree(Buffer);
    ok(Status == NERR_Success, "NetApiBufferFree returned %lu\n", Status);
    return TRUE;
}

static BOOL UserEnumOnce(DWORD Level)
{
    LPBYTE Buffer = NULL;
    DWORD Read = 0, Total = 0, Resume = 0;
    NET_API_STATUS Status;

    Status = NetUserEnum(NULL, Level, 0, &Buffer, MAX_PREFERRED_LENGTH, &Read, &Total, &Resume);
    if (Status != NERR_Success)
        return FALSE;
    if (Buffer != NULL)
        NetApiBufferFree(Buffer);
    return TRUE;
}

static void CheckGrowth(PCSTR What, HEAP_TOTALS *Before, HEAP_TOTALS *After)
{
    trace("%s: heap busy before: %Iu blocks, %Iu bytes; after %d calls: %Iu blocks, %Iu bytes\n",
          What, Before->Blocks, Before->Bytes, CALL_ITERATIONS, After->Blocks, After->Bytes);
    /* A leak costs at least one block per call; allow slack for the RPC runtime's own caches */
    ok(After->Blocks < Before->Blocks + 100, "%s: heap blocks grew from %Iu to %Iu\n", What, Before->Blocks, After->Blocks);
    ok(After->Bytes < Before->Bytes + 32 * 1024, "%s: heap bytes grew from %Iu to %Iu\n", What, Before->Bytes, After->Bytes);
}

START_TEST(NetApiLeak)
{
    static const DWORD WkstaLevels[] = { 100, 101, 102 };
    static const DWORD UserLevels[] = { 0, 1, 2, 3, 20 };
    HEAP_TOTALS Before, After;
    char Name[32];
    ULONG i, k;

    for (k = 0; k < ARRAYSIZE(WkstaLevels); k++)
    {
        sprintf(Name, "NetWkstaGetInfo(%lu)", WkstaLevels[k]);
        if (!WkstaOnce(WkstaLevels[k], TRUE))
        {
            skip("%s failed\n", Name);
            continue;
        }

        for (i = 0; i < WARMUP_ITERATIONS; i++)
            WkstaOnce(WkstaLevels[k], FALSE);
        SnapshotHeaps(&Before);
        for (i = 0; i < CALL_ITERATIONS; i++)
            WkstaOnce(WkstaLevels[k], FALSE);
        SnapshotHeaps(&After);
        CheckGrowth(Name, &Before, &After);
    }

    for (k = 0; k < ARRAYSIZE(UserLevels); k++)
    {
        sprintf(Name, "NetUserEnum(%lu)", UserLevels[k]);
        if (!UserEnumOnce(UserLevels[k]))
        {
            skip("%s failed\n", Name);
            continue;
        }

        for (i = 0; i < WARMUP_ITERATIONS; i++)
            UserEnumOnce(UserLevels[k]);
        SnapshotHeaps(&Before);
        for (i = 0; i < CALL_ITERATIONS; i++)
            UserEnumOnce(UserLevels[k]);
        SnapshotHeaps(&After);
        CheckGrowth(Name, &Before, &After);
    }
}
