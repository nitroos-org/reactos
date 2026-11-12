/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Kernel-Mode Test Suite for ExInitializeLookasideListEx,
 *              ExFlushLookasideListEx and ExDeleteLookasideListEx
 */

#include <kmt_test.h>

typedef NTSTATUS (NTAPI *PEX_INIT_EX)(PLOOKASIDE_LIST_EX, PALLOCATE_FUNCTION_EX, PFREE_FUNCTION_EX,
                                      POOL_TYPE, ULONG, SIZE_T, ULONG, USHORT);
typedef VOID (NTAPI *PEX_LISTOP_EX)(PLOOKASIDE_LIST_EX);

/* the documented behaviour of the allocation and free fast paths (the
   inline versions need a newer DDI level than these tests are built for) */
static
PVOID
ExAllocateFromLookasideListEx(
    _Inout_ PLOOKASIDE_LIST_EX Lookaside)
{
    PVOID Entry;

    Lookaside->L.TotalAllocates += 1;
    Entry = InterlockedPopEntrySList(&Lookaside->L.ListHead);
    if (Entry == NULL)
    {
        Lookaside->L.AllocateMisses += 1;
        Entry = Lookaside->L.AllocateEx(Lookaside->L.Type, Lookaside->L.Size, Lookaside->L.Tag, Lookaside);
    }
    return Entry;
}

static
VOID
ExFreeToLookasideListEx(
    _Inout_ PLOOKASIDE_LIST_EX Lookaside,
    _In_ PVOID Entry)
{
    Lookaside->L.TotalFrees += 1;
    if (ExQueryDepthSList(&Lookaside->L.ListHead) >= Lookaside->L.Depth)
    {
        Lookaside->L.FreeMisses += 1;
        Lookaside->L.FreeEx(Entry, Lookaside);
    }
    else
    {
        InterlockedPushEntrySList(&Lookaside->L.ListHead, (PSLIST_ENTRY)Entry);
    }
}

static LONG Allocations;
static LONG Frees;
static PLOOKASIDE_LIST_EX LastList;

static
PVOID
NTAPI
MyAllocate(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag,
    _Inout_ PLOOKASIDE_LIST_EX Lookaside)
{
    LastList = Lookaside;
    InterlockedIncrement(&Allocations);
    return ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag);
}

static
VOID
NTAPI
MyFree(
    _In_ PVOID Buffer,
    _Inout_ PLOOKASIDE_LIST_EX Lookaside)
{
    LastList = Lookaside;
    InterlockedIncrement(&Frees);
    ExFreePoolWithTag(Buffer, 'kLtK');
}

START_TEST(ExLookasideListEx)
{
    PEX_INIT_EX pInit = KmtGetSystemRoutineAddress(L"ExInitializeLookasideListEx");
    PEX_LISTOP_EX pFlush = KmtGetSystemRoutineAddress(L"ExFlushLookasideListEx");
    PEX_LISTOP_EX pDelete = KmtGetSystemRoutineAddress(L"ExDeleteLookasideListEx");
    LOOKASIDE_LIST_EX List;
    PVOID Entry[8];
    NTSTATUS Status;
    ULONG i;

    ok(pInit != NULL, "ExInitializeLookasideListEx is not exported\n");
    ok(pFlush != NULL, "ExFlushLookasideListEx is not exported\n");
    ok(pDelete != NULL, "ExDeleteLookasideListEx is not exported\n");
    if (!pInit || !pFlush || !pDelete)
        return;

    /* parameter checks: both flags, an unknown flag, a too small size */
    Status = pInit(&List, NULL, NULL, NonPagedPool, 3, 64, 'kLtK', 0);
    ok_eq_hex(Status, STATUS_INVALID_PARAMETER);
    Status = pInit(&List, NULL, NULL, NonPagedPool, 0x80, 64, 'kLtK', 0);
    ok_eq_hex(Status, STATUS_INVALID_PARAMETER);
    Status = pInit(&List, NULL, NULL, NonPagedPool, 0, 1, 'kLtK', 0);
    ok_eq_hex(Status, STATUS_INVALID_PARAMETER);

    /* default allocate and free routines */
    Status = pInit(&List, NULL, NULL, NonPagedPool, 0, 64, 'kLtK', 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        Entry[0] = ExAllocateFromLookasideListEx(&List);
        ok(Entry[0] != NULL, "allocation failed\n");
        ok_eq_ulong(List.L.TotalAllocates, 1);
        ok_eq_ulong(List.L.AllocateMisses, 1);
        if (Entry[0])
        {
            RtlFillMemory(Entry[0], 64, 0xAA);
            ExFreeToLookasideListEx(&List, Entry[0]);
            /* the entry is cached: the next allocation is a hit */
            Entry[1] = ExAllocateFromLookasideListEx(&List);
            ok_eq_pointer(Entry[1], Entry[0]);
            ok_eq_ulong(List.L.AllocateMisses, 1);
            ExFreeToLookasideListEx(&List, Entry[1]);
        }
        pDelete(&List);
    }

    /* our own routines get the list as last parameter */
    Allocations = Frees = 0;
    Status = pInit(&List, MyAllocate, MyFree, NonPagedPool, 0, 64, 'kLtK', 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        for (i = 0; i < RTL_NUMBER_OF(Entry); i++)
            Entry[i] = ExAllocateFromLookasideListEx(&List);
        ok_eq_long(Allocations, (LONG)RTL_NUMBER_OF(Entry));
        ok_eq_pointer(LastList, &List);
        for (i = 0; i < RTL_NUMBER_OF(Entry); i++)
            if (Entry[i])
                ExFreeToLookasideListEx(&List, Entry[i]);
        /* more than the depth were freed: the surplus went to our routine */
        ok(Frees > 0 && Frees < (LONG)RTL_NUMBER_OF(Entry), "unexpected free count %ld\n", Frees);
        /* flush releases what the list still holds */
        pFlush(&List);
        ok_eq_long(Frees, (LONG)RTL_NUMBER_OF(Entry));
        ok_eq_ulong(ExQueryDepthSList(&List.L.ListHead), 0);
        pDelete(&List);
    }
}
