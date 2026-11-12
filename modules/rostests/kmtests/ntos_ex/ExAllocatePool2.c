/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Kernel-Mode Test Suite for ExAllocatePool2 / ExAllocatePool3
 *              (semantics from the public WDK documentation)
 */

#include <kmt_test.h>

#define TAG_POOL2 '2loP'

typedef PVOID (NTAPI *PEX_ALLOCATE_POOL2)(ULONG64, SIZE_T, ULONG);
typedef PVOID (NTAPI *PEX_ALLOCATE_POOL3)(ULONG64, SIZE_T, ULONG, PVOID, ULONG);

#define F_USE_QUOTA     0x01ULL
#define F_UNINIT        0x02ULL
#define F_CACHE_ALIGNED 0x08ULL
#define F_NON_PAGED     0x40ULL
#define F_PAGED         0x100ULL

static
BOOLEAN
IsZero(
    _In_ PVOID Buffer,
    _In_ SIZE_T Size)
{
    PUCHAR p = Buffer;
    SIZE_T i;

    for (i = 0; i < Size; i++)
        if (p[i] != 0)
            return FALSE;
    return TRUE;
}

START_TEST(ExAllocatePool2)
{
    PEX_ALLOCATE_POOL2 pExAllocatePool2;
    PEX_ALLOCATE_POOL3 pExAllocatePool3;
    PVOID Buffer;
    SIZE_T Size = 3000;
    NTSTATUS ExceptionStatus;

    pExAllocatePool2 = KmtGetSystemRoutineAddress(L"ExAllocatePool2");
    pExAllocatePool3 = KmtGetSystemRoutineAddress(L"ExAllocatePool3");
    ok(pExAllocatePool2 != NULL, "ExAllocatePool2 is not exported\n");
    ok(pExAllocatePool3 != NULL, "ExAllocatePool3 is not exported\n");
    if (!pExAllocatePool2 || !pExAllocatePool3)
        return;

    /* Non-paged, zeroed by default */
    Buffer = pExAllocatePool2(F_NON_PAGED, Size, TAG_POOL2);
    ok(Buffer != NULL, "NonPaged allocation failed\n");
    if (Buffer)
    {
        ok(IsZero(Buffer, Size), "NonPaged allocation is not zeroed\n");
        ExFreePoolWithTag(Buffer, TAG_POOL2);
    }

    /* Dirty the pool, free it, allocate again: still zero */
    Buffer = ExAllocatePoolWithTag(NonPagedPool, Size, TAG_POOL2);
    if (Buffer)
    {
        RtlFillMemory(Buffer, Size, 0xAB);
        ExFreePoolWithTag(Buffer, TAG_POOL2);
    }
    Buffer = pExAllocatePool2(F_NON_PAGED, Size, TAG_POOL2);
    ok(Buffer != NULL, "allocation failed\n");
    if (Buffer)
    {
        ok(IsZero(Buffer, Size), "recycled allocation is not zeroed\n");
        ExFreePoolWithTag(Buffer, TAG_POOL2);
    }

    /* Paged */
    Buffer = pExAllocatePool2(F_PAGED, Size, TAG_POOL2);
    ok(Buffer != NULL, "Paged allocation failed\n");
    if (Buffer)
    {
        ok(IsZero(Buffer, Size), "Paged allocation is not zeroed\n");
        ExFreePoolWithTag(Buffer, TAG_POOL2);
    }

    /* Uninitialized is accepted */
    Buffer = pExAllocatePool2(F_NON_PAGED | F_UNINIT, Size, TAG_POOL2);
    ok(Buffer != NULL, "Uninitialized allocation failed\n");
    if (Buffer)
        ExFreePoolWithTag(Buffer, TAG_POOL2);

    /* Cache aligned */
    Buffer = pExAllocatePool2(F_NON_PAGED | F_CACHE_ALIGNED, 100, TAG_POOL2);
    ok(Buffer != NULL, "CacheAligned allocation failed\n");
    if (Buffer)
    {
        ok(((ULONG_PTR)Buffer & (KeGetRecommendedSharedDataAlignment() - 1)) == 0 ||
           ((ULONG_PTR)Buffer & 0x3F) == 0 || ((ULONG_PTR)Buffer & 0x1F) == 0,
           "CacheAligned allocation %p is not aligned\n", Buffer);
        ExFreePoolWithTag(Buffer, TAG_POOL2);
    }

    /* Two pool types: invalid */
    Buffer = pExAllocatePool2(F_NON_PAGED | F_PAGED, Size, TAG_POOL2);
    ok(Buffer == NULL, "NonPaged|Paged returned %p\n", Buffer);
    if (Buffer)
        ExFreePoolWithTag(Buffer, TAG_POOL2);

    /* Unknown flag bits: invalid */
    Buffer = pExAllocatePool2(F_NON_PAGED | 0x8000000000000000ULL, Size, TAG_POOL2);
    ok(Buffer == NULL, "unknown flag returned %p\n", Buffer);
    if (Buffer)
        ExFreePoolWithTag(Buffer, TAG_POOL2);

    /* Absurd size fails with NULL, no exception, without RAISE_ON_FAILURE */
    ExceptionStatus = STATUS_SUCCESS;
    Buffer = NULL;
    _SEH2_TRY
    {
        Buffer = pExAllocatePool2(F_NON_PAGED, (SIZE_T)-1 / 2, TAG_POOL2);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        ExceptionStatus = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    ok_eq_hex(ExceptionStatus, STATUS_SUCCESS);
    ok(Buffer == NULL, "huge allocation returned %p\n", Buffer);
    if (Buffer)
        ExFreePoolWithTag(Buffer, TAG_POOL2);

    /* The same with RAISE_ON_FAILURE raises STATUS_INSUFFICIENT_RESOURCES */
    ExceptionStatus = STATUS_SUCCESS;
    Buffer = NULL;
    _SEH2_TRY
    {
        Buffer = pExAllocatePool2(F_NON_PAGED | 0x20ULL, (SIZE_T)-1 / 2, TAG_POOL2);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        ExceptionStatus = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    ok_eq_hex(ExceptionStatus, STATUS_INSUFFICIENT_RESOURCES);
    ok(Buffer == NULL, "huge raising allocation returned %p\n", Buffer);

    /* ExAllocatePool3 without extended parameters behaves the same */
    Buffer = pExAllocatePool3(F_NON_PAGED, Size, TAG_POOL2, NULL, 0);
    ok(Buffer != NULL, "ExAllocatePool3 failed\n");
    if (Buffer)
    {
        ok(IsZero(Buffer, Size), "ExAllocatePool3 allocation is not zeroed\n");
        ExFreePoolWithTag(Buffer, TAG_POOL2);
    }
}
