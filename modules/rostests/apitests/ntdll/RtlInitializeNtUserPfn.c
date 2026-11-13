/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Test for RtlRetrieveNtUserPfn
 * COPYRIGHT:   Copyright 2026 Timo Kreuzer <timo.kreuzer@reactos.org>
 */

#include "precomp.h"

/* ndk/rtlfuncs.h declares the NtUser PFN constants for NT6 and later only */
#if _WIN32_WINNT >= _WIN32_WINNT_VISTA

typedef
NTSTATUS
NTAPI
FN_RtlInitializeNtUserPfn(
    PVOID ProcsA,
    SIZE_T SizeOfProcsA,
    PVOID ProcsW,
    SIZE_T SizeOfProcsW,
    PVOID OtherProcs,
    SIZE_T SizeOfOtherProcs);

FN_RtlInitializeNtUserPfn* pRtlInitializeNtUserPfn;

START_TEST(RtlInitializeNtUserPfn)
{
    HINSTANCE hinstNtdll = GetModuleHandleW(L"ntdll.dll");
    pRtlInitializeNtUserPfn = (FN_RtlInitializeNtUserPfn*)GetProcAddress(hinstNtdll, "RtlInitializeNtUserPfn");
    if (pRtlInitializeNtUserPfn == NULL)
    {
        skip("RtlInitializeNtUserPfn is not available\n");
        return;
    }

    NTSTATUS Status;
    /* The entries are 64 bits wide for a 32-bit process under WoW64 (the arrays are sized for that) */
    ULONG64 ProcsA[24] = { 0 };
    ULONG64 ProcsW[24] = { 0 };
    ULONG64 OtherProcs[11] = { 0 };
    ULONG Count1, Count2;
    BOOL IsWow64 = FALSE;
    SIZE_T FieldSize;

    IsWow64Process(GetCurrentProcess(), &IsWow64);
    FieldSize = IsWow64 ? sizeof(ULONG64) : sizeof(PVOID);

    Status = pRtlInitializeNtUserPfn(NULL, 1, NULL, 0, NULL, 0);
    ok_ntstatus(Status, STATUS_INVALID_PARAMETER);
    Status = pRtlInitializeNtUserPfn(NULL, 0, NULL, 1, NULL, 0);
    ok_ntstatus(Status, STATUS_INVALID_PARAMETER);
    Status = pRtlInitializeNtUserPfn(NULL, 0, NULL, 0, NULL, 1);
    ok_ntstatus(Status, STATUS_INVALID_PARAMETER);
    Status = pRtlInitializeNtUserPfn(ProcsA, 0, ProcsW, 0, OtherProcs, 1);
    ok_ntstatus(Status, STATUS_INVALID_PARAMETER);

    printf("NTDDI version: %lx\n", GetNTDDIVersion());

    if (is_reactos())
    {
        /* The table sizes are fixed at build time, they don't follow the version we report */
        Count1 = RTLP_NUMBER_OF_NTUSER_WNDPROCS;
        Count2 = RTLP_NUMBER_OF_NTUSER_WORKERPROCS;
    }
    else
    {
        /* OS version specific count of A/W functions */
        Count1 = (GetNTDDIVersion() >= NTDDI_WIN10) ? 24 : 23;

        /* OS version specific count of other functions */
        Count2 = (GetNTDDIVersion() >= NTDDI_WIN11) ? 18 : 11;
    }

    /* Try different variants of too large sizes */
    Status = pRtlInitializeNtUserPfn(ProcsA, (Count1 + 1) * FieldSize, ProcsW, Count1 * FieldSize, OtherProcs, Count2 * FieldSize);
    ok_ntstatus(Status, STATUS_INVALID_PARAMETER);
    Status = pRtlInitializeNtUserPfn(ProcsA, Count1 * FieldSize, ProcsW, (Count1 + 1) * FieldSize, OtherProcs, Count2 * FieldSize);
    ok_ntstatus(Status, STATUS_INVALID_PARAMETER);
    Status = pRtlInitializeNtUserPfn(ProcsA, (Count1 + 1) * FieldSize, ProcsW, (Count1 + 1) * FieldSize, OtherProcs, Count2 * FieldSize);
    ok_ntstatus(Status, STATUS_INVALID_PARAMETER);
    Status = pRtlInitializeNtUserPfn(ProcsA, Count1 * FieldSize, ProcsW, Count1 * FieldSize, OtherProcs, (Count2 + 1) * FieldSize);
    ok_ntstatus(Status, STATUS_INVALID_PARAMETER);

    if (GetNTVersion() < _WIN32_WINNT_WIN10)
    {
        /* Try different variants of too small sizes (these succeed on Windows 10) */
        Status = pRtlInitializeNtUserPfn(ProcsA, (Count1 - 1) * FieldSize, ProcsW, Count1 * FieldSize, OtherProcs, Count2 * FieldSize);
        ok_ntstatus(Status, STATUS_INVALID_PARAMETER);
        Status = pRtlInitializeNtUserPfn(ProcsA, Count1 * FieldSize, ProcsW, (Count1 - 1) * FieldSize, OtherProcs, Count2 * FieldSize);
        ok_ntstatus(Status, STATUS_INVALID_PARAMETER);
        Status = pRtlInitializeNtUserPfn(ProcsA, (Count1 - 1) * FieldSize, ProcsW, (Count1 - 1) * FieldSize, OtherProcs, Count2 * FieldSize);
        ok_ntstatus(Status, STATUS_INVALID_PARAMETER);
        Status = pRtlInitializeNtUserPfn(ProcsA, Count1 * FieldSize, ProcsW, Count1 * FieldSize, OtherProcs, (Count2 - 1) * FieldSize);
        ok_ntstatus(Status, STATUS_INVALID_PARAMETER);
    }

    /* Try unaligned sizes */
    Status = pRtlInitializeNtUserPfn(ProcsA, (Count1 * FieldSize) - 1, ProcsW, Count1 * FieldSize, OtherProcs, Count2 * FieldSize);
    ok_ntstatus(Status, STATUS_INVALID_PARAMETER);
    Status = pRtlInitializeNtUserPfn(ProcsA, Count1 * FieldSize, ProcsW, (Count1 * FieldSize) - 1, OtherProcs, Count2 * FieldSize);
    ok_ntstatus(Status, STATUS_INVALID_PARAMETER);
    Status = pRtlInitializeNtUserPfn(ProcsA, Count1 * FieldSize, ProcsW, Count1 * FieldSize, OtherProcs, (Count2 * FieldSize) - 1);
    ok_ntstatus(Status, STATUS_INVALID_PARAMETER);

    /* Pass the expected sizes */
    Status = pRtlInitializeNtUserPfn(ProcsA, Count1 * FieldSize, ProcsW, Count1 * FieldSize, OtherProcs, Count2 * FieldSize);
    ok_ntstatus(Status, STATUS_SUCCESS);

    /* Try to initialize again */
    Status = pRtlInitializeNtUserPfn(ProcsA, Count1 * FieldSize, ProcsW, Count1 * FieldSize, OtherProcs, Count2 * FieldSize);
    ok_ntstatus(Status, STATUS_INVALID_PARAMETER);
}

#else

START_TEST(RtlInitializeNtUserPfn)
{
    skip("RtlInitializeNtUserPfn needs the NT6 headers\n");
}

#endif
