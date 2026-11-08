/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     NtQuerySystemTime of a 32-bit process under WoW64: the value and the invalid outputs
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

START_TEST(Wow64QuerySystemTime)
{
    LARGE_INTEGER Time, Next, Now;
    FILETIME FileTime;
    NTSTATUS Status;
    LONG64 Previous = 0;
    int i;
    BOOL Backwards = FALSE;
    PVOID Base;
    ULONG Old;

    Status = NtQuerySystemTime(&Time);
    ok_ntstatus(Status, STATUS_SUCCESS);
    GetSystemTimeAsFileTime(&FileTime);
    Now.LowPart = FileTime.dwLowDateTime;
    Now.HighPart = (LONG)FileTime.dwHighDateTime;
    ok(Now.QuadPart - Time.QuadPart >= -10000000LL && Now.QuadPart - Time.QuadPart < 100000000LL,
       "NtQuerySystemTime %I64d, GetSystemTimeAsFileTime %I64d\n", Time.QuadPart, Now.QuadPart);

    for (i = 0; i < 100000; i++)
    {
        NtQuerySystemTime(&Next);
        if (Next.QuadPart < Previous) Backwards = TRUE;
        Previous = Next.QuadPart;
    }
    ok(!Backwards, "The time went backwards\n");

    /* Outputs the probe refuses or the write faults on */
    Status = NtQuerySystemTime(NULL);
    ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);
    Status = NtQuerySystemTime((PLARGE_INTEGER)(ULONG_PTR)0x7ffe0000);
    ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);

    Base = VirtualAlloc(NULL, 8192, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok(Base != NULL, "VirtualAlloc failed: %lu\n", GetLastError());
    if (!Base) return;
    VirtualProtect((PUCHAR)Base + 4096, 4096, PAGE_NOACCESS, &Old);
    Status = NtQuerySystemTime((PLARGE_INTEGER)((PUCHAR)Base + 4096 - 8));
    ok_ntstatus(Status, STATUS_SUCCESS);
    Status = NtQuerySystemTime((PLARGE_INTEGER)((PUCHAR)Base + 4096 - 4));
    ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);
    VirtualProtect(Base, 4096, PAGE_READONLY, &Old);
    Status = NtQuerySystemTime((PLARGE_INTEGER)((PUCHAR)Base + 16));
    ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);
    VirtualFree(Base, 0, MEM_RELEASE);
}
