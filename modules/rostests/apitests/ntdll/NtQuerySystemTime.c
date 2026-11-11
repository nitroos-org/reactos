/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.0-or-later (https://spdx.org/licenses/LGPL-2.0-or-later)
 * PURPOSE:     Tests for NtQuerySystemTime: the result for good and bad output pointers, and agreement with the shared page
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */
#include "precomp.h"

static volatile LONG s_VehHits;

static LONG CALLBACK
CountFault(PEXCEPTION_POINTERS Pointers)
{
    s_VehHits++;
    return EXCEPTION_CONTINUE_SEARCH;
}

START_TEST(NtQuerySystemTime)
{
    LARGE_INTEGER First, Second;
    NTSTATUS Status;
    FILETIME FileTime;
    ULONGLONG Now;
    PVOID Vectored, Page;
    DWORD OldProtect;
    int i;

    Status = NtQuerySystemTime(&First);
    ok_hex(Status, STATUS_SUCCESS);
    Sleep(30);
    Status = NtQuerySystemTime(&Second);
    ok_hex(Status, STATUS_SUCCESS);
    ok(Second.QuadPart > First.QuadPart, "time did not advance: %I64x then %I64x\n", First.QuadPart, Second.QuadPart);

    GetSystemTimeAsFileTime(&FileTime);
    Now = ((ULONGLONG)FileTime.dwHighDateTime << 32) | FileTime.dwLowDateTime;
    ok(Now >= (ULONGLONG)Second.QuadPart && Now - (ULONGLONG)Second.QuadPart < 100 * 10000000ULL,
       "GetSystemTimeAsFileTime %I64x is not close to %I64x\n", Now, Second.QuadPart);

    /* A bad output pointer is reported as the status of the access, not raised */
    Vectored = AddVectoredExceptionHandler(1, CountFault);
    s_VehHits = 0;
    Status = NtQuerySystemTime(NULL);
    ok_hex(Status, STATUS_ACCESS_VIOLATION);
    ok(s_VehHits == 1, "a vectored handler saw %ld faults for a null pointer\n", s_VehHits);
    Status = NtQuerySystemTime((PLARGE_INTEGER)(ULONG_PTR)1);
    ok_hex(Status, STATUS_ACCESS_VIOLATION);
    Status = NtQuerySystemTime((PLARGE_INTEGER)(ULONG_PTR)(sizeof(PVOID) == 8 ? 0xFFFF800000000000ULL : 0x80000000UL));
    ok_hex(Status, STATUS_ACCESS_VIOLATION);

    Page = VirtualAlloc(NULL, 2 * 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!Page)
    {
        skip("VirtualAlloc failed\n");
    }
    else
    {
        VirtualProtect(Page, 4096, PAGE_READONLY, &OldProtect);
        Status = NtQuerySystemTime(Page);
        ok_hex(Status, STATUS_ACCESS_VIOLATION);
        VirtualProtect((PUCHAR)Page + 4096, 4096, PAGE_NOACCESS, &OldProtect);
        Status = NtQuerySystemTime((PLARGE_INTEGER)((PUCHAR)Page + 4096));
        ok_hex(Status, STATUS_ACCESS_VIOLATION);
        /* Eight bytes that start in a writable page and end in one that is not: no part is stored */
        VirtualProtect(Page, 4096, PAGE_READWRITE, &OldProtect);
        Status = NtQuerySystemTime((PLARGE_INTEGER)((PUCHAR)Page + 4096 - 4));
        ok_hex(Status, STATUS_ACCESS_VIOLATION);
        VirtualFree(Page, 0, MEM_RELEASE);
    }

    /* Failures leave nothing behind: the next good call works, many failures in a row too */
    for (i = 0; i < 20000; i++)
        NtQuerySystemTime(NULL);
    Status = NtQuerySystemTime(&First);
    ok_hex(Status, STATUS_SUCCESS);
    if (Vectored)
        RemoveVectoredExceptionHandler(Vectored);
}
