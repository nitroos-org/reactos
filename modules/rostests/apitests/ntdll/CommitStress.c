/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     An application that commits until the system says no: the failure is
 *              STATUS_COMMITMENT_LIMIT, everything committed can be used, and the system
 *              carries on once it is released
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#define CHUNK_PAGES 256 /* 1 MB */

static SIZE_T PageSize = 4096;
static PVOID Chunks[1 << 16];

static
ULONG_PTR
QueryCommit(
    _Out_opt_ PULONG_PTR CommitLimit)
{
    SYSTEM_PERFORMANCE_INFORMATION Info;
    NTSTATUS Status;

    Status = NtQuerySystemInformation(SystemPerformanceInformation, &Info, sizeof(Info), NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (CommitLimit)
        *CommitLimit = Info.CommitLimit;
    return Info.CommittedPages;
}

START_TEST(CommitStress)
{
    SYSTEM_BASIC_INFORMATION BasicInfo;
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInfo;
    WCHAR CommandLine[MAX_PATH + 32];
    ULONG_PTR Start, AtFailure, CommitLimit, i, Count = 0;
    SIZE_T Size, Offset;
    PVOID Base;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG Touched = 0;

    if (!is_reactos())
    {
        skip("fills the commit limit: ReactOS only\n");
        return;
    }

    Status = NtQuerySystemInformation(SystemBasicInformation, &BasicInfo, sizeof(BasicInfo), NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;
    PageSize = BasicInfo.PageSize;

    /* Touching everything that fits takes a while: stay with small test systems */
    if ((ULONGLONG)BasicInfo.NumberOfPhysicalPages * PageSize > 4096ULL * 1024 * 1024)
    {
        skip("%lu pages of RAM\n", BasicInfo.NumberOfPhysicalPages);
        return;
    }

    Start = QueryCommit(&CommitLimit);

    /* Commit 1 MB at a time until the first refusal */
    for (Count = 0; Count < _countof(Chunks); Count++)
    {
        Size = CHUNK_PAGES * PageSize;
        Base = NULL;
        Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &Size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!NT_SUCCESS(Status))
            break;
        Chunks[Count] = Base;
    }
    ok_ntstatus(Status, STATUS_COMMITMENT_LIMIT);
    ok(Count > 16, "only %Iu MB could be committed\n", Count);
    AtFailure = QueryCommit(NULL);
    trace("committed %Iu MB, system commit %Iu of %Iu pages (from %Iu)\n", Count, AtFailure, CommitLimit, Start);
    ok(AtFailure <= CommitLimit, "commit %Iu above the limit %Iu\n", AtFailure, CommitLimit);

    /* A refused request leaves nothing behind, and keeps being refused */
    Size = CHUNK_PAGES * PageSize;
    Base = NULL;
    Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &Size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok_ntstatus(Status, STATUS_COMMITMENT_LIMIT);
    ok(QueryCommit(NULL) <= AtFailure + 256, "a refused request moved the commit\n");
    SetLastError(0xdeadbeef);
    ok(VirtualAlloc(NULL, CHUNK_PAGES * PageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) == NULL, "VirtualAlloc succeeded at the limit\n");
    ok_err(ERROR_COMMITMENT_LIMIT);

    /* Everything that was granted is backed: touching it all neither hangs nor crashes */
    for (i = 0; i < Count; i++)
    {
        for (Offset = 0; Offset < CHUNK_PAGES * PageSize; Offset += PageSize)
        {
            *((volatile UCHAR *)Chunks[i] + Offset) = (UCHAR)i;
            Touched++;
        }
    }
    ok(Touched == Count * CHUNK_PAGES, "touched %lu pages\n", Touched);
    for (i = 0; i < Count; i += 17)
        ok(*(volatile UCHAR *)Chunks[i] == (UCHAR)i, "chunk %Iu lost its data\n", i);

    /* Release it all: the charge returns, and the system is usable */
    for (i = 0; i < Count; i++)
    {
        Size = 0;
        Base = Chunks[i];
        Status = NtFreeVirtualMemory(NtCurrentProcess(), &Base, &Size, MEM_RELEASE);
        ok_ntstatus(Status, STATUS_SUCCESS);
    }
    Sleep(200);
    ok(QueryCommit(NULL) <= Start + 2048, "commit %Iu after release, %Iu before\n", QueryCommit(NULL), Start);

    Size = 64 * 1024 * 1024;
    Base = NULL;
    Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &Size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        RtlFillMemory(Base, Size, 0x5A);
        Size = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), &Base, &Size, MEM_RELEASE);
    }

    Size = GetSystemDirectoryW(CommandLine, MAX_PATH);
    ok(Size != 0 && Size < MAX_PATH, "GetSystemDirectoryW returned %Iu\n", Size);
    StringCchCatW(CommandLine, _countof(CommandLine), L"\\cmd.exe /c exit 7");
    if (CreateProcessW(NULL, CommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &StartupInfo, &ProcessInfo))
    {
        DWORD ExitCode = 0;

        ok_long(WaitForSingleObject(ProcessInfo.hProcess, 60000), WAIT_OBJECT_0);
        GetExitCodeProcess(ProcessInfo.hProcess, &ExitCode);
        ok_long(ExitCode, 7);
        CloseHandle(ProcessInfo.hThread);
        CloseHandle(ProcessInfo.hProcess);
    }
    else
    {
        ok(FALSE, "CreateProcessW failed with %lu after release\n", GetLastError());
    }
}
