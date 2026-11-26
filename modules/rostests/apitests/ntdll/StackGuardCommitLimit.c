/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     A stack that cannot commit its next guard page ends the thread with a stack overflow, not an assertion
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * A thread whose stack grows into the guard page needs one more page of commit for the next guard page. At the
 * commit limit that fails; the thread gets the stack overflow exception (checked kernels used to stop in an assertion
 * of the memory manager). Where the stack has no room left for the exception dispatch itself, the process ends
 * instead, so the test runs the thread in a child process and accepts either end: the exception caught, the
 * process terminated by STATUS_STACK_OVERFLOW or by the access violation of the dispatch. What it checks is that the
 * system goes on (a checked kernel stops) and that the process ends.
 *
 * The child uses up the commit with unmapped sections, so the test needs a paging file that cannot grow (a fixed size
 * in the registry: a system managed one is grown to make room for the request instead) and skips otherwise. The commit
 * is held for a few seconds only.
 * Windows: not measured (verify on the Windows reference with a fixed size paging file: the exit code of the child).
 */

#include "precomp.h"

#define SECTION_COUNT 8192
#define CHILD_VARIABLE L"STACKGUARDCOMMITLIMIT_CHILD"
#define CHILD_CAUGHT 0x5a5a0001
#define CHILD_NOT_EXHAUSTED 0x5a5a0002

static HANDLE Started, Go;

static
ULONG
NTAPI
Dive(ULONG Depth)
{
    volatile UCHAR Buffer[3000];

    if (Depth > 1000000)
        return 0;
    RtlFillMemory((PVOID)Buffer, sizeof(Buffer), (UCHAR)Depth);
    return Dive(Depth + 1) + Buffer[Depth % sizeof(Buffer)];
}

static
DWORD
WINAPI
DiveThread(PVOID Context)
{
    SetEvent(Started);
    WaitForSingleObject(Go, INFINITE);

    _SEH2_TRY
    {
        Dive(0);
    }
    _SEH2_EXCEPT(_SEH2_GetExceptionCode() == STATUS_STACK_OVERFLOW ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
    {
        ExitProcess(CHILD_CAUGHT);
    }
    _SEH2_END;
    return 0;
}

/* One paging file with equal initial and maximum sizes: "C:\pagefile.sys 128 128" */
static
BOOLEAN
HasFixedPagingFile(VOID)
{
    UNICODE_STRING KeyName = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management");
    UNICODE_STRING ValueName = RTL_CONSTANT_STRING(L"PagingFiles");
    OBJECT_ATTRIBUTES ObjectAttributes;
    static UCHAR Buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 1024];
    PKEY_VALUE_PARTIAL_INFORMATION Info = (PKEY_VALUE_PARTIAL_INFORMATION)Buffer;
    PWSTR Value, End;
    HANDLE Key;
    ULONG Length, Initial, Maximum;
    NTSTATUS Status;

    InitializeObjectAttributes(&ObjectAttributes, &KeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenKey(&Key, KEY_QUERY_VALUE, &ObjectAttributes);
    if (!NT_SUCCESS(Status))
        return FALSE;

    RtlZeroMemory(Buffer, sizeof(Buffer));
    Status = NtQueryValueKey(Key, &ValueName, KeyValuePartialInformation, Info, sizeof(Buffer) - 2 * sizeof(WCHAR), &Length);
    NtClose(Key);
    if (!NT_SUCCESS(Status) || (Info->Type != 7 /* REG_MULTI_SZ */))
        return FALSE;

    Value = (PWSTR)Info->Data;
    if ((Value[0] == UNICODE_NULL) || (Value[wcslen(Value) + 1] != UNICODE_NULL))
        return FALSE;

    Value = wcschr(Value, L' ');
    if (!Value)
        return FALSE;
    Initial = wcstoul(Value, &End, 10);
    Maximum = wcstoul(End, NULL, 10);
    return (Initial != 0) && (Initial == Maximum);
}

/* The child: uses up the commit, lets the thread dive. Ends the process with a code; does not return */
static
VOID
RunChild(VOID)
{
    static HANDLE Sections[SECTION_COUNT];
    ULONG Count = 0, i, Chunk;
    LARGE_INTEGER MaximumSize;
    HANDLE Thread;
    PVOID Base = NULL;
    SIZE_T RegionSize;
    NTSTATUS Status;

    Started = CreateEventW(NULL, TRUE, FALSE, NULL);
    Go = CreateEventW(NULL, TRUE, FALSE, NULL);
    Thread = CreateThread(NULL, 4 * 1024 * 1024, DiveThread, NULL, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
    if (!Started || !Go || !Thread)
        ExitProcess(CHILD_NOT_EXHAUSTED);
    WaitForSingleObject(Started, 10000);

    /* A region of ours to commit single pages in; the sections take the rest, from large to small */
    RegionSize = 1024 * 1024;
    Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &RegionSize, MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(Status))
        ExitProcess(CHILD_NOT_EXHAUSTED);

    for (Chunk = 64 * 1024 * 1024; Chunk >= 64 * 1024; Chunk /= 2)
    {
        while (Count < SECTION_COUNT)
        {
            MaximumSize.QuadPart = Chunk;
            Status = NtCreateSection(&Sections[Count], SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_READWRITE,
                                     SEC_COMMIT, NULL);
            if (!NT_SUCCESS(Status))
                break;
            Count++;
        }
    }

    /* The last pages one by one, up to the first that does not fit */
    for (i = 0; i < RegionSize / PAGE_SIZE; i++)
    {
        PVOID Page = (PUCHAR)Base + i * PAGE_SIZE;
        SIZE_T Size = PAGE_SIZE;

        Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Page, 0, &Size, MEM_COMMIT, PAGE_READWRITE);
        if (!NT_SUCCESS(Status))
            break;
    }
    if (Status != STATUS_COMMITMENT_LIMIT)
        ExitProcess(CHILD_NOT_EXHAUSTED);

    /* Everything is committed: the thread dives into its stack and ends the process, one way or the other */
    SetEvent(Go);
    WaitForSingleObject(Thread, 60000);
    ExitProcess(CHILD_NOT_EXHAUSTED);
}

START_TEST(StackGuardCommitLimit)
{
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInfo;
    PWSTR CommandLine;
    DWORD Wait, ExitCode = 0;

    if (GetEnvironmentVariableW(CHILD_VARIABLE, NULL, 0) != 0)
        RunChild();

    if (!HasFixedPagingFile())
    {
        skip("the paging file can grow (set one with equal initial and maximum size)\n");
        return;
    }

    /* The child is this program with this test, marked by the variable */
    CommandLine = _wcsdup(GetCommandLineW());
    ok(CommandLine != NULL, "no memory\n");
    if (!CommandLine)
        return;
    SetEnvironmentVariableW(CHILD_VARIABLE, L"1");
    if (!CreateProcessW(NULL, CommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &StartupInfo, &ProcessInfo))
    {
        ok(0, "CreateProcessW failed with %lu\n", GetLastError());
        SetEnvironmentVariableW(CHILD_VARIABLE, NULL);
        free(CommandLine);
        return;
    }
    SetEnvironmentVariableW(CHILD_VARIABLE, NULL);
    free(CommandLine);

    Wait = WaitForSingleObject(ProcessInfo.hProcess, 180000);
    ok(Wait == WAIT_OBJECT_0, "the child did not end: %lu\n", Wait);
    if (Wait != WAIT_OBJECT_0)
        TerminateProcess(ProcessInfo.hProcess, 1);
    GetExitCodeProcess(ProcessInfo.hProcess, &ExitCode);
    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);

    trace("the child ended with 0x%08lx\n", ExitCode);
    if (ExitCode == CHILD_NOT_EXHAUSTED)
    {
        skip("the commit could not be used up\n");
        return;
    }
    ok(ExitCode == CHILD_CAUGHT || ExitCode == STATUS_STACK_OVERFLOW || ExitCode == STATUS_ACCESS_VIOLATION,
       "the child ended with 0x%08lx\n", ExitCode);
}
