/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test an exception whose dispatch frame does not fit the stack
 */

#include "precomp.h"
#include <stdlib.h>
#include <strsafe.h>

/*
 * A thread grows its stack until the guard page is the last one before the
 * stack is exhausted, then faults with its stack pointer just above that guard
 * page. Writing the exception dispatch frame touches the guard page, which
 * raises the overflow: the thread must get STATUS_STACK_OVERFLOW, at the
 * address of the original fault, and the process must not be ended.
 * Each fault runs in a child process, so a failure does not end the test.
 */

VOID StackOverflowDispatchFault(PVOID StackPointer);
extern UCHAR StackOverflowDispatchFaultIp[];
extern UCHAR StackOverflowDispatchResume[];
PVOID StackOverflowDispatchSavedSp;

#define CHILD_NO_HANDLER    0xE1
#define CHILD_NO_THREAD     0xE2
#define CHILD_NO_LAYOUT     0xE3
#define CHILD_NO_GUARD      0xE4
#define CHILD_NO_EXCEPTION  0xE5

/* Child exit code: the exception, the stack pointer and the stack limit after it */
#define RESULT_OVERFLOW     0x5000
#define RESULT_ACCESS       0xA000
#define RESULT_OTHER        0xF000
#define RESULT_BAD_SP       0x0200
#define RESULT_BAD_RECORD   0x0400  /* flags, chained record or parameters */
#define RESULT_LIMIT_DEAD   0x0010  /* StackLimit = DeallocationStack + 1 page */
#define RESULT_LIMIT_SAME   0x0020  /* StackLimit unchanged */
#define RESULT_LIMIT_OTHER  0x0040

#define CONTROL_OFFSET      0x8000

static ULONG_PTR Offset, Reserve, Target, FaultSp, LimitAfter;
static NTSTATUS FaultCode;
static ULONG Faults;
static EXCEPTION_RECORD FaultRecord;

static
LONG
CALLBACK
DispatchHandler(PEXCEPTION_POINTERS Pointers)
{
    if (Pointers->ExceptionRecord->ExceptionAddress != (PVOID)StackOverflowDispatchFaultIp)
        return EXCEPTION_CONTINUE_SEARCH;
    Faults++;
    FaultCode = Pointers->ExceptionRecord->ExceptionCode;
    FaultRecord = *Pointers->ExceptionRecord;
#ifdef _M_IX86
    FaultSp = Pointers->ContextRecord->Esp;
    Pointers->ContextRecord->Eip = (ULONG_PTR)StackOverflowDispatchResume;
#else
    FaultSp = Pointers->ContextRecord->Rsp;
    Pointers->ContextRecord->Rip = (ULONG_PTR)StackOverflowDispatchResume;
#endif
    return EXCEPTION_CONTINUE_EXECUTION;
}

static
DWORD
WINAPI
DispatchThread(PVOID Parameter)
{
    PNT_TIB Tib = &NtCurrentTeb()->NtTib;
    MEMORY_BASIC_INFORMATION Info;
    NTSTATUS Status;
    ULONG i;

    UNREFERENCED_PARAMETER(Parameter);
    Reserve = (ULONG_PTR)NtCurrentTeb()->DeallocationStack;
    Target = Reserve + 4 * PAGE_SIZE;
    /* Grow the stack one guard page at a time until the guard page is at
     * DeallocationStack + 3 pages, the last one before the overflow (a guard
     * page hit up to there raises it, on Windows x64 as well) */
    for (i = 0; i < 1024 && (ULONG_PTR)Tib->StackLimit > Target; i++)
        *((volatile CHAR *)Tib->StackLimit - 1) = 0;
    if ((ULONG_PTR)Tib->StackLimit != Target)
        return CHILD_NO_LAYOUT;
    Status = NtQueryVirtualMemory(NtCurrentProcess(), (PVOID)(Target - PAGE_SIZE),
                                  MemoryBasicInformation, &Info, sizeof(Info), NULL);
    if (!NT_SUCCESS(Status) || Info.Protect != (PAGE_READWRITE | PAGE_GUARD))
        return CHILD_NO_GUARD;
    StackOverflowDispatchFault((PVOID)(Target + Offset));
    LimitAfter = (ULONG_PTR)Tib->StackLimit;
    return 0;
}

static
VOID
RunChild(ULONG_PTR ChildOffset)
{
    HANDLE Thread;
    DWORD Exit = CHILD_NO_THREAD;
    ULONG Result;

    if (!AddVectoredExceptionHandler(1, DispatchHandler))
        ExitProcess(CHILD_NO_HANDLER);
    Offset = ChildOffset;
    Thread = CreateThread(NULL, 256 * 1024, DispatchThread, NULL, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
    if (!Thread)
        ExitProcess(CHILD_NO_THREAD);
    WaitForSingleObject(Thread, INFINITE);
    GetExitCodeThread(Thread, &Exit);
    CloseHandle(Thread);
    if (Exit)
        ExitProcess(Exit);
    if (Faults != 1)
        ExitProcess(CHILD_NO_EXCEPTION);
    if (FaultCode == STATUS_STACK_OVERFLOW)
        Result = RESULT_OVERFLOW;
    else if (FaultCode == STATUS_ACCESS_VIOLATION)
        Result = RESULT_ACCESS;
    else
        Result = RESULT_OTHER;
    if (FaultSp != Target + Offset)
        Result |= RESULT_BAD_SP;
    /* An overflow reports the guard page the frame touched, an access
     * violation the write to address 0 */
    if (FaultRecord.ExceptionFlags != 0 || FaultRecord.ExceptionRecord != NULL ||
        FaultRecord.NumberParameters != 2 ||
        (FaultCode == STATUS_STACK_OVERFLOW &&
         (FaultRecord.ExceptionInformation[1] < Target - PAGE_SIZE ||
          FaultRecord.ExceptionInformation[1] >= Target)) ||
        (FaultCode == STATUS_ACCESS_VIOLATION &&
         (FaultRecord.ExceptionInformation[0] != 1 || FaultRecord.ExceptionInformation[1] != 0)))
    {
        Result |= RESULT_BAD_RECORD;
    }
    if (LimitAfter == Reserve + PAGE_SIZE)
        Result |= RESULT_LIMIT_DEAD;
    else if (LimitAfter == Target)
        Result |= RESULT_LIMIT_SAME;
    else
        Result |= RESULT_LIMIT_OTHER;
    ExitProcess(Result);
}

static
DWORD
RunChildProcess(ULONG ChildOffset)
{
    WCHAR FileName[MAX_PATH];
    WCHAR CommandLine[MAX_PATH + 64];
    STARTUPINFOW StartupInfo;
    PROCESS_INFORMATION ProcessInfo;
    DWORD ExitCode = 0xFFFFFFFF;

    GetModuleFileNameW(NULL, FileName, _countof(FileName));
    StringCbPrintfW(CommandLine, sizeof(CommandLine), L"\"%ls\" StackOverflowDispatch child %lx",
                    FileName, ChildOffset);
    RtlZeroMemory(&StartupInfo, sizeof(StartupInfo));
    StartupInfo.cb = sizeof(StartupInfo);
    if (!CreateProcessW(FileName, CommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &StartupInfo, &ProcessInfo))
    {
        ok(0, "CreateProcess failed with %lu\n", GetLastError());
        return ExitCode;
    }
    CloseHandle(ProcessInfo.hThread);
    if (WaitForSingleObject(ProcessInfo.hProcess, 30000) != WAIT_OBJECT_0)
    {
        ok(0, "The child for offset 0x%lx did not end\n", ChildOffset);
        TerminateProcess(ProcessInfo.hProcess, 0xDEAD);
        WaitForSingleObject(ProcessInfo.hProcess, 10000);
    }
    GetExitCodeProcess(ProcessInfo.hProcess, &ExitCode);
    CloseHandle(ProcessInfo.hProcess);
    return ExitCode;
}

START_TEST(StackOverflowDispatch)
{
    /* Stack pointers above the last guard page that leave less room than the
     * dispatch frame on i386 and amd64, WoW64 included */
    static const ULONG Overflow[] = { 0x10, 0x100, 0x200 };
    char **argv;
    int argc;
    ULONG i;
    DWORD ExitCode;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 4 && !strcmp(argv[2], "child"))
    {
        RunChild(strtoul(argv[3], NULL, 16));
        return;
    }

    for (i = 0; i < _countof(Overflow); i++)
    {
        ExitCode = RunChildProcess(Overflow[i]);
        ok(ExitCode == (RESULT_OVERFLOW | RESULT_LIMIT_DEAD),
           "Fault 0x%lx above the last guard page: child exit code 0x%lx, expected 0x%x\n",
           Overflow[i], ExitCode, RESULT_OVERFLOW | RESULT_LIMIT_DEAD);
    }

    /* Far enough above it, the fault is delivered as it is */
    ExitCode = RunChildProcess(CONTROL_OFFSET);
    ok(ExitCode == (RESULT_ACCESS | RESULT_LIMIT_SAME),
       "Fault 0x%x above the last guard page: child exit code 0x%lx, expected 0x%x\n",
       CONTROL_OFFSET, ExitCode, RESULT_ACCESS | RESULT_LIMIT_SAME);

    /* In between, the frame fits and the overflow, if any, comes later in the
     * dispatch. Only report what happens there. */
    for (i = 0x400; i <= 0x700; i += 0x100)
        trace("Fault 0x%lx above the last guard page: child exit code 0x%lx\n", i, RunChildProcess(i));
}
