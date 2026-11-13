/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     A thread routine that returns with EBX, ESI, EDI and EBP clobbered (as the
 *              Go runtime's thread entry does) must still end its thread normally
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#if defined(_M_IX86) && defined(__GNUC__)

#define THREAD_COUNT 24

/*
 * Thread routines written in assembly: they replace every register a C routine has to preserve with
 * garbage and return the way a thread routine returns (stdcall, the parameter popped), or the way an
 * image entry returns (the parameter left on the stack, the exit code in EAX).
 */
extern DWORD WINAPI ClobberStdcallThread(_In_ PVOID Parameter);
extern DWORD __cdecl ClobberCdeclThread(_In_ PVOID Parameter);

__asm__(
    ".text\n"
    ".globl _ClobberStdcallThread@4\n"
    "_ClobberStdcallThread@4:\n"
    "    movl 4(%esp), %eax\n"
    "    movl $0x11111111, %ebx\n"
    "    movl $0x22222222, %esi\n"
    "    movl $0x33333333, %edi\n"
    "    movl $0x44444444, %ebp\n"
    "    addl $0x1000, %eax\n"
    "    ret $4\n"
    ".globl _ClobberCdeclThread\n"
    "_ClobberCdeclThread:\n"
    "    movl 4(%esp), %eax\n"
    "    movl $0x55555555, %ebx\n"
    "    movl $0x66666666, %esi\n"
    "    movl $0x77777777, %edi\n"
    "    movl $0x88888888, %ebp\n"
    "    addl $0x2000, %eax\n"
    "    ret\n");

static
VOID
RunThreads(
    _In_ LPTHREAD_START_ROUTINE Routine,
    _In_ DWORD Base)
{
    HANDLE Threads[THREAD_COUNT];
    DWORD i, Wait, ExitCode;
    BOOL Success;

    for (i = 0; i < THREAD_COUNT; i++)
    {
        Threads[i] = CreateThread(NULL, 0, Routine, (PVOID)(ULONG_PTR)i, 0, NULL);
        ok(Threads[i] != NULL, "CreateThread %lu failed with %lu\n", i, GetLastError());
    }

    for (i = 0; i < THREAD_COUNT; i++)
    {
        if (!Threads[i])
            continue;
        Wait = WaitForSingleObject(Threads[i], 30000);
        ok(Wait == WAIT_OBJECT_0, "Wait for thread %lu returned %lu\n", i, Wait);
        ExitCode = 0xDEADBEEF;
        Success = GetExitCodeThread(Threads[i], &ExitCode);
        ok(Success, "GetExitCodeThread failed with %lu\n", GetLastError());
        ok(ExitCode == Base + i, "Thread %lu exit code %#lx, expected %#lx\n", i, ExitCode, Base + i);
        CloseHandle(Threads[i]);
    }
}

START_TEST(ThreadReturnClobber)
{
    RunThreads(ClobberStdcallThread, 0x1000);
    RunThreads((LPTHREAD_START_ROUTINE)ClobberCdeclThread, 0x2000);
}

#else

START_TEST(ThreadReturnClobber)
{
    skip("i386 only\n");
}

#endif
