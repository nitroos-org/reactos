/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Segment registers of threads that are created and joined in a loop, in 64-bit
 *              code and in 32-bit code running under WoW64. The mode switch of a 32-bit thread
 *              returns through the gate to compatibility mode: SS must be the 64-bit user data
 *              selector with a usable stack segment, CS the 32-bit code selector.
 */

#include "precomp.h"

#if defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__))

#ifdef _WIN64
#define EXPECTED_CS 0x33
#else
#define EXPECTED_CS 0x23
#endif
#define EXPECTED_DATA 0x2B

static LONG BadSs, BadCs, BadData;

static void CheckSegments(void)
{
    unsigned short Ss, Cs, Ds, Es;

    __asm__ volatile("mov %%ss, %0" : "=r"(Ss));
    __asm__ volatile("mov %%cs, %0" : "=r"(Cs));
    __asm__ volatile("mov %%ds, %0" : "=r"(Ds));
    __asm__ volatile("mov %%es, %0" : "=r"(Es));
    if (Ss != EXPECTED_DATA)
        InterlockedIncrement(&BadSs);
    if (Cs != EXPECTED_CS)
        InterlockedIncrement(&BadCs);
    if (Ds != EXPECTED_DATA || Es != EXPECTED_DATA)
        InterlockedIncrement(&BadData);
}

static DWORD WINAPI SegmentThread(void *Parameter)
{
    CheckSegments();
    /* a system call in between returns to user mode through SYSRET and, for a 32-bit thread, the gate */
    SwitchToThread();
    CheckSegments();
    return (DWORD)(ULONG_PTR)Parameter;
}

START_TEST(Wow64ThreadSegments)
{
    BOOL IsWow64 = FALSE;
    int i;

#ifndef _WIN64
    if (!IsWow64Process(GetCurrentProcess(), &IsWow64) || !IsWow64)
    {
        skip("The segment values checked here are those of a WoW64 process\n");
        return;
    }
#endif
    (void)IsWow64;

    CheckSegments();
    for (i = 0; i < 2000; i++)
    {
        DWORD ExitCode = 0xFFFFFFFF;
        HANDLE Thread = CreateThread(NULL, 0, SegmentThread, (void *)(ULONG_PTR)(i & 0xFF), 0, NULL);

        if (!Thread)
        {
            ok(FALSE, "CreateThread %d failed: %lu\n", i, GetLastError());
            break;
        }
        if (WaitForSingleObject(Thread, 30000) != WAIT_OBJECT_0)
        {
            ok(FALSE, "thread %d did not finish\n", i);
            CloseHandle(Thread);
            break;
        }
        GetExitCodeThread(Thread, &ExitCode);
        if (ExitCode != (DWORD)(i & 0xFF))
        {
            ok(FALSE, "thread %d exit code %lu\n", i, ExitCode);
            CloseHandle(Thread);
            break;
        }
        CloseHandle(Thread);
    }
    ok(BadSs == 0, "SS was not 0x%x in %ld checks\n", EXPECTED_DATA, BadSs);
    ok(BadCs == 0, "CS was not 0x%x in %ld checks\n", EXPECTED_CS, BadCs);
    ok(BadData == 0, "DS or ES was not 0x%x in %ld checks\n", EXPECTED_DATA, BadData);
}

#else

START_TEST(Wow64ThreadSegments)
{
    skip("x86 and x64 GCC inline assembly only\n");
}

#endif
