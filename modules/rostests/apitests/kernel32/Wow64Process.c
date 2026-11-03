/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later
 * PURPOSE:     Native process WoW64 queries and system information
 */

#include "precomp.h"
#include <ndk/psfuncs.h>

START_TEST(Wow64Process)
{
    BOOL Result, Wow64;
    HANDLE Process;
    ULONG_PTR Peb32;
    ULONG Length;
    NTSTATUS Status;
    SYSTEM_INFO NativeInfo, Info;
    unsigned int i;

    Wow64 = 0x55;
    Result = IsWow64Process(GetCurrentProcess(), &Wow64);
    ok(Result, "IsWow64Process failed: %lu\n", GetLastError());
    if (!Result) return;

    Status = NtQueryInformationProcess(NtCurrentProcess(), ProcessWow64Information,
                                      &Peb32, sizeof(Peb32), &Length);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok(Length == sizeof(Peb32), "Return length %lu\n", Length);
    ok(Wow64 == (Peb32 != 0), "Win32/native query disagree: %d, %Ix\n", Wow64, Peb32);
#ifdef _WIN64
    ok(!Wow64, "Native 64-bit process reported as WoW64\n");
#endif
    if (Wow64)
    {
        skip("Remaining checks require a native process\n");
        return;
    }

    Process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
    ok(Process != NULL, "OpenProcess failed: %lu\n", GetLastError());
    if (Process)
    {
        for (i = 0; i < 4; ++i)
        {
            Peb32 = ~(ULONG_PTR)0;
            Length = 0;
            Status = NtQueryInformationProcess(Process, ProcessWow64Information,
                                              &Peb32, sizeof(Peb32), &Length);
            ok_ntstatus(Status, STATUS_SUCCESS);
            ok(Peb32 == 0, "Native process PEB32 is %Ix\n", Peb32);
            ok(Length == sizeof(Peb32), "Return length %lu\n", Length);
            Wow64 = TRUE;
            ok(IsWow64Process(Process, &Wow64), "IsWow64Process failed\n");
            ok(!Wow64, "Query changed native process state\n");
        }
        CloseHandle(Process);
    }

    Status = NtQueryInformationProcess(NtCurrentProcess(), ProcessWow64Information,
                                      &Peb32, sizeof(Peb32) - 1, NULL);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
    Wow64 = 0x55;
    SetLastError(0xdeadbeef);
    /* Windows 10 22H2 accepts a NULL handle: TRUE, not a WoW64 process (32 and 64-bit callers) */
    ok(IsWow64Process(NULL, &Wow64), "NULL process handle rejected: %lu\n", GetLastError());
    ok(Wow64 == FALSE, "NULL process handle reads as WoW64: %d\n", Wow64);

    RtlFillMemory(&Info, sizeof(Info), 0x55);
    RtlFillMemory(&NativeInfo, sizeof(NativeInfo), 0xaa);
    GetSystemInfo(&Info);
    GetNativeSystemInfo(&NativeInfo);
    ok(!memcmp(&Info, &NativeInfo, sizeof(Info)), "Native GetSystemInfo and GetNativeSystemInfo differ\n");
#ifdef _M_AMD64
    ok(NativeInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64,
       "Architecture %u\n", NativeInfo.wProcessorArchitecture);
#elif defined(_M_IX86)
    ok(NativeInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL,
       "Architecture %u\n", NativeInfo.wProcessorArchitecture);
#endif
    ok(NativeInfo.dwPageSize != 0, "No page size returned\n");
    ok(NativeInfo.dwNumberOfProcessors != 0, "No processor count returned\n");
    ok(NativeInfo.lpMaximumApplicationAddress > NativeInfo.lpMinimumApplicationAddress,
       "Invalid user address range\n");
}
