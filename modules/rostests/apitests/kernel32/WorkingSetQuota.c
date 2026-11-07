/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for SetProcessWorkingSetSize / GetProcessWorkingSetSize and the native quota limits
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The results were measured on Windows 10 22H2 (x64): a minimum below 20 pages is raised to 20 pages
 * (the maximum is raised with it, status STATUS_WORKING_SET_LIMIT_RANGE), a minimum above the maximum is
 * refused with STATUS_BAD_WORKING_SET_LIMIT (ERROR_INVALID_PARAMETER), a maximum of several times the
 * physical memory is accepted without any status, and a minimum that the resident available pages cannot
 * cover gives STATUS_INSUFFICIENT_RESOURCES. The default limits of a process (50 and 345 pages) are not tested.
 */

#include "precomp.h"
#include <ndk/psfuncs.h>

#ifndef STATUS_WORKING_SET_LIMIT_RANGE
#define STATUS_WORKING_SET_LIMIT_RANGE ((NTSTATUS)0x40000002)
#endif
#ifndef STATUS_BAD_WORKING_SET_LIMIT
#define STATUS_BAD_WORKING_SET_LIMIT ((NTSTATUS)0xC000004C)
#endif

typedef struct _WSQ_QUOTA_LIMITS
{
    SIZE_T PagedPoolLimit;
    SIZE_T NonPagedPoolLimit;
    SIZE_T MinimumWorkingSetSize;
    SIZE_T MaximumWorkingSetSize;
    SIZE_T PagefileLimit;
    LARGE_INTEGER TimeLimit;
} WSQ_QUOTA_LIMITS;

#define PAGES(n) ((SIZE_T)(n) * 4096)

static ULONGLONG TotalPhys;

static void EnablePrivilege(LPCWSTR Name)
{
    HANDLE Token;
    TOKEN_PRIVILEGES Tp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token))
        return;
    Tp.PrivilegeCount = 1;
    Tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (LookupPrivilegeValueW(NULL, Name, &Tp.Privileges[0].Luid))
        AdjustTokenPrivileges(Token, FALSE, &Tp, 0, NULL, NULL);
    CloseHandle(Token);
}

static NTSTATUS NativeSet(SIZE_T Min, SIZE_T Max)
{
    WSQ_QUOTA_LIMITS Limits = { 0 };

    Limits.MinimumWorkingSetSize = Min;
    Limits.MaximumWorkingSetSize = Max;
    return NtSetInformationProcess(GetCurrentProcess(), ProcessQuotaLimits, &Limits, sizeof(Limits));
}

static void ExpectLimits(SIZE_T Min, SIZE_T Max, int Line)
{
    SIZE_T GotMin = 1, GotMax = 1;
    BOOL Ret = GetProcessWorkingSetSize(GetCurrentProcess(), &GotMin, &GotMax);

    ok(Ret, "line %d: GetProcessWorkingSetSize failed %lu\n", Line, GetLastError());
    ok(GotMin == Min && GotMax == Max, "line %d: got %Iu,%Iu, expected %Iu,%Iu\n", Line, GotMin, GotMax, Min, Max);
}

static void ExpectSet(SIZE_T Min, SIZE_T Max, DWORD Error, int Line)
{
    BOOL Ret;

    SetLastError(0xdeadbeef);
    Ret = SetProcessWorkingSetSize(GetCurrentProcess(), Min, Max);
    if (Error == ERROR_SUCCESS)
        ok(Ret, "line %d: Set(%Iu,%Iu) failed %lu\n", Line, Min, Max, GetLastError());
    else
    {
        ok(!Ret, "line %d: Set(%Iu,%Iu) succeeded\n", Line, Min, Max);
        ok(GetLastError() == Error, "line %d: Set(%Iu,%Iu) error %lu, expected %lu\n", Line, Min, Max, GetLastError(), Error);
    }
}

#define EXPECT_LIMITS(a, b) ExpectLimits(a, b, __LINE__)
#define EXPECT_SET(a, b, e) ExpectSet(a, b, e, __LINE__)

static void TestSetGet(void)
{
    SIZE_T OrigMin, OrigMax;
    NTSTATUS Status;

    ok(GetProcessWorkingSetSize(GetCurrentProcess(), &OrigMin, &OrigMax), "Get failed %lu\n", GetLastError());

    /* an ordinary change round-trips */
    EXPECT_SET(PAGES(256), PAGES(1024), ERROR_SUCCESS);
    EXPECT_LIMITS(PAGES(256), PAGES(1024));

    /* minimum above maximum, and a zero in only one of the two, are refused and change nothing */
    EXPECT_SET(PAGES(1024), PAGES(256), ERROR_INVALID_PARAMETER);
    EXPECT_LIMITS(PAGES(256), PAGES(1024));
    EXPECT_SET(0, 0, ERROR_INVALID_PARAMETER);
    EXPECT_LIMITS(PAGES(256), PAGES(1024));
    EXPECT_SET(PAGES(256), 0, ERROR_INVALID_PARAMETER);
    EXPECT_SET(0, PAGES(2048), ERROR_INVALID_PARAMETER);
    EXPECT_LIMITS(PAGES(256), PAGES(1024));

    /* a minimum above the maximum natively */
    Status = NativeSet(PAGES(1024), PAGES(256));
    ok(Status == STATUS_BAD_WORKING_SET_LIMIT, "min>max: status 0x%lx\n", Status);

    /* values below the system minimum are raised to 20 pages, both of them */
    Status = NativeSet(PAGES(1), PAGES(2));
    ok(Status == STATUS_WORKING_SET_LIMIT_RANGE, "below the minimum: status 0x%lx\n", Status);
    EXPECT_LIMITS(PAGES(20), PAGES(20));

    /* (-1,-1) empties the working set on Windows; it is not tested here (it needs the pager) */

#ifdef _WIN64
    /* a maximum of several times the physical memory is accepted without a status */
    Status = NativeSet(PAGES(20), (SIZE_T)(TotalPhys * 4));
    ok(Status == STATUS_SUCCESS, "max 4x physical memory: status 0x%lx\n", Status);
    EXPECT_SET(PAGES(20), (SIZE_T)(TotalPhys * 2), ERROR_SUCCESS);

    /* a minimum the resident available pages cannot cover */
    Status = NativeSet((SIZE_T)(TotalPhys * 4), (SIZE_T)(TotalPhys * 4));
    ok(Status == STATUS_INSUFFICIENT_RESOURCES, "min 4x physical memory: status 0x%lx\n", Status);
#endif

    /* put it back */
    ok(SetProcessWorkingSetSize(GetCurrentProcess(), OrigMin ? OrigMin : PAGES(20), OrigMax),
       "restore failed %lu\n", GetLastError());
}

/* The minimum is charged to the resident available pages: a process that ends gives it back */
static int ChildMain(void)
{
    SIZE_T Min = (SIZE_T)(TotalPhys / 4);
    int Try;

    EnablePrivilege(L"SeIncreaseWorkingSetPrivilege");
    EnablePrivilege(L"SeIncreaseQuotaPrivilege");
    for (Try = 0; Try < 30; Try++)
    {
        if (SetProcessWorkingSetSize(GetCurrentProcess(), Min, Min + PAGES(256)))
            return 0;
        Sleep(100);
    }
    return (int)GetLastError();
}

static void TestMinimumReturned(void)
{
    WCHAR Path[MAX_PATH], Cmd[MAX_PATH + 16];
    int i;

    GetModuleFileNameW(NULL, Path, ARRAYSIZE(Path));
    for (i = 0; i < 12; i++)
    {
        STARTUPINFOW Si = { sizeof(Si) };
        PROCESS_INFORMATION Pi;
        DWORD Exit = 1;

        StringCbPrintfW(Cmd, sizeof(Cmd), L"\"%s\" WorkingSetQuota child", Path);
        if (!CreateProcessW(NULL, Cmd, NULL, NULL, FALSE, 0, NULL, NULL, &Si, &Pi))
        {
            skip("CreateProcess failed %lu\n", GetLastError());
            return;
        }
        WaitForSingleObject(Pi.hProcess, 60000);
        GetExitCodeProcess(Pi.hProcess, &Exit);
        CloseHandle(Pi.hThread);
        CloseHandle(Pi.hProcess);
        ok(Exit == 0, "child %d: could not reserve a quarter of the physical memory, error %lu\n", i, Exit);
        if (Exit != 0)
            break;
    }
}

START_TEST(WorkingSetQuota)
{
    MEMORYSTATUSEX Ms = { sizeof(Ms) };
    int argc;
    char **argv;

    GlobalMemoryStatusEx(&Ms);
    TotalPhys = Ms.ullTotalPhys;

    argc = winetest_get_mainargs(&argv);
    if (argc > 2 && !strcmp(argv[2], "child"))
        ExitProcess(ChildMain());

    EnablePrivilege(L"SeIncreaseWorkingSetPrivilege");
    EnablePrivilege(L"SeIncreaseQuotaPrivilege");
    TestSetGet();
    TestMinimumReturned();
}
