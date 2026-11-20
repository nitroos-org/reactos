/*
 * PROJECT:     NitroOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for the multimedia class scheduler calls of avrt.dll (measured on Windows Server 2022)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * https://learn.microsoft.com/windows/win32/procthread/multimedia-class-scheduler-service
 * The task table is the registry key SystemProfile\Tasks; the priority a Medium or High task gives a thread is not
 * pinned here (only the Low category's, which the caller can set for its own thread).
 */

#define WIN32_NO_STATUS
#include <apitest.h>
#include <winreg.h>
#include <strsafe.h>

typedef HANDLE (WINAPI *PFN_Set)(LPCWSTR, LPDWORD);
typedef HANDLE (WINAPI *PFN_SetMax)(LPCWSTR, LPCWSTR, LPDWORD);
typedef BOOL (WINAPI *PFN_Revert)(HANDLE);
typedef BOOL (WINAPI *PFN_Priority)(HANDLE, int);
typedef BOOL (WINAPI *PFN_Query)(HANDLE, PULONG);

static PFN_Set pSet;
static PFN_SetMax pSetMax;
static PFN_Revert pRevert;
static PFN_Priority pPriority;
static PFN_Query pQuery;

#define TASKS_KEY L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile"

/* a result and the error that went with it, taken in the order the call happened */
static DWORD g_Error;
static HANDLE SetTask(LPCWSTR Name, DWORD *Index)
{
    HANDLE Handle;

    SetLastError(0xdeadbeef);
    Handle = pSet(Name, Index);
    g_Error = Handle ? 0 : GetLastError();
    return Handle;
}

static BOOL Call(BOOL Ret)
{
    g_Error = Ret ? 0 : GetLastError();
    return Ret;
}

static void TestNames(void)
{
    static const WCHAR *Good[] =
        { L"Audio", L"Capture", L"DisplayPostProcessing", L"Distribution", L"Games", L"Playback", L"Pro Audio",
          L"Window Manager", L"audio", L"pro audio" };
    static const WCHAR *Bad[] =
        { L"Low Latency", L"Video", L"NoSuchTask", L"", L"Audio ", L"Tasks\\Audio" };
    DWORD Last = 0;
    size_t i;

    for (i = 0; i < ARRAYSIZE(Good); i++)
    {
        DWORD Index = 0;
        HANDLE Handle = SetTask(Good[i], &Index);

        ok(Handle != NULL, "%ls: failed with %lu\n", Good[i], g_Error);
        ok(Index > Last, "%ls: the index %lu is not above the previous one %lu\n", Good[i], Index, Last);
        Last = Index;
        if (Handle)
            ok(Call(pRevert(Handle)), "%ls: revert failed: %lu\n", Good[i], g_Error);
    }

    for (i = 0; i < ARRAYSIZE(Bad); i++)
    {
        DWORD Index = 0;
        HANDLE Handle = SetTask(Bad[i], &Index);

        ok(Handle == NULL, "'%ls': the task was found\n", Bad[i]);
        ok(g_Error == ERROR_INVALID_TASK_NAME, "'%ls': error %lu\n", Bad[i], g_Error);
        ok(Index == 0, "'%ls': the index was set to %lu\n", Bad[i], Index);
        if (Handle)
            pRevert(Handle);
    }
}

static HANDLE g_Handle;
static DWORD g_Index;
static DWORD g_Results[4];

static DWORD WINAPI OtherThread(void *Param)
{
    DWORD Index = 0;
    HANDLE Handle;

    g_Results[0] = Call(pRevert(g_Handle));                 /* a thread can end another thread's registration */
    g_Results[1] = Call(pPriority(g_Handle, 1));            /* and the handle is gone then */
    g_Results[2] = g_Error;
    Handle = SetTask(L"Games", &Index);
    g_Results[3] = Handle != NULL;
    if (Handle)
        pRevert(Handle);
    return 0;
}

static void TestRegistration(void)
{
    DWORD Index = 0, Index2, Saved;
    HANDLE Handle, Other;
    HANDLE Thread;

    Handle = SetTask(L"Audio", &Index);
    ok(Handle != NULL && Index != 0, "registration failed: %lu\n", g_Error);

    /* a thread is in one task: asking again is refused, naming another index is not its own */
    Index2 = Index;
    ok(SetTask(L"Audio", &Index2) == NULL && g_Error == ERROR_THREAD_ALREADY_IN_TASK, "same task and index: error %lu\n", g_Error);
    ok(Index2 == Index, "the index changed\n");
    Index2 = 0;
    ok(SetTask(L"Games", &Index2) == NULL && g_Error == ERROR_THREAD_ALREADY_IN_TASK, "other task: error %lu\n", g_Error);
    Index2 = Index;
    ok(SetTask(L"Games", &Index2) == NULL && g_Error == ERROR_INVALID_TASK_INDEX, "other task, own index: error %lu\n", g_Error);
    Index2 = Index + 100;
    ok(SetTask(L"Audio", &Index2) == NULL && g_Error == ERROR_INVALID_TASK_INDEX, "wrong index: error %lu\n", g_Error);

    /* the other thread ends this registration */
    g_Handle = Handle;
    g_Index = Index;
    Thread = CreateThread(NULL, 0, OtherThread, NULL, 0, NULL);
    WaitForSingleObject(Thread, 10000);
    CloseHandle(Thread);
    ok(g_Results[0], "revert from another thread failed\n");
    ok(!g_Results[1] && g_Results[2] == ERROR_INVALID_HANDLE, "priority on a reverted handle: %lu, error %lu\n", g_Results[1], g_Results[2]);
    ok(g_Results[3], "the other thread could not register\n");
    Index2 = 0;
    Other = SetTask(L"Games", &Index2);
    ok(Other != NULL, "registration after the revert failed: %lu\n", g_Error);
    ok(!Call(pRevert(Handle)) && g_Error == ERROR_INVALID_HANDLE, "revert again: error %lu\n", g_Error);
    if (Other)
        ok(Call(pRevert(Other)), "revert failed\n");

    /* an index of a thread that is not in a task is not its own */
    Index2 = 77;
    ok(SetTask(L"Audio", &Index2) == NULL && g_Error == ERROR_INVALID_TASK_INDEX, "index without a task: error %lu\n", g_Error);
    ok(Index2 == 77, "the index changed\n");

    /* handles that are not task handles */
    ok(!Call(pRevert(NULL)) && g_Error == ERROR_INVALID_HANDLE, "revert NULL: error %lu\n", g_Error);
    ok(!Call(pRevert((HANDLE)0x1234)) && g_Error == ERROR_INVALID_HANDLE, "revert garbage: error %lu\n", g_Error);
    ok(!Call(pPriority(NULL, 0)) && g_Error == ERROR_INVALID_HANDLE, "priority NULL: error %lu\n", g_Error);
    ok(!Call(pPriority((HANDLE)0x1234, 0)) && g_Error == ERROR_INVALID_HANDLE, "priority garbage: error %lu\n", g_Error);

    /* priorities */
    Index = 0;
    Handle = SetTask(L"Games", &Index);
    ok(Handle != NULL, "registration failed\n");
    if (Handle)
    {
        int Priority;

        for (Priority = -2; Priority <= 2; Priority++)
            ok(Call(pPriority(Handle, Priority)), "priority %d: error %lu\n", Priority, g_Error);
        ok(!Call(pPriority(Handle, 3)) && g_Error == ERROR_INVALID_PARAMETER, "priority 3: error %lu\n", g_Error);
        ok(!Call(pPriority(Handle, -3)) && g_Error == ERROR_INVALID_PARAMETER, "priority -3: error %lu\n", g_Error);
        ok(!Call(pPriority(Handle, 100)) && g_Error == ERROR_INVALID_PARAMETER, "priority 100: error %lu\n", g_Error);
        Saved = 0;
        ok(Call(pQuery(Handle, &Saved)), "query failed: %lu\n", g_Error);
        if (g_Error == 0)
        {
            DWORD Value = 20, Size = sizeof(Value);
            HKEY Key;

            if (!RegOpenKeyExW(HKEY_LOCAL_MACHINE, TASKS_KEY, 0, KEY_QUERY_VALUE, &Key))
            {
                RegQueryValueExW(Key, L"SystemResponsiveness", NULL, NULL, (BYTE *)&Value, &Size);
                RegCloseKey(Key);
            }
            ok(Saved == Value, "responsiveness %lu, the registry has %lu\n", Saved, Value);
        }
        ok(!Call(pQuery(Handle, NULL)) && g_Error == ERROR_NOACCESS, "query with no value: error %lu\n", g_Error);
        ok(Call(pRevert(Handle)), "revert failed\n");
    }
    Saved = 99;
    ok(!Call(pQuery(NULL, &Saved)) && g_Error == ERROR_INVALID_HANDLE, "query NULL: error %lu\n", g_Error);
    ok(Saved == 99, "the value was written\n");
    ok(!Call(pQuery((HANDLE)0x1234, &Saved)) && g_Error == ERROR_INVALID_HANDLE, "query garbage: error %lu\n", g_Error);
}

static void TestMax(void)
{
    DWORD Index = 0;
    HANDLE Handle;

    Handle = pSetMax(L"Audio", L"Games", &Index);
    ok(Handle != NULL && Index != 0, "max registration failed: %lu\n", GetLastError());
    if (Handle)
        ok(Call(pRevert(Handle)), "revert failed\n");
    Index = 0;
    Handle = pSetMax(L"Audio", L"Audio", &Index);
    ok(Handle != NULL, "max with one task twice failed: %lu\n", GetLastError());
    if (Handle)
        pRevert(Handle);
    Index = 0;
    Handle = pSetMax(L"Audio", NULL, &Index);
    ok(Handle != NULL, "max with one task failed: %lu\n", GetLastError());
    if (Handle)
        pRevert(Handle);
    Index = 0;
    SetLastError(0xdeadbeef);
    Handle = pSetMax(L"Games", L"NoSuchTask", &Index);
    ok(Handle == NULL && GetLastError() == ERROR_INVALID_TASK_NAME, "max with an unknown task: error %lu\n", GetLastError());
    ok(Index == 0, "the index was set\n");
    if (Handle)
        pRevert(Handle);
}

static struct
{
    const WCHAR *Name;
    const WCHAR *Category;   /* NULL: no value */
    int Priority;            /* -1: no value */
    BOOL Valid;
    BOOL Created;
} g_Custom[] =
{
    { L"ApitestLow",     L"Low",   4,  TRUE },
    { L"ApitestNoCat",   NULL,     3,  TRUE },
    { L"ApitestEmpty",   NULL,     -1, TRUE },
    { L"ApitestMedium",  L"Medium", 8, TRUE },
    { L"ApitestHigh",    L"High",  8,  TRUE },
    { L"ApitestPrio0",   L"Low",   0,  FALSE },
    { L"ApitestPrio9",   L"Low",   9,  FALSE },
    { L"ApitestBadCat",  L"Bogus", 3,  FALSE },
};

static BOOL MakeCustomTasks(void)
{
    size_t i;
    BOOL All = TRUE;

    for (i = 0; i < ARRAYSIZE(g_Custom); i++)
    {
        WCHAR Path[MAX_PATH];
        HKEY Key;
        DWORD Disposition = 0;
        LONG Err;

        StringCchPrintfW(Path, MAX_PATH, TASKS_KEY L"\\Tasks\\%ls", g_Custom[i].Name);
        Err = RegCreateKeyExW(HKEY_LOCAL_MACHINE, Path, 0, NULL, 0, KEY_SET_VALUE, NULL, &Key, &Disposition);
        if (Err)
        {
            All = FALSE;
            continue;
        }
        if (Disposition == REG_CREATED_NEW_KEY)
        {
            g_Custom[i].Created = TRUE;
            if (g_Custom[i].Category)
                RegSetValueExW(Key, L"Scheduling Category", 0, REG_SZ, (const BYTE *)g_Custom[i].Category, (lstrlenW(g_Custom[i].Category) + 1) * sizeof(WCHAR));
            if (g_Custom[i].Priority >= 0)
            {
                DWORD Value = g_Custom[i].Priority;
                RegSetValueExW(Key, L"Priority", 0, REG_DWORD, (const BYTE *)&Value, sizeof(Value));
            }
        }
        RegCloseKey(Key);
    }
    return All;
}

static void DeleteCustomTasks(void)
{
    size_t i;

    for (i = 0; i < ARRAYSIZE(g_Custom); i++)
    {
        WCHAR Path[MAX_PATH];

        if (!g_Custom[i].Created)
            continue;
        StringCchPrintfW(Path, MAX_PATH, TASKS_KEY L"\\Tasks\\%ls", g_Custom[i].Name);
        RegDeleteKeyW(HKEY_LOCAL_MACHINE, Path);
    }
}

static void TestCustomTasks(void)
{
    static const int Starts[] = { THREAD_PRIORITY_IDLE, THREAD_PRIORITY_LOWEST, 0, THREAD_PRIORITY_HIGHEST, THREAD_PRIORITY_TIME_CRITICAL };
    size_t i, j;

    for (i = 0; i < ARRAYSIZE(g_Custom); i++)
    {
        DWORD Index = 0;
        HANDLE Handle = SetTask(g_Custom[i].Name, &Index);

        if (!g_Custom[i].Valid)
        {
            ok(Handle == NULL && g_Error == ERROR_INVALID_TASK_NAME, "%ls: a task with invalid values was accepted (error %lu)\n", g_Custom[i].Name, g_Error);
            if (Handle)
                pRevert(Handle);
            continue;
        }
        ok(Handle != NULL, "%ls: failed with %lu\n", g_Custom[i].Name, g_Error);
        if (Handle)
            pRevert(Handle);
    }

    /* a task of the Low category leaves the thread's priority as it is, AvSetMmThreadPriority sets the one asked for
       relative to the process, and the revert gives the old one back */
    for (j = 0; j < ARRAYSIZE(Starts); j++)
    {
        static const WCHAR *Lows[] = { L"ApitestLow", L"ApitestNoCat", L"ApitestEmpty" };
        size_t k;

        for (k = 0; k < ARRAYSIZE(Lows); k++)
        {
            DWORD Index = 0;
            HANDLE Handle;
            int Priority;

            SetThreadPriority(GetCurrentThread(), Starts[j]);
            Handle = SetTask(Lows[k], &Index);
            if (!Handle)
            {
                skip("%ls is not available\n", Lows[k]);
                continue;
            }
            ok(GetThreadPriority(GetCurrentThread()) == Starts[j], "%ls: the priority changed to %d\n", Lows[k], GetThreadPriority(GetCurrentThread()));
            for (Priority = -2; Priority <= 2; Priority++)
            {
                ok(Call(pPriority(Handle, Priority)), "priority %d failed: %lu\n", Priority, g_Error);
                ok(GetThreadPriority(GetCurrentThread()) == Priority, "%ls: priority %d gave %d\n", Lows[k], Priority, GetThreadPriority(GetCurrentThread()));
            }
            ok(Call(pRevert(Handle)), "revert failed\n");
            ok(GetThreadPriority(GetCurrentThread()) == Starts[j], "%ls: after the revert the priority is %d, expected %d\n", Lows[k], GetThreadPriority(GetCurrentThread()), Starts[j]);
        }
    }
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
}

/* a thread that joins and ends without a revert must not keep a later thread (which may get its identifier) out of a task */
static DWORD WINAPI JoinAndEnd(PVOID Context)
{
    DWORD Index = 0;
    HANDLE Handle = pSet(L"Games", &Index);

    *(LONG *)Context = Handle != NULL;
    return 0;
}

static void TestEndedThreads(void)
{
    int i, Failed = 0;
    HANDLE Handle;
    DWORD Index = 0;

    for (i = 0; i < 3000; i++)
    {
        LONG Joined = 0;
        HANDLE Thread = CreateThread(NULL, 0, JoinAndEnd, &Joined, 0, NULL);

        WaitForSingleObject(Thread, 10000);
        CloseHandle(Thread);
        if (!Joined)
            Failed++;
    }
    ok(Failed == 0, "%d of 3000 threads were refused a task after earlier threads ended inside one\n", Failed);
    Handle = SetTask(L"Games", &Index);
    ok(Handle != NULL, "the main thread is refused a task: %lu\n", g_Error);
    if (Handle)
        pRevert(Handle);
}

/* the thread ordering groups fail as a group (ERROR_SERVICE_DISABLED on Windows Server 2022), they do not stop the process */
static void TestOrderingGroups(HMODULE Avrt)
{
    BOOL (WINAPI *pCreate)(PHANDLE, PLARGE_INTEGER, GUID *, PLARGE_INTEGER) = (PVOID)GetProcAddress(Avrt, "AvRtCreateThreadOrderingGroup");
    BOOL (WINAPI *pCreateEx)(PHANDLE, PLARGE_INTEGER, GUID *, PLARGE_INTEGER, LPCWSTR) = (PVOID)GetProcAddress(Avrt, "AvRtCreateThreadOrderingGroupExW");
    BOOL (WINAPI *pJoin)(PHANDLE, GUID *, BOOL) = (PVOID)GetProcAddress(Avrt, "AvRtJoinThreadOrderingGroup");
    BOOL (WINAPI *pWait)(HANDLE) = (PVOID)GetProcAddress(Avrt, "AvRtWaitOnThreadOrderingGroup");
    BOOL (WINAPI *pLeave)(HANDLE) = (PVOID)GetProcAddress(Avrt, "AvRtLeaveThreadOrderingGroup");
    BOOL (WINAPI *pDelete)(HANDLE) = (PVOID)GetProcAddress(Avrt, "AvRtDeleteThreadOrderingGroup");
    HANDLE Group = NULL;
    LARGE_INTEGER Period, Timeout;
    GUID Guid = { 0 };
    BOOL Ok;

    if (!pCreate || !pCreateEx || !pJoin || !pWait || !pLeave || !pDelete)
    {
        skip("the thread ordering group exports are missing\n");
        return;
    }
    Period.QuadPart = 100000;
    Timeout.QuadPart = 10000000;

#define GROUP_FAILS(Call, Name) \
    SetLastError(0xdeadbeef); Ok = Call; \
    ok(!Ok && GetLastError() == ERROR_SERVICE_DISABLED, Name ": %d, error %lu\n", Ok, GetLastError())
    GROUP_FAILS(pCreate(&Group, &Period, &Guid, &Timeout), "create");
    GROUP_FAILS(pCreateEx(&Group, &Period, &Guid, &Timeout, L"Audio"), "create ex");
    GROUP_FAILS(pJoin(&Group, &Guid, TRUE), "join");
    GROUP_FAILS(pWait(Group), "wait");
    GROUP_FAILS(pLeave(Group), "leave");
    GROUP_FAILS(pDelete(Group), "delete");
#undef GROUP_FAILS
}

START_TEST(AvrtScheduler)
{
    HMODULE Avrt = LoadLibraryW(L"avrt.dll");

    if (!Avrt)
    {
        skip("avrt.dll is missing\n");
        return;
    }
    pSet = (PVOID)GetProcAddress(Avrt, "AvSetMmThreadCharacteristicsW");
    pSetMax = (PVOID)GetProcAddress(Avrt, "AvSetMmMaxThreadCharacteristicsW");
    pRevert = (PVOID)GetProcAddress(Avrt, "AvRevertMmThreadCharacteristics");
    pPriority = (PVOID)GetProcAddress(Avrt, "AvSetMmThreadPriority");
    pQuery = (PVOID)GetProcAddress(Avrt, "AvQuerySystemResponsiveness");
    if (!pSet || !pSetMax || !pRevert || !pPriority || !pQuery)
    {
        skip("avrt exports are missing\n");
        return;
    }

    TestNames();
    TestRegistration();
    TestMax();
    TestEndedThreads();
    TestOrderingGroups(Avrt);
    if (MakeCustomTasks())
        TestCustomTasks();
    else
        skip("the task table cannot be changed\n");
    DeleteCustomTasks();
}
