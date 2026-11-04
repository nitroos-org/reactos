/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     A window station and a desktop a child process creates, uses and closes are freed
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A sandbox broker creates an unnamed window station with a desktop for its child processes,
 * and the processes on that desktop create windows (some of which fail). Once the last handle
 * and reference go, the window station and the desktop are deleted: the number of objects of
 * both types returns to where it was. ReactOS kept a reference on the window station for every
 * window creation that failed (one window station per Firefox run, before the sandbox processes
 * stopped failing there).
 */

#include "precomp.h"

#define CHILD_COUNT 50
#define FAILED_WINDOWS 3

typedef LONG (NTAPI *PFN_NTQUERYOBJECT)(HANDLE, ULONG, PVOID, ULONG, PULONG);

/* The start of OBJECT_TYPE_INFORMATION (ObjectTypeInformation = 2) */
typedef struct _WSL_TYPE_INFO
{
    USHORT NameLength;
    USHORT NameMaximumLength;
    PWSTR NameBuffer;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG Rest[64];
} WSL_TYPE_INFO;

static PFN_NTQUERYOBJECT pNtQueryObject;

static LONG
GetObjectCount(HANDLE Handle)
{
    WSL_TYPE_INFO Info;
    ULONG Length = 0;
    LONG Status;

    ZeroMemory(&Info, sizeof(Info));
    Status = pNtQueryObject(Handle, 2, &Info, sizeof(Info), &Length);
    if (Status < 0)
    {
        ok(0, "NtQueryObject(ObjectTypeInformation) failed, status 0x%08lx\n", Status);
        return -1;
    }
    return (LONG)Info.TotalNumberOfObjects;
}

/* Object deletion can be deferred to a worker: give it a moment to reach the baseline */
static LONG
WaitForObjectCount(HANDLE Handle, LONG Baseline)
{
    LONG Count = GetObjectCount(Handle);
    UINT i;

    for (i = 0; i < 50 && Count > Baseline; i++)
    {
        Sleep(100);
        Count = GetObjectCount(Handle);
    }
    return Count;
}

typedef struct _CHILD_THREAD_PARAM
{
    HDESK Desktop;
    UINT Failures;
} CHILD_THREAD_PARAM;

/* What a sandboxed process does on its desktop */
static DWORD WINAPI
ChildThreadProc(LPVOID Param)
{
    CHILD_THREAD_PARAM *ThreadParam = Param;
    HWND Window;
    UINT i;

    if (!SetThreadDesktop(ThreadParam->Desktop))
    {
        ThreadParam->Failures++;
        return 1;
    }

    /* Window creations that fail must not keep anything */
    for (i = 0; i < FAILED_WINDOWS; i++)
    {
        Window = CreateWindowExW(0, L"WindowStationLeakNoSuchClass", L"x", WS_POPUP, 0, 0, 10, 10,
                                 NULL, NULL, GetModuleHandleW(NULL), NULL);
        if (Window != NULL)
        {
            ThreadParam->Failures++;
            DestroyWindow(Window);
        }
        Window = CreateWindowExW(0, L"STATIC", L"x", WS_CHILD, 0, 0, 10, 10,
                                 NULL, NULL, GetModuleHandleW(NULL), NULL);
        if (Window != NULL)
        {
            ThreadParam->Failures++;
            DestroyWindow(Window);
        }
    }

    /* And one that works */
    Window = CreateWindowExW(0, L"STATIC", L"x", WS_POPUP, 0, 0, 10, 10, NULL, NULL, GetModuleHandleW(NULL), NULL);
    if (Window == NULL)
        ThreadParam->Failures++;
    else if (!DestroyWindow(Window))
        ThreadParam->Failures++;

    return 0;
}

/* Child: returns the number of steps that did not work, as its exit code */
static UINT
RunChild(BOOL CloseHandles)
{
    CHILD_THREAD_PARAM ThreadParam = { NULL, 0 };
    HWINSTA OldWinSta, WinSta;
    HANDLE Thread;
    WCHAR Name[64];
    DWORD Needed;

    OldWinSta = GetProcessWindowStation();
    WinSta = CreateWindowStationW(NULL, 0, WINSTA_ALL_ACCESS, NULL);
    if (WinSta == NULL)
        return 100;

    /* The broker creates the desktop in the new window station */
    if (!SetProcessWindowStation(WinSta))
        return 101;
    wsprintfW(Name, L"WindowStationLeak%lu", GetCurrentProcessId());
    ThreadParam.Desktop = CreateDesktopW(Name, NULL, NULL, 0, DESKTOP_ALL_ACCESS, NULL);
    if (ThreadParam.Desktop == NULL)
        return 103;

    if (!GetUserObjectInformationW(WinSta, UOI_NAME, Name, sizeof(Name), &Needed) &&
        GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    {
        ThreadParam.Failures++;
    }
    if (!GetUserObjectInformationW(ThreadParam.Desktop, UOI_NAME, Name, sizeof(Name), &Needed))
        ThreadParam.Failures++;

    Thread = CreateThread(NULL, 0, ChildThreadProc, &ThreadParam, 0, NULL);
    if (Thread == NULL)
        return 104;
    WaitForSingleObject(Thread, INFINITE);
    CloseHandle(Thread);

    /* Half of the children close their handles, the others exit with them open (and the
       window station still their process window station, as a sandboxed process) */
    if (CloseHandles)
    {
        if (!SetProcessWindowStation(OldWinSta))
            return 102;
        if (!CloseDesktop(ThreadParam.Desktop))
            ThreadParam.Failures++;
        if (!CloseWindowStation(WinSta))
            ThreadParam.Failures++;
    }

    return ThreadParam.Failures;
}

START_TEST(WindowStationLeak)
{
    CHAR Self[MAX_PATH], CommandLine[MAX_PATH + 64];
    LONG WinStaBefore, WinStaAfter, DesktopBefore, DesktopAfter;
    HWINSTA WinSta;
    HDESK Desktop;
    char **argv;
    int argc = winetest_get_mainargs(&argv);
    UINT i, Done = 0;

    if (argc >= 4 && !strcmp(argv[2], "child"))
    {
        ExitProcess(RunChild(!strcmp(argv[3], "close")));
    }

    pNtQueryObject = (PFN_NTQUERYOBJECT)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject");
    if (!pNtQueryObject)
    {
        skip("NtQueryObject not found\n");
        return;
    }

    WinSta = GetProcessWindowStation();
    Desktop = GetThreadDesktop(GetCurrentThreadId());
    WinStaBefore = GetObjectCount(WinSta);
    DesktopBefore = GetObjectCount(Desktop);
    ok(WinStaBefore > 0, "window station count %ld\n", WinStaBefore);
    ok(DesktopBefore > 0, "desktop count %ld\n", DesktopBefore);
    if (WinStaBefore <= 0 || DesktopBefore <= 0)
        return;

    GetModuleFileNameA(NULL, Self, sizeof(Self));
    for (i = 0; i < CHILD_COUNT; i++)
    {
        STARTUPINFOA Startup = { sizeof(Startup) };
        PROCESS_INFORMATION Info;
        DWORD ExitCode = 0xDEADBEEF;

        sprintf(CommandLine, "\"%s\" WindowStationLeak child %s", Self, (i & 1) ? "close" : "exit");
        if (!CreateProcessA(NULL, CommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &Startup, &Info))
        {
            ok(0, "CreateProcess %u failed, error %lu\n", i, GetLastError());
            break;
        }
        ok(WaitForSingleObject(Info.hProcess, 60000) == WAIT_OBJECT_0, "child %u did not exit\n", i);
        GetExitCodeProcess(Info.hProcess, &ExitCode);
        ok(ExitCode == 0, "child %u (%s) exit code %lu\n", i, (i & 1) ? "close" : "exit", ExitCode);
        CloseHandle(Info.hThread);
        CloseHandle(Info.hProcess);
        if (ExitCode == 0)
            Done++;
    }
    ok(Done == CHILD_COUNT, "%u of %u children worked\n", Done, CHILD_COUNT);

    WinStaAfter = WaitForObjectCount(WinSta, WinStaBefore);
    DesktopAfter = WaitForObjectCount(Desktop, DesktopBefore);
    trace("window stations %ld -> %ld, desktops %ld -> %ld after %u children\n",
          WinStaBefore, WinStaAfter, DesktopBefore, DesktopAfter, Done);
    ok(WinStaAfter <= WinStaBefore, "window stations: %ld before, %ld after %u children\n",
       WinStaBefore, WinStaAfter, Done);
    ok(DesktopAfter <= DesktopBefore, "desktops: %ld before, %ld after %u children\n",
       DesktopBefore, DesktopAfter, Done);
}
