/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test the CPU share of the foreground window's process against a background process
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * With Win32PrioritySeparation 2 the threads of the process that owns the foreground window run with
 * a quantum three times as long as those of a background process (18 against 6 quantum units). Two
 * CPU-bound normal-priority processes on one processor therefore split it 3:1 (Windows 10 measured
 * 73 percent for the foreground process), and the background process still gets its quarter.
 * This test is a console program with a window of its own: when its console window loses the focus
 * to that window, the console server must not take the foreground quantum back.
 */

#include "precomp.h"

#include <winreg.h>

#define MEASURE_MS 4000
#define SETTLE_MS  1000

static volatile LONG g_Stop;

static DWORD WINAPI BusyThread(LPVOID Param)
{
    volatile ULONG_PTR Sink = 0;
    ULONG i;

    UNREFERENCED_PARAMETER(Param);
    while (!g_Stop)
    {
        for (i = 0; i < 100000; i++)
            Sink += i * 3 + 1;
    }
    return 0;
}

static void PumpMessages(DWORD Ms)
{
    DWORD Start = GetTickCount();
    MSG Msg;

    while (GetTickCount() - Start < Ms)
    {
        while (PeekMessageA(&Msg, NULL, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&Msg);
            DispatchMessageA(&Msg);
        }
        MsgWaitForMultipleObjects(0, NULL, FALSE, 20, QS_ALLINPUT);
    }
}

static double CpuMs(const FILETIME *Kernel, const FILETIME *User)
{
    ULARGE_INTEGER K, U;

    K.LowPart = Kernel->dwLowDateTime; K.HighPart = Kernel->dwHighDateTime;
    U.LowPart = User->dwLowDateTime;   U.HighPart = User->dwHighDateTime;
    return (double)(K.QuadPart + U.QuadPart) / 10000.0;
}

static BOOL PrioritySeparationIsTwo(void)
{
    HKEY Key;
    DWORD Value = 2, Size = sizeof(Value), Type;

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\PriorityControl",
                      0, KEY_READ, &Key) == ERROR_SUCCESS)
    {
        if (RegQueryValueExA(Key, "Win32PrioritySeparation", NULL, &Type, (LPBYTE)&Value, &Size) != ERROR_SUCCESS ||
            Type != REG_DWORD)
            Value = 2;
        RegCloseKey(Key);
    }
    return (Value & 3) == 2;
}

static DWORD_PTR LowestProcessor(void)
{
    DWORD_PTR Process, System, Bit = 1;

    if (!GetProcessAffinityMask(GetCurrentProcess(), &Process, &System) || !Process)
        return 0;
    while (!(Process & Bit))
        Bit <<= 1;
    return Bit;
}

static void RunChild(const char *EventName)
{
    HANDLE Stop = OpenEventA(SYNCHRONIZE, FALSE, EventName);
    DWORD Start = GetTickCount();
    volatile ULONG_PTR Sink = 0;
    ULONG i;

    if (!Stop)
        return;
    while (WaitForSingleObject(Stop, 0) == WAIT_TIMEOUT && GetTickCount() - Start < 30000)
    {
        for (i = 0; i < 100000; i++)
            Sink += i * 3 + 1;
    }
    CloseHandle(Stop);
}

START_TEST(ForegroundQuantumShare)
{
    char **argv;
    int argc = winetest_get_mainargs(&argv);
    WNDCLASSA Class;
    HWND Window;
    HANDLE Stop, Busy;
    STARTUPINFOA Si;
    PROCESS_INFORMATION Pi;
    char EventName[64], CommandLine[MAX_PATH + 128], Module[MAX_PATH];
    FILETIME Create, Exit, K0, U0, K1, U1, CK0, CU0, CK1, CU1;
    double Parent, Child, Share;
    DWORD_PTR Cpu;

    /* Make this a GUI process */
    GetSystemMetrics(SM_CXSCREEN);

    if (argc >= 4 && !strcmp(argv[2], "child"))
    {
        RunChild(argv[3]);
        return;
    }

    if (!PrioritySeparationIsTwo())
    {
        skip("Win32PrioritySeparation is not 2\n");
        return;
    }

    /* Both processes on one processor: the child inherits the affinity */
    Cpu = LowestProcessor();
    ok(Cpu != 0, "no processor in the affinity mask\n");
    if (!Cpu || !SetProcessAffinityMask(GetCurrentProcess(), Cpu))
    {
        skip("cannot pin the process\n");
        return;
    }
    SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);

    ZeroMemory(&Class, sizeof(Class));
    Class.lpfnWndProc = DefWindowProcA;
    Class.hInstance = GetModuleHandleA(NULL);
    Class.lpszClassName = "ForegroundQuantumShareClass";
    RegisterClassA(&Class);
    Window = CreateWindowA(Class.lpszClassName, "ForegroundQuantumShare", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                           60, 60, 300, 200, NULL, NULL, Class.hInstance, NULL);
    ok(Window != NULL, "CreateWindow failed: %lu\n", GetLastError());
    if (!Window)
        return;
    AllowSetForegroundWindow(ASFW_ANY);
    SetForegroundWindow(Window);
    SetFocus(Window);
    PumpMessages(500);
    if (GetForegroundWindow() != Window)
    {
        skip("cannot bring the test window to the foreground\n");
        DestroyWindow(Window);
        return;
    }

    wsprintfA(EventName, "ForegroundQuantumShare-%lu", GetCurrentProcessId());
    Stop = CreateEventA(NULL, TRUE, FALSE, EventName);
    ok(Stop != NULL, "CreateEvent failed: %lu\n", GetLastError());
    GetModuleFileNameA(NULL, Module, sizeof(Module));
    wsprintfA(CommandLine, "\"%s\" ForegroundQuantumShare child %s", Module, EventName);
    ZeroMemory(&Si, sizeof(Si));
    Si.cb = sizeof(Si);
    if (!Stop || !CreateProcessA(NULL, CommandLine, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, NULL, &Si, &Pi))
    {
        ok(0, "cannot start the background process: %lu\n", GetLastError());
        if (Stop) CloseHandle(Stop);
        DestroyWindow(Window);
        return;
    }

    g_Stop = 0;
    Busy = CreateThread(NULL, 0, BusyThread, NULL, 0, NULL);
    ok(Busy != NULL, "CreateThread failed: %lu\n", GetLastError());

    /* Let the child start and the console and window focus changes settle, then measure */
    PumpMessages(SETTLE_MS);
    ok(GetForegroundWindow() == Window, "the test window lost the foreground\n");
    GetThreadTimes(Busy, &Create, &Exit, &K0, &U0);
    GetProcessTimes(Pi.hProcess, &Create, &Exit, &CK0, &CU0);
    PumpMessages(MEASURE_MS);
    GetThreadTimes(Busy, &Create, &Exit, &K1, &U1);
    GetProcessTimes(Pi.hProcess, &Create, &Exit, &CK1, &CU1);

    g_Stop = 1;
    SetEvent(Stop);
    WaitForSingleObject(Busy, 5000);
    if (WaitForSingleObject(Pi.hProcess, 10000) == WAIT_TIMEOUT)
        TerminateProcess(Pi.hProcess, 0);
    CloseHandle(Pi.hProcess);
    CloseHandle(Pi.hThread);
    CloseHandle(Busy);
    CloseHandle(Stop);
    DestroyWindow(Window);

    Parent = CpuMs(&K1, &U1) - CpuMs(&K0, &U0);
    Child = CpuMs(&CK1, &CU1) - CpuMs(&CK0, &CU0);
    ok(Parent + Child > MEASURE_MS * 0.8, "only %.0f ms of CPU in %d ms on one processor\n", Parent + Child, MEASURE_MS);
    Share = 100.0 * Parent / (Parent + Child);
    trace("foreground process %.0f ms, background process %.0f ms, foreground share %.1f%%\n", Parent, Child, Share);
    /* The foreground quantum alone is 3:1, 75 percent. Windows 10 gives the background process about 5 percent of
       the wall clock against a busy foreground process (foreground slices of about a quantum, background slices
       under one clock tick): the 73 of an earlier probe was a GetProcessTimes artefact. */
    ok(Share > 65.0, "foreground share %.1f%%, expected 75%% or more\n", Share);
    ok(Share < 97.0, "foreground share %.1f%%: the background process is starved (Windows leaves it about 5%%)\n", Share);
}
