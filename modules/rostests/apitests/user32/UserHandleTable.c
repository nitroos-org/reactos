/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The table of user handles of a session holds more than 4096 entries
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Windows has 65536 user handles per session and a quota of 10000 per process. The table of a session used to hold
 * 4096 entries: one process taking 3960 objects left every other process without a window, a menu or a hook.
 * The rows: one process takes 6000 hooks (more than the old table held), a second process still makes a window, a
 * menu and a hook, the handles that existed before keep their value and stay valid, and the table is empty again
 * when the hooks are gone.
 */

#include "precomp.h"

#define HOOKS 6000

static LRESULT CALLBACK MouseProc(int Code, WPARAM wParam, LPARAM lParam)
{
    return CallNextHookEx(NULL, Code, wParam, lParam);
}

static DWORD RunChild(void)
{
    WCHAR Path[MAX_PATH + 32];
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    DWORD Exit = 0xdead;

    SetEnvironmentVariableW(L"HANDLEQUOTA_CHILD", L"1");
    GetModuleFileNameW(NULL, Path, MAX_PATH);
    wcscat(Path, L" HandleQuotaChild");
    if (CreateProcessW(NULL, Path, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        WaitForSingleObject(pi.hProcess, 60000);
        GetExitCodeProcess(pi.hProcess, &Exit);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    return Exit;
}

START_TEST(UserHandleTable)
{
    HHOOK *Hooks;
    HWND hWnd0, hWnd1;
    HMENU hMenu0;
    ULONG Count, i, Start;
    DWORD Low0, Low1;

    Hooks = HeapAlloc(GetProcessHeap(), 0, HOOKS * sizeof(*Hooks));
    if (!Hooks)
    {
        skip("no memory\n");
        return;
    }

    hWnd0 = CreateWindowExW(0, L"STATIC", L"first", WS_OVERLAPPED, 0, 0, 10, 10, NULL, NULL, NULL, NULL);
    hMenu0 = CreateMenu();
    ok(hWnd0 != NULL, "CreateWindowEx failed: %lu\n", GetLastError());
    ok(hMenu0 != NULL, "CreateMenu failed: %lu\n", GetLastError());
    Low0 = (DWORD)(ULONG_PTR)hWnd0 & 0xffff;
    /* the layout of a handle: the low word is 0x20 + 2 * index of the table, the high word the uniqueness */
    ok(Low0 >= 0x20 && !(Low0 & 1), "the handle %p does not have the layout of a user handle\n", hWnd0);

    Start = GetGuiResources(GetCurrentProcess(), GR_USEROBJECTS);
    for (Count = 0; Count < HOOKS; Count++)
    {
        Hooks[Count] = SetWindowsHookExW(WH_MOUSE, MouseProc, NULL, GetCurrentThreadId());
        if (!Hooks[Count])
            break;
    }
    ok(Count == HOOKS, "%lu of %d hooks were made (last error %lu)\n", Count, HOOKS, GetLastError());
    ok(GetGuiResources(GetCurrentProcess(), GR_USEROBJECTS) == Start + Count, "GetGuiResources(GR_USEROBJECTS) says %lu\n",
       GetGuiResources(GetCurrentProcess(), GR_USEROBJECTS));

    /* the handles that existed before are as they were */
    ok(IsWindow(hWnd0), "the first window is gone\n");
    ok(((DWORD)(ULONG_PTR)hWnd0 & 0xffff) == Low0, "the handle changed\n");
    ok(IsMenu(hMenu0), "the first menu is gone\n");

    /* a window made now is above the old limit of the table and works */
    hWnd1 = CreateWindowExW(0, L"STATIC", L"second", WS_OVERLAPPED, 0, 0, 10, 10, NULL, NULL, NULL, NULL);
    ok(hWnd1 != NULL, "CreateWindowEx with %lu hooks held failed: %lu\n", Count, GetLastError());
    if (hWnd1)
    {
        Low1 = (DWORD)(ULONG_PTR)hWnd1 & 0xffff;
        ok(Low1 >= 0x20 && !(Low1 & 1) && hWnd1 != hWnd0, "the handle %p does not have the layout of a user handle\n", hWnd1);
        ok(IsWindow(hWnd1), "the second window is not valid\n");
        ok(DestroyWindow(hWnd1), "DestroyWindow failed: %lu\n", GetLastError());
        ok(!IsWindow(hWnd1), "the destroyed window is valid\n");
    }

    /* a second process is not affected */
    ok(RunChild() == 0, "a second process cannot make its objects while the first holds %lu hooks\n", Count);

    for (i = 0; i < Count; i++)
        UnhookWindowsHookEx(Hooks[i]);
    ok(GetGuiResources(GetCurrentProcess(), GR_USEROBJECTS) == Start, "USER objects are left: %lu, expected %lu\n",
       GetGuiResources(GetCurrentProcess(), GR_USEROBJECTS), Start);
    ok(IsWindow(hWnd0), "the first window is gone after the hooks\n");
    DestroyMenu(hMenu0);
    DestroyWindow(hWnd0);
    HeapFree(GetProcessHeap(), 0, Hooks);
}
