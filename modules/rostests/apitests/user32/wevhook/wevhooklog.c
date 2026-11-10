/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     wevhook.c plus a marker: every process that loads the DLL appends its id to user32_wevhook.log
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winuser.h>

static volatile LONG HookCount;

VOID WINAPI
WevHookProc(HWINEVENTHOOK hHook, DWORD Event, HWND hWnd, LONG idObject, LONG idChild, DWORD EventThread, DWORD EventTime)
{
    InterlockedIncrement(&HookCount);
}

LONG WINAPI
WevGetCount(VOID)
{
    return HookCount;
}

/* Every process that loads the DLL appends its id to user32_wevhook.log next to it (the WinEventInContext test
   reads it to see where the hook DLL was loaded) */
static VOID
LogLoad(HINSTANCE hInstDll)
{
    WCHAR Path[MAX_PATH], *p;
    char Line[32];
    DWORD Written, Len;
    HANDLE hFile;

    if (!GetModuleFileNameW(hInstDll, Path, MAX_PATH))
        return;
    p = Path + lstrlenW(Path);
    while (p > Path && p[-1] != L'\\')
        p--;
    lstrcpyW(p, L"user32_wevhook.log");
    hFile = CreateFileW(Path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return;
    Len = wsprintfA(Line, "%lu\r\n", GetCurrentProcessId());
    WriteFile(hFile, Line, Len, &Written, NULL);
    CloseHandle(hFile);
}

BOOL WINAPI
DllMain(HINSTANCE hInstDll, DWORD Reason, LPVOID Reserved)
{
    if (Reason == DLL_PROCESS_ATTACH)
        LogLoad(hInstDll);
    return TRUE;
}
