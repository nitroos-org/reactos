/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test that opening and closing folder windows does not leak GDI/USER objects in the shell
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * ShellExecute "open" and "explore" on a folder open a folder window in the shell process, on a thread of
 * its own. On Windows 10 22H2 the shell's GDI and USER object counts stay flat over 50 such windows opened
 * and closed.
 */

#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#include <winuser.h>
#include <shellapi.h>
#include <strsafe.h>

#define WINDOWS 8
/* Windows caches objects for the first few windows, then flattens out. Measured on Windows 10 22H2 over 50
 * windows: GDI flat with transients up to +9, USER drifting by +4/+5. The leak this test is about is 8 GDI and
 * 2 USER objects per window, i.e. +64 and +16 over WINDOWS windows, far above these bounds. */
#define WARMUP_WINDOWS 4
#define MAX_GDI_DRIFT 8
#define MAX_USER_DRIFT 6

static DWORD g_HostPid;
static HWND g_Known[64];
static int g_KnownCount;

static BOOL IsFolderWindow(HWND hwnd)
{
    WCHAR szClass[64];

    if (!IsWindowVisible(hwnd))
        return FALSE;
    if (!GetClassNameW(hwnd, szClass, _countof(szClass)))
        return FALSE;
    return !wcscmp(szClass, L"CabinetWClass") || !wcscmp(szClass, L"ExploreWClass");
}

static BOOL CALLBACK CollectProc(HWND hwnd, LPARAM lParam)
{
    if (IsFolderWindow(hwnd) && g_KnownCount < _countof(g_Known))
        g_Known[g_KnownCount++] = hwnd;
    return TRUE;
}

static BOOL CALLBACK FindNewProc(HWND hwnd, LPARAM lParam)
{
    int i;

    if (!IsFolderWindow(hwnd))
        return TRUE;
    for (i = 0; i < g_KnownCount; i++)
    {
        if (g_Known[i] == hwnd)
            return TRUE;
    }
    *(HWND *)lParam = hwnd;
    return FALSE;
}

/* Closes a folder window; posts WM_CLOSE again once if the window is still there after 5 s */
static BOOL CloseFolderWindow(HWND hwnd)
{
    int attempt, i;

    for (attempt = 0; attempt < 2; attempt++)
    {
        PostMessageW(hwnd, WM_CLOSE, 0, 0);
        for (i = 0; i < 50 && IsWindow(hwnd); i++)
            Sleep(100);
        if (!IsWindow(hwnd))
            return TRUE;
    }
    return FALSE;
}

/* Opens a folder window with a verb and closes it again; returns the process that hosted it, 0 on failure */
static DWORD OpenAndCloseFolder(PCWSTR pszVerb, PCWSTR pszDir)
{
    HINSTANCE hInst;
    HWND hwnd = NULL;
    DWORD pid = 0;
    int i;

    g_KnownCount = 0;
    EnumWindows(CollectProc, 0);

    hInst = ShellExecuteW(NULL, pszVerb, pszDir, NULL, NULL, SW_SHOWNORMAL);
    if ((INT_PTR)hInst <= 32)
        return 0;

    for (i = 0; i < 150 && !hwnd; i++)
    {
        Sleep(100);
        EnumWindows(FindNewProc, (LPARAM)&hwnd);
    }
    if (!hwnd)
        return 0;
    GetWindowThreadProcessId(hwnd, &pid);

    Sleep(1500);
    return CloseFolderWindow(hwnd) ? pid : 0;
}

static void TestFolderWindows(PCWSTR pszVerb, PCWSTR pszDir)
{
    DWORD gdi0, user0, gdi1, user1;
    HANDLE hHost;
    int i, failed = 0;

    /* The first windows load the shell extensions and make the shared image lists */
    g_HostPid = OpenAndCloseFolder(pszVerb, pszDir);
    if (!g_HostPid)
    {
        skip("ShellExecute(%ls) did not open and close a folder window\n", pszVerb);
        return;
    }
    if (g_HostPid == GetCurrentProcessId())
    {
        skip("ShellExecute(%ls) opened the folder window in this process\n", pszVerb);
        return;
    }
    hHost = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, g_HostPid);
    if (!hHost)
    {
        skip("Cannot open the folder window process: %lu\n", GetLastError());
        return;
    }
    if (GetGuiResources(hHost, GR_USEROBJECTS) == 0)
    {
        /* Not on the interactive window station */
        skip("GetGuiResources returns 0 for the folder window process\n");
        CloseHandle(hHost);
        return;
    }

    for (i = 1; i < WARMUP_WINDOWS; i++)
        OpenAndCloseFolder(pszVerb, pszDir);

    gdi0 = GetGuiResources(hHost, GR_GDIOBJECTS);
    user0 = GetGuiResources(hHost, GR_USEROBJECTS);
    for (i = 0; i < WINDOWS; i++)
    {
        if (OpenAndCloseFolder(pszVerb, pszDir) != g_HostPid)
            failed++;
    }
    gdi1 = GetGuiResources(hHost, GR_GDIOBJECTS);
    user1 = GetGuiResources(hHost, GR_USEROBJECTS);
    CloseHandle(hHost);

    ok(failed == 0, "%ls: %d of %d folder windows did not open and close in process %lu\n",
       pszVerb, failed, WINDOWS, g_HostPid);
    ok((LONG)(gdi1 - gdi0) <= MAX_GDI_DRIFT, "%ls: %d folder windows changed the shell's GDI object count from %lu to %lu\n",
       pszVerb, WINDOWS, gdi0, gdi1);
    ok((LONG)(user1 - user0) <= MAX_USER_DRIFT, "%ls: %d folder windows changed the shell's USER object count from %lu to %lu\n",
       pszVerb, WINDOWS, user0, user1);
}

START_TEST(FolderWindowResources)
{
    WCHAR szDir[MAX_PATH], szFile[MAX_PATH];
    HANDLE hFile;

    if (!GetShellWindow())
    {
        skip("No shell window\n");
        return;
    }

    GetTempPathW(_countof(szDir), szDir);
    StringCchPrintfW(szDir + wcslen(szDir), _countof(szDir) - wcslen(szDir), L"FolderWindowResources%lu", GetCurrentProcessId());
    ok(CreateDirectoryW(szDir, NULL), "CreateDirectoryW failed: %lu\n", GetLastError());
    StringCchPrintfW(szFile, _countof(szFile), L"%s\\file.txt", szDir);
    hFile = CreateFileW(szFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    ok(hFile != INVALID_HANDLE_VALUE, "CreateFileW failed: %lu\n", GetLastError());
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);

    TestFolderWindows(L"explore", szDir);
    TestFolderWindows(L"open", szDir);

    DeleteFileW(szFile);
    RemoveDirectoryW(szDir);
}
