/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.0-or-later (https://spdx.org/licenses/LGPL-2.0-or-later)
 * PURPOSE:     Test for SHChangeNotify
 * COPYRIGHT:   Copyright 2020-2024 Katayama Hirofumi MZ (katayama.hirofumi.mz@gmail.com)
 */

// This program is used in SHChangeNotify, ShellExecCmdLine, and ShellState testcases.

#include "shelltest.h"
#include "shell32_apitest_sub.h"
#include <assert.h>

typedef enum DIRTYPE
{
    DIRTYPE_DESKTOP = 0,
    DIRTYPE_DESKTOP_DIR,
    DIRTYPE_DRIVES,
    DIRTYPE_PRINTERS,
    DIRTYPE_DIR1,
    DIRTYPE_MAX
} DIRTYPE;

static HWND s_hMainWnd = NULL, s_hSubWnd = NULL;
static LPITEMIDLIST s_pidl[DIRTYPE_MAX];
static UINT s_uRegID = 0;
static INT s_iStage = -1;

#define EVENTS (SHCNE_CREATE | SHCNE_DELETE | SHCNE_MKDIR | SHCNE_RMDIR | \
                SHCNE_RENAMEFOLDER | SHCNE_RENAMEITEM | SHCNE_UPDATEDIR | SHCNE_UPDATEITEM)

inline LPITEMIDLIST DoGetPidl(INT iDir)
{
    LPITEMIDLIST ret = NULL;

    switch (iDir)
    {
        case DIRTYPE_DESKTOP:
        {
            SHGetSpecialFolderLocation(NULL, CSIDL_DESKTOP, &ret);
            break;
        }
        case DIRTYPE_DESKTOP_DIR:
        {
            WCHAR szPath1[MAX_PATH];
            SHGetSpecialFolderPathW(NULL, szPath1, CSIDL_DESKTOPDIRECTORY, FALSE);
            ret = ILCreateFromPathW(szPath1);
            break;
        }
        case DIRTYPE_DRIVES:
        {
            SHGetSpecialFolderLocation(NULL, CSIDL_DRIVES, &ret);
            break;
        }
        case DIRTYPE_PRINTERS:
        {
            SHGetSpecialFolderLocation(NULL, CSIDL_PRINTERS, &ret);
            break;
        }
        case DIRTYPE_DIR1:
        {
            WCHAR szPath1[MAX_PATH];
            SHGetSpecialFolderPathW(NULL, szPath1, CSIDL_PERSONAL, FALSE); // My Documents
            PathAppendW(szPath1, L"_TESTDIR_1_");
            ret = ILCreateFromPathW(szPath1);
            break;
        }
        default:
        {
            assert(0);
            break;
        }
    }

    return ret;
}

static BOOL OnCreate(HWND hwnd)
{
    s_hSubWnd = hwnd;

    for (INT i = 0; i < DIRTYPE_MAX; ++i)
        s_pidl[i] = DoGetPidl(i);

    return TRUE;
}

static BOOL InitSHCN(HWND hwnd)
{
    assert(0 <= s_iStage);
    assert(s_iStage < NUM_STAGE);

    SHChangeNotifyEntry entry;
    INT sources = 0;
    LONG events = EVENTS;
    switch (s_iStage)
    {
        case 0:
        {
            entry.fRecursive = FALSE;
            entry.pidl = NULL;
            sources = SHCNRF_NewDelivery | SHCNRF_ShellLevel;
            events = EVENTS;
            break;
        }
        case 1:
        {
            entry.fRecursive = TRUE;
            entry.pidl = NULL;
            sources = SHCNRF_NewDelivery | SHCNRF_ShellLevel;
            events = EVENTS;
            break;
        }
        case 2:
        {
            entry.fRecursive = FALSE;
            entry.pidl = s_pidl[DIRTYPE_DESKTOP];
            sources = SHCNRF_NewDelivery | SHCNRF_ShellLevel;
            events = EVENTS;
            break;
        }
        case 3:
        {
            entry.fRecursive = TRUE;
            entry.pidl = s_pidl[DIRTYPE_DESKTOP];
            sources = SHCNRF_NewDelivery | SHCNRF_ShellLevel;
            events = EVENTS;
            break;
        }
        case 4:
        {
            entry.fRecursive = TRUE;
            entry.pidl = s_pidl[DIRTYPE_DESKTOP_DIR];
            sources = SHCNRF_NewDelivery | SHCNRF_ShellLevel;
            events = EVENTS;
            break;
        }
        case 5:
        {
            entry.fRecursive = FALSE;
            entry.pidl = s_pidl[DIRTYPE_DRIVES];
            sources = SHCNRF_NewDelivery | SHCNRF_ShellLevel;
            events = EVENTS;
            break;
        }
        case 6:
        {
            entry.fRecursive = TRUE;
            entry.pidl = s_pidl[DIRTYPE_DRIVES];
            sources = SHCNRF_NewDelivery | SHCNRF_ShellLevel;
            events = EVENTS;
            break;
        }
        case 7:
        {
            entry.fRecursive = TRUE;
            entry.pidl = s_pidl[DIRTYPE_PRINTERS];
            sources = SHCNRF_NewDelivery | SHCNRF_ShellLevel;
            events = EVENTS;
            break;
        }
        case 8:
        {
            entry.fRecursive = FALSE;
            entry.pidl = s_pidl[DIRTYPE_DIR1];
            sources = SHCNRF_NewDelivery | SHCNRF_ShellLevel;
            events = EVENTS;
            break;
        }
        case 9:
        {
            entry.fRecursive = TRUE;
            entry.pidl = s_pidl[DIRTYPE_DIR1];
            sources = SHCNRF_NewDelivery | SHCNRF_ShellLevel | SHCNRF_InterruptLevel |
                      SHCNRF_RecursiveInterrupt;
            events = EVENTS;
            break;
        }
        DEFAULT_UNREACHABLE;
    }

    s_uRegID = SHChangeNotifyRegister(hwnd, sources, events, WM_SHELL_NOTIFY, 1, &entry);
    if (s_uRegID == 0)
        return FALSE;

    return TRUE;
}

static void UnInitSHCN(HWND hwnd)
{
    if (s_uRegID)
    {
        SHChangeNotifyDeregister(s_uRegID);
        s_uRegID = 0;
    }
}

static void OnCommand(HWND hwnd, UINT id)
{
    switch (id)
    {
        case IDYES: // Start testing
        {
            s_hMainWnd = ::FindWindow(MAIN_CLASSNAME, MAIN_CLASSNAME);
            if (!s_hMainWnd)
            {
                ::DestroyWindow(hwnd);
                break;
            }
            s_iStage = 0;
            InitSHCN(hwnd);
            ::PostMessageW(s_hMainWnd, WM_COMMAND, IDYES, 0);
            break;
        }
        case IDRETRY: // New stage
        {
            UnInitSHCN(hwnd);
            ++s_iStage;
            InitSHCN(hwnd);
            ::PostMessageW(s_hMainWnd, WM_COMMAND, IDRETRY, 0);
            break;
        }
        case IDNO: // Quit
        {
            s_iStage = -1;
            UnInitSHCN(hwnd);
            ::DestroyWindow(hwnd);
            break;
        }
    }
}

static void OnDestroy(HWND hwnd)
{
    UnInitSHCN(hwnd);

    for (auto& pidl : s_pidl)
    {
        CoTaskMemFree(pidl);
        pidl = NULL;
    }

    ::PostMessageW(s_hMainWnd, WM_COMMAND, IDNO, 0);

    PostQuitMessage(0);
}

static BOOL DoSendData(LONG lEvent, LPCITEMIDLIST pidl1, LPCITEMIDLIST pidl2)
{
    DWORD cbPidl1 = ILGetSize(pidl1), cbPidl2 = ILGetSize(pidl2);
    DWORD cbTotal = sizeof(lEvent) + sizeof(cbPidl1) + sizeof(cbPidl2) + cbPidl1 + cbPidl2;
    LPBYTE pbData = (LPBYTE)::LocalAlloc(LPTR, cbTotal);
    if (!pbData)
        return FALSE;

    LPBYTE pb = pbData;

    *(LONG*)pb = lEvent;
    pb += sizeof(lEvent);

    *(DWORD*)pb = cbPidl1;
    pb += sizeof(cbPidl1);

    *(DWORD*)pb = cbPidl2;
    pb += sizeof(cbPidl2);

    CopyMemory(pb, pidl1, cbPidl1);
    pb += cbPidl1;

    CopyMemory(pb, pidl2, cbPidl2);
    pb += cbPidl2;

    assert(INT(pb - pbData) == INT(cbTotal));

    COPYDATASTRUCT CopyData;
    CopyData.dwData = 0xBEEFCAFE;
    CopyData.cbData = cbTotal;
    CopyData.lpData = pbData;
    BOOL ret = (BOOL)::SendMessageW(s_hMainWnd, WM_COPYDATA, (WPARAM)s_hSubWnd, (LPARAM)&CopyData);

    ::LocalFree(pbData);
    return ret;
}

static void DoShellNotify(HWND hwnd, PIDLIST_ABSOLUTE pidl1, PIDLIST_ABSOLUTE pidl2, LONG lEvent)
{
    if (s_iStage < 0)
        return;

    DoSendData(lEvent, pidl1, pidl2);
}

static INT_PTR OnShellNotify(HWND hwnd, WPARAM wParam, LPARAM lParam)
{
    LONG lEvent;
    PIDLIST_ABSOLUTE *pidlAbsolute;
    HANDLE hLock = SHChangeNotification_Lock((HANDLE)wParam, (DWORD)lParam, &pidlAbsolute, &lEvent);
    if (hLock)
    {
        DoShellNotify(hwnd, pidlAbsolute[0], pidlAbsolute[1], lEvent);
        SHChangeNotification_Unlock(hLock);
    }
    else
    {
        pidlAbsolute = (PIDLIST_ABSOLUTE *)wParam;
        DoShellNotify(hwnd, pidlAbsolute[0], pidlAbsolute[1], lParam);
    }
    return TRUE;
}

static LRESULT OnCopyData(HWND hwnd, LPARAM lParam)
{
    COPYDATASTRUCT *cds = (COPYDATASTRUCT*)lParam;

    if (!cds || hwnd != 0 || cds->dwData != ID_SHSTATE)
        return 0;

    PSHELLSTATE_SUB sub = (PSHELLSTATE_SUB)cds->lpData;
    if (sub->bGetSet && sub->dwMask == SSF_NOCONFIRMRECYCLE)
    {
        SHGetSetSettings(&sub->ss, sub->dwMask, FALSE);
        // Flip the flag
        sub->ss.fNoConfirmRecycle = !sub->ss.fNoConfirmRecycle;
        SHGetSetSettings(&sub->ss, sub->dwMask, TRUE);
        // Flip back
        sub->ss.fNoConfirmRecycle = !sub->ss.fNoConfirmRecycle;
        SHGetSetSettings(&sub->ss, sub->dwMask, TRUE);
        return 1;
    }
    SHGetSetSettings(&sub->ss, sub->dwMask, sub->bSet);
    return 1;
}

static LRESULT CALLBACK SubWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
        case WM_CREATE:
            return (OnCreate(hwnd) ? 0 : -1);

        case WM_COMMAND:
            OnCommand(hwnd, LOWORD(wParam));
            break;

        case WM_SHELL_NOTIFY:
            return OnShellNotify(hwnd, wParam, lParam);

        case WM_COPYDATA:
            return OnCopyData((HWND)wParam, lParam);

        case WM_DESTROY:
            OnDestroy(hwnd);
            break;

        default:
            return ::DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

/* Take  /lnkmarker="<file>"  off the front of the command line */
static BOOL
GetLnkMarkerArgument(_Inout_ LPWSTR *ppszCmdLine, _Out_ PWSTR pszMarker, _In_ UINT cchMarker)
{
    const SIZE_T cchPrefix = _countof(LNK_MARKER_ARGUMENT) - 1;
    LPWSTR pszCmdLine = *ppszCmdLine;
    if (_wcsnicmp(pszCmdLine, LNK_MARKER_ARGUMENT, cchPrefix) != 0)
        return FALSE;
    PCWSTR pchEnd = wcschr(pszCmdLine + cchPrefix, L'"');
    if (!pchEnd || (SIZE_T)(pchEnd - (pszCmdLine + cchPrefix)) >= cchMarker)
        return FALSE;
    StringCchCopyNW(pszMarker, cchMarker, pszCmdLine + cchPrefix, pchEnd - (pszCmdLine + cchPrefix));
    pszCmdLine = (LPWSTR)pchEnd + 1;
    while (*pszCmdLine == L' ')
        ++pszCmdLine;
    *ppszCmdLine = pszCmdLine;
    return TRUE;
}

INT APIENTRY
wWinMain(
    HINSTANCE hInstance,
    HINSTANCE hPrevInstance,
    LPWSTR    lpCmdLine,
    INT       nCmdShow)
{
    WCHAR szMarker[MAX_PATH];
    if (GetEnvironmentVariableW(DRIVETOOLS_MARKER_VARIABLE, szMarker, _countof(szMarker)))
    {
        WCHAR szModule[MAX_PATH], szLine[MAX_PATH * 3];
        DWORD cbWritten;
        GetModuleFileNameW(NULL, szModule, _countof(szModule));
        StringCchPrintfW(szLine, _countof(szLine), L"%s|%s\n", PathFindFileNameW(szModule), lpCmdLine);
        HANDLE hFile = CreateFileW(szMarker, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                   OPEN_ALWAYS, 0, NULL);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            WriteFile(hFile, szLine, lstrlenW(szLine) * sizeof(WCHAR), &cbWritten, NULL);
            CloseHandle(hFile);
        }
        return 0;
    }

    if (GetLnkMarkerArgument(&lpCmdLine, szMarker, _countof(szMarker)) ||
        GetEnvironmentVariableW(LNK_MARKER_VARIABLE, szMarker, _countof(szMarker)))
    {
        WCHAR szDir[MAX_PATH], szVar[MAX_PATH], szLine[MAX_PATH * 4];
        DWORD cbWritten;
        if (!GetCurrentDirectoryW(_countof(szDir), szDir))
            szDir[0] = UNICODE_NULL;
        if (!GetEnvironmentVariableW(L"LNKTEST_VAR", szVar, _countof(szVar)))
            StringCchCopyW(szVar, _countof(szVar), L"(unset)");
        StringCchPrintfW(szLine, _countof(szLine), L"%s|%d|%s|%s\n", szDir, nCmdShow, lpCmdLine, szVar);
        HANDLE hFile = CreateFileW(szMarker, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                   OPEN_ALWAYS, 0, NULL);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            WriteFile(hFile, szLine, lstrlenW(szLine) * sizeof(WCHAR), &cbWritten, NULL);
            CloseHandle(hFile);
        }
        return 0;
    }

    if (lstrcmpiW(lpCmdLine, L"") == 0 || lstrcmpiW(lpCmdLine, L"TEST") == 0)
        return 0;

    WNDCLASSW wc = { 0, SubWindowProc };
    wc.hInstance = hInstance;
    wc.hIcon = LoadIconW(NULL, IDI_APPLICATION);
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_3DFACE + 1);
    wc.lpszClassName = SUB_CLASSNAME;
    if (!RegisterClassW(&wc))
    {
        assert(0);
        return -1;
    }

    HWND hwnd = CreateWindowW(SUB_CLASSNAME, SUB_CLASSNAME, WS_OVERLAPPEDWINDOW,
                              CW_USEDEFAULT, CW_USEDEFAULT, 400, 100,
                              NULL, NULL, hInstance, NULL);
    if (!hwnd)
    {
        assert(0);
        return -2;
    }

    ShowWindow(hwnd, SW_SHOWNORMAL);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return 0;
}
