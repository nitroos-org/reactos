/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Installs the features an unattended setup could not install while it ran (no network yet),
 *              at the first start of the new system, as SYSTEM, whoever logs on (or nobody does).
 *
 *   nitro-firstrun /service   auto-start LocalSystem service. It reads HKLM\SOFTWARE\ReactOS\Nitro\Unattend
 *                             value PendingFeatures (feature names separated by blanks, written by setup from
 *                             [Features] Install of unattend.inf), and runs "featmgr /enable <name>" for each,
 *                             trying again every 30 seconds for up to 20 minutes while the network comes up.
 *                             The result of each is appended to <windir>\Panther\unattend.log and the output of
 *                             the feature manager is in <windir>\Panther\feature-<name>.log. When the list is
 *                             done the value is deleted and the service has nothing to do at later starts.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */

#include <stdio.h>
#include <wchar.h>
#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <winnls.h>
#include <winsvc.h>
#include <stdarg.h>

#define KEY_NAME   L"SOFTWARE\\ReactOS\\Nitro\\Unattend"
#define VAL_NAME   L"PendingFeatures"
#define MAX_TRIES  40
#define RETRY_MS   30000

static SERVICE_STATUS_HANDLE g_hStatus;
static SERVICE_STATUS g_Status;

static VOID
LogLine(PCWSTR pszFormat, ...)
{
    WCHAR szText[400], szLine[480], szPath[MAX_PATH];
    CHAR szUtf8[1500];
    SYSTEMTIME st;
    va_list args;
    HANDLE hFile;
    DWORD cbWritten;
    int n;

    va_start(args, pszFormat);
    _vsnwprintf(szText, sizeof(szText) / sizeof(WCHAR) - 1, pszFormat, args);
    va_end(args);
    szText[sizeof(szText) / sizeof(WCHAR) - 1] = 0;
    GetSystemTime(&st);
    _snwprintf(szLine, sizeof(szLine) / sizeof(WCHAR) - 1, L"%04u-%02u-%02uT%02u:%02u:%02uZ firstrun: %s\r\n",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, szText);
    szLine[sizeof(szLine) / sizeof(WCHAR) - 1] = 0;
    if (!GetWindowsDirectoryW(szPath, MAX_PATH - 32))
        return;
    wcscat(szPath, L"\\Panther");
    CreateDirectoryW(szPath, NULL);
    wcscat(szPath, L"\\unattend.log");
    n = WideCharToMultiByte(CP_UTF8, 0, szLine, -1, szUtf8, sizeof(szUtf8), NULL, NULL);
    if (n <= 1)
        return;
    hFile = CreateFileW(szPath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return;
    SetFilePointer(hFile, 0, NULL, FILE_END);
    WriteFile(hFile, szUtf8, n - 1, &cbWritten, NULL);
    CloseHandle(hFile);
}

/* One try: featmgr /enable <name>, its output into Panther\feature-<name>.log; TRUE when it exits with 0 */
static BOOL
TryFeature(PCWSTR pszName)
{
    WCHAR szWin[MAX_PATH], szCmd[MAX_PATH + 200];
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    DWORD dwExit = 1;

    if (!GetWindowsDirectoryW(szWin, MAX_PATH))
        return FALSE;
    _snwprintf(szCmd, sizeof(szCmd) / sizeof(WCHAR) - 1,
               L"cmd.exe /c featmgr.exe /enable %s > \"%s\\Panther\\feature-%s.log\" 2>&1", pszName, szWin, pszName);
    szCmd[sizeof(szCmd) / sizeof(WCHAR) - 1] = 0;
    if (!CreateProcessW(NULL, szCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return FALSE;
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &dwExit);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return dwExit == 0;
}

static VOID
RunPending(VOID)
{
    HKEY hKey;
    WCHAR szList[512], *p, *tok;
    DWORD cb = sizeof(szList) - sizeof(WCHAR), type;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, KEY_NAME, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
        return;
    ZeroMemory(szList, sizeof(szList));
    if (RegQueryValueExW(hKey, VAL_NAME, NULL, &type, (LPBYTE)szList, &cb) != ERROR_SUCCESS || type != REG_SZ)
    {
        RegCloseKey(hKey);
        return;
    }
    p = szList;
    while (*p)
    {
        int nTry;
        BOOL bDone = FALSE;

        while (*p == L' ')
            p++;
        tok = p;
        while (*p && *p != L' ')
            p++;
        if (*p)
            *p++ = 0;
        if (!*tok)
            continue;
        LogLine(L"installing feature \"%s\" at the first start", tok);
        for (nTry = 1; nTry <= MAX_TRIES; nTry++)
        {
            if (TryFeature(tok))
            {
                bDone = TRUE;
                break;
            }
            Sleep(RETRY_MS);
        }
        if (bDone)
            LogLine(L"feature \"%s\" installed (try %d)", tok, nTry);
        else
            LogLine(L"feature \"%s\" could not be installed after %d tries: see Panther\\feature-%s.log", tok, MAX_TRIES, tok);
    }
    RegDeleteValueW(hKey, VAL_NAME);
    RegCloseKey(hKey);
}

static VOID
WINAPI
ServiceHandler(DWORD dwControl)
{
    UNREFERENCED_PARAMETER(dwControl);
    SetServiceStatus(g_hStatus, &g_Status);
}

static VOID
WINAPI
ServiceMain(DWORD argc, LPWSTR *argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    g_Status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_Status.dwCurrentState = SERVICE_RUNNING;
    g_hStatus = RegisterServiceCtrlHandlerW(L"NitroFirstRun", ServiceHandler);
    if (!g_hStatus)
        return;
    SetServiceStatus(g_hStatus, &g_Status);

    /* Reported as running first: the boot does not wait for the downloads */
    RunPending();

    g_Status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_hStatus, &g_Status);
}

int
wmain(int argc, WCHAR **argv)
{
    SERVICE_TABLE_ENTRYW Table[] = { { L"NitroFirstRun", ServiceMain }, { NULL, NULL } };

    if (argc > 1 && !_wcsicmp(argv[1], L"/service"))
        return StartServiceCtrlDispatcherW(Table) ? 0 : 1;

    RunPending();
    return 0;
}
