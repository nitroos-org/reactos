/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     DLL custom action of the CustomActionDir test: reports its current directory
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <windows.h>
#include <msi.h>
#include <msiquery.h>
#include <stdio.h>

UINT WINAPI CheckDir(MSIHANDLE hInstall)
{
    WCHAR szDir[MAX_PATH], szCmd[] = L"/c exit 7", szResult[32];
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    DWORD dwExit = 0;

    GetCurrentDirectoryW(ARRAYSIZE(szDir), szDir);
    MsiSetPropertyW(hInstall, L"CA_CWD", szDir);

    /* The application name has no path: it is looked for in the current directory only */
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    if (CreateProcessW(L"cmd.exe", szCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        WaitForSingleObject(pi.hProcess, 30000);
        GetExitCodeProcess(pi.hProcess, &dwExit);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        swprintf(szResult, ARRAYSIZE(szResult), L"%lu", dwExit);
    }
    else
    {
        swprintf(szResult, ARRAYSIZE(szResult), L"error %lu", GetLastError());
    }
    MsiSetPropertyW(hInstall, L"CA_CMD", szResult);
    return ERROR_SUCCESS;
}
