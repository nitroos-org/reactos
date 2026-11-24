/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     DLL custom action of the CustomActionDir test: reports its current directory
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <windows.h>
#include <sddl.h>
#include <msi.h>
#include <msiquery.h>
#include <stdio.h>

/*
 * Deferred custom action of the NoImpersonateAction test: writes the SID of the user of its process token to the file
 * named by CustomActionData ("S-1-5-18" when the action runs as LocalSystem).
 */
UINT WINAPI ReportIdentity(MSIHANDLE hInstall)
{
    WCHAR szFile[MAX_PATH], szSid[128];
    DWORD cch = ARRAYSIZE(szFile), cb, cbWritten;
    BYTE buf[256];
    HANDLE hToken, hFile;
    LPWSTR pszSid = NULL;

    szFile[0] = UNICODE_NULL;
    MsiGetPropertyW(hInstall, L"CustomActionData", szFile, &cch);
    szSid[0] = UNICODE_NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        if (GetTokenInformation(hToken, TokenUser, buf, sizeof(buf), &cb) &&
            ConvertSidToStringSidW(((PTOKEN_USER)buf)->User.Sid, &pszSid))
        {
            lstrcpynW(szSid, pszSid, ARRAYSIZE(szSid));
            LocalFree(pszSid);
        }
        CloseHandle(hToken);
    }
    hFile = CreateFileW(szFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return ERROR_INSTALL_FAILURE;
    WriteFile(hFile, szSid, lstrlenW(szSid) * sizeof(WCHAR), &cbWritten, NULL);
    CloseHandle(hFile);
    return ERROR_SUCCESS;
}

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

/*
 * Deferred custom action of the RemoteRefusal test. Its own call to the installation (MsiGetProperty on its package
 * handle goes through the installation's RPC interface) must work: it reads CustomActionData, the path stem of two
 * files. It writes "<installer process id> <result>" to <stem>.ready and waits for <stem>.done, so that the test
 * can call the interface from another process meanwhile. The installer process id is what its custom action server
 * got on its command line ("-Embedding <pid>").
 */
UINT WINAPI WaitForRefusal(MSIHANDLE hInstall)
{
    WCHAR szStem[MAX_PATH], szReady[MAX_PATH + 8], szDone[MAX_PATH + 8], szText[64];
    DWORD cch = ARRAYSIZE(szStem), cbWritten, i;
    PCWSTR pszCmd;
    HANDLE hFile;
    UINT r;

    szStem[0] = UNICODE_NULL;
    r = MsiGetPropertyW(hInstall, L"CustomActionData", szStem, &cch);
    if (r != ERROR_SUCCESS || !szStem[0])
        return ERROR_INSTALL_FAILURE;

    pszCmd = wcsstr(GetCommandLineW(), L"-Embedding ");
    swprintf(szText, ARRAYSIZE(szText), L"%lu %u", pszCmd ? wcstoul(pszCmd + 11, NULL, 10) : 0, r);
    swprintf(szReady, ARRAYSIZE(szReady), L"%s.ready", szStem);
    swprintf(szDone, ARRAYSIZE(szDone), L"%s.done", szStem);
    hFile = CreateFileW(szReady, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return ERROR_INSTALL_FAILURE;
    WriteFile(hFile, szText, lstrlenW(szText) * sizeof(WCHAR), &cbWritten, NULL);
    CloseHandle(hFile);

    for (i = 0; i < 600 && GetFileAttributesW(szDone) == INVALID_FILE_ATTRIBUTES; i++)
        Sleep(100);
    return ERROR_SUCCESS;
}
