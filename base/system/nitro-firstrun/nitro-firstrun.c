/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Installs the features an unattended setup could not install while it ran (no network yet),
 *              at the first start of the new system, as SYSTEM, whoever logs on (or nobody does).
 *
 *   nitro-firstrun /service   LocalSystem service. Only an unattended setup that has features left over creates it
 *                             (a normal installation has no such service). It reads the list of feature names from
 *                             <windir>\Panther\firstrun.lst (one name per line, written by setup) and runs
 *                             "featmgr /enable <name>" for each, trying again every 30 seconds for up to 20 minutes
 *                             in all while the network comes up. When it is done, or has given up, or finds
 *                             nothing to do, or does not trust the list, it deletes the list and the service
 *                             itself: it does not start again at the next boot.
 *                             The result of each is appended to <windir>\Panther\unattend.log and the output of
 *                             the feature manager is in <windir>\Panther\feature-<name>.log.
 *
 *   What it trusts: only that file. The folder <windir>\Panther is given to SYSTEM and the Administrators alone
 *   (everybody else may read) by setup; on a volume that keeps access control lists the service checks that the
 *   file and its folder still are that way and does nothing otherwise. The registry is not read: while the
 *   registry access control is only audited, any user could write there. A name is a catalog name (letters,
 *   digits, '-', '_', '.') and never reaches a shell: featmgr.exe is started directly, by its full path.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */

#include <stdio.h>
#include <string.h>
#include <wchar.h>
#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <winnls.h>
#include <winsvc.h>
#include <winnt.h>
#include <stdarg.h>

#define SERVICE_NAME    L"NitroFirstRun"
#define LIST_NAME       L"firstrun.lst"
#define MAX_NAMES       16
#define MAX_NAME_CHARS  64
#define RETRY_MS        30000
#define TOTAL_MS        (20 * 60 * 1000)    /* all tries together */
#define RUN_MS          (10 * 60 * 1000)    /* one featmgr run */

static SERVICE_STATUS_HANDLE g_hStatus;
static SERVICE_STATUS g_Status;
static HANDLE g_hStop;

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

/* ACCESS CHECK OF THE LIST *************************************************/

#define WRITE_RIGHTS (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | \
                      FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL)

/* TRUE when only SYSTEM and the Administrators can change the file or folder (or when nobody else is allowed
 * anything that changes it). A volume without access control lists has no way to say so: see IsListTrusted. */
static BOOL
OnlyAdminsCanWrite(PCWSTR pszPath)
{
    SID_IDENTIFIER_AUTHORITY nt = { SECURITY_NT_AUTHORITY };
    PSID pSystem = NULL, pAdmins = NULL;
    PSECURITY_DESCRIPTOR pSd = NULL;
    PACL pAcl = NULL;
    DWORD cb = 0, i;
    BOOL bPresent = FALSE, bDefaulted = FALSE, bOk = FALSE;

    GetFileSecurityW(pszPath, DACL_SECURITY_INFORMATION, NULL, 0, &cb);
    if (!cb)
        return FALSE;
    pSd = HeapAlloc(GetProcessHeap(), 0, cb);
    if (!pSd)
        return FALSE;
    if (!GetFileSecurityW(pszPath, DACL_SECURITY_INFORMATION, pSd, cb, &cb) ||
        !GetSecurityDescriptorDacl(pSd, &bPresent, &pAcl, &bDefaulted) ||
        !bPresent || !pAcl)
    {
        /* no DACL at all means everybody can do everything */
        HeapFree(GetProcessHeap(), 0, pSd);
        return FALSE;
    }
    if (!AllocateAndInitializeSid(&nt, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &pSystem) ||
        !AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                  &pAdmins))
        goto done;

    bOk = TRUE;
    for (i = 0; i < pAcl->AceCount; i++)
    {
        PACE_HEADER pAce;
        PACCESS_ALLOWED_ACE pAllowed;

        if (!GetAce(pAcl, i, (PVOID *)&pAce))
        {
            bOk = FALSE;
            break;
        }
        if (pAce->AceFlags & INHERIT_ONLY_ACE)
            continue;
        if (pAce->AceType == ACCESS_DENIED_ACE_TYPE)
            continue;
        if (pAce->AceType != ACCESS_ALLOWED_ACE_TYPE)
        {
            /* callback and object ACEs: not what setup writes, not understood here */
            if (pAce->AceType == ACCESS_ALLOWED_COMPOUND_ACE_TYPE ||
                pAce->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE ||
                pAce->AceType == ACCESS_ALLOWED_CALLBACK_ACE_TYPE ||
                pAce->AceType == ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE)
                bOk = FALSE;
            continue;
        }
        pAllowed = (PACCESS_ALLOWED_ACE)pAce;
        if ((pAllowed->Mask & WRITE_RIGHTS) &&
            !EqualSid((PSID)&pAllowed->SidStart, pSystem) &&
            !EqualSid((PSID)&pAllowed->SidStart, pAdmins))
        {
            bOk = FALSE;
            break;
        }
    }

done:
    if (pSystem)
        FreeSid(pSystem);
    if (pAdmins)
        FreeSid(pAdmins);
    HeapFree(GetProcessHeap(), 0, pSd);
    return bOk;
}

static BOOL
IsListTrusted(PCWSTR pszDir, PCWSTR pszFile)
{
    WCHAR szRoot[MAX_PATH];
    DWORD dwFlags = 0;

    if (!GetWindowsDirectoryW(szRoot, MAX_PATH) || szRoot[1] != L':')
        return FALSE;
    szRoot[3] = 0;
    szRoot[2] = L'\\';
    if (!GetVolumeInformationW(szRoot, NULL, 0, NULL, NULL, &dwFlags, NULL, 0))
        return FALSE;
    if (!(dwFlags & FILE_PERSISTENT_ACLS))
    {
        /* FAT: no file has an owner or a list of who may write it; every user can change every system file */
        LogLine(L"the volume keeps no access control lists: the list of features is taken as it is");
        return TRUE;
    }
    return OnlyAdminsCanWrite(pszDir) && OnlyAdminsCanWrite(pszFile);
}

/* THE LIST *****************************************************************/

/* A catalog name: 1..64 of letters, digits, '-', '_', '.'; it starts with a letter or digit; no two dots in a row */
static BOOL
IsFeatureName(PCWSTR psz, size_t len)
{
    size_t i;

    if (!len || len > MAX_NAME_CHARS)
        return FALSE;
    for (i = 0; i < len; i++)
    {
        WCHAR c = psz[i];
        BOOL bAlnum = (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') || (c >= L'0' && c <= L'9');

        if (!bAlnum && (i == 0 || (c != L'-' && c != L'_' && c != L'.')))
            return FALSE;
        if (c == L'.' && i + 1 < len && psz[i + 1] == L'.')
            return FALSE;
    }
    return TRUE;
}

/* Reads <windir>\Panther\firstrun.lst into names[] (each MAX_NAME_CHARS + 1 wide characters).
 * Returns the number of names, 0 for none (also for a file that is not trusted: *pbTrusted FALSE). */
static UINT
ReadList(PCWSTR pszFile, PCWSTR pszDir, WCHAR names[MAX_NAMES][MAX_NAME_CHARS + 1], PBOOL pbExists, PBOOL pbTrusted)
{
    HANDLE hFile;
    CHAR szBuf[2048];
    DWORD cb = 0, i;
    UINT n = 0;
    size_t len = 0;
    WCHAR szName[MAX_NAME_CHARS + 2];
    BOOL bTooLong = FALSE;

    *pbExists = FALSE;
    *pbTrusted = TRUE;
    hFile = CreateFileW(pszFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return 0;
    *pbExists = TRUE;
    if (!IsListTrusted(pszDir, pszFile))
    {
        CloseHandle(hFile);
        *pbTrusted = FALSE;
        return 0;
    }
    if (!ReadFile(hFile, szBuf, sizeof(szBuf) - 1, &cb, NULL))
        cb = 0;
    CloseHandle(hFile);
    szBuf[cb] = 0;

    for (i = 0; i <= cb; i++)
    {
        CHAR c = szBuf[i];

        if (c == '\r' || c == '\n' || c == 0)
        {
            if (len)
            {
                szName[len] = 0;
                if (!bTooLong && IsFeatureName(szName, len) && n < MAX_NAMES)
                    wcscpy(names[n++], szName);
                else
                    LogLine(L"an entry of the list is not a feature name: skipped");
            }
            len = 0;
            bTooLong = FALSE;
        }
        else if (len < MAX_NAME_CHARS + 1)
        {
            szName[len++] = (WCHAR)(UCHAR)c;
        }
        else
        {
            bTooLong = TRUE;
        }
    }
    return n;
}

/* RUNNING featmgr **********************************************************/

/* One try: "<windir>\system32\featmgr.exe" /enable <name>, started directly (no shell), its output into
 * Panther\feature-<name>.log. Returns the exit code of featmgr, or 0xFFFF when it could not be run or did
 * not end in 10 minutes. */
static DWORD
TryFeature(PCWSTR pszName)
{
    WCHAR szWin[MAX_PATH], szExe[MAX_PATH], szLog[MAX_PATH], szSys[MAX_PATH], szCmd[MAX_PATH + 100];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    SECURITY_ATTRIBUTES sa;
    HANDLE hLog;
    DWORD dwExit = 0xFFFF, dwWait;

    if (!GetWindowsDirectoryW(szWin, MAX_PATH - 64))
        return dwExit;
    _snwprintf(szSys, MAX_PATH - 1, L"%s\\system32", szWin);
    _snwprintf(szExe, MAX_PATH - 1, L"%s\\featmgr.exe", szSys);
    _snwprintf(szLog, MAX_PATH - 1, L"%s\\Panther\\feature-%s.log", szWin, pszName);
    _snwprintf(szCmd, sizeof(szCmd) / sizeof(WCHAR) - 1, L"\"%s\" /enable %s", szExe, pszName);
    szSys[MAX_PATH - 1] = szExe[MAX_PATH - 1] = szLog[MAX_PATH - 1] = 0;
    szCmd[sizeof(szCmd) / sizeof(WCHAR) - 1] = 0;

    ZeroMemory(&sa, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    hLog = CreateFileW(szLog, GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    if (hLog != INVALID_HANDLE_VALUE)
    {
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = INVALID_HANDLE_VALUE;
        si.hStdOutput = hLog;
        si.hStdError = hLog;
    }
    if (CreateProcessW(szExe, szCmd, NULL, NULL, hLog != INVALID_HANDLE_VALUE, CREATE_NO_WINDOW, NULL, szSys, &si, &pi))
    {
        dwWait = WaitForSingleObject(pi.hProcess, RUN_MS);
        if (dwWait == WAIT_OBJECT_0)
        {
            GetExitCodeProcess(pi.hProcess, &dwExit);
        }
        else
        {
            TerminateProcess(pi.hProcess, 1);
            LogLine(L"featmgr did not end in 10 minutes for \"%s\": stopped", pszName);
        }
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    if (hLog != INVALID_HANDLE_VALUE)
        CloseHandle(hLog);
    return dwExit;
}

/* TRUE when the output of featmgr says the feature is not in the catalog: a try later gives the same answer */
static BOOL
LogSaysUnknownFeature(PCWSTR pszName)
{
    WCHAR szPath[MAX_PATH];
    CHAR szBuf[2048];
    HANDLE hFile;
    DWORD cb = 0;

    if (!GetWindowsDirectoryW(szPath, MAX_PATH - 64))
        return FALSE;
    _snwprintf(szPath + wcslen(szPath), MAX_PATH - wcslen(szPath) - 1, L"\\Panther\\feature-%s.log", pszName);
    szPath[MAX_PATH - 1] = 0;
    hFile = CreateFileW(szPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;
    if (!ReadFile(hFile, szBuf, sizeof(szBuf) - 1, &cb, NULL))
        cb = 0;
    CloseHandle(hFile);
    szBuf[cb] = 0;
    return strstr(szBuf, "unknown feature") != NULL;
}

/* Deletes this service (it is removed when it stops): nothing starts at the next boot */
static VOID
DeleteSelf(VOID)
{
    SC_HANDLE hScm, hSvc;

    hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hScm)
        return;
    hSvc = OpenServiceW(hScm, SERVICE_NAME, DELETE);
    if (hSvc)
    {
        DeleteService(hSvc);
        CloseServiceHandle(hSvc);
    }
    CloseServiceHandle(hScm);
}

static VOID
RunPending(BOOL bAsService)
{
    WCHAR szWin[MAX_PATH], szDir[MAX_PATH], szFile[MAX_PATH];
    WCHAR names[MAX_NAMES][MAX_NAME_CHARS + 1];
    BOOL bDone[MAX_NAMES] = { FALSE };
    BOOL bExists, bTrusted;
    UINT n, i, nLeft;
    DWORD dwStart = GetTickCount(), dwPass = 0;

    if (GetWindowsDirectoryW(szWin, MAX_PATH - 32))
    {
        _snwprintf(szDir, MAX_PATH - 1, L"%s\\Panther", szWin);
        _snwprintf(szFile, MAX_PATH - 1, L"%s\\Panther\\" LIST_NAME, szWin);
        szDir[MAX_PATH - 1] = szFile[MAX_PATH - 1] = 0;
        n = ReadList(szFile, szDir, names, &bExists, &bTrusted);
        if (!bTrusted)
            LogLine(L"%s can be changed by users: not used", szFile);
        else if (n)
        {
            nLeft = n;
            while (nLeft)
            {
                for (i = 0; i < n; i++)
                {
                    DWORD rc;

                    if (bDone[i])
                        continue;
                    if (!dwPass)
                        LogLine(L"installing feature \"%s\" at the first start", names[i]);
                    rc = TryFeature(names[i]);
                    if (rc == 0)
                    {
                        LogLine(L"feature \"%s\" installed (try %lu)", names[i], dwPass + 1);
                        bDone[i] = TRUE;
                        nLeft--;
                    }
                    else if (LogSaysUnknownFeature(names[i]))
                    {
                        /* featmgr: no such feature; waiting does not help */
                        LogLine(L"feature \"%s\" is not in the catalog: see Panther\\feature-%s.log", names[i], names[i]);
                        bDone[i] = TRUE;
                        nLeft--;
                    }
                }
                dwPass++;
                if (!nLeft)
                    break;
                if (GetTickCount() - dwStart + RETRY_MS > TOTAL_MS)
                {
                    for (i = 0; i < n; i++)
                    {
                        if (!bDone[i])
                            LogLine(L"feature \"%s\" could not be installed in 20 minutes: see Panther\\feature-%s.log;"
                                    L" run \"featmgr /enable %s\" when the network is up", names[i], names[i], names[i]);
                    }
                    break;
                }
                if (g_hStop && WaitForSingleObject(g_hStop, RETRY_MS) == WAIT_OBJECT_0)
                {
                    LogLine(L"stopped before all the features were installed");
                    break;
                }
                if (!g_hStop)
                    Sleep(RETRY_MS);
            }
        }
        else if (bExists)
            LogLine(L"the list of features is empty: nothing to do");

        /* done, given up or not trusted: the list goes, and with it the reason to start again */
        if (bExists)
            DeleteFileW(szFile);
    }
    if (bAsService)
        DeleteSelf();
}

/* SERVICE ******************************************************************/

static VOID
WINAPI
ServiceHandler(DWORD dwControl)
{
    if (dwControl == SERVICE_CONTROL_STOP || dwControl == SERVICE_CONTROL_SHUTDOWN)
    {
        g_Status.dwCurrentState = SERVICE_STOP_PENDING;
        g_Status.dwControlsAccepted = 0;
        if (g_hStop)
            SetEvent(g_hStop);
    }
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
    g_Status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_hStop = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_hStatus = RegisterServiceCtrlHandlerW(SERVICE_NAME, ServiceHandler);
    if (!g_hStatus)
        return;
    SetServiceStatus(g_hStatus, &g_Status);

    /* Reported as running first: the boot does not wait for the downloads */
    RunPending(TRUE);

    g_Status.dwCurrentState = SERVICE_STOPPED;
    g_Status.dwControlsAccepted = 0;
    SetServiceStatus(g_hStatus, &g_Status);
}

int
wmain(int argc, WCHAR **argv)
{
    SERVICE_TABLE_ENTRYW Table[] = { { SERVICE_NAME, ServiceMain }, { NULL, NULL } };

    if (argc > 1 && !_wcsicmp(argv[1], L"/service"))
        return StartServiceCtrlDispatcherW(Table) ? 0 : 1;

    RunPending(FALSE);
    return 0;
}
