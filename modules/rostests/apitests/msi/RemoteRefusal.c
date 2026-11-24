/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test that the RPC interface of an installation refuses a caller that is not one of its custom action servers
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * An installation serves IWineMsiRemote on the ncalrpc endpoint msi<pid> so that its custom action servers can reach
 * the package; everyone may open that endpoint's pipe, so the interface checks the caller: only a custom action
 * server that the installation started may call it.
 *
 * The test installs a package with a deferred DLL action that makes its own call to the installation (MsiGetProperty
 * on its package handle, which must work), reports the process id of the installation and waits. Meanwhile this
 * process, which is not a custom action server of that installation, binds to the endpoint and calls two methods
 * of the interface: both must be refused with RPC_S_ACCESS_DENIED. Nothing in the call reads or changes the
 * installation. Needs an elevated administrator and the Installer service (it installs a package); the interface
 * is ours, so there is nothing to compare on Windows.
 */

#define WIN32_NO_STATUS
#include <apitest.h>

#include <winnls.h>
#include <wtypes.h>
#include <msi.h>
#include <msidefs.h>
#include <msiquery.h>
#include <strsafe.h>
#include <rpc.h>
#include <rpcndr.h>

#include "winemsi_c.h"

void __RPC_FAR * __RPC_USER MIDL_user_allocate(SIZE_T len)
{
    return HeapAlloc(GetProcessHeap(), 0, len);
}

void __RPC_USER MIDL_user_free(void __RPC_FAR *ptr)
{
    HeapFree(GetProcessHeap(), 0, ptr);
}

static BOOL RunQuery(MSIHANDLE hDatabase, LPCWSTR pszQuery, MSIHANDLE hRecord)
{
    MSIHANDLE hView;
    UINT r;

    r = MsiDatabaseOpenViewW(hDatabase, pszQuery, &hView);
    if (r == ERROR_SUCCESS)
    {
        r = MsiViewExecute(hView, hRecord);
        MsiCloseHandle(hView);
    }
    ok(r == ERROR_SUCCESS, "%S failed: %u\n", pszQuery, r);
    return r == ERROR_SUCCESS;
}

static BOOL AddStream(MSIHANDLE hDatabase, LPCWSTR pszName, LPCWSTR pszFile)
{
    WCHAR szQuery[160];
    MSIHANDLE hRecord = MsiCreateRecord(1);
    UINT r = MsiRecordSetStreamW(hRecord, 1, pszFile);
    BOOL bOk;

    ok(r == ERROR_SUCCESS, "MsiRecordSetStreamW(%S) failed: %u\n", pszFile, r);
    StringCchPrintfW(szQuery, ARRAYSIZE(szQuery), L"INSERT INTO `Binary` (`Name`, `Data`) VALUES ('%s', ?)", pszName);
    bOk = (r == ERROR_SUCCESS) && RunQuery(hDatabase, szQuery, hRecord);
    MsiCloseHandle(hRecord);
    return bOk;
}

static BOOL CreatePackage(LPCWSTR pszPath, LPCWSTR pszDll, LPCWSTR pszStem)
{
    MSIHANDLE hDatabase, hSummary;
    WCHAR szQuery[400];
    UINT r;
    BOOL bOk;

    DeleteFileW(pszPath);
    r = MsiOpenDatabaseW(pszPath, (LPCWSTR)MSIDBOPEN_CREATE, &hDatabase);
    ok(r == ERROR_SUCCESS, "MsiOpenDatabaseW failed: %u\n", r);
    if (r != ERROR_SUCCESS)
        return FALSE;

    /* the property named like the deferred action is its CustomActionData: the stem of the two files */
    StringCchPrintfW(szQuery, ARRAYSIZE(szQuery),
                     L"INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`) VALUES ('SetWaitRef', 51, 'WaitRefDeferred', '%s')",
                     pszStem);
    bOk = RunQuery(hDatabase, L"CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` CHAR(0) NOT NULL PRIMARY KEY `Property`)", 0) &&
          RunQuery(hDatabase, L"INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductCode', '{9B2E4C71-5A3D-4F08-B6E1-0D7A8C3F5A24}')", 0) &&
          RunQuery(hDatabase, L"INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductName', 'Remote interface refusal test')", 0) &&
          RunQuery(hDatabase, L"INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductVersion', '1.0.0')", 0) &&
          RunQuery(hDatabase, L"INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductLanguage', '1033')", 0) &&
          RunQuery(hDatabase, L"INSERT INTO `Property` (`Property`, `Value`) VALUES ('Manufacturer', 'Test')", 0) &&
          RunQuery(hDatabase, L"CREATE TABLE `Binary` (`Name` CHAR(72) NOT NULL, `Data` OBJECT NOT NULL PRIMARY KEY `Name`)", 0) &&
          RunQuery(hDatabase, L"CREATE TABLE `CustomAction` (`Action` CHAR(72) NOT NULL, `Type` SHORT NOT NULL, `Source` CHAR(72), `Target` CHAR(255), `ExtendedType` LONG PRIMARY KEY `Action`)", 0) &&
          RunQuery(hDatabase, szQuery, 0) &&
          /* deferred (0x400) + DLL in the Binary table (1) */
          RunQuery(hDatabase, L"INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`) VALUES ('WaitRefDeferred', 1025, 'cadir', 'WaitForRefusal')", 0) &&
          RunQuery(hDatabase, L"CREATE TABLE `InstallExecuteSequence` (`Action` CHAR(72) NOT NULL, `Condition` CHAR(255), `Sequence` SHORT PRIMARY KEY `Action`)", 0) &&
          RunQuery(hDatabase, L"INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('SetWaitRef', 100)", 0) &&
          RunQuery(hDatabase, L"INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('InstallInitialize', 1500)", 0) &&
          RunQuery(hDatabase, L"INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('WaitRefDeferred', 1600)", 0) &&
          RunQuery(hDatabase, L"INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('InstallFinalize', 6600)", 0) &&
          AddStream(hDatabase, L"cadir", pszDll);
    if (!bOk)
    {
        MsiCloseHandle(hDatabase);
        return FALSE;
    }

    r = MsiGetSummaryInformationW(hDatabase, NULL, 5, &hSummary);
    ok(r == ERROR_SUCCESS, "MsiGetSummaryInformationW failed: %u\n", r);
    if (r == ERROR_SUCCESS)
    {
        MsiSummaryInfoSetPropertyW(hSummary, PID_TEMPLATE, VT_LPSTR, 0, NULL, L"Intel;1033");
        MsiSummaryInfoSetPropertyW(hSummary, PID_REVNUMBER, VT_LPSTR, 0, NULL, L"{4C8E1A52-7D39-4B60-A2F5-3E91B0D6C847}");
        MsiSummaryInfoSetPropertyW(hSummary, PID_PAGECOUNT, VT_I4, 200, NULL, NULL);
        MsiSummaryInfoSetPropertyW(hSummary, PID_WORDCOUNT, VT_I4, 0, NULL, NULL);
        r = MsiSummaryInfoPersist(hSummary);
        ok(r == ERROR_SUCCESS, "MsiSummaryInfoPersist failed: %u\n", r);
        MsiCloseHandle(hSummary);
    }
    if (r == ERROR_SUCCESS)
    {
        r = MsiDatabaseCommit(hDatabase);
        ok(r == ERROR_SUCCESS, "MsiDatabaseCommit failed: %u\n", r);
    }
    MsiCloseHandle(hDatabase);
    return r == ERROR_SUCCESS;
}

static BOOL IsElevatedAdministrator(void)
{
    HANDLE hToken;
    TOKEN_ELEVATION Elevation;
    DWORD cb;
    BOOL bOk = FALSE;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cb))
            bOk = Elevation.TokenIsElevated;
        CloseHandle(hToken);
    }
    return bOk;
}

static UINT g_InstallResult = (UINT)-1;
static WCHAR g_szPackage[MAX_PATH];

static DWORD WINAPI InstallThread(PVOID pParam)
{
    MsiSetInternalUI(INSTALLUILEVEL_NONE, NULL);
    g_InstallResult = MsiInstallProductW(g_szPackage, L"");
    return 0;
}

/* The status the call fails with; ERROR_SUCCESS when it was not refused */
typedef enum { CALL_PROPERTY, CALL_ACTION } CALL_KIND;

static ULONG CallInterface(CALL_KIND Kind)
{
    ULONG Code = ERROR_SUCCESS;
    LPWSTR pszValue = NULL;
    DWORD cchValue = 0;

    RpcTryExcept
    {
        if (Kind == CALL_PROPERTY)
            remote_GetProperty(1, L"ProductCode", &pszValue, &cchValue);
        else
            remote_DoAction(1, L"WaitRefDeferred");
    }
    RpcExcept(1)
    {
        Code = RpcExceptionCode();
    }
    RpcEndExcept;
    if (pszValue)
        midl_user_free(pszValue);
    return Code;
}

static BOOL ReadReady(LPCWSTR pszFile, ULONG *pPid, UINT *pResult)
{
    WCHAR szText[64];
    DWORD cb = 0;
    HANDLE hFile = CreateFileW(pszFile, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;
    ZeroMemory(szText, sizeof(szText));
    ReadFile(hFile, szText, sizeof(szText) - sizeof(WCHAR), &cb, NULL);
    CloseHandle(hFile);
    if (cb < 4)
        return FALSE;
    *pPid = wcstoul(szText, NULL, 10);
    *pResult = (UINT)wcstoul(wcschr(szText, L' ') ? wcschr(szText, L' ') + 1 : L"0", NULL, 10);
    return TRUE;
}

START_TEST(RemoteRefusal)
{
    WCHAR szExe[MAX_PATH], szDll[MAX_PATH], szTemp[MAX_PATH], szStem[MAX_PATH], szReady[MAX_PATH + 8], szDone[MAX_PATH + 8];
    WCHAR szEndpoint[16];
    RPC_WSTR pszBinding = NULL;
    SC_HANDLE hScm, hService;
    HANDLE hThread, hFile;
    ULONG Pid = 0, Code;
    UINT ActionResult = (UINT)-1;
    RPC_STATUS Status;
    PWSTR pSlash;
    DWORD i;

    if (!IsElevatedAdministrator())
    {
        skip("not an elevated administrator\n");
        return;
    }
    hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    hService = hScm ? OpenServiceW(hScm, L"MSIServer", SERVICE_QUERY_STATUS) : NULL;
    if (hService)
        CloseServiceHandle(hService);
    if (hScm)
        CloseServiceHandle(hScm);
    if (!hService)
    {
        skip("no Installer service\n");
        return;
    }

    GetModuleFileNameW(NULL, szExe, ARRAYSIZE(szExe));
    pSlash = wcsrchr(szExe, L'\\');
    if (pSlash)
        pSlash[1] = UNICODE_NULL;
    StringCchPrintfW(szDll, ARRAYSIZE(szDll), L"%smsi_cadir.dll", szExe);
    if (GetFileAttributesW(szDll) == INVALID_FILE_ATTRIBUTES)
    {
        skip("%S not found\n", szDll);
        return;
    }

    GetTempPathW(ARRAYSIZE(szTemp), szTemp);
    StringCchPrintfW(g_szPackage, ARRAYSIZE(g_szPackage), L"%smsi_refuse.msi", szTemp);
    StringCchPrintfW(szStem, ARRAYSIZE(szStem), L"%smsi_refuse", szTemp);
    StringCchPrintfW(szReady, ARRAYSIZE(szReady), L"%s.ready", szStem);
    StringCchPrintfW(szDone, ARRAYSIZE(szDone), L"%s.done", szStem);
    DeleteFileW(szReady);
    DeleteFileW(szDone);
    if (!CreatePackage(g_szPackage, szDll, szStem))
    {
        skip("Could not create the package\n");
        return;
    }

    hThread = CreateThread(NULL, 0, InstallThread, NULL, 0, NULL);
    ok(hThread != NULL, "CreateThread failed: %lu\n", GetLastError());
    if (!hThread)
        return;

    /* the action is up when it has made its own call and written the file */
    for (i = 0; i < 600; i++)
    {
        if (ReadReady(szReady, &Pid, &ActionResult))
            break;
        Sleep(100);
    }
    ok(Pid != 0, "the custom action did not report (its own call to the installation failed, or the installation did not start)\n");
    if (Pid != 0)
        ok(ActionResult == ERROR_SUCCESS, "the action's own MsiGetProperty returned %u\n", ActionResult);

    if (Pid != 0)
    {
        StringCchPrintfW(szEndpoint, ARRAYSIZE(szEndpoint), L"msi%x", Pid);
        Status = RpcStringBindingComposeW(NULL, (RPC_WSTR)L"ncalrpc", NULL, (RPC_WSTR)szEndpoint, NULL, &pszBinding);
        ok(Status == RPC_S_OK, "RpcStringBindingCompose failed: %lu\n", (ULONG)Status);
        if (Status == RPC_S_OK)
        {
            Status = RpcBindingFromStringBindingW(pszBinding, &rpc_handle);
            RpcStringFreeW(&pszBinding);
            ok(Status == RPC_S_OK, "RpcBindingFromStringBinding failed: %lu\n", (ULONG)Status);
        }
        if (Status == RPC_S_OK)
        {
            Code = CallInterface(CALL_PROPERTY);
            ok(Code == RPC_S_ACCESS_DENIED, "remote_GetProperty by a process that is not a custom action server: %lu, expected %u\n",
               Code, RPC_S_ACCESS_DENIED);
            Code = CallInterface(CALL_ACTION);
            ok(Code == RPC_S_ACCESS_DENIED, "remote_DoAction by a process that is not a custom action server: %lu, expected %u\n",
               Code, RPC_S_ACCESS_DENIED);
            RpcBindingFree(&rpc_handle);
        }
    }

    /* let the action go on, whatever happened above */
    hFile = CreateFileW(szDone, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);
    ok(WaitForSingleObject(hThread, 60000) == WAIT_OBJECT_0, "the installation did not finish\n");
    CloseHandle(hThread);
    ok(g_InstallResult == ERROR_SUCCESS, "MsiInstallProductW returned %u\n", g_InstallResult);

    DeleteFileW(szReady);
    DeleteFileW(szDone);
    DeleteFileW(g_szPackage);
}
