/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The Installer service's launch pipe (sdk/include/reactos/msilaunch.h): who it serves, what it
 *              starts, and the pipes of the custom action servers
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * The Installer service (msiexec /V, LocalSystem) starts the program of a deferred "no impersonation" custom action,
 * or a custom action server, for an elevated administrator. Every case here is a refusal or a property of the
 * process it starts; the programs asked for are harmless (this test itself in a reporting mode, cmd.exe /c exit).
 *  - the pipe is served by the service's process;
 *  - an elevated administrator's request starts the program as LocalSystem, in the system directory, with
 *    LocalSystem's environment, and standard handles that are none or its own console's; the handle in the reply is
 *    that process's;
 *  - refused: a token whose Administrators group is deny-only, a restricted token, Medium and Low integrity, an
 *    AppContainer token, a process that sends a request on a pipe handle opened by another process;
 *  - refused requests: an application without a full path, a path with "..", a missing terminator, strings that do
 *    not fill the message, a custom action server request with strings;
 *  - a client that connects and never writes holds the next client up for about 10 s, not for ever;
 *  - with the launch pipe's name taken by another program, the service stops with an error and an installation with
 *    a no-impersonation action fails without writing to that pipe; the same for a taken custom action server pipe.
 * Needs an elevated administrator and the Installer service. Not run on the Windows reference (the pipe is ours).
 */

#include <apitest.h>

#include <winnls.h>
#include <wtypes.h>
#include <sddl.h>
#include <msi.h>
#include <msidefs.h>
#include <msiquery.h>
#include <strsafe.h>
#include <reactos/msilaunch.h>

typedef LONG (NTAPI *PFN_NtCreateLowBoxToken)(PHANDLE, HANDLE, ACCESS_MASK, PVOID, PSID, ULONG, PVOID, ULONG, HANDLE *);

static WCHAR g_szExe[MAX_PATH], g_szSysDir[MAX_PATH], g_szCmd[MAX_PATH];

/* ---- the service ---- */

static DWORD ServiceState(DWORD *pdwPid, DWORD *pdwExit)
{
    SC_HANDLE hScm, hService;
    SERVICE_STATUS_PROCESS Status;
    DWORD cb, dwState = 0;

    *pdwPid = 0;
    if (pdwExit) *pdwExit = 0;
    hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    hService = hScm ? OpenServiceW(hScm, L"MSIServer", SERVICE_QUERY_STATUS) : NULL;
    if (hService && QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (BYTE *)&Status, sizeof(Status), &cb))
    {
        dwState = Status.dwCurrentState;
        *pdwPid = Status.dwProcessId;
        if (pdwExit) *pdwExit = Status.dwWin32ExitCode;
    }
    if (hService) CloseServiceHandle(hService);
    if (hScm) CloseServiceHandle(hScm);
    return dwState;
}

/* Starts (bStart) or stops the service and waits up to 30 s for the state; returns the service's process id */
static DWORD ControlInstallerService(BOOL bStart)
{
    SC_HANDLE hScm, hService;
    SERVICE_STATUS Status;
    DWORD i, dwPid = 0, dwWanted = bStart ? SERVICE_RUNNING : SERVICE_STOPPED, dwState;

    hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    hService = hScm ? OpenServiceW(hScm, L"MSIServer", SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS) : NULL;
    if (hService)
    {
        if (bStart) StartServiceW(hService, 0, NULL);
        else ControlService(hService, SERVICE_CONTROL_STOP, &Status);
        CloseServiceHandle(hService);
    }
    if (hScm) CloseServiceHandle(hScm);
    for (i = 0; i < 300; i++)
    {
        dwState = ServiceState(&dwPid, NULL);
        if (dwState == dwWanted || (bStart && dwState == SERVICE_STOPPED && i > 20))
            break;
        Sleep(100);
    }
    /* the pipe exists a moment after the service reports running */
    if (bStart && dwState == SERVICE_RUNNING)
    {
        for (i = 0; i < 50 && !WaitNamedPipeW(MSI_LAUNCH_PIPE_NAME, 100) && GetLastError() == ERROR_FILE_NOT_FOUND; i++)
            Sleep(100);
    }
    return dwState == dwWanted ? (bStart ? dwPid : 1) : 0;
}

/* ---- requests ---- */

static HANDLE OpenLaunchPipe(DWORD *pdwError)
{
    HANDLE hPipe = INVALID_HANDLE_VALUE;
    DWORD i, dwMode = PIPE_READMODE_MESSAGE;

    for (i = 0; i < 40; i++)
    {
        hPipe = CreateFileW(MSI_LAUNCH_PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                            SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL);
        if (hPipe != INVALID_HANDLE_VALUE || GetLastError() != ERROR_PIPE_BUSY)
            break;
        WaitNamedPipeW(MSI_LAUNCH_PIPE_NAME, 1000);
    }
    *pdwError = (hPipe == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
    if (hPipe != INVALID_HANDLE_VALUE)
        SetNamedPipeHandleState(hPipe, &dwMode, NULL, NULL);
    return hPipe;
}

/* Builds a request; cbExtra bytes of garbage follow the strings, bNoTerminator drops the command line's terminator */
static MSI_LAUNCH_REQUEST *MakeRequest(DWORD dwKind, DWORD dwArch, DWORD dwPid, PCWSTR pszApp, PCWSTR pszCmd, PCWSTR pszDir,
                                       DWORD cbExtra, BOOL bNoTerminator, DWORD *pcb)
{
    DWORD a = pszApp ? lstrlenW(pszApp) + 1 : 0, c = pszCmd ? lstrlenW(pszCmd) + 1 : 0, d = pszDir ? lstrlenW(pszDir) + 1 : 0;
    MSI_LAUNCH_REQUEST *pReq;
    WCHAR *p;

    *pcb = sizeof(*pReq) + (a + c + d) * sizeof(WCHAR) + cbExtra;
    pReq = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *pcb);
    if (!pReq) return NULL;
    pReq->Magic = MSI_LAUNCH_MAGIC;
    pReq->Kind = dwKind;
    pReq->ClientPid = dwPid;
    pReq->Arch = dwArch;
    pReq->ApplicationChars = a;
    pReq->CommandLineChars = c;
    pReq->DirectoryChars = d;
    p = (WCHAR *)(pReq + 1);
    if (a) memcpy(p, pszApp, a * sizeof(WCHAR));
    if (c) memcpy(p + a, pszCmd, c * sizeof(WCHAR));
    if (c && bNoTerminator) p[a + c - 1] = L'x';
    if (d) memcpy(p + a + c, pszDir, d * sizeof(WCHAR));
    if (cbExtra) memset((BYTE *)pReq + *pcb - cbExtra, 'A', cbExtra);
    return pReq;
}

/* Sends a request on an open pipe; returns the reply's error, or 0x80000000 | the I/O error */
static DWORD SendOnPipe(HANDLE hPipe, MSI_LAUNCH_REQUEST *pReq, DWORD cbReq, MSI_LAUNCH_REPLY *pReply)
{
    DWORD cb;

    ZeroMemory(pReply, sizeof(*pReply));
    if (!WriteFile(hPipe, pReq, cbReq, &cb, NULL))
        return 0x80000000 | GetLastError();
    if (!ReadFile(hPipe, pReply, sizeof(*pReply), &cb, NULL) || cb != sizeof(*pReply))
        return 0x80000000 | GetLastError();
    return pReply->Error;
}

/* Opens the pipe and sends a request; the open's own error is returned as 0x40000000 | error */
static DWORD Send(MSI_LAUNCH_REQUEST *pReq, DWORD cbReq, MSI_LAUNCH_REPLY *pReply)
{
    DWORD dwError, dwResult;
    HANDLE hPipe = OpenLaunchPipe(&dwError);

    if (hPipe == INVALID_HANDLE_VALUE)
        return 0x40000000 | dwError;
    dwResult = SendOnPipe(hPipe, pReq, cbReq, pReply);
    CloseHandle(hPipe);
    return dwResult;
}

/* A harmless program request of this process: cmd.exe /c exit 0 */
static DWORD SendHarmless(DWORD dwPid, MSI_LAUNCH_REPLY *pReply)
{
    WCHAR szCmdLine[MAX_PATH + 16];
    MSI_LAUNCH_REQUEST *pReq;
    DWORD cb, dwResult;

    StringCchPrintfW(szCmdLine, ARRAYSIZE(szCmdLine), L"\"%s\" /c exit 0", g_szCmd);
    pReq = MakeRequest(MSI_LAUNCH_PROGRAM, 0, dwPid, g_szCmd, szCmdLine, NULL, 0, FALSE, &cb);
    if (!pReq) return 0x80000000 | ERROR_OUTOFMEMORY;
    dwResult = Send(pReq, cb, pReply);
    HeapFree(GetProcessHeap(), 0, pReq);
    if (dwResult == 0 && pReply->ProcessHandle)
    {
        /* it ran: do not leave it behind */
        WaitForSingleObject((HANDLE)(ULONG_PTR)pReply->ProcessHandle, 10000);
        CloseHandle((HANDLE)(ULONG_PTR)pReply->ProcessHandle);
    }
    return dwResult;
}

/* ---- tokens of callers that must be refused ---- */

static PSID AdminsSid(void)
{
    static SID_IDENTIFIER_AUTHORITY Nt = { SECURITY_NT_AUTHORITY };
    PSID pSid = NULL;
    AllocateAndInitializeSid(&Nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pSid);
    return pSid;
}

/* An impersonation token made from this process's token: 1 Administrators deny-only, 2 restricted to Administrators,
 * 3 Medium integrity, 4 Low integrity, 5 AppContainer (a package SID of the test's own, no profile) */
static HANDLE MakeToken(int nKind)
{
    HANDLE hProcess = NULL, hRestricted = NULL, hImp = NULL;
    SID_AND_ATTRIBUTES Sid = { 0 };
    PSID pAdmins = AdminsSid();

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hProcess))
        goto done;
    Sid.Sid = pAdmins;
    if (nKind == 1)
    {
        if (!CreateRestrictedToken(hProcess, 0, 1, &Sid, 0, NULL, 0, NULL, &hRestricted)) goto done;
    }
    else if (nKind == 2)
    {
        if (!CreateRestrictedToken(hProcess, 0, 0, NULL, 0, NULL, 1, &Sid, &hRestricted)) goto done;
    }
    else if (nKind == 5)
    {
        static struct { BYTE Revision, Count, Authority[6]; ULONG Sub[8]; } Package =
            { 1, 8, { 0, 0, 0, 0, 0, 15 }, { 2, 0x4D534C50, 2, 3, 4, 5, 6, 7 } };
        PFN_NtCreateLowBoxToken pCreate =
            (PFN_NtCreateLowBoxToken)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateLowBoxToken");
        if (!pCreate || pCreate(&hRestricted, hProcess, TOKEN_ALL_ACCESS, NULL, (PSID)&Package, 0, NULL, 0, NULL) < 0)
        {
            hRestricted = NULL;
            goto done;
        }
    }
    else if (!DuplicateTokenEx(hProcess, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hRestricted))
        goto done;

    if (!DuplicateTokenEx(hRestricted, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &hImp))
        hImp = NULL;
    else if (nKind == 3 || nKind == 4)
    {
        PSID pLabel = NULL;
        TOKEN_MANDATORY_LABEL Label;
        ConvertStringSidToSidW(nKind == 3 ? L"S-1-16-8192" : L"S-1-16-4096", &pLabel);
        Label.Label.Sid = pLabel;
        Label.Label.Attributes = SE_GROUP_INTEGRITY;
        if (!pLabel || !SetTokenInformation(hImp, TokenIntegrityLevel, &Label, sizeof(Label) + GetLengthSid(pLabel)))
        {
            CloseHandle(hImp);
            hImp = NULL;
        }
        LocalFree(pLabel);
    }

done:
    if (hRestricted) CloseHandle(hRestricted);
    if (hProcess) CloseHandle(hProcess);
    FreeSid(pAdmins);
    return hImp;
}

static void TestRefusedTokens(void)
{
    static const char *Names[] = { "", "Administrators deny-only", "restricted", "Medium integrity", "Low integrity", "AppContainer" };
    MSI_LAUNCH_REPLY Reply;
    DWORD dwResult;
    HANDLE hToken;
    int n;

    for (n = 1; n <= 5; n++)
    {
        hToken = MakeToken(n);
        ok(hToken != NULL, "%s: no token: %lu\n", Names[n], GetLastError());
        if (!hToken)
            continue;
        ok(SetThreadToken(NULL, hToken), "%s: SetThreadToken failed: %lu\n", Names[n], GetLastError());
        dwResult = SendHarmless(GetCurrentProcessId(), &Reply);
        RevertToSelf();
        CloseHandle(hToken);
        /* refused when opening the pipe (its descriptor), or by the service's own check */
        ok(dwResult == (0x40000000 | ERROR_ACCESS_DENIED) || dwResult == ERROR_ACCESS_DENIED,
           "%s caller: result 0x%lx, expected a refusal\n", Names[n], dwResult);
        trace("%s caller: refused %s (0x%lx)\n", Names[n], (dwResult & 0x40000000) ? "when opening the pipe" : "by the service", dwResult);
    }
}

/* A process that sends a request on a handle another process opened: the request names the sender, the pipe's
 * client is the opener: refused. The child is this test ("LaunchPipe inherit <handle>"); its exit code is the result. */
static void TestInheritedHandle(void)
{
    WCHAR szCmdLine[2 * MAX_PATH];
    STARTUPINFOW Si = { sizeof(Si) };
    PROCESS_INFORMATION Pi;
    HANDLE hPipe, hInherit = NULL;
    DWORD dwError, dwExit = MAXDWORD;

    hPipe = OpenLaunchPipe(&dwError);
    ok(hPipe != INVALID_HANDLE_VALUE, "the administrator cannot open the pipe: %lu\n", dwError);
    if (hPipe == INVALID_HANDLE_VALUE)
        return;
    DuplicateHandle(GetCurrentProcess(), hPipe, GetCurrentProcess(), &hInherit, 0, TRUE, DUPLICATE_SAME_ACCESS);
    StringCchPrintfW(szCmdLine, ARRAYSIZE(szCmdLine), L"\"%s\" LaunchPipe inherit %Iu", g_szExe, (ULONG_PTR)hInherit);
    if (CreateProcessW(g_szExe, szCmdLine, NULL, NULL, TRUE, 0, NULL, NULL, &Si, &Pi))
    {
        WaitForSingleObject(Pi.hProcess, 60000);
        GetExitCodeProcess(Pi.hProcess, &dwExit);
        CloseHandle(Pi.hProcess);
        CloseHandle(Pi.hThread);
    }
    ok(dwExit == ERROR_ACCESS_DENIED, "a request on a handle of another process: result %lu, expected 5\n", dwExit);
    CloseHandle(hInherit);
    CloseHandle(hPipe);
}

static DWORD InheritChild(HANDLE hPipe)
{
    WCHAR szCmdLine[MAX_PATH + 16];
    MSI_LAUNCH_REQUEST *pReq;
    MSI_LAUNCH_REPLY Reply;
    DWORD cb, dwResult;

    StringCchPrintfW(szCmdLine, ARRAYSIZE(szCmdLine), L"\"%s\" /c exit 0", g_szCmd);
    pReq = MakeRequest(MSI_LAUNCH_PROGRAM, 0, GetCurrentProcessId(), g_szCmd, szCmdLine, NULL, 0, FALSE, &cb);
    dwResult = pReq ? SendOnPipe(hPipe, pReq, cb, &Reply) : 1;
    if (dwResult == 0 && Reply.ProcessHandle)
        CloseHandle((HANDLE)(ULONG_PTR)Reply.ProcessHandle);
    return dwResult;
}

static void TestBadRequests(void)
{
    WCHAR szCmdLine[MAX_PATH + 16], szDotDot[MAX_PATH + 32];
    MSI_LAUNCH_REQUEST *pReq;
    MSI_LAUNCH_REPLY Reply;
    DWORD cb, dwResult, dwPid = GetCurrentProcessId();
    PWSTR pSlash;

    StringCchPrintfW(szCmdLine, ARRAYSIZE(szCmdLine), L"cmd.exe /c exit 0");

    /* no application path: the service would search for it */
    pReq = MakeRequest(MSI_LAUNCH_PROGRAM, 0, dwPid, NULL, szCmdLine, NULL, 0, FALSE, &cb);
    dwResult = Send(pReq, cb, &Reply);
    ok(dwResult == ERROR_INVALID_PARAMETER, "no application: %lu, expected 87\n", dwResult);
    HeapFree(GetProcessHeap(), 0, pReq);

    /* a bare name */
    pReq = MakeRequest(MSI_LAUNCH_PROGRAM, 0, dwPid, L"cmd.exe", szCmdLine, NULL, 0, FALSE, &cb);
    dwResult = Send(pReq, cb, &Reply);
    ok(dwResult == ERROR_BAD_PATHNAME, "application cmd.exe: %lu, expected 161\n", dwResult);
    HeapFree(GetProcessHeap(), 0, pReq);

    /* a full path with ".." in it */
    StringCchCopyW(szDotDot, ARRAYSIZE(szDotDot), g_szSysDir);
    pSlash = wcsrchr(szDotDot, L'\\');
    StringCchPrintfW(szDotDot, ARRAYSIZE(szDotDot), L"%s\\..\\%s\\cmd.exe", g_szSysDir, pSlash ? pSlash + 1 : L"system32");
    pReq = MakeRequest(MSI_LAUNCH_PROGRAM, 0, dwPid, szDotDot, szCmdLine, NULL, 0, FALSE, &cb);
    dwResult = Send(pReq, cb, &Reply);
    ok(dwResult == ERROR_BAD_PATHNAME, "application %S: %lu, expected 161\n", szDotDot, dwResult);
    HeapFree(GetProcessHeap(), 0, pReq);

    /* a relative directory */
    pReq = MakeRequest(MSI_LAUNCH_PROGRAM, 0, dwPid, g_szCmd, szCmdLine, L"temp", 0, FALSE, &cb);
    dwResult = Send(pReq, cb, &Reply);
    ok(dwResult == ERROR_BAD_PATHNAME, "directory 'temp': %lu, expected 161\n", dwResult);
    HeapFree(GetProcessHeap(), 0, pReq);

    /* the command line without its terminator */
    pReq = MakeRequest(MSI_LAUNCH_PROGRAM, 0, dwPid, g_szCmd, szCmdLine, NULL, 0, TRUE, &cb);
    dwResult = Send(pReq, cb, &Reply);
    ok(dwResult == ERROR_INVALID_PARAMETER, "no terminator: %lu, expected 87\n", dwResult);
    HeapFree(GetProcessHeap(), 0, pReq);

    /* bytes after the strings */
    pReq = MakeRequest(MSI_LAUNCH_PROGRAM, 0, dwPid, g_szCmd, szCmdLine, NULL, 6, FALSE, &cb);
    dwResult = Send(pReq, cb, &Reply);
    ok(dwResult == ERROR_INVALID_PARAMETER, "trailing bytes: %lu, expected 87\n", dwResult);
    HeapFree(GetProcessHeap(), 0, pReq);

    /* lengths that point past the message */
    pReq = MakeRequest(MSI_LAUNCH_PROGRAM, 0, dwPid, g_szCmd, szCmdLine, NULL, 0, FALSE, &cb);
    pReq->DirectoryChars = MSI_LAUNCH_MAX_STRING;
    dwResult = Send(pReq, cb, &Reply);
    ok(dwResult == ERROR_INVALID_PARAMETER, "lengths past the message: %lu, expected 87\n", dwResult);
    pReq->DirectoryChars = 0xFFFFFFF0;
    dwResult = Send(pReq, cb, &Reply);
    ok(dwResult == ERROR_INVALID_PARAMETER, "huge length: %lu, expected 87\n", dwResult);
    HeapFree(GetProcessHeap(), 0, pReq);

    /* a custom action server request with strings */
    pReq = MakeRequest(MSI_LAUNCH_CA_SERVER, 64, dwPid, g_szCmd, szCmdLine, NULL, 0, FALSE, &cb);
    dwResult = Send(pReq, cb, &Reply);
    ok(dwResult == ERROR_INVALID_PARAMETER, "server request with strings: %lu, expected 87\n", dwResult);
    HeapFree(GetProcessHeap(), 0, pReq);

    /* another process's id */
    dwResult = SendHarmless(dwPid + 4, &Reply);
    ok(dwResult == ERROR_ACCESS_DENIED, "another process id: %lu, expected 5\n", dwResult);
}

/* The program the service starts, as this test in reporting mode: who it is, its directory, its environment, its
 * standard handles */
static void TestLaunchedProgram(DWORD dwServicePid)
{
    WCHAR szCmdLine[3 * MAX_PATH], szOut[MAX_PATH], szText[1024];
    MSI_LAUNCH_REQUEST *pReq;
    MSI_LAUNCH_REPLY Reply;
    DWORD cb, dwResult, dwExit = MAXDWORD;
    HANDLE hProcess, hFile;
    char buf[2048];

    GetTempPathW(ARRAYSIZE(szOut), szOut);
    StringCchCatW(szOut, ARRAYSIZE(szOut), L"msi_launch_report.txt");
    DeleteFileW(szOut);
    StringCchPrintfW(szCmdLine, ARRAYSIZE(szCmdLine), L"\"%s\" LaunchPipe report \"%s\"", g_szExe, szOut);
    pReq = MakeRequest(MSI_LAUNCH_PROGRAM, 0, GetCurrentProcessId(), g_szExe, szCmdLine, NULL, 0, FALSE, &cb);
    dwResult = Send(pReq, cb, &Reply);
    HeapFree(GetProcessHeap(), 0, pReq);
    ok(dwResult == 0, "an elevated administrator's request failed: 0x%lx\n", dwResult);
    if (dwResult)
        return;
    hProcess = (HANDLE)(ULONG_PTR)Reply.ProcessHandle;
    ok(Reply.ProcessId != 0 && GetProcessId(hProcess) == Reply.ProcessId, "the reply's handle is not process %lu\n", Reply.ProcessId);
    ok(WaitForSingleObject(hProcess, 60000) == WAIT_OBJECT_0, "the program did not end\n");
    GetExitCodeProcess(hProcess, &dwExit);
    ok(dwExit == 0, "the program's exit code: %lu\n", dwExit);
    CloseHandle(hProcess);

    hFile = CreateFileW(szOut, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    ok(hFile != INVALID_HANDLE_VALUE, "no report: %lu\n", GetLastError());
    if (hFile == INVALID_HANDLE_VALUE)
        return;
    cb = 0;
    ReadFile(hFile, buf, sizeof(buf) - 1, &cb, NULL);
    CloseHandle(hFile);
    DeleteFileW(szOut);
    buf[cb] = 0;
    MultiByteToWideChar(CP_ACP, 0, buf, -1, szText, ARRAYSIZE(szText));
    trace("launched program: %S\n", szText);
    ok(wcsstr(szText, L"user=S-1-5-18;") != NULL, "not LocalSystem: %S\n", szText);
    ok(!wcsstr(szText, L"stdin=x") && !wcsstr(szText, L"stdout=x") && !wcsstr(szText, L"stderr=x"),
       "standard handles that are neither absent nor its own console: %S\n", szText);
    ok(wcsstr(szText, L"cwdsys=1;") != NULL, "current directory is not the system directory: %S\n", szText);
    ok(wcsstr(szText, L"profile=systemprofile;") != NULL, "not LocalSystem's environment: %S\n", szText);
    (void)dwServicePid;
}

/* A standard handle of the reporting program: 'n' none, 'c' a console handle (its own console: a console program
 * started without inherited handles gets a new one), 'x' anything else (a handle that came from elsewhere) */
static char StdKind(DWORD dwWhich)
{
    HANDLE h = GetStdHandle(dwWhich);
    DWORD dwMode;

    if (!h || h == INVALID_HANDLE_VALUE)
        return 'n';
    return GetConsoleMode(h, &dwMode) ? 'c' : 'x';
}

static DWORD ReportChild(PCWSTR pszOut)
{
    char buf[1024];
    WCHAR szDir[MAX_PATH], szProfile[MAX_PATH];
    LPWSTR pszSid = NULL;
    BYTE tu[256];
    HANDLE hToken, hFile;
    DWORD cb;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        if (GetTokenInformation(hToken, TokenUser, tu, sizeof(tu), &cb))
            ConvertSidToStringSidW(((PTOKEN_USER)tu)->User.Sid, &pszSid);
        CloseHandle(hToken);
    }
    GetCurrentDirectoryW(ARRAYSIZE(szDir), szDir);
    if (lstrlenW(szDir) > 3 && szDir[lstrlenW(szDir) - 1] == L'\\') szDir[lstrlenW(szDir) - 1] = 0;
    szProfile[0] = 0;
    GetEnvironmentVariableW(L"USERPROFILE", szProfile, ARRAYSIZE(szProfile));
    CharLowerW(szProfile);
    StringCchPrintfA(buf, sizeof(buf), "user=%S;stdin=%c;stdout=%c;stderr=%c;cwdsys=%d;profile=%s;handles=%lu;cwd=%S;userprofile=%S;",
                     pszSid ? pszSid : L"?",
                     StdKind(STD_INPUT_HANDLE), StdKind(STD_OUTPUT_HANDLE), StdKind(STD_ERROR_HANDLE),
                     !lstrcmpiW(szDir, g_szSysDir),
                     wcsstr(szProfile, L"systemprofile") ? "systemprofile" : "other",
                     GetProcessHandleCount(GetCurrentProcess(), &cb) ? cb : 0, szDir, szProfile);
    if (pszSid) LocalFree(pszSid);
    hFile = CreateFileW(pszOut, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return 2;
    WriteFile(hFile, buf, lstrlenA(buf), &cb, NULL);
    CloseHandle(hFile);
    return 0;
}

/* A client that connects and never writes: the next client is served after about 10 s */
static void TestSilentClient(void)
{
    MSI_LAUNCH_REPLY Reply;
    DWORD dwError, dwStart, dwElapsed, dwResult;
    HANDLE hSilent = OpenLaunchPipe(&dwError);

    ok(hSilent != INVALID_HANDLE_VALUE, "cannot open the pipe: %lu\n", dwError);
    dwStart = GetTickCount();
    dwResult = SendHarmless(GetCurrentProcessId(), &Reply);
    dwElapsed = GetTickCount() - dwStart;
    ok(dwResult == 0, "the client after a silent one: 0x%lx\n", dwResult);
    ok(dwElapsed < 25000, "the client after a silent one waited %lu ms\n", dwElapsed);
    trace("the client after a silent one waited %lu ms\n", dwElapsed);
    if (hSilent != INVALID_HANDLE_VALUE)
        CloseHandle(hSilent);
}

/* ---- installations: squatted pipe names ---- */

static BOOL RunQuery(MSIHANDLE hDb, LPCWSTR pszQuery, MSIHANDLE hRec)
{
    MSIHANDLE hView;
    UINT r = MsiDatabaseOpenViewW(hDb, pszQuery, &hView);
    if (r == ERROR_SUCCESS)
    {
        r = MsiViewExecute(hView, hRec);
        MsiCloseHandle(hView);
    }
    ok(r == ERROR_SUCCESS, "%S failed: %u\n", pszQuery, r);
    return r == ERROR_SUCCESS;
}

/* A package with one deferred action of the given type whose source is the file pszBinary (stored in the Binary
 * table) and target pszTarget */
static BOOL CreatePackage(LPCWSTR pszPath, int nType, LPCWSTR pszBinary, LPCWSTR pszTarget)
{
    MSIHANDLE hDb, hSummary, hRec;
    WCHAR szQuery[512];
    UINT r;
    BOOL bOk;

    DeleteFileW(pszPath);
    r = MsiOpenDatabaseW(pszPath, (LPCWSTR)MSIDBOPEN_CREATE, &hDb);
    ok(r == ERROR_SUCCESS, "MsiOpenDatabaseW failed: %u\n", r);
    if (r != ERROR_SUCCESS)
        return FALSE;
    StringCchPrintfW(szQuery, ARRAYSIZE(szQuery),
                     L"INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`) VALUES ('Act', %d, 'bin', '%s')", nType, pszTarget);
    bOk = RunQuery(hDb, L"CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` CHAR(0) NOT NULL PRIMARY KEY `Property`)", 0) &&
          RunQuery(hDb, L"INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductCode', '{6E1B3C57-9A42-4F08-B3D1-27C5E9A04B16}')", 0) &&
          RunQuery(hDb, L"INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductName', 'Launch pipe test')", 0) &&
          RunQuery(hDb, L"INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductVersion', '1.0.0')", 0) &&
          RunQuery(hDb, L"INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductLanguage', '1033')", 0) &&
          RunQuery(hDb, L"INSERT INTO `Property` (`Property`, `Value`) VALUES ('Manufacturer', 'Test')", 0) &&
          RunQuery(hDb, L"CREATE TABLE `Binary` (`Name` CHAR(72) NOT NULL, `Data` OBJECT NOT NULL PRIMARY KEY `Name`)", 0) &&
          RunQuery(hDb, L"CREATE TABLE `CustomAction` (`Action` CHAR(72) NOT NULL, `Type` SHORT NOT NULL, `Source` CHAR(72), `Target` CHAR(255), `ExtendedType` LONG PRIMARY KEY `Action`)", 0) &&
          RunQuery(hDb, szQuery, 0) &&
          RunQuery(hDb, L"CREATE TABLE `InstallExecuteSequence` (`Action` CHAR(72) NOT NULL, `Condition` CHAR(255), `Sequence` SHORT PRIMARY KEY `Action`)", 0) &&
          RunQuery(hDb, L"INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('InstallInitialize', 1500)", 0) &&
          RunQuery(hDb, L"INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('Act', 1600)", 0) &&
          RunQuery(hDb, L"INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('InstallFinalize', 6600)", 0);
    if (bOk)
    {
        hRec = MsiCreateRecord(1);
        r = MsiRecordSetStreamW(hRec, 1, pszBinary);
        ok(r == ERROR_SUCCESS, "MsiRecordSetStreamW(%S) failed: %u\n", pszBinary, r);
        bOk = r == ERROR_SUCCESS && RunQuery(hDb, L"INSERT INTO `Binary` (`Name`, `Data`) VALUES ('bin', ?)", hRec);
        MsiCloseHandle(hRec);
    }
    if (bOk && MsiGetSummaryInformationW(hDb, NULL, 5, &hSummary) == ERROR_SUCCESS)
    {
        MsiSummaryInfoSetPropertyW(hSummary, PID_TEMPLATE, VT_LPSTR, 0, NULL, sizeof(void *) == 8 ? L"x64;1033" : L"Intel;1033");
        MsiSummaryInfoSetPropertyW(hSummary, PID_REVNUMBER, VT_LPSTR, 0, NULL, L"{9C24E1A7-5D3B-4B60-8E19-F0A2C6D73B58}");
        MsiSummaryInfoSetPropertyW(hSummary, PID_PAGECOUNT, VT_I4, 200, NULL, NULL);
        MsiSummaryInfoSetPropertyW(hSummary, PID_WORDCOUNT, VT_I4, 0, NULL, NULL);
        bOk = MsiSummaryInfoPersist(hSummary) == ERROR_SUCCESS;
        MsiCloseHandle(hSummary);
    }
    if (bOk)
        bOk = MsiDatabaseCommit(hDb) == ERROR_SUCCESS;
    MsiCloseHandle(hDb);
    return bOk;
}

/* Creates the pipe pszName first (as another program would) and starts waiting for a client on it */
static HANDLE Squat(PCWSTR pszName, OVERLAPPED *pOv)
{
    HANDLE hPipe = CreateNamedPipeW(pszName, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                                    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, NULL);

    ok(hPipe != INVALID_HANDLE_VALUE, "could not create %S first: %lu\n", pszName, GetLastError());
    if (hPipe == INVALID_HANDLE_VALUE)
        return hPipe;
    ZeroMemory(pOv, sizeof(*pOv));
    pOv->hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!ConnectNamedPipe(hPipe, pOv) && GetLastError() == ERROR_PIPE_CONNECTED)
        SetEvent(pOv->hEvent);
    return hPipe;
}

/* What reached the squatted pipe: 0 nothing, 1 a client connected but sent nothing, 2 a client sent data */
static int SquatResult(HANDLE hPipe, OVERLAPPED *pOv)
{
    DWORD dwAvail = 0, cb;
    int nResult = 0;

    if (WaitForSingleObject(pOv->hEvent, 0) == WAIT_OBJECT_0)
    {
        nResult = 1;
        if (PeekNamedPipe(hPipe, NULL, 0, NULL, &dwAvail, NULL) && dwAvail)
            nResult = 2;
    }
    else
    {
        CancelIo(hPipe);
        GetOverlappedResult(hPipe, pOv, &cb, TRUE);
    }
    CloseHandle(pOv->hEvent);
    CloseHandle(hPipe);
    return nResult;
}

static void TestSquattedLaunchPipe(PCWSTR pszPkg)
{
    OVERLAPPED Ov;
    HANDLE hSquat;
    DWORD dwPid, dwExit = 0, dwState, i;
    UINT r;
    int nResult;

    ok(ControlInstallerService(FALSE) != 0, "the Installer service did not stop\n");
    hSquat = Squat(MSI_LAUNCH_PIPE_NAME, &Ov);
    if (hSquat == INVALID_HANDLE_VALUE)
        return;
    r = MsiInstallProductW(pszPkg, L"");
    ok(r == ERROR_INSTALL_FAILURE, "an installation with the launch pipe taken: %u, expected 1603\n", r);
    /* msi.dll may have refused the other program's pipe before the service got to its own attempt: give it 30 s */
    for (i = 0; i < 300 && (dwState = ServiceState(&dwPid, &dwExit)) != SERVICE_STOPPED; i++)
        Sleep(100);
    ok(dwState == SERVICE_STOPPED && dwExit != 0, "the service with its pipe taken: state %lu, exit code %lu\n", dwState, dwExit);
    trace("the service with its pipe taken: state %lu, exit code %lu\n", dwState, dwExit);
    nResult = SquatResult(hSquat, &Ov);
    ok(nResult != 2, "msi.dll wrote its request to the pipe of another program\n");
    trace("the squatted launch pipe: %s\n", nResult ? "a client connected and sent nothing" : "no client");
    /* the name is free again: the next installation works */
    r = MsiInstallProductW(pszPkg, L"");
    ok(r == ERROR_SUCCESS, "the installation after the pipe was freed: %u\n", r);
    MsiConfigureProductW(L"{6E1B3C57-9A42-4F08-B3D1-27C5E9A04B16}", INSTALLLEVEL_DEFAULT, INSTALLSTATE_ABSENT);
}

static void TestSquattedServerPipe(PCWSTR pszPkg, BOOL bSystem)
{
    WCHAR szName[64];
    OVERLAPPED Ov;
    HANDLE hSquat;
    UINT r;
    int nResult;

    StringCchPrintfW(szName, ARRAYSIZE(szName), L"\\\\.\\pipe\\msica_%x_%d%s", GetCurrentProcessId(),
                     (int)(sizeof(void *) * 8), bSystem ? L"_s" : L"");
    hSquat = Squat(szName, &Ov);
    if (hSquat == INVALID_HANDLE_VALUE)
        return;
    r = MsiInstallProductW(pszPkg, L"");
    /* the action cannot start (ERROR_FUNCTION_FAILED); what matters is that no server connected to the other pipe */
    ok(r != ERROR_SUCCESS, "%S taken: the installation returned %u, expected a failure\n", szName, r);
    Sleep(2000);
    nResult = SquatResult(hSquat, &Ov);
    ok(nResult == 0, "%S taken: a custom action server connected to it (%d)\n", szName, nResult);
    MsiConfigureProductW(L"{6E1B3C57-9A42-4F08-B3D1-27C5E9A04B16}", INSTALLLEVEL_DEFAULT, INSTALLSTATE_ABSENT);
}

START_TEST(LaunchPipe)
{
    WCHAR szDir[MAX_PATH], szPkg[MAX_PATH], szDll[MAX_PATH], szTemp[MAX_PATH];
    HANDLE hToken, hPipe;
    TOKEN_ELEVATION Elevation;
    DWORD cb, dwPid, dwServer = 0, dwError;
    PWSTR pSlash;
    int argc;
    char **argv;

    GetModuleFileNameW(NULL, g_szExe, ARRAYSIZE(g_szExe));
    GetSystemDirectoryW(g_szSysDir, ARRAYSIZE(g_szSysDir));
    StringCchPrintfW(g_szCmd, ARRAYSIZE(g_szCmd), L"%s\\cmd.exe", g_szSysDir);

    argc = winetest_get_mainargs(&argv);
    if (argc >= 4 && !strcmp(argv[2], "report"))
    {
        WCHAR szOut[MAX_PATH];
        MultiByteToWideChar(CP_ACP, 0, argv[3], -1, szOut, ARRAYSIZE(szOut));
        ExitProcess(ReportChild(szOut));
    }
    if (argc >= 4 && !strcmp(argv[2], "inherit"))
        ExitProcess(InheritChild((HANDLE)(ULONG_PTR)_strtoui64(argv[3], NULL, 10)));

    Elevation.TokenIsElevated = FALSE;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cb);
        CloseHandle(hToken);
    }
    if (!Elevation.TokenIsElevated)
    {
        skip("not an elevated administrator\n");
        return;
    }
    dwPid = ControlInstallerService(TRUE);
    if (!dwPid)
    {
        skip("the Installer service does not run\n");
        return;
    }

    /* the pipe's server is the service */
    hPipe = OpenLaunchPipe(&dwError);
    ok(hPipe != INVALID_HANDLE_VALUE, "cannot open the launch pipe: %lu\n", dwError);
    if (hPipe != INVALID_HANDLE_VALUE)
    {
        ok(GetNamedPipeServerProcessId(hPipe, &dwServer) && dwServer == dwPid,
           "the launch pipe is served by %lu, the service is %lu\n", dwServer, dwPid);
        CloseHandle(hPipe);
    }

    TestLaunchedProgram(dwPid);
    TestRefusedTokens();
    TestInheritedHandle();
    TestBadRequests();
    TestSilentClient();
    ok(ServiceState(&dwServer, NULL) == SERVICE_RUNNING && dwServer == dwPid, "the service did not survive the requests\n");

    /* installations with a no-impersonation EXE action (cmd.exe /c exit 0), then DLL actions (msi_cadir.dll) */
    MsiSetInternalUI(INSTALLUILEVEL_NONE, NULL);
    GetTempPathW(ARRAYSIZE(szTemp), szTemp);
    StringCchPrintfW(szPkg, ARRAYSIZE(szPkg), L"%smsi_launchpipe.msi", szTemp);
    if (CreatePackage(szPkg, 3074, g_szCmd, L"/c exit 0"))
        TestSquattedLaunchPipe(szPkg);
    ok(ControlInstallerService(TRUE) != 0, "the Installer service does not start again\n");

    StringCchCopyW(szDir, ARRAYSIZE(szDir), g_szExe);
    pSlash = wcsrchr(szDir, L'\\');
    if (pSlash) pSlash[1] = UNICODE_NULL;
    StringCchPrintfW(szDll, ARRAYSIZE(szDll), L"%smsi_cadir.dll", szDir);
    if (GetFileAttributesW(szDll) == INVALID_FILE_ATTRIBUTES)
        skip("%S not found\n", szDll);
    else
    {
        /* the action reports into a file named by CustomActionData: absent here, it fails if it ever runs */
        if (CreatePackage(szPkg, 3073, szDll, L"ReportIdentity"))
            TestSquattedServerPipe(szPkg, TRUE);
        if (CreatePackage(szPkg, 1025, szDll, L"ReportIdentity"))
            TestSquattedServerPipe(szPkg, FALSE);
    }
    DeleteFileW(szPkg);
}
