/*
 * msiexec.exe implementation
 *
 * Copyright 2007 Google (James Hawkins)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsvc.h>

#include "wine/debug.h"
#include "msiexec_internal.h"

WINE_DEFAULT_DEBUG_CHANNEL(msiexec);

static SERVICE_STATUS_HANDLE hstatus;

static HANDLE thread;
static HANDLE kill_event;
#ifdef __REACTOS__
static DWORD service_exit_code; /* the reason the service stopped on its own (SERVICE_STATUS.dwWin32ExitCode) */
#endif

static void KillService(void)
{
    WINE_TRACE("Killing service\n");
    SetEvent(kill_event);
}

static BOOL UpdateSCMStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode,
                            DWORD dwServiceSpecificExitCode)
{
    SERVICE_STATUS status;

    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = dwCurrentState;

    if (dwCurrentState == SERVICE_START_PENDING
            || dwCurrentState == SERVICE_STOP_PENDING
            || dwCurrentState == SERVICE_STOPPED)
        status.dwControlsAccepted = 0;
    else
    {
        status.dwControlsAccepted = SERVICE_ACCEPT_STOP |
                                    SERVICE_ACCEPT_PAUSE_CONTINUE |
                                    SERVICE_ACCEPT_SHUTDOWN;
    }

    if (dwServiceSpecificExitCode == 0)
    {
        status.dwWin32ExitCode = dwWin32ExitCode;
    }
    else
    {
        status.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
    }

    status.dwServiceSpecificExitCode = dwServiceSpecificExitCode;
    status.dwCheckPoint = 0;
    status.dwWaitHint = 0;

    if (!SetServiceStatus(hstatus, &status))
    {
        report_error("Failed to set service status\n");
        KillService();
        return FALSE;
    }

    return TRUE;
}

static void WINAPI ServiceCtrlHandler(DWORD code)
{
    WINE_TRACE("%ld\n", code);

    switch (code)
    {
        case SERVICE_CONTROL_SHUTDOWN:
        case SERVICE_CONTROL_STOP:
            UpdateSCMStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
            KillService();
            break;
        default:
            report_error("Unhandled service control code: %ld\n", code);
            UpdateSCMStatus(SERVICE_RUNNING, NO_ERROR, 0);
            break;
    }
}

#ifdef __REACTOS__

/*
 * Programs of deferred "no impersonation" custom actions.
 *
 * On Windows the Installer service runs such an action as LocalSystem. Here msi.dll runs in the process of whoever
 * started msiexec, so an elevated administrator asks this service (LocalSystem) to start the program and gets a
 * handle to the new process back. Only elevated administrators and the system may connect to the pipe; the request
 * is checked again with the client's token.
 */

#include <sddl.h>
#include <reactos/msilaunch.h>

/* A failure that stops the service: in the debug log, in the Application event log, and as the service's exit code
 * (a service has no desktop to show a message on) */
static void ReportServiceError(const WCHAR *text, DWORD error)
{
    HANDLE source;
    WCHAR buffer[400];
    const WCHAR *strings[1];

    ERR("%s: %lu\n", wine_dbgstr_w(text), error);
    swprintf(buffer, ARRAY_SIZE(buffer), L"%s: error %lu.", text, error);
    strings[0] = buffer;
    if ((source = RegisterEventSourceW(NULL, L"MsiInstaller")))
    {
        ReportEventW(source, EVENTLOG_ERROR_TYPE, 0, 0, NULL, 1, 0, strings, NULL);
        DeregisterEventSource(source);
    }
    service_exit_code = error ? error : ERROR_GEN_FAILURE;
}

#ifndef TokenIsAppContainer
#define TokenIsAppContainer 29
#endif

/*
 * Who may ask: the token the client opened the pipe with (its thread's, when it impersonated) must be elevated, of
 * High or System integrity, not restricted, not an AppContainer token, with the Administrators group enabled (a
 * deny-only group does not count). The pipe's descriptor already refuses most of them (Administrators only, High
 * label with no write up, no entry for an AppContainer); this is the second check. Identification is enough for
 * these queries; the token is never used to open anything.
 */
static BOOL IsElevatedAdministrator(HANDLE pipe)
{
    HANDLE token = NULL;
    TOKEN_ELEVATION elevation;
    union { TOKEN_MANDATORY_LABEL label; BYTE buffer[64]; } integrity;
    SECURITY_IMPERSONATION_LEVEL level = SecurityAnonymous;
    DWORD size, appcontainer = 1, count;
    BOOL ok = FALSE, member = FALSE;
    PSID admins = NULL;
    SID_IDENTIFIER_AUTHORITY nt = { SECURITY_NT_AUTHORITY };

    if (!ImpersonateNamedPipeClient(pipe))
        return FALSE;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token))
        token = NULL;
    RevertToSelf();
    if (!token)
        return FALSE;

    if (GetTokenInformation(token, TokenImpersonationLevel, &level, sizeof(level), &size) && level >= SecurityIdentification &&
        GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size) && elevation.TokenIsElevated &&
        GetTokenInformation(token, TokenIntegrityLevel, &integrity, sizeof(integrity), &size) &&
        (count = *GetSidSubAuthorityCount(integrity.label.Label.Sid)) &&
        *GetSidSubAuthority(integrity.label.Label.Sid, count - 1) >= SECURITY_MANDATORY_HIGH_RID &&
        !IsTokenRestricted(token) &&
        GetTokenInformation(token, TokenIsAppContainer, &appcontainer, sizeof(appcontainer), &size) && !appcontainer &&
        AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admins))
    {
        ok = CheckTokenMembership(token, admins, &member) && member;
        FreeSid(admins);
    }
    if (!ok) WARN("refused a client: level %d, appcontainer %lu, administrator %d\n", level, appcontainer, member);
    CloseHandle(token);
    return ok;
}

/* A string of the request: exactly `chars` characters, the last one the terminator and no other */
static WCHAR *DupString(const WCHAR *base, DWORD chars)
{
    WCHAR *s;

    if (chars == 0 || chars > MSI_LAUNCH_MAX_STRING || base[chars - 1] != 0 || lstrlenW(base) != chars - 1)
        return NULL;
    s = HeapAlloc(GetProcessHeap(), 0, chars * sizeof(WCHAR));
    if (s) memcpy(s, base, chars * sizeof(WCHAR));
    return s;
}

/* A path the service may use without searching: "X:\..." in its full form (no relative part, no "." or ".."
 * components, no device or \\?\ prefix), naming an existing file or directory as asked */
static BOOL IsFullyQualifiedPath(const WCHAR *path, BOOL directory)
{
    WCHAR full[MAX_PATH * 2];
    DWORD len, attributes;

    if (!(((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) && path[1] == L':' &&
          path[2] == L'\\'))
        return FALSE;
    len = GetFullPathNameW(path, ARRAY_SIZE(full), full, NULL);
    if (!len || len >= ARRAY_SIZE(full) || lstrcmpiW(full, path))
        return FALSE;
    attributes = GetFileAttributesW(path);
    if (attributes == INVALID_FILE_ATTRIBUTES)
        return FALSE;
    return directory ? (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 : (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

/*
 * What the service starts: a program named by its full path (CreateProcessW does not search for it, so nothing is
 * taken from the service's directories, its PATH or a directory the request names before the program runs), in a
 * fully qualified existing directory (the system directory when none is given), with the service's own LocalSystem
 * environment (the request cannot name one), and no handle of the service: nothing is inherited and no standard handles
 * are passed (a console program gets a console of its own, measured by msi_apitest LaunchPipe).
 */
static DWORD LaunchProgram(const MSI_LAUNCH_REQUEST *req, DWORD client_pid, HANDLE *process, DWORD *pid)
{
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    WCHAR path[MAX_PATH + 16], dir[MAX_PATH], *cmd = NULL, *app = NULL, *cwd = NULL;
    DWORD error = ERROR_SUCCESS, len;
    const WCHAR *strings = (const WCHAR *)(req + 1);

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);

    if (req->Kind == MSI_LAUNCH_CA_SERVER)
    {
        if ((req->Arch != 32 && req->Arch != 64) || req->ApplicationChars || req->CommandLineChars || req->DirectoryChars)
            return ERROR_INVALID_PARAMETER;
        /* the custom action server of the architecture: msiexec.exe -Embedding <the client's process id> */
#ifdef _WIN64
        if (req->Arch == 32)
            len = GetSystemWow64DirectoryW(dir, MAX_PATH);
        else
#endif
            len = GetSystemDirectoryW(dir, MAX_PATH);
        if (!len || len >= MAX_PATH - 16)
            return ERROR_PATH_NOT_FOUND;
        wsprintfW(path, L"%s\\msiexec.exe", dir);
        cmd = HeapAlloc(GetProcessHeap(), 0, (MAX_PATH + 40) * sizeof(WCHAR));
        if (!cmd) return ERROR_OUTOFMEMORY;
        wsprintfW(cmd, L"%s -Embedding %us", path, client_pid);  /* "s": the pipe of the LocalSystem server */
        GetSystemDirectoryW(dir, MAX_PATH);
        if (!CreateProcessW(path, cmd, NULL, NULL, FALSE, 0, NULL, dir, &si, &pi))
            error = GetLastError();
        HeapFree(GetProcessHeap(), 0, cmd);
    }
    else if (req->Kind == MSI_LAUNCH_PROGRAM)
    {
        DWORD a = req->ApplicationChars, c = req->CommandLineChars, d = req->DirectoryChars;

        if (a == 0 || c == 0 || a > MSI_LAUNCH_MAX_STRING || c > MSI_LAUNCH_MAX_STRING || d > MSI_LAUNCH_MAX_STRING)
            return ERROR_INVALID_PARAMETER;
        if (!(app = DupString(strings, a))) return ERROR_INVALID_PARAMETER;
        if (!(cmd = DupString(strings + a, c))) { HeapFree(GetProcessHeap(), 0, app); return ERROR_INVALID_PARAMETER; }
        if (d && !(cwd = DupString(strings + a + c, d))) { HeapFree(GetProcessHeap(), 0, app); HeapFree(GetProcessHeap(), 0, cmd); return ERROR_INVALID_PARAMETER; }
        if (!IsFullyQualifiedPath(app, FALSE) || (cwd && !IsFullyQualifiedPath(cwd, TRUE)))
            error = ERROR_BAD_PATHNAME;
        else
        {
            if (!cwd) GetSystemDirectoryW(dir, MAX_PATH);
            if (!CreateProcessW(app, cmd, NULL, NULL, FALSE, 0, NULL, cwd ? cwd : dir, &si, &pi))
                error = GetLastError();
        }
        HeapFree(GetProcessHeap(), 0, app);
        HeapFree(GetProcessHeap(), 0, cmd);
        HeapFree(GetProcessHeap(), 0, cwd);
    }
    else
        return ERROR_INVALID_PARAMETER;

    if (error) return error;
    CloseHandle(pi.hThread);
    *process = pi.hProcess;
    *pid = pi.dwProcessId;
    return ERROR_SUCCESS;
}

/* Completes an overlapped operation on the pipe within 10 s, or cancels it and waits for the cancellation (the
 * buffer is not used any more when this returns). One client is served at a time, so a client is held up by the
 * one before it for 20 s at most (10 s for its request, 10 s for it to take the reply). */
static BOOL WaitPipeIo(HANDLE pipe, OVERLAPPED *ov, BOOL started, DWORD *size)
{
    *size = 0;
    if (!started && GetLastError() != ERROR_IO_PENDING)
        return FALSE;
    if (WaitForSingleObject(ov->hEvent, 10000) != WAIT_OBJECT_0)
    {
        CancelIo(pipe);
        GetOverlappedResult(pipe, ov, size, TRUE);
        return FALSE;
    }
    return GetOverlappedResult(pipe, ov, size, FALSE);
}

static void HandleLaunchClient(HANDLE pipe)
{
    BYTE *buffer;
    const DWORD buffer_size = sizeof(MSI_LAUNCH_REQUEST) + 3 * MSI_LAUNCH_MAX_STRING * sizeof(WCHAR);
    MSI_LAUNCH_REPLY reply;
    MSI_LAUNCH_REQUEST *req;
    OVERLAPPED ov;
    DWORD size = 0, client_pid = 0, check_pid = 0, error;
    HANDLE process = NULL, client = NULL, dup = NULL;
    ULONG64 total;

    memset(&reply, 0, sizeof(reply));
    reply.Magic = MSI_LAUNCH_MAGIC;

    buffer = HeapAlloc(GetProcessHeap(), 0, buffer_size);
    if (!buffer) return;
    req = (MSI_LAUNCH_REQUEST *)buffer;

    memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!ov.hEvent) { HeapFree(GetProcessHeap(), 0, buffer); return; }
    /* The request is one message no larger than the buffer (a larger one fails with ERROR_MORE_DATA and is dropped).
     * A client that does not send it within 10 s is dropped. */
    if (!WaitPipeIo(pipe, &ov, ReadFile(pipe, buffer, buffer_size, NULL, &ov), &size) || size < sizeof(*req))
        goto done;

    /* the three strings fill the rest of the message exactly; each is checked for its terminator when it is read */
    total = (ULONG64)sizeof(*req) + ((ULONG64)req->ApplicationChars + req->CommandLineChars + req->DirectoryChars) * sizeof(WCHAR);
    if (req->Magic != MSI_LAUNCH_MAGIC || total != size)
        error = ERROR_INVALID_PARAMETER;
    else if (!GetNamedPipeClientProcessId(pipe, &client_pid) || client_pid != req->ClientPid)
        error = ERROR_ACCESS_DENIED;
    else if (!IsElevatedAdministrator(pipe))
        error = ERROR_ACCESS_DENIED;
    else if (!(client = OpenProcess(PROCESS_DUP_HANDLE, FALSE, client_pid)))
        error = GetLastError();
    /* the process opened is the client: it still holds its end (a process id of a client that has gone may be
     * another process's by now) */
    else if (!PeekNamedPipe(pipe, NULL, 0, NULL, NULL, NULL) ||
             !GetNamedPipeClientProcessId(pipe, &check_pid) || check_pid != client_pid)
        error = ERROR_BROKEN_PIPE;
    else if ((error = LaunchProgram(req, client_pid, &process, &reply.ProcessId)) == ERROR_SUCCESS)
    {
        /* what msi.dll does with it: wait, read the exit code, terminate it on failure, and take the thread handles
         * of a custom action server */
        if (DuplicateHandle(GetCurrentProcess(), process, client, &dup,
                            SYNCHRONIZE | PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE |
                            (req->Kind == MSI_LAUNCH_CA_SERVER ? PROCESS_DUP_HANDLE : 0), FALSE, 0))
            reply.ProcessHandle = (ULONG64)(ULONG_PTR)dup;
        else
        {
            error = GetLastError();
            TerminateProcess(process, 1);
        }
        CloseHandle(process);
    }
    if (client) CloseHandle(client);
    reply.Error = error;

    /* Write the reply, then wait (10 s at most) for the client to read it and close its end: disconnecting at once
     * would throw the reply away, and FlushFileBuffers() would wait for ever for a client that does not read */
    ResetEvent(ov.hEvent);
    if (WaitPipeIo(pipe, &ov, WriteFile(pipe, &reply, sizeof(reply), NULL, &ov), &size))
    {
        BYTE byte;
        ResetEvent(ov.hEvent);
        WaitPipeIo(pipe, &ov, ReadFile(pipe, &byte, 1, NULL, &ov), &size);
    }

done:
    CloseHandle(ov.hEvent);
    HeapFree(GetProcessHeap(), 0, buffer);
}

static DWORD WINAPI ServiceExecutionThread(LPVOID param)
{
    SECURITY_ATTRIBUTES sa;
    OVERLAPPED ov;
    HANDLE pipe, next, wait[2];
    DWORD err;

    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;
    sa.lpSecurityDescriptor = NULL;
    /* LocalSystem, and the Administrators group as clients only: not FILE_CREATE_PIPE_INSTANCE (= FILE_APPEND_DATA),
     * so that every instance of the name is this service's. The High label refuses writers below High integrity (an
     * administrator's program started at Medium or Low) when they open it. */
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;0x12019b;;;BA)S:(ML;;NW;;;HI)", SDDL_REVISION_1,
                                                              &sa.lpSecurityDescriptor, NULL))
    {
        ReportServiceError(L"The Installer service could not build the security descriptor of its launch pipe",
                           GetLastError());
        return 0;
    }

    memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!ov.hEvent)
    {
        ReportServiceError(L"The Installer service could not create an event", GetLastError());
        LocalFree(sa.lpSecurityDescriptor);
        return 0;
    }
    wait[0] = kill_event;
    wait[1] = ov.hEvent;

    /* The first instance must be new: when the name exists, someone else made it, and the clients would talk to them.
     * msi.dll checks that the pipe's server is this service and fails the installation when the service stopped. */
    pipe = CreateNamedPipeW(MSI_LAUNCH_PIPE_NAME, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 2, 4096, 4096, 0, &sa);
    if (pipe == INVALID_HANDLE_VALUE)
    {
        err = GetLastError();
        ReportServiceError(L"The Installer service could not create its launch pipe " MSI_LAUNCH_PIPE_NAME
                           L" (the name may be in use by another program)", err);
        CloseHandle(ov.hEvent);
        LocalFree(sa.lpSecurityDescriptor);
        return 0;
    }

    for (;;)
    {
        ResetEvent(ov.hEvent);
        if (!ConnectNamedPipe(pipe, &ov))
        {
            err = GetLastError();
            if (err == ERROR_IO_PENDING)
            {
                if (WaitForMultipleObjects(2, wait, FALSE, INFINITE) != WAIT_OBJECT_0 + 1)
                {
                    CancelIo(pipe);
                    GetOverlappedResult(pipe, &ov, &err, TRUE);
                    break;
                }
            }
            else if (err != ERROR_PIPE_CONNECTED)
            {
                DisconnectNamedPipe(pipe);
                continue;
            }
        }

        /* The next instance exists before this one is closed: the name never disappears while the service runs, so
         * nobody else can take it between two clients. At most two instances: this one and the next. */
        next = CreateNamedPipeW(MSI_LAUNCH_PIPE_NAME, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 2, 4096, 4096, 0, &sa);
        if (next == INVALID_HANDLE_VALUE)
        {
            err = GetLastError();
            HandleLaunchClient(pipe);
            DisconnectNamedPipe(pipe);
            /* keep the instance we have (the name stays ours) and try again with the next client */
            WARN("could not create the next instance of the launch pipe: %lu\n", err);
            continue;
        }

        HandleLaunchClient(pipe);
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        pipe = next;
    }

    CloseHandle(pipe);
    CloseHandle(ov.hEvent);
    LocalFree(sa.lpSecurityDescriptor);
    return 0;
}

#else /* __REACTOS__ */

static DWORD WINAPI ServiceExecutionThread(LPVOID param)
{
    WaitForSingleObject(kill_event, INFINITE);

    return 0;
}

#endif

static BOOL StartServiceThread(void)
{
    DWORD id;

    thread = CreateThread(0, 0, ServiceExecutionThread, 0, 0, &id);
    if (!thread)
    {
        report_error("Failed to create thread\n");
        return FALSE;
    }

    return TRUE;
}

static void WINAPI ServiceMain(DWORD argc, LPSTR *argv)
{
    hstatus = RegisterServiceCtrlHandlerA("MSIServer", ServiceCtrlHandler);
    if (!hstatus)
    {
        report_error("Failed to register service ctrl handler\n");
        return;
    }

    UpdateSCMStatus(SERVICE_START_PENDING, NO_ERROR, 0);

    kill_event = CreateEventW(0, TRUE, FALSE, 0);
    if (!kill_event)
    {
        report_error("Failed to create event\n");
        KillService();
        UpdateSCMStatus(SERVICE_STOPPED, NO_ERROR, 0);
        return;
    }

    if (!StartServiceThread())
    {
        KillService();
        UpdateSCMStatus(SERVICE_STOPPED, NO_ERROR, 0);
        return;
    }

    UpdateSCMStatus(SERVICE_RUNNING, NO_ERROR, 0);
    WaitForSingleObject(thread, INFINITE);
#ifdef __REACTOS__
    UpdateSCMStatus(SERVICE_STOPPED, service_exit_code, 0);
#else
    UpdateSCMStatus(SERVICE_STOPPED, NO_ERROR, 0);
#endif
}

DWORD DoService(void)
{
    char service_name[] = "MSIServer";

    const SERVICE_TABLE_ENTRYA service[] =
    {
        {service_name, ServiceMain},
        {NULL, NULL},
    };

    WINE_TRACE("Starting MSIServer service\n");

    if (!StartServiceCtrlDispatcherA(service))
    {
        report_error("Failed to start MSIServer service\n");
        return 1;
    }

    return 0;
}
