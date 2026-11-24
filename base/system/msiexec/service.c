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

static BOOL IsElevatedAdministrator(HANDLE pipe)
{
    HANDLE token = NULL;
    TOKEN_ELEVATION elevation;
    DWORD size;
    BOOL ok = FALSE, member = FALSE;
    PSID admins = NULL;
    SID_IDENTIFIER_AUTHORITY nt = { SECURITY_NT_AUTHORITY };

    if (!ImpersonateNamedPipeClient(pipe))
        return FALSE;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token))
    {
        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size) && elevation.TokenIsElevated &&
            AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admins))
        {
            /* the thread has the client's token: an enabled Administrators group */
            ok = CheckTokenMembership(NULL, admins, &member) && member;
            FreeSid(admins);
        }
        CloseHandle(token);
    }
    RevertToSelf();
    return ok;
}

static WCHAR *DupString(const WCHAR *base, DWORD chars)
{
    WCHAR *s;

    if (chars == 0 || chars > MSI_LAUNCH_MAX_STRING || base[chars - 1] != 0)
        return NULL;
    s = HeapAlloc(GetProcessHeap(), 0, chars * sizeof(WCHAR));
    if (s) memcpy(s, base, chars * sizeof(WCHAR));
    return s;
}

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
        if (req->Arch != 32 && req->Arch != 64)
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

        if (c == 0 || c > MSI_LAUNCH_MAX_STRING || a > MSI_LAUNCH_MAX_STRING || d > MSI_LAUNCH_MAX_STRING)
            return ERROR_INVALID_PARAMETER;
        if (a && !(app = DupString(strings, a))) return ERROR_INVALID_PARAMETER;
        if (!(cmd = DupString(strings + a, c))) { HeapFree(GetProcessHeap(), 0, app); return ERROR_INVALID_PARAMETER; }
        if (d && !(cwd = DupString(strings + a + c, d))) { HeapFree(GetProcessHeap(), 0, app); HeapFree(GetProcessHeap(), 0, cmd); return ERROR_INVALID_PARAMETER; }
        if (!CreateProcessW(app, cmd, NULL, NULL, FALSE, 0, NULL, cwd, &si, &pi))
            error = GetLastError();
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

static void HandleLaunchClient(HANDLE pipe)
{
    BYTE *buffer;
    const DWORD buffer_size = sizeof(MSI_LAUNCH_REQUEST) + 3 * MSI_LAUNCH_MAX_STRING * sizeof(WCHAR);
    MSI_LAUNCH_REPLY reply;
    MSI_LAUNCH_REQUEST *req;
    OVERLAPPED ov;
    DWORD size = 0, client_pid = 0, error;
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
    if (!ReadFile(pipe, buffer, buffer_size, NULL, &ov) && GetLastError() == ERROR_IO_PENDING)
    {
        if (WaitForSingleObject(ov.hEvent, 10000) != WAIT_OBJECT_0)
        {
            CancelIo(pipe);
            goto done;  /* a client that does not send its request is dropped */
        }
    }
    if (!GetOverlappedResult(pipe, &ov, &size, FALSE) || size < sizeof(*req))
        goto done;

    total = (ULONG64)sizeof(*req) + ((ULONG64)req->ApplicationChars + req->CommandLineChars + req->DirectoryChars) * sizeof(WCHAR);
    if (req->Magic != MSI_LAUNCH_MAGIC || total > size)
        error = ERROR_INVALID_PARAMETER;
    else if (!GetNamedPipeClientProcessId(pipe, &client_pid) || client_pid != req->ClientPid)
        error = ERROR_ACCESS_DENIED;
    else if (!IsElevatedAdministrator(pipe))
        error = ERROR_ACCESS_DENIED;
    else if (!(client = OpenProcess(PROCESS_DUP_HANDLE, FALSE, client_pid)))
        error = GetLastError();
    else if ((error = LaunchProgram(req, client_pid, &process, &reply.ProcessId)) == ERROR_SUCCESS)
    {
        if (DuplicateHandle(GetCurrentProcess(), process, client, &dup, 0, FALSE, DUPLICATE_SAME_ACCESS))
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

    memset(&ov, 0, sizeof(ov) - sizeof(ov.hEvent));
    ResetEvent(ov.hEvent);
    if (!WriteFile(pipe, &reply, sizeof(reply), NULL, &ov) && GetLastError() == ERROR_IO_PENDING)
        WaitForSingleObject(ov.hEvent, 10000);
    FlushFileBuffers(pipe);

done:
    CloseHandle(ov.hEvent);
    HeapFree(GetProcessHeap(), 0, buffer);
}

static DWORD WINAPI ServiceExecutionThread(LPVOID param)
{
    SECURITY_ATTRIBUTES sa;
    OVERLAPPED ov;
    HANDLE pipe, wait[2];
    BOOL first = TRUE;

    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;
    sa.lpSecurityDescriptor = NULL;
    /* LocalSystem and the Administrators group only */
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1,
                                                              &sa.lpSecurityDescriptor, NULL))
    {
        report_error("Failed to build the security descriptor of the launch pipe\n");
        WaitForSingleObject(kill_event, INFINITE);
        return 0;
    }

    memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    wait[0] = kill_event;
    wait[1] = ov.hEvent;

    for (;;)
    {
        pipe = CreateNamedPipeW(MSI_LAUNCH_PIPE_NAME,
                                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | (first ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0),
                                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                                PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, &sa);
        if (pipe == INVALID_HANDLE_VALUE)
        {
            report_error("Failed to create the launch pipe\n");
            break;
        }
        first = FALSE;

        ResetEvent(ov.hEvent);
        if (!ConnectNamedPipe(pipe, &ov))
        {
            DWORD err = GetLastError();
            if (err == ERROR_IO_PENDING)
            {
                if (WaitForMultipleObjects(2, wait, FALSE, INFINITE) == WAIT_OBJECT_0)
                {
                    CancelIo(pipe);
                    CloseHandle(pipe);
                    break;
                }
            }
            else if (err != ERROR_PIPE_CONNECTED)
            {
                CloseHandle(pipe);
                continue;
            }
        }

        HandleLaunchClient(pipe);
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    }

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
    UpdateSCMStatus(SERVICE_STOPPED, NO_ERROR, 0);
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
