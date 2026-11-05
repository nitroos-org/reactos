/*
 *  ReactOS kernel
 *  Copyright (C) 2005 ReactOS Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
/*
 * COPYRIGHT:        See COPYING in the top level directory
 * PROJECT:          ReactOS kernel
 * FILE:             base/services/umpnpmgr/install.c
 * PURPOSE:          Device installer
 * PROGRAMMER:       Eric Kohl (eric.kohl@reactos.org)
 *                   Hervé Poussineau (hpoussin@reactos.org)
 *                   Colin Finck (colin@reactos.org)
 */

/* INCLUDES *****************************************************************/

#include "precomp.h"

#define NDEBUG
#include <debug.h>


/* GLOBALS ******************************************************************/

HANDLE hUserToken = NULL;
CRITICAL_SECTION UserTokenLock; /* guards hUserToken: PNP_ReportLogOn writes it, InstallDevice duplicates it */
HANDLE hInstallEvent = NULL;
HANDLE hNoPendingInstalls = NULL;
HANDLE hUserLogOnEvent = NULL; /* auto-reset: set by PNP_ReportLogOn, wakes the install thread */

/* Device-install event list */
HANDLE hDeviceInstallListMutex;
LIST_ENTRY DeviceInstallListHead;
HANDLE hDeviceInstallListNotEmpty;

DWORD
CreatePnpInstallEventSecurity(
    _Out_ PSECURITY_DESCRIPTOR *EventSd);

/* Bounds, so that an install process that dies or hangs cannot block the install queue forever */
#define PNP_PIPE_CONNECT_TIMEOUT    (60 * 1000)         /* the process must connect within 60 s */
#define PNP_DRVINST_TIMEOUT         (10 * 60 * 1000)    /* the service-side install gets 10 min */

/* The things of an install process that outlive RunInstallProcess (the restart page) */
typedef struct _PNP_DETACHED_INSTALL
{
    HANDLE hProcess;
    HANDLE hThread;
    HANDLE hPipe;
    HANDLE hIoEvent;
    HANDLE hInstallEvent;
    LPVOID Environment;
} PNP_DETACHED_INSTALL, *PPNP_DETACHED_INSTALL;

/* FUNCTIONS *****************************************************************/

/* Waits for the restart page to end, then closes what RunInstallProcess handed over */
static DWORD WINAPI
DetachedInstallThread(LPVOID Context)
{
    PPNP_DETACHED_INSTALL Detached = Context;

    WaitForSingleObject(Detached->hProcess, INFINITE);
    CloseHandle(Detached->hProcess);
    CloseHandle(Detached->hThread);
    CloseHandle(Detached->hPipe);
    CloseHandle(Detached->hIoEvent);
    CloseHandle(Detached->hInstallEvent);
    if (Detached->Environment)
        DestroyEnvironmentBlock(Detached->Environment);
    HeapFree(GetProcessHeap(), 0, Detached);
    return 0;
}

/*
 * Waits for an overlapped operation on the install pipe, but not longer than
 * Timeout, and not after the install process has died (it can no longer
 * connect or read). On failure the operation is cancelled and has completed.
 */
static BOOL
WaitPipeOperation(
    _In_ HANDLE hPipe,
    _Inout_ LPOVERLAPPED Overlapped,
    _In_ HANDLE hProcess,
    _In_ DWORD Timeout,
    _In_ PCSTR Operation)
{
    HANDLE Handles[2];
    DWORD Wait, Bytes;

    Handles[0] = Overlapped->hEvent;
    Handles[1] = hProcess;
    Wait = WaitForMultipleObjects(2, Handles, FALSE, Timeout);
    if (Wait == WAIT_OBJECT_0)
        return GetOverlappedResult(hPipe, Overlapped, &Bytes, FALSE);

    if (Wait == WAIT_TIMEOUT)
        DPRINT1("The install process did not %s the pipe within %lu ms\n", Operation, Timeout);
    else
        DPRINT1("The install process exited before it could %s the pipe\n", Operation);

    CancelIo(hPipe);
    WaitForSingleObject(Overlapped->hEvent, 5000);
    return FALSE;
}

static BOOL
WritePipeTimeout(
    _In_ HANDLE hPipe,
    _In_ HANDLE hEvent,
    _In_ HANDLE hProcess,
    _In_reads_bytes_(Size) LPCVOID Data,
    _In_ DWORD Size)
{
    OVERLAPPED Overlapped;
    DWORD Written;

    ZeroMemory(&Overlapped, sizeof(Overlapped));
    Overlapped.hEvent = hEvent;
    ResetEvent(hEvent);
    if (WriteFile(hPipe, Data, Size, &Written, &Overlapped))
        return TRUE;
    if (GetLastError() != ERROR_IO_PENDING)
        return FALSE;
    return WaitPipeOperation(hPipe, &Overlapped, hProcess, PNP_PIPE_CONNECT_TIMEOUT, "read from");
}

/*
 * The install pipe of a process in the user's session: SYSTEM and
 * Administrators as before, and read access for that user only (the default
 * DACL of the service's token does not let a standard user open it).
 */
static PSECURITY_DESCRIPTOR
CreateUserPipeSecurity(
    _In_ HANDLE hToken)
{
    BYTE Buffer[256];
    PTOKEN_USER User = (PTOKEN_USER)Buffer;
    DWORD Size;
    LPWSTR SidString = NULL;
    WCHAR Sddl[160];
    PSECURITY_DESCRIPTOR Sd = NULL;

    if (!GetTokenInformation(hToken, TokenUser, Buffer, sizeof(Buffer), &Size) ||
        !ConvertSidToStringSidW(User->User.Sid, &SidString))
    {
        DPRINT1("Cannot get the user of the token, error %lu\n", GetLastError());
        return NULL;
    }

    if (_snwprintf(Sddl, _countof(Sddl), L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;%s)", SidString) > 0)
    {
        Sddl[_countof(Sddl) - 1] = UNICODE_NULL;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(Sddl, SDDL_REVISION_1, &Sd, NULL))
        {
            DPRINT1("ConvertStringSecurityDescriptorToSecurityDescriptorW failed, error %lu\n", GetLastError());
            Sd = NULL;
        }
    }

    LocalFree(SidString);
    return Sd;
}


/*
 * Starts one install process for DeviceInstance and waits for it. With
 * hToken == NULL the process is drvinst.exe in the service's own context
 * (SYSTEM), with no UI, as DrvInst.exe on Windows: it does the driver search
 * and every registry and file write of the install. Otherwise it is the
 * newdev.dll wizard (ClientSideInstall) in the user's session, as that user.
 * Both read the device and the UI mode (NEWDEV_UI_*) from the same pipe and
 * signal the event on success.
 */
static BOOL
RunInstallProcess(
    _In_ PCWSTR DeviceInstance,
    _In_opt_ HANDLE hToken,
    _In_ DWORD UiMode,
    _Out_opt_ PDWORD ExitCode)
{
    BOOL DeviceInstalled = FALSE;
    DWORD Value;
    DWORD ErrCode;
    HANDLE hInstallEvent;
    HANDLE hPipe = INVALID_HANDLE_VALUE;
    HANDLE hIoEvent = NULL;
    OVERLAPPED Overlapped;
    BOOL Abandon = FALSE, PassedAll;
    WCHAR DrvInstPath[MAX_PATH];
    UINT SystemDirLength;
    LPVOID Environment = NULL;
    PROCESS_INFORMATION ProcessInfo;
    STARTUPINFOW StartupInfo;
    UUID RandomUuid;
    SECURITY_ATTRIBUTES EventAttrs;
    PSECURITY_DESCRIPTOR EventSd;
    SECURITY_ATTRIBUTES PipeAttrs;
    PSECURITY_DESCRIPTOR PipeSd = NULL;

    /* The following lengths are constant (see below), they cannot overflow */
    WCHAR CommandLine[MAX_PATH + 100];
    WCHAR InstallEventName[73];
    WCHAR PipeName[74];
    WCHAR UuidString[39];

    ZeroMemory(&ProcessInfo, sizeof(ProcessInfo));
    if (ExitCode)
        *ExitCode = ERROR_GEN_FAILURE;

    /* Create a random UUID for the named pipe & event*/
    UuidCreate(&RandomUuid);
    _swprintf(UuidString, L"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        RandomUuid.Data1, RandomUuid.Data2, RandomUuid.Data3,
        RandomUuid.Data4[0], RandomUuid.Data4[1], RandomUuid.Data4[2],
        RandomUuid.Data4[3], RandomUuid.Data4[4], RandomUuid.Data4[5],
        RandomUuid.Data4[6], RandomUuid.Data4[7]);

    ErrCode = CreatePnpInstallEventSecurity(&EventSd);
    if (ErrCode != ERROR_SUCCESS)
    {
        DPRINT1("CreatePnpInstallEventSecurity failed with error %u\n", GetLastError());
        return FALSE;
    }

    /* Set up the security attributes for the event */
    EventAttrs.nLength = sizeof(SECURITY_ATTRIBUTES);
    EventAttrs.lpSecurityDescriptor = EventSd;
    EventAttrs.bInheritHandle = FALSE;

    /* Create the event */
    wcscpy(InstallEventName, L"Global\\PNP_Device_Install_Event_0.");
    wcscat(InstallEventName, UuidString);
    hInstallEvent = CreateEventW(&EventAttrs, TRUE, FALSE, InstallEventName);
    HeapFree(GetProcessHeap(), 0, EventSd);
    if (!hInstallEvent)
    {
        DPRINT1("CreateEventW('%ls') failed with error %lu\n", InstallEventName, GetLastError());
        goto cleanup;
    }

    /* Create the named pipe */
    wcscpy(PipeName, L"\\\\.\\pipe\\PNP_Device_Install_Pipe_0.");
    wcscat(PipeName, UuidString);
    if (hToken)
    {
        PipeSd = CreateUserPipeSecurity(hToken);
        if (!PipeSd)
            goto cleanup;
        PipeAttrs.nLength = sizeof(PipeAttrs);
        PipeAttrs.lpSecurityDescriptor = PipeSd;
        PipeAttrs.bInheritHandle = FALSE;
    }
    /* Overlapped, so that waiting for the install process can time out; and it must be
       the first instance of this (random) name, so nothing else can have created it */
    hPipe = CreateNamedPipeW(PipeName,
                             PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                             PIPE_TYPE_BYTE, 1, 512, 512, 0, PipeSd ? &PipeAttrs : NULL);
    if (PipeSd)
        LocalFree(PipeSd);
    if (hPipe == INVALID_HANDLE_VALUE)
    {
        DPRINT1("CreateNamedPipeW failed with error %u\n", GetLastError());
        goto cleanup;
    }

    ZeroMemory(&StartupInfo, sizeof(StartupInfo));
    StartupInfo.cb = sizeof(StartupInfo);

    if (hToken)
    {
        /* Launch rundll32 to call ClientSideInstallW */
        wcscpy(CommandLine, L"rundll32.exe newdev.dll,ClientSideInstall ");
        wcscat(CommandLine, PipeName);

        /* newdev has to run under the environment of the current user */
        if (!CreateEnvironmentBlock(&Environment, hToken, FALSE))
        {
            DPRINT1("CreateEnvironmentBlock failed with error %d\n", GetLastError());
            goto cleanup;
        }

        if (!CreateProcessAsUserW(hToken, NULL, CommandLine, NULL, NULL, FALSE, CREATE_UNICODE_ENVIRONMENT, Environment, NULL, &StartupInfo, &ProcessInfo))
        {
            DPRINT1("CreateProcessAsUserW failed with error %u\n", GetLastError());
            goto cleanup;
        }
    }
    else
    {
        /* The service-side installer runs as SYSTEM and never shows UI. It is started by its full
           path in the system directory, so that no search can find another program of that name. */
        SystemDirLength = GetSystemDirectoryW(DrvInstPath, _countof(DrvInstPath));
        if (SystemDirLength == 0 || SystemDirLength + 13 >= _countof(DrvInstPath))
        {
            DPRINT1("GetSystemDirectoryW failed with error %u\n", GetLastError());
            goto cleanup;
        }
        wcscat(DrvInstPath, L"\\drvinst.exe");
        _snwprintf(CommandLine, _countof(CommandLine), L"\"%s\" %s", DrvInstPath, PipeName);
        CommandLine[_countof(CommandLine) - 1] = UNICODE_NULL;

        if (!CreateProcessW(DrvInstPath, CommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &StartupInfo, &ProcessInfo))
        {
            DPRINT1("CreateProcessW failed with error %u\n", GetLastError());
            goto cleanup;
        }
    }

    /* Wait (bounded) for the process to connect to our pipe. If it dies or hangs first, this install fails. */
    hIoEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!hIoEvent)
    {
        DPRINT1("CreateEventW failed with error %u\n", GetLastError());
        goto cleanup;
    }
    ZeroMemory(&Overlapped, sizeof(Overlapped));
    Overlapped.hEvent = hIoEvent;
    if (!ConnectNamedPipe(hPipe, &Overlapped))
    {
        ErrCode = GetLastError();
        if (ErrCode == ERROR_IO_PENDING)
        {
            if (!WaitPipeOperation(hPipe, &Overlapped, ProcessInfo.hProcess, PNP_PIPE_CONNECT_TIMEOUT, "connect to"))
            {
                DPRINT1("Install process for '%ls' did not connect, install abandoned\n", DeviceInstance);
                Abandon = TRUE;
                goto cleanup;
            }
        }
        else if (ErrCode != ERROR_PIPE_CONNECTED)
        {
            DPRINT1("ConnectNamedPipe failed with error %u\n", ErrCode);
            goto cleanup;
        }
    }

    /* Pass the data. The following output is partly compatible to Windows XP SP2 (researched using a modified newdev.dll to log this stuff).
       I couldn't figure out what the UI value means under WinXP. It's usually 0 in my tests, but was also 5 once.
       Therefore that value is entirely ReactOS-specific. We use it to pass the UI mode.
       drvinst.exe never shows UI; for it the value says whether the wizard follows if it finds no driver. */
    Value = sizeof(InstallEventName);
    PassedAll = WritePipeTimeout(hPipe, hIoEvent, ProcessInfo.hProcess, &Value, sizeof(Value)) &&
                WritePipeTimeout(hPipe, hIoEvent, ProcessInfo.hProcess, InstallEventName, Value) &&
                WritePipeTimeout(hPipe, hIoEvent, ProcessInfo.hProcess, &UiMode, sizeof(UiMode));
    if (PassedAll)
    {
        Value = (wcslen(DeviceInstance) + 1) * sizeof(WCHAR);
        PassedAll = WritePipeTimeout(hPipe, hIoEvent, ProcessInfo.hProcess, &Value, sizeof(Value)) &&
                    WritePipeTimeout(hPipe, hIoEvent, ProcessInfo.hProcess, DeviceInstance, Value);
    }
    if (!PassedAll)
    {
        DPRINT1("Cannot pass the device to the install process, error %u\n", GetLastError());
        Abandon = TRUE;
        goto cleanup;
    }

    /* The restart page is a notification: Windows goes on installing while it is open, so the queue does not
       wait for it. A thread waits for the process and closes the handles (the pipe stays open meanwhile). */
    if (hToken && UiMode == NEWDEV_UI_RESTART_PAGE)
    {
        PPNP_DETACHED_INSTALL Detached = HeapAlloc(GetProcessHeap(), 0, sizeof(*Detached));
        HANDLE hWaiter = NULL;

        if (Detached)
        {
            Detached->hProcess = ProcessInfo.hProcess;
            Detached->hThread = ProcessInfo.hThread;
            Detached->hPipe = hPipe;
            Detached->hIoEvent = hIoEvent;
            Detached->hInstallEvent = hInstallEvent;
            Detached->Environment = Environment;
            hWaiter = CreateThread(NULL, 0, DetachedInstallThread, Detached, 0, NULL);
            if (hWaiter)
            {
                CloseHandle(hWaiter);
                /* The thread owns them now */
                ZeroMemory(&ProcessInfo, sizeof(ProcessInfo));
                hPipe = INVALID_HANDLE_VALUE;
                hIoEvent = NULL;
                hInstallEvent = NULL;
                Environment = NULL;
                DeviceInstalled = TRUE;
                goto cleanup;
            }
            HeapFree(GetProcessHeap(), 0, Detached);
        }
        /* Could not detach: wait for it as before */
    }

    /* Wait for the install process to finish. The service-side install is bounded; the wizard
       and the restart page (when it could not be detached) wait for the user, so they are not. */
    if (WaitForSingleObject(ProcessInfo.hProcess, hToken ? INFINITE : PNP_DRVINST_TIMEOUT) == WAIT_TIMEOUT)
    {
        DPRINT1("The install of '%ls' did not finish within %lu ms, terminating it\n", DeviceInstance, PNP_DRVINST_TIMEOUT);
        TerminateProcess(ProcessInfo.hProcess, ERROR_TIMEOUT);
        WaitForSingleObject(ProcessInfo.hProcess, 5000);
        if (ExitCode)
            *ExitCode = ERROR_TIMEOUT;
        goto cleanup;
    }

    if (ExitCode && !GetExitCodeProcess(ProcessInfo.hProcess, ExitCode))
        *ExitCode = ERROR_GEN_FAILURE;

    /* If the event got signalled, this is success. drvinst also reports success by its exit code,
       which covers an event it could not open after the install had succeeded. */
    DeviceInstalled = WaitForSingleObject(hInstallEvent, 0) == WAIT_OBJECT_0;
    if (!DeviceInstalled && !hToken && ExitCode &&
        (*ExitCode == ERROR_SUCCESS || *ExitCode == ERROR_SUCCESS_REBOOT_REQUIRED))
        DeviceInstalled = TRUE;

cleanup:
    /* A process that failed to connect or to read is of no use any more */
    if (Abandon && ProcessInfo.hProcess && WaitForSingleObject(ProcessInfo.hProcess, 0) == WAIT_TIMEOUT)
    {
        TerminateProcess(ProcessInfo.hProcess, ERROR_TIMEOUT);
        WaitForSingleObject(ProcessInfo.hProcess, 5000);
    }

    if (hIoEvent)
        CloseHandle(hIoEvent);

    if (hInstallEvent)
        CloseHandle(hInstallEvent);

    if (hPipe != INVALID_HANDLE_VALUE)
        CloseHandle(hPipe);

    if (Environment)
        DestroyEnvironmentBlock(Environment);

    if (ProcessInfo.hProcess)
        CloseHandle(ProcessInfo.hProcess);

    if (ProcessInfo.hThread)
        CloseHandle(ProcessInfo.hThread);

    return DeviceInstalled;
}


static BOOL
UserIsLoggedOn(VOID)
{
    BOOL LoggedOn;

    EnterCriticalSection(&UserTokenLock);
    LoggedOn = (hUserToken != NULL);
    LeaveCriticalSection(&UserTokenLock);
    return LoggedOn;
}

/*
 * Installs one device. With ShowWizard and nobody logged on, the install runs without UI; if that finds
 * no driver, *NeedWizard is set (when given) so that the caller offers the wizard after the logon.
 */
static BOOL
InstallDevice(PCWSTR DeviceInstance, BOOL ShowWizard, PBOOL NeedWizard)
{
    BOOL DeviceInstalled;
    DWORD BytesWritten;
    DWORD Value;
    DWORD UiMode;
    DWORD ExitCode = ERROR_SUCCESS;
    HKEY DeviceKey;
    HANDLE hToken = NULL;

    DPRINT("InstallDevice(%S, %d)\n", DeviceInstance, ShowWizard);

    if (NeedWizard)
        *NeedWizard = FALSE;

    if (RegOpenKeyExW(hEnumKey,
                      DeviceInstance,
                      0,
                      KEY_QUERY_VALUE,
                      &DeviceKey) == ERROR_SUCCESS)
    {
        if (RegQueryValueExW(DeviceKey,
                             L"Class",
                             NULL,
                             NULL,
                             NULL,
                             NULL) == ERROR_SUCCESS)
        {
            DPRINT("No need to install: %S\n", DeviceInstance);
            RegCloseKey(DeviceKey);
            return TRUE;
        }

        BytesWritten = sizeof(DWORD);
        if (RegQueryValueExW(DeviceKey,
                             L"ConfigFlags",
                             NULL,
                             NULL,
                             (PBYTE)&Value,
                             &BytesWritten) == ERROR_SUCCESS)
        {
            if (Value & CONFIGFLAG_FAILEDINSTALL)
            {
                DPRINT("No need to install: %S\n", DeviceInstance);
                RegCloseKey(DeviceKey);
                return TRUE;
            }
        }

        RegCloseKey(DeviceKey);
    }

    DPRINT1("Installing: %S\n", DeviceInstance);

    /* Take the user's token once: PNP_ReportLogOn replaces and closes hUserToken on another
       RPC thread, under UserTokenLock, so the duplicate is made under that lock too. */
    if (ShowWizard)
    {
        EnterCriticalSection(&UserTokenLock);
        if (hUserToken != NULL &&
            !DuplicateHandle(GetCurrentProcess(), hUserToken, GetCurrentProcess(), &hToken, 0, FALSE, DUPLICATE_SAME_ACCESS))
        {
            DPRINT1("Cannot duplicate the user token, error %lu\n", GetLastError());
            hToken = NULL;
        }
        LeaveCriticalSection(&UserTokenLock);
    }

    /* UI is only possible in an interactive user's session */
    UiMode = (ShowWizard && hToken != NULL) ? NEWDEV_UI_WIZARD : NEWDEV_UI_HIDDEN;

    /* As on Windows: the install itself (driver search in the system INF
       directory, class installers, registry and file writes) runs here in the
       service context, as SYSTEM, for administrators and standard users alike. */
    DeviceInstalled = RunInstallProcess(DeviceInstance, NULL, UiMode, &ExitCode);

    if (DeviceInstalled)
    {
        /* The UI of the install stays in the user's session: the restart page */
        if (ExitCode == ERROR_SUCCESS_REBOOT_REQUIRED && UiMode != NEWDEV_UI_HIDDEN)
            RunInstallProcess(DeviceInstance, hToken, NEWDEV_UI_RESTART_PAGE, NULL);
    }
    else if (UiMode == NEWDEV_UI_WIZARD)
    {
        /* No driver found: the wizard lets the user point to one, in the user's
           session and as the user. newdev.dll allows that to administrators only. */
        DPRINT1("No driver installed for '%ws', starting the wizard\n", DeviceInstance);
        DeviceInstalled = RunInstallProcess(DeviceInstance, hToken, NEWDEV_UI_WIZARD, NULL);
    }
    else if (ShowWizard && NeedWizard)
    {
        /* Nobody is logged on yet: the wizard follows at the logon */
        *NeedWizard = TRUE;
    }

    if (hToken)
        CloseHandle(hToken);

    if (!DeviceInstalled)
    {
        DPRINT1("InstallDevice failed for DeviceInstance '%ws'\n", DeviceInstance);
    }

    return DeviceInstalled;
}


static LONG
ReadRegSzKey(
    IN HKEY hKey,
    IN LPCWSTR pszKey,
    OUT LPWSTR* pValue)
{
    LONG rc;
    DWORD dwType;
    DWORD cbData = 0;
    LPWSTR Value;

    if (!pValue)
        return ERROR_INVALID_PARAMETER;

    *pValue = NULL;
    rc = RegQueryValueExW(hKey, pszKey, NULL, &dwType, NULL, &cbData);
    if (rc != ERROR_SUCCESS)
        return rc;
    if (dwType != REG_SZ)
        return ERROR_FILE_NOT_FOUND;
    Value = HeapAlloc(GetProcessHeap(), 0, cbData + sizeof(WCHAR));
    if (!Value)
        return ERROR_NOT_ENOUGH_MEMORY;
    rc = RegQueryValueExW(hKey, pszKey, NULL, NULL, (LPBYTE)Value, &cbData);
    if (rc != ERROR_SUCCESS)
    {
        HeapFree(GetProcessHeap(), 0, Value);
        return rc;
    }
    /* NULL-terminate the string */
    Value[cbData / sizeof(WCHAR)] = '\0';

    *pValue = Value;
    return ERROR_SUCCESS;
}


BOOL
SetupIsActive(VOID)
{
    HKEY hKey = NULL;
    DWORD regType, active, size;
    LONG rc;
    BOOL ret = FALSE;

    rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\Setup", 0, KEY_QUERY_VALUE, &hKey);
    if (rc != ERROR_SUCCESS)
        goto cleanup;

    size = sizeof(DWORD);
    rc = RegQueryValueExW(hKey, L"SystemSetupInProgress", NULL, &regType, (LPBYTE)&active, &size);
    if (rc != ERROR_SUCCESS)
        goto cleanup;
    if (regType != REG_DWORD || size != sizeof(DWORD))
        goto cleanup;

    ret = (active != 0);

cleanup:
    if (hKey != NULL)
        RegCloseKey(hKey);

    DPRINT("System setup in progress? %S\n", ret ? L"YES" : L"NO");

    return ret;
}


/**
 * @brief
 * Creates a security descriptor for the PnP event
 * installation.
 *
 * @param[out] EventSd
 * A pointer to an allocated security descriptor
 * for the event.
 *
 * @return
 * ERROR_SUCCESS is returned if the function has
 * successfully created the descriptor, otherwise
 * a Win32 error code is returned.
 *
 * @remarks
 * Only admins and local system have full power
 * over this event as privileged users can install
 * devices on a system.
 */
DWORD
CreatePnpInstallEventSecurity(
    _Out_ PSECURITY_DESCRIPTOR *EventSd)
{
    DWORD ErrCode;
    PACL Dacl;
    ULONG DaclSize;
    SECURITY_DESCRIPTOR AbsoluteSd;
    ULONG Size = 0;
    PSECURITY_DESCRIPTOR RelativeSd = NULL;
    PSID SystemSid = NULL, AdminsSid = NULL;
    static SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};

    if (!AllocateAndInitializeSid(&NtAuthority,
                                  1,
                                  SECURITY_LOCAL_SYSTEM_RID,
                                  0, 0, 0, 0, 0, 0, 0,
                                  &SystemSid))
    {
        return GetLastError();
    }

    if (!AllocateAndInitializeSid(&NtAuthority,
                                  2,
                                  SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS,
                                  0, 0, 0, 0, 0, 0,
                                  &AdminsSid))
    {
        ErrCode = GetLastError();
        goto Quit;
    }

    /* Compute the size needed for the DACL and allocate it */
    DaclSize = sizeof(ACL) +
               sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(SystemSid) +
               sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(AdminsSid);

    Dacl = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, DaclSize);
    if (!Dacl)
    {
        ErrCode = ERROR_OUTOFMEMORY;
        goto Quit;
    }
    if (!InitializeAcl(Dacl, DaclSize, ACL_REVISION))
    {
        ErrCode = GetLastError();
        goto Quit;
    }

    if (!AddAccessAllowedAce(Dacl,
                             ACL_REVISION,
                             EVENT_ALL_ACCESS,
                             SystemSid))
    {
        ErrCode = GetLastError();
        goto Quit;
    }

    if (!AddAccessAllowedAce(Dacl,
                             ACL_REVISION,
                             EVENT_ALL_ACCESS,
                             AdminsSid))
    {
        ErrCode = GetLastError();
        goto Quit;
    }

    if (!InitializeSecurityDescriptor(&AbsoluteSd, SECURITY_DESCRIPTOR_REVISION))
    {
        ErrCode = GetLastError();
        goto Quit;
    }

    if (!SetSecurityDescriptorDacl(&AbsoluteSd, TRUE, Dacl, FALSE))
    {
        ErrCode = GetLastError();
        goto Quit;
    }

    if (!SetSecurityDescriptorOwner(&AbsoluteSd, SystemSid, FALSE))
    {
        ErrCode = GetLastError();
        goto Quit;
    }

    if (!SetSecurityDescriptorGroup(&AbsoluteSd, AdminsSid, FALSE))
    {
        ErrCode = GetLastError();
        goto Quit;
    }

    /* Retrieve the size needed for the relative SD */
    if (MakeSelfRelativeSD(&AbsoluteSd, NULL, &Size) ||
        (GetLastError() != ERROR_INSUFFICIENT_BUFFER))
    {
        ErrCode = GetLastError();
        goto Quit;
    }

    /* Build the relative SD */
    RelativeSd = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Size);
    if (RelativeSd == NULL)
    {
        ErrCode = ERROR_OUTOFMEMORY;
        goto Quit;
    }
    if (!MakeSelfRelativeSD(&AbsoluteSd, RelativeSd, &Size))
    {
        ErrCode = GetLastError();
        HeapFree(GetProcessHeap(), 0, RelativeSd);
        goto Quit;
    }

    *EventSd = RelativeSd;
    ErrCode = ERROR_SUCCESS;

Quit:
    if (SystemSid)
        FreeSid(SystemSid);

    if (AdminsSid)
        FreeSid(AdminsSid);

    if (Dacl)
        HeapFree(GetProcessHeap(), 0, Dacl);

    return ErrCode;
}


static BOOL
IsConsoleBoot(VOID)
{
    HKEY ControlKey = NULL;
    LPWSTR SystemStartOptions = NULL;
    LPWSTR CurrentOption, NextOption; /* Pointers into SystemStartOptions */
    BOOL ConsoleBoot = FALSE;
    LONG rc;

    rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                       L"SYSTEM\\CurrentControlSet\\Control",
                       0,
                       KEY_QUERY_VALUE,
                       &ControlKey);
    if (rc != ERROR_SUCCESS)
        goto cleanup;

    rc = ReadRegSzKey(ControlKey, L"SystemStartOptions", &SystemStartOptions);
    if (rc != ERROR_SUCCESS)
        goto cleanup;

    /* Check for CONSOLE switch in SystemStartOptions */
    CurrentOption = SystemStartOptions;
    while (CurrentOption)
    {
        NextOption = wcschr(CurrentOption, L' ');
        if (NextOption)
            *NextOption = L'\0';
        if (_wcsicmp(CurrentOption, L"CONSOLE") == 0)
        {
            DPRINT("Found %S. Switching to console boot\n", CurrentOption);
            ConsoleBoot = TRUE;
            goto cleanup;
        }
        CurrentOption = NextOption ? NextOption + 1 : NULL;
    }

cleanup:
    if (ControlKey != NULL)
        RegCloseKey(ControlKey);
    HeapFree(GetProcessHeap(), 0, SystemStartOptions);
    return ConsoleBoot;
}


FORCEINLINE
BOOL
IsUISuppressionAllowed(VOID)
{
    /* Display the newdev.dll wizard UI only if it's allowed */
    return (g_IsUISuppressed || GetSuppressNewUIValue());
}


/* Loop to install all queued devices installations */
DWORD
WINAPI
DeviceInstallThread(LPVOID lpParameter)
{
    PLIST_ENTRY ListEntry;
    DeviceInstallParams* Params;
    LIST_ENTRY WaitingForUser;
    BOOL NeedWizard;

    UNREFERENCED_PARAMETER(lpParameter);

    InitializeListHead(&WaitingForUser);

    // Step 1: install all drivers which were configured during the boot

    DPRINT("Step 1: Installing devices configured during the boot\n");

    PWSTR deviceList;

    while (TRUE)
    {
        ULONG devListSize;
        DWORD status = PNP_GetDeviceListSize(NULL, NULL, &devListSize, 0);
        if (status != CR_SUCCESS)
        {
            goto Step2;
        }

        deviceList = HeapAlloc(GetProcessHeap(), 0, devListSize * sizeof(WCHAR));
        if (!deviceList)
        {
            goto Step2;
        }

        status = PNP_GetDeviceList(NULL, NULL, deviceList, &devListSize, 0);
        if (status == CR_BUFFER_SMALL)
        {
            HeapFree(GetProcessHeap(), 0, deviceList);
        }
        else if (status != CR_SUCCESS)
        {
            DPRINT1("PNP_GetDeviceList failed with error %u\n", status);
            goto Cleanup;
        }
        else // status == CR_SUCCESS
        {
            break;
        }
    }

    for (PWSTR currentDev = deviceList;
         currentDev[0] != UNICODE_NULL;
         currentDev += lstrlenW(currentDev) + 1)
    {
        InstallDevice(currentDev, FALSE, NULL);
    }

Cleanup:
    HeapFree(GetProcessHeap(), 0, deviceList);

    // Step 2: start the wait-loop for newly added devices
Step2:

    DPRINT("Step 2: Starting the wait-loop\n");

    /* Devices are installed from here on, whether or not a user is logged on (Windows installs with
       nobody logged on): the install itself runs service-side. Only the wizard needs a user. */
    BOOL showWizard = !SetupIsActive() && !IsConsoleBoot();

    while (TRUE)
    {
        /* Devices for which no driver was found before the logon get the wizard now */
        if (!IsListEmpty(&WaitingForUser) && UserIsLoggedOn())
        {
            while (!IsListEmpty(&WaitingForUser))
            {
                ListEntry = RemoveHeadList(&WaitingForUser);
                Params = CONTAINING_RECORD(ListEntry, DeviceInstallParams, ListEntry);
                InstallDevice(Params->DeviceIds, showWizard && !IsUISuppressionAllowed(), NULL);
                HeapFree(GetProcessHeap(), 0, Params);
            }
        }

        /* Dequeue the next oldest device-install event */
        WaitForSingleObject(hDeviceInstallListMutex, INFINITE);
        ListEntry = (IsListEmpty(&DeviceInstallListHead)
                        ? NULL : RemoveHeadList(&DeviceInstallListHead));
        ReleaseMutex(hDeviceInstallListMutex);

        if (ListEntry == NULL)
        {
            HANDLE WakeUp[2];

            SetEvent(hNoPendingInstalls);
            WakeUp[0] = hDeviceInstallListNotEmpty;
            WakeUp[1] = hUserLogOnEvent;
            WaitForMultipleObjects(hUserLogOnEvent ? 2 : 1, WakeUp, FALSE, INFINITE);
        }
        else
        {
            ResetEvent(hNoPendingInstalls);
            Params = CONTAINING_RECORD(ListEntry, DeviceInstallParams, ListEntry);
            NeedWizard = FALSE;
            InstallDevice(Params->DeviceIds, showWizard && !IsUISuppressionAllowed(), &NeedWizard);
            if (NeedWizard)
                InsertTailList(&WaitingForUser, &Params->ListEntry);
            else
                HeapFree(GetProcessHeap(), 0, Params);
        }
    }

    return 0;
}
