/*
 * PROJECT:     ReactOS DCOM launcher
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Start the service that hosts a COM class (AppID LocalService) for the activating client
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A COM class whose AppID has a LocalService value runs in that service. On Windows the client needs no
 * right on the service: the DCOM launcher (LocalSystem) starts it. The activating process (combase) asks
 * here when it may not start the service itself, which is the case for a standard user and most services.
 * Only the machine's registration is read (never the caller's own classes), the AppID's service parameters
 * are passed, and only a Win32 service is started.
 */

#define WIN32_NO_STATUS
#define _INC_WINDOWS
#define COM_NO_WINDOWS_H
#include <stdarg.h>
#include <stdio.h>
#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <winsvc.h>
#include <winerror.h>
#include <dcomlaunch_s.h>

#define NDEBUG
#include <debug.h>

/* A REG_SZ value of an HKLM key, NUL terminated; FALSE when it is missing or not a string */
static BOOL
ReadMachineString(PCWSTR SubKey, REGSAM View, PCWSTR Value, PWSTR Buffer, DWORD Cch)
{
    HKEY Key;
    DWORD Type, Size = (Cch - 1) * sizeof(WCHAR);
    LONG Error;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, SubKey, 0, KEY_QUERY_VALUE | View, &Key) != ERROR_SUCCESS)
        return FALSE;
    Error = RegQueryValueExW(Key, Value, NULL, &Type, (LPBYTE)Buffer, &Size);
    RegCloseKey(Key);
    if (Error != ERROR_SUCCESS || Type != REG_SZ)
        return FALSE;
    Buffer[Size / sizeof(WCHAR)] = UNICODE_NULL;
    return Buffer[0] != UNICODE_NULL;
}

HRESULT
__cdecl
DcomLaunchStartLocalService(
    handle_t BindingHandle,
    const GUID *Clsid)
{
    static const REGSAM Views[] = { KEY_WOW64_64KEY, KEY_WOW64_32KEY };
    WCHAR ClsidString[39], AppId[40], Key[96], Name[257], Params[512], *p;
    LPCWSTR Args[16];
    DWORD NumArgs = 0, Needed;
    LPQUERY_SERVICE_CONFIGW Config = NULL;
    SC_HANDLE Scm, Service;
    ULONG i;
    HRESULT hr;

    UNREFERENCED_PARAMETER(BindingHandle);

    if (Clsid == NULL)
        return E_INVALIDARG;

    _snwprintf(ClsidString, ARRAYSIZE(ClsidString), L"{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
               Clsid->Data1, Clsid->Data2, Clsid->Data3, Clsid->Data4[0], Clsid->Data4[1], Clsid->Data4[2],
               Clsid->Data4[3], Clsid->Data4[4], Clsid->Data4[5], Clsid->Data4[6], Clsid->Data4[7]);
    ClsidString[ARRAYSIZE(ClsidString) - 1] = UNICODE_NULL;

    wcscpy(Key, L"Software\\Classes\\CLSID\\");
    wcscat(Key, ClsidString);
    for (i = 0; i < ARRAYSIZE(Views); i++)
    {
        if (ReadMachineString(Key, Views[i], L"AppID", AppId, ARRAYSIZE(AppId)))
            break;
    }
    if (i == ARRAYSIZE(Views) || AppId[0] != L'{' || wcslen(AppId) != 38)
        return REGDB_E_CLASSNOTREG;

    wcscpy(Key, L"Software\\Classes\\AppID\\");
    wcscat(Key, AppId);
    if (!ReadMachineString(Key, KEY_WOW64_64KEY, L"LocalService", Name, ARRAYSIZE(Name)))
        return REGDB_E_CLASSNOTREG;

    /* Windows documents ServiceParameters; Wine used ServiceParams. Split on spaces. */
    if (ReadMachineString(Key, KEY_WOW64_64KEY, L"ServiceParameters", Params, ARRAYSIZE(Params)) ||
        ReadMachineString(Key, KEY_WOW64_64KEY, L"ServiceParams", Params, ARRAYSIZE(Params)))
    {
        for (p = Params; *p && NumArgs < ARRAYSIZE(Args); )
        {
            while (*p == L' ')
                *p++ = UNICODE_NULL;
            if (*p == UNICODE_NULL)
                break;
            Args[NumArgs++] = p;
            while (*p && *p != L' ')
                p++;
        }
    }

    Scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (Scm == NULL)
        return HRESULT_FROM_WIN32(GetLastError());
    Service = OpenServiceW(Scm, Name, SERVICE_START | SERVICE_QUERY_CONFIG);
    CloseServiceHandle(Scm);
    if (Service == NULL)
        return HRESULT_FROM_WIN32(GetLastError());

    hr = E_ACCESSDENIED;
    Needed = 8192; /* the most QueryServiceConfig returns */
    Config = HeapAlloc(GetProcessHeap(), 0, Needed);
    if (Config != NULL &&
        QueryServiceConfigW(Service, Config, Needed, &Needed) &&
        (Config->dwServiceType & SERVICE_WIN32))
    {
        DPRINT("Starting %S for %S\n", Name, ClsidString);
        if (StartServiceW(Service, NumArgs, NumArgs ? Args : NULL) ||
            GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
            hr = S_OK;
        else
            hr = HRESULT_FROM_WIN32(GetLastError());
    }
    if (Config != NULL)
        HeapFree(GetProcessHeap(), 0, Config);
    CloseServiceHandle(Service);
    return hr;
}

VOID
StartServiceStartServer(VOID)
{
    RPC_STATUS Status;

    Status = RpcServerUseProtseqEpW((RPC_WSTR)DCOMLAUNCH_START_PROTSEQ,
                                    RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
                                    (RPC_WSTR)DCOMLAUNCH_START_ENDPOINT,
                                    NULL);
    if (Status != RPC_S_OK)
    {
        DPRINT1("RpcServerUseProtseqEpW() failed (Status %lx)\n", Status);
        return;
    }

    /* An interface is served on every endpoint of the process (the Plug and Play service of this svchost listens on
       a named pipe): only local callers may use this one */
    Status = RpcServerRegisterIfEx(IDcomLaunchServiceStart_v1_0_s_ifspec, NULL, NULL,
                                   RPC_IF_ALLOW_LOCAL_ONLY, RPC_C_LISTEN_MAX_CALLS_DEFAULT, NULL);
    if (Status != RPC_S_OK)
    {
        DPRINT1("RpcServerRegisterIf() failed (Status %lx)\n", Status);
        return;
    }

    /* Another service of this svchost process may listen already */
    Status = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, TRUE);
    if (Status != RPC_S_OK && Status != RPC_S_ALREADY_LISTENING)
        DPRINT1("RpcServerListen() failed (Status %lx)\n", Status);
}

void __RPC_FAR * __RPC_USER midl_user_allocate(SIZE_T len)
{
    return HeapAlloc(GetProcessHeap(), 0, len);
}

void __RPC_USER midl_user_free(void __RPC_FAR * ptr)
{
    HeapFree(GetProcessHeap(), 0, ptr);
}
