/*
 * PROJECT:     NitroOS basic firewall
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     mpssvc: loads the firewall policy from the registry at start and on every change and
 *              pushes it to the kernel filter (see sdk/include/reactos/nitrofw.h). A missing filter
 *              device is not an error: the rules stay stored and are pushed when the device appears.
 */
#include <stdio.h>
#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <winsvc.h>
#include <winioctl.h>
#include <reactos/nitrofw.h>
#include <fwstore.h>

static WCHAR g_Name[] = L"mpssvc";
static SERVICE_STATUS_HANDLE g_hStatus;
static SERVICE_STATUS g_Status;
static HANDLE g_hStop;
static ULONGLONG g_Generation;

static VOID SetState(DWORD state)
{
    g_Status.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
    g_Status.dwCurrentState = state;
    g_Status.dwControlsAccepted = (state == SERVICE_RUNNING) ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    g_Status.dwWaitHint = (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING) ? 3000 : 0;
    SetServiceStatus(g_hStatus, &g_Status);
}

static DWORD WINAPI CtrlHandler(DWORD ctl, DWORD type, LPVOID data, LPVOID ctx)
{
    switch (ctl)
    {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            SetState(SERVICE_STOP_PENDING);
            SetEvent(g_hStop);
            return NO_ERROR;
        case SERVICE_CONTROL_INTERROGATE:
            SetServiceStatus(g_hStatus, &g_Status);
            return NO_ERROR;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

/* record the outcome where an administrator can look: HKLM\SOFTWARE\ReactOS\Nitro\Firewall */
static VOID Report(DWORD err, BOOL present)
{
    HKEY hk; DWORD disp, v;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\ReactOS\\Nitro\\Firewall", 0, NULL, 0, KEY_SET_VALUE, NULL, &hk, &disp)) return;
    v = present ? 1 : 0; RegSetValueExW(hk, L"KernelFilterPresent", 0, REG_DWORD, (BYTE *)&v, 4);
    RegSetValueExW(hk, L"LastPushError", 0, REG_DWORD, (BYTE *)&err, 4);
    RegSetValueExW(hk, L"Generation", 0, REG_QWORD, (BYTE *)&g_Generation, 8);
    RegCloseKey(hk);
}

static VOID Push(VOID)
{
    BOOL present; DWORD err;
    err = FwPushToKernel(++g_Generation, &present);
    Report(err, present);
}

static VOID WINAPI ServiceMainImpl(DWORD argc, LPWSTR *argv)
{
    HKEY hKey = NULL; HANDLE hChange = NULL, hs[2]; DWORD wait;
    FILETIME ft;

    g_hStatus = RegisterServiceCtrlHandlerExW(g_Name, CtrlHandler, NULL);
    if (!g_hStatus) return;
    SetState(SERVICE_START_PENDING);
    g_hStop = CreateEventW(NULL, TRUE, FALSE, NULL);
    hChange = CreateEventW(NULL, FALSE, FALSE, NULL);
    /* a boot-time base keeps generations increasing across service restarts (the device outlives us) */
    GetSystemTimeAsFileTime(&ft);
    g_Generation = (((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime) / 10000000ULL;
    if (!g_hStop || !hChange || FwWatchOpen(&hKey)) goto done;
    RegNotifyChangeKeyValue(hKey, TRUE, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, hChange, TRUE);
    SetState(SERVICE_RUNNING);
    Push();
    hs[0] = g_hStop; hs[1] = hChange;
    for (;;)
    {
        /* when the device is absent retry periodically; netsh/COM changes arrive through the key notification */
        wait = WaitForMultipleObjects(2, hs, FALSE, NITROFW_RETRY_SECONDS * 1000);
        if (wait == WAIT_OBJECT_0) break;
        if (wait == WAIT_OBJECT_0 + 1)
        {
            Sleep(200);   /* coalesce bursts (netsh writes several values) */
            RegNotifyChangeKeyValue(hKey, TRUE, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, hChange, TRUE);
            Push();
        }
        else if (wait == WAIT_TIMEOUT)
        {
            HKEY hk; DWORD present = 0, cb = 4, t;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\ReactOS\\Nitro\\Firewall", 0, KEY_READ, &hk) == 0)
            { RegQueryValueExW(hk, L"KernelFilterPresent", NULL, &t, (BYTE *)&present, &cb); RegCloseKey(hk); }
            if (!present) Push();   /* device may have appeared */
        }
    }
done:
    if (hKey) RegCloseKey(hKey);
    if (hChange) CloseHandle(hChange);
    if (g_hStop) CloseHandle(g_hStop);
    SetState(SERVICE_STOPPED);
}

VOID WINAPI ServiceMain(DWORD argc, LPWSTR *argv) { ServiceMainImpl(argc, argv); }

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r)
{
    if (reason == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(h);
    return TRUE;
}
