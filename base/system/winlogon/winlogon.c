/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Winlogon
 * FILE:            base/system/winlogon/winlogon.c
 * PURPOSE:         Logon
 * PROGRAMMERS:     Thomas Weidenmueller (w3seek@users.sourceforge.net)
 *                  Filip Navara
 *                  Hervé Poussineau (hpoussin@reactos.org)
 */

/* INCLUDES *****************************************************************/

#include "winlogon.h"

#include <ndk/cmfuncs.h>
#include <ndk/psfuncs.h>

/* GLOBALS ******************************************************************/

HINSTANCE hAppInstance;

/* userenv private export (ordinal 300): gives the well-known folders of an older install the DACLs of Windows */
BOOL WINAPI SecureSystemDirectories(VOID);

/* userenv private export (ordinal 301): the control flags of the system hive keys of an older install (as Windows 10 has them) */
BOOL WINAPI SecureRegistryKeys(VOID);

/* userenv private export (ordinal 302): the IPv6 transport and Winsock catalog entries of an install that predates them */
BOOL WINAPI UpgradeNetworkCatalog(VOID);
PWLSESSION WLSession = NULL;

/* NitroSessions 3: what this Winlogon does (see WlGetSessionRole) */
WL_SESSION_ROLE WlSessionRole = WlRoleSingle;
ULONG WlSessionId = 0;

/* FUNCTIONS *****************************************************************/

/**
 * @brief
 * Duplicates the given string, allocating a buffer on the heap.
 **/
PWSTR
WlStrDup(
    _In_opt_ PCWSTR String)
{
    PWSTR ptr;

    if (!String)
        return NULL;

    ptr = RtlAllocateHeap(RtlGetProcessHeap(), 0,
                          (wcslen(String) + 1) * sizeof(WCHAR));
    if (ptr)
        wcscpy(ptr, String);
    return ptr;
}


static
BOOL
StartServicesManager(VOID)
{
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInformation;
    LPCWSTR ServiceString = L"services.exe";
    BOOL res;

    /* Start the service control manager (services.exe) */
    TRACE("WL: Creating new process - %S\n", ServiceString);
    res = CreateProcessW(ServiceString,
                         NULL,
                         NULL,
                         NULL,
                         FALSE,
                         DETACHED_PROCESS,
                         NULL,
                         NULL,
                         &StartupInfo,
                         &ProcessInformation);
    if (!res)
    {
        ERR("WL: Failed to execute services (error %lu)\n", GetLastError());
        return FALSE;
    }

    TRACE("WL: Created new process - %S\n", ServiceString);

    CloseHandle(ProcessInformation.hThread);
    CloseHandle(ProcessInformation.hProcess);

    TRACE("WL: StartServicesManager() done.\n");

    return TRUE;
}


static
BOOL
StartLsass(VOID)
{
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInformation;
    LPCWSTR ServiceString = L"lsass.exe";
    BOOL res;

    /* Start the local security authority subsystem (lsass.exe) */
    TRACE("WL: Creating new process - %S\n", ServiceString);
    res = CreateProcessW(ServiceString,
                         NULL,
                         NULL,
                         NULL,
                         FALSE,
                         DETACHED_PROCESS,
                         NULL,
                         NULL,
                         &StartupInfo,
                         &ProcessInformation);

    TRACE("WL: Created new process - %S\n", ServiceString);

    CloseHandle(ProcessInformation.hThread);
    CloseHandle(ProcessInformation.hProcess);

    return res;
}


/*
 * NitroSessions 3 (HKLM\SYSTEM\CurrentControlSet\Control\Session Manager, DWORD): session 1 holds the
 * console. Session 0's Winlogon then only starts the services and the LSA (the part Windows gives
 * wininit); session 1's Winlogon, started by the Session Manager, logs the interactive user on and serves
 * the shutdown requests. Any other value: one Winlogon in session 0 does everything, as before.
 */
static
VOID
WlGetSessionRole(VOID)
{
    HKEY hKey;
    DWORD dwType, dwValue = 0, cbData = sizeof(dwValue);
    PROCESS_SESSION_INFORMATION SessionInfo;
    NTSTATUS Status;

    WlSessionRole = WlRoleSingle;
    WlSessionId = 0;

    /* The kernel's value, never the PEB's */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessSessionInformation,
                                       &SessionInfo,
                                       sizeof(SessionInfo),
                                       NULL);
    if (NT_SUCCESS(Status))
        WlSessionId = SessionInfo.SessionId;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\Session Manager",
                      0,
                      KEY_QUERY_VALUE,
                      &hKey) != ERROR_SUCCESS)
    {
        return;
    }
    if ((RegQueryValueExW(hKey, L"NitroSessions", NULL, &dwType, (PBYTE)&dwValue, &cbData) != ERROR_SUCCESS) ||
        (dwType != REG_DWORD) || (cbData != sizeof(dwValue)))
    {
        dwValue = 0;
    }
    RegCloseKey(hKey);

    if (dwValue == 3)
        WlSessionRole = (WlSessionId == 0) ? WlRoleServices : WlRoleInteractive;

    if (WlSessionRole != WlRoleSingle)
        ERR("WL: session %lu, %s\n", WlSessionId,
            (WlSessionRole == WlRoleServices) ? "services and LSA only" : "interactive logon");
}


static
VOID
WaitForLsass(VOID)
{
    HANDLE hEvent;
    DWORD dwError;
    /* The LSA creates the event in session 0; from another session it is reached by its global name */
    PCWSTR EventName = (WlSessionId == 0) ? L"LSA_RPC_SERVER_ACTIVE" : L"Global\\LSA_RPC_SERVER_ACTIVE";

    hEvent = CreateEventW(NULL,
                          TRUE,
                          FALSE,
                          EventName);
    if (hEvent == NULL)
    {
        dwError = GetLastError();
        TRACE("WL: Failed to create the notification event (Error %lu)\n", dwError);

        if (dwError == ERROR_ALREADY_EXISTS)
        {
            hEvent = OpenEventW(SYNCHRONIZE,
                                FALSE,
                                EventName);
            if (hEvent == NULL)
            {
               ERR("WL: Could not open the notification event (Error %lu)\n", GetLastError());
               return;
            }
        }
    }

    TRACE("WL: Wait for the LSA server!\n");
    WaitForSingleObject(hEvent, INFINITE);
    TRACE("WL: LSA server running!\n");

    CloseHandle(hEvent);
}


static
VOID
UpdateTcpIpInformation(VOID)
{
    LONG lError;
    HKEY hKey = NULL;
    DWORD dwType, dwSize;
    PWSTR pszBuffer;
    WCHAR szBuffer[128] = L"";

    lError = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                           L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                           0,
                           KEY_QUERY_VALUE | KEY_SET_VALUE,
                           &hKey);
    if (lError != ERROR_SUCCESS)
    {
        ERR("WL: RegOpenKeyExW(\"HKLM\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\") failed (error %lu)\n", lError);
        return;
    }

    /*
     * Read the "NV Hostname" value and copy it into the "Hostname" value.
     */

    pszBuffer = szBuffer;
    dwSize = ARRAYSIZE(szBuffer);

    lError = RegQueryValueExW(hKey,
                              L"NV Hostname",
                              NULL,
                              &dwType,
                              (LPBYTE)pszBuffer,
                              &dwSize);
    if (((lError == ERROR_INSUFFICIENT_BUFFER) || (lError == ERROR_MORE_DATA)) && (dwType == REG_SZ))
    {
        pszBuffer = HeapAlloc(GetProcessHeap(), 0, dwSize);
        if (pszBuffer)
        {
            lError = RegQueryValueExW(hKey,
                                      L"NV Hostname",
                                      NULL,
                                      &dwType,
                                      (LPBYTE)pszBuffer,
                                      &dwSize);
        }
        else
        {
            ERR("WL: Could not reallocate memory for pszBuffer\n");
            goto Quit;
        }
    }
    if ((lError == ERROR_SUCCESS) && (dwType == REG_SZ))
    {
        TRACE("NV Hostname is '%S'.\n", pszBuffer);

        lError = RegSetValueExW(hKey,
                                L"Hostname",
                                0,
                                REG_SZ,
                                (LPBYTE)pszBuffer,
                                dwSize);
        if (lError != ERROR_SUCCESS)
            ERR("WL: RegSetValueExW(\"Hostname\") failed (error %lu)\n", lError);
    }

    /*
     * Read the "NV Domain" value and copy it into the "Domain" value.
     */

    // pszBuffer = szBuffer;
    // dwSize = ARRAYSIZE(szBuffer);

    lError = RegQueryValueExW(hKey,
                              L"NV Domain",
                              NULL,
                              &dwType,
                              (LPBYTE)pszBuffer,
                              &dwSize);
    if (((lError == ERROR_INSUFFICIENT_BUFFER) || (lError == ERROR_MORE_DATA)) && (dwType == REG_SZ))
    {
        if (pszBuffer != szBuffer)
        {
            PWSTR pszNewBuffer;
            pszNewBuffer = HeapReAlloc(GetProcessHeap(), 0, pszBuffer, dwSize);
            if (pszNewBuffer)
            {
                pszBuffer = pszNewBuffer;
            }
            else
            {
                HeapFree(GetProcessHeap(), 0, pszBuffer);
                pszBuffer = NULL;
            }
        }
        else
        {
            pszBuffer = HeapAlloc(GetProcessHeap(), 0, dwSize);
        }
        if (pszBuffer)
        {
            lError = RegQueryValueExW(hKey,
                                      L"NV Domain",
                                      NULL,
                                      &dwType,
                                      (LPBYTE)pszBuffer,
                                      &dwSize);
        }
        else
        {
            ERR("WL: Could not reallocate memory for pszBuffer\n");
            goto Quit;
        }
    }
    if ((lError == ERROR_SUCCESS) && (dwType == REG_SZ))
    {
        TRACE("NV Domain is '%S'.\n", pszBuffer);

        lError = RegSetValueExW(hKey,
                                L"Domain",
                                0,
                                REG_SZ,
                                (LPBYTE)pszBuffer,
                                dwSize);
        if (lError != ERROR_SUCCESS)
            ERR("WL: RegSetValueExW(\"Domain\") failed (error %lu)\n", lError);
    }

    if (pszBuffer != szBuffer)
        HeapFree(GetProcessHeap(), 0, pszBuffer);

Quit:
    RegCloseKey(hKey);
}


static
BOOL
InitKeyboardLayouts(VOID)
{
    WCHAR wszKeyName[12], wszKLID[10];
    DWORD dwSize = sizeof(wszKLID), dwType, i = 1;
    HKEY hKey;
    UINT Flags;
    BOOL bRet = FALSE;

    /* Open registry key with preloaded layouts */
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Keyboard Layout\\Preload", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        while (TRUE)
        {
            /* Read values with integer names only */
            _swprintf(wszKeyName, L"%d", i++);
            if (RegQueryValueExW(hKey, wszKeyName, NULL, &dwType, (LPBYTE)wszKLID, &dwSize) != ERROR_SUCCESS)
            {
                /* There is no more entries */
                break;
            }

            /* Only REG_SZ values are valid */
            if (dwType != REG_SZ)
            {
                ERR("Wrong type: %ws!\n", wszKLID);
                continue;
            }

            /* Load keyboard layout with given locale id */
            Flags = KLF_SUBSTITUTE_OK;
            if (i > 1)
                Flags |= KLF_NOTELLSHELL|KLF_REPLACELANG;
            else // First layout
                Flags |= KLF_ACTIVATE; // |0x40000000
            if (!LoadKeyboardLayoutW(wszKLID, Flags))
            {
                ERR("LoadKeyboardLayoutW(%ws) failed!\n", wszKLID);
                continue;
            }
            else
            {
                /* We loaded at least one layout - success */
                bRet = TRUE;
            }
        }

        /* Close the key now */
        RegCloseKey(hKey);
    }
    else
        WARN("RegOpenKeyExW(Keyboard Layout\\Preload) failed!\n");

    if (!bRet)
    {
        /* If we failed, load US keyboard layout */
        if (LoadKeyboardLayoutW(L"00000409", KLF_ACTIVATE | KLF_SUBSTITUTE_OK | KLF_REPLACELANG | KLF_SETFORPROCESS))
            bRet = TRUE;
    }

    return bRet;
}


BOOL
DisplayStatusMessage(
     IN PWLSESSION Session,
     IN HDESK hDesktop,
     IN UINT ResourceId)
{
    WCHAR StatusMsg[MAX_PATH];

    if (Session->Gina.Version < WLX_VERSION_1_3)
        return TRUE;

    if (Session->SuppressStatus)
        return TRUE;

    if (LoadStringW(hAppInstance, ResourceId, StatusMsg, MAX_PATH) == 0)
        return FALSE;

    return Session->Gina.Functions.WlxDisplayStatusMessage(Session->Gina.Context, hDesktop, 0, NULL, StatusMsg);
}


BOOL
RemoveStatusMessage(
    IN PWLSESSION Session)
{
    if (Session->Gina.Version < WLX_VERSION_1_3)
        return TRUE;

    return Session->Gina.Functions.WlxRemoveStatusMessage(Session->Gina.Context);
}


static
INT_PTR
CALLBACK
GinaLoadFailedWindowProc(
    IN HWND hwndDlg,
    IN UINT uMsg,
    IN WPARAM wParam,
    IN LPARAM lParam)
{
    switch (uMsg)
    {
        case WM_COMMAND:
        {
            switch (LOWORD(wParam))
            {
                case IDOK:
                    EndDialog(hwndDlg, IDOK);
                    return TRUE;
            }
            break;
        }

        case WM_INITDIALOG:
        {
            int len;
            WCHAR templateText[MAX_PATH], text[MAX_PATH];

            len = GetDlgItemTextW(hwndDlg, IDC_GINALOADFAILED, templateText, MAX_PATH);
            if (len)
            {
                wsprintfW(text, templateText, (LPWSTR)lParam);
                SetDlgItemTextW(hwndDlg, IDC_GINALOADFAILED, text);
            }
            return TRUE;
        }

        case WM_CLOSE:
        {
            EndDialog(hwndDlg, IDCANCEL);
            return TRUE;
        }
    }

    return FALSE;
}


int
WINAPI
WinMain(
    IN HINSTANCE hInstance,
    IN HINSTANCE hPrevInstance,
    IN LPSTR lpCmdLine,
    IN int nShowCmd)
{
#if 0
    LSA_STRING ProcessName, PackageName;
    HANDLE LsaHandle;
    LSA_OPERATIONAL_MODE Mode;
    BOOLEAN Old;
    ULONG AuthenticationPackage;
    NTSTATUS Status;
#endif
    ULONG HardErrorResponse;
    MSG Msg;

    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    UNREFERENCED_PARAMETER(nShowCmd);

    hAppInstance = hInstance;

    /* Make us critical */
    RtlSetProcessIsCritical(TRUE, NULL, FALSE);
    RtlSetThreadIsCritical(TRUE, NULL, FALSE);

    /* Which part of the work is ours (NitroSessions) */
    WlGetSessionRole();

    /* The machine-wide work is session 0's */
    if (WlSessionRole != WlRoleInteractive)
    {
        /* Installs from before the well-known folders had the DACLs of Windows get them now (nothing happens once they have) */
        SecureSystemDirectories();
        SecureRegistryKeys();

        /* An install from before the IPv6 transport and catalog entries gets them now when the stack's IPv6 switch is on (once) */
        UpgradeNetworkCatalog();

        /* Update the cached TCP/IP Information in the registry */
        UpdateTcpIpInformation();
    }

    if (!RegisterLogonProcess(GetCurrentProcessId(), TRUE))
    {
        ERR("WL: Could not register logon process\n");
        NtRaiseHardError(STATUS_SYSTEM_PROCESS_TERMINATED, 0, 0, NULL, OptionOk, &HardErrorResponse);
        ExitProcess(1);
    }

    WLSession = (PWLSESSION)HeapAlloc(GetProcessHeap(), 0, sizeof(WLSESSION));
    if (!WLSession)
    {
        ERR("WL: Could not allocate memory for winlogon instance\n");
        NtRaiseHardError(STATUS_SYSTEM_PROCESS_TERMINATED, 0, 0, NULL, OptionOk, &HardErrorResponse);
        ExitProcess(1);
    }

    ZeroMemory(WLSession, sizeof(WLSESSION));
    WLSession->DialogTimeout = 120; /* 2 minutes */

    /* Initialize the dialog tracking list */
    InitDialogListHead();

    if (!CreateWindowStationAndDesktops(WLSession))
    {
        ERR("WL: Could not create window station and desktops\n");
        NtRaiseHardError(STATUS_SYSTEM_PROCESS_TERMINATED, 0, 0, NULL, OptionOk, &HardErrorResponse);
        ExitProcess(1);
    }

    LockWorkstation(WLSession);

    /* Load default keyboard layouts */
    if (!InitKeyboardLayouts())
    {
        ERR("WL: Could not preload keyboard layouts\n");
        NtRaiseHardError(STATUS_SYSTEM_PROCESS_TERMINATED, 0, 0, NULL, OptionOk, &HardErrorResponse);
        ExitProcess(1);
    }

    /*
     * Session 0 without the console draws into memory, and its display is set up only while a program of
     * the session uses it (a window or a device context); a session that runs only services may have none.
     * Then a console or an icon that a service asks for finds no display. Winlogon uses the display for as
     * long as it runs (a device context taken once counts until the process ends), so it is always there.
     */
    if (WlSessionRole == WlRoleServices)
    {
        HDC hdc = GetDC(NULL);
        if (hdc)
            ReleaseDC(NULL, hdc);
        else
            ERR("WL: no display in session 0, error %lu\n", GetLastError());
    }

    /*
     * The shutdown requests (InitiateSystemShutdown) go to the Winlogon of the console session: it shows
     * the warning where the user is and logs the user off before the system goes down
     */
    if ((WlSessionRole != WlRoleServices) && !StartRpcServer())
    {
        ERR("WL: Could not start the RPC server\n");
        NtRaiseHardError(STATUS_SYSTEM_PROCESS_TERMINATED, 0, 0, NULL, OptionOk, &HardErrorResponse);
        ExitProcess(1);
    }

    /* The services and the LSA run in session 0 */
    if (WlSessionRole != WlRoleInteractive)
    {
        if (!StartServicesManager())
        {
            ERR("WL: Could not start services.exe\n");
            NtRaiseHardError(STATUS_SYSTEM_PROCESS_TERMINATED, 0, 0, NULL, OptionOk, &HardErrorResponse);
            ExitProcess(1);
        }

        if (!StartLsass())
        {
            ERR("WL: Failed to start lsass.exe service (error %lu)\n", GetLastError());
            NtRaiseHardError(STATUS_SYSTEM_PROCESS_TERMINATED, 0, 0, NULL, OptionOk, &HardErrorResponse);
            ExitProcess(1);
        }
    }

    /* Wait for the LSA server */
    WaitForLsass();

    if (WlSessionRole == WlRoleServices)
    {
        /* No logon in this session: the console session's Winlogon does it */
        NtInitializeRegistry(CM_BOOT_FLAG_ACCEPTED | 1);
        ERR("WL: services and LSA started, the interactive logon is in another session\n");
        SleepEx(INFINITE, FALSE);
        return 0;
    }

    /* Init Notifications */
    InitNotifications();

    /* Load and initialize gina */
    if (!GinaInit(WLSession))
    {
        ERR("WL: Failed to initialize Gina\n");
        // FIXME: Retrieve the real name of the GINA DLL we were trying to load.
        // It is known only inside the GinaInit function...
        DialogBoxParam(hAppInstance, MAKEINTRESOURCE(IDD_GINALOADFAILED), GetDesktopWindow(), GinaLoadFailedWindowProc, (LPARAM)L"msgina.dll");
        HandleShutdown(WLSession, WLX_SAS_ACTION_SHUTDOWN_REBOOT);
        ExitProcess(1);
    }

    DisplayStatusMessage(WLSession, WLSession->WinlogonDesktop, IDS_REACTOSISSTARTINGUP);

#if 0
    /* Connect to NetLogon service (lsass.exe) */
    /* Real winlogon uses "Winlogon" */
    RtlInitUnicodeString((PUNICODE_STRING)&ProcessName, L"Winlogon");
    Status = LsaRegisterLogonProcess(&ProcessName, &LsaHandle, &Mode);
    if (Status == STATUS_PORT_CONNECTION_REFUSED)
    {
        /* Add the 'SeTcbPrivilege' privilege and try again */
        Status = RtlAdjustPrivilege(SE_TCB_PRIVILEGE, TRUE, TRUE, &Old);
        if (!NT_SUCCESS(Status))
        {
            ERR("RtlAdjustPrivilege() failed with error %lu\n", LsaNtStatusToWinError(Status));
            return 1;
        }

        Status = LsaRegisterLogonProcess(&ProcessName, &LsaHandle, &Mode);
    }

    if (!NT_SUCCESS(Status))
    {
        ERR("LsaRegisterLogonProcess() failed with error %lu\n", LsaNtStatusToWinError(Status));
        return 1;
    }

    RtlInitUnicodeString((PUNICODE_STRING)&PackageName, MICROSOFT_KERBEROS_NAME_W);
    Status = LsaLookupAuthenticationPackage(LsaHandle, &PackageName, &AuthenticationPackage);
    if (!NT_SUCCESS(Status))
    {
        ERR("LsaLookupAuthenticationPackage() failed with error %lu\n", LsaNtStatusToWinError(Status));
        LsaDeregisterLogonProcess(LsaHandle);
        return 1;
    }
#endif

    CallNotificationDlls(WLSession, StartupHandler);

    /* Create a hidden window to get SAS notifications */
    if (!InitializeSAS(WLSession))
    {
        ERR("WL: Failed to initialize SAS\n");
        ExitProcess(2);
    }

    // DisplayStatusMessage(Session, Session->WinlogonDesktop, IDS_PREPARENETWORKCONNECTIONS);
    // DisplayStatusMessage(Session, Session->WinlogonDesktop, IDS_APPLYINGCOMPUTERSETTINGS);

    /* Display logged out screen */
    WLSession->LogonState = STATE_INIT;
    RemoveStatusMessage(WLSession);

    /* Check for pending setup */
    if (GetSetupType() != 0)
    {
        /* Run setup and reboot when done */
        TRACE("WL: Setup mode detected\n");
        RunSetup();
    }
    else
    {
        PostMessageW(WLSession->SASWindow, WLX_WM_SAS, WLX_SAS_TYPE_CTRL_ALT_DEL, 0);
    }

    /* Tell kernel that CurrentControlSet is good (needed
     * to support Last good known configuration boot); session 0's Winlogon does it */
    if (WlSessionRole == WlRoleSingle)
        NtInitializeRegistry(CM_BOOT_FLAG_ACCEPTED | 1);

    /* Message loop for the SAS window */
    while (GetMessageW(&Msg, WLSession->SASWindow, 0, 0))
    {
        TranslateMessage(&Msg);
        DispatchMessageW(&Msg);
    }

    CleanupNotifications();

    /* We never go there */
    // TODO: Shutdown if we are in session 0, otherwise let the process terminate.
    SleepEx(INFINITE, FALSE);
    return 0;
}
