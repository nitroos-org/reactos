/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Winlogon
 * FILE:            base/system/winlogon/screensaver.c
 * PURPOSE:         Screen saver management
 * PROGRAMMERS:     Hervé Poussineau (hpoussin@reactos.org)
 */

/* INCLUDES *****************************************************************/

#include "winlogon.h"
#include <winbase_undoc.h>
#include <stdlib.h>

/* FUNCTIONS ****************************************************************/

#ifndef USE_GETLASTINPUTINFO
static
LRESULT
CALLBACK
KeyboardActivityProc(
    IN INT nCode,
    IN WPARAM wParam,
    IN LPARAM lParam)
{
    InterlockedExchange((LONG*)&WLSession->LastActivity, ((PKBDLLHOOKSTRUCT)lParam)->time);
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}


static
LRESULT
CALLBACK
MouseActivityProc(
    IN INT nCode,
    IN WPARAM wParam,
    IN LPARAM lParam)
{
    InterlockedExchange((LONG*)&WLSession->LastActivity, ((PMSLLHOOKSTRUCT)lParam)->time);
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}
#endif


static
VOID
LoadScreenSaverParameters(
    OUT LPDWORD Timeout)
{
    BOOL Enabled;

    if (!SystemParametersInfoW(SPI_GETSCREENSAVETIMEOUT, 0, Timeout, 0))
    {
        WARN("WL: Unable to get screen saver timeout (error %lu). Disabling it\n", GetLastError());
        *Timeout = INFINITE;
    }
    else if (!SystemParametersInfoW(SPI_GETSCREENSAVEACTIVE, 0, &Enabled, 0))
    {
        WARN("WL: Unable to check if screen saver is enabled (error %lu). Disabling it\n", GetLastError());
        *Timeout = INFINITE;
    }
    else if (!Enabled)
    {
        TRACE("WL: Screen saver is disabled\n");
        *Timeout = INFINITE;
    }
    else if (*Timeout == 0)
    {
        /* A timeout of zero means that the screen saver is never started */
        TRACE("WL: Screen saver timeout is zero\n");
        *Timeout = INFINITE;
    }
    else
    {
        TRACE("WL: Screen saver timeout: %lu seconds\n", *Timeout);
        *Timeout *= 1000;
    }
}


static
DWORD
WINAPI
ScreenSaverThreadMain(
    IN LPVOID lpParameter)
{
    PWLSESSION Session = (PWLSESSION)lpParameter;
    HANDLE HandleArray[3];
#ifdef USE_GETLASTINPUTINFO
    LASTINPUTINFO lastInputInfo;
#else
    DWORD LastActivity;
#endif
    DWORD TimeToWait;
    DWORD Timeout; /* Timeout before screen saver starts, in milliseconds */
    DWORD ret;

    if (!ImpersonateLoggedOnUser(Session->UserToken))
    {
        ERR("ImpersonateLoggedOnUser() failed with error %lu\n", GetLastError());
        return 0;
    }

    Session->hUserActivity = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!Session->hUserActivity)
    {
        ERR("WL: Unable to create event (error %lu)\n", GetLastError());
        goto cleanup;
    }

    Session->hEndOfScreenSaver = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!Session->hEndOfScreenSaver)
    {
        ERR("WL: Unable to create event (error %lu)\n", GetLastError());
        goto cleanup;
    }

    HandleArray[0] = Session->hEndOfScreenSaverThread;
    HandleArray[1] = Session->hScreenSaverParametersChanged;
    HandleArray[2] = Session->hEndOfScreenSaver;

    LoadScreenSaverParameters(&Timeout);

#ifndef USE_GETLASTINPUTINFO
    InterlockedExchange((LONG*)&Session->LastActivity, GetTickCount());
#else
    lastInputInfo.cbSize = sizeof(LASTINPUTINFO);
#endif
    for (;;)
    {
        /* See the time of last activity and calculate a timeout */
#ifndef USE_GETLASTINPUTINFO
        LastActivity = InterlockedCompareExchange((LONG*)&Session->LastActivity, 0, 0);
        TimeToWait = Timeout - (GetTickCount() - LastActivity);
#else
        if (GetLastInputInfo(&lastInputInfo))
            TimeToWait = Timeout - (GetTickCount() - lastInputInfo.dwTime);
        else
        {
            WARN("GetLastInputInfo() failed with error %lu\n", GetLastError());
            TimeToWait = 10; /* Try again in 10 ms */
        }
#endif

        if (TimeToWait > Timeout)
        {
            /* GetTickCount() got back to 0 */
            TimeToWait = Timeout;
        }

        /* Wait for the timeout, or the end of this thread */
        ret = WaitForMultipleObjects(2, HandleArray, FALSE, TimeToWait);
        if (ret == WAIT_OBJECT_0)
            break;
        else if (ret == WAIT_OBJECT_0 + 1)
            LoadScreenSaverParameters(&Timeout);

        /* Check if we didn't had recent activity */
#ifndef USE_GETLASTINPUTINFO
        LastActivity = InterlockedCompareExchange((LONG*)&Session->LastActivity, 0, 0);
        if (LastActivity + Timeout > GetTickCount())
            continue;
#else
        if (!GetLastInputInfo(&lastInputInfo))
        {
            WARN("GetLastInputInfo() failed with error %lu\n", GetLastError());
            continue;
        }

        if (lastInputInfo.dwTime + Timeout > GetTickCount())
            continue;
#endif

        /* Run screen saver */
        PostMessageW(Session->SASWindow, WLX_WM_SAS, WLX_SAS_TYPE_SCRNSVR_TIMEOUT, 0);

        /* Wait for the end of this thread or of the screen saver */
        ret = WaitForMultipleObjects(3, HandleArray, FALSE, INFINITE);
        if (ret == WAIT_OBJECT_0)
            break;
        else if (ret == WAIT_OBJECT_0 + 1)
            LoadScreenSaverParameters(&Timeout);
        else if (ret == WAIT_OBJECT_0 + 2)
        {
            SystemParametersInfoW(SPI_SETSCREENSAVERRUNNING, FALSE, NULL, 0);

            /* A start that was skipped (the workstation is locked, nobody is logged on) leaves
             * the user idle: do not ask for the next one at once */
            if (WaitForSingleObject(HandleArray[0], 1000) == WAIT_OBJECT_0)
                break;
        }
    }

cleanup:
    if (Session->hUserActivity)
        CloseHandle(Session->hUserActivity);

    if (Session->hEndOfScreenSaver)
        CloseHandle(Session->hEndOfScreenSaver);

    RevertToSelf();

#ifndef USE_GETLASTINPUTINFO
    if (Session->KeyboardHook)
        UnhookWindowsHookEx(Session->KeyboardHook);

    if (Session->MouseHook)
        UnhookWindowsHookEx(Session->MouseHook);
#endif

    CloseHandle(Session->hEndOfScreenSaverThread);
    CloseHandle(Session->hScreenSaverParametersChanged);

    return 0;
}


BOOL
InitializeScreenSaver(
    IN OUT PWLSESSION Session)
{
    HANDLE ScreenSaverThread;

#ifndef USE_GETLASTINPUTINFO
    /* Register hooks to detect keyboard and mouse activity */
    Session->KeyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardActivityProc, hAppInstance, 0);
    if (!Session->KeyboardHook)
    {
        ERR("WL: Unable to register keyboard hook\n");
        return FALSE;
    }

    Session->MouseHook = SetWindowsHookEx(WH_MOUSE_LL, MouseActivityProc, hAppInstance, 0);
    if (!Session->MouseHook)
    {
        ERR("WL: Unable to register mouse hook\n");
        return FALSE;
    }
#endif

    Session->hScreenSaverParametersChanged = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!Session->hScreenSaverParametersChanged)
    {
        WARN("WL: Unable to create screen saver event (error %lu)\n", GetLastError());
        return TRUE;
    }

    Session->hEndOfScreenSaverThread = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!Session->hEndOfScreenSaverThread)
    {
        WARN("WL: Unable to create screen saver event (error %lu)\n", GetLastError());
        CloseHandle(Session->hScreenSaverParametersChanged);
        return TRUE;
    }

    ScreenSaverThread = CreateThread(NULL,
                                     0,
                                     ScreenSaverThreadMain,
                                     Session,
                                     0,
                                     NULL);
    if (ScreenSaverThread)
        Session->hScreenSaverThread = ScreenSaverThread;
    else
        ERR("WL: Unable to start screen saver thread\n");

    return TRUE;
}


/*
 * The screen saver thread runs as the logged-on user (it impersonates the user token) and was
 * only ever stopped when Winlogon shuts down: every logon left one thread behind that kept an
 * impersonation token, so the logon session of every logged-off user stayed referenced forever.
 * Stop it when the user logs off.
 */
VOID
TerminateScreenSaverThread(
    IN OUT PWLSESSION Session)
{
    if (!Session->hScreenSaverThread)
        return;

    if (Session->hEndOfScreenSaverThread)
        SetEvent(Session->hEndOfScreenSaverThread);

    if (WaitForSingleObject(Session->hScreenSaverThread, 10000) != WAIT_OBJECT_0)
        WARN("WL: The screen saver thread did not end\n");

    CloseHandle(Session->hScreenSaverThread);
    Session->hScreenSaverThread = NULL;

    /* The thread closed these */
    Session->hEndOfScreenSaverThread = NULL;
    Session->hScreenSaverParametersChanged = NULL;
}


/*
 * The grace period: the time, in milliseconds, between the start of a password protected screen saver
 * and the moment its end locks the workstation (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon,
 * ScreenSaverGracePeriod, in seconds, at most 24 hours; missing = 5 seconds, as on Windows).
 */
#define DEFAULT_SCREENSAVER_GRACE_PERIOD 5 /* seconds */
static
DWORD
GetScreenSaverGracePeriod(VOID)
{
    HKEY hKey;
    DWORD Buffer[8]; /* Aligned room for a DWORD or for a string of up to 15 characters */
    PWCHAR pwszBuffer = (PWCHAR)Buffer;
    DWORD dwType, cbData, Seconds = DEFAULT_SCREENSAVER_GRACE_PERIOD;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                      0,
                      KEY_QUERY_VALUE,
                      &hKey) != ERROR_SUCCESS)
    {
        return DEFAULT_SCREENSAVER_GRACE_PERIOD * 1000;
    }

    ZeroMemory(Buffer, sizeof(Buffer));
    cbData = sizeof(Buffer) - sizeof(WCHAR);
    if (RegQueryValueExW(hKey,
                         L"ScreenSaverGracePeriod",
                         NULL,
                         &dwType,
                         (LPBYTE)Buffer,
                         &cbData) == ERROR_SUCCESS)
    {
        if (dwType == REG_DWORD && cbData == sizeof(DWORD))
        {
            Seconds = Buffer[0];
        }
        else if (dwType == REG_SZ)
        {
            pwszBuffer[cbData / sizeof(WCHAR)] = UNICODE_NULL;
            Seconds = wcstoul(pwszBuffer, NULL, 10);
        }
    }

    RegCloseKey(hKey);

    if (Seconds > 24 * 60 * 60)
        Seconds = 24 * 60 * 60;
    return Seconds * 1000;
}


/*
 * The policy "Screen saver executable name":
 * HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop : SCRNSAVE.EXE (REG_SZ, not empty).
 * Returns ERROR_SUCCESS with the name in Buffer (*pcbData bytes, at most MAX_PATH - 1 characters, terminated).
 */
static
LONG
ReadPolicyScreenSaverFile(
    IN HKEY hCurrentUser,
    OUT PWCHAR Buffer,
    IN OUT PDWORD pcbData)
{
    HKEY hPolicyKey;
    DWORD dwType, cbData = *pcbData;
    LONG rc;

    rc = RegOpenKeyExW(hCurrentUser,
                       L"Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop",
                       0,
                       KEY_QUERY_VALUE,
                       &hPolicyKey);
    if (rc != ERROR_SUCCESS)
        return rc;

    cbData = MAX_PATH * sizeof(WCHAR) - sizeof(WCHAR);
    rc = RegQueryValueExW(hPolicyKey, L"SCRNSAVE.EXE", 0, &dwType, (LPBYTE)Buffer, &cbData);
    RegCloseKey(hPolicyKey);

    if (rc == ERROR_SUCCESS)
    {
        Buffer[cbData / sizeof(WCHAR)] = UNICODE_NULL; /* Terminate the string */
        if (dwType != REG_SZ || Buffer[0] == UNICODE_NULL)
            rc = ERROR_FILE_NOT_FOUND;
        else
            *pcbData = cbData;
    }
    return rc;
}


/*
 * Tells whether the SAS window has a request that ends a running screen saver: a hot key (Ctrl-Alt-Delete,
 * Win+L, ...), a request to lock the workstation or to log off, or any other SAS. The requests to start a
 * screen saver that are queued while one runs (win32k asks every second until the saver connects, the idle
 * thread asks once) are dropped here. Only the first request of each kind is looked at.
 */
static
BOOL
IsSasRequestPending(
    IN PWLSESSION Session)
{
    MSG Message;

    while (PeekMessageW(&Message, Session->SASWindow, WM_LOGONNOTIFY, WM_LOGONNOTIFY, PM_NOREMOVE))
    {
        if (Message.wParam == LN_LOCK_WORKSTATION || Message.wParam == LN_LOGOFF)
            return TRUE;
        if (Message.wParam != LN_START_SCREENSAVE)
            break;
        PeekMessageW(&Message, Session->SASWindow, WM_LOGONNOTIFY, WM_LOGONNOTIFY, PM_REMOVE);
    }

    while (PeekMessageW(&Message, Session->SASWindow, WLX_WM_SAS, WLX_WM_SAS, PM_NOREMOVE))
    {
        if (Message.wParam != WLX_SAS_TYPE_SCRNSVR_TIMEOUT)
            return TRUE;
        PeekMessageW(&Message, Session->SASWindow, WLX_WM_SAS, WLX_WM_SAS, PM_REMOVE);
    }

    return PeekMessageW(&Message, Session->SASWindow, WM_HOTKEY, WM_HOTKEY, PM_NOREMOVE);
}


/*
 * A password protected screen saver is configured but there is no screen saver file (the setting
 * "(None)" with "On resume, display the logon screen"): Windows shows the empty screen saver desktop for
 * the grace period and then locks the workstation, without any input; input within the grace period
 * ends it without a lock. A grace period of zero locks at once.
 * Returns TRUE when the workstation is to be locked.
 */
static
BOOL
RunEmptyScreenSaver(
    IN PWLSESSION Session,
    IN DWORD GracePeriod)
{
    LASTINPUTINFO InputInfo;
    DWORD StartTick, LastInput, Elapsed;

    if (GracePeriod == 0)
        return TRUE;

    InputInfo.cbSize = sizeof(InputInfo);
    LastInput = GetLastInputInfo(&InputInfo) ? InputInfo.dwTime : 0;

    StartTick = GetTickCount();
    SwitchDesktop(Session->ScreenSaverDesktop);

    for (;;)
    {
        Elapsed = GetTickCount() - StartTick;
        if (Elapsed >= GracePeriod)
            return TRUE;

        Sleep(min(50, GracePeriod - Elapsed));

        if (GetLastInputInfo(&InputInfo) && InputInfo.dwTime != LastInput)
        {
            SwitchDesktop(Session->LogonState == STATE_LOCKED ? Session->WinlogonDesktop : Session->ApplicationDesktop);
            return FALSE;
        }
    }
}


/*
 * Runs the screen saver of the logged-on user and waits for its end.
 *
 * Returns TRUE if the saver was started and ended, it was a password protected one (bSecure)
 * and it ran for at least the grace period: the caller locks the workstation then.
 * A saver that could not be started never locks.
 */
BOOL
StartScreenSaver(
    IN PWLSESSION Session,
    IN BOOL bSecure)
{
    HKEY hKey = NULL, hCurrentUser = NULL;
    WCHAR szApplicationName[MAX_PATH];
    WCHAR szCommandLine[MAX_PATH + 3];
    DWORD bufferSize = sizeof(szApplicationName) - sizeof(WCHAR);
    DWORD dwType;
    STARTUPINFOW StartupInfo;
    PROCESS_INFORMATION ProcessInformation;
    HANDLE HandleArray[2];
    LONG rc;
    DWORD Status;
    BOOL ret = FALSE;
    BOOL bLock = FALSE;
    BOOL bNoSaver = FALSE;
    BOOL bStartFailed = FALSE;
    BOOL bSwitched = FALSE;
    DWORD StartTick = 0;
    /* A machine setting: read as winlogon, not as the user */
    DWORD GracePeriod = bSecure ? GetScreenSaverGracePeriod() : 0;

    if (!ImpersonateLoggedOnUser(Session->UserToken))
    {
        ERR("WL: ImpersonateLoggedOnUser() failed with error %lu\n", GetLastError());
        goto cleanup;
    }

    rc = RegOpenCurrentUser(KEY_READ,
                            &hCurrentUser);
    if (rc != ERROR_SUCCESS)
    {
        ERR("WL: RegOpenCurrentUser error %lu\n", rc);
        goto cleanup;
    }

    rc = RegOpenKeyExW(hCurrentUser,
                       L"Control Panel\\Desktop",
                       0,
                       KEY_QUERY_VALUE,
                       &hKey);
    if (rc != ERROR_SUCCESS)
    {
        ERR("WL: RegOpenKeyEx error %lu\n", rc);
        goto cleanup;
    }

    /* The policy "Screen saver executable name" decides when it is present (measured on Windows Server 2022) */
    rc = ReadPolicyScreenSaverFile(hCurrentUser, szApplicationName, &bufferSize);
    if (rc != ERROR_SUCCESS)
    {
        bufferSize = sizeof(szApplicationName) - sizeof(WCHAR);
        rc = RegQueryValueExW(hKey,
                              L"SCRNSAVE.EXE",
                              0,
                              &dwType,
                              (LPBYTE)szApplicationName,
                              &bufferSize);
    }
    else
    {
        dwType = REG_SZ;
    }
    if (rc != ERROR_SUCCESS || dwType != REG_SZ)
    {
        if (rc == ERROR_FILE_NOT_FOUND)
            bNoSaver = TRUE;
        else
            ERR("WL: RegQueryValueEx error %lu\n", rc);
        goto cleanup;
    }

    if (bufferSize == 0)
    {
        bNoSaver = TRUE;
        goto cleanup;
    }

    szApplicationName[bufferSize / sizeof(WCHAR)] = 0; /* Terminate the string */

    if (wcslen(szApplicationName) == 0)
    {
        bNoSaver = TRUE;
        goto cleanup;
    }

    wsprintfW(szCommandLine, L"%s /s", szApplicationName);
    TRACE("WL: Executing %S\n", szCommandLine);

    ZeroMemory(&StartupInfo, sizeof(STARTUPINFOW));
    ZeroMemory(&ProcessInformation, sizeof(PROCESS_INFORMATION));
    StartupInfo.cb = sizeof(STARTUPINFOW);
    StartupInfo.dwFlags = STARTF_SCREENSAVER;

    /* The screen saver runs on its own desktop, so that nothing typed or clicked while it runs
     * (and nothing typed to wake it) can reach the application desktop */
    StartupInfo.lpDesktop = L"WinSta0\\Screen-Saver";

    /* Show the screen saver desktop before the saver exists: its window is created and activated on the desktop that
     * has the input, and the application desktop is out of reach until the saver ends. A saver that is not there is
     * not shown (nothing would be on the screen for the time it takes to find out) */
    if (GetFileAttributesW(szApplicationName) != INVALID_FILE_ATTRIBUTES)
    {
        SwitchDesktop(Session->ScreenSaverDesktop);
        bSwitched = TRUE;
    }

    ret = CreateProcessAsUserW(Session->UserToken,
                               szApplicationName,
                               szCommandLine,
                               NULL,
                               NULL,
                               FALSE,
                               IDLE_PRIORITY_CLASS,
                               NULL,
                               NULL,
                               &StartupInfo,
                               &ProcessInformation);
    if (!ret)
    {
        ERR("WL: Unable to start %S, error %lu\n", szApplicationName, GetLastError());
        if (bSwitched)
        {
            SwitchDesktop(Session->LogonState == STATE_LOCKED ? Session->WinlogonDesktop : Session->ApplicationDesktop);
        }
        bStartFailed = TRUE;
        goto cleanup;
    }

    CloseHandle(ProcessInformation.hThread);
    StartTick = GetTickCount();

    if (!bSwitched)
        SwitchDesktop(Session->ScreenSaverDesktop);

    SystemParametersInfoW(SPI_SETSCREENSAVERRUNNING, TRUE, NULL, 0);

    CallNotificationDlls(Session, StartScreenSaverHandler);

    /* Wait the end of the process or some other activity */
    ResetEvent(Session->hUserActivity);
    HandleArray[0] = ProcessInformation.hProcess;
    HandleArray[1] = Session->hUserActivity;
    for (;;)
    {
        Status = WaitForMultipleObjects(2, HandleArray, FALSE, 100);
        if (Status != WAIT_TIMEOUT)
            break;

        /*
         * This thread owns the SAS window: a Ctrl-Alt-Delete or Win+L (hot keys of that window), a request to
         * lock the workstation or to log off, that arrives while a saver that does not end on input (it hangs,
         * or it never created a window) shows the empty screen saver desktop would otherwise wait behind
         * the saver for ever. End the saver; the request is handled when this function has returned (after
         * the lock, if the saver was password protected).
         */
        if (IsSasRequestPending(Session))
        {
            Status = WAIT_OBJECT_0 + 1;
            break;
        }
    }
    if (Status == WAIT_OBJECT_0 + 1)
    {
        /* Kill the screen saver */
        TerminateProcess(ProcessInformation.hProcess, 0);
    }

    /* The saver is gone: tell the window station, as SPI_GETSCREENSAVERRUNNING answers for it */
    SystemParametersInfoW(SPI_SETSCREENSAVERRUNNING, FALSE, NULL, 0);

    SetEvent(Session->hEndOfScreenSaver);

    CloseHandle(ProcessInformation.hProcess);

    Session->LastScreenSaverEnd = GetTickCount();
    Session->bScreenSaverRan = TRUE;

    /* The end of the saver locks the workstation, unless it ended within the grace period */
    if (bSecure && (GetTickCount() - StartTick) >= GracePeriod)
        bLock = TRUE;

    /* A workstation that is locked (or is to be locked by the caller) goes from the screen saver desktop to the
     * Winlogon desktop without showing the application desktop in between */
    if (Session->LogonState == STATE_LOCKED)
    {
        SwitchDesktop(Session->WinlogonDesktop);
        bLock = FALSE;
    }
    else if (!bLock)
    {
        SwitchDesktop(Session->ApplicationDesktop);
    }

    CallNotificationDlls(Session, StopScreenSaverHandler);

cleanup:
    if (hKey)
        RegCloseKey(hKey);

    if (hCurrentUser)
        RegCloseKey(hCurrentUser);

    RevertToSelf();

    if (!ret)
    {
        /* Windows locks a workstation with a password protected screen saver setting when there is no
         * screen saver to show (after the grace period) or when the saver cannot be started (at once) */
        if (Session->LogonState == STATE_LOCKED)
            bLock = FALSE; /* locked already, nothing to show */
        else if (bSecure && bNoSaver)
            bLock = RunEmptyScreenSaver(Session, GracePeriod);
        else if (bSecure && bStartFailed)
            bLock = TRUE;

        if (bNoSaver || bStartFailed)
        {
            Session->LastScreenSaverEnd = GetTickCount();
            Session->bScreenSaverRan = TRUE;
        }

        PostMessageW(Session->SASWindow, WLX_WM_SAS, WLX_SAS_TYPE_SCRNSVR_ACTIVITY, 0);
#ifndef USE_GETLASTINPUTINFO
        InterlockedExchange((LONG*)&Session->LastActivity, GetTickCount());
#endif
    }

    return bLock;
}
