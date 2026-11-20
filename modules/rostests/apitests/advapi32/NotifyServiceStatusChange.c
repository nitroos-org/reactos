/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for NotifyServiceStatusChangeA/W
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Rows measured on Windows Server 2022. The service under test is one that is running on every
 * system (RpcSs): it is only observed, never controlled.
 */

#include "precomp.h"

static volatile LONG s_Hits;
static PVOID s_LastParam;

static VOID CALLBACK NotifyCallback(PVOID Param)
{
    s_LastParam = Param;
    InterlockedIncrement(&s_Hits);
}

static LONG Pump(DWORD Ms)
{
    DWORD Start = GetTickCount();

    s_Hits = 0;
    while (GetTickCount() - Start < Ms)
        SleepEx(20, TRUE);
    return s_Hits;
}

START_TEST(NotifyServiceStatusChange)
{
    HMODULE hAdvapi = LoadLibraryW(L"advapi32.dll");
    DWORD (WINAPI *pW)(SC_HANDLE, DWORD, SERVICE_NOTIFYW *) = (PVOID)GetProcAddress(hAdvapi, "NotifyServiceStatusChangeW");
    DWORD (WINAPI *pA)(SC_HANDLE, DWORD, SERVICE_NOTIFYA *) = (PVOID)GetProcAddress(hAdvapi, "NotifyServiceStatusChangeA");
    SC_HANDLE hScm, hQuery, hInterrogate;
    SERVICE_NOTIFYW Notify, Notify2, Notify3;
    SERVICE_NOTIFYA NotifyA;
    SERVICE_STATUS_PROCESS Status;
    DWORD Err, Needed;

    ok(pW != NULL, "NotifyServiceStatusChangeW is not exported\n");
    ok(pA != NULL, "NotifyServiceStatusChangeA is not exported\n");
    if (!pW || !pA)
    {
        skip("exports missing\n");
        return;
    }

    hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    ok(hScm != NULL, "OpenSCManager failed: %lu\n", GetLastError());
    if (!hScm)
        return;
    hQuery = OpenServiceW(hScm, L"RpcSs", SERVICE_QUERY_STATUS);
    hInterrogate = OpenServiceW(hScm, L"RpcSs", SERVICE_INTERROGATE);
    if (!hQuery || !hInterrogate)
    {
        skip("cannot open RpcSs: %lu\n", GetLastError());
        goto cleanup;
    }

    memset(&Notify, 0, sizeof(Notify));
    Notify.dwVersion = SERVICE_NOTIFY_STATUS_CHANGE;
    Notify.pfnNotifyCallback = NotifyCallback;

    /* parameters */
    ok_dec(pW(hQuery, SERVICE_NOTIFY_STOPPED, NULL), ERROR_INVALID_PARAMETER);
    ok_dec(pW(hQuery, 0, &Notify), ERROR_INVALID_PARAMETER);
    ok_dec(pW(hQuery, 0x80000000, &Notify), ERROR_INVALID_PARAMETER);
    ok_dec(pW(hQuery, 0x400, &Notify), ERROR_INVALID_PARAMETER);
    ok_dec(pW(hQuery, 0x1ff, &Notify), ERROR_INVALID_PARAMETER);
    ok_dec(pW(NULL, SERVICE_NOTIFY_STOPPED, &Notify), ERROR_INVALID_PARAMETER);
    Notify.dwVersion = 0;
    ok_dec(pW(hQuery, SERVICE_NOTIFY_STOPPED, &Notify), ERROR_INVALID_PARAMETER);
    Notify.dwVersion = 3;
    ok_dec(pW(hQuery, SERVICE_NOTIFY_STOPPED, &Notify), ERROR_INVALID_PARAMETER);
    Notify.dwVersion = SERVICE_NOTIFY_STATUS_CHANGE;
    Notify.pfnNotifyCallback = NULL;
    ok_dec(pW(hQuery, SERVICE_NOTIFY_STOPPED, &Notify), ERROR_INVALID_PARAMETER);
    Notify.pfnNotifyCallback = NotifyCallback;
    ok_dec(pA(hQuery, 0, NULL), ERROR_INVALID_PARAMETER);

    /* handles */
    ok_dec(pW(hInterrogate, SERVICE_NOTIFY_STOPPED, &Notify), ERROR_ACCESS_DENIED);
    ok_dec(pW(hScm, SERVICE_NOTIFY_STOPPED, &Notify), ERROR_INVALID_HANDLE);
    ok_dec(pW(hQuery, SERVICE_NOTIFY_CREATED, &Notify), ERROR_INVALID_HANDLE);
    ok_dec(pW(hQuery, SERVICE_NOTIFY_DELETED, &Notify), ERROR_INVALID_HANDLE);
    ok_dec(pW(hScm, SERVICE_NOTIFY_DELETE_PENDING, &Notify), ERROR_INVALID_HANDLE);

    /* a service that is in a requested state notifies at once, through an APC of the calling thread */
    ok(QueryServiceStatusEx(hQuery, SC_STATUS_PROCESS_INFO, (LPBYTE)&Status, sizeof(Status), &Needed),
       "QueryServiceStatusEx failed: %lu\n", GetLastError());
    if (Status.dwCurrentState != SERVICE_RUNNING)
    {
        skip("RpcSs is not running\n");
        goto cleanup;
    }
    Notify.dwNotificationStatus = 0x1234;
    Notify.dwNotificationTriggered = 0x1234;
    s_LastParam = NULL;
    Err = pW(hQuery, SERVICE_NOTIFY_RUNNING | SERVICE_NOTIFY_STOPPED, &Notify);
    ok_dec(Err, ERROR_SUCCESS);
    ok_long(Pump(1000), 1);
    ok(s_LastParam == &Notify, "callback parameter %p\n", s_LastParam);
    ok_dec(Notify.dwNotificationStatus, ERROR_SUCCESS);
    ok_hex(Notify.dwNotificationTriggered, SERVICE_NOTIFY_RUNNING);
    ok_dec(Notify.ServiceStatus.dwCurrentState, SERVICE_RUNNING);
    ok(Notify.pszServiceNames == NULL, "pszServiceNames %p\n", Notify.pszServiceNames);

    /* every registration fires once, also several on one handle */
    memset(&Notify2, 0, sizeof(Notify2));
    Notify2.dwVersion = SERVICE_NOTIFY_STATUS_CHANGE;
    Notify2.pfnNotifyCallback = NotifyCallback;
    ok_dec(pW(hQuery, SERVICE_NOTIFY_RUNNING, &Notify), ERROR_SUCCESS);
    ok_dec(pW(hQuery, SERVICE_NOTIFY_RUNNING, &Notify2), ERROR_SUCCESS);
    ok_long(Pump(1000), 2);
    ok_long(Pump(300), 0);

    /* the A form is the same thing */
    memset(&NotifyA, 0, sizeof(NotifyA));
    NotifyA.dwVersion = SERVICE_NOTIFY_STATUS_CHANGE;
    NotifyA.pfnNotifyCallback = NotifyCallback;
    NotifyA.dwNotificationStatus = 0x1234;
    ok_dec(pA(hQuery, SERVICE_NOTIFY_RUNNING, &NotifyA), ERROR_SUCCESS);
    ok_long(Pump(1000), 1);
    ok(s_LastParam == &NotifyA, "callback parameter %p\n", s_LastParam);
    ok_dec(NotifyA.dwNotificationStatus, ERROR_SUCCESS);
    ok_hex(NotifyA.dwNotificationTriggered, SERVICE_NOTIFY_RUNNING);

    /* a state it is not in: no notification, the status of the structure is cleared by the call and nothing else is stored */
    memset(&Notify3, 0, sizeof(Notify3));
    Notify3.dwVersion = SERVICE_NOTIFY_STATUS_CHANGE;
    Notify3.pfnNotifyCallback = NotifyCallback;
    Notify3.dwNotificationStatus = 0x1234;
    Notify3.dwNotificationTriggered = 0x5678;
    ok_dec(pW(hQuery, SERVICE_NOTIFY_STOPPED | SERVICE_NOTIFY_PAUSED, &Notify3), ERROR_SUCCESS);
    ok_long(Pump(500), 0);
    /* the status is cleared by the registration, the rest is written when the notification fires */
    ok_hex(Notify3.dwNotificationStatus, ERROR_SUCCESS);
    ok_hex(Notify3.dwNotificationTriggered, 0x5678);

    /* closing the handle cancels what is pending on it */
    {
        SC_HANDLE hOther = OpenServiceW(hScm, L"RpcSs", SERVICE_QUERY_STATUS);

        ok(hOther != NULL, "OpenService failed: %lu\n", GetLastError());
        if (hOther)
        {
            ok_dec(pW(hOther, SERVICE_NOTIFY_STOPPED, &Notify2), ERROR_SUCCESS);
            CloseServiceHandle(hOther);
            ok_long(Pump(500), 0);
        }
    }

cleanup:
    if (hInterrogate)
        CloseServiceHandle(hInterrogate);
    if (hQuery)
        CloseServiceHandle(hQuery);
    CloseServiceHandle(hScm);
}
