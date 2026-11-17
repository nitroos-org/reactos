/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS net command
 * FILE:            base/applications/network/net/cmdStop.c
 * PURPOSE:
 *
 * PROGRAMMERS:     Magnus Olsen (greatlord@reactos.org)
 */

#include "net.h"

INT cmdStop(INT argc, WCHAR **argv)
{
    SC_HANDLE hManager = NULL;
    SC_HANDLE hService = NULL;
    SERVICE_STATUS ServiceStatus;
    SERVICE_STATUS_PROCESS Status;
    PWSTR pszDisplayName = NULL;
    DWORD dwSize, dwCheckPoint, dwWait, dwStartTick;
    DWORD dwError = ERROR_SUCCESS;
    INT nError = 0;
    INT i;

    if (argc != 3)
    {
        PrintMessageString(4381);
        ConPuts(StdOut, L"\n");
        PrintNetMessage(MSG_STOP_SYNTAX);
        return 1;
    }

    for (i = 2; i < argc; i++)
    {
        if (_wcsicmp(argv[i], L"/help") == 0)
        {
            PrintMessageString(4381);
            ConPuts(StdOut, L"\n");
            PrintNetMessage(MSG_STOP_SYNTAX);
            PrintNetMessage(MSG_STOP_HELP);
            return 1;
        }
    }

    hManager = OpenSCManagerW(NULL,
                              SERVICES_ACTIVE_DATABASE,
                              SC_MANAGER_CONNECT);
    if (hManager == NULL)
    {
        dwError = GetLastError();
        nError = 1;
        goto done;
    }

    hService = OpenServiceW(hManager,
                            argv[2],
                            SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (hService == NULL)
    {
        dwError = GetLastError();
        nError = 1;
        goto done;
    }

    if (!ControlService(hService, SERVICE_CONTROL_STOP, &ServiceStatus))
    {
        dwError = GetLastError();
        nError = 1;
        goto done;
    }

    dwSize = 0;
    GetServiceDisplayNameW(hManager, argv[2], NULL, &dwSize);
    pszDisplayName = HeapAlloc(GetProcessHeap(), 0, (dwSize + 1) * sizeof(WCHAR));
    if (pszDisplayName != NULL)
    {
        dwSize++;
        if (!GetServiceDisplayNameW(hManager, argv[2], pszDisplayName, &dwSize))
        {
            HeapFree(GetProcessHeap(), 0, pszDisplayName);
            pszDisplayName = NULL;
        }
    }

    PrintMessageStringV(3527, pszDisplayName ? pszDisplayName : argv[2]);

    /* Wait until the service has stopped, as long as it makes progress (its wait hint allows) */
    dwStartTick = GetTickCount();
    dwCheckPoint = 0;
    for (;;)
    {
        ConPuts(StdOut, L".");

        if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&Status,
                                  sizeof(Status), &dwSize))
        {
            dwError = GetLastError();
            ConPuts(StdOut, L"\n");
            nError = 1;
            goto done;
        }

        if (Status.dwCurrentState == SERVICE_STOPPED)
            break;

        if (Status.dwCheckPoint != dwCheckPoint)
        {
            dwCheckPoint = Status.dwCheckPoint;
            dwStartTick = GetTickCount();
        }
        else if (GetTickCount() - dwStartTick > max(Status.dwWaitHint, 30000))
        {
            break;
        }

        dwWait = Status.dwWaitHint / 10;
        Sleep(min(max(dwWait, 250), 1000));
    }
    ConPuts(StdOut, L"\n");

    if (Status.dwCurrentState == SERVICE_STOPPED)
    {
        PrintMessageStringV(3529, pszDisplayName ? pszDisplayName : argv[2]);
        ConPuts(StdOut, L"\n");
    }
    else
    {
        PrintMessageStringV(3528, pszDisplayName ? pszDisplayName : argv[2]);
        ConPuts(StdOut, L"\n");
        PrintErrorMessage(NERR_ServiceCtlTimeout);
        nError = 2;
    }

done:
    if (pszDisplayName != NULL)
        HeapFree(GetProcessHeap(), 0, pszDisplayName);

    if (hService != NULL)
        CloseServiceHandle(hService);

    if (hManager != NULL)
        CloseServiceHandle(hManager);

    if (dwError == ERROR_SERVICE_DOES_NOT_EXIST)
        dwError = NERR_BadServiceName;

    if (dwError != ERROR_SUCCESS)
    {
        PrintErrorMessage(dwError);
        nError = 2;
    }

    return nError;
}
