/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS net command
 * FILE:            base/applications/network/net/cmdStart.c
 * PURPOSE:
 *
 * PROGRAMMERS:     Magnus Olsen (greatlord@reactos.org)
 */

#include "net.h"

static
int
__cdecl
CompareServiceNames(
    const void *p1,
    const void *p2)
{
    return lstrcmpiW(*(PCWSTR *)p1, *(PCWSTR *)p2);
}

/* Enumerate all running services */
static
INT
EnumerateRunningServices(VOID)
{
    SC_HANDLE hManager = NULL;
    DWORD dwBufferSize = 0;
    DWORD dwBytesNeeded = 0;
    DWORD dwServiceCount;
    DWORD dwResumeHandle = 0;
    LPENUM_SERVICE_STATUSW lpServiceBuffer = NULL;
    PWSTR *pNames = NULL, *pNewNames;
    DWORD dwNameCount = 0, i;
    DWORD dwError = ERROR_SUCCESS;
    BOOL ret;

    hManager = OpenSCManagerW(NULL,
                              SERVICES_ACTIVE_DATABASE,
                              SC_MANAGER_ENUMERATE_SERVICE);
    if (hManager == NULL)
    {
        dwError = GetLastError();
        goto done;
    }

    /* Collect the display names; ERROR_MORE_DATA asks for another call */
    for (;;)
    {
        ret = EnumServicesStatusW(hManager,
                                  SERVICE_WIN32,
                                  SERVICE_ACTIVE,
                                  lpServiceBuffer,
                                  dwBufferSize,
                                  &dwBytesNeeded,
                                  &dwServiceCount,
                                  &dwResumeHandle);
        if (!ret && GetLastError() != ERROR_MORE_DATA)
        {
            dwError = GetLastError();
            goto done;
        }

        if (dwServiceCount != 0)
        {
            if (pNames == NULL)
                pNewNames = HeapAlloc(GetProcessHeap(), 0, dwServiceCount * sizeof(PWSTR));
            else
                pNewNames = HeapReAlloc(GetProcessHeap(), 0, pNames,
                                        (dwNameCount + dwServiceCount) * sizeof(PWSTR));
            if (pNewNames == NULL)
            {
                dwError = ERROR_NOT_ENOUGH_MEMORY;
                goto done;
            }
            pNames = pNewNames;

            for (i = 0; i < dwServiceCount; i++)
            {
                SIZE_T cbName = (wcslen(lpServiceBuffer[i].lpDisplayName) + 1) * sizeof(WCHAR);
                pNames[dwNameCount] = HeapAlloc(GetProcessHeap(), 0, cbName);
                if (pNames[dwNameCount] == NULL)
                {
                    dwError = ERROR_NOT_ENOUGH_MEMORY;
                    goto done;
                }
                CopyMemory(pNames[dwNameCount], lpServiceBuffer[i].lpDisplayName, cbName);
                dwNameCount++;
            }
        }

        if (ret)
            break;

        if (dwServiceCount == 0 && dwBytesNeeded <= dwBufferSize)
        {
            dwError = ERROR_MORE_DATA;
            goto done;
        }

        if (dwBytesNeeded > dwBufferSize)
        {
            if (lpServiceBuffer != NULL)
                HeapFree(GetProcessHeap(), 0, lpServiceBuffer);
            dwBufferSize = dwBytesNeeded;
            lpServiceBuffer = HeapAlloc(GetProcessHeap(), 0, dwBufferSize);
            if (lpServiceBuffer == NULL)
            {
                dwError = ERROR_NOT_ENOUGH_MEMORY;
                goto done;
            }
        }
    }

    qsort(pNames, dwNameCount, sizeof(PWSTR), CompareServiceNames);

    PrintMessageString(3520);
    ConPuts(StdOut, L"\n");
    for (i = 0; i < dwNameCount; i++)
    {
        ConPrintf(StdOut, L"   %s\n", pNames[i]);
    }
    ConPuts(StdOut, L"\n");
    PrintMessageString(3500);
    ConPuts(StdOut, L"\n");

done:
    if (pNames != NULL)
    {
        for (i = 0; i < dwNameCount; i++)
            HeapFree(GetProcessHeap(), 0, pNames[i]);
        HeapFree(GetProcessHeap(), 0, pNames);
    }

    if (lpServiceBuffer != NULL)
        HeapFree(GetProcessHeap(), 0, lpServiceBuffer);

    if (hManager != NULL)
        CloseServiceHandle(hManager);

    if (dwError != ERROR_SUCCESS)
    {
        PrintErrorMessage(dwError);
        return 2;
    }

    return 0;
}

/* Report a failed start the way the service ended */
static
VOID
PrintStartFailure(
    PCWSTR pszDisplayName,
    SERVICE_STATUS_PROCESS *pStatus)
{
    WCHAR szCode[16];

    PrintMessageStringV(3523, pszDisplayName);
    ConPuts(StdOut, L"\n");

    if (pStatus->dwCurrentState == SERVICE_START_PENDING)
    {
        PrintErrorMessage(NERR_ServiceCtlTimeout);
    }
    else if (pStatus->dwWin32ExitCode == ERROR_SERVICE_SPECIFIC_ERROR)
    {
        StringCchPrintfW(szCode, ARRAYSIZE(szCode), L"%lu", pStatus->dwServiceSpecificExitCode);
        PrintMessageStringV(3547, szCode);
        ConPuts(StdOut, L"\n");
        PrintMessageStringV(3514, L"3547");
        ConPuts(StdOut, L"\n");
    }
    else if (pStatus->dwWin32ExitCode != ERROR_SUCCESS)
    {
        PrintErrorMessage(pStatus->dwWin32ExitCode);
    }
    else
    {
        PrintErrorMessage(3534);
    }
}

/* Start the service argv[2] */
static
INT
StartOneService(INT argc, WCHAR **argv)
{
    SC_HANDLE hManager = NULL;
    SC_HANDLE hService = NULL;
    LPCWSTR *lpArgVectors = NULL;
    SERVICE_STATUS_PROCESS Status;
    PCWSTR pszServiceName = argv[2];
    WCHAR szKeyName[257];
    PWSTR pszDisplayName = NULL;
    DWORD dwSize, dwCheckPoint, dwWait, dwStartTick;
    DWORD dwError = ERROR_SUCCESS;
    INT nError = 0;
    INT i;

    hManager = OpenSCManagerW(NULL,
                              SERVICES_ACTIVE_DATABASE,
                              SC_MANAGER_CONNECT);
    if (hManager == NULL)
    {
        dwError = GetLastError();
        nError = 2;
        goto done;
    }

    hService = OpenServiceW(hManager,
                            argv[2],
                            SERVICE_START | SERVICE_QUERY_STATUS);
    if (hService == NULL && GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST)
    {
        /* The service may be named by its display name */
        dwSize = ARRAYSIZE(szKeyName);
        if (GetServiceKeyNameW(hManager, argv[2], szKeyName, &dwSize))
        {
            pszServiceName = szKeyName;
            hService = OpenServiceW(hManager, pszServiceName, SERVICE_START | SERVICE_QUERY_STATUS);
        }
        else if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        {
            /* Longer than any key name: not a name of an installed service */
            SetLastError(ERROR_SERVICE_DOES_NOT_EXIST);
        }
    }
    if (hService == NULL)
    {
        dwError = GetLastError();
        nError = 2;
        goto done;
    }

    /*
     * The arguments after the service name are the start arguments; the name
     * itself is not one of them (the service gets it as its argv[0]).
     */
    lpArgVectors = HeapAlloc(GetProcessHeap(),
                             0,
                             (argc - 2) * sizeof(LPCWSTR));
    if (lpArgVectors == NULL)
    {
        dwError = ERROR_NOT_ENOUGH_MEMORY;
        nError = 2;
        goto done;
    }

    for (i = 3; i < argc; i++)
    {
        lpArgVectors[i - 3] = argv[i];
    }

    if (!StartServiceW(hService,
                       (DWORD)argc - 3,
                       argc > 3 ? lpArgVectors : NULL))
    {
        dwError = GetLastError();
        nError = 2;
        goto done;
    }

    dwSize = 0;
    GetServiceDisplayNameW(hManager, pszServiceName, NULL, &dwSize);
    pszDisplayName = HeapAlloc(GetProcessHeap(), 0, (dwSize + 1) * sizeof(WCHAR));
    if (pszDisplayName != NULL)
    {
        dwSize++;
        if (!GetServiceDisplayNameW(hManager, pszServiceName, pszDisplayName, &dwSize))
        {
            HeapFree(GetProcessHeap(), 0, pszDisplayName);
            pszDisplayName = NULL;
        }
    }

    PrintMessageStringV(3522, pszDisplayName ? pszDisplayName : pszServiceName);

    /* Wait while the service makes progress, as its wait hint allows */
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
            nError = 2;
            goto done;
        }

        if (Status.dwCurrentState != SERVICE_START_PENDING)
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

    if (Status.dwCurrentState == SERVICE_RUNNING)
    {
        PrintMessageStringV(3524, pszDisplayName ? pszDisplayName : pszServiceName);
        ConPuts(StdOut, L"\n");
    }
    else
    {
        PrintStartFailure(pszDisplayName ? pszDisplayName : pszServiceName, &Status);
        nError = 2;
    }

done:
    if (pszDisplayName != NULL)
        HeapFree(GetProcessHeap(), 0, pszDisplayName);

    if (lpArgVectors != NULL)
        HeapFree(GetProcessHeap(), 0, (LPVOID)lpArgVectors);

    if (hService != NULL)
        CloseServiceHandle(hService);

    if (hManager != NULL)
        CloseServiceHandle(hManager);

    if (dwError == ERROR_SERVICE_ALREADY_RUNNING)
        PrintErrorMessage(NERR_ServiceInstalled);
    else if (dwError == ERROR_SERVICE_DOES_NOT_EXIST)
        PrintErrorMessage(NERR_BadServiceName);
    else if (dwError != ERROR_SUCCESS)
        PrintErrorMessage(dwError);

    return nError;
}

INT
cmdStart(INT argc, WCHAR **argv)
{
    INT i;

    if (argc == 2)
    {
        return EnumerateRunningServices();
    }

    for (i = 2; i < argc; i++)
    {
        if (_wcsicmp(argv[i], L"/help") == 0)
        {
            PrintMessageString(4381);
            ConPuts(StdOut, L"\n");
            PrintNetMessage(MSG_START_SYNTAX);
            PrintNetMessage(MSG_START_HELP);
            return 1;
        }
    }

    return StartOneService(argc, argv);
}
