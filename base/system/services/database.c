/*
 * PROJECT:     ReactOS Service Control Manager
 * LICENSE:     GPL - See COPYING in the top level directory
 * FILE:        base/system/services/database.c
 * PURPOSE:     Database control interface
 * COPYRIGHT:   Copyright 2002-2006 Eric Kohl
 *              Copyright 2006 Hervé Poussineau <hpoussin@reactos.org>
 *              Copyright 2007 Ged Murphy <gedmurphy@reactos.org>
 *                             Gregor Brunmar <gregor.brunmar@home.se>
 *
 */

/* INCLUDES *****************************************************************/

#include "services.h"

#include <winbase_undoc.h>
#include <userenv.h>
#include <reason.h>
#include <strsafe.h>
#include <ntsecapi.h>

#define NDEBUG
#include <debug.h>


/* GLOBALS *******************************************************************/

LIST_ENTRY ImageListHead;
LIST_ENTRY ServiceListHead;

static RTL_RESOURCE DatabaseLock;
static DWORD ResumeCount = 1;
static LONG StatusHandleCount = 0;
static DWORD NoInteractiveServices = 0;
static DWORD ServiceTag = 0;

/* Threads that touch the database on their own: the shutdown waits for them */
static LONG ScmActiveWorkers = 0;
static HANDLE hFailureShutdownEvent = NULL; /* Set at shutdown: ends the delay of the failure actions */

/* The critical section synchronizes service control requests */
static CRITICAL_SECTION ControlServiceCriticalSection;
static DWORD PipeTimeout = 30000; /* 30 Seconds */


/* FUNCTIONS *****************************************************************/

static
BOOL
ScmIsSecurityService(
    _In_ PSERVICE_IMAGE pServiceImage)
{
    return (wcsstr(pServiceImage->pszImagePath, L"\\system32\\lsass.exe") != NULL);
}


static DWORD
ScmCreateNewControlPipe(
    _In_ PSERVICE_IMAGE pServiceImage,
    _In_ BOOL bSecurityServiceProcess)
{
    WCHAR szControlPipeName[MAX_PATH + 1];
    SECURITY_ATTRIBUTES SecurityAttributes;
    HKEY hServiceCurrentKey = INVALID_HANDLE_VALUE;
    DWORD dwServiceCurrent = 1;
    DWORD dwKeyDisposition;
    DWORD dwKeySize;
    DWORD dwError;

    /* Get the service number */
    if (bSecurityServiceProcess == FALSE)
    {
        /* TODO: Create registry entry with correct write access */
        dwError = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                                  L"SYSTEM\\CurrentControlSet\\Control\\ServiceCurrent",
                                  0,
                                  NULL,
                                  REG_OPTION_VOLATILE,
                                  KEY_WRITE | KEY_READ,
                                  NULL,
                                  &hServiceCurrentKey,
                                  &dwKeyDisposition);
        if (dwError != ERROR_SUCCESS)
        {
            DPRINT1("RegCreateKeyEx() failed with error %lu\n", dwError);
            return dwError;
        }

        if (dwKeyDisposition == REG_OPENED_EXISTING_KEY)
        {
            dwKeySize = sizeof(DWORD);
            dwError = RegQueryValueExW(hServiceCurrentKey,
                                       L"",
                                       0,
                                       NULL,
                                       (BYTE*)&dwServiceCurrent,
                                       &dwKeySize);
            if (dwError != ERROR_SUCCESS)
            {
                RegCloseKey(hServiceCurrentKey);
                DPRINT1("RegQueryValueEx() failed with error %lu\n", dwError);
                return dwError;
            }

            dwServiceCurrent++;
        }

        dwError = RegSetValueExW(hServiceCurrentKey,
                                 L"",
                                 0,
                                 REG_DWORD,
                                 (BYTE*)&dwServiceCurrent,
                                 sizeof(dwServiceCurrent));

        RegCloseKey(hServiceCurrentKey);

        if (dwError != ERROR_SUCCESS)
        {
            DPRINT1("RegSetValueExW() failed (Error %lu)\n", dwError);
            return dwError;
        }
    }
    else
    {
        dwServiceCurrent = 0;
    }

    /* Create '\\.\pipe\net\NtControlPipeXXX' instance */
    StringCchPrintfW(szControlPipeName, ARRAYSIZE(szControlPipeName),
                     L"\\\\.\\pipe\\net\\NtControlPipe%lu", dwServiceCurrent);

    DPRINT("PipeName: %S\n", szControlPipeName);

    SecurityAttributes.nLength = sizeof(SecurityAttributes);
    SecurityAttributes.lpSecurityDescriptor = pPipeSD;
    SecurityAttributes.bInheritHandle = FALSE;

    pServiceImage->hControlPipe = CreateNamedPipeW(szControlPipeName,
                                                   PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                                                   PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                                                   100,
                                                   8000,
                                                   4,
                                                   PipeTimeout,
                                                   &SecurityAttributes);
    DPRINT("CreateNamedPipeW(%S) done\n", szControlPipeName);
    if (pServiceImage->hControlPipe == INVALID_HANDLE_VALUE)
    {
        DPRINT1("Failed to create control pipe\n");
        return GetLastError();
    }

    return ERROR_SUCCESS;
}


static PSERVICE_IMAGE
ScmGetServiceImageByImagePath(LPWSTR lpImagePath)
{
    PLIST_ENTRY ImageEntry;
    PSERVICE_IMAGE CurrentImage;

    DPRINT("ScmGetServiceImageByImagePath(%S) called\n", lpImagePath);

    ImageEntry = ImageListHead.Flink;
    while (ImageEntry != &ImageListHead)
    {
        CurrentImage = CONTAINING_RECORD(ImageEntry,
                                         SERVICE_IMAGE,
                                         ImageListEntry);
        if (CurrentImage->bSharedProcess && !CurrentImage->bProcessEnded &&
            _wcsicmp(CurrentImage->pszImagePath, lpImagePath) == 0)
        {
            DPRINT("Found image: '%S'\n", CurrentImage->pszImagePath);
            return CurrentImage;
        }

        ImageEntry = ImageEntry->Flink;
    }

    DPRINT("Couldn't find a matching image\n");

    return NULL;

}


DWORD
ScmGetServiceNameFromTag(IN PTAG_INFO_NAME_FROM_TAG_IN_PARAMS InParams,
                         OUT PTAG_INFO_NAME_FROM_TAG_OUT_PARAMS *OutParams)
{
    PLIST_ENTRY ServiceEntry;
    PSERVICE CurrentService;
    PSERVICE_IMAGE CurrentImage;
    PTAG_INFO_NAME_FROM_TAG_OUT_PARAMS OutBuffer = NULL;
    DWORD dwError;

    /* Lock the database */
    ScmLockDatabaseExclusive();

    /* Find the matching service */
    ServiceEntry = ServiceListHead.Flink;
    while (ServiceEntry != &ServiceListHead)
    {
        CurrentService = CONTAINING_RECORD(ServiceEntry,
                                           SERVICE,
                                           ServiceListEntry);

        /* We must match the tag */
        if (CurrentService->dwServiceTag == InParams->dwTag &&
            CurrentService->lpImage != NULL)
        {
            CurrentImage = CurrentService->lpImage;
            /* And matching the PID */
            if (CurrentImage->dwProcessId == InParams->dwPid)
            {
                break;
            }
        }

        ServiceEntry = ServiceEntry->Flink;
    }

    /* No match! */
    if (ServiceEntry == &ServiceListHead)
    {
        dwError = ERROR_RETRY;
        goto Cleanup;
    }

    /* Allocate the output buffer */
    OutBuffer = MIDL_user_allocate(sizeof(TAG_INFO_NAME_FROM_TAG_OUT_PARAMS));
    if (OutBuffer == NULL)
    {
        dwError = ERROR_NOT_ENOUGH_MEMORY;
        goto Cleanup;
    }

    /* And the buffer for the name */
    OutBuffer->pszName = MIDL_user_allocate(wcslen(CurrentService->lpServiceName) * sizeof(WCHAR) + sizeof(UNICODE_NULL));
    if (OutBuffer->pszName == NULL)
    {
        dwError = ERROR_NOT_ENOUGH_MEMORY;
        goto Cleanup;
    }

    /* Fill in output data */
    wcscpy(OutBuffer->pszName, CurrentService->lpServiceName);
    OutBuffer->TagType = TagTypeService;

    /* And return */
    *OutParams = OutBuffer;
    dwError = ERROR_SUCCESS;

Cleanup:

    /* Unlock database */
    ScmUnlockDatabase();

    /* If failure, free allocated memory */
    if (dwError != ERROR_SUCCESS)
    {
        if (OutBuffer != NULL)
        {
            MIDL_user_free(OutBuffer);
        }
    }

    /* Return error/success */
    return dwError;
}


static
BOOL
ScmIsSameServiceAccount(
    _In_ PCWSTR pszAccountName1,
    _In_ PCWSTR pszAccountName2)
{
    if (pszAccountName1 == NULL &&
        pszAccountName2 == NULL)
        return TRUE;

    if (pszAccountName1 == NULL &&
        pszAccountName2 != NULL &&
        _wcsicmp(pszAccountName2, L"LocalSystem") == 0)
        return TRUE;

    if (pszAccountName1 != NULL &&
        pszAccountName2 == NULL &&
        _wcsicmp(pszAccountName1, L"LocalSystem") == 0)
        return TRUE;

    if (pszAccountName1 != NULL &&
        pszAccountName2 != NULL &&
        _wcsicmp(pszAccountName1, pszAccountName2) == 0)
        return TRUE;

    return FALSE;
}


static
BOOL
ScmIsLocalSystemAccount(
    _In_ PCWSTR pszAccountName)
{
    if (pszAccountName == NULL ||
        _wcsicmp(pszAccountName, L"LocalSystem") == 0)
        return TRUE;

    return FALSE;
}


static
BOOL
ScmEnableBackupRestorePrivileges(
    _In_ HANDLE hToken,
    _In_ BOOL bEnable)
{
    PTOKEN_PRIVILEGES pTokenPrivileges = NULL;
    DWORD dwSize;
    BOOL bRet = FALSE;

    DPRINT("ScmEnableBackupRestorePrivileges(%p %d)\n", hToken, bEnable);

    dwSize = sizeof(TOKEN_PRIVILEGES) + 2 * sizeof(LUID_AND_ATTRIBUTES);
    pTokenPrivileges = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    if (pTokenPrivileges == NULL)
    {
        DPRINT1("Failed to allocate privilege buffer\n");
        goto done;
    }

    pTokenPrivileges->PrivilegeCount = 2;
    pTokenPrivileges->Privileges[0].Luid.LowPart = SE_BACKUP_PRIVILEGE;
    pTokenPrivileges->Privileges[0].Luid.HighPart = 0;
    pTokenPrivileges->Privileges[0].Attributes = (bEnable ? SE_PRIVILEGE_ENABLED : 0);
    pTokenPrivileges->Privileges[1].Luid.LowPart = SE_RESTORE_PRIVILEGE;
    pTokenPrivileges->Privileges[1].Luid.HighPart = 0;
    pTokenPrivileges->Privileges[1].Attributes = (bEnable ? SE_PRIVILEGE_ENABLED : 0);

    bRet = AdjustTokenPrivileges(hToken, FALSE, pTokenPrivileges, 0, NULL, NULL);
    if (!bRet)
    {
        DPRINT1("AdjustTokenPrivileges() failed with error %lu\n", GetLastError());
    }
    else if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        DPRINT1("AdjustTokenPrivileges() succeeded, but with not all privileges assigned\n");
        bRet = FALSE;
    }

done:
    if (pTokenPrivileges != NULL)
        HeapFree(GetProcessHeap(), 0, pTokenPrivileges);

    return bRet;
}


/*
 * The password of a service's account is kept as the LSA secret _SC_<service name>. Read it here, in the
 * service control manager that runs as SYSTEM and may: the logon must never take the name of a secret
 * for a password, which would let any caller log on as the account. Without such a secret (the special
 * accounts LocalService and NetworkService have none) the name is passed as an ordinary, meaningless
 * password. Returns a heap string the caller zeroes and frees.
 */
static PWSTR
ScmGetServicePassword(
    _In_ PCWSTR pszServiceName,
    _In_ BOOL bSpecialAccount)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    LSA_HANDLE PolicyHandle = NULL;
    UNICODE_STRING SecretName;
    PUNICODE_STRING PrivateData = NULL;
    PWSTR pszPassword = NULL;
    SIZE_T Length = wcslen(pszServiceName);

    SecretName.Buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (Length + 5) * sizeof(WCHAR));
    if (SecretName.Buffer == NULL)
        return NULL;
    wcscpy(SecretName.Buffer, L"_SC_");
    wcscat(SecretName.Buffer, pszServiceName);
    SecretName.Length = (USHORT)((Length + 4) * sizeof(WCHAR));
    SecretName.MaximumLength = SecretName.Length + sizeof(WCHAR);

    RtlZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
    if (!bSpecialAccount &&
        NT_SUCCESS(LsaOpenPolicy(NULL, &ObjectAttributes, POLICY_GET_PRIVATE_INFORMATION, &PolicyHandle)))
    {
        if (NT_SUCCESS(LsaRetrievePrivateData(PolicyHandle, &SecretName, &PrivateData)) && PrivateData)
        {
            pszPassword = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PrivateData->Length + sizeof(WCHAR));
            if (pszPassword)
                RtlCopyMemory(pszPassword, PrivateData->Buffer, PrivateData->Length);
            SecureZeroMemory(PrivateData->Buffer, PrivateData->Length);
            LsaFreeMemory(PrivateData);
        }
        LsaClose(PolicyHandle);
    }

    if (pszPassword == NULL)
        return SecretName.Buffer;   /* no secret: the name itself */

    HeapFree(GetProcessHeap(), 0, SecretName.Buffer);
    return pszPassword;
}


static
DWORD
ScmLogonService(
    IN PSERVICE pService,
    IN PSERVICE_IMAGE pImage)
{
    PROFILEINFOW ProfileInfo;
    PWSTR pszUserName = NULL;
    PWSTR pszDomainName = NULL;
    PWSTR pszPassword = NULL;
    PWSTR ptr;
    DWORD dwError = ERROR_SUCCESS;

    DPRINT("ScmLogonService(%p %p)\n", pService, pImage);
    DPRINT("Service %S\n", pService->lpServiceName);

    if (ScmIsLocalSystemAccount(pImage->pszAccountName) || ScmLiveSetup || ScmSetupInProgress)
        return ERROR_SUCCESS;

    /* Get the user and domain names */
    ptr = wcschr(pImage->pszAccountName, L'\\');
    if (ptr != NULL)
    {
        *ptr = L'\0';
        pszUserName = ptr + 1;
        pszDomainName = pImage->pszAccountName;
    }
    else
    {
        // ERROR_INVALID_SERVICE_ACCOUNT
        pszUserName = pImage->pszAccountName;
        pszDomainName = NULL;
    }

    /* Get the password of the account: the LSA secret _SC_<service name>. The special accounts of
     * NT AUTHORITY and the virtual accounts of NT SERVICE have none (and the LSA may not be up yet when they are started) */
    pszPassword = ScmGetServicePassword(pService->lpServiceName,
                                        pszDomainName != NULL &&
                                        (!_wcsicmp(pszDomainName, L"NT AUTHORITY") ||
                                         !_wcsicmp(pszDomainName, L"NT SERVICE")));
    if (pszPassword == NULL)
    {
        dwError = ERROR_NOT_ENOUGH_MEMORY;
        goto done;
    }

    DPRINT("Domain: %S  User: %S\n", pszDomainName, pszUserName);

    /* Do the service logon */
    if (!LogonUserW(pszUserName,
                    pszDomainName,
                    pszPassword,
                    LOGON32_LOGON_SERVICE,
                    LOGON32_PROVIDER_DEFAULT,
                    &pImage->hToken))
    {
        dwError = GetLastError();
        DPRINT1("LogonUserW() failed (Error %lu)\n", dwError);

        /* Normalize the returned error */
        dwError = ERROR_SERVICE_LOGON_FAILED;
        goto done;
    }

    /* Load the user profile; the per-user environment variables are thus correctly initialized */
    ZeroMemory(&ProfileInfo, sizeof(ProfileInfo));
    ProfileInfo.dwSize = sizeof(ProfileInfo);
    ProfileInfo.dwFlags = PI_NOUI;
    ProfileInfo.lpUserName = pszUserName;
    // ProfileInfo.lpProfilePath = NULL;
    // ProfileInfo.lpDefaultPath = NULL;
    // ProfileInfo.lpServerName = NULL;
    // ProfileInfo.lpPolicyPath = NULL;
    // ProfileInfo.hProfile = NULL;

    ScmEnableBackupRestorePrivileges(pImage->hToken, TRUE);
    if (!LoadUserProfileW(pImage->hToken, &ProfileInfo))
        dwError = GetLastError();
    ScmEnableBackupRestorePrivileges(pImage->hToken, FALSE);

    if (dwError != ERROR_SUCCESS)
    {
        DPRINT1("LoadUserProfileW() failed (Error %lu)\n", dwError);
        goto done;
    }

    pImage->hProfile = ProfileInfo.hProfile;

done:
    if (pszPassword != NULL)
    {
        SecureZeroMemory(pszPassword, (wcslen(pszPassword) + 1) * sizeof(WCHAR));
        HeapFree(GetProcessHeap(), 0, pszPassword);
    }

    if (ptr != NULL)
        *ptr = L'\\';

    return dwError;
}


static DWORD
ScmCreateOrReferenceServiceImage(PSERVICE pService)
{
    RTL_QUERY_REGISTRY_TABLE QueryTable[3];
    UNICODE_STRING ImagePath;
    UNICODE_STRING ObjectName;
    PSERVICE_IMAGE pServiceImage = NULL;
    NTSTATUS Status;
    DWORD dwError = ERROR_SUCCESS;
    DWORD dwRecordSize;
    LPWSTR pString;
    BOOL bSecurityService;

    DPRINT("ScmCreateOrReferenceServiceImage(%p)\n", pService);

    RtlInitUnicodeString(&ImagePath, NULL);
    RtlInitUnicodeString(&ObjectName, NULL);

    /* Get service data */
    RtlZeroMemory(&QueryTable,
                  sizeof(QueryTable));

    QueryTable[0].Name = L"ImagePath";
    QueryTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_REQUIRED;
    QueryTable[0].EntryContext = &ImagePath;
    QueryTable[1].Name = L"ObjectName";
    QueryTable[1].Flags = RTL_QUERY_REGISTRY_DIRECT;
    QueryTable[1].EntryContext = &ObjectName;

    Status = RtlQueryRegistryValues(RTL_REGISTRY_SERVICES,
                                    pService->lpServiceName,
                                    QueryTable,
                                    NULL,
                                    NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("RtlQueryRegistryValues() failed (Status %lx)\n", Status);
        return RtlNtStatusToDosError(Status);
    }

    DPRINT("ImagePath: '%wZ'\n", &ImagePath);
    DPRINT("ObjectName: '%wZ'\n", &ObjectName);

    /* An own-process service always gets a process of its own */
    if (pService->Status.dwServiceType & SERVICE_WIN32_SHARE_PROCESS)
        pServiceImage = ScmGetServiceImageByImagePath(ImagePath.Buffer);
    if (pServiceImage == NULL)
    {
        dwRecordSize = sizeof(SERVICE_IMAGE) +
                       ImagePath.Length + sizeof(WCHAR) +
                       ((ObjectName.Length != 0) ? (ObjectName.Length + sizeof(WCHAR)) : 0);

        /* Create a new service image */
        pServiceImage = HeapAlloc(GetProcessHeap(),
                                  HEAP_ZERO_MEMORY,
                                  dwRecordSize);
        if (pServiceImage == NULL)
        {
            dwError = ERROR_NOT_ENOUGH_MEMORY;
            goto done;
        }

        pServiceImage->dwImageRunCount = 1;
        pServiceImage->bSharedProcess = (pService->Status.dwServiceType & SERVICE_WIN32_SHARE_PROCESS) != 0;
        pServiceImage->hControlPipe = INVALID_HANDLE_VALUE;
        pServiceImage->hProcess = INVALID_HANDLE_VALUE;

        pString = (PWSTR)((INT_PTR)pServiceImage + sizeof(SERVICE_IMAGE));

        /* Set the image path */
        pServiceImage->pszImagePath = pString;
        wcscpy(pServiceImage->pszImagePath,
               ImagePath.Buffer);

        /* Set the account name */
        if (ObjectName.Length > 0)
        {
            pString = pString + wcslen(pString) + 1;

            pServiceImage->pszAccountName = pString;
            wcscpy(pServiceImage->pszAccountName,
                   ObjectName.Buffer);
        }

        /* Service logon */
        dwError = ScmLogonService(pService, pServiceImage);
        if (dwError != ERROR_SUCCESS)
        {
            DPRINT1("ScmLogonService() failed (Error %lu)\n", dwError);

            /* Release the service image */
            HeapFree(GetProcessHeap(), 0, pServiceImage);

            goto done;
        }

        bSecurityService = ScmIsSecurityService(pServiceImage);

        /* Create the control pipe */
        dwError = ScmCreateNewControlPipe(pServiceImage,
                                          bSecurityService);
        if (dwError != ERROR_SUCCESS)
        {
            DPRINT1("ScmCreateNewControlPipe() failed (Error %lu)\n", dwError);

            /* Unload the user profile */
            if (pServiceImage->hProfile != NULL)
            {
                ScmEnableBackupRestorePrivileges(pServiceImage->hToken, TRUE);
                UnloadUserProfile(pServiceImage->hToken, pServiceImage->hProfile);
                ScmEnableBackupRestorePrivileges(pServiceImage->hToken, FALSE);
            }

            /* Close the logon token */
            if (pServiceImage->hToken != NULL)
                CloseHandle(pServiceImage->hToken);

            /* Release the service image */
            HeapFree(GetProcessHeap(), 0, pServiceImage);

            goto done;
        }

        if (bSecurityService)
        {
            SetSecurityServicesEvent();
        }

        /* FIXME: Add more initialization code here */


        /* Append service record */
        InsertTailList(&ImageListHead,
                       &pServiceImage->ImageListEntry);
    }
    else
    {
        /* Fail if services in an image use different accounts */
        if (!ScmIsSameServiceAccount(pServiceImage->pszAccountName, ObjectName.Buffer))
        {
            dwError = ERROR_DIFFERENT_SERVICE_ACCOUNT;
            goto done;
        }

        /* Increment the run counter */
        pServiceImage->dwImageRunCount++;
    }

    DPRINT("pServiceImage->pszImagePath: %S\n", pServiceImage->pszImagePath);
    DPRINT("pServiceImage->pszAccountName: %S\n", pServiceImage->pszAccountName);
    DPRINT("pServiceImage->dwImageRunCount: %lu\n", pServiceImage->dwImageRunCount);

    /* Link the service image to the service */
    pService->lpImage = pServiceImage;

done:
    RtlFreeUnicodeString(&ObjectName);
    RtlFreeUnicodeString(&ImagePath);

    DPRINT("ScmCreateOrReferenceServiceImage() done (Error: %lu)\n", dwError);

    return dwError;
}


/*
 * A service process is watched on a thread of its own. When the process ends while a
 * service of it is not stopped, the service did not end on its own: the process crashed
 * or was killed. The service is reported as stopped and its failure actions run.
 */
struct _SERVICE_PROCESS_WATCH
{
    LONG RefCount;
    HANDLE hProcess;
    HANDLE hCancel;
};

typedef struct _FAILURE_ACTION_CONTEXT
{
    PSERVICE Service;
    SC_ACTION_TYPE Type;
    DWORD dwDelay;
    DWORD dwFailureCount;
    LPWSTR lpCommand;
    HANDLE hToken; /* The account of the service, or NULL for the account of the controller */
    LPVOID lpEnvironment; /* Made while the profile of the service account is still loaded */
} FAILURE_ACTION_CONTEXT, *PFAILURE_ACTION_CONTEXT;

static VOID
ScmReleaseProcessWatch(PSERVICE_PROCESS_WATCH pWatch)
{
    if (InterlockedDecrement(&pWatch->RefCount) == 0)
    {
        CloseHandle(pWatch->hProcess);
        CloseHandle(pWatch->hCancel);
        HeapFree(GetProcessHeap(), 0, pWatch);
    }
}

/* The command of a failure action names the failure count as "%1%" */
static LPWSTR
ScmExpandFailureCommand(LPCWSTR lpCommand, DWORD dwFailureCount)
{
    WCHAR szCount[16];
    SIZE_T cchCount, cchNeeded = 1;
    LPCWSTR lpSrc;
    LPWSTR lpResult, lpDst;

    StringCchPrintfW(szCount, ARRAYSIZE(szCount), L"%lu", dwFailureCount);
    cchCount = wcslen(szCount);

    for (lpSrc = lpCommand; *lpSrc; )
    {
        if (!_wcsnicmp(lpSrc, L"%1%", 3))
        {
            cchNeeded += cchCount;
            lpSrc += 3;
        }
        else
        {
            cchNeeded++;
            lpSrc++;
        }
    }

    lpResult = HeapAlloc(GetProcessHeap(), 0, cchNeeded * sizeof(WCHAR));
    if (lpResult == NULL)
        return NULL;

    for (lpSrc = lpCommand, lpDst = lpResult; *lpSrc; )
    {
        if (!_wcsnicmp(lpSrc, L"%1%", 3))
        {
            wcscpy(lpDst, szCount);
            lpDst += cchCount;
            lpSrc += 3;
        }
        else
        {
            *lpDst++ = *lpSrc++;
        }
    }
    *lpDst = UNICODE_NULL;
    return lpResult;
}

static VOID
ScmRunFailureCommand(PFAILURE_ACTION_CONTEXT pContext)
{
    STARTUPINFOW StartupInfo;
    PROCESS_INFORMATION ProcessInformation;
    LPWSTR lpCommandLine;
    BOOL bResult = FALSE;
    DWORD dwError = ERROR_SUCCESS;

    if (pContext->lpCommand == NULL)
        return;

    lpCommandLine = ScmExpandFailureCommand(pContext->lpCommand, pContext->dwFailureCount);
    if (lpCommandLine == NULL)
        return;

    ZeroMemory(&StartupInfo, sizeof(StartupInfo));
    StartupInfo.cb = sizeof(StartupInfo);

    if (pContext->hToken != NULL)
    {
        /* The command runs in the account of the service */
        if (ImpersonateLoggedOnUser(pContext->hToken))
        {
            bResult = CreateProcessAsUserW(pContext->hToken,
                                           NULL,
                                           lpCommandLine,
                                           NULL,
                                           NULL,
                                           FALSE,
                                           CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
                                           pContext->lpEnvironment,
                                           NULL,
                                           &StartupInfo,
                                           &ProcessInformation);
            if (!bResult)
                dwError = GetLastError();
            RevertToSelf();
        }
        else
        {
            dwError = GetLastError();
        }
    }
    else
    {
        bResult = CreateProcessW(NULL,
                                 lpCommandLine,
                                 NULL,
                                 NULL,
                                 FALSE,
                                 CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
                                 pContext->lpEnvironment,
                                 NULL,
                                 &StartupInfo,
                                 &ProcessInformation);
        if (!bResult)
            dwError = GetLastError();
    }

    if (bResult)
    {
        CloseHandle(ProcessInformation.hThread);
        CloseHandle(ProcessInformation.hProcess);
    }
    else
    {
        DPRINT1("Failure command of service %S failed with error %lu\n",
                pContext->Service->lpServiceName, dwError);
    }

    HeapFree(GetProcessHeap(), 0, lpCommandLine);
}

static VOID
ScmFreeFailureActionContext(PFAILURE_ACTION_CONTEXT pContext)
{
    if (pContext->lpEnvironment)
        DestroyEnvironmentBlock(pContext->lpEnvironment);
    if (pContext->hToken)
        CloseHandle(pContext->hToken);
    if (pContext->lpCommand)
        HeapFree(GetProcessHeap(), 0, pContext->lpCommand);
    HeapFree(GetProcessHeap(), 0, pContext);
}

static DWORD WINAPI
ScmFailureActionThread(PVOID pParam)
{
    PFAILURE_ACTION_CONTEXT pContext = pParam;
    PSERVICE Service = pContext->Service;
    BOOL bStart = FALSE;
    DWORD dwRemaining = pContext->dwDelay, dwSlice;

    /* The delay ends early when the system shuts down */
    if (hFailureShutdownEvent != NULL)
    {
        if (dwRemaining != 0 && !ScmShutdown)
            WaitForSingleObject(hFailureShutdownEvent, dwRemaining);
    }
    else
    {
        while (dwRemaining != 0 && !ScmShutdown)
        {
            dwSlice = min(100, dwRemaining);
            Sleep(dwSlice);
            dwRemaining -= dwSlice;
        }
    }

    /* The database goes away at shutdown: touch nothing of it then */
    if (ScmShutdown)
    {
        ScmFreeFailureActionContext(pContext);
        InterlockedDecrement(&ScmActiveWorkers);
        return 0;
    }

    if (pContext->Type == SC_ACTION_RESTART)
    {
        ScmLockDatabaseShared();
        bStart = !ScmShutdown &&
                 !Service->bDeleted &&
                 Service->dwStartType != SERVICE_DISABLED &&
                 Service->Status.dwCurrentState == SERVICE_STOPPED;
        ScmUnlockDatabase();

        if (bStart)
            ScmStartService(Service, 0, NULL);
    }
    else if (pContext->Type == SC_ACTION_RUN_COMMAND)
    {
        ScmRunFailureCommand(pContext);
    }
    else if (pContext->Type == SC_ACTION_REBOOT)
    {
        BOOLEAN bOld;

        RtlAdjustPrivilege(SE_SHUTDOWN_PRIVILEGE, TRUE, FALSE, &bOld);
        if (!InitiateSystemShutdownExW(NULL,
                                       pContext->lpCommand, /* the reboot message */
                                       0,
                                       TRUE,
                                       TRUE,
                                       SHTDN_REASON_MAJOR_APPLICATION | SHTDN_REASON_MINOR_MAINTENANCE))
        {
            DPRINT1("Reboot for service %S failed with error %lu\n", Service->lpServiceName, GetLastError());
        }
    }

    /* Drop the reference that kept the service for this action */
    if (!ScmShutdown)
    {
        ScmLockDatabaseExclusive();
        ScmDereferenceService(Service);
        ScmUnlockDatabase();
    }

    ScmFreeFailureActionContext(pContext);
    InterlockedDecrement(&ScmActiveWorkers);
    return 0;
}

/*
 * The events about failed services are queued while the database lock is held and written when it is
 * released: the event log is another service, and the database must not wait for it.
 */
typedef struct _FAILURE_LOG_ENTRY
{
    LIST_ENTRY ListEntry;
    DWORD dwEventId;
    WORD wStrings;
    WCHAR szName[MAX_PATH];
    WCHAR szCount[16];
    WCHAR szDelay[16];
    LPCWSTR lpActionText;
} FAILURE_LOG_ENTRY, *PFAILURE_LOG_ENTRY;

static VOID
ScmQueueFailureLog(PLIST_ENTRY pQueue,
                   DWORD dwEventId,
                   LPCWSTR lpName,
                   DWORD dwCount,
                   DWORD dwDelay,
                   LPCWSTR lpActionText)
{
    PFAILURE_LOG_ENTRY pEntry = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*pEntry));

    if (pEntry == NULL)
        return;

    pEntry->dwEventId = dwEventId;
    pEntry->wStrings = (lpActionText != NULL) ? 5 : 2;
    pEntry->lpActionText = lpActionText;
    StringCchCopyW(pEntry->szName, ARRAYSIZE(pEntry->szName), lpName);
    StringCchPrintfW(pEntry->szCount, ARRAYSIZE(pEntry->szCount), L"%lu", dwCount);
    StringCchPrintfW(pEntry->szDelay, ARRAYSIZE(pEntry->szDelay), L"%lu", dwDelay);
    InsertTailList(pQueue, &pEntry->ListEntry);
}

/* Called without the database lock */
VOID
ScmFlushFailureLog(PLIST_ENTRY pQueue)
{
    PFAILURE_LOG_ENTRY pEntry;
    LPCWSTR lpLogStrings[5];

    while (!IsListEmpty(pQueue))
    {
        pEntry = CONTAINING_RECORD(RemoveHeadList(pQueue), FAILURE_LOG_ENTRY, ListEntry);

        lpLogStrings[0] = pEntry->szName;
        lpLogStrings[1] = pEntry->szCount;
        lpLogStrings[2] = pEntry->szDelay;
        lpLogStrings[3] = L"";
        lpLogStrings[4] = pEntry->lpActionText;
        ScmLogEvent(pEntry->dwEventId, EVENTLOG_ERROR_TYPE, pEntry->wStrings, lpLogStrings);

        HeapFree(GetProcessHeap(), 0, pEntry);
    }
}

/*
 * Count a failure of a service and run the action its failure actions name for that count.
 * Called with the database lock held exclusively.
 */
static VOID
ScmProcessServiceFailure(PSERVICE Service, PSERVICE_IMAGE Image, PLIST_ENTRY pLogQueue)
{
    HKEY hServiceKey;
    DWORD dwResetPeriod = 0, cActions = 0, dwError;
    LPSC_ACTION lpActions = NULL;
    LPWSTR lpCommand = NULL, lpRebootMsg = NULL;
    PFAILURE_ACTION_CONTEXT pContext;
    HANDLE hThread;
    SC_ACTION Action = { SC_ACTION_NONE, 0 };
    FILETIME ft;
    ULARGE_INTEGER Now;
    LPCWSTR lpActionText;

    GetSystemTimeAsFileTime(&ft);
    Now.LowPart = ft.dwLowDateTime;
    Now.HighPart = ft.dwHighDateTime;

    dwError = ScmOpenServiceKey(Service->lpServiceName, KEY_READ, &hServiceKey);
    if (dwError == ERROR_SUCCESS)
    {
        if (ScmReadFailureActions(hServiceKey, &dwResetPeriod, &cActions, &lpActions) != ERROR_SUCCESS)
            cActions = 0;
        ScmReadString(hServiceKey, L"FailureCommand", &lpCommand);
        ScmReadString(hServiceKey, L"RebootMessage", &lpRebootMsg);
        RegCloseKey(hServiceKey);
    }

    /* The failure count starts over when the service ran without failing for the reset period.
       A clock that was set back does not do that. */
    if (Service->dwFailureCount != 0 &&
        (dwResetPeriod != INFINITE) &&
        (Now.QuadPart >= Service->ullLastFailureTime) &&
        ((Now.QuadPart - Service->ullLastFailureTime) / 10000000ULL) >= dwResetPeriod)
    {
        Service->dwFailureCount = 0;
    }
    Service->dwFailureCount++;
    Service->ullLastFailureTime = Now.QuadPart;

    if (cActions != 0)
        Action = lpActions[min(Service->dwFailureCount, cActions) - 1];

    if (Action.Type == SC_ACTION_RESTART || Action.Type == SC_ACTION_RUN_COMMAND || Action.Type == SC_ACTION_REBOOT)
    {
        lpActionText = (Action.Type == SC_ACTION_RESTART) ? L"Restart the service" :
                       (Action.Type == SC_ACTION_RUN_COMMAND) ? L"Run a command" : L"Reboot the computer";
        ScmQueueFailureLog(pLogQueue, EVENT_SERVICE_CRASH, Service->lpDisplayName,
                           Service->dwFailureCount, Action.Delay, lpActionText);

        pContext = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*pContext));
        if (pContext != NULL)
        {
            pContext->Service = Service;
            pContext->Type = Action.Type;
            pContext->dwDelay = Action.Delay;
            pContext->dwFailureCount = Service->dwFailureCount;
            /* A reboot action carries the reboot message in place of the command */
            if (Action.Type == SC_ACTION_REBOOT)
            {
                pContext->lpCommand = lpRebootMsg;
                lpRebootMsg = NULL;
            }
            else
            {
                pContext->lpCommand = lpCommand;
                lpCommand = NULL;
            }

            /* A command runs in the account of the service, which the image no longer holds by then */
            if (Action.Type == SC_ACTION_RUN_COMMAND &&
                Image != NULL &&
                Image->hToken != NULL &&
                !DuplicateTokenEx(Image->hToken,
                                  MAXIMUM_ALLOWED,
                                  NULL,
                                  SecurityImpersonation,
                                  TokenPrimary,
                                  &pContext->hToken))
            {
                DPRINT1("Cannot copy the token of service %S (Error %lu), no recovery command runs\n",
                        Service->lpServiceName, GetLastError());
                ScmFreeFailureActionContext(pContext);
                pContext = NULL;
            }
            else if (Action.Type == SC_ACTION_RUN_COMMAND)
            {
                /* The environment of a service account needs its profile, which goes with the image */
                if (!CreateEnvironmentBlock(&pContext->lpEnvironment, pContext->hToken, pContext->hToken == NULL))
                    pContext->lpEnvironment = NULL;
            }
        }

        if (pContext != NULL)
        {
            ScmReferenceService(Service);
            InterlockedIncrement(&ScmActiveWorkers);
            hThread = CreateThread(NULL, 0, ScmFailureActionThread, pContext, 0, NULL);
            if (hThread != NULL)
            {
                CloseHandle(hThread);
            }
            else
            {
                DPRINT1("Failed to create the failure action thread of service %S\n", Service->lpServiceName);
                InterlockedDecrement(&ScmActiveWorkers);
                ScmDereferenceService(Service);
                ScmFreeFailureActionContext(pContext);
            }
        }
    }
    else
    {
        ScmQueueFailureLog(pLogQueue, EVENT_SERVICE_CRASH_NO_ACTION, Service->lpDisplayName,
                           Service->dwFailureCount, 0, NULL);
    }

    if (lpCommand)
        HeapFree(GetProcessHeap(), 0, lpCommand);
    if (lpRebootMsg)
        HeapFree(GetProcessHeap(), 0, lpRebootMsg);
    if (lpActions)
        HeapFree(GetProcessHeap(), 0, lpActions);
}

/*
 * A service that reported itself stopped with an error: its failure actions run only when it asked for
 * that (the FailureActionsOnNonCrashFailures value). Called with the database lock held exclusively,
 * before the service gives up its image.
 */
VOID
ScmServiceStoppedWithError(PSERVICE Service, PSERVICE_IMAGE Image, PLIST_ENTRY pLogQueue)
{
    if (ScmShutdown || Service->bDeleted)
        return;

    if (Service->Status.dwWin32ExitCode == ERROR_SUCCESS ||
        (Service->Status.dwWin32ExitCode == ERROR_SERVICE_SPECIFIC_ERROR &&
         Service->Status.dwServiceSpecificExitCode == 0))
        return;

    /* Only a service that asked for it has failure actions to run: no registry access for the others */
    if (Service->bFailureOnNonCrash)
        ScmProcessServiceFailure(Service, Image, pLogQueue);
}

/* Called with the database lock held exclusively */
static VOID
ScmHandleServiceProcessExit(PSERVICE_PROCESS_WATCH pWatch, PLIST_ENTRY pLogQueue)
{
    PLIST_ENTRY ServiceEntry;
    PSERVICE Service;
    PSERVICE_IMAGE Image;

    /* The services stop with their processes at shutdown */
    if (ScmShutdown)
        return;

    ServiceEntry = ServiceListHead.Flink;
    while (ServiceEntry != &ServiceListHead)
    {
        Service = CONTAINING_RECORD(ServiceEntry, SERVICE, ServiceListEntry);
        ServiceEntry = ServiceEntry->Flink;

        /* Only a service that is not stopped holds its image and keeps it valid */
        if (Service->Status.dwCurrentState == SERVICE_STOPPED ||
            Service->lpImage == NULL ||
            Service->lpImage->pWatch != pWatch)
            continue;

        Image = Service->lpImage;
        DPRINT1("The process of service %S ended\n", Service->lpServiceName);

        Service->Status.dwCurrentState = SERVICE_STOPPED;
        Service->Status.dwControlsAccepted = 0;
        Service->Status.dwWin32ExitCode = ERROR_PROCESS_ABORTED;
        Service->Status.dwServiceSpecificExitCode = 0;
        Service->Status.dwCheckPoint = 0;
        Service->Status.dwWaitHint = 0;

        /* A restart makes a new image; this one goes when the services that still hold it let it go */
        Image->bProcessEnded = TRUE;

        /* A deleted service has no failure actions: it must not log a crash or run what its key still holds */
        if (!Service->bDeleted)
            ScmProcessServiceFailure(Service, Image, pLogQueue);

        Service->lpImage = NULL;
        Image->dwImageRunCount--;
        if (Image->dwImageRunCount == 0)
            ScmRemoveServiceImage(Image);

        /* Remove the reference that was added when the service started; this can delete the service */
        ScmDereferenceService(Service);
    }
}

static DWORD WINAPI
ScmProcessWatchThread(PVOID pParam)
{
    PSERVICE_PROCESS_WATCH pWatch = pParam;
    HANDLE Handles[2];

    Handles[0] = pWatch->hProcess;
    Handles[1] = pWatch->hCancel;
    if (WaitForMultipleObjects(2, Handles, FALSE, INFINITE) == WAIT_OBJECT_0)
    {
        /* Count before the shutdown flag is read, so that shutdown cannot miss this thread */
        InterlockedIncrement(&ScmActiveWorkers);
        if (!ScmShutdown)
        {
            LIST_ENTRY LogQueue;

            InitializeListHead(&LogQueue);
            ScmLockDatabaseExclusive();
            ScmHandleServiceProcessExit(pWatch, &LogQueue);
            ScmUnlockDatabase();
            ScmFlushFailureLog(&LogQueue);
        }
        InterlockedDecrement(&ScmActiveWorkers);
    }

    ScmReleaseProcessWatch(pWatch);
    return 0;
}

VOID
ScmWatchServiceProcess(PSERVICE_IMAGE pServiceImage)
{
    PSERVICE_PROCESS_WATCH pWatch;
    HANDLE hThread;

    if (pServiceImage->hProcess == NULL || pServiceImage->hProcess == INVALID_HANDLE_VALUE)
        return;

    pWatch = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*pWatch));
    if (pWatch == NULL)
        return;

    pWatch->RefCount = 2; /* The image and the watching thread */
    pWatch->hCancel = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (pWatch->hCancel == NULL ||
        !DuplicateHandle(GetCurrentProcess(),
                         pServiceImage->hProcess,
                         GetCurrentProcess(),
                         &pWatch->hProcess,
                         SYNCHRONIZE,
                         FALSE,
                         0))
    {
        DPRINT1("Cannot watch the process of %S\n", pServiceImage->pszImagePath);
        if (pWatch->hCancel)
            CloseHandle(pWatch->hCancel);
        HeapFree(GetProcessHeap(), 0, pWatch);
        return;
    }

    pServiceImage->pWatch = pWatch;
    hThread = CreateThread(NULL, 0, ScmProcessWatchThread, pWatch, 0, NULL);
    if (hThread == NULL)
    {
        DPRINT1("Cannot create a thread to watch %S\n", pServiceImage->pszImagePath);
        pServiceImage->pWatch = NULL;
        pWatch->RefCount = 1;
        ScmReleaseProcessWatch(pWatch);
        return;
    }
    CloseHandle(hThread);
}

/*
 * The watching thread cannot see a process that ended before the service had left the stopped
 * state, so the loader looks once more when the service has been started.
 */
VOID
ScmCheckServiceProcessExited(PSERVICE Service)
{
    PSERVICE_PROCESS_WATCH pWatch;
    LIST_ENTRY LogQueue;

    InitializeListHead(&LogQueue);

    ScmLockDatabaseExclusive();
    if (Service->Status.dwCurrentState != SERVICE_STOPPED &&
        Service->lpImage != NULL &&
        Service->lpImage->pWatch != NULL)
    {
        pWatch = Service->lpImage->pWatch;
        InterlockedIncrement(&pWatch->RefCount);
        if (WaitForSingleObject(pWatch->hProcess, 0) == WAIT_OBJECT_0)
            ScmHandleServiceProcessExit(pWatch, &LogQueue);
        ScmReleaseProcessWatch(pWatch);
    }
    ScmUnlockDatabase();

    ScmFlushFailureLog(&LogQueue);
}


VOID
ScmRemoveServiceImage(PSERVICE_IMAGE pServiceImage)
{
    DPRINT1("ScmRemoveServiceImage() called\n");

    /* Stop watching the process; the watching thread may be the caller, it keeps its own reference */
    if (pServiceImage->pWatch != NULL)
    {
        SetEvent(pServiceImage->pWatch->hCancel);
        ScmReleaseProcessWatch(pServiceImage->pWatch);
        pServiceImage->pWatch = NULL;
    }

    /* FIXME: Terminate the process */

    /* Remove the service image from the list */
    RemoveEntryList(&pServiceImage->ImageListEntry);

    /* Close the process handle */
    if (pServiceImage->hProcess != INVALID_HANDLE_VALUE)
        CloseHandle(pServiceImage->hProcess);

    /* Close the control pipe */
    if (pServiceImage->hControlPipe != INVALID_HANDLE_VALUE)
        CloseHandle(pServiceImage->hControlPipe);

    /* Unload the user profile */
    if (pServiceImage->hProfile != NULL)
    {
        ScmEnableBackupRestorePrivileges(pServiceImage->hToken, TRUE);
        UnloadUserProfile(pServiceImage->hToken, pServiceImage->hProfile);
        ScmEnableBackupRestorePrivileges(pServiceImage->hToken, FALSE);
    }

    /* Close the logon token */
    if (pServiceImage->hToken != NULL)
        CloseHandle(pServiceImage->hToken);

    /* Release the service image */
    HeapFree(GetProcessHeap(), 0, pServiceImage);
}


PSERVICE
ScmGetServiceEntryByName(LPCWSTR lpServiceName)
{
    PLIST_ENTRY ServiceEntry;
    PSERVICE CurrentService;

    DPRINT("ScmGetServiceEntryByName() called\n");

    ServiceEntry = ServiceListHead.Flink;
    while (ServiceEntry != &ServiceListHead)
    {
        CurrentService = CONTAINING_RECORD(ServiceEntry,
                                           SERVICE,
                                           ServiceListEntry);
        if (_wcsicmp(CurrentService->lpServiceName, lpServiceName) == 0)
        {
            DPRINT("Found service: '%S'\n", CurrentService->lpServiceName);
            return CurrentService;
        }

        ServiceEntry = ServiceEntry->Flink;
    }

    DPRINT("Couldn't find a matching service\n");

    return NULL;
}


PSERVICE
ScmGetServiceEntryByDisplayName(LPCWSTR lpDisplayName)
{
    PLIST_ENTRY ServiceEntry;
    PSERVICE CurrentService;

    DPRINT("ScmGetServiceEntryByDisplayName() called\n");

    ServiceEntry = ServiceListHead.Flink;
    while (ServiceEntry != &ServiceListHead)
    {
        CurrentService = CONTAINING_RECORD(ServiceEntry,
                                           SERVICE,
                                           ServiceListEntry);
        if (_wcsicmp(CurrentService->lpDisplayName, lpDisplayName) == 0)
        {
            DPRINT("Found service: '%S'\n", CurrentService->lpDisplayName);
            return CurrentService;
        }

        ServiceEntry = ServiceEntry->Flink;
    }

    DPRINT("Couldn't find a matching service\n");

    return NULL;
}


PSERVICE
ScmGetServiceEntryByResumeCount(DWORD dwResumeCount)
{
    PLIST_ENTRY ServiceEntry;
    PSERVICE CurrentService;

    DPRINT("ScmGetServiceEntryByResumeCount() called\n");

    ServiceEntry = ServiceListHead.Flink;
    while (ServiceEntry != &ServiceListHead)
    {
        CurrentService = CONTAINING_RECORD(ServiceEntry,
                                           SERVICE,
                                           ServiceListEntry);
        if (CurrentService->dwResumeCount > dwResumeCount)
        {
            DPRINT("Found service: '%S'\n", CurrentService->lpDisplayName);
            return CurrentService;
        }

        ServiceEntry = ServiceEntry->Flink;
    }

    DPRINT("Couldn't find a matching service\n");

    return NULL;
}


DWORD
ScmGenerateServiceTag(PSERVICE lpServiceRecord)
{
    /* Check for an overflow */
    if (ServiceTag == -1)
    {
        return ERROR_INVALID_DATA;
    }

    /* This is only valid for Win32 services */
    if (!(lpServiceRecord->Status.dwServiceType & SERVICE_WIN32))
    {
        return ERROR_INVALID_PARAMETER;
    }

    /* Increment the tag counter and set it */
    ServiceTag = ServiceTag % 0xFFFFFFFF + 1;
    lpServiceRecord->dwServiceTag = ServiceTag;

    return ERROR_SUCCESS;
}


DWORD
ScmCreateNewServiceRecord(LPCWSTR lpServiceName,
                          PSERVICE *lpServiceRecord,
                          DWORD dwServiceType,
                          DWORD dwStartType)
{
    PSERVICE lpService = NULL;

    DPRINT("Service: '%S'\n", lpServiceName);

    /* Allocate service entry */
    lpService = HeapAlloc(GetProcessHeap(),
                          HEAP_ZERO_MEMORY,
                          FIELD_OFFSET(SERVICE, szServiceName[wcslen(lpServiceName) + 1]));
    if (lpService == NULL)
        return ERROR_NOT_ENOUGH_MEMORY;

    *lpServiceRecord = lpService;

    /* Copy service name */
    wcscpy(lpService->szServiceName, lpServiceName);
    lpService->lpServiceName = lpService->szServiceName;
    lpService->lpDisplayName = lpService->lpServiceName;

    /* Set the start type */
    lpService->dwStartType = dwStartType;

    /* Set the resume count */
    lpService->dwResumeCount = ResumeCount++;

    /* Give the service its status handle cookie (never 0) */
    do
    {
        lpService->dwStatusHandle = (DWORD)InterlockedIncrement(&StatusHandleCount);
    } while (lpService->dwStatusHandle == 0);

    /* Append service record */
    InsertTailList(&ServiceListHead,
                   &lpService->ServiceListEntry);

    /* Initialize the service status */
    lpService->Status.dwServiceType = dwServiceType;
    lpService->Status.dwCurrentState = SERVICE_STOPPED;
    lpService->Status.dwControlsAccepted = 0;
    lpService->Status.dwWin32ExitCode =
        (dwStartType == SERVICE_DISABLED) ? ERROR_SERVICE_DISABLED : ERROR_SERVICE_NEVER_STARTED;
    lpService->Status.dwServiceSpecificExitCode = 0;
    lpService->Status.dwCheckPoint = 0;
    lpService->Status.dwWaitHint =
        (dwServiceType & SERVICE_DRIVER) ? 0 : 2000; /* 2 seconds */

    return ERROR_SUCCESS;
}


/*
 * Map a service status handle, as handed out to the service process and
 * returned by it, back to the service record. The handle is a 32-bit cookie
 * rather than the record address, so that a WoW64 (32-bit) service process,
 * which keeps it in a 32-bit SERVICE_STATUS_HANDLE, cannot truncate it.
 * Returns NULL if no service has that handle.
 */
PSERVICE
ScmGetServiceByStatusHandle(_In_ ULONG64 hServiceStatus)
{
    PLIST_ENTRY ServiceEntry;
    PSERVICE CurrentService, Found = NULL;

    if (hServiceStatus == 0 || hServiceStatus > MAXDWORD)
        return NULL;

    ScmLockDatabaseShared();
    for (ServiceEntry = ServiceListHead.Flink;
         ServiceEntry != &ServiceListHead;
         ServiceEntry = ServiceEntry->Flink)
    {
        CurrentService = CONTAINING_RECORD(ServiceEntry, SERVICE, ServiceListEntry);
        if (CurrentService->dwStatusHandle == (DWORD)hServiceStatus)
        {
            Found = CurrentService;
            break;
        }
    }
    ScmUnlockDatabase();

    return Found;
}


VOID
ScmDeleteServiceRecord(PSERVICE lpService)
{
    DPRINT("Deleting Service %S\n", lpService->lpServiceName);

    /* Delete the display name */
    if (lpService->lpDisplayName != NULL &&
        lpService->lpDisplayName != lpService->lpServiceName)
        HeapFree(GetProcessHeap(), 0, lpService->lpDisplayName);

    /* Dereference the service image */
    if (lpService->lpImage)
    {
        lpService->lpImage->dwImageRunCount--;

        if (lpService->lpImage->dwImageRunCount == 0)
        {
            ScmRemoveServiceImage(lpService->lpImage);
            lpService->lpImage = NULL;
        }
    }

    /* Decrement the group reference counter */
    ScmSetServiceGroup(lpService, NULL);

    /* Release the SecurityDescriptor */
    if (lpService->pSecurityDescriptor != NULL)
        HeapFree(GetProcessHeap(), 0, lpService->pSecurityDescriptor);

    /* Remove the Service from the List */
    RemoveEntryList(&lpService->ServiceListEntry);

    DPRINT("Deleted Service %S\n", lpService->lpServiceName);

    /* Delete the service record */
    HeapFree(GetProcessHeap(), 0, lpService);

    DPRINT("Done\n");
}

DWORD
Int_EnumDependentServicesW(HKEY hServicesKey,
                           PSERVICE lpService,
                           DWORD dwServiceState,
                           PSERVICE *lpServices,
                           LPDWORD pcbBytesNeeded,
                           LPDWORD lpServicesReturned);

DWORD ScmDeleteService(PSERVICE lpService)
{
    DWORD dwError;
    DWORD pcbBytesNeeded = 0;
    DWORD dwServicesReturned = 0;
    HKEY hServicesKey;

    ASSERT(lpService->RefCount == 0);

    /* Open the Services Reg key */
    dwError = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"System\\CurrentControlSet\\Services",
                            0,
                            KEY_SET_VALUE | KEY_READ,
                            &hServicesKey);
    if (dwError != ERROR_SUCCESS)
    {
        DPRINT1("Failed to open services key\n");
        return dwError;
    }

    /* Call the function with NULL, just to get bytes we need */
    Int_EnumDependentServicesW(hServicesKey,
                               lpService,
                               SERVICE_ACTIVE,
                               NULL,
                               &pcbBytesNeeded,
                               &dwServicesReturned);

    /* If pcbBytesNeeded returned a value then there are services running that are dependent on this service */
    if (pcbBytesNeeded)
    {
        DPRINT1("Deletion failed due to running dependencies\n");
        RegCloseKey(hServicesKey);
        return ERROR_DEPENDENT_SERVICES_RUNNING;
    }

    /* There are no references and no running dependencies,
       it is now safe to delete the service */

    /* Delete the Service Key */
    dwError = ScmDeleteRegKey(hServicesKey, lpService->lpServiceName);

    RegCloseKey(hServicesKey);

    if (dwError != ERROR_SUCCESS)
    {
        DPRINT1("Failed to delete the Service Registry key\n");
        return dwError;
    }

    /* Delete the Service */
    ScmDeleteServiceRecord(lpService);

    return ERROR_SUCCESS;
}

/*
 * This function allows the caller to be sure that the service won't be freed unexpectedly.
 * In order to be sure that lpService will be valid until the reference is added
 * the caller needs to hold the database lock.
 * A running service will keep a reference for the whole time it is not SERVICE_STOPPED.
 * A service handle will also keep a reference to a service. Keeping a reference is
 * really needed so that ScmControlService can be called without keeping the database locked.
 * This means that eventually the correct order of operations to send a control message to
 * a service looks like: lock, reference, unlock, send control, lock, dereference, unlock.
 */
DWORD
ScmReferenceService(PSERVICE lpService)
{
    return InterlockedIncrement(&lpService->RefCount);
}

/* This function must be called with the database lock held exclusively as
   it can end up deleting the service */
DWORD
ScmDereferenceService(PSERVICE lpService)
{
    DWORD ref;

    ASSERT(lpService->RefCount > 0);

    ref = InterlockedDecrement(&lpService->RefCount);

    if (ref == 0 && lpService->bDeleted &&
        lpService->Status.dwCurrentState == SERVICE_STOPPED)
    {
        ScmDeleteService(lpService);
    }
    return ref;
}

static DWORD
CreateServiceListEntry(LPCWSTR lpServiceName,
                       HKEY hServiceKey)
{
    PSERVICE lpService = NULL;
    LPWSTR lpDisplayName = NULL;
    LPWSTR lpGroup = NULL;
    DWORD dwSize;
    DWORD dwFlag, dwType;
    DWORD dwError;
    DWORD dwServiceType;
    DWORD dwStartType;
    DWORD dwErrorControl;
    DWORD dwTagId;

    DPRINT("Service: '%S'\n", lpServiceName);
    if (*lpServiceName == L'{')
        return ERROR_SUCCESS;

    dwSize = sizeof(DWORD);
    dwError = RegQueryValueExW(hServiceKey,
                               L"Type",
                               NULL,
                               NULL,
                               (LPBYTE)&dwServiceType,
                               &dwSize);
    if (dwError != ERROR_SUCCESS)
        return ERROR_SUCCESS;

    if (((dwServiceType & ~SERVICE_INTERACTIVE_PROCESS) != SERVICE_WIN32_OWN_PROCESS) &&
        ((dwServiceType & ~SERVICE_INTERACTIVE_PROCESS) != SERVICE_WIN32_SHARE_PROCESS) &&
        (dwServiceType != SERVICE_KERNEL_DRIVER) &&
        (dwServiceType != SERVICE_FILE_SYSTEM_DRIVER))
        return ERROR_SUCCESS;

    DPRINT("Service type: %lx\n", dwServiceType);

    dwSize = sizeof(DWORD);
    dwError = RegQueryValueExW(hServiceKey,
                               L"Start",
                               NULL,
                               NULL,
                               (LPBYTE)&dwStartType,
                               &dwSize);
    if (dwError != ERROR_SUCCESS)
        return ERROR_SUCCESS;

    DPRINT("Start type: %lx\n", dwStartType);

    dwSize = sizeof(DWORD);
    dwError = RegQueryValueExW(hServiceKey,
                               L"ErrorControl",
                               NULL,
                               NULL,
                               (LPBYTE)&dwErrorControl,
                               &dwSize);
    if (dwError != ERROR_SUCCESS)
        return ERROR_SUCCESS;

    DPRINT("Error control: %lx\n", dwErrorControl);

    dwError = RegQueryValueExW(hServiceKey,
                               L"Tag",
                               NULL,
                               NULL,
                               (LPBYTE)&dwTagId,
                               &dwSize);
    if (dwError != ERROR_SUCCESS)
        dwTagId = 0;

    DPRINT("Tag: %lx\n", dwTagId);

    dwError = ScmReadString(hServiceKey,
                            L"Group",
                            &lpGroup);
    if (dwError != ERROR_SUCCESS)
        lpGroup = NULL;

    DPRINT("Group: %S\n", lpGroup);

    dwError = ScmReadString(hServiceKey,
                            L"DisplayName",
                            &lpDisplayName);
    if (dwError != ERROR_SUCCESS)
        lpDisplayName = NULL;

    DPRINT("Display name: %S\n", lpDisplayName);

    dwError = ScmCreateNewServiceRecord(lpServiceName,
                                        &lpService,
                                        dwServiceType,
                                        dwStartType);
    if (dwError != ERROR_SUCCESS)
        goto done;

    lpService->dwErrorControl = dwErrorControl;
    lpService->dwTag = dwTagId;

    if (lpGroup != NULL)
    {
        dwError = ScmSetServiceGroup(lpService, lpGroup);
        if (dwError != ERROR_SUCCESS)
            goto done;
    }

    if (lpDisplayName != NULL)
    {
        lpService->lpDisplayName = lpDisplayName;
        lpDisplayName = NULL;
    }

    DPRINT("ServiceName: '%S'\n", lpService->lpServiceName);
    if (lpService->lpGroup != NULL)
    {
        DPRINT("Group: '%S'\n", lpService->lpGroup->lpGroupName);
    }
    DPRINT("Start %lx  Type %lx  Tag %lx  ErrorControl %lx\n",
           lpService->dwStartType,
           lpService->Status.dwServiceType,
           lpService->dwTag,
           lpService->dwErrorControl);

    dwSize = sizeof(DWORD);
    dwFlag = 0;
    if (RegQueryValueExW(hServiceKey, L"FailureActionsOnNonCrashFailures", NULL, &dwType,
                         (LPBYTE)&dwFlag, &dwSize) == ERROR_SUCCESS && dwType == REG_DWORD)
        lpService->bFailureOnNonCrash = (dwFlag != 0);

    if (ScmIsDeleteFlagSet(hServiceKey))
        lpService->bDeleted = TRUE;
    else
        ScmGenerateServiceTag(lpService);

    if (lpService->Status.dwServiceType & SERVICE_WIN32)
    {
        dwError = ScmReadSecurityDescriptor(hServiceKey,
                                            &lpService->pSecurityDescriptor);
        if (dwError != ERROR_SUCCESS)
            goto done;

        /* Assing the default security descriptor if the security descriptor cannot be read */
        if (lpService->pSecurityDescriptor == NULL)
        {
            DPRINT("No security descriptor found! Assign default security descriptor\n");
            dwError = ScmCreateDefaultServiceSD(&lpService->pSecurityDescriptor);
            if (dwError != ERROR_SUCCESS)
                goto done;

            dwError = ScmWriteSecurityDescriptor(hServiceKey,
                                                 lpService->pSecurityDescriptor);
            if (dwError != ERROR_SUCCESS)
                goto done;
        }
    }

done:
    if (lpGroup != NULL)
        HeapFree(GetProcessHeap(), 0, lpGroup);

    if (lpDisplayName != NULL)
        HeapFree(GetProcessHeap(), 0, lpDisplayName);

    if (lpService != NULL)
    {
        ASSERT(lpService->lpImage == NULL);
    }

    return dwError;
}


VOID
ScmDeleteMarkedServices(VOID)
{
    PLIST_ENTRY ServiceEntry;
    PSERVICE CurrentService;
    HKEY hServicesKey;
    DWORD dwError;

    ServiceEntry = ServiceListHead.Flink;
    while (ServiceEntry != &ServiceListHead)
    {
        CurrentService = CONTAINING_RECORD(ServiceEntry, SERVICE, ServiceListEntry);

        ServiceEntry = ServiceEntry->Flink;

        if (CurrentService->bDeleted != FALSE)
        {
            dwError = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                                    L"System\\CurrentControlSet\\Services",
                                    0,
                                    DELETE,
                                    &hServicesKey);
            if (dwError == ERROR_SUCCESS)
            {
                dwError = ScmDeleteRegKey(hServicesKey, CurrentService->lpServiceName);
                RegCloseKey(hServicesKey);
                if (dwError == ERROR_SUCCESS)
                {
                    RemoveEntryList(&CurrentService->ServiceListEntry);
                    HeapFree(GetProcessHeap(), 0, CurrentService);
                }
            }

            if (dwError != ERROR_SUCCESS)
                DPRINT1("Delete service failed: %S\n", CurrentService->lpServiceName);
        }
    }
}


static
VOID
ScmGetNoInteractiveServicesValue(VOID)
{
    HKEY hKey;
    DWORD dwKeySize;
    LONG lError;

    lError = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                           L"SYSTEM\\CurrentControlSet\\Control\\Windows",
                           0,
                           KEY_READ,
                           &hKey);
    if (lError == ERROR_SUCCESS)
    {
        dwKeySize = sizeof(NoInteractiveServices);
        lError = RegQueryValueExW(hKey,
                                  L"NoInteractiveServices",
                                  0,
                                  NULL,
                                  (LPBYTE)&NoInteractiveServices,
                                  &dwKeySize);
        RegCloseKey(hKey);
    }
}


DWORD
ScmCreateServiceDatabase(VOID)
{
    WCHAR szSubKey[MAX_PATH];
    HKEY hServicesKey;
    HKEY hServiceKey;
    DWORD dwSubKey;
    DWORD dwSubKeyLength;
    FILETIME ftLastChanged;
    DWORD dwError;

    DPRINT("ScmCreateServiceDatabase() called\n");

    hFailureShutdownEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

    /* Retrieve the NoInteractiveServies value */
    ScmGetNoInteractiveServicesValue();

    /* Create the service group list */
    dwError = ScmCreateGroupList();
    if (dwError != ERROR_SUCCESS)
        return dwError;

    /* Initialize image and service lists */
    InitializeListHead(&ImageListHead);
    InitializeListHead(&ServiceListHead);

    /* Initialize the database lock */
    RtlInitializeResource(&DatabaseLock);

    dwError = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"System\\CurrentControlSet\\Services",
                            0,
                            KEY_READ,
                            &hServicesKey);
    if (dwError != ERROR_SUCCESS)
        return dwError;

    dwSubKey = 0;
    for (;;)
    {
        dwSubKeyLength = MAX_PATH;
        dwError = RegEnumKeyExW(hServicesKey,
                                dwSubKey,
                                szSubKey,
                                &dwSubKeyLength,
                                NULL,
                                NULL,
                                NULL,
                                &ftLastChanged);
        if (dwError == ERROR_SUCCESS &&
            szSubKey[0] != L'{')
        {
            DPRINT("SubKeyName: '%S'\n", szSubKey);

            dwError = RegOpenKeyExW(hServicesKey,
                                    szSubKey,
                                    0,
                                    KEY_READ,
                                    &hServiceKey);
            if (dwError == ERROR_SUCCESS)
            {
                dwError = CreateServiceListEntry(szSubKey,
                                                 hServiceKey);

                RegCloseKey(hServiceKey);
            }
        }

        if (dwError != ERROR_SUCCESS)
            break;

        dwSubKey++;
    }

    RegCloseKey(hServicesKey);

    /* Wait for the LSA server */
    ScmWaitForLsa();

    /* Delete services that are marked for delete */
    ScmDeleteMarkedServices();

    DPRINT("ScmCreateServiceDatabase() done\n");

    return ERROR_SUCCESS;
}


VOID
ScmShutdownServiceDatabase(VOID)
{
    DWORD i;

    DPRINT("ScmShutdownServiceDatabase() called\n");

    /*
     * A worker that began before the shutdown flag was set finishes first; wait for it outside the locks.
     * One that does not finish keeps the database: the process is ending anyway.
     */
    if (hFailureShutdownEvent != NULL)
        SetEvent(hFailureShutdownEvent);
    for (i = 0; i < 50 && InterlockedCompareExchange(&ScmActiveWorkers, 0, 0) != 0; i++)
        Sleep(100);

    /* Marked services go in any case, or they come back after the reboot */
    ScmDeleteMarkedServices();

    /* A worker that is still running keeps the lock: the process is ending anyway */
    if (InterlockedCompareExchange(&ScmActiveWorkers, 0, 0) == 0)
        RtlDeleteResource(&DatabaseLock);

    DPRINT("ScmShutdownServiceDatabase() done\n");
}


static NTSTATUS
ScmCheckDriver(PSERVICE Service)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING DirName;
    HANDLE DirHandle;
    NTSTATUS Status;
    POBJECT_DIRECTORY_INFORMATION DirInfo;
    ULONG BufferLength;
    ULONG DataLength;
    ULONG Index;

    DPRINT("ScmCheckDriver(%S) called\n", Service->lpServiceName);

    if (Service->Status.dwServiceType == SERVICE_KERNEL_DRIVER)
    {
        RtlInitUnicodeString(&DirName, L"\\Driver");
    }
    else // if (Service->Status.dwServiceType == SERVICE_FILE_SYSTEM_DRIVER)
    {
        ASSERT(Service->Status.dwServiceType == SERVICE_FILE_SYSTEM_DRIVER);
        RtlInitUnicodeString(&DirName, L"\\FileSystem");
    }

    InitializeObjectAttributes(&ObjectAttributes,
                               &DirName,
                               0,
                               NULL,
                               NULL);

    Status = NtOpenDirectoryObject(&DirHandle,
                                   DIRECTORY_QUERY | DIRECTORY_TRAVERSE,
                                   &ObjectAttributes);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    BufferLength = sizeof(OBJECT_DIRECTORY_INFORMATION) +
                       2 * MAX_PATH * sizeof(WCHAR);
    DirInfo = HeapAlloc(GetProcessHeap(),
                        HEAP_ZERO_MEMORY,
                        BufferLength);

    Index = 0;
    while (TRUE)
    {
        Status = NtQueryDirectoryObject(DirHandle,
                                        DirInfo,
                                        BufferLength,
                                        TRUE,
                                        FALSE,
                                        &Index,
                                        &DataLength);
        if (Status == STATUS_NO_MORE_ENTRIES)
        {
            /* FIXME: Add current service to 'failed service' list */
            DPRINT("Service '%S' failed\n", Service->lpServiceName);
            break;
        }

        if (!NT_SUCCESS(Status))
            break;

        DPRINT("Comparing: '%S'  '%wZ'\n", Service->lpServiceName, &DirInfo->Name);

        if (_wcsicmp(Service->lpServiceName, DirInfo->Name.Buffer) == 0)
        {
            DPRINT("Found: '%S'  '%wZ'\n",
                   Service->lpServiceName, &DirInfo->Name);

            /* Mark service as 'running' */
            Service->Status.dwCurrentState = SERVICE_RUNNING;
            Service->Status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
            Service->Status.dwWin32ExitCode = ERROR_SUCCESS;
            Service->Status.dwServiceSpecificExitCode = 0;
            Service->Status.dwCheckPoint = 0;
            Service->Status.dwWaitHint = 0;

            /* Mark the service group as 'running' */
            if (Service->lpGroup != NULL)
            {
                Service->lpGroup->ServicesRunning = TRUE;
            }

            break;
        }
    }

    HeapFree(GetProcessHeap(),
             0,
             DirInfo);
    NtClose(DirHandle);

    return STATUS_SUCCESS;
}


VOID
ScmGetBootAndSystemDriverState(VOID)
{
    PLIST_ENTRY ServiceEntry;
    PSERVICE CurrentService;

    DPRINT("ScmGetBootAndSystemDriverState() called\n");

    ServiceEntry = ServiceListHead.Flink;
    while (ServiceEntry != &ServiceListHead)
    {
        CurrentService = CONTAINING_RECORD(ServiceEntry, SERVICE, ServiceListEntry);

        if (CurrentService->dwStartType == SERVICE_BOOT_START ||
            CurrentService->dwStartType == SERVICE_SYSTEM_START)
        {
            /* Check driver */
            DPRINT("  Checking service: %S\n", CurrentService->lpServiceName);

            ScmCheckDriver(CurrentService);
        }

        ServiceEntry = ServiceEntry->Flink;
    }

    DPRINT("ScmGetBootAndSystemDriverState() done\n");
}


/*
 * ScmSendControlPacket must never be called with the database lock being held.
 * The service passed must always be referenced instead.
 */
DWORD
ScmSendControlPacket(
    _In_ HANDLE hControlPipe,
    _In_ PCWSTR pServiceName,
    _In_ DWORD dwControl,
    _In_ DWORD dwControlPacketSize,
    _In_ PVOID pControlPacket)
{
    DWORD dwError = ERROR_SUCCESS;
    BOOL bResult;
    SCM_REPLY_PACKET ReplyPacket;
    DWORD dwReadCount = 0;
    OVERLAPPED Overlapped = {0};

    DPRINT("ScmSendControlPacket(%p, %lu, %p) called\n",
           hControlPipe, dwControlPacketSize, pControlPacket);

    /* Acquire the service control critical section, to synchronize requests */
    EnterCriticalSection(&ControlServiceCriticalSection);

    bResult = TransactNamedPipe(hControlPipe,
                                pControlPacket,
                                dwControlPacketSize,
                                &ReplyPacket,
                                sizeof(ReplyPacket),
                                &dwReadCount,
                                &Overlapped);
    if (!bResult)
    {
        /* Fail for any error other than pending IO */
        dwError = GetLastError();
        if (dwError != ERROR_IO_PENDING)
        {
            DPRINT1("TransactNamedPipe(%S, %d) failed (Error %lu)\n", pServiceName, dwControl, dwError);
            goto Done;
        }

        DPRINT("TransactNamedPipe(%S, %d) returned ERROR_IO_PENDING\n", pServiceName, dwControl);

        dwError = WaitForSingleObject(hControlPipe, PipeTimeout);
        DPRINT("WaitForSingleObject(%S, %d) returned %lu\n", pServiceName, dwControl, dwError);

        if (dwError == WAIT_TIMEOUT)
        {
            DPRINT1("WaitForSingleObject(%S, %d) timed out\n", pServiceName, dwControl);
            bResult = CancelIo(hControlPipe);
            if (!bResult)
                DPRINT1("CancelIo(%S, %d) failed (Error %lu)\n", pServiceName, dwControl, GetLastError());

            dwError = ERROR_SERVICE_REQUEST_TIMEOUT;
        }
        else if (dwError == WAIT_OBJECT_0)
        {
            bResult = GetOverlappedResult(hControlPipe,
                                          &Overlapped,
                                          &dwReadCount,
                                          TRUE);
            if (!bResult)
            {
                dwError = GetLastError();
                DPRINT1("GetOverlappedResult(%S, %d) failed (Error %lu)\n", pServiceName, dwControl, dwError);
            }
        }
    }

Done:
    /* Release the service control critical section */
    LeaveCriticalSection(&ControlServiceCriticalSection);

    if (dwReadCount == sizeof(ReplyPacket))
        dwError = ReplyPacket.dwError;

    return dwError;
}


DWORD
ScmControlServiceEx(
    _In_ HANDLE hControlPipe,
    _In_ PCWSTR pServiceName,
    _In_ DWORD dwControl,
    _In_ DWORD dwStatusHandle,
    _In_opt_ DWORD dwServiceTag,
    _In_opt_ DWORD argc,
    _In_reads_opt_(argc) const PCWSTR* argv)
{
    DWORD dwError = ERROR_SUCCESS;
    PSCM_CONTROL_PACKET ControlPacket;
    DWORD PacketSize;
    DWORD i;
    PWSTR Ptr;

    DPRINT("ScmControlServiceEx(%S, %d) called\n", pServiceName, dwControl);

    /* Calculate the total size of the control packet:
     * initial structure, the start command line, and the argument vector */
    PacketSize = sizeof(SCM_CONTROL_PACKET);
    PacketSize += (DWORD)((wcslen(pServiceName) + 1) * sizeof(WCHAR));

    /*
     * Calculate the required packet size for the start argument vector 'argv',
     * composed of the DWORD offsets list, followed by UNICODE strings.
     * DWORD (not pointer-sized) offsets keep the layout identical for
     * 32-bit (WoW64) service processes.
     * The strings are stored successively after the offsets vector, with
     * the offsets being relative to the beginning of the vector, as in the
     * following layout (with N == argc):
     *     [argOff(0)]...[argOff(N-1)][str(0)]...[str(N-1)] .
     */
    if (argc > 0 && argv != NULL)
    {
        PacketSize = ALIGN_UP(PacketSize, DWORD);
        PacketSize += (argc * sizeof(DWORD));

        DPRINT("Argc: %lu\n", argc);
        for (i = 0; i < argc; i++)
        {
            DPRINT("Argv[%lu]: %S\n", i, argv[i]);
            PacketSize += (DWORD)((wcslen(argv[i]) + 1) * sizeof(WCHAR));
        }
    }

    /* Allocate the control packet */
    ControlPacket = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PacketSize);
    if (!ControlPacket)
        return ERROR_NOT_ENOUGH_MEMORY;

    ControlPacket->dwSize = PacketSize;
    ControlPacket->dwControl = dwControl;
    ControlPacket->hServiceStatus = dwStatusHandle;
    ControlPacket->dwServiceTag = dwServiceTag;

    /* Copy the start command line */
    ControlPacket->dwServiceNameOffset = sizeof(SCM_CONTROL_PACKET);
    Ptr = (PWSTR)((ULONG_PTR)ControlPacket + ControlPacket->dwServiceNameOffset);
    wcscpy(Ptr, pServiceName);

    ControlPacket->dwArgumentsCount  = 0;
    ControlPacket->dwArgumentsOffset = 0;

    /* Copy the argument vector */
    if (argc > 0 && argv != NULL)
    {
        PDWORD pOffPtr;
        PWSTR pArgPtr;

        Ptr += wcslen(pServiceName) + 1;
        pOffPtr = (PDWORD)ALIGN_UP_POINTER(Ptr, DWORD);
        pArgPtr = (PWSTR)((ULONG_PTR)pOffPtr + argc * sizeof(DWORD));

        ControlPacket->dwArgumentsCount  = argc;
        ControlPacket->dwArgumentsOffset = (DWORD)((ULONG_PTR)pOffPtr - (ULONG_PTR)ControlPacket);

        DPRINT("dwArgumentsCount: %lu\n", ControlPacket->dwArgumentsCount);
        DPRINT("dwArgumentsOffset: %lu\n", ControlPacket->dwArgumentsOffset);

        for (i = 0; i < argc; i++)
        {
            wcscpy(pArgPtr, argv[i]);
            pOffPtr[i] = (DWORD)((ULONG_PTR)pArgPtr - (ULONG_PTR)pOffPtr);
            DPRINT("offset[%lu]: %lu\n", i, pOffPtr[i]);
            pArgPtr += wcslen(argv[i]) + 1;
        }
    }

    dwError = ScmSendControlPacket(hControlPipe,
                                   pServiceName,
                                   dwControl,
                                   PacketSize,
                                   ControlPacket);

    /* Free the control packet */
    HeapFree(GetProcessHeap(), 0, ControlPacket);

    DPRINT("ScmControlServiceEx(%S, %d) done (Error %lu)\n", pServiceName, dwControl, dwError);
    return dwError;
}


DWORD
ScmControlService(
    _In_ HANDLE hControlPipe,
    _In_ PCWSTR pServiceName,
    _In_ DWORD dwControl,
    _In_ DWORD dwStatusHandle)
{
    DWORD dwError = ERROR_SUCCESS;
    PSCM_CONTROL_PACKET ControlPacket;
    DWORD PacketSize;
    PWSTR Ptr;

    DPRINT("ScmControlService(%S, %d) called\n", pServiceName, dwControl);

    /* Calculate the total size of the control packet:
     * initial structure, the start command line, and the argument vector */
    PacketSize = sizeof(SCM_CONTROL_PACKET);
    PacketSize += (DWORD)((wcslen(pServiceName) + 1) * sizeof(WCHAR));

    /* Allocate the control packet */
    ControlPacket = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PacketSize);
    if (!ControlPacket)
        return ERROR_NOT_ENOUGH_MEMORY;

    ControlPacket->dwSize = PacketSize;
    ControlPacket->dwControl = dwControl;
    ControlPacket->hServiceStatus = dwStatusHandle;

    /* Copy the service name */
    ControlPacket->dwServiceNameOffset = sizeof(SCM_CONTROL_PACKET);
    Ptr = (PWSTR)((ULONG_PTR)ControlPacket + ControlPacket->dwServiceNameOffset);
    wcscpy(Ptr, pServiceName);

    /* Send the control packet */
    dwError = ScmSendControlPacket(hControlPipe,
                                   pServiceName,
                                   dwControl,
                                   PacketSize,
                                   ControlPacket);

    /* Free the control packet */
    HeapFree(GetProcessHeap(), 0, ControlPacket);

    DPRINT("ScmControlService(%S, %d) done (Error %lu)\n", pServiceName, dwControl, dwError);
    return dwError;
}


static DWORD
ScmWaitForServiceConnect(PSERVICE Service)
{
    DWORD dwRead = 0;
    DWORD dwProcessId = 0;
    DWORD dwError = ERROR_SUCCESS;
    BOOL bResult;
    OVERLAPPED Overlapped = {0};
#if 0
    LPCWSTR lpLogStrings[3];
    WCHAR szBuffer1[20];
    WCHAR szBuffer2[20];
#endif

    DPRINT("ScmWaitForServiceConnect()\n");

    bResult = ConnectNamedPipe(Service->lpImage->hControlPipe,
                               &Overlapped);
    if (bResult == FALSE)
    {
        DPRINT("ConnectNamedPipe() returned FALSE\n");

        dwError = GetLastError();
        if (dwError == ERROR_IO_PENDING)
        {
            DPRINT("dwError: ERROR_IO_PENDING\n");

            dwError = WaitForSingleObject(Service->lpImage->hControlPipe,
                                          PipeTimeout);
            DPRINT("WaitForSingleObject() returned %lu\n", dwError);

            if (dwError == WAIT_TIMEOUT)
            {
                DPRINT("WaitForSingleObject() returned WAIT_TIMEOUT\n");

                bResult = CancelIo(Service->lpImage->hControlPipe);
                if (bResult == FALSE)
                {
                    DPRINT1("CancelIo() failed (Error: %lu)\n", GetLastError());
                }

#if 0
                _ultow(PipeTimeout, szBuffer1, 10);
                lpLogStrings[0] = Service->lpDisplayName;
                lpLogStrings[1] = szBuffer1;

                ScmLogEvent(EVENT_CONNECTION_TIMEOUT,
                            EVENTLOG_ERROR_TYPE,
                            2,
                            lpLogStrings);
#endif
                DPRINT1("Log EVENT_CONNECTION_TIMEOUT by %S\n", Service->lpDisplayName);

                return ERROR_SERVICE_REQUEST_TIMEOUT;
            }
            else if (dwError == WAIT_OBJECT_0)
            {
                bResult = GetOverlappedResult(Service->lpImage->hControlPipe,
                                              &Overlapped,
                                              &dwRead,
                                              TRUE);
                if (bResult == FALSE)
                {
                    dwError = GetLastError();
                    DPRINT1("GetOverlappedResult failed (Error %lu)\n", dwError);

                    return dwError;
                }
            }
        }
        else if (dwError != ERROR_PIPE_CONNECTED)
        {
            DPRINT1("ConnectNamedPipe failed (Error %lu)\n", dwError);
            return dwError;
        }
    }

    DPRINT("Control pipe connected\n");

    Overlapped.hEvent = NULL;

    /* Read the process id from pipe */
    bResult = ReadFile(Service->lpImage->hControlPipe,
                       (LPVOID)&dwProcessId,
                       sizeof(DWORD),
                       &dwRead,
                       &Overlapped);
    if (bResult == FALSE)
    {
        DPRINT("ReadFile() returned FALSE\n");

        dwError = GetLastError();
        if (dwError == ERROR_IO_PENDING)
        {
            DPRINT("dwError: ERROR_IO_PENDING\n");

            dwError = WaitForSingleObject(Service->lpImage->hControlPipe,
                                          PipeTimeout);
            if (dwError == WAIT_TIMEOUT)
            {
                DPRINT("WaitForSingleObject() returned WAIT_TIMEOUT\n");

                bResult = CancelIo(Service->lpImage->hControlPipe);
                if (bResult == FALSE)
                {
                    DPRINT1("CancelIo() failed (Error: %lu)\n", GetLastError());
                }

#if 0
                _ultow(PipeTimeout, szBuffer1, 10);
                lpLogStrings[0] = szBuffer1;

                ScmLogEvent(EVENT_READFILE_TIMEOUT,
                            EVENTLOG_ERROR_TYPE,
                            1,
                            lpLogStrings);
#endif
                DPRINT1("Log EVENT_READFILE_TIMEOUT by %S\n", Service->lpDisplayName);

                return ERROR_SERVICE_REQUEST_TIMEOUT;
            }
            else if (dwError == WAIT_OBJECT_0)
            {
                DPRINT("WaitForSingleObject() returned WAIT_OBJECT_0\n");

                DPRINT("Process Id: %lu\n", dwProcessId);

                bResult = GetOverlappedResult(Service->lpImage->hControlPipe,
                                              &Overlapped,
                                              &dwRead,
                                              TRUE);
                if (bResult == FALSE)
                {
                    dwError = GetLastError();
                    DPRINT1("GetOverlappedResult() failed (Error %lu)\n", dwError);

                    return dwError;
                }
            }
            else
            {
                DPRINT1("WaitForSingleObject() returned %lu\n", dwError);
            }
        }
        else
        {
            DPRINT1("ReadFile() failed (Error %lu)\n", dwError);
            return dwError;
        }
    }

    if ((ScmIsSecurityService(Service->lpImage) == FALSE)&&
        (dwProcessId != Service->lpImage->dwProcessId))
    {
#if 0
        _ultow(Service->lpImage->dwProcessId, szBuffer1, 10);
        _ultow(dwProcessId, szBuffer2, 10);

        lpLogStrings[0] = Service->lpDisplayName;
        lpLogStrings[1] = szBuffer1;
        lpLogStrings[2] = szBuffer2;

        ScmLogEvent(EVENT_SERVICE_DIFFERENT_PID_CONNECTED,
                    EVENTLOG_WARNING_TYPE,
                    3,
                    lpLogStrings);
#endif

        DPRINT1("Log EVENT_SERVICE_DIFFERENT_PID_CONNECTED by %S\n", Service->lpDisplayName);
    }

    DPRINT("ScmWaitForServiceConnect() done\n");

    return ERROR_SUCCESS;
}


static DWORD
ScmStartUserModeService(PSERVICE Service,
                        DWORD argc,
                        const PCWSTR* argv)
{
    PROCESS_INFORMATION ProcessInformation;
    STARTUPINFOW StartupInfo;
    LPVOID lpEnvironment;
    BOOL Result;
    DWORD dwError = ERROR_SUCCESS;

    DPRINT("ScmStartUserModeService(%p)\n", Service);

    /* If the image is already running, just send a start command */
    if (Service->lpImage->dwImageRunCount > 1)
        goto Quit;

    /* Otherwise start its process */
    ZeroMemory(&StartupInfo, sizeof(StartupInfo));
    StartupInfo.cb = sizeof(StartupInfo);
    ZeroMemory(&ProcessInformation, sizeof(ProcessInformation));

    if (Service->lpImage->hToken)
    {
        /* User token: Run the service under the user account */

        if (!CreateEnvironmentBlock(&lpEnvironment, Service->lpImage->hToken, FALSE))
        {
            /* We failed, run the service with the current environment */
            DPRINT1("CreateEnvironmentBlock() failed with error %d; service '%S' will run with current environment\n",
                    GetLastError(), Service->lpServiceName);
            lpEnvironment = NULL;
        }

        /* Impersonate the new user */
        Result = ImpersonateLoggedOnUser(Service->lpImage->hToken);
        if (Result)
        {
            /* Launch the process in the user's logon session */
            Result = CreateProcessAsUserW(Service->lpImage->hToken,
                                          NULL,
                                          Service->lpImage->pszImagePath,
                                          NULL,
                                          NULL,
                                          FALSE,
                                          CREATE_UNICODE_ENVIRONMENT | DETACHED_PROCESS | CREATE_SUSPENDED,
                                          lpEnvironment,
                                          NULL,
                                          &StartupInfo,
                                          &ProcessInformation);
            if (!Result)
                dwError = GetLastError();

            /* Revert the impersonation */
            RevertToSelf();
        }
        else
        {
            dwError = GetLastError();
            DPRINT1("ImpersonateLoggedOnUser() failed with error %d\n", dwError);
        }
    }
    else
    {
        /* No user token: Run the service under the LocalSystem account */

        if (!CreateEnvironmentBlock(&lpEnvironment, NULL, TRUE))
        {
            /* We failed, run the service with the current environment */
            DPRINT1("CreateEnvironmentBlock() failed with error %d; service '%S' will run with current environment\n",
                    GetLastError(), Service->lpServiceName);
            lpEnvironment = NULL;
        }

        /* Use the interactive desktop if the service is interactive */
        if ((NoInteractiveServices == 0) &&
            (Service->Status.dwServiceType & SERVICE_INTERACTIVE_PROCESS))
        {
            StartupInfo.dwFlags |= STARTF_INHERITDESKTOP;
            StartupInfo.lpDesktop = L"WinSta0\\Default";
        }

        if (!ScmIsSecurityService(Service->lpImage))
        {
            Result = CreateProcessW(NULL,
                                    Service->lpImage->pszImagePath,
                                    NULL,
                                    NULL,
                                    FALSE,
                                    CREATE_UNICODE_ENVIRONMENT | DETACHED_PROCESS | CREATE_SUSPENDED,
                                    lpEnvironment,
                                    NULL,
                                    &StartupInfo,
                                    &ProcessInformation);
            if (!Result)
                dwError = GetLastError();
        }
        else
        {
            Result = TRUE;
            dwError = ERROR_SUCCESS;
        }
    }

    if (lpEnvironment)
        DestroyEnvironmentBlock(lpEnvironment);

    if (!Result)
    {
        DPRINT1("Starting '%S' failed with error %d\n",
                Service->lpServiceName, dwError);
        return dwError;
    }

    DPRINT("Process Id: %lu  Handle %p\n",
           ProcessInformation.dwProcessId,
           ProcessInformation.hProcess);
    DPRINT("Thread Id: %lu  Handle %p\n",
           ProcessInformation.dwThreadId,
           ProcessInformation.hThread);

    /* Get the process handle and ID */
    Service->lpImage->hProcess = ProcessInformation.hProcess;
    Service->lpImage->dwProcessId = ProcessInformation.dwProcessId;

    /* Notice when the process ends without the service having stopped */
    ScmWatchServiceProcess(Service->lpImage);

    /* Resume the main thread and close its handle */
    ResumeThread(ProcessInformation.hThread);
    CloseHandle(ProcessInformation.hThread);

    /* Connect control pipe */
    dwError = ScmWaitForServiceConnect(Service);
    if (dwError != ERROR_SUCCESS)
    {
        DPRINT1("Connecting control pipe failed! (Error %lu)\n", dwError);
        Service->lpImage->dwProcessId = 0;
        return dwError;
    }

Quit:
    /* Send the start command and return */
    return ScmControlServiceEx(Service->lpImage->hControlPipe,
                               Service->lpServiceName,
                               (Service->Status.dwServiceType & SERVICE_WIN32_OWN_PROCESS)
                                  ? SERVICE_CONTROL_START_OWN : SERVICE_CONTROL_START_SHARE,
                               Service->dwStatusHandle,
                               Service->dwServiceTag,
                               argc, argv);
}


static DWORD
ScmLoadService(PSERVICE Service,
               DWORD argc,
               const PCWSTR* argv)
{
    PSERVICE_GROUP Group = Service->lpGroup;
    DWORD dwError = ERROR_SUCCESS;
    LPCWSTR lpLogStrings[2];
    WCHAR szLogBuffer[80];

    DPRINT("ScmLoadService() called\n");
    DPRINT("Start Service %p (%S)\n", Service, Service->lpServiceName);

    DPRINT("Service->Type: %lu\n", Service->Status.dwServiceType);

    if (Service->Status.dwServiceType & SERVICE_DRIVER)
    {
        if (Service->Status.dwCurrentState != SERVICE_STOPPED)
        {
            DPRINT("Service %S is already running\n", Service->lpServiceName);
            return ERROR_SERVICE_ALREADY_RUNNING;
        }

        /* Start the driver */
        dwError = ScmStartDriver(Service);
    }
    else // if (Service->Status.dwServiceType & (SERVICE_WIN32 | SERVICE_INTERACTIVE_PROCESS))
    {
        /*
         * Start user-mode service. The state check and the attachment of the
         * image are done under the database lock: the stop of the previous
         * run clears the image and sets the state under that lock.
         */
        ScmLockDatabaseExclusive();
        if (Service->Status.dwCurrentState != SERVICE_STOPPED)
        {
            ScmUnlockDatabase();
            DPRINT("Service %S is already running\n", Service->lpServiceName);
            return ERROR_SERVICE_ALREADY_RUNNING;
        }
        dwError = ScmCreateOrReferenceServiceImage(Service);
        ScmUnlockDatabase();
        if (dwError == ERROR_SUCCESS)
        {
            dwError = ScmStartUserModeService(Service, argc, argv);
            if (dwError == ERROR_SUCCESS)
            {
                /*
                 * The service may have reported its state already, before the start control returned.
                 * It then took the reference of a started service, and its state must not be set back.
                 */
                ScmLockDatabaseExclusive();
                if (Service->Status.dwCurrentState == SERVICE_STOPPED && Service->lpImage != NULL)
                {
                    Service->Status.dwCurrentState = SERVICE_START_PENDING;
                    Service->Status.dwControlsAccepted = 0;
                    ScmReferenceService(Service);
                }
                ScmUnlockDatabase();

                ScmCheckServiceProcessExited(Service);
            }
            else
            {
                /* A stop of the service has released the image already */
                ScmLockDatabaseExclusive();
                if (Service->lpImage != NULL)
                {
                    Service->lpImage->dwImageRunCount--;
                    if (Service->lpImage->dwImageRunCount == 0)
                        ScmRemoveServiceImage(Service->lpImage);
                    Service->lpImage = NULL;
                }
                ScmUnlockDatabase();
            }
        }
    }

    DPRINT("ScmLoadService() done (Error %lu)\n", dwError);

    if (dwError == ERROR_SUCCESS)
    {
        if (Group != NULL)
        {
            Group->ServicesRunning = TRUE;
        }

        /* Log a successful service start */
        LoadStringW(GetModuleHandle(NULL), IDS_SERVICE_START, szLogBuffer, 80);
        lpLogStrings[0] = Service->lpDisplayName;
        lpLogStrings[1] = szLogBuffer;

        ScmLogEvent(EVENT_SERVICE_CONTROL_SUCCESS,
                    EVENTLOG_INFORMATION_TYPE,
                    2,
                    lpLogStrings);
    }
    else
    {
        if (Service->dwErrorControl != SERVICE_ERROR_IGNORE)
        {
            /* Log a failed service start */
            StringCchPrintfW(szLogBuffer, ARRAYSIZE(szLogBuffer),
                             L"%lu", dwError);
            lpLogStrings[0] = Service->lpServiceName;
            lpLogStrings[1] = szLogBuffer;
            ScmLogEvent(EVENT_SERVICE_START_FAILED,
                        EVENTLOG_ERROR_TYPE,
                        2,
                        lpLogStrings);
        }

#if 0
        switch (Service->dwErrorControl)
        {
            case SERVICE_ERROR_SEVERE:
                if (IsLastKnownGood == FALSE)
                {
                    /* FIXME: Boot last known good configuration */
                }
                break;

            case SERVICE_ERROR_CRITICAL:
                if (IsLastKnownGood == FALSE)
                {
                    /* FIXME: Boot last known good configuration */
                }
                else
                {
                    /* FIXME: BSOD! */
                }
                break;
        }
#endif
    }

    return dwError;
}


DWORD
ScmStartService(PSERVICE Service,
                DWORD argc,
                const PCWSTR* argv)
{
    DWORD dwError = ERROR_SUCCESS;
    SC_RPC_LOCK Lock = NULL;

    DPRINT("ScmStartService() called\n");
    DPRINT("Start Service %p (%S)\n", Service, Service->lpServiceName);

    /* Acquire the service control critical section, to synchronize starts */
    EnterCriticalSection(&ControlServiceCriticalSection);

    /*
     * Acquire the user service start lock while the service is starting, if
     * needed (i.e. if we are not starting it during the initialization phase).
     * If we don't success, bail out.
     */
    if (!ScmInitialize)
    {
        dwError = ScmAcquireServiceStartLock(TRUE, &Lock);
        if (dwError != ERROR_SUCCESS)
            goto done;
    }

    /* Really start the service */
    dwError = ScmLoadService(Service, argc, argv);

    /* Release the service start lock, if needed, and the critical section */
    if (Lock) ScmReleaseServiceStartLock(&Lock);

done:
    LeaveCriticalSection(&ControlServiceCriticalSection);

    DPRINT("ScmStartService() done (Error %lu)\n", dwError);

    return dwError;
}


VOID
ScmAutoStartServices(VOID)
{
    DWORD dwError;
    PLIST_ENTRY GroupEntry;
    PLIST_ENTRY ServiceEntry;
    PSERVICE_GROUP CurrentGroup;
    PSERVICE CurrentService;
    WCHAR szSafeBootServicePath[MAX_PATH];
    DWORD SafeBootEnabled;
    HKEY hKey;
    DWORD dwKeySize;
    ULONG i;

    /*
     * This function MUST be called ONLY at initialization time.
     * Therefore, no need to acquire the user service start lock.
     */
    ASSERT(ScmInitialize);

    /* Retrieve the SafeBoot parameter */
    dwError = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Option",
                            0,
                            KEY_READ,
                            &hKey);
    if (dwError == ERROR_SUCCESS)
    {
        dwKeySize = sizeof(SafeBootEnabled);
        dwError = RegQueryValueExW(hKey,
                                   L"OptionValue",
                                   0,
                                   NULL,
                                   (LPBYTE)&SafeBootEnabled,
                                   &dwKeySize);
        RegCloseKey(hKey);
    }

    /* Default to Normal boot if the value doesn't exist */
    if (dwError != ERROR_SUCCESS)
        SafeBootEnabled = 0;

    /* Acquire the service control critical section, to synchronize starts */
    EnterCriticalSection(&ControlServiceCriticalSection);

    /* Clear 'ServiceVisited' flag (or set if not to start in Safe Mode) */
    ServiceEntry = ServiceListHead.Flink;
    while (ServiceEntry != &ServiceListHead)
    {
        CurrentService = CONTAINING_RECORD(ServiceEntry, SERVICE, ServiceListEntry);

        /* Build the safe boot path */
        StringCchCopyW(szSafeBootServicePath, ARRAYSIZE(szSafeBootServicePath),
                       L"SYSTEM\\CurrentControlSet\\Control\\SafeBoot");

        switch (SafeBootEnabled)
        {
            /* NOTE: Assumes MINIMAL (1) and DSREPAIR (3) load same items */
            case 1:
            case 3:
                StringCchCatW(szSafeBootServicePath, ARRAYSIZE(szSafeBootServicePath),
                              L"\\Minimal\\");
                break;

            case 2:
                StringCchCatW(szSafeBootServicePath, ARRAYSIZE(szSafeBootServicePath),
                              L"\\Network\\");
                break;
        }

        if (SafeBootEnabled != 0)
        {
            /* If key does not exist then do not assume safe mode */
            dwError = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                                    szSafeBootServicePath,
                                    0,
                                    KEY_READ,
                                    &hKey);
            if (dwError == ERROR_SUCCESS)
            {
                RegCloseKey(hKey);

                /* Finish Safe Boot path off */
                StringCchCatW(szSafeBootServicePath, ARRAYSIZE(szSafeBootServicePath),
                              CurrentService->lpServiceName);

                /* Check that the key is in the Safe Boot path */
                dwError = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                                        szSafeBootServicePath,
                                        0,
                                        KEY_READ,
                                        &hKey);
                if (dwError != ERROR_SUCCESS)
                {
                    /* Mark service as visited so it is not auto-started */
                    CurrentService->ServiceVisited = TRUE;
                }
                else
                {
                    /* Must be auto-started in safe mode - mark as unvisited */
                    RegCloseKey(hKey);
                    CurrentService->ServiceVisited = FALSE;
                }
            }
            else
            {
                DPRINT1("WARNING: Could not open the associated Safe Boot key\n");
                CurrentService->ServiceVisited = FALSE;
            }
        }

        ServiceEntry = ServiceEntry->Flink;
    }

    /* Start all services which are members of an existing group */
    GroupEntry = GroupListHead.Flink;
    while (GroupEntry != &GroupListHead)
    {
        CurrentGroup = CONTAINING_RECORD(GroupEntry, SERVICE_GROUP, GroupListEntry);

        DPRINT("Group '%S'\n", CurrentGroup->lpGroupName);

        /* Start all services witch have a valid tag */
        for (i = 0; i < CurrentGroup->TagCount; i++)
        {
            ServiceEntry = ServiceListHead.Flink;
            while (ServiceEntry != &ServiceListHead)
            {
                CurrentService = CONTAINING_RECORD(ServiceEntry, SERVICE, ServiceListEntry);

                if ((CurrentService->lpGroup == CurrentGroup) &&
                    (CurrentService->dwStartType == SERVICE_AUTO_START) &&
                    (CurrentService->ServiceVisited == FALSE) &&
                    (CurrentService->dwTag == CurrentGroup->TagArray[i]))
                {
                    CurrentService->ServiceVisited = TRUE;
                    ScmLoadService(CurrentService, 0, NULL);
                }

                ServiceEntry = ServiceEntry->Flink;
             }
        }

        /* Start all services which have an invalid tag or which do not have a tag */
        ServiceEntry = ServiceListHead.Flink;
        while (ServiceEntry != &ServiceListHead)
        {
            CurrentService = CONTAINING_RECORD(ServiceEntry, SERVICE, ServiceListEntry);

            if ((CurrentService->lpGroup == CurrentGroup) &&
                (CurrentService->dwStartType == SERVICE_AUTO_START) &&
                (CurrentService->ServiceVisited == FALSE))
            {
                CurrentService->ServiceVisited = TRUE;
                ScmLoadService(CurrentService, 0, NULL);
            }

            ServiceEntry = ServiceEntry->Flink;
        }

        GroupEntry = GroupEntry->Flink;
    }

    /* Start all services which are members of any non-existing group */
    ServiceEntry = ServiceListHead.Flink;
    while (ServiceEntry != &ServiceListHead)
    {
        CurrentService = CONTAINING_RECORD(ServiceEntry, SERVICE, ServiceListEntry);

        if ((CurrentService->lpGroup != NULL) &&
            (CurrentService->dwStartType == SERVICE_AUTO_START) &&
            (CurrentService->ServiceVisited == FALSE))
        {
            CurrentService->ServiceVisited = TRUE;
            ScmLoadService(CurrentService, 0, NULL);
        }

        ServiceEntry = ServiceEntry->Flink;
    }

    /* Start all services which are not a member of any group */
    ServiceEntry = ServiceListHead.Flink;
    while (ServiceEntry != &ServiceListHead)
    {
        CurrentService = CONTAINING_RECORD(ServiceEntry, SERVICE, ServiceListEntry);

        if ((CurrentService->lpGroup == NULL) &&
            (CurrentService->dwStartType == SERVICE_AUTO_START) &&
            (CurrentService->ServiceVisited == FALSE))
        {
            CurrentService->ServiceVisited = TRUE;
            ScmLoadService(CurrentService, 0, NULL);
        }

        ServiceEntry = ServiceEntry->Flink;
    }

    /* Clear 'ServiceVisited' flag again */
    ServiceEntry = ServiceListHead.Flink;
    while (ServiceEntry != &ServiceListHead)
    {
        CurrentService = CONTAINING_RECORD(ServiceEntry, SERVICE, ServiceListEntry);
        CurrentService->ServiceVisited = FALSE;
        ServiceEntry = ServiceEntry->Flink;
    }

    /* Release the critical section */
    LeaveCriticalSection(&ControlServiceCriticalSection);
}


VOID
ScmAutoShutdownServices(VOID)
{
    PLIST_ENTRY ServiceEntry;
    PSERVICE CurrentService;

    DPRINT("ScmAutoShutdownServices() called\n");

    /* Lock the service database exclusively */
    ScmLockDatabaseExclusive();

    ServiceEntry = ServiceListHead.Flink;
    while (ServiceEntry != &ServiceListHead)
    {
        CurrentService = CONTAINING_RECORD(ServiceEntry, SERVICE, ServiceListEntry);

        if ((CurrentService->Status.dwControlsAccepted & SERVICE_ACCEPT_SHUTDOWN) &&
            (CurrentService->Status.dwCurrentState == SERVICE_RUNNING ||
             CurrentService->Status.dwCurrentState == SERVICE_START_PENDING))
        {
            /* Send the shutdown notification */
            DPRINT("Shutdown service: %S\n", CurrentService->lpServiceName);
            ScmControlService(CurrentService->lpImage->hControlPipe,
                              CurrentService->lpServiceName,
                              SERVICE_CONTROL_SHUTDOWN,
                              CurrentService->dwStatusHandle);
        }

        ServiceEntry = ServiceEntry->Flink;
    }

    /* Unlock the service database */
    ScmUnlockDatabase();

    DPRINT("ScmAutoShutdownServices() done\n");
}


BOOL
ScmLockDatabaseExclusive(VOID)
{
    return RtlAcquireResourceExclusive(&DatabaseLock, TRUE);
}


BOOL
ScmLockDatabaseShared(VOID)
{
    return RtlAcquireResourceShared(&DatabaseLock, TRUE);
}


VOID
ScmUnlockDatabase(VOID)
{
    RtlReleaseResource(&DatabaseLock);
}


VOID
ScmInitNamedPipeCriticalSection(VOID)
{
    HKEY hKey;
    DWORD dwKeySize;
    DWORD dwError;

    InitializeCriticalSection(&ControlServiceCriticalSection);

    dwError = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\CurrentControlSet\\Control",
                            0,
                            KEY_READ,
                            &hKey);
   if (dwError == ERROR_SUCCESS)
   {
        dwKeySize = sizeof(PipeTimeout);
        RegQueryValueExW(hKey,
                         L"ServicesPipeTimeout",
                         0,
                         NULL,
                         (LPBYTE)&PipeTimeout,
                         &dwKeySize);
       RegCloseKey(hKey);
   }
}


VOID
ScmDeleteNamedPipeCriticalSection(VOID)
{
    DeleteCriticalSection(&ControlServiceCriticalSection);
}

/* EOF */
