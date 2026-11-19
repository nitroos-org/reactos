/*
 * PROJECT:     ReactOS Service Control Manager
 * LICENSE:     GPL - See COPYING in the top level directory
 * FILE:        base/system/services/rpcserver.c
 * PURPOSE:     RPC server interface for the advapi32 calls
 * COPYRIGHT:   Copyright 2005-2006 Eric Kohl
 *              Copyright 2006-2007 Hervé Poussineau <hpoussin@reactos.org>
 *              Copyright 2007 Ged Murphy <gedmurphy@reactos.org>
 */

/* INCLUDES ****************************************************************/

#include "services.h"

#include <winnls.h>
#include <strsafe.h>

#include <pseh/pseh2.h>

#define NDEBUG
#include <debug.h>

/* GLOBALS *****************************************************************/

#define MANAGER_TAG 0x72674D68  /* 'hMgr' */
#define SERVICE_TAG 0x63765368  /* 'hSvc' */
#define INVALID_TAG 0xAABBCCDD

typedef struct _SCMGR_HANDLE
{
    DWORD Tag;
    DWORD DesiredAccess;
} SCMGR_HANDLE;


typedef struct _MANAGER_HANDLE
{
    SCMGR_HANDLE Handle;
    WCHAR DatabaseName[1];
} MANAGER_HANDLE, *PMANAGER_HANDLE;


typedef struct _SERVICE_HANDLE
{
    SCMGR_HANDLE Handle;
    PSERVICE ServiceEntry;
} SERVICE_HANDLE, *PSERVICE_HANDLE;


#define SC_MANAGER_READ \
  (STANDARD_RIGHTS_READ | \
   SC_MANAGER_QUERY_LOCK_STATUS | \
   SC_MANAGER_ENUMERATE_SERVICE)

#define SC_MANAGER_WRITE \
  (STANDARD_RIGHTS_WRITE | \
   SC_MANAGER_MODIFY_BOOT_CONFIG | \
   SC_MANAGER_CREATE_SERVICE)

#define SC_MANAGER_EXECUTE \
  (STANDARD_RIGHTS_EXECUTE | \
   SC_MANAGER_LOCK | \
   SC_MANAGER_ENUMERATE_SERVICE | \
   SC_MANAGER_CONNECT | \
   SC_MANAGER_CREATE_SERVICE)


#define SERVICE_READ \
  (STANDARD_RIGHTS_READ | \
   SERVICE_INTERROGATE | \
   SERVICE_ENUMERATE_DEPENDENTS | \
   SERVICE_QUERY_STATUS | \
   SERVICE_QUERY_CONFIG)

#define SERVICE_WRITE \
  (STANDARD_RIGHTS_WRITE | \
   SERVICE_CHANGE_CONFIG)

#define SERVICE_EXECUTE \
  (STANDARD_RIGHTS_EXECUTE | \
   SERVICE_USER_DEFINED_CONTROL | \
   SERVICE_PAUSE_CONTINUE | \
   SERVICE_STOP | \
   SERVICE_START)

#define TAG_ARRAY_SIZE 32

/* VARIABLES ***************************************************************/

static GENERIC_MAPPING
ScmManagerMapping = {SC_MANAGER_READ,
                     SC_MANAGER_WRITE,
                     SC_MANAGER_EXECUTE,
                     SC_MANAGER_ALL_ACCESS};

static GENERIC_MAPPING
ScmServiceMapping = {SERVICE_READ,
                     SERVICE_WRITE,
                     SERVICE_EXECUTE,
                     SERVICE_ALL_ACCESS};

DWORD g_dwServiceBits = 0;

/* FUNCTIONS ***************************************************************/

VOID
ScmStartRpcServer(VOID)
{
    RPC_STATUS Status;

    DPRINT("ScmStartRpcServer() called\n");

    Status = RpcServerUseProtseqEpW(L"ncacn_np",
                                    10,
                                    L"\\pipe\\ntsvcs",
                                    NULL);
    if (Status != RPC_S_OK)
    {
        DPRINT1("RpcServerUseProtseqEpW() failed (Status %lx)\n", Status);
        return;
    }

    Status = RpcServerRegisterIf(svcctl_v2_0_s_ifspec,
                                 NULL,
                                 NULL);
    if (Status != RPC_S_OK)
    {
        DPRINT1("RpcServerRegisterIf() failed (Status %lx)\n", Status);
        return;
    }

    Status = RpcServerListen(1, 20, TRUE);
    if (Status != RPC_S_OK)
    {
        DPRINT1("RpcServerListen() failed (Status %lx)\n", Status);
        return;
    }

    DPRINT("ScmStartRpcServer() done\n");
}


static DWORD
ScmCreateManagerHandle(LPWSTR lpDatabaseName,
                       SC_HANDLE *Handle)
{
    PMANAGER_HANDLE Ptr;

    if (lpDatabaseName == NULL)
        lpDatabaseName = SERVICES_ACTIVE_DATABASEW;

    if (_wcsicmp(lpDatabaseName, SERVICES_FAILED_DATABASEW) == 0)
    {
        DPRINT("Database %S, does not exist\n", lpDatabaseName);
        return ERROR_DATABASE_DOES_NOT_EXIST;
    }
    else if (_wcsicmp(lpDatabaseName, SERVICES_ACTIVE_DATABASEW) != 0)
    {
        DPRINT("Invalid Database name %S\n", lpDatabaseName);
        return ERROR_INVALID_NAME;
    }

    Ptr = HeapAlloc(GetProcessHeap(),
                    HEAP_ZERO_MEMORY,
                    FIELD_OFFSET(MANAGER_HANDLE, DatabaseName[wcslen(lpDatabaseName) + 1]));
    if (Ptr == NULL)
        return ERROR_NOT_ENOUGH_MEMORY;

    Ptr->Handle.Tag = MANAGER_TAG;

    wcscpy(Ptr->DatabaseName, lpDatabaseName);

    *Handle = (SC_HANDLE)Ptr;

    return ERROR_SUCCESS;
}


static DWORD
ScmCreateServiceHandle(PSERVICE lpServiceEntry,
                       SC_HANDLE *Handle)
{
    PSERVICE_HANDLE Ptr;

    Ptr = HeapAlloc(GetProcessHeap(),
                    HEAP_ZERO_MEMORY,
                    sizeof(SERVICE_HANDLE));
    if (Ptr == NULL)
        return ERROR_NOT_ENOUGH_MEMORY;

    Ptr->Handle.Tag = SERVICE_TAG;

    Ptr->ServiceEntry = lpServiceEntry;

    *Handle = (SC_HANDLE)Ptr;

    return ERROR_SUCCESS;
}


static PMANAGER_HANDLE
ScmGetServiceManagerFromHandle(SC_RPC_HANDLE Handle)
{
    PMANAGER_HANDLE pManager = NULL;

    _SEH2_TRY
    {
        if (((PMANAGER_HANDLE)Handle)->Handle.Tag == MANAGER_TAG)
            pManager = (PMANAGER_HANDLE)Handle;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT1("Exception: Invalid Service Manager handle\n");
    }
    _SEH2_END;

    return pManager;
}


static PSERVICE_HANDLE
ScmGetServiceFromHandle(SC_RPC_HANDLE Handle)
{
    PSERVICE_HANDLE pService = NULL;

    _SEH2_TRY
    {
        if (((PSERVICE_HANDLE)Handle)->Handle.Tag == SERVICE_TAG)
            pService = (PSERVICE_HANDLE)Handle;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT1("Exception: Invalid Service handle\n");
    }
    _SEH2_END;

    return pService;
}


/*
 * The account a service runs as must exist: the short names LocalService and NetworkService are no account names
 * (the full names are NT AUTHORITY\\LocalService and NT AUTHORITY\\NetworkService) and a name the LSA cannot map is
 * refused; Windows Server 2022 answers both CreateService and ChangeServiceConfig with ERROR_INVALID_SERVICE_ACCOUNT
 * (1057). A lookup that fails for another reason lets the name pass.
 */
static DWORD
ScmCheckServiceStartName(
    _In_opt_ LPCWSTR lpServiceStartName)
{
    BYTE SidBuffer[SECURITY_MAX_SID_SIZE];
    WCHAR szDomain[256];
    DWORD dwSidSize, dwDomainSize;
    SID_NAME_USE Use;

    if (lpServiceStartName == NULL || *lpServiceStartName == UNICODE_NULL ||
        !_wcsicmp(lpServiceStartName, L"LocalSystem"))
        return ERROR_SUCCESS;

    if (!_wcsicmp(lpServiceStartName, L"LocalService") || !_wcsicmp(lpServiceStartName, L"NetworkService"))
        return ERROR_INVALID_SERVICE_ACCOUNT;

    /* virtual accounts have no entry in the account database, the LSA derives their SIDs */
    if (!_wcsnicmp(lpServiceStartName, L"NT SERVICE\\", 11))
        return ERROR_SUCCESS;

    dwSidSize = sizeof(SidBuffer);
    dwDomainSize = ARRAYSIZE(szDomain);
    if (!LookupAccountNameW(NULL, lpServiceStartName, (PSID)SidBuffer, &dwSidSize, szDomain, &dwDomainSize, &Use) &&
        GetLastError() == ERROR_NONE_MAPPED)
    {
        DPRINT1("Service account %S is not known\n", lpServiceStartName);
        return ERROR_INVALID_SERVICE_ACCOUNT;
    }

    return ERROR_SUCCESS;
}


static DWORD
ScmCheckAccess(SC_HANDLE Handle,
               DWORD dwDesiredAccess)
{
    PMANAGER_HANDLE hMgr;

    hMgr = (PMANAGER_HANDLE)Handle;
    if (hMgr->Handle.Tag == MANAGER_TAG)
    {
        RtlMapGenericMask(&dwDesiredAccess,
                          &ScmManagerMapping);

        hMgr->Handle.DesiredAccess = dwDesiredAccess;

        return ERROR_SUCCESS;
    }
    else if (hMgr->Handle.Tag == SERVICE_TAG)
    {
        RtlMapGenericMask(&dwDesiredAccess,
                          &ScmServiceMapping);

        hMgr->Handle.DesiredAccess = dwDesiredAccess;

        return ERROR_SUCCESS;
    }

    return ERROR_INVALID_HANDLE;
}


DWORD
ScmAssignNewTag(PSERVICE lpService)
{
    HKEY hKey = NULL;
    DWORD dwError;
    DWORD dwGroupTagCount = 0;
    PDWORD pdwGroupTags = NULL;
    DWORD dwFreeTag = 0;
    DWORD dwTagUsedBase = 1;
    BOOLEAN TagUsed[TAG_ARRAY_SIZE];
    INT nTagOffset;
    DWORD i;
    DWORD cbDataSize;
    PLIST_ENTRY ServiceEntry;
    PSERVICE CurrentService;

    ASSERT(lpService != NULL);
    ASSERT(lpService->lpGroup != NULL);

    dwError = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"System\\CurrentControlSet\\Control\\GroupOrderList",
                            0,
                            KEY_READ,
                            &hKey);

    if (dwError != ERROR_SUCCESS)
        goto findFreeTag;

    /* query value length */
    cbDataSize = 0;
    dwError = RegQueryValueExW(hKey,
                               lpService->lpGroup->szGroupName,
                               NULL,
                               NULL,
                               NULL,
                               &cbDataSize);

    if (dwError != ERROR_SUCCESS && dwError != ERROR_MORE_DATA)
        goto findFreeTag;

    pdwGroupTags = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbDataSize);
    if (!pdwGroupTags)
    {
        dwError = ERROR_NOT_ENOUGH_MEMORY;
        goto cleanup;
    }

    dwError = RegQueryValueExW(hKey,
                               lpService->lpGroup->szGroupName,
                               NULL,
                               NULL,
                               (LPBYTE)pdwGroupTags,
                               &cbDataSize);

    if (dwError != ERROR_SUCCESS)
        goto findFreeTag;

    if (cbDataSize < sizeof(pdwGroupTags[0]))
        goto findFreeTag;

    dwGroupTagCount = min(pdwGroupTags[0], cbDataSize / sizeof(pdwGroupTags[0]) - 1);

findFreeTag:
    do
    {
        /* mark all tags as unused */
        for (i = 0; i < TAG_ARRAY_SIZE; i++)
            TagUsed[i] = FALSE;

        /* mark tags in GroupOrderList as used */
        for (i = 1; i <= dwGroupTagCount; i++)
        {
            nTagOffset = pdwGroupTags[i] - dwTagUsedBase;
            if (nTagOffset >= 0 && nTagOffset < TAG_ARRAY_SIZE)
                TagUsed[nTagOffset] = TRUE;
        }

        /* mark tags in service list as used */
        ServiceEntry = lpService->ServiceListEntry.Flink;
        while (ServiceEntry != &lpService->ServiceListEntry)
        {
            ASSERT(ServiceEntry != NULL);
            CurrentService = CONTAINING_RECORD(ServiceEntry, SERVICE, ServiceListEntry);
            if (CurrentService->lpGroup == lpService->lpGroup)
            {
                nTagOffset = CurrentService->dwTag - dwTagUsedBase;
                if (nTagOffset >= 0 && nTagOffset < TAG_ARRAY_SIZE)
                    TagUsed[nTagOffset] = TRUE;
            }

            ServiceEntry = ServiceEntry->Flink;
        }

        /* find unused tag, if any */
        for (i = 0; i < TAG_ARRAY_SIZE; i++)
        {
            if (!TagUsed[i])
            {
                dwFreeTag = dwTagUsedBase + i;
                break;
            }
        }

        dwTagUsedBase += TAG_ARRAY_SIZE;
    } while (!dwFreeTag);

cleanup:
    if (pdwGroupTags)
        HeapFree(GetProcessHeap(), 0, pdwGroupTags);

    if (hKey)
        RegCloseKey(hKey);

    if (dwFreeTag)
    {
        lpService->dwTag = dwFreeTag;
        DPRINT("Assigning new tag %lu to service %S in group %S\n",
               lpService->dwTag, lpService->lpServiceName, lpService->lpGroup->szGroupName);
        dwError = ERROR_SUCCESS;
    }
    else
    {
        DPRINT1("Failed to assign new tag to service %S, error=%lu\n",
                lpService->lpServiceName, dwError);
    }

    return dwError;
}


/* Create a path suitable for the bootloader out of the full path */
DWORD
ScmConvertToBootPathName(wchar_t *CanonName, wchar_t **RelativeName)
{
    SIZE_T ServiceNameLen, ExpandedLen;
    DWORD BufferSize;
    WCHAR Dest;
    WCHAR *Expanded;
    UNICODE_STRING NtPathName, SystemRoot, LinkTarget;
    OBJECT_ATTRIBUTES ObjectAttributes;
    NTSTATUS Status;
    HANDLE SymbolicLinkHandle;

    DPRINT("ScmConvertToBootPathName %S\n", CanonName);

    if (!RelativeName)
        return ERROR_INVALID_PARAMETER;

    *RelativeName = NULL;

    ServiceNameLen = wcslen(CanonName);

    /* First check, if it's already good */
    if (ServiceNameLen > 12 &&
        !_wcsnicmp(L"\\SystemRoot\\", CanonName, 12))
    {
        *RelativeName = HeapAlloc(GetProcessHeap(),
                                  HEAP_ZERO_MEMORY,
                                  (ServiceNameLen + 1) * sizeof(WCHAR));
        if (*RelativeName == NULL)
        {
            DPRINT("Error allocating memory for boot driver name\n");
            return ERROR_NOT_ENOUGH_MEMORY;
        }

        /* Copy it */
        wcscpy(*RelativeName, CanonName);

        DPRINT("Bootdriver name %S\n", *RelativeName);
        return ERROR_SUCCESS;
    }

    /* If it has %SystemRoot% prefix, substitute it to \System*/
    if (ServiceNameLen > 13 &&
        !_wcsnicmp(L"%SystemRoot%\\", CanonName, 13))
    {
        /* There is no +sizeof(wchar_t) because the name is less by 1 wchar */
        *RelativeName = HeapAlloc(GetProcessHeap(),
                                  HEAP_ZERO_MEMORY,
                                  ServiceNameLen * sizeof(WCHAR));

        if (*RelativeName == NULL)
        {
            DPRINT("Error allocating memory for boot driver name\n");
            return ERROR_NOT_ENOUGH_MEMORY;
        }

        /* Copy it */
        wcscpy(*RelativeName, L"\\SystemRoot\\");
        wcscat(*RelativeName, CanonName + 13);

        DPRINT("Bootdriver name %S\n", *RelativeName);
        return ERROR_SUCCESS;
    }

    /* Get buffer size needed for expanding env strings */
    BufferSize = ExpandEnvironmentStringsW(L"%SystemRoot%\\", &Dest, 1);
    if (BufferSize <= 1)
    {
        DPRINT("Error during a call to ExpandEnvironmentStringsW()\n");
        return ERROR_INVALID_ENVIRONMENT;
    }

    /* Allocate memory, since the size is known now */
    Expanded = HeapAlloc(GetProcessHeap(),
                         HEAP_ZERO_MEMORY,
                         (BufferSize + 1) * sizeof(WCHAR));
    if (!Expanded)
    {
        DPRINT("Error allocating memory for boot driver name\n");
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    /* Expand it */
    if (ExpandEnvironmentStringsW(L"%SystemRoot%\\", Expanded, BufferSize) >
        BufferSize)
    {
        DPRINT("Error during a call to ExpandEnvironmentStringsW()\n");
        HeapFree(GetProcessHeap(), 0, Expanded);
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    /* Convert to NT-style path */
    if (!RtlDosPathNameToNtPathName_U(Expanded, &NtPathName, NULL, NULL))
    {
        DPRINT("Error during a call to RtlDosPathNameToNtPathName_U()\n");
        return ERROR_INVALID_ENVIRONMENT;
    }

    DPRINT("Converted to NT-style %wZ\n", &NtPathName);

    /* No need to keep the dos-path anymore */
    HeapFree(GetProcessHeap(), 0, Expanded);

    /* Copy it to the allocated place */
    Expanded = HeapAlloc(GetProcessHeap(),
                         HEAP_ZERO_MEMORY,
                         NtPathName.Length + sizeof(UNICODE_NULL));
    if (!Expanded)
    {
        DPRINT("Error allocating memory for boot driver name\n");
        RtlFreeUnicodeString(&NtPathName);
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    ExpandedLen = NtPathName.Length / sizeof(WCHAR);
    wcsncpy(Expanded, NtPathName.Buffer, ExpandedLen);
    Expanded[ExpandedLen] = UNICODE_NULL;
    RtlFreeUnicodeString(&NtPathName);

    if (ServiceNameLen > ExpandedLen &&
        !_wcsnicmp(Expanded, CanonName, ExpandedLen))
    {
        HeapFree(GetProcessHeap(), 0, Expanded);

        /* Only \SystemRoot\ is missing */
        *RelativeName = HeapAlloc(GetProcessHeap(),
                                  HEAP_ZERO_MEMORY,
                                  (ServiceNameLen - ExpandedLen) * sizeof(WCHAR) + 13*sizeof(WCHAR));
        if (*RelativeName == NULL)
        {
            DPRINT("Error allocating memory for boot driver name\n");
            return ERROR_NOT_ENOUGH_MEMORY;
        }

        wcscpy(*RelativeName, L"\\SystemRoot\\");
        wcscat(*RelativeName, CanonName + ExpandedLen);

        return ERROR_SUCCESS;
    }

    /* No longer need this */
    HeapFree(GetProcessHeap(), 0, Expanded);

    /* The most complex case starts here */
    RtlInitUnicodeString(&SystemRoot, L"\\SystemRoot");
    InitializeObjectAttributes(&ObjectAttributes,
                               &SystemRoot,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    /* Open this symlink */
    Status = NtOpenSymbolicLinkObject(&SymbolicLinkHandle, SYMBOLIC_LINK_QUERY, &ObjectAttributes);
    if (NT_SUCCESS(Status))
    {
        DPRINT("Opened symbolic link object\n");

        RtlInitEmptyUnicodeString(&LinkTarget, NULL, 0);
        Status = NtQuerySymbolicLinkObject(SymbolicLinkHandle, &LinkTarget, &BufferSize);
        if (NT_SUCCESS(Status) || Status == STATUS_BUFFER_TOO_SMALL)
        {
            /* Check if required buffer size is sane */
            if (BufferSize > UNICODE_STRING_MAX_BYTES - sizeof(UNICODE_NULL))
            {
                DPRINT("Too large buffer required\n");

                NtClose(SymbolicLinkHandle);
                return ERROR_NOT_ENOUGH_MEMORY;
            }

            /* Alloc the string */
            LinkTarget.Length = (USHORT)BufferSize;
            LinkTarget.MaximumLength = LinkTarget.Length + sizeof(UNICODE_NULL);
            LinkTarget.Buffer = HeapAlloc(GetProcessHeap(),
                                          HEAP_ZERO_MEMORY,
                                          LinkTarget.MaximumLength);
            if (!LinkTarget.Buffer)
            {
                DPRINT("Unable to alloc buffer\n");
                NtClose(SymbolicLinkHandle);
                return ERROR_NOT_ENOUGH_MEMORY;
            }

            /* Do a real query now */
            Status = NtQuerySymbolicLinkObject(SymbolicLinkHandle, &LinkTarget, &BufferSize);
            NtClose(SymbolicLinkHandle);
            if (NT_SUCCESS(Status))
            {
                DPRINT("LinkTarget: %wZ\n", &LinkTarget);

                ExpandedLen = LinkTarget.Length / sizeof(WCHAR);
                if ((ServiceNameLen > ExpandedLen) &&
                    !_wcsnicmp(LinkTarget.Buffer, CanonName, ExpandedLen))
                {
                    *RelativeName = HeapAlloc(GetProcessHeap(),
                                              HEAP_ZERO_MEMORY,
                                              (ServiceNameLen - ExpandedLen) * sizeof(WCHAR) + 13*sizeof(WCHAR));

                    if (*RelativeName == NULL)
                    {
                        DPRINT("Unable to alloc buffer\n");
                        return ERROR_NOT_ENOUGH_MEMORY;
                    }

                    /* Copy it over, substituting the first part
                       with SystemRoot */
                    wcscpy(*RelativeName, L"\\SystemRoot\\");
                    wcscat(*RelativeName, CanonName+ExpandedLen+1);

                    /* Return success */
                    return ERROR_SUCCESS;
                }
                else
                {
                    return ERROR_INVALID_PARAMETER;
                }
            }
            else
            {
                DPRINT("Error, Status = %08X\n", Status);
                return ERROR_INVALID_PARAMETER;
            }
        }
        else
        {
            DPRINT("Error, Status = %08X\n", Status);
            NtClose(SymbolicLinkHandle);
            return ERROR_INVALID_PARAMETER;
        }
    }
    else
    {
        /* Failure */
        DPRINT("Error, Status = %08X\n", Status);
        return ERROR_INVALID_PARAMETER;
    }
}


DWORD
ScmCanonDriverImagePath(DWORD dwStartType,
                        const wchar_t *lpServiceName,
                        wchar_t **lpCanonName)
{
    DWORD Result;
    SIZE_T ServiceNameLen;
    UNICODE_STRING NtServiceName;
    WCHAR *RelativeName;
    const WCHAR *SourceName = lpServiceName;

    /* Calculate the length of the service's name */
    ServiceNameLen = wcslen(lpServiceName);

    /* 12 is wcslen(L"\\SystemRoot\\") */
    if (ServiceNameLen > 12 &&
        !_wcsnicmp(L"\\SystemRoot\\", lpServiceName, 12))
    {
        /* SystemRoot prefix is already included */
        *lpCanonName = HeapAlloc(GetProcessHeap(),
                                 HEAP_ZERO_MEMORY,
                                 (ServiceNameLen + 1) * sizeof(WCHAR));

        if (*lpCanonName == NULL)
        {
            DPRINT("Error allocating memory for canonized service name\n");
            return ERROR_NOT_ENOUGH_MEMORY;
        }

        /* If it's a boot-time driver, it must be systemroot relative */
        if (dwStartType == SERVICE_BOOT_START)
            SourceName += 12;

        /* Copy it */
        wcscpy(*lpCanonName, SourceName);

        DPRINT("Canonicalized name %S\n", *lpCanonName);
        return NO_ERROR;
    }

    /* Check if it has %SystemRoot% (len=13) */
    if (ServiceNameLen > 13 &&
        !_wcsnicmp(L"%SystemRoot%\\", lpServiceName, 13))
    {
        /* Substitute %SystemRoot% with \\SystemRoot\\ */
        *lpCanonName = HeapAlloc(GetProcessHeap(),
                                 HEAP_ZERO_MEMORY,
                                 (ServiceNameLen + 1) * sizeof(WCHAR));

        if (*lpCanonName == NULL)
        {
            DPRINT("Error allocating memory for canonized service name\n");
            return ERROR_NOT_ENOUGH_MEMORY;
        }

        /* If it's a boot-time driver, it must be systemroot relative */
        if (dwStartType == SERVICE_BOOT_START)
            wcscpy(*lpCanonName, L"\\SystemRoot\\");

        wcscat(*lpCanonName, lpServiceName + 13);

        DPRINT("Canonicalized name %S\n", *lpCanonName);
        return NO_ERROR;
    }

    /* Check if it's a relative path name, or an NT path (\??\C:\...) that needs no conversion */
    if ((lpServiceName[0] != L'\\' && lpServiceName[1] != L':') ||
        !_wcsnicmp(L"\\??\\", lpServiceName, 4))
    {
        *lpCanonName = HeapAlloc(GetProcessHeap(),
                                 HEAP_ZERO_MEMORY,
                                 (ServiceNameLen + 1) * sizeof(WCHAR));

        if (*lpCanonName == NULL)
        {
            DPRINT("Error allocating memory for canonized service name\n");
            return ERROR_NOT_ENOUGH_MEMORY;
        }

        /* Just copy it over without changing */
        wcscpy(*lpCanonName, lpServiceName);

        return NO_ERROR;
    }

    /* It seems to be a DOS path, convert it */
    if (!RtlDosPathNameToNtPathName_U(lpServiceName, &NtServiceName, NULL, NULL))
    {
        DPRINT("RtlDosPathNameToNtPathName_U() failed\n");
        return ERROR_INVALID_PARAMETER;
    }

    *lpCanonName = HeapAlloc(GetProcessHeap(),
                             HEAP_ZERO_MEMORY,
                             NtServiceName.Length + sizeof(WCHAR));

    if (*lpCanonName == NULL)
    {
        DPRINT("Error allocating memory for canonized service name\n");
        RtlFreeUnicodeString(&NtServiceName);
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    /* Copy the string */
    wcsncpy(*lpCanonName, NtServiceName.Buffer, NtServiceName.Length / sizeof(WCHAR));

    /* The unicode string is not needed anymore */
    RtlFreeUnicodeString(&NtServiceName);

    if (dwStartType != SERVICE_BOOT_START)
    {
        DPRINT("Canonicalized name %S\n", *lpCanonName);
        return NO_ERROR;
    }

    /* The service is boot-started, so must be relative */
    Result = ScmConvertToBootPathName(*lpCanonName, &RelativeName);
    if (Result)
    {
        /* There is a problem, free name and return */
        HeapFree(GetProcessHeap(), 0, *lpCanonName);
        DPRINT("Error converting named\n");
        return Result;
    }

    ASSERT(RelativeName);

    /* Copy that string */
    wcscpy(*lpCanonName, RelativeName + 12);

    /* Free the allocated buffer */
    HeapFree(GetProcessHeap(), 0, RelativeName);

    DPRINT("Canonicalized name %S\n", *lpCanonName);

    /* Success */
    return NO_ERROR;
}


/* Recursively search for every dependency on every service */
DWORD
Int_EnumDependentServicesW(HKEY hServicesKey,
                           PSERVICE lpService,
                           DWORD dwServiceState,
                           PSERVICE *lpServices,
                           LPDWORD pcbBytesNeeded,
                           LPDWORD lpServicesReturned)
{
    DWORD dwError = ERROR_SUCCESS;
    WCHAR szNameBuf[MAX_PATH];
    WCHAR szValueBuf[MAX_PATH];
    WCHAR *lpszNameBuf = szNameBuf;
    WCHAR *lpszValueBuf = szValueBuf;
    DWORD dwSize;
    DWORD dwNumSubKeys;
    DWORD dwIteration;
    PSERVICE lpCurrentService;
    HKEY hServiceEnumKey;
    DWORD dwCurrentServiceState = SERVICE_ACTIVE;
    DWORD dwDependServiceStrPtr = 0;
    DWORD dwRequiredSize = 0;
    DWORD dwValueError;

    /* Get the number of service keys */
    dwError = RegQueryInfoKeyW(hServicesKey,
                               NULL,
                               NULL,
                               NULL,
                               &dwNumSubKeys,
                               NULL,
                               NULL,
                               NULL,
                               NULL,
                               NULL,
                               NULL,
                               NULL);
    if (dwError != ERROR_SUCCESS)
    {
        DPRINT("ERROR! Unable to get number of services keys\n");
        return dwError;
    }

    /* Iterate the service keys to see if another service depends on the this service */
    for (dwIteration = 0; dwIteration < dwNumSubKeys; dwIteration++)
    {
        dwSize = MAX_PATH;
        dwError = RegEnumKeyExW(hServicesKey,
                                dwIteration,
                                lpszNameBuf,
                                &dwSize,
                                NULL,
                                NULL,
                                NULL,
                                NULL);
        if (dwError != ERROR_SUCCESS)
            return dwError;

        /* Open the Service key */
        dwError = RegOpenKeyExW(hServicesKey,
                                lpszNameBuf,
                                0,
                                KEY_READ,
                                &hServiceEnumKey);
        if (dwError != ERROR_SUCCESS)
            return dwError;

        dwSize = MAX_PATH * sizeof(WCHAR);

        /* Check for the DependOnService Value; a service without it is not an error */
        dwValueError = RegQueryValueExW(hServiceEnumKey,
                                        L"DependOnService",
                                        NULL,
                                        NULL,
                                        (LPBYTE)lpszValueBuf,
                                        &dwSize);

        /* FIXME: Handle load order. */

        /* If the service found has a DependOnService value */
        if (dwValueError == ERROR_SUCCESS)
        {
            dwDependServiceStrPtr = 0;

            /* Can be more than one Dependencies in the DependOnService string */
            while (wcslen(lpszValueBuf + dwDependServiceStrPtr) > 0)
            {
                if (_wcsicmp(lpszValueBuf + dwDependServiceStrPtr, lpService->lpServiceName) == 0)
                {
                    /* Get the current enumed service pointer */
                    lpCurrentService = ScmGetServiceEntryByName(lpszNameBuf);

                    /* A key of the registry that is not a service of the database cannot be running */
                    if (!lpCurrentService)
                    {
                        dwDependServiceStrPtr += (DWORD)(wcslen(lpszValueBuf + dwDependServiceStrPtr) + 1);
                        continue;
                    }

                    /* Determine state the service is in */
                    if (lpCurrentService->Status.dwCurrentState == SERVICE_STOPPED)
                        dwCurrentServiceState = SERVICE_INACTIVE;

                    /* If the ServiceState matches that requested or searching for SERVICE_STATE_ALL */
                    if ((dwCurrentServiceState == dwServiceState) ||
                        (dwServiceState == SERVICE_STATE_ALL))
                    {
                        /*
                         * Calculate the size of this element: the ENUM_SERVICE_STATUSW itself (the name and
                         * display name pointers, the status, and the padding that follows it on 64-bit)
                         * and the two strings
                         */
                        dwRequiredSize = sizeof(ENUM_SERVICE_STATUSW);
                        dwRequiredSize += (DWORD)((wcslen(lpCurrentService->lpServiceName) + 1) * sizeof(WCHAR));
                        dwRequiredSize += (DWORD)((wcslen(lpCurrentService->lpDisplayName) + 1) * sizeof(WCHAR));

                        /* increase the BytesNeeded size */
                        *pcbBytesNeeded = *pcbBytesNeeded + dwRequiredSize;

                        /* Don't fill callers buffer yet, as MSDN read that the last service with dependency
                           comes first */

                        /* Recursive call to check for its dependencies */
                        Int_EnumDependentServicesW(hServicesKey,
                                                   lpCurrentService,
                                                   dwServiceState,
                                                   lpServices,
                                                   pcbBytesNeeded,
                                                   lpServicesReturned);

                        /* If the lpServices is valid set the service pointer */
                        if (lpServices)
                            lpServices[*lpServicesReturned] = lpCurrentService;

                        *lpServicesReturned = *lpServicesReturned + 1;
                    }
                }

                dwDependServiceStrPtr += (DWORD)(wcslen(lpszValueBuf + dwDependServiceStrPtr) + 1);
            }
        }

        RegCloseKey(hServiceEnumKey);
    }

    return dwError;
}


/* Function 0 */
DWORD
WINAPI
RCloseServiceHandle(
    LPSC_RPC_HANDLE hSCObject)
{
    PMANAGER_HANDLE hManager;
    PSERVICE_HANDLE hService;
    PSERVICE lpService;

    DPRINT("RCloseServiceHandle() called\n");

    DPRINT("hSCObject = %p\n", *hSCObject);

    if (*hSCObject == 0)
        return ERROR_INVALID_HANDLE;

    hManager = ScmGetServiceManagerFromHandle(*hSCObject);
    hService = ScmGetServiceFromHandle(*hSCObject);

    if (hManager != NULL)
    {
        DPRINT("Found manager handle\n");

        /* Make sure we don't access stale memory if someone tries to use this handle again. */
        hManager->Handle.Tag = INVALID_TAG;

        HeapFree(GetProcessHeap(), 0, hManager);
        hManager = NULL;

        *hSCObject = NULL;

        DPRINT("RCloseServiceHandle() done\n");
        return ERROR_SUCCESS;
    }
    else if (hService != NULL)
    {
        DPRINT("Found service handle\n");

        /* Lock the service database exclusively */
        ScmLockDatabaseExclusive();

        /* Get the pointer to the service record */
        lpService = hService->ServiceEntry;

        /* Make sure we don't access stale memory if someone tries to use this handle again. */
        hService->Handle.Tag = INVALID_TAG;

        /* Free the handle */
        HeapFree(GetProcessHeap(), 0, hService);
        hService = NULL;


        DPRINT("Closing service %S with %d references\n", lpService->lpServiceName, lpService->RefCount);
        ScmDereferenceService(lpService);

        ScmUnlockDatabase();

        *hSCObject = NULL;

        DPRINT("RCloseServiceHandle() done\n");
        return ERROR_SUCCESS;
    }

    DPRINT("Invalid handle tag (Tag %lx)\n", hManager->Handle.Tag);

    return ERROR_INVALID_HANDLE;
}


/* Function 1 */
DWORD
WINAPI
RControlService(
    SC_RPC_HANDLE hService,
    DWORD dwControl,
    LPSERVICE_STATUS lpServiceStatus)
{
    PSERVICE_HANDLE hSvc;
    PSERVICE lpService;
    ACCESS_MASK DesiredAccess;
    DWORD dwError = ERROR_SUCCESS;
    DWORD pcbBytesNeeded = 0;
    DWORD dwServicesReturned = 0;
    DWORD dwControlsAccepted;
    DWORD dwCurrentState;
    PSERVICE_IMAGE lpImage;
    HKEY hServicesKey = NULL;
    LPCWSTR lpLogStrings[2];
    WCHAR szLogBuffer[80];
    UINT uID;

    DPRINT("RControlService() called\n");

    if (ScmShutdown)
        return ERROR_SHUTDOWN_IN_PROGRESS;

    /* Check the service handle */
    hSvc = ScmGetServiceFromHandle(hService);
    if (hSvc == NULL)
    {
        DPRINT1("Invalid service handle\n");
        return ERROR_INVALID_HANDLE;
    }

    /* Check the service entry point */
    lpService = hSvc->ServiceEntry;
    if (lpService == NULL)
    {
        DPRINT1("lpService == NULL\n");
        return ERROR_INVALID_HANDLE;
    }

    /* Check access rights */
    switch (dwControl)
    {
        case SERVICE_CONTROL_STOP:
            DesiredAccess = SERVICE_STOP;
            break;

        case SERVICE_CONTROL_PAUSE:
        case SERVICE_CONTROL_CONTINUE:
        case SERVICE_CONTROL_PARAMCHANGE:
        case SERVICE_CONTROL_NETBINDADD:
        case SERVICE_CONTROL_NETBINDREMOVE:
        case SERVICE_CONTROL_NETBINDENABLE:
        case SERVICE_CONTROL_NETBINDDISABLE:
            DesiredAccess = SERVICE_PAUSE_CONTINUE;
            break;

        case SERVICE_CONTROL_INTERROGATE:
            DesiredAccess = SERVICE_INTERROGATE;
            break;

        default:
            if (dwControl >= 128 && dwControl <= 255)
                DesiredAccess = SERVICE_USER_DEFINED_CONTROL;
            else
                return ERROR_INVALID_PARAMETER;
            break;
    }

    if (!RtlAreAllAccessesGranted(hSvc->Handle.DesiredAccess,
                                  DesiredAccess))
        return ERROR_ACCESS_DENIED;

    /* Return the current service status information */
    RtlCopyMemory(lpServiceStatus,
                  &lpService->Status,
                  sizeof(SERVICE_STATUS));

    if (dwControl == SERVICE_CONTROL_STOP)
    {
        /* Check if the service has dependencies running as windows
           doesn't stop a service that does */

        /* Open the Services Reg key */
        dwError = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                                L"System\\CurrentControlSet\\Services",
                                0,
                                KEY_READ,
                                &hServicesKey);
        if (dwError != ERROR_SUCCESS)
        {
            DPRINT("Failed to open services key\n");
            return dwError;
        }

        /* Call the internal function with NULL, just to get bytes we need */
        Int_EnumDependentServicesW(hServicesKey,
                                   lpService,
                                   SERVICE_ACTIVE,
                                   NULL,
                                   &pcbBytesNeeded,
                                   &dwServicesReturned);

        RegCloseKey(hServicesKey);

        /* If pcbBytesNeeded is not zero then there are services running that
           are dependent on this service */
        if (pcbBytesNeeded != 0)
        {
            DPRINT("Service has running dependencies. Failed to stop service\n");
            return ERROR_DEPENDENT_SERVICES_RUNNING;
        }
    }

    if (lpService->Status.dwServiceType & SERVICE_DRIVER)
    {
        /* Send control code to the driver */
        dwError = ScmControlDriver(lpService,
                                   dwControl,
                                   lpServiceStatus);
    }
    else
    {
        dwControlsAccepted = lpService->Status.dwControlsAccepted;
        dwCurrentState = lpService->Status.dwCurrentState;
        /* Read once: a stop clears it without the caller holding a lock */
        lpImage = *(PSERVICE_IMAGE volatile *)&lpService->lpImage;

        /* Return ERROR_SERVICE_NOT_ACTIVE if the service has not been started */
        if (lpImage == NULL || dwCurrentState == SERVICE_STOPPED)
            return ERROR_SERVICE_NOT_ACTIVE;

        /* Check the current state before sending a control request */
        switch (dwCurrentState)
        {
            case SERVICE_STOP_PENDING:
            case SERVICE_STOPPED:
                return ERROR_SERVICE_CANNOT_ACCEPT_CTRL;

            case SERVICE_START_PENDING:
                switch (dwControl)
                {
                    case SERVICE_CONTROL_STOP:
                        break;

                    case SERVICE_CONTROL_INTERROGATE:
                        RtlCopyMemory(lpServiceStatus,
                                      &lpService->Status,
                                      sizeof(SERVICE_STATUS));
                        return ERROR_SUCCESS;

                    default:
                        return ERROR_SERVICE_CANNOT_ACCEPT_CTRL;
                }
                break;
        }

        /* Check if the control code is acceptable to the service */
        switch (dwControl)
        {
            case SERVICE_CONTROL_STOP:
                if ((dwControlsAccepted & SERVICE_ACCEPT_STOP) == 0)
                    return ERROR_INVALID_SERVICE_CONTROL;
                break;

            case SERVICE_CONTROL_PAUSE:
            case SERVICE_CONTROL_CONTINUE:
                if ((dwControlsAccepted & SERVICE_ACCEPT_PAUSE_CONTINUE) == 0)
                    return ERROR_INVALID_SERVICE_CONTROL;
                break;

            case SERVICE_CONTROL_PARAMCHANGE:
                if ((dwControlsAccepted & SERVICE_ACCEPT_PARAMCHANGE) == 0)
                    return ERROR_INVALID_SERVICE_CONTROL;
                break;

            case SERVICE_CONTROL_NETBINDADD:
            case SERVICE_CONTROL_NETBINDREMOVE:
            case SERVICE_CONTROL_NETBINDENABLE:
            case SERVICE_CONTROL_NETBINDDISABLE:
                if ((dwControlsAccepted & SERVICE_ACCEPT_NETBINDCHANGE) == 0)
                    return ERROR_INVALID_SERVICE_CONTROL;
                break;
        }

        /* Send control code to the service */
        dwError = ScmControlService(lpImage->hControlPipe,
                                    lpService->lpServiceName,
                                    dwControl,
                                    lpService->dwStatusHandle);

        /* Return service status information */
        RtlCopyMemory(lpServiceStatus,
                      &lpService->Status,
                      sizeof(SERVICE_STATUS));
    }

    if (dwError == ERROR_SUCCESS)
    {
        if (dwControl == SERVICE_CONTROL_STOP ||
            dwControl == SERVICE_CONTROL_PAUSE ||
            dwControl == SERVICE_CONTROL_CONTINUE)
        {
            /* Log a successful send control */

            switch (dwControl)
            {
                case SERVICE_CONTROL_STOP:
                    uID = IDS_SERVICE_STOP;
                    break;

                case SERVICE_CONTROL_PAUSE:
                    uID = IDS_SERVICE_PAUSE;
                    break;

                case SERVICE_CONTROL_CONTINUE:
                    uID = IDS_SERVICE_RESUME;
                    break;
            }
            LoadStringW(GetModuleHandle(NULL), uID, szLogBuffer, ARRAYSIZE(szLogBuffer));

            lpLogStrings[0] = lpService->lpDisplayName;
            lpLogStrings[1] = szLogBuffer;

            ScmLogEvent(EVENT_SERVICE_CONTROL_SUCCESS,
                        EVENTLOG_INFORMATION_TYPE,
                        2,
                        lpLogStrings);
        }
    }

    return dwError;
}


/* Function 2 */
DWORD
WINAPI
RDeleteService(
    SC_RPC_HANDLE hService)
{
    PSERVICE_HANDLE hSvc;
    PSERVICE lpService;
    DWORD dwError;

    DPRINT("RDeleteService() called\n");

    if (ScmShutdown)
        return ERROR_SHUTDOWN_IN_PROGRESS;

    hSvc = ScmGetServiceFromHandle(hService);
    if (hSvc == NULL)
    {
        DPRINT1("Invalid service handle\n");
        return ERROR_INVALID_HANDLE;
    }

    if (!RtlAreAllAccessesGranted(hSvc->Handle.DesiredAccess,
                                  DELETE))
        return ERROR_ACCESS_DENIED;

    lpService = hSvc->ServiceEntry;
    if (lpService == NULL)
    {
        DPRINT("lpService == NULL\n");
        return ERROR_INVALID_HANDLE;
    }

    /* Lock the service database exclusively */
    ScmLockDatabaseExclusive();

    if (lpService->bDeleted)
    {
        DPRINT("Service has already been marked for delete\n");
        dwError = ERROR_SERVICE_MARKED_FOR_DELETE;
        goto Done;
    }

    /* Mark service for delete */
    lpService->bDeleted = TRUE;

    dwError = ScmMarkServiceForDelete(lpService);

Done:
    /* Unlock the service database */
    ScmUnlockDatabase();

    DPRINT("RDeleteService() done\n");

    return dwError;
}


/* Function 3 */
DWORD
WINAPI
RLockServiceDatabase(
    SC_RPC_HANDLE hSCManager,
    LPSC_RPC_LOCK lpLock)
{
    PMANAGER_HANDLE hMgr;

    DPRINT("RLockServiceDatabase() called\n");

    *lpLock = NULL;

    hMgr = ScmGetServiceManagerFromHandle(hSCManager);
    if (hMgr == NULL)
    {
        DPRINT1("Invalid service manager handle\n");
        return ERROR_INVALID_HANDLE;
    }

    if (!RtlAreAllAccessesGranted(hMgr->Handle.DesiredAccess,
                                  SC_MANAGER_LOCK))
        return ERROR_ACCESS_DENIED;

    return ScmAcquireServiceStartLock(FALSE, lpLock);
}


/*
 * Services that are not Win32 services (drivers) come without a security descriptor: give them the
 * default one when somebody asks for it. The caller holds the service database exclusive.
 */
static
DWORD
ScmEnsureServiceSD(
    _In_ PSERVICE lpService)
{
    if (lpService->pSecurityDescriptor != NULL)
        return ERROR_SUCCESS;

    return ScmCreateDefaultServiceSD(&lpService->pSecurityDescriptor);
}


/* Function 4 */
DWORD
WINAPI
RQueryServiceObjectSecurity(
    SC_RPC_HANDLE hService,
    SECURITY_INFORMATION dwSecurityInformation,
    LPBYTE lpSecurityDescriptor,
    DWORD cbBufSize,
    LPBOUNDED_DWORD_256K pcbBytesNeeded)
{
    PSERVICE_HANDLE hSvc;
    PSERVICE lpService;
    ULONG DesiredAccess = 0;
    NTSTATUS Status;
    DWORD dwBytesNeeded;
    DWORD dwError;

    DPRINT("RQueryServiceObjectSecurity() called\n");

    hSvc = ScmGetServiceFromHandle(hService);
    if (hSvc == NULL)
    {
        DPRINT1("Invalid service handle\n");
        return ERROR_INVALID_HANDLE;
    }

    if (dwSecurityInformation & (DACL_SECURITY_INFORMATION |
                                 GROUP_SECURITY_INFORMATION |
                                 OWNER_SECURITY_INFORMATION))
        DesiredAccess |= READ_CONTROL;

    if (dwSecurityInformation & SACL_SECURITY_INFORMATION)
        DesiredAccess |= ACCESS_SYSTEM_SECURITY;

    if (!RtlAreAllAccessesGranted(hSvc->Handle.DesiredAccess,
                                  DesiredAccess))
    {
        DPRINT("Insufficient access rights! 0x%lx\n", hSvc->Handle.DesiredAccess);
        return ERROR_ACCESS_DENIED;
    }

    lpService = hSvc->ServiceEntry;
    if (lpService == NULL)
    {
        DPRINT("lpService == NULL\n");
        return ERROR_INVALID_HANDLE;
    }

    /* Lock the service database (exclusive: a missing descriptor is created) */
    ScmLockDatabaseExclusive();

    dwError = ScmEnsureServiceSD(lpService);
    if (dwError != ERROR_SUCCESS)
    {
        ScmUnlockDatabase();
        return dwError;
    }

    /* Retrieve the security descriptor */
    Status = RtlQuerySecurityObject(lpService->pSecurityDescriptor,
                                    dwSecurityInformation,
                                    (PSECURITY_DESCRIPTOR)lpSecurityDescriptor,
                                    cbBufSize,
                                    &dwBytesNeeded);

    /* Unlock the service database */
    ScmUnlockDatabase();

    if (NT_SUCCESS(Status))
    {
        *pcbBytesNeeded = dwBytesNeeded;
        dwError = STATUS_SUCCESS;
    }
    else if (Status == STATUS_BUFFER_TOO_SMALL)
    {
        *pcbBytesNeeded = dwBytesNeeded;
        dwError = ERROR_INSUFFICIENT_BUFFER;
    }
    else if (Status == STATUS_BAD_DESCRIPTOR_FORMAT)
    {
        dwError = ERROR_GEN_FAILURE;
    }
    else
    {
        dwError = RtlNtStatusToDosError(Status);
    }

    return dwError;
}


/* Function 5 */
DWORD
WINAPI
RSetServiceObjectSecurity(
    SC_RPC_HANDLE hService,
    DWORD dwSecurityInformation,
    LPBYTE lpSecurityDescriptor,
    DWORD dwSecurityDescriptorSize)
{
    PSERVICE_HANDLE hSvc;
    PSERVICE lpService;
    ACCESS_MASK DesiredAccess = 0;
    HANDLE hToken = NULL;
    HKEY hServiceKey = NULL;
    BOOL bDatabaseLocked = FALSE;
    NTSTATUS Status;
    DWORD dwError;

    DPRINT("RSetServiceObjectSecurity() called\n");

    hSvc = ScmGetServiceFromHandle(hService);
    if (hSvc == NULL)
    {
        DPRINT1("Invalid service handle\n");
        return ERROR_INVALID_HANDLE;
    }

    if (dwSecurityInformation == 0 ||
        dwSecurityInformation & ~(OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION
        | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION))
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (!RtlValidSecurityDescriptor((PSECURITY_DESCRIPTOR)lpSecurityDescriptor))
        return ERROR_INVALID_PARAMETER;

    if (dwSecurityInformation & SACL_SECURITY_INFORMATION)
        DesiredAccess |= ACCESS_SYSTEM_SECURITY;

    if (dwSecurityInformation & DACL_SECURITY_INFORMATION)
        DesiredAccess |= WRITE_DAC;

    if (dwSecurityInformation & (OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION))
        DesiredAccess |= WRITE_OWNER;

    if ((dwSecurityInformation & OWNER_SECURITY_INFORMATION) &&
        (((PISECURITY_DESCRIPTOR)lpSecurityDescriptor)->Owner == NULL))
    {
        return ERROR_INVALID_PARAMETER;
    }

    if ((dwSecurityInformation & GROUP_SECURITY_INFORMATION) &&
        (((PISECURITY_DESCRIPTOR)lpSecurityDescriptor)->Group == NULL))
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (!RtlAreAllAccessesGranted(hSvc->Handle.DesiredAccess,
                                  DesiredAccess))
    {
        DPRINT1("Insufficient access rights! 0x%lx\n", hSvc->Handle.DesiredAccess);
        return ERROR_ACCESS_DENIED;
    }

    lpService = hSvc->ServiceEntry;
    if (lpService == NULL)
    {
        DPRINT1("lpService == NULL\n");
        return ERROR_INVALID_HANDLE;
    }

    if (lpService->bDeleted)
        return ERROR_SERVICE_MARKED_FOR_DELETE;

#if 0
    RpcImpersonateClient(NULL);

    Status = NtOpenThreadToken(NtCurrentThread(),
                               8,
                               TRUE,
                               &hToken);
    if (!NT_SUCCESS(Status))
        return RtlNtStatusToDosError(Status);

    RpcRevertToSelf();
#endif

    /* Lock the service database exclusive */
    ScmLockDatabaseExclusive();
    bDatabaseLocked = TRUE;

    dwError = ScmEnsureServiceSD(lpService);
    if (dwError != ERROR_SUCCESS)
        goto Done;

    /* Build the new security descriptor */
    Status = RtlSetSecurityObject(dwSecurityInformation,
                                  (PSECURITY_DESCRIPTOR)lpSecurityDescriptor,
                                  &lpService->pSecurityDescriptor,
                                  &ScmServiceMapping,
                                  hToken);
    if (!NT_SUCCESS(Status))
    {
        dwError = RtlNtStatusToDosError(Status);
        goto Done;
    }

    /* Open the service key */
    dwError = ScmOpenServiceKey(lpService->lpServiceName,
                                READ_CONTROL | KEY_CREATE_SUB_KEY | KEY_SET_VALUE,
                                &hServiceKey);
    if (dwError != ERROR_SUCCESS)
        goto Done;

    /* Store the new security descriptor */
    dwError = ScmWriteSecurityDescriptor(hServiceKey,
                                         lpService->pSecurityDescriptor);

    RegFlushKey(hServiceKey);

Done:
    if (hServiceKey != NULL)
        RegCloseKey(hServiceKey);

    /* Unlock service database */
    if (bDatabaseLocked == TRUE)
        ScmUnlockDatabase();

    if (hToken != NULL)
        NtClose(hToken);

    DPRINT("RSetServiceObjectSecurity() done (Error %lu)\n", dwError);

    return dwError;
}


/* Function 6 */
DWORD
WINAPI
RQueryServiceStatus(
    SC_RPC_HANDLE hService,
    LPSERVICE_STATUS lpServiceStatus)
{
    PSERVICE_HANDLE hSvc;
    PSERVICE lpService;

    DPRINT("RQueryServiceStatus() called\n");

    if (ScmShutdown)
        return ERROR_SHUTDOWN_IN_PROGRESS;

    hSvc = ScmGetServiceFromHandle(hService);
    if (hSvc == NULL)
    {
        DPRINT1("Invalid service handle\n");
        return ERROR_INVALID_HANDLE;
    }

    if (!RtlAreAllAccessesGranted(hSvc->Handle.DesiredAccess,
                                  SERVICE_QUERY_STATUS))
    {
        DPRINT("Insufficient access rights! 0x%lx\n", hSvc->Handle.DesiredAccess);
        return ERROR_ACCESS_DENIED;
    }

    lpService = hSvc->ServiceEntry;
    if (lpService == NULL)
    {
        DPRINT("lpService == NULL\n");
        return ERROR_INVALID_HANDLE;
    }

    /* Lock the service database shared */
    ScmLockDatabaseShared();

    /* Return service status information */
    RtlCopyMemory(lpServiceStatus,
                  &lpService->Status,
                  sizeof(SERVICE_STATUS));

    /* Unlock the service database */
    ScmUnlockDatabase();

    return ERROR_SUCCESS;
}


static BOOL
ScmIsValidServiceState(DWORD dwCurrentState)
{
    switch (dwCurrentState)
    {
        case SERVICE_STOPPED:
        case SERVICE_START_PENDING:
        case SERVICE_STOP_PENDING:
        case SERVICE_RUNNING:
        case SERVICE_CONTINUE_PENDING:
        case SERVICE_PAUSE_PENDING:
        case SERVICE_PAUSED:
            return TRUE;

        default:
            return FALSE;
    }
}

typedef struct _SCM_STOP_CONTEXT
{
    PSERVICE lpService;
    PSERVICE_IMAGE lpImage;
} SCM_STOP_CONTEXT, *PSCM_STOP_CONTEXT;

/* Called with the database locked exclusively */
static
VOID
ScmReleaseStoppedImage(
    _In_ PSERVICE lpService,
    _In_opt_ PSERVICE_IMAGE lpImage)
{
    if (lpImage == NULL)
        return;

    DPRINT("Service %S image count:%d\n", lpService->lpServiceName, lpImage->dwImageRunCount);

    /* The service is not waiting any more (it was counted when it reported STOPPED) */
    lpImage->dwImageStopCount--;

    /* Decrement the image run counter */
    lpImage->dwImageRunCount--;

    /* If we just stopped the last running service... */
    if (lpImage->dwImageRunCount == 0)
    {
        /* Remove the service image */
        DPRINT("Removing service image for %S\n", lpService->lpServiceName);
        ScmRemoveServiceImage(lpImage);
    }
}

static
DWORD
WINAPI
ScmStopThread(PVOID pParam)
{
    PSCM_STOP_CONTEXT Context = (PSCM_STOP_CONTEXT)pParam;
    PSERVICE lpService = Context->lpService;
    PSERVICE_IMAGE lpImage = Context->lpImage;
    BOOL bStopDispatcher;
    WCHAR szLogBuffer[80];
    LPCWSTR lpLogStrings[2];
    LIST_ENTRY LogQueue;

    HeapFree(GetProcessHeap(), 0, Context);

    /*
     * Decide now, with the database locked, whether this stop ends the dispatcher of the image: every service
     * left in the image is waiting for its stop thread, and no other stop thread took that already. A service
     * of the image that started after this one reported STOPPED is counted in dwImageRunCount only, so the
     * image keeps its process; once the dispatcher stop is taken, a new start makes a new image.
     */
    bStopDispatcher = FALSE;
    if (lpImage != NULL)
    {
        ScmLockDatabaseExclusive();
        if (!lpImage->bDispatcherStopSent &&
            lpImage->dwImageRunCount == lpImage->dwImageStopCount)
        {
            lpImage->bDispatcherStopSent = TRUE;
            bStopDispatcher = TRUE;
        }
        ScmUnlockDatabase();
    }

    if (bStopDispatcher)
    {
        /* Stop the dispatcher thread.
         * We must not send a control message while holding the database lock, otherwise it can cause timeouts
         * We are sure that the service won't be deleted in the meantime because we still have a reference to it. */
        DPRINT("Stopping the dispatcher thread for service %S\n", lpService->lpServiceName);
        ScmControlService(lpImage->hControlPipe,
                          L"",
                          SERVICE_CONTROL_STOP,
                          lpService->dwStatusHandle);
    }

    /* Lock the service database exclusively */
    ScmLockDatabaseExclusive();

    /* A service that stopped with an error may have failure actions for that (before the image goes) */
    InitializeListHead(&LogQueue);
    ScmServiceStoppedWithError(lpService, lpImage, &LogQueue);

    /* Release the image the service ran in; a restarted service has its own reference */
    ScmReleaseStoppedImage(lpService, lpImage);

    /* Report the results of the status change here */
    if (lpService->Status.dwWin32ExitCode != ERROR_SUCCESS)
    {
        /* Log a failed service stop */
        StringCchPrintfW(szLogBuffer, ARRAYSIZE(szLogBuffer),
                         L"%lu", lpService->Status.dwWin32ExitCode);
        lpLogStrings[0] = lpService->lpDisplayName;
        lpLogStrings[1] = szLogBuffer;

        ScmLogEvent(EVENT_SERVICE_EXIT_FAILED,
                    EVENTLOG_ERROR_TYPE,
                    ARRAYSIZE(lpLogStrings),
                    lpLogStrings);
    }
    else
    {
        /* Log a successful service status change */
        LoadStringW(GetModuleHandle(NULL), IDS_SERVICE_STOPPED, szLogBuffer, ARRAYSIZE(szLogBuffer));
        lpLogStrings[0] = lpService->lpDisplayName;
        lpLogStrings[1] = szLogBuffer;

        ScmLogEvent(EVENT_SERVICE_STATUS_SUCCESS,
                    EVENTLOG_INFORMATION_TYPE,
                    ARRAYSIZE(lpLogStrings),
                    lpLogStrings);
    }

    /* Remove the reference that was added when the service started */
    DPRINT("Service %S has %d references while stoping\n", lpService->lpServiceName, lpService->RefCount);
    ScmDereferenceService(lpService);

    /* Unlock the service database */
    ScmUnlockDatabase();

    /* The event log is a service too: write its events without the database lock */
    ScmFlushFailureLog(&LogQueue);

    return 0;
}

/* Function 7 */
DWORD
WINAPI
RSetServiceStatus(
    RPC_SERVICE_STATUS_HANDLE hServiceStatus,
    LPSERVICE_STATUS lpServiceStatus)
{
    PSERVICE lpService;
    DWORD dwPreviousState;
    DWORD dwPreviousType;
    LPCWSTR lpLogStrings[2];
    WCHAR szLogBuffer[80];
    UINT uID;

    DPRINT("RSetServiceStatus() called\n");
    DPRINT("hServiceStatus = %I64u\n", hServiceStatus);
    DPRINT("dwServiceType = 0x%lx\n", lpServiceStatus->dwServiceType);
    DPRINT("dwCurrentState = %lu\n", lpServiceStatus->dwCurrentState);
    DPRINT("dwControlsAccepted = %lu\n", lpServiceStatus->dwControlsAccepted);
    DPRINT("dwWin32ExitCode = %lu\n", lpServiceStatus->dwWin32ExitCode);
    DPRINT("dwServiceSpecificExitCode = %lu\n", lpServiceStatus->dwServiceSpecificExitCode);
    DPRINT("dwCheckPoint = %lu\n", lpServiceStatus->dwCheckPoint);
    DPRINT("dwWaitHint = %lu\n", lpServiceStatus->dwWaitHint);

    if (hServiceStatus == 0)
    {
        DPRINT("hServiceStatus == NULL\n");
        return ERROR_INVALID_HANDLE;
    }

    lpService = ScmGetServiceByStatusHandle(hServiceStatus);
    if (lpService == NULL)
        return ERROR_INVALID_HANDLE;

    /* Check current state */
    if (!ScmIsValidServiceState(lpServiceStatus->dwCurrentState))
    {
        DPRINT("Invalid service state\n");
        return ERROR_INVALID_DATA;
    }

    /* Check service type */
    if (!(lpServiceStatus->dwServiceType & SERVICE_WIN32) &&
         (lpServiceStatus->dwServiceType & SERVICE_DRIVER))
    {
        DPRINT("Invalid service type\n");
        return ERROR_INVALID_DATA;
    }

    /* Check accepted controls */
    if (lpServiceStatus->dwControlsAccepted & ~0xFF)
    {
        DPRINT("Invalid controls accepted\n");
        return ERROR_INVALID_DATA;
    }

    /* Set the wait hint and check point only if the service is in a pending state,
       otherwise they should be 0 */
    if (lpServiceStatus->dwCurrentState == SERVICE_STOPPED ||
        lpServiceStatus->dwCurrentState == SERVICE_PAUSED ||
        lpServiceStatus->dwCurrentState == SERVICE_RUNNING)
    {
        lpServiceStatus->dwWaitHint = 0;
        lpServiceStatus->dwCheckPoint = 0;
    }

    /* Lock the service database exclusively */
    ScmLockDatabaseExclusive();

    /* Save the current service state */
    dwPreviousState = lpService->Status.dwCurrentState;

    /* Save the current service type */
    dwPreviousType = lpService->Status.dwServiceType;

    /* Update the service status */
    RtlCopyMemory(&lpService->Status,
                  lpServiceStatus,
                  sizeof(SERVICE_STATUS));

    /* Restore the previous service type */
    lpService->Status.dwServiceType = dwPreviousType;

    DPRINT("Service %S changed state %d to %d\n", lpService->lpServiceName, dwPreviousState, lpServiceStatus->dwCurrentState);

    if (lpServiceStatus->dwCurrentState != SERVICE_STOPPED &&
        dwPreviousState == SERVICE_STOPPED)
    {
        /* Keep a reference on all non stopped services */
        ScmReferenceService(lpService);
        DPRINT("Service %S has %d references after starting\n", lpService->lpServiceName, lpService->RefCount);
    }

    /* Check if the service just stopped */
    if (lpServiceStatus->dwCurrentState == SERVICE_STOPPED &&
        dwPreviousState != SERVICE_STOPPED)
    {
        HANDLE hStopThread;
        DWORD dwStopThreadId;
        PSERVICE_IMAGE lpStoppedImage;
        PSCM_STOP_CONTEXT StopContext;
        DPRINT("Service %S, currentstate: %d, prev: %d\n", lpService->lpServiceName, lpServiceStatus->dwCurrentState, dwPreviousState);

        /*
         * The service just changed its status to stopped.
         * Create a thread that will complete the stop sequence.
         * This thread will remove the reference that was added when the service started.
         * This will ensure that the service will remain valid as long as this reference is still held.
         */
        /* The stopped service gives up its image now; the stop thread releases that image */
        lpStoppedImage = lpService->lpImage;
        lpService->lpImage = NULL;
        if (lpStoppedImage != NULL)
            lpStoppedImage->dwImageStopCount++;

        hStopThread = NULL;
        StopContext = HeapAlloc(GetProcessHeap(), 0, sizeof(*StopContext));
        if (StopContext != NULL)
        {
            StopContext->lpService = lpService;
            StopContext->lpImage = lpStoppedImage;
            hStopThread = CreateThread(NULL,
                                       0,
                                       ScmStopThread,
                                       (LPVOID)StopContext,
                                       0,
                                       &dwStopThreadId);
            if (hStopThread == NULL)
                HeapFree(GetProcessHeap(), 0, StopContext);
        }
        if (hStopThread == NULL)
        {
            DPRINT1("Failed to create thread to complete service stop\n");
            /* We can't leave without releasing the references; we hold the lock */
            ScmReleaseStoppedImage(lpService, lpStoppedImage);
            DPRINT1("Service %S has %d references before the final release\n", lpService->lpServiceName, lpService->RefCount);
            ScmDereferenceService(lpService);
        }
        else
        {
            CloseHandle(hStopThread);
        }
    }

    /* Unlock the service database */
    ScmUnlockDatabase();

    /* Don't log any events here regarding a service stop as it can become invalid at any time */

    if (lpServiceStatus->dwCurrentState != dwPreviousState &&
        (lpServiceStatus->dwCurrentState == SERVICE_RUNNING ||
         lpServiceStatus->dwCurrentState == SERVICE_PAUSED))
    {
        /* Log a successful service status change */
        switch(lpServiceStatus->dwCurrentState)
        {
            case SERVICE_RUNNING:
                uID = IDS_SERVICE_RUNNING;
                break;

            case SERVICE_PAUSED:
                uID = IDS_SERVICE_PAUSED;
                break;
        }

        LoadStringW(GetModuleHandle(NULL), uID, szLogBuffer, ARRAYSIZE(szLogBuffer));
        lpLogStrings[0] = lpService->lpDisplayName;
        lpLogStrings[1] = szLogBuffer;

        ScmLogEvent(EVENT_SERVICE_STATUS_SUCCESS,
                    EVENTLOG_INFORMATION_TYPE,
                    2,
                    lpLogStrings);
    }

    DPRINT("Set %S to %lu\n", lpService->lpDisplayName, lpService->Status.dwCurrentState);
    DPRINT("RSetServiceStatus() done\n");

    return ERROR_SUCCESS;
}


/* Function 8 */
DWORD
WINAPI
RUnlockServiceDatabase(
    LPSC_RPC_LOCK Lock)
{
    DPRINT("RUnlockServiceDatabase(%p)\n", Lock);
    return ScmReleaseServiceStartLock(Lock);
}


/* Function 9 */
DWORD
WINAPI
RNotifyBootConfigStatus(
    SVCCTL_HANDLEW lpMachineName,
    DWORD BootAcceptable)
{
    DPRINT("RNotifyBootConfigStatus(%p %lu)\n",
           lpMachineName, BootAcceptable);

    if (BootAcceptable)
        return ScmAcceptBoot();

    return ScmRunLastKnownGood();
}


/* Function 10 */
DWORD
WINAPI
RI_ScSetServiceBitsW(
    RPC_SERVICE_STATUS_HANDLE hServiceStatus,
    DWORD dwServiceBits,
    int bSetBitsOn,
    int bUpdateImmediately,
    wchar_t *lpString)
{
    PSERVICE pService;

    DPRINT("RI_ScSetServiceBitsW(%p %lx %d %d %S)\n",
           hServiceStatus, dwServiceBits, bSetBitsOn,
           bUpdateImmediately, lpString);

    if (ScmShutdown)
        return ERROR_SHUTDOWN_IN_PROGRESS;

    if (lpString != NULL)
        return ERROR_INVALID_PARAMETER;

    if (hServiceStatus == 0)
    {
        DPRINT("hServiceStatus == NULL\n");
        return ERROR_INVALID_HANDLE;
    }

    // FIXME: Validate the status handle
    pService = ScmGetServiceByStatusHandle(hServiceStatus);
    if (pService == NULL)
        return ERROR_INVALID_HANDLE;

    if (bSetBitsOn)
    {
        DPRINT("Old service bits: %08lx\n", pService->dwServiceBits);
        DPRINT("Old global service bits: %08lx\n", g_dwServiceBits);
        pService->dwServiceBits |= dwServiceBits;
        g_dwServiceBits |= dwServiceBits;
        DPRINT("New service bits: %08lx\n", pService->dwServiceBits);
        DPRINT("New global service bits: %08lx\n", g_dwServiceBits);
    }
    else
    {
        DPRINT("Old service bits: %08lx\n", pService->dwServiceBits);
        DPRINT("Old global service bits: %08lx\n", g_dwServiceBits);
        pService->dwServiceBits &= ~dwServiceBits;
        g_dwServiceBits &= ~dwServiceBits;
        DPRINT("New service bits: %08lx\n", pService->dwServiceBits);
        DPRINT("New global service bits: %08lx\n", g_dwServiceBits);
    }

    return ERROR_SUCCESS;
}


/* Function 11 */
DWORD
WINAPI
RChangeServiceConfigW(
    SC_RPC_HANDLE hService,
    DWORD dwServiceType,
    DWORD dwStartType,
    DWORD dwErrorControl,
    LPWSTR lpBinaryPathName,
    LPWSTR lpLoadOrderGroup,
    LPDWORD lpdwTagId,
    LPBYTE lpDependencies,
    DWORD dwDependSize,
    LPWSTR lpServiceStartName,
    LPBYTE lpPassword,
    DWORD dwPwSize,
    LPWSTR lpDisplayName)
{
    DWORD dwError = ERROR_SUCCESS;
    PSERVICE_HANDLE hSvc;
    PSERVICE lpService = NULL;
    HKEY hServiceKey = NULL;
    LPWSTR lpDisplayNameW = NULL;
    LPWSTR lpImagePathW = NULL;
    LPWSTR lpClearTextPassword = NULL;

    DPRINT("RChangeServiceConfigW() called\n");
    DPRINT("dwServiceType = 0x%lx\n", dwServiceType);
    DPRINT("dwStartType = %lu\n", dwStartType);
    DPRINT("dwErrorControl = %lu\n", dwErrorControl);
    DPRINT("lpBinaryPathName = %S\n", lpBinaryPathName);
    DPRINT("lpLoadOrderGroup = %S\n", lpLoadOrderGroup);
    DPRINT("lpServiceStartName = %S\n", lpServiceStartName);
    DPRINT("lpPassword = %p\n", lpPassword);
    DPRINT("dwPwSite = %lu\n", dwPwSize);
    DPRINT("lpDisplayName = %S\n", lpDisplayName);

    if (ScmShutdown)
        return ERROR_SHUTDOWN_IN_PROGRESS;

    hSvc = ScmGetServiceFromHandle(hService);
    if (hSvc == NULL)
    {
        DPRINT1("Invalid service handle\n");
        return ERROR_INVALID_HANDLE;
    }

    if (!RtlAreAllAccessesGranted(hSvc->Handle.DesiredAccess,
                                  SERVICE_CHANGE_CONFIG))
    {
        DPRINT("Insufficient access rights! 0x%lx\n", hSvc->Handle.DesiredAccess);
        return ERROR_ACCESS_DENIED;
    }

    dwError = ScmCheckServiceStartName(lpServiceStartName);
    if (dwError != ERROR_SUCCESS)
        return dwError;

    /* Check for invalid service type value */
    if ((dwServiceType != SERVICE_NO_CHANGE) &&
        (dwServiceType != SERVICE_KERNEL_DRIVER) &&
        (dwServiceType != SERVICE_FILE_SYSTEM_DRIVER) &&
        ((dwServiceType & ~SERVICE_INTERACTIVE_PROCESS) != SERVICE_WIN32_OWN_PROCESS) &&
        ((dwServiceType & ~SERVICE_INTERACTIVE_PROCESS) != SERVICE_WIN32_SHARE_PROCESS))
    {
        return ERROR_INVALID_PARAMETER;
    }

    /* Check for invalid start type value */
    if ((dwStartType != SERVICE_NO_CHANGE) &&
        (dwStartType != SERVICE_BOOT_START) &&
        (dwStartType != SERVICE_SYSTEM_START) &&
        (dwStartType != SERVICE_AUTO_START) &&
        (dwStartType != SERVICE_DEMAND_START) &&
        (dwStartType != SERVICE_DISABLED))
    {
        return ERROR_INVALID_PARAMETER;
    }

    /* Only drivers can be boot start or system start services */
    if ((dwStartType == SERVICE_BOOT_START) ||
        (dwStartType == SERVICE_SYSTEM_START))
    {
        if ((dwServiceType != SERVICE_KERNEL_DRIVER) &&
            (dwServiceType != SERVICE_FILE_SYSTEM_DRIVER))
            return ERROR_INVALID_PARAMETER;
    }

    /* Check for invalid error control value */
    if ((dwErrorControl != SERVICE_NO_CHANGE) &&
        (dwErrorControl != SERVICE_ERROR_IGNORE) &&
        (dwErrorControl != SERVICE_ERROR_NORMAL) &&
        (dwErrorControl != SERVICE_ERROR_SEVERE) &&
        (dwErrorControl != SERVICE_ERROR_CRITICAL))
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (lpdwTagId && (!lpLoadOrderGroup || !*lpLoadOrderGroup))
    {
        return ERROR_INVALID_PARAMETER;
    }

    lpService = hSvc->ServiceEntry;
    if (lpService == NULL)
    {
        DPRINT("lpService == NULL\n");
        return ERROR_INVALID_HANDLE;
    }

    /* Lock the service database exclusively */
    ScmLockDatabaseExclusive();

    if (lpService->bDeleted)
    {
        DPRINT("Service has already been marked for delete\n");
        dwError = ERROR_SERVICE_MARKED_FOR_DELETE;
        goto done;
    }

    /* Open the service key */
    dwError = ScmOpenServiceKey(lpService->szServiceName,
                                KEY_SET_VALUE,
                                &hServiceKey);
    if (dwError != ERROR_SUCCESS)
        goto done;

    /* Write service data to the registry */

    /* Set the display name */
    if (lpDisplayName != NULL && *lpDisplayName != 0)
    {
        RegSetValueExW(hServiceKey,
                       L"DisplayName",
                       0,
                       REG_SZ,
                       (LPBYTE)lpDisplayName,
                       (DWORD)((wcslen(lpDisplayName) + 1) * sizeof(WCHAR)));

        /* Update the display name */
        lpDisplayNameW = HeapAlloc(GetProcessHeap(),
                                   HEAP_ZERO_MEMORY,
                                   (wcslen(lpDisplayName) + 1) * sizeof(WCHAR));
        if (lpDisplayNameW == NULL)
        {
            dwError = ERROR_NOT_ENOUGH_MEMORY;
            goto done;
        }

        wcscpy(lpDisplayNameW, lpDisplayName);
        if (lpService->lpDisplayName != lpService->lpServiceName)
            HeapFree(GetProcessHeap(), 0, lpService->lpDisplayName);

        lpService->lpDisplayName = lpDisplayNameW;
    }

    if (dwServiceType != SERVICE_NO_CHANGE)
    {
        /* Set the service type */
        dwError = RegSetValueExW(hServiceKey,
                                 L"Type",
                                 0,
                                 REG_DWORD,
                                 (LPBYTE)&dwServiceType,
                                 sizeof(DWORD));
        if (dwError != ERROR_SUCCESS)
            goto done;

        lpService->Status.dwServiceType = dwServiceType;
    }

    if (dwStartType != SERVICE_NO_CHANGE)
    {
        /* Set the start value */
        dwError = RegSetValueExW(hServiceKey,
                                 L"Start",
                                 0,
                                 REG_DWORD,
                                 (LPBYTE)&dwStartType,
                                 sizeof(DWORD));
        if (dwError != ERROR_SUCCESS)
            goto done;

        lpService->dwStartType = dwStartType;
    }

    if (dwErrorControl != SERVICE_NO_CHANGE)
    {
        /* Set the error control value */
        dwError = RegSetValueExW(hServiceKey,
                                 L"ErrorControl",
                                 0,
                                 REG_DWORD,
                                 (LPBYTE)&dwErrorControl,
                                 sizeof(DWORD));
        if (dwError != ERROR_SUCCESS)
            goto done;

        lpService->dwErrorControl = dwErrorControl;
    }

    if (lpBinaryPathName != NULL && *lpBinaryPathName != 0)
    {
        /* Set the image path */
        lpImagePathW = lpBinaryPathName;

        if (lpService->Status.dwServiceType & SERVICE_DRIVER)
        {
            dwError = ScmCanonDriverImagePath(lpService->dwStartType,
                                              lpBinaryPathName,
                                              &lpImagePathW);

            if (dwError != ERROR_SUCCESS)
                goto done;
        }

        dwError = RegSetValueExW(hServiceKey,
                                 L"ImagePath",
                                 0,
                                 REG_EXPAND_SZ,
                                 (LPBYTE)lpImagePathW,
                                 (DWORD)((wcslen(lpImagePathW) + 1) * sizeof(WCHAR)));

        if (lpImagePathW != lpBinaryPathName)
            HeapFree(GetProcessHeap(), 0, lpImagePathW);

        if (dwError != ERROR_SUCCESS)
            goto done;
    }

    /* Set the group name */
    if (lpLoadOrderGroup != NULL && *lpLoadOrderGroup != 0)
    {
        dwError = RegSetValueExW(hServiceKey,
                                 L"Group",
                                 0,
                                 REG_SZ,
                                 (LPBYTE)lpLoadOrderGroup,
                                 (DWORD)((wcslen(lpLoadOrderGroup) + 1) * sizeof(WCHAR)));
        if (dwError != ERROR_SUCCESS)
            goto done;

        dwError = ScmSetServiceGroup(lpService,
                                     lpLoadOrderGroup);
        if (dwError != ERROR_SUCCESS)
            goto done;
    }

    /* Set the tag */
    if (lpdwTagId != NULL)
    {
        dwError = ScmAssignNewTag(lpService);
        if (dwError != ERROR_SUCCESS)
            goto done;

        dwError = RegSetValueExW(hServiceKey,
                                 L"Tag",
                                 0,
                                 REG_DWORD,
                                 (LPBYTE)&lpService->dwTag,
                                 sizeof(DWORD));
        if (dwError != ERROR_SUCCESS)
            goto done;

        *lpdwTagId = lpService->dwTag;
    }

    /* Write dependencies */
    if (lpDependencies != NULL && *lpDependencies != 0)
    {
        dwError = ScmWriteDependencies(hServiceKey,
                                       (LPWSTR)lpDependencies,
                                       dwDependSize);
        if (dwError != ERROR_SUCCESS)
            goto done;
    }

    /* Start name and password are only used by Win32 services */
    if (lpService->Status.dwServiceType & SERVICE_WIN32)
    {
        /* Write service start name */
        if (lpServiceStartName != NULL && *lpServiceStartName != 0)
        {
            dwError = RegSetValueExW(hServiceKey,
                                     L"ObjectName",
                                     0,
                                     REG_SZ,
                                     (LPBYTE)lpServiceStartName,
                                     (DWORD)((wcslen(lpServiceStartName) + 1) * sizeof(WCHAR)));
            if (dwError != ERROR_SUCCESS)
                goto done;
        }

        if (lpPassword != NULL)
        {
            if (*(LPWSTR)lpPassword != 0)
            {
                /* Decrypt the password */
                dwError = ScmDecryptPassword(hService,
                                             lpPassword,
                                             dwPwSize,
                                             &lpClearTextPassword);
                if (dwError != ERROR_SUCCESS)
                {
                    DPRINT1("ScmDecryptPassword failed (Error %lu)\n", dwError);
                    goto done;
                }
                DPRINT("Clear text password: %S\n", lpClearTextPassword);

                /* Write the password */
                dwError = ScmSetServicePassword(lpService->szServiceName,
                                                lpClearTextPassword);
                if (dwError != ERROR_SUCCESS)
                {
                    DPRINT1("ScmSetServicePassword failed (Error %lu)\n", dwError);
                    goto done;
                }
            }
            else
            {
                /* Delete the password */
                dwError = ScmSetServicePassword(lpService->szServiceName,
                                                NULL);
                if (dwError == ERROR_FILE_NOT_FOUND)
                    dwError = ERROR_SUCCESS;

                if (dwError != ERROR_SUCCESS)
                {
                    DPRINT1("ScmSetServicePassword failed (Error %lu)\n", dwError);
                    goto done;
                }
            }
        }
    }

done:
    if (lpClearTextPassword != NULL)
    {
        /* Wipe and release the password buffer */
        SecureZeroMemory(lpClearTextPassword,
                         (wcslen(lpClearTextPassword) + 1) * sizeof(WCHAR));
        HeapFree(GetProcessHeap(), 0, lpClearTextPassword);
    }

    if (hServiceKey != NULL)
        RegCloseKey(hServiceKey);

    /* Unlock the service database */
    ScmUnlockDatabase();

    DPRINT("RChangeServiceConfigW() done (Error %lu)\n", dwError);

    return dwError;
}


/* Function 12 */
DWORD
WINAPI
RCreateServiceW(
    SC_RPC_HANDLE hSCManager,
    LPCWSTR lpServiceName,
    LPCWSTR lpDisplayName,
    DWORD dwDesiredAccess,
    DWORD dwServiceType,
    DWORD dwStartType,
    DWORD dwErrorControl,
    LPCWSTR lpBinaryPathName,
    LPCWSTR lpLoadOrderGroup,
    LPDWORD lpdwTagId,
    LPBYTE lpDependencies,
    DWORD dwDependSize,
    LPCWSTR lpServiceStartName,
    LPBYTE lpPassword,
    DWORD dwPwSize,
    LPSC_RPC_HANDLE lpServiceHandle)
{
    PMANAGER_HANDLE hManager;
    DWORD dwError = ERROR_SUCCESS;
    PSERVICE lpService = NULL;
    SC_HANDLE hServiceHandle = NULL;
    LPWSTR lpImagePath = NULL;
    LPWSTR lpClearTextPassword = NULL;
    HKEY hServiceKey = NULL;
    LPWSTR lpObjectName;

    DPRINT("RCreateServiceW() called\n");
    DPRINT("lpServiceName = %S\n", lpServiceName);
    DPRINT("lpDisplayName = %S\n", lpDisplayName);
    DPRINT("dwDesiredAccess = %lx\n", dwDesiredAccess);
    DPRINT("dwServiceType = 0x%lx\n", dwServiceType);
    DPRINT("dwStartType = %lu\n", dwStartType);
    DPRINT("dwErrorControl = %lu\n", dwErrorControl);
    DPRINT("lpBinaryPathName = %S\n", lpBinaryPathName);
    DPRINT("lpLoadOrderGroup = %S\n", lpLoadOrderGroup);
    DPRINT("lpdwTagId = %p\n", lpdwTagId);

    if (ScmShutdown)
        return ERROR_SHUTDOWN_IN_PROGRESS;

    hManager = ScmGetServiceManagerFromHandle(hSCManager);
    if (hManager == NULL)
    {
        DPRINT1("Invalid service manager handle\n");
        return ERROR_INVALID_HANDLE;
    }

    /* Check access rights */
    if (!RtlAreAllAccessesGranted(hManager->Handle.DesiredAccess,
                                  SC_MANAGER_CREATE_SERVICE))
    {
        DPRINT("Insufficient access rights! 0x%lx\n",
               hManager->Handle.DesiredAccess);
        return ERROR_ACCESS_DENIED;
    }

    if (*lpServiceName == 0)
        return ERROR_INVALID_NAME;

    if (*lpBinaryPathName == 0)
        return ERROR_INVALID_PARAMETER;

    /* Check for invalid service type value */
    if ((dwServiceType != SERVICE_KERNEL_DRIVER) &&
        (dwServiceType != SERVICE_FILE_SYSTEM_DRIVER) &&
        ((dwServiceType & ~SERVICE_INTERACTIVE_PROCESS) != SERVICE_WIN32_OWN_PROCESS) &&
        ((dwServiceType & ~SERVICE_INTERACTIVE_PROCESS) != SERVICE_WIN32_SHARE_PROCESS))
    {
        return ERROR_INVALID_PARAMETER;
    }

    /* Check for invalid start type value */
    if ((dwStartType != SERVICE_BOOT_START) &&
        (dwStartType != SERVICE_SYSTEM_START) &&
        (dwStartType != SERVICE_AUTO_START) &&
        (dwStartType != SERVICE_DEMAND_START) &&
        (dwStartType != SERVICE_DISABLED))
    {
        return ERROR_INVALID_PARAMETER;
    }

    /* Only drivers can be boot start or system start services */
    if ((dwStartType == SERVICE_BOOT_START) ||
        (dwStartType == SERVICE_SYSTEM_START))
    {
        if ((dwServiceType != SERVICE_KERNEL_DRIVER) &&
            (dwServiceType != SERVICE_FILE_SYSTEM_DRIVER))
        {
            return ERROR_INVALID_PARAMETER;
        }
    }

    /* Check for invalid error control value */
    if ((dwErrorControl != SERVICE_ERROR_IGNORE) &&
        (dwErrorControl != SERVICE_ERROR_NORMAL) &&
        (dwErrorControl != SERVICE_ERROR_SEVERE) &&
        (dwErrorControl != SERVICE_ERROR_CRITICAL))
    {
        return ERROR_INVALID_PARAMETER;
    }

    dwError = ScmCheckServiceStartName(lpServiceStartName);
    if (dwError != ERROR_SUCCESS)
        return dwError;

    if ((dwServiceType == (SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS)) &&
        (lpServiceStartName))
    {
        /* We allow LocalSystem to run interactive. */
        if (_wcsicmp(lpServiceStartName, L"LocalSystem"))
        {
            return ERROR_INVALID_PARAMETER;
        }
    }

    if (lpdwTagId && (!lpLoadOrderGroup || !*lpLoadOrderGroup))
    {
        return ERROR_INVALID_PARAMETER;
    }

    /* Lock the service database exclusively */
    ScmLockDatabaseExclusive();

    lpService = ScmGetServiceEntryByName(lpServiceName);
    if (lpService)
    {
        /* Unlock the service database */
        ScmUnlockDatabase();

        /* Check if it is marked for deletion */
        if (lpService->bDeleted)
            return ERROR_SERVICE_MARKED_FOR_DELETE;

        /* Return service-exists error */
        return ERROR_SERVICE_EXISTS;
    }

    if (lpDisplayName != NULL &&
        ScmGetServiceEntryByDisplayName(lpDisplayName) != NULL)
    {
        /* Unlock the service database */
        ScmUnlockDatabase();

        return ERROR_DUPLICATE_SERVICE_NAME;
    }

    if (dwServiceType & SERVICE_DRIVER)
    {
        dwError = ScmCanonDriverImagePath(dwStartType,
                                          lpBinaryPathName,
                                          &lpImagePath);
        if (dwError != ERROR_SUCCESS)
            goto done;
    }
    else
    {
        if (dwStartType == SERVICE_BOOT_START ||
            dwStartType == SERVICE_SYSTEM_START)
        {
            /* Unlock the service database */
            ScmUnlockDatabase();

            return ERROR_INVALID_PARAMETER;
        }
    }

    /* Allocate a new service entry */
    dwError = ScmCreateNewServiceRecord(lpServiceName,
                                        &lpService,
                                        dwServiceType,
                                        dwStartType);
    if (dwError != ERROR_SUCCESS)
        goto done;

    /* Fill the new service entry */
    lpService->dwErrorControl = dwErrorControl;

    /* Fill the display name */
    if (lpDisplayName != NULL &&
        *lpDisplayName != 0 &&
        _wcsicmp(lpService->lpDisplayName, lpDisplayName) != 0)
    {
        lpService->lpDisplayName = HeapAlloc(GetProcessHeap(),
                                             HEAP_ZERO_MEMORY,
                                             (wcslen(lpDisplayName) + 1) * sizeof(WCHAR));
        if (lpService->lpDisplayName == NULL)
        {
            dwError = ERROR_NOT_ENOUGH_MEMORY;
            goto done;
        }
        wcscpy(lpService->lpDisplayName, lpDisplayName);
    }

    /* Assign the service to a group */
    if (lpLoadOrderGroup != NULL && *lpLoadOrderGroup != 0)
    {
        dwError = ScmSetServiceGroup(lpService,
                                     lpLoadOrderGroup);
        if (dwError != ERROR_SUCCESS)
            goto done;
    }

    /* Assign a new tag */
    if (lpdwTagId != NULL)
    {
        dwError = ScmAssignNewTag(lpService);
        if (dwError != ERROR_SUCCESS)
            goto done;
    }

    /* Assign the default security descriptor */
    if (dwServiceType & SERVICE_WIN32)
    {
        dwError = ScmCreateDefaultServiceSD(&lpService->pSecurityDescriptor);
        if (dwError != ERROR_SUCCESS)
            goto done;
    }

    /* Write service data to the registry */
    /* Create the service key */
    dwError = ScmCreateServiceKey(lpServiceName,
                                  KEY_WRITE,
                                  &hServiceKey);
    if (dwError != ERROR_SUCCESS)
        goto done;

    /* Set the display name */
    if (lpDisplayName != NULL && *lpDisplayName != 0)
    {
        RegSetValueExW(hServiceKey,
                       L"DisplayName",
                       0,
                       REG_SZ,
                       (LPBYTE)lpDisplayName,
                       (DWORD)((wcslen(lpDisplayName) + 1) * sizeof(WCHAR)));
    }

    /* Set the service type */
    dwError = RegSetValueExW(hServiceKey,
                             L"Type",
                             0,
                             REG_DWORD,
                             (LPBYTE)&dwServiceType,
                             sizeof(DWORD));
    if (dwError != ERROR_SUCCESS)
        goto done;

    /* Set the start value */
    dwError = RegSetValueExW(hServiceKey,
                             L"Start",
                             0,
                             REG_DWORD,
                             (LPBYTE)&dwStartType,
                             sizeof(DWORD));
    if (dwError != ERROR_SUCCESS)
        goto done;

    /* Set the error control value */
    dwError = RegSetValueExW(hServiceKey,
                             L"ErrorControl",
                             0,
                             REG_DWORD,
                             (LPBYTE)&dwErrorControl,
                             sizeof(DWORD));
    if (dwError != ERROR_SUCCESS)
        goto done;

    /* Set the image path */
    if (dwServiceType & SERVICE_WIN32)
    {
        dwError = RegSetValueExW(hServiceKey,
                                 L"ImagePath",
                                 0,
                                 REG_EXPAND_SZ,
                                 (LPBYTE)lpBinaryPathName,
                                 (DWORD)((wcslen(lpBinaryPathName) + 1) * sizeof(WCHAR)));
        if (dwError != ERROR_SUCCESS)
            goto done;
    }
    else if (dwServiceType & SERVICE_DRIVER)
    {
        dwError = RegSetValueExW(hServiceKey,
                                 L"ImagePath",
                                 0,
                                 REG_EXPAND_SZ,
                                 (LPBYTE)lpImagePath,
                                 (DWORD)((wcslen(lpImagePath) + 1) * sizeof(WCHAR)));
        if (dwError != ERROR_SUCCESS)
            goto done;
    }

    /* Set the group name */
    if (lpLoadOrderGroup != NULL && *lpLoadOrderGroup != 0)
    {
        dwError = RegSetValueExW(hServiceKey,
                                 L"Group",
                                 0,
                                 REG_SZ,
                                 (LPBYTE)lpLoadOrderGroup,
                                 (DWORD)((wcslen(lpLoadOrderGroup) + 1) * sizeof(WCHAR)));
        if (dwError != ERROR_SUCCESS)
            goto done;
    }

    /* Set the service tag */
    if (lpdwTagId != NULL)
    {
        dwError = RegSetValueExW(hServiceKey,
                                 L"Tag",
                                 0,
                                 REG_DWORD,
                                 (LPBYTE)&lpService->dwTag,
                                 sizeof(DWORD));
        if (dwError != ERROR_SUCCESS)
            goto done;
    }

    /* Write dependencies */
    if (lpDependencies != NULL && *lpDependencies != 0)
    {
        dwError = ScmWriteDependencies(hServiceKey,
                                       (LPCWSTR)lpDependencies,
                                       dwDependSize);
        if (dwError != ERROR_SUCCESS)
            goto done;
    }

    /* Start name and password are only used by Win32 services */
    if (dwServiceType & SERVICE_WIN32)
    {
        /* Write service start name */
        lpObjectName = (lpServiceStartName != NULL) ? (LPWSTR)lpServiceStartName : L"LocalSystem";
        dwError = RegSetValueExW(hServiceKey,
                                 L"ObjectName",
                                 0,
                                 REG_SZ,
                                 (LPBYTE)lpObjectName,
                                 (DWORD)((wcslen(lpObjectName) + 1) * sizeof(WCHAR)));
        if (dwError != ERROR_SUCCESS)
            goto done;

        if (lpPassword != NULL && *(LPWSTR)lpPassword != 0)
        {
            /* Decrypt the password */
            dwError = ScmDecryptPassword(hSCManager,
                                         lpPassword,
                                         dwPwSize,
                                         &lpClearTextPassword);
            if (dwError != ERROR_SUCCESS)
                goto done;

            /* Write the password */
            dwError = ScmSetServicePassword(lpServiceName,
                                            lpClearTextPassword);
            if (dwError != ERROR_SUCCESS)
                goto done;
        }

        /* Write the security descriptor */
        dwError = ScmWriteSecurityDescriptor(hServiceKey,
                                             lpService->pSecurityDescriptor);
        if (dwError != ERROR_SUCCESS)
            goto done;
    }

    dwError = ScmCreateServiceHandle(lpService,
                                     &hServiceHandle);
    if (dwError != ERROR_SUCCESS)
        goto done;

    dwError = ScmCheckAccess(hServiceHandle,
                             dwDesiredAccess);
    if (dwError != ERROR_SUCCESS)
        goto done;

    ScmReferenceService(lpService);

    /* Get the service tag (if Win32) */
    ScmGenerateServiceTag(lpService);

    DPRINT("CreateService - lpService->RefCount %u\n", lpService->RefCount);

done:
    /* Unlock the service database */
    ScmUnlockDatabase();

    if (hServiceKey != NULL)
        RegCloseKey(hServiceKey);

    if (lpClearTextPassword != NULL)
    {
        /* Wipe and release the password buffer */
        SecureZeroMemory(lpClearTextPassword,
                         (wcslen(lpClearTextPassword) + 1) * sizeof(WCHAR));
        HeapFree(GetProcessHeap(), 0, lpClearTextPassword);
    }

    if (dwError == ERROR_SUCCESS)
    {
        DPRINT("hService %p\n", hServiceHandle);
        *lpServiceHandle = (SC_RPC_HANDLE)hServiceHandle;

        if (lpdwTagId != NULL)
            *lpdwTagId = lpService->dwTag;
    }
    else
    {
        if (lpService != NULL &&
            lpService->lpServiceName != NULL)
        {
            /* Release the display name buffer */
            HeapFree(GetProcessHeap(), 0, lpService->lpDisplayName);
        }

        if (hServiceHandle)
        {
            /* Remove the service handle */
            HeapFree(GetProcessHeap(), 0, hServiceHandle);
        }

        if (lpService != NULL)
        {
            /* FIXME: remove the service entry */
        }
    }

    if (lpImagePath != NULL)
        HeapFree(GetProcessHeap(), 0, lpImagePath);

    DPRINT("RCreateServiceW() done (Error %lu)\n", dwError);

    return dwError;
}


/* Function 13 */
DWORD
WINAPI
REnumDependentServicesW(
    SC_RPC_HANDLE hService,
    DWORD dwServiceState,
    LPBYTE lpServices,
    DWORD cbBufSize,
    LPBOUNDED_DWORD_256K pcbBytesNeeded,
    LPBOUNDED_DWORD_256K lpServicesReturned)
{
    DWORD dwError = ERROR_SUCCESS;
    DWORD dwServicesReturned = 0;
    DWORD dwServiceCount;
    HKEY hServicesKey = NULL;
    PSERVICE_HANDLE hSvc;
    PSERVICE lpService = NULL;
    PSERVICE *lpServicesArray = NULL;
    LPENUM_SERVICE_STATUSW lpServicesPtr = NULL;
    LPWSTR lpStr;

    *pcbBytesNeeded = 0;
    *lpServicesReturned = 0;

    DPRINT("REnumDependentServicesW() called\n");

    hSvc = ScmGetServiceFromHandle(hService);
    if (hSvc == NULL)
    {
        DPRINT1("Invalid service handle\n");
        return ERROR_INVALID_HANDLE;
    }

    lpService = hSvc->ServiceEntry;

    /* A service handle needs SERVICE_ENUMERATE_DEPENDENTS (SC_MANAGER_ENUMERATE_SERVICE is a manager right) */
    if (!RtlAreAllAccessesGranted(hSvc->Handle.DesiredAccess,
                                  SERVICE_ENUMERATE_DEPENDENTS))
    {
        DPRINT("Insufficient access rights! 0x%lx\n",
               hSvc->Handle.DesiredAccess);
        return ERROR_ACCESS_DENIED;
    }

    /* Open the Services Reg key */
    dwError = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"System\\CurrentControlSet\\Services",
                            0,
                            KEY_READ,
                            &hServicesKey);
    if (dwError != ERROR_SUCCESS)
        return dwError;

    /* First determine the bytes needed and get the number of dependent services */
    dwError = Int_EnumDependentServicesW(hServicesKey,
                                         lpService,
                                         dwServiceState,
                                         NULL,
                                         pcbBytesNeeded,
                                         &dwServicesReturned);
    if (dwError != ERROR_SUCCESS)
        goto Done;

    /* If buffer size is less than the bytes needed or pointer is null */
    if ((!lpServices) || (cbBufSize < *pcbBytesNeeded))
    {
        dwError = ERROR_MORE_DATA;
        goto Done;
    }

    /* Allocate memory for array of service pointers */
    lpServicesArray = HeapAlloc(GetProcessHeap(),
                                HEAP_ZERO_MEMORY,
                                (dwServicesReturned + 1) * sizeof(PSERVICE));
    if (!lpServicesArray)
    {
        DPRINT1("Could not allocate buffer\n");
        dwError = ERROR_NOT_ENOUGH_MEMORY;
        goto Done;
    }

    dwServicesReturned = 0;
    *pcbBytesNeeded = 0;

    dwError = Int_EnumDependentServicesW(hServicesKey,
                                         lpService,
                                         dwServiceState,
                                         lpServicesArray,
                                         pcbBytesNeeded,
                                         &dwServicesReturned);
    if (dwError != ERROR_SUCCESS)
    {
        goto Done;
    }

    lpServicesPtr = (LPENUM_SERVICE_STATUSW)lpServices;
    lpStr = (LPWSTR)(lpServices + (dwServicesReturned * sizeof(ENUM_SERVICE_STATUSW)));

    /* Copy EnumDepenedentService to Buffer */
    for (dwServiceCount = 0; dwServiceCount < dwServicesReturned; dwServiceCount++)
    {
        lpService = lpServicesArray[dwServiceCount];

        /* Copy status info */
        memcpy(&lpServicesPtr->ServiceStatus,
               &lpService->Status,
               sizeof(SERVICE_STATUS));

        /* Copy display name */
        wcscpy(lpStr, lpService->lpDisplayName);
        lpServicesPtr->lpDisplayName = (LPWSTR)((ULONG_PTR)lpStr - (ULONG_PTR)lpServices);
        lpStr += (wcslen(lpService->lpDisplayName) + 1);

        /* Copy service name */
        wcscpy(lpStr, lpService->lpServiceName);
        lpServicesPtr->lpServiceName = (LPWSTR)((ULONG_PTR)lpStr - (ULONG_PTR)lpServices);
        lpStr += (wcslen(lpService->lpServiceName) + 1);

        lpServicesPtr++;
    }

    *lpServicesReturned = dwServicesReturned;

    /* Nothing is left to be fetched */
    *pcbBytesNeeded = 0;

Done:
    if (lpServicesArray != NULL)
        HeapFree(GetProcessHeap(), 0, lpServicesArray);

    RegCloseKey(hServicesKey);

    DPRINT("REnumDependentServicesW() done (Error %lu)\n", dwError);

    return dwError;
}


/* Function 14 */
DWORD
WINAPI
REnumServicesStatusW(
    SC_RPC_HANDLE hSCManager,
    DWORD dwServiceType,
    DWORD dwServiceState,
    LPBYTE lpBuffer,
    DWORD dwBufSize,
    LPBOUNDED_DWORD_256K pcbBytesNeeded,
    LPBOUNDED_DWORD_256K lpServicesReturned,
    LPBOUNDED_DWORD_256K lpResumeHandle)
{
    /* Enumerate all the services, not regarding of their group */
    return REnumServiceGroupW(hSCManager,
                              dwServiceType,
                              dwServiceState,
                              lpBuffer,
                              dwBufSize,
                              pcbBytesNeeded,
                              lpServicesReturned,
                              lpResumeHandle,
                              NULL);
}


/* Function 15 */
DWORD
WINAPI
ROpenSCManagerW(
    LPWSTR lpMachineName,
    LPWSTR lpDatabaseName,
    DWORD dwDesiredAccess,
    LPSC_RPC_HANDLE lpScHandle)
{
    DWORD dwError;
    SC_HANDLE hHandle;

    DPRINT("ROpenSCManagerW() called\n");
    DPRINT("lpMachineName = %p\n", lpMachineName);
    DPRINT("lpMachineName: %S\n", lpMachineName);
    DPRINT("lpDataBaseName = %p\n", lpDatabaseName);
    DPRINT("lpDataBaseName: %S\n", lpDatabaseName);
    DPRINT("dwDesiredAccess = %x\n", dwDesiredAccess);

    if (ScmShutdown)
        return ERROR_SHUTDOWN_IN_PROGRESS;

    if (!lpScHandle)
        return ERROR_INVALID_PARAMETER;

    dwError = ScmCreateManagerHandle(lpDatabaseName,
                                     &hHandle);
    if (dwError != ERROR_SUCCESS)
    {
        DPRINT("ScmCreateManagerHandle() failed (Error %lu)\n", dwError);
        return dwError;
    }

    /* Check the desired access */
    dwError = ScmCheckAccess(hHandle,
                             dwDesiredAccess | SC_MANAGER_CONNECT);
    if (dwError != ERROR_SUCCESS)
    {
        DPRINT("ScmCheckAccess() failed (Error %lu)\n", dwError);
        HeapFree(GetProcessHeap(), 0, hHandle);
        return dwError;
    }

    *lpScHandle = (SC_RPC_HANDLE)hHandle;
    DPRINT("*hScm = %p\n", *lpScHandle);

    DPRINT("ROpenSCManagerW() done\n");

    return ERROR_SUCCESS;
}


/* Function 16 */
DWORD
WINAPI
ROpenServiceW(
    SC_RPC_HANDLE hSCManager,
    LPWSTR lpServiceName,
    DWORD dwDesiredAccess,
    LPSC_RPC_HANDLE lpServiceHandle)
{
    PSERVICE lpService;
    PMANAGER_HANDLE hManager;
    SC_HANDLE hHandle;
    DWORD dwError = ERROR_SUCCESS;

    DPRINT("ROpenServiceW() called\n");
    DPRINT("hSCManager = %p\n", hSCManager);
    DPRINT("lpServiceName = %p\n", lpServiceName);
    DPRINT("lpServiceName: %S\n", lpServiceName);
    DPRINT("dwDesiredAccess = %x\n", dwDesiredAccess);

    if (ScmShutdown)
        return ERROR_SHUTDOWN_IN_PROGRESS;

    hManager = ScmGetServiceManagerFromHandle(hSCManager);
    if (hManager == NULL)
    {
        DPRINT1("Invalid service manager handle\n");
        return ERROR_INVALID_HANDLE;
    }

    if (!lpServiceHandle)
        return ERROR_INVALID_PARAMETER;

    if (!lpServiceName)
        return ERROR_INVALID_ADDRESS;

    /* Lock the service database exclusive */
    ScmLockDatabaseExclusive();

    /* Get service database entry */
    lpService = ScmGetServiceEntryByName(lpServiceName);
    if (lpService == NULL)
    {
        DPRINT("Could not find service\n");
        dwError = ERROR_SERVICE_DOES_NOT_EXIST;
        goto Done;
    }

    /* Create a service handle */
    dwError = ScmCreateServiceHandle(lpService,
                                     &hHandle);
    if (dwError != ERROR_SUCCESS)
    {
        DPRINT("ScmCreateServiceHandle() failed (Error %lu)\n", dwError);
        goto Done;
    }

    /* Check the desired access */
    dwError = ScmCheckAccess(hHandle,
                             dwDesiredAccess);
    if (dwError != ERROR_SUCCESS)
    {
        DPRINT("ScmCheckAccess() failed (Error %lu)\n", dwError);
        HeapFree(GetProcessHeap(), 0, hHandle);
        goto Done;
    }

    ScmReferenceService(lpService);
    DPRINT("OpenService %S - lpService->RefCount %u\n", lpService->lpServiceName, lpService->RefCount);

    *lpServiceHandle = (SC_RPC_HANDLE)hHandle;
    DPRINT("*hService = %p\n", *lpServiceHandle);

Done:
    /* Unlock the service database */
    ScmUnlockDatabase();

    DPRINT("ROpenServiceW() done\n");

    return dwError;
}


/* Function 17 */
DWORD
WINAPI
RQueryServiceConfigW(
    SC_RPC_HANDLE hService,
    LPBYTE lpBuf, //LPQUERY_SERVICE_CONFIGW lpServiceConfig,
    DWORD cbBufSize,
    LPBOUNDED_DWORD_8K pcbBytesNeeded)
{
    LPQUERY_SERVICE_CONFIGW lpServiceConfig = (LPQUERY_SERVICE_CONFIGW)lpBuf;
    DWORD dwError = ERROR_SUCCESS;
    PSERVICE_HANDLE hSvc;
    PSERVICE lpService = NULL;
    HKEY hServiceKey = NULL;
    LPWSTR lpImagePath = NULL;
    LPWSTR lpServiceStartName = NULL;
    LPWSTR lpDependencies = NULL;
    DWORD dwDependenciesLength = 0;
    DWORD dwRequiredSize;
    LPWSTR lpStr;

    DPRINT("RQueryServiceConfigW() called\n");

    if (ScmShutdown)
        return ERROR_SHUTDOWN_IN_PROGRESS;

    hSvc = ScmGetServiceFromHandle(hService);
    if (hSvc == NULL)
    {
        DPRINT1("Invalid service handle\n");
        return ERROR_INVALID_HANDLE;
    }

    if (!RtlAreAllAccessesGranted(hSvc->Handle.DesiredAccess,
                                  SERVICE_QUERY_CONFIG))
    {
        DPRINT("Insufficient access rights! 0x%lx\n", hSvc->Handle.DesiredAccess);
        return ERROR_ACCESS_DENIED;
    }

    lpService = hSvc->ServiceEntry;
    if (lpService == NULL)
    {
        DPRINT("lpService == NULL\n");
        return ERROR_INVALID_HANDLE;
    }

    /* Lock the service database shared */
    ScmLockDatabaseShared();

    dwError = ScmOpenServiceKey(lpService->lpServiceName,
                                KEY_READ,
                                &hServiceKey);
    if (dwError != ERROR_SUCCESS)
        goto Done;

    /* Read the image path */
    dwError = ScmReadString(hServiceKey,
                            L"ImagePath",
                            &lpImagePath);
    if (dwError != ERROR_SUCCESS)
        goto Done;

    /* Read the service start name */
    ScmReadString(hServiceKey,
                  L"ObjectName",
                  &lpServiceStartName);

    /* Read the dependencies */
    ScmReadDependencies(hServiceKey,
                        &lpDependencies,
                        &dwDependenciesLength);

    dwRequiredSize = sizeof(QUERY_SERVICE_CONFIGW);

    if (lpImagePath != NULL)
        dwRequiredSize += (DWORD)((wcslen(lpImagePath) + 1) * sizeof(WCHAR));
    else
        dwRequiredSize += 2 * sizeof(WCHAR);

    if ((lpService->lpGroup != NULL) && (lpService->lpGroup->lpGroupName != NULL))
        dwRequiredSize += (DWORD)((wcslen(lpService->lpGroup->lpGroupName) + 1) * sizeof(WCHAR));
    else
        dwRequiredSize += 2 * sizeof(WCHAR);

    if (lpDependencies != NULL)
        dwRequiredSize += dwDependenciesLength * sizeof(WCHAR);
    else
        dwRequiredSize += 2 * sizeof(WCHAR);

    if (lpServiceStartName != NULL)
        dwRequiredSize += (DWORD)((wcslen(lpServiceStartName) + 1) * sizeof(WCHAR));
    else
        dwRequiredSize += 2 * sizeof(WCHAR);

    if (lpService->lpDisplayName != NULL)
        dwRequiredSize += (DWORD)((wcslen(lpService->lpDisplayName) + 1) * sizeof(WCHAR));
    else
        dwRequiredSize += 2 * sizeof(WCHAR);

    if (lpServiceConfig == NULL || cbBufSize < dwRequiredSize)
    {
        dwError = ERROR_INSUFFICIENT_BUFFER;
    }
    else
    {
        lpServiceConfig->dwServiceType = lpService->Status.dwServiceType;
        lpServiceConfig->dwStartType = lpService->dwStartType;
        lpServiceConfig->dwErrorControl = lpService->dwErrorControl;
        lpServiceConfig->dwTagId = lpService->dwTag;

        lpStr = (LPWSTR)(lpServiceConfig + 1);

        /* Append the image path */
        if (lpImagePath != NULL)
        {
            wcscpy(lpStr, lpImagePath);
        }
        else
        {
            *lpStr = 0;
        }

        lpServiceConfig->lpBinaryPathName = (LPWSTR)((ULONG_PTR)lpStr - (ULONG_PTR)lpServiceConfig);
        lpStr += (wcslen(lpStr) + 1);

        /* Append the group name */
        if ((lpService->lpGroup != NULL) && (lpService->lpGroup->lpGroupName != NULL))
        {
            wcscpy(lpStr, lpService->lpGroup->lpGroupName);
        }
        else
        {
            *lpStr = 0;
        }

        lpServiceConfig->lpLoadOrderGroup = (LPWSTR)((ULONG_PTR)lpStr - (ULONG_PTR)lpServiceConfig);
        lpStr += (wcslen(lpStr) + 1);

        /* Append Dependencies */
        if (lpDependencies != NULL)
        {
            memcpy(lpStr,
                   lpDependencies,
                   dwDependenciesLength * sizeof(WCHAR));
        }
        else
        {
            *lpStr = 0;
        }

        lpServiceConfig->lpDependencies = (LPWSTR)((ULONG_PTR)lpStr - (ULONG_PTR)lpServiceConfig);
        if (lpDependencies != NULL)
            lpStr += dwDependenciesLength;
        else
            lpStr += (wcslen(lpStr) + 1);

        /* Append the service start name */
        if (lpServiceStartName != NULL)
        {
            wcscpy(lpStr, lpServiceStartName);
        }
        else
        {
            *lpStr = 0;
        }

        lpServiceConfig->lpServiceStartName = (LPWSTR)((ULONG_PTR)lpStr - (ULONG_PTR)lpServiceConfig);
        lpStr += (wcslen(lpStr) + 1);

        /* Append the display name */
        if (lpService->lpDisplayName != NULL)
        {
            wcscpy(lpStr, lpService->lpDisplayName);
        }
        else
        {
            *lpStr = 0;
        }

        lpServiceConfig->lpDisplayName = (LPWSTR)((ULONG_PTR)lpStr - (ULONG_PTR)lpServiceConfig);
    }

    if (pcbBytesNeeded != NULL)
        *pcbBytesNeeded = dwRequiredSize;

Done:
    /* Unlock the service database */
    ScmUnlockDatabase();

    if (lpImagePath != NULL)
        HeapFree(GetProcessHeap(), 0, lpImagePath);

    if (lpServiceStartName != NULL)
        HeapFree(GetProcessHeap(), 0, lpServiceStartName);

    if (lpDependencies != NULL)
        HeapFree(GetProcessHeap(), 0, lpDependencies);

    if (hServiceKey != NULL)
        RegCloseKey(hServiceKey);

    DPRINT("RQueryServiceConfigW() done\n");

    return dwError;
}


/* Function 18 */
DWORD
WINAPI
RQueryServiceLockStatusW(
    SC_RPC_HANDLE hSCManager,
    LPBYTE lpBuf, // LPQUERY_SERVICE_LOCK_STATUSW lpLockStatus,
    DWORD cbBufSize,
    LPBOUNDED_DWORD_4K pcbBytesNeeded)
{
    LPQUERY_SERVICE_LOCK_STATUSW lpLockStatus = (LPQUERY_SERVICE_LOCK_STATUSW)lpBuf;
    PMANAGER_HANDLE hMgr;
    DWORD dwRequiredSize, dwError;

    if (!lpLockStatus || !pcbBytesNeeded)
        return ERROR_INVALID_PARAMETER;

    hMgr = ScmGetServiceManagerFromHandle(hSCManager);
    if (hMgr == NULL)
    {
        DPRINT1("Invalid service manager handle\n");
        return ERROR_INVALID_HANDLE;
    }

    if (!RtlAreAllAccessesGranted(hMgr->Handle.DesiredAccess,
                                  SC_MANAGER_QUERY_LOCK_STATUS))
    {
        DPRINT("Insufficient access rights! 0x%lx\n", hMgr->Handle.DesiredAccess);
        return ERROR_ACCESS_DENIED;
    }

    /* The owner's name is part of what is returned, so the size is worked out with it */
    dwError = ScmQueryServiceLockStatusW(lpLockStatus, cbBufSize, &dwRequiredSize);
    *pcbBytesNeeded = dwRequiredSize;
    return dwError;
}


/* Function 19 */
DWORD
WINAPI
RStartServiceW(
    SC_RPC_HANDLE hService,
    DWORD argc,
    LPSTRING_PTRSW argv)
{
    DWORD dwError = ERROR_SUCCESS;
    PSERVICE_HANDLE hSvc;
    PSERVICE lpService = NULL;

#ifndef NDEBUG
    DWORD i;

    DPRINT("RStartServiceW(%p %lu %p) called\n", hService, argc, argv);
    DPRINT("  argc: %lu\n", argc);
    if (argv != NULL)
    {
        for (i = 0; i < argc; i++)
        {
            DPRINT("  argv[%lu]: %S\n", i, argv[i].StringPtr);
        }
    }
#endif

    if (ScmShutdown)
        return ERROR_SHUTDOWN_IN_PROGRESS;

    hSvc = ScmGetServiceFromHandle(hService);
    if (hSvc == NULL)
    {
        DPRINT1("Invalid service handle\n");
        return ERROR_INVALID_HANDLE;
    }

    if (!RtlAreAllAccessesGranted(hSvc->Handle.DesiredAccess,
                                  SERVICE_START))
    {
        DPRINT("Insufficient access rights! 0x%lx\n", hSvc->Handle.DesiredAccess);
        return ERROR_ACCESS_DENIED;
    }

    lpService = hSvc->ServiceEntry;
    if (lpService == NULL)
    {
        DPRINT("lpService == NULL\n");
        return ERROR_INVALID_HANDLE;
    }

    if (lpService->dwStartType == SERVICE_DISABLED)
        return ERROR_SERVICE_DISABLED;

    if (lpService->bDeleted)
        return ERROR_SERVICE_MARKED_FOR_DELETE;

    /* Start the service */
    dwError = ScmStartService(lpService, argc, (PCWSTR*)argv);

    return dwError;
}


/* Function 20 */
DWORD
WINAPI
RGetServiceDisplayNameW(
    SC_RPC_HANDLE hSCManager,
    LPCWSTR lpServiceName,
    LPWSTR lpDisplayName,
    DWORD *lpcchBuffer)
{
    // PMANAGER_HANDLE hManager;
    PSERVICE lpService;
    LPCWSTR lpSvcDisplayName;
    DWORD dwLength;
    DWORD dwError;

    DPRINT("RGetServiceDisplayNameW() called\n");
    DPRINT("hSCManager = %p\n", hSCManager);
    DPRINT("lpServiceName: %S\n", lpServiceName);
    DPRINT("lpDisplayName: %p\n", lpDisplayName);
    DPRINT("*lpcchBuffer: %lu\n", *lpcchBuffer);

#if 0
    hManager = (PMANAGER_HANDLE)hSCManager;
    if (hManager->Handle.Tag != MANAGER_TAG)
    {
        DPRINT("Invalid manager handle\n");
        return ERROR_INVALID_HANDLE;
    }
#endif

    /* Get service database entry */
    lpService = ScmGetServiceEntryByName(lpServiceName);
    if (lpService == NULL)
    {
        DPRINT("Could not find service\n");
        return ERROR_SERVICE_DOES_NOT_EXIST;
    }

    if (lpService->lpDisplayName)
        lpSvcDisplayName = lpService->lpDisplayName;
    else
        lpSvcDisplayName = lpService->lpServiceName;

    dwLength = (DWORD)wcslen(lpSvcDisplayName);

    if (*lpcchBuffer > dwLength)
    {
        if (lpDisplayName != NULL)
            wcscpy(lpDisplayName, lpSvcDisplayName);

        dwError = ERROR_SUCCESS;
    }
    else
    {
        dwError = ERROR_INSUFFICIENT_BUFFER;
    }

    *lpcchBuffer = dwLength;

    return dwError;
}


/* Function 21 */
DWORD
WINAPI
RGetServiceKeyNameW(
    SC_RPC_HANDLE hSCManager,
    LPCWSTR lpDisplayName,
    LPWSTR lpServiceName,
    DWORD *lpcchBuffer)
{
    // PMANAGER_HANDLE hManager;
    PSERVICE lpService;
    DWORD dwLength;
    DWORD dwError;

    DPRINT("RGetServiceKeyNameW() called\n");
    DPRINT("hSCManager = %p\n", hSCManager);
    DPRINT("lpDisplayName: %S\n", lpDisplayName);
    DPRINT("lpServiceName: %p\n", lpServiceName);
    DPRINT("*lpcchBuffer: %lu\n", *lpcchBuffer);

#if 0
    hManager = (PMANAGER_HANDLE)hSCManager;
    if (hManager->Handle.Tag != MANAGER_TAG)
    {
        DPRINT("Invalid manager handle\n");
        return ERROR_INVALID_HANDLE;
    }
#endif

    /* Get service database entry */
    lpService = ScmGetServiceEntryByDisplayName(lpDisplayName);
    if (lpService == NULL)
    {
        DPRINT("Could not find service\n");
        return ERROR_SERVICE_DOES_NOT_EXIST;
    }

    dwLength = (DWORD)wcslen(lpService->lpServiceName);

    if (*lpcchBuffer > dwLength)
    {
        if (lpServiceName != NULL)
            wcscpy(lpServiceName, lpService->lpServiceName);

        dwError = ERROR_SUCCESS;
    }
    else
    {
        dwError = ERROR_INSUFFICIENT_BUFFER;
    }

    *lpcchBuffer = dwLength;

    return dwError;
}


/* Function 22 */
DWORD
WINAPI
RI_ScSetServiceBitsA(
    RPC_SERVICE_STATUS_HANDLE hServiceStatus,
    DWORD dwServiceBits,
    int bSetBitsOn,
    int bUpdateImmediately,
    char *lpString)
{
    if (ScmShutdown)
        return ERROR_SHUTDOWN_IN_PROGRESS;

    if (lpString != NULL)
        return ERROR_INVALID_PARAMETER;

    return RI_ScSetServiceBitsW(hServiceStatus,
                                dwServiceBits,
                                bSetBitsOn,
                                bUpdateImmediately,
                                NULL);
}


/* Function 23 */
DWORD
WINAPI
RChangeServiceConfigA(
    SC_RPC_HANDLE hService,
    DWORD dwServiceType,
    DWORD dwStartType,
    DWORD dwErrorControl,
    LPSTR lpBinaryPathName,
    LPSTR lpLoadOrderGroup,
    LPDWORD lpdwTagId,
    LPBYTE lpDependencies,
    DWORD dwDependSize,
    LPSTR lpServiceStartName,
    LPBYTE lpPassword,
    DWORD dwPwSize,
    LPSTR lpDisplayName)
{
    DWORD dwError = ERROR_SUCCESS;
    LPWSTR lpBinaryPathNameW = NULL;
    LPWSTR lpLoadOrderGroupW = NULL;
    LPWSTR lpDependenciesW = NULL;
    LPWSTR lpServiceStartNameW = NULL;
    LPWSTR lpDisplayNameW = NULL;
    DWORD dwDependenciesLength = 0;
    SIZE_T cchLength;
    int len;
    LPCSTR lpStr;

    if (lpBinaryPathName)
    {
        len = MultiByteToWideChar(CP_ACP, 0, lpBinaryPathName, -1, NULL, 0);
        lpBinaryPathNameW = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len * sizeof(WCHAR));
        if (!lpBinaryPathNameW)
        {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            goto cleanup;
        }
        MultiByteToWideChar(CP_ACP, 0, lpBinaryPathName, -1, lpBinaryPathNameW, len);
    }

    if (lpLoadOrderGroup)
    {
        len = MultiByteToWideChar(CP_ACP, 0, lpLoadOrderGroup, -1, NULL, 0);
        lpLoadOrderGroupW = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len * sizeof(WCHAR));
        if (!lpLoadOrderGroupW)
        {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            goto cleanup;
        }
        MultiByteToWideChar(CP_ACP, 0, lpLoadOrderGroup, -1, lpLoadOrderGroupW, len);
    }

    if (lpDependencies)
    {
        lpStr = (LPCSTR)lpDependencies;
        while (*lpStr)
        {
            cchLength = strlen(lpStr) + 1;
            dwDependenciesLength += (DWORD)cchLength;
            lpStr = lpStr + cchLength;
        }
        dwDependenciesLength++;

        lpDependenciesW = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwDependenciesLength * sizeof(WCHAR));
        if (!lpDependenciesW)
        {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            goto cleanup;
        }
        MultiByteToWideChar(CP_ACP, 0, (LPCSTR)lpDependencies, dwDependenciesLength, lpDependenciesW, dwDependenciesLength);
    }

    if (lpServiceStartName)
    {
        len = MultiByteToWideChar(CP_ACP, 0, lpServiceStartName, -1, NULL, 0);
        lpServiceStartNameW = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len * sizeof(WCHAR));
        if (!lpServiceStartNameW)
        {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            goto cleanup;
        }
        MultiByteToWideChar(CP_ACP, 0, lpServiceStartName, -1, lpServiceStartNameW, len);
    }

    if (lpDisplayName)
    {
        len = MultiByteToWideChar(CP_ACP, 0, lpDisplayName, -1, NULL, 0);
        lpDisplayNameW = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len * sizeof(WCHAR));
        if (!lpDisplayNameW)
        {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            goto cleanup;
        }
        MultiByteToWideChar(CP_ACP, 0, lpDisplayName, -1, lpDisplayNameW, len);
    }

    dwError = RChangeServiceConfigW(hService,
                                    dwServiceType,
                                    dwStartType,
                                    dwErrorControl,
                                    lpBinaryPathNameW,
                                    lpLoadOrderGroupW,
                                    lpdwTagId,
                                    (LPBYTE)lpDependenciesW,
                                    dwDependenciesLength,
                                    lpServiceStartNameW,
                                    lpPassword,
                                    dwPwSize,
                                    lpDisplayNameW);

cleanup:
    if (lpBinaryPathNameW != NULL)
        HeapFree(GetProcessHeap(), 0, lpBinaryPathNameW);

    if (lpLoadOrderGroupW != NULL)
        HeapFree(GetProcessHeap(), 0, lpLoadOrderGroupW);

    if (lpDependenciesW != NULL)
        HeapFree(GetProcessHeap(), 0, lpDependenciesW);

    if (lpServiceStartNameW != NULL)
        HeapFree(GetProcessHeap(), 0, lpServiceStartNameW);

    if (lpDisplayNameW != NULL)
        HeapFree(GetProcessHeap(), 0, lpDisplayNameW);

    return dwError;
}


/* Function 24 */
DWORD
WINAPI
RCreateServiceA(
    SC_RPC_HANDLE hSCManager,
    LPSTR lpServiceName,
    LPSTR lpDisplayName,
    DWORD dwDesiredAccess,
    DWORD dwServiceType,
    DWORD dwStartType,
    DWORD dwErrorControl,
    LPSTR lpBinaryPathName,
    LPSTR lpLoadOrderGroup,
    LPDWORD lpdwTagId,
    LPBYTE lpDependencies,
    DWORD dwDependSize,
    LPSTR lpServiceStartName,
    LPBYTE lpPassword,
    DWORD dwPwSize,
    LPSC_RPC_HANDLE lpServiceHandle)
{
    DWORD dwError = ERROR_SUCCESS;
    LPWSTR lpServiceNameW = NULL;
    LPWSTR lpDisplayNameW = NULL;
    LPWSTR lpBinaryPathNameW = NULL;
    LPWSTR lpLoadOrderGroupW = NULL;
    LPWSTR lpDependenciesW = NULL;
    LPWSTR lpServiceStartNameW = NULL;
    DWORD dwDependenciesLength = 0;
    SIZE_T cchLength;
    int len;
    LPCSTR lpStr;

    if (lpServiceName)
    {
        len = MultiByteToWideChar(CP_ACP, 0, lpServiceName, -1, NULL, 0);
        lpServiceNameW = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len * sizeof(WCHAR));
        if (!lpServiceNameW)
        {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            goto cleanup;
        }
        MultiByteToWideChar(CP_ACP, 0, lpServiceName, -1, lpServiceNameW, len);
    }

    if (lpDisplayName)
    {
        len = MultiByteToWideChar(CP_ACP, 0, lpDisplayName, -1, NULL, 0);
        lpDisplayNameW = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len * sizeof(WCHAR));
        if (!lpDisplayNameW)
        {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            goto cleanup;
        }
        MultiByteToWideChar(CP_ACP, 0, lpDisplayName, -1, lpDisplayNameW, len);
    }

    if (lpBinaryPathName)
    {
        len = MultiByteToWideChar(CP_ACP, 0, lpBinaryPathName, -1, NULL, 0);
        lpBinaryPathNameW = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len * sizeof(WCHAR));
        if (!lpBinaryPathNameW)
        {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            goto cleanup;
        }
        MultiByteToWideChar(CP_ACP, 0, lpBinaryPathName, -1, lpBinaryPathNameW, len);
    }

    if (lpLoadOrderGroup)
    {
        len = MultiByteToWideChar(CP_ACP, 0, lpLoadOrderGroup, -1, NULL, 0);
        lpLoadOrderGroupW = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len * sizeof(WCHAR));
        if (!lpLoadOrderGroupW)
        {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            goto cleanup;
        }
        MultiByteToWideChar(CP_ACP, 0, lpLoadOrderGroup, -1, lpLoadOrderGroupW, len);
    }

    if (lpDependencies)
    {
        lpStr = (LPCSTR)lpDependencies;
        while (*lpStr)
        {
            cchLength = strlen(lpStr) + 1;
            dwDependenciesLength += (DWORD)cchLength;
            lpStr = lpStr + cchLength;
        }
        dwDependenciesLength++;

        lpDependenciesW = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwDependenciesLength * sizeof(WCHAR));
        if (!lpDependenciesW)
        {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            goto cleanup;
        }
        MultiByteToWideChar(CP_ACP, 0, (LPCSTR)lpDependencies, dwDependenciesLength, lpDependenciesW, dwDependenciesLength);
    }

    if (lpServiceStartName)
    {
        len = MultiByteToWideChar(CP_ACP, 0, lpServiceStartName, -1, NULL, 0);
        lpServiceStartNameW = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len * sizeof(WCHAR));
        if (!lpServiceStartNameW)
        {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            goto cleanup;
        }
        MultiByteToWideChar(CP_ACP, 0, lpServiceStartName, -1, lpServiceStartNameW, len);
    }

    dwError = RCreateServiceW(hSCManager,
                              lpServiceNameW,
                              lpDisplayNameW,
                              dwDesiredAccess,
                              dwServiceType,
                              dwStartType,
                              dwErrorControl,
                              lpBinaryPathNameW,
                              lpLoadOrderGroupW,
                              lpdwTagId,
                              (LPBYTE)lpDependenciesW,
                              dwDependenciesLength,
                              lpServiceStartNameW,
                              lpPassword,
                              dwPwSize,
                              lpServiceHandle);

cleanup:
    if (lpServiceNameW !=NULL)
        HeapFree(GetProcessHeap(), 0, lpServiceNameW);

    if (lpDisplayNameW != NULL)
        HeapFree(GetProcessHeap(), 0, lpDisplayNameW);

    if (lpBinaryPathNameW != NULL)
        HeapFree(GetProcessHeap(), 0, lpBinaryPathNameW);

    if (lpLoadOrderGroupW != NULL)
        HeapFree(GetProcessHeap(), 0, lpLoadOrderGroupW);

    if (lpDependenciesW != NULL)
        HeapFree(GetProcessHeap(), 0, lpDependenciesW);

    if (lpServiceStartNameW != NULL)
        HeapFree(GetProcessHeap(), 0, lpServiceStartNameW);

    return dwError;
}


/* Function 25 */
DWORD
WINAPI
REnumDependentServicesA(
    SC_RPC_HANDLE hService,
    DWORD dwServiceState,
    LPBYTE lpServices,
    DWORD cbBufSize,
    LPBOUNDED_DWORD_256K pcbBytesNeeded,
    LPBOUNDED_DWORD_256K lpServicesReturned)
{
    DWORD dwError = ERROR_SUCCESS;
    DWORD dwServicesReturned = 0;
    DWORD dwServiceCount;
    HKEY hServicesKey = NULL;
    PSERVICE_HANDLE hSvc;
    PSERVICE lpService = NULL;
    PSERVICE *lpServicesArray = NULL;
    LPENUM_SERVICE_STATUSA lpServicesPtr = NULL;
    LPSTR lpStr;

    *pcbBytesNeeded = 0;
    *lpServicesReturned = 0;

    DPRINT("REnumDependentServicesA() called\n");

    hSvc = ScmGetServiceFromHandle(hService);
    if (hSvc == NULL)
    {
        DPRINT1("Invalid service handle\n");
        return ERROR_INVALID_HANDLE;
    }

    lpService = hSvc->ServiceEntry;

    /* A service handle needs SERVICE_ENUMERATE_DEPENDENTS (SC_MANAGER_ENUMERATE_SERVICE is a manager right) */
    if (!RtlAreAllAccessesGranted(hSvc->Handle.DesiredAccess,
                                  SERVICE_ENUMERATE_DEPENDENTS))
    {
        DPRINT("Insufficient access rights! 0x%lx\n",
               hSvc->Handle.DesiredAccess);
        return ERROR_ACCESS_DENIED;
    }

    /* Open the Services Reg key */
    dwError = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"System\\CurrentControlSet\\Services",
                            0,
                            KEY_READ,
                            &hServicesKey);

    if (dwError != ERROR_SUCCESS)
        return dwError;

    /* NOTE: Windows calculates the pcbBytesNeeded based on WCHAR strings for
             both EnumDependentServicesA and EnumDependentServicesW. So returned pcbBytesNeeded
             are the same for both. Verified in WINXP. */

    /* First determine the bytes needed and get the number of dependent services*/
    dwError = Int_EnumDependentServicesW(hServicesKey,
                                         lpService,
                                         dwServiceState,
                                         NULL,
                                         pcbBytesNeeded,
                                         &dwServicesReturned);
    if (dwError != ERROR_SUCCESS)
        goto Done;

    /* If buffer size is less than the bytes needed or pointer is null*/
    if ((!lpServices) || (cbBufSize < *pcbBytesNeeded))
    {
        dwError = ERROR_MORE_DATA;
        goto Done;
    }

    /* Allocate memory for array of service pointers */
    lpServicesArray = HeapAlloc(GetProcessHeap(),
                                HEAP_ZERO_MEMORY,
                                (dwServicesReturned + 1) * sizeof(PSERVICE));
    if (!lpServicesArray)
    {
        DPRINT("Could not allocate buffer\n");
        dwError = ERROR_NOT_ENOUGH_MEMORY;
        goto Done;
    }

    dwServicesReturned = 0;
    *pcbBytesNeeded = 0;

    dwError = Int_EnumDependentServicesW(hServicesKey,
                                         lpService,
                                         dwServiceState,
                                         lpServicesArray,
                                         pcbBytesNeeded,
                                         &dwServicesReturned);
    if (dwError != ERROR_SUCCESS)
    {
        goto Done;
    }

    lpServicesPtr = (LPENUM_SERVICE_STATUSA)lpServices;
    lpStr = (LPSTR)(lpServices + (dwServicesReturned * sizeof(ENUM_SERVICE_STATUSA)));

    /* Copy EnumDepenedentService to Buffer */
    for (dwServiceCount = 0; dwServiceCount < dwServicesReturned; dwServiceCount++)
    {
        lpService = lpServicesArray[dwServiceCount];

        /* Copy the status info */
        memcpy(&lpServicesPtr->ServiceStatus,
               &lpService->Status,
               sizeof(SERVICE_STATUS));

        /* Copy display name */
        WideCharToMultiByte(CP_ACP,
                            0,
                            lpService->lpDisplayName,
                            -1,
                            lpStr,
                            (int)wcslen(lpService->lpDisplayName),
                            0,
                            0);
        lpServicesPtr->lpDisplayName = (LPSTR)((ULONG_PTR)lpStr - (ULONG_PTR)lpServices);
        lpStr += strlen(lpStr) + 1;

        /* Copy service name */
        WideCharToMultiByte(CP_ACP,
                            0,
                            lpService->lpServiceName,
                            -1,
                            lpStr,
                            (int)wcslen(lpService->lpServiceName),
                            0,
                            0);
        lpServicesPtr->lpServiceName = (LPSTR)((ULONG_PTR)lpStr - (ULONG_PTR)lpServices);
        lpStr += strlen(lpStr) + 1;

        lpServicesPtr++;
    }

    *lpServicesReturned = dwServicesReturned;

    /* Nothing is left to be fetched */
    *pcbBytesNeeded = 0;

Done:
    if (lpServicesArray)
        HeapFree(GetProcessHeap(), 0, lpServicesArray);

    RegCloseKey(hServicesKey);

    DPRINT("REnumDependentServicesA() done (Error %lu)\n", dwError);

    return dwError;
}


/* Function 26 */
DWORD
WINAPI
REnumServicesStatusA(
    SC_RPC_HANDLE hSCManager,
    DWORD dwServiceType,
    DWORD dwServiceState,
    LPBYTE lpBuffer,
    DWORD dwBufSize,
    LPBOUNDED_DWORD_256K pcbBytesNeeded,
    LPBOUNDED_DWORD_256K lpServicesReturned,
    LPBOUNDED_DWORD_256K lpResumeHandle)
{
    LPENUM_SERVICE_STATUSW lpStatusPtrW = NULL;
    LPENUM_SERVICE_STATUSW lpStatusPtrIncrW;
    LPENUM_SERVICE_STATUSA lpStatusPtrA = NULL;
    LPWSTR lpStringPtrW;
    LPSTR lpStringPtrA;
    DWORD dwError;
    DWORD dwServiceCount;

    DPRINT("REnumServicesStatusA() called\n");

    if (pcbBytesNeeded == NULL || lpServicesReturned == NULL)
    {
        return ERROR_INVALID_ADDRESS;
    }

    if ((dwBufSize > 0) && (lpBuffer))
    {
        lpStatusPtrW = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufSize);
        if (!lpStatusPtrW)
        {
            DPRINT("Failed to allocate buffer\n");
            return ERROR_NOT_ENOUGH_MEMORY;
        }
    }

    dwError = REnumServicesStatusW(hSCManager,
                                   dwServiceType,
                                   dwServiceState,
                                   (LPBYTE)lpStatusPtrW,
                                   dwBufSize,
                                   pcbBytesNeeded,
                                   lpServicesReturned,
                                   lpResumeHandle);

    /* if no services were returned then we are Done */
    if (*lpServicesReturned == 0)
        goto Done;

    lpStatusPtrIncrW = lpStatusPtrW;
    lpStatusPtrA = (LPENUM_SERVICE_STATUSA)lpBuffer;
    lpStringPtrA = (LPSTR)((ULONG_PTR)lpBuffer +
                  *lpServicesReturned * sizeof(ENUM_SERVICE_STATUSA));
    lpStringPtrW = (LPWSTR)((ULONG_PTR)lpStatusPtrW +
                  *lpServicesReturned * sizeof(ENUM_SERVICE_STATUSW));

    for (dwServiceCount = 0; dwServiceCount < *lpServicesReturned; dwServiceCount++)
    {
        /* Copy the service name */
        WideCharToMultiByte(CP_ACP,
                            0,
                            lpStringPtrW,
                            -1,
                            lpStringPtrA,
                            (int)wcslen(lpStringPtrW),
                            0,
                            0);

        lpStatusPtrA->lpServiceName = (LPSTR)((ULONG_PTR)lpStringPtrA - (ULONG_PTR)lpBuffer);
        lpStringPtrA += wcslen(lpStringPtrW) + 1;
        lpStringPtrW += wcslen(lpStringPtrW) + 1;

        /* Copy the display name */
        WideCharToMultiByte(CP_ACP,
                            0,
                            lpStringPtrW,
                            -1,
                            lpStringPtrA,
                            (int)wcslen(lpStringPtrW),
                            0,
                            0);

        lpStatusPtrA->lpDisplayName = (LPSTR)((ULONG_PTR)lpStringPtrA - (ULONG_PTR)lpBuffer);
        lpStringPtrA += wcslen(lpStringPtrW) + 1;
        lpStringPtrW += wcslen(lpStringPtrW) + 1;

        /* Copy the status information */
        memcpy(&lpStatusPtrA->ServiceStatus,
               &lpStatusPtrIncrW->ServiceStatus,
               sizeof(SERVICE_STATUS));

        lpStatusPtrIncrW++;
        lpStatusPtrA++;
    }

Done:
    if (lpStatusPtrW)
        HeapFree(GetProcessHeap(), 0, lpStatusPtrW);

    DPRINT("REnumServicesStatusA() done (Error %lu)\n", dwError);

    return dwError;
}


/* Function 27 */
DWORD
WINAPI
ROpenSCManagerA(
    LPSTR lpMachineName,
    LPSTR lpDatabaseName,
    DWORD dwDesiredAccess,
    LPSC_RPC_HANDLE lpScHandle)
{
    UNICODE_STRING MachineName;
    UNICODE_STRING DatabaseName;
    DWORD dwError;

    DPRINT("ROpenSCManagerA() called\n");

    if (lpMachineName)
        RtlCreateUnicodeStringFromAsciiz(&MachineName,
                                         lpMachineName);

    if (lpDatabaseName)
        RtlCreateUnicodeStringFromAsciiz(&DatabaseName,
                                         lpDatabaseName);

    dwError = ROpenSCManagerW(lpMachineName ? MachineName.Buffer : NULL,
                              lpDatabaseName ? DatabaseName.Buffer : NULL,
                              dwDesiredAccess,
                              lpScHandle);

    if (lpMachineName)
        RtlFreeUnicodeString(&MachineName);

    if (lpDatabaseName)
        RtlFreeUnicodeString(&DatabaseName);

    return dwError;
}


/* Function 28 */
DWORD
WINAPI
ROpenServiceA(
    SC_RPC_HANDLE hSCManager,
    LPSTR lpServiceName,
    DWORD dwDesiredAccess,
    LPSC_RPC_HANDLE lpServiceHandle)
{
    UNICODE_STRING ServiceName;
    DWORD dwError;

    DPRINT("ROpenServiceA() called\n");

    if (lpServiceName)
        RtlCreateUnicodeStringFromAsciiz(&ServiceName,
                                         lpServiceName);

    dwError = ROpenServiceW(hSCManager,
                            lpServiceName ? ServiceName.Buffer : NULL,
                            dwDesiredAccess,
                            lpServiceHandle);

    if (lpServiceName)
        RtlFreeUnicodeString(&ServiceName);

    return dwError;
}


/* Function 29 */
DWORD
WINAPI
RQueryServiceConfigA(
    SC_RPC_HANDLE hService,
    LPBYTE lpBuf, //LPQUERY_SERVICE_CONFIGA lpServiceConfig,
    DWORD cbBufSize,
    LPBOUNDED_DWORD_8K pcbBytesNeeded)
{
    LPQUERY_SERVICE_CONFIGA lpServiceConfig = (LPQUERY_SERVICE_CONFIGA)lpBuf;
    DWORD dwError = ERROR_SUCCESS;
    PSERVICE_HANDLE hSvc;
    PSERVICE lpService = NULL;
    HKEY hServiceKey = NULL;
    LPWSTR lpImagePath = NULL;
    LPWSTR lpServiceStartName = NULL;
    LPWSTR lpDependencies = NULL;
    DWORD dwDependenciesLength = 0;
    DWORD dwRequiredSize;
    LPSTR lpStr;

    DPRINT("RQueryServiceConfigA() called\n");

    if (ScmShutdown)
        return ERROR_SHUTDOWN_IN_PROGRESS;

    hSvc = ScmGetServiceFromHandle(hService);
    if (hSvc == NULL)
    {
        DPRINT1("Invalid service handle\n");
        return ERROR_INVALID_HANDLE;
    }

    if (!RtlAreAllAccessesGranted(hSvc->Handle.DesiredAccess,
                                  SERVICE_QUERY_CONFIG))
    {
        DPRINT("Insufficient access rights! 0x%lx\n", hSvc->Handle.DesiredAccess);
        return ERROR_ACCESS_DENIED;
    }

    lpService = hSvc->ServiceEntry;
    if (lpService == NULL)
    {
        DPRINT("lpService == NULL\n");
        return ERROR_INVALID_HANDLE;
    }

    /* Lock the service database shared */
    ScmLockDatabaseShared();

    dwError = ScmOpenServiceKey(lpService->lpServiceName,
                                KEY_READ,
                                &hServiceKey);
    if (dwError != ERROR_SUCCESS)
        goto Done;

    /* Read the image path */
    dwError = ScmReadString(hServiceKey,
                            L"ImagePath",
                            &lpImagePath);
    if (dwError != ERROR_SUCCESS)
        goto Done;

    /* Read the service start name */
    ScmReadString(hServiceKey,
                  L"ObjectName",
                  &lpServiceStartName);

    /* Read the dependencies */
    ScmReadDependencies(hServiceKey,
                        &lpDependencies,
                        &dwDependenciesLength);

    dwRequiredSize = sizeof(QUERY_SERVICE_CONFIGA);

    if (lpImagePath != NULL)
        dwRequiredSize += (DWORD)(wcslen(lpImagePath) + 1);
    else
        dwRequiredSize += 2 * sizeof(CHAR);

    if ((lpService->lpGroup != NULL) && (lpService->lpGroup->lpGroupName != NULL))
        dwRequiredSize += (DWORD)(wcslen(lpService->lpGroup->lpGroupName) + 1);
    else
        dwRequiredSize += 2 * sizeof(CHAR);

    /* Add Dependencies length */
    if (lpDependencies != NULL)
        dwRequiredSize += dwDependenciesLength;
    else
        dwRequiredSize += 2 * sizeof(CHAR);

    if (lpServiceStartName != NULL)
        dwRequiredSize += (DWORD)(wcslen(lpServiceStartName) + 1);
    else
        dwRequiredSize += 2 * sizeof(CHAR);

    if (lpService->lpDisplayName != NULL)
        dwRequiredSize += (DWORD)(wcslen(lpService->lpDisplayName) + 1);
    else
        dwRequiredSize += 2 * sizeof(CHAR);

    if (lpServiceConfig == NULL || cbBufSize < dwRequiredSize)
    {
        dwError = ERROR_INSUFFICIENT_BUFFER;
    }
    else
    {
        lpServiceConfig->dwServiceType = lpService->Status.dwServiceType;
        lpServiceConfig->dwStartType = lpService->dwStartType;
        lpServiceConfig->dwErrorControl = lpService->dwErrorControl;
        lpServiceConfig->dwTagId = lpService->dwTag;

        lpStr = (LPSTR)(lpServiceConfig + 1);

        /* NOTE: Strings that are NULL for QUERY_SERVICE_CONFIG are pointers to empty strings.
           Verified in WINXP */

        if (lpImagePath)
        {
            WideCharToMultiByte(CP_ACP,
                                0,
                                lpImagePath,
                                -1,
                                lpStr,
                                (int)(wcslen(lpImagePath) + 1),
                                0,
                                0);
        }
        else
        {
            *lpStr = 0;
        }

        lpServiceConfig->lpBinaryPathName = (LPSTR)((ULONG_PTR)lpStr - (ULONG_PTR)lpServiceConfig);
        lpStr += (strlen((LPSTR)lpStr) + 1);

        if (lpService->lpGroup && lpService->lpGroup->lpGroupName)
        {
            WideCharToMultiByte(CP_ACP,
                                0,
                                lpService->lpGroup->lpGroupName,
                                -1,
                                lpStr,
                                (int)(wcslen(lpService->lpGroup->lpGroupName) + 1),
                                0,
                                0);
        }
        else
        {
            *lpStr = 0;
        }

        lpServiceConfig->lpLoadOrderGroup = (LPSTR)((ULONG_PTR)lpStr - (ULONG_PTR)lpServiceConfig);
        lpStr += (strlen(lpStr) + 1);

        /* Append Dependencies */
        if (lpDependencies)
        {
            WideCharToMultiByte(CP_ACP,
                                0,
                                lpDependencies,
                                dwDependenciesLength,
                                lpStr,
                                dwDependenciesLength,
                                0,
                                0);
        }
        else
        {
            *lpStr = 0;
        }

        lpServiceConfig->lpDependencies = (LPSTR)((ULONG_PTR)lpStr - (ULONG_PTR)lpServiceConfig);
        if (lpDependencies)
            lpStr += dwDependenciesLength;
        else
            lpStr += (strlen(lpStr) + 1);

        if (lpServiceStartName)
        {
            WideCharToMultiByte(CP_ACP,
                                0,
                                lpServiceStartName,
                                -1,
                                lpStr,
                                (int)(wcslen(lpServiceStartName) + 1),
                                0,
                                0);
        }
        else
        {
            *lpStr = 0;
        }

        lpServiceConfig->lpServiceStartName = (LPSTR)((ULONG_PTR)lpStr - (ULONG_PTR)lpServiceConfig);
        lpStr += (strlen(lpStr) + 1);

        if (lpService->lpDisplayName)
        {
            WideCharToMultiByte(CP_ACP,
                                0,
                                lpService->lpDisplayName,
                                -1,
                                lpStr,
                                (int)(wcslen(lpService->lpDisplayName) + 1),
                                0,
                                0);
        }
        else
        {
            *lpStr = 0;
        }

        lpServiceConfig->lpDisplayName = (LPSTR)((ULONG_PTR)lpStr - (ULONG_PTR)lpServiceConfig);
    }

    if (pcbBytesNeeded != NULL)
        *pcbBytesNeeded = dwRequiredSize;

Done:
    /* Unlock the service database */
    ScmUnlockDatabase();

    if (lpImagePath != NULL)
        HeapFree(GetProcessHeap(), 0, lpImagePath);

    if (lpServiceStartName != NULL)
        HeapFree(GetProcessHeap(), 0, lpServiceStartName);

    if (lpDependencies != NULL)
        HeapFree(GetProcessHeap(), 0, lpDependencies);

    if (hServiceKey != NULL)
        RegCloseKey(hServiceKey);

    DPRINT("RQueryServiceConfigA() done\n");

    return dwError;
}


/* Function 30 */
DWORD
WINAPI
RQueryServiceLockStatusA(
    SC_RPC_HANDLE hSCManager,
    LPBYTE lpBuf, // LPQUERY_SERVICE_LOCK_STATUSA lpLockStatus,
    DWORD cbBufSize,
    LPBOUNDED_DWORD_4K pcbBytesNeeded)
{
    LPQUERY_SERVICE_LOCK_STATUSA lpLockStatus = (LPQUERY_SERVICE_LOCK_STATUSA)lpBuf;
    PMANAGER_HANDLE hMgr;
    DWORD dwRequiredSize, dwError;

    if (!lpLockStatus || !pcbBytesNeeded)
        return ERROR_INVALID_PARAMETER;

    hMgr = ScmGetServiceManagerFromHandle(hSCManager);
    if (hMgr == NULL)
    {
        DPRINT1("Invalid service manager handle\n");
        return ERROR_INVALID_HANDLE;
    }

    if (!RtlAreAllAccessesGranted(hMgr->Handle.DesiredAccess,
                                  SC_MANAGER_QUERY_LOCK_STATUS))
    {
        DPRINT("Insufficient access rights! 0x%lx\n", hMgr->Handle.DesiredAccess);
        return ERROR_ACCESS_DENIED;
    }

    /* The owner's name is part of what is returned, so the size is worked out with it */
    dwError = ScmQueryServiceLockStatusA(lpLockStatus, cbBufSize, &dwRequiredSize);
    *pcbBytesNeeded = dwRequiredSize;
    return dwError;
}


/* Function 31 */
DWORD
WINAPI
RStartServiceA(
    SC_RPC_HANDLE hService,
    DWORD argc,
    LPSTRING_PTRSA argv)
{
    DWORD dwError = ERROR_SUCCESS;
    PSERVICE_HANDLE hSvc;
    PSERVICE lpService = NULL;
    PWSTR* pVector = NULL;
    DWORD i;
    DWORD dwLength;

    DPRINT("RStartServiceA() called\n");

    if (ScmShutdown)
        return ERROR_SHUTDOWN_IN_PROGRESS;

    hSvc = ScmGetServiceFromHandle(hService);
    if (hSvc == NULL)
    {
        DPRINT1("Invalid service handle\n");
        return ERROR_INVALID_HANDLE;
    }

    if (!RtlAreAllAccessesGranted(hSvc->Handle.DesiredAccess,
                                  SERVICE_START))
    {
        DPRINT("Insufficient access rights! 0x%lx\n", hSvc->Handle.DesiredAccess);
        return ERROR_ACCESS_DENIED;
    }

    lpService = hSvc->ServiceEntry;
    if (lpService == NULL)
    {
        DPRINT("lpService == NULL\n");
        return ERROR_INVALID_HANDLE;
    }

    if (lpService->dwStartType == SERVICE_DISABLED)
        return ERROR_SERVICE_DISABLED;

    if (lpService->bDeleted)
        return ERROR_SERVICE_MARKED_FOR_DELETE;

    /* Build a Unicode argument vector */
    if (argc > 0)
    {
        pVector = HeapAlloc(GetProcessHeap(),
                            HEAP_ZERO_MEMORY,
                            argc * sizeof(PWSTR));
        if (!pVector)
            return ERROR_NOT_ENOUGH_MEMORY;

        for (i = 0; i < argc; i++)
        {
            dwLength = MultiByteToWideChar(CP_ACP,
                                           0,
                                           argv[i].StringPtr,
                                           -1,
                                           NULL,
                                           0);

            pVector[i] = HeapAlloc(GetProcessHeap(),
                                   HEAP_ZERO_MEMORY,
                                   dwLength * sizeof(WCHAR));
            if (!pVector[i])
            {
                dwError = ERROR_NOT_ENOUGH_MEMORY;
                goto done;
            }

            MultiByteToWideChar(CP_ACP,
                                0,
                                argv[i].StringPtr,
                                -1,
                                pVector[i],
                                dwLength);
        }
    }

    /* Start the service */
    dwError = ScmStartService(lpService, argc, (PCWSTR*)pVector);

done:
    /* Free the Unicode argument vector */
    if (pVector)
    {
        for (i = 0; i < argc; i++)
        {
            if (pVector[i])
                HeapFree(GetProcessHeap(), 0, pVector[i]);
        }
        HeapFree(GetProcessHeap(), 0, pVector);
    }

    return dwError;
}


/* Function 32 */
DWORD
WINAPI
RGetServiceDisplayNameA(
    SC_RPC_HANDLE hSCManager,
    LPCSTR lpServiceName,
    LPSTR lpDisplayName,
    LPBOUNDED_DWORD_4K lpcchBuffer)
{
    // PMANAGER_HANDLE hManager;
    PSERVICE lpService = NULL;
    LPCWSTR lpSvcDisplayName;
    LPWSTR lpServiceNameW;
    DWORD dwLength;

    DPRINT("RGetServiceDisplayNameA() called\n");
    DPRINT("hSCManager = %p\n", hSCManager);
    DPRINT("lpServiceName: %s\n", lpServiceName);
    DPRINT("lpDisplayName: %p\n", lpDisplayName);
    DPRINT("*lpcchBuffer: %lu\n", *lpcchBuffer);

#if 0
    hManager = (PMANAGER_HANDLE)hSCManager;
    if (hManager->Handle.Tag != MANAGER_TAG)
    {
        DPRINT("Invalid manager handle\n");
        return ERROR_INVALID_HANDLE;
    }
#endif

    /* Get service database entry */
    if (lpServiceName != NULL)
    {
        dwLength = (DWORD)(strlen(lpServiceName) + 1);
        lpServiceNameW = HeapAlloc(GetProcessHeap(),
                                   HEAP_ZERO_MEMORY,
                                   dwLength * sizeof(WCHAR));
        if (!lpServiceNameW)
            return ERROR_NOT_ENOUGH_MEMORY;

        MultiByteToWideChar(CP_ACP,
                            0,
                            lpServiceName,
                            -1,
                            lpServiceNameW,
                            dwLength);

        lpService = ScmGetServiceEntryByName(lpServiceNameW);

        HeapFree(GetProcessHeap(), 0, lpServiceNameW);
    }

    if (lpService == NULL)
    {
        DPRINT("Could not find service\n");
        return ERROR_SERVICE_DOES_NOT_EXIST;
    }

    if (lpService->lpDisplayName)
        lpSvcDisplayName = lpService->lpDisplayName;
    else
        lpSvcDisplayName = lpService->lpServiceName;

    /*
     * NOTE: On Windows the comparison on *lpcchBuffer is made against
     * the number of (wide) characters of the UNICODE display name, and
     * not against the number of bytes needed to store the ANSI string.
     */
    dwLength = (DWORD)wcslen(lpSvcDisplayName);

    if (*lpcchBuffer > dwLength)
    {
        if (lpDisplayName != NULL &&
            WideCharToMultiByte(CP_ACP,
                                0,
                                lpSvcDisplayName,
                                -1,
                                lpDisplayName,
                                (int)*lpcchBuffer,
                                NULL,
                                NULL) == 0)
        {
            /*
             * But then, if *lpcchBuffer was greater than the number of
             * (wide) characters of the UNICODE display name, yet smaller
             * than the number of bytes needed due to the possible presence
             * of DBCS characters, the *exact* number of bytes is returned
             * (without the NULL terminator).
             */
            dwLength = (DWORD)WideCharToMultiByte(CP_ACP,
                                                  0,
                                                  lpSvcDisplayName,
                                                  (int)dwLength,
                                                  NULL,
                                                  0,
                                                  NULL,
                                                  NULL);
            *lpDisplayName = 0;
            *lpcchBuffer = dwLength;
            return ERROR_INSUFFICIENT_BUFFER;
        }

        /*
         * NOTE: On Windows, RGetServiceDisplayNameA() does not update
         * *lpcchBuffer on success, contrary to RGetServiceDisplayNameW().
         */
        return ERROR_SUCCESS;
    }
    else
    {
        /*
         * NOTE: On Windows, if *lpcchBuffer is smaller than the number of
         * (wide) characters of the UNICODE display name, only an upper
         * estimation is returned by doubling the string length, to account
         * for the presence of any possible DBCS characters.
         */
        *lpcchBuffer = dwLength * sizeof(WCHAR);
        return ERROR_INSUFFICIENT_BUFFER;
    }
}


/* Function 33 */
DWORD
WINAPI
RGetServiceKeyNameA(
    SC_RPC_HANDLE hSCManager,
    LPCSTR lpDisplayName,
    LPSTR lpServiceName,
    LPBOUNDED_DWORD_4K lpcchBuffer)
{
    // PMANAGER_HANDLE hManager;
    PSERVICE lpService;
    LPWSTR lpDisplayNameW;
    DWORD dwLength;

    DPRINT("RGetServiceKeyNameA() called\n");
    DPRINT("hSCManager = %p\n", hSCManager);
    DPRINT("lpDisplayName: %s\n", lpDisplayName);
    DPRINT("lpServiceName: %p\n", lpServiceName);
    DPRINT("*lpcchBuffer: %lu\n", *lpcchBuffer);

#if 0
    hManager = (PMANAGER_HANDLE)hSCManager;
    if (hManager->Handle.Tag != MANAGER_TAG)
    {
        DPRINT("Invalid manager handle\n");
        return ERROR_INVALID_HANDLE;
    }
#endif

    /* Get service database entry */

    dwLength = (DWORD)(strlen(lpDisplayName) + 1);
    lpDisplayNameW = HeapAlloc(GetProcessHeap(),
                               HEAP_ZERO_MEMORY,
                               dwLength * sizeof(WCHAR));
    if (!lpDisplayNameW)
        return ERROR_NOT_ENOUGH_MEMORY;

    MultiByteToWideChar(CP_ACP,
                        0,
                        lpDisplayName,
                        -1,
                        lpDisplayNameW,
                        dwLength);

    lpService = ScmGetServiceEntryByDisplayName(lpDisplayNameW);

    HeapFree(GetProcessHeap(), 0, lpDisplayNameW);

    if (lpService == NULL)
    {
        DPRINT("Could not find service\n");
        return ERROR_SERVICE_DOES_NOT_EXIST;
    }

    /*
     * NOTE: On Windows the comparison on *lpcchBuffer is made against
     * the number of (wide) characters of the UNICODE service name, and
     * not against the number of bytes needed to store the ANSI string.
     */
    dwLength = (DWORD)wcslen(lpService->lpServiceName);

    if (*lpcchBuffer > dwLength)
    {
        if (lpServiceName != NULL &&
            WideCharToMultiByte(CP_ACP,
                                0,
                                lpService->lpServiceName,
                                -1,
                                lpServiceName,
                                (int)*lpcchBuffer,
                                NULL,
                                NULL) == 0)
        {
            /*
             * But then, if *lpcchBuffer was greater than the number of
             * (wide) characters of the UNICODE service name, yet smaller
             * than the number of bytes needed due to the possible presence
             * of DBCS characters, the *exact* number of bytes is returned
             * (without the NULL terminator).
             */
            dwLength = (DWORD)WideCharToMultiByte(CP_ACP,
                                                  0,
                                                  lpService->lpServiceName,
                                                  (int)dwLength,
                                                  NULL,
                                                  0,
                                                  NULL,
                                                  NULL);
            *lpServiceName = 0;
            *lpcchBuffer = dwLength;
            return ERROR_INSUFFICIENT_BUFFER;
        }

        /*
         * NOTE: On Windows, RGetServiceKeyNameA() does not update
         * *lpcchBuffer on success, contrary to RGetServiceKeyNameW().
         */
        return ERROR_SUCCESS;
    }
    else
    {
        /*
         * NOTE: On Windows, if *lpcchBuffer is smaller than the number of
         * (wide) characters of the UNICODE service name, only an upper
         * estimation is returned by doubling the string length, to account
         * for the presence of any possible DBCS characters.
         */
        *lpcchBuffer = dwLength * sizeof(WCHAR);
        return ERROR_INSUFFICIENT_BUFFER;
    }
}


/* Function 34 */
DWORD
WINAPI
RI_ScGetCurrentGroupStateW(
    SC_RPC_HANDLE hSCManager,
    LPWSTR lpLoadOrderGroup,
    LPDWORD lpState)
{
    PMANAGER_HANDLE hManager;
    PSERVICE_GROUP pServiceGroup;
    DWORD dwError = ERROR_SUCCESS;

    DPRINT("RI_ScGetCurrentGroupStateW() called\n");

    if (ScmShutdown)
        return ERROR_SHUTDOWN_IN_PROGRESS;

    hManager = ScmGetServiceManagerFromHandle(hSCManager);
    if (hManager == NULL)
    {
        DPRINT1("Invalid service manager handle\n");
        return ERROR_INVALID_HANDLE;
    }

    /* Check for SC_MANAGER_ENUMERATE_SERVICE access right */
    if (!RtlAreAllAccessesGranted(hManager->Handle.DesiredAccess,
                                  SC_MANAGER_ENUMERATE_SERVICE))
    {
        DPRINT("Insufficient access rights! 0x%lx\n",
                hManager->Handle.DesiredAccess);
        return ERROR_ACCESS_DENIED;
    }

    /* Lock the service database shared */
    ScmLockDatabaseShared();

    /* Get the group list entry */
    pServiceGroup = ScmGetServiceGroupByName(lpLoadOrderGroup);
    if (pServiceGroup == NULL)
    {
        dwError = ERROR_SERVICE_DOES_NOT_EXIST;
        goto done;
    }

    /* FIXME: Return the group state */
    *lpState = 0;

done:
    /* Unlock the service database */
    ScmUnlockDatabase();

    DPRINT("RI_ScGetCurrentGroupStateW() done (Error %lu)\n", dwError);

    return dwError;
}


/* Function 35 */
DWORD
WINAPI
REnumServiceGroupW(
    SC_RPC_HANDLE hSCManager,
    DWORD dwServiceType,
    DWORD dwServiceState,
    LPBYTE lpBuffer,
    DWORD cbBufSize,
    LPBOUNDED_DWORD_256K pcbBytesNeeded,
    LPBOUNDED_DWORD_256K lpServicesReturned,
    LPBOUNDED_DWORD_256K lpResumeIndex,
    LPCWSTR pszGroupName)
{
    PMANAGER_HANDLE hManager;
    PSERVICE lpService;
    DWORD dwError = ERROR_SUCCESS;
    PLIST_ENTRY ServiceEntry;
    PSERVICE CurrentService;
    DWORD dwState;
    DWORD dwRequiredSize;
    DWORD dwServiceCount;
    DWORD dwSize;
    DWORD dwLastResumeCount = 0;
    LPENUM_SERVICE_STATUSW lpStatusPtr;
    LPWSTR lpStringPtr;

    DPRINT("REnumServiceGroupW() called\n");

    if (ScmShutdown)
        return ERROR_SHUTDOWN_IN_PROGRESS;

    hManager = ScmGetServiceManagerFromHandle(hSCManager);
    if (hManager == NULL)
    {
        DPRINT1("Invalid service manager handle\n");
        return ERROR_INVALID_HANDLE;
    }

    if (pcbBytesNeeded == NULL || lpServicesReturned == NULL)
    {
        return ERROR_INVALID_ADDRESS;
    }

    *pcbBytesNeeded = 0;
    *lpServicesReturned = 0;

    if ((dwServiceType == 0) ||
        ((dwServiceType & ~SERVICE_TYPE_ALL) != 0))
    {
        DPRINT("Invalid Service Type\n");
        return ERROR_INVALID_PARAMETER;
    }

    if ((dwServiceState == 0) ||
        ((dwServiceState & ~SERVICE_STATE_ALL) != 0))
    {
        DPRINT("Invalid Service State\n");
        return ERROR_INVALID_PARAMETER;
    }

    /* Check access rights */
    if (!RtlAreAllAccessesGranted(hManager->Handle.DesiredAccess,
                                  SC_MANAGER_ENUMERATE_SERVICE))
    {
        DPRINT("Insufficient access rights! 0x%lx\n",
                hManager->Handle.DesiredAccess);
        return ERROR_ACCESS_DENIED;
    }

    if (lpResumeIndex)
        dwLastResumeCount = *lpResumeIndex;

    /* Lock the service database shared */
    ScmLockDatabaseShared();

    lpService = ScmGetServiceEntryByResumeCount(dwLastResumeCount);
    if (lpService == NULL)
    {
        dwError = ERROR_SUCCESS;
        goto Done;
    }

    dwRequiredSize = 0;
    dwServiceCount = 0;

    for (ServiceEntry = &lpService->ServiceListEntry;
         ServiceEntry != &ServiceListHead;
         ServiceEntry = ServiceEntry->Flink)
    {
        CurrentService = CONTAINING_RECORD(ServiceEntry,
                                           SERVICE,
                                           ServiceListEntry);

        if ((CurrentService->Status.dwServiceType & dwServiceType) == 0)
            continue;

        dwState = SERVICE_ACTIVE;
        if (CurrentService->Status.dwCurrentState == SERVICE_STOPPED)
            dwState = SERVICE_INACTIVE;

        if ((dwState & dwServiceState) == 0)
            continue;

        if (pszGroupName)
        {
            if (*pszGroupName == 0)
            {
                if (CurrentService->lpGroup != NULL)
                    continue;
            }
            else
            {
                if ((CurrentService->lpGroup == NULL) ||
                    _wcsicmp(pszGroupName, CurrentService->lpGroup->lpGroupName) != 0)
                    continue;
            }
        }

        dwSize = sizeof(ENUM_SERVICE_STATUSW) +
                 (DWORD)((wcslen(CurrentService->lpServiceName) + 1) * sizeof(WCHAR)) +
                 (DWORD)((wcslen(CurrentService->lpDisplayName) + 1) * sizeof(WCHAR));

        if (dwRequiredSize + dwSize > cbBufSize)
        {
            DPRINT("Service name: %S  no fit\n", CurrentService->lpServiceName);
            break;
        }

        DPRINT("Service name: %S  fit\n", CurrentService->lpServiceName);
        dwRequiredSize += dwSize;
        dwServiceCount++;
        dwLastResumeCount = CurrentService->dwResumeCount;
    }

    DPRINT("dwRequiredSize: %lu\n", dwRequiredSize);
    DPRINT("dwServiceCount: %lu\n", dwServiceCount);

    for (;
         ServiceEntry != &ServiceListHead;
         ServiceEntry = ServiceEntry->Flink)
    {
        CurrentService = CONTAINING_RECORD(ServiceEntry,
                                           SERVICE,
                                           ServiceListEntry);

        if ((CurrentService->Status.dwServiceType & dwServiceType) == 0)
            continue;

        dwState = SERVICE_ACTIVE;
        if (CurrentService->Status.dwCurrentState == SERVICE_STOPPED)
            dwState = SERVICE_INACTIVE;

        if ((dwState & dwServiceState) == 0)
            continue;

        if (pszGroupName)
        {
            if (*pszGroupName == 0)
            {
                if (CurrentService->lpGroup != NULL)
                    continue;
            }
            else
            {
                if ((CurrentService->lpGroup == NULL) ||
                    _wcsicmp(pszGroupName, CurrentService->lpGroup->lpGroupName) != 0)
                    continue;
            }
        }

        dwRequiredSize += (sizeof(ENUM_SERVICE_STATUSW) +
                           (DWORD)((wcslen(CurrentService->lpServiceName) + 1) * sizeof(WCHAR)) +
                           (DWORD)((wcslen(CurrentService->lpDisplayName) + 1) * sizeof(WCHAR)));

        dwError = ERROR_MORE_DATA;
    }

    DPRINT("*pcbBytesNeeded: %lu\n", dwRequiredSize);

    if (lpResumeIndex)
        *lpResumeIndex = dwLastResumeCount;

    *lpServicesReturned = dwServiceCount;
    *pcbBytesNeeded = dwRequiredSize;

    lpStatusPtr = (LPENUM_SERVICE_STATUSW)lpBuffer;
    lpStringPtr = (LPWSTR)((ULONG_PTR)lpBuffer +
                           dwServiceCount * sizeof(ENUM_SERVICE_STATUSW));

    dwRequiredSize = 0;
    for (ServiceEntry = &lpService->ServiceListEntry;
         ServiceEntry != &ServiceListHead;
         ServiceEntry = ServiceEntry->Flink)
    {
        CurrentService = CONTAINING_RECORD(ServiceEntry,
                                           SERVICE,
                                           ServiceListEntry);

        if ((CurrentService->Status.dwServiceType & dwServiceType) == 0)
            continue;

        dwState = SERVICE_ACTIVE;
        if (CurrentService->Status.dwCurrentState == SERVICE_STOPPED)
            dwState = SERVICE_INACTIVE;

        if ((dwState & dwServiceState) == 0)
            continue;

        if (pszGroupName)
        {
            if (*pszGroupName == 0)
            {
                if (CurrentService->lpGroup != NULL)
                    continue;
            }
            else
            {
                if ((CurrentService->lpGroup == NULL) ||
                    _wcsicmp(pszGroupName, CurrentService->lpGroup->lpGroupName) != 0)
                    continue;
            }
        }

        dwSize = sizeof(ENUM_SERVICE_STATUSW) +
                 (DWORD)((wcslen(CurrentService->lpServiceName) + 1) * sizeof(WCHAR)) +
                 (DWORD)((wcslen(CurrentService->lpDisplayName) + 1) * sizeof(WCHAR));

        if (dwRequiredSize + dwSize > cbBufSize)
            break;

        /* Copy the service name */
        wcscpy(lpStringPtr, CurrentService->lpServiceName);
        lpStatusPtr->lpServiceName = (LPWSTR)((ULONG_PTR)lpStringPtr - (ULONG_PTR)lpBuffer);
        lpStringPtr += (wcslen(CurrentService->lpServiceName) + 1);

        /* Copy the display name */
        wcscpy(lpStringPtr, CurrentService->lpDisplayName);
        lpStatusPtr->lpDisplayName = (LPWSTR)((ULONG_PTR)lpStringPtr - (ULONG_PTR)lpBuffer);
        lpStringPtr += (wcslen(CurrentService->lpDisplayName) + 1);

        /* Copy the status information */
        memcpy(&lpStatusPtr->ServiceStatus,
               &CurrentService->Status,
               sizeof(SERVICE_STATUS));

        lpStatusPtr++;
        dwRequiredSize += dwSize;
    }

    if (dwError == ERROR_SUCCESS)
    {
        *pcbBytesNeeded = 0;
        if (lpResumeIndex) *lpResumeIndex = 0;
    }

Done:
    /* Unlock the service database */
    ScmUnlockDatabase();

    DPRINT("REnumServiceGroupW() done (Error %lu)\n", dwError);

    return dwError;
}


/*
 * The levels of the service configuration the controller keeps: description, failure actions,
 * delayed automatic start, the failure actions flag, the service SID type, the required privileges,
 * the preshutdown timeout and the triggers
 */
static BOOL
ScmIsSupportedConfigLevel(DWORD dwInfoLevel)
{
    return dwInfoLevel == SERVICE_CONFIG_DESCRIPTION ||
           dwInfoLevel == SERVICE_CONFIG_FAILURE_ACTIONS ||
           dwInfoLevel == SERVICE_CONFIG_DELAYED_AUTO_START_INFO ||
           dwInfoLevel == SERVICE_CONFIG_FAILURE_ACTIONS_FLAG ||
           dwInfoLevel == SERVICE_CONFIG_SERVICE_SID_INFO ||
           dwInfoLevel == SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO ||
           dwInfoLevel == SERVICE_CONFIG_PRESHUTDOWN_INFO ||
           dwInfoLevel == SERVICE_CONFIG_TRIGGER_INFO;
}


/* The levels whose data is a single DWORD kept in a registry value of the service key */
static PCWSTR
ScmGetDwordConfigValueName(DWORD dwInfoLevel,
                           PDWORD pdwDefault)
{
    switch (dwInfoLevel)
    {
        case SERVICE_CONFIG_DELAYED_AUTO_START_INFO:
            *pdwDefault = 0;
            return L"DelayedAutostart";

        case SERVICE_CONFIG_SERVICE_SID_INFO:
            *pdwDefault = SERVICE_SID_TYPE_NONE;
            return L"ServiceSidType";

        case SERVICE_CONFIG_PRESHUTDOWN_INFO:
            *pdwDefault = 10000; /* what Windows reports when the value is absent */
            return L"PreshutdownTimeout";
    }

    return NULL;
}


static DWORD
ScmQueryDwordConfig(HKEY hServiceKey,
                    DWORD dwInfoLevel,
                    LPBYTE lpBuffer,
                    DWORD cbBufSize,
                    LPBOUNDED_DWORD_8K pcbBytesNeeded)
{
    DWORD dwValue, dwSize = sizeof(dwValue), dwType;
    PCWSTR pszName = ScmGetDwordConfigValueName(dwInfoLevel, &dwValue);

    *pcbBytesNeeded = sizeof(DWORD);
    if (cbBufSize < sizeof(DWORD))
        return ERROR_INSUFFICIENT_BUFFER;

    if (RegQueryValueExW(hServiceKey,
                         pszName,
                         NULL,
                         &dwType,
                         (LPBYTE)&dwValue,
                         &dwSize) != ERROR_SUCCESS || dwType != REG_DWORD)
        ScmGetDwordConfigValueName(dwInfoLevel, &dwValue);

    *(PDWORD)lpBuffer = dwValue;
    return ERROR_SUCCESS;
}


/*
 * SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO is kept as the REG_MULTI_SZ value RequiredPrivileges, and
 * SERVICE_CONFIG_TRIGGER_INFO as the key TriggerInfo of the service key, as Windows does:
 *
 *   TriggerInfo\<n>      Type (DWORD), Action (DWORD), Guid (the 16 bytes of the subtype), and for each
 *                        data item <i>: Data<i> (REG_BINARY) and DataType<i> (DWORD)
 */
/* Declared for Vista and later only, the services do not build for it; advapi32_vista has it */
LSTATUS WINAPI RegDeleteTreeW(_In_ HKEY, _In_opt_ LPCWSTR);

#define SCM_TRIGGER_KEY             L"TriggerInfo"
#define SCM_MAX_TRIGGERS            64
#define SCM_MAX_TRIGGER_DATA_ITEMS  64
#define SCM_MAX_TRIGGER_DATA        1024

/* Subtypes of the network endpoint trigger: an RPC interface, and a named pipe */
static const GUID ScmRpcInterfaceEventGuid =
    {0xbc90d167, 0x9470, 0x4139, {0xa9, 0xba, 0xbe, 0x0b, 0xbb, 0xf5, 0xb7, 0x4d}};
static const GUID ScmNamedPipeEventGuid =
    {0x1f81d131, 0x3fac, 0x4537, {0x9e, 0x0c, 0x7e, 0x7b, 0x0c, 0x2f, 0x4b, 0x55}};

typedef enum _SCM_PRIVILEGES_ACTION
{
    ScmPrivilegesIgnore,
    ScmPrivilegesDelete,
    ScmPrivilegesStore
} SCM_PRIVILEGES_ACTION;


/*
 * What a ChangeServiceConfig2 call with a list of required privileges does, as Windows does it:
 * the list ends with the first empty string, an empty list removes the setting, and a list with a
 * privilege that is not known leaves the setting as it is, without an error (Windows does the same
 * with one that has others that are known). It looks the names up, so the caller must not hold the
 * service database. *pcchNames is the length of the names with the terminators of each of them
 * (not of the list).
 */
static DWORD
ScmCheckRequiredPrivileges(const SERVICE_RPC_REQUIRED_PRIVILEGES_INFO *pInfo,
                           SCM_PRIVILEGES_ACTION *pAction,
                           PDWORD pcchNames)
{
    PCWSTR pszList = (PCWSTR)pInfo->pRequiredPrivileges;
    DWORD cchList = (pszList != NULL) ? pInfo->cbRequiredPrivileges / sizeof(WCHAR) : 0;
    DWORD i = 0, cchName, dwNames = 0, dwKnown = 0;
    LUID Luid;

    *pAction = ScmPrivilegesIgnore;
    *pcchNames = 0;

    while (i < cchList && pszList[i] != 0)
    {
        for (cchName = 0; i + cchName < cchList && pszList[i + cchName] != 0; cchName++)
            ;
        if (i + cchName >= cchList)
            return ERROR_INVALID_PARAMETER;   /* the last name has no terminator */

        dwNames++;
        if (LookupPrivilegeValueW(NULL, pszList + i, &Luid))
            dwKnown++;
        i += cchName + 1;
    }

    if (dwNames == 0)
    {
        *pAction = ScmPrivilegesDelete;
        return ERROR_SUCCESS;
    }

    if (dwKnown != dwNames)
        return ERROR_SUCCESS;

    *pAction = ScmPrivilegesStore;
    *pcchNames = i;
    return ERROR_SUCCESS;
}


static DWORD
ScmSetRequiredPrivileges(HKEY hServiceKey,
                         const SERVICE_RPC_REQUIRED_PRIVILEGES_INFO *pInfo,
                         SCM_PRIVILEGES_ACTION Action,
                         DWORD cchNames)
{
    PWSTR pszValue;
    DWORD dwError;

    if (Action == ScmPrivilegesDelete)
    {
        dwError = RegDeleteValueW(hServiceKey, L"RequiredPrivileges");
        return (dwError == ERROR_FILE_NOT_FOUND) ? ERROR_SUCCESS : dwError;
    }

    if (Action != ScmPrivilegesStore)
        return ERROR_SUCCESS;

    /* The names, then the empty string that ends the list */
    pszValue = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (cchNames + 1) * sizeof(WCHAR));
    if (pszValue == NULL)
        return ERROR_NOT_ENOUGH_MEMORY;

    RtlCopyMemory(pszValue, pInfo->pRequiredPrivileges, cchNames * sizeof(WCHAR));
    dwError = RegSetValueExW(hServiceKey,
                             L"RequiredPrivileges",
                             0,
                             REG_MULTI_SZ,
                             (LPBYTE)pszValue,
                             (cchNames + 1) * sizeof(WCHAR));
    HeapFree(GetProcessHeap(), 0, pszValue);
    return dwError;
}


/*
 * The required privileges for QueryServiceConfig2: a SERVICE_REQUIRED_PRIVILEGES_INFO whose pointer holds
 * the offset of the multi-string, which follows it, the caller makes the pointer. Without the setting the
 * pointer is NULL. The size needed is that of the Unicode string for both the Unicode and the ANSI call,
 * as Windows has it.
 */
static DWORD
ScmQueryRequiredPrivileges(HKEY hServiceKey,
                           BOOL bUnicode,
                           LPBYTE lpBuffer,
                           DWORD cbBufSize,
                           LPBOUNDED_DWORD_8K pcbBytesNeeded)
{
    PWSTR pszValue = NULL;
    DWORD dwType, dwSize = 0, cchList = 0, cbData = 0, i;
    DWORD dwError;

    dwError = RegQueryValueExW(hServiceKey, L"RequiredPrivileges", NULL, &dwType, NULL, &dwSize);
    if (dwError == ERROR_SUCCESS && dwType == REG_MULTI_SZ && dwSize >= sizeof(WCHAR))
    {
        pszValue = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize + 2 * sizeof(WCHAR));
        if (pszValue == NULL)
            return ERROR_NOT_ENOUGH_MEMORY;

        if (RegQueryValueExW(hServiceKey, L"RequiredPrivileges", NULL, &dwType,
                             (LPBYTE)pszValue, &dwSize) == ERROR_SUCCESS)
        {
            /* The list ends with the first empty string, which is part of it */
            for (i = 0; i < dwSize / sizeof(WCHAR) && pszValue[i] != 0; i += wcslen(pszValue + i) + 1)
                ;
            if (i > 0)
                cchList = i + 1;
        }
    }

    cbData = cchList * sizeof(WCHAR);

    *pcbBytesNeeded = sizeof(SERVICE_REQUIRED_PRIVILEGES_INFOW) + cbData;
    if (cbBufSize < *pcbBytesNeeded)
    {
        if (pszValue != NULL)
            HeapFree(GetProcessHeap(), 0, pszValue);
        return ERROR_INSUFFICIENT_BUFFER;
    }

    ((LPSERVICE_REQUIRED_PRIVILEGES_INFOW)lpBuffer)->pmszRequiredPrivileges =
        cbData ? (LPWSTR)(ULONG_PTR)sizeof(SERVICE_REQUIRED_PRIVILEGES_INFOW) : NULL;
    if (cbData)
    {
        if (bUnicode)
            RtlCopyMemory(lpBuffer + sizeof(SERVICE_REQUIRED_PRIVILEGES_INFOW), pszValue, cbData);
        else
            WideCharToMultiByte(CP_ACP, 0, pszValue, cchList,
                                (LPSTR)(lpBuffer + sizeof(SERVICE_REQUIRED_PRIVILEGES_INFOW)), cchList * sizeof(WCHAR), NULL, NULL);
    }

    if (pszValue != NULL)
        HeapFree(GetProcessHeap(), 0, pszValue);
    return ERROR_SUCCESS;
}


/*
 * Checks a trigger list as Windows does. A trigger needs a subtype, a start or stop action and one of the
 * types the SCM knows; the data items are binary, string, or the level and keyword filters of an ETW
 * provider (one byte, and eight); a device trigger takes strings, a group policy trigger takes no data and
 * an endpoint trigger an RPC interface or a pipe with its name.
 */
static DWORD
ScmCheckTriggerInfo(const SERVICE_TRIGGER_INFO *pInfo)
{
    DWORD i, j;

    if (pInfo->cTriggers > SCM_MAX_TRIGGERS ||
        (pInfo->cTriggers != 0 && pInfo->pTriggers == NULL))
        return ERROR_INVALID_PARAMETER;

    for (i = 0; i < pInfo->cTriggers; i++)
    {
        const SERVICE_TRIGGER *pTrigger = &pInfo->pTriggers[i];

        switch (pTrigger->dwTriggerType)
        {
            case SERVICE_TRIGGER_TYPE_DEVICE_INTERFACE_ARRIVAL:
            case SERVICE_TRIGGER_TYPE_IP_ADDRESS_AVAILABILITY:
            case SERVICE_TRIGGER_TYPE_DOMAIN_JOIN:
            case SERVICE_TRIGGER_TYPE_FIREWALL_PORT_EVENT:
            case SERVICE_TRIGGER_TYPE_GROUP_POLICY:
            case SERVICE_TRIGGER_TYPE_NETWORK_ENDPOINT:
            case SERVICE_TRIGGER_TYPE_CUSTOM:
                break;

            default:
                return ERROR_INVALID_PARAMETER;
        }

        if (pTrigger->dwAction != SERVICE_TRIGGER_ACTION_SERVICE_START &&
            pTrigger->dwAction != SERVICE_TRIGGER_ACTION_SERVICE_STOP)
            return ERROR_INVALID_PARAMETER;

        if (pTrigger->pTriggerSubtype == NULL)
            return ERROR_INVALID_PARAMETER;

        if (pTrigger->cDataItems > SCM_MAX_TRIGGER_DATA_ITEMS ||
            (pTrigger->cDataItems != 0 && pTrigger->pDataItems == NULL))
            return ERROR_INVALID_PARAMETER;

        for (j = 0; j < pTrigger->cDataItems; j++)
        {
            const SERVICE_TRIGGER_SPECIFIC_DATA_ITEM *pItem = &pTrigger->pDataItems[j];

            if (pItem->dwDataType < SERVICE_TRIGGER_DATA_TYPE_BINARY ||
                pItem->dwDataType > SERVICE_TRIGGER_DATA_TYPE_KEYWORD_ALL ||
                pItem->cbData == 0 || pItem->cbData > SCM_MAX_TRIGGER_DATA ||
                pItem->pData == NULL)
                return ERROR_INVALID_PARAMETER;

            if ((pItem->dwDataType == SERVICE_TRIGGER_DATA_TYPE_LEVEL && pItem->cbData != sizeof(BYTE)) ||
                ((pItem->dwDataType == SERVICE_TRIGGER_DATA_TYPE_KEYWORD_ANY ||
                  pItem->dwDataType == SERVICE_TRIGGER_DATA_TYPE_KEYWORD_ALL) && pItem->cbData != sizeof(ULONGLONG)))
                return ERROR_INVALID_PARAMETER;

            if (pTrigger->dwTriggerType == SERVICE_TRIGGER_TYPE_DEVICE_INTERFACE_ARRIVAL &&
                pItem->dwDataType != SERVICE_TRIGGER_DATA_TYPE_STRING)
                return ERROR_INVALID_PARAMETER;
        }

        if (pTrigger->dwTriggerType == SERVICE_TRIGGER_TYPE_GROUP_POLICY && pTrigger->cDataItems != 0)
            return ERROR_NOT_SUPPORTED;

        if (pTrigger->dwTriggerType == SERVICE_TRIGGER_TYPE_NETWORK_ENDPOINT)
        {
            if (!IsEqualGUID(pTrigger->pTriggerSubtype, &ScmRpcInterfaceEventGuid) &&
                !IsEqualGUID(pTrigger->pTriggerSubtype, &ScmNamedPipeEventGuid))
                return ERROR_NOT_FOUND;

            /* The endpoint is named by the data, and Windows has no better word for its absence */
            if (pTrigger->cDataItems == 0)
                return ERROR_ALREADY_EXISTS;
        }
    }

    return ERROR_SUCCESS;
}


/* The trigger list is checked. No triggers delete them, which is an error when there are none. */
static DWORD
ScmSetTriggerInfo(HKEY hServiceKey,
                  const SERVICE_TRIGGER_INFO *pInfo)
{
    HKEY hTriggersKey = NULL, hTriggerKey;
    WCHAR szName[32];
    DWORD i, j, dwError;

    if (pInfo->cTriggers == 0)
    {
        dwError = RegOpenKeyExW(hServiceKey, SCM_TRIGGER_KEY, 0, KEY_READ, &hTriggersKey);
        if (dwError != ERROR_SUCCESS)
            return ERROR_INVALID_PARAMETER;

        RegCloseKey(hTriggersKey);
        return RegDeleteTreeW(hServiceKey, SCM_TRIGGER_KEY);
    }

    /* The new list replaces the old one */
    dwError = RegDeleteTreeW(hServiceKey, SCM_TRIGGER_KEY);
    if (dwError != ERROR_SUCCESS && dwError != ERROR_FILE_NOT_FOUND)
        return dwError;

    dwError = RegCreateKeyExW(hServiceKey, SCM_TRIGGER_KEY, 0, NULL, REG_OPTION_NON_VOLATILE,
                              KEY_CREATE_SUB_KEY | KEY_SET_VALUE, NULL, &hTriggersKey, NULL);
    if (dwError != ERROR_SUCCESS)
        return dwError;

    for (i = 0; i < pInfo->cTriggers && dwError == ERROR_SUCCESS; i++)
    {
        const SERVICE_TRIGGER *pTrigger = &pInfo->pTriggers[i];

        StringCchPrintfW(szName, ARRAYSIZE(szName), L"%lu", i);
        dwError = RegCreateKeyExW(hTriggersKey, szName, 0, NULL, REG_OPTION_NON_VOLATILE,
                                  KEY_SET_VALUE, NULL, &hTriggerKey, NULL);
        if (dwError != ERROR_SUCCESS)
            break;

        dwError = RegSetValueExW(hTriggerKey, L"Type", 0, REG_DWORD,
                                 (LPBYTE)&pTrigger->dwTriggerType, sizeof(DWORD));
        if (dwError == ERROR_SUCCESS)
            dwError = RegSetValueExW(hTriggerKey, L"Action", 0, REG_DWORD,
                                     (LPBYTE)&pTrigger->dwAction, sizeof(DWORD));
        if (dwError == ERROR_SUCCESS)
            dwError = RegSetValueExW(hTriggerKey, L"Guid", 0, REG_BINARY,
                                     (LPBYTE)pTrigger->pTriggerSubtype, sizeof(GUID));

        for (j = 0; j < pTrigger->cDataItems && dwError == ERROR_SUCCESS; j++)
        {
            const SERVICE_TRIGGER_SPECIFIC_DATA_ITEM *pItem = &pTrigger->pDataItems[j];

            StringCchPrintfW(szName, ARRAYSIZE(szName), L"Data%lu", j);
            dwError = RegSetValueExW(hTriggerKey, szName, 0, REG_BINARY, pItem->pData, pItem->cbData);
            if (dwError == ERROR_SUCCESS)
            {
                StringCchPrintfW(szName, ARRAYSIZE(szName), L"DataType%lu", j);
                dwError = RegSetValueExW(hTriggerKey, szName, 0, REG_DWORD,
                                         (LPBYTE)&pItem->dwDataType, sizeof(DWORD));
            }
        }

        RegCloseKey(hTriggerKey);
    }

    RegCloseKey(hTriggersKey);

    /* Not a half list */
    if (dwError != ERROR_SUCCESS)
        RegDeleteTreeW(hServiceKey, SCM_TRIGGER_KEY);

    return dwError;
}


typedef struct _SCM_TRIGGER_DATA
{
    DWORD dwType;
    DWORD dwAction;
    GUID Guid;
    DWORD cItems;
    DWORD dwItemType[SCM_MAX_TRIGGER_DATA_ITEMS];
    DWORD cbItem[SCM_MAX_TRIGGER_DATA_ITEMS];
    PBYTE pItem[SCM_MAX_TRIGGER_DATA_ITEMS];
} SCM_TRIGGER_DATA, *PSCM_TRIGGER_DATA;


/* Reads a trigger of the registry; FALSE when there is no such trigger or it is incomplete */
static BOOL
ScmReadTrigger(HKEY hTriggersKey,
               DWORD dwIndex,
               PSCM_TRIGGER_DATA pTrigger)
{
    HKEY hTriggerKey;
    WCHAR szName[32];
    DWORD dwSize, dwType, j;
    BOOL bResult = FALSE;

    StringCchPrintfW(szName, ARRAYSIZE(szName), L"%lu", dwIndex);
    if (RegOpenKeyExW(hTriggersKey, szName, 0, KEY_READ, &hTriggerKey) != ERROR_SUCCESS)
        return FALSE;

    RtlZeroMemory(pTrigger, sizeof(*pTrigger));

    dwSize = sizeof(DWORD);
    if (RegQueryValueExW(hTriggerKey, L"Type", NULL, &dwType, (LPBYTE)&pTrigger->dwType, &dwSize) != ERROR_SUCCESS ||
        dwType != REG_DWORD)
        goto done;

    dwSize = sizeof(DWORD);
    if (RegQueryValueExW(hTriggerKey, L"Action", NULL, &dwType, (LPBYTE)&pTrigger->dwAction, &dwSize) != ERROR_SUCCESS ||
        dwType != REG_DWORD)
        goto done;

    dwSize = sizeof(GUID);
    if (RegQueryValueExW(hTriggerKey, L"Guid", NULL, &dwType, (LPBYTE)&pTrigger->Guid, &dwSize) != ERROR_SUCCESS ||
        dwType != REG_BINARY || dwSize != sizeof(GUID))
        goto done;

    for (j = 0; j < SCM_MAX_TRIGGER_DATA_ITEMS; j++)
    {
        PBYTE pData;
        DWORD cbData = 0, dwTypeSize = sizeof(DWORD);

        StringCchPrintfW(szName, ARRAYSIZE(szName), L"Data%lu", j);
        if (RegQueryValueExW(hTriggerKey, szName, NULL, &dwType, NULL, &cbData) != ERROR_SUCCESS)
            break;
        if (dwType != REG_BINARY || cbData == 0 || cbData > SCM_MAX_TRIGGER_DATA)
            goto done;

        pData = HeapAlloc(GetProcessHeap(), 0, cbData);
        if (pData == NULL)
            goto done;
        if (RegQueryValueExW(hTriggerKey, szName, NULL, &dwType, pData, &cbData) != ERROR_SUCCESS)
        {
            HeapFree(GetProcessHeap(), 0, pData);
            goto done;
        }

        StringCchPrintfW(szName, ARRAYSIZE(szName), L"DataType%lu", j);
        if (RegQueryValueExW(hTriggerKey, szName, NULL, &dwType,
                             (LPBYTE)&pTrigger->dwItemType[j], &dwTypeSize) != ERROR_SUCCESS)
            pTrigger->dwItemType[j] = SERVICE_TRIGGER_DATA_TYPE_BINARY;

        pTrigger->pItem[j] = pData;
        pTrigger->cbItem[j] = cbData;
        pTrigger->cItems = j + 1;
    }

    bResult = TRUE;

done:
    RegCloseKey(hTriggerKey);
    if (!bResult)
    {
        for (j = 0; j < pTrigger->cItems; j++)
            HeapFree(GetProcessHeap(), 0, pTrigger->pItem[j]);
        pTrigger->cItems = 0;
    }
    return bResult;
}


/*
 * The triggers for QueryServiceConfig2, in the layout Windows uses: the SERVICE_TRIGGER_INFO, the array of
 * triggers, then the data items and the subtype of each trigger, and last the data of the items, the last
 * item first. All pointers hold the offset in the buffer; the caller makes them pointers. The size is
 * that of the 64-bit layout on 64-bit.
 */
static DWORD
ScmQueryTriggerInfo(HKEY hServiceKey,
                    LPBYTE lpBuffer,
                    DWORD cbBufSize,
                    LPBOUNDED_DWORD_8K pcbBytesNeeded)
{
    HKEY hTriggersKey = NULL;
    PSCM_TRIGGER_DATA pTriggers = NULL;
    DWORD dwCount = 0, dwSize, dwOffset, i, j;
    SERVICE_TRIGGER_INFO *pInfo;
    SERVICE_TRIGGER *pOut;
    DWORD dwError = ERROR_SUCCESS;

    if (RegOpenKeyExW(hServiceKey, SCM_TRIGGER_KEY, 0, KEY_READ, &hTriggersKey) == ERROR_SUCCESS)
    {
        pTriggers = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SCM_MAX_TRIGGERS * sizeof(SCM_TRIGGER_DATA));
        if (pTriggers == NULL)
        {
            RegCloseKey(hTriggersKey);
            return ERROR_NOT_ENOUGH_MEMORY;
        }

        while (dwCount < SCM_MAX_TRIGGERS && ScmReadTrigger(hTriggersKey, dwCount, &pTriggers[dwCount]))
            dwCount++;

        RegCloseKey(hTriggersKey);
    }

    dwSize = sizeof(SERVICE_TRIGGER_INFO) + dwCount * sizeof(SERVICE_TRIGGER);
    for (i = 0; i < dwCount; i++)
    {
        dwSize += pTriggers[i].cItems * sizeof(SERVICE_TRIGGER_SPECIFIC_DATA_ITEM) + sizeof(GUID);
        for (j = 0; j < pTriggers[i].cItems; j++)
            dwSize += pTriggers[i].cbItem[j];
    }

    *pcbBytesNeeded = dwSize;
    if (cbBufSize < dwSize)
    {
        dwError = ERROR_INSUFFICIENT_BUFFER;
        goto done;
    }

    pInfo = (SERVICE_TRIGGER_INFO *)lpBuffer;
    pInfo->cTriggers = dwCount;
    pInfo->pTriggers = NULL;
    pInfo->pReserved = NULL;
    if (dwCount == 0)
        goto done;

    pOut = (SERVICE_TRIGGER *)(lpBuffer + sizeof(SERVICE_TRIGGER_INFO));
    pInfo->pTriggers = (PSERVICE_TRIGGER)(ULONG_PTR)sizeof(SERVICE_TRIGGER_INFO);
    dwOffset = sizeof(SERVICE_TRIGGER_INFO) + dwCount * sizeof(SERVICE_TRIGGER);

    for (i = 0; i < dwCount; i++)
    {
        pOut[i].dwTriggerType = pTriggers[i].dwType;
        pOut[i].dwAction = pTriggers[i].dwAction;
        pOut[i].cDataItems = pTriggers[i].cItems;
        pOut[i].pDataItems = NULL;

        if (pTriggers[i].cItems != 0)
        {
            pOut[i].pDataItems = (PSERVICE_TRIGGER_SPECIFIC_DATA_ITEM)(ULONG_PTR)dwOffset;
            dwOffset += pTriggers[i].cItems * sizeof(SERVICE_TRIGGER_SPECIFIC_DATA_ITEM);
        }

        pOut[i].pTriggerSubtype = (GUID *)(ULONG_PTR)dwOffset;
        RtlCopyMemory(lpBuffer + dwOffset, &pTriggers[i].Guid, sizeof(GUID));
        dwOffset += sizeof(GUID);
    }

    for (i = dwCount; i-- > 0;)
    {
        SERVICE_TRIGGER_SPECIFIC_DATA_ITEM *pItems = (SERVICE_TRIGGER_SPECIFIC_DATA_ITEM *)
            (lpBuffer + (ULONG_PTR)pOut[i].pDataItems);

        for (j = pTriggers[i].cItems; j-- > 0;)
        {
            pItems[j].dwDataType = pTriggers[i].dwItemType[j];
            pItems[j].cbData = pTriggers[i].cbItem[j];
            pItems[j].pData = (PBYTE)(ULONG_PTR)dwOffset;
            RtlCopyMemory(lpBuffer + dwOffset, pTriggers[i].pItem[j], pTriggers[i].cbItem[j]);
            dwOffset += pTriggers[i].cbItem[j];
        }
    }

done:
    if (pTriggers != NULL)
    {
        for (i = 0; i < dwCount; i++)
            for (j = 0; j < pTriggers[i].cItems; j++)
                HeapFree(GetProcessHeap(), 0, pTriggers[i].pItem[j]);
        HeapFree(GetProcessHeap(), 0, pTriggers);
    }

    return dwError;
}


/* Function 36 */
DWORD
WINAPI
RChangeServiceConfig2A(
    SC_RPC_HANDLE hService,
    SC_RPC_CONFIG_INFOA Info)
{
    SC_RPC_CONFIG_INFOW InfoW = { 0 };
    SERVICE_RPC_REQUIRED_PRIVILEGES_INFO PrivilegesW;
    DWORD dwRet, dwLength;
    PVOID ptr = NULL;

    DPRINT("RChangeServiceConfig2A() called\n");
    DPRINT("dwInfoLevel = %lu\n", Info.dwInfoLevel);

    if (!ScmIsSupportedConfigLevel(Info.dwInfoLevel))
    {
        return ERROR_INVALID_LEVEL;
    }

    InfoW.dwInfoLevel = Info.dwInfoLevel;

    if (InfoW.dwInfoLevel == SERVICE_CONFIG_DESCRIPTION)
    {
        LPSERVICE_DESCRIPTIONW lpServiceDescriptionW;
        LPSERVICE_DESCRIPTIONA lpServiceDescriptionA;

        lpServiceDescriptionA = Info.psd;

        if (lpServiceDescriptionA &&
            lpServiceDescriptionA->lpDescription)
        {
            dwLength = (DWORD)((strlen(lpServiceDescriptionA->lpDescription) + 1) * sizeof(WCHAR));

            lpServiceDescriptionW = HeapAlloc(GetProcessHeap(),
                                              HEAP_ZERO_MEMORY,
                                              dwLength + sizeof(SERVICE_DESCRIPTIONW));
            if (!lpServiceDescriptionW)
            {
                return ERROR_NOT_ENOUGH_MEMORY;
            }

            lpServiceDescriptionW->lpDescription = (LPWSTR)(lpServiceDescriptionW + 1);

            MultiByteToWideChar(CP_ACP,
                                0,
                                lpServiceDescriptionA->lpDescription,
                                -1,
                                lpServiceDescriptionW->lpDescription,
                                dwLength);

            ptr = lpServiceDescriptionW;
            InfoW.psd = lpServiceDescriptionW;
        }
    }
    else if (Info.dwInfoLevel == SERVICE_CONFIG_FAILURE_ACTIONS)
    {
        LPSERVICE_FAILURE_ACTIONSW lpServiceFailureActionsW;
        LPSERVICE_FAILURE_ACTIONSA lpServiceFailureActionsA;
        DWORD dwRebootLen  = 0;
        DWORD dwCommandLen = 0;
        DWORD dwActionArrayLen = 0;
        LPWSTR lpStr = NULL;

        lpServiceFailureActionsA = Info.psfa;

        if (lpServiceFailureActionsA)
        {
            /*
             * The following code is inspired by the
             * SERVICE_CONFIG_FAILURE_ACTIONS case of
             * the RQueryServiceConfig2W function.
             */

            /* Retrieve the needed length for the two data strings */
            if (lpServiceFailureActionsA->lpRebootMsg)
            {
                dwRebootLen = (DWORD)((strlen(lpServiceFailureActionsA->lpRebootMsg) + 1) * sizeof(WCHAR));
            }
            if (lpServiceFailureActionsA->lpCommand)
            {
                dwCommandLen = (DWORD)((strlen(lpServiceFailureActionsA->lpCommand) + 1) * sizeof(WCHAR));
            }

            /*
             * Retrieve the size of the lpsaActions array if needed.
             * We will copy the lpsaActions array only if there is at
             * least one action AND that the original array is valid.
             */
            if (lpServiceFailureActionsA->cActions > 0 && lpServiceFailureActionsA->lpsaActions)
            {
                dwActionArrayLen = lpServiceFailureActionsA->cActions * sizeof(SC_ACTION);
            }

            /* Compute the total length for the UNICODE structure, including data */
            dwLength = sizeof(SERVICE_FAILURE_ACTIONSW) +
                       dwActionArrayLen + dwRebootLen + dwCommandLen;

            /* Allocate the structure */
            lpServiceFailureActionsW = HeapAlloc(GetProcessHeap(),
                                                 HEAP_ZERO_MEMORY,
                                                 dwLength);
            if (!lpServiceFailureActionsW)
            {
                return ERROR_NOT_ENOUGH_MEMORY;
            }

            /* Copy the members */
            lpServiceFailureActionsW->dwResetPeriod = lpServiceFailureActionsA->dwResetPeriod;
            lpServiceFailureActionsW->cActions      = lpServiceFailureActionsA->cActions;

            /* Copy the lpsaActions array if needed */
            if (dwActionArrayLen > 0)
            {
                /* The storage zone is just after the end of the SERVICE_FAILURE_ACTIONSW structure */
                lpServiceFailureActionsW->lpsaActions = (LPSC_ACTION)((ULONG_PTR)(lpServiceFailureActionsW + 1));

                /* dwActionArrayLen == lpServiceFailureActionsW->cActions * sizeof(SC_ACTION) */
                RtlCopyMemory(lpServiceFailureActionsW->lpsaActions,
                              lpServiceFailureActionsA->lpsaActions,
                              dwActionArrayLen);
            }
            else
            {
                /* No lpsaActions array */
                lpServiceFailureActionsW->lpsaActions = NULL;
            }
            /* The data strings are stored just after the lpsaActions array */
            lpStr = (LPWSTR)((ULONG_PTR)(lpServiceFailureActionsW + 1) + dwActionArrayLen);

            /*
             * Convert the data strings to UNICODE
             */

            lpServiceFailureActionsW->lpRebootMsg = NULL;
            lpServiceFailureActionsW->lpCommand   = NULL;

            if (dwRebootLen)
            {
                /* lpRebootMsg points just after the lpsaActions array */
                lpServiceFailureActionsW->lpRebootMsg = lpStr;

                MultiByteToWideChar(CP_ACP,
                                    0,
                                    lpServiceFailureActionsA->lpRebootMsg,
                                    -1,
                                    lpServiceFailureActionsW->lpRebootMsg,
                                    dwRebootLen);

                lpStr += dwRebootLen / sizeof(WCHAR);
            }

            if (dwCommandLen)
            {
                /* lpRebootMsg points just after the lpRebootMsg data string */
                lpServiceFailureActionsW->lpCommand = lpStr;

                MultiByteToWideChar(CP_ACP,
                                    0,
                                    lpServiceFailureActionsA->lpCommand,
                                    -1,
                                    lpServiceFailureActionsW->lpCommand,
                                    dwCommandLen);
            }

            /* Set the pointers */
            ptr = lpServiceFailureActionsW;
            InfoW.psfa = lpServiceFailureActionsW;
        }
    }

    else if (Info.dwInfoLevel == SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO)
    {
        /* The list of privileges is converted to Unicode; the bytes are characters */
        if (Info.psrp && Info.psrp->pRequiredPrivileges)
        {
            LPWSTR lpPrivilegesW;

            dwLength = Info.psrp->cbRequiredPrivileges;
            lpPrivilegesW = HeapAlloc(GetProcessHeap(),
                                      HEAP_ZERO_MEMORY,
                                      (dwLength + 1) * sizeof(WCHAR));
            if (!lpPrivilegesW)
                return ERROR_NOT_ENOUGH_MEMORY;

            if (dwLength != 0)
            {
                MultiByteToWideChar(CP_ACP,
                                    0,
                                    (LPCSTR)Info.psrp->pRequiredPrivileges,
                                    dwLength,
                                    lpPrivilegesW,
                                    dwLength);
            }

            PrivilegesW.cbRequiredPrivileges = dwLength * sizeof(WCHAR);
            PrivilegesW.pRequiredPrivileges = (PBYTE)lpPrivilegesW;
            ptr = lpPrivilegesW;
            InfoW.psrp = &PrivilegesW;
        }
    }

    if (InfoW.dwInfoLevel == SERVICE_CONFIG_FAILURE_ACTIONS_FLAG)
        InfoW.psfaf = Info.psfaf;
    else if (InfoW.dwInfoLevel == SERVICE_CONFIG_DELAYED_AUTO_START_INFO)
        InfoW.psda = Info.psda;
    else if (InfoW.dwInfoLevel == SERVICE_CONFIG_SERVICE_SID_INFO)
        InfoW.pssid = Info.pssid;
    else if (InfoW.dwInfoLevel == SERVICE_CONFIG_PRESHUTDOWN_INFO)
        InfoW.psps = Info.psps;
    else if (InfoW.dwInfoLevel == SERVICE_CONFIG_TRIGGER_INFO)
        InfoW.psti = Info.psti;

    dwRet = RChangeServiceConfig2W(hService, InfoW);

    HeapFree(GetProcessHeap(), 0, ptr);

    return dwRet;
}


/*
 * The FailureActions registry value has the same layout on every architecture:
 * five DWORDs (reset period, reboot message offset, command offset, action
 * count, offset of the action array) followed by the SC_ACTION array. The
 * reboot message and the command are stored in their own values.
 */
#define FAILURE_ACTIONS_HEADER_SIZE (5 * sizeof(DWORD))

DWORD
ScmReadFailureActions(HKEY hServiceKey,
                      PDWORD pdwResetPeriod,
                      PDWORD pcActions,
                      LPSC_ACTION *ppActions)
{
    PBYTE pValue = NULL;
    DWORD dwType = 0;
    DWORD dwSize = 0;
    DWORD dwOffset, cActions, dwError;

    *pdwResetPeriod = 0;
    *pcActions = 0;
    *ppActions = NULL;

    dwError = RegQueryValueExW(hServiceKey,
                               L"FailureActions",
                               NULL,
                               &dwType,
                               NULL,
                               &dwSize);
    if (dwError != ERROR_SUCCESS)
        return dwError;

    if (dwType != REG_BINARY || dwSize < FAILURE_ACTIONS_HEADER_SIZE)
        return ERROR_INVALID_DATA;

    pValue = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    if (pValue == NULL)
        return ERROR_NOT_ENOUGH_MEMORY;

    dwError = RegQueryValueExW(hServiceKey,
                               L"FailureActions",
                               NULL,
                               NULL,
                               pValue,
                               &dwSize);
    if (dwError != ERROR_SUCCESS)
        goto done;

    if (dwSize < FAILURE_ACTIONS_HEADER_SIZE)
    {
        dwError = ERROR_INVALID_DATA;
        goto done;
    }

    cActions = ((PDWORD)pValue)[3];
    dwOffset = ((PDWORD)pValue)[4];

    /* Values written before the offset was stored have 0 here */
    if (dwOffset < FAILURE_ACTIONS_HEADER_SIZE)
        dwOffset = FAILURE_ACTIONS_HEADER_SIZE;

#ifdef _WIN64
    /* Earlier amd64 builds stored the 40-byte in-memory structure: the count at byte 24 and the actions at byte 40 */
    if (cActions == 0 && dwSize >= 40 && ((PDWORD)pValue)[6] != 0 &&
        dwSize == 40 + ((PDWORD)pValue)[6] * sizeof(SC_ACTION))
    {
        cActions = ((PDWORD)pValue)[6];
        dwOffset = 40;
    }
#endif

    if (dwOffset >= dwSize)
        cActions = 0;
    else
        cActions = min(cActions, (dwSize - dwOffset) / sizeof(SC_ACTION));

    if (cActions > 0)
    {
        *ppActions = HeapAlloc(GetProcessHeap(), 0, cActions * sizeof(SC_ACTION));
        if (*ppActions == NULL)
        {
            dwError = ERROR_NOT_ENOUGH_MEMORY;
            goto done;
        }

        RtlCopyMemory(*ppActions, pValue + dwOffset, cActions * sizeof(SC_ACTION));
    }

    *pdwResetPeriod = ((PDWORD)pValue)[0];
    *pcActions = cActions;

done:
    HeapFree(GetProcessHeap(), 0, pValue);
    return dwError;
}


static DWORD
ScmSetFailureActions(HKEY hServiceKey,
                     LPSERVICE_FAILURE_ACTIONSW lpFailureActions)
{
    LPSC_ACTION lpOldActions = NULL;
    PBYTE pWriteBuffer = NULL;
    DWORD dwOldResetPeriod = 0;
    DWORD cOldActions = 0;
    DWORD dwResetPeriod, cActions;
    LPSC_ACTION lpActions;
    DWORD dwRequiredSize = 0;
    DWORD dwError;

    /* There is nothing to be done if we have no failure actions */
    if (lpFailureActions == NULL)
        return ERROR_SUCCESS;

    /* Retrieve the original value of FailureActions (none if it is missing or invalid) */
    dwError = ScmReadFailureActions(hServiceKey,
                                    &dwOldResetPeriod,
                                    &cOldActions,
                                    &lpOldActions);
    if (dwError != ERROR_SUCCESS &&
        dwError != ERROR_FILE_NOT_FOUND &&
        dwError != ERROR_INVALID_DATA)
        return dwError;

    if (lpFailureActions->lpsaActions == NULL)
    {
        /*
         * lpFailureActions->dwResetPeriod and lpFailureActions->cActions are ignored.
         * Therefore we use the original values of dwResetPeriod, cActions and the actions.
         */
        dwResetPeriod = dwOldResetPeriod;
        cActions = cOldActions;
        lpActions = lpOldActions;
    }
    else if (lpFailureActions->cActions > 0)
    {
        dwResetPeriod = lpFailureActions->dwResetPeriod;
        cActions = lpFailureActions->cActions;
        lpActions = lpFailureActions->lpsaActions;
    }
    else
    {
        /* The reset period and array of failure actions are deleted */
        dwResetPeriod = 0;
        cActions = 0;
        lpActions = NULL;
    }

    dwRequiredSize = FAILURE_ACTIONS_HEADER_SIZE + cActions * sizeof(SC_ACTION);
    pWriteBuffer = HeapAlloc(GetProcessHeap(),
                             HEAP_ZERO_MEMORY,
                             dwRequiredSize);
    if (pWriteBuffer == NULL)
    {
        dwError = ERROR_NOT_ENOUGH_MEMORY;
        goto done;
    }

    ((PDWORD)pWriteBuffer)[0] = dwResetPeriod;
    ((PDWORD)pWriteBuffer)[3] = cActions;
    ((PDWORD)pWriteBuffer)[4] = FAILURE_ACTIONS_HEADER_SIZE;

    if (cActions > 0)
    {
        RtlCopyMemory(pWriteBuffer + FAILURE_ACTIONS_HEADER_SIZE,
                      lpActions,
                      cActions * sizeof(SC_ACTION));
    }

    /* Save the new failure actions into the registry */
    dwError = RegSetValueExW(hServiceKey,
                             L"FailureActions",
                             0,
                             REG_BINARY,
                             pWriteBuffer,
                             dwRequiredSize);

    /* We modify the strings only in case of success.*/
    if (dwError == ERROR_SUCCESS)
    {
        /* Modify the Reboot Message value, if specified */
        if (lpFailureActions->lpRebootMsg != NULL)
        {
            /* If the Reboot Message is "" then we delete it */
            if (*lpFailureActions->lpRebootMsg == 0)
            {
                DPRINT("Delete Reboot Message value\n");
                RegDeleteValueW(hServiceKey, L"RebootMessage");
            }
            else
            {
                DPRINT("Setting Reboot Message value %S\n", lpFailureActions->lpRebootMsg);
                RegSetValueExW(hServiceKey,
                               L"RebootMessage",
                               0,
                               REG_SZ,
                               (LPBYTE)lpFailureActions->lpRebootMsg,
                               (DWORD)((wcslen(lpFailureActions->lpRebootMsg) + 1) * sizeof(WCHAR)));
            }
        }

        /* Modify the Failure Command value, if specified */
        if (lpFailureActions->lpCommand != NULL)
        {
            /* If the FailureCommand string is an empty string, delete the value */
            if (*lpFailureActions->lpCommand == 0)
            {
                DPRINT("Delete Failure Command value\n");
                RegDeleteValueW(hServiceKey, L"FailureCommand");
            }
            else
            {
                DPRINT("Setting Failure Command value %S\n", lpFailureActions->lpCommand);
                RegSetValueExW(hServiceKey,
                               L"FailureCommand",
                               0,
                               REG_SZ,
                               (LPBYTE)lpFailureActions->lpCommand,
                               (DWORD)((wcslen(lpFailureActions->lpCommand) + 1) * sizeof(WCHAR)));
            }
        }
    }

done:
    if (pWriteBuffer != NULL)
        HeapFree(GetProcessHeap(), 0, pWriteBuffer);

    if (lpOldActions != NULL)
        HeapFree(GetProcessHeap(), 0, lpOldActions);

    return dwError;
}


/* Function 37 */
DWORD
WINAPI
RChangeServiceConfig2W(
    SC_RPC_HANDLE hService,
    SC_RPC_CONFIG_INFOW Info)
{
    DWORD dwError = ERROR_SUCCESS;
    PSERVICE_HANDLE hSvc;
    PSERVICE lpService = NULL;
    HKEY hServiceKey = NULL;
    ACCESS_MASK RequiredAccess = SERVICE_CHANGE_CONFIG;
    SCM_PRIVILEGES_ACTION PrivilegesAction = ScmPrivilegesIgnore;
    DWORD cchPrivileges = 0;

    DPRINT("RChangeServiceConfig2W() called\n");
    DPRINT("dwInfoLevel = %lu\n", Info.dwInfoLevel);

    if (ScmShutdown)
        return ERROR_SHUTDOWN_IN_PROGRESS;

    if (!ScmIsSupportedConfigLevel(Info.dwInfoLevel))
    {
        return ERROR_INVALID_LEVEL;
    }

    hSvc = ScmGetServiceFromHandle(hService);
    if (hSvc == NULL)
    {
        DPRINT("Invalid service handle\n");
        return ERROR_INVALID_HANDLE;
    }

    if (Info.dwInfoLevel == SERVICE_CONFIG_FAILURE_ACTIONS)
        RequiredAccess |= SERVICE_START;

    /* Check the access rights */
    if (!RtlAreAllAccessesGranted(hSvc->Handle.DesiredAccess,
                                  RequiredAccess))
    {
        DPRINT("Insufficient access rights! 0x%lx\n", hSvc->Handle.DesiredAccess);
        return ERROR_ACCESS_DENIED;
    }

    if (Info.dwInfoLevel == SERVICE_CONFIG_FAILURE_ACTIONS)
    {
        /* FIXME: Check if the caller has the SE_SHUTDOWN_NAME privilege */

    }

    lpService = hSvc->ServiceEntry;
    if (lpService == NULL)
    {
        DPRINT("lpService == NULL\n");
        return ERROR_INVALID_HANDLE;
    }

    /* Failure actions can only be set for Win32 services, not for drivers */
    if (Info.dwInfoLevel == SERVICE_CONFIG_FAILURE_ACTIONS ||
        Info.dwInfoLevel == SERVICE_CONFIG_FAILURE_ACTIONS_FLAG)
    {
        if (lpService->Status.dwServiceType & SERVICE_DRIVER)
            return ERROR_CANNOT_DETECT_DRIVER_FAILURE;
    }

    /* Check what is going to be stored before the database is locked: the privileges are looked up in the LSA */
    if (Info.dwInfoLevel == SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO && Info.psrp != NULL)
    {
        dwError = ScmCheckRequiredPrivileges(Info.psrp, &PrivilegesAction, &cchPrivileges);
        if (dwError != ERROR_SUCCESS)
            return dwError;
    }
    else if (Info.dwInfoLevel == SERVICE_CONFIG_TRIGGER_INFO && Info.psti != NULL)
    {
        dwError = ScmCheckTriggerInfo(Info.psti);
        if (dwError != ERROR_SUCCESS)
            return dwError;
    }

    /* Lock the service database exclusively */
    ScmLockDatabaseExclusive();

    if (lpService->bDeleted)
    {
        DPRINT("Service has already been marked for delete\n");
        dwError = ERROR_SERVICE_MARKED_FOR_DELETE;
        goto done;
    }

    /* Open the service key */
    dwError = ScmOpenServiceKey(lpService->szServiceName,
                                KEY_READ | KEY_SET_VALUE | KEY_CREATE_SUB_KEY,
                                &hServiceKey);
    if (dwError != ERROR_SUCCESS)
        goto done;

    if (Info.dwInfoLevel == SERVICE_CONFIG_DESCRIPTION)
    {
        LPSERVICE_DESCRIPTIONW lpServiceDescription = (LPSERVICE_DESCRIPTIONW)Info.psd;

        /* Modify the service description, if specified */
        if (lpServiceDescription != NULL &&
            lpServiceDescription->lpDescription != NULL)
        {
            /* If the description is "" then we delete it */
            if (*lpServiceDescription->lpDescription == 0)
            {
                DPRINT("Delete service description\n");
                dwError = RegDeleteValueW(hServiceKey, L"Description");

                if (dwError == ERROR_FILE_NOT_FOUND)
                    dwError = ERROR_SUCCESS;
            }
            else
            {
                DPRINT("Setting service description value %S\n", lpServiceDescription->lpDescription);
                dwError = RegSetValueExW(hServiceKey,
                                         L"Description",
                                         0,
                                         REG_SZ,
                                         (LPBYTE)lpServiceDescription->lpDescription,
                                         (DWORD)((wcslen(lpServiceDescription->lpDescription) + 1) * sizeof(WCHAR)));
            }
        }
        else
        {
            dwError = ERROR_SUCCESS;
        }
    }
    else if (Info.dwInfoLevel == SERVICE_CONFIG_FAILURE_ACTIONS)
    {
        dwError = ScmSetFailureActions(hServiceKey,
                                       (LPSERVICE_FAILURE_ACTIONSW)Info.psfa);
    }
    else if (Info.dwInfoLevel == SERVICE_CONFIG_FAILURE_ACTIONS_FLAG)
    {
        /* Without a structure there is nothing to change */
        if (Info.psfaf != NULL)
        {
            DWORD dwFlag = Info.psfaf->fFailureActionsOnNonCrashFailures ? 1 : 0;

            dwError = RegSetValueExW(hServiceKey,
                                     L"FailureActionsOnNonCrashFailures",
                                     0,
                                     REG_DWORD,
                                     (LPBYTE)&dwFlag,
                                     sizeof(dwFlag));
            if (dwError == ERROR_SUCCESS)
                lpService->bFailureOnNonCrash = (dwFlag != 0);
        }
    }
    else if (Info.dwInfoLevel == SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO)
    {
        /* Without a structure there is nothing to change */
        if (Info.psrp != NULL)
            dwError = ScmSetRequiredPrivileges(hServiceKey, Info.psrp, PrivilegesAction, cchPrivileges);
    }
    else if (Info.dwInfoLevel == SERVICE_CONFIG_TRIGGER_INFO)
    {
        /* Without a structure there is nothing to change */
        if (Info.psti != NULL)
            dwError = ScmSetTriggerInfo(hServiceKey, Info.psti);
    }
    else if (Info.dwInfoLevel == SERVICE_CONFIG_DELAYED_AUTO_START_INFO ||
             Info.dwInfoLevel == SERVICE_CONFIG_SERVICE_SID_INFO ||
             Info.dwInfoLevel == SERVICE_CONFIG_PRESHUTDOWN_INFO)
    {
        DWORD dwValue, dwDefault;
        PCWSTR pszName = ScmGetDwordConfigValueName(Info.dwInfoLevel, &dwDefault);

        /* Without a structure there is nothing to change */
        if (Info.psda != NULL)
        {
            if (Info.dwInfoLevel == SERVICE_CONFIG_DELAYED_AUTO_START_INFO)
                dwValue = (DWORD)Info.psda->fDelayedAutoStart;
            else if (Info.dwInfoLevel == SERVICE_CONFIG_SERVICE_SID_INFO)
                dwValue = Info.pssid->dwServicesSidType;
            else
                dwValue = Info.psps->dwPreshutdownTimeout;

            /* Windows accepts only FALSE and TRUE as the delayed start flag, and only the three SID types */
            if ((Info.dwInfoLevel == SERVICE_CONFIG_DELAYED_AUTO_START_INFO && dwValue > 1) ||
                (Info.dwInfoLevel == SERVICE_CONFIG_SERVICE_SID_INFO &&
                 dwValue != SERVICE_SID_TYPE_NONE &&
                 dwValue != SERVICE_SID_TYPE_UNRESTRICTED &&
                 dwValue != SERVICE_SID_TYPE_RESTRICTED))
            {
                dwError = ERROR_INVALID_PARAMETER;
            }
            else
            {
                dwError = RegSetValueExW(hServiceKey,
                                         pszName,
                                         0,
                                         REG_DWORD,
                                         (LPBYTE)&dwValue,
                                         sizeof(dwValue));
            }
        }
    }

done:
    if (hServiceKey != NULL)
        RegCloseKey(hServiceKey);

    /* Unlock the service database */
    ScmUnlockDatabase();

    DPRINT("RChangeServiceConfig2W() done (Error %lu)\n", dwError);

    return dwError;
}


/* Function 38 */
DWORD
WINAPI
RQueryServiceConfig2A(
    SC_RPC_HANDLE hService,
    DWORD dwInfoLevel,
    LPBYTE lpBuffer,
    DWORD cbBufSize,
    LPBOUNDED_DWORD_8K pcbBytesNeeded)
{
    DWORD dwError = ERROR_SUCCESS;
    PSERVICE_HANDLE hSvc;
    PSERVICE lpService = NULL;
    HKEY hServiceKey = NULL;
    DWORD dwRequiredSize = 0;
    LPSC_ACTION lpActions = NULL;
    LPWSTR lpDescriptionW = NULL;
    LPWSTR lpRebootMessageW = NULL;
    LPWSTR lpFailureCommandW = NULL;

    DPRINT("RQueryServiceConfig2A() called hService %p dwInfoLevel %u, lpBuffer %p cbBufSize %u pcbBytesNeeded %p\n",
           hService, dwInfoLevel, lpBuffer, cbBufSize, pcbBytesNeeded);

    if (!lpBuffer)
        return ERROR_INVALID_ADDRESS;

    if (ScmShutdown)
        return ERROR_SHUTDOWN_IN_PROGRESS;

    if (!ScmIsSupportedConfigLevel(dwInfoLevel))
    {
        return ERROR_INVALID_LEVEL;
    }

    hSvc = ScmGetServiceFromHandle(hService);
    if (hSvc == NULL)
    {
        DPRINT1("Invalid service handle\n");
        return ERROR_INVALID_HANDLE;
    }

    if (!RtlAreAllAccessesGranted(hSvc->Handle.DesiredAccess,
                                  SERVICE_QUERY_CONFIG))
    {
        DPRINT("Insufficient access rights! 0x%lx\n", hSvc->Handle.DesiredAccess);
        return ERROR_ACCESS_DENIED;
    }

    lpService = hSvc->ServiceEntry;
    if (lpService == NULL)
    {
        DPRINT("lpService == NULL\n");
        return ERROR_INVALID_HANDLE;
    }

    /* Lock the service database shared */
    ScmLockDatabaseShared();

    dwError = ScmOpenServiceKey(lpService->lpServiceName,
                                KEY_READ,
                                &hServiceKey);
    if (dwError != ERROR_SUCCESS)
        goto done;

    if (dwInfoLevel == SERVICE_CONFIG_DESCRIPTION)
    {
        LPSERVICE_DESCRIPTIONA lpServiceDescription = (LPSERVICE_DESCRIPTIONA)lpBuffer;
        LPSTR lpStr;

        dwError = ScmReadString(hServiceKey,
                                L"Description",
                                &lpDescriptionW);
        if (dwError != ERROR_SUCCESS && dwError != ERROR_FILE_NOT_FOUND)
            goto done;

        *pcbBytesNeeded = sizeof(SERVICE_DESCRIPTIONA);
        if (dwError == ERROR_SUCCESS)
            *pcbBytesNeeded += (DWORD)((wcslen(lpDescriptionW) + 1) * sizeof(WCHAR));

        if (cbBufSize < *pcbBytesNeeded)
        {
            dwError = ERROR_INSUFFICIENT_BUFFER;
            goto done;
        }

        if (dwError == ERROR_SUCCESS)
        {
            lpStr = (LPSTR)(lpServiceDescription + 1);

            WideCharToMultiByte(CP_ACP,
                                0,
                                lpDescriptionW,
                                -1,
                                lpStr,
                                (int)wcslen(lpDescriptionW),
                                NULL,
                                NULL);
            lpServiceDescription->lpDescription = (LPSTR)((ULONG_PTR)lpStr - (ULONG_PTR)lpServiceDescription);
        }
        else
        {
            lpServiceDescription->lpDescription = NULL;
            dwError = ERROR_SUCCESS;
        }
    }
    else if (dwInfoLevel == SERVICE_CONFIG_FAILURE_ACTIONS)
    {
        LPSERVICE_FAILURE_ACTIONSA lpFailureActions = (LPSERVICE_FAILURE_ACTIONSA)lpBuffer;
        LPSTR lpStr = NULL;

        DWORD dwResetPeriod = 0;
        DWORD cActions = 0;

        /* A missing or invalid value means that no failure actions are set */
        dwError = ScmReadFailureActions(hServiceKey,
                                        &dwResetPeriod,
                                        &cActions,
                                        &lpActions);
        if (dwError != ERROR_SUCCESS &&
            dwError != ERROR_FILE_NOT_FOUND &&
            dwError != ERROR_INVALID_DATA)
            goto done;

        dwRequiredSize = sizeof(SERVICE_FAILURE_ACTIONSA) + cActions * sizeof(SC_ACTION);

        /* Get the strings */
        ScmReadString(hServiceKey,
                      L"FailureCommand",
                      &lpFailureCommandW);

        ScmReadString(hServiceKey,
                      L"RebootMessage",
                      &lpRebootMessageW);

        if (lpRebootMessageW)
            dwRequiredSize += (DWORD)((wcslen(lpRebootMessageW) + 1) * sizeof(WCHAR));

        if (lpFailureCommandW)
            dwRequiredSize += (DWORD)((wcslen(lpFailureCommandW) + 1) * sizeof(WCHAR));

        if (cbBufSize < dwRequiredSize)
        {
            *pcbBytesNeeded = dwRequiredSize;
            dwError = ERROR_INSUFFICIENT_BUFFER;
            goto done;
        }

        lpFailureActions->dwResetPeriod = dwResetPeriod;
        lpFailureActions->cActions = cActions;
        lpFailureActions->lpsaActions = NULL;

        if (cActions > 0)
        {
            /* Here lpFailureActions->lpsaActions contains an offset. The conversion is done by the caller. */
            lpFailureActions->lpsaActions = (LPSC_ACTION)(ULONG_PTR)sizeof(SERVICE_FAILURE_ACTIONSA);
            RtlCopyMemory(lpFailureActions + 1, lpActions, cActions * sizeof(SC_ACTION));
        }

        lpStr = (LPSTR)((ULONG_PTR)(lpFailureActions + 1) + cActions * sizeof(SC_ACTION));

        lpFailureActions->lpRebootMsg = NULL;
        lpFailureActions->lpCommand = NULL;

        if (lpRebootMessageW)
        {
            WideCharToMultiByte(CP_ACP,
                                0,
                                lpRebootMessageW,
                                -1,
                                lpStr,
                                (int)((wcslen(lpRebootMessageW) + 1) * sizeof(WCHAR)),
                                NULL,
                                NULL);
            lpFailureActions->lpRebootMsg = (LPSTR)((ULONG_PTR)lpStr - (ULONG_PTR)lpFailureActions);
            lpStr += strlen(lpStr) + 1;
        }

        if (lpFailureCommandW)
        {
            WideCharToMultiByte(CP_ACP,
                                0,
                                lpFailureCommandW,
                                -1,
                                lpStr,
                                (int)((wcslen(lpFailureCommandW) + 1) * sizeof(WCHAR)),
                                NULL,
                                NULL);
            lpFailureActions->lpCommand = (LPSTR)((ULONG_PTR)lpStr - (ULONG_PTR)lpFailureActions);
            /* lpStr += strlen(lpStr) + 1; */
        }

        dwError = ERROR_SUCCESS;
    }
    else if (dwInfoLevel == SERVICE_CONFIG_FAILURE_ACTIONS_FLAG)
    {
        LPSERVICE_FAILURE_ACTIONS_FLAG lpFlag = (LPSERVICE_FAILURE_ACTIONS_FLAG)lpBuffer;
        DWORD dwFlag = 0, dwSize = sizeof(dwFlag), dwType;

        *pcbBytesNeeded = sizeof(SERVICE_FAILURE_ACTIONS_FLAG);
        if (cbBufSize < *pcbBytesNeeded)
        {
            dwError = ERROR_INSUFFICIENT_BUFFER;
            goto done;
        }

        if (RegQueryValueExW(hServiceKey,
                             L"FailureActionsOnNonCrashFailures",
                             NULL,
                             &dwType,
                             (LPBYTE)&dwFlag,
                             &dwSize) != ERROR_SUCCESS || dwType != REG_DWORD)
            dwFlag = 0;

        lpFlag->fFailureActionsOnNonCrashFailures = (dwFlag != 0);
        dwError = ERROR_SUCCESS;
    }
    else if (dwInfoLevel == SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO)
    {
        dwError = ScmQueryRequiredPrivileges(hServiceKey,
                                             FALSE,
                                             lpBuffer,
                                             cbBufSize,
                                             pcbBytesNeeded);
    }
    else if (dwInfoLevel == SERVICE_CONFIG_TRIGGER_INFO)
    {
        /* The data items are binary, there is no character set to convert */
        dwError = ScmQueryTriggerInfo(hServiceKey,
                                      lpBuffer,
                                      cbBufSize,
                                      pcbBytesNeeded);
    }
    else
    {
        /* The remaining supported levels are a single DWORD, the same in both character sets */
        dwError = ScmQueryDwordConfig(hServiceKey,
                                      dwInfoLevel,
                                      lpBuffer,
                                      cbBufSize,
                                      pcbBytesNeeded);
    }

done:
    /* Unlock the service database */
    ScmUnlockDatabase();

    if (lpDescriptionW != NULL)
        HeapFree(GetProcessHeap(), 0, lpDescriptionW);

    if (lpRebootMessageW != NULL)
        HeapFree(GetProcessHeap(), 0, lpRebootMessageW);

    if (lpFailureCommandW != NULL)
        HeapFree(GetProcessHeap(), 0, lpFailureCommandW);

    if (lpActions != NULL)
        HeapFree(GetProcessHeap(), 0, lpActions);

    if (hServiceKey != NULL)
        RegCloseKey(hServiceKey);

    DPRINT("RQueryServiceConfig2A() done (Error %lu)\n", dwError);

    return dwError;
}


/* Function 39 */
DWORD
WINAPI
RQueryServiceConfig2W(
    SC_RPC_HANDLE hService,
    DWORD dwInfoLevel,
    LPBYTE lpBuffer,
    DWORD cbBufSize,
    LPBOUNDED_DWORD_8K pcbBytesNeeded)
{
    DWORD dwError = ERROR_SUCCESS;
    PSERVICE_HANDLE hSvc;
    PSERVICE lpService = NULL;
    HKEY hServiceKey = NULL;
    DWORD dwRequiredSize = 0;
    LPSC_ACTION lpActions = NULL;
    LPWSTR lpDescription = NULL;
    LPWSTR lpRebootMessage = NULL;
    LPWSTR lpFailureCommand = NULL;

    DPRINT("RQueryServiceConfig2W() called\n");

    if (!lpBuffer)
        return ERROR_INVALID_ADDRESS;

    if (ScmShutdown)
        return ERROR_SHUTDOWN_IN_PROGRESS;

    if (!ScmIsSupportedConfigLevel(dwInfoLevel))
    {
        return ERROR_INVALID_LEVEL;
    }

    hSvc = ScmGetServiceFromHandle(hService);
    if (hSvc == NULL)
    {
        DPRINT1("Invalid service handle\n");
        return ERROR_INVALID_HANDLE;
    }

    if (!RtlAreAllAccessesGranted(hSvc->Handle.DesiredAccess,
                                  SERVICE_QUERY_CONFIG))
    {
        DPRINT("Insufficient access rights! 0x%lx\n", hSvc->Handle.DesiredAccess);
        return ERROR_ACCESS_DENIED;
    }

    lpService = hSvc->ServiceEntry;
    if (lpService == NULL)
    {
        DPRINT("lpService == NULL\n");
        return ERROR_INVALID_HANDLE;
    }

    /* Lock the service database shared */
    ScmLockDatabaseShared();

    dwError = ScmOpenServiceKey(lpService->lpServiceName,
                                KEY_READ,
                                &hServiceKey);
    if (dwError != ERROR_SUCCESS)
        goto done;

    if (dwInfoLevel == SERVICE_CONFIG_DESCRIPTION)
    {
        LPSERVICE_DESCRIPTIONW lpServiceDescription = (LPSERVICE_DESCRIPTIONW)lpBuffer;
        LPWSTR lpStr;

        dwError = ScmReadString(hServiceKey,
                                L"Description",
                                &lpDescription);
        if (dwError != ERROR_SUCCESS && dwError != ERROR_FILE_NOT_FOUND)
            goto done;

        *pcbBytesNeeded = sizeof(SERVICE_DESCRIPTIONW);
        if (dwError == ERROR_SUCCESS)
            *pcbBytesNeeded += (DWORD)((wcslen(lpDescription) + 1) * sizeof(WCHAR));

        if (cbBufSize < *pcbBytesNeeded)
        {
            dwError = ERROR_INSUFFICIENT_BUFFER;
            goto done;
        }

        if (dwError == ERROR_SUCCESS)
        {
            lpStr = (LPWSTR)(lpServiceDescription + 1);
            wcscpy(lpStr, lpDescription);
            lpServiceDescription->lpDescription = (LPWSTR)((ULONG_PTR)lpStr - (ULONG_PTR)lpServiceDescription);
        }
        else
        {
            lpServiceDescription->lpDescription = NULL;
            dwError = ERROR_SUCCESS;
        }
    }
    else if (dwInfoLevel == SERVICE_CONFIG_FAILURE_ACTIONS)
    {
        LPSERVICE_FAILURE_ACTIONSW lpFailureActions = (LPSERVICE_FAILURE_ACTIONSW)lpBuffer;
        LPWSTR lpStr = NULL;

        DWORD dwResetPeriod = 0;
        DWORD cActions = 0;

        /* A missing or invalid value means that no failure actions are set */
        dwError = ScmReadFailureActions(hServiceKey,
                                        &dwResetPeriod,
                                        &cActions,
                                        &lpActions);
        if (dwError != ERROR_SUCCESS &&
            dwError != ERROR_FILE_NOT_FOUND &&
            dwError != ERROR_INVALID_DATA)
            goto done;

        dwRequiredSize = sizeof(SERVICE_FAILURE_ACTIONSW) + cActions * sizeof(SC_ACTION);

        /* Get the strings */
        ScmReadString(hServiceKey,
                      L"FailureCommand",
                      &lpFailureCommand);

        ScmReadString(hServiceKey,
                      L"RebootMessage",
                      &lpRebootMessage);

        if (lpRebootMessage)
            dwRequiredSize += (DWORD)((wcslen(lpRebootMessage) + 1) * sizeof(WCHAR));

        if (lpFailureCommand)
            dwRequiredSize += (DWORD)((wcslen(lpFailureCommand) + 1) * sizeof(WCHAR));

        if (cbBufSize < dwRequiredSize)
        {
            *pcbBytesNeeded = dwRequiredSize;
            dwError = ERROR_INSUFFICIENT_BUFFER;
            goto done;
        }

        lpFailureActions->dwResetPeriod = dwResetPeriod;
        lpFailureActions->cActions = cActions;
        lpFailureActions->lpsaActions = NULL;

        if (cActions > 0)
        {
            /* Here lpFailureActions->lpsaActions contains an offset. The conversion is done by the caller. */
            lpFailureActions->lpsaActions = (LPSC_ACTION)(ULONG_PTR)sizeof(SERVICE_FAILURE_ACTIONSW);
            RtlCopyMemory(lpFailureActions + 1, lpActions, cActions * sizeof(SC_ACTION));
        }

        lpStr = (LPWSTR)((ULONG_PTR)(lpFailureActions + 1) + cActions * sizeof(SC_ACTION));

        lpFailureActions->lpRebootMsg = NULL;
        lpFailureActions->lpCommand   = NULL;

        if (lpRebootMessage)
        {
            wcscpy(lpStr, lpRebootMessage);
            lpFailureActions->lpRebootMsg = (LPWSTR)((ULONG_PTR)lpStr - (ULONG_PTR)lpFailureActions);
            lpStr += wcslen(lpStr) + 1;
        }

        if (lpFailureCommand)
        {
            wcscpy(lpStr, lpFailureCommand);
            lpFailureActions->lpCommand = (LPWSTR)((ULONG_PTR)lpStr - (ULONG_PTR)lpFailureActions);
            /* lpStr += wcslen(lpStr) + 1; */
        }

        dwError = ERROR_SUCCESS;
    }
    else if (dwInfoLevel == SERVICE_CONFIG_FAILURE_ACTIONS_FLAG)
    {
        LPSERVICE_FAILURE_ACTIONS_FLAG lpFlag = (LPSERVICE_FAILURE_ACTIONS_FLAG)lpBuffer;
        DWORD dwFlag = 0, dwSize = sizeof(dwFlag), dwType;

        *pcbBytesNeeded = sizeof(SERVICE_FAILURE_ACTIONS_FLAG);
        if (cbBufSize < *pcbBytesNeeded)
        {
            dwError = ERROR_INSUFFICIENT_BUFFER;
            goto done;
        }

        if (RegQueryValueExW(hServiceKey,
                             L"FailureActionsOnNonCrashFailures",
                             NULL,
                             &dwType,
                             (LPBYTE)&dwFlag,
                             &dwSize) != ERROR_SUCCESS || dwType != REG_DWORD)
            dwFlag = 0;

        lpFlag->fFailureActionsOnNonCrashFailures = (dwFlag != 0);
        dwError = ERROR_SUCCESS;
    }
    else if (dwInfoLevel == SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO)
    {
        dwError = ScmQueryRequiredPrivileges(hServiceKey,
                                             TRUE,
                                             lpBuffer,
                                             cbBufSize,
                                             pcbBytesNeeded);
    }
    else if (dwInfoLevel == SERVICE_CONFIG_TRIGGER_INFO)
    {
        /* The data items are binary, there is no character set to convert */
        dwError = ScmQueryTriggerInfo(hServiceKey,
                                      lpBuffer,
                                      cbBufSize,
                                      pcbBytesNeeded);
    }
    else
    {
        /* The remaining supported levels are a single DWORD, the same in both character sets */
        dwError = ScmQueryDwordConfig(hServiceKey,
                                      dwInfoLevel,
                                      lpBuffer,
                                      cbBufSize,
                                      pcbBytesNeeded);
    }

done:
    /* Unlock the service database */
    ScmUnlockDatabase();

    if (lpDescription != NULL)
        HeapFree(GetProcessHeap(), 0, lpDescription);

    if (lpRebootMessage != NULL)
        HeapFree(GetProcessHeap(), 0, lpRebootMessage);

    if (lpFailureCommand != NULL)
        HeapFree(GetProcessHeap(), 0, lpFailureCommand);

    if (lpActions != NULL)
        HeapFree(GetProcessHeap(), 0, lpActions);

    if (hServiceKey != NULL)
        RegCloseKey(hServiceKey);

    DPRINT("RQueryServiceConfig2W() done (Error %lu)\n", dwError);

    return dwError;
}


/* Function 40 */
DWORD
WINAPI
RQueryServiceStatusEx(
    SC_RPC_HANDLE hService,
    SC_STATUS_TYPE InfoLevel,
    LPBYTE lpBuffer,
    DWORD cbBufSize,
    LPBOUNDED_DWORD_8K pcbBytesNeeded)
{
    LPSERVICE_STATUS_PROCESS lpStatus;
    PSERVICE_HANDLE hSvc;
    PSERVICE lpService;

    DPRINT("RQueryServiceStatusEx() called\n");

    if (ScmShutdown)
        return ERROR_SHUTDOWN_IN_PROGRESS;

    if (InfoLevel != SC_STATUS_PROCESS_INFO)
        return ERROR_INVALID_LEVEL;

    *pcbBytesNeeded = sizeof(SERVICE_STATUS_PROCESS);

    if (cbBufSize < sizeof(SERVICE_STATUS_PROCESS))
        return ERROR_INSUFFICIENT_BUFFER;

    hSvc = ScmGetServiceFromHandle(hService);
    if (hSvc == NULL)
    {
        DPRINT1("Invalid service handle\n");
        return ERROR_INVALID_HANDLE;
    }

    if (!RtlAreAllAccessesGranted(hSvc->Handle.DesiredAccess,
                                  SERVICE_QUERY_STATUS))
    {
        DPRINT("Insufficient access rights! 0x%lx\n", hSvc->Handle.DesiredAccess);
        return ERROR_ACCESS_DENIED;
    }

    lpService = hSvc->ServiceEntry;
    if (lpService == NULL)
    {
        DPRINT("lpService == NULL\n");
        return ERROR_INVALID_HANDLE;
    }

    /* Lock the service database shared */
    ScmLockDatabaseShared();

    lpStatus = (LPSERVICE_STATUS_PROCESS)lpBuffer;

    /* Return service status information */
    RtlCopyMemory(lpStatus,
                  &lpService->Status,
                  sizeof(SERVICE_STATUS));

    /* Copy the service process ID */
    if ((lpService->Status.dwCurrentState == SERVICE_STOPPED) || (lpService->lpImage == NULL))
        lpStatus->dwProcessId = 0;
    else
        lpStatus->dwProcessId = lpService->lpImage->dwProcessId;

    lpStatus->dwServiceFlags = 0;   /* FIXME */

    /* Unlock the service database */
    ScmUnlockDatabase();

    return ERROR_SUCCESS;
}


/* Function 41 */
DWORD
WINAPI
REnumServicesStatusExA(
    SC_RPC_HANDLE hSCManager,
    SC_ENUM_TYPE InfoLevel,
    DWORD dwServiceType,
    DWORD dwServiceState,
    LPBYTE lpBuffer,
    DWORD cbBufSize,
    LPBOUNDED_DWORD_256K pcbBytesNeeded,
    LPBOUNDED_DWORD_256K lpServicesReturned,
    LPBOUNDED_DWORD_256K lpResumeIndex,
    LPCSTR pszGroupName)
{
    LPENUM_SERVICE_STATUS_PROCESSW lpStatusPtrW = NULL;
    LPENUM_SERVICE_STATUS_PROCESSW lpStatusPtrIncrW;
    LPENUM_SERVICE_STATUS_PROCESSA lpStatusPtrA = NULL;
    LPWSTR lpStringPtrW;
    LPSTR lpStringPtrA;
    LPWSTR pszGroupNameW = NULL;
    DWORD dwError;
    DWORD dwServiceCount;

    DPRINT("REnumServicesStatusExA() called\n");

    if (pcbBytesNeeded == NULL || lpServicesReturned == NULL)
    {
        return ERROR_INVALID_ADDRESS;
    }

    if (pszGroupName)
    {
        pszGroupNameW = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (strlen(pszGroupName) + 1) * sizeof(WCHAR));
        if (!pszGroupNameW)
        {
             DPRINT("Failed to allocate buffer\n");
             dwError = ERROR_NOT_ENOUGH_MEMORY;
             goto Done;
        }

        MultiByteToWideChar(CP_ACP,
                            0,
                            pszGroupName,
                            -1,
                            pszGroupNameW,
                            (int)(strlen(pszGroupName) + 1));
    }

    if ((cbBufSize > 0) && (lpBuffer))
    {
        lpStatusPtrW = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbBufSize);
        if (!lpStatusPtrW)
        {
            DPRINT("Failed to allocate buffer\n");
            dwError = ERROR_NOT_ENOUGH_MEMORY;
            goto Done;
        }
    }

    dwError = REnumServicesStatusExW(hSCManager,
                                     InfoLevel,
                                     dwServiceType,
                                     dwServiceState,
                                     (LPBYTE)lpStatusPtrW,
                                     cbBufSize,
                                     pcbBytesNeeded,
                                     lpServicesReturned,
                                     lpResumeIndex,
                                     pszGroupNameW);

    /* if no services were returned then we are Done */
    if (*lpServicesReturned == 0)
        goto Done;

    lpStatusPtrIncrW = lpStatusPtrW;
    lpStatusPtrA = (LPENUM_SERVICE_STATUS_PROCESSA)lpBuffer;
    lpStringPtrA = (LPSTR)((ULONG_PTR)lpBuffer +
                  *lpServicesReturned * sizeof(ENUM_SERVICE_STATUS_PROCESSA));
    lpStringPtrW = (LPWSTR)((ULONG_PTR)lpStatusPtrW +
                  *lpServicesReturned * sizeof(ENUM_SERVICE_STATUS_PROCESSW));

    for (dwServiceCount = 0; dwServiceCount < *lpServicesReturned; dwServiceCount++)
    {
        /* Copy the service name */
        WideCharToMultiByte(CP_ACP,
                            0,
                            lpStringPtrW,
                            -1,
                            lpStringPtrA,
                            (int)wcslen(lpStringPtrW),
                            0,
                            0);

        lpStatusPtrA->lpServiceName = (LPSTR)((ULONG_PTR)lpStringPtrA - (ULONG_PTR)lpBuffer);
        lpStringPtrA += wcslen(lpStringPtrW) + 1;
        lpStringPtrW += wcslen(lpStringPtrW) + 1;

        /* Copy the display name */
        WideCharToMultiByte(CP_ACP,
                            0,
                            lpStringPtrW,
                            -1,
                            lpStringPtrA,
                            (int)wcslen(lpStringPtrW),
                            0,
                            0);

        lpStatusPtrA->lpDisplayName = (LPSTR)((ULONG_PTR)lpStringPtrA - (ULONG_PTR)lpBuffer);
        lpStringPtrA += wcslen(lpStringPtrW) + 1;
        lpStringPtrW += wcslen(lpStringPtrW) + 1;

        /* Copy the status information */
        memcpy(&lpStatusPtrA->ServiceStatusProcess,
               &lpStatusPtrIncrW->ServiceStatusProcess,
               sizeof(SERVICE_STATUS));

        /* Copy the service process ID */
        lpStatusPtrA->ServiceStatusProcess.dwProcessId = lpStatusPtrIncrW->ServiceStatusProcess.dwProcessId;

        lpStatusPtrA->ServiceStatusProcess.dwServiceFlags = 0; /* FIXME */

        lpStatusPtrIncrW++;
        lpStatusPtrA++;
    }

Done:
    if (pszGroupNameW)
        HeapFree(GetProcessHeap(), 0, pszGroupNameW);

    if (lpStatusPtrW)
        HeapFree(GetProcessHeap(), 0, lpStatusPtrW);

    DPRINT("REnumServicesStatusExA() done (Error %lu)\n", dwError);

    return dwError;
}


/* Function 42 */
DWORD
WINAPI
REnumServicesStatusExW(
    SC_RPC_HANDLE hSCManager,
    SC_ENUM_TYPE InfoLevel,
    DWORD dwServiceType,
    DWORD dwServiceState,
    LPBYTE lpBuffer,
    DWORD cbBufSize,
    LPBOUNDED_DWORD_256K pcbBytesNeeded,
    LPBOUNDED_DWORD_256K lpServicesReturned,
    LPBOUNDED_DWORD_256K lpResumeIndex,
    LPCWSTR pszGroupName)
{
    PMANAGER_HANDLE hManager;
    PSERVICE lpService;
    DWORD dwError = ERROR_SUCCESS;
    PLIST_ENTRY ServiceEntry;
    PSERVICE CurrentService;
    DWORD dwState;
    DWORD dwRequiredSize;
    DWORD dwServiceCount;
    DWORD dwSize;
    DWORD dwLastResumeCount = 0;
    LPENUM_SERVICE_STATUS_PROCESSW lpStatusPtr;
    LPWSTR lpStringPtr;

    DPRINT("REnumServicesStatusExW() called\n");

    if (ScmShutdown)
        return ERROR_SHUTDOWN_IN_PROGRESS;

    if (InfoLevel != SC_ENUM_PROCESS_INFO)
        return ERROR_INVALID_LEVEL;

    hManager = ScmGetServiceManagerFromHandle(hSCManager);
    if (hManager == NULL)
    {
        DPRINT1("Invalid service manager handle\n");
        return ERROR_INVALID_HANDLE;
    }

    if (pcbBytesNeeded == NULL || lpServicesReturned == NULL)
    {
        return ERROR_INVALID_ADDRESS;
    }

    *pcbBytesNeeded = 0;
    *lpServicesReturned = 0;

    if ((dwServiceType == 0) ||
        ((dwServiceType & ~SERVICE_TYPE_ALL) != 0))
    {
        DPRINT("Invalid Service Type\n");
        return ERROR_INVALID_PARAMETER;
    }

    if ((dwServiceState == 0) ||
        ((dwServiceState & ~SERVICE_STATE_ALL) != 0))
    {
        DPRINT("Invalid Service State\n");
        return ERROR_INVALID_PARAMETER;
    }

    /* Check access rights */
    if (!RtlAreAllAccessesGranted(hManager->Handle.DesiredAccess,
                                  SC_MANAGER_ENUMERATE_SERVICE))
    {
        DPRINT("Insufficient access rights 0x%lx\n",
               hManager->Handle.DesiredAccess);
        return ERROR_ACCESS_DENIED;
    }

    if (lpResumeIndex)
        dwLastResumeCount = *lpResumeIndex;

    /* Lock the service database shared */
    ScmLockDatabaseShared();

    lpService = ScmGetServiceEntryByResumeCount(dwLastResumeCount);
    if (lpService == NULL)
    {
        dwError = ERROR_SUCCESS;
        goto Done;
    }

    dwRequiredSize = 0;
    dwServiceCount = 0;

    for (ServiceEntry = &lpService->ServiceListEntry;
         ServiceEntry != &ServiceListHead;
         ServiceEntry = ServiceEntry->Flink)
    {
        CurrentService = CONTAINING_RECORD(ServiceEntry,
                                           SERVICE,
                                           ServiceListEntry);

        if ((CurrentService->Status.dwServiceType & dwServiceType) == 0)
            continue;

        dwState = SERVICE_ACTIVE;
        if (CurrentService->Status.dwCurrentState == SERVICE_STOPPED)
            dwState = SERVICE_INACTIVE;

        if ((dwState & dwServiceState) == 0)
            continue;

        if (pszGroupName)
        {
            if (*pszGroupName == 0)
            {
                if (CurrentService->lpGroup != NULL)
                    continue;
            }
            else
            {
                if ((CurrentService->lpGroup == NULL) ||
                    _wcsicmp(pszGroupName, CurrentService->lpGroup->lpGroupName) != 0)
                    continue;
            }
        }

        dwSize = sizeof(ENUM_SERVICE_STATUS_PROCESSW) +
                 (DWORD)((wcslen(CurrentService->lpServiceName) + 1) * sizeof(WCHAR)) +
                 (DWORD)((wcslen(CurrentService->lpDisplayName) + 1) * sizeof(WCHAR));

        if (dwRequiredSize + dwSize <= cbBufSize)
        {
            DPRINT("Service name: %S  fit\n", CurrentService->lpServiceName);
            dwRequiredSize += dwSize;
            dwServiceCount++;
            dwLastResumeCount = CurrentService->dwResumeCount;
        }
        else
        {
            DPRINT("Service name: %S  no fit\n", CurrentService->lpServiceName);
            break;
        }

    }

    DPRINT("dwRequiredSize: %lu\n", dwRequiredSize);
    DPRINT("dwServiceCount: %lu\n", dwServiceCount);

    for (;
         ServiceEntry != &ServiceListHead;
         ServiceEntry = ServiceEntry->Flink)
    {
        CurrentService = CONTAINING_RECORD(ServiceEntry,
                                           SERVICE,
                                           ServiceListEntry);

        if ((CurrentService->Status.dwServiceType & dwServiceType) == 0)
            continue;

        dwState = SERVICE_ACTIVE;
        if (CurrentService->Status.dwCurrentState == SERVICE_STOPPED)
            dwState = SERVICE_INACTIVE;

        if ((dwState & dwServiceState) == 0)
            continue;

        if (pszGroupName)
        {
            if (*pszGroupName == 0)
            {
                if (CurrentService->lpGroup != NULL)
                    continue;
            }
            else
            {
                if ((CurrentService->lpGroup == NULL) ||
                    _wcsicmp(pszGroupName, CurrentService->lpGroup->lpGroupName) != 0)
                    continue;
            }
        }

        dwRequiredSize += (sizeof(ENUM_SERVICE_STATUS_PROCESSW) +
                           (DWORD)((wcslen(CurrentService->lpServiceName) + 1) * sizeof(WCHAR)) +
                           (DWORD)((wcslen(CurrentService->lpDisplayName) + 1) * sizeof(WCHAR)));

        dwError = ERROR_MORE_DATA;
    }

    DPRINT("*pcbBytesNeeded: %lu\n", dwRequiredSize);

    if (lpResumeIndex)
        *lpResumeIndex = dwLastResumeCount;

    *lpServicesReturned = dwServiceCount;
    *pcbBytesNeeded = dwRequiredSize;

    /* If there was no services that matched */
    if ((!dwServiceCount) && (dwError != ERROR_MORE_DATA))
    {
        dwError = ERROR_SERVICE_DOES_NOT_EXIST;
        goto Done;
    }

    lpStatusPtr = (LPENUM_SERVICE_STATUS_PROCESSW)lpBuffer;
    lpStringPtr = (LPWSTR)((ULONG_PTR)lpBuffer +
                           dwServiceCount * sizeof(ENUM_SERVICE_STATUS_PROCESSW));

    dwRequiredSize = 0;
    for (ServiceEntry = &lpService->ServiceListEntry;
         ServiceEntry != &ServiceListHead;
         ServiceEntry = ServiceEntry->Flink)
    {
        CurrentService = CONTAINING_RECORD(ServiceEntry,
                                           SERVICE,
                                           ServiceListEntry);

        if ((CurrentService->Status.dwServiceType & dwServiceType) == 0)
            continue;

        dwState = SERVICE_ACTIVE;
        if (CurrentService->Status.dwCurrentState == SERVICE_STOPPED)
            dwState = SERVICE_INACTIVE;

        if ((dwState & dwServiceState) == 0)
            continue;

        if (pszGroupName)
        {
            if (*pszGroupName == 0)
            {
                if (CurrentService->lpGroup != NULL)
                    continue;
            }
            else
            {
                if ((CurrentService->lpGroup == NULL) ||
                    _wcsicmp(pszGroupName, CurrentService->lpGroup->lpGroupName) != 0)
                    continue;
            }
        }

        dwSize = sizeof(ENUM_SERVICE_STATUS_PROCESSW) +
                 (DWORD)((wcslen(CurrentService->lpServiceName) + 1) * sizeof(WCHAR)) +
                 (DWORD)((wcslen(CurrentService->lpDisplayName) + 1) * sizeof(WCHAR));

        if (dwRequiredSize + dwSize <= cbBufSize)
        {
            /* Copy the service name */
            wcscpy(lpStringPtr,
                   CurrentService->lpServiceName);
            lpStatusPtr->lpServiceName = (LPWSTR)((ULONG_PTR)lpStringPtr - (ULONG_PTR)lpBuffer);
            lpStringPtr += (wcslen(CurrentService->lpServiceName) + 1);

            /* Copy the display name */
            wcscpy(lpStringPtr,
                   CurrentService->lpDisplayName);
            lpStatusPtr->lpDisplayName = (LPWSTR)((ULONG_PTR)lpStringPtr - (ULONG_PTR)lpBuffer);
            lpStringPtr += (wcslen(CurrentService->lpDisplayName) + 1);

            /* Copy the status information */
            memcpy(&lpStatusPtr->ServiceStatusProcess,
                   &CurrentService->Status,
                   sizeof(SERVICE_STATUS));

            /* Copy the service process ID */
            if ((CurrentService->Status.dwCurrentState == SERVICE_STOPPED) || (CurrentService->lpImage == NULL))
                lpStatusPtr->ServiceStatusProcess.dwProcessId = 0;
            else
                lpStatusPtr->ServiceStatusProcess.dwProcessId = CurrentService->lpImage->dwProcessId;

            lpStatusPtr->ServiceStatusProcess.dwServiceFlags = 0; /* FIXME */

            lpStatusPtr++;
            dwRequiredSize += dwSize;
        }
        else
        {
            break;
        }
    }

    if (dwError == 0)
    {
        *pcbBytesNeeded = 0;
        if (lpResumeIndex)
            *lpResumeIndex = 0;
    }

Done:
    /* Unlock the service database */
    ScmUnlockDatabase();

    DPRINT("REnumServicesStatusExW() done (Error %lu)\n", dwError);

    return dwError;
}


/* Function 43 */
DWORD
WINAPI
RSendTSMessage(
    handle_t BindingHandle)  /* FIXME */
{
    UNIMPLEMENTED;
    return ERROR_CALL_NOT_IMPLEMENTED;
}


/* Function 44 */
DWORD
WINAPI
RCreateServiceWOW64A(
    handle_t BindingHandle,
    LPSTR lpServiceName,
    LPSTR lpDisplayName,
    DWORD dwDesiredAccess,
    DWORD dwServiceType,
    DWORD dwStartType,
    DWORD dwErrorControl,
    LPSTR lpBinaryPathName,
    LPSTR lpLoadOrderGroup,
    LPDWORD lpdwTagId,
    LPBYTE lpDependencies,
    DWORD dwDependSize,
    LPSTR lpServiceStartName,
    LPBYTE lpPassword,
    DWORD dwPwSize,
    LPSC_RPC_HANDLE lpServiceHandle)
{
    UNIMPLEMENTED;
    return ERROR_CALL_NOT_IMPLEMENTED;
}


/* Function 45 */
DWORD
WINAPI
RCreateServiceWOW64W(
    handle_t BindingHandle,
    LPWSTR lpServiceName,
    LPWSTR lpDisplayName,
    DWORD dwDesiredAccess,
    DWORD dwServiceType,
    DWORD dwStartType,
    DWORD dwErrorControl,
    LPWSTR lpBinaryPathName,
    LPWSTR lpLoadOrderGroup,
    LPDWORD lpdwTagId,
    LPBYTE lpDependencies,
    DWORD dwDependSize,
    LPWSTR lpServiceStartName,
    LPBYTE lpPassword,
    DWORD dwPwSize,
    LPSC_RPC_HANDLE lpServiceHandle)
{
    UNIMPLEMENTED;
    return ERROR_CALL_NOT_IMPLEMENTED;
}


/* Function 46 */
DWORD
WINAPI
RI_ScQueryServiceTagInfo(
    SC_RPC_HANDLE hSCManager,
    TAG_INFO_LEVEL dwInfoLevel,
    PTAG_INFO_NAME_FROM_TAG_IN_PARAMS * lpInParams,
    PTAG_INFO_NAME_FROM_TAG_OUT_PARAMS * lpOutParams)
{
    PMANAGER_HANDLE hManager;

    /* Validate handle */
    hManager = ScmGetServiceManagerFromHandle(hSCManager);
    if (hManager == NULL)
    {
        return ERROR_INVALID_HANDLE;
    }

    /* FIXME: should check whether client is local */

    /* Check access rights */
    if (!RtlAreAllAccessesGranted(hManager->Handle.DesiredAccess,
                                  SC_MANAGER_ENUMERATE_SERVICE))
    {
        return ERROR_ACCESS_DENIED;
    }

    /* Check parameters */
    if (lpInParams == NULL || lpOutParams == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }

    /* Check info level */
    if (dwInfoLevel != TagInfoLevelNameFromTag)
    {
        return ERROR_RETRY;
    }

    /* Call internal helper */
    return ScmGetServiceNameFromTag(*lpInParams, lpOutParams);
}


/* Function 47 */
DWORD
WINAPI
RNotifyServiceStatusChange(
    SC_RPC_HANDLE hService,
    SC_RPC_NOTIFY_PARAMS NotifyParams,
    GUID *pClientProcessGuid,
    GUID *pSCMProcessGuid,
    PBOOL pfCreateRemoteQueue,
    LPSC_NOTIFY_RPC_HANDLE phNotify)
{
    UNIMPLEMENTED;
    return ERROR_CALL_NOT_IMPLEMENTED;
}


/* Function 48 */
DWORD
WINAPI
RGetNotifyResults(
    SC_NOTIFY_RPC_HANDLE hNotify,
    PSC_RPC_NOTIFY_PARAMS_LIST *ppNotifyParams)
{
    UNIMPLEMENTED;
    return ERROR_CALL_NOT_IMPLEMENTED;
}


/* Function 49 */
DWORD
WINAPI
RCloseNotifyHandle(
    LPSC_NOTIFY_RPC_HANDLE phNotify,
    PBOOL pfApcFired)
{
    UNIMPLEMENTED;
    return ERROR_CALL_NOT_IMPLEMENTED;
}


/* Function 50 */
DWORD
WINAPI
RControlServiceExA(
    SC_RPC_HANDLE hService,
    DWORD dwControl,
    DWORD dwInfoLevel)
{
    UNIMPLEMENTED;
    return ERROR_CALL_NOT_IMPLEMENTED;
}


/* Function 51 */
DWORD
WINAPI
RControlServiceExW(
    SC_RPC_HANDLE hService,
    DWORD dwControl,
    DWORD dwInfoLevel)
{
    UNIMPLEMENTED;
    return ERROR_CALL_NOT_IMPLEMENTED;
}


/* Function 52 */
DWORD
WINAPI
RI_ScSendPnPMessage(
    _In_ RPC_SERVICE_STATUS_HANDLE hServiceStatus,
    _In_ DWORD dwControl,
    _In_ DWORD dwEventType,
    _In_ DWORD dwEventSize,
    _In_ LPBYTE pEventData)
{
    PSCM_CONTROL_PACKET ControlPacket;
    DWORD PacketSize;
    PSERVICE pService;
    PSERVICE_IMAGE pImage;
    ULONG_PTR Ptr;
    DWORD dwControlsAccepted, dwCurrentState;
    DWORD dwError = ERROR_SUCCESS;

    DPRINT("RI_ScSendPnPMessage(%p %lx %lu %lu %p)\n",
           hServiceStatus, dwControl, dwEventType, dwEventSize, pEventData);

    /* FIXME: Verify the status handle */
    pService = ScmGetServiceByStatusHandle(hServiceStatus);
    if (pService == NULL)
        return ERROR_INVALID_HANDLE;

    /* Fail, if the service is a driver */
    if (pService->Status.dwServiceType & SERVICE_DRIVER)
        return ERROR_INVALID_SERVICE_CONTROL;

    dwControlsAccepted = pService->Status.dwControlsAccepted;
    dwCurrentState = pService->Status.dwCurrentState;

    /* Read once: a stop clears it without the caller holding a lock */
    pImage = *(PSERVICE_IMAGE volatile *)&pService->lpImage;

    /* Return ERROR_SERVICE_NOT_ACTIVE if the service has not been started */
    if (pImage == NULL || dwCurrentState == SERVICE_STOPPED)
        return ERROR_SERVICE_NOT_ACTIVE;

    /* The service cannot accept a control code if it is not running */
    if (dwCurrentState != SERVICE_RUNNING)
        return ERROR_SERVICE_CANNOT_ACCEPT_CTRL;

    /* Check if the control code is acceptable to the service */
    switch (dwControl)
    {
        case SERVICE_CONTROL_DEVICEEVENT:
            break;

        case SERVICE_CONTROL_HARDWAREPROFILECHANGE:
            if ((dwControlsAccepted & SERVICE_ACCEPT_HARDWAREPROFILECHANGE) == 0)
                return ERROR_INVALID_SERVICE_CONTROL;
            break;

        case SERVICE_CONTROL_POWEREVENT:
            if ((dwControlsAccepted & SERVICE_ACCEPT_POWEREVENT) == 0)
                return ERROR_INVALID_SERVICE_CONTROL;
            break;

        case SERVICE_CONTROL_SESSIONCHANGE:
            if ((dwControlsAccepted & SERVICE_ACCEPT_SESSIONCHANGE) == 0)
                return ERROR_INVALID_SERVICE_CONTROL;
            break;

        default:
            return ERROR_INVALID_SERVICE_CONTROL;
    }

    /* Calculate the total size of the control packet:
     * initial structure, event type and event data */
    PacketSize = sizeof(SCM_CONTROL_PACKET) + sizeof(DWORD) + dwEventSize;

    /* Allocate the control packet */
    ControlPacket = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PacketSize);
    if (!ControlPacket)
        return ERROR_NOT_ENOUGH_MEMORY;

    ControlPacket->dwSize = PacketSize;
    ControlPacket->dwControl = dwControl;

    /* Copy the event type and event data into the control packet */
    Ptr = ((ULONG_PTR)ControlPacket + sizeof(SCM_CONTROL_PACKET));
    RtlCopyMemory((PULONG)Ptr, &dwEventType, sizeof(dwEventType));
    if (dwEventSize != 0)
    {
        Ptr = Ptr + sizeof(dwEventType);
        RtlCopyMemory((PULONG)Ptr, pEventData, dwEventSize);
    }

    /* Send the control packet */
    dwError = ScmSendControlPacket(pImage->hControlPipe,
                                   pService->lpServiceName,
                                   dwControl,
                                   PacketSize,
                                   ControlPacket);

    /* Free the control packet */
    HeapFree(GetProcessHeap(), 0, ControlPacket);

    return dwError;
}


/* Function 53 */
DWORD
WINAPI
RI_ScValidatePnPService(
    _In_ SC_RPC_HANDLE hSCManager,
    _In_ LPWSTR pszServiceName,
    _Out_ RPC_SERVICE_STATUS_HANDLE *phServiceStatus)
{
    PMANAGER_HANDLE hManager;
    PSERVICE pService;

    DPRINT("RI_ScValidatePnPService(%p %S %p)\n", hSCManager, pszServiceName, phServiceStatus);

    /* Validate handle */
    hManager = ScmGetServiceManagerFromHandle(hSCManager);
    if (hManager == NULL)
    {
        DPRINT1("Invalid handle\n");
        return ERROR_INVALID_HANDLE;
    }

    /* FIXME: should check whether client is local */

    /* Check access rights */
    if (!RtlAreAllAccessesGranted(hManager->Handle.DesiredAccess,
                                  SC_MANAGER_CONNECT))
    {
        DPRINT1("No SC_MANAGER_CONNECT access\n");
        return ERROR_ACCESS_DENIED;
    }

    pService = ScmGetServiceEntryByName(pszServiceName);
    DPRINT("pService: %p\n", pService);
    if (pService == NULL)
        return ERROR_SERVICE_DOES_NOT_EXIST;

    *phServiceStatus = pService->dwStatusHandle;

    return ERROR_SUCCESS;
}


/* Function 54 */
DWORD
WINAPI
ROpenServiceStatusHandle(
    handle_t BindingHandle)  /* FIXME */
{
    UNIMPLEMENTED;
    return ERROR_CALL_NOT_IMPLEMENTED;
}


/* Function 55 */
DWORD
WINAPI
RFunction55(
    handle_t BindingHandle)  /* FIXME */
{
    UNIMPLEMENTED;
    return ERROR_CALL_NOT_IMPLEMENTED;
}


void __RPC_FAR * __RPC_USER midl_user_allocate(SIZE_T len)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len);
}


void __RPC_USER midl_user_free(void __RPC_FAR * ptr)
{
    HeapFree(GetProcessHeap(), 0, ptr);
}


void __RPC_USER SC_RPC_HANDLE_rundown(SC_RPC_HANDLE hSCObject)
{
    /* Close the handle */
    RCloseServiceHandle(&hSCObject);
}


void __RPC_USER SC_RPC_LOCK_rundown(SC_RPC_LOCK Lock)
{
    /* Unlock the database */
    RUnlockServiceDatabase(&Lock);
}


void __RPC_USER SC_NOTIFY_RPC_HANDLE_rundown(SC_NOTIFY_RPC_HANDLE hNotify)
{
}

/* EOF */
