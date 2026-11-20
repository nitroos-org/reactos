/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            lib/advapi32/service/scm.c
 * PURPOSE:         Service control manager functions
 * PROGRAMMER:      Emanuele Aliberti
 *                  Eric Kohl
 *                  Pierre Schweitzer
 */

/* INCLUDES ******************************************************************/

#include <advapi32.h>
WINE_DEFAULT_DEBUG_CHANNEL(advapi);

NTSTATUS
WINAPI
SystemFunction004(
    const struct ustring *in,
    const struct ustring *key,
    struct ustring *out);

NTSTATUS
WINAPI
SystemFunction028(
    IN PVOID ContextHandle,
    OUT LPBYTE SessionKey);

/* FUNCTIONS *****************************************************************/

VOID ScmCancelServiceNotifications(SC_HANDLE hService);

handle_t __RPC_USER
SVCCTL_HANDLEA_bind(SVCCTL_HANDLEA szMachineName)
{
    handle_t hBinding = NULL;
    RPC_CSTR pszStringBinding;
    RPC_STATUS status;

    TRACE("SVCCTL_HANDLEA_bind(%s)\n",
          debugstr_a(szMachineName));

    status = RpcStringBindingComposeA(NULL,
                                      (RPC_CSTR)"ncacn_np",
                                      (RPC_CSTR)szMachineName,
                                      (RPC_CSTR)"\\pipe\\ntsvcs",
                                      NULL,
                                      &pszStringBinding);
    if (status != RPC_S_OK)
    {
        ERR("RpcStringBindingCompose returned 0x%x\n", status);
        return NULL;
    }

    /* Set the binding handle that will be used to bind to the server. */
    status = RpcBindingFromStringBindingA(pszStringBinding,
                                          &hBinding);
    if (status != RPC_S_OK)
    {
        ERR("RpcBindingFromStringBinding returned 0x%x\n", status);
    }

    status = RpcStringFreeA(&pszStringBinding);
    if (status != RPC_S_OK)
    {
        ERR("RpcStringFree returned 0x%x\n", status);
    }

    return hBinding;
}


void __RPC_USER
SVCCTL_HANDLEA_unbind(SVCCTL_HANDLEA szMachineName,
                      handle_t hBinding)
{
    RPC_STATUS status;

    TRACE("SVCCTL_HANDLEA_unbind(%s %p)\n",
          debugstr_a(szMachineName), hBinding);

    status = RpcBindingFree(&hBinding);
    if (status != RPC_S_OK)
    {
        ERR("RpcBindingFree returned 0x%x\n", status);
    }
}


handle_t __RPC_USER
SVCCTL_HANDLEW_bind(SVCCTL_HANDLEW szMachineName)
{
    handle_t hBinding = NULL;
    RPC_WSTR pszStringBinding;
    RPC_STATUS status;

    TRACE("SVCCTL_HANDLEW_bind(%s)\n",
          debugstr_w(szMachineName));

    status = RpcStringBindingComposeW(NULL,
                                      L"ncacn_np",
                                      szMachineName,
                                      L"\\pipe\\ntsvcs",
                                      NULL,
                                      &pszStringBinding);
    if (status != RPC_S_OK)
    {
        ERR("RpcStringBindingCompose returned 0x%x\n", status);
        return NULL;
    }

    /* Set the binding handle that will be used to bind to the server. */
    status = RpcBindingFromStringBindingW(pszStringBinding,
                                          &hBinding);
    if (status != RPC_S_OK)
    {
        ERR("RpcBindingFromStringBinding returned 0x%x\n", status);
    }

    status = RpcStringFreeW(&pszStringBinding);
    if (status != RPC_S_OK)
    {
        ERR("RpcStringFree returned 0x%x\n", status);
    }

    return hBinding;
}


void __RPC_USER
SVCCTL_HANDLEW_unbind(SVCCTL_HANDLEW szMachineName,
                      handle_t hBinding)
{
    RPC_STATUS status;

    TRACE("SVCCTL_HANDLEW_unbind(%s %p)\n",
          debugstr_w(szMachineName), hBinding);

    status = RpcBindingFree(&hBinding);
    if (status != RPC_S_OK)
    {
        ERR("RpcBindingFree returned 0x%x\n", status);
    }
}


DWORD
ScmRpcStatusToWinError(RPC_STATUS Status)
{
    TRACE("ScmRpcStatusToWinError(%lx)\n",
          Status);

    switch (Status)
    {
        case STATUS_ACCESS_VIOLATION:
        case RPC_S_INVALID_BINDING:
        case RPC_X_SS_IN_NULL_CONTEXT:
            return ERROR_INVALID_HANDLE;

        case RPC_X_ENUM_VALUE_OUT_OF_RANGE:
        case RPC_X_BYTE_COUNT_TOO_SMALL:
            return ERROR_INVALID_PARAMETER;

        case RPC_X_NULL_REF_POINTER:
            return ERROR_INVALID_ADDRESS;

        default:
            return (DWORD)Status;
    }
}


static
DWORD
ScmEncryptPassword(
    _In_ PVOID ContextHandle,
    _In_ PCWSTR pClearTextPassword,
    _Out_ PBYTE *pEncryptedPassword,
    _Out_ PDWORD pEncryptedPasswordSize)
{
    struct ustring inData, keyData, outData;
    BYTE SessionKey[16];
    PBYTE pBuffer;
    NTSTATUS Status;

    /* Get the session key */
    Status = SystemFunction028(ContextHandle,
                               SessionKey);
    if (!NT_SUCCESS(Status))
    {
        ERR("SystemFunction028 failed (Status 0x%08lx)\n", Status);
        return RtlNtStatusToDosError(Status);
    }

    inData.Length = (wcslen(pClearTextPassword) + 1) * sizeof(WCHAR);
    inData.MaximumLength = inData.Length;
    inData.Buffer = (unsigned char *)pClearTextPassword;

    keyData.Length = sizeof(SessionKey);
    keyData.MaximumLength = keyData.Length;
    keyData.Buffer = SessionKey;

    outData.Length = 0;
    outData.MaximumLength = 0;
    outData.Buffer = NULL;

    /* Get the required buffer size */
    Status = SystemFunction004(&inData,
                               &keyData,
                               &outData);
    if (Status != STATUS_BUFFER_TOO_SMALL)
    {
        ERR("SystemFunction004 failed (Status 0x%08lx)\n", Status);
        return RtlNtStatusToDosError(Status);
    }

    /* Allocate a buffer for the encrypted password */
    pBuffer = HeapAlloc(GetProcessHeap(), 0, outData.Length);
    if (pBuffer == NULL)
        return ERROR_OUTOFMEMORY;

    outData.MaximumLength = outData.Length;
    outData.Buffer = pBuffer;

    /* Encrypt the password */
    Status = SystemFunction004(&inData,
                               &keyData,
                               &outData);
    if (!NT_SUCCESS(Status))
    {
        ERR("SystemFunction004 failed (Status 0x%08lx)\n", Status);
        HeapFree(GetProcessHeap(), 0, pBuffer);
        return RtlNtStatusToDosError(Status);
    }

    *pEncryptedPassword = outData.Buffer;
    *pEncryptedPasswordSize = outData.Length;

    return ERROR_SUCCESS;
}


/**********************************************************************
 *  ChangeServiceConfig2A
 *
 * @implemented
 */
BOOL WINAPI
ChangeServiceConfig2A(SC_HANDLE hService,
                      DWORD dwInfoLevel,
                      LPVOID lpInfo)
{
    SC_RPC_CONFIG_INFOA Info;
    SERVICE_RPC_REQUIRED_PRIVILEGES_INFO RpcPrivileges;
    DWORD dwError;

    TRACE("ChangeServiceConfig2A(%p %lu %p)\n",
          hService, dwInfoLevel, lpInfo);

    if (lpInfo == NULL) return TRUE;

    /* Fill relevant field of the Info structure */
    Info.dwInfoLevel = dwInfoLevel;
    switch (dwInfoLevel)
    {
        case SERVICE_CONFIG_DESCRIPTION:
            Info.psd = lpInfo;
            break;

        case SERVICE_CONFIG_FAILURE_ACTIONS:
            Info.psfa = lpInfo;
            break;

        case SERVICE_CONFIG_DELAYED_AUTO_START_INFO:
            Info.psda = lpInfo;
            break;

        case SERVICE_CONFIG_FAILURE_ACTIONS_FLAG:
            Info.psfaf = lpInfo;
            break;

        case SERVICE_CONFIG_SERVICE_SID_INFO:
            Info.pssid = lpInfo;
            break;

        case SERVICE_CONFIG_PRESHUTDOWN_INFO:
            Info.psps = lpInfo;
            break;

        case SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO:
            {
                LPCSTR lpPrivileges = ((LPSERVICE_REQUIRED_PRIVILEGES_INFOA)lpInfo)->pmszRequiredPrivileges;

                /* Without a list there is nothing to change */
                if (lpPrivileges == NULL) return TRUE;

                /* The list of strings ends with an empty one, which is part of what is sent */
                for (RpcPrivileges.cbRequiredPrivileges = 1;
                     lpPrivileges[0] != 0;
                     lpPrivileges += strlen(lpPrivileges) + 1)
                    RpcPrivileges.cbRequiredPrivileges += (DWORD)strlen(lpPrivileges) + 1;
                RpcPrivileges.pRequiredPrivileges = (PBYTE)((LPSERVICE_REQUIRED_PRIVILEGES_INFOA)lpInfo)->pmszRequiredPrivileges;
                Info.psrp = &RpcPrivileges;
            }
            break;

        case SERVICE_CONFIG_TRIGGER_INFO:
            Info.psti = lpInfo;
            break;

        default:
            WARN("Unknown info level 0x%lx\n", dwInfoLevel);
            SetLastError(ERROR_INVALID_LEVEL);
            return FALSE;
    }

    RpcTryExcept
    {
        dwError = RChangeServiceConfig2A((SC_RPC_HANDLE)hService,
                                         Info);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    if (dwError != ERROR_SUCCESS)
    {
        TRACE("RChangeServiceConfig2A() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
        return FALSE;
    }

    return TRUE;
}


/**********************************************************************
 *  ChangeServiceConfig2W
 *
 * @implemented
 */
BOOL WINAPI
ChangeServiceConfig2W(SC_HANDLE hService,
                      DWORD dwInfoLevel,
                      LPVOID lpInfo)
{
    SC_RPC_CONFIG_INFOW Info;
    SERVICE_RPC_REQUIRED_PRIVILEGES_INFO RpcPrivileges;
    DWORD dwError;

    TRACE("ChangeServiceConfig2W(%p %lu %p)\n",
          hService, dwInfoLevel, lpInfo);

    if (lpInfo == NULL) return TRUE;

    /* Fill relevant field of the Info structure */
    Info.dwInfoLevel = dwInfoLevel;
    switch (dwInfoLevel)
    {
        case SERVICE_CONFIG_DESCRIPTION:
            Info.psd = lpInfo;
            break;

        case SERVICE_CONFIG_FAILURE_ACTIONS:
            Info.psfa = lpInfo;
            break;

        case SERVICE_CONFIG_DELAYED_AUTO_START_INFO:
            Info.psda = lpInfo;
            break;

        case SERVICE_CONFIG_FAILURE_ACTIONS_FLAG:
            Info.psfaf = lpInfo;
            break;

        case SERVICE_CONFIG_SERVICE_SID_INFO:
            Info.pssid = lpInfo;
            break;

        case SERVICE_CONFIG_PRESHUTDOWN_INFO:
            Info.psps = lpInfo;
            break;

        case SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO:
            {
                LPCWSTR lpPrivileges = ((LPSERVICE_REQUIRED_PRIVILEGES_INFOW)lpInfo)->pmszRequiredPrivileges;

                /* Without a list there is nothing to change */
                if (lpPrivileges == NULL) return TRUE;

                /* The list of strings ends with an empty one, which is part of what is sent */
                for (RpcPrivileges.cbRequiredPrivileges = sizeof(WCHAR);
                     lpPrivileges[0] != 0;
                     lpPrivileges += wcslen(lpPrivileges) + 1)
                    RpcPrivileges.cbRequiredPrivileges += (DWORD)(wcslen(lpPrivileges) + 1) * sizeof(WCHAR);
                RpcPrivileges.pRequiredPrivileges = (PBYTE)((LPSERVICE_REQUIRED_PRIVILEGES_INFOW)lpInfo)->pmszRequiredPrivileges;
                Info.psrp = &RpcPrivileges;
            }
            break;

        case SERVICE_CONFIG_TRIGGER_INFO:
            Info.psti = lpInfo;
            break;

        default:
            WARN("Unknown info level 0x%lx\n", dwInfoLevel);
            SetLastError(ERROR_INVALID_LEVEL);
            return FALSE;
    }

    RpcTryExcept
    {
        dwError = RChangeServiceConfig2W((SC_RPC_HANDLE)hService,
                                         Info);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    if (dwError != ERROR_SUCCESS)
    {
        TRACE("RChangeServiceConfig2W() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
        return FALSE;
    }

    return TRUE;
}


/**********************************************************************
 *  ChangeServiceConfigA
 *
 * @implemented
 */
BOOL WINAPI
ChangeServiceConfigA(SC_HANDLE hService,
                     DWORD dwServiceType,
                     DWORD dwStartType,
                     DWORD dwErrorControl,
                     LPCSTR lpBinaryPathName,
                     LPCSTR lpLoadOrderGroup,
                     LPDWORD lpdwTagId,
                     LPCSTR lpDependencies,
                     LPCSTR lpServiceStartName,
                     LPCSTR lpPassword,
                     LPCSTR lpDisplayName)
{
    DWORD dwError;
    DWORD dwDependenciesLength = 0;
    SIZE_T cchLength;
    LPCSTR lpStr;
    DWORD dwPasswordSize = 0;
    LPWSTR lpPasswordW = NULL;
    LPBYTE lpEncryptedPassword = NULL;

    TRACE("ChangeServiceConfigA(%p %lu %lu %lu %s %s %p %s %s %s %s)\n",
          hService, dwServiceType, dwStartType, dwErrorControl, debugstr_a(lpBinaryPathName),
          debugstr_a(lpLoadOrderGroup), lpdwTagId, debugstr_a(lpDependencies),
          debugstr_a(lpServiceStartName), debugstr_a(lpPassword), debugstr_a(lpDisplayName));

    /* Calculate the Dependencies length*/
    if (lpDependencies != NULL)
    {
        lpStr = lpDependencies;
        while (*lpStr)
        {
            cchLength = strlen(lpStr) + 1;
            dwDependenciesLength += (DWORD)cchLength;
            lpStr = lpStr + cchLength;
        }
        dwDependenciesLength++;
    }

    if (lpPassword != NULL)
    {
        /* Convert the password to unicode */
        lpPasswordW = HeapAlloc(GetProcessHeap(),
                                HEAP_ZERO_MEMORY,
                                (strlen(lpPassword) + 1) * sizeof(WCHAR));
        if (lpPasswordW == NULL)
        {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return FALSE;
        }

        MultiByteToWideChar(CP_ACP,
                            0,
                            lpPassword,
                            -1,
                            lpPasswordW,
                            (int)(strlen(lpPassword) + 1));

        /* Encrypt the unicode password */
        dwError = ScmEncryptPassword(hService,
                                     lpPasswordW,
                                     &lpEncryptedPassword,
                                     &dwPasswordSize);
        if (dwError != ERROR_SUCCESS)
            goto done;
    }

    RpcTryExcept
    {
        dwError = RChangeServiceConfigA((SC_RPC_HANDLE)hService,
                                        dwServiceType,
                                        dwStartType,
                                        dwErrorControl,
                                        (LPSTR)lpBinaryPathName,
                                        (LPSTR)lpLoadOrderGroup,
                                        lpdwTagId,
                                        (LPBYTE)lpDependencies,
                                        dwDependenciesLength,
                                        (LPSTR)lpServiceStartName,
                                        lpEncryptedPassword,
                                        dwPasswordSize,
                                        (LPSTR)lpDisplayName);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

done:
    if (lpPasswordW != NULL)
    {
        /* Wipe and release the password buffers */
        SecureZeroMemory(lpPasswordW, (wcslen(lpPasswordW) + 1) * sizeof(WCHAR));
        HeapFree(GetProcessHeap(), 0, lpPasswordW);

        if (lpEncryptedPassword != NULL)
        {
            SecureZeroMemory(lpEncryptedPassword, dwPasswordSize);
            HeapFree(GetProcessHeap(), 0, lpEncryptedPassword);
        }
    }

    if (dwError != ERROR_SUCCESS)
    {
        TRACE("RChangeServiceConfigA() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
        return FALSE;
    }

    return TRUE;
}


/**********************************************************************
 *  ChangeServiceConfigW
 *
 * @implemented
 */
BOOL WINAPI
ChangeServiceConfigW(SC_HANDLE hService,
                     DWORD dwServiceType,
                     DWORD dwStartType,
                     DWORD dwErrorControl,
                     LPCWSTR lpBinaryPathName,
                     LPCWSTR lpLoadOrderGroup,
                     LPDWORD lpdwTagId,
                     LPCWSTR lpDependencies,
                     LPCWSTR lpServiceStartName,
                     LPCWSTR lpPassword,
                     LPCWSTR lpDisplayName)
{
    DWORD dwError;
    DWORD dwDependenciesLength = 0;
    SIZE_T cchLength;
    LPCWSTR lpStr;
    DWORD dwPasswordSize = 0;
    LPBYTE lpEncryptedPassword = NULL;

    TRACE("ChangeServiceConfigW(%p %lu %lu %lu %s %s %p %s %s %s %s)\n",
          hService, dwServiceType, dwStartType, dwErrorControl, debugstr_w(lpBinaryPathName),
          debugstr_w(lpLoadOrderGroup), lpdwTagId, debugstr_w(lpDependencies),
          debugstr_w(lpServiceStartName), debugstr_w(lpPassword), debugstr_w(lpDisplayName));

    /* Calculate the Dependencies length*/
    if (lpDependencies != NULL)
    {
        lpStr = lpDependencies;
        while (*lpStr)
        {
            cchLength = wcslen(lpStr) + 1;
            dwDependenciesLength += (DWORD)cchLength;
            lpStr = lpStr + cchLength;
        }
        dwDependenciesLength++;
        dwDependenciesLength *= sizeof(WCHAR);
    }

    if (lpPassword != NULL)
    {
        dwError = ScmEncryptPassword(hService,
                                     lpPassword,
                                     &lpEncryptedPassword,
                                     &dwPasswordSize);
        if (dwError != ERROR_SUCCESS)
        {
            ERR("ScmEncryptPassword failed (Error %lu)\n", dwError);
            goto done;
        }
    }

    RpcTryExcept
    {
        dwError = RChangeServiceConfigW((SC_RPC_HANDLE)hService,
                                        dwServiceType,
                                        dwStartType,
                                        dwErrorControl,
                                        (LPWSTR)lpBinaryPathName,
                                        (LPWSTR)lpLoadOrderGroup,
                                        lpdwTagId,
                                        (LPBYTE)lpDependencies,
                                        dwDependenciesLength,
                                        (LPWSTR)lpServiceStartName,
                                        lpEncryptedPassword,
                                        dwPasswordSize,
                                        (LPWSTR)lpDisplayName);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

done:
    if (lpEncryptedPassword != NULL)
    {
        /* Wipe and release the password buffer */
        SecureZeroMemory(lpEncryptedPassword, dwPasswordSize);
        HeapFree(GetProcessHeap(), 0, lpEncryptedPassword);
    }

    if (dwError != ERROR_SUCCESS)
    {
        TRACE("RChangeServiceConfigW() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
        return FALSE;
    }

    return TRUE;
}


/**********************************************************************
 *  CloseServiceHandle
 *
 * @implemented
 */
BOOL WINAPI
CloseServiceHandle(SC_HANDLE hSCObject)
{
    DWORD dwError;

    TRACE("CloseServiceHandle(%p)\n",
          hSCObject);

    if (!hSCObject)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    ScmCancelServiceNotifications(hSCObject);

    RpcTryExcept
    {
        dwError = RCloseServiceHandle((LPSC_RPC_HANDLE)&hSCObject);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    if (dwError)
    {
        TRACE("RCloseServiceHandle() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
        return FALSE;
    }

    TRACE("CloseServiceHandle() done\n");

    return TRUE;
}


/**********************************************************************
 *  ControlService
 *
 * @implemented
 */
BOOL WINAPI
ControlService(SC_HANDLE hService,
               DWORD dwControl,
               LPSERVICE_STATUS lpServiceStatus)
{
    DWORD dwError;

    TRACE("ControlService(%p %lu %p)\n",
          hService, dwControl, lpServiceStatus);

    RpcTryExcept
    {
        dwError = RControlService((SC_RPC_HANDLE)hService,
                                  dwControl,
                                  lpServiceStatus);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    if (dwError != ERROR_SUCCESS)
    {
        TRACE("RControlService() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
        return FALSE;
    }

    TRACE("ControlService() done\n");

    return TRUE;
}


/**********************************************************************
 *  ControlServiceEx
 *
 * @unimplemented
 */
BOOL WINAPI
ControlServiceEx(IN SC_HANDLE hService,
                 IN DWORD dwControl,
                 IN DWORD dwInfoLevel,
                 IN OUT PVOID pControlParams)
{
    FIXME("ControlServiceEx(%p %lu %lu %p)\n",
          hService, dwControl, dwInfoLevel, pControlParams);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}


/**********************************************************************
 *  CreateServiceA
 *
 * @implemented
 */
SC_HANDLE WINAPI
CreateServiceA(SC_HANDLE hSCManager,
               LPCSTR lpServiceName,
               LPCSTR lpDisplayName,
               DWORD dwDesiredAccess,
               DWORD dwServiceType,
               DWORD dwStartType,
               DWORD dwErrorControl,
               LPCSTR lpBinaryPathName,
               LPCSTR lpLoadOrderGroup,
               LPDWORD lpdwTagId,
               LPCSTR lpDependencies,
               LPCSTR lpServiceStartName,
               LPCSTR lpPassword)
{
    SC_HANDLE hService = NULL;
    DWORD dwDependenciesLength = 0;
    DWORD dwError;
    SIZE_T cchLength;
    LPCSTR lpStr;
    DWORD dwPasswordSize = 0;
    LPWSTR lpPasswordW = NULL;
    LPBYTE lpEncryptedPassword = NULL;

    TRACE("CreateServiceA(%p %s %s %lx %lu %lu %lu %s %s %p %s %s %s)\n",
          hSCManager, debugstr_a(lpServiceName), debugstr_a(lpDisplayName),
          dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl,
          debugstr_a(lpBinaryPathName), debugstr_a(lpLoadOrderGroup), lpdwTagId,
          debugstr_a(lpDependencies), debugstr_a(lpServiceStartName), debugstr_a(lpPassword));

    if (!hSCManager)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return NULL;
    }

    /* Calculate the Dependencies length */
    if (lpDependencies != NULL)
    {
        lpStr = lpDependencies;
        while (*lpStr)
        {
            cchLength = strlen(lpStr) + 1;
            dwDependenciesLength += (DWORD)cchLength;
            lpStr = lpStr + cchLength;
        }
        dwDependenciesLength++;
    }

    if (lpPassword != NULL)
    {
        /* Convert the password to unicode */
        lpPasswordW = HeapAlloc(GetProcessHeap(),
                                HEAP_ZERO_MEMORY,
                                (strlen(lpPassword) + 1) * sizeof(WCHAR));
        if (lpPasswordW == NULL)
        {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return FALSE;
        }

        MultiByteToWideChar(CP_ACP,
                            0,
                            lpPassword,
                            -1,
                            lpPasswordW,
                            (int)(strlen(lpPassword) + 1));

        /* Encrypt the password */
        dwError = ScmEncryptPassword(hSCManager,
                                     lpPasswordW,
                                     &lpEncryptedPassword,
                                     &dwPasswordSize);
        if (dwError != ERROR_SUCCESS)
            goto done;
    }

    RpcTryExcept
    {
        dwError = RCreateServiceA((SC_RPC_HANDLE)hSCManager,
                                  (LPSTR)lpServiceName,
                                  (LPSTR)lpDisplayName,
                                  dwDesiredAccess,
                                  dwServiceType,
                                  dwStartType,
                                  dwErrorControl,
                                  (LPSTR)lpBinaryPathName,
                                  (LPSTR)lpLoadOrderGroup,
                                  lpdwTagId,
                                  (LPBYTE)lpDependencies,
                                  dwDependenciesLength,
                                  (LPSTR)lpServiceStartName,
                                  lpEncryptedPassword,
                                  dwPasswordSize,
                                  (SC_RPC_HANDLE *)&hService);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

done:
    if (lpPasswordW != NULL)
    {
        /* Wipe and release the password buffers */
        SecureZeroMemory(lpPasswordW, (wcslen(lpPasswordW) + 1) * sizeof(WCHAR));
        HeapFree(GetProcessHeap(), 0, lpPasswordW);

        if (lpEncryptedPassword != NULL)
        {
            SecureZeroMemory(lpEncryptedPassword, dwPasswordSize);
            HeapFree(GetProcessHeap(), 0, lpEncryptedPassword);
        }
    }

    SetLastError(dwError);
    if (dwError != ERROR_SUCCESS)
    {
        TRACE("RCreateServiceA() failed (Error %lu)\n", dwError);
        return NULL;
    }

    return hService;
}


/**********************************************************************
 *  CreateServiceW
 *
 * @implemented
 */
SC_HANDLE WINAPI
CreateServiceW(SC_HANDLE hSCManager,
               LPCWSTR lpServiceName,
               LPCWSTR lpDisplayName,
               DWORD dwDesiredAccess,
               DWORD dwServiceType,
               DWORD dwStartType,
               DWORD dwErrorControl,
               LPCWSTR lpBinaryPathName,
               LPCWSTR lpLoadOrderGroup,
               LPDWORD lpdwTagId,
               LPCWSTR lpDependencies,
               LPCWSTR lpServiceStartName,
               LPCWSTR lpPassword)
{
    SC_HANDLE hService = NULL;
    DWORD dwDependenciesLength = 0;
    DWORD dwError;
    SIZE_T cchLength;
    LPCWSTR lpStr;
    DWORD dwPasswordSize = 0;
    LPBYTE lpEncryptedPassword = NULL;

    TRACE("CreateServiceW(%p %s %s %lx %lu %lu %lu %s %s %p %s %s %s)\n",
          hSCManager, debugstr_w(lpServiceName), debugstr_w(lpDisplayName),
          dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl,
          debugstr_w(lpBinaryPathName), debugstr_w(lpLoadOrderGroup), lpdwTagId,
          debugstr_w(lpDependencies), debugstr_w(lpServiceStartName), debugstr_w(lpPassword));

    if (!hSCManager)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return NULL;
    }

    /* Calculate the Dependencies length */
    if (lpDependencies != NULL)
    {
        lpStr = lpDependencies;
        while (*lpStr)
        {
            cchLength = wcslen(lpStr) + 1;
            dwDependenciesLength += (DWORD)cchLength;
            lpStr = lpStr + cchLength;
        }
        dwDependenciesLength++;
        dwDependenciesLength *= sizeof(WCHAR);
    }

    if (lpPassword != NULL)
    {
        /* Encrypt the password */
        dwError = ScmEncryptPassword(hSCManager,
                                     lpPassword,
                                     &lpEncryptedPassword,
                                     &dwPasswordSize);
        if (dwError != ERROR_SUCCESS)
            goto done;
    }

    RpcTryExcept
    {
        dwError = RCreateServiceW((SC_RPC_HANDLE)hSCManager,
                                  lpServiceName,
                                  lpDisplayName,
                                  dwDesiredAccess,
                                  dwServiceType,
                                  dwStartType,
                                  dwErrorControl,
                                  lpBinaryPathName,
                                  lpLoadOrderGroup,
                                  lpdwTagId,
                                  (LPBYTE)lpDependencies,
                                  dwDependenciesLength,
                                  lpServiceStartName,
                                  lpEncryptedPassword,
                                  dwPasswordSize,
                                  (SC_RPC_HANDLE *)&hService);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

done:
    if (lpEncryptedPassword != NULL)
    {
        /* Wipe and release the password buffers */
        SecureZeroMemory(lpEncryptedPassword, dwPasswordSize);
        HeapFree(GetProcessHeap(), 0, lpEncryptedPassword);
    }

    SetLastError(dwError);
    if (dwError != ERROR_SUCCESS)
    {
        TRACE("RCreateServiceW() failed (Error %lu)\n", dwError);
        return NULL;
    }

    return hService;
}


/**********************************************************************
 *  DeleteService
 *
 * @implemented
 */
BOOL WINAPI
DeleteService(SC_HANDLE hService)
{
    DWORD dwError;

    TRACE("DeleteService(%p)\n",
          hService);

    RpcTryExcept
    {
        dwError = RDeleteService((SC_RPC_HANDLE)hService);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    if (dwError != ERROR_SUCCESS)
    {
        TRACE("RDeleteService() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
        return FALSE;
    }

    return TRUE;
}


#ifdef SYSWOW64_GUEST
/*
 * The SCM (services.exe) is a native 64-bit process, and the calls below return a structure, or an
 * array of them, as raw bytes in the 64-bit layout. The pointer members are 8 bytes wide there and hold
 * an offset from the start of the buffer, the strings follow the array:
 *
 *   ENUM_SERVICE_STATUS(_PROCESS): lpServiceName (0) lpDisplayName (8) SERVICE_STATUS(_PROCESS) (16)
 *       48 bytes per element (56 with the process information), 36 and 44 in the 32-bit layout
 *   QUERY_SERVICE_LOCK_STATUS:     fIsLocked (0) lpLockOwner (8) dwLockDuration (16), 24 bytes (12)
 *   SERVICE_DESCRIPTION:           lpDescription (0), 8 bytes (4)
 *   SERVICE_REQUIRED_PRIVILEGES_INFO: pmszRequiredPrivileges (0), 8 bytes (4)
 *   SERVICE_TRIGGER_INFO:          cTriggers (0) pTriggers (8) pReserved (16), 24 bytes (12); a trigger
 *                                  dwTriggerType (0) dwAction (4) pTriggerSubtype (8) cDataItems (16)
 *                                  pDataItems (24), 32 bytes (20); a data item dwDataType (0) cbData (4)
 *                                  pData (8), 16 bytes (12)
 *   SERVICE_FAILURE_ACTIONS:       dwResetPeriod (0) lpRebootMsg (8) lpCommand (16) cActions (24)
 *                                  lpsaActions (32), 40 bytes (20)
 *
 * A 32-bit caller gets the 32-bit layout, the pointers made absolute, and the sizes and the resume handle
 * in terms of that layout, so that a buffer of the size that is reported is always enough.
 */
#define SCM64_ENUM_STATUS_SIZE          48
#define SCM64_ENUM_STATUS_PROCESS_SIZE  56

/* Smaller than the smallest entry (an element and two one-character names) in the 64-bit layout */
#define SCM64_ENUM_PROBE_SIZE           47

typedef struct _SCM_WOW64_ENUM
{
    SC_HANDLE hHandle;
    BOOL bDependents;
    BOOL bProcess;
    BOOL bUnicode;
    DWORD dwServiceType;
    DWORD dwServiceState;
    LPCVOID pszGroupName;
} SCM_WOW64_ENUM;

static DWORD
ScmWow64EnumRpc(const SCM_WOW64_ENUM *pEnum,
                LPBYTE lpBuffer,
                DWORD cbBufSize,
                LPDWORD pcbBytesNeeded,
                LPDWORD lpServicesReturned,
                LPDWORD lpResumeHandle)
{
    DWORD dwError;

    RpcTryExcept
    {
        if (pEnum->bDependents)
        {
            if (pEnum->bUnicode)
                dwError = REnumDependentServicesW((SC_RPC_HANDLE)pEnum->hHandle,
                                                  pEnum->dwServiceState,
                                                  lpBuffer,
                                                  cbBufSize,
                                                  pcbBytesNeeded,
                                                  lpServicesReturned);
            else
                dwError = REnumDependentServicesA((SC_RPC_HANDLE)pEnum->hHandle,
                                                  pEnum->dwServiceState,
                                                  lpBuffer,
                                                  cbBufSize,
                                                  pcbBytesNeeded,
                                                  lpServicesReturned);
        }
        else if (pEnum->bProcess)
        {
            if (pEnum->bUnicode)
                dwError = REnumServicesStatusExW((SC_RPC_HANDLE)pEnum->hHandle,
                                                 SC_ENUM_PROCESS_INFO,
                                                 pEnum->dwServiceType,
                                                 pEnum->dwServiceState,
                                                 lpBuffer,
                                                 cbBufSize,
                                                 pcbBytesNeeded,
                                                 lpServicesReturned,
                                                 lpResumeHandle,
                                                 (LPWSTR)pEnum->pszGroupName);
            else
                dwError = REnumServicesStatusExA((SC_RPC_HANDLE)pEnum->hHandle,
                                                 SC_ENUM_PROCESS_INFO,
                                                 pEnum->dwServiceType,
                                                 pEnum->dwServiceState,
                                                 lpBuffer,
                                                 cbBufSize,
                                                 pcbBytesNeeded,
                                                 lpServicesReturned,
                                                 lpResumeHandle,
                                                 (LPSTR)pEnum->pszGroupName);
        }
        else
        {
            if (pEnum->bUnicode)
                dwError = REnumServicesStatusW((SC_RPC_HANDLE)pEnum->hHandle,
                                               pEnum->dwServiceType,
                                               pEnum->dwServiceState,
                                               lpBuffer,
                                               cbBufSize,
                                               pcbBytesNeeded,
                                               lpServicesReturned,
                                               lpResumeHandle);
            else
                dwError = REnumServicesStatusA((SC_RPC_HANDLE)pEnum->hHandle,
                                               pEnum->dwServiceType,
                                               pEnum->dwServiceState,
                                               lpBuffer,
                                               cbBufSize,
                                               pcbBytesNeeded,
                                               lpServicesReturned,
                                               lpResumeHandle);
        }
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    return dwError;
}

/* The number of characters of a string at an offset in the SCM's buffer, without the terminator */
static BOOL
ScmWow64StringLength(LPBYTE lpBase,
                     DWORD cbBase,
                     ULONG64 ullOffset,
                     BOOL bUnicode,
                     PDWORD pdwLength)
{
    DWORD dwLength = 0;

    if (ullOffset >= cbBase)
        return FALSE;

    if (bUnicode)
    {
        PWCHAR pch = (PWCHAR)(lpBase + (ULONG)ullOffset);
        DWORD dwMax = (cbBase - (ULONG)ullOffset) / sizeof(WCHAR);

        while (dwLength < dwMax && pch[dwLength] != UNICODE_NULL)
            dwLength++;
        if (dwLength == dwMax)
            return FALSE;
    }
    else
    {
        PCHAR pch = (PCHAR)(lpBase + (ULONG)ullOffset);
        DWORD dwMax = cbBase - (ULONG)ullOffset;

        while (dwLength < dwMax && pch[dwLength] != ANSI_NULL)
            dwLength++;
        if (dwLength == dwMax)
            return FALSE;
    }

    *pdwLength = dwLength;
    return TRUE;
}

/*
 * EnumServicesStatusA/W, EnumServicesStatusExA/W and EnumDependentServicesA/W.
 *
 * What fits in a buffer, what is needed for the rest and where to resume depend on the size of the
 * elements, which the SCM works out for its own layout. So take the whole remaining list from the SCM
 * (the size comes from a first call that cannot return any element) and make the caller's buffer from it.
 * The SCM sizes the strings in characters of the Unicode call for both the Unicode and the ANSI call, and
 * so does the size reported here.
 */
static BOOL
ScmWow64EnumStatus(const SCM_WOW64_ENUM *pEnum,
                   LPBYTE lpServices,
                   DWORD cbBufSize,
                   LPDWORD pcbBytesNeeded,
                   LPDWORD lpServicesReturned,
                   LPDWORD lpResumeHandle)
{
    const DWORD dwSize64 = pEnum->bProcess ? SCM64_ENUM_STATUS_PROCESS_SIZE : SCM64_ENUM_STATUS_SIZE;
    const DWORD dwSize32 = pEnum->bProcess ? sizeof(ENUM_SERVICE_STATUS_PROCESSW) : sizeof(ENUM_SERVICE_STATUSW);
    const DWORD dwCharSize = pEnum->bUnicode ? sizeof(WCHAR) : sizeof(CHAR);
    const DWORD dwResumeIn = lpResumeHandle ? *lpResumeHandle : 0;
    BYTE Probe[SCM64_ENUM_STATUS_PROCESS_SIZE];
    LPBYTE lpBuffer = NULL, lpEntry, lpString;
    DWORD dwNeeded = 0, dwReturned = 0, dwResume, dwError, dwBufSize, dwTry, i;
    DWORD dwTotal32 = 0, dwUsed32 = 0, dwUsed64 = 0, dwFit = 0;
    BOOL bFits = TRUE, bMore;

    if (pcbBytesNeeded == NULL || lpServicesReturned == NULL)
    {
        SetLastError(ERROR_INVALID_ADDRESS);
        return FALSE;
    }

    /* How much is left; no element can be returned in this buffer */
    RtlZeroMemory(Probe, sizeof(Probe));
    dwResume = dwResumeIn;
    dwError = ScmWow64EnumRpc(pEnum, Probe, SCM64_ENUM_PROBE_SIZE, &dwNeeded, &dwReturned,
                              lpResumeHandle ? &dwResume : NULL);
    if (dwError == ERROR_SUCCESS)
    {
        *pcbBytesNeeded = 0;
        *lpServicesReturned = 0;
        return TRUE;
    }
    if (dwError != ERROR_MORE_DATA)
        goto Fail;

    /* All of it; a little more room than the SCM says does no harm */
    for (dwTry = 0; ; dwTry++)
    {
        dwBufSize = (dwNeeded > 1024 * 256 - 64) ? 1024 * 256 : dwNeeded + 64;
        lpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufSize);
        if (lpBuffer == NULL)
        {
            dwError = ERROR_NOT_ENOUGH_MEMORY;
            goto Fail;
        }

        dwResume = dwResumeIn;
        dwReturned = 0;
        dwError = ScmWow64EnumRpc(pEnum, lpBuffer, dwBufSize, &dwNeeded, &dwReturned,
                                  lpResumeHandle ? &dwResume : NULL);
        if (dwError == ERROR_SUCCESS || dwBufSize == 1024 * 256 || dwTry >= 3)
            break;
        if (dwError != ERROR_MORE_DATA)
            goto Fail;

        /* More services than a moment ago */
        HeapFree(GetProcessHeap(), 0, lpBuffer);
        lpBuffer = NULL;
    }
    if (dwError != ERROR_SUCCESS && dwError != ERROR_MORE_DATA)
        goto Fail;

    /* What of it fits the caller's buffer in the 32-bit layout */
    for (i = 0; i < dwReturned; i++)
    {
        ULONG64 ullName, ullDisplay;
        DWORD dwNameLength, dwDisplayLength, dwStrings;

        RtlCopyMemory(&ullName, lpBuffer + i * dwSize64, sizeof(ULONG64));
        RtlCopyMemory(&ullDisplay, lpBuffer + i * dwSize64 + sizeof(ULONG64), sizeof(ULONG64));
        if (!ScmWow64StringLength(lpBuffer, dwBufSize, ullName, pEnum->bUnicode, &dwNameLength) ||
            !ScmWow64StringLength(lpBuffer, dwBufSize, ullDisplay, pEnum->bUnicode, &dwDisplayLength))
        {
            dwError = ERROR_INVALID_DATA;
            goto Fail;
        }

        dwStrings = (dwNameLength + dwDisplayLength + 2) * sizeof(WCHAR);
        dwTotal32 += dwSize32 + dwStrings;
        if (bFits && lpServices != NULL && dwUsed32 + dwSize32 + dwStrings <= cbBufSize)
        {
            dwUsed32 += dwSize32 + dwStrings;
            dwUsed64 += dwSize64 + dwStrings;
            dwFit++;
        }
        else
        {
            bFits = FALSE;
        }
    }

    /* The dependents come all or none */
    if (pEnum->bDependents && dwFit != dwReturned)
        dwFit = 0;

    lpEntry = lpServices;
    lpString = lpServices + dwFit * dwSize32;
    for (i = 0; i < dwFit; i++)
    {
        ULONG64 ullName, ullDisplay;
        DWORD dwNameLength, dwDisplayLength;
        LPBYTE lpSource = lpBuffer + i * dwSize64;
        PVOID pName, pDisplay;

        RtlCopyMemory(&ullName, lpSource, sizeof(ULONG64));
        RtlCopyMemory(&ullDisplay, lpSource + sizeof(ULONG64), sizeof(ULONG64));
        ScmWow64StringLength(lpBuffer, dwBufSize, ullName, pEnum->bUnicode, &dwNameLength);
        ScmWow64StringLength(lpBuffer, dwBufSize, ullDisplay, pEnum->bUnicode, &dwDisplayLength);

        pName = lpString;
        RtlCopyMemory(lpString, lpBuffer + (ULONG)ullName, (dwNameLength + 1) * dwCharSize);
        lpString += (dwNameLength + 1) * dwCharSize;
        pDisplay = lpString;
        RtlCopyMemory(lpString, lpBuffer + (ULONG)ullDisplay, (dwDisplayLength + 1) * dwCharSize);
        lpString += (dwDisplayLength + 1) * dwCharSize;

        /* Both kinds have the two pointers first, then the status (the 32-bit pointers are 4 bytes) */
        RtlCopyMemory(lpEntry, &pName, sizeof(PVOID));
        RtlCopyMemory(lpEntry + sizeof(PVOID), &pDisplay, sizeof(PVOID));
        RtlCopyMemory(lpEntry + 2 * sizeof(PVOID),
                      lpSource + 2 * sizeof(ULONG64),
                      dwSize32 - 2 * sizeof(PVOID));
        lpEntry += dwSize32;
    }

    *lpServicesReturned = dwFit;

    bMore = (dwFit != dwReturned) || (dwError == ERROR_MORE_DATA);
    if (!bMore)
    {
        *pcbBytesNeeded = 0;
        if (lpResumeHandle)
            *lpResumeHandle = 0;
        HeapFree(GetProcessHeap(), 0, lpBuffer);
        return TRUE;
    }

    /* What the SCM could not return in the buffer, in the sizes of the 64-bit layout, is left as it is */
    *pcbBytesNeeded = dwTotal32;
    if (dwError == ERROR_MORE_DATA)
    {
        DWORD dwTaken64 = 0;

        for (i = 0; i < dwReturned; i++)
        {
            ULONG64 ullName, ullDisplay;
            DWORD dwNameLength, dwDisplayLength;

            RtlCopyMemory(&ullName, lpBuffer + i * dwSize64, sizeof(ULONG64));
            RtlCopyMemory(&ullDisplay, lpBuffer + i * dwSize64 + sizeof(ULONG64), sizeof(ULONG64));
            ScmWow64StringLength(lpBuffer, dwBufSize, ullName, pEnum->bUnicode, &dwNameLength);
            ScmWow64StringLength(lpBuffer, dwBufSize, ullDisplay, pEnum->bUnicode, &dwDisplayLength);
            dwTaken64 += dwSize64 + (dwNameLength + dwDisplayLength + 2) * sizeof(WCHAR);
        }
        if (dwNeeded > dwTaken64)
            *pcbBytesNeeded += dwNeeded - dwTaken64;
    }

    if (lpResumeHandle)
    {
        if (dwFit == 0)
        {
            *lpResumeHandle = dwResumeIn;
        }
        else if (dwFit == dwReturned)
        {
            *lpResumeHandle = dwResume;
        }
        else
        {
            /* The resume handle after the last element that fit: the SCM stops there with exactly its size */
            dwResume = dwResumeIn;
            ScmWow64EnumRpc(pEnum, lpBuffer, dwUsed64, &dwNeeded, &dwReturned, &dwResume);
            *lpResumeHandle = dwResume;
        }
    }

    HeapFree(GetProcessHeap(), 0, lpBuffer);
    SetLastError(ERROR_MORE_DATA);
    return FALSE;

Fail:
    if (lpBuffer)
        HeapFree(GetProcessHeap(), 0, lpBuffer);
    /* What the SCM reported with the error: both are set to zero first thing */
    *pcbBytesNeeded = dwNeeded;
    *lpServicesReturned = dwReturned;
    SetLastError(dwError);
    return FALSE;
}
#endif

/**********************************************************************
 *  EnumDependentServicesA
 *
 * @implemented
 */
BOOL WINAPI
EnumDependentServicesA(SC_HANDLE hService,
                       DWORD dwServiceState,
                       LPENUM_SERVICE_STATUSA lpServices,
                       DWORD cbBufSize,
                       LPDWORD pcbBytesNeeded,
                       LPDWORD lpServicesReturned)
{
    ENUM_SERVICE_STATUSA ServiceStatus;
    LPENUM_SERVICE_STATUSA lpStatusPtr;
    DWORD dwBufferSize;
    DWORD dwError;
    DWORD dwCount;

    TRACE("EnumDependentServicesA(%p %lu %p %lu %p %p)\n",
          hService, dwServiceState, lpServices, cbBufSize,
          pcbBytesNeeded, lpServicesReturned);

#ifdef SYSWOW64_GUEST
    {
        SCM_WOW64_ENUM Enum = { hService, TRUE, FALSE, FALSE, 0, dwServiceState, NULL };

        return ScmWow64EnumStatus(&Enum, (LPBYTE)lpServices, cbBufSize,
                                  pcbBytesNeeded, lpServicesReturned, NULL);
    }
#endif

    if (lpServices == NULL || cbBufSize < sizeof(ENUM_SERVICE_STATUSA))
    {
        lpStatusPtr = &ServiceStatus;
        dwBufferSize = sizeof(ENUM_SERVICE_STATUSA);
    }
    else
    {
        lpStatusPtr = lpServices;
        dwBufferSize = cbBufSize;
    }

    RpcTryExcept
    {
        dwError = REnumDependentServicesA((SC_RPC_HANDLE)hService,
                                          dwServiceState,
                                          (LPBYTE)lpStatusPtr,
                                          dwBufferSize,
                                          pcbBytesNeeded,
                                          lpServicesReturned);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    if (dwError == ERROR_SUCCESS || dwError == ERROR_MORE_DATA)
    {
        for (dwCount = 0; dwCount < *lpServicesReturned; dwCount++)
        {
            if (lpStatusPtr->lpServiceName)
                lpStatusPtr->lpServiceName =
                    (LPSTR)((ULONG_PTR)lpServices + (ULONG_PTR)lpStatusPtr->lpServiceName);

            if (lpStatusPtr->lpDisplayName)
                lpStatusPtr->lpDisplayName =
                    (LPSTR)((ULONG_PTR)lpServices + (ULONG_PTR)lpStatusPtr->lpDisplayName);

            lpStatusPtr++;
        }
    }

    if (dwError != ERROR_SUCCESS)
    {
        TRACE("REnumDependentServicesA() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
        return FALSE;
    }

    TRACE("EnumDependentServicesA() done\n");

    return TRUE;
}


/**********************************************************************
 *  EnumDependentServicesW
 *
 * @implemented
 */
BOOL WINAPI
EnumDependentServicesW(SC_HANDLE hService,
                       DWORD dwServiceState,
                       LPENUM_SERVICE_STATUSW lpServices,
                       DWORD cbBufSize,
                       LPDWORD pcbBytesNeeded,
                       LPDWORD lpServicesReturned)
{
    ENUM_SERVICE_STATUSW ServiceStatus;
    LPENUM_SERVICE_STATUSW lpStatusPtr;
    DWORD dwBufferSize;
    DWORD dwError;
    DWORD dwCount;

    TRACE("EnumDependentServicesW(%p %lu %p %lu %p %p)\n",
          hService, dwServiceState, lpServices, cbBufSize,
          pcbBytesNeeded, lpServicesReturned);

#ifdef SYSWOW64_GUEST
    {
        SCM_WOW64_ENUM Enum = { hService, TRUE, FALSE, TRUE, 0, dwServiceState, NULL };

        return ScmWow64EnumStatus(&Enum, (LPBYTE)lpServices, cbBufSize,
                                  pcbBytesNeeded, lpServicesReturned, NULL);
    }
#endif

    if (lpServices == NULL || cbBufSize < sizeof(ENUM_SERVICE_STATUSW))
    {
        lpStatusPtr = &ServiceStatus;
        dwBufferSize = sizeof(ENUM_SERVICE_STATUSW);
    }
    else
    {
        lpStatusPtr = lpServices;
        dwBufferSize = cbBufSize;
    }

    RpcTryExcept
    {
        dwError = REnumDependentServicesW((SC_RPC_HANDLE)hService,
                                          dwServiceState,
                                          (LPBYTE)lpStatusPtr,
                                          dwBufferSize,
                                          pcbBytesNeeded,
                                          lpServicesReturned);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    if (dwError == ERROR_SUCCESS || dwError == ERROR_MORE_DATA)
    {
        for (dwCount = 0; dwCount < *lpServicesReturned; dwCount++)
        {
            if (lpStatusPtr->lpServiceName)
                lpStatusPtr->lpServiceName =
                    (LPWSTR)((ULONG_PTR)lpServices + (ULONG_PTR)lpStatusPtr->lpServiceName);

            if (lpStatusPtr->lpDisplayName)
                lpStatusPtr->lpDisplayName =
                    (LPWSTR)((ULONG_PTR)lpServices + (ULONG_PTR)lpStatusPtr->lpDisplayName);

            lpStatusPtr++;
        }
    }

    if (dwError != ERROR_SUCCESS)
    {
        TRACE("REnumDependentServicesW() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
        return FALSE;
    }

    TRACE("EnumDependentServicesW() done\n");

    return TRUE;
}


/**********************************************************************
 *  EnumServiceGroupW
 *
 * @implemented
 */
BOOL WINAPI
EnumServiceGroupW(SC_HANDLE hSCManager,
                  DWORD dwServiceType,
                  DWORD dwServiceState,
                  LPENUM_SERVICE_STATUSW lpServices,
                  DWORD cbBufSize,
                  LPDWORD pcbBytesNeeded,
                  LPDWORD lpServicesReturned,
                  LPDWORD lpResumeHandle,
                  LPCWSTR lpGroup)
{
    ENUM_SERVICE_STATUSW ServiceStatus;
    LPENUM_SERVICE_STATUSW lpStatusPtr;
    DWORD dwBufferSize;
    DWORD dwError;
    DWORD dwCount;

    TRACE("EnumServiceGroupW(%p %lu %lu %p %lu %p %p %p %s)\n",
          hSCManager, dwServiceType, dwServiceState, lpServices,
          cbBufSize, pcbBytesNeeded, lpServicesReturned,
          lpResumeHandle, debugstr_w(lpGroup));

    if (!hSCManager)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if (pcbBytesNeeded == NULL || lpServicesReturned == NULL)
    {
        SetLastError(ERROR_INVALID_ADDRESS);
        return FALSE;
    }

    if (lpServices == NULL || cbBufSize < sizeof(ENUM_SERVICE_STATUSW))
    {
        lpStatusPtr = &ServiceStatus;
        dwBufferSize = sizeof(ENUM_SERVICE_STATUSW);
    }
    else
    {
        lpStatusPtr = lpServices;
        dwBufferSize = cbBufSize;
    }

    RpcTryExcept
    {
        if (lpGroup == NULL)
        {
            dwError = REnumServicesStatusW((SC_RPC_HANDLE)hSCManager,
                                           dwServiceType,
                                           dwServiceState,
                                           (LPBYTE)lpStatusPtr,
                                           dwBufferSize,
                                           pcbBytesNeeded,
                                           lpServicesReturned,
                                           lpResumeHandle);
        }
        else
        {
            dwError = REnumServiceGroupW((SC_RPC_HANDLE)hSCManager,
                                         dwServiceType,
                                         dwServiceState,
                                         (LPBYTE)lpStatusPtr,
                                         dwBufferSize,
                                         pcbBytesNeeded,
                                         lpServicesReturned,
                                         lpResumeHandle,
                                         lpGroup);
        }
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    if (dwError == ERROR_SUCCESS || dwError == ERROR_MORE_DATA)
    {
        for (dwCount = 0; dwCount < *lpServicesReturned; dwCount++)
        {
            if (lpStatusPtr->lpServiceName)
                lpStatusPtr->lpServiceName =
                    (LPWSTR)((ULONG_PTR)lpServices + (ULONG_PTR)lpStatusPtr->lpServiceName);

            if (lpStatusPtr->lpDisplayName)
                lpStatusPtr->lpDisplayName =
                    (LPWSTR)((ULONG_PTR)lpServices + (ULONG_PTR)lpStatusPtr->lpDisplayName);

            lpStatusPtr++;
        }
    }

    if (dwError != ERROR_SUCCESS)
    {
        TRACE("REnumServiceGroupW() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
        return FALSE;
    }

    TRACE("EnumServiceGroupW() done\n");

    return TRUE;
}


/**********************************************************************
 *  EnumServicesStatusA
 *
 * @implemented
 */
BOOL WINAPI
EnumServicesStatusA(SC_HANDLE hSCManager,
                    DWORD dwServiceType,
                    DWORD dwServiceState,
                    LPENUM_SERVICE_STATUSA lpServices,
                    DWORD cbBufSize,
                    LPDWORD pcbBytesNeeded,
                    LPDWORD lpServicesReturned,
                    LPDWORD lpResumeHandle)
{
    ENUM_SERVICE_STATUSA ServiceStatus;
    LPENUM_SERVICE_STATUSA lpStatusPtr;
    DWORD dwBufferSize;
    DWORD dwError;
    DWORD dwCount;

    TRACE("EnumServicesStatusA(%p %lu %lu %p %lu %p %p %p)\n",
          hSCManager, dwServiceType, dwServiceState, lpServices,
          cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle);

    if (!hSCManager)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if (pcbBytesNeeded == NULL || lpServicesReturned == NULL)
    {
        SetLastError(ERROR_INVALID_ADDRESS);
        return FALSE;
    }

#ifdef SYSWOW64_GUEST
    {
        SCM_WOW64_ENUM Enum = { hSCManager, FALSE, FALSE, FALSE, dwServiceType, dwServiceState, NULL };

        return ScmWow64EnumStatus(&Enum, (LPBYTE)lpServices, cbBufSize,
                                  pcbBytesNeeded, lpServicesReturned, lpResumeHandle);
    }
#endif

    if (lpServices == NULL || cbBufSize < sizeof(ENUM_SERVICE_STATUSA))
    {
        lpStatusPtr = &ServiceStatus;
        dwBufferSize = sizeof(ENUM_SERVICE_STATUSA);
    }
    else
    {
        lpStatusPtr = lpServices;
        dwBufferSize = cbBufSize;
    }

    RpcTryExcept
    {
        dwError = REnumServicesStatusA((SC_RPC_HANDLE)hSCManager,
                                       dwServiceType,
                                       dwServiceState,
                                       (LPBYTE)lpStatusPtr,
                                       dwBufferSize,
                                       pcbBytesNeeded,
                                       lpServicesReturned,
                                       lpResumeHandle);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    if (dwError == ERROR_SUCCESS || dwError == ERROR_MORE_DATA)
    {
        for (dwCount = 0; dwCount < *lpServicesReturned; dwCount++)
        {
            if (lpStatusPtr->lpServiceName)
                lpStatusPtr->lpServiceName =
                    (LPSTR)((ULONG_PTR)lpServices + (ULONG_PTR)lpStatusPtr->lpServiceName);

            if (lpStatusPtr->lpDisplayName)
                lpStatusPtr->lpDisplayName =
                    (LPSTR)((ULONG_PTR)lpServices + (ULONG_PTR)lpStatusPtr->lpDisplayName);

            lpStatusPtr++;
        }
    }

    if (dwError != ERROR_SUCCESS)
    {
        TRACE("REnumServicesStatusA() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
        return FALSE;
    }

    TRACE("EnumServicesStatusA() done\n");

    return TRUE;
}


/**********************************************************************
 *  EnumServicesStatusW
 *
 * @implemented
 */
BOOL WINAPI
EnumServicesStatusW(SC_HANDLE hSCManager,
                    DWORD dwServiceType,
                    DWORD dwServiceState,
                    LPENUM_SERVICE_STATUSW lpServices,
                    DWORD cbBufSize,
                    LPDWORD pcbBytesNeeded,
                    LPDWORD lpServicesReturned,
                    LPDWORD lpResumeHandle)
{
    ENUM_SERVICE_STATUSW ServiceStatus;
    LPENUM_SERVICE_STATUSW lpStatusPtr;
    DWORD dwBufferSize;
    DWORD dwError;
    DWORD dwCount;

    TRACE("EnumServicesStatusW(%p %lu %lu %p %lu %p %p %p)\n",
          hSCManager, dwServiceType, dwServiceState, lpServices,
          cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle);

    if (!hSCManager)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if (pcbBytesNeeded == NULL || lpServicesReturned == NULL)
    {
        SetLastError(ERROR_INVALID_ADDRESS);
        return FALSE;
    }

#ifdef SYSWOW64_GUEST
    {
        SCM_WOW64_ENUM Enum = { hSCManager, FALSE, FALSE, TRUE, dwServiceType, dwServiceState, NULL };

        return ScmWow64EnumStatus(&Enum, (LPBYTE)lpServices, cbBufSize,
                                  pcbBytesNeeded, lpServicesReturned, lpResumeHandle);
    }
#endif

    if (lpServices == NULL || cbBufSize < sizeof(ENUM_SERVICE_STATUSW))
    {
        lpStatusPtr = &ServiceStatus;
        dwBufferSize = sizeof(ENUM_SERVICE_STATUSW);
    }
    else
    {
        lpStatusPtr = lpServices;
        dwBufferSize = cbBufSize;
    }

    RpcTryExcept
    {
        dwError = REnumServicesStatusW((SC_RPC_HANDLE)hSCManager,
                                       dwServiceType,
                                       dwServiceState,
                                       (LPBYTE)lpStatusPtr,
                                       dwBufferSize,
                                       pcbBytesNeeded,
                                       lpServicesReturned,
                                       lpResumeHandle);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    if (dwError == ERROR_SUCCESS || dwError == ERROR_MORE_DATA)
    {
        for (dwCount = 0; dwCount < *lpServicesReturned; dwCount++)
        {
            if (lpStatusPtr->lpServiceName)
                lpStatusPtr->lpServiceName =
                    (LPWSTR)((ULONG_PTR)lpServices + (ULONG_PTR)lpStatusPtr->lpServiceName);

            if (lpStatusPtr->lpDisplayName)
                lpStatusPtr->lpDisplayName =
                    (LPWSTR)((ULONG_PTR)lpServices + (ULONG_PTR)lpStatusPtr->lpDisplayName);

            lpStatusPtr++;
        }
    }

    if (dwError != ERROR_SUCCESS)
    {
        TRACE("REnumServicesStatusW() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
        return FALSE;
    }

    TRACE("EnumServicesStatusW() done\n");

    return TRUE;
}


/**********************************************************************
 *  EnumServicesStatusExA
 *
 * @implemented
 */
BOOL WINAPI
EnumServicesStatusExA(SC_HANDLE hSCManager,
                      SC_ENUM_TYPE InfoLevel,
                      DWORD dwServiceType,
                      DWORD dwServiceState,
                      LPBYTE lpServices,
                      DWORD cbBufSize,
                      LPDWORD pcbBytesNeeded,
                      LPDWORD lpServicesReturned,
                      LPDWORD lpResumeHandle,
                      LPCSTR pszGroupName)
{
    ENUM_SERVICE_STATUS_PROCESSA ServiceStatus;
    LPENUM_SERVICE_STATUS_PROCESSA lpStatusPtr;
    DWORD dwBufferSize;
    DWORD dwError;
    DWORD dwCount;

    TRACE("EnumServicesStatusExA(%p %lu %lu %p %lu %p %p %p %s)\n",
          hSCManager, dwServiceType, dwServiceState, lpServices,
          cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle,
          debugstr_a(pszGroupName));

    if (InfoLevel != SC_ENUM_PROCESS_INFO)
    {
        SetLastError(ERROR_INVALID_LEVEL);
        return FALSE;
    }

    if (!hSCManager)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if (pcbBytesNeeded == NULL || lpServicesReturned == NULL)
    {
        SetLastError(ERROR_INVALID_ADDRESS);
        return FALSE;
    }

#ifdef SYSWOW64_GUEST
    {
        SCM_WOW64_ENUM Enum = { hSCManager, FALSE, TRUE, FALSE, dwServiceType, dwServiceState, pszGroupName };

        return ScmWow64EnumStatus(&Enum, (LPBYTE)lpServices, cbBufSize,
                                  pcbBytesNeeded, lpServicesReturned, lpResumeHandle);
    }
#endif

    if (lpServices == NULL || cbBufSize < sizeof(ENUM_SERVICE_STATUS_PROCESSA))
    {
        lpStatusPtr = &ServiceStatus;
        dwBufferSize = sizeof(ENUM_SERVICE_STATUS_PROCESSA);
    }
    else
    {
        lpStatusPtr = (LPENUM_SERVICE_STATUS_PROCESSA)lpServices;
        dwBufferSize = cbBufSize;
    }

    RpcTryExcept
    {
        dwError = REnumServicesStatusExA((SC_RPC_HANDLE)hSCManager,
                                         InfoLevel,
                                         dwServiceType,
                                         dwServiceState,
                                         (LPBYTE)lpStatusPtr,
                                         dwBufferSize,
                                         pcbBytesNeeded,
                                         lpServicesReturned,
                                         lpResumeHandle,
                                         (LPSTR)pszGroupName);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    if (dwError == ERROR_SUCCESS || dwError == ERROR_MORE_DATA)
    {
        if (InfoLevel == SC_ENUM_PROCESS_INFO)
        {
            for (dwCount = 0; dwCount < *lpServicesReturned; dwCount++)
            {
                if (lpStatusPtr->lpServiceName)
                    lpStatusPtr->lpServiceName =
                        (LPSTR)((ULONG_PTR)lpServices + (ULONG_PTR)lpStatusPtr->lpServiceName);

                if (lpStatusPtr->lpDisplayName)
                    lpStatusPtr->lpDisplayName =
                        (LPSTR)((ULONG_PTR)lpServices + (ULONG_PTR)lpStatusPtr->lpDisplayName);

                lpStatusPtr++;
            }
        }
    }

    if (dwError != ERROR_SUCCESS)
    {
        TRACE("REnumServicesStatusExA() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
        return FALSE;
    }

    TRACE("EnumServicesStatusExA() done\n");

    return TRUE;
}


/**********************************************************************
 *  EnumServicesStatusExW
 *
 * @implemented
 */
BOOL WINAPI
EnumServicesStatusExW(SC_HANDLE hSCManager,
                      SC_ENUM_TYPE InfoLevel,
                      DWORD dwServiceType,
                      DWORD dwServiceState,
                      LPBYTE lpServices,
                      DWORD cbBufSize,
                      LPDWORD pcbBytesNeeded,
                      LPDWORD lpServicesReturned,
                      LPDWORD lpResumeHandle,
                      LPCWSTR pszGroupName)
{
    ENUM_SERVICE_STATUS_PROCESSW ServiceStatus;
    LPENUM_SERVICE_STATUS_PROCESSW lpStatusPtr;
    DWORD dwBufferSize;
    DWORD dwError;
    DWORD dwCount;

    TRACE("EnumServicesStatusExW(%p %lu %lu %p %lu %p %p %p %s)\n",
          hSCManager, dwServiceType, dwServiceState, lpServices,
          cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle,
          debugstr_w(pszGroupName));

    if (InfoLevel != SC_ENUM_PROCESS_INFO)
    {
        SetLastError(ERROR_INVALID_LEVEL);
        return FALSE;
    }

    if (!hSCManager)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if (pcbBytesNeeded == NULL || lpServicesReturned == NULL)
    {
        SetLastError(ERROR_INVALID_ADDRESS);
        return FALSE;
    }

#ifdef SYSWOW64_GUEST
    {
        SCM_WOW64_ENUM Enum = { hSCManager, FALSE, TRUE, TRUE, dwServiceType, dwServiceState, pszGroupName };

        return ScmWow64EnumStatus(&Enum, (LPBYTE)lpServices, cbBufSize,
                                  pcbBytesNeeded, lpServicesReturned, lpResumeHandle);
    }
#endif

    if (lpServices == NULL || cbBufSize < sizeof(ENUM_SERVICE_STATUS_PROCESSW))
    {
        lpStatusPtr = &ServiceStatus;
        dwBufferSize = sizeof(ENUM_SERVICE_STATUS_PROCESSW);
    }
    else
    {
        lpStatusPtr = (LPENUM_SERVICE_STATUS_PROCESSW)lpServices;
        dwBufferSize = cbBufSize;
    }

    RpcTryExcept
    {
        dwError = REnumServicesStatusExW((SC_RPC_HANDLE)hSCManager,
                                         InfoLevel,
                                         dwServiceType,
                                         dwServiceState,
                                         (LPBYTE)lpStatusPtr,
                                         dwBufferSize,
                                         pcbBytesNeeded,
                                         lpServicesReturned,
                                         lpResumeHandle,
                                         (LPWSTR)pszGroupName);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    if (dwError == ERROR_SUCCESS || dwError == ERROR_MORE_DATA)
    {
        if (InfoLevel == SC_ENUM_PROCESS_INFO)
        {
            for (dwCount = 0; dwCount < *lpServicesReturned; dwCount++)
            {
                if (lpStatusPtr->lpServiceName)
                    lpStatusPtr->lpServiceName =
                        (LPWSTR)((ULONG_PTR)lpServices + (ULONG_PTR)lpStatusPtr->lpServiceName);

                if (lpStatusPtr->lpDisplayName)
                    lpStatusPtr->lpDisplayName =
                        (LPWSTR)((ULONG_PTR)lpServices + (ULONG_PTR)lpStatusPtr->lpDisplayName);

                lpStatusPtr++;
            }
        }
    }

    if (dwError != ERROR_SUCCESS)
    {
        TRACE("REnumServicesStatusExW() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
        return FALSE;
    }

    TRACE("EnumServicesStatusExW() done\n");

    return TRUE;
}


/**********************************************************************
 *  I_ScSendPnPMessage
 *
 * Undocumented
 *
 * @unimplemented
 */
BOOL
WINAPI
I_ScSendPnPMessage(
    _In_ SERVICE_STATUS_HANDLE hServiceStatus,
    _In_ DWORD dwControlCode,
    _In_ DWORD dwEventType,
    _In_ PVOID pEventData)
{
    BOOL bResult;

    TRACE("I_ScSendPnPMessage(%p %lu %lu %p)\n",
          hServiceStatus, dwControlCode, dwEventType, pEventData);

    RpcTryExcept
    {
        bResult = RI_ScSendPnPMessage((RPC_SERVICE_STATUS_HANDLE)(ULONG_PTR)hServiceStatus,
                                       dwControlCode,
                                       dwEventType,
                                       ((PDEV_BROADCAST_HDR)pEventData)->dbch_size,
                                       pEventData);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        SetLastError(ScmRpcStatusToWinError(RpcExceptionCode()));
        bResult = FALSE;
    }
    RpcEndExcept;

    return bResult;
}


/**********************************************************************
 *  GetServiceDisplayNameA
 *
 * @implemented
 */
BOOL WINAPI
GetServiceDisplayNameA(SC_HANDLE hSCManager,
                       LPCSTR lpServiceName,
                       LPSTR lpDisplayName,
                       LPDWORD lpcchBuffer)
{
    DWORD dwError;
    LPSTR lpNameBuffer;
    CHAR szEmptyName[] = "";

    TRACE("GetServiceDisplayNameA(%p %s %p %p)\n",
          hSCManager, debugstr_a(lpServiceName), lpDisplayName, lpcchBuffer);

    if (!hSCManager)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if (!lpDisplayName || *lpcchBuffer < sizeof(CHAR))
    {
        lpNameBuffer = szEmptyName;
        *lpcchBuffer = sizeof(CHAR);
    }
    else
    {
        lpNameBuffer = lpDisplayName;
    }

    RpcTryExcept
    {
        dwError = RGetServiceDisplayNameA((SC_RPC_HANDLE)hSCManager,
                                          lpServiceName,
                                          lpNameBuffer,
                                          lpcchBuffer);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    if (dwError != ERROR_SUCCESS)
    {
        TRACE("RGetServiceDisplayNameA() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
        return FALSE;
    }

    return TRUE;
}


/**********************************************************************
 *  GetServiceDisplayNameW
 *
 * @implemented
 */
BOOL WINAPI
GetServiceDisplayNameW(SC_HANDLE hSCManager,
                       LPCWSTR lpServiceName,
                       LPWSTR lpDisplayName,
                       LPDWORD lpcchBuffer)
{
    DWORD dwError;
    LPWSTR lpNameBuffer;
    WCHAR szEmptyName[] = L"";

    TRACE("GetServiceDisplayNameW(%p %s %p %p)\n",
          hSCManager, debugstr_w(lpServiceName), lpDisplayName, lpcchBuffer);

    if (!hSCManager)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    /*
     * NOTE: A size of 1 character would be enough, but tests show that
     * Windows returns 2 characters instead, certainly due to a WCHAR/bytes
     * mismatch in their code.
     */
    if (!lpDisplayName || *lpcchBuffer < sizeof(WCHAR))
    {
        lpNameBuffer = szEmptyName;
        *lpcchBuffer = sizeof(WCHAR);
    }
    else
    {
        lpNameBuffer = lpDisplayName;
    }

    RpcTryExcept
    {
        dwError = RGetServiceDisplayNameW((SC_RPC_HANDLE)hSCManager,
                                          lpServiceName,
                                          lpNameBuffer,
                                          lpcchBuffer);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    if (dwError != ERROR_SUCCESS)
    {
        TRACE("RGetServiceDisplayNameW() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
        return FALSE;
    }

    return TRUE;
}


/**********************************************************************
 *  GetServiceKeyNameA
 *
 * @implemented
 */
BOOL WINAPI
GetServiceKeyNameA(SC_HANDLE hSCManager,
                   LPCSTR lpDisplayName,
                   LPSTR lpServiceName,
                   LPDWORD lpcchBuffer)
{
    DWORD dwError;
    LPSTR lpNameBuffer;
    CHAR szEmptyName[] = "";

    TRACE("GetServiceKeyNameA(%p %s %p %p)\n",
          hSCManager, debugstr_a(lpDisplayName), lpServiceName, lpcchBuffer);

    if (!hSCManager)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if (!lpServiceName || *lpcchBuffer < sizeof(CHAR))
    {
        lpNameBuffer = szEmptyName;
        *lpcchBuffer = sizeof(CHAR);
    }
    else
    {
        lpNameBuffer = lpServiceName;
    }

    RpcTryExcept
    {
        dwError = RGetServiceKeyNameA((SC_RPC_HANDLE)hSCManager,
                                      lpDisplayName,
                                      lpNameBuffer,
                                      lpcchBuffer);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        /* HACK: because of a problem with rpcrt4, rpcserver is hacked to return 6 for ERROR_SERVICE_DOES_NOT_EXIST */
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    if (dwError != ERROR_SUCCESS)
    {
        TRACE("RGetServiceKeyNameA() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
        return FALSE;
    }

    return TRUE;
}


/**********************************************************************
 *  GetServiceKeyNameW
 *
 * @implemented
 */
BOOL WINAPI
GetServiceKeyNameW(SC_HANDLE hSCManager,
                   LPCWSTR lpDisplayName,
                   LPWSTR lpServiceName,
                   LPDWORD lpcchBuffer)
{
    DWORD dwError;
    LPWSTR lpNameBuffer;
    WCHAR szEmptyName[] = L"";

    TRACE("GetServiceKeyNameW(%p %s %p %p)\n",
          hSCManager, debugstr_w(lpDisplayName), lpServiceName, lpcchBuffer);

    if (!hSCManager)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    /*
     * NOTE: A size of 1 character would be enough, but tests show that
     * Windows returns 2 characters instead, certainly due to a WCHAR/bytes
     * mismatch in their code.
     */
    if (!lpServiceName || *lpcchBuffer < sizeof(WCHAR))
    {
        lpNameBuffer = szEmptyName;
        *lpcchBuffer = sizeof(WCHAR);
    }
    else
    {
        lpNameBuffer = lpServiceName;
    }

    RpcTryExcept
    {
        dwError = RGetServiceKeyNameW((SC_RPC_HANDLE)hSCManager,
                                      lpDisplayName,
                                      lpNameBuffer,
                                      lpcchBuffer);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    if (dwError != ERROR_SUCCESS)
    {
        TRACE("RGetServiceKeyNameW() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
        return FALSE;
    }

    return TRUE;
}


/**********************************************************************
 *  I_ScGetCurrentGroupStateW
 *
 * @implemented
 */
DWORD WINAPI
I_ScGetCurrentGroupStateW(SC_HANDLE hSCManager,
                          LPWSTR pszGroupName,
                          LPDWORD pdwGroupState)
{
    DWORD dwError;

    TRACE("I_ScGetCurrentGroupStateW(%p %s %p)\n",
          hSCManager, debugstr_w(pszGroupName), pdwGroupState);

    RpcTryExcept
    {
        dwError = RI_ScGetCurrentGroupStateW((SC_RPC_HANDLE)hSCManager,
                                             pszGroupName,
                                             pdwGroupState);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept

    if (dwError != ERROR_SUCCESS)
    {
        TRACE("RI_ScGetCurrentGroupStateW() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
    }

    return dwError;
}


/**********************************************************************
 *  I_ScValidatePnpService
 *
 * Undocumented
 *
 * @implemented
 */
DWORD
WINAPI
I_ScValidatePnpService(
    _In_ LPCWSTR pszMachineName,
    _In_ LPCWSTR pszServiceName,
    _Out_ SERVICE_STATUS_HANDLE *phServiceStatus)
{
    SC_RPC_HANDLE hSCManager = NULL;
    SERVICE_STATUS_HANDLE hServiceStatus = NULL;
    RPC_SERVICE_STATUS_HANDLE hRpcServiceStatus = 0;
    DWORD dwError;

    TRACE("I_ScValidatePnpService(%S %S %p)\n",
         pszMachineName, pszServiceName, phServiceStatus);

    hSCManager = OpenSCManagerW(pszMachineName,
                                SERVICES_ACTIVE_DATABASEW,
                                SC_MANAGER_CONNECT);
    if (hSCManager == NULL)
    {
        dwError = GetLastError();
        goto done;
    }

    RpcTryExcept
    {
        dwError = RI_ScValidatePnPService(hSCManager,
                                          (LPWSTR)pszServiceName,
                                          &hRpcServiceStatus);
        hServiceStatus = (SERVICE_STATUS_HANDLE)(ULONG_PTR)hRpcServiceStatus;
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept

    *phServiceStatus = hServiceStatus;

done:
    if (hSCManager != NULL)
        CloseServiceHandle(hSCManager);

    return dwError;
}


/**********************************************************************
 *  LockServiceDatabase
 *
 * @implemented
 */
SC_LOCK WINAPI
LockServiceDatabase(SC_HANDLE hSCManager)
{
    SC_LOCK hLock;
    DWORD dwError;

    TRACE("LockServiceDatabase(%p)\n",
          hSCManager);

    RpcTryExcept
    {
        dwError = RLockServiceDatabase((SC_RPC_HANDLE)hSCManager,
                                       (SC_RPC_LOCK *)&hLock);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    if (dwError != ERROR_SUCCESS)
    {
        TRACE("RLockServiceDatabase() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
        return NULL;
    }

    TRACE("hLock = %p\n", hLock);

    return hLock;
}


static VOID
WaitForSCManager(VOID)
{
    HANDLE hEvent;

    TRACE("WaitForSCManager()\n");

    /* Try to open the existing event */
    hEvent = OpenEventW(SYNCHRONIZE, FALSE, SCM_START_EVENT);
    if (hEvent == NULL)
    {
        if (GetLastError() != ERROR_FILE_NOT_FOUND)
            return;

        /* Try to create a new event */
        hEvent = CreateEventW(NULL, TRUE, FALSE, SCM_START_EVENT);
        if (hEvent == NULL)
            return;
    }

    /* Wait for 3 minutes */
    WaitForSingleObject(hEvent, 180000);
    CloseHandle(hEvent);

    TRACE("ScmWaitForSCManager() done\n");
}


/**********************************************************************
 *  OpenSCManagerA
 *
 * @implemented
 */
SC_HANDLE WINAPI
OpenSCManagerA(LPCSTR lpMachineName,
               LPCSTR lpDatabaseName,
               DWORD dwDesiredAccess)
{
    SC_HANDLE hScm = NULL;
    DWORD dwError;

    TRACE("OpenSCManagerA(%s %s %lx)\n",
          debugstr_a(lpMachineName), debugstr_a(lpDatabaseName), dwDesiredAccess);

    WaitForSCManager();

    RpcTryExcept
    {
        dwError = ROpenSCManagerA((LPSTR)lpMachineName,
                                  (LPSTR)lpDatabaseName,
                                  dwDesiredAccess,
                                  (SC_RPC_HANDLE *)&hScm);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    SetLastError(dwError);
    if (dwError != ERROR_SUCCESS)
    {
        TRACE("ROpenSCManagerA() failed (Error %lu)\n", dwError);
        return NULL;
    }

    TRACE("hScm = %p\n", hScm);

    return hScm;
}


/**********************************************************************
 *  OpenSCManagerW
 *
 * @implemented
 */
SC_HANDLE WINAPI
OpenSCManagerW(LPCWSTR lpMachineName,
               LPCWSTR lpDatabaseName,
               DWORD dwDesiredAccess)
{
    SC_HANDLE hScm = NULL;
    DWORD dwError;

    TRACE("OpenSCManagerW(%s %s %lx)\n",
          debugstr_w(lpMachineName), debugstr_w(lpDatabaseName), dwDesiredAccess);

    WaitForSCManager();

    RpcTryExcept
    {
        dwError = ROpenSCManagerW((LPWSTR)lpMachineName,
                                  (LPWSTR)lpDatabaseName,
                                  dwDesiredAccess,
                                  (SC_RPC_HANDLE *)&hScm);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    SetLastError(dwError);
    if (dwError != ERROR_SUCCESS)
    {
        TRACE("ROpenSCManagerW() failed (Error %lu)\n", dwError);
        return NULL;
    }

    TRACE("hScm = %p\n", hScm);

    return hScm;
}


/**********************************************************************
 *  OpenServiceA
 *
 * @implemented
 */
SC_HANDLE WINAPI
OpenServiceA(SC_HANDLE hSCManager,
             LPCSTR lpServiceName,
             DWORD dwDesiredAccess)
{
    SC_HANDLE hService = NULL;
    DWORD dwError;

    TRACE("OpenServiceA(%p %s %lx)\n",
           hSCManager, debugstr_a(lpServiceName), dwDesiredAccess);

    if (!hSCManager)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return NULL;
    }

    RpcTryExcept
    {
        dwError = ROpenServiceA((SC_RPC_HANDLE)hSCManager,
                                (LPSTR)lpServiceName,
                                dwDesiredAccess,
                                (SC_RPC_HANDLE *)&hService);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    SetLastError(dwError);
    if (dwError != ERROR_SUCCESS)
    {
        TRACE("ROpenServiceA() failed (Error %lu)\n", dwError);
        return NULL;
    }

    TRACE("hService = %p\n", hService);

    return hService;
}


/**********************************************************************
 *  OpenServiceW
 *
 * @implemented
 */
SC_HANDLE WINAPI
OpenServiceW(SC_HANDLE hSCManager,
             LPCWSTR lpServiceName,
             DWORD dwDesiredAccess)
{
    SC_HANDLE hService = NULL;
    DWORD dwError;

    TRACE("OpenServiceW(%p %s %lx)\n",
           hSCManager, debugstr_w(lpServiceName), dwDesiredAccess);

    if (!hSCManager)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return NULL;
    }

    RpcTryExcept
    {
        dwError = ROpenServiceW((SC_RPC_HANDLE)hSCManager,
                                (LPWSTR)lpServiceName,
                                dwDesiredAccess,
                                (SC_RPC_HANDLE *)&hService);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    SetLastError(dwError);
    if (dwError != ERROR_SUCCESS)
    {
        TRACE("ROpenServiceW() failed (Error %lu)\n", dwError);
        return NULL;
    }

    TRACE("hService = %p\n", hService);

    return hService;
}


#ifdef SYSWOW64_GUEST
/*
 * The SCM (services.exe) is a native 64-bit process. RQueryServiceConfigA/W
 * return its QUERY_SERVICE_CONFIG in the 64-bit layout, where every string
 * member is 8 bytes wide (and holds an offset from the start of the buffer):
 *
 *   0 dwServiceType  4 dwStartType  8 dwErrorControl  16 lpBinaryPathName
 *  24 lpLoadOrderGroup  32 dwTagId  40 lpDependencies  48 lpServiceStartName
 *  56 lpDisplayName  (64 bytes)
 *
 * A 32-bit caller expects the 36-byte 32-bit layout. Rewrite the header in
 * place; the strings stay where the SCM put them, so the offsets stay valid,
 * and the 64-bit header is larger than the 32-bit one, so nothing overlaps.
 */
static VOID
ScmWow64ServiceConfigTo32(LPBYTE lpBuffer)
{
    DWORD dwServiceType, dwStartType, dwErrorControl, dwTagId;
    ULONG64 ullStrings[5];
    LPQUERY_SERVICE_CONFIGW lpConfig = (LPQUERY_SERVICE_CONFIGW)lpBuffer;

    RtlCopyMemory(&dwServiceType, lpBuffer + 0, sizeof(DWORD));
    RtlCopyMemory(&dwStartType, lpBuffer + 4, sizeof(DWORD));
    RtlCopyMemory(&dwErrorControl, lpBuffer + 8, sizeof(DWORD));
    RtlCopyMemory(&ullStrings[0], lpBuffer + 16, sizeof(ULONG64));
    RtlCopyMemory(&ullStrings[1], lpBuffer + 24, sizeof(ULONG64));
    RtlCopyMemory(&dwTagId, lpBuffer + 32, sizeof(DWORD));
    RtlCopyMemory(&ullStrings[2], lpBuffer + 40, sizeof(ULONG64));
    RtlCopyMemory(&ullStrings[3], lpBuffer + 48, sizeof(ULONG64));
    RtlCopyMemory(&ullStrings[4], lpBuffer + 56, sizeof(ULONG64));

    lpConfig->dwServiceType = dwServiceType;
    lpConfig->dwStartType = dwStartType;
    lpConfig->dwErrorControl = dwErrorControl;
    lpConfig->lpBinaryPathName = (LPWSTR)(ULONG_PTR)ullStrings[0];
    lpConfig->lpLoadOrderGroup = (LPWSTR)(ULONG_PTR)ullStrings[1];
    lpConfig->dwTagId = dwTagId;
    lpConfig->lpDependencies = (LPWSTR)(ULONG_PTR)ullStrings[2];
    lpConfig->lpServiceStartName = (LPWSTR)(ULONG_PTR)ullStrings[3];
    lpConfig->lpDisplayName = (LPWSTR)(ULONG_PTR)ullStrings[4];
}
#endif

/**********************************************************************
 *  QueryServiceConfigA
 *
 * @implemented
 */
BOOL WINAPI
QueryServiceConfigA(SC_HANDLE hService,
                    LPQUERY_SERVICE_CONFIGA lpServiceConfig,
                    DWORD cbBufSize,
                    LPDWORD pcbBytesNeeded)
{
    QUERY_SERVICE_CONFIGA ServiceConfig;
    LPQUERY_SERVICE_CONFIGA lpConfigPtr;
    DWORD dwBufferSize;
    DWORD dwError;

    TRACE("QueryServiceConfigA(%p %p %lu %p)\n",
           hService, lpServiceConfig, cbBufSize, pcbBytesNeeded);

    if (lpServiceConfig == NULL ||
        cbBufSize < sizeof(QUERY_SERVICE_CONFIGA))
    {
        lpConfigPtr = &ServiceConfig;
        dwBufferSize = sizeof(QUERY_SERVICE_CONFIGA);
    }
    else
    {
        lpConfigPtr = lpServiceConfig;
        dwBufferSize = cbBufSize;
    }

    RpcTryExcept
    {
        dwError = RQueryServiceConfigA((SC_RPC_HANDLE)hService,
                                       (LPBYTE)lpConfigPtr,
                                       dwBufferSize,
                                       pcbBytesNeeded);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    if (dwError != ERROR_SUCCESS)
    {
        TRACE("RQueryServiceConfigA() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
        return FALSE;
    }

#ifdef SYSWOW64_GUEST
    ScmWow64ServiceConfigTo32((LPBYTE)lpConfigPtr);
#endif

    /* Adjust the pointers */
    if (lpConfigPtr->lpBinaryPathName)
        lpConfigPtr->lpBinaryPathName =
            (LPSTR)((ULONG_PTR)lpConfigPtr +
                    (ULONG_PTR)lpConfigPtr->lpBinaryPathName);

    if (lpConfigPtr->lpLoadOrderGroup)
        lpConfigPtr->lpLoadOrderGroup =
            (LPSTR)((ULONG_PTR)lpConfigPtr +
                    (ULONG_PTR)lpConfigPtr->lpLoadOrderGroup);

    if (lpConfigPtr->lpDependencies)
        lpConfigPtr->lpDependencies =
            (LPSTR)((ULONG_PTR)lpConfigPtr +
                    (ULONG_PTR)lpConfigPtr->lpDependencies);

    if (lpConfigPtr->lpServiceStartName)
        lpConfigPtr->lpServiceStartName =
            (LPSTR)((ULONG_PTR)lpConfigPtr +
                    (ULONG_PTR)lpConfigPtr->lpServiceStartName);

    if (lpConfigPtr->lpDisplayName)
        lpConfigPtr->lpDisplayName =
           (LPSTR)((ULONG_PTR)lpConfigPtr +
                   (ULONG_PTR)lpConfigPtr->lpDisplayName);

    TRACE("QueryServiceConfigA() done\n");

    return TRUE;
}


/**********************************************************************
 *  QueryServiceConfigW
 *
 * @implemented
 */
BOOL WINAPI
QueryServiceConfigW(SC_HANDLE hService,
                    LPQUERY_SERVICE_CONFIGW lpServiceConfig,
                    DWORD cbBufSize,
                    LPDWORD pcbBytesNeeded)
{
    QUERY_SERVICE_CONFIGW ServiceConfig;
    LPQUERY_SERVICE_CONFIGW lpConfigPtr;
    DWORD dwBufferSize;
    DWORD dwError;

    TRACE("QueryServiceConfigW(%p %p %lu %p)\n",
           hService, lpServiceConfig, cbBufSize, pcbBytesNeeded);

    if (lpServiceConfig == NULL ||
        cbBufSize < sizeof(QUERY_SERVICE_CONFIGW))
    {
        lpConfigPtr = &ServiceConfig;
        dwBufferSize = sizeof(QUERY_SERVICE_CONFIGW);
    }
    else
    {
        lpConfigPtr = lpServiceConfig;
        dwBufferSize = cbBufSize;
    }

    RpcTryExcept
    {
        dwError = RQueryServiceConfigW((SC_RPC_HANDLE)hService,
                                       (LPBYTE)lpConfigPtr,
                                       dwBufferSize,
                                       pcbBytesNeeded);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    if (dwError != ERROR_SUCCESS)
    {
        TRACE("RQueryServiceConfigW() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
        return FALSE;
    }

#ifdef SYSWOW64_GUEST
    ScmWow64ServiceConfigTo32((LPBYTE)lpConfigPtr);
#endif

    /* Adjust the pointers */
    if (lpConfigPtr->lpBinaryPathName)
        lpConfigPtr->lpBinaryPathName =
            (LPWSTR)((ULONG_PTR)lpConfigPtr +
                     (ULONG_PTR)lpConfigPtr->lpBinaryPathName);

    if (lpConfigPtr->lpLoadOrderGroup)
        lpConfigPtr->lpLoadOrderGroup =
            (LPWSTR)((ULONG_PTR)lpConfigPtr +
                     (ULONG_PTR)lpConfigPtr->lpLoadOrderGroup);

    if (lpConfigPtr->lpDependencies)
        lpConfigPtr->lpDependencies =
            (LPWSTR)((ULONG_PTR)lpConfigPtr +
                     (ULONG_PTR)lpConfigPtr->lpDependencies);

    if (lpConfigPtr->lpServiceStartName)
        lpConfigPtr->lpServiceStartName =
            (LPWSTR)((ULONG_PTR)lpConfigPtr +
                     (ULONG_PTR)lpConfigPtr->lpServiceStartName);

    if (lpConfigPtr->lpDisplayName)
        lpConfigPtr->lpDisplayName =
           (LPWSTR)((ULONG_PTR)lpConfigPtr +
                    (ULONG_PTR)lpConfigPtr->lpDisplayName);

    TRACE("QueryServiceConfigW() done\n");

    return TRUE;
}


#ifdef SYSWOW64_GUEST
/*
 * QueryServiceConfig2A/W for the levels with pointer members: SERVICE_DESCRIPTION,
 * SERVICE_REQUIRED_PRIVILEGES_INFO and SERVICE_FAILURE_ACTIONS. The SCM fills a buffer in the 64-bit
 * layout, which is larger by dwDelta bytes than the 32-bit header; give it that much more room than the
 * caller has, and move what it returns, the strings and the actions that follow the header, down by
 * dwDelta bytes.
 * Called only after the info level is known to be one of the three.
 */
static BOOL
ScmWow64QueryServiceConfig2(SC_HANDLE hService,
                            DWORD dwInfoLevel,
                            BOOL bUnicode,
                            LPBYTE lpBuffer,
                            DWORD cbBufSize,
                            LPDWORD pcbBytesNeeded)
{
    DWORD dwHeader64, dwHeader32, dwDelta, dwBufSize, dwError;
    LPBYTE lpTemp;
    ULONG64 ullPointers[3];
    DWORD dwFirst, dwSecond;
    PVOID pPointers[3] = { NULL, NULL, NULL };
    int i;

    /* The privileges, like the description, are a pointer to a string that follows it */
    if (dwInfoLevel == SERVICE_CONFIG_DESCRIPTION ||
        dwInfoLevel == SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO)
    {
        dwHeader64 = 8;
        dwHeader32 = 4;
    }
    else
    {
        dwHeader64 = 40;
        dwHeader32 = 20;
    }
    dwDelta = dwHeader64 - dwHeader32;

    if (lpBuffer == NULL)
        cbBufSize = 0;

    /* The request is bounded by 8 KB */
    dwBufSize = (cbBufSize > 8 * 1024 - dwDelta) ? 8 * 1024 : cbBufSize + dwDelta;
    lpTemp = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufSize);
    if (lpTemp == NULL)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }

    RpcTryExcept
    {
        if (bUnicode)
            dwError = RQueryServiceConfig2W((SC_RPC_HANDLE)hService,
                                            dwInfoLevel,
                                            lpTemp,
                                            dwBufSize,
                                            pcbBytesNeeded);
        else
            dwError = RQueryServiceConfig2A((SC_RPC_HANDLE)hService,
                                            dwInfoLevel,
                                            lpTemp,
                                            dwBufSize,
                                            pcbBytesNeeded);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    /* The size in the 32-bit layout, once the SCM has counted it (it does not on every success) */
    if (pcbBytesNeeded != NULL && *pcbBytesNeeded >= dwHeader64 &&
        (dwError == ERROR_SUCCESS || dwError == ERROR_INSUFFICIENT_BUFFER))
        *pcbBytesNeeded -= dwDelta;

    if (dwError != ERROR_SUCCESS)
    {
        HeapFree(GetProcessHeap(), 0, lpTemp);
        TRACE("RQueryServiceConfig2%c() failed (Error %lu)\n", bUnicode ? 'W' : 'A', dwError);
        SetLastError(dwError);
        return FALSE;
    }

    /* The caller's buffer is dwDelta bytes shorter than the SCM's */
    RtlCopyMemory(lpBuffer + dwHeader32, lpTemp + dwHeader64, dwBufSize - dwHeader64);

    if (dwInfoLevel == SERVICE_CONFIG_DESCRIPTION ||
        dwInfoLevel == SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO)
    {
        RtlCopyMemory(&ullPointers[0], lpTemp, sizeof(ULONG64));
        if (ullPointers[0] != 0)
            pPointers[0] = lpBuffer + (ULONG)ullPointers[0] - dwDelta;
        RtlCopyMemory(lpBuffer, &pPointers[0], sizeof(PVOID));
    }
    else
    {
        /* dwResetPeriod, lpRebootMsg, lpCommand, cActions, lpsaActions */
        RtlCopyMemory(&dwFirst, lpTemp + 0, sizeof(DWORD));
        RtlCopyMemory(&ullPointers[0], lpTemp + 8, sizeof(ULONG64));
        RtlCopyMemory(&ullPointers[1], lpTemp + 16, sizeof(ULONG64));
        RtlCopyMemory(&dwSecond, lpTemp + 24, sizeof(DWORD));
        RtlCopyMemory(&ullPointers[2], lpTemp + 32, sizeof(ULONG64));

        for (i = 0; i < 3; i++)
        {
            if (ullPointers[i] != 0)
                pPointers[i] = lpBuffer + (ULONG)ullPointers[i] - dwDelta;
        }

        RtlCopyMemory(lpBuffer + 0, &dwFirst, sizeof(DWORD));
        RtlCopyMemory(lpBuffer + 4, &pPointers[0], sizeof(PVOID));
        RtlCopyMemory(lpBuffer + 8, &pPointers[1], sizeof(PVOID));
        RtlCopyMemory(lpBuffer + 12, &dwSecond, sizeof(DWORD));
        RtlCopyMemory(lpBuffer + 16, &pPointers[2], sizeof(PVOID));
    }

    HeapFree(GetProcessHeap(), 0, lpTemp);
    return TRUE;
}

/*
 * QueryServiceConfig2A/W for the triggers. The SCM returns SERVICE_TRIGGER_INFO in the 64-bit layout, as
 * the sizes above say, with the pointers as offsets into the buffer: the header, the array of triggers,
 * then for each trigger the array of its data items and its subtype, and last the data of the items,
 * the last item first. The 32-bit layout has the same order with smaller structures, so it is built from
 * the SCM's, with all of it taken from the SCM (the request is bounded by 8 KB) and the size reported in
 * terms of the 32-bit layout.
 */
static BOOL
ScmWow64QueryTriggerInfo(SC_HANDLE hService,
                         BOOL bUnicode,
                         LPBYTE lpBuffer,
                         DWORD cbBufSize,
                         LPDWORD pcbBytesNeeded)
{
    const DWORD dwBufSize = 8 * 1024;
    DWORD dwNeeded64 = 0, dwNeeded32, dwError, cTriggers, cItems, i, j, dwOffset, dwData;
    ULONG64 ullTriggers = 0, ullItems, ullData, ullSubtype;
    LPBYTE lpTemp, lpTrigger64, lpItem64;
    PSERVICE_TRIGGER_INFO pInfo;
    PSERVICE_TRIGGER pTriggers;

    lpTemp = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufSize);
    if (lpTemp == NULL)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }

    RpcTryExcept
    {
        if (bUnicode)
            dwError = RQueryServiceConfig2W((SC_RPC_HANDLE)hService,
                                            SERVICE_CONFIG_TRIGGER_INFO,
                                            lpTemp,
                                            dwBufSize,
                                            &dwNeeded64);
        else
            dwError = RQueryServiceConfig2A((SC_RPC_HANDLE)hService,
                                            SERVICE_CONFIG_TRIGGER_INFO,
                                            lpTemp,
                                            dwBufSize,
                                            &dwNeeded64);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    if (dwError != ERROR_SUCCESS)
    {
        /* Too many triggers for the request: all the size there is to report is the SCM's */
        if (dwError == ERROR_INSUFFICIENT_BUFFER && pcbBytesNeeded != NULL)
            *pcbBytesNeeded = dwNeeded64;
        HeapFree(GetProcessHeap(), 0, lpTemp);
        SetLastError(dwError);
        return FALSE;
    }

    /* The offsets of the SCM's buffer are not to be trusted further than the buffer */
#define SCM64_FITS(off, len) ((ULONG64)(off) <= dwNeeded64 && (ULONG64)(len) <= dwNeeded64 - (ULONG64)(off))

    if (dwNeeded64 < 24 || dwNeeded64 > dwBufSize)
        goto Invalid;

    RtlCopyMemory(&cTriggers, lpTemp, sizeof(DWORD));
    RtlCopyMemory(&ullTriggers, lpTemp + 8, sizeof(ULONG64));
    if (cTriggers > 64 || (cTriggers != 0 && !SCM64_FITS(ullTriggers, cTriggers * 32)))
        goto Invalid;

    /* The size of the 32-bit layout */
    dwNeeded32 = sizeof(SERVICE_TRIGGER_INFO) + cTriggers * sizeof(SERVICE_TRIGGER);
    for (i = 0; i < cTriggers; i++)
    {
        lpTrigger64 = lpTemp + (ULONG)ullTriggers + i * 32;
        RtlCopyMemory(&cItems, lpTrigger64 + 16, sizeof(DWORD));
        RtlCopyMemory(&ullItems, lpTrigger64 + 24, sizeof(ULONG64));
        if (cItems > 64 || (cItems != 0 && !SCM64_FITS(ullItems, cItems * 16)))
            goto Invalid;

        dwNeeded32 += cItems * sizeof(SERVICE_TRIGGER_SPECIFIC_DATA_ITEM) + sizeof(GUID);
        for (j = 0; j < cItems; j++)
        {
            lpItem64 = lpTemp + (ULONG)ullItems + j * 16;
            RtlCopyMemory(&dwData, lpItem64 + 4, sizeof(DWORD));
            dwNeeded32 += dwData;
        }
    }

    if (lpBuffer == NULL || cbBufSize < dwNeeded32)
    {
        if (pcbBytesNeeded != NULL)
            *pcbBytesNeeded = dwNeeded32;
        HeapFree(GetProcessHeap(), 0, lpTemp);
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    pInfo = (PSERVICE_TRIGGER_INFO)lpBuffer;
    pInfo->cTriggers = cTriggers;
    pInfo->pTriggers = NULL;
    pInfo->pReserved = NULL;
    if (cTriggers != 0)
    {
        pTriggers = (PSERVICE_TRIGGER)(lpBuffer + sizeof(SERVICE_TRIGGER_INFO));
        pInfo->pTriggers = pTriggers;
        dwOffset = sizeof(SERVICE_TRIGGER_INFO) + cTriggers * sizeof(SERVICE_TRIGGER);

        for (i = 0; i < cTriggers; i++)
        {
            lpTrigger64 = lpTemp + (ULONG)ullTriggers + i * 32;
            RtlCopyMemory(&pTriggers[i].dwTriggerType, lpTrigger64 + 0, sizeof(DWORD));
            RtlCopyMemory(&pTriggers[i].dwAction, lpTrigger64 + 4, sizeof(DWORD));
            RtlCopyMemory(&ullSubtype, lpTrigger64 + 8, sizeof(ULONG64));
            RtlCopyMemory(&cItems, lpTrigger64 + 16, sizeof(DWORD));
            pTriggers[i].cDataItems = cItems;
            pTriggers[i].pDataItems = NULL;
            if (cItems != 0)
            {
                pTriggers[i].pDataItems = (PSERVICE_TRIGGER_SPECIFIC_DATA_ITEM)(lpBuffer + dwOffset);
                dwOffset += cItems * sizeof(SERVICE_TRIGGER_SPECIFIC_DATA_ITEM);
            }

            if (!SCM64_FITS(ullSubtype, sizeof(GUID)))
                goto Invalid;
            pTriggers[i].pTriggerSubtype = (GUID *)(lpBuffer + dwOffset);
            RtlCopyMemory(lpBuffer + dwOffset, lpTemp + (ULONG)ullSubtype, sizeof(GUID));
            dwOffset += sizeof(GUID);
        }

        for (i = cTriggers; i-- > 0;)
        {
            lpTrigger64 = lpTemp + (ULONG)ullTriggers + i * 32;
            RtlCopyMemory(&ullItems, lpTrigger64 + 24, sizeof(ULONG64));

            for (j = pTriggers[i].cDataItems; j-- > 0;)
            {
                PSERVICE_TRIGGER_SPECIFIC_DATA_ITEM pItem = &pTriggers[i].pDataItems[j];

                lpItem64 = lpTemp + (ULONG)ullItems + j * 16;
                RtlCopyMemory(&pItem->dwDataType, lpItem64 + 0, sizeof(DWORD));
                RtlCopyMemory(&pItem->cbData, lpItem64 + 4, sizeof(DWORD));
                RtlCopyMemory(&ullData, lpItem64 + 8, sizeof(ULONG64));
                if (!SCM64_FITS(ullData, pItem->cbData))
                    goto Invalid;

                pItem->pData = lpBuffer + dwOffset;
                RtlCopyMemory(lpBuffer + dwOffset, lpTemp + (ULONG)ullData, pItem->cbData);
                dwOffset += pItem->cbData;
            }
        }
    }

#undef SCM64_FITS

    HeapFree(GetProcessHeap(), 0, lpTemp);
    return TRUE;

Invalid:
    HeapFree(GetProcessHeap(), 0, lpTemp);
    SetLastError(ERROR_INVALID_DATA);
    return FALSE;
}


/*
 * QueryServiceLockStatusA/W: the SCM's QUERY_SERVICE_LOCK_STATUS is dwDelta (12) bytes larger than the
 * 32-bit one, the owner's name follows it.
 */
static BOOL
ScmWow64QueryServiceLockStatus(SC_HANDLE hSCManager,
                               BOOL bUnicode,
                               LPBYTE lpLockStatus,
                               DWORD cbBufSize,
                               LPDWORD pcbBytesNeeded)
{
    const DWORD dwHeader64 = 24, dwHeader32 = 12, dwDelta = 12;
    DWORD dwBufSize, dwError, dwLocked, dwDuration;
    ULONG64 ullOwner;
    PVOID pOwner = NULL;
    LPBYTE lpTemp;

    if (lpLockStatus == NULL)
        cbBufSize = 0;

    /* The request is bounded by 4 KB */
    dwBufSize = (cbBufSize > 4 * 1024 - dwDelta) ? 4 * 1024 : cbBufSize + dwDelta;
    lpTemp = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufSize);
    if (lpTemp == NULL)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }

    RpcTryExcept
    {
        if (bUnicode)
            dwError = RQueryServiceLockStatusW((SC_RPC_HANDLE)hSCManager,
                                               lpTemp,
                                               dwBufSize,
                                               pcbBytesNeeded);
        else
            dwError = RQueryServiceLockStatusA((SC_RPC_HANDLE)hSCManager,
                                               lpTemp,
                                               dwBufSize,
                                               pcbBytesNeeded);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    if (pcbBytesNeeded != NULL && *pcbBytesNeeded >= dwHeader64 &&
        (dwError == ERROR_SUCCESS || dwError == ERROR_INSUFFICIENT_BUFFER))
        *pcbBytesNeeded -= dwDelta;

    if (dwError != ERROR_SUCCESS)
    {
        HeapFree(GetProcessHeap(), 0, lpTemp);
        TRACE("RQueryServiceLockStatus%c() failed (Error %lu)\n", bUnicode ? 'W' : 'A', dwError);
        SetLastError(dwError);
        return FALSE;
    }

    RtlCopyMemory(&dwLocked, lpTemp + 0, sizeof(DWORD));
    RtlCopyMemory(&ullOwner, lpTemp + 8, sizeof(ULONG64));
    RtlCopyMemory(&dwDuration, lpTemp + 16, sizeof(DWORD));
    if (ullOwner != 0)
        pOwner = lpLockStatus + (ULONG)ullOwner - dwDelta;

    RtlCopyMemory(lpLockStatus + dwHeader32, lpTemp + dwHeader64, dwBufSize - dwHeader64);
    RtlCopyMemory(lpLockStatus + 0, &dwLocked, sizeof(DWORD));
    RtlCopyMemory(lpLockStatus + 4, &pOwner, sizeof(PVOID));
    RtlCopyMemory(lpLockStatus + 8, &dwDuration, sizeof(DWORD));

    HeapFree(GetProcessHeap(), 0, lpTemp);
    return TRUE;
}
#endif

/*
 * The triggers the SCM returns hold offsets for pointers, from the start of the buffer. Makes them
 * pointers; FALSE if one of them leads out of the buffer, of the size the SCM was told.
 */
static BOOL
ScmFixupTriggerInfo(LPBYTE lpBase,
                    DWORD cbSize)
{
    PSERVICE_TRIGGER_INFO pInfo = (PSERVICE_TRIGGER_INFO)lpBase;
    PSERVICE_TRIGGER pTrigger;
    DWORD i, j;

#define SCM_FITS(off, len) ((ULONG_PTR)(off) <= cbSize && (ULONG_PTR)(len) <= cbSize - (ULONG_PTR)(off))

    if (pInfo->cTriggers == 0)
        return TRUE;

    if (pInfo->cTriggers > 64 ||
        !SCM_FITS(pInfo->pTriggers, pInfo->cTriggers * sizeof(SERVICE_TRIGGER)))
        return FALSE;
    pInfo->pTriggers = (PSERVICE_TRIGGER)(lpBase + (ULONG_PTR)pInfo->pTriggers);

    for (i = 0; i < pInfo->cTriggers; i++)
    {
        pTrigger = &pInfo->pTriggers[i];

        if (!SCM_FITS(pTrigger->pTriggerSubtype, sizeof(GUID)))
            return FALSE;
        pTrigger->pTriggerSubtype = (GUID *)(lpBase + (ULONG_PTR)pTrigger->pTriggerSubtype);

        if (pTrigger->cDataItems == 0)
        {
            pTrigger->pDataItems = NULL;
            continue;
        }

        if (pTrigger->cDataItems > 64 ||
            !SCM_FITS(pTrigger->pDataItems, pTrigger->cDataItems * sizeof(SERVICE_TRIGGER_SPECIFIC_DATA_ITEM)))
            return FALSE;
        pTrigger->pDataItems = (PSERVICE_TRIGGER_SPECIFIC_DATA_ITEM)(lpBase + (ULONG_PTR)pTrigger->pDataItems);

        for (j = 0; j < pTrigger->cDataItems; j++)
        {
            PSERVICE_TRIGGER_SPECIFIC_DATA_ITEM pItem = &pTrigger->pDataItems[j];

            if (!SCM_FITS(pItem->pData, pItem->cbData))
                return FALSE;
            pItem->pData = lpBase + (ULONG_PTR)pItem->pData;
        }
    }

#undef SCM_FITS

    return TRUE;
}


/**********************************************************************
 *  QueryServiceConfig2A
 *
 * @implemented
 */
BOOL WINAPI
QueryServiceConfig2A(SC_HANDLE hService,
                     DWORD dwInfoLevel,
                     LPBYTE lpBuffer,
                     DWORD cbBufSize,
                     LPDWORD pcbBytesNeeded)
{
    SERVICE_DESCRIPTIONA ServiceDescription;
    SERVICE_FAILURE_ACTIONSA ServiceFailureActions;
    LPBYTE lpTempBuffer;
    BOOL bUseTempBuffer = FALSE;
    DWORD dwBufferSize;
    DWORD dwError;
    DWORD dwTriggerNeeded = 0;
    LPDWORD pcbRpcNeeded = pcbBytesNeeded;

    TRACE("QueryServiceConfig2A(%p %lu %p %lu %p)\n",
          hService, dwInfoLevel, lpBuffer, cbBufSize, pcbBytesNeeded);

#ifdef SYSWOW64_GUEST
    if (dwInfoLevel == SERVICE_CONFIG_DESCRIPTION ||
        dwInfoLevel == SERVICE_CONFIG_FAILURE_ACTIONS ||
        dwInfoLevel == SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO)
        return ScmWow64QueryServiceConfig2(hService, dwInfoLevel, FALSE,
                                           lpBuffer, cbBufSize, pcbBytesNeeded);
    if (dwInfoLevel == SERVICE_CONFIG_TRIGGER_INFO)
        return ScmWow64QueryTriggerInfo(hService, FALSE,
                                        lpBuffer, cbBufSize, pcbBytesNeeded);
#endif

    lpTempBuffer = lpBuffer;
    dwBufferSize = cbBufSize;

    switch (dwInfoLevel)
    {
        case SERVICE_CONFIG_DESCRIPTION:
            if ((lpBuffer == NULL) || (cbBufSize < sizeof(SERVICE_DESCRIPTIONA)))
            {
                lpTempBuffer = (LPBYTE)&ServiceDescription;
                dwBufferSize = sizeof(SERVICE_DESCRIPTIONA);
                bUseTempBuffer = TRUE;
            }
            break;

        case SERVICE_CONFIG_FAILURE_ACTIONS:
            if ((lpBuffer == NULL) || (cbBufSize < sizeof(SERVICE_FAILURE_ACTIONSA)))
            {
                lpTempBuffer = (LPBYTE)&ServiceFailureActions;
                dwBufferSize = sizeof(SERVICE_FAILURE_ACTIONSA);
                bUseTempBuffer = TRUE;
            }
            break;

        case SERVICE_CONFIG_FAILURE_ACTIONS_FLAG:
            if ((lpBuffer == NULL) || (cbBufSize < sizeof(SERVICE_FAILURE_ACTIONS_FLAG)))
            {
                lpTempBuffer = (LPBYTE)&ServiceFailureActions;
                dwBufferSize = sizeof(SERVICE_FAILURE_ACTIONS_FLAG);
                bUseTempBuffer = TRUE;
            }
            break;

        /* Delayed automatic start, service SID type and preshutdown timeout: a single DWORD */
        case SERVICE_CONFIG_DELAYED_AUTO_START_INFO:
        case SERVICE_CONFIG_SERVICE_SID_INFO:
        case SERVICE_CONFIG_PRESHUTDOWN_INFO:
            if ((lpBuffer == NULL) || (cbBufSize < sizeof(DWORD)))
            {
                lpTempBuffer = (LPBYTE)&ServiceFailureActions;
                dwBufferSize = sizeof(DWORD);
                bUseTempBuffer = TRUE;
            }
            break;

        case SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO:
            if ((lpBuffer == NULL) || (cbBufSize < sizeof(SERVICE_REQUIRED_PRIVILEGES_INFOA)))
            {
                lpTempBuffer = (LPBYTE)&ServiceFailureActions;
                dwBufferSize = sizeof(SERVICE_REQUIRED_PRIVILEGES_INFOA);
                bUseTempBuffer = TRUE;
            }
            break;

        /* The size needed comes back only when the buffer is too small */
        case SERVICE_CONFIG_TRIGGER_INFO:
            if ((lpBuffer == NULL) || (cbBufSize < sizeof(SERVICE_TRIGGER_INFO)))
            {
                lpTempBuffer = (LPBYTE)&ServiceFailureActions;
                dwBufferSize = sizeof(SERVICE_TRIGGER_INFO);
                bUseTempBuffer = TRUE;
            }
            pcbRpcNeeded = &dwTriggerNeeded;
            break;

        default:
            WARN("Unknown info level 0x%lx\n", dwInfoLevel);
            SetLastError(ERROR_INVALID_LEVEL);
            return FALSE;
    }

    RpcTryExcept
    {
        dwError = RQueryServiceConfig2A((SC_RPC_HANDLE)hService,
                                        dwInfoLevel,
                                        lpTempBuffer,
                                        dwBufferSize,
                                        pcbRpcNeeded);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    if (dwError != ERROR_SUCCESS)
    {
        TRACE("RQueryServiceConfig2A() failed (Error %lu)\n", dwError);
        if (pcbRpcNeeded != pcbBytesNeeded && pcbBytesNeeded != NULL &&
            dwError == ERROR_INSUFFICIENT_BUFFER)
            *pcbBytesNeeded = dwTriggerNeeded;
        SetLastError(dwError);
        return FALSE;
    }

    if (bUseTempBuffer != FALSE)
    {
        TRACE("RQueryServiceConfig2A() returns ERROR_INSUFFICIENT_BUFFER\n");
        *pcbBytesNeeded = dwBufferSize;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    switch (dwInfoLevel)
    {
        case SERVICE_CONFIG_DESCRIPTION:
            {
                LPSERVICE_DESCRIPTIONA lpPtr = (LPSERVICE_DESCRIPTIONA)lpTempBuffer;

                if (lpPtr->lpDescription != NULL)
                    lpPtr->lpDescription =
                        (LPSTR)((ULONG_PTR)lpPtr + (ULONG_PTR)lpPtr->lpDescription);
            }
            break;

        case SERVICE_CONFIG_FAILURE_ACTIONS:
            {
                LPSERVICE_FAILURE_ACTIONSA lpPtr = (LPSERVICE_FAILURE_ACTIONSA)lpTempBuffer;

                if (lpPtr->lpRebootMsg != NULL)
                    lpPtr->lpRebootMsg =
                        (LPSTR)((ULONG_PTR)lpPtr + (ULONG_PTR)lpPtr->lpRebootMsg);

                if (lpPtr->lpCommand != NULL)
                    lpPtr->lpCommand =
                        (LPSTR)((ULONG_PTR)lpPtr + (ULONG_PTR)lpPtr->lpCommand);

                if (lpPtr->lpsaActions != NULL)
                    lpPtr->lpsaActions =
                        (LPSC_ACTION)((ULONG_PTR)lpPtr + (ULONG_PTR)lpPtr->lpsaActions);
            }
            break;

        case SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO:
            {
                LPSERVICE_REQUIRED_PRIVILEGES_INFOA lpPtr = (LPSERVICE_REQUIRED_PRIVILEGES_INFOA)lpTempBuffer;

                if (lpPtr->pmszRequiredPrivileges != NULL)
                    lpPtr->pmszRequiredPrivileges =
                        (LPSTR)((ULONG_PTR)lpPtr + (ULONG_PTR)lpPtr->pmszRequiredPrivileges);
            }
            break;

        case SERVICE_CONFIG_TRIGGER_INFO:
            if (!ScmFixupTriggerInfo(lpTempBuffer, dwBufferSize))
            {
                SetLastError(ERROR_INVALID_DATA);
                return FALSE;
            }
            break;
    }

    TRACE("QueryServiceConfig2A() done\n");

    return TRUE;
}


/**********************************************************************
 *  QueryServiceConfig2W
 *
 * @implemented
 */
BOOL WINAPI
QueryServiceConfig2W(SC_HANDLE hService,
                     DWORD dwInfoLevel,
                     LPBYTE lpBuffer,
                     DWORD cbBufSize,
                     LPDWORD pcbBytesNeeded)
{
    SERVICE_DESCRIPTIONW ServiceDescription;
    SERVICE_FAILURE_ACTIONSW ServiceFailureActions;
    LPBYTE lpTempBuffer;
    BOOL bUseTempBuffer = FALSE;
    DWORD dwBufferSize;
    DWORD dwError;
    DWORD dwTriggerNeeded = 0;
    LPDWORD pcbRpcNeeded = pcbBytesNeeded;

    TRACE("QueryServiceConfig2W(%p %lu %p %lu %p)\n",
          hService, dwInfoLevel, lpBuffer, cbBufSize, pcbBytesNeeded);

#ifdef SYSWOW64_GUEST
    if (dwInfoLevel == SERVICE_CONFIG_DESCRIPTION ||
        dwInfoLevel == SERVICE_CONFIG_FAILURE_ACTIONS ||
        dwInfoLevel == SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO)
        return ScmWow64QueryServiceConfig2(hService, dwInfoLevel, TRUE,
                                           lpBuffer, cbBufSize, pcbBytesNeeded);
    if (dwInfoLevel == SERVICE_CONFIG_TRIGGER_INFO)
        return ScmWow64QueryTriggerInfo(hService, TRUE,
                                        lpBuffer, cbBufSize, pcbBytesNeeded);
#endif

    lpTempBuffer = lpBuffer;
    dwBufferSize = cbBufSize;

    switch (dwInfoLevel)
    {
        case SERVICE_CONFIG_DESCRIPTION:
            if ((lpBuffer == NULL) || (cbBufSize < sizeof(SERVICE_DESCRIPTIONW)))
            {
                lpTempBuffer = (LPBYTE)&ServiceDescription;
                dwBufferSize = sizeof(SERVICE_DESCRIPTIONW);
                bUseTempBuffer = TRUE;
            }
            break;

        case SERVICE_CONFIG_FAILURE_ACTIONS:
            if ((lpBuffer == NULL) || (cbBufSize < sizeof(SERVICE_FAILURE_ACTIONSW)))
            {
                lpTempBuffer = (LPBYTE)&ServiceFailureActions;
                dwBufferSize = sizeof(SERVICE_FAILURE_ACTIONSW);
                bUseTempBuffer = TRUE;
            }
            break;

        case SERVICE_CONFIG_FAILURE_ACTIONS_FLAG:
            if ((lpBuffer == NULL) || (cbBufSize < sizeof(SERVICE_FAILURE_ACTIONS_FLAG)))
            {
                lpTempBuffer = (LPBYTE)&ServiceFailureActions;
                dwBufferSize = sizeof(SERVICE_FAILURE_ACTIONS_FLAG);
                bUseTempBuffer = TRUE;
            }
            break;

        /* Delayed automatic start, service SID type and preshutdown timeout: a single DWORD */
        case SERVICE_CONFIG_DELAYED_AUTO_START_INFO:
        case SERVICE_CONFIG_SERVICE_SID_INFO:
        case SERVICE_CONFIG_PRESHUTDOWN_INFO:
            if ((lpBuffer == NULL) || (cbBufSize < sizeof(DWORD)))
            {
                lpTempBuffer = (LPBYTE)&ServiceFailureActions;
                dwBufferSize = sizeof(DWORD);
                bUseTempBuffer = TRUE;
            }
            break;

        case SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO:
            if ((lpBuffer == NULL) || (cbBufSize < sizeof(SERVICE_REQUIRED_PRIVILEGES_INFOW)))
            {
                lpTempBuffer = (LPBYTE)&ServiceFailureActions;
                dwBufferSize = sizeof(SERVICE_REQUIRED_PRIVILEGES_INFOW);
                bUseTempBuffer = TRUE;
            }
            break;

        /* The size needed comes back only when the buffer is too small */
        case SERVICE_CONFIG_TRIGGER_INFO:
            if ((lpBuffer == NULL) || (cbBufSize < sizeof(SERVICE_TRIGGER_INFO)))
            {
                lpTempBuffer = (LPBYTE)&ServiceFailureActions;
                dwBufferSize = sizeof(SERVICE_TRIGGER_INFO);
                bUseTempBuffer = TRUE;
            }
            pcbRpcNeeded = &dwTriggerNeeded;
            break;

        default:
            WARN("Unknown info level 0x%lx\n", dwInfoLevel);
            SetLastError(ERROR_INVALID_LEVEL);
            return FALSE;
    }

    RpcTryExcept
    {
        dwError = RQueryServiceConfig2W((SC_RPC_HANDLE)hService,
                                        dwInfoLevel,
                                        lpTempBuffer,
                                        dwBufferSize,
                                        pcbRpcNeeded);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    if (dwError != ERROR_SUCCESS)
    {
        TRACE("RQueryServiceConfig2W() failed (Error %lu)\n", dwError);
        if (pcbRpcNeeded != pcbBytesNeeded && pcbBytesNeeded != NULL &&
            dwError == ERROR_INSUFFICIENT_BUFFER)
            *pcbBytesNeeded = dwTriggerNeeded;
        SetLastError(dwError);
        return FALSE;
    }

    if (bUseTempBuffer != FALSE)
    {
        TRACE("RQueryServiceConfig2W() returns ERROR_INSUFFICIENT_BUFFER\n");
        *pcbBytesNeeded = dwBufferSize;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    switch (dwInfoLevel)
    {
        case SERVICE_CONFIG_DESCRIPTION:
            {
                LPSERVICE_DESCRIPTIONW lpPtr = (LPSERVICE_DESCRIPTIONW)lpTempBuffer;

                if (lpPtr->lpDescription != NULL)
                    lpPtr->lpDescription =
                        (LPWSTR)((ULONG_PTR)lpPtr + (ULONG_PTR)lpPtr->lpDescription);
            }
            break;

        case SERVICE_CONFIG_FAILURE_ACTIONS:
            {
                LPSERVICE_FAILURE_ACTIONSW lpPtr = (LPSERVICE_FAILURE_ACTIONSW)lpTempBuffer;

                if (lpPtr->lpRebootMsg != NULL)
                    lpPtr->lpRebootMsg =
                        (LPWSTR)((ULONG_PTR)lpPtr + (ULONG_PTR)lpPtr->lpRebootMsg);

                if (lpPtr->lpCommand != NULL)
                    lpPtr->lpCommand =
                        (LPWSTR)((ULONG_PTR)lpPtr + (ULONG_PTR)lpPtr->lpCommand);

                if (lpPtr->lpsaActions != NULL)
                    lpPtr->lpsaActions =
                        (LPSC_ACTION)((ULONG_PTR)lpPtr + (ULONG_PTR)lpPtr->lpsaActions);
            }
            break;

        case SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO:
            {
                LPSERVICE_REQUIRED_PRIVILEGES_INFOW lpPtr = (LPSERVICE_REQUIRED_PRIVILEGES_INFOW)lpTempBuffer;

                if (lpPtr->pmszRequiredPrivileges != NULL)
                    lpPtr->pmszRequiredPrivileges =
                        (LPWSTR)((ULONG_PTR)lpPtr + (ULONG_PTR)lpPtr->pmszRequiredPrivileges);
            }
            break;

        case SERVICE_CONFIG_TRIGGER_INFO:
            if (!ScmFixupTriggerInfo(lpTempBuffer, dwBufferSize))
            {
                SetLastError(ERROR_INVALID_DATA);
                return FALSE;
            }
            break;
    }

    TRACE("QueryServiceConfig2W() done\n");

    return TRUE;
}


/**********************************************************************
 *  QueryServiceLockStatusA
 *
 * @implemented
 */
BOOL WINAPI
QueryServiceLockStatusA(SC_HANDLE hSCManager,
                        LPQUERY_SERVICE_LOCK_STATUSA lpLockStatus,
                        DWORD cbBufSize,
                        LPDWORD pcbBytesNeeded)
{
    QUERY_SERVICE_LOCK_STATUSA LockStatus;
    LPQUERY_SERVICE_LOCK_STATUSA lpStatusPtr;
    DWORD dwBufferSize;
    DWORD dwError;

    TRACE("QueryServiceLockStatusA(%p %p %lu %p)\n",
          hSCManager, lpLockStatus, cbBufSize, pcbBytesNeeded);

#ifdef SYSWOW64_GUEST
    return ScmWow64QueryServiceLockStatus(hSCManager, FALSE, (LPBYTE)lpLockStatus,
                                          cbBufSize, pcbBytesNeeded);
#endif

    if (lpLockStatus == NULL || cbBufSize < sizeof(QUERY_SERVICE_LOCK_STATUSA))
    {
        lpStatusPtr = &LockStatus;
        dwBufferSize = sizeof(QUERY_SERVICE_LOCK_STATUSA);
    }
    else
    {
        lpStatusPtr = lpLockStatus;
        dwBufferSize = cbBufSize;
    }

    RpcTryExcept
    {
        dwError = RQueryServiceLockStatusA((SC_RPC_HANDLE)hSCManager,
                                           (LPBYTE)lpStatusPtr,
                                           dwBufferSize,
                                           pcbBytesNeeded);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    if (dwError != ERROR_SUCCESS)
    {
        TRACE("RQueryServiceLockStatusA() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
        return FALSE;
    }

    if (lpStatusPtr->lpLockOwner != NULL)
    {
        lpStatusPtr->lpLockOwner =
            (LPSTR)((ULONG_PTR)lpStatusPtr + (ULONG_PTR)lpStatusPtr->lpLockOwner);
    }

    TRACE("QueryServiceLockStatusA() done\n");

    return TRUE;
}


/**********************************************************************
 *  QueryServiceLockStatusW
 *
 * @implemented
 */
BOOL WINAPI
QueryServiceLockStatusW(SC_HANDLE hSCManager,
                        LPQUERY_SERVICE_LOCK_STATUSW lpLockStatus,
                        DWORD cbBufSize,
                        LPDWORD pcbBytesNeeded)
{
    QUERY_SERVICE_LOCK_STATUSW LockStatus;
    LPQUERY_SERVICE_LOCK_STATUSW lpStatusPtr;
    DWORD dwBufferSize;
    DWORD dwError;

    TRACE("QueryServiceLockStatusW(%p %p %lu %p)\n",
          hSCManager, lpLockStatus, cbBufSize, pcbBytesNeeded);

#ifdef SYSWOW64_GUEST
    return ScmWow64QueryServiceLockStatus(hSCManager, TRUE, (LPBYTE)lpLockStatus,
                                          cbBufSize, pcbBytesNeeded);
#endif

    if (lpLockStatus == NULL || cbBufSize < sizeof(QUERY_SERVICE_LOCK_STATUSW))
    {
        lpStatusPtr = &LockStatus;
        dwBufferSize = sizeof(QUERY_SERVICE_LOCK_STATUSW);
    }
    else
    {
        lpStatusPtr = lpLockStatus;
        dwBufferSize = cbBufSize;
    }

    RpcTryExcept
    {
        dwError = RQueryServiceLockStatusW((SC_RPC_HANDLE)hSCManager,
                                           (LPBYTE)lpStatusPtr,
                                           dwBufferSize,
                                           pcbBytesNeeded);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    if (dwError != ERROR_SUCCESS)
    {
        TRACE("RQueryServiceLockStatusW() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
        return FALSE;
    }

    if (lpStatusPtr->lpLockOwner != NULL)
    {
        lpStatusPtr->lpLockOwner =
            (LPWSTR)((ULONG_PTR)lpStatusPtr + (ULONG_PTR)lpStatusPtr->lpLockOwner);
    }

    TRACE("QueryServiceLockStatusW() done\n");

    return TRUE;
}


/**********************************************************************
 *  QueryServiceObjectSecurity
 *
 * @implemented
 */
BOOL WINAPI
QueryServiceObjectSecurity(SC_HANDLE hService,
                           SECURITY_INFORMATION dwSecurityInformation,
                           PSECURITY_DESCRIPTOR lpSecurityDescriptor,
                           DWORD cbBufSize,
                           LPDWORD pcbBytesNeeded)
{
    DWORD dwError;
    BYTE Dummy;

    TRACE("QueryServiceObjectSecurity(%p %lu %p)\n",
           hService, dwSecurityInformation, lpSecurityDescriptor);

    /* A NULL buffer asks for the size: the RPC stub does not take a NULL output pointer */
    if (lpSecurityDescriptor == NULL)
    {
        lpSecurityDescriptor = (PSECURITY_DESCRIPTOR)&Dummy;
        cbBufSize = 0;
    }

    RpcTryExcept
    {
        dwError = RQueryServiceObjectSecurity((SC_RPC_HANDLE)hService,
                                              dwSecurityInformation,
                                              (LPBYTE)lpSecurityDescriptor,
                                              cbBufSize,
                                              pcbBytesNeeded);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    if (dwError != ERROR_SUCCESS)
    {
        TRACE("QueryServiceObjectSecurity() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
        return FALSE;
    }

    return TRUE;
}


/**********************************************************************
 *  SetServiceObjectSecurity
 *
 * @implemented
 */
BOOL WINAPI
SetServiceObjectSecurity(SC_HANDLE hService,
                         SECURITY_INFORMATION dwSecurityInformation,
                         PSECURITY_DESCRIPTOR lpSecurityDescriptor)
{
    PSECURITY_DESCRIPTOR SelfRelativeSD = NULL;
    ULONG Length;
    NTSTATUS Status;
    DWORD dwError;

    TRACE("SetServiceObjectSecurity(%p %lu %p)\n",
          hService, dwSecurityInformation, lpSecurityDescriptor);

    Length = 0;
    Status = RtlMakeSelfRelativeSD(lpSecurityDescriptor,
                                   SelfRelativeSD,
                                   &Length);
    if (Status != STATUS_BUFFER_TOO_SMALL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    SelfRelativeSD = HeapAlloc(GetProcessHeap(), 0, Length);
    if (SelfRelativeSD == NULL)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }

    Status = RtlMakeSelfRelativeSD(lpSecurityDescriptor,
                                   SelfRelativeSD,
                                   &Length);
    if (!NT_SUCCESS(Status))
    {
        HeapFree(GetProcessHeap(), 0, SelfRelativeSD);
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    RpcTryExcept
    {
        dwError = RSetServiceObjectSecurity((SC_RPC_HANDLE)hService,
                                            dwSecurityInformation,
                                            (LPBYTE)SelfRelativeSD,
                                            Length);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    HeapFree(GetProcessHeap(), 0, SelfRelativeSD);

    if (dwError != ERROR_SUCCESS)
    {
        TRACE("RServiceObjectSecurity() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
        return FALSE;
    }

    return TRUE;
}


/**********************************************************************
 *  QueryServiceStatus
 *
 * @implemented
 */
BOOL WINAPI
QueryServiceStatus(SC_HANDLE hService,
                   LPSERVICE_STATUS lpServiceStatus)
{
    DWORD dwError;

    TRACE("QueryServiceStatus(%p %p)\n",
          hService, lpServiceStatus);

    if (!hService)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    RpcTryExcept
    {
        dwError = RQueryServiceStatus((SC_RPC_HANDLE)hService,
                                      lpServiceStatus);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    if (dwError != ERROR_SUCCESS)
    {
        TRACE("RQueryServiceStatus() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
        return FALSE;
    }

    return TRUE;
}


/**********************************************************************
 *  QueryServiceStatusEx
 *
 * @implemented
 */
BOOL WINAPI
QueryServiceStatusEx(SC_HANDLE hService,
                     SC_STATUS_TYPE InfoLevel,
                     LPBYTE lpBuffer,
                     DWORD cbBufSize,
                     LPDWORD pcbBytesNeeded)
{
    DWORD dwError;

    TRACE("QueryServiceStatusEx(%p %lu %p %lu %p)\n",
          hService, InfoLevel, lpBuffer, cbBufSize, pcbBytesNeeded);

    if (InfoLevel != SC_STATUS_PROCESS_INFO)
    {
        SetLastError(ERROR_INVALID_LEVEL);
        return FALSE;
    }

    if (cbBufSize < sizeof(SERVICE_STATUS_PROCESS))
    {
        *pcbBytesNeeded = sizeof(SERVICE_STATUS_PROCESS);
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    RpcTryExcept
    {
        dwError = RQueryServiceStatusEx((SC_RPC_HANDLE)hService,
                                        InfoLevel,
                                        lpBuffer,
                                        cbBufSize,
                                        pcbBytesNeeded);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    if (dwError != ERROR_SUCCESS)
    {
        TRACE("RQueryServiceStatusEx() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
        return FALSE;
    }

    return TRUE;
}


/**********************************************************************
 *  StartServiceA
 *
 * @implemented
 */
BOOL WINAPI
StartServiceA(SC_HANDLE hService,
              DWORD dwNumServiceArgs,
              LPCSTR *lpServiceArgVectors)
{
    DWORD dwError;

    TRACE("StartServiceA(%p %lu %p)\n",
          hService, dwNumServiceArgs, lpServiceArgVectors);

    RpcTryExcept
    {
        dwError = RStartServiceA((SC_RPC_HANDLE)hService,
                                 dwNumServiceArgs,
                                 (LPSTRING_PTRSA)lpServiceArgVectors);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    if (dwError != ERROR_SUCCESS)
    {
        ERR("RStartServiceA() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
        return FALSE;
    }

    return TRUE;
}


/**********************************************************************
 *  StartServiceW
 *
 * @implemented
 */
BOOL WINAPI
StartServiceW(SC_HANDLE hService,
              DWORD dwNumServiceArgs,
              LPCWSTR *lpServiceArgVectors)
{
    DWORD dwError;

    TRACE("StartServiceW(%p %lu %p)\n",
          hService, dwNumServiceArgs, lpServiceArgVectors);

    RpcTryExcept
    {
        dwError = RStartServiceW((SC_RPC_HANDLE)hService,
                                 dwNumServiceArgs,
                                 (LPSTRING_PTRSW)lpServiceArgVectors);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    if (dwError != ERROR_SUCCESS)
    {
        ERR("RStartServiceW() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
        return FALSE;
    }

    return TRUE;
}


/**********************************************************************
 *  UnlockServiceDatabase
 *
 * @implemented
 */
BOOL WINAPI
UnlockServiceDatabase(SC_LOCK ScLock)
{
    DWORD dwError;

    TRACE("UnlockServiceDatabase(%x)\n",
          ScLock);

    RpcTryExcept
    {
        dwError = RUnlockServiceDatabase((LPSC_RPC_LOCK)&ScLock);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    if (dwError == ERROR_INVALID_HANDLE)
        dwError = ERROR_INVALID_SERVICE_LOCK;

    if (dwError != ERROR_SUCCESS)
    {
        TRACE("RUnlockServiceDatabase() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
        return FALSE;
    }

    return TRUE;
}


/**********************************************************************
 *  NotifyBootConfigStatus
 *
 * @implemented
 */
BOOL WINAPI
NotifyBootConfigStatus(BOOL BootAcceptable)
{
    DWORD dwError;

    TRACE("NotifyBootConfigStatus(%u)\n",
          BootAcceptable);

    RpcTryExcept
    {
        dwError = RNotifyBootConfigStatus(NULL,
                                          BootAcceptable);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    if (dwError != ERROR_SUCCESS)
    {
        TRACE("NotifyBootConfigStatus() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
        return FALSE;
    }

    return TRUE;
}

DWORD
I_ScQueryServiceTagInfo(PVOID Unused,
                        TAG_INFO_LEVEL dwInfoLevel,
                        PTAG_INFO_NAME_FROM_TAG InOutParams)
{
    SC_HANDLE hScm;
    DWORD dwError;
    PTAG_INFO_NAME_FROM_TAG_IN_PARAMS InParams;
    PTAG_INFO_NAME_FROM_TAG_OUT_PARAMS OutParams;
    LPWSTR lpszName;

    /* We only support one class */
    if (dwInfoLevel != TagInfoLevelNameFromTag)
    {
        return ERROR_RETRY;
    }

    /* Validate input structure */
    if (InOutParams->InParams.dwPid == 0 || InOutParams->InParams.dwTag == 0)
    {
        return ERROR_INVALID_PARAMETER;
    }

    /* Validate output structure */
    if (InOutParams->OutParams.pszName != NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }

    /* Open service manager */
    hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (hScm == NULL)
    {
        return GetLastError();
    }

    /* Setup call parameters */
    InParams = &InOutParams->InParams;
    OutParams = NULL;

    /* Call SCM to query tag information */
    RpcTryExcept
    {
        dwError = RI_ScQueryServiceTagInfo(hScm, TagInfoLevelNameFromTag, &InParams, &OutParams);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = ScmRpcStatusToWinError(RpcExceptionCode());
    }
    RpcEndExcept;

    /* Quit if not a success */
    if (dwError != ERROR_SUCCESS)
    {
        goto Cleanup;
    }

    /* OutParams must be set now and we must have a name */
    if (OutParams == NULL ||
        OutParams->pszName == NULL)
    {
        dwError = ERROR_INVALID_DATA;
        goto Cleanup;
    }

    /* Copy back what SCM returned */
    lpszName = LocalAlloc(LPTR,
                          sizeof(WCHAR) * wcslen(OutParams->pszName) + sizeof(UNICODE_NULL));
    if (lpszName == NULL)
    {
        dwError = GetLastError();
        goto Cleanup;
    }

    wcscpy(lpszName, OutParams->pszName);
    InOutParams->OutParams.pszName = lpszName;
    InOutParams->OutParams.TagType = OutParams->TagType;

Cleanup:
    CloseServiceHandle(hScm);

    /* Free memory allocated by SCM */
    if (OutParams != NULL)
    {
        if (OutParams->pszName != NULL)
        {
            midl_user_free(OutParams->pszName);
        }

        midl_user_free(OutParams);
    }

    return dwError;
}

/**********************************************************************
 *  I_QueryTagInformation
 *
 * @implemented
 */
DWORD WINAPI
I_QueryTagInformation(PVOID Unused,
                      TAG_INFO_LEVEL dwInfoLevel,
                      PTAG_INFO_NAME_FROM_TAG InOutParams)
{
    /*
     * We only support one information class and it
     * needs parameters
     */
    if (dwInfoLevel != TagInfoLevelNameFromTag ||
        InOutParams == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }

    /* Validate input structure */
    if (InOutParams->InParams.dwPid == 0 || InOutParams->InParams.dwTag == 0)
    {
        return ERROR_INVALID_PARAMETER;
    }

    /* Validate output structure */
    if (InOutParams->OutParams.pszName != NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }

    /* Call internal function for the RPC call */
    return I_ScQueryServiceTagInfo(Unused, TagInfoLevelNameFromTag, InOutParams);
}

/* EOF */
