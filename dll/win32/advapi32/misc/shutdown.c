/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS system libraries
 * FILE:        dll/win32/advapi32/misc/shutdown.c
 * PURPOSE:     System shutdown functions
 * PROGRAMMER:  Lee Schroeder <spaceseel at gmail dot com>
 *              Emanuele Aliberti
 */

#include <advapi32.h>

WINE_DEFAULT_DEBUG_CHANNEL(advapi);

/**********************************************************************
 *      AbortSystemShutdownA
 *
 * see AbortSystemShutdownW
 */
BOOL WINAPI
AbortSystemShutdownA(LPCSTR lpMachineName)
{
    ANSI_STRING MachineNameA;
    UNICODE_STRING MachineNameW;
    NTSTATUS Status;
    BOOL rv;

    RtlInitAnsiString(&MachineNameA, (LPSTR)lpMachineName);
    Status = RtlAnsiStringToUnicodeString(&MachineNameW, &MachineNameA, TRUE);
    if (STATUS_SUCCESS != Status)
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    rv = AbortSystemShutdownW(MachineNameW.Buffer);
    RtlFreeUnicodeString(&MachineNameW);
    SetLastError(ERROR_SUCCESS);
    return rv;
}


/**********************************************************************
 *      AbortSystemShutdownW
 *
 * @implemented
 */
BOOL WINAPI
AbortSystemShutdownW(LPCWSTR lpMachineName)
{
    DWORD dwError;

    RpcTryExcept
    {
        dwError = BaseAbortSystemShutdown((PREGISTRY_SERVER_NAME)lpMachineName);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = RtlNtStatusToDosError(RpcExceptionCode());
    }
    RpcEndExcept;

    if (dwError != ERROR_SUCCESS)
    {
        TRACE("BaseAbortSystemShutdown() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
        return FALSE;
    }

    return TRUE;
}


/**********************************************************************
 *      InitiateSystemShutdownA
 *
 * @implemented
 */
BOOL
WINAPI
InitiateSystemShutdownA(LPSTR lpMachineName,
                        LPSTR lpMessage,
                        DWORD dwTimeout,
                        BOOL bForceAppsClosed,
                        BOOL bRebootAfterShutdown)
{
    ANSI_STRING MachineNameA, MessageA;
    UNICODE_STRING MachineNameW, MessageW;
    NTSTATUS Status;
    BOOL res;

    MachineNameW.Buffer = NULL;
    MessageW.Buffer = NULL;

    if (lpMachineName)
    {
        RtlInitAnsiString(&MachineNameA, lpMachineName);
        Status = RtlAnsiStringToUnicodeString(&MachineNameW, &MachineNameA, TRUE);
        if (STATUS_SUCCESS != Status)
        {
            if(MachineNameW.Buffer)
                RtlFreeUnicodeString(&MachineNameW);

            SetLastError(RtlNtStatusToDosError(Status));
            return FALSE;
        }
    }

    if (lpMessage)
    {
        RtlInitAnsiString(&MessageA, lpMessage);
        Status = RtlAnsiStringToUnicodeString(&MessageW, &MessageA, TRUE);
        if (STATUS_SUCCESS != Status)
        {
            if (MessageW.Buffer)
                RtlFreeUnicodeString(&MessageW);

            SetLastError(RtlNtStatusToDosError(Status));
            return FALSE;
        }
    }

    res = InitiateSystemShutdownW(MachineNameW.Buffer,
                                  MessageW.Buffer,
                                  dwTimeout,
                                  bForceAppsClosed,
                                  bRebootAfterShutdown);

    /* Clear the values of both strings */
    if (lpMachineName)
        RtlFreeUnicodeString(&MachineNameW);

    if (lpMessage)
        RtlFreeUnicodeString(&MessageW);

    return res;
}


/**********************************************************************
 *      InitiateSystemShutdownW
 *
 * @implemented
 */
BOOL WINAPI
InitiateSystemShutdownW(LPWSTR lpMachineName,
                        LPWSTR lpMessage,
                        DWORD dwTimeout,
                        BOOL bForceAppsClosed,
                        BOOL bRebootAfterShutdown)
{
    UNICODE_STRING Message;
    DWORD dwError;

    RtlInitUnicodeString(&Message, lpMessage);

    RpcTryExcept
    {
        dwError = BaseInitiateSystemShutdown((PREGISTRY_SERVER_NAME)lpMachineName,
                                             (PRPC_UNICODE_STRING)&Message,
                                             dwTimeout,
                                             bForceAppsClosed,
                                             bRebootAfterShutdown);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = RtlNtStatusToDosError(RpcExceptionCode());
    }
    RpcEndExcept;

    if (dwError != ERROR_SUCCESS)
    {
        TRACE("BaseInitiateSystemShutdown() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
        return FALSE;
    }

    return TRUE;
}


/******************************************************************************
 * InitiateSystemShutdownExA [ADVAPI32.@]
 *
 * see InitiateSystemShutdownExW
 */
BOOL WINAPI
InitiateSystemShutdownExA(LPSTR lpMachineName,
                          LPSTR lpMessage,
                          DWORD dwTimeout,
                          BOOL bForceAppsClosed,
                          BOOL bRebootAfterShutdown,
                          DWORD dwReason)
{
    ANSI_STRING MachineNameA, MessageA;
    UNICODE_STRING MachineNameW, MessageW;
    NTSTATUS Status;
    BOOL res;

    MachineNameW.Buffer = NULL;
    MessageW.Buffer = NULL;

    if (lpMachineName)
    {
        RtlInitAnsiString(&MachineNameA, lpMachineName);
        Status = RtlAnsiStringToUnicodeString(&MachineNameW, &MachineNameA, TRUE);
        if (STATUS_SUCCESS != Status)
        {
            if(MachineNameW.Buffer)
                RtlFreeUnicodeString(&MachineNameW);

            SetLastError(RtlNtStatusToDosError(Status));
            return FALSE;
        }
    }

    if (lpMessage)
    {
        RtlInitAnsiString(&MessageA, lpMessage);
        Status = RtlAnsiStringToUnicodeString(&MessageW, &MessageA, TRUE);
        if (STATUS_SUCCESS != Status)
        {
            if (MessageW.Buffer)
                RtlFreeUnicodeString(&MessageW);

            SetLastError(RtlNtStatusToDosError(Status));
            return FALSE;
        }
    }

    res = InitiateSystemShutdownExW(MachineNameW.Buffer,
                                    MessageW.Buffer,
                                    dwTimeout,
                                    bForceAppsClosed,
                                    bRebootAfterShutdown,
                                    dwReason);

    /* Clear the values of both strings */
    if (lpMachineName)
        RtlFreeUnicodeString(&MachineNameW);

    if (lpMessage)
        RtlFreeUnicodeString(&MessageW);

    return res;
}


/******************************************************************************
 * InitiateSystemShutdownExW [ADVAPI32.@]
 *
 * @unimplemented
 */
BOOL WINAPI
InitiateSystemShutdownExW(LPWSTR lpMachineName,
                          LPWSTR lpMessage,
                          DWORD dwTimeout,
                          BOOL bForceAppsClosed,
                          BOOL bRebootAfterShutdown,
                          DWORD dwReason)
{
    UNICODE_STRING Message;
    DWORD dwError;

    RtlInitUnicodeString(&Message, lpMessage);

    RpcTryExcept
    {
        dwError = BaseInitiateSystemShutdownEx((PREGISTRY_SERVER_NAME)lpMachineName,
                                               (PRPC_UNICODE_STRING)&Message,
                                               dwTimeout,
                                               bForceAppsClosed,
                                               bRebootAfterShutdown,
                                               dwReason);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = RpcExceptionCode();
    }
    RpcEndExcept;

    if (dwError != ERROR_SUCCESS)
    {
        TRACE("BaseInitiateSystemShutdownEx() failed (Error %lu)\n", dwError);
        SetLastError(dwError);
        return FALSE;
    }

    return TRUE;
}


/******************************************************************************
 * InitiateShutdownW [ADVAPI32.@]
 *
 * The shutdown of InitiateSystemShutdownExW with the flags of Windows 8: SHUTDOWN_FORCE_OTHERS and
 * SHUTDOWN_FORCE_SELF force the applications closed, SHUTDOWN_RESTART restarts, anything else powers off.
 * SHUTDOWN_GRACE_OVERRIDE, SHUTDOWN_INSTALL_UPDATES, SHUTDOWN_RESTART_APPS, SHUTDOWN_SKIP_SVC_PRE_SHUTDOWN,
 * SHUTDOWN_HYBRID and SHUTDOWN_SOFT_REBOOT are accepted and have no effect: there is no update installer, no
 * application restart manager, no hybrid boot and no soft reboot here. A flag outside of those is an invalid
 * parameter. The result is the error code (0 for success), not a BOOL.
 */
DWORD WINAPI
InitiateShutdownW(LPWSTR lpMachineName,
                  LPWSTR lpMessage,
                  DWORD dwGracePeriod,
                  DWORD dwShutdownFlags,
                  DWORD dwReason)
{
    const DWORD ValidFlags = 0x7FF; /* SHUTDOWN_FORCE_OTHERS (0x1) up to SHUTDOWN_SOFT_REBOOT (0x400) */
    UNICODE_STRING Message;
    DWORD dwError;

    if (dwShutdownFlags & ~ValidFlags)
        return ERROR_INVALID_PARAMETER;

    RtlInitUnicodeString(&Message, lpMessage);

    RpcTryExcept
    {
        dwError = BaseInitiateSystemShutdownEx((PREGISTRY_SERVER_NAME)lpMachineName,
                                               (PRPC_UNICODE_STRING)&Message,
                                               dwGracePeriod,
                                               (dwShutdownFlags & (0x1 | 0x2)) != 0,
                                               (dwShutdownFlags & 0x4) != 0,
                                               dwReason);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        dwError = RpcExceptionCode();
    }
    RpcEndExcept;

    if (dwError != ERROR_SUCCESS)
        TRACE("BaseInitiateSystemShutdownEx() failed (Error %lu)\n", dwError);

    return dwError;
}

/******************************************************************************
 * InitiateShutdownA [ADVAPI32.@]
 *
 * see InitiateShutdownW
 */
DWORD WINAPI
InitiateShutdownA(LPSTR lpMachineName,
                  LPSTR lpMessage,
                  DWORD dwGracePeriod,
                  DWORD dwShutdownFlags,
                  DWORD dwReason)
{
    ANSI_STRING MachineNameA, MessageA;
    UNICODE_STRING MachineNameW, MessageW;
    NTSTATUS Status;
    INT LastError;
    DWORD rv;

    MachineNameW.Buffer = NULL;
    MessageW.Buffer = NULL;

    if (lpMachineName)
    {
        RtlInitAnsiString(&MachineNameA, lpMachineName);
        Status = RtlAnsiStringToUnicodeString(&MachineNameW, &MachineNameA, TRUE);
        if (STATUS_SUCCESS != Status)
        {
            if(MachineNameW.Buffer)
                RtlFreeUnicodeString(&MachineNameW);

            SetLastError(RtlNtStatusToDosError(Status));
            return FALSE;
        }
    }

    if (lpMessage)
    {
        RtlInitAnsiString(&MessageA, lpMessage);
        Status = RtlAnsiStringToUnicodeString(&MessageW, &MessageA, TRUE);
        if (STATUS_SUCCESS != Status)
        {
            if (MessageW.Buffer)
                RtlFreeUnicodeString(&MessageW);

            SetLastError(RtlNtStatusToDosError(Status));
            return FALSE;
        }
    }

    rv = InitiateShutdownW(MachineNameW.Buffer,
                           MessageW.Buffer,
                           dwGracePeriod,
                           dwShutdownFlags,
                           dwReason);
    LastError = GetLastError();

    /* Clear the values of both strings */
    if (lpMachineName)
        RtlFreeUnicodeString(&MachineNameW);

    if (lpMessage)
        RtlFreeUnicodeString(&MessageW);

    SetLastError(LastError);
    return rv;
}

/* EOF */
