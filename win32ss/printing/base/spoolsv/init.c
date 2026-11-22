/*
 * PROJECT:     ReactOS Print Spooler Service
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Various initialization functions
 * COPYRIGHT:   Copyright 2015-2017 Colin Finck (colin@reactos.org)
 */

#include "precomp.h"

DWORD
_RpcSpoolerInit(VOID)
{
    DWORD dwErrorCode;

    // Call SpoolerInit in the security context of the client.
    // This delay-loads spoolss.dll in the user context and all further calls to functions in spoolss.dll will be done in the user context as well.
    dwErrorCode = RpcImpersonateClient(NULL);
    if (dwErrorCode != ERROR_SUCCESS)
    {
        ERR("RpcImpersonateClient failed with error %lu!\n", dwErrorCode);
        return dwErrorCode;
    }

    if (!SpoolerInit())
        dwErrorCode = GetLastError();

    RpcRevertToSelf();
    return dwErrorCode;
}

/*
 * Is the client that the calling thread impersonates the anonymous logon? (to be called between
 * RpcImpersonateClient and RpcRevertToSelf) Windows refuses that caller the print server:
 * OpenPrinter is ERROR_ACCESS_DENIED, EnumPrinters of the local printers 16385 (measured).
 */
BOOL
SplCallerIsAnonymous(VOID)
{
    HANDLE hToken;
    BYTE Buffer[SECURITY_MAX_SID_SIZE + sizeof(TOKEN_USER)];
    BYTE Anonymous[SECURITY_MAX_SID_SIZE];
    DWORD dwSize = sizeof(Anonymous);
    BOOL bAnonymous = FALSE;

    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken))
        return FALSE;

    if (GetTokenInformation(hToken, TokenUser, Buffer, sizeof(Buffer), &dwSize) &&
        (dwSize = sizeof(Anonymous), CreateWellKnownSid(WinAnonymousSid, NULL, Anonymous, &dwSize)) &&
        EqualSid(((PTOKEN_USER)Buffer)->User.Sid, Anonymous))
        bAnonymous = TRUE;

    CloseHandle(hToken);
    return bAnonymous;
}
