/*
 * PROJECT:     ReactOS Secondary Logon Service
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Secondary Logon service RPC server
 * COPYRIGHT:   Eric Kohl 2022 <eric.kohl@reactos.org>
 */

/* INCLUDES *****************************************************************/

#include "precomp.h"
#include <ndk/setypes.h>

#include <seclogon_s.h>

WINE_DEFAULT_DEBUG_CHANNEL(seclogon);

/* FUNCTIONS *****************************************************************/


void __RPC_FAR * __RPC_USER midl_user_allocate(SIZE_T len)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len);
}


void __RPC_USER midl_user_free(void __RPC_FAR * ptr)
{
    HeapFree(GetProcessHeap(), 0, ptr);
}


DWORD
StartRpcServer(VOID)
{
    NTSTATUS Status;

    Status = lpServiceGlobals->StartRpcServer(L"seclogon", ISeclogon_v1_0_s_ifspec);
    TRACE("StartRpcServer returned 0x%08lx\n", Status);

    return RtlNtStatusToDosError(Status);
}


DWORD
StopRpcServer(VOID)
{
    NTSTATUS Status;

    Status = lpServiceGlobals->StopRpcServer(ISeclogon_v1_0_s_ifspec);
    TRACE("StopRpcServer returned 0x%08lx\n", Status);

    return RtlNtStatusToDosError(Status);
}


/*
 * The session of the RPC caller: the session of the process at the other end of the call, which the
 * kernel recorded when that process opened the pipe. Never the session of the token the call came
 * with: a token's session id is only what its creator set (a token from LogonUser and the anonymous
 * token say session 0 whatever session the program runs in), and any program may impersonate one.
 * The caller must also be the process the request names, the one that gets the handles.
 */
static
DWORD
SeclGetCallerSession(
    _In_ handle_t hBinding,
    _In_ DWORD dwRequestProcessId,
    _Out_ PDWORD SessionId)
{
    ULONG ClientProcessId = 0;
    RPC_STATUS RpcStatus;

    RpcStatus = I_RpcBindingInqLocalClientPID(hBinding, &ClientProcessId);
    if (RpcStatus != RPC_S_OK || ClientProcessId == 0)
    {
        WARN("No local client process for the call, RPC status %lu\n", RpcStatus);
        return ERROR_ACCESS_DENIED;
    }
    if (ClientProcessId != dwRequestProcessId)
    {
        WARN("The request names process %lu, the caller is process %lu\n", dwRequestProcessId, ClientProcessId);
        return ERROR_ACCESS_DENIED;
    }
    if (!ProcessIdToSessionId(ClientProcessId, SessionId))
    {
        WARN("Cannot read the session of process %lu, Error %lu\n", ClientProcessId, GetLastError());
        return ERROR_ACCESS_DENIED;
    }
    return ERROR_SUCCESS;
}

VOID
__stdcall
SeclCreateProcessWithLogonW(
    _In_ handle_t hBinding,
    _In_ SECL_REQUEST *pRequest,
    _Out_ SECL_RESPONSE *pResponse)
{
    STARTUPINFOW StartupInfo;
    PROCESS_INFORMATION ProcessInfo;

    PROFILEINFOW ProfileInfo;
    SECL_DESKTOP_ACCESS *DesktopAccess = NULL;
    SECL_NAMESPACE_ACCESS *NamespaceAccess = NULL;
    PWSTR pszDesktop = NULL;
    PCWSTR ClientDesktop = NULL;
    LPVOID pEnvironment = NULL;
    DWORD dwCreationFlags;
    HANDLE hToken = NULL;
    HANDLE hTargetProcessHandle = NULL;

    ULONG dwError = ERROR_SUCCESS;
    BOOL rc;
    DWORD CallerSessionId = 0, OwnSessionId = 0;
    BOOL bOtherSession = FALSE;

    TRACE("SeclCreateProcessWithLogonW(%p %p %p)\n", hBinding, pRequest, pResponse);

    if (pRequest != NULL)
    {
        TRACE("Username: '%S'\n", pRequest->Username);
        TRACE("Domain: '%S'\n", pRequest->Domain);
        TRACE("Password: '%S'\n", pRequest->Password);
        TRACE("ApplicationName: '%S'\n", pRequest->ApplicationName);
        TRACE("CommandLine: '%S'\n", pRequest->CommandLine);
        TRACE("CurrentDirectory: '%S'\n", pRequest->CurrentDirectory);
        TRACE("Desktop: '%S'\n", pRequest->Desktop);
        TRACE("LogonFlags: 0x%lx\n", pRequest->dwLogonFlags);
        TRACE("CreationFlags: 0x%lx\n", pRequest->dwCreationFlags);
        TRACE("ProcessId: %lu\n", pRequest->dwProcessId);
    }

    if (pResponse != NULL)
    {
        pResponse->dwFlags = 0;
        pResponse->dwLogonSidLength = 0;
    }

    hTargetProcessHandle = OpenProcess(PROCESS_DUP_HANDLE,
                                       FALSE,
                                       pRequest->dwProcessId);
    if (hTargetProcessHandle == NULL)
    {
        dwError = GetLastError();
        WARN("OpenProcess() failed with Error %lu\n", dwError);
        goto done;
    }

    /*
     * The program runs in the caller's session, as runas does on Windows (on the caller's desktop). The
     * session is the one of the calling process, never anything the request or the caller's token says;
     * the process the handles go to is the calling process.
     */
    dwError = SeclGetCallerSession(hBinding, pRequest->dwProcessId, &CallerSessionId);
    if (dwError != ERROR_SUCCESS)
        goto done;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &OwnSessionId))
        OwnSessionId = 0;
    bOtherSession = (CallerSessionId != OwnSessionId);

    ZeroMemory(&ProfileInfo, sizeof(ProfileInfo));
    ZeroMemory(&ProcessInfo, sizeof(ProcessInfo));

    /* Logon */
    rc = LogonUser(pRequest->Username,
                   pRequest->Domain,
                   pRequest->Password,
                   LOGON32_LOGON_INTERACTIVE,
                   LOGON32_PROVIDER_DEFAULT,
                   &hToken);
    if (rc == FALSE)
    {
        dwError = GetLastError();
        WARN("LogonUser() failed with Error %lu\n", dwError);
        goto done;
    }

    /* The new logon's process is created in the caller's session (setting it needs SeTcbPrivilege) */
    if (bOtherSession)
    {
        BOOLEAN Old;

        RtlAdjustPrivilege(SE_TCB_PRIVILEGE, TRUE, FALSE, &Old);
        if (!SetTokenInformation(hToken, TokenSessionId, &CallerSessionId, sizeof(CallerSessionId)))
        {
            dwError = GetLastError();
            WARN("Cannot give the token session %lu, Error %lu\n", CallerSessionId, dwError);
            goto done;
        }
    }

    /* Load the user profile */
    if (pRequest->dwLogonFlags & LOGON_WITH_PROFILE)
    {
        ProfileInfo.dwSize = sizeof(ProfileInfo);
        ProfileInfo.lpUserName = pRequest->Username;

        rc = LoadUserProfileW(hToken,
                              &ProfileInfo);
        if (rc == FALSE)
        {
            dwError = GetLastError();
            WARN("LoadUserProfile() failed with Error %lu\n", dwError);
            goto done;
        }
    }

    /* Initialize the startup information */
    ZeroMemory(&StartupInfo, sizeof(StartupInfo));
    StartupInfo.cb = sizeof(StartupInfo);

    /* FIXME: Get more startup info from the caller */

    /*
     * The process runs on the desktop the caller named, else on the interactive one (WinSta0\Default).
     * Its new logon needs access to the window station and the desktop to create a window there.
     */
    if (!bOtherSession)
    {
        SeclGrantDesktopAccess(hToken, pRequest->Desktop, &DesktopAccess, &pszDesktop);
        StartupInfo.lpDesktop = pszDesktop;
    }
    else
    {
        /* This service cannot reach the window stations of another session: its helper there gives the access
           (SeclGrantClientDesktop), the process waits suspended until it has */
        StartupInfo.lpDesktop = pRequest->Desktop ? pRequest->Desktop : L"WinSta0\\Default";
    }

    /*
     * Without an environment from the caller, the new process gets one made from the profile of
     * the user (CreateProcessWithLogonW documents that); passing none would give it the one of this
     * service, with the profile of the system as USERPROFILE.
     */
    dwCreationFlags = pRequest->dwCreationFlags;
    if (bOtherSession)
        dwCreationFlags |= CREATE_SUSPENDED;
    if (pRequest->Environment != NULL)
    {
        pEnvironment = pRequest->Environment;
    }
    else if (CreateEnvironmentBlock(&pEnvironment, hToken, FALSE))
    {
        dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;
    }
    else
    {
        WARN("CreateEnvironmentBlock() failed with Error %lu\n", GetLastError());
        pEnvironment = NULL;
    }

    /* Create Process */
    rc = CreateProcessAsUserW(hToken,
                              pRequest->ApplicationName,
                              pRequest->CommandLine,
                              NULL,  // lpProcessAttributes,
                              NULL,  // lpThreadAttributes,
                              FALSE, // bInheritHandles,
                              dwCreationFlags,
                              pEnvironment,  // lpEnvironment,
                              pRequest->CurrentDirectory,
                              &StartupInfo,
                              &ProcessInfo);
    if (pEnvironment != NULL && pEnvironment != pRequest->Environment)
    {
        DestroyEnvironmentBlock(pEnvironment);
        pEnvironment = NULL;
    }

    if (rc == FALSE)
    {
        dwError = GetLastError();
        WARN("CreateProcessAsUser() failed with Error %lu\n", dwError);
        goto done;
    }

    /*
     * The program's named objects in the caller's session (unqualified and Local\ names): the new logon
     * gets the rights a program of a secondary logon has there on Windows. The process is still suspended
     * (it runs in another session than this service); the entries go when it has exited.
     */
    if (bOtherSession &&
        SeclGrantNamespaceAccess(hToken, CallerSessionId, &NamespaceAccess) != ERROR_SUCCESS)
    {
        WARN("The new logon gets no access to the named objects of session %lu\n", CallerSessionId);
    }

    /*
     * The window station and the desktop in the caller's session: the helper gives the new logon its entries there,
     * as far as the caller may change them itself (it opens both with the caller's token; the caller waits for
     * this answer). A name that is not a plain window station and desktop name gets no entry.
     */
    if (bOtherSession)
    {
        PSID LogonSid = SeclGetLogonSid(hToken);

        if (LogonSid != NULL && SeclValidDesktopName(StartupInfo.lpDesktop))
        {
            ClientDesktop = StartupInfo.lpDesktop;
            if (!SeclGrantClientDesktop(CallerSessionId, pRequest->dwProcessId, LogonSid, ClientDesktop))
                WARN("The new logon gets no access to desktop %S of session %lu\n", ClientDesktop, CallerSessionId);
        }
        else
        {
            WARN("No window station and desktop access for the new logon (desktop name refused)\n");
        }
        if (LogonSid != NULL)
            HeapFree(GetProcessHeap(), 0, LogonSid);
    }

    /*
     * Keep the access of the logon and the user's profile (HKEY_CURRENT_USER of the new process is
     * its hive) until the logon has no process left: the program may be a launcher that starts the real
     * one and exits. In another session the window station and desktop entries the helper gave are taken
     * back by the helper as well. If that cannot be arranged, the profile stays loaded (it is reference
     * counted, a later logon of the user reuses it) rather than being unloaded under the running process.
     */
    if (DesktopAccess != NULL || NamespaceAccess != NULL || ProfileInfo.hProfile != NULL || bOtherSession)
    {
        if (SeclStartLogonWait(DesktopAccess, NamespaceAccess, hToken, ProfileInfo.hProfile, ProcessInfo.hProcess,
                               CallerSessionId, ClientDesktop))
        {
            DesktopAccess = NULL;
            NamespaceAccess = NULL;
            ProfileInfo.hProfile = NULL;
        }
        else
        {
            /* The entries in the named-object directories go now (below): never left after the process */
            WARN("Cannot wait for the process to exit, Error %lu\n", GetLastError());
            ProfileInfo.hProfile = NULL;
        }
    }

    /* Return process info to the caller */
    if (pResponse != NULL)
    {
        HANDLE hProcessCopy = NULL, hThreadCopy = NULL;

        if (!DuplicateHandle(GetCurrentProcess(),
                             ProcessInfo.hProcess,
                             hTargetProcessHandle,
                             &hProcessCopy,
                             0,
                             FALSE,
                             DUPLICATE_SAME_ACCESS) ||
            !DuplicateHandle(GetCurrentProcess(),
                             ProcessInfo.hThread,
                             hTargetProcessHandle,
                             &hThreadCopy,
                             0,
                             FALSE,
                             DUPLICATE_SAME_ACCESS))
        {
            dwError = GetLastError();
            WARN("DuplicateHandle() failed with Error %lu\n", dwError);
            if (hProcessCopy != NULL)
            {
                /* Close the copy in the caller */
                DuplicateHandle(hTargetProcessHandle, hProcessCopy, NULL, NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
            }
            goto done;
        }

        pResponse->hProcess = (DWORD)(ULONG_PTR)hProcessCopy;
        pResponse->hThread = (DWORD)(ULONG_PTR)hThreadCopy;
        pResponse->dwProcessId = ProcessInfo.dwProcessId;
        pResponse->dwThreadId = ProcessInfo.dwThreadId;
    }

    /* Created suspended in another session for the grant: it runs now, unless the caller asked otherwise */
    if (bOtherSession && !(pRequest->dwCreationFlags & CREATE_SUSPENDED))
        ResumeThread(ProcessInfo.hThread);

done:
    /* A process created suspended for the caller that the caller will not get is ended */
    if (dwError != ERROR_SUCCESS && bOtherSession && ProcessInfo.hProcess)
        TerminateProcess(ProcessInfo.hProcess, dwError);

    SeclRevokeDesktopAccess(DesktopAccess);
    SeclRevokeNamespaceAccess(NamespaceAccess);

    if (pszDesktop)
        HeapFree(GetProcessHeap(), 0, pszDesktop);

    if (hTargetProcessHandle)
        CloseHandle(hTargetProcessHandle);

    if (ProcessInfo.hThread)
        CloseHandle(ProcessInfo.hThread);

    if (ProcessInfo.hProcess)
        CloseHandle(ProcessInfo.hProcess);

    if (ProfileInfo.hProfile != NULL)
        UnloadUserProfile(hToken, ProfileInfo.hProfile);

    if (hToken != NULL)
        CloseHandle(hToken);

    if (pResponse != NULL)
        pResponse->dwError = dwError;
}
