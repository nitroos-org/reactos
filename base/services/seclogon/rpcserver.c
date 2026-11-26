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


typedef struct _SECL_EXIT_WAIT
{
    SECL_DESKTOP_ACCESS *Access;
    HANDLE hProcess;
    HANDLE hToken;
    HANDLE hProfile;
} SECL_EXIT_WAIT, *PSECL_EXIT_WAIT;


/*
 * When the process is gone: takes the logon SID out of the window station and the desktop, and
 * unloads the user profile loaded for it (LOGON_WITH_PROFILE). CreateProcessWithLogonW documents
 * that the profile stays loaded for the new process and is unloaded after it has terminated.
 */
static DWORD
WINAPI
WaitForProcessExit(
    _In_ PVOID Context)
{
    PSECL_EXIT_WAIT Wait = Context;

    WaitForSingleObject(Wait->hProcess, INFINITE);
    SeclRevokeDesktopAccess(Wait->Access);
    if (Wait->hProfile != NULL)
    {
        if (!UnloadUserProfile(Wait->hToken, Wait->hProfile))
            WARN("UnloadUserProfile() failed with Error %lu\n", GetLastError());
    }
    if (Wait->hToken != NULL)
        CloseHandle(Wait->hToken);
    CloseHandle(Wait->hProcess);
    HeapFree(GetProcessHeap(), 0, Wait);
    return 0;
}


/*
 * Hands the desktop access and the loaded profile (each may be NULL) to a thread that releases
 * them when the process exits. On success the thread owns both; on failure the caller keeps them.
 */
static BOOL
StartExitWait(
    _In_opt_ SECL_DESKTOP_ACCESS *Access,
    _In_opt_ HANDLE hToken,
    _In_opt_ HANDLE hProfile,
    _In_ HANDLE hProcess)
{
    PSECL_EXIT_WAIT Wait;
    HANDLE hThread;

    Wait = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Wait));
    if (Wait == NULL)
        return FALSE;

    Wait->Access = Access;
    if (!DuplicateHandle(GetCurrentProcess(), hProcess, GetCurrentProcess(), &Wait->hProcess,
                         SYNCHRONIZE, FALSE, 0))
    {
        HeapFree(GetProcessHeap(), 0, Wait);
        return FALSE;
    }

    /* UnloadUserProfile needs the token of the logon the profile was loaded for */
    if (hProfile != NULL)
    {
        if (!DuplicateHandle(GetCurrentProcess(), hToken, GetCurrentProcess(), &Wait->hToken,
                             0, FALSE, DUPLICATE_SAME_ACCESS))
        {
            CloseHandle(Wait->hProcess);
            HeapFree(GetProcessHeap(), 0, Wait);
            return FALSE;
        }
        Wait->hProfile = hProfile;
    }

    hThread = CreateThread(NULL, 0, WaitForProcessExit, Wait, 0, NULL);
    if (hThread == NULL)
    {
        if (Wait->hToken != NULL)
            CloseHandle(Wait->hToken);
        CloseHandle(Wait->hProcess);
        HeapFree(GetProcessHeap(), 0, Wait);
        return FALSE;
    }

    CloseHandle(hThread);
    return TRUE;
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

/* A copy of the logon SID of a token */
static
BOOL
SeclCopyLogonSid(
    _In_ HANDLE hToken,
    _Out_writes_bytes_(Size) PBYTE Buffer,
    _In_ DWORD Size,
    _Out_ PDWORD Length)
{
    PTOKEN_GROUPS Groups;
    DWORD Needed = 0, i;
    BOOL Found = FALSE;

    *Length = 0;
    GetTokenInformation(hToken, TokenGroups, NULL, 0, &Needed);
    if (!Needed) return FALSE;
    Groups = HeapAlloc(GetProcessHeap(), 0, Needed);
    if (!Groups) return FALSE;
    if (GetTokenInformation(hToken, TokenGroups, Groups, Needed, &Needed))
    {
        for (i = 0; i < Groups->GroupCount; i++)
        {
            if ((Groups->Groups[i].Attributes & SE_GROUP_LOGON_ID) != SE_GROUP_LOGON_ID) continue;
            if (GetLengthSid(Groups->Groups[i].Sid) <= Size &&
                CopySid(Size, Buffer, Groups->Groups[i].Sid))
            {
                *Length = GetLengthSid(Groups->Groups[i].Sid);
                Found = TRUE;
            }
            break;
        }
    }
    HeapFree(GetProcessHeap(), 0, Groups);
    return Found;
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
    PWSTR pszDesktop = NULL;
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
        /* This service cannot reach the window stations of another session: the caller grants the access
           (SECL_RESPONSE_GRANT_DESKTOP), the process waits suspended until it has */
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
     * Keep the access of the logon and the user's profile (HKEY_CURRENT_USER of the new process is
     * its hive) until the process has exited. If that cannot be arranged, the profile stays loaded
     * (it is reference counted, a later logon of the user reuses it) rather than being unloaded
     * under the running process.
     */
    if (DesktopAccess != NULL || ProfileInfo.hProfile != NULL)
    {
        if (StartExitWait(DesktopAccess, hToken, ProfileInfo.hProfile, ProcessInfo.hProcess))
        {
            DesktopAccess = NULL;
            ProfileInfo.hProfile = NULL;
        }
        else
        {
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

        if (bOtherSession)
        {
            /* The logon SID the caller grants the access to (CreateProcessWithLogonW resumes the thread) */
            if (!SeclCopyLogonSid(hToken, pResponse->LogonSid, sizeof(pResponse->LogonSid),
                                  &pResponse->dwLogonSidLength))
            {
                dwError = ERROR_NO_SUCH_LOGON_SESSION;
                DuplicateHandle(hTargetProcessHandle, hProcessCopy, NULL, NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
                DuplicateHandle(hTargetProcessHandle, hThreadCopy, NULL, NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
                pResponse->hProcess = pResponse->hThread = 0;
                goto done;
            }
            pResponse->dwFlags |= SECL_RESPONSE_GRANT_DESKTOP;
        }
    }

done:
    /* A process created suspended for the caller that the caller will not get is ended */
    if (dwError != ERROR_SUCCESS && bOtherSession && ProcessInfo.hProcess)
        TerminateProcess(ProcessInfo.hProcess, dwError);

    SeclRevokeDesktopAccess(DesktopAccess);

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
