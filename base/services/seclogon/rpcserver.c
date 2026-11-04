/*
 * PROJECT:     ReactOS Secondary Logon Service
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Secondary Logon service RPC server
 * COPYRIGHT:   Eric Kohl 2022 <eric.kohl@reactos.org>
 */

/* INCLUDES *****************************************************************/

#include "precomp.h"

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
} SECL_EXIT_WAIT, *PSECL_EXIT_WAIT;


/* Takes the logon SID out of the window station and the desktop when the process is gone */
static DWORD
WINAPI
WaitForProcessExit(
    _In_ PVOID Context)
{
    PSECL_EXIT_WAIT Wait = Context;

    WaitForSingleObject(Wait->hProcess, INFINITE);
    SeclRevokeDesktopAccess(Wait->Access);
    CloseHandle(Wait->hProcess);
    HeapFree(GetProcessHeap(), 0, Wait);
    return 0;
}


static BOOL
StartExitWait(
    _In_ SECL_DESKTOP_ACCESS *Access,
    _In_ HANDLE hProcess)
{
    PSECL_EXIT_WAIT Wait;
    HANDLE hThread;

    Wait = HeapAlloc(GetProcessHeap(), 0, sizeof(*Wait));
    if (Wait == NULL)
        return FALSE;

    Wait->Access = Access;
    if (!DuplicateHandle(GetCurrentProcess(), hProcess, GetCurrentProcess(), &Wait->hProcess,
                         SYNCHRONIZE, FALSE, 0))
    {
        HeapFree(GetProcessHeap(), 0, Wait);
        return FALSE;
    }

    hThread = CreateThread(NULL, 0, WaitForProcessExit, Wait, 0, NULL);
    if (hThread == NULL)
    {
        CloseHandle(Wait->hProcess);
        HeapFree(GetProcessHeap(), 0, Wait);
        return FALSE;
    }

    CloseHandle(hThread);
    return TRUE;
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
    HANDLE hToken = NULL;
    HANDLE hTargetProcessHandle = NULL;

    ULONG dwError = ERROR_SUCCESS;
    BOOL rc;

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

    hTargetProcessHandle = OpenProcess(PROCESS_DUP_HANDLE,
                                       FALSE,
                                       pRequest->dwProcessId);
    if (hTargetProcessHandle == NULL)
    {
        dwError = GetLastError();
        WARN("OpenProcess() failed with Error %lu\n", dwError);
        goto done;
    }

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
    SeclGrantDesktopAccess(hToken, pRequest->Desktop, &DesktopAccess, &pszDesktop);
    StartupInfo.lpDesktop = pszDesktop;

    /* Create Process */
    rc = CreateProcessAsUserW(hToken,
                              pRequest->ApplicationName,
                              pRequest->CommandLine,
                              NULL,  // lpProcessAttributes,
                              NULL,  // lpThreadAttributes,
                              FALSE, // bInheritHandles,
                              pRequest->dwCreationFlags,
                              pRequest->Environment,  // lpEnvironment,
                              pRequest->CurrentDirectory,
                              &StartupInfo,
                              &ProcessInfo);
    if (rc == FALSE)
    {
        dwError = GetLastError();
        WARN("CreateProcessAsUser() failed with Error %lu\n", dwError);
        goto done;
    }

    /* Keep the access of the logon until the process has exited */
    if (DesktopAccess != NULL)
    {
        if (StartExitWait(DesktopAccess, ProcessInfo.hProcess))
            DesktopAccess = NULL;
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

done:
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
