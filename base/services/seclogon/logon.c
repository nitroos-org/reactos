/*
 * PROJECT:     ReactOS Secondary Logon Service
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     The lifetime of a secondary logon: what was given to it is taken back when its last process is gone
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The program of a secondary logon gets entries for its logon SID in the named-object directories of its session,
 * in the DACL of the window station and the desktop it runs on, and a loaded profile. Many programs are launchers:
 * they start the real program and exit. So none of this goes when the first process exits, but when the logon has
 * no process left: after the first process has exited, the processes whose token carries the logon SID are looked
 * up (a process of the logon can only be started while another one of it still runs) and waited for, again and
 * again, until there is none.
 *
 * This service cannot reach the window stations of another session. For a program started in another session, the
 * window station and the desktop entries are given and taken back by a short helper the service starts in that
 * session as SYSTEM (seclhelp.exe, see SeclHelperMain): on the session's Winlogon desktop, which no program of the
 * session can open, so no hook a program installs on its own desktop reaches it, and it makes no window. It gives
 * the entry only on what the caller of CreateProcessWithLogonW may change itself (it opens both with the caller's
 * token) and takes out only the entries of that logon SID.
 *
 * The wait runs in this service's process and keeps the DLL loaded: stopping and starting the service in between
 * changes nothing. If the process itself ends (the entries of a logon then stay), the next start of the service
 * takes the entries of logons without a process out of the named-object directories (SeclSweepNamespaceAccess).
 */

#include "precomp.h"
#include <ndk/setypes.h>
#include <tlhelp32.h>
#include <sddl.h>
#include <strsafe.h>

WINE_DEFAULT_DEBUG_CHANNEL(seclogon);

typedef struct _SECL_LOGON_WAIT
{
    SECL_DESKTOP_ACCESS *Access;
    SECL_NAMESPACE_ACCESS *Namespace;
    HANDLE hProcess;
    HANDLE hToken;
    HANDLE hProfile;
    PSID LogonSid;
    DWORD ClientSessionId;
    PWSTR ClientDesktop;
    HMODULE hSelf;
} SECL_LOGON_WAIT, *PSECL_LOGON_WAIT;

/* Whether the token of the process carries LogonSid as its logon SID */
static BOOL
ProcessHasLogonSid(
    _In_ HANDLE hProcess,
    _In_ PSID LogonSid)
{
    PTOKEN_GROUPS Groups = NULL;
    HANDLE hToken;
    DWORD Size = 0, i;
    BOOL Found = FALSE;

    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
        return FALSE;
    GetTokenInformation(hToken, TokenGroups, NULL, 0, &Size);
    if (Size != 0)
        Groups = HeapAlloc(GetProcessHeap(), 0, Size);
    if (Groups != NULL && GetTokenInformation(hToken, TokenGroups, Groups, Size, &Size))
    {
        for (i = 0; i < Groups->GroupCount && !Found; i++)
        {
            Found = ((Groups->Groups[i].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID) &&
                    EqualSid(Groups->Groups[i].Sid, LogonSid);
        }
    }
    if (Groups != NULL)
        HeapFree(GetProcessHeap(), 0, Groups);
    CloseHandle(hToken);
    return Found;
}

/*
 * Opens (SYNCHRONIZE) up to Max running processes of the logon. Returns how many, or MAXDWORD if the processes
 * could not be listed. More than Max processes: the others are found again once one of these has exited.
 */
static DWORD
OpenLogonProcesses(
    _In_ PSID LogonSid,
    _Out_writes_(Max) HANDLE *Handles,
    _In_ DWORD Max)
{
    PROCESSENTRY32W Entry;
    HANDLE hSnapshot, hProcess;
    DWORD Count = 0, Self = GetCurrentProcessId();
    BOOL More;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return MAXDWORD;
    Entry.dwSize = sizeof(Entry);
    for (More = Process32FirstW(hSnapshot, &Entry); More && Count < Max; More = Process32NextW(hSnapshot, &Entry))
    {
        if (Entry.th32ProcessID == 0 || Entry.th32ProcessID == Self)
            continue;
        hProcess = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION, FALSE, Entry.th32ProcessID);
        if (hProcess == NULL)
            continue;
        /* An exited process stays listed while handles to it are open */
        if (WaitForSingleObject(hProcess, 0) == WAIT_TIMEOUT && ProcessHasLogonSid(hProcess, LogonSid))
            Handles[Count++] = hProcess;
        else
            CloseHandle(hProcess);
    }
    CloseHandle(hSnapshot);
    return Count;
}

/* Returns when no process of the logon is left */
VOID
SeclWaitForLogonProcesses(
    _In_ PSID LogonSid)
{
    HANDLE Handles[MAXIMUM_WAIT_OBJECTS];
    DWORD Count, i;

    for (;;)
    {
        Count = OpenLogonProcesses(LogonSid, Handles, RTL_NUMBER_OF(Handles));
        if (Count == 0)
            break;
        if (Count == MAXDWORD)
        {
            WARN("Cannot list the processes, Error %lu: looking again\n", GetLastError());
            Sleep(1000);
            continue;
        }
        WaitForMultipleObjects(Count, Handles, FALSE, INFINITE);
        for (i = 0; i < Count; i++)
            CloseHandle(Handles[i]);
    }
}

static DWORD
RunHelper(
    _In_ DWORD SessionId,
    _In_ PCWSTR Mode,
    _In_ DWORD CallerProcessId,
    _In_ PSID LogonSid,
    _In_ PCWSTR Desktop);

/*
 * Takes the entries of LogonSid out of the window station and desktop Desktop ("WinSta\Desktop") of session
 * SessionId: the helper started there as SYSTEM does it (see SeclHelperMain).
 */
VOID
SeclRevokeClientDesktop(
    _In_ DWORD SessionId,
    _In_ PSID LogonSid,
    _In_ PCWSTR Desktop)
{
    if (RunHelper(SessionId, L"revoke", 0, LogonSid, Desktop) != ERROR_SUCCESS)
        WARN("The window station and desktop entries of a logon in session %lu may stay\n", SessionId);
}

/*
 * Gives LogonSid its entries on the window station and desktop Desktop of session SessionId, as far as the caller of
 * CreateProcessWithLogonW (process CallerProcessId, which waits for this service's answer) may change them itself.
 */
BOOL
SeclGrantClientDesktop(
    _In_ DWORD SessionId,
    _In_ DWORD CallerProcessId,
    _In_ PSID LogonSid,
    _In_ PCWSTR Desktop)
{
    return RunHelper(SessionId, L"grant", CallerProcessId, LogonSid, Desktop) == ERROR_SUCCESS;
}

/*
 * Starts seclhelp.exe as SYSTEM in session SessionId, on that session's Winlogon desktop, and waits for it (see
 * SeclHelperMain): "<Mode> [<CallerProcessId>] <LogonSid> <Desktop>". Desktop must pass SeclValidDesktopName.
 * Returns the helper's exit code, or an error of its start.
 */
static DWORD
RunHelper(
    _In_ DWORD SessionId,
    _In_ PCWSTR Mode,
    _In_ DWORD CallerProcessId,
    _In_ PSID LogonSid,
    _In_ PCWSTR Desktop)
{
    WCHAR Path[MAX_PATH], Command[MAX_PATH + 512];
    PWSTR SidString = NULL;
    STARTUPINFOW StartupInfo;
    PROCESS_INFORMATION ProcessInfo;
    HANDLE hOwn = NULL, hToken = NULL;
    DWORD Exit = ERROR_GEN_FAILURE;
    BOOLEAN Old;
    HRESULT hr;

    if (!SeclValidDesktopName(Desktop))
        return ERROR_INVALID_PARAMETER;
    if (!ConvertSidToStringSidW(LogonSid, &SidString))
        return GetLastError();
    if (!GetSystemDirectoryW(Path, RTL_NUMBER_OF(Path) - 16) ||
        FAILED(StringCchCatW(Path, RTL_NUMBER_OF(Path), L"\\seclhelp.exe")))
    {
        LocalFree(SidString);
        return ERROR_BUFFER_OVERFLOW;
    }
    if (CallerProcessId != 0)
        hr = StringCchPrintfW(Command, RTL_NUMBER_OF(Command), L"\"%s\" %s %lu %s %s",
                              Path, Mode, CallerProcessId, SidString, Desktop);
    else
        hr = StringCchPrintfW(Command, RTL_NUMBER_OF(Command), L"\"%s\" %s %s %s", Path, Mode, SidString, Desktop);
    LocalFree(SidString);
    if (FAILED(hr))
        return ERROR_BUFFER_OVERFLOW;

    /* This service's own token, in the session of the window station (setting the session needs SeTcbPrivilege) */
    RtlAdjustPrivilege(SE_TCB_PRIVILEGE, TRUE, FALSE, &Old);
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &hOwn) ||
        !DuplicateTokenEx(hOwn, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hToken) ||
        !SetTokenInformation(hToken, TokenSessionId, &SessionId, sizeof(SessionId)))
    {
        Exit = GetLastError();
        ERR("No token for the helper in session %lu, Error %lu\n", SessionId, Exit);
        goto done;
    }

    /* The Winlogon desktop: SYSTEM only, so no program of the session can hook a thread there */
    ZeroMemory(&StartupInfo, sizeof(StartupInfo));
    StartupInfo.cb = sizeof(StartupInfo);
    StartupInfo.lpDesktop = L"WinSta0\\Winlogon";
    if (!CreateProcessAsUserW(hToken, Path, Command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL,
                              &StartupInfo, &ProcessInfo))
    {
        Exit = GetLastError();
        ERR("Cannot start the helper in session %lu, Error %lu\n", SessionId, Exit);
        goto done;
    }
    if (WaitForSingleObject(ProcessInfo.hProcess, 60000) != WAIT_OBJECT_0)
    {
        TerminateProcess(ProcessInfo.hProcess, ERROR_TIMEOUT);
        Exit = ERROR_TIMEOUT;
    }
    else if (!GetExitCodeProcess(ProcessInfo.hProcess, &Exit))
    {
        Exit = GetLastError();
    }
    if (Exit != ERROR_SUCCESS)
        WARN("The helper (%S) in session %lu ended with %lu\n", Mode, SessionId, Exit);
    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);

done:
    if (hToken != NULL)
        CloseHandle(hToken);
    if (hOwn != NULL)
        CloseHandle(hOwn);
    return Exit;
}

static DWORD
WINAPI
WaitForLogonEnd(
    _In_ PVOID Context)
{
    PSECL_LOGON_WAIT Wait = Context;
    HMODULE hSelf = Wait->hSelf;

    /* The first process, then every process of its logon */
    WaitForSingleObject(Wait->hProcess, INFINITE);
    CloseHandle(Wait->hProcess);
    if (Wait->LogonSid != NULL)
        SeclWaitForLogonProcesses(Wait->LogonSid);

    SeclRevokeDesktopAccess(Wait->Access);
    SeclRevokeNamespaceAccess(Wait->Namespace);
    if (Wait->ClientDesktop != NULL && Wait->LogonSid != NULL)
        SeclRevokeClientDesktop(Wait->ClientSessionId, Wait->LogonSid, Wait->ClientDesktop);
    if (Wait->hProfile != NULL)
    {
        if (!UnloadUserProfile(Wait->hToken, Wait->hProfile))
            WARN("UnloadUserProfile() failed with Error %lu\n", GetLastError());
    }
    if (Wait->hToken != NULL)
        CloseHandle(Wait->hToken);
    if (Wait->ClientDesktop != NULL)
        HeapFree(GetProcessHeap(), 0, Wait->ClientDesktop);
    if (Wait->LogonSid != NULL)
        HeapFree(GetProcessHeap(), 0, Wait->LogonSid);
    HeapFree(GetProcessHeap(), 0, Wait);

    if (hSelf != NULL)
        FreeLibraryAndExitThread(hSelf, 0);
    return 0;
}

/*
 * Hands what was given to the logon of hToken (each may be NULL) to a thread that takes it back when the logon has
 * no process left. ClientDesktop: the window station and desktop of session ClientSessionId the helper gave the
 * logon its entries on. On success the thread owns Access, Namespace and hProfile; on failure the caller keeps them.
 */
BOOL
SeclStartLogonWait(
    _In_opt_ SECL_DESKTOP_ACCESS *Access,
    _In_opt_ SECL_NAMESPACE_ACCESS *Namespace,
    _In_ HANDLE hToken,
    _In_opt_ HANDLE hProfile,
    _In_ HANDLE hProcess,
    _In_ DWORD ClientSessionId,
    _In_opt_ PCWSTR ClientDesktop)
{
    PSECL_LOGON_WAIT Wait;
    HANDLE hThread;
    SIZE_T Length;

    Wait = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Wait));
    if (Wait == NULL)
        return FALSE;

    Wait->LogonSid = SeclGetLogonSid(hToken);
    if (ClientDesktop != NULL)
    {
        Length = (wcslen(ClientDesktop) + 1) * sizeof(WCHAR);
        Wait->ClientDesktop = HeapAlloc(GetProcessHeap(), 0, Length);
        if (Wait->ClientDesktop != NULL)
            CopyMemory(Wait->ClientDesktop, ClientDesktop, Length);
        Wait->ClientSessionId = ClientSessionId;
    }
    if (!DuplicateHandle(GetCurrentProcess(), hProcess, GetCurrentProcess(), &Wait->hProcess,
                         SYNCHRONIZE, FALSE, 0) ||
        !DuplicateHandle(GetCurrentProcess(), hToken, GetCurrentProcess(), &Wait->hToken,
                         0, FALSE, DUPLICATE_SAME_ACCESS))
    {
        goto fail;
    }

    /* The thread keeps this DLL loaded until it is done */
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (PCWSTR)SeclStartLogonWait, &Wait->hSelf))
        Wait->hSelf = NULL;

    Wait->Access = Access;
    Wait->Namespace = Namespace;
    Wait->hProfile = hProfile;
    hThread = CreateThread(NULL, 0, WaitForLogonEnd, Wait, 0, NULL);
    if (hThread == NULL)
    {
        if (Wait->hSelf != NULL)
            FreeLibrary(Wait->hSelf);
        goto fail;
    }
    CloseHandle(hThread);
    return TRUE;

fail:
    if (Wait->hToken != NULL)
        CloseHandle(Wait->hToken);
    if (Wait->hProcess != NULL)
        CloseHandle(Wait->hProcess);
    if (Wait->ClientDesktop != NULL)
        HeapFree(GetProcessHeap(), 0, Wait->ClientDesktop);
    if (Wait->LogonSid != NULL)
        HeapFree(GetProcessHeap(), 0, Wait->LogonSid);
    HeapFree(GetProcessHeap(), 0, Wait);
    return FALSE;
}
