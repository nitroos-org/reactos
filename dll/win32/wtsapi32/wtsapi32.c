/* Copyright 2005 Ulrich Czekalla
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdarg.h>
#include <stdlib.h>
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winnls.h"
#include "wine/winternl.h"
#include "wtsapi32.h"
#include "wine/debug.h"
#include "wine/heap.h"

WINE_DEFAULT_DEBUG_CHANNEL(wtsapi);

#ifdef __REACTOS__ /* FIXME: Inspect */
#define GetCurrentProcessToken() ((HANDLE)~(ULONG_PTR)3)
#endif

/************************************************************
 *                WTSCloseServer  (WTSAPI32.@)
 */
void WINAPI WTSCloseServer(HANDLE hServer)
{
    FIXME("Stub %p\n", hServer);
}

/************************************************************
 *                WTSConnectSessionA  (WTSAPI32.@)
 */
BOOL WINAPI WTSConnectSessionA(ULONG LogonId, ULONG TargetLogonId, PSTR pPassword, BOOL bWait)
{
   FIXME("Stub %d %d (%s) %d\n", LogonId, TargetLogonId, debugstr_a(pPassword), bWait);
   return TRUE;
}

/************************************************************
 *                WTSConnectSessionW  (WTSAPI32.@)
 */
BOOL WINAPI WTSConnectSessionW(ULONG LogonId, ULONG TargetLogonId, PWSTR pPassword, BOOL bWait)
{
   FIXME("Stub %d %d (%s) %d\n", LogonId, TargetLogonId, debugstr_w(pPassword), bWait);
   return TRUE;
}

/************************************************************
 *                WTSDisconnectSession  (WTSAPI32.@)
 */
BOOL WINAPI WTSDisconnectSession(HANDLE hServer, DWORD SessionId, BOOL bWait)
{
    FIXME("Stub %p 0x%08x %d\n", hServer, SessionId, bWait);
    return TRUE;
}

/************************************************************
 *                WTSEnableChildSessions  (WTSAPI32.@)
 */
BOOL WINAPI WTSEnableChildSessions(BOOL enable)
{
    FIXME("Stub %d\n", enable);
    return TRUE;
}


/************************************************************
 *                WTSEnumerateProcessesExW  (WTSAPI32.@)
 */
BOOL WINAPI WTSEnumerateProcessesExW(HANDLE server, DWORD *level, DWORD session_id, WCHAR **info, DWORD *count)
{
    FIXME("Stub %p %p %d %p %p\n", server, level, session_id, info, count);
    if (count) *count = 0;
    return FALSE;
}

/************************************************************
 *                WTSEnumerateProcessesExA  (WTSAPI32.@)
 */
BOOL WINAPI WTSEnumerateProcessesExA(HANDLE server, DWORD *level, DWORD session_id, char **info, DWORD *count)
{
    FIXME("Stub %p %p %d %p %p\n", server, level, session_id, info, count);
    if (count) *count = 0;
    return FALSE;
}

/************************************************************
 *                WTSEnumerateProcessesA  (WTSAPI32.@)
 */
BOOL WINAPI WTSEnumerateProcessesA(HANDLE hServer, DWORD Reserved, DWORD Version,
    PWTS_PROCESS_INFOA* ppProcessInfo, DWORD* pCount)
{
    FIXME("Stub %p 0x%08x 0x%08x %p %p\n", hServer, Reserved, Version,
          ppProcessInfo, pCount);

    if (!ppProcessInfo || !pCount) return FALSE;

    *pCount = 0;
    *ppProcessInfo = NULL;

    return TRUE;
}

/************************************************************
 *                WTSEnumerateProcessesW  (WTSAPI32.@)
 */
BOOL WINAPI WTSEnumerateProcessesW(HANDLE hServer, DWORD Reserved, DWORD Version,
    PWTS_PROCESS_INFOW* ppProcessInfo, DWORD* pCount)
{
    WTS_PROCESS_INFOW *processInfo;
    SYSTEM_PROCESS_INFORMATION *spi;
    ULONG size = 0x4000;
    void *buf = NULL;
    NTSTATUS status;
    DWORD count;
    WCHAR *name;

    if (!ppProcessInfo || !pCount || Reserved != 0 || Version != 1)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (hServer != WTS_CURRENT_SERVER_HANDLE)
    {
        SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    do
    {
        size *= 2;
        HeapFree(GetProcessHeap(), 0, buf);
        buf = HeapAlloc(GetProcessHeap(), 0, size);
        if (!buf)
        {
            SetLastError(ERROR_OUTOFMEMORY);
            return FALSE;
        }
        status = NtQuerySystemInformation(SystemProcessInformation, buf, size, NULL);
    }
    while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (status != STATUS_SUCCESS)
    {
        HeapFree(GetProcessHeap(), 0, buf);
        SetLastError(RtlNtStatusToDosError(status));
        return FALSE;
    }

    spi = buf;
    count = size = 0;
    for (;;)
    {
        size += sizeof(WTS_PROCESS_INFOW) + spi->ProcessName.Length + sizeof(WCHAR);
        count++;
        if (spi->NextEntryOffset == 0) break;
        spi = (SYSTEM_PROCESS_INFORMATION *)(((PCHAR)spi) + spi->NextEntryOffset);
    }

    processInfo = HeapAlloc(GetProcessHeap(), 0, size);
    if (!processInfo)
    {
        HeapFree(GetProcessHeap(), 0, buf);
        SetLastError(ERROR_OUTOFMEMORY);
        return FALSE;
    }
    name = (WCHAR *)&processInfo[count];

    *ppProcessInfo = processInfo;
    *pCount = count;

    spi = buf;
    while (count--)
    {
        processInfo->SessionId = spi->SessionId;
        processInfo->ProcessId = HandleToUlong(spi->UniqueProcessId);
        processInfo->pProcessName = name;
        processInfo->pUserSid = NULL;
        memcpy( name, spi->ProcessName.Buffer, spi->ProcessName.Length );
        name[ spi->ProcessName.Length/sizeof(WCHAR) ] = 0;

        processInfo++;
        name += (spi->ProcessName.Length + sizeof(WCHAR))/sizeof(WCHAR);
        spi = (SYSTEM_PROCESS_INFORMATION *)(((PCHAR)spi) + spi->NextEntryOffset);
    }

    HeapFree(GetProcessHeap(), 0, buf);
    return TRUE;
}

/************************************************************
 *                WTSEnumerateServersA  (WTSAPI32.@)
 */
BOOL WINAPI WTSEnumerateServersA(LPSTR pDomainName, DWORD Reserved, DWORD Version, PWTS_SERVER_INFOA *ppServerInfo, DWORD *pCount)
{
    FIXME("Stub %s 0x%08x 0x%08x %p %p\n", debugstr_a(pDomainName), Reserved, Version, ppServerInfo, pCount);
    return FALSE;
}

/************************************************************
 *                WTSEnumerateServersW  (WTSAPI32.@)
 */
BOOL WINAPI WTSEnumerateServersW(LPWSTR pDomainName, DWORD Reserved, DWORD Version, PWTS_SERVER_INFOW *ppServerInfo, DWORD *pCount)
{
    FIXME("Stub %s 0x%08x 0x%08x %p %p\n", debugstr_w(pDomainName), Reserved, Version, ppServerInfo, pCount);
    return FALSE;
}


/************************************************************
 *                WTSEnumerateEnumerateSessionsExW  (WTSAPI32.@)
 */
BOOL WINAPI WTSEnumerateSessionsExW(HANDLE server, DWORD *level, DWORD filter, WTS_SESSION_INFO_1W* info, DWORD *count)
{
    FIXME("Stub %p %p %d %p %p\n", server, level, filter, info, count);
    if (count) *count = 0;
    return FALSE;
}

/************************************************************
 *                WTSEnumerateEnumerateSessionsExA  (WTSAPI32.@)
 */
BOOL WINAPI WTSEnumerateSessionsExA(HANDLE server, DWORD *level, DWORD filter, WTS_SESSION_INFO_1A* info, DWORD *count)
{
    FIXME("Stub %p %p %d %p %p\n", server, level, filter, info, count);
    if (count) *count = 0;
    return FALSE;
}

/*
 * The sessions that have a process, in ascending order (at most Max). Session 0 holds the services, the
 * console session (session 1) the logged-on user; there are no remote sessions.
 */
static DWORD get_session_ids(DWORD *ids, DWORD max)
{
    SYSTEM_PROCESS_INFORMATION *spi;
    ULONG size = 0x4000;
    void *buf = NULL;
    NTSTATUS status;
    DWORD count = 0, i, j;

    do
    {
        size *= 2;
        heap_free(buf);
        buf = heap_alloc(size);
        if (!buf) return 0;
        status = NtQuerySystemInformation(SystemProcessInformation, buf, size, NULL);
    }
    while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (status == STATUS_SUCCESS)
    {
        spi = buf;
        for (;;)
        {
            for (i = 0; i < count && ids[i] != spi->SessionId; i++) ;
            if (i == count && count < max)
            {
                /* keep the list sorted */
                for (j = count; j > 0 && ids[j - 1] > spi->SessionId; j--) ids[j] = ids[j - 1];
                ids[j] = spi->SessionId;
                count++;
            }
            if (spi->NextEntryOffset == 0) break;
            spi = (SYSTEM_PROCESS_INFORMATION *)(((PCHAR)spi) + spi->NextEntryOffset);
        }
    }
    heap_free(buf);
    return count;
}

/* Windows 10 (measured): session 0 "Services" disconnected, the console session "Console" active */
static void get_session_state(DWORD id, WTS_CONNECTSTATE_CLASS *state, const WCHAR **name)
{
    if (id == WTSGetActiveConsoleSessionId())
    {
        *state = WTSActive;
        *name = L"Console";
    }
    else
    {
        *state = WTSDisconnected;
        *name = id ? L"" : L"Services";
    }
}

/************************************************************
 *                WTSEnumerateEnumerateSessionsA  (WTSAPI32.@)
 */
BOOL WINAPI WTSEnumerateSessionsA(HANDLE hServer, DWORD Reserved, DWORD Version,
    PWTS_SESSION_INFOA* ppSessionInfo, DWORD* pCount)
{
    WTS_SESSION_INFOA *info;
    const WCHAR *name;
    DWORD ids[64], count, i, size;
    char *str;
    int len;

    if (!ppSessionInfo || !pCount || Reserved != 0 || Version != 1)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (hServer != WTS_CURRENT_SERVER_HANDLE)
    {
        SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    count = get_session_ids(ids, ARRAY_SIZE(ids));
    size = count * sizeof(*info);
    for (i = 0; i < count; i++)
    {
        WTS_CONNECTSTATE_CLASS state;
        get_session_state(ids[i], &state, &name);
        size += WideCharToMultiByte(CP_ACP, 0, name, -1, NULL, 0, NULL, NULL);
    }
    info = heap_alloc(size ? size : 1);
    if (!info)
    {
        SetLastError(ERROR_OUTOFMEMORY);
        return FALSE;
    }
    str = (char *)&info[count];
    for (i = 0; i < count; i++)
    {
        info[i].SessionId = ids[i];
        get_session_state(ids[i], &info[i].State, &name);
        len = WideCharToMultiByte(CP_ACP, 0, name, -1, str, size - (DWORD)(str - (char *)info), NULL, NULL);
        info[i].pWinStationName = str;
        str += len;
    }
    *ppSessionInfo = info;
    *pCount = count;
    return TRUE;
}

/************************************************************
 *                WTSEnumerateEnumerateSessionsW  (WTSAPI32.@)
 */
BOOL WINAPI WTSEnumerateSessionsW(HANDLE hServer, DWORD Reserved, DWORD Version,
    PWTS_SESSION_INFOW* ppSessionInfo, DWORD* pCount)
{
    WTS_SESSION_INFOW *info;
    const WCHAR *name;
    DWORD ids[64], count, i, size;
    WCHAR *str;

    if (!ppSessionInfo || !pCount || Reserved != 0 || Version != 1)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (hServer != WTS_CURRENT_SERVER_HANDLE)
    {
        SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    count = get_session_ids(ids, ARRAY_SIZE(ids));
    size = count * sizeof(*info);
    for (i = 0; i < count; i++)
    {
        WTS_CONNECTSTATE_CLASS state;
        get_session_state(ids[i], &state, &name);
        size += (lstrlenW(name) + 1) * sizeof(WCHAR);
    }
    info = heap_alloc(size ? size : 1);
    if (!info)
    {
        SetLastError(ERROR_OUTOFMEMORY);
        return FALSE;
    }
    str = (WCHAR *)&info[count];
    for (i = 0; i < count; i++)
    {
        info[i].SessionId = ids[i];
        get_session_state(ids[i], &info[i].State, &name);
        lstrcpyW(str, name);
        info[i].pWinStationName = str;
        str += lstrlenW(name) + 1;
    }
    *ppSessionInfo = info;
    *pCount = count;
    return TRUE;
}

/************************************************************
 *                WTSFreeMemory (WTSAPI32.@)
 */
void WINAPI WTSFreeMemory(PVOID pMemory)
{
    heap_free(pMemory);
}

/************************************************************
 *                WTSFreeMemoryExA (WTSAPI32.@)
 */
BOOL WINAPI WTSFreeMemoryExA(WTS_TYPE_CLASS type, void *ptr, ULONG nmemb)
{
    TRACE("%d %p %d\n", type, ptr, nmemb);
    heap_free(ptr);
    return TRUE;
}

/************************************************************
 *                WTSFreeMemoryExW (WTSAPI32.@)
 */
BOOL WINAPI WTSFreeMemoryExW(WTS_TYPE_CLASS type, void *ptr, ULONG nmemb)
{
    TRACE("%d %p %d\n", type, ptr, nmemb);
    heap_free(ptr);
    return TRUE;
}


/************************************************************
 *                WTSLogoffSession (WTSAPI32.@)
 */
BOOL WINAPI WTSLogoffSession(HANDLE hserver, DWORD session_id, BOOL bwait)
{
    FIXME("(%p, 0x%x, %d): stub\n", hserver, session_id, bwait);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}


/************************************************************
 *                WTSOpenServerExW (WTSAPI32.@)
 */
HANDLE WINAPI WTSOpenServerExW(WCHAR *server_name)
{
    FIXME("(%s) stub\n", debugstr_w(server_name));
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return NULL;
}

/************************************************************
 *                WTSOpenServerExA (WTSAPI32.@)
 */
HANDLE WINAPI WTSOpenServerExA(char *server_name)
{
    FIXME("(%s) stub\n", debugstr_a(server_name));
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return NULL;
}

/************************************************************
 *                WTSOpenServerA (WTSAPI32.@)
 */
HANDLE WINAPI WTSOpenServerA(LPSTR pServerName)
{
    FIXME("(%s) stub\n", debugstr_a(pServerName));
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return NULL;
}

/************************************************************
 *                WTSOpenServerW (WTSAPI32.@)
 */
HANDLE WINAPI WTSOpenServerW(LPWSTR pServerName)
{
    FIXME("(%s) stub\n", debugstr_w(pServerName));
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return NULL;
}

/************************************************************
 *                WTSQuerySessionInformationA  (WTSAPI32.@)
 */
BOOL WINAPI WTSQuerySessionInformationA(
    HANDLE hServer,
    DWORD SessionId,
    WTS_INFO_CLASS WTSInfoClass,
    LPSTR* Buffer,
    DWORD* BytesReturned)
{
#ifdef __REACTOS__
    const size_t wcsErrorCode = -1;
    LPWSTR buffer = NULL;
    LPSTR ansiBuffer = NULL;
    DWORD bytesReturned = 0;
    BOOL result = FALSE;
    size_t len;

    if (!BytesReturned || !Buffer)
    {
        SetLastError(ERROR_INVALID_USER_BUFFER);
        return FALSE;
    }

    if (!WTSQuerySessionInformationW(hServer, SessionId, WTSInfoClass, &buffer, &bytesReturned))
    {
        ansiBuffer = (LPSTR)buffer;
        *Buffer = ansiBuffer;
        *BytesReturned = bytesReturned;
        return FALSE;
    }

    switch (WTSInfoClass)
    {
        case WTSInitialProgram:
        case WTSApplicationName:
        case WTSWorkingDirectory:
        case WTSOEMId:
        case WTSUserName:
        case WTSWinStationName:
        case WTSDomainName:
        case WTSClientName:
        case WTSClientDirectory:
        {
            len = wcstombs(NULL, buffer, 0);
            if (len != wcsErrorCode)
            {
                len++;
                ansiBuffer = heap_alloc_zero(len);
                if (ansiBuffer && (wcstombs(ansiBuffer, buffer, len) != wcsErrorCode))
                {
                    result = TRUE;
                    bytesReturned = len;
                }
            }
            WTSFreeMemory(buffer);
            break;
        }

        default:
        {
            result = TRUE;
            ansiBuffer = (LPSTR)buffer;
            break;
        }
    }

    *Buffer = ansiBuffer;
    *BytesReturned = bytesReturned;

    return result;
#else
    /* FIXME: Forward request to winsta.dll::WinStationQueryInformationA */
    FIXME("Stub %p 0x%08x %d %p %p\n", hServer, SessionId, WTSInfoClass,
        Buffer, BytesReturned);

    return FALSE;
#endif
}

/************************************************************
 *                WTSQuerySessionInformationW  (WTSAPI32.@)
 */
BOOL WINAPI WTSQuerySessionInformationW(
    HANDLE hServer,
    DWORD SessionId,
    WTS_INFO_CLASS WTSInfoClass,
    LPWSTR* Buffer,
    DWORD* BytesReturned)
{
#ifdef __REACTOS__
    if (!BytesReturned || !Buffer)
    {
        SetLastError(ERROR_INVALID_USER_BUFFER);
        return FALSE;
    }

#if (NTDDI_VERSION >= NTDDI_WS08)
    if (WTSInfoClass > WTSIsRemoteSession)
#else
    if (WTSInfoClass > WTSClientProtocolType)
#endif
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    switch (WTSInfoClass)
    {
        case WTSSessionId:
        {
            const DWORD size = sizeof(ULONG);
            ULONG* output = heap_alloc_zero(size);
            if (!output)
            {
                SetLastError(ERROR_NOT_ENOUGH_MEMORY);
                return FALSE;
            }

            *output = NtCurrentTeb()->Peb->SessionId;
            *Buffer = (LPWSTR)output;
            *BytesReturned = size;
            return TRUE;
        }

        case WTSUserName:
        {
            WCHAR* username;
            DWORD count = 0;

            GetUserNameW(NULL, &count);
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
                return FALSE;
            username = heap_alloc(count * sizeof(WCHAR));
            if (!username)
            {
                SetLastError(ERROR_NOT_ENOUGH_MEMORY);
                return FALSE;
            }

            GetUserNameW(username, &count);
            *Buffer = username;
            *BytesReturned = count * sizeof(WCHAR);
            return TRUE;
        }

        case WTSConnectState:
        {
            const DWORD size = sizeof(DWORD);
            WCHAR* output = heap_alloc_zero(size);
            if (!output)
            {
                SetLastError(ERROR_NOT_ENOUGH_MEMORY);
                return FALSE;
            }

            *Buffer = output;
            *BytesReturned = size;
            return TRUE;
        }

        case WTSClientProtocolType:
        {
            const DWORD size = sizeof(WORD);
            WCHAR* output = heap_alloc_zero(size);
            if (!output)
            {
                SetLastError(ERROR_NOT_ENOUGH_MEMORY);
                return FALSE;
            }

            *Buffer = output;
            *BytesReturned = size;
            return TRUE;
        }

#if (NTDDI_VERSION >= NTDDI_WS08)
        case WTSIdleTime:
        case WTSLogonTime:
        case WTSIncomingBytes:
        case WTSOutgoingBytes:
        case WTSIncomingFrames:
        case WTSOutgoingFrames:
        {
            SetLastError(ERROR_NOT_SUPPORTED);
            return FALSE;
        }
#endif /* (NTDDI_VERSION >= NTDDI_WS08) */

        default:
        {
            if (BytesReturned)
                *BytesReturned = 0;

            break;
        }
    }

    /* FIXME: Forward request to winsta.dll::WinStationQueryInformationW */
    FIXME("Stub %p 0x%08x %d %p %p\n", hServer, SessionId, WTSInfoClass,
        Buffer, BytesReturned);

    return FALSE;
#else
    /* FIXME: Forward request to winsta.dll::WinStationQueryInformationW */
    FIXME("Stub %p 0x%08x %d %p %p\n", hServer, SessionId, WTSInfoClass,
        Buffer, BytesReturned);

    if (WTSInfoClass == WTSUserName)
    {
        WCHAR *username;
        DWORD count = 0;

        GetUserNameW(NULL, &count);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return FALSE;
        if (!(username = heap_alloc(count * sizeof(WCHAR)))) return FALSE;
        GetUserNameW(username, &count);
        *Buffer = username;
        *BytesReturned = count * sizeof(WCHAR);
        return TRUE;
    }
    return FALSE;
#endif
}

/************************************************************
 *                WTSQueryUserToken (WTSAPI32.@)
 */
/* The caller holds SeTcbPrivilege, enabled (documented: LocalSystem with SE_TCB_NAME) */
static BOOL caller_has_tcb(void)
{
    PRIVILEGE_SET set;
    HANDLE token;
    BOOL ok = FALSE, has = FALSE;

    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token))
    {
        if (GetLastError() != ERROR_NO_TOKEN) return FALSE;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return FALSE;
    }
    set.PrivilegeCount = 1;
    set.Control = PRIVILEGE_SET_ALL_NECESSARY;
    set.Privilege[0].Attributes = 0;
    if (LookupPrivilegeValueW(NULL, L"SeTcbPrivilege", &set.Privilege[0].Luid))
        ok = PrivilegeCheck(token, &set, &has);
    CloseHandle(token);
    return ok && has;
}

/*
 * Whether a process token is the token of an interactive user: not a service account, not restricted,
 * with the INTERACTIVE group enabled and a logon SID.
 */
static BOOL is_interactive_user_token(HANDLE token)
{
    static const SID_IDENTIFIER_AUTHORITY nt = { SECURITY_NT_AUTHORITY };
    BYTE user_buf[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    TOKEN_USER *user = (TOKEN_USER *)user_buf;
    TOKEN_GROUPS *groups = NULL;
    PSID interactive = NULL;
    BOOL interactive_found = FALSE, logon_found = FALSE;
    DWORD len, i, rid;

    if (!GetTokenInformation(token, TokenUser, user, sizeof(user_buf), &len)) return FALSE;
    if (*GetSidSubAuthorityCount(user->User.Sid) == 1 &&
        !memcmp(GetSidIdentifierAuthority(user->User.Sid), &nt, sizeof(nt)))
    {
        rid = *GetSidSubAuthority(user->User.Sid, 0);
        if (rid == SECURITY_LOCAL_SYSTEM_RID || rid == SECURITY_LOCAL_SERVICE_RID ||
            rid == SECURITY_NETWORK_SERVICE_RID)
            return FALSE;
    }
    /* a restricted token (restricting SIDs) is not the user's logon token */
    {
        BYTE rbuf[sizeof(TOKEN_GROUPS)];
        TOKEN_GROUPS *restricted = (TOKEN_GROUPS *)rbuf;

        /* a buffer too small for one SID fails when there are restricting SIDs; any failure: not this one */
        if (!GetTokenInformation(token, TokenRestrictedSids, restricted, sizeof(rbuf), &len) ||
            restricted->GroupCount)
            return FALSE;
    }

    GetTokenInformation(token, TokenGroups, NULL, 0, &len);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || !(groups = heap_alloc(len))) return FALSE;
    if (GetTokenInformation(token, TokenGroups, groups, len, &len) &&
        AllocateAndInitializeSid((PSID_IDENTIFIER_AUTHORITY)&nt, 1, SECURITY_INTERACTIVE_RID, 0, 0, 0, 0, 0, 0, 0,
                                 &interactive))
    {
        for (i = 0; i < groups->GroupCount; i++)
        {
            if (!(groups->Groups[i].Attributes & SE_GROUP_ENABLED)) continue;
            if (EqualSid(groups->Groups[i].Sid, interactive)) interactive_found = TRUE;
            if ((groups->Groups[i].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID) logon_found = TRUE;
        }
        FreeSid(interactive);
    }
    heap_free(groups);
    return interactive_found && logon_found;
}

/*
 * The primary token of the user logged on in a session, for a LocalSystem caller holding SeTcbPrivilege
 * (documented contract of WTSQueryUserToken). The user's token is taken from the first process the logon
 * started in the session (the oldest interactive-user process there: userinit or the shell); a program
 * that the user starts later as another account (runas) is younger and is never chosen.
 * Errors: ERROR_INVALID_PARAMETER (no output), ERROR_PRIVILEGE_NOT_HELD, ERROR_NO_TOKEN (no user logged on
 * in the session, or no such session).
 */
BOOL WINAPI WTSQueryUserToken(ULONG session_id, PHANDLE token)
{
    SYSTEM_PROCESS_INFORMATION *spi;
    ULONG size = 0x4000;
    void *buf = NULL;
    NTSTATUS status;
    HANDLE best = NULL;
    LARGE_INTEGER best_time;

    if (!token)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    *token = NULL;

    if (!caller_has_tcb())
    {
        SetLastError(ERROR_PRIVILEGE_NOT_HELD);
        return FALSE;
    }

    do
    {
        size *= 2;
        heap_free(buf);
        buf = heap_alloc(size);
        if (!buf)
        {
            SetLastError(ERROR_OUTOFMEMORY);
            return FALSE;
        }
        status = NtQuerySystemInformation(SystemProcessInformation, buf, size, NULL);
    }
    while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (status != STATUS_SUCCESS)
    {
        heap_free(buf);
        SetLastError(RtlNtStatusToDosError(status));
        return FALSE;
    }

    best_time.QuadPart = MAXLONGLONG;
    for (spi = buf; ; spi = (SYSTEM_PROCESS_INFORMATION *)(((PCHAR)spi) + spi->NextEntryOffset))
    {
        if (spi->SessionId == session_id && spi->UniqueProcessId &&
            spi->CreationTime.QuadPart < best_time.QuadPart)
        {
            HANDLE process, process_token;

            process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, HandleToUlong(spi->UniqueProcessId));
            if (process)
            {
                if (OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, &process_token))
                {
                    if (is_interactive_user_token(process_token))
                    {
                        if (best) CloseHandle(best);
                        best = process_token;
                        best_time = spi->CreationTime;
                    }
                    else
                        CloseHandle(process_token);
                }
                CloseHandle(process);
            }
        }
        if (spi->NextEntryOffset == 0) break;
    }
    heap_free(buf);

    if (!best)
    {
        SetLastError(ERROR_NO_TOKEN);
        return FALSE;
    }

    if (!DuplicateTokenEx(best, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, token))
    {
        CloseHandle(best);
        return FALSE;
    }
    CloseHandle(best);
    return TRUE;
}

/************************************************************
 *                WTSQueryUserConfigA (WTSAPI32.@)
 */
BOOL WINAPI WTSQueryUserConfigA(LPSTR pServerName, LPSTR pUserName, WTS_CONFIG_CLASS WTSConfigClass, LPSTR *ppBuffer, DWORD *pBytesReturned)
{
   FIXME("Stub (%s) (%s) 0x%08x %p %p\n", debugstr_a(pServerName), debugstr_a(pUserName), WTSConfigClass,
        ppBuffer, pBytesReturned);
   return FALSE;
}

/************************************************************
 *                WTSQueryUserConfigW (WTSAPI32.@)
 */
BOOL WINAPI WTSQueryUserConfigW(LPWSTR pServerName, LPWSTR pUserName, WTS_CONFIG_CLASS WTSConfigClass, LPWSTR *ppBuffer, DWORD *pBytesReturned)
{
   FIXME("Stub (%s) (%s) 0x%08x %p %p\n", debugstr_w(pServerName), debugstr_w(pUserName), WTSConfigClass,
        ppBuffer, pBytesReturned);
   return FALSE;
}


/************************************************************
 *                WTSRegisterSessionNotification (WTSAPI32.@)
 */
BOOL WINAPI WTSRegisterSessionNotification(HWND hWnd, DWORD dwFlags)
{
    FIXME("Stub %p 0x%08x\n", hWnd, dwFlags);
    return TRUE;
}

/************************************************************
 *                WTSRegisterSessionNotificationEx (WTSAPI32.@)
 */
BOOL WINAPI WTSRegisterSessionNotificationEx(HANDLE hServer, HWND hWnd, DWORD dwFlags)
{
    FIXME("Stub %p %p 0x%08x\n", hServer, hWnd, dwFlags);
    return FALSE;
}


/************************************************************
 *                WTSSendMessageA (WTSAPI32.@)
 */
BOOL WINAPI WTSSendMessageA(HANDLE hServer, DWORD SessionId, LPSTR pTitle, DWORD TitleLength, LPSTR pMessage,
   DWORD MessageLength, DWORD Style, DWORD Timeout, DWORD *pResponse, BOOL bWait)
{
   FIXME("Stub %p 0x%08x (%s) %d (%s) %d 0x%08x %d %p %d\n", hServer, SessionId, debugstr_a(pTitle), TitleLength, debugstr_a(pMessage), MessageLength, Style, Timeout, pResponse, bWait);
   return FALSE;
}

/************************************************************
 *                WTSSendMessageW (WTSAPI32.@)
 */
BOOL WINAPI WTSSendMessageW(HANDLE hServer, DWORD SessionId, LPWSTR pTitle, DWORD TitleLength, LPWSTR pMessage,
   DWORD MessageLength, DWORD Style, DWORD Timeout, DWORD *pResponse, BOOL bWait)
{
   FIXME("Stub %p 0x%08x (%s) %d (%s) %d 0x%08x %d %p %d\n", hServer, SessionId, debugstr_w(pTitle), TitleLength, debugstr_w(pMessage), MessageLength, Style, Timeout, pResponse, bWait);
   return FALSE;
}

/************************************************************
 *                WTSSetUserConfigA (WTSAPI32.@)
 */
BOOL WINAPI WTSSetUserConfigA(LPSTR pServerName, LPSTR pUserName, WTS_CONFIG_CLASS WTSConfigClass, LPSTR pBuffer, DWORD DataLength)
{
   FIXME("Stub (%s) (%s) 0x%08x %p %d\n", debugstr_a(pServerName), debugstr_a(pUserName), WTSConfigClass,pBuffer, DataLength);
   return FALSE;
}

/************************************************************
 *                WTSSetUserConfigW (WTSAPI32.@)
 */
BOOL WINAPI WTSSetUserConfigW(LPWSTR pServerName, LPWSTR pUserName, WTS_CONFIG_CLASS WTSConfigClass, LPWSTR pBuffer, DWORD DataLength)
{
   FIXME("Stub (%s) (%s) 0x%08x %p %d\n", debugstr_w(pServerName), debugstr_w(pUserName), WTSConfigClass,pBuffer, DataLength);
   return FALSE;
}

/************************************************************
 *                WTSShutdownSystem (WTSAPI32.@)
 */
BOOL WINAPI WTSShutdownSystem(HANDLE hServer, DWORD ShutdownFlag)
{
   FIXME("Stub %p 0x%08x\n", hServer,ShutdownFlag);
   return FALSE;
}

/************************************************************
 *                WTSStartRemoteControlSessionA (WTSAPI32.@)
 */
BOOL WINAPI WTSStartRemoteControlSessionA(LPSTR pTargetServerName, ULONG TargetLogonId, BYTE HotkeyVk, USHORT HotkeyModifiers)
{
   FIXME("Stub (%s) %d %d %d\n", debugstr_a(pTargetServerName), TargetLogonId, HotkeyVk, HotkeyModifiers);
   return FALSE;
}

/************************************************************
 *                WTSStartRemoteControlSessionW (WTSAPI32.@)
 */
BOOL WINAPI WTSStartRemoteControlSessionW(LPWSTR pTargetServerName, ULONG TargetLogonId, BYTE HotkeyVk, USHORT HotkeyModifiers)
{
   FIXME("Stub (%s) %d %d %d\n", debugstr_w(pTargetServerName), TargetLogonId, HotkeyVk, HotkeyModifiers);
   return FALSE;
}

/************************************************************
 *                WTSStopRemoteControlSession (WTSAPI32.@)
 */
BOOL WINAPI WTSStopRemoteControlSession(ULONG LogonId)
{
   FIXME("Stub %d\n",  LogonId);
   return FALSE;
}

/************************************************************
 *                WTSTerminateProcess (WTSAPI32.@)
 */
BOOL WINAPI WTSTerminateProcess(HANDLE hServer, DWORD ProcessId, DWORD ExitCode)
{
   FIXME("Stub %p %d %d\n", hServer, ProcessId, ExitCode);
   return FALSE;
}

/************************************************************
 *                WTSUnRegisterSessionNotification (WTSAPI32.@)
 */
BOOL WINAPI WTSUnRegisterSessionNotification(HWND hWnd)
{
    FIXME("Stub %p\n", hWnd);
    return FALSE;
}

/************************************************************
 *                WTSUnRegisterSessionNotification (WTSAPI32.@)
 */
BOOL WINAPI WTSUnRegisterSessionNotificationEx(HANDLE hServer, HWND hWnd)
{
    FIXME("Stub %p %p\n", hServer, hWnd);
    return FALSE;
}


/************************************************************
 *                WTSVirtualChannelClose (WTSAPI32.@)
 */
BOOL WINAPI WTSVirtualChannelClose(HANDLE hChannelHandle)
{
   FIXME("Stub %p\n", hChannelHandle);
   return FALSE;
}

/************************************************************
 *                WTSVirtualChannelOpen (WTSAPI32.@)
 */
HANDLE WINAPI WTSVirtualChannelOpen(HANDLE hServer, DWORD SessionId, LPSTR pVirtualName)
{
   FIXME("Stub %p %d (%s)\n", hServer, SessionId, debugstr_a(pVirtualName));
   return NULL;
}

/************************************************************
 *                WTSVirtualChannelOpen (WTSAPI32.@)
 */
HANDLE WINAPI WTSVirtualChannelOpenEx(DWORD SessionId, LPSTR pVirtualName, DWORD flags)
{
   FIXME("Stub %d (%s) %d\n",  SessionId, debugstr_a(pVirtualName), flags);
   return NULL;
}

/************************************************************
 *                WTSVirtualChannelPurgeInput (WTSAPI32.@)
 */
BOOL WINAPI WTSVirtualChannelPurgeInput(HANDLE hChannelHandle)
{
   FIXME("Stub %p\n", hChannelHandle);
   return FALSE;
}

/************************************************************
 *                WTSVirtualChannelPurgeOutput (WTSAPI32.@)
 */
BOOL WINAPI WTSVirtualChannelPurgeOutput(HANDLE hChannelHandle)
{
   FIXME("Stub %p\n", hChannelHandle);
   return FALSE;
}


/************************************************************
 *                WTSVirtualChannelQuery (WTSAPI32.@)
 */
BOOL WINAPI WTSVirtualChannelQuery(HANDLE hChannelHandle, WTS_VIRTUAL_CLASS WtsVirtualClass, PVOID *ppBuffer, DWORD *pBytesReturned)
{
   FIXME("Stub %p %d %p %p\n", hChannelHandle, WtsVirtualClass, ppBuffer, pBytesReturned);
   return FALSE;
}

/************************************************************
 *                WTSVirtualChannelRead (WTSAPI32.@)
 */
BOOL WINAPI WTSVirtualChannelRead(HANDLE hChannelHandle, ULONG TimeOut, PCHAR Buffer, ULONG BufferSize, PULONG pBytesRead)
{
   FIXME("Stub %p %d %p %d %p\n", hChannelHandle, TimeOut, Buffer, BufferSize, pBytesRead);
   return FALSE;
}

/************************************************************
 *                WTSVirtualChannelWrite (WTSAPI32.@)
 */
BOOL WINAPI WTSVirtualChannelWrite(HANDLE hChannelHandle, PCHAR Buffer, ULONG Length, PULONG pBytesWritten)
{
   FIXME("Stub %p %p %d %p\n", hChannelHandle, Buffer, Length, pBytesWritten);
   return FALSE;
}

/************************************************************
 *                WTSWaitSystemEvent (WTSAPI32.@)
 */
BOOL WINAPI WTSWaitSystemEvent(HANDLE hServer, DWORD Mask, DWORD* Flags)
{
    /* FIXME: Forward request to winsta.dll::WinStationWaitSystemEvent */
    FIXME("Stub %p 0x%08x %p\n", hServer, Mask, Flags);
    return FALSE;
}
