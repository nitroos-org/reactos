/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The WTS APIs report the real sessions
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <winbase.h>
#include <wtsapi32.h>

/*
 * Rows recorded on Windows 10 22H2 (design probe of the session work): session 0 is listed as
 * "Services", state WTSDisconnected; the console session as "Console", state WTSActive; every
 * process reports the session ProcessIdToSessionId gives it. WTSQueryUserToken needs
 * SeTcbPrivilege (documented): without it the call fails and returns no token.
 */

static
BOOL
HasTcb(VOID)
{
    HANDLE Token;
    LUID Tcb;
    PRIVILEGE_SET Set;
    BOOL Result = FALSE;

    if (!LookupPrivilegeValueW(NULL, L"SeTcbPrivilege", &Tcb) ||
        !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token))
        return FALSE;

    Set.PrivilegeCount = 1;
    Set.Control = PRIVILEGE_SET_ALL_NECESSARY;
    Set.Privilege[0].Luid = Tcb;
    Set.Privilege[0].Attributes = 0;
    if (!PrivilegeCheck(Token, &Set, &Result))
        Result = FALSE;
    CloseHandle(Token);
    return Result;
}

START_TEST(WtsSessions)
{
    DWORD Own, Console, Count, i, Found0 = 0, FoundOwn = 0, FoundConsole = 0, Seen = 0, Mismatch = 0;
    PWTS_SESSION_INFOW Sessions = NULL;
    PWTS_PROCESS_INFOW Processes = NULL;
    LPWSTR Buffer = NULL;
    DWORD Bytes;
    HANDLE Token;
    BOOL Ret;

    ok(ProcessIdToSessionId(GetCurrentProcessId(), &Own), "ProcessIdToSessionId failed\n");

    /* The caller's session as the query reports it */
    Ret = WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSSessionId, &Buffer, &Bytes);
    ok(Ret, "WTSQuerySessionInformationW(WTSSessionId) failed %lu\n", GetLastError());
    if (Ret)
    {
        ok(Bytes == sizeof(DWORD), "bytes %lu\n", Bytes);
        ok(*(DWORD *)Buffer == Own, "session id %lu, process is in %lu\n", *(DWORD *)Buffer, Own);
        WTSFreeMemory(Buffer);
    }

    /* The session list */
    Console = WTSGetActiveConsoleSessionId();
    Ret = WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &Sessions, &Count);
    ok(Ret, "WTSEnumerateSessionsW failed %lu\n", GetLastError());
    if (Ret)
    {
        ok(Count != 0, "no session listed\n");
        for (i = 0; i < Count; i++)
        {
            if (Sessions[i].SessionId == 0)
            {
                Found0++;
                ok(Sessions[i].State == WTSDisconnected, "session 0 state %d\n", Sessions[i].State);
                ok(!lstrcmpW(Sessions[i].pWinStationName, L"Services"), "session 0 name %ls\n", Sessions[i].pWinStationName);
            }
            if (Sessions[i].SessionId == Own)
                FoundOwn++;
            if (Console != 0xFFFFFFFF && Sessions[i].SessionId == Console)
            {
                FoundConsole++;
                if (Console != 0)
                {
                    ok(Sessions[i].State == WTSActive, "console session state %d\n", Sessions[i].State);
                    ok(!lstrcmpW(Sessions[i].pWinStationName, L"Console"), "console name %ls\n", Sessions[i].pWinStationName);
                }
            }
        }
        ok(Found0 == 1, "session 0 listed %lu times\n", Found0);
        ok(FoundOwn == 1, "own session %lu listed %lu times\n", Own, FoundOwn);
        if (Console != 0xFFFFFFFF)
            ok(FoundConsole == 1, "console session %lu listed %lu times\n", Console, FoundConsole);
        WTSFreeMemory(Sessions);
    }

    /* Every process reports the session ProcessIdToSessionId gives it */
    Ret = WTSEnumerateProcessesW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &Processes, &Count);
    ok(Ret, "WTSEnumerateProcessesW failed %lu\n", GetLastError());
    if (Ret)
    {
        for (i = 0; i < Count; i++)
        {
            DWORD Session;

            if (Processes[i].ProcessId == GetCurrentProcessId())
            {
                Seen++;
                ok(Processes[i].SessionId == Own, "own process listed in session %lu, not %lu\n",
                   Processes[i].SessionId, Own);
            }
            if (Processes[i].ProcessId != 0 &&
                ProcessIdToSessionId(Processes[i].ProcessId, &Session) &&
                Session != Processes[i].SessionId)
            {
                Mismatch++;
            }
        }
        ok(Seen == 1, "own process listed %lu times\n", Seen);
        ok(Mismatch == 0, "%lu processes listed in another session than ProcessIdToSessionId gives\n", Mismatch);
        WTSFreeMemory(Processes);
    }

    /* The user's token: only with SeTcbPrivilege; a failure returns no token */
    Token = (HANDLE)(ULONG_PTR)0x1234;
    SetLastError(0xdeadbeef);
    Ret = WTSQueryUserToken(Console, &Token);
    if (Ret)
    {
        ok(HasTcb(), "WTSQueryUserToken succeeded without SeTcbPrivilege\n");
        ok(Token != NULL, "no token\n");
        CloseHandle(Token);
    }
    else
    {
        DWORD Error = GetLastError();

        ok(Token == NULL, "failure left token %p\n", Token);
        if (HasTcb())
            ok(Error == ERROR_NO_TOKEN, "error %lu with SeTcbPrivilege\n", Error);
        else
            ok(Error == ERROR_PRIVILEGE_NOT_HELD, "error %lu without SeTcbPrivilege\n", Error);
    }
}
