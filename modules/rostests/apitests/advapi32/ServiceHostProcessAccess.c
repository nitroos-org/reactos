/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     An elevated administrator may open every service host (svchost.exe) for the limited query right and
 *              for nothing more; a standard user may open none
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Windows Server 2022 (measured, own throw-away overlay, 2026-11-27): the process descriptor of every service
 * host of LocalService, NetworkService and LocalSystem lists an entry for the Administrators (0x1400 or 0x121411)
 * and, for an elevated administrator whose privileges are disabled, OpenProcess gives PROCESS_QUERY_LIMITED_INFORMATION
 * (and OpenProcessToken(TOKEN_QUERY) through that handle) but not PROCESS_VM_READ and not PROCESS_QUERY_INFORMATION
 * on every svchost.exe. A scratch standard user is refused with ERROR_ACCESS_DENIED for every right.
 */

#include "precomp.h"
#include <tlhelp32.h>
#include <lm.h>

static DWORD Pids[256];
static ULONG PidCount;

static void CollectServiceHosts(void)
{
    HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W Entry;

    PidCount = 0;
    if (Snapshot == INVALID_HANDLE_VALUE)
        return;
    Entry.dwSize = sizeof(Entry);
    if (Process32FirstW(Snapshot, &Entry))
    {
        do
        {
            if (!_wcsicmp(Entry.szExeFile, L"svchost.exe") && PidCount < RTL_NUMBER_OF(Pids))
                Pids[PidCount++] = Entry.th32ProcessID;
        } while (Process32NextW(Snapshot, &Entry));
    }
    CloseHandle(Snapshot);
}

static void DisableAllPrivileges(void)
{
    HANDLE Token;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &Token))
    {
        AdjustTokenPrivileges(Token, TRUE, NULL, 0, NULL, NULL);
        CloseHandle(Token);
    }
}

static void AdministratorRows(void)
{
    ULONG i, Opened = 0;
    TOKEN_ELEVATION Elevation;
    DWORD Length;
    HANDLE Token;
    BOOL Elevated = FALSE;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token))
    {
        Elevated = GetTokenInformation(Token, TokenElevation, &Elevation, sizeof(Elevation), &Length) &&
                   Elevation.TokenIsElevated;
        CloseHandle(Token);
    }
    if (!Elevated)
    {
        skip("not an elevated administrator\n");
        return;
    }

    DisableAllPrivileges();
    CollectServiceHosts();
    ok(PidCount != 0, "no svchost.exe is running\n");
    for (i = 0; i < PidCount; i++)
    {
        HANDLE Process, Query;

        Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pids[i]);
        ok(Process != NULL, "administrator: OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, svchost %lu) failed: %lu\n",
           Pids[i], GetLastError());
        if (Process)
        {
            Opened++;
            Token = NULL;
            ok(OpenProcessToken(Process, TOKEN_QUERY, &Token), "administrator: OpenProcessToken(svchost %lu) failed: %lu\n",
               Pids[i], GetLastError());
            if (Token)
                CloseHandle(Token);
            CloseHandle(Process);
        }

        SetLastError(0xdeadbeef);
        Query = OpenProcess(PROCESS_VM_READ, FALSE, Pids[i]);
        ok(Query == NULL && GetLastError() == ERROR_ACCESS_DENIED,
           "administrator: PROCESS_VM_READ of svchost %lu: %p (%lu), expected ERROR_ACCESS_DENIED\n",
           Pids[i], Query, GetLastError());
        if (Query)
            CloseHandle(Query);

        SetLastError(0xdeadbeef);
        Query = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, Pids[i]);
        ok(Query == NULL && GetLastError() == ERROR_ACCESS_DENIED,
           "administrator: PROCESS_QUERY_INFORMATION of svchost %lu: %p (%lu), expected ERROR_ACCESS_DENIED\n",
           Pids[i], Query, GetLastError());
        if (Query)
            CloseHandle(Query);
    }
    trace("administrator opened %lu of %lu service hosts\n", Opened, PidCount);
}

static void StandardUserRows(void)
{
    static const WCHAR Name[] = L"kbsvcstd";
    WCHAR Password[40];
    USER_INFO_1 Info = { 0 };
    DWORD Error = 0, i;
    HANDLE Token = NULL, Impersonation = NULL;
    LARGE_INTEGER Counter;
    ULONG Seed, Index;

    QueryPerformanceCounter(&Counter);
    Seed = Counter.LowPart ^ GetCurrentProcessId() ^ GetTickCount();
    wcscpy(Password, L"Aa1!");
    for (i = 0; i < 24; i++)
    {
        Seed = Seed * 1103515245 + 12345;
        Password[4 + i] = L"abcdefghijklmnopqrstuvwxyz0123456789"[(Seed >> 16) % 36];
    }
    Password[28] = 0;

    Info.usri1_name = (LPWSTR)Name;
    Info.usri1_password = Password;
    Info.usri1_priv = USER_PRIV_USER;
    Info.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    NetUserDel(NULL, Name);
    if (NetUserAdd(NULL, 1, (LPBYTE)&Info, &Error) != NERR_Success)
    {
        skip("NetUserAdd failed: %lu\n", Error);
        return;
    }
    if (!LogonUserW((LPWSTR)Name, (LPWSTR)L".", Password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &Token))
    {
        skip("LogonUser failed: %lu\n", GetLastError());
    }
    else
    {
        if (DuplicateTokenEx(Token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &Impersonation))
        {
            if (SetThreadToken(NULL, Impersonation))
            {
                static const DWORD Rights[] = { PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_QUERY_INFORMATION,
                                                PROCESS_VM_READ, SYNCHRONIZE };

                for (Index = 0; Index < PidCount; Index++)
                {
                    for (i = 0; i < RTL_NUMBER_OF(Rights); i++)
                    {
                        HANDLE Process;

                        SetLastError(0xdeadbeef);
                        Process = OpenProcess(Rights[i], FALSE, Pids[Index]);
                        ok(Process == NULL && GetLastError() == ERROR_ACCESS_DENIED,
                           "standard user: right 0x%lx of svchost %lu: %p (%lu), expected ERROR_ACCESS_DENIED\n",
                           Rights[i], Pids[Index], Process, GetLastError());
                        if (Process)
                            CloseHandle(Process);
                    }
                }
                RevertToSelf();
            }
            else
                skip("SetThreadToken failed: %lu\n", GetLastError());
            CloseHandle(Impersonation);
        }
        CloseHandle(Token);
    }
    NetUserDel(NULL, Name);
    SecureZeroMemory(Password, sizeof(Password));
}

START_TEST(ServiceHostProcessAccess)
{
    /* The standard user first: the administrator's privileges are disabled for good in AdministratorRows, and
       without SeImpersonatePrivilege enabled a thread that impersonates the logon of another user runs at the
       identification level here (the requests then fail with ERROR_BAD_IMPERSONATION_LEVEL) */
    CollectServiceHosts();
    StandardUserRows();
    AdministratorRows();
}
