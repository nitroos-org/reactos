/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test ExitWindowsEx when the caller does not hold SeShutdownPrivilege
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/*
 * A shutdown, reboot or power-off request needs SeShutdownPrivilege; the call fails with
 * ERROR_PRIVILEGE_NOT_HELD without it. Measured on Windows 10 22H2, a 32-bit and a 64-bit
 * process alike: EWX_REBOOT, EWX_SHUTDOWN, EWX_POWEROFF and EWX_REBOOT | EWX_FORCE all return
 * FALSE with error 1314. A 32-bit process under WoW64 on ReactOS used to get
 * ERROR_NOT_SUPPORTED (50): the request was not passed to the server.
 *
 * The privilege is removed from an impersonation token of the test thread, and the calls are
 * made only when it is verified absent, so none of them can shut the system down. A logoff
 * needs no privilege and is not requested.
 */

static
BOOL
HasShutdownPrivilege(
    _In_ HANDLE Token,
    _In_ PLUID Luid,
    _Out_ PBOOL Present)
{
    BYTE Buffer[2048];
    PTOKEN_PRIVILEGES Privileges = (PTOKEN_PRIVILEGES)Buffer;
    DWORD Length, i;

    if (!GetTokenInformation(Token, TokenPrivileges, Buffer, sizeof(Buffer), &Length))
        return FALSE;

    *Present = FALSE;
    for (i = 0; i < Privileges->PrivilegeCount; i++)
    {
        if (Privileges->Privileges[i].Luid.LowPart == Luid->LowPart &&
            Privileges->Privileges[i].Luid.HighPart == Luid->HighPart)
            *Present = TRUE;
    }
    return TRUE;
}

/* Give the thread an impersonation token without SeShutdownPrivilege; FALSE if that cannot be verified */
static
BOOL
ImpersonateWithoutShutdownPrivilege(VOID)
{
    HANDLE ProcessToken, ThreadToken = NULL;
    TOKEN_PRIVILEGES Privileges;
    LUID Luid;
    BOOL Present = TRUE, Ok = FALSE;

    if (!LookupPrivilegeValueW(NULL, L"SeShutdownPrivilege", &Luid) ||
        !OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &ProcessToken))
        return FALSE;

    if (DuplicateTokenEx(ProcessToken, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_IMPERSONATE, NULL,
                         SecurityImpersonation, TokenImpersonation, &ThreadToken))
    {
        Privileges.PrivilegeCount = 1;
        Privileges.Privileges[0].Luid = Luid;
        Privileges.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;
        if (AdjustTokenPrivileges(ThreadToken, FALSE, &Privileges, 0, NULL, NULL) &&
            HasShutdownPrivilege(ThreadToken, &Luid, &Present) && !Present &&
            SetThreadToken(NULL, ThreadToken))
            Ok = TRUE;
        CloseHandle(ThreadToken);
    }
    CloseHandle(ProcessToken);
    return Ok;
}

START_TEST(ExitWindowsEx)
{
    static const struct
    {
        UINT Flags;
        PCSTR Name;
    } Requests[] =
    {
        { EWX_REBOOT,                "EWX_REBOOT" },
        { EWX_SHUTDOWN,              "EWX_SHUTDOWN" },
        { EWX_POWEROFF,              "EWX_POWEROFF" },
        { EWX_REBOOT | EWX_FORCE,    "EWX_REBOOT | EWX_FORCE" },
    };
    ULONG i;
    BOOL Ret;
    DWORD Error;

    if (!ImpersonateWithoutShutdownPrivilege())
    {
        skip("Cannot remove SeShutdownPrivilege from the thread\n");
        return;
    }

    for (i = 0; i < RTL_NUMBER_OF(Requests); i++)
    {
        SetLastError(0xdeadbeef);
        Ret = ExitWindowsEx(Requests[i].Flags, 0);
        Error = GetLastError();
        ok(Ret == FALSE, "ExitWindowsEx(%s) returned %d\n", Requests[i].Name, Ret);
        ok(Error == ERROR_PRIVILEGE_NOT_HELD, "ExitWindowsEx(%s): error %lu, expected %d\n",
           Requests[i].Name, Error, ERROR_PRIVILEGE_NOT_HELD);
        /* Must not have shut anything down: stop at once rather than call it again */
        if (Ret)
            break;
    }

    SetThreadToken(NULL, NULL);
}
