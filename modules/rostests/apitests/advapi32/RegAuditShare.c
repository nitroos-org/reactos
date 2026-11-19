/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Registry key security audit log (a NitroOS mechanism, no Windows counterpart): one standard
 *              user cannot use the whole per-boot budget of distinct log entries up
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Run by an administrator. A new standard user makes 300 distinct denied opens of HKLM\SECURITY (one access
 * mask each; denied in audit mode as a logged shadow decision and in enforcement for real); at most 128 of
 * them may become log entries, the rest are counted as dropped (AuditStats ShareDropped). The counters are
 * published once a minute.
 */

#include "precomp.h"
#include <lm.h>

#define DENIALS     300
#define USER_SHARE  128

static WCHAR TestPassword[] = L"AuditShare-Test-2026!";

static BOOL GetStat(PCWSTR Name, DWORD *Value)
{
    HKEY Key;
    DWORD Size = sizeof(*Value), Type;
    LONG Error;

    *Value = 0;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\RegAcl\\AuditStats",
                      0, KEY_QUERY_VALUE, &Key) != ERROR_SUCCESS)
        return FALSE;
    Error = RegQueryValueExW(Key, Name, NULL, &Type, (BYTE *)Value, &Size);
    RegCloseKey(Key);
    return Error == ERROR_SUCCESS && Type == REG_DWORD;
}

/* The child, as the standard user: the denied opens */
static DWORD Child(VOID)
{
    static const ACCESS_MASK Bits[] =
    {
        KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_CREATE_SUB_KEY, KEY_ENUMERATE_SUB_KEYS, KEY_NOTIFY,
        KEY_CREATE_LINK, DELETE, READ_CONTROL, WRITE_DAC, WRITE_OWNER
    };
    DWORD i, b, Granted = 0;
    ACCESS_MASK Access;
    HKEY Key;

    for (i = 1; i <= DENIALS; i++)
    {
        Access = 0;
        for (b = 0; b < RTL_NUMBER_OF(Bits); b++)
        {
            if (i & (1 << b))
                Access |= Bits[b];
        }
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SECURITY", 0, Access, &Key) == ERROR_SUCCESS)
        {
            Granted++;
            RegCloseKey(Key);
        }
    }
    return Granted;
}

START_TEST(RegAuditShare)
{
    WCHAR User[32], Exe[MAX_PATH], Command[MAX_PATH + 64];
    USER_INFO_1 Info;
    NET_API_STATUS Status;
    DWORD Err, Mode, Dropped0, Dropped1, Entries0, Entries1, Exit = MAXDWORD, i;
    STARTUPINFOW Si = { sizeof(Si) };
    PROCESS_INFORMATION Pi;
    int argc;
    char **argv;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 3 && !strcmp(argv[2], "child"))
        ExitProcess(Child());

    if (!GetStat(L"Mode", &Mode) || Mode == 0 || !GetStat(L"ShareDropped", &Dropped0))
    {
        skip("registry access control audit not running (or no ShareDropped)\n");
        return;
    }

    StringCchPrintfW(User, RTL_NUMBER_OF(User), L"rshr%lx", GetTickCount() & 0xffffff);
    ZeroMemory(&Info, sizeof(Info));
    Info.usri1_name = User;
    Info.usri1_password = TestPassword;
    Info.usri1_priv = USER_PRIV_USER;
    Info.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    Status = NetUserAdd(NULL, 1, (PBYTE)&Info, &Err);
    if (Status == ERROR_ACCESS_DENIED)
    {
        skip("NetUserAdd needs an administrator\n");
        return;
    }
    ok(Status == NERR_Success, "NetUserAdd failed: %lu\n", Status);
    if (Status != NERR_Success)
        return;

    /* The counters of the last publication (the worker publishes about 10 s after new entries) */
    Sleep(15000);
    GetStat(L"ShareDropped", &Dropped0);
    GetStat(L"Entries", &Entries0);

    GetModuleFileNameW(NULL, Exe, RTL_NUMBER_OF(Exe));
    StringCchPrintfW(Command, RTL_NUMBER_OF(Command), L"\"%ls\" RegAuditShare child", Exe);
    if (CreateProcessWithLogonW(User, L".", TestPassword, 0, NULL, Command, 0, NULL, NULL, &Si, &Pi))
    {
        ok(WaitForSingleObject(Pi.hProcess, 120000) == WAIT_OBJECT_0, "the child did not exit\n");
        GetExitCodeProcess(Pi.hProcess, &Exit);
        CloseHandle(Pi.hProcess);
        CloseHandle(Pi.hThread);
        /* Audit mode grants them (and logs the shadow denial); enforcement refuses them */
        if (Mode == 2)
            ok(Exit == 0, "the standard user was granted %lu of the opens of HKLM\\SECURITY\n", Exit);

        Dropped1 = Dropped0;
        for (i = 0; i < 15 && Dropped1 == Dropped0; i++)
        {
            Sleep(10000);
            GetStat(L"ShareDropped", &Dropped1);
        }
        GetStat(L"Entries", &Entries1);
        ok(Dropped1 - Dropped0 >= DENIALS - USER_SHARE,
           "ShareDropped grew by %lu, expected at least %u\n", Dropped1 - Dropped0, DENIALS - USER_SHARE);
        /* Others may log meanwhile: the user's own entries are at most its share */
        ok(Entries1 - Entries0 <= USER_SHARE + 16,
           "Entries grew by %lu for %u distinct denials of one user\n", Entries1 - Entries0, DENIALS);
    }
    else
    {
        ok(0, "CreateProcessWithLogonW failed: %lu\n", GetLastError());
    }

    Status = NetUserDel(NULL, User);
    ok(Status == NERR_Success, "NetUserDel failed: %lu\n", Status);
}
