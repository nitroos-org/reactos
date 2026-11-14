/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The DACL control flags of the system hive keys are those of Windows 10 22H2
 *              (SE_DACL_PROTECTED and SE_DACL_AUTO_INHERITED, read with READ_CONTROL)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Expected flags were read from Windows 10 22H2 (the 64-bit view: a 32-bit caller asks for it, SOFTWARE is Wow6432Node else). A key the system lacks (service keys, Wow6432Node) is skipped.
 */

#include "precomp.h"

#define PAI (SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED)
#define AI  SE_DACL_AUTO_INHERITED

static const struct
{
    PCWSTR Path;
    WORD Expected;
} s_Keys[] =
{
    { L"SOFTWARE", PAI },
    { L"SOFTWARE\\Microsoft", 0 },
    { L"SOFTWARE\\Microsoft\\Windows", 0 },
    { L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion", PAI },
    { L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", AI },
    { L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", PAI },
    { L"SOFTWARE\\Microsoft\\Windows NT", 0 },
    { L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", PAI },
    { L"SOFTWARE\\Classes", PAI },
    { L"SOFTWARE\\Wow6432Node", AI },
    { L"SYSTEM", PAI },
    { L"SYSTEM\\CurrentControlSet\\Services", AI },
    { L"SYSTEM\\CurrentControlSet\\Services\\Tcpip", PAI },
    { L"SYSTEM\\CurrentControlSet\\Services\\EventLog", PAI },
    { L"SYSTEM\\CurrentControlSet\\Services\\Dnscache", AI },
    { L"SYSTEM\\CurrentControlSet\\Services\\Spooler", AI },
    { L"SYSTEM\\CurrentControlSet\\Control", 0 },
    { L"SYSTEM\\CurrentControlSet\\Control\\Lsa", PAI },
};

START_TEST(RegHiveKeyControl)
{
    BYTE Buffer[4096];
    SIZE_T i;

    for (i = 0; i < _countof(s_Keys); i++)
    {
        HKEY hKey;
        DWORD Length = sizeof(Buffer), Revision;
        WORD Control;
        LONG Error;

        Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, s_Keys[i].Path, 0, KEY_READ | KEY_WOW64_64KEY, &hKey);
        if (Error != ERROR_SUCCESS)
        {
            skip("%ls: not there (error %ld)\n", s_Keys[i].Path, Error);
            continue;
        }
        Error = RegGetKeySecurity(hKey, DACL_SECURITY_INFORMATION, Buffer, &Length);
        ok(Error == ERROR_SUCCESS, "%ls: RegGetKeySecurity error %ld\n", s_Keys[i].Path, Error);
        if (Error == ERROR_SUCCESS)
        {
            ok(GetSecurityDescriptorControl(Buffer, &Control, &Revision), "%ls: no control\n", s_Keys[i].Path);
            ok((Control & PAI) == s_Keys[i].Expected, "%ls: control 0x%04x, expected the P/AI bits 0x%04x\n",
               s_Keys[i].Path, Control, s_Keys[i].Expected);
        }
        RegCloseKey(hKey);
    }
}
