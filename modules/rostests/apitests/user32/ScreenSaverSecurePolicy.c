/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1+ (https://spdx.org/licenses/LGPL-2.1+)
 * PURPOSE:     SPI_SETSCREENSAVESECURE while the user policy ScreenSaverIsSecure is set
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Windows Server 2022: with a policy value (REG_DWORD 0 measured, any value) SPI_SETSCREENSAVESECURE fails with
 * ERROR_ACCESS_DISABLED_BY_POLICY (1260); SPI_GETSCREENSAVESECURE is not changed by the policy, it returns the user's
 * setting.
 */

#include "precomp.h"
#include <winreg.h>

#ifndef SPI_GETSCREENSAVESECURE
#define SPI_GETSCREENSAVESECURE 0x0076
#define SPI_SETSCREENSAVESECURE 0x0077
#endif
#ifndef ERROR_ACCESS_DISABLED_BY_POLICY
#define ERROR_ACCESS_DISABLED_BY_POLICY 1260
#endif

static const WCHAR PolicyKey[] = L"Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop";

START_TEST(ScreenSaverSecurePolicy)
{
    HKEY Key;
    DWORD Policy = 0, Error;
    BOOL Old = FALSE, Secure = FALSE, Ret;

    if (!SystemParametersInfoW(SPI_GETSCREENSAVESECURE, 0, &Old, 0))
    {
        skip("SPI_GETSCREENSAVESECURE is not available\n");
        return;
    }

    /* no policy: the setting can be written (and is restored) */
    Ret = SystemParametersInfoW(SPI_SETSCREENSAVESECURE, !Old, NULL, 0);
    if (!Ret && GetLastError() == ERROR_OPERATION_IN_PROGRESS)
    {
        skip("a screen saver is running or the desktop is the Winlogon one\n");
        return;
    }
    ok(Ret, "SPI_SETSCREENSAVESECURE without a policy failed: %lu\n", GetLastError());
    if (Ret)
        SystemParametersInfoW(SPI_SETSCREENSAVESECURE, Old, NULL, 0);

    Error = RegCreateKeyExW(HKEY_CURRENT_USER, PolicyKey, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Key, NULL);
    ok(Error == ERROR_SUCCESS, "cannot create the policy key: %lu\n", Error);
    if (Error != ERROR_SUCCESS)
        return;
    Error = RegSetValueExW(Key, L"ScreenSaverIsSecure", 0, REG_DWORD, (PBYTE)&Policy, sizeof(Policy));
    ok(Error == ERROR_SUCCESS, "cannot set the policy value: %lu\n", Error);

    SetLastError(0xDEADBEEF);
    Ret = SystemParametersInfoW(SPI_SETSCREENSAVESECURE, !Old, NULL, 0);
    Error = GetLastError();
    ok(!Ret, "SPI_SETSCREENSAVESECURE with a policy succeeded\n");
    ok(Error == ERROR_ACCESS_DISABLED_BY_POLICY, "error %lu, expected 1260\n", Error);
    if (Ret)
        SystemParametersInfoW(SPI_SETSCREENSAVESECURE, Old, NULL, 0);

    /* the getter is the user's setting */
    Secure = !Old;
    ok(SystemParametersInfoW(SPI_GETSCREENSAVESECURE, 0, &Secure, 0), "SPI_GETSCREENSAVESECURE failed\n");
    ok(Secure == Old, "SPI_GETSCREENSAVESECURE returned %d with the policy set, the user's setting is %d\n", Secure, Old);

    /* a string value counts too */
    RegDeleteValueW(Key, L"ScreenSaverIsSecure");
    RegSetValueExW(Key, L"ScreenSaverIsSecure", 0, REG_SZ, (PBYTE)L"1", sizeof(L"1"));
    SetLastError(0xDEADBEEF);
    Ret = SystemParametersInfoW(SPI_SETSCREENSAVESECURE, !Old, NULL, 0);
    Error = GetLastError();
    ok(!Ret && Error == ERROR_ACCESS_DISABLED_BY_POLICY, "REG_SZ policy: result %d, error %lu\n", Ret, Error);

    /* removed: writable again */
    RegDeleteValueW(Key, L"ScreenSaverIsSecure");
    RegCloseKey(Key);
    Ret = SystemParametersInfoW(SPI_SETSCREENSAVESECURE, !Old, NULL, 0);
    ok(Ret, "SPI_SETSCREENSAVESECURE after the policy is gone failed: %lu\n", GetLastError());
    if (Ret)
        SystemParametersInfoW(SPI_SETSCREENSAVESECURE, Old, NULL, 0);
}
