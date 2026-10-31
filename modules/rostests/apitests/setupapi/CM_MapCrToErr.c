/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Tests for CM_MapCrToWin32Err and CM_MapCrToSpErr (cfgmgr32.dll)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The tables were measured on Windows 10 22H2 (x64 and x86) for every code from 0 to 0x3c and a few beyond. A code
 * that has no entry gives the default the caller passes, which is how the entries below are listed.
 */

#include <apitest.h>

#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <winuser.h>
#include <cfgmgr32.h>

typedef DWORD (WINAPI *FN_MAP)(CONFIGRET, DWORD);

static const struct
{
    ULONG Cr;
    DWORD Win32;
    DWORD Setup;
} Mapped[] =
{
    { 0x00, 0, 0 },
    { 0x02, 8, 8 },                         /* CR_OUT_OF_MEMORY */
    { 0x03, 1784, 0x6f8 },                  /* CR_INVALID_POINTER */
    { 0x04, 1004, 0x3ec },                  /* CR_INVALID_FLAG */
    { 0x05, 13, 0xe000020b },               /* CR_INVALID_DEVNODE */
    { 0x0d, 1168, 0xe000020b },             /* CR_NO_SUCH_DEVNODE */
    { 0x10, 183, 0xe0000207 },              /* CR_ALREADY_SUCH_DEVNODE */
    { 0x1a, 122, 0x7a },                    /* CR_BUFFER_SMALL */
    { 0x1c, 6, 6 },                         /* CR_NO_REGISTRY_HANDLE */
    { 0x1d, 1015, 0xe000023a },             /* CR_REGISTRY_ERROR */
    { 0x1e, 13, 0xe0000205 },               /* CR_INVALID_DEVICE_ID */
    { 0x25, 1168, 0x490 },                  /* CR_NO_SUCH_VALUE */
    { 0x28, 0x7777, 0xe0000231 },           /* CR_NOT_DISABLEABLE: no Win32 error */
    { 0x2e, 2, 0xe0000204 },                /* CR_NO_SUCH_REGISTRY_KEY */
    { 0x2f, 13, 0xe0000220 },               /* CR_INVALID_MACHINENAME */
    { 0x30, 1062, 0xe0000221 },             /* CR_REMOTE_COMM_FAILURE */
    { 0x31, 1062, 0xe0000222 },             /* CR_MACHINE_UNAVAILABLE */
    { 0x32, 1062, 0xe0000223 },             /* CR_NO_CM_SERVICES */
    { 0x33, 5, 5 },                         /* CR_ACCESS_DENIED */
    { 0x34, 120, 0x78 },                    /* CR_CALL_NOT_IMPLEMENTED */
    { 0x35, 13, 0xe0000209 },               /* CR_INVALID_PROPERTY */
    { 0x37, 1168, 0xe0000225 },             /* CR_NO_SUCH_DEVICE_INTERFACE */
    { 0x38, 13, 0xe000021f },               /* CR_INVALID_REFERENCE_STRING */
};

START_TEST(CM_MapCrToErr)
{
    HMODULE hCfgMgr = LoadLibraryW(L"cfgmgr32.dll");
    FN_MAP pWin32 = hCfgMgr ? (FN_MAP)GetProcAddress(hCfgMgr, "CM_MapCrToWin32Err") : NULL;
    FN_MAP pSetup = hCfgMgr ? (FN_MAP)GetProcAddress(hCfgMgr, "CM_MapCrToSpErr") : NULL;
    static const ULONG Beyond[] = { 0x3d, 0x40, 0xff, 0x100, 0x1000, 0xffffffff };
    DWORD Result;
    ULONG Cr, i;

    if (!pWin32 || !pSetup)
    {
        ok(!is_reactos(), "CM_MapCrToWin32Err / CM_MapCrToSpErr are not exported by cfgmgr32.dll\n");
        skip("CM_MapCrToWin32Err is not available\n");
        return;
    }

    for (Cr = 0; Cr <= 0x3c; Cr++)
    {
        DWORD ExpectedWin32 = 0x7777, ExpectedSetup = 0x7777;

        for (i = 0; i < ARRAYSIZE(Mapped); i++)
        {
            if (Mapped[i].Cr == Cr)
            {
                ExpectedWin32 = Mapped[i].Win32;
                ExpectedSetup = Mapped[i].Setup;
            }
        }

        Result = pWin32(Cr, 0x7777);
        ok(Result == ExpectedWin32, "CM_MapCrToWin32Err(0x%lx) = %lu, expected %lu\n", Cr, Result, ExpectedWin32);
        Result = pWin32(Cr, 0xdead);
        ok(Result == (ExpectedWin32 == 0x7777 ? 0xdead : ExpectedWin32), "CM_MapCrToWin32Err(0x%lx, 0xdead) = %lu\n", Cr, Result);

        Result = pSetup(Cr, 0x7777);
        ok(Result == ExpectedSetup, "CM_MapCrToSpErr(0x%lx) = 0x%lx, expected 0x%lx\n", Cr, Result, ExpectedSetup);
        Result = pSetup(Cr, 0xdead);
        ok(Result == (ExpectedSetup == 0x7777 ? 0xdead : ExpectedSetup), "CM_MapCrToSpErr(0x%lx, 0xdead) = 0x%lx\n", Cr, Result);
    }

    for (i = 0; i < ARRAYSIZE(Beyond); i++)
    {
        Result = pWin32(Beyond[i], 0x7777);
        ok(Result == 0x7777, "CM_MapCrToWin32Err(0x%lx) = %lu, expected the default\n", Beyond[i], Result);
        Result = pSetup(Beyond[i], 0x7777);
        ok(Result == 0x7777, "CM_MapCrToSpErr(0x%lx) = 0x%lx, expected the default\n", Beyond[i], Result);
    }
}
