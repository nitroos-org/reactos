/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Tests for the power scheme calls of cfgmgr32.dll (CM_Apply_PowerScheme and the like) and
 *              CMP_RegisterServiceNotification
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Windows 10 22H2 (x64 and x86) answers CR_CALL_NOT_IMPLEMENTED to the power scheme calls whatever they are given,
 * and CR_SUCCESS to CMP_RegisterServiceNotification. The numbers of arguments are those of the x86 versions, which
 * clean their stacks by them; the calls here pass that many, so that a wrong count shows as a crash or a stack check.
 */

#include <apitest.h>

#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <cfgmgr32.h>

typedef CONFIGRET (WINAPI *FN0)(void);
typedef CONFIGRET (WINAPI *FN1)(ULONG_PTR);
typedef CONFIGRET (WINAPI *FN2)(ULONG_PTR, ULONG_PTR);
typedef CONFIGRET (WINAPI *FN3)(ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef CONFIGRET (WINAPI *FN4)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef CONFIGRET (WINAPI *FN8)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);

static const struct
{
    PCSTR Name;
    ULONG Args;
    CONFIGRET Expected;
} Calls[] =
{
    { "CM_Apply_PowerScheme", 0, CR_CALL_NOT_IMPLEMENTED },
    { "CM_Delete_PowerScheme", 2, CR_CALL_NOT_IMPLEMENTED },
    { "CM_Duplicate_PowerScheme", 3, CR_CALL_NOT_IMPLEMENTED },
    { "CM_Import_PowerScheme", 3, CR_CALL_NOT_IMPLEMENTED },
    { "CM_RestoreAll_DefaultPowerSchemes", 1, CR_CALL_NOT_IMPLEMENTED },
    { "CM_Restore_DefaultPowerScheme", 2, CR_CALL_NOT_IMPLEMENTED },
    { "CM_Set_ActiveScheme", 2, CR_CALL_NOT_IMPLEMENTED },
    { "CM_Write_UserPowerKey", 8, CR_CALL_NOT_IMPLEMENTED },
    { "CMP_RegisterServiceNotification", 4, CR_SUCCESS },
};

START_TEST(CM_PowerScheme)
{
    HMODULE hCfgMgr = LoadLibraryW(L"cfgmgr32.dll");
    CONFIGRET cr;
    FARPROC p;
    ULONG i, Round;

    if (!hCfgMgr)
    {
        skip("cfgmgr32.dll is not available\n");
        return;
    }

    for (i = 0; i < ARRAYSIZE(Calls); i++)
    {
        p = GetProcAddress(hCfgMgr, Calls[i].Name);
        if (!p)
        {
            ok(!is_reactos(), "%s is not exported by cfgmgr32.dll\n", Calls[i].Name);
            continue;
        }

        /* Twice, with arguments of zero and of garbage */
        for (Round = 0; Round < 2; Round++)
        {
            ULONG_PTR A = Round ? (ULONG_PTR)0x12345678 : 0;

            switch (Calls[i].Args)
            {
                case 0: cr = ((FN0)p)(); break;
                case 1: cr = ((FN1)p)(A); break;
                case 2: cr = ((FN2)p)(A, A); break;
                case 3: cr = ((FN3)p)(A, A, A); break;
                case 4: cr = ((FN4)p)(A, A, A, A); break;
                default: cr = ((FN8)p)(A, A, A, A, A, A, A, A); break;
            }
            ok(cr == Calls[i].Expected, "%s (%lu): 0x%lx, expected 0x%lx\n", Calls[i].Name, Round, cr, Calls[i].Expected);
        }
    }
}
