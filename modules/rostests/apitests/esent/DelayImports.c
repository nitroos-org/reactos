/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     esent exports that msedge.dll delay-loads: JetDetachDatabase2W, JetGetSystemParameterW
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <windef.h>
#include <winbase.h>

typedef LONG (WINAPI *FN_Detach2W)(ULONG_PTR, PCWSTR, ULONG);
typedef LONG (WINAPI *FN_GetParamW)(ULONG_PTR, ULONG_PTR, ULONG, ULONG_PTR *, PWSTR, ULONG);

START_TEST(DelayImports)
{
    HMODULE hEsent = LoadLibraryW(L"esent.dll");
    FN_Detach2W pDetach2W;
    FN_GetParamW pGetParamW;
    ULONG_PTR Param = 0x1234;
    WCHAR Buffer[16] = L"x";
    LONG Ret;

    ok(hEsent != NULL, "no esent.dll\n");
    if (!hEsent)
        return;
    pDetach2W = (FN_Detach2W)GetProcAddress(hEsent, "JetDetachDatabase2W");
    pGetParamW = (FN_GetParamW)GetProcAddress(hEsent, "JetGetSystemParameterW");
    ok(pDetach2W != NULL, "JetDetachDatabase2W is not exported\n");
    ok(pGetParamW != NULL, "JetGetSystemParameterW is not exported\n");

    /* No engine on ReactOS: a failing JET_err, never a trap. Windows returns real engine values. */
    if (pDetach2W)
    {
        Ret = pDetach2W(0, L"C:\\nonexistent.edb", 0);
        ok(Ret < 0, "JetDetachDatabase2W returned %ld\n", Ret);
    }
    if (pGetParamW)
    {
        Ret = pGetParamW(0, 0, 0, &Param, Buffer, sizeof(Buffer));
        ok(Ret != 0 || Param != 0x1234, "JetGetSystemParameterW reported success and wrote nothing\n");
    }
}
