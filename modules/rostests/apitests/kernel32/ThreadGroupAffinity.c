/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     GetThreadGroupAffinity with a NULL output must fail, not crash
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

static BOOL (WINAPI *pGetThreadGroupAffinity)(HANDLE, PGROUP_AFFINITY);

START_TEST(ThreadGroupAffinity)
{
    GROUP_AFFINITY Affinity;
    BOOL Ret;

    pGetThreadGroupAffinity = (void *)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),
                                                     "GetThreadGroupAffinity");
    if (!pGetThreadGroupAffinity)
    {
        skip("GetThreadGroupAffinity is not exported\n");
        return;
    }

    memset(&Affinity, 0xCC, sizeof(Affinity));
    SetLastError(0xdeadbeef);
    Ret = pGetThreadGroupAffinity(GetCurrentThread(), &Affinity);
    ok(Ret, "GetThreadGroupAffinity failed, error %lu\n", GetLastError());
    ok(Affinity.Group == 0, "Group = %u\n", Affinity.Group);
    ok(Affinity.Mask != 0, "Mask is zero\n");
    ok(Affinity.Reserved[0] == 0 && Affinity.Reserved[1] == 0 && Affinity.Reserved[2] == 0,
       "Reserved is not cleared\n");

    /* VERIFY ON ORACLE: the error for a NULL output; the Wine test expects ERROR_INVALID_PARAMETER
     * (Windows 7/8 may give ERROR_NOACCESS). The crash itself is the regression. */
    SetLastError(0xdeadbeef);
    Ret = pGetThreadGroupAffinity(GetCurrentThread(), NULL);
    ok(!Ret, "GetThreadGroupAffinity with NULL succeeded\n");
    ok(GetLastError() == ERROR_INVALID_PARAMETER || GetLastError() == ERROR_NOACCESS,
       "Unexpected error %lu\n", GetLastError());
}
