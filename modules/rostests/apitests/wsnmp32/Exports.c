/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     wsnmp32.dll exports its functions under the documented ordinals
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Oracle XE 21c orageneric.dll imports 21 functions of wsnmp32.dll by ordinal. With the library missing,
 * every Oracle DLL that depends on orageneric.dll (oracommon, oraclient, oranl, ... and oranjni, which netca
 * loads) fails to load with "Can not find dependent libraries".
 */

#include <apitest.h>

START_TEST(Exports)
{
    /* the ordinals orageneric.dll imports: Snmp{Set}TranslateMode ... SnmpGetLastError */
    static const WORD Ordinals[] = { 101, 103, 203, 204, 205, 220, 300, 302, 400, 402, 500, 501, 504,
                                     600, 602, 603, 604, 605, 900, 903, 999 };
    HMODULE hMod = LoadLibraryA("wsnmp32.dll");
    DWORD (WINAPI *pSnmpStartup)(DWORD *, DWORD *, DWORD *, DWORD *, DWORD *);
    DWORD (WINAPI *pSnmpCleanup)(void);
    DWORD Major = 0, Minor = 0, Level = 0, Translate = 0, Retransmit = 0;
    DWORD i;

    ok(hMod != NULL, "wsnmp32.dll does not load: %lu\n", GetLastError());
    if (!hMod)
        return;

    for (i = 0; i < ARRAYSIZE(Ordinals); i++)
        ok(GetProcAddress(hMod, (LPCSTR)(ULONG_PTR)Ordinals[i]) != NULL, "ordinal %u is not exported\n", Ordinals[i]);

    pSnmpStartup = (void *)GetProcAddress(hMod, "SnmpStartup");
    pSnmpCleanup = (void *)GetProcAddress(hMod, "SnmpCleanup");
    ok(pSnmpStartup != NULL, "SnmpStartup is not exported\n");
    ok(pSnmpCleanup != NULL, "SnmpCleanup is not exported\n");
    if (pSnmpStartup)
    {
        ok(pSnmpStartup(&Major, &Minor, &Level, &Translate, &Retransmit) == 1 /* SNMPAPI_SUCCESS */, "SnmpStartup failed\n");
        ok(Major == 2 && Minor == 0, "WinSNMP version %lu.%lu\n", Major, Minor);
    }
    if (pSnmpCleanup)
        ok(pSnmpCleanup() == 1, "SnmpCleanup failed\n");
}
