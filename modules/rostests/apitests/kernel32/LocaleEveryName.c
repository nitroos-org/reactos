/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Every locale name of the kernel32 locale data resolves through LocaleNameToLCID and GetLocaleInfoEx
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 *
 * The names come from the locale resources of kernel32 (the same enumeration that EnumSystemLocalesEx is built on,
 * but without its filter). Windows 10 does not know some of them: GetLocaleInfoEx fails with ERROR_INVALID_PARAMETER
 * for "nl-SR" (a Wine extension, not in MS-LCID), and for the languages whose data was hand written (Esperanto,
 * Asturian, Cornish, Manx, Walloon; the Windows side of this is the MS-LCID list, to be confirmed on the oracle). Those names must fail the same way here, and EnumSystemLocalesEx must not list
 * them (.NET creates a culture for every name that function reports); every other name must resolve to its own
 * LCID and report its own name.
 */

#include "precomp.h"

#include <winnls.h>
#include <winuser.h>

#ifndef LOCALE_ALLOW_NEUTRAL_NAMES
#define LOCALE_ALLOW_NEUTRAL_NAMES 0x08000000
#endif

typedef LCID (WINAPI *PFN_LocaleNameToLCID)(LPCWSTR, DWORD);
typedef int (WINAPI *PFN_GetLocaleInfoEx)(LPCWSTR, LCTYPE, LPWSTR, int);
typedef BOOL (CALLBACK *PFN_ENUMPROCEX)(LPWSTR, DWORD, LPARAM);
typedef BOOL (WINAPI *PFN_EnumSystemLocalesEx)(PFN_ENUMPROCEX, DWORD, LPARAM, LPVOID);

/* Names of the locale data that Windows 10 does not know. The data also has "eo-AA", but it shares the language
 * id of "eo", so the resource enumeration sees one of the two. */
static const PCWSTR NotWindows[] =
{
    L"ast-ES", L"eo", L"gv-IM", L"kw-GB", L"nl-SR", L"wa-BE"
};

static PFN_LocaleNameToLCID pLocaleNameToLCID;
static PFN_GetLocaleInfoEx pGetLocaleInfoEx;
static ULONG g_Names, g_Resolved, g_Unknown;

static BOOL
IsNotWindows(PCWSTR Name)
{
    ULONG i;

    for (i = 0; i < ARRAYSIZE(NotWindows); i++)
        if (!_wcsicmp(Name, NotWindows[i]))
            return TRUE;
    return FALSE;
}

static BOOL CALLBACK
EnumLanguageProc(HMODULE Module, LPCWSTR Type, LPCWSTR Name, WORD Lang, LONG_PTR Param)
{
    WCHAR Buffer[128], ExName[128];
    LCID Lcid = MAKELCID(Lang, SORT_DEFAULT), Resolved;
    int Ret;

    if (PRIMARYLANGID(Lang) == LANG_NEUTRAL)
        return TRUE;
    if (!GetLocaleInfoW(Lcid, LOCALE_SNAME | LOCALE_NOUSEROVERRIDE, Buffer, ARRAYSIZE(Buffer)) || !Buffer[0])
        return TRUE;
    g_Names++;

    if (IsNotWindows(Buffer))
    {
        g_Unknown++;
        SetLastError(0xdeadbeef);
        Resolved = pLocaleNameToLCID(Buffer, LOCALE_ALLOW_NEUTRAL_NAMES);
        ok(Resolved == 0, "%ls: LocaleNameToLCID returned 0x%lx, expected 0 (as on Windows 10)\n", Buffer, Resolved);
        ok(GetLastError() == ERROR_INVALID_PARAMETER, "%ls: LocaleNameToLCID error %lu\n", Buffer, GetLastError());
        SetLastError(0xdeadbeef);
        Ret = pGetLocaleInfoEx(Buffer, LOCALE_SNAME, ExName, ARRAYSIZE(ExName));
        ok(Ret == 0, "%ls: GetLocaleInfoEx returned %d, expected 0\n", Buffer, Ret);
        ok(GetLastError() == ERROR_INVALID_PARAMETER, "%ls: GetLocaleInfoEx error %lu\n", Buffer, GetLastError());
        return TRUE;
    }

    SetLastError(0xdeadbeef);
    Resolved = pLocaleNameToLCID(Buffer, LOCALE_ALLOW_NEUTRAL_NAMES);
    ok(Resolved != 0, "%ls (0x%04x): LocaleNameToLCID failed (error %lu)\n", Buffer, Lang, GetLastError());
    if (Resolved)
    {
        g_Resolved++;
        ok(LANGIDFROMLCID(Resolved) == Lang, "%ls: LocaleNameToLCID returned 0x%lx, expected 0x%04x\n",
           Buffer, Resolved, Lang);
    }

    RtlFillMemory(ExName, sizeof(ExName), 0xcc);
    SetLastError(0xdeadbeef);
    Ret = pGetLocaleInfoEx(Buffer, LOCALE_SNAME, ExName, ARRAYSIZE(ExName));
    ok(Ret == (int)wcslen(Buffer) + 1, "%ls: GetLocaleInfoEx returned %d (error %lu)\n", Buffer, Ret, GetLastError());
    if (Ret > 0)
        ok(!wcscmp(ExName, Buffer), "%ls: GetLocaleInfoEx(LOCALE_SNAME) returned '%ls'\n", Buffer, ExName);
    return TRUE;
}

static BOOL CALLBACK
EnumExProc(LPWSTR Name, DWORD Flags, LPARAM Param)
{
    ok(!IsNotWindows(Name), "EnumSystemLocalesEx lists %ls, which Windows 10 does not know\n", Name);
    /* the invariant locale (empty name) is listed, but has no resource of its own */
    if (Name[0])
        (*(PULONG)Param)++;
    return TRUE;
}

START_TEST(LocaleEveryName)
{
    HMODULE Kernel32 = GetModuleHandleW(L"kernel32.dll");
    PFN_EnumSystemLocalesEx pEnumSystemLocalesEx;
    ULONG Listed = 0;

    pLocaleNameToLCID = (PFN_LocaleNameToLCID)GetProcAddress(Kernel32, "LocaleNameToLCID");
    pGetLocaleInfoEx = (PFN_GetLocaleInfoEx)GetProcAddress(Kernel32, "GetLocaleInfoEx");
    pEnumSystemLocalesEx = (PFN_EnumSystemLocalesEx)GetProcAddress(Kernel32, "EnumSystemLocalesEx");
    if (!pLocaleNameToLCID || !pGetLocaleInfoEx || !pEnumSystemLocalesEx)
    {
        skip("LocaleNameToLCID, GetLocaleInfoEx or EnumSystemLocalesEx not found\n");
        return;
    }

    if (!EnumResourceLanguagesW(Kernel32, (LPCWSTR)RT_STRING, MAKEINTRESOURCEW((LOCALE_SNAME >> 4) + 1),
                                EnumLanguageProc, 0))
    {
        skip("The locale resources of kernel32 cannot be enumerated (error %lu)\n", GetLastError());
        return;
    }

    ok(g_Names > 200, "Only %lu locale names found\n", g_Names);
    ok(g_Unknown == ARRAYSIZE(NotWindows), "%lu of the %u names of the non-Windows list are in the locale data\n",
       g_Unknown, (UINT)ARRAYSIZE(NotWindows));
    ok(g_Resolved == g_Names - g_Unknown, "%lu names resolved, expected %lu\n", g_Resolved, g_Names - g_Unknown);
    trace("%lu locale names, %lu resolved, %lu not known to Windows 10\n", g_Names, g_Resolved, g_Unknown);

    ok(pEnumSystemLocalesEx(EnumExProc, LOCALE_ALL, (LPARAM)&Listed, NULL), "EnumSystemLocalesEx failed\n");
    ok(Listed == g_Resolved, "EnumSystemLocalesEx lists %lu names, expected %lu\n", Listed, g_Resolved);
}
