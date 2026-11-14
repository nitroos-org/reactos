/*
 * PROJECT:         ReactOS api tests
 * LICENSE:         GPLv2+ - See COPYING in the top level directory
 * PURPOSE:         Test for GetLocaleInfo(Ex)
 * PROGRAMMER:      Timo Kreuzer <timo.kreuzer@reactos.org>
 */

#include "precomp.h"

#ifndef LOCALE_SPARENT
#define LOCALE_SPARENT 0x6d
#endif

typedef
int
WINAPI
FN_GetLocaleInfoEx(
    _In_opt_ LPCWSTR lpLocaleName,
    _In_ LCTYPE  LCType,
    _Out_opt_ LPWSTR lpLCData,
    _In_ int cchData);

FN_GetLocaleInfoEx* pGetLocaleInfoEx = NULL;

static void Test_GetLocaleInfoEx(void)
{
    HMODULE hmodKernel32;
    int Ret;
    ULONG CodePage;

    hmodKernel32 = GetModuleHandleW(L"kernel32.dll");
    pGetLocaleInfoEx = (FN_GetLocaleInfoEx*)GetProcAddress(hmodKernel32, "GetLocaleInfoEx");
    if (pGetLocaleInfoEx == NULL)
    {
        hmodKernel32 = LoadLibraryW(L"kernel32_vista.dll");
        pGetLocaleInfoEx = (FN_GetLocaleInfoEx*)GetProcAddress(hmodKernel32, "GetLocaleInfoEx");
        if (pGetLocaleInfoEx == NULL)
        {
            skip("GetLocaleInfoEx not found in kernel32.dll\n");
            return;
        }
    }

    // Test normal usage
    Ret = pGetLocaleInfoEx(L"en-US",
                           LOCALE_IDEFAULTANSICODEPAGE | LOCALE_RETURN_NUMBER,
                           (WCHAR*)&CodePage,
                           sizeof(DWORD) / sizeof(WCHAR));
    ok_eq_int(Ret, 2);
    ok_eq_long(CodePage, 1252ul);

    // Test with neutral locale
    Ret = pGetLocaleInfoEx(L"en",
                           LOCALE_IDEFAULTANSICODEPAGE | LOCALE_RETURN_NUMBER,
                           NULL,
                           0);
    ok_eq_int(Ret, 2);
    ok_eq_long(CodePage, 1252ul);

    // Test with NULL locale name
    CodePage = 0xdeadbeef;
    Ret = pGetLocaleInfoEx(NULL,
                           LOCALE_IDEFAULTANSICODEPAGE | LOCALE_RETURN_NUMBER,
                           (WCHAR *)&CodePage,
                           sizeof(DWORD) /sizeof(WCHAR));
    ok_eq_int(Ret, 2);
    ok_eq_long(CodePage, 1252ul);

    // Test with empty locale name
    CodePage = 0xdeadbeef;
    Ret = pGetLocaleInfoEx(L"",
                           LOCALE_IDEFAULTANSICODEPAGE | LOCALE_RETURN_NUMBER,
                           (WCHAR *)&CodePage,
                           sizeof(DWORD) /sizeof(WCHAR));
    ok_eq_int(Ret, 2);
    ok_eq_long(CodePage, 1252ul);

    // Test with invalid locale name
    CodePage = 0xdeadbeef;
    Ret = pGetLocaleInfoEx(L"invalid",
                           LOCALE_IDEFAULTANSICODEPAGE | LOCALE_RETURN_NUMBER,
                           (WCHAR *)&CodePage,
                           sizeof(DWORD) /sizeof(WCHAR));
    ok_eq_int(Ret, 0);
    ok_eq_long(GetLastError(), (ULONG)ERROR_INVALID_PARAMETER);
    ok(CodePage == 0xdeadbeef, "CodePage should not have been modified: %lx\n", CodePage);

    // A neutral name keeps its name and its parent, with LOCALE_NOUSEROVERRIDE too (the .NET culture chain)
    {
        static const struct { PCWSTR Locale; LCTYPE Type; PCWSTR Expected; } Names[] =
        {
            { L"en-US", LOCALE_SNAME, L"en-US" },
            { L"en-US", LOCALE_SPARENT, L"en" },
            { L"en-US", LOCALE_SPARENT | LOCALE_NOUSEROVERRIDE, L"en" },
            { L"en", LOCALE_SNAME, L"en" },
            { L"en", LOCALE_SNAME | LOCALE_NOUSEROVERRIDE, L"en" },
            { L"en", LOCALE_SPARENT, L"" },
            { L"en", LOCALE_SPARENT | LOCALE_NOUSEROVERRIDE, L"" },
            { L"de", LOCALE_SPARENT | LOCALE_NOUSEROVERRIDE, L"" },
            { L"", LOCALE_SNAME, L"" },
            { L"", LOCALE_SPARENT, L"" },
            { L"", LOCALE_SPARENT | LOCALE_NOUSEROVERRIDE, L"" },
        };
        WCHAR Buffer[85];
        ULONG i;

        for (i = 0; i < _countof(Names); i++)
        {
            Buffer[0] = L'?';
            Buffer[1] = 0;
            Ret = pGetLocaleInfoEx(Names[i].Locale, Names[i].Type, Buffer, _countof(Buffer));
            ok(Ret == (INT)wcslen(Names[i].Expected) + 1, "%ls 0x%lx: returned %d\n", Names[i].Locale, Names[i].Type, Ret);
            ok(!wcscmp(Buffer, Names[i].Expected), "%ls 0x%lx: got '%ls', expected '%ls'\n",
               Names[i].Locale, Names[i].Type, Buffer, Names[i].Expected);
        }
    }
}

/* Measured on Windows 10 22H2 (19045), x64 and x86 with the same results */
static void Test_FontSignatureAndCustomLcid(void)
{
    typedef int (WINAPI *PFN_LCIDToLocaleName)(LCID, LPWSTR, int, DWORD);
    PFN_LCIDToLocaleName pLCIDToLocaleName;
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    struct { DWORD lsUsb[4]; DWORD lsCsbDefault[2]; DWORD lsCsbSupported[2]; } Sig; /* LOCALESIGNATURE */
    WCHAR Name[85];
    INT Ret;

    /* the invariant locale has the Latin signature of en-US: usb {3, 0, 0, 0x80000000}, default code pages 1 and
       0x80000000, and supports only code page 1252 (the first supported word is 1) */
    memset(&Sig, 0xcc, sizeof(Sig));
    Ret = GetLocaleInfoW(0x7f, LOCALE_FONTSIGNATURE, (LPWSTR)&Sig, sizeof(Sig) / sizeof(WCHAR));
    ok(Ret == sizeof(Sig) / sizeof(WCHAR), "invariant: returned %d\n", Ret);
    ok(Sig.lsUsb[0] == 3 && Sig.lsUsb[1] == 0 && Sig.lsUsb[2] == 0 && Sig.lsUsb[3] == 0x80000000,
       "invariant: usb %08lx %08lx %08lx %08lx\n", Sig.lsUsb[0], Sig.lsUsb[1], Sig.lsUsb[2], Sig.lsUsb[3]);
    ok(Sig.lsCsbDefault[0] == 1 && Sig.lsCsbDefault[1] == 0x80000000,
       "invariant: default csb %08lx %08lx\n", Sig.lsCsbDefault[0], Sig.lsCsbDefault[1]);
    ok(Sig.lsCsbSupported[0] == 1, "invariant: supported csb %08lx\n", Sig.lsCsbSupported[0]);

    /* LOCALE_CUSTOM_UNSPECIFIED names the user default locale (en-US here, which is the test default) */
    pLCIDToLocaleName = (PFN_LCIDToLocaleName)GetProcAddress(hKernel32, "LCIDToLocaleName");
    if (!pLCIDToLocaleName)
    {
        hKernel32 = LoadLibraryW(L"kernel32_vista.dll");
        if (hKernel32)
            pLCIDToLocaleName = (PFN_LCIDToLocaleName)GetProcAddress(hKernel32, "LCIDToLocaleName");
    }
    if (!pLCIDToLocaleName)
    {
        skip("LCIDToLocaleName not found\n");
        return;
    }
    {
        WCHAR UserName[85];
        INT UserRet = pLCIDToLocaleName(GetUserDefaultLCID(), UserName, _countof(UserName), 0);

        wcscpy(Name, L"?");
        SetLastError(0xdeadbeef);
        Ret = pLCIDToLocaleName(0x1000, Name, _countof(Name), 0);
        ok(Ret == UserRet && Ret != 0, "0x1000: returned %d, user default %d (error %lu)\n", Ret, UserRet, GetLastError());
        ok(!wcscmp(Name, UserName), "0x1000: got '%ls', user default '%ls'\n", Name, UserName);
        Ret = pLCIDToLocaleName(0x1000, NULL, 0, 0);
        ok(Ret == UserRet, "0x1000 size query: returned %d, expected %d\n", Ret, UserRet);
    }
}

#undef GetLocaleInfo
START_TEST(GetLocaleInfo)
{
    Test_GetLocaleInfoEx();
    Test_FontSignatureAndCustomLcid();
}
