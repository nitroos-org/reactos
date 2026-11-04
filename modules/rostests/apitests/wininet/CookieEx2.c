/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for InternetGetCookieEx2 and InternetFreeCookies (Win8+ wininet)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#include <wininet.h>

typedef DWORD (WINAPI *FN_GetCookieEx2)(PCWSTR, PCWSTR, DWORD, INTERNET_COOKIE2 **, PDWORD);
typedef VOID (WINAPI *FN_FreeCookies)(INTERNET_COOKIE2 *, DWORD);
typedef BOOL (WINAPI *FN_SetCookieW)(PCWSTR, PCWSTR, PCWSTR);

START_TEST(CookieEx2)
{
    HMODULE hWininet = LoadLibraryW(L"wininet.dll");
    FN_GetCookieEx2 pGetCookieEx2;
    FN_FreeCookies pFreeCookies;
    FN_SetCookieW pSetCookie;
    INTERNET_COOKIE2 *Cookies;
    DWORD Count, Error, i;
    BOOL Found1 = FALSE, Found2 = FALSE;
    static const WCHAR Url[] = L"http://cookieex2.example.test/dir/page.htm";

    ok(hWininet != NULL, "no wininet\n");
    if (!hWininet)
        return;
    pGetCookieEx2 = (FN_GetCookieEx2)GetProcAddress(hWininet, "InternetGetCookieEx2");
    pFreeCookies = (FN_FreeCookies)GetProcAddress(hWininet, "InternetFreeCookies");
    ok(pGetCookieEx2 && pFreeCookies, "InternetGetCookieEx2/InternetFreeCookies not exported: %p %p\n",
       pGetCookieEx2, pFreeCookies);
    pSetCookie = (FN_SetCookieW)GetProcAddress(hWininet, "InternetSetCookieW");
    if (!pGetCookieEx2 || !pFreeCookies || !pSetCookie)
        return;

    Cookies = (INTERNET_COOKIE2 *)(ULONG_PTR)1;
    Count = 77;
    Error = pGetCookieEx2(Url, NULL, 0, &Cookies, &Count);
    ok(Error != ERROR_SUCCESS, "no cookies stored, got success\n");
    ok(Cookies == NULL && Count == 0, "outputs not cleared: %p %lu\n", Cookies, Count);

    /* session cookies, nothing is written to the persistent store */
    ok(pSetCookie(Url, NULL, L"one=1; path=/"), "InternetSetCookieW failed: %lu\n", GetLastError());
    ok(pSetCookie(Url, NULL, L"two=22; path=/"), "InternetSetCookieW failed: %lu\n", GetLastError());

    Cookies = NULL;
    Count = 0;
    Error = pGetCookieEx2(Url, NULL, 0, &Cookies, &Count);
    ok(Error == ERROR_SUCCESS, "InternetGetCookieEx2 returned %lu\n", Error);
    ok(Count == 2 && Cookies, "count %lu, cookies %p\n", Count, Cookies);
    for (i = 0; Cookies && i < Count; i++)
    {
        ok(Cookies[i].pwszName && Cookies[i].pwszValue && Cookies[i].pwszDomain && Cookies[i].pwszPath,
           "cookie %lu has a NULL string\n", i);
        if (!Cookies[i].pwszName || !Cookies[i].pwszValue)
            continue;
        if (!lstrcmpW(Cookies[i].pwszName, L"one"))
        {
            Found1 = TRUE;
            ok(!lstrcmpW(Cookies[i].pwszValue, L"1"), "value %ls\n", Cookies[i].pwszValue);
        }
        if (!lstrcmpW(Cookies[i].pwszName, L"two"))
        {
            Found2 = TRUE;
            ok(!lstrcmpW(Cookies[i].pwszValue, L"22"), "value %ls\n", Cookies[i].pwszValue);
        }
        ok(!Cookies[i].fExpiresSet, "session cookie with an expiry\n");
    }
    ok(Found1 && Found2, "cookies missing: %d %d\n", Found1, Found2);
    if (Cookies)
        pFreeCookies(Cookies, Count);

    Cookies = NULL;
    Count = 0;
    Error = pGetCookieEx2(Url, L"two", 0, &Cookies, &Count);
    ok(Error == ERROR_SUCCESS, "name filter: %lu\n", Error);
    ok(Count == 1 && Cookies && !lstrcmpW(Cookies[0].pwszName, L"two"), "name filter: count %lu\n", Count);
    if (Cookies)
        pFreeCookies(Cookies, Count);

    Cookies = NULL;
    Count = 5;
    Error = pGetCookieEx2(Url, L"nonexistent", 0, &Cookies, &Count);
    ok(Error != ERROR_SUCCESS, "unknown name: success\n");
    ok(Cookies == NULL && Count == 0, "unknown name: %p %lu\n", Cookies, Count);

    pFreeCookies(NULL, 0);
}
