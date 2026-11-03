/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     winscard.dll card type database queries (HKLM\SOFTWARE\Microsoft\Cryptography\Calais\SmartCards)
 *              as measured on Windows 10 22H2 with SCardSvr stopped and no reader attached
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <windows.h>
#include <winscard.h>
#include <stdio.h>

#ifndef SCARD_AUTOALLOCATE
#define SCARD_AUTOALLOCATE ((DWORD)-1)
#endif

#define SCARD_PROVIDER_PRIMARY 1
#define SCARD_PROVIDER_CSP 2
#define SCARD_PROVIDER_KSP 3

#define E_INSUFFICIENT_BUFFER ((LONG)0x80100008)
#define E_INVALID_TARGET ((LONG)0x80100005)

static LONG (WINAPI *pSCardListCardsW)(SCARDCONTEXT, LPCBYTE, LPCGUID, DWORD, LPWSTR, LPDWORD);
static LONG (WINAPI *pSCardListCardsA)(SCARDCONTEXT, LPCBYTE, LPCGUID, DWORD, LPSTR, LPDWORD);
static LONG (WINAPI *pSCardGetCardTypeProviderNameW)(SCARDCONTEXT, LPCWSTR, DWORD, LPWSTR, LPDWORD);
static LONG (WINAPI *pSCardGetCardTypeProviderNameA)(SCARDCONTEXT, LPCSTR, DWORD, LPSTR, LPDWORD);
static LONG (WINAPI *pSCardGetProviderIdW)(SCARDCONTEXT, LPCWSTR, LPGUID);
static LONG (WINAPI *pSCardListInterfacesW)(SCARDCONTEXT, LPCWSTR, LPGUID, LPDWORD);
static LONG (WINAPI *pSCardFreeMemory)(SCARDCONTEXT, LPCVOID);
static LONG (WINAPI *pSCardEstablishContext)(DWORD, LPCVOID, LPCVOID, LPSCARDCONTEXT);
static LONG (WINAPI *pSCardReleaseContext)(SCARDCONTEXT);
static HANDLE (WINAPI *pSCardAccessStartedEvent)(void);
static void (WINAPI *pSCardReleaseStartedEvent)(void);

static const WCHAR GenericCard[] = L"Identity Device (Microsoft Generic Profile)";
static const WCHAR PivCard[] = L"Identity Device (NIST SP 800-73 [PIV])";

static BOOL multi_has(const WCHAR *list, const WCHAR *name)
{
    while (*list)
    {
        if (!lstrcmpW(list, name))
            return TRUE;
        list += lstrlenW(list) + 1;
    }
    return FALSE;
}

static DWORD multi_len(const WCHAR *list)
{
    const WCHAR *p = list;

    while (*p)
        p += lstrlenW(p) + 1;
    return (DWORD)(p - list) + 1;
}

static void test_list_cards(void)
{
    WCHAR buffer[1024], *allocated = NULL, tiny[3];
    CHAR bufferA[1024];
    DWORD length, lengthA, need;
    LONG ret;

    length = 0xdeadbeef;
    ret = pSCardListCardsW(0, NULL, NULL, 0, NULL, &length);
    ok(ret == SCARD_S_SUCCESS, "SCardListCardsW size query: 0x%08lx\n", ret);
    ok(length >= (DWORD)(lstrlenW(GenericCard) + lstrlenW(PivCard) + 3), "length = %lu\n", length);
    need = length;

    memset(buffer, 0, sizeof(buffer));
    length = ARRAYSIZE(buffer);
    ret = pSCardListCardsW(0, NULL, NULL, 0, buffer, &length);
    ok(ret == SCARD_S_SUCCESS, "SCardListCardsW: 0x%08lx\n", ret);
    ok(length == need, "length = %lu, expected %lu\n", length, need);
    ok(multi_has(buffer, GenericCard), "no %ls\n", GenericCard);
    ok(multi_has(buffer, PivCard), "no %ls\n", PivCard);
    ok(multi_len(buffer) == length, "list is %lu characters, reported %lu\n", multi_len(buffer), length);

    /* a buffer that is too tiny reports the size */
    length = ARRAYSIZE(tiny);
    ret = pSCardListCardsW(0, NULL, NULL, 0, tiny, &length);
    ok(ret == E_INSUFFICIENT_BUFFER, "SCardListCardsW(tiny): 0x%08lx\n", ret);
    ok(length == need, "length = %lu, expected %lu\n", length, need);

    length = SCARD_AUTOALLOCATE;
    ret = pSCardListCardsW(0, NULL, NULL, 0, (LPWSTR)&allocated, &length);
    ok(ret == SCARD_S_SUCCESS, "SCardListCardsW autoallocate: 0x%08lx\n", ret);
    ok(length == need, "length = %lu, expected %lu\n", length, need);
    ok(allocated != NULL, "no buffer\n");
    if (allocated)
    {
        ok(multi_has(allocated, PivCard), "no %ls\n", PivCard);
        ret = pSCardFreeMemory(0, allocated);
        ok(ret == SCARD_S_SUCCESS, "SCardFreeMemory: 0x%08lx\n", ret);
    }

    lengthA = ARRAYSIZE(bufferA);
    ret = pSCardListCardsA(0, NULL, NULL, 0, bufferA, &lengthA);
    ok(ret == SCARD_S_SUCCESS, "SCardListCardsA: 0x%08lx\n", ret);
    ok(lengthA == need, "lengthA = %lu, expected %lu\n", lengthA, need);
    ok(strstr(bufferA, "Identity Device (Microsoft Generic Profile)") != NULL, "no generic card in the A list\n");
}

static void test_provider_names(void)
{
    WCHAR buffer[256], *allocated;
    CHAR bufferA[256];
    DWORD length;
    GUID guid;
    LONG ret;

    length = ARRAYSIZE(buffer);
    ret = pSCardGetCardTypeProviderNameW(0, GenericCard, SCARD_PROVIDER_CSP, buffer, &length);
    ok(ret == SCARD_S_SUCCESS, "CSP: 0x%08lx\n", ret);
    ok(!lstrcmpW(buffer, L"Microsoft Base Smart Card Crypto Provider"), "CSP = %ls\n", buffer);
    ok(length == lstrlenW(buffer) + 1, "length = %lu\n", length);

    length = ARRAYSIZE(buffer);
    ret = pSCardGetCardTypeProviderNameW(0, PivCard, SCARD_PROVIDER_KSP, buffer, &length);
    ok(ret == SCARD_S_SUCCESS, "KSP: 0x%08lx\n", ret);
    ok(!lstrcmpW(buffer, L"Microsoft Smart Card Key Storage Provider"), "KSP = %ls\n", buffer);

    allocated = NULL;
    length = SCARD_AUTOALLOCATE;
    ret = pSCardGetCardTypeProviderNameW(0, GenericCard, SCARD_PROVIDER_CSP, (LPWSTR)&allocated, &length);
    ok(ret == SCARD_S_SUCCESS, "CSP autoallocate: 0x%08lx\n", ret);
    ok(allocated && !lstrcmpW(allocated, L"Microsoft Base Smart Card Crypto Provider"), "CSP = %ls\n",
       allocated ? allocated : L"(null)");
    if (allocated)
        pSCardFreeMemory(0, allocated);

    length = ARRAYSIZE(bufferA);
    ret = pSCardGetCardTypeProviderNameA(0, "Identity Device (Microsoft Generic Profile)", SCARD_PROVIDER_CSP, bufferA, &length);
    ok(ret == SCARD_S_SUCCESS, "CSP (A): 0x%08lx\n", ret);
    ok(!strcmp(bufferA, "Microsoft Base Smart Card Crypto Provider"), "CSP = %s\n", bufferA);

    /* the card module value */
    length = ARRAYSIZE(buffer);
    ret = pSCardGetCardTypeProviderNameW(0, GenericCard, 0x80000001, buffer, &length);
    ok(ret == SCARD_S_SUCCESS, "card module: 0x%08lx\n", ret);
    ok(length >= 11 && !lstrcmpiW(buffer + lstrlenW(buffer) - 10, L"msclmd.dll"), "card module = %ls\n", buffer);

    /* these cards have no primary provider: the registry error is returned as is */
    length = ARRAYSIZE(buffer);
    ret = pSCardGetCardTypeProviderNameW(0, GenericCard, SCARD_PROVIDER_PRIMARY, buffer, &length);
    ok(ret == ERROR_FILE_NOT_FOUND, "primary: 0x%08lx\n", ret);

    ret = pSCardGetProviderIdW(0, GenericCard, &guid);
    ok(ret == E_INVALID_TARGET, "SCardGetProviderIdW: 0x%08lx\n", ret);

    length = 0xdeadbeef;
    ret = pSCardListInterfacesW(0, GenericCard, NULL, &length);
    ok(ret == SCARD_S_SUCCESS, "SCardListInterfacesW: 0x%08lx\n", ret);
    ok(length == 0, "interface count = %lu\n", length);
}

static void test_started_event(void)
{
    SCARDCONTEXT context = 0;
    HANDLE event, event2;
    LONG ret = pSCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &context);
    BOOL running = (ret == SCARD_S_SUCCESS);

    if (running)
        pSCardReleaseContext(context);

    /* With SCardSvr stopped (the Windows 10 default until a reader arrives) there is no event: the call
     * returns NULL, both times. While the service runs the event exists and is signaled. */
    event = pSCardAccessStartedEvent();
    event2 = pSCardAccessStartedEvent();
    if (!running)
    {
        ok(event == NULL, "service stopped, but the started event is %p\n", event);
        ok(event2 == NULL, "service stopped, but the second started event is %p\n", event2);
        return;
    }
    ok(event != NULL, "service running, but there is no started event\n");
    ok(event2 == event, "second call returned %p, first %p\n", event2, event);
    if (event)
        ok(WaitForSingleObject(event, 0) == WAIT_OBJECT_0, "the started event is not signaled\n");
    pSCardReleaseStartedEvent();
    pSCardReleaseStartedEvent();
}

START_TEST(Cards)
{
    HMODULE module = LoadLibraryA("winscard.dll");

    ok(module != NULL, "LoadLibrary(winscard.dll) failed: %lu\n", GetLastError());
    if (!module)
        return;
#define LOAD(name) do { p##name = (void *)GetProcAddress(module, #name); \
    ok(p##name != NULL, #name " missing\n"); if (!p##name) return; } while (0)
    LOAD(SCardListCardsW);
    LOAD(SCardListCardsA);
    LOAD(SCardGetCardTypeProviderNameW);
    LOAD(SCardGetCardTypeProviderNameA);
    LOAD(SCardGetProviderIdW);
    LOAD(SCardListInterfacesW);
    LOAD(SCardFreeMemory);
    LOAD(SCardEstablishContext);
    LOAD(SCardReleaseContext);
    LOAD(SCardAccessStartedEvent);
    LOAD(SCardReleaseStartedEvent);
#undef LOAD

    test_started_event();
    test_list_cards();
    test_provider_names();
}
