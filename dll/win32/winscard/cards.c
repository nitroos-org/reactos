/*
 * PROJECT:     ReactOS SmartCard API
 * LICENSE:     LGPL-2.1+ (https://spdx.org/licenses/LGPL-2.1+)
 * PURPOSE:     The smart card database: card types read from HKLM\SOFTWARE\Microsoft\Cryptography\Calais\SmartCards
 *
 * With SCardSvr stopped, winscard.dll on Windows answers the card queries from this registry key itself
 * (measured on Windows 10 22H2 with no reader: SCardListCardsW lists the card names, SCardGetCardTypeProviderNameW
 * returns the named value, SCardGetProviderIdW and SCardListInterfacesW read the card key). The context
 * argument is not looked at.
 */

#include "precomp.h"

#include <winreg.h>
#include <winnls.h>
#include <wchar.h>

WINE_DEFAULT_DEBUG_CHANNEL(winscard);

#define CALAIS_CARDS_KEY    L"SOFTWARE\\Microsoft\\Cryptography\\Calais\\SmartCards"

#ifndef SCARD_PROVIDER_PRIMARY
#define SCARD_PROVIDER_PRIMARY          1
#define SCARD_PROVIDER_CSP              2
#define SCARD_PROVIDER_KSP              3
#endif
#define SCARD_PROVIDER_CARD_MODULE_ID   0x80000001

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

static LONG open_cards_key(HKEY *key)
{
    return RegOpenKeyExW(HKEY_LOCAL_MACHINE, CALAIS_CARDS_KEY, 0, KEY_READ, key);
}

/* Parses "{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}" (the braces are optional) */
static BOOL parse_hex(const WCHAR **p, int digits, ULONGLONG *out)
{
    ULONGLONG v = 0;

    while (digits--)
    {
        WCHAR c = *(*p)++;

        if (c >= L'0' && c <= L'9') v = v * 16 + (c - L'0');
        else if (c >= L'a' && c <= L'f') v = v * 16 + (c - L'a' + 10);
        else if (c >= L'A' && c <= L'F') v = v * 16 + (c - L'A' + 10);
        else return FALSE;
    }
    *out = v;
    return TRUE;
}

static BOOL parse_guid(const WCHAR *s, GUID *guid)
{
    const WCHAR *p = s;
    ULONGLONG v;
    BOOL braces = (*p == L'{');
    int i;

    if (braces) p++;
    if (!parse_hex(&p, 8, &v)) return FALSE;
    guid->Data1 = (DWORD)v;
    if (*p++ != L'-' || !parse_hex(&p, 4, &v)) return FALSE;
    guid->Data2 = (WORD)v;
    if (*p++ != L'-' || !parse_hex(&p, 4, &v)) return FALSE;
    guid->Data3 = (WORD)v;
    if (*p++ != L'-') return FALSE;
    for (i = 0; i < 8; i++)
    {
        if (i == 2 && *p++ != L'-') return FALSE;
        if (!parse_hex(&p, 2, &v)) return FALSE;
        guid->Data4[i] = (BYTE)v;
    }
    if (braces && *p++ != L'}') return FALSE;
    return *p == 0;
}

/* The length of an ATR (ISO 7816-3): TS, T0, the interface bytes TAi..TDi, the historical bytes and TCK */
static DWORD atr_length(const BYTE *atr)
{
    DWORD len = 2, protocols = 0;
    BYTE y = atr[1] & 0xF0, k = atr[1] & 0x0F;

    for (;;)
    {
        BYTE td = 0;
        BOOL has_td = FALSE;

        if (y & 0x10) len++;
        if (y & 0x20) len++;
        if (y & 0x40) len++;
        if (y & 0x80) { td = atr[len]; has_td = TRUE; len++; }
        if (!has_td) break;
        if (td & 0x0F) protocols |= 1u << 1; /* a protocol other than T=0: a TCK follows */
        y = td & 0xF0;
        if (!(y & 0xF0)) break;
        if (len > 33) return 0;
    }
    len += k;
    if (protocols) len++;
    return len > 33 ? 0 : len;
}

static BOOL card_matches_atr(HKEY card, const BYTE *atr, DWORD atrlen)
{
    BYTE catr[36], cmask[36];
    DWORD sz = sizeof(catr), type, i, masklen = sizeof(cmask);

    if (RegQueryValueExW(card, L"ATR", NULL, &type, catr, &sz) != ERROR_SUCCESS || type != REG_BINARY)
        return FALSE;
    if (sz != atrlen) return FALSE;
    if (RegQueryValueExW(card, L"ATRMask", NULL, &type, cmask, &masklen) != ERROR_SUCCESS ||
        type != REG_BINARY || masklen != sz)
        memset(cmask, 0xFF, sizeof(cmask));
    for (i = 0; i < sz; i++)
        if ((atr[i] & cmask[i]) != (catr[i] & cmask[i])) return FALSE;
    return TRUE;
}

static BOOL card_has_interfaces(HKEY card, const GUID *guids, DWORD count)
{
    HKEY ikey;
    DWORD i;
    BOOL ok = TRUE;

    if (!count) return TRUE;
    if (RegOpenKeyExW(card, L"Supported Interfaces", 0, KEY_READ, &ikey) != ERROR_SUCCESS) return FALSE;
    for (i = 0; i < count && ok; i++)
    {
        WCHAR name[64];
        DWORD n, idx;
        BOOL found = FALSE;

        for (idx = 0; !found; idx++)
        {
            GUID g;

            n = ARRAY_SIZE(name);
            if (RegEnumValueW(ikey, idx, name, &n, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
            found = parse_guid(name, &g) && !memcmp(&g, &guids[i], sizeof(GUID));
        }
        ok = found;
    }
    RegCloseKey(ikey);
    return ok;
}

/* Stores the multi-string result as the API does: size query, SCARD_AUTOALLOCATE, a caller's buffer */
LONG scard_return_multistring(BOOL wide, const WCHAR *src, DWORD srclen, void *buf, DWORD *len)
{
    DWORD need = srclen; /* in characters, with the terminating empty string */
    char *conv = NULL;

    if (!len) return SCARD_E_INVALID_PARAMETER;
    if (!wide)
    {
        int n = srclen ? WideCharToMultiByte(CP_ACP, 0, src, srclen, NULL, 0, NULL, NULL) : 0;

        conv = HeapAlloc(GetProcessHeap(), 0, n + 1);
        if (!conv) return SCARD_E_NO_MEMORY;
        if (n) WideCharToMultiByte(CP_ACP, 0, src, srclen, conv, n, NULL, NULL);
        need = n;
    }
    if (!buf)
    {
        *len = need;
        HeapFree(GetProcessHeap(), 0, conv);
        return SCARD_S_SUCCESS;
    }
    if (*len == SCARD_AUTOALLOCATE)
    {
        void *mem = HeapAlloc(GetProcessHeap(), 0, need * (wide ? sizeof(WCHAR) : 1));

        if (!mem)
        {
            HeapFree(GetProcessHeap(), 0, conv);
            return SCARD_E_NO_MEMORY;
        }
        memcpy(mem, wide ? (void *)src : (void *)conv, need * (wide ? sizeof(WCHAR) : 1));
        *(void **)buf = mem;
        *len = need;
        HeapFree(GetProcessHeap(), 0, conv);
        return SCARD_S_SUCCESS;
    }
    if (*len < need)
    {
        *len = need;
        HeapFree(GetProcessHeap(), 0, conv);
        return SCARD_E_INSUFFICIENT_BUFFER;
    }
    memcpy(buf, wide ? (void *)src : (void *)conv, need * (wide ? sizeof(WCHAR) : 1));
    *len = need;
    HeapFree(GetProcessHeap(), 0, conv);
    return SCARD_S_SUCCESS;
}

static LONG list_cards(BOOL wide, LPCBYTE atr, LPCGUID guids, DWORD guidcount, void *cards, LPDWORD len)
{
    HKEY hcards;
    WCHAR *list = NULL, *p;
    DWORD cap = 0, used = 0, idx, atrlen = 0;
    LONG ret;

    if (!len) return SCARD_E_INVALID_PARAMETER;
    if (atr)
    {
        if (atr[0] != 0x3B && atr[0] != 0x3F) return SCARD_E_INVALID_ATR;
        atrlen = atr_length(atr);
        if (!atrlen) return SCARD_E_INVALID_ATR;
    }

    if (open_cards_key(&hcards) == ERROR_SUCCESS)
    {
        for (idx = 0;; idx++)
        {
            WCHAR name[256];
            DWORD n = ARRAY_SIZE(name);
            HKEY card;
            BOOL ok;

            if (RegEnumKeyExW(hcards, idx, name, &n, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
            if (RegOpenKeyExW(hcards, name, 0, KEY_READ, &card) != ERROR_SUCCESS) continue;
            ok = (!atr || card_matches_atr(card, atr, atrlen)) && card_has_interfaces(card, guids, guidcount);
            RegCloseKey(card);
            if (!ok) continue;
            if (used + n + 2 > cap)
            {
                WCHAR *nl;

                cap = (used + n + 2) * 2;
                nl = list ? HeapReAlloc(GetProcessHeap(), 0, list, cap * sizeof(WCHAR))
                          : HeapAlloc(GetProcessHeap(), 0, cap * sizeof(WCHAR));
                if (!nl)
                {
                    HeapFree(GetProcessHeap(), 0, list);
                    RegCloseKey(hcards);
                    return SCARD_E_NO_MEMORY;
                }
                list = nl;
            }
            memcpy(list + used, name, n * sizeof(WCHAR));
            list[used + n] = 0;
            used += n + 1;
        }
        RegCloseKey(hcards);
    }
    if (!list)
    {
        list = HeapAlloc(GetProcessHeap(), 0, 2 * sizeof(WCHAR));
        if (!list) return SCARD_E_NO_MEMORY;
    }
    p = list + used;
    *p = 0;
    ret = scard_return_multistring(wide, list, used + 1, cards, len);
    HeapFree(GetProcessHeap(), 0, list);
    return ret;
}

LONG WINAPI SCardListCardsW(SCARDCONTEXT hContext, LPCBYTE pbAtr, LPCGUID rgguidInterfaces,
                            DWORD cguidInterfaceCount, LPWSTR mszCards, LPDWORD pcchCards)
{
    TRACE("(%lx, %p, %p, %lu, %p, %p)\n", hContext, pbAtr, rgguidInterfaces, cguidInterfaceCount, mszCards, pcchCards);
    return list_cards(TRUE, pbAtr, rgguidInterfaces, cguidInterfaceCount, mszCards, pcchCards);
}

LONG WINAPI SCardListCardsA(SCARDCONTEXT hContext, LPCBYTE pbAtr, LPCGUID rgguidInterfaces,
                            DWORD cguidInterfaceCount, LPSTR mszCards, LPDWORD pcchCards)
{
    TRACE("(%lx, %p, %p, %lu, %p, %p)\n", hContext, pbAtr, rgguidInterfaces, cguidInterfaceCount, mszCards, pcchCards);
    return list_cards(FALSE, pbAtr, rgguidInterfaces, cguidInterfaceCount, mszCards, pcchCards);
}

static LONG open_card(const WCHAR *name, HKEY *card)
{
    HKEY hcards;
    LONG err;

    if (!name) return SCARD_E_INVALID_PARAMETER;
    if (open_cards_key(&hcards) != ERROR_SUCCESS) return SCARD_E_UNKNOWN_CARD;
    err = RegOpenKeyExW(hcards, name, 0, KEY_READ, card);
    RegCloseKey(hcards);
    return err == ERROR_SUCCESS ? SCARD_S_SUCCESS : SCARD_E_UNKNOWN_CARD;
}

static LONG provider_name(BOOL wide, const WCHAR *cardw, DWORD id, void *out, LPDWORD len)
{
    const WCHAR *value;
    HKEY card;
    DWORD type, size = 0, chars;
    WCHAR *data;
    LONG ret, err;

    switch (id)
    {
        case SCARD_PROVIDER_PRIMARY: value = L"Primary Provider"; break;
        case SCARD_PROVIDER_CSP: value = L"Crypto Provider"; break;
        case SCARD_PROVIDER_KSP: value = L"Smart Card Key Storage Provider"; break;
        case SCARD_PROVIDER_CARD_MODULE_ID: value = L"80000001"; break;
        default: return SCARD_E_INVALID_PARAMETER;
    }
    if (!len) return SCARD_E_INVALID_PARAMETER;
    if ((ret = open_card(cardw, &card)) != SCARD_S_SUCCESS) return ret;
    err = RegQueryValueExW(card, value, NULL, &type, NULL, &size);
    if (err != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ))
    {
        RegCloseKey(card);
        return err != ERROR_SUCCESS ? err : ERROR_FILE_NOT_FOUND; /* Windows returns the registry error as is */
    }
    data = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size + 2 * sizeof(WCHAR));
    if (!data)
    {
        RegCloseKey(card);
        return SCARD_E_NO_MEMORY;
    }
    err = RegQueryValueExW(card, value, NULL, &type, (BYTE *)data, &size);
    RegCloseKey(card);
    if (err != ERROR_SUCCESS)
    {
        HeapFree(GetProcessHeap(), 0, data);
        return err;
    }
    chars = (DWORD)wcslen(data) + 1;
    ret = scard_return_multistring(wide, data, chars, out, len); /* one string: the same buffer rules */
    HeapFree(GetProcessHeap(), 0, data);
    return ret;
}

LONG WINAPI SCardGetCardTypeProviderNameW(SCARDCONTEXT hContext, LPCWSTR szCardName, DWORD dwProviderId,
                                          LPWSTR szProvider, LPDWORD pcchProvider)
{
    TRACE("(%lx, %s, %lx, %p, %p)\n", hContext, debugstr_w(szCardName), dwProviderId, szProvider, pcchProvider);
    return provider_name(TRUE, szCardName, dwProviderId, szProvider, pcchProvider);
}

LONG WINAPI SCardGetCardTypeProviderNameA(SCARDCONTEXT hContext, LPCSTR szCardName, DWORD dwProviderId,
                                          LPSTR szProvider, LPDWORD pcchProvider)
{
    WCHAR name[256];

    TRACE("(%lx, %s, %lx, %p, %p)\n", hContext, debugstr_a(szCardName), dwProviderId, szProvider, pcchProvider);
    if (!szCardName) return SCARD_E_INVALID_PARAMETER;
    if (!MultiByteToWideChar(CP_ACP, 0, szCardName, -1, name, ARRAY_SIZE(name))) return SCARD_E_INVALID_PARAMETER;
    return provider_name(FALSE, name, dwProviderId, szProvider, pcchProvider);
}

static LONG provider_id(const WCHAR *cardw, LPGUID guid)
{
    HKEY card;
    WCHAR str[64];
    DWORD type, size = sizeof(str) - sizeof(WCHAR);
    LONG ret;

    if (!guid) return SCARD_E_INVALID_PARAMETER;
    if ((ret = open_card(cardw, &card)) != SCARD_S_SUCCESS) return ret;
    memset(str, 0, sizeof(str));
    if (RegQueryValueExW(card, L"Primary Provider", NULL, &type, (BYTE *)str, &size) != ERROR_SUCCESS ||
        type != REG_SZ || !parse_guid(str, guid))
        ret = SCARD_E_INVALID_TARGET; /* measured: a card without a primary provider */
    RegCloseKey(card);
    return ret;
}

LONG WINAPI SCardGetProviderIdW(SCARDCONTEXT hContext, LPCWSTR szCard, LPGUID pguidProviderId)
{
    TRACE("(%lx, %s, %p)\n", hContext, debugstr_w(szCard), pguidProviderId);
    return provider_id(szCard, pguidProviderId);
}

LONG WINAPI SCardGetProviderIdA(SCARDCONTEXT hContext, LPCSTR szCard, LPGUID pguidProviderId)
{
    WCHAR name[256];

    TRACE("(%lx, %s, %p)\n", hContext, debugstr_a(szCard), pguidProviderId);
    if (!szCard) return SCARD_E_INVALID_PARAMETER;
    if (!MultiByteToWideChar(CP_ACP, 0, szCard, -1, name, ARRAY_SIZE(name))) return SCARD_E_INVALID_PARAMETER;
    return provider_id(name, pguidProviderId);
}

static LONG list_interfaces(const WCHAR *cardw, LPGUID guids, LPDWORD count)
{
    HKEY card, ikey;
    DWORD found = 0, idx, cap;
    GUID *tmp;
    LONG ret;

    if (!count) return SCARD_E_INVALID_PARAMETER;
    if ((ret = open_card(cardw, &card)) != SCARD_S_SUCCESS) return ret;
    cap = 16;
    tmp = HeapAlloc(GetProcessHeap(), 0, cap * sizeof(GUID));
    if (!tmp)
    {
        RegCloseKey(card);
        return SCARD_E_NO_MEMORY;
    }
    if (RegOpenKeyExW(card, L"Supported Interfaces", 0, KEY_READ, &ikey) == ERROR_SUCCESS)
    {
        for (idx = 0; found < cap; idx++)
        {
            WCHAR name[64];
            DWORD n = ARRAY_SIZE(name);

            if (RegEnumValueW(ikey, idx, name, &n, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
            if (parse_guid(name, &tmp[found])) found++;
        }
        RegCloseKey(ikey);
    }
    RegCloseKey(card);
    if (guids && *count < found)
        ret = SCARD_E_INSUFFICIENT_BUFFER;
    else if (guids && found)
        memcpy(guids, tmp, found * sizeof(GUID));
    *count = found;
    HeapFree(GetProcessHeap(), 0, tmp);
    return ret;
}

LONG WINAPI SCardListInterfacesW(SCARDCONTEXT hContext, LPCWSTR szCard, LPGUID pguidInterfaces, LPDWORD pcguidInterfaces)
{
    TRACE("(%lx, %s, %p, %p)\n", hContext, debugstr_w(szCard), pguidInterfaces, pcguidInterfaces);
    return list_interfaces(szCard, pguidInterfaces, pcguidInterfaces);
}

LONG WINAPI SCardListInterfacesA(SCARDCONTEXT hContext, LPCSTR szCard, LPGUID pguidInterfaces, LPDWORD pcguidInterfaces)
{
    WCHAR name[256];

    TRACE("(%lx, %s, %p, %p)\n", hContext, debugstr_a(szCard), pguidInterfaces, pcguidInterfaces);
    if (!szCard) return SCARD_E_INVALID_PARAMETER;
    if (!MultiByteToWideChar(CP_ACP, 0, szCard, -1, name, ARRAY_SIZE(name))) return SCARD_E_INVALID_PARAMETER;
    return list_interfaces(name, pguidInterfaces, pcguidInterfaces);
}
