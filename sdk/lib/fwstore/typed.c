/*
 * PROJECT:     NitroOS basic firewall
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Typed view of a rule and the conversions to and from the stored tokens
 */
#include "precomp.h"

BOOL FwRuleSetStr(PWSTR *field, PCWSTR v)
{
    PWSTR n = NULL;
    if (v && *v)
    {
        n = HeapAlloc(GetProcessHeap(), 0, (wcslen(v) + 1) * sizeof(WCHAR));
        if (!n) return FALSE;
        wcscpy(n, v);
    }
    FwFree(*field);
    *field = n;
    return TRUE;
}

VOID FwRuleInit(FW_RULE *r)
{
    memset(r, 0, sizeof(*r));
    r->Action = 1; r->Dir = 1; r->Protocol = 256; r->Profiles = FWP_ANY_COM;
    FwrInit(&r->Raw);
}

VOID FwRuleFree(FW_RULE *r)
{
    FwFree(r->Id); FwFree(r->Name); FwFree(r->Desc); FwFree(r->App); FwFree(r->Svc); FwFree(r->Group);
    FwFree(r->LPorts); FwFree(r->RPorts); FwFree(r->LAddr); FwFree(r->RAddr); FwFree(r->Icmp); FwFree(r->IfTypes);
    FwrFree(&r->Raw);
    memset(r, 0, sizeof(*r));
}

/* append "item" to a comma list */
static BOOL ListAdd(PWSTR *list, PCWSTR item)
{
    SIZE_T a = *list ? wcslen(*list) + 1 : 0, b = wcslen(item);
    PWSTR n = HeapAlloc(GetProcessHeap(), 0, (a + b + 1) * sizeof(WCHAR));
    if (!n) return FALSE;
    if (*list) { wcscpy(n, *list); wcscat(n, L","); } else n[0] = 0;
    wcscat(n, item);
    FwFree(*list); *list = n;
    return TRUE;
}

static BOOL IsKeyword(PCWSTR s)
{
    static const PCWSTR kw[] = { L"LocalSubnet", L"DNS", L"DHCP", L"WINS", L"DefaultGateway", L"Internet", L"Intranet", L"PlayToDevice", L"Ply2Renders" };
    ULONG i;
    for (i = 0; i < _countof(kw); i++) if (!_wcsicmp(s, kw[i])) return TRUE;
    return FALSE;
}

static BOOL FromRawLists(FW_RULE *r, const FWR *raw)
{
    ULONG i;
    for (i = 0; i < raw->N; i++)
    {
        PCWSTR k = raw->T[i].Key, v = raw->T[i].Val;
        BOOL ok = TRUE;
        if (!_wcsicmp(k, L"LPort") || !_wcsicmp(k, L"LPort2_10") || !_wcsicmp(k, L"LPort2_20")) ok = ListAdd(&r->LPorts, v);
        else if (!_wcsicmp(k, L"RPort") || !_wcsicmp(k, L"RPort2_10") || !_wcsicmp(k, L"RPort2_20")) ok = ListAdd(&r->RPorts, v);
        else if (!_wcsicmp(k, L"LA4") || !_wcsicmp(k, L"LA6")) ok = ListAdd(&r->LAddr, v);
        else if (!_wcsicmp(k, L"RA4") || !_wcsicmp(k, L"RA42") || !_wcsicmp(k, L"RA6") || !_wcsicmp(k, L"RA62"))
        {
            /* keywords are stored once for IPv4 and once for IPv6: show them once */
            if (IsKeyword(v) && r->RAddr)
            {
                PWSTR p = r->RAddr; BOOL dup = FALSE; SIZE_T l = wcslen(v);
                while ((p = wcsstr(p, v)) != NULL) { if ((p == r->RAddr || p[-1] == L',') && (p[l] == 0 || p[l] == L',')) { dup = TRUE; break; } p++; }
                if (dup) continue;
            }
            ok = ListAdd(&r->RAddr, v);
        }
        else if (!_wcsicmp(k, L"ICMP4") || !_wcsicmp(k, L"ICMP6")) ok = ListAdd(&r->Icmp, v);
        else if (!_wcsicmp(k, L"IFType")) ok = ListAdd(&r->IfTypes, v);
        if (!ok) return FALSE;
    }
    return TRUE;
}

BOOL FwRuleFromRaw(FW_RULE *r, const FWR *raw)
{
    PCWSTR v;
    ULONG i, n;
    FwRuleInit(r);
    if (!FwrClone(&r->Raw, raw)) return FALSE;
    if (raw->Id && !FwRuleSetStr(&r->Id, raw->Id)) return FALSE;
    v = FwrGet(raw, L"Action", 0); r->Action = (v && !_wcsnicmp(v, L"Block", 5)) ? 0 : 1;
    v = FwrGet(raw, L"Active", 0); r->Enabled = (v && !_wcsicmp(v, L"TRUE"));
    v = FwrGet(raw, L"Dir", 0);    r->Dir = (v && !_wcsicmp(v, L"Out")) ? 2 : 1;
    v = FwrGet(raw, L"Protocol", 0); r->Protocol = v ? _wtoi(v) : 256;
    n = FwrCount(raw, L"Profile");
    if (n)
    {
        r->Profiles = 0;
        for (i = 0; i < n; i++)
        {
            v = FwrGet(raw, L"Profile", i);
            if (!_wcsicmp(v, L"Domain")) r->Profiles |= FWP_DOMAIN;
            else if (!_wcsicmp(v, L"Private")) r->Profiles |= FWP_PRIVATE;
            else if (!_wcsicmp(v, L"Public")) r->Profiles |= FWP_PUBLIC;
            else if (!_wcsicmp(v, L"All")) r->Profiles = FWP_ANY_COM;
        }
        if (r->Profiles == FWP_ALL) r->Profiles = FWP_ANY_COM;
    }
    v = FwrGet(raw, L"Edge", 0); r->Edge = (v && !_wcsicmp(v, L"TRUE"));
    if ((v = FwrGet(raw, L"Name", 0)) && !FwRuleSetStr(&r->Name, v)) return FALSE;
    if ((v = FwrGet(raw, L"Desc", 0)) && !FwRuleSetStr(&r->Desc, v)) return FALSE;
    if ((v = FwrGet(raw, L"App", 0)) && !FwRuleSetStr(&r->App, v)) return FALSE;
    if ((v = FwrGet(raw, L"Svc", 0)) && !FwRuleSetStr(&r->Svc, v)) return FALSE;
    if ((v = FwrGet(raw, L"EmbedCtxt", 0)) && !FwRuleSetStr(&r->Group, v)) return FALSE;
    return FromRawLists(r, raw);
}

BOOL FwRuleCopy(FW_RULE *dst, const FW_RULE *src)
{
    FWR raw;
    BOOL ok;
    if (!FwRuleToRaw(src, &raw)) return FALSE;
    ok = FwRuleFromRaw(dst, &raw);
    FwrFree(&raw);
    if (ok && src->Id) ok = FwRuleSetStr(&dst->Id, src->Id);
    return ok;
}

/* ---------- typed -> tokens ---------- */

static BOOL ParseV4(PCWSTR s, PCWSTR *end, ULONG *out)
{
    ULONG v = 0; int parts = 0;
    for (;;)
    {
        ULONG n = 0; int d = 0;
        while (*s >= L'0' && *s <= L'9') { n = n * 10 + (*s - L'0'); s++; d++; if (n > 255 || d > 3) return FALSE; }
        if (!d) return FALSE;
        v = (v << 8) | n; parts++;
        if (parts == 4) break;
        if (*s != L'.') return FALSE;
        s++;
    }
    *out = v; *end = s;
    return TRUE;
}

static ULONG MaskFromPrefix(ULONG p) { return p == 0 ? 0 : (p >= 32 ? 0xFFFFFFFF : (0xFFFFFFFFu << (32 - p))); }

/* Validates one address item and returns its canonical stored form. Returns 0 (ok) or ERROR_INVALID_PARAMETER.
   *pV6: item is IPv6; *pKey: sort key for IPv4; *pKw: keyword. */
static DWORD NormAddr(PCWSTR item, WCHAR *out, SIZE_T cch, BOOL *pV6, ULONG *pKey, BOOL *pKw)
{
    ULONG a, b; PCWSTR e;
    *pV6 = FALSE; *pKey = 0; *pKw = FALSE;
    if (IsKeyword(item))
    {
        static const PCWSTR canon[] = { L"LocalSubnet", L"DNS", L"DHCP", L"WINS", L"DefaultGateway", L"Internet", L"Intranet", L"PlayToDevice", L"Ply2Renders" };
        ULONG i; for (i = 0; i < _countof(canon); i++) if (!_wcsicmp(item, canon[i])) { wcsncpy(out, canon[i], cch); out[cch-1] = 0; }
        *pKw = TRUE; return 0;
    }
    if (wcschr(item, L':'))
    {
        const WCHAR *p;
        for (p = item; *p; p++) if (!((*p >= L'0' && *p <= L'9') || (*p >= L'a' && *p <= L'f') || (*p >= L'A' && *p <= L'F') || *p == L':' || *p == L'/' || *p == L'-' || *p == L'.')) return ERROR_INVALID_PARAMETER;
        if (wcslen(item) >= cch) return ERROR_INVALID_PARAMETER;
        wcscpy(out, item); *pV6 = TRUE; return 0;
    }
    if (!ParseV4(item, &e, &a)) return ERROR_INVALID_PARAMETER;
    *pKey = a;
    if (*e == 0) { _swprintf(out, L"%u.%u.%u.%u", a >> 24, (a >> 16) & 255, (a >> 8) & 255, a & 255); return 0; }
    if (*e == L'/')
    {
        e++;
        if (*e >= L'0' && *e <= L'9' && !wcschr(e, L'.'))
        {
            ULONG p = (ULONG)_wtoi(e), m;
            PCWSTR q = e; while (*q) { if (*q < L'0' || *q > L'9') return ERROR_INVALID_PARAMETER; q++; }
            if (p > 32) return ERROR_INVALID_PARAMETER;
            m = MaskFromPrefix(p);
            a &= m; *pKey = a;
            _swprintf(out, L"%u.%u.%u.%u/%u.%u.%u.%u", a >> 24, (a >> 16) & 255, (a >> 8) & 255, a & 255,
                      m >> 24, (m >> 16) & 255, (m >> 8) & 255, m & 255);
            return 0;
        }
        if (!ParseV4(e, &e, &b) || *e) return ERROR_INVALID_PARAMETER;
        _swprintf(out, L"%u.%u.%u.%u/%u.%u.%u.%u", a >> 24, (a >> 16) & 255, (a >> 8) & 255, a & 255,
                  b >> 24, (b >> 16) & 255, (b >> 8) & 255, b & 255);
        return 0;
    }
    if (*e == L'-')
    {
        if (!ParseV4(e + 1, &e, &b) || *e || b < a) return ERROR_INVALID_PARAMETER;
        _swprintf(out, L"%u.%u.%u.%u-%u.%u.%u.%u", a >> 24, (a >> 16) & 255, (a >> 8) & 255, a & 255,
                  b >> 24, (b >> 16) & 255, (b >> 8) & 255, b & 255);
        return 0;
    }
    return ERROR_INVALID_PARAMETER;
}

DWORD FwCheckAddrs(PCWSTR s)
{
    WCHAR *copy, *tok, *ctx = NULL, out[128];
    DWORD err = 0;
    if (!s || !*s || !wcscmp(s, L"*") || !_wcsicmp(s, L"any")) return 0;
    copy = HeapAlloc(GetProcessHeap(), 0, (wcslen(s) + 1) * sizeof(WCHAR));
    if (!copy) return ERROR_NOT_ENOUGH_MEMORY;
    wcscpy(copy, s);
    for (tok = wcstok(copy, L","); tok && !err; tok = wcstok(NULL, L","))
    { BOOL v6, kw; ULONG k; err = NormAddr(tok, out, _countof(out), &v6, &k, &kw); }
    FwFree(copy);
    return err;
}

static int CmpKey(const void *a, const void *b)
{
    const struct { ULONG key; WCHAR s[64]; } *x = a, *y = b;
    return x->key < y->key ? -1 : x->key > y->key;
}

typedef struct { ULONG key; WCHAR s[64]; } ADDRITEM;

static BOOL AddrToTokens(FWR *raw, PCWSTR list, PCWSTR k4, PCWSTR k6)
{
    WCHAR *copy, *tok, *ctx = NULL, out[128];
    ADDRITEM *items; ULONG n = 0, i, cap;
    BOOL ok = TRUE;
    if (!list || !*list || !wcscmp(list, L"*") || !_wcsicmp(list, L"any")) return TRUE;
    copy = HeapAlloc(GetProcessHeap(), 0, (wcslen(list) + 1) * sizeof(WCHAR));
    cap = (ULONG)wcslen(list) / 2 + 2;
    items = HeapAlloc(GetProcessHeap(), 0, cap * sizeof(ADDRITEM));
    if (!copy || !items) { FwFree(copy); FwFree(items); return FALSE; }
    wcscpy(copy, list);
    for (tok = wcstok(copy, L","); tok; tok = wcstok(NULL, L","))
    {
        BOOL v6, kw; ULONG key;
        if (NormAddr(tok, out, _countof(out), &v6, &key, &kw) || n >= cap) { ok = FALSE; break; }
        if (kw) { ok = FwrAdd(raw, k4, out) && FwrAdd(raw, k6, out); if (!ok) break; continue; }
        if (v6) { ok = FwrAdd(raw, k6, out); if (!ok) break; continue; }
        items[n].key = key; wcsncpy(items[n].s, out, 63); items[n].s[63] = 0; n++;
    }
    if (ok)
    {
        qsort(items, n, sizeof(ADDRITEM), CmpKey);
        for (i = 0; i < n && ok; i++) ok = FwrAdd(raw, k4, items[i].s);
    }
    FwFree(copy); FwFree(items);
    return ok;
}

DWORD FwCheckPorts(PCWSTR s)
{
    WCHAR *copy, *tok, *ctx = NULL; (void)ctx;
    DWORD err = 0;
    if (!s || !*s || !wcscmp(s, L"*") || !_wcsicmp(s, L"any")) return 0;
    copy = HeapAlloc(GetProcessHeap(), 0, (wcslen(s) + 1) * sizeof(WCHAR));
    if (!copy) return ERROR_NOT_ENOUGH_MEMORY;
    wcscpy(copy, s);
    for (tok = wcstok(copy, L","); tok && !err; tok = wcstok(NULL, L","))
    {
        PCWSTR p = tok; ULONG lo = 0, hi = 0; int d = 0;
        if (!_wcsicmp(tok, L"RPC") || !_wcsicmp(tok, L"RPC-EPMap") || !_wcsicmp(tok, L"IPHTTPS") || !_wcsicmp(tok, L"Teredo") || !_wcsicmp(tok, L"PlayToDiscovery")) continue;
        while (*p >= L'0' && *p <= L'9') { lo = lo * 10 + (*p - L'0'); p++; d++; if (lo > 65535) { err = ERROR_INVALID_PARAMETER; break; } }
        if (!d) err = ERROR_INVALID_PARAMETER;
        if (!err && *p == L'-')
        {
            p++; d = 0;
            while (*p >= L'0' && *p <= L'9') { hi = hi * 10 + (*p - L'0'); p++; d++; if (hi > 65535) { err = ERROR_INVALID_PARAMETER; break; } }
            if (!d || hi < lo) err = ERROR_INVALID_PARAMETER;
        }
        if (!err && *p) err = ERROR_INVALID_PARAMETER;
    }
    FwFree(copy);
    return err;
}

static BOOL PortsToTokens(FWR *raw, PCWSTR list, PCWSTR kSingle, PCWSTR kRange)
{
    WCHAR *copy, *tok, *ctx = NULL; (void)ctx;
    BOOL ok = TRUE;
    FWR rng, sgl; ULONG i;
    if (!list || !*list || !wcscmp(list, L"*") || !_wcsicmp(list, L"any")) return TRUE;
    copy = HeapAlloc(GetProcessHeap(), 0, (wcslen(list) + 1) * sizeof(WCHAR));
    if (!copy) return FALSE;
    wcscpy(copy, list);
    FwrInit(&rng); FwrInit(&sgl);
    for (tok = wcstok(copy, L","); tok && ok; tok = wcstok(NULL, L","))
        ok = wcschr(tok, L'-') && !wcschr(tok, L'R') ? FwrAdd(&rng, kRange, tok) : FwrAdd(&sgl, kSingle, tok);
    /* ranges first, then single ports, like the strings Windows writes */
    for (i = 0; ok && i < rng.N; i++) ok = FwrAdd(raw, rng.T[i].Key, rng.T[i].Val);
    for (i = 0; ok && i < sgl.N; i++) ok = FwrAdd(raw, sgl.T[i].Key, sgl.T[i].Val);
    FwrFree(&rng); FwrFree(&sgl); FwFree(copy);
    return ok;
}

BOOL FwRuleToRaw(const FW_RULE *r, FWR *out)
{
    static const PCWSTR managed[] = { L"Action", L"Active", L"Dir", L"Protocol", L"Profile", L"ICMP4", L"ICMP6",
        L"LPort", L"LPort2_10", L"LPort2_20", L"RPort", L"RPort2_10", L"RPort2_20", L"LA4", L"LA6", L"RA4", L"RA42", L"RA6", L"RA62",
        L"IFType", L"App", L"Svc", L"Name", L"Desc", L"EmbedCtxt", L"Edge" };
    ULONG i;
    WCHAR num[16];
    BOOL ok = TRUE;
    if (!FwrClone(out, &r->Raw)) return FALSE;
    for (i = 0; i < _countof(managed); i++) FwrRemove(out, managed[i]);
    if (r->Id) { FwFree(out->Id); out->Id = HeapAlloc(GetProcessHeap(), 0, (wcslen(r->Id) + 1) * sizeof(WCHAR)); if (!out->Id) return FALSE; wcscpy(out->Id, r->Id); }
    wcscpy(out->Ver, FW_RULE_VERSION);
    ok &= FwrAdd(out, L"Action", r->Action ? L"Allow" : L"Block");
    ok &= FwrAdd(out, L"Active", r->Enabled ? L"TRUE" : L"FALSE");
    ok &= FwrAdd(out, L"Dir", r->Dir == 2 ? L"Out" : L"In");
    if (r->Protocol != 256) { _swprintf(num, L"%d", r->Protocol); ok &= FwrAdd(out, L"Protocol", num); }
    if (r->Profiles != FWP_ANY_COM && (r->Profiles & FWP_ALL) != FWP_ALL)
    {
        if (r->Profiles & FWP_DOMAIN) ok &= FwrAdd(out, L"Profile", L"Domain");
        if (r->Profiles & FWP_PRIVATE) ok &= FwrAdd(out, L"Profile", L"Private");
        if (r->Profiles & FWP_PUBLIC) ok &= FwrAdd(out, L"Profile", L"Public");
    }
    if (r->Icmp && *r->Icmp && wcscmp(r->Icmp, L"*") && (r->Protocol == 1 || r->Protocol == 58))
    {
        WCHAR *copy = HeapAlloc(GetProcessHeap(), 0, (wcslen(r->Icmp) + 1) * sizeof(WCHAR)), *tok, *ctx = NULL; (void)ctx;
        if (!copy) return FALSE;
        wcscpy(copy, r->Icmp);
        for (tok = wcstok(copy, L","); tok; tok = wcstok(NULL, L",")) ok &= FwrAdd(out, r->Protocol == 1 ? L"ICMP4" : L"ICMP6", tok);
        FwFree(copy);
    }
    ok &= PortsToTokens(out, r->LPorts, L"LPort", L"LPort2_10");
    ok &= PortsToTokens(out, r->RPorts, L"RPort", L"RPort2_10");
    ok &= AddrToTokens(out, r->LAddr, L"LA4", L"LA6");
    ok &= AddrToTokens(out, r->RAddr, L"RA4", L"RA6");
    if (r->IfTypes && *r->IfTypes && _wcsicmp(r->IfTypes, L"All"))
    {
        WCHAR *copy = HeapAlloc(GetProcessHeap(), 0, (wcslen(r->IfTypes) + 1) * sizeof(WCHAR)), *tok, *ctx = NULL; (void)ctx;
        if (!copy) return FALSE;
        wcscpy(copy, r->IfTypes);
        for (tok = wcstok(copy, L","); tok; tok = wcstok(NULL, L",")) ok &= FwrAdd(out, L"IFType", tok);
        FwFree(copy);
    }
    if (r->App) ok &= FwrAdd(out, L"App", r->App);
    if (r->Svc) ok &= FwrAdd(out, L"Svc", r->Svc);
    ok &= FwrAdd(out, L"Name", r->Name ? r->Name : L"");
    if (r->Desc) ok &= FwrAdd(out, L"Desc", r->Desc);
    if (r->Group) ok &= FwrAdd(out, L"EmbedCtxt", r->Group);
    if (r->Edge) ok &= FwrAdd(out, L"Edge", L"TRUE"); else FwrRemove(out, L"Defer");
    FwrNormalize(out);
    return ok;
}
