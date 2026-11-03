/*
 * PROJECT:     NitroOS basic firewall
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Token model of the v2.x FirewallRules strings
 */
#include "precomp.h"

VOID FwFree(PVOID p) { if (p) HeapFree(GetProcessHeap(), 0, p); }

static PWSTR Dup(PCWSTR s, SIZE_T cch)
{
    PWSTR d = HeapAlloc(GetProcessHeap(), 0, (cch + 1) * sizeof(WCHAR));
    if (d) { memcpy(d, s, cch * sizeof(WCHAR)); d[cch] = 0; }
    return d;
}

VOID FwrInit(FWR *r) { memset(r, 0, sizeof(*r)); wcscpy(r->Ver, FW_RULE_VERSION); }

VOID FwrFree(FWR *r)
{
    ULONG i;
    for (i = 0; i < r->N; i++) { FwFree(r->T[i].Key); FwFree(r->T[i].Val); }
    FwFree(r->T); FwFree(r->Id);
    FwrInit(r);
}

static BOOL Grow(FWR *r)
{
    FWR_TOKEN *n;
    if (r->N < r->Cap) return TRUE;
    n = HeapAlloc(GetProcessHeap(), 0, (r->Cap ? r->Cap * 2 : 16) * sizeof(FWR_TOKEN));
    if (!n) return FALSE;
    if (r->T) { memcpy(n, r->T, r->N * sizeof(FWR_TOKEN)); FwFree(r->T); }
    r->T = n; r->Cap = r->Cap ? r->Cap * 2 : 16;
    return TRUE;
}

BOOL FwrAdd(FWR *r, PCWSTR Key, PCWSTR Val)
{
    if (!Grow(r)) return FALSE;
    r->T[r->N].Key = Dup(Key, wcslen(Key));
    r->T[r->N].Val = Dup(Val, wcslen(Val));
    if (!r->T[r->N].Key || !r->T[r->N].Val) return FALSE;
    r->N++;
    return TRUE;
}

BOOL FwrParse(FWR *r, PCWSTR Id, PCWSTR Data)
{
    PCWSTR p = Data, e;
    FwrInit(r);
    if (Id) { r->Id = Dup(Id, wcslen(Id)); if (!r->Id) return FALSE; }
    if (_wcsnicmp(p, L"v2.", 3) != 0) return FALSE;
    e = wcschr(p, L'|');
    if (!e || (SIZE_T)(e - p) >= _countof(r->Ver)) return FALSE;
    memcpy(r->Ver, p, (e - p) * sizeof(WCHAR)); r->Ver[e - p] = 0;
    p = e + 1;
    while (*p)
    {
        PCWSTR eq, end = wcschr(p, L'|');
        PWSTR k, v;
        if (!end) end = p + wcslen(p);
        eq = p;
        while (eq < end && *eq != L'=') eq++;
        if (eq < end)
        {
            k = Dup(p, eq - p); v = Dup(eq + 1, end - eq - 1);
            if (!k || !v || !Grow(r)) { FwFree(k); FwFree(v); return FALSE; }
            r->T[r->N].Key = k; r->T[r->N].Val = v; r->N++;
        }
        p = *end ? end + 1 : end;
    }
    return TRUE;
}

PWSTR FwrFormat(const FWR *r)
{
    SIZE_T len = wcslen(r->Ver) + 2;
    ULONG i;
    PWSTR out, p;
    for (i = 0; i < r->N; i++) len += wcslen(r->T[i].Key) + wcslen(r->T[i].Val) + 2;
    out = HeapAlloc(GetProcessHeap(), 0, len * sizeof(WCHAR));
    if (!out) return NULL;
    p = out;
    p += _swprintf(p, L"%s|", r->Ver);
    for (i = 0; i < r->N; i++)
        p += _swprintf(p, L"%s=%s|", r->T[i].Key, r->T[i].Val);
    return out;
}

BOOL FwrClone(FWR *dst, const FWR *src)
{
    ULONG i;
    FwrInit(dst);
    wcscpy(dst->Ver, src->Ver);
    if (src->Id) { dst->Id = Dup(src->Id, wcslen(src->Id)); if (!dst->Id) return FALSE; }
    for (i = 0; i < src->N; i++) if (!FwrAdd(dst, src->T[i].Key, src->T[i].Val)) return FALSE;
    return TRUE;
}

PCWSTR FwrGet(const FWR *r, PCWSTR Key, ULONG Index)
{
    ULONG i;
    for (i = 0; i < r->N; i++)
        if (!_wcsicmp(r->T[i].Key, Key) && Index-- == 0) return r->T[i].Val;
    return NULL;
}

ULONG FwrCount(const FWR *r, PCWSTR Key)
{
    ULONG i, n = 0;
    for (i = 0; i < r->N; i++) if (!_wcsicmp(r->T[i].Key, Key)) n++;
    return n;
}

VOID FwrRemove(FWR *r, PCWSTR Key)
{
    ULONG i = 0;
    while (i < r->N)
    {
        if (!_wcsicmp(r->T[i].Key, Key))
        {
            FwFree(r->T[i].Key); FwFree(r->T[i].Val);
            memmove(&r->T[i], &r->T[i + 1], (r->N - i - 1) * sizeof(FWR_TOKEN));
            r->N--;
        }
        else i++;
    }
}

BOOL FwrSet(FWR *r, PCWSTR Key, PCWSTR Val)
{
    ULONG i;
    if (!Val) { FwrRemove(r, Key); return TRUE; }
    for (i = 0; i < r->N; i++)
        if (!_wcsicmp(r->T[i].Key, Key))
        {
            PWSTR nv;
            ULONG j = i + 1;
            nv = Dup(Val, wcslen(Val));
            if (!nv) return FALSE;
            FwFree(r->T[i].Val); r->T[i].Val = nv;
            /* drop the other occurrences */
            while (j < r->N)
            {
                if (!_wcsicmp(r->T[j].Key, Key))
                {
                    FwFree(r->T[j].Key); FwFree(r->T[j].Val);
                    memmove(&r->T[j], &r->T[j + 1], (r->N - j - 1) * sizeof(FWR_TOKEN));
                    r->N--;
                }
                else j++;
            }
            return TRUE;
        }
    return FwrAdd(r, Key, Val);
}

/* canonical order, see the Windows-written strings; unknown keys keep their relative place at the end */
static const PCWSTR g_Order[] = {
    L"Action", L"Active", L"Dir", L"Protocol", L"Profile", L"ICMP4", L"ICMP6", L"LPort2_10", L"LPort2_20", L"LPort",
    L"RPort2_10", L"RPort2_20", L"RPort", L"LA4", L"LA6", L"RA4", L"RA42", L"RA6", L"RA62", L"IF", L"IFType",
    L"App", L"Svc", L"Name", L"Desc", L"LUOwn", L"LUAuth", L"AppPkgId", L"EmbedCtxt", L"Platform", L"Platform2",
    L"TTK", L"TTK2_22", L"TTK2_27", L"TTK2_28", L"Edge", L"Defer", L"Security", L"LSM", L"RUAuth", L"RMauth", L"LOwner"
};

static int OrderOf(PCWSTR k)
{
    int i;
    for (i = 0; i < (int)_countof(g_Order); i++) if (!_wcsicmp(k, g_Order[i])) return i;
    return (int)_countof(g_Order);
}

VOID FwrNormalize(FWR *r)
{
    ULONG i, j;
    for (i = 1; i < r->N; i++)   /* stable insertion sort */
    {
        FWR_TOKEN t = r->T[i];
        int o = OrderOf(t.Key);
        for (j = i; j > 0 && OrderOf(r->T[j - 1].Key) > o; j--) r->T[j] = r->T[j - 1];
        r->T[j] = t;
    }
}
