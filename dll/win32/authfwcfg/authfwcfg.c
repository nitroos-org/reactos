/*
 * PROJECT:     NitroOS basic firewall
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     netsh helper "advfirewall": advfirewall / firewall / consec / mainmode / monitor contexts.
 *              Texts and parsing behaviour follow Windows 10 22H2 (captured from a reference machine).
 */
#include "precomp.h"

HINSTANCE hDllInstance;

/* {B2A5C5A0-6D2B-4E55-9D5F-6E1D2A7B0001} etc.: helper GUIDs (private to this DLL) */
static const GUID GUID_ADVFW   = {0xB2A5C5A0, 0x6D2B, 0x4E55, {0x9D, 0x5F, 0x6E, 0x1D, 0x2A, 0x7B, 0x00, 0x01}};
static const GUID GUID_FW      = {0xB2A5C5A0, 0x6D2B, 0x4E55, {0x9D, 0x5F, 0x6E, 0x1D, 0x2A, 0x7B, 0x00, 0x02}};
static const GUID GUID_CONSEC  = {0xB2A5C5A0, 0x6D2B, 0x4E55, {0x9D, 0x5F, 0x6E, 0x1D, 0x2A, 0x7B, 0x00, 0x03}};
static const GUID GUID_MAIN    = {0xB2A5C5A0, 0x6D2B, 0x4E55, {0x9D, 0x5F, 0x6E, 0x1D, 0x2A, 0x7B, 0x00, 0x04}};
static const GUID GUID_MON     = {0xB2A5C5A0, 0x6D2B, 0x4E55, {0x9D, 0x5F, 0x6E, 0x1D, 0x2A, 0x7B, 0x00, 0x05}};

/* ---------------------------------------------------------------- output helpers */

static PWSTR ResText(UINT id)
{
    LPCWSTR p = NULL;
    int len = LoadStringW(hDllInstance, id, (LPWSTR)&p, 0);
    PWSTR out;
    if (len <= 0) return NULL;
    out = HeapAlloc(GetProcessHeap(), 0, (len + 1) * sizeof(WCHAR));
    if (out) { memcpy(out, p, len * sizeof(WCHAR)); out[len] = 0; }
    return out;
}

static VOID Out(PCWSTR s)
{
    SIZE_T n = wcslen(s);
    WCHAR chunk[257];
    while (n)
    {
        SIZE_T c = n > 256 ? 256 : n;
        memcpy(chunk, s, c * sizeof(WCHAR)); chunk[c] = 0;
        PrintMessage(L"%s", chunk);
        s += c; n -= c;
    }
}

static VOID OutRes(UINT id)
{
    PWSTR t = ResText(id);
    if (t) { Out(t); HeapFree(GetProcessHeap(), 0, t); }
}

static VOID OutResFmt(UINT id, PCWSTR a)
{
    PWSTR t = ResText(id), buf;
    if (!t) return;
    buf = HeapAlloc(GetProcessHeap(), 0, (wcslen(t) + wcslen(a) + 16) * sizeof(WCHAR));
    if (buf) { _swprintf(buf, t, a); Out(buf); HeapFree(GetProcessHeap(), 0, buf); }
    HeapFree(GetProcessHeap(), 0, t);
}

static VOID OutResCount(UINT id, ULONG n)
{
    PWSTR t = ResText(id), buf;
    if (!t) return;
    buf = HeapAlloc(GetProcessHeap(), 0, (wcslen(t) + 16) * sizeof(WCHAR));
    if (buf) { _swprintf(buf, t, n); Out(buf); HeapFree(GetProcessHeap(), 0, buf); }
    HeapFree(GetProcessHeap(), 0, t);
}

/* prefix text + usage block; the help-token form of a usage text is "\nUsage...", the error form has no leading newline */
static DWORD Fail(UINT pfx, UINT usage, BOOL helpForm)
{
    OutRes(pfx);
    if (usage)
    {
        PWSTR t = ResText(usage);
        if (t)
        {
            PCWSTR u = t;
            if (helpForm && *u == L'\n') u++;
            Out(u);
            if (helpForm) Out(L"\n");
            HeapFree(GetProcessHeap(), 0, t);
        }
    }
    return ERROR_SUPPRESS_OUTPUT;
}

/* ---------------------------------------------------------------- argument parsing */

enum { P_NAME, P_DIR, P_ACTION, P_PROGRAM, P_SERVICE, P_DESC, P_ENABLE, P_PROFILE, P_LOCALIP, P_REMOTEIP,
       P_LOCALPORT, P_REMOTEPORT, P_PROTOCOL, P_IFTYPE, P_RMTCOMP, P_RMTUSR, P_EDGE, P_SECURITY, P_GROUP,
       P_TYPE, P_STATUS, P_COUNT };

static const PCWSTR g_ParamName[P_COUNT] = { L"name", L"dir", L"action", L"program", L"service", L"description", L"enable",
    L"profile", L"localip", L"remoteip", L"localport", L"remoteport", L"protocol", L"interfacetype", L"rmtcomputergrp",
    L"rmtusrgrp", L"edge", L"security", L"group", L"type", L"status" };

#define M(x) (1u << (x))
#define MASK_RULE   (M(P_NAME)|M(P_DIR)|M(P_ACTION)|M(P_PROGRAM)|M(P_SERVICE)|M(P_DESC)|M(P_ENABLE)|M(P_PROFILE)|M(P_LOCALIP)|M(P_REMOTEIP)|\
                     M(P_LOCALPORT)|M(P_REMOTEPORT)|M(P_PROTOCOL)|M(P_IFTYPE)|M(P_RMTCOMP)|M(P_RMTUSR)|M(P_EDGE)|M(P_SECURITY))
#define MASK_FILTER (M(P_NAME)|M(P_DIR)|M(P_PROFILE)|M(P_PROGRAM)|M(P_SERVICE)|M(P_LOCALIP)|M(P_REMOTEIP)|M(P_LOCALPORT)|M(P_REMOTEPORT)|M(P_PROTOCOL))
#define MASK_SHOW   (MASK_FILTER|M(P_TYPE)|M(P_STATUS))
#define MASK_SETSEL (MASK_FILTER|M(P_GROUP))

typedef struct _PARAMS
{
    PWSTR val[P_COUNT];
    BOOL has[P_COUNT];
    BOOL verbose;
    PWSTR positional;
} PARAMS;

enum { PE_OK = 0, PE_DUP, PE_BOGUS };

static VOID FreeParams(PARAMS *p)
{
    int i;
    (void)i;
    memset(p, 0, sizeof(*p));
}

/* arguments argv[from..to): "tag=value" pairs, a bare "verbose" (when allowed), a bare first word (show) */
static int ParseParams(LPWSTR *argv, DWORD from, DWORD to, ULONG allowed, BOOL allowVerbose, PARAMS *p, PCWSTR *bogus)
{
    DWORD i;
    memset(p, 0, sizeof(*p));
    for (i = from; i < to; i++)
    {
        WCHAR *eq = wcschr(argv[i], L'=');
        int k;
        if (!eq)
        {
            if (allowVerbose && !_wcsicmp(argv[i], L"verbose")) { p->verbose = TRUE; continue; }
            if (!p->positional) p->positional = argv[i];
            continue;
        }
        for (k = 0; k < P_COUNT; k++)
            if ((allowed & M(k)) && (SIZE_T)(eq - argv[i]) == wcslen(g_ParamName[k]) && !_wcsnicmp(argv[i], g_ParamName[k], eq - argv[i])) break;
        if (k == P_COUNT) { *bogus = argv[i]; return PE_BOGUS; }
        if (p->has[k]) return PE_DUP;
        p->has[k] = TRUE; p->val[k] = eq + 1;
    }
    return PE_OK;
}

static DWORD ReportParseError(int pe, PCWSTR bogus)
{
    if (pe == PE_DUP) OutRes(IDS_MSG_DUPNAME);
    else
    {
        WCHAR name[128]; PCWSTR eq = wcschr(bogus, L'=');
        SIZE_T n = eq ? (SIZE_T)(eq - bogus) : wcslen(bogus);
        if (n > 120) n = 120;
        memcpy(name, bogus, n * sizeof(WCHAR)); name[n] = 0;
        OutResFmt(IDS_MSG_BOGUSARG, name);
    }
    return ERROR_SUPPRESS_OUTPUT;
}

/* ---------------------------------------------------------------- value conversion */

static BOOL ParseProfiles(PCWSTR s, LONG *mask)
{
    WCHAR *copy = _wcsdup(s), *tok;
    LONG m = 0; BOOL any = FALSE, ok = TRUE, others = FALSE;
    if (!copy) return FALSE;
    for (tok = wcstok(copy, L","); tok; tok = wcstok(NULL, L","))
    {
        if (!_wcsicmp(tok, L"public")) { m |= FWP_PUBLIC; others = TRUE; }
        else if (!_wcsicmp(tok, L"private")) { m |= FWP_PRIVATE; others = TRUE; }
        else if (!_wcsicmp(tok, L"domain")) { m |= FWP_DOMAIN; others = TRUE; }
        else if (!_wcsicmp(tok, L"any")) any = TRUE;
        else ok = FALSE;
    }
    if (any && others) ok = FALSE;
    if (!any && !others) ok = FALSE;
    free(copy);
    if (!ok) return FALSE;
    *mask = any ? FWP_ANY_COM : m;
    return TRUE;
}

static BOOL ParseIcmpPart(PCWSTR s, UCHAR *v, BOOL *any)
{
    ULONG n = 0; int d = 0;
    if (!_wcsicmp(s, L"any")) { *any = TRUE; return TRUE; }
    *any = FALSE;
    while (*s >= L'0' && *s <= L'9') { n = n * 10 + (*s++ - L'0'); d++; if (n > 255) return FALSE; }
    if (!d || *s) return FALSE;
    *v = (UCHAR)n;
    return TRUE;
}

/* protocol=...: returns FALSE if invalid */
static BOOL ParseProtocol(PCWSTR s, LONG *proto, WCHAR *icmp, SIZE_T cch)
{
    icmp[0] = 0;
    if (!_wcsicmp(s, L"tcp")) { *proto = 6; return TRUE; }
    if (!_wcsicmp(s, L"udp")) { *proto = 17; return TRUE; }
    if (!_wcsicmp(s, L"any")) { *proto = 256; return TRUE; }
    if (!_wcsicmp(s, L"icmpv4")) { *proto = 1; return TRUE; }
    if (!_wcsicmp(s, L"icmpv6")) { *proto = 58; return TRUE; }
    if (!_wcsnicmp(s, L"icmpv4:", 7) || !_wcsnicmp(s, L"icmpv6:", 7))
    {
        WCHAR *copy = _wcsdup(s + 7), *comma;
        UCHAR t = 0, c = 0; BOOL ta = FALSE, ca = TRUE, ok;
        if (!copy) return FALSE;
        comma = wcschr(copy, L',');
        if (comma) *comma = 0;
        ok = ParseIcmpPart(copy, &t, &ta);
        if (ok && comma) ok = ParseIcmpPart(comma + 1, &c, &ca);
        free(copy);
        if (!ok) return FALSE;
        *proto = (s[4] == L'4') ? 1 : 58;
        { WCHAR a[8], b[8]; if (ta) wcscpy(a, L"*"); else _swprintf(a, L"%u", t); if (ca) wcscpy(b, L"*"); else _swprintf(b, L"%u", c);
          _swprintf(icmp, L"%s:%s", a, b); (void)cch; }
        return TRUE;
    }
    {
        ULONG n = 0; int d = 0; PCWSTR p = s;
        while (*p >= L'0' && *p <= L'9') { n = n * 10 + (*p++ - L'0'); d++; if (n > 255) return FALSE; }
        if (!d || *p) return FALSE;
        *proto = (LONG)n;
        return TRUE;
    }
}

static BOOL IsPortProto(LONG p) { return p == 6 || p == 17; }

static VOID SetEmptyDesc(FW_RULE *r)
{
    FwRuleSetStr(&r->Desc, NULL);
    r->Desc = HeapAlloc(GetProcessHeap(), 0, sizeof(WCHAR));
    if (r->Desc) r->Desc[0] = 0;
}

typedef struct { UINT pfx; UINT usage; BOOL full; } PERR;   /* full: pfx is a complete message, no usage */

/* apply the "new" side (or all of add) of a rule command to r. Returns 0 or fills *e */
static BOOL ApplyParams(FW_RULE *r, const PARAMS *p, BOOL isSet, PERR *e, UINT usage)
{
    LONG proto = r->Protocol; WCHAR icmp[24];
    BOOL protoGiven = p->has[P_PROTOCOL];

    e->usage = usage; e->full = FALSE;
    if (p->has[P_NAME]) { if (!*p->val[P_NAME] || !_wcsicmp(p->val[P_NAME], L"all")) { e->pfx = IDS_PFX_VALUE; return FALSE; } FwRuleSetStr(&r->Name, p->val[P_NAME]); }
    if (p->has[P_DIR])
    {
        if (!_wcsicmp(p->val[P_DIR], L"in")) r->Dir = 1; else if (!_wcsicmp(p->val[P_DIR], L"out")) r->Dir = 2;
        else { e->pfx = IDS_PFX_VALUE; return FALSE; }
    }
    if (p->has[P_ACTION])
    {
        if (!_wcsicmp(p->val[P_ACTION], L"allow")) r->Action = 1; else if (!_wcsicmp(p->val[P_ACTION], L"block")) r->Action = 0;
        else { e->pfx = IDS_PFX_VALUE; return FALSE; }
    }
    if (p->has[P_PROGRAM]) FwRuleSetStr(&r->App, p->val[P_PROGRAM]);
    if (p->has[P_SERVICE]) FwRuleSetStr(&r->Svc, !_wcsicmp(p->val[P_SERVICE], L"any") ? L"*" : p->val[P_SERVICE]);
    if (p->has[P_DESC]) { if (*p->val[P_DESC]) FwRuleSetStr(&r->Desc, p->val[P_DESC]); else SetEmptyDesc(r); }
    if (p->has[P_ENABLE])
    {
        if (!_wcsicmp(p->val[P_ENABLE], L"yes")) r->Enabled = TRUE; else if (!_wcsicmp(p->val[P_ENABLE], L"no")) r->Enabled = FALSE;
        else { e->pfx = IDS_PFX_VALUE; return FALSE; }
    }
    if (p->has[P_PROFILE])
    {
        LONG m;
        if (!ParseProfiles(p->val[P_PROFILE], &m)) { e->pfx = IDS_MSG_BADPROFILE; e->full = TRUE; return FALSE; }
        r->Profiles = m;
    }
    if (p->has[P_LOCALIP])
    {
        if (FwCheckAddrs(p->val[P_LOCALIP])) { e->pfx = IDS_PFX_IP; return FALSE; }
        FwRuleSetStr(&r->LAddr, !_wcsicmp(p->val[P_LOCALIP], L"any") ? NULL : p->val[P_LOCALIP]);
    }
    if (p->has[P_REMOTEIP])
    {
        if (FwCheckAddrs(p->val[P_REMOTEIP])) { e->pfx = IDS_PFX_IP; return FALSE; }
        FwRuleSetStr(&r->RAddr, !_wcsicmp(p->val[P_REMOTEIP], L"any") ? NULL : p->val[P_REMOTEIP]);
    }
    if (p->has[P_LOCALPORT])
    {
        if (FwCheckPorts(p->val[P_LOCALPORT])) { e->pfx = IDS_PFX_PORT; return FALSE; }
        FwRuleSetStr(&r->LPorts, !_wcsicmp(p->val[P_LOCALPORT], L"any") ? NULL : p->val[P_LOCALPORT]);
    }
    if (p->has[P_REMOTEPORT])
    {
        if (FwCheckPorts(p->val[P_REMOTEPORT])) { e->pfx = IDS_PFX_PORT; return FALSE; }
        FwRuleSetStr(&r->RPorts, !_wcsicmp(p->val[P_REMOTEPORT], L"any") ? NULL : p->val[P_REMOTEPORT]);
    }
    if (protoGiven)
    {
        if (!ParseProtocol(p->val[P_PROTOCOL], &proto, icmp, _countof(icmp))) { e->pfx = IDS_PFX_PROTO; return FALSE; }
        r->Protocol = proto;
        FwRuleSetStr(&r->Icmp, icmp[0] ? icmp : NULL);
    }
    if (p->has[P_IFTYPE])
    {
        WCHAR *copy = _wcsdup(p->val[P_IFTYPE]), *tok, list[64]; BOOL ok = TRUE, any = FALSE;
        list[0] = 0;
        if (!copy) return FALSE;
        for (tok = wcstok(copy, L","); tok; tok = wcstok(NULL, L","))
        {
            PCWSTR n = NULL;
            if (!_wcsicmp(tok, L"lan")) n = L"Lan"; else if (!_wcsicmp(tok, L"wireless")) n = L"Wireless";
            else if (!_wcsicmp(tok, L"ras")) n = L"RemoteAccess"; else if (!_wcsicmp(tok, L"any")) any = TRUE; else ok = FALSE;
            if (n) { if (list[0]) wcscat(list, L","); wcscat(list, n); }
        }
        free(copy);
        if (!ok || (any && list[0])) { e->pfx = IDS_PFX_IFTYPE; return FALSE; }
        FwRuleSetStr(&r->IfTypes, any ? NULL : list);
    }
    if (p->has[P_RMTCOMP]) FwrSet(&r->Raw, L"RMauth", *p->val[P_RMTCOMP] ? p->val[P_RMTCOMP] : NULL);
    if (p->has[P_RMTUSR]) FwrSet(&r->Raw, L"RUAuth", *p->val[P_RMTUSR] ? p->val[P_RMTUSR] : NULL);
    if (p->has[P_EDGE])
    {
        PCWSTR v = p->val[P_EDGE];
        if (!_wcsicmp(v, L"yes")) { r->Edge = TRUE; FwrRemove(&r->Raw, L"Defer"); }
        else if (!_wcsicmp(v, L"deferapp")) { r->Edge = TRUE; FwrSet(&r->Raw, L"Defer", L"App"); }
        else if (!_wcsicmp(v, L"deferuser")) { r->Edge = TRUE; FwrSet(&r->Raw, L"Defer", L"User"); }
        else if (!_wcsicmp(v, L"no")) { r->Edge = FALSE; FwrRemove(&r->Raw, L"Defer"); }
        else { e->pfx = IDS_PFX_VALUE; return FALSE; }
    }
    if (p->has[P_SECURITY])
    {
        PCWSTR v = p->val[P_SECURITY], s = NULL;
        if (!_wcsicmp(v, L"authenticate")) s = L"Authenticate"; else if (!_wcsicmp(v, L"authenc")) s = L"AuthEnc";
        else if (!_wcsicmp(v, L"authdynenc")) s = L"AuthDynEnc"; else if (!_wcsicmp(v, L"authnoencap")) s = L"AuthNoEncap";
        else if (_wcsicmp(v, L"notrequired")) { e->pfx = IDS_PFX_SECURITY; return FALSE; }
        FwrSet(&r->Raw, L"Security", s);
    }
    /* cross checks */
    if ((p->has[P_LOCALPORT] || p->has[P_REMOTEPORT]) && !IsPortProto(r->Protocol)) { e->pfx = IDS_PFX_PORTPROTO; return FALSE; }
    if (isSet && protoGiven && !IsPortProto(r->Protocol) && ((r->LPorts && *r->LPorts) || (r->RPorts && *r->RPorts)))
    { e->pfx = IDS_PFX_PROTOMISMATCH; return FALSE; }
    if (r->Edge && r->Dir != 1) { e->pfx = IDS_PFX_FLAGS; return FALSE; }
    return TRUE;
}

/* ---------------------------------------------------------------- rule matching and display */

static PWSTR Resolve(PCWSTR s)
{
    WCHAR buf[512];
    if (s && s[0] == L'@')
    {
        buf[0] = 0;
        if (SUCCEEDED(SHLoadIndirectString(s, buf, _countof(buf), NULL)) && buf[0])
        { PWSTR d = _wcsdup(buf); if (d) return d; }
    }
    return _wcsdup(s ? s : L"");
}

static BOOL EqI(PCWSTR a, PCWSTR b) { return !_wcsicmp(a ? a : L"", b ? b : L""); }

static BOOL SameAddrs(const FW_RULE *r, const FW_RULE *f, BOOL local)
{
    FWR a, b; BOOL same = TRUE; PCWSTR k[2];
    ULONG i, j;
    k[0] = local ? L"LA4" : L"RA4"; k[1] = local ? L"LA6" : L"RA6";
    FwRuleToRaw(r, &a); FwRuleToRaw(f, &b);
    for (i = 0; i < 2; i++)
    {
        if (FwrCount(&a, k[i]) != FwrCount(&b, k[i])) { same = FALSE; break; }
        for (j = 0; j < FwrCount(&a, k[i]); j++) if (!EqI(FwrGet(&a, k[i], j), FwrGet(&b, k[i], j))) same = FALSE;
    }
    FwrFree(&a); FwrFree(&b);
    return same;
}

typedef struct _FILTER
{
    const PARAMS *p;
    FW_RULE tmpl;       /* typed form of the address/port/protocol filters */
    LONG profiles;
    LONG dir;
} FILTER;

static BOOL RuleMatches(const FW_RULE *r, const FILTER *f)
{
    const PARAMS *p = f->p;
    if (p->has[P_NAME] && _wcsicmp(p->val[P_NAME], L"all"))
    {
        PWSTR n = Resolve(r->Name); BOOL ok = EqI(n, p->val[P_NAME]); free(n);
        if (!ok) return FALSE;
    }
    else if (!p->has[P_NAME] && !p->has[P_GROUP] && p->positional)
    {
        PWSTR n = Resolve(r->Name); BOOL ok = EqI(n, p->positional); free(n);
        if (!ok) return FALSE;
    }
    if (p->has[P_GROUP]) { PWSTR g = Resolve(r->Group); BOOL ok = EqI(g, p->val[P_GROUP]); free(g); if (!ok) return FALSE; }
    if (p->has[P_DIR] && r->Dir != f->dir) return FALSE;
    if (p->has[P_PROFILE] && !(((r->Profiles == FWP_ANY_COM) ? FWP_ALL : r->Profiles) & ((f->profiles == FWP_ANY_COM) ? FWP_ALL : f->profiles))) return FALSE;
    if (p->has[P_PROGRAM] && !EqI(r->App, p->val[P_PROGRAM])) return FALSE;
    if (p->has[P_SERVICE] && !EqI(r->Svc, !_wcsicmp(p->val[P_SERVICE], L"any") ? L"*" : p->val[P_SERVICE])) return FALSE;
    if (p->has[P_PROTOCOL] && r->Protocol != f->tmpl.Protocol) return FALSE;
    if (p->has[P_LOCALPORT] && !EqI(r->LPorts, f->tmpl.LPorts)) return FALSE;
    if (p->has[P_REMOTEPORT] && !EqI(r->RPorts, f->tmpl.RPorts)) return FALSE;
    if (p->has[P_LOCALIP] && !SameAddrs(r, &f->tmpl, TRUE)) return FALSE;
    if (p->has[P_REMOTEIP] && !SameAddrs(r, &f->tmpl, FALSE)) return FALSE;
    return TRUE;
}

/* validate the filter values; fills the typed template */
static BOOL BuildFilter(FILTER *f, const PARAMS *p, PERR *e, UINT usage)
{
    PARAMS q = *p;
    memset(f, 0, sizeof(*f));
    f->p = p; f->profiles = FWP_ANY_COM; f->dir = 1;
    FwRuleInit(&f->tmpl);
    q.has[P_NAME] = FALSE; q.has[P_ACTION] = FALSE; q.has[P_ENABLE] = FALSE; q.has[P_DESC] = FALSE; q.has[P_GROUP] = FALSE;
    q.has[P_TYPE] = FALSE; q.has[P_STATUS] = FALSE;
    if (p->has[P_TYPE] && _wcsicmp(p->val[P_TYPE], L"static") && _wcsicmp(p->val[P_TYPE], L"dynamic"))
    { e->pfx = IDS_PFX_VALUE; e->usage = usage; e->full = FALSE; return FALSE; }
    if (!ApplyParams(&f->tmpl, &q, FALSE, e, usage)) return FALSE;
    f->dir = f->tmpl.Dir; f->profiles = f->tmpl.Profiles;
    return TRUE;
}

static const WCHAR g_Dashes[] = L"----------------------------------------------------------------------";

static VOID Line(PCWSTR label, PCWSTR value)
{
    WCHAR b[1400];
    _swprintf(b, L"%-37s %s\n", label, value);
    Out(b);
}

static VOID ShowRule(const FW_RULE *r, BOOL verbose)
{
    PWSTR name = Resolve(r->Name), grp = Resolve(r->Group), desc = Resolve(r->Desc);
    WCHAR prof[64] = L"", tmp[512];
    LONG pm = (r->Profiles == FWP_ANY_COM) ? FWP_ALL : r->Profiles;
    PCWSTR proto, ed;

    Out(L"\n");
    Line(L"Rule Name:", name);
    Out(g_Dashes); Out(L"\n");
    if (verbose) Line(L"Description:", desc);
    Line(L"Enabled:", r->Enabled ? L"Yes" : L"No");
    Line(L"Direction:", r->Dir == 2 ? L"Out" : L"In");
    if (pm & FWP_DOMAIN) wcscat(prof, L"Domain");
    if (pm & FWP_PRIVATE) { if (prof[0]) wcscat(prof, L","); wcscat(prof, L"Private"); }
    if (pm & FWP_PUBLIC) { if (prof[0]) wcscat(prof, L","); wcscat(prof, L"Public"); }
    Line(L"Profiles:", prof);
    Line(L"Grouping:", grp);
    /* addresses: single IPv4 as /32, masks as prefix lengths */
    {
        int side;
        for (side = 0; side < 2; side++)
        {
            FWR raw; WCHAR list[1024]; ULONG i; PCWSTR k4 = side ? L"RA4" : L"LA4", k6 = side ? L"RA6" : L"LA6";
            list[0] = 0;
            FwRuleToRaw(r, &raw);
            for (i = 0; i < FwrCount(&raw, k4); i++)
            {
                PCWSTR v = FwrGet(&raw, k4, i); WCHAR one[96];
                ULONG a, b, c, d, m1, m2, m3, m4;
                if (wcslen(list) > 900) break;
                if (swscanf(v, L"%u.%u.%u.%u/%u.%u.%u.%u", &a, &b, &c, &d, &m1, &m2, &m3, &m4) == 8)
                {
                    ULONG m = (m1 << 24) | (m2 << 16) | (m3 << 8) | m4, pl = 0;
                    while (m & 0x80000000) { pl++; m <<= 1; }
                    _swprintf(one, L"%u.%u.%u.%u/%u", a, b, c, d, pl);
                }
                else if (swscanf(v, L"%u.%u.%u.%u", &a, &b, &c, &d) == 4 && !wcschr(v, L'-')) _swprintf(one, L"%s/32", v);
                else wcscpy(one, v);
                if (list[0]) wcscat(list, L","); wcscat(list, one);
            }
            for (i = 0; i < FwrCount(&raw, k6); i++)
            {
                PCWSTR v = FwrGet(&raw, k6, i);
                if (wcslen(list) > 900) break;
                /* keywords were already listed for IPv4 */
                if (!wcschr(v, L':') && !wcschr(v, L'.')) continue;
                if (list[0]) wcscat(list, L","); wcscat(list, v);
            }
            FwrFree(&raw);
            Line(side ? L"RemoteIP:" : L"LocalIP:", list[0] ? list : L"Any");
        }
    }
    switch (r->Protocol)
    {
        case 6: proto = L"TCP"; break; case 17: proto = L"UDP"; break; case 1: proto = L"ICMPv4"; break;
        case 58: proto = L"ICMPv6"; break; case 256: proto = L"Any"; break;
        default: _swprintf(tmp, L"%d", r->Protocol); proto = tmp; break;
    }
    Line(L"Protocol:", proto);
    if (r->Protocol == 1 || r->Protocol == 58)
    {
        if (r->Icmp && *r->Icmp)
        {
            WCHAR *copy = _wcsdup(r->Icmp), *tok, b[200];
            WCHAR pad[40]; int i;
            for (i = 0; i < 38; i++) pad[i] = L' ';
            pad[38] = 0;
            _swprintf(b, L"%sType    Code\n", pad); Out(b);
            for (tok = wcstok(copy, L","); tok; tok = wcstok(NULL, L","))
            {
                WCHAR t[16], c[16]; PCWSTR col = wcschr(tok, L':');
                if (col) { wcsncpy(t, tok, col - tok); t[col - tok] = 0; wcscpy(c, col + 1); } else { wcscpy(t, tok); wcscpy(c, L"*"); }
                if (!wcscmp(t, L"*")) wcscpy(t, L"Any");
                if (!wcscmp(c, L"*")) wcscpy(c, L"Any");
                _swprintf(b, L"%s%-8s%s \n", pad, t, c); Out(b);
            }
            free(copy);
        }
    }
    else if (r->Protocol == 6 || r->Protocol == 17)
    {
        Line(L"LocalPort:", r->LPorts ? r->LPorts : L"Any");
        Line(L"RemotePort:", r->RPorts ? r->RPorts : L"Any");
    }
    ed = L"No";
    if (r->Edge)
    {
        PCWSTR d = FwrGet(&r->Raw, L"Defer", 0);
        ed = !d ? L"Yes" : (!_wcsicmp(d, L"App") ? L"Defer to application" : L"Defer to user");
    }
    Line(L"Edge traversal:", ed);
    if (verbose)
    {
        PCWSTR sec = FwrGet(&r->Raw, L"Security", 0);
        if (r->App) Line(L"Program:", r->App);
        if (r->Svc) Line(L"Service:", wcscmp(r->Svc, L"*") ? r->Svc : L"Any");
        {
            WCHAR it[64]; it[0] = 0;
            if (r->IfTypes && _wcsicmp(r->IfTypes, L"All"))
            {
                WCHAR *copy = _wcsdup(r->IfTypes), *tok;
                for (tok = wcstok(copy, L","); tok; tok = wcstok(NULL, L","))
                {
                    if (it[0]) wcscat(it, L",");
                    wcscat(it, !_wcsicmp(tok, L"Lan") ? L"LAN" : (!_wcsicmp(tok, L"RemoteAccess") ? L"RAS" : tok));
                }
                free(copy);
            }
            Line(L"InterfaceTypes:", it[0] ? it : L"Any");
        }
        Line(L"Security:", sec ? sec : L"NotRequired");
        Line(L"Rule source:", L"Local Setting");
    }
    Line(L"Action:", r->Action ? L"Allow" : L"Block");
    free(name); free(grp); free(desc);
}

/* ---------------------------------------------------------------- commands: firewall context */

static DWORD WINAPI AddRule(LPCWSTR m, LPWSTR *argv, DWORD cur, DWORD cnt, DWORD fl, LPCVOID pv, BOOL *pDone)
{
    PARAMS p; PCWSTR bogus = NULL; int pe; FW_RULE r; PERR e; DWORD err;
    if (cnt - cur < 1) return Fail(IDS_PFX_NUMARGS, IDS_USG_ADDRULE, FALSE);
    pe = ParseParams(argv, cur, cnt, MASK_RULE, FALSE, &p, &bogus);
    if (pe) return ReportParseError(pe, bogus);
    if (!p.has[P_NAME] || !*p.val[P_NAME] || !p.has[P_DIR] || !*p.val[P_DIR] || !p.has[P_ACTION] || !*p.val[P_ACTION])
    { OutRes(IDS_MSG_ESSENTIAL); return ERROR_SUPPRESS_OUTPUT; }
    FwRuleInit(&r);
    r.Enabled = TRUE;
    if (!ApplyParams(&r, &p, FALSE, &e, IDS_USG_ADDRULE))
    {
        FwRuleFree(&r);
        if (e.full) { OutRes(e.pfx); return ERROR_SUPPRESS_OUTPUT; }
        return Fail(e.pfx, e.usage, FALSE);
    }
    err = FwStoreAdd(&r);
    FwRuleFree(&r);
    if (err) return err;
    OutRes(IDS_MSG_OK_ADD);
    return ERROR_SUCCESS;
}

static DWORD LoadMatches(const FILTER *f, FW_RULESET *all, ULONG **idx, ULONG *n)
{
    ULONG i;
    DWORD err = FwStoreLoad(all);
    if (err) return err;
    *idx = HeapAlloc(GetProcessHeap(), 0, (all->N + 1) * sizeof(ULONG));
    *n = 0;
    if (!*idx) { FwRuleSetFree(all); return ERROR_NOT_ENOUGH_MEMORY; }
    for (i = 0; i < all->N; i++) if (RuleMatches(&all->R[i], f)) (*idx)[(*n)++] = i;
    return 0;
}

static DWORD WINAPI DeleteRule(LPCWSTR m, LPWSTR *argv, DWORD cur, DWORD cnt, DWORD fl, LPCVOID pv, BOOL *pDone)
{
    PARAMS p; PCWSTR bogus = NULL; int pe; FILTER f; PERR e; FW_RULESET rs; ULONG *idx, n, i; DWORD err;
    if (cnt - cur < 1) return Fail(IDS_PFX_NUMARGS, IDS_USG_DELRULE, FALSE);
    pe = ParseParams(argv, cur, cnt, MASK_FILTER, FALSE, &p, &bogus);
    if (pe) return ReportParseError(pe, bogus);
    if (!p.has[P_NAME]) { OutRes(IDS_MSG_ESSENTIAL); return ERROR_SUPPRESS_OUTPUT; }
    if (!BuildFilter(&f, &p, &e, IDS_USG_DELRULE))
    {
        FwRuleFree(&f.tmpl);
        if (e.full) { OutRes(e.pfx); return ERROR_SUPPRESS_OUTPUT; }
        return Fail(e.pfx, e.usage, FALSE);
    }
    err = LoadMatches(&f, &rs, &idx, &n);
    FwRuleFree(&f.tmpl);
    if (err) return err;
    if (!n) { OutRes(IDS_MSG_NORULES); FwRuleSetFree(&rs); HeapFree(GetProcessHeap(), 0, idx); return ERROR_SUPPRESS_OUTPUT; }
    for (i = 0; i < n; i++) { err = FwStoreDelete(rs.R[idx[i]].Id); if (err) break; }
    FwRuleSetFree(&rs); HeapFree(GetProcessHeap(), 0, idx);
    if (err) return err;
    OutResCount(IDS_MSG_DEL_DELETED, n);
    return ERROR_SUCCESS;
}

static DWORD WINAPI ShowRuleCmd(LPCWSTR m, LPWSTR *argv, DWORD cur, DWORD cnt, DWORD fl, LPCVOID pv, BOOL *pDone)
{
    PARAMS p; PCWSTR bogus = NULL; int pe; FILTER f; PERR e; FW_RULESET rs; ULONG *idx, n, i; DWORD err;
    if (cnt - cur < 1) return Fail(IDS_PFX_NUMARGS, IDS_USG_SHOWRULE, FALSE);
    pe = ParseParams(argv, cur, cnt, MASK_SHOW, TRUE, &p, &bogus);
    if (pe) return ReportParseError(pe, bogus);
    if (!p.has[P_NAME] && !p.positional)
    {
        if (p.verbose && cnt - cur == 1) { OutRes(IDS_MSG_NOMEM); return ERROR_SUPPRESS_OUTPUT; }
        OutRes(IDS_MSG_ESSENTIAL); return ERROR_SUPPRESS_OUTPUT;
    }
    if (!BuildFilter(&f, &p, &e, IDS_USG_SHOWRULE))
    {
        FwRuleFree(&f.tmpl);
        if (e.full) { OutRes(e.pfx); return ERROR_SUPPRESS_OUTPUT; }
        return Fail(e.pfx, e.usage, FALSE);
    }
    err = LoadMatches(&f, &rs, &idx, &n);
    FwRuleFree(&f.tmpl);
    if (err) return err;
    if (!n) { OutRes(IDS_MSG_NORULES); FwRuleSetFree(&rs); HeapFree(GetProcessHeap(), 0, idx); return ERROR_SUPPRESS_OUTPUT; }
    for (i = 0; i < n; i++) ShowRule(&rs.R[idx[i]], p.verbose);
    OutRes(IDS_MSG_OK_ADD);   /* "Ok.\n\n" */
    FwRuleSetFree(&rs); HeapFree(GetProcessHeap(), 0, idx);
    return ERROR_SUCCESS;
}

static DWORD WINAPI SetRule(LPCWSTR m, LPWSTR *argv, DWORD cur, DWORD cnt, DWORD fl, LPCVOID pv, BOOL *pDone)
{
    PARAMS sel, nw; PCWSTR bogus = NULL; int pe; FILTER f; PERR e; FW_RULESET rs; ULONG *idx, n, i; DWORD err, k, newPos = cnt;
    if (cnt - cur < 1) return Fail(IDS_PFX_NUMARGS, IDS_USG_SETRULE, FALSE);
    for (k = cur; k < cnt; k++) if (!_wcsicmp(argv[k], L"new")) { newPos = k; break; }
    if (newPos == cnt || newPos + 1 >= cnt) return Fail(IDS_PFX_SETNEW, IDS_USG_SETRULE, FALSE);
    pe = ParseParams(argv, cur, newPos, MASK_SETSEL, FALSE, &sel, &bogus);
    if (pe) return ReportParseError(pe, bogus);
    pe = ParseParams(argv, newPos + 1, cnt, MASK_RULE, FALSE, &nw, &bogus);
    if (pe) return ReportParseError(pe, bogus);
    if (!sel.has[P_NAME] && !sel.has[P_GROUP]) { OutRes(IDS_MSG_ESSENTIAL); return ERROR_SUPPRESS_OUTPUT; }
    if (!BuildFilter(&f, &sel, &e, IDS_USG_SETRULE))
    {
        FwRuleFree(&f.tmpl);
        if (e.full) { OutRes(e.pfx); return ERROR_SUPPRESS_OUTPUT; }
        return Fail(e.pfx, e.usage, FALSE);
    }
    err = LoadMatches(&f, &rs, &idx, &n);
    FwRuleFree(&f.tmpl);
    if (err) return err;
    if (!n) { OutRes(IDS_MSG_NORULES); FwRuleSetFree(&rs); HeapFree(GetProcessHeap(), 0, idx); return ERROR_SUPPRESS_OUTPUT; }
    /* validate against every matching rule first, then write */
    for (i = 0; i < n; i++)
    {
        FW_RULE c; BOOL ok;
        FwRuleInit(&c); FwRuleCopy(&c, &rs.R[idx[i]]);
        ok = ApplyParams(&c, &nw, TRUE, &e, IDS_USG_SETRULE);
        if (ok) { FwRuleFree(&rs.R[idx[i]]); rs.R[idx[i]] = c; }
        else
        {
            FwRuleFree(&c); FwRuleSetFree(&rs); HeapFree(GetProcessHeap(), 0, idx);
            if (e.full) { OutRes(e.pfx); return ERROR_SUPPRESS_OUTPUT; }
            return Fail(e.pfx, e.usage, FALSE);
        }
    }
    for (i = 0; i < n; i++) { err = FwStoreUpdate(&rs.R[idx[i]]); if (err) break; }
    FwRuleSetFree(&rs); HeapFree(GetProcessHeap(), 0, idx);
    if (err) return err;
    OutResCount(IDS_MSG_SET_UPDATED, n);
    return ERROR_SUCCESS;
}

/* ---------------------------------------------------------------- profiles */

static PCWSTR ProfileTitle(ULONG bit) { return bit == FWP_DOMAIN ? L"Domain" : (bit == FWP_PRIVATE ? L"Private" : L"Public"); }

enum { SEC_STATE = 1, SEC_POLICY = 2, SEC_SETTINGS = 4, SEC_LOGGING = 8, SEC_ALL = 15 };

static BOOL RemoteAdminEnabled(ULONG bit)
{
    WCHAR path[300]; HKEY hk; DWORD v = 0, cb = 4, t;
    _swprintf(path, L"%s\\RemoteAdminSettings", FwProfileKey(bit));
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &hk) == 0)
    { if (RegQueryValueExW(hk, L"Enabled", NULL, &t, (BYTE *)&v, &cb) != 0) v = 0; RegCloseKey(hk); }
    return v != 0;
}

static VOID ShowProfileBlock(ULONG bit, DWORD sec)
{
    FW_PROFILE p; WCHAR b[400];
    FwProfileLoad(bit, &p);
    _swprintf(b, L"\n%s Profile Settings: \n", ProfileTitle(bit)); Out(b);
    Out(g_Dashes); Out(L"\n");
    if (sec & SEC_STATE) Line(L"State", p.Enable ? L"ON" : L"OFF");
    if (sec & SEC_POLICY)
        Line(L"Firewall Policy", p.DefaultInbound ? (p.DoNotAllowExceptions ? (p.DefaultOutbound ? L"BlockInboundAlways,BlockOutbound" : L"BlockInboundAlways,AllowOutbound")
                                                                          : (p.DefaultOutbound ? L"BlockInbound,BlockOutbound" : L"BlockInbound,AllowOutbound"))
                                  : (p.DefaultOutbound ? L"AllowInbound,BlockOutbound" : L"AllowInbound,AllowOutbound"));
    if (sec & SEC_SETTINGS)
    {
        Line(L"LocalFirewallRules", L"N/A (GPO-store only)");
        Line(L"LocalConSecRules", L"N/A (GPO-store only)");
        Line(L"InboundUserNotification", p.DisableNotifications ? L"Disable" : L"Enable");
        Line(L"RemoteManagement", RemoteAdminEnabled(bit) ? L"Enable" : L"Disable");
        Line(L"UnicastResponseToMulticast", p.DisableUnicastResponses ? L"Disable" : L"Enable");
    }
    if (sec == SEC_ALL) Out(L"\n");
    if (sec & SEC_LOGGING)
    {
        WCHAR n[16];
        if (sec == SEC_ALL) Out(L"Logging:\n");
        Line(L"LogAllowedConnections", p.LogSuccess ? L"Enable" : L"Disable");
        Line(L"LogDroppedConnections", p.LogDropped ? L"Enable" : L"Disable");
        Line(L"FileName", p.LogFile);
        _swprintf(n, L"%u", p.LogFileSize);
        Line(L"MaxFileSize", n);
    }
    if (sec == SEC_ALL) Out(L"\n");
}

static DWORD ShowProfile(ULONG bits, LPWSTR *argv, DWORD cur, DWORD cnt, UINT helpId)
{
    DWORD sec = SEC_ALL, left = cnt - cur;
    ULONG b;
    if (left > 1) return Fail(IDS_PFX_SHOWNUMARGS, helpId, TRUE);
    if (left == 1)
    {
        if (!_wcsicmp(argv[cur], L"state")) sec = SEC_STATE;
        else if (!_wcsicmp(argv[cur], L"firewallpolicy")) sec = SEC_POLICY;
        else if (!_wcsicmp(argv[cur], L"settings")) sec = SEC_SETTINGS;
        else if (!_wcsicmp(argv[cur], L"logging")) sec = SEC_LOGGING;
        else return Fail(IDS_PFX_SHOWVALUE, helpId, TRUE);
    }
    for (b = 1; b <= 4; b <<= 1) if (bits & b) ShowProfileBlock(b, sec);
    OutRes(IDS_MSG_OK_ADD);
    return ERROR_SUCCESS;
}

#define SHOWFN(fn, bits, id) \
static DWORD WINAPI fn(LPCWSTR m, LPWSTR *argv, DWORD cur, DWORD cnt, DWORD fl, LPCVOID pv, BOOL *pDone) \
{ return ShowProfile(bits, argv, cur, cnt, id); }
SHOWFN(ShowAll, FWP_ALL, IDS_HLP_SHOW_ALL)
SHOWFN(ShowDomain, FWP_DOMAIN, IDS_HLP_SHOW_DOM)
SHOWFN(ShowPrivate, FWP_PRIVATE, IDS_HLP_SHOW_PRIV)
SHOWFN(ShowPublic, FWP_PUBLIC, IDS_HLP_SHOW_PUB)

static DWORD WINAPI ShowCurrent(LPCWSTR m, LPWSTR *argv, DWORD cur, DWORD cnt, DWORD fl, LPCVOID pv, BOOL *pDone)
{ return ShowProfile(FwCurrentProfiles(), argv, cur, cnt, IDS_HLP_SHOW_CUR); }

static DWORD WINAPI ShowGlobal(LPCWSTR m, LPWSTR *argv, DWORD cur, DWORD cnt, DWORD fl, LPCVOID pv, BOOL *pDone)
{ OutRes(IDS_OUT_SHOW_GLOBAL); return ERROR_SUCCESS; }

static DWORD WINAPI ShowStore(LPCWSTR m, LPWSTR *argv, DWORD cur, DWORD cnt, DWORD fl, LPCVOID pv, BOOL *pDone)
{ OutRes(IDS_OUT_SHOW_STORE); return ERROR_SUCCESS; }

/* set <profile> state|firewallpolicy|settings|logging ...   (PROVISIONAL: not probed on the reference machine) */
static BOOL YesNo(PCWSTR s, PCWSTR yes, PCWSTR no, DWORD *v)
{
    if (!_wcsicmp(s, yes)) { *v = 1; return TRUE; }
    if (!_wcsicmp(s, no)) { *v = 0; return TRUE; }
    return FALSE;
}

static DWORD SetProfileCmd(ULONG bits, LPWSTR *argv, DWORD cur, DWORD cnt, UINT helpId)
{
    DWORD left = cnt - cur, v, err = 0; ULONG b;
    if (left < 2) return Fail(IDS_PFX_NUMARGS, helpId, TRUE);
    if (!_wcsicmp(argv[cur], L"state"))
    {
        if (left != 2 || !YesNo(argv[cur + 1], L"on", L"off", &v)) return Fail(IDS_PFX_VALUE, helpId, TRUE);
        for (b = 1; b <= 4 && !err; b <<= 1) if (bits & b) err = FwProfileSetDword(b, L"EnableFirewall", v, FALSE);
    }
    else if (!_wcsicmp(argv[cur], L"firewallpolicy"))
    {
        WCHAR *copy = _wcsdup(argv[cur + 1]), *tok; DWORD in = 2, out = 2, dna = 2;   /* 2 = unchanged */
        BOOL ok = left == 2 && copy != NULL;
        for (tok = ok ? wcstok(copy, L",") : NULL; tok; tok = wcstok(NULL, L","))
        {
            if (!_wcsicmp(tok, L"blockinbound")) { in = 1; dna = 0; }
            else if (!_wcsicmp(tok, L"blockinboundalways")) { in = 1; dna = 1; }
            else if (!_wcsicmp(tok, L"allowinbound")) { in = 0; dna = 0; }
            else if (!_wcsicmp(tok, L"allowoutbound")) out = 0;
            else if (!_wcsicmp(tok, L"blockoutbound")) out = 1;
            else ok = FALSE;
        }
        free(copy);
        if (!ok || (in == 2 && out == 2)) return Fail(IDS_PFX_POLICY, helpId, TRUE);
        for (b = 1; b <= 4 && !err; b <<= 1) if (bits & b)
        {
            if (in != 2) err = FwProfileSetDword(b, L"DefaultInboundAction", in, FALSE);
            if (!err && dna != 2) err = FwProfileSetDword(b, L"DoNotAllowExceptions", dna, FALSE);
            if (!err && out != 2) err = FwProfileSetDword(b, L"DefaultOutboundAction", out, FALSE);
        }
    }
    else if (!_wcsicmp(argv[cur], L"settings"))
    {
        PCWSTR nm = NULL; BOOL inv = FALSE;
        if (left != 3) return Fail(IDS_PFX_NUMARGS, helpId, TRUE);
        if (!YesNo(argv[cur + 2], L"enable", L"disable", &v)) return Fail(IDS_PFX_VALUE, helpId, TRUE);
        if (!_wcsicmp(argv[cur + 1], L"inboundusernotification")) { nm = L"DisableNotifications"; inv = TRUE; }
        else if (!_wcsicmp(argv[cur + 1], L"unicastresponsetomulticast")) { nm = L"DisableUnicastResponsesToMulticastBroadcast"; inv = TRUE; }
        else if (!_wcsicmp(argv[cur + 1], L"remotemanagement")) nm = L"RemoteAdminSettings";
        else return Fail(IDS_PFX_VALUE, helpId, TRUE);
        for (b = 1; b <= 4 && !err; b <<= 1) if (bits & b)
        {
            if (inv) err = FwProfileSetDword(b, nm, !v, FALSE);
            else
            {
                WCHAR path[300]; HKEY hk; DWORD disp;
                _swprintf(path, L"%s\\RemoteAdminSettings", FwProfileKey(b));
                err = RegCreateKeyExW(HKEY_LOCAL_MACHINE, path, 0, NULL, 0, KEY_SET_VALUE, NULL, &hk, &disp);
                if (!err) { err = RegSetValueExW(hk, L"Enabled", 0, REG_DWORD, (BYTE *)&v, 4); RegCloseKey(hk); }
            }
        }
    }
    else if (!_wcsicmp(argv[cur], L"logging"))
    {
        if (left != 3) return Fail(IDS_PFX_NUMARGS, helpId, TRUE);
        if (!_wcsicmp(argv[cur + 1], L"allowedconnections") || !_wcsicmp(argv[cur + 1], L"droppedconnections"))
        {
            PCWSTR nm = !_wcsicmp(argv[cur + 1], L"allowedconnections") ? L"LogSuccessfulConnections" : L"LogDroppedPackets";
            if (!YesNo(argv[cur + 2], L"enable", L"disable", &v)) return Fail(IDS_PFX_VALUE, helpId, TRUE);
            for (b = 1; b <= 4 && !err; b <<= 1) if (bits & b) err = FwProfileSetDword(b, nm, v, TRUE);
        }
        else if (!_wcsicmp(argv[cur + 1], L"filename"))
        {
            if (wcspbrk(argv[cur + 2], L"?*\"<>|") || !*argv[cur + 2]) { OutRes(IDS_MSG_UNRECOVERABLE); return ERROR_SUPPRESS_OUTPUT; }
            for (b = 1; b <= 4 && !err; b <<= 1) if (bits & b) err = FwProfileSetString(b, L"LogFilePath", argv[cur + 2], TRUE);
        }
        else if (!_wcsicmp(argv[cur + 1], L"maxfilesize"))
        {
            PCWSTR s = argv[cur + 2]; ULONG n = 0;
            if (!*s) return Fail(IDS_PFX_NUMERIC, helpId, TRUE);
            for (; *s; s++) { if (*s < L'0' || *s > L'9') return Fail(IDS_PFX_NUMERIC, helpId, TRUE); n = n * 10 + (*s - L'0'); if (n > 99999999) break; }
            if (n < 1 || n > 32767) return Fail(IDS_PFX_VALUE, helpId, TRUE);
            for (b = 1; b <= 4 && !err; b <<= 1) if (bits & b) err = FwProfileSetDword(b, L"LogFileSize", n, TRUE);
        }
        else return Fail(IDS_PFX_VALUE, helpId, TRUE);
    }
    else return Fail(IDS_PFX_VALUE, helpId, TRUE);
    if (err) return err;
    OutRes(IDS_MSG_OK_ADD);   /* PROVISIONAL: "Ok.\n\n" like every other successful change */
    return ERROR_SUCCESS;
}

#define SETFN(fn, bits, id) \
static DWORD WINAPI fn(LPCWSTR m, LPWSTR *argv, DWORD cur, DWORD cnt, DWORD fl, LPCVOID pv, BOOL *pDone) \
{ return SetProfileCmd(bits, argv, cur, cnt, id); }
SETFN(SetAll, FWP_ALL, IDS_HLP_SET_ALL)
SETFN(SetDomain, FWP_DOMAIN, IDS_HLP_SET_DOM)
SETFN(SetPrivate, FWP_PRIVATE, IDS_HLP_SET_PRIV)
SETFN(SetPublic, FWP_PUBLIC, IDS_HLP_SET_PUB)
static DWORD WINAPI SetCurrent(LPCWSTR m, LPWSTR *argv, DWORD cur, DWORD cnt, DWORD fl, LPCVOID pv, BOOL *pDone)
{ return SetProfileCmd(FwCurrentProfiles(), argv, cur, cnt, IDS_HLP_SET_CUR); }

static DWORD WINAPI NotSupported(LPCWSTR m, LPWSTR *argv, DWORD cur, DWORD cnt, DWORD fl, LPCVOID pv, BOOL *pDone)
{ return ERROR_NOT_SUPPORTED; }

static DWORD WINAPI ResetCmd(LPCWSTR m, LPWSTR *argv, DWORD cur, DWORD cnt, DWORD fl, LPCVOID pv, BOOL *pDone)
{
    DWORD err;
    if (cnt - cur != 0) return ERROR_NOT_SUPPORTED;    /* reset export <file> is not implemented */
    err = FwResetAll();
    if (err) return err;
    OutRes(IDS_MSG_OK_ADD);   /* PROVISIONAL */
    return ERROR_SUCCESS;
}

/* ---------------------------------------------------------------- tables and registration */

static CMD_ENTRY g_FwAdd[]    = { { L"rule", AddRule,     IDS_SH_FW_ADD,    IDS_HLP_ADDRULE,  0, NULL } };
static CMD_ENTRY g_FwDelete[] = { { L"rule", DeleteRule,  IDS_SH_FW_DELETE, IDS_HLP_DELRULE,  0, NULL } };
static CMD_ENTRY g_FwSet[]    = { { L"rule", SetRule,     IDS_SH_FW_SET,    IDS_HLP_SETRULE,  0, NULL } };
static CMD_ENTRY g_FwShow[]   = { { L"rule", ShowRuleCmd, IDS_SH_FW_SHOW,   IDS_HLP_SHOWRULE, 0, NULL } };
static CMD_ENTRY g_FwTop[]    = { { L"dump", NotSupported, IDS_SH_FW_DUMP,  IDS_HLP_FWDUMP,   0, NULL } };
static CMD_GROUP_ENTRY g_FwGroups[] =
{
    { L"add",    IDS_SH_FW_ADD,    1, 0, g_FwAdd,    NULL },
    { L"delete", IDS_SH_FW_DELETE, 1, 0, g_FwDelete, NULL },
    { L"set",    IDS_SH_FW_SET,    1, 0, g_FwSet,    NULL },
    { L"show",   IDS_SH_FW_SHOW,   1, 0, g_FwShow,   NULL },
};

static CMD_ENTRY g_AdvSet[] =
{
    { L"allprofiles",    SetAll,     IDS_SH_SETG_SET_ALLPROFILES,    IDS_HLP_SET_ALL,  0, NULL },
    { L"currentprofile", SetCurrent, IDS_SH_SETG_SET_CURRENTPROFILE, IDS_HLP_SET_CUR,  0, NULL },
    { L"domainprofile",  SetDomain,  IDS_SH_SETG_SET_DOMAINPROFILE,  IDS_HLP_SET_DOM,  0, NULL },
    { L"global",         NotSupported, IDS_SH_SETG_SET_GLOBAL,      IDS_HLP_SET_GLOBAL, 0, NULL },
    { L"privateprofile", SetPrivate, IDS_SH_SETG_SET_PRIVATEPROFILE, IDS_HLP_SET_PRIV, 0, NULL },
    { L"publicprofile",  SetPublic,  IDS_SH_SETG_SET_PUBLICPROFILE,  IDS_HLP_SET_PUB,  0, NULL },
};
static CMD_ENTRY g_AdvShow[] =
{
    { L"allprofiles",    ShowAll,     IDS_SH_SHOWG_SHOW_ALLPROFILES,    IDS_HLP_SHOW_ALL,  0, NULL },
    { L"currentprofile", ShowCurrent, IDS_SH_SHOWG_SHOW_CURRENTPROFILE, IDS_HLP_SHOW_CUR,  0, NULL },
    { L"domainprofile",  ShowDomain,  IDS_SH_SHOWG_SHOW_DOMAINPROFILE,  IDS_HLP_SHOW_DOM,  0, NULL },
    { L"global",         ShowGlobal,  IDS_SH_SHOWG_SHOW_GLOBAL,         IDS_HLP_SHOW_GLOBAL, 0, NULL },
    { L"privateprofile", ShowPrivate, IDS_SH_SHOWG_SHOW_PRIVATEPROFILE, IDS_HLP_SHOW_PRIV, 0, NULL },
    { L"publicprofile",  ShowPublic,  IDS_SH_SHOWG_SHOW_PUBLICPROFILE,  IDS_HLP_SHOW_PUB,  0, NULL },
    { L"store",          ShowStore,   IDS_SH_SHOWG_SHOW_STORE,          IDS_HLP_SHOW_STORE, 0, NULL },
};
static CMD_ENTRY g_AdvTop[] =
{
    { L"dump",   NotSupported, IDS_SH_ADV_DUMP,   IDS_HLP_ADVDUMP, 0, NULL },
    { L"export", NotSupported, IDS_SH_ADV_EXPORT, IDS_HLP_EXPORT,  0, NULL },
    { L"import", NotSupported, IDS_SH_ADV_IMPORT, IDS_HLP_IMPORT,  0, NULL },
    { L"reset",  ResetCmd,     IDS_SH_ADV_RESET,  IDS_HLP_RESET,   0, NULL },
};
static CMD_GROUP_ENTRY g_AdvGroups[] =
{
    { L"set",  IDS_SH_ADV_SET,  sizeof(g_AdvSet) / sizeof(CMD_ENTRY),  0, g_AdvSet,  NULL },
    { L"show", IDS_SH_ADV_SHOW, sizeof(g_AdvShow) / sizeof(CMD_ENTRY), 0, g_AdvShow, NULL },
};

/* consec / mainmode / monitor: listed and reachable, not implemented */
static CMD_ENTRY g_ConsecAdd[]  = { { L"rule", NotSupported, IDS_SH_CONSEC_ADD,    0, 0, NULL } };
static CMD_ENTRY g_ConsecDel[]  = { { L"rule", NotSupported, IDS_SH_CONSEC_DELETE, 0, 0, NULL } };
static CMD_ENTRY g_ConsecSet[]  = { { L"rule", NotSupported, IDS_SH_CONSEC_SET,    0, 0, NULL } };
static CMD_ENTRY g_ConsecShow[] = { { L"rule", NotSupported, IDS_SH_CONSEC_SHOW,   0, 0, NULL } };
static CMD_ENTRY g_ConsecTop[]  = { { L"dump", NotSupported, IDS_SH_CONSEC_DUMP,   0, 0, NULL } };
static CMD_GROUP_ENTRY g_ConsecGroups[] =
{
    { L"add", IDS_SH_CONSEC_ADD, 1, 0, g_ConsecAdd, NULL }, { L"delete", IDS_SH_CONSEC_DELETE, 1, 0, g_ConsecDel, NULL },
    { L"set", IDS_SH_CONSEC_SET, 1, 0, g_ConsecSet, NULL }, { L"show", IDS_SH_CONSEC_SHOW, 1, 0, g_ConsecShow, NULL },
};
static CMD_ENTRY g_MainAdd[]  = { { L"rule", NotSupported, IDS_SH_MAIN_ADD,    0, 0, NULL } };
static CMD_ENTRY g_MainDel[]  = { { L"rule", NotSupported, IDS_SH_MAIN_DELETE, 0, 0, NULL } };
static CMD_ENTRY g_MainSet[]  = { { L"rule", NotSupported, IDS_SH_MAIN_SET,    0, 0, NULL } };
static CMD_ENTRY g_MainShow[] = { { L"rule", NotSupported, IDS_SH_MAIN_SHOW,   0, 0, NULL } };
static CMD_ENTRY g_MainTop[]  = { { L"dump", NotSupported, IDS_SH_MAIN_DUMP,   0, 0, NULL } };
static CMD_GROUP_ENTRY g_MainGroups[] =
{
    { L"add", IDS_SH_MAIN_ADD, 1, 0, g_MainAdd, NULL }, { L"delete", IDS_SH_MAIN_DELETE, 1, 0, g_MainDel, NULL },
    { L"set", IDS_SH_MAIN_SET, 1, 0, g_MainSet, NULL }, { L"show", IDS_SH_MAIN_SHOW, 1, 0, g_MainShow, NULL },
};
static CMD_ENTRY g_MonDel[]  = { { L"mmsa", NotSupported, IDS_SH_MON_DELETE, 0, 0, NULL } };
static CMD_ENTRY g_MonShow[] = { { L"mmsa", NotSupported, IDS_SH_MON_SHOW,   0, 0, NULL } };
static CMD_ENTRY g_MonTop[]  = { { L"dump", NotSupported, IDS_SH_MON_DUMP,   0, 0, NULL } };
static CMD_GROUP_ENTRY g_MonGroups[] =
{
    { L"delete", IDS_SH_MON_DELETE, 1, 0, g_MonDel, NULL }, { L"show", IDS_SH_MON_SHOW, 1, 0, g_MonShow, NULL },
};

static DWORD WINAPI NoticeConnect(LPCWSTR pwszRouter)
{
    OutRes(IDS_MSG_NOTICE);
    return ERROR_SUCCESS;
}

static DWORD WINAPI DumpFn(LPCWSTR pwszRouter, LPWSTR *ppwcArguments, DWORD dwArgCount, LPCVOID pvData)
{
    return ERROR_SUCCESS;
}

static VOID Register(PCWSTR name, const GUID *guid, CMD_ENTRY *top, ULONG ntop, CMD_GROUP_ENTRY *groups, ULONG ngroups, PNS_CONTEXT_CONNECT_FN conn)
{
    NS_CONTEXT_ATTRIBUTES ca;
    ZeroMemory(&ca, sizeof(ca));
    ca.dwVersion = 1;
    ca.pwszContext = (LPWSTR)name;
    ca.guidHelper = *guid;
    ca.ulNumTopCmds = ntop; ca.pTopCmds = top;
    ca.ulNumGroups = ngroups; ca.pCmdGroups = groups;
    ca.pfnConnectFn = conn;
    ca.pfnDumpFn = DumpFn;
    RegisterContext(&ca);
}

static DWORD WINAPI StartAdv(const GUID *parent, DWORD ver)
{ Register(L"advfirewall", &GUID_ADVFW, g_AdvTop, _countof(g_AdvTop), g_AdvGroups, _countof(g_AdvGroups), NoticeConnect); return ERROR_SUCCESS; }
static DWORD WINAPI StartFw(const GUID *parent, DWORD ver)
{ Register(L"firewall", &GUID_FW, g_FwTop, _countof(g_FwTop), g_FwGroups, _countof(g_FwGroups), NULL); return ERROR_SUCCESS; }
static DWORD WINAPI StartConsec(const GUID *parent, DWORD ver)
{ Register(L"consec", &GUID_CONSEC, g_ConsecTop, 1, g_ConsecGroups, _countof(g_ConsecGroups), NULL); return ERROR_SUCCESS; }
static DWORD WINAPI StartMain(const GUID *parent, DWORD ver)
{ Register(L"mainmode", &GUID_MAIN, g_MainTop, 1, g_MainGroups, _countof(g_MainGroups), NULL); return ERROR_SUCCESS; }
static DWORD WINAPI StartMon(const GUID *parent, DWORD ver)
{ Register(L"monitor", &GUID_MON, g_MonTop, 1, g_MonGroups, _countof(g_MonGroups), NULL); return ERROR_SUCCESS; }

DWORD WINAPI InitHelperDll(DWORD dwNetshVersion, PVOID pReserved)
{
    NS_HELPER_ATTRIBUTES a;
    ZeroMemory(&a, sizeof(a));
    a.dwVersion = 1; a.guidHelper = GUID_ADVFW; a.pfnStart = StartAdv;
    RegisterHelper(NULL, &a);
    a.guidHelper = GUID_FW; a.pfnStart = StartFw; RegisterHelper(&GUID_ADVFW, &a);
    a.guidHelper = GUID_CONSEC; a.pfnStart = StartConsec; RegisterHelper(&GUID_ADVFW, &a);
    a.guidHelper = GUID_MAIN; a.pfnStart = StartMain; RegisterHelper(&GUID_ADVFW, &a);
    a.guidHelper = GUID_MON; a.pfnStart = StartMon; RegisterHelper(&GUID_ADVFW, &a);
    return ERROR_SUCCESS;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH) { hDllInstance = hinst; DisableThreadLibraryCalls(hinst); }
    return TRUE;
}
