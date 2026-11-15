/*
 * PROJECT:     NitroOS basic firewall
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Build the NITROFW_POLICY blob from the store and send it to the kernel filter
 */
#include "precomp.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

typedef struct { BYTE *p; SIZE_T len, cap; } BUF;

static BOOL Put(BUF *b, const void *d, SIZE_T n)
{
    if (b->len + n > b->cap)
    {
        SIZE_T nc = b->cap ? b->cap * 2 : 4096; BYTE *np;
        while (nc < b->len + n) nc *= 2;
        np = HeapAlloc(GetProcessHeap(), 0, nc);
        if (!np) return FALSE;
        if (b->p) { memcpy(np, b->p, b->len); HeapFree(GetProcessHeap(), 0, b->p); }
        b->p = np; b->cap = nc;
    }
    if (d) memcpy(b->p + b->len, d, n); else memset(b->p + b->len, 0, n);
    b->len += n;
    return TRUE;
}

static BOOL PadTo8(BUF *b) { SIZE_T pad = (8 - (b->len & 7)) & 7; return !pad || Put(b, NULL, pad); }

/* ---- growable lists of parsed entries ----
   A list is never cut at a fixed size: a rule with more entries than one kernel rule carries is split into several
   kernel rules of the same action (see EmitRule), because dropping entries of a Block rule makes it match less
   (fail open) and dropping entries of an Allow rule is only safe by accident. */

typedef struct { BYTE *p; ULONG n, cap, esz; } DL;

/* one dimension of a rule (local ports, remote IPv4 addresses, ...) as parsed from its tokens */
typedef struct
{
    DL    l;       /* the entries that resolved */
    ULONG cnt;     /* tokens in the rule */
    ULONG bad;     /* tokens that gave no entry (keyword that is not resolvable here, bad number, empty keyword) */
    BOOL  wild;    /* a "*" token: any */
    BOOL  oom;
} DIM;

static VOID DimInit(DIM *d, ULONG esz) { memset(d, 0, sizeof(*d)); d->l.esz = esz; }
static VOID DimFree(DIM *d) { if (d->l.p) HeapFree(GetProcessHeap(), 0, d->l.p); memset(d, 0, sizeof(*d)); }

static BOOL DlAdd(DL *l, const void *e)
{
    if (l->n == l->cap)
    {
        ULONG nc = l->cap ? l->cap * 2 : 16; BYTE *np;
        if (nc > 0x100000) return FALSE;
        np = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)nc * l->esz);
        if (!np) return FALSE;
        if (l->p) { memcpy(np, l->p, (SIZE_T)l->n * l->esz); HeapFree(GetProcessHeap(), 0, l->p); }
        l->p = np; l->cap = nc;
    }
    memcpy(l->p + (SIZE_T)l->n * l->esz, e, l->esz);
    l->n++;
    return TRUE;
}

static VOID DimAdd(DIM *d, const void *e) { if (!DlAdd(&d->l, e)) d->oom = TRUE; }

/* the dimension restricts the rule: it has tokens and no wildcard among them */
static BOOL DimScoped(const DIM *d) { return d->cnt && !d->wild; }
/* ... and at least one token resolved to something the kernel can match */
static BOOL DimAlive(const DIM *d) { return d->l.n != 0; }

static BOOL ParseV4Str(PCWSTR s, PCWSTR *end, ULONG *out)
{
    ULONG v = 0; int parts = 0;
    for (;;)
    {
        ULONG n = 0; int d = 0;
        while (*s >= L'0' && *s <= L'9') { n = n * 10 + (*s - L'0'); s++; d++; if (n > 255) return FALSE; }
        if (!d) return FALSE;
        v = (v << 8) | n;
        if (++parts == 4) break;
        if (*s != L'.') return FALSE;
        s++;
    }
    *out = v; *end = s;
    return TRUE;
}

/* resolve an address keyword to IPv4 ranges at push time */
static VOID AddKeyword(DIM *d, PCWSTR kw)
{
    IP_ADAPTER_INFO *ai = NULL; ULONG len = 0;
    IP_ADAPTER_INFO *a;
    if (GetAdaptersInfo(NULL, &len) != ERROR_BUFFER_OVERFLOW) return;
    ai = HeapAlloc(GetProcessHeap(), 0, len);
    if (!ai) { d->oom = TRUE; return; }
    if (GetAdaptersInfo(ai, &len) == 0)
    {
        for (a = ai; a; a = a->Next)
        {
            IP_ADDR_STRING *s; PCWSTR e; ULONG ip, mask; WCHAR w[32]; NITROFW_ADDR4_RANGE r;
            if (!_wcsicmp(kw, L"LocalSubnet"))
            {
                for (s = &a->IpAddressList; s; s = s->Next)
                {
                    MultiByteToWideChar(CP_ACP, 0, s->IpAddress.String, -1, w, 32);
                    if (!ParseV4Str(w, &e, &ip)) continue;
                    MultiByteToWideChar(CP_ACP, 0, s->IpMask.String, -1, w, 32);
                    if (!ParseV4Str(w, &e, &mask) || !ip) continue;
                    r.Low = ip & mask; r.High = ip | ~mask; DimAdd(d, &r);
                }
            }
            else if (!_wcsicmp(kw, L"DefaultGateway") || !_wcsicmp(kw, L"DHCP") || !_wcsicmp(kw, L"WINS"))
            {
                s = !_wcsicmp(kw, L"DefaultGateway") ? &a->GatewayList : (!_wcsicmp(kw, L"DHCP") ? &a->DhcpServer : &a->PrimaryWinsServer);
                for (; s; s = s->Next)
                {
                    MultiByteToWideChar(CP_ACP, 0, s->IpAddress.String, -1, w, 32);
                    if (ParseV4Str(w, &e, &ip) && ip) { r.Low = r.High = ip; DimAdd(d, &r); }
                }
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, ai);
}

/* LA4/RA4: "addr", "addr/mask", "addr-addr", keywords, "*". A token that gives nothing is counted in d->bad. */
static VOID ParseAddr4(const FWR *raw, PCWSTR key, DIM *d)
{
    ULONG i;
    DimInit(d, sizeof(NITROFW_ADDR4_RANGE));
    d->cnt = FwrCount(raw, key);
    for (i = 0; i < d->cnt; i++)
    {
        PCWSTR v = FwrGet(raw, key, i), e; ULONG a, b, before = d->l.n; NITROFW_ADDR4_RANGE r;
        if (!wcscmp(v, L"*")) { d->wild = TRUE; continue; }
        if (!ParseV4Str(v, &e, &a))
        {
            if (!wcschr(v, L':')) AddKeyword(d, v);
        }
        else if (*e == L'/') { if (ParseV4Str(e + 1, &e, &b)) { r.Low = a & b; r.High = a | ~b; DimAdd(d, &r); } }
        else if (*e == L'-') { if (ParseV4Str(e + 1, &e, &b) && a <= b) { r.Low = a; r.High = b; DimAdd(d, &r); } }
        else { r.Low = r.High = a; DimAdd(d, &r); }
        if (d->l.n == before) d->bad++;
    }
}

/* Does the running tcpip have IPv6? The kernel decides (IOCTL_NITROFW_GET_VERSION, NITROFW_FEATURE_IPV6: tcpip read
   the Ipv6Enable registry value once, at load), not the registry value, which can change while tcpip runs: the rule
   service must send the rules' IPv6 addresses (LA6/RA6) exactly when the kernel can see an IPv6 packet, or an Allow
   rule whose only scope is an IPv6 address is pushed without any address condition and matches everything. An
   older driver, or a failed query, means no IPv6: the addresses are not sent, as before IPv6 existed. */
static BOOL KernelHasIpv6(HANDLE h)
{
    NITROFW_VERSION_INFO vi; DWORD ret = 0;
    memset(&vi, 0, sizeof(vi));
    if (!DeviceIoControl(h, IOCTL_NITROFW_GET_VERSION, NULL, 0, &vi, sizeof(vi), &ret, NULL) || ret < sizeof(vi)) return FALSE;
    return (vi.Features & NITROFW_FEATURE_IPV6) != 0;
}

/* An IPv6 address in text (RFC 4291 2.2 forms 1 and 2: hex groups, one "::"; no embedded IPv4, no zone) up to
   a '/', '-' or the end. */
static BOOL ParseV6Str(PCWSTR s, PCWSTR *end, BYTE *out)
{
    WORD g[8]; int n = 0, gap = -1, i;
    memset(out, 0, 16);
    if (s[0] == L':' && s[1] == L':') { gap = 0; s += 2; }
    else if (s[0] == L':') return FALSE;
    while (*s && *s != L'/' && *s != L'-')
    {
        DWORD v = 0; int d = 0;
        while ((*s >= L'0' && *s <= L'9') || (*s >= L'a' && *s <= L'f') || (*s >= L'A' && *s <= L'F'))
        {
            v = v * 16 + (*s <= L'9' ? *s - L'0' : (*s | 0x20) - L'a' + 10); s++; d++;
            if (d > 4) return FALSE;
        }
        if (!d || n >= 8) return FALSE;
        g[n++] = (WORD)v;
        if (*s == L':')
        {
            s++;
            if (*s == L':') { if (gap >= 0) return FALSE; gap = n; s++; }
            else if (!*s || *s == L'/' || *s == L'-') return FALSE;
        }
        else if (*s && *s != L'/' && *s != L'-') return FALSE;
    }
    if (gap < 0 ? n != 8 : n > 7) return FALSE;
    {
        int zeros = 8 - n, o = 0;
        for (i = 0; i < n; i++)
        {
            if (i == gap) o += zeros;
            out[o * 2] = (BYTE)(g[i] >> 8); out[o * 2 + 1] = (BYTE)g[i]; o++;
        }
    }
    *end = s;
    return TRUE;
}

#ifndef GAA_FLAG_SKIP_ANYCAST
#define GAA_FLAG_SKIP_ANYCAST 0x0002
#define GAA_FLAG_SKIP_MULTICAST 0x0004
#define GAA_FLAG_SKIP_DNS_SERVER 0x0008
#endif

static VOID V6Range(DIM *d, const BYTE *a, int len)
{
    NITROFW_ADDR6_RANGE r; int k;
    for (k = 0; k < 16; k++)
    {
        int bits = len - k * 8; BYTE mask = bits >= 8 ? 0xFF : (bits <= 0 ? 0 : (BYTE)(0xFF << (8 - bits)));
        r.Low[k] = a[k] & mask; r.High[k] = a[k] | (BYTE)~mask;
    }
    DimAdd(d, &r);
}

/* The one IPv6 keyword resolved here: LocalSubnet = the on-link prefix of every unicast address of the host (a link-local
   address gives fe80::/64). The others (DefaultGateway, DNS, DHCP, WINS, Internet, ...) are not resolved for IPv6: the
   token stays unresolved and the caller treats the IPv6 half of the rule accordingly (never as "matches nothing"). */
static VOID AddKeyword6(DIM *d, PCWSTR kw)
{
    IP_ADAPTER_ADDRESSES *aa = NULL, *a; ULONG len = 16384, rc = ERROR_BUFFER_OVERFLOW, tries;
    if (_wcsicmp(kw, L"LocalSubnet")) return;
    for (tries = 0; tries < 3 && rc == ERROR_BUFFER_OVERFLOW; tries++)
    {
        aa = HeapAlloc(GetProcessHeap(), 0, len);
        if (!aa) { d->oom = TRUE; return; }
        rc = GetAdaptersAddresses(AF_INET6, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, NULL, aa, &len);
        if (rc != NO_ERROR) { HeapFree(GetProcessHeap(), 0, aa); aa = NULL; }
    }
    if (!aa) return;
    for (a = aa; a; a = a->Next)
    {
        IP_ADAPTER_UNICAST_ADDRESS *u;
        for (u = a->FirstUnicastAddress; u; u = u->Next)
        {
            const SOCKADDR_IN6 *sa = (const SOCKADDR_IN6 *)u->Address.lpSockaddr;
            const BYTE *ad;
            if (!sa || u->Address.iSockaddrLength < (INT)sizeof(*sa) || sa->sin6_family != AF_INET6) continue;
            ad = (const BYTE *)&sa->sin6_addr;
            if (ad[0] == 0xFE && (ad[1] & 0xC0) == 0x80) V6Range(d, ad, 64);
            else if (u->OnLinkPrefixLength >= 1 && u->OnLinkPrefixLength <= 128) V6Range(d, ad, u->OnLinkPrefixLength);
        }
    }
    HeapFree(GetProcessHeap(), 0, aa);
}

/* IPv6 ranges of LA6/RA6: "addr", "addr/prefixlength", "addr-addr", LocalSubnet. A token that gives nothing is counted
   in d->bad. A list of which no token resolves is NOT turned into a range that never matches: the caller sees
   DimScoped && !DimAlive and leaves the IPv6 half of the rule out (and says so loudly for a Block rule). */
static VOID ParseAddr6(const FWR *raw, PCWSTR key, DIM *d)
{
    ULONG i;
    DimInit(d, sizeof(NITROFW_ADDR6_RANGE));
    d->cnt = FwrCount(raw, key);
    for (i = 0; i < d->cnt; i++)
    {
        PCWSTR v = FwrGet(raw, key, i), e; BYTE a[16], b[16]; ULONG before = d->l.n;
        if (!wcscmp(v, L"*")) { d->wild = TRUE; continue; }
        if (!ParseV6Str(v, &e, a)) AddKeyword6(d, v);
        else if (*e == L'/')
        {
            int len = _wtoi(e + 1);
            if (e[1] >= L'0' && e[1] <= L'9' && len >= 0 && len <= 128) V6Range(d, a, len);
        }
        else if (*e == L'-')
        {
            NITROFW_ADDR6_RANGE r;
            if (ParseV6Str(e + 1, &e, b) && memcmp(a, b, 16) <= 0) { memcpy(r.Low, a, 16); memcpy(r.High, b, 16); DimAdd(d, &r); }
        }
        else { NITROFW_ADDR6_RANGE r; memcpy(r.Low, a, 16); memcpy(r.High, a, 16); DimAdd(d, &r); }
        if (d->l.n == before) d->bad++;
    }
}

static BOOL ParseUShort(PCWSTR *ps, ULONG *out)
{
    PCWSTR s = *ps; ULONG v = 0; int d = 0;
    while (*s >= L'0' && *s <= L'9') { v = v * 10 + (*s - L'0'); s++; d++; if (v > 65535) return FALSE; }
    if (!d) return FALSE;
    *out = v; *ps = s;
    return TRUE;
}

/* ports of the two keys (single ports and ranges); a token that gives nothing (keyword such as Teredo, number above
   65535, range with Low > High: the kernel would reject the whole policy for it) is counted in d->bad */
static VOID ParsePorts(const FWR *raw, PCWSTR k1, PCWSTR k2, DIM *d)
{
    ULONG pass, i; PCWSTR keys[2];
    keys[0] = k1; keys[1] = k2;
    DimInit(d, sizeof(NITROFW_PORT_RANGE));
    for (pass = 0; pass < 2; pass++)
    {
        ULONG cnt = FwrCount(raw, keys[pass]);
        d->cnt += cnt;
        for (i = 0; i < cnt; i++)
        {
            PCWSTR v = FwrGet(raw, keys[pass], i); ULONG lo, hi; NITROFW_PORT_RANGE r; BOOL ok = FALSE;
            if (!wcscmp(v, L"*")) { d->wild = TRUE; continue; }
            if (!_wcsicmp(v, L"RPC")) { r.Low = 49152; r.High = 65535; ok = TRUE; }
            else if (!_wcsicmp(v, L"RPC-EPMap")) { r.Low = r.High = 135; ok = TRUE; }
            else if (ParseUShort(&v, &lo))
            {
                hi = lo;
                if (*v == L'-') { v++; ok = ParseUShort(&v, &hi) && !*v && lo <= hi; }
                else ok = !*v;
                r.Low = (USHORT)lo; r.High = (USHORT)hi;
            }
            if (ok) DimAdd(d, &r); else d->bad++;
        }
    }
}

/* ICMP type[:code] entries, "*" = any */
static VOID ParseIcmp(const FWR *raw, PCWSTR key, DIM *d)
{
    ULONG i;
    DimInit(d, sizeof(NITROFW_ICMP_ENTRY));
    d->cnt = FwrCount(raw, key);
    for (i = 0; i < d->cnt; i++)
    {
        PCWSTR e = FwrGet(raw, key, i), c = wcschr(e, L':'); NITROFW_ICMP_ENTRY ic; int t = 0, cd = 0;
        if (*e != L'*' && (*e < L'0' || *e > L'9')) { d->bad++; continue; }
        t = (*e == L'*') ? NITROFW_ICMP_ANY : _wtoi(e);
        cd = (!c || c[1] == L'*') ? NITROFW_ICMP_ANY : _wtoi(c + 1);
        if (t < 0 || t > 255 || cd < 0 || cd > 255) { d->bad++; continue; }
        ic.Type = (UCHAR)t; ic.Code = (UCHAR)cd;
        DimAdd(d, &ic);
    }
}

/* NT path of the App value; NULL when it cannot be resolved (the caller must not drop the program condition then:
   a rule for one program would match every program) */
static PWSTR ToNtPath(PCWSTR app)
{
    WCHAR exp[MAX_PATH], dev[MAX_PATH], drv[3];
    PWSTR out;
    DWORD n;
    if (!app || !*app) return NULL;
    n = ExpandEnvironmentStringsW(app, exp, MAX_PATH);
    if (!n || n > MAX_PATH) return NULL;
    if (!_wcsicmp(exp, L"System")) { out = HeapAlloc(GetProcessHeap(), 0, 14); if (out) wcscpy(out, L"System"); return out; }
    if (!exp[0] || exp[1] != L':') return NULL;     /* exp[1] is only read after exp[0] proved the string is not empty */
    drv[0] = exp[0]; drv[1] = L':'; drv[2] = 0;
    if (!QueryDosDeviceW(drv, dev, MAX_PATH)) return NULL;
    out = HeapAlloc(GetProcessHeap(), 0, (wcslen(dev) + wcslen(exp) + 1) * sizeof(WCHAR));
    if (out) { wcscpy(out, dev); wcscat(out, exp + 2); }
    return out;
}

/* ---- rules that were not (or not fully) pushed: the rule service reports them (FwPushGetReport) ---- */

#define REPORT_CHARS 1024
static ULONG g_Rejected, g_Partial;
static WCHAR g_RejNames[REPORT_CHARS];

static VOID Note(PCWSTR tag, const FW_RULE *r)
{
    SIZE_T have = wcslen(g_RejNames);
    PCWSTR name = r->Name && *r->Name ? r->Name : L"(unnamed)";
    if (have + wcslen(tag) + wcslen(name) + 6 >= REPORT_CHARS) { if (have + 4 < REPORT_CHARS) wcscat(g_RejNames, L"..."); return; }
    if (have) wcscat(g_RejNames, L"; ");
    wcscat(g_RejNames, tag); wcscat(g_RejNames, L": "); wcscat(g_RejNames, name);
}

/* ---- one source rule -> one or more kernel rules ----
   The kernel carries at most NITROFW_MAX_LIST entries per list, and the lists of a rule are ANDed with each other
   (OR inside a list). A list longer than LIST_CHUNK is therefore cut into chunks and a kernel rule with the same
   action is emitted for every combination of chunks: the union of those rules is exactly the source rule. Nothing
   is ever left out of a list. */

#define LIST_CHUNK 64
C_ASSERT(LIST_CHUNK <= NITROFW_MAX_LIST);

static ULONG Chunks(const DL *l) { return (!l || !l->n) ? 1 : (l->n + LIST_CHUNK - 1) / LIST_CHUNK; }

static BOOL PutChunk(BUF *b, ULONG start, const DL *l, ULONG ci, ULONG *cnt, ULONG *off)
{
    ULONG n;
    if (!l || !l->n) return TRUE;
    n = l->n - ci * LIST_CHUNK;
    if (n > LIST_CHUNK) n = LIST_CHUNK;
    if (!PadTo8(b)) return FALSE;
    *cnt = n; *off = (ULONG)b->len - start;
    return Put(b, l->p + (SIZE_T)ci * LIST_CHUNK * l->esz, (SIZE_T)n * l->esz);
}

/* the lists are NULL when the rule does not restrict that dimension; fam 4 or 6 says what la/ra hold */
static BOOL EmitHalf(BUF *b, const NITROFW_RULE *tmpl, int fam, const DL *lp, const DL *rp, const DL *la, const DL *ra,
                     const DL *ic, PCWSTR nt, PCWSTR svc, ULONG *pieces, ULONG maxPieces)
{
    ULONG nc[5], total = 1, idx[5] = { 0 }, k;
    nc[0] = Chunks(lp); nc[1] = Chunks(rp); nc[2] = Chunks(la); nc[3] = Chunks(ra); nc[4] = Chunks(ic);
    for (k = 0; k < 5; k++)
    {
        if (nc[k] > maxPieces || total > maxPieces / nc[k]) return FALSE;     /* too many kernel rules: caller rejects */
        total *= nc[k];
    }
    if (total > maxPieces - *pieces) return FALSE;
    for (;;)
    {
        NITROFW_RULE hdr = *tmpl; ULONG start = (ULONG)b->len;
        if (!Put(b, &hdr, sizeof(hdr))) return FALSE;
        if (!PutChunk(b, start, lp, idx[0], &hdr.LocalPortCount, &hdr.LocalPortOffset) ||
            !PutChunk(b, start, rp, idx[1], &hdr.RemotePortCount, &hdr.RemotePortOffset)) return FALSE;
        if (fam == 4)
        {
            if (!PutChunk(b, start, la, idx[2], &hdr.LocalAddr4Count, &hdr.LocalAddr4Offset) ||
                !PutChunk(b, start, ra, idx[3], &hdr.RemoteAddr4Count, &hdr.RemoteAddr4Offset)) return FALSE;
        }
        else if (fam == 6)
        {
            if (!PutChunk(b, start, la, idx[2], &hdr.LocalAddr6Count, &hdr.LocalAddr6Offset) ||
                !PutChunk(b, start, ra, idx[3], &hdr.RemoteAddr6Count, &hdr.RemoteAddr6Offset)) return FALSE;
        }
        if (!PutChunk(b, start, ic, idx[4], &hdr.IcmpCount, &hdr.IcmpOffset)) return FALSE;
        if (nt) { if (!PadTo8(b)) return FALSE; hdr.AppPathOffset = (ULONG)b->len - start; if (!Put(b, nt, (wcslen(nt) + 1) * sizeof(WCHAR))) return FALSE; }
        if (svc) { if (!PadTo8(b)) return FALSE; hdr.ServiceNameOffset = (ULONG)b->len - start; if (!Put(b, svc, (wcslen(svc) + 1) * sizeof(WCHAR))) return FALSE; }
        if (!PadTo8(b)) return FALSE;
        hdr.Size = (ULONG)b->len - start;
        memcpy(b->p + start, &hdr, sizeof(hdr));
        (*pieces)++;
        for (k = 0; k < 5; k++) { if (++idx[k] < nc[k]) break; idx[k] = 0; }
        if (k == 5) break;
    }
    return TRUE;
}

typedef enum { BR_OK, BR_SKIPPED, BR_REJECTED } BR_RESULT;

/* Turns one stored rule into kernel rules. BR_SKIPPED: the rule can never match anything in this configuration
   (it is scoped to IPv6 addresses only and the kernel has no IPv6), nothing is pushed and that is exact.
   BR_REJECTED: the rule cannot be represented without becoming broader or narrower than it is (a list of which no
   token resolves, a program path that does not resolve, too many kernel rules, out of memory): nothing is pushed
   for it, b is as before. The caller counts and reports it. *pPartial is set when a Block rule is pushed but a
   part of it is not enforced (an IPv6 half whose keywords do not resolve, or tokens that gave nothing). */
static BR_RESULT BuildRule(BUF *b, const FW_RULE *r, BOOL v6, ULONG *pieces, ULONG maxPieces, BOOL *pPartial)
{
    NITROFW_RULE hdr; DIM lp, rp, la4, ra4, la6, ra6, ic;
    ULONG start = (ULONG)b->len, i, ifm = 0, first = *pieces;
    PWSTR nt = NULL; PCWSTR v, svc = NULL, icKey; BR_RESULT res = BR_REJECTED;
    BOOL block, v4Scoped, v6Tok, v6Scoped, do4, do6, dead4, dead6, v4Alive, v6Alive, ok = TRUE;
    ULONG bad = 0;

    *pPartial = FALSE;
    memset(&hdr, 0, sizeof(hdr));
    hdr.Action = r->Action ? NITROFW_ACTION_ALLOW : NITROFW_ACTION_BLOCK;
    block = !r->Action;
    hdr.Direction = (UCHAR)(r->Dir == 2 ? NITROFW_DIR_OUT : NITROFW_DIR_IN);
    hdr.Protocol = (USHORT)r->Protocol;
    hdr.ProfileMask = (r->Profiles == FWP_ANY_COM) ? FWP_ALL : (r->Profiles & FWP_ALL);
    if (!hdr.ProfileMask) hdr.ProfileMask = FWP_ALL;
    for (i = 0; (v = FwrGet(&r->Raw, L"IFType", i)) != NULL; i++)
        ifm |= !_wcsicmp(v, L"Lan") ? NITROFW_IFTYPE_LAN : (!_wcsicmp(v, L"Wireless") ? NITROFW_IFTYPE_WIRELESS : (!_wcsicmp(v, L"RemoteAccess") ? NITROFW_IFTYPE_REMOTEACCESS : 0));
    hdr.IfTypes = ifm ? ifm : NITROFW_IFTYPE_ALL;

    ParsePorts(&r->Raw, L"LPort2_10", L"LPort", &lp);
    ParsePorts(&r->Raw, L"RPort2_10", L"RPort", &rp);
    ParseAddr4(&r->Raw, L"LA4", &la4);
    ParseAddr4(&r->Raw, L"RA4", &ra4);
    DimInit(&la6, sizeof(NITROFW_ADDR6_RANGE)); DimInit(&ra6, sizeof(NITROFW_ADDR6_RANGE));
    if (v6)
    {
        DimFree(&la6); DimFree(&ra6);
        ParseAddr6(&r->Raw, L"LA6", &la6);
        ParseAddr6(&r->Raw, L"RA6", &ra6);
    }
    icKey = r->Protocol == 1 ? L"ICMP4" : L"ICMP6";
    if (r->Icmp && (r->Protocol == 1 || r->Protocol == 58)) ParseIcmp(&r->Raw, icKey, &ic);
    else DimInit(&ic, sizeof(NITROFW_ICMP_ENTRY));
    if (r->Svc && *r->Svc && wcscmp(r->Svc, L"*")) svc = r->Svc;     /* an empty name would make the kernel reject the policy */
    if (r->App && *r->App)
    {
        nt = ToNtPath(r->App);
        if (!nt) ok = FALSE;       /* dropping the program condition would widen the rule to every program */
    }
    if (lp.oom || rp.oom || la4.oom || ra4.oom || la6.oom || ra6.oom || ic.oom) ok = FALSE;
    /* a scoped dimension of which no token resolved is never "any": the rule cannot be represented */
    if ((DimScoped(&lp) && !DimAlive(&lp)) || (DimScoped(&rp) && !DimAlive(&rp)) || (DimScoped(&ic) && !DimAlive(&ic))) ok = FALSE;
    if (!ok) goto done;

    bad = (DimScoped(&lp) ? lp.bad : 0) + (DimScoped(&rp) ? rp.bad : 0) + (DimScoped(&ic) ? ic.bad : 0);
    v4Scoped = DimScoped(&la4) || DimScoped(&ra4);
    v4Alive = (!DimScoped(&la4) || DimAlive(&la4)) && (!DimScoped(&ra4) || DimAlive(&ra4));
    v6Tok = FwrCount(&r->Raw, L"LA6") || FwrCount(&r->Raw, L"RA6");     /* the rule has IPv6 address tokens */
    v6Scoped = v6 && (DimScoped(&la6) || DimScoped(&ra6));
    v6Alive = (!DimScoped(&la6) || DimAlive(&la6)) && (!DimScoped(&ra6) || DimAlive(&ra6));
    if (v4Scoped) bad += (DimScoped(&la4) ? la4.bad : 0) + (DimScoped(&ra4) ? ra4.bad : 0);
    if (v6Scoped) bad += (DimScoped(&la6) ? la6.bad : 0) + (DimScoped(&ra6) ? ra6.bad : 0);

    if (!v4Scoped && v6Tok && !v6)
    {
        /* scoped to IPv6 addresses only, and the kernel has no IPv6: no packet it sees can match */
        res = BR_SKIPPED;
        goto done;
    }
    if (!v4Scoped && !v6Scoped)
    {
        /* no address condition: one kernel rule (more if a list is long) for both families */
        if (!EmitHalf(b, &hdr, 0, DimScoped(&lp) ? &lp.l : NULL, DimScoped(&rp) ? &rp.l : NULL, NULL, NULL,
                      DimScoped(&ic) ? &ic.l : NULL, nt, svc, pieces, maxPieces)) goto fail;
        if (block && bad) *pPartial = TRUE;
        res = BR_OK;
        goto done;
    }
    do4 = v4Scoped && v4Alive; do6 = v6Scoped && v6Alive;
    dead4 = v4Scoped && !v4Alive; dead6 = v6Scoped && !v6Alive;
    if (!do4 && !do6) goto fail;          /* every address half is unresolvable: reject, never a never-matching rule */
    if (do4 && !EmitHalf(b, &hdr, 4, DimScoped(&lp) ? &lp.l : NULL, DimScoped(&rp) ? &rp.l : NULL,
                         DimScoped(&la4) ? &la4.l : NULL, DimScoped(&ra4) ? &ra4.l : NULL,
                         DimScoped(&ic) ? &ic.l : NULL, nt, svc, pieces, maxPieces)) goto fail;
    if (do6 && !EmitHalf(b, &hdr, 6, DimScoped(&lp) ? &lp.l : NULL, DimScoped(&rp) ? &rp.l : NULL,
                         DimScoped(&la6) ? &la6.l : NULL, DimScoped(&ra6) ? &ra6.l : NULL,
                         DimScoped(&ic) ? &ic.l : NULL, nt, svc, pieces, maxPieces)) goto fail;
    if (block && (bad || dead4 || dead6)) *pPartial = TRUE;
    res = BR_OK;
    goto done;
fail:
    res = BR_REJECTED;
done:
    if (res != BR_OK) { b->len = start; *pieces = first; }
    if (nt) HeapFree(GetProcessHeap(), 0, nt);
    DimFree(&lp); DimFree(&rp); DimFree(&la4); DimFree(&ra4); DimFree(&la6); DimFree(&ra6); DimFree(&ic);
    return res;
}

VOID FwPushGetReport(ULONG *pRejected, ULONG *pPartial, PWSTR Names, ULONG Chars)
{
    if (pRejected) *pRejected = g_Rejected;
    if (pPartial) *pPartial = g_Partial;
    if (Names && Chars) { wcsncpy(Names, g_RejNames, Chars - 1); Names[Chars - 1] = 0; }
}

DWORD FwPushToKernel(ULONGLONG gen, BOOL *pPresent)
{
    FW_RULESET rs; BUF b = { 0 }; NITROFW_POLICY pol; HANDLE h; DWORD err, ret, i;
    ULONG cnt = 0; ULONG bit; BOOL v6on;
    HKEY hk; DWORD enforce = 1, cb = sizeof(DWORD), t;
    g_Rejected = 0; g_Partial = 0; g_RejNames[0] = 0;
    if (pPresent) *pPresent = FALSE;
    h = CreateFileW(NITROFW_USER_PATH, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return GetLastError();
    if (pPresent) *pPresent = TRUE;
    v6on = KernelHasIpv6(h);
    err = FwStoreLoad(&rs);
    if (err) { CloseHandle(h); return err; }
    memset(&pol, 0, sizeof(pol));
    pol.Magic = NITROFW_POLICY_MAGIC; pol.AbiVersion = NITROFW_ABI_VERSION; pol.Generation = gen;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\ReactOS\\Nitro\\Firewall", 0, KEY_READ, &hk) == 0)
    {
        if (RegQueryValueExW(hk, L"Enforce", NULL, &t, (BYTE *)&enforce, &cb) != 0 || t != REG_DWORD) enforce = 1;
        RegCloseKey(hk);
    }
    pol.Flags = enforce ? NITROFW_POLICY_ENFORCE : 0;
    pol.ActiveProfiles = FwCurrentProfiles();
    for (bit = 1, i = 0; i < NITROFW_PROFILE_COUNT; i++, bit <<= 1)
    {
        FW_PROFILE p; FwProfileLoad(bit, &p);
        pol.Profile[i].Flags = (p.Enable ? NITROFW_PROFILE_ENABLED : 0) | (p.DoNotAllowExceptions ? NITROFW_PROFILE_BLOCK_ALL_INBOUND : 0) |
                                (p.DisableUnicastResponses ? NITROFW_PROFILE_NO_UNICAST_RESPONSES : 0) | (p.LogDropped ? NITROFW_PROFILE_LOG_DROPPED : 0);
        pol.Profile[i].DefaultInbound = (UCHAR)(p.DefaultInbound ? NITROFW_ACTION_BLOCK : NITROFW_ACTION_ALLOW);
        pol.Profile[i].DefaultOutbound = (UCHAR)(p.DefaultOutbound ? NITROFW_ACTION_BLOCK : NITROFW_ACTION_ALLOW);
    }
    if (!Put(&b, &pol, sizeof(pol))) { FwRuleSetFree(&rs); CloseHandle(h); return ERROR_NOT_ENOUGH_MEMORY; }
    ((NITROFW_POLICY *)b.p)->RulesOffset = sizeof(pol);
    for (i = 0; i < rs.N; i++)
    {
        ULONG before = cnt, savedLen = (ULONG)b.len; BOOL partial = FALSE; BR_RESULT br;
        if (!rs.R[i].Enabled) continue;
        br = BuildRule(&b, &rs.R[i], v6on, &cnt, NITROFW_MAX_RULES, &partial);
        /* a rule that would take the policy past its size limit is rejected on its own: the final size check below
           would fail the whole push and leave the previous policy in force */
        if (br == BR_OK && b.len > NITROFW_MAX_POLICY_SIZE) { b.len = savedLen; cnt = before; br = BR_REJECTED; }
        if (br == BR_REJECTED)
        {
            g_Rejected++;
            Note(L"rejected", &rs.R[i]);
        }
        else if (br == BR_OK && partial)
        {
            g_Partial++;
            Note(L"Block rule not fully enforced", &rs.R[i]);
        }
    }
    ((NITROFW_POLICY *)b.p)->RuleCount = cnt;
    ((NITROFW_POLICY *)b.p)->TotalSize = (ULONG)b.len;
    FwRuleSetFree(&rs);
    if (b.len > NITROFW_MAX_POLICY_SIZE) err = ERROR_INSUFFICIENT_BUFFER;
    else if (!DeviceIoControl(h, IOCTL_NITROFW_SET_POLICY, b.p, (DWORD)b.len, NULL, 0, &ret, NULL)) err = GetLastError();
    HeapFree(GetProcessHeap(), 0, b.p);
    CloseHandle(h);
    return err;
}
