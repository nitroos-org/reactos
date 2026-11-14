/*
 * PROJECT:     NitroOS basic firewall
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Build the NITROFW_POLICY blob from the store and send it to the kernel filter
 */
#include "precomp.h"
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
static BOOL AddKeyword(NITROFW_ADDR4_RANGE *arr, ULONG *n, ULONG max, PCWSTR kw)
{
    IP_ADAPTER_INFO *ai = NULL; ULONG len = 0; BOOL ok = TRUE;
    IP_ADAPTER_INFO *a;
    if (GetAdaptersInfo(NULL, &len) != ERROR_BUFFER_OVERFLOW) return TRUE;
    ai = HeapAlloc(GetProcessHeap(), 0, len);
    if (!ai) return FALSE;
    if (GetAdaptersInfo(ai, &len) == 0)
    {
        for (a = ai; a && *n < max; a = a->Next)
        {
            IP_ADDR_STRING *s; PCWSTR e; ULONG ip, mask; WCHAR w[32];
            if (!_wcsicmp(kw, L"LocalSubnet"))
            {
                for (s = &a->IpAddressList; s && *n < max; s = s->Next)
                {
                    MultiByteToWideChar(CP_ACP, 0, s->IpAddress.String, -1, w, 32);
                    if (!ParseV4Str(w, &e, &ip)) continue;
                    MultiByteToWideChar(CP_ACP, 0, s->IpMask.String, -1, w, 32);
                    if (!ParseV4Str(w, &e, &mask) || !ip) continue;
                    arr[*n].Low = ip & mask; arr[*n].High = ip | ~mask; (*n)++;
                }
            }
            else if (!_wcsicmp(kw, L"DefaultGateway") || !_wcsicmp(kw, L"DHCP") || !_wcsicmp(kw, L"WINS"))
            {
                s = !_wcsicmp(kw, L"DefaultGateway") ? &a->GatewayList : (!_wcsicmp(kw, L"DHCP") ? &a->DhcpServer : &a->PrimaryWinsServer);
                for (; s && *n < max; s = s->Next)
                {
                    MultiByteToWideChar(CP_ACP, 0, s->IpAddress.String, -1, w, 32);
                    if (ParseV4Str(w, &e, &ip) && ip) { arr[*n].Low = arr[*n].High = ip; (*n)++; }
                }
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, ai);
    return ok;
}

static ULONG ParseAddr4(const FWR *raw, PCWSTR key, NITROFW_ADDR4_RANGE *arr, ULONG max)
{
    ULONG i, n = 0, cnt = FwrCount(raw, key);
    for (i = 0; i < cnt && n < max; i++)
    {
        PCWSTR v = FwrGet(raw, key, i), e; ULONG a, b;
        if (!ParseV4Str(v, &e, &a))
        {
            if (!wcschr(v, L':') && wcscmp(v, L"*")) AddKeyword(arr, &n, max, v);
            continue;
        }
        if (*e == L'/') { if (ParseV4Str(e + 1, &e, &b)) { arr[n].Low = a & b; arr[n].High = a | ~b; n++; } }
        else if (*e == L'-') { if (ParseV4Str(e + 1, &e, &b)) { arr[n].Low = a; arr[n].High = b; n++; } }
        else { arr[n].Low = arr[n].High = a; n++; }
    }
    return n;
}

/* The IPv6 address filter (HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Ipv6Enable, REG_DWORD,
   non-zero = tcpip has IPv6). Off, the rules' IPv6 addresses (LA6/RA6) are not sent, as before IPv6 existed. */
static BOOL Ipv6SwitchOn(void)
{
    HKEY hk; DWORD v = 0, cb = sizeof(v), t = 0; BOOL on = FALSE;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", 0, KEY_READ, &hk) == 0)
    {
        if (RegQueryValueExW(hk, L"Ipv6Enable", NULL, &t, (BYTE *)&v, &cb) == 0 && t == REG_DWORD && v) on = TRUE;
        RegCloseKey(hk);
    }
    return on;
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

/* IPv6 ranges of LA6/RA6: "addr", "addr/prefixlength", "addr-addr"; entries that do not parse (keywords such as
   LocalSubnet are not resolved for IPv6) are skipped. A list with entries of which none parses becomes one
   range that no packet is in, so that the rule never matches instead of matching everything. */
static ULONG ParseAddr6(const FWR *raw, PCWSTR key, NITROFW_ADDR6_RANGE *arr, ULONG max)
{
    ULONG i, n = 0, cnt = FwrCount(raw, key);
    for (i = 0; i < cnt && n < max; i++)
    {
        PCWSTR v = FwrGet(raw, key, i), e; BYTE a[16], b[16];
        if (!ParseV6Str(v, &e, a)) continue;
        if (*e == L'/')
        {
            int len = _wtoi(e + 1), k;
            if (len < 0 || len > 128 || e[1] < L'0' || e[1] > L'9') continue;
            for (k = 0; k < 16; k++)
            {
                int bits = len - k * 8; BYTE mask = bits >= 8 ? 0xFF : (bits <= 0 ? 0 : (BYTE)(0xFF << (8 - bits)));
                arr[n].Low[k] = a[k] & mask; arr[n].High[k] = a[k] | (BYTE)~mask;
            }
            n++;
        }
        else if (*e == L'-')
        {
            if (!ParseV6Str(e + 1, &e, b) || memcmp(a, b, 16) > 0) continue;
            memcpy(arr[n].Low, a, 16); memcpy(arr[n].High, b, 16); n++;
        }
        else { memcpy(arr[n].Low, a, 16); memcpy(arr[n].High, a, 16); n++; }
    }
    if (cnt && !n)
    {
        memset(arr[0].Low, 0xFF, 16); memset(arr[0].High, 0xFF, 16); n = 1;
    }
    return n;
}

static ULONG ParsePorts(const FWR *raw, PCWSTR k1, PCWSTR k2, NITROFW_PORT_RANGE *arr, ULONG max)
{
    ULONG pass, i, n = 0;
    PCWSTR keys[2]; keys[0] = k1; keys[1] = k2;
    for (pass = 0; pass < 2; pass++)
    {
        ULONG cnt = FwrCount(raw, keys[pass]);
        for (i = 0; i < cnt && n < max; i++)
        {
            PCWSTR v = FwrGet(raw, keys[pass], i); ULONG lo, hi;
            if (!_wcsicmp(v, L"RPC")) { arr[n].Low = 49152; arr[n].High = 65535; n++; continue; }
            if (!_wcsicmp(v, L"RPC-EPMap")) { arr[n].Low = arr[n].High = 135; n++; continue; }
            if (*v < L'0' || *v > L'9') continue;   /* other keywords: not resolvable here */
            lo = hi = (ULONG)_wtoi(v);
            if (wcschr(v, L'-')) hi = (ULONG)_wtoi(wcschr(v, L'-') + 1);
            arr[n].Low = (USHORT)lo; arr[n].High = (USHORT)hi; n++;
        }
    }
    return n;
}

static PWSTR ToNtPath(PCWSTR app)
{
    WCHAR exp[MAX_PATH], dev[MAX_PATH], drv[3];
    PWSTR out;
    DWORD n = ExpandEnvironmentStringsW(app, exp, MAX_PATH);
    if (!n || n > MAX_PATH) return NULL;
    if (!_wcsicmp(exp, L"System")) { out = HeapAlloc(GetProcessHeap(), 0, 14); if (out) wcscpy(out, L"System"); return out; }
    if (exp[1] != L':') return NULL;
    drv[0] = exp[0]; drv[1] = L':'; drv[2] = 0;
    if (!QueryDosDeviceW(drv, dev, MAX_PATH)) return NULL;
    out = HeapAlloc(GetProcessHeap(), 0, (wcslen(dev) + wcslen(exp) + 1) * sizeof(WCHAR));
    if (out) { wcscpy(out, dev); wcscat(out, exp + 2); }
    return out;
}

static BOOL BuildRule(BUF *b, const FW_RULE *r, BOOL v6)
{
    NITROFW_RULE hdr; NITROFW_PORT_RANGE lp[64], rp[64]; NITROFW_ADDR4_RANGE la[64], ra[64];
    NITROFW_ADDR6_RANGE la6[64], ra6[64];
    ULONG start = (ULONG)b->len, nlp, nrp, nla, nra, nla6 = 0, nra6 = 0, i;
    PWSTR nt = NULL; PCWSTR v; ULONG ifm = 0;
    memset(&hdr, 0, sizeof(hdr));
    hdr.Action = r->Action ? NITROFW_ACTION_ALLOW : NITROFW_ACTION_BLOCK;
    hdr.Direction = (UCHAR)(r->Dir == 2 ? NITROFW_DIR_OUT : NITROFW_DIR_IN);
    hdr.Protocol = (USHORT)r->Protocol;
    hdr.ProfileMask = (r->Profiles == FWP_ANY_COM) ? FWP_ALL : (r->Profiles & FWP_ALL);
    if (!hdr.ProfileMask) hdr.ProfileMask = FWP_ALL;
    nlp = ParsePorts(&r->Raw, L"LPort2_10", L"LPort", lp, 64);
    nrp = ParsePorts(&r->Raw, L"RPort2_10", L"RPort", rp, 64);
    nla = ParseAddr4(&r->Raw, L"LA4", la, 64);
    nra = ParseAddr4(&r->Raw, L"RA4", ra, 64);
    if (v6)
    {
        nla6 = ParseAddr6(&r->Raw, L"LA6", la6, 64);
        nra6 = ParseAddr6(&r->Raw, L"RA6", ra6, 64);
    }
    for (i = 0; (v = FwrGet(&r->Raw, L"IFType", i)) != NULL; i++)
        ifm |= !_wcsicmp(v, L"Lan") ? NITROFW_IFTYPE_LAN : (!_wcsicmp(v, L"Wireless") ? NITROFW_IFTYPE_WIRELESS : (!_wcsicmp(v, L"RemoteAccess") ? NITROFW_IFTYPE_REMOTEACCESS : 0));
    hdr.IfTypes = ifm ? ifm : NITROFW_IFTYPE_ALL;
    if (r->App) nt = ToNtPath(r->App);
    if (!Put(b, &hdr, sizeof(hdr))) return FALSE;
    if (nlp) { PadTo8(b); hdr.LocalPortCount = nlp; hdr.LocalPortOffset = (ULONG)b->len - start; Put(b, lp, nlp * sizeof(lp[0])); }
    if (nrp) { PadTo8(b); hdr.RemotePortCount = nrp; hdr.RemotePortOffset = (ULONG)b->len - start; Put(b, rp, nrp * sizeof(rp[0])); }
    if (nla) { PadTo8(b); hdr.LocalAddr4Count = nla; hdr.LocalAddr4Offset = (ULONG)b->len - start; Put(b, la, nla * sizeof(la[0])); }
    if (nra) { PadTo8(b); hdr.RemoteAddr4Count = nra; hdr.RemoteAddr4Offset = (ULONG)b->len - start; Put(b, ra, nra * sizeof(ra[0])); }
    if (nla6) { PadTo8(b); hdr.LocalAddr6Count = nla6; hdr.LocalAddr6Offset = (ULONG)b->len - start; Put(b, la6, nla6 * sizeof(la6[0])); }
    if (nra6) { PadTo8(b); hdr.RemoteAddr6Count = nra6; hdr.RemoteAddr6Offset = (ULONG)b->len - start; Put(b, ra6, nra6 * sizeof(ra6[0])); }
    if (r->Icmp && (r->Protocol == 1 || r->Protocol == 58))
    {
        NITROFW_ICMP_ENTRY ic[32]; ULONG n = 0;
        for (i = 0; i < FwrCount(&r->Raw, r->Protocol == 1 ? L"ICMP4" : L"ICMP6") && n < 32; i++)
        {
            PCWSTR e = FwrGet(&r->Raw, r->Protocol == 1 ? L"ICMP4" : L"ICMP6", i), c = wcschr(e, L':');
            ic[n].Type = (*e == L'*') ? NITROFW_ICMP_ANY : (UCHAR)_wtoi(e);
            ic[n].Code = (!c || c[1] == L'*') ? NITROFW_ICMP_ANY : (UCHAR)_wtoi(c + 1);
            n++;
        }
        if (n) { PadTo8(b); hdr.IcmpCount = n; hdr.IcmpOffset = (ULONG)b->len - start; Put(b, ic, n * sizeof(ic[0])); }
    }
    if (nt) { PadTo8(b); hdr.AppPathOffset = (ULONG)b->len - start; Put(b, nt, (wcslen(nt) + 1) * sizeof(WCHAR)); HeapFree(GetProcessHeap(), 0, nt); }
    if (r->Svc && wcscmp(r->Svc, L"*")) { PadTo8(b); hdr.ServiceNameOffset = (ULONG)b->len - start; Put(b, r->Svc, (wcslen(r->Svc) + 1) * sizeof(WCHAR)); }
    PadTo8(b);
    hdr.Size = (ULONG)b->len - start;
    memcpy(b->p + start, &hdr, sizeof(hdr));
    return TRUE;
}

DWORD FwPushToKernel(ULONGLONG gen, BOOL *pPresent)
{
    FW_RULESET rs; BUF b = { 0 }; NITROFW_POLICY pol; HANDLE h; DWORD err, ret, i;
    ULONG cnt = 0; ULONG bit; BOOL v6on = Ipv6SwitchOn();
    HKEY hk; DWORD enforce = 1, cb = sizeof(DWORD), t;
    if (pPresent) *pPresent = FALSE;
    h = CreateFileW(NITROFW_USER_PATH, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return GetLastError();
    if (pPresent) *pPresent = TRUE;
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
    Put(&b, &pol, sizeof(pol));
    ((NITROFW_POLICY *)b.p)->RulesOffset = sizeof(pol);
    for (i = 0; i < rs.N && cnt < NITROFW_MAX_RULES; i++)
        if (rs.R[i].Enabled && BuildRule(&b, &rs.R[i], v6on)) cnt++;
    ((NITROFW_POLICY *)b.p)->RuleCount = cnt;
    ((NITROFW_POLICY *)b.p)->TotalSize = (ULONG)b.len;
    FwRuleSetFree(&rs);
    if (b.len > NITROFW_MAX_POLICY_SIZE) err = ERROR_INSUFFICIENT_BUFFER;
    else if (!DeviceIoControl(h, IOCTL_NITROFW_SET_POLICY, b.p, (DWORD)b.len, NULL, 0, &ret, NULL)) err = GetLastError();
    HeapFree(GetProcessHeap(), 0, b.p);
    CloseHandle(h);
    return err;
}
