/*
 * PROJECT:     NitroOS basic firewall
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Registry store: rules and profiles in Windows' own layout
 */
#include "precomp.h"
#include <rpc.h>

PCWSTR FwProfileKey(ULONG bit)
{
    switch (bit)
    {
        case FWP_DOMAIN: return FW_KEY_DOMAIN;
        case FWP_PRIVATE: return FW_KEY_STANDARD;
        case FWP_PUBLIC: return FW_KEY_PUBLIC;
    }
    return NULL;
}

static DWORD OpenRules(REGSAM sam, BOOL create, HKEY *phk)
{
    if (create)
    {
        DWORD disp;
        return RegCreateKeyExW(HKEY_LOCAL_MACHINE, FW_KEY_RULES, 0, NULL, 0, sam, NULL, phk, &disp);
    }
    return RegOpenKeyExW(HKEY_LOCAL_MACHINE, FW_KEY_RULES, 0, sam, phk);
}

DWORD FwNewId(PWSTR *pId)
{
    UUID u; RPC_WSTR s = NULL; PWSTR id;
    if (UuidCreate(&u) != RPC_S_OK && 0) return ERROR_GEN_FAILURE;
    if (UuidToStringW(&u, &s) != RPC_S_OK) return ERROR_NOT_ENOUGH_MEMORY;
    id = HeapAlloc(GetProcessHeap(), 0, (wcslen((PCWSTR)s) + 3) * sizeof(WCHAR));
    if (!id) { RpcStringFreeW(&s); return ERROR_NOT_ENOUGH_MEMORY; }
    _swprintf(id, L"{%s}", (PCWSTR)s);
    _wcsupr(id);
    RpcStringFreeW(&s);
    *pId = id;
    return 0;
}

VOID FwRuleSetFree(FW_RULESET *rs)
{
    ULONG i;
    for (i = 0; i < rs->N; i++) FwRuleFree(&rs->R[i]);
    FwFree(rs->R);
    rs->R = NULL; rs->N = 0;
}

DWORD FwStoreLoad(FW_RULESET *rs)
{
    HKEY hk;
    DWORD err, i, nvals, maxname, maxdata;
    PWSTR name = NULL; BYTE *data = NULL;
    rs->R = NULL; rs->N = 0;
    err = OpenRules(KEY_READ, FALSE, &hk);
    if (err == ERROR_FILE_NOT_FOUND) return 0;
    if (err) return err;
    err = RegQueryInfoKeyW(hk, NULL, NULL, NULL, NULL, NULL, NULL, &nvals, &maxname, &maxdata, NULL, NULL);
    if (err || !nvals) { RegCloseKey(hk); return err; }
    name = HeapAlloc(GetProcessHeap(), 0, (maxname + 2) * sizeof(WCHAR));
    data = HeapAlloc(GetProcessHeap(), 0, maxdata + 4);
    rs->R = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, nvals * sizeof(FW_RULE));
    if (!name || !data || !rs->R) { err = ERROR_NOT_ENOUGH_MEMORY; goto done; }
    for (i = 0; i < nvals; i++)
    {
        DWORD cn = maxname + 1, cd = maxdata, type;
        FWR raw;
        LONG rc = RegEnumValueW(hk, i, name, &cn, NULL, &type, data, &cd);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc || (type != REG_SZ && type != REG_EXPAND_SZ)) continue;
        data[cd] = data[cd + 1] = 0;
        if (!FwrParse(&raw, name, (PCWSTR)data)) { FwrFree(&raw); continue; }
        if (FwRuleFromRaw(&rs->R[rs->N], &raw)) rs->N++; else FwRuleFree(&rs->R[rs->N]);
        FwrFree(&raw);
    }
done:
    FwFree(name); FwFree(data); RegCloseKey(hk);
    if (err) FwRuleSetFree(rs);
    return err;
}

static DWORD WriteRule(const FW_RULE *r)
{
    HKEY hk; FWR raw; PWSTR s; DWORD err;
    if (!r->Id) return ERROR_INVALID_PARAMETER;
    if (!FwRuleToRaw(r, &raw)) { FwrFree(&raw); return ERROR_NOT_ENOUGH_MEMORY; }
    s = FwrFormat(&raw);
    FwrFree(&raw);
    if (!s) return ERROR_NOT_ENOUGH_MEMORY;
    err = OpenRules(KEY_SET_VALUE, TRUE, &hk);
    if (!err)
    {
        err = RegSetValueExW(hk, r->Id, 0, REG_SZ, (BYTE *)s, (DWORD)((wcslen(s) + 1) * sizeof(WCHAR)));
        RegCloseKey(hk);
    }
    FwFree(s);
    return err;
}

DWORD FwStoreAdd(FW_RULE *r)
{
    DWORD err;
    if (!r->Id) { PWSTR id; err = FwNewId(&id); if (err) return err; r->Id = id; }
    return WriteRule(r);
}

DWORD FwStoreUpdate(const FW_RULE *r) { return WriteRule(r); }

DWORD FwStoreDelete(PCWSTR Id)
{
    HKEY hk; DWORD err = OpenRules(KEY_SET_VALUE, FALSE, &hk);
    if (err) return err;
    err = RegDeleteValueW(hk, Id);
    RegCloseKey(hk);
    return err;
}

DWORD FwStoreDeleteAll(VOID)
{
    DWORD err = RegDeleteKeyW(HKEY_LOCAL_MACHINE, FW_KEY_RULES);
    return err == ERROR_FILE_NOT_FOUND ? 0 : err;
}

/* ---- profiles ---- */

static DWORD GetDw(HKEY hk, PCWSTR n, DWORD def)
{
    DWORD v, cb = sizeof(v), t;
    if (hk && RegQueryValueExW(hk, n, NULL, &t, (BYTE *)&v, &cb) == 0 && t == REG_DWORD) return v;
    return def;
}

DWORD FwProfileLoad(ULONG bit, FW_PROFILE *p)
{
    HKEY hk = NULL, hl = NULL;
    PCWSTR key = FwProfileKey(bit);
    WCHAR path[300];
    DWORD cb, t;
    if (!key) return ERROR_INVALID_PARAMETER;
    memset(p, 0, sizeof(*p));
    RegOpenKeyExW(HKEY_LOCAL_MACHINE, key, 0, KEY_READ, &hk);
    _swprintf(path, L"%s\\Logging", key);
    RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &hl);
    p->Enable = GetDw(hk, L"EnableFirewall", 1);
    p->DoNotAllowExceptions = GetDw(hk, L"DoNotAllowExceptions", 0);
    p->DisableNotifications = GetDw(hk, L"DisableNotifications", 0);
    p->DefaultInbound = GetDw(hk, L"DefaultInboundAction", 1);
    p->DefaultOutbound = GetDw(hk, L"DefaultOutboundAction", 0);
    p->DisableUnicastResponses = GetDw(hk, L"DisableUnicastResponsesToMulticastBroadcast", 0);
    p->LogFileSize = GetDw(hl, L"LogFileSize", 4096);
    p->LogDropped = GetDw(hl, L"LogDroppedPackets", 0);
    p->LogSuccess = GetDw(hl, L"LogSuccessfulConnections", 0);
    wcscpy(p->LogFile, L"%systemroot%\\system32\\LogFiles\\Firewall\\pfirewall.log");
    cb = sizeof(p->LogFile) - sizeof(WCHAR);
    if (hl && RegQueryValueExW(hl, L"LogFilePath", NULL, &t, (BYTE *)p->LogFile, &cb) == 0) p->LogFile[cb / sizeof(WCHAR)] = 0;
    if (hk) RegCloseKey(hk);
    if (hl) RegCloseKey(hl);
    return 0;
}

static DWORD OpenProfileKey(ULONG bit, BOOL logging, HKEY *phk)
{
    WCHAR path[300]; DWORD disp; PCWSTR key = FwProfileKey(bit);
    if (!key) return ERROR_INVALID_PARAMETER;
    if (logging) _swprintf(path, L"%s\\Logging", key); else wcscpy(path, key);
    return RegCreateKeyExW(HKEY_LOCAL_MACHINE, path, 0, NULL, 0, KEY_SET_VALUE, NULL, phk, &disp);
}

DWORD FwProfileSetDword(ULONG bit, PCWSTR name, DWORD v, BOOL logging)
{
    HKEY hk; DWORD err = OpenProfileKey(bit, logging, &hk);
    if (err) return err;
    err = RegSetValueExW(hk, name, 0, REG_DWORD, (BYTE *)&v, sizeof(v));
    RegCloseKey(hk);
    return err;
}

DWORD FwProfileSetString(ULONG bit, PCWSTR name, PCWSTR v, BOOL logging)
{
    HKEY hk; DWORD err = OpenProfileKey(bit, logging, &hk);
    if (err) return err;
    err = RegSetValueExW(hk, name, 0, REG_EXPAND_SZ, (BYTE *)v, (DWORD)((wcslen(v) + 1) * sizeof(WCHAR)));
    RegCloseKey(hk);
    return err;
}

DWORD FwProfileReset(ULONG bit)
{
    PCWSTR key = FwProfileKey(bit);
    DWORD err;
    if (!key) return ERROR_INVALID_PARAMETER;
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, key);   /* the Logging subkey is empty-leafed by the delete below */
    { WCHAR path[300]; _swprintf(path, L"%s\\Logging", key); RegDeleteKeyW(HKEY_LOCAL_MACHINE, path); RegDeleteKeyW(HKEY_LOCAL_MACHINE, key); }
    err = FwProfileSetDword(bit, L"DisableNotifications", 0, FALSE);
    if (!err) err = FwProfileSetDword(bit, L"EnableFirewall", 1, FALSE);
    if (!err) err = FwProfileSetDword(bit, L"LogDroppedPackets", 0, TRUE);
    if (!err) err = FwProfileSetString(bit, L"LogFilePath", L"%systemroot%\\system32\\LogFiles\\Firewall\\pfirewall.log", TRUE);
    if (!err) err = FwProfileSetDword(bit, L"LogFileSize", 4096, TRUE);
    if (!err) err = FwProfileSetDword(bit, L"LogSuccessfulConnections", 0, TRUE);
    return err;
}

/* Default rule set: the Windows 10 Core Networking group as measured on the oracle (inbound IPv4 DHCP, IGMP,
   ICMPv4 errors; the IPv6/NDP rules are stored for parity and match nothing in the IPv4-only filter), plus
   rules that ship DISABLED so that netsh/INetFwPolicy2 can enable them by group, as on Windows. Rules whose
   Windows form needs a service or keyword the filter cannot match are not included (Teredo, IPHTTPS, mDNS,
   Delivery Optimization, Network Discovery, WinRM). The same strings are in boot/bootdata/hivesys.inf: keep
   them identical (generated from one list; see the tools note in the commit). */
static const struct { PCWSTR Id, Rule; } g_Defaults[] = {
    { L"CoreNet-DHCP-In",
      L"v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=17|LPort=68|RPort=67|Name=Core Networking - Dynamic Host Configuration Protocol (DHCP-In)|Desc=Allows inbound DHCP replies (UDP 67 -> 68).|EmbedCtxt=Core Networking|" },
    { L"CoreNet-DHCPV6-In",
      L"v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=17|LPort=546|RPort=547|Name=Core Networking - Dynamic Host Configuration Protocol for IPv6(DHCPV6-In)|Desc=Allows inbound DHCPv6 replies (UDP 547 -> 546).|EmbedCtxt=Core Networking|" },
    { L"CoreNet-ICMP4-DUFRAG-In",
      L"v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=1|ICMP4=3:4|Name=Core Networking - Destination Unreachable Fragmentation Needed (ICMPv4-In)|Desc=Allows inbound ICMPv4 destination unreachable, fragmentation needed (type 3 code 4).|EmbedCtxt=Core Networking|" },
    { L"CoreNet-IGMP-In",
      L"v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=2|Name=Core Networking - Internet Group Management Protocol (IGMP-In)|Desc=Allows inbound IGMP (IP protocol 2) multicast membership messages.|EmbedCtxt=Core Networking|" },
    { L"CoreNet-IPv6-In",
      L"v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=41|Name=Core Networking - IPv6 (IPv6-In)|Desc=Allows inbound IPv6-in-IPv4 encapsulated traffic (IP protocol 41).|EmbedCtxt=Core Networking|" },
    { L"CoreNet-ICMP6-LD-In",
      L"v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=58|ICMP6=132:*|Name=Core Networking - Multicast Listener Done (ICMPv6-In)|Desc=Allows inbound ICMPv6 multicast listener done (type 132).|EmbedCtxt=Core Networking|" },
    { L"CoreNet-ICMP6-LR2-In",
      L"v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=58|ICMP6=143:*|Name=Core Networking - Multicast Listener Report v2 (ICMPv6-In)|Desc=Allows inbound ICMPv6 multicast listener report v2 (type 143).|EmbedCtxt=Core Networking|" },
    { L"CoreNet-ICMP6-LR-In",
      L"v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=58|ICMP6=131:*|Name=Core Networking - Multicast Listener Report (ICMPv6-In)|Desc=Allows inbound ICMPv6 multicast listener report (type 131).|EmbedCtxt=Core Networking|" },
    { L"CoreNet-ICMP6-LQ-In",
      L"v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=58|ICMP6=130:*|Name=Core Networking - Multicast Listener Query (ICMPv6-In)|Desc=Allows inbound ICMPv6 multicast listener query (type 130).|EmbedCtxt=Core Networking|" },
    { L"CoreNet-ICMP6-RS-In",
      L"v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=58|ICMP6=133:*|Name=Core Networking - Router Solicitation (ICMPv6-In)|Desc=Allows inbound ICMPv6 router solicitation (type 133).|EmbedCtxt=Core Networking|" },
    { L"CoreNet-ICMP6-RA-In",
      L"v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=58|ICMP6=134:*|Name=Core Networking - Router Advertisement (ICMPv6-In)|Desc=Allows inbound ICMPv6 router advertisement (type 134).|EmbedCtxt=Core Networking|" },
    { L"CoreNet-ICMP6-NDA-In",
      L"v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=58|ICMP6=136:*|Name=Core Networking - Neighbor Discovery Advertisement (ICMPv6-In)|Desc=Allows inbound ICMPv6 neighbor advertisement (type 136).|EmbedCtxt=Core Networking|" },
    { L"CoreNet-ICMP6-NDS-In",
      L"v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=58|ICMP6=135:*|Name=Core Networking - Neighbor Discovery Solicitation (ICMPv6-In)|Desc=Allows inbound ICMPv6 neighbor solicitation (type 135).|EmbedCtxt=Core Networking|" },
    { L"CoreNet-ICMP6-PP-In",
      L"v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=58|ICMP6=4:*|Name=Core Networking - Parameter Problem (ICMPv6-In)|Desc=Allows inbound ICMPv6 parameter problem errors (type 4).|EmbedCtxt=Core Networking|" },
    { L"CoreNet-ICMP6-TE-In",
      L"v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=58|ICMP6=3:*|Name=Core Networking - Time Exceeded (ICMPv6-In)|Desc=Allows inbound ICMPv6 time exceeded errors (type 3).|EmbedCtxt=Core Networking|" },
    { L"CoreNet-ICMP6-PTB-In",
      L"v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=58|ICMP6=2:*|Name=Core Networking - Packet Too Big (ICMPv6-In)|Desc=Allows inbound ICMPv6 packet too big errors (type 2).|EmbedCtxt=Core Networking|" },
    { L"CoreNet-ICMP6-DU-In",
      L"v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=58|ICMP6=1:*|Name=Core Networking - Destination Unreachable (ICMPv6-In)|Desc=Allows inbound ICMPv6 destination unreachable errors (type 1).|EmbedCtxt=Core Networking|" },
    { L"CoreNet-DHCP-Out",
      L"v2.30|Action=Allow|Active=TRUE|Dir=Out|Protocol=17|LPort=68|RPort=67|Name=Core Networking - Dynamic Host Configuration Protocol (DHCP-Out)|Desc=Allows outbound DHCP client requests (UDP 68 -> 67).|EmbedCtxt=Core Networking|" },
    { L"CoreNet-DNS-Out-UDP",
      L"v2.30|Action=Allow|Active=TRUE|Dir=Out|Protocol=17|RPort=53|Name=Core Networking - DNS (UDP-Out)|Desc=Allows outbound DNS queries over UDP (port 53).|EmbedCtxt=Core Networking|" },
    { L"CoreNet-IPv6-Out",
      L"v2.30|Action=Allow|Active=TRUE|Dir=Out|Protocol=41|Name=Core Networking - IPv6 (IPv6-Out)|Desc=Allows outbound IPv6-in-IPv4 encapsulated traffic (IP protocol 41).|EmbedCtxt=Core Networking|" },
    { L"CoreNet-Diag-ICMP4-EchoRequest-In",
      L"v2.30|Action=Allow|Active=FALSE|Dir=In|Protocol=1|Profile=Private|Profile=Public|ICMP4=8:*|RA4=LocalSubnet|Name=Core Networking Diagnostics - ICMP Echo Request (ICMPv4-In)|Desc=Allows inbound ICMPv4 echo requests (ping) from the local subnet. Disabled by default.|EmbedCtxt=Core Networking Diagnostics|" },
    { L"CoreNet-Diag-ICMP4-EchoRequest-In-NoScope",
      L"v2.30|Action=Allow|Active=FALSE|Dir=In|Protocol=1|Profile=Domain|ICMP4=8:*|Name=Core Networking Diagnostics - ICMP Echo Request (ICMPv4-In)|Desc=Allows inbound ICMPv4 echo requests (ping) from any address, Domain profile. Disabled by default.|EmbedCtxt=Core Networking Diagnostics|" },
    { L"FPS-ICMP4-ERQ-In",
      L"v2.30|Action=Allow|Active=FALSE|Dir=In|Protocol=1|Profile=Private|Profile=Public|ICMP4=8:*|RA4=LocalSubnet|Name=File and Printer Sharing (Echo Request - ICMPv4-In)|Desc=Allows inbound ICMPv4 echo requests (ping) from the local subnet. Disabled by default.|EmbedCtxt=File and Printer Sharing|" },
    { L"FPS-ICMP4-ERQ-In-NoScope",
      L"v2.30|Action=Allow|Active=FALSE|Dir=In|Protocol=1|Profile=Domain|ICMP4=8:*|Name=File and Printer Sharing (Echo Request - ICMPv4-In)|Desc=Allows inbound ICMPv4 echo requests (ping) from any address, Domain profile. Disabled by default.|EmbedCtxt=File and Printer Sharing|" },
    { L"FPS-SMB-In-TCP",
      L"v2.30|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=445|RA4=LocalSubnet|Name=File and Printer Sharing (SMB-In)|Desc=Allows inbound SMB file sharing (TCP 445) from the local subnet. Disabled by default.|EmbedCtxt=File and Printer Sharing|" },
    { L"FPS-SMB-In-TCP-NoScope",
      L"v2.30|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=445|Name=File and Printer Sharing (SMB-In)|Desc=Allows inbound SMB file sharing (TCP 445), Domain profile. Disabled by default.|EmbedCtxt=File and Printer Sharing|" },
    { L"FPS-NB_Session-In-TCP",
      L"v2.30|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=139|RA4=LocalSubnet|Name=File and Printer Sharing (NB-Session-In)|Desc=Allows inbound NetBIOS session service (TCP 139) from the local subnet. Disabled by default.|EmbedCtxt=File and Printer Sharing|" },
    { L"FPS-NB_Session-In-TCP-NoScope",
      L"v2.30|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|LPort=139|Name=File and Printer Sharing (NB-Session-In)|Desc=Allows inbound NetBIOS session service (TCP 139), Domain profile. Disabled by default.|EmbedCtxt=File and Printer Sharing|" },
    { L"FPS-NB_Datagram-In-UDP",
      L"v2.30|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Private|Profile=Public|LPort=138|RA4=LocalSubnet|Name=File and Printer Sharing (NB-Datagram-In)|Desc=Allows inbound NetBIOS datagram service (UDP 138) from the local subnet. Disabled by default.|EmbedCtxt=File and Printer Sharing|" },
    { L"FPS-NB_Datagram-In-UDP-NoScope",
      L"v2.30|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|LPort=138|Name=File and Printer Sharing (NB-Datagram-In)|Desc=Allows inbound NetBIOS datagram service (UDP 138), Domain profile. Disabled by default.|EmbedCtxt=File and Printer Sharing|" },
    { L"FPS-NB_Name-In-UDP",
      L"v2.30|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Private|Profile=Public|LPort=137|RA4=LocalSubnet|Name=File and Printer Sharing (NB-Name-In)|Desc=Allows inbound NetBIOS name service (UDP 137) from the local subnet. Disabled by default.|EmbedCtxt=File and Printer Sharing|" },
    { L"FPS-NB_Name-In-UDP-NoScope",
      L"v2.30|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|LPort=137|Name=File and Printer Sharing (NB-Name-In)|Desc=Allows inbound NetBIOS name service (UDP 137), Domain profile. Disabled by default.|EmbedCtxt=File and Printer Sharing|" },
    { L"RemoteDesktop-UserMode-In-TCP",
      L"v2.30|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|Profile=Private|Profile=Public|LPort=3389|Name=Remote Desktop - User Mode (TCP-In)|Desc=Allows inbound Remote Desktop connections (TCP 3389). Disabled by default.|EmbedCtxt=Remote Desktop|" },
    { L"RemoteDesktop-UserMode-In-UDP",
      L"v2.30|Action=Allow|Active=FALSE|Dir=In|Protocol=17|Profile=Domain|Profile=Private|Profile=Public|LPort=3389|Name=Remote Desktop - User Mode (UDP-In)|Desc=Allows inbound Remote Desktop traffic (UDP 3389). Disabled by default.|EmbedCtxt=Remote Desktop|" },
};

static DWORD WriteDefaultRules(VOID)
{
    ULONG i; DWORD err = 0;
    for (i = 0; i < _countof(g_Defaults) && !err; i++)
    {
        FW_RULE r; FWR raw;
        if (!FwrParse(&raw, g_Defaults[i].Id, g_Defaults[i].Rule)) { FwrFree(&raw); return ERROR_OUTOFMEMORY; }
        FwRuleInit(&r);
        if (!FwRuleFromRaw(&r, &raw)) { FwRuleFree(&r); FwrFree(&raw); return ERROR_OUTOFMEMORY; }
        FwrFree(&raw);
        err = FwStoreAdd(&r);
        FwRuleFree(&r);
    }
    return err;
}

DWORD FwResetAll(VOID)
{
    DWORD err;
    FwStoreDeleteAll();
    err = FwProfileReset(FWP_DOMAIN);
    if (!err) err = FwProfileReset(FWP_PRIVATE);
    if (!err) err = FwProfileReset(FWP_PUBLIC);
    if (!err) err = WriteDefaultRules();
    return err;
}

ULONG FwCurrentProfiles(VOID)
{
    HKEY hk; DWORD v = FWP_PRIVATE;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\ReactOS\\Nitro\\Firewall", 0, KEY_READ, &hk) == 0)
    {
        v = GetDw(hk, L"CurrentProfile", FWP_PRIVATE);
        RegCloseKey(hk);
    }
    return (v == FWP_DOMAIN || v == FWP_PRIVATE || v == FWP_PUBLIC) ? v : FWP_PRIVATE;
}

DWORD FwWatchOpen(HKEY *phk)
{
    DWORD disp;
    return RegCreateKeyExW(HKEY_LOCAL_MACHINE, FW_KEY_POLICY, 0, NULL, 0, KEY_NOTIFY | KEY_READ, NULL, phk, &disp);
}
