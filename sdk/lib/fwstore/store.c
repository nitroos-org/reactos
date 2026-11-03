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

/* NitroOS default rule set: the two rules a stateless inbound filter needs to keep the network usable.
   This is NOT Microsoft's default rule set. */
static const struct { PCWSTR Id, Name, Desc, Group, Proto, Port, RPort; } g_Defaults[] = {
    { L"NitroOS-CoreNet-DHCP-In", L"NitroOS Core Networking - Dynamic Host Configuration Protocol (DHCP-In)",
      L"Allows DHCP (Dynamic Host Configuration Protocol) messages for stateful auto-configuration.",
      L"NitroOS Core Networking", L"17", L"68", L"67" },
    { L"NitroOS-CoreNet-ICMP4-DU-In", L"NitroOS Core Networking - Destination Unreachable (ICMPv4-In)",
      L"Destination Unreachable error messages are sent from any node that a packet traveled through and was unable to be forwarded at the IP layer.",
      L"NitroOS Core Networking", L"1", NULL, NULL },
};

static DWORD WriteDefaultRules(VOID)
{
    ULONG i; DWORD err = 0;
    for (i = 0; i < _countof(g_Defaults) && !err; i++)
    {
        FW_RULE r;
        FwRuleInit(&r);
        FwRuleSetStr(&r.Id, g_Defaults[i].Id); FwRuleSetStr(&r.Name, g_Defaults[i].Name);
        FwRuleSetStr(&r.Desc, g_Defaults[i].Desc); FwRuleSetStr(&r.Group, g_Defaults[i].Group);
        r.Enabled = TRUE; r.Dir = 1; r.Action = 1; r.Protocol = _wtoi(g_Defaults[i].Proto);
        if (g_Defaults[i].Port) { FwRuleSetStr(&r.LPorts, g_Defaults[i].Port); FwRuleSetStr(&r.RPorts, g_Defaults[i].RPort); }
        else FwRuleSetStr(&r.Icmp, L"3:*");
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
