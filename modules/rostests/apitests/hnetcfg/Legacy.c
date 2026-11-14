/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The legacy firewall automation objects of hnetcfg.dll (INetFwMgr, INetFwProfile,
 *              AuthorizedApplications, GloballyOpenPorts, Services): entries become rules of INetFwPolicy2
 *              and are listed and removed through the collections
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define COBJMACROS
#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#include <ole2.h>
#include <oleauto.h>
#include <netfw.h>
#include <wchar.h>

static const GUID MY_CLSID_Mgr  = {0x304CE942, 0x6E39, 0x40D8, {0x94, 0x3A, 0xB9, 0x13, 0xC4, 0x0C, 0x9C, 0xD4}};
static const GUID MY_CLSID_App  = {0xEC9846B3, 0x2762, 0x4A6B, {0xA2, 0x14, 0x6A, 0xCB, 0x60, 0x34, 0x62, 0xD2}};
static const GUID MY_CLSID_Port = {0x0CA545C6, 0x37AD, 0x4A6C, {0xBF, 0x92, 0x9F, 0x76, 0x10, 0x06, 0x7E, 0xF5}};
static const GUID MY_CLSID_Pol2 = {0xE2B3C97F, 0x6AE1, 0x41AC, {0x81, 0x7A, 0xF6, 0xF9, 0x21, 0x66, 0xD7, 0xDD}};
static const GUID MY_IID_Mgr    = {0xF7898AF5, 0xCAC4, 0x4632, {0xA2, 0xEC, 0xDA, 0x06, 0xE5, 0x11, 0x1A, 0xF2}};
static const GUID MY_IID_App    = {0xB5E64FFA, 0xC2C5, 0x444E, {0xA3, 0x01, 0xFB, 0x5E, 0x00, 0x01, 0x80, 0x50}};
static const GUID MY_IID_Port   = {0xE0483BA0, 0x47FF, 0x4D9C, {0xA6, 0xD6, 0x77, 0x41, 0xD0, 0xB1, 0x95, 0xF7}};
static const GUID MY_IID_Pol2   = {0x98325047, 0xC671, 0x4174, {0x8D, 0x81, 0xDE, 0xFC, 0xD3, 0xF0, 0x31, 0x86}};

static BSTR B(const wchar_t *s) { return SysAllocString(s); }

static INetFwProfile *CurrentProfile(INetFwMgr *mgr)
{
    INetFwPolicy *pol = NULL; INetFwProfile *prof = NULL;
    HRESULT hr = INetFwMgr_get_LocalPolicy(mgr, &pol);
    if (FAILED(hr)) return NULL;
    hr = INetFwPolicy_get_CurrentProfile(pol, &prof);
    INetFwPolicy_Release(pol);
    return SUCCEEDED(hr) ? prof : NULL;
}

static INetFwRule *FindRule(INetFwPolicy2 *p2, const wchar_t *name)
{
    INetFwRules *rules = NULL; INetFwRule *r = NULL; BSTR n = B(name);
    if (SUCCEEDED(INetFwPolicy2_get_Rules(p2, &rules))) { if (FAILED(INetFwRules_Item(rules, n, &r))) r = NULL; INetFwRules_Release(rules); }
    SysFreeString(n);
    return r;
}

static int EnumCount(IUnknown *unk, int *names)
{
    IEnumVARIANT *e = NULL; VARIANT v; ULONG got; int n = 0;
    if (FAILED(IUnknown_QueryInterface(unk, &IID_IEnumVARIANT, (void **)&e))) return -1;
    for (;;)
    {
        VariantInit(&v);
        if (IEnumVARIANT_Next(e, 1, &v, &got) != S_OK || got != 1) break;
        if (V_VT(&v) == VT_DISPATCH && V_DISPATCH(&v)) n++;
        VariantClear(&v);
    }
    IEnumVARIANT_Release(e);
    return n;
}

static void TestApps(INetFwProfile *prof, INetFwPolicy2 *p2, const wchar_t *self)
{
    INetFwAuthorizedApplications *apps = NULL; INetFwAuthorizedApplication *app = NULL, *app2 = NULL;
    HRESULT hr; LONG c0, c1; BSTR s; NET_FW_SCOPE sc; VARIANT_BOOL vb; INetFwRule *r; IUnknown *en = NULL;
    NET_FW_IP_VERSION ipv;
    trace("%s\n", "apps");
    hr = INetFwProfile_get_AuthorizedApplications(prof, &apps);
    ok(hr == S_OK && apps, "get_AuthorizedApplications %08lx\n", hr);
    if (!apps) return;
    hr = INetFwAuthorizedApplications_get_Count(apps, &c0);
    ok(hr == S_OK, "Count %08lx\n", hr);
    hr = INetFwAuthorizedApplications_Add(apps, NULL);
    ok(hr == E_POINTER, "Add(NULL) %08lx\n", hr);
    s = B(L"C:\\fwleg\\missing.exe");
    hr = INetFwAuthorizedApplications_Item(apps, s, &app);
    ok(hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), "Item missing %08lx\n", hr);
    SysFreeString(s);

    hr = CoCreateInstance(&MY_CLSID_App, NULL, CLSCTX_INPROC_SERVER, &MY_IID_App, (void **)&app);
    ok(hr == S_OK, "CoCreate app %08lx\n", hr);
    if (!app) { INetFwAuthorizedApplications_Release(apps); return; }
    hr = INetFwAuthorizedApplications_Add(apps, app);
    ok(hr == E_INVALIDARG, "Add without image %08lx\n", hr);
    s = B(L"FwLegTestApp"); hr = INetFwAuthorizedApplication_put_Name(app, s); SysFreeString(s);
    ok(hr == S_OK, "put_Name %08lx\n", hr);
    s = B(self); hr = INetFwAuthorizedApplication_put_ProcessImageFileName(app, s); SysFreeString(s);
    ok(hr == S_OK, "put_Image %08lx\n", hr);
    hr = INetFwAuthorizedApplication_put_Scope(app, NET_FW_SCOPE_LOCAL_SUBNET);
    ok(hr == S_OK, "put_Scope %08lx\n", hr);
    hr = INetFwAuthorizedApplication_put_Scope(app, (NET_FW_SCOPE)7);
    ok(hr == E_INVALIDARG, "put_Scope(7) %08lx\n", hr);
    hr = INetFwAuthorizedApplication_put_IpVersion(app, NET_FW_IP_VERSION_V4);
    ok(hr == S_OK, "put_IpVersion %08lx\n", hr);
    hr = INetFwAuthorizedApplication_put_IpVersion(app, (NET_FW_IP_VERSION)9);
    ok(hr == E_INVALIDARG, "put_IpVersion(9) %08lx\n", hr);
    hr = INetFwAuthorizedApplication_put_Enabled(app, VARIANT_TRUE);
    hr = INetFwAuthorizedApplications_Add(apps, app);
    ok(hr == S_OK, "Add %08lx\n", hr);
    hr = INetFwAuthorizedApplications_get_Count(apps, &c1);
    ok(hr == S_OK && c1 == c0 + 1, "Count after add %ld (was %ld)\n", c1, c0);
    /* adding the same program again replaces the entry */
    hr = INetFwAuthorizedApplications_Add(apps, app);
    ok(hr == S_OK, "Add again %08lx\n", hr);
    hr = INetFwAuthorizedApplications_get_Count(apps, &c1);
    ok(hr == S_OK && c1 == c0 + 1, "Count after second add %ld\n", c1);

    s = B(self); hr = INetFwAuthorizedApplications_Item(apps, s, &app2); SysFreeString(s);
    ok(hr == S_OK && app2, "Item %08lx\n", hr);
    if (app2)
    {
        hr = INetFwAuthorizedApplication_get_Name(app2, &s);
        ok(hr == S_OK && s && !wcscmp(s, L"FwLegTestApp"), "Item name %ls\n", s ? s : L"(null)"); SysFreeString(s);
        hr = INetFwAuthorizedApplication_get_Scope(app2, &sc);
        ok(hr == S_OK && sc == NET_FW_SCOPE_LOCAL_SUBNET, "Item scope %d\n", (int)sc);
        hr = INetFwAuthorizedApplication_get_IpVersion(app2, &ipv);
        ok(hr == S_OK && ipv == NET_FW_IP_VERSION_V4, "Item ipver %d\n", (int)ipv);
        hr = INetFwAuthorizedApplication_get_RemoteAddresses(app2, &s);
        ok(hr == S_OK && s && !_wcsicmp(s, L"LocalSubnet"), "Item remote %ls\n", s ? s : L"(null)"); SysFreeString(s);
        hr = INetFwAuthorizedApplication_get_Enabled(app2, &vb);
        ok(hr == S_OK && vb == VARIANT_TRUE, "Item enabled %d\n", (int)vb);
        /* a property write on a stored entry is committed at once */
        hr = INetFwAuthorizedApplication_put_Enabled(app2, VARIANT_FALSE);
        ok(hr == S_OK, "put_Enabled(stored) %08lx\n", hr);
        INetFwAuthorizedApplication_Release(app2); app2 = NULL;
        s = B(self); hr = INetFwAuthorizedApplications_Item(apps, s, &app2); SysFreeString(s);
        if (app2) { INetFwAuthorizedApplication_get_Enabled(app2, &vb); ok(vb == VARIANT_FALSE, "disabled persisted %d\n", (int)vb);
                    INetFwAuthorizedApplication_put_Enabled(app2, VARIANT_TRUE); INetFwAuthorizedApplication_Release(app2); }
    }
    /* INetFwPolicy2 sees a real rule */
    r = FindRule(p2, L"FwLegTestApp");
    ok(r != NULL, "policy2 rule FwLegTestApp not found\n");
    if (r)
    {
        NET_FW_ACTION act; NET_FW_RULE_DIRECTION dir; BSTR app_;
        INetFwRule_get_Action(r, &act); ok(act == NET_FW_ACTION_ALLOW, "rule action %d\n", (int)act);
        INetFwRule_get_Direction(r, &dir); ok(dir == NET_FW_RULE_DIR_IN, "rule dir %d\n", (int)dir);
        INetFwRule_get_Enabled(r, &vb); ok(vb == VARIANT_TRUE, "rule enabled %d\n", (int)vb);
        hr = INetFwRule_get_ApplicationName(r, &app_);
        ok(hr == S_OK && app_ && !_wcsicmp(app_, self), "rule app %ls\n", app_ ? app_ : L"(null)"); SysFreeString(app_);
        INetFwRule_Release(r);
    }
    hr = INetFwAuthorizedApplications_get__NewEnum(apps, &en);
    ok(hr == S_OK && en, "NewEnum %08lx\n", hr);
    if (en) { int n = EnumCount(en, NULL); ok(n == c0 + 1, "enum count %d\n", n); IUnknown_Release(en); }
    /* custom scope */
    s = B(L"10.1.2.3,192.168.0.0/255.255.0.0"); hr = INetFwAuthorizedApplication_put_RemoteAddresses(app, s); SysFreeString(s);
    ok(hr == S_OK, "put_RemoteAddresses %08lx\n", hr);
    hr = INetFwAuthorizedApplication_get_Scope(app, &sc);
    ok(hr == S_OK && sc == NET_FW_SCOPE_CUSTOM, "custom scope %d\n", (int)sc);
    s = B(L"not an address"); hr = INetFwAuthorizedApplication_put_RemoteAddresses(app, s); SysFreeString(s);
    ok(hr == E_INVALIDARG, "bad address %08lx\n", hr);

    s = B(self); hr = INetFwAuthorizedApplications_Remove(apps, s); SysFreeString(s);
    ok(hr == S_OK, "Remove %08lx\n", hr);
    hr = INetFwAuthorizedApplications_get_Count(apps, &c1);
    ok(hr == S_OK && c1 == c0, "Count after remove %ld\n", c1);
    r = FindRule(p2, L"FwLegTestApp");
    ok(r == NULL, "rule still there after Remove\n");
    if (r) INetFwRule_Release(r);
    s = B(self); hr = INetFwAuthorizedApplications_Remove(apps, s); SysFreeString(s);
    ok(hr == S_OK, "Remove again %08lx\n", hr);
    INetFwAuthorizedApplication_Release(app);
    INetFwAuthorizedApplications_Release(apps);
}

static void TestPorts(INetFwProfile *prof, INetFwPolicy2 *p2)
{
    INetFwOpenPorts *ports = NULL; INetFwOpenPort *port = NULL, *port2 = NULL;
    HRESULT hr; LONG c0, c1, num; BSTR s; VARIANT_BOOL vb; INetFwRule *r; IUnknown *en = NULL;
    NET_FW_IP_PROTOCOL proto;
    trace("%s\n", "ports");
    hr = INetFwProfile_get_GloballyOpenPorts(prof, &ports);
    ok(hr == S_OK && ports, "get_GloballyOpenPorts %08lx\n", hr);
    if (!ports) return;
    hr = INetFwOpenPorts_get_Count(ports, &c0);
    ok(hr == S_OK, "Count %08lx\n", hr);
    hr = INetFwOpenPorts_Item(ports, 54321, NET_FW_IP_PROTOCOL_TCP, &port);
    ok(hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), "Item missing %08lx\n", hr);
    hr = INetFwOpenPorts_Item(ports, 54321, (NET_FW_IP_PROTOCOL)5, &port);
    ok(hr == E_INVALIDARG, "Item bad proto %08lx\n", hr);
    hr = CoCreateInstance(&MY_CLSID_Port, NULL, CLSCTX_INPROC_SERVER, &MY_IID_Port, (void **)&port);
    ok(hr == S_OK, "CoCreate port %08lx\n", hr);
    if (!port) { INetFwOpenPorts_Release(ports); return; }
    hr = INetFwOpenPorts_Add(ports, port);
    ok(hr == E_INVALIDARG, "Add without port %08lx\n", hr);
    hr = INetFwOpenPort_put_Port(port, 0); ok(hr == E_INVALIDARG, "put_Port(0) %08lx\n", hr);
    hr = INetFwOpenPort_put_Port(port, 70000); ok(hr == E_INVALIDARG, "put_Port(70000) %08lx\n", hr);
    hr = INetFwOpenPort_put_Protocol(port, (NET_FW_IP_PROTOCOL)5); ok(hr == E_INVALIDARG, "put_Protocol(5) %08lx\n", hr);
    s = B(L"FwLegTestPort"); hr = INetFwOpenPort_put_Name(port, s); SysFreeString(s);
    hr = INetFwOpenPort_put_Port(port, 54321); ok(hr == S_OK, "put_Port %08lx\n", hr);
    hr = INetFwOpenPort_put_Protocol(port, NET_FW_IP_PROTOCOL_UDP); ok(hr == S_OK, "put_Protocol %08lx\n", hr);
    hr = INetFwOpenPort_get_BuiltIn(port, &vb); ok(hr == S_OK && vb == VARIANT_FALSE, "BuiltIn\n");
    hr = INetFwOpenPorts_Add(ports, port);
    ok(hr == S_OK, "Add %08lx\n", hr);
    hr = INetFwOpenPorts_get_Count(ports, &c1);
    ok(hr == S_OK && c1 == c0 + 1, "Count after add %ld (was %ld)\n", c1, c0);
    hr = INetFwOpenPorts_Item(ports, 54321, NET_FW_IP_PROTOCOL_TCP, &port2);
    ok(hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), "Item TCP (entry is UDP) %08lx\n", hr);
    hr = INetFwOpenPorts_Item(ports, 54321, NET_FW_IP_PROTOCOL_UDP, &port2);
    ok(hr == S_OK && port2, "Item UDP %08lx\n", hr);
    if (port2)
    {
        hr = INetFwOpenPort_get_Name(port2, &s); ok(hr == S_OK && s && !wcscmp(s, L"FwLegTestPort"), "Item name\n"); SysFreeString(s);
        hr = INetFwOpenPort_get_Port(port2, &num); ok(hr == S_OK && num == 54321, "Item port %ld\n", num);
        hr = INetFwOpenPort_get_Protocol(port2, &proto); ok(hr == S_OK && proto == NET_FW_IP_PROTOCOL_UDP, "Item proto %d\n", (int)proto);
        hr = INetFwOpenPort_get_Enabled(port2, &vb); ok(hr == S_OK && vb == VARIANT_TRUE, "Item enabled\n");
        INetFwOpenPort_Release(port2);
    }
    r = FindRule(p2, L"FwLegTestPort");
    ok(r != NULL, "policy2 rule FwLegTestPort not found\n");
    if (r)
    {
        LONG pr; BSTR lp;
        INetFwRule_get_Protocol(r, &pr); ok(pr == 17, "rule protocol %ld\n", pr);
        hr = INetFwRule_get_LocalPorts(r, &lp); ok(hr == S_OK && lp && !wcscmp(lp, L"54321"), "rule lports %ls\n", lp ? lp : L"(null)"); SysFreeString(lp);
        INetFwRule_Release(r);
    }
    /* a TCP entry on the same number is a different entry */
    INetFwOpenPort_put_Protocol(port, NET_FW_IP_PROTOCOL_TCP);
    hr = INetFwOpenPorts_Add(ports, port); ok(hr == S_OK, "Add TCP %08lx\n", hr);
    hr = INetFwOpenPorts_get_Count(ports, &c1); ok(hr == S_OK && c1 == c0 + 2, "Count with both %ld\n", c1);
    hr = INetFwOpenPorts_get__NewEnum(ports, &en);
    ok(hr == S_OK && en, "NewEnum %08lx\n", hr);
    if (en) { int n = EnumCount(en, NULL); ok(n == c0 + 2, "enum count %d\n", n); IUnknown_Release(en); }
    hr = INetFwOpenPorts_Remove(ports, 54321, NET_FW_IP_PROTOCOL_TCP); ok(hr == S_OK, "Remove TCP %08lx\n", hr);
    hr = INetFwOpenPorts_Remove(ports, 54321, NET_FW_IP_PROTOCOL_UDP); ok(hr == S_OK, "Remove UDP %08lx\n", hr);
    hr = INetFwOpenPorts_Remove(ports, 0, NET_FW_IP_PROTOCOL_UDP); ok(hr == E_INVALIDARG, "Remove(0) %08lx\n", hr);
    hr = INetFwOpenPorts_get_Count(ports, &c1); ok(hr == S_OK && c1 == c0, "Count after remove %ld\n", c1);
    r = FindRule(p2, L"FwLegTestPort"); ok(r == NULL, "port rule still there\n"); if (r) INetFwRule_Release(r);
    INetFwOpenPort_Release(port);
    INetFwOpenPorts_Release(ports);
}

static void TestServices(INetFwProfile *prof)
{
    INetFwServices *svcs = NULL; INetFwService *svc = NULL; HRESULT hr; LONG n; BSTR s; VARIANT_BOOL en0, en1;
    NET_FW_SERVICE_TYPE t; IUnknown *e = NULL; INetFwOpenPorts *gp = NULL;
    trace("%s\n", "services");
    hr = INetFwProfile_get_Services(prof, &svcs);
    ok(hr == S_OK && svcs, "get_Services %08lx\n", hr);
    if (!svcs) return;
    hr = INetFwServices_get_Count(svcs, &n); ok(hr == S_OK && n == 3, "Count %ld\n", n);
    hr = INetFwServices_Item(svcs, NET_FW_SERVICE_NONE, &svc); ok(hr == E_INVALIDARG, "Item(NONE) %08lx\n", hr);
    hr = INetFwServices_Item(svcs, NET_FW_SERVICE_FILE_AND_PRINT, &svc);
    ok(hr == S_OK && svc, "Item FPS %08lx\n", hr);
    if (svc)
    {
        hr = INetFwService_get_Name(svc, &s); ok(hr == S_OK && s && !wcscmp(s, L"File and Printer Sharing"), "name %ls\n", s ? s : L"(null)"); SysFreeString(s);
        hr = INetFwService_get_Type(svc, &t); ok(hr == S_OK && t == NET_FW_SERVICE_FILE_AND_PRINT, "type\n");
        hr = INetFwService_get_Enabled(svc, &en0); ok(hr == S_OK, "get_Enabled %08lx\n", hr);
        trace("FPS enabled at start: %d\n", (int)en0);
        hr = INetFwService_put_Enabled(svc, en0 == VARIANT_TRUE ? VARIANT_FALSE : VARIANT_TRUE);
        ok(hr == S_OK, "put_Enabled %08lx\n", hr);
        hr = INetFwService_get_Enabled(svc, &en1); ok(hr == S_OK && en1 != en0, "Enabled flipped %d -> %d\n", (int)en0, (int)en1);
        INetFwService_put_Enabled(svc, VARIANT_FALSE);   /* the default state of the group is disabled */
        hr = INetFwService_get_GloballyOpenPorts(svc, &gp); ok(hr == S_OK && gp, "service ports %08lx\n", hr);
        if (gp) { LONG c = -1; hr = INetFwOpenPorts_get_Count(gp, &c); ok(hr == S_OK && c == 0, "service ports count %ld\n", c); INetFwOpenPorts_Release(gp); }
        INetFwService_Release(svc);
    }
    hr = INetFwServices_get__NewEnum(svcs, &e); ok(hr == S_OK && e, "NewEnum %08lx\n", hr);
    if (e) { int k = EnumCount(e, NULL); ok(k == 3, "enum count %d\n", k); IUnknown_Release(e); }
    INetFwServices_Release(svcs);
}

static void TestProfile(INetFwMgr *mgr, INetFwProfile *prof)
{
    VARIANT_BOOL a, b, c; HRESULT hr; NET_FW_PROFILE_TYPE t, mt; INetFwPolicy *pol = NULL; INetFwProfile *p2 = NULL;
    trace("%s\n", "profile");
    hr = INetFwProfile_get_Type(prof, &t); ok(hr == S_OK && (t == NET_FW_PROFILE_DOMAIN || t == NET_FW_PROFILE_STANDARD), "Type %d\n", (int)t);
    hr = INetFwMgr_get_CurrentProfileType(mgr, &mt); ok(hr == S_OK && mt == t, "CurrentProfileType %d vs %d\n", (int)mt, (int)t);
    hr = INetFwProfile_get_FirewallEnabled(prof, &a); ok(hr == S_OK, "get_FirewallEnabled %08lx\n", hr);
    trace("FirewallEnabled=%d\n", (int)a);
    hr = INetFwProfile_get_NotificationsDisabled(prof, &a); ok(hr == S_OK, "get_NotificationsDisabled\n");
    hr = INetFwProfile_put_NotificationsDisabled(prof, a ? VARIANT_FALSE : VARIANT_TRUE); ok(hr == S_OK, "put_NotificationsDisabled\n");
    hr = INetFwProfile_get_NotificationsDisabled(prof, &b); ok(hr == S_OK && b != a, "NotificationsDisabled flipped\n");
    INetFwProfile_put_NotificationsDisabled(prof, a);
    hr = INetFwProfile_get_ExceptionsNotAllowed(prof, &a); ok(hr == S_OK, "get_ExceptionsNotAllowed\n");
    hr = INetFwProfile_put_ExceptionsNotAllowed(prof, a ? VARIANT_FALSE : VARIANT_TRUE); ok(hr == S_OK, "put_ExceptionsNotAllowed\n");
    hr = INetFwProfile_get_ExceptionsNotAllowed(prof, &b); ok(hr == S_OK && b != a, "ExceptionsNotAllowed flipped\n");
    INetFwProfile_put_ExceptionsNotAllowed(prof, a);
    hr = INetFwProfile_get_UnicastResponsesToMulticastBroadcastDisabled(prof, &a); ok(hr == S_OK, "get_Unicast\n");
    hr = INetFwProfile_put_UnicastResponsesToMulticastBroadcastDisabled(prof, a ? VARIANT_FALSE : VARIANT_TRUE); ok(hr == S_OK, "put_Unicast\n");
    hr = INetFwProfile_get_UnicastResponsesToMulticastBroadcastDisabled(prof, &b); ok(hr == S_OK && b != a, "Unicast flipped\n");
    INetFwProfile_put_UnicastResponsesToMulticastBroadcastDisabled(prof, a);
    hr = INetFwProfile_get_ExceptionsNotAllowed(prof, &c); ok(hr == S_OK, "restored read\n");
    hr = INetFwMgr_get_LocalPolicy(mgr, &pol);
    if (pol)
    {
        hr = INetFwPolicy_GetProfileByType(pol, NET_FW_PROFILE_DOMAIN, &p2);
        ok(hr == S_OK && p2, "GetProfileByType(DOMAIN) %08lx\n", hr);
        if (p2) { hr = INetFwProfile_get_Type(p2, &t); ok(t == NET_FW_PROFILE_DOMAIN, "domain type %d\n", (int)t); INetFwProfile_Release(p2); p2 = NULL; }
        hr = INetFwPolicy_GetProfileByType(pol, NET_FW_PROFILE_STANDARD, &p2);
        ok(hr == S_OK && p2, "GetProfileByType(STANDARD) %08lx\n", hr);
        if (p2) INetFwProfile_Release(p2);
        hr = INetFwPolicy_GetProfileByType(pol, NET_FW_PROFILE_TYPE_MAX, &p2);
        ok(hr == E_INVALIDARG, "GetProfileByType(MAX) %08lx\n", hr);
        INetFwPolicy_Release(pol);
    }
}


START_TEST(HnetcfgLegacy)
{
    INetFwMgr *mgr = NULL;
    INetFwProfile *prof = NULL;
    INetFwPolicy2 *p2 = NULL;
    wchar_t self[MAX_PATH];
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    ok(SUCCEEDED(hr), "CoInitializeEx returned %08lx\n", hr);
    hr = CoCreateInstance(&MY_CLSID_Mgr, NULL, CLSCTX_INPROC_SERVER, &MY_IID_Mgr, (void **)&mgr);
    ok(hr == S_OK, "CoCreateInstance(NetFwMgr) returned %08lx\n", hr);
    if (hr == S_OK)
    {
        prof = CurrentProfile(mgr);
        ok(prof != NULL, "no current profile\n");
        hr = CoCreateInstance(&MY_CLSID_Pol2, NULL, CLSCTX_INPROC_SERVER, &MY_IID_Pol2, (void **)&p2);
        ok(hr == S_OK, "CoCreateInstance(NetFwPolicy2) returned %08lx\n", hr);
        GetModuleFileNameW(NULL, self, MAX_PATH);
        if (prof)
        {
            TestProfile(mgr, prof);
            if (p2)
            {
                TestApps(prof, p2, self);
                TestPorts(prof, p2);
            }
            TestServices(prof);
            INetFwProfile_Release(prof);
        }
        if (p2)
            INetFwPolicy2_Release(p2);
        INetFwMgr_Release(mgr);
    }
    CoUninitialize();
}
