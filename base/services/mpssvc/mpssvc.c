/*
 * PROJECT:     NitroOS basic firewall
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     mpssvc: loads the firewall policy from the registry at start and on every change and
 *              pushes it to the kernel filter (see sdk/include/reactos/nitrofw.h). A missing filter
 *              device is not an error: the rules stay stored and are pushed when the device appears.
 */
#include <stdio.h>
#include <wchar.h>
#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <winsvc.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <winioctl.h>
#include <reactos/nitrofw.h>
#include <fwstore.h>

static WCHAR g_Name[] = L"mpssvc";
static SERVICE_STATUS_HANDLE g_hStatus;
static SERVICE_STATUS g_Status;
static HANDLE g_hStop;
static ULONGLONG g_Generation;

static VOID SetState(DWORD state)
{
    g_Status.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
    g_Status.dwCurrentState = state;
    g_Status.dwControlsAccepted = (state == SERVICE_RUNNING) ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    g_Status.dwWaitHint = (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING) ? 3000 : 0;
    SetServiceStatus(g_hStatus, &g_Status);
}

static DWORD WINAPI CtrlHandler(DWORD ctl, DWORD type, LPVOID data, LPVOID ctx)
{
    switch (ctl)
    {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            SetState(SERVICE_STOP_PENDING);
            SetEvent(g_hStop);
            return NO_ERROR;
        case SERVICE_CONTROL_INTERROGATE:
            SetServiceStatus(g_hStatus, &g_Status);
            return NO_ERROR;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

/* record the outcome where an administrator can look: HKLM\SOFTWARE\ReactOS\Nitro\Firewall */
static VOID Report(DWORD err, BOOL present)
{
    HKEY hk; DWORD disp, v;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\ReactOS\\Nitro\\Firewall", 0, NULL, 0, KEY_SET_VALUE, NULL, &hk, &disp)) return;
    v = present ? 1 : 0; RegSetValueExW(hk, L"KernelFilterPresent", 0, REG_DWORD, (BYTE *)&v, 4);
    RegSetValueExW(hk, L"LastPushError", 0, REG_DWORD, (BYTE *)&err, 4);
    RegSetValueExW(hk, L"Generation", 0, REG_QWORD, (BYTE *)&g_Generation, 8);
    RegCloseKey(hk);
}

/* Rules the push could not carry (or not fully): HKLM\SOFTWARE\ReactOS\Nitro\Firewall LastPushRejectedRules (all),
   LastPushRejectedBlockRules (the Block rules among them: NOT enforced), LastPushPartialBlockRules,
   LastPushBroadBlockRules (Block rules whose only restriction is a condition the filter cannot match: the filter blocks
   all traffic of their direction (of their protocol), Windows only the traffic that matches the condition),
   LastPushRejectedNames, and one Application event per change of that state (not per push): event 1 (error) when a rule
   was rejected or is not fully enforced, 2 (warning) when only broad Block rules are left, 3 (information) when the
   state is clean again. */
static VOID ReportRules(VOID)
{
    static ULONG lastRej, lastRejBlock, lastPar, lastBroad; static WCHAR lastNames[1024];
    ULONG rej, rejBlock, par, broad; WCHAR names[1024]; HKEY hk; DWORD disp;
    FwPushGetReport(&rej, &rejBlock, &par, &broad, names, 1024);
    if (!RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\ReactOS\\Nitro\\Firewall", 0, NULL, 0, KEY_SET_VALUE, NULL, &hk, &disp))
    {
        RegSetValueExW(hk, L"LastPushRejectedRules", 0, REG_DWORD, (BYTE *)&rej, 4);
        RegSetValueExW(hk, L"LastPushRejectedBlockRules", 0, REG_DWORD, (BYTE *)&rejBlock, 4);
        RegSetValueExW(hk, L"LastPushPartialBlockRules", 0, REG_DWORD, (BYTE *)&par, 4);
        RegSetValueExW(hk, L"LastPushBroadBlockRules", 0, REG_DWORD, (BYTE *)&broad, 4);
        RegSetValueExW(hk, L"LastPushRejectedNames", 0, REG_SZ, (BYTE *)names, (DWORD)((wcslen(names) + 1) * sizeof(WCHAR)));
        RegCloseKey(hk);
    }
    if ((rej || par || broad) && (rej != lastRej || rejBlock != lastRejBlock || par != lastPar || broad != lastBroad || wcscmp(names, lastNames)))
    {
        HANDLE hes = RegisterEventSourceW(NULL, g_Name);
        if (hes)
        {
            WCHAR msg[1280]; PCWSTR str[1];
            _snwprintf(msg, 1279, L"NitroOS Firewall: %lu rule(s) were not pushed to the filter (%lu of them Block rule(s): not enforced), %lu Block rule(s) are not fully enforced and %lu Block rule(s) have only a condition the filter cannot match and now block all traffic of their direction (of their protocol): %ls",
                       rej, rejBlock, par, broad, names);
            msg[1279] = 0; str[0] = msg;
            ReportEventW(hes, (rej || par) ? EVENTLOG_ERROR_TYPE : EVENTLOG_WARNING_TYPE, 0, (rej || par) ? 1 : 2, NULL, 1, 0, str, NULL);
            DeregisterEventSource(hes);
        }
        OutputDebugStringW(L"mpssvc: firewall rules not pushed or not fully enforced\n");
    }
    else if (!rej && !par && !broad && (lastRej || lastPar || lastBroad))
    {
        HANDLE hes = RegisterEventSourceW(NULL, g_Name);
        if (hes)
        {
            PCWSTR str[1] = { L"NitroOS Firewall: every rule is pushed to the filter again, nothing is left out or not fully enforced" };
            ReportEventW(hes, EVENTLOG_INFORMATION_TYPE, 0, 3, NULL, 1, 0, str, NULL);
            DeregisterEventSource(hes);
        }
    }
    lastRej = rej; lastRejBlock = rejBlock; lastPar = par; lastBroad = broad; wcscpy(lastNames, names);
}

/* ---- address changes ----
   The address keywords of a rule (LocalSubnet, DefaultGateway, DHCP, WINS; LocalSubnet for IPv6 too) are resolved
   when the policy is pushed. A push before the address is up, or an address that changes later (DHCP, SLAAC), would
   leave an Allow LocalSubnet rule allowing the old subnet (broader than written) and a Block LocalSubnet rule missing
   the new one. So the policy is pushed again when what the keywords resolve from changes. NotifyAddrChange wakes the
   service for IPv4 changes; the signature below (the same fields the resolution reads) is also checked every
   ADDR_POLL_TICKS poll ticks, which covers a failed notification request or registration (IPv6 changes are notified through
   NotifyUnicastIpAddressChange), and a
   push happens only when the signature differs from the one of the last push. A change must stay quiet for
   ADDR_QUIET_MS before it is pushed (debounce: DHCP and SLAAC set several addresses), but never longer than
   ADDR_MAX_MS after the first change (an interface that keeps flapping must not postpone the push for ever).
   A notification is not acted on at once: the addresses are read once, ADDR_COALESCE_MS after it, so the service
   reads them at most a few times a second however often the stack completes the request. */

#define ADDR_POLL_TICKS    5
#define ADDR_COALESCE_MS   200      /* after a notification: wait this long for more changes, then check once */
#define ADDR_QUIET_MS      1500
#define ADDR_MAX_MS        10000

static ULONG g_LastSig, g_PendingSig;
static BOOL g_SigDirty;
static DWORD g_SigDue, g_SigFirst;
static HANDLE g_hAddr;
static OVERLAPPED g_AddrOv;
static HANDLE g_AddrFile;
static BOOL g_AddrArmed;
static BOOL g_AddrStuck;    /* the last request could not be confirmed cancelled: g_AddrOv stays untouched until it is */

/* IPv6 address changes: NotifyAddrChange is IPv4 only, so the service also registers for the IPv6 unicast addresses.
   The callback only sets g_hAddr6 (a manual-reset event, waited on with the others); what changed is found by the
   signature, as for IPv4. The registration queues its next request in the stack before it reads its table, and the
   stack completes only the requests that were queued before a change began, so it cannot loop. */
DWORD WINAPI NotifyUnicastIpAddressChange(ADDRESS_FAMILY Family, PVOID Callback, PVOID CallerContext,
                                          BOOLEAN InitialNotification, HANDLE *NotificationHandle);
DWORD WINAPI CancelMibChangeNotify2(HANDLE NotificationHandle);
static HANDLE g_hAddr6;
static HANDLE g_Notify6;

static VOID WINAPI Addr6Changed(PVOID Context, PVOID Row, DWORD Type)
{
    if (g_hAddr6) SetEvent(g_hAddr6);
}

static ULONG SigAdd(ULONG h, const void *p, SIZE_T n)
{
    const BYTE *b = p;
    while (n--) { h ^= *b++; h *= 16777619u; }
    return h;
}

/* The signature of the addresses now. FALSE when they could not be read (no memory, a table that kept growing, a
   failing call): the caller then keeps what it has, it never takes an empty answer for "all addresses are gone". No
   address at all (ERROR_NO_DATA) is a valid answer. */
static BOOL AddrSignature(ULONG *Sig)
{
    ULONG h = 2166136261u, len = 0, tries; DWORD rc = ERROR_BUFFER_OVERFLOW;
    IP_ADAPTER_INFO *ai = NULL, *a; IP_ADAPTER_ADDRESSES *aa = NULL, *w;
    BOOL ok = TRUE;
    for (tries = 0; tries < 3 && rc == ERROR_BUFFER_OVERFLOW; tries++)
    {
        if (ai) HeapFree(GetProcessHeap(), 0, ai);
        ai = len ? HeapAlloc(GetProcessHeap(), 0, len) : NULL;
        if (len && !ai) { rc = ERROR_NOT_ENOUGH_MEMORY; break; }
        rc = GetAdaptersInfo(ai, &len);
    }
    if (rc != NO_ERROR && rc != ERROR_NO_DATA) ok = FALSE;
    if (rc == NO_ERROR && ai)
    {
        for (a = ai; a; a = a->Next)
        {
            IP_ADDR_STRING *s;
            h = SigAdd(h, &a->Index, sizeof(a->Index));
            for (s = &a->IpAddressList; s; s = s->Next)
            { h = SigAdd(h, s->IpAddress.String, sizeof(s->IpAddress.String)); h = SigAdd(h, s->IpMask.String, sizeof(s->IpMask.String)); }
            for (s = &a->GatewayList; s; s = s->Next) h = SigAdd(h, s->IpAddress.String, sizeof(s->IpAddress.String));
            for (s = &a->DhcpServer; s; s = s->Next) h = SigAdd(h, s->IpAddress.String, sizeof(s->IpAddress.String));
            for (s = &a->PrimaryWinsServer; s; s = s->Next) h = SigAdd(h, s->IpAddress.String, sizeof(s->IpAddress.String));
        }
    }
    if (ai) HeapFree(GetProcessHeap(), 0, ai);
    len = 16384; rc = ERROR_BUFFER_OVERFLOW;
    for (tries = 0; tries < 3 && rc == ERROR_BUFFER_OVERFLOW; tries++)
    {
        if (aa) HeapFree(GetProcessHeap(), 0, aa);
        aa = HeapAlloc(GetProcessHeap(), 0, len);
        if (!aa) { ok = FALSE; break; }
        rc = GetAdaptersAddresses(AF_INET6, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, NULL, aa, &len);
    }
    if (rc == ERROR_BUFFER_OVERFLOW || rc == ERROR_NOT_ENOUGH_MEMORY) ok = FALSE;
    if (aa && rc == NO_ERROR)
    {
        for (w = aa; w; w = w->Next)
        {
            IP_ADAPTER_UNICAST_ADDRESS *u;
            for (u = w->FirstUnicastAddress; u; u = u->Next)
            {
                const SOCKADDR_IN6 *sa = (const SOCKADDR_IN6 *)u->Address.lpSockaddr;
                if (!sa || u->Address.iSockaddrLength < (INT)sizeof(*sa) || sa->sin6_family != AF_INET6) continue;
                h = SigAdd(h, &sa->sin6_addr, sizeof(sa->sin6_addr));
                h = SigAdd(h, &u->OnLinkPrefixLength, sizeof(u->OnLinkPrefixLength));
            }
        }
    }
    if (aa) HeapFree(GetProcessHeap(), 0, aa);
    *Sig = h;
    return ok;
}

/* queue the next NotifyAddrChange request; without one the signature poll still runs */
static VOID ArmAddrNotify(VOID)
{
    g_AddrArmed = FALSE;
    if (!g_hAddr) return;
    if (g_AddrStuck)
    {
        /* a request from before a service restart that was not confirmed cancelled: the static OVERLAPPED is only
           reused once it has completed; until then only the signature poll runs */
        if (!HasOverlappedIoCompleted(&g_AddrOv)) return;
        g_AddrStuck = FALSE;
    }
    ResetEvent(g_hAddr);
    memset(&g_AddrOv, 0, sizeof(g_AddrOv));
    g_AddrOv.hEvent = g_hAddr;
    g_AddrFile = NULL;
    if (NotifyAddrChange(&g_AddrFile, &g_AddrOv) == ERROR_IO_PENDING) g_AddrArmed = TRUE;
}

/* the signature differs from the last push's: (re)start the quiet period. SINCE is when the change was first seen (the
   tick of the notification, not of the check that the coalescing delayed), so the push is due ADDR_QUIET_MS after the
   change. The addresses that cannot be read change nothing: the policy in force stays. */
static VOID AddrCheck(DWORD since)
{
    ULONG sig;
    if (!AddrSignature(&sig)) return;
    if (sig == g_LastSig && !g_SigDirty) return;
    if (sig == g_LastSig) { g_SigDirty = FALSE; return; }      /* changed and changed back before the push */
    if (!g_SigDirty || sig != g_PendingSig)
    {
        if (!g_SigDirty) g_SigFirst = since;
        g_SigDirty = TRUE; g_PendingSig = sig;
        g_SigDue = since + ADDR_QUIET_MS;
        if ((LONG)(g_SigDue - (g_SigFirst + ADDR_MAX_MS)) > 0) g_SigDue = g_SigFirst + ADDR_MAX_MS;   /* upper bound */
    }
}

static VOID Push(VOID)
{
    BOOL present; DWORD err; ULONG sig;
    if (AddrSignature(&sig)) g_LastSig = sig;    /* taken before the push reads the addresses: a later change is seen as a difference */
    g_SigDirty = FALSE;
    err = FwPushToKernel(++g_Generation, &present);
    Report(err, present);
    if (present) ReportRules();
}

static VOID AddrPushIfDue(VOID)
{
    if (g_SigDirty && (LONG)(GetTickCount() - g_SigDue) >= 0) Push();
}

/* prompt.c: the "NitroOS Firewall has blocked some features of this app" prompt */
VOID PromptInit(HANDLE hStop);
VOID PromptStop(VOID);
VOID PromptPoll(VOID);
VOID PromptRulesChanged(VOID);

#define POLL_MS            1000   /* block prompt poll; the filter-device retry below runs every NITROFW_RETRY_SECONDS */

static VOID WINAPI ServiceMainImpl(DWORD argc, LPWSTR *argv)
{
    HKEY hKey = NULL; HANDLE hChange = NULL; DWORD wait, nWait; ULONG retryTicks = 0, addrTicks = 0;
    FILETIME ft;

    g_hStatus = RegisterServiceCtrlHandlerExW(g_Name, CtrlHandler, NULL);
    if (!g_hStatus) return;
    SetState(SERVICE_START_PENDING);
    g_hStop = CreateEventW(NULL, TRUE, FALSE, NULL);
    hChange = CreateEventW(NULL, FALSE, FALSE, NULL);
    /* a boot-time base keeps generations increasing across service restarts (the device outlives us) */
    GetSystemTimeAsFileTime(&ft);
    g_Generation = (((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime) / 10000000ULL;
    if (!g_hStop || !hChange) goto done;
    FwUpgradeDefaults();   /* before the key watch is armed, so the write does not cause a second push */
    if (FwWatchOpen(&hKey)) goto done;
    RegNotifyChangeKeyValue(hKey, TRUE, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, hChange, TRUE);
    SetState(SERVICE_RUNNING);
    g_hAddr = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_hAddr6 = CreateEventW(NULL, TRUE, FALSE, NULL);
    /* registered before the first push: an IPv6 address that comes up after it is notified (without a registration
       the signature poll still finds it) */
    if (g_hAddr6 && NotifyUnicastIpAddressChange(AF_INET6, Addr6Changed, NULL, FALSE, &g_Notify6) != NO_ERROR)
        g_Notify6 = NULL;
    ArmAddrNotify();
    Push();
    PromptInit(g_hStop);
    for (;;)
    {
        /* wake every POLL_MS for the block prompt; when the device is absent retry every NITROFW_RETRY_SECONDS;
           netsh/COM changes arrive through the key notification */
        DWORD timeout = POLL_MS; BOOL early = FALSE; BOOL addrWake;
        HANDLE ws[4];
        nWait = 0;
        ws[nWait++] = g_hStop;
        ws[nWait++] = hChange;
        if (g_hAddr6) ws[nWait++] = g_hAddr6;
        if (g_AddrArmed) ws[nWait++] = g_hAddr;
        if (g_SigDirty)
        {
            /* a push is due: wake for it, not at the next poll tick */
            LONG left = (LONG)(g_SigDue - GetTickCount());
            if (left < 0) left = 0;
            if ((DWORD)left < POLL_MS) { timeout = (DWORD)left; early = TRUE; }
        }
        wait = WaitForMultipleObjects(nWait, ws, FALSE, timeout);
        if (wait == WAIT_OBJECT_0) break;
        addrWake = (wait >= WAIT_OBJECT_0 + 2 && wait < WAIT_OBJECT_0 + nWait);
        if (addrWake)
        {
            /* The address table changed (IPv4 or IPv6). Whatever the stack does, the addresses are read at most once
               every ADDR_COALESCE_MS: a burst of changes (DHCP, SLAAC) is one check after it, and a notification that
               completes again at once cannot make this loop spin. The request is queued again before the check, so a
               change after the check is notified; the IPv6 event is reset before it for the same reason. */
            DWORD since = GetTickCount();
            if (WaitForSingleObject(g_hStop, ADDR_COALESCE_MS) == WAIT_OBJECT_0) break;
            if (g_hAddr6) ResetEvent(g_hAddr6);
            ArmAddrNotify();
            AddrCheck(since);
        }
        else if (wait == WAIT_TIMEOUT && !early && ++addrTicks >= ADDR_POLL_TICKS)
        {
            addrTicks = 0;
            if (g_AddrStuck) ArmAddrNotify();    /* the request of an earlier run may have completed since: notify again */
            AddrCheck(GetTickCount());
        }
        AddrPushIfDue();
        if (wait == WAIT_OBJECT_0 + 1)
        {
            Sleep(200);   /* coalesce bursts (netsh writes several values) */
            RegNotifyChangeKeyValue(hKey, TRUE, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, hChange, TRUE);
            Push();
            PromptRulesChanged();   /* a program whose rules were deleted is asked again */
        }
        else if (wait == WAIT_TIMEOUT)
        {
            HKEY hk; DWORD present = 0, cb = 4, t;
            if (early) continue;    /* only woken for the push that was due */
            PromptPoll();
            if (++retryTicks < NITROFW_RETRY_SECONDS * 1000 / POLL_MS) continue;
            retryTicks = 0;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\ReactOS\\Nitro\\Firewall", 0, KEY_READ, &hk) == 0)
            { RegQueryValueExW(hk, L"KernelFilterPresent", NULL, &t, (BYTE *)&present, &cb); RegCloseKey(hk); }
            if (!present) Push();   /* device may have appeared */
        }
    }
    PromptStop();
    if (g_Notify6)
    {
        /* waits for a callback that is running, none runs after it returns */
        CancelMibChangeNotify2(g_Notify6);
        g_Notify6 = NULL;
    }
    if (g_AddrArmed)
    {
        /* the request completes (aborted) once cancelled; confirm that before the event is closed and the static
           OVERLAPPED can be reused by a restarted service */
        CancelIPChangeNotify(&g_AddrOv);
        WaitForSingleObject(g_hAddr, 2000);
        if (!HasOverlappedIoCompleted(&g_AddrOv))
        {
            /* svchost unloads this DLL on stop (ServiceDllUnloadOnStop): the request would complete into unmapped or
               reused memory and the flag would be lost. Keep the DLL loaded for the life of the process. */
            HMODULE self;
            g_AddrStuck = TRUE;
            GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN, (LPCWSTR)&g_AddrOv, &self);
        }
        g_AddrArmed = FALSE;
    }
done:
    if (g_hAddr) CloseHandle(g_hAddr);
    if (g_hAddr6) { HANDLE h6 = g_hAddr6; g_hAddr6 = NULL; CloseHandle(h6); }
    if (hKey) RegCloseKey(hKey);
    if (hChange) CloseHandle(hChange);
    if (g_hStop) CloseHandle(g_hStop);
    SetState(SERVICE_STOPPED);
}

VOID WINAPI ServiceMain(DWORD argc, LPWSTR *argv) { ServiceMainImpl(argc, argv); }

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r)
{
    if (reason == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(h);
    return TRUE;
}
