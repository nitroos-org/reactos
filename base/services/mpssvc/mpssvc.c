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
   LastPushRejectedBlockRules (the Block rules among them: NOT enforced), LastPushPartialBlockRules, LastPushRejectedNames,
   and one Application event per change of that state (not per push). */
static VOID ReportRules(VOID)
{
    static ULONG lastRej, lastRejBlock, lastPar; static WCHAR lastNames[1024];
    ULONG rej, rejBlock, par; WCHAR names[1024]; HKEY hk; DWORD disp;
    FwPushGetReport(&rej, &rejBlock, &par, names, 1024);
    if (!RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\ReactOS\\Nitro\\Firewall", 0, NULL, 0, KEY_SET_VALUE, NULL, &hk, &disp))
    {
        RegSetValueExW(hk, L"LastPushRejectedRules", 0, REG_DWORD, (BYTE *)&rej, 4);
        RegSetValueExW(hk, L"LastPushRejectedBlockRules", 0, REG_DWORD, (BYTE *)&rejBlock, 4);
        RegSetValueExW(hk, L"LastPushPartialBlockRules", 0, REG_DWORD, (BYTE *)&par, 4);
        RegSetValueExW(hk, L"LastPushRejectedNames", 0, REG_SZ, (BYTE *)names, (DWORD)((wcslen(names) + 1) * sizeof(WCHAR)));
        RegCloseKey(hk);
    }
    if ((rej || par) && (rej != lastRej || rejBlock != lastRejBlock || par != lastPar || wcscmp(names, lastNames)))
    {
        HANDLE hes = RegisterEventSourceW(NULL, g_Name);
        if (hes)
        {
            WCHAR msg[1280]; PCWSTR str[1];
            _snwprintf(msg, 1279, L"NitroOS Firewall: %lu rule(s) were not pushed to the filter (%lu of them Block rule(s): not enforced) and %lu Block rule(s) are not fully enforced: %ls",
                       rej, rejBlock, par, names);
            msg[1279] = 0; str[0] = msg;
            ReportEventW(hes, EVENTLOG_ERROR_TYPE, 0, 1, NULL, 1, 0, str, NULL);
            DeregisterEventSource(hes);
        }
        OutputDebugStringW(L"mpssvc: firewall rules not pushed or not fully enforced\n");
    }
    lastRej = rej; lastRejBlock = rejBlock; lastPar = par; wcscpy(lastNames, names);
}

/* ---- address changes ----
   The address keywords of a rule (LocalSubnet, DefaultGateway, DHCP, WINS; LocalSubnet for IPv6 too) are resolved
   when the policy is pushed. A push before the address is up, or an address that changes later (DHCP, SLAAC), would
   leave an Allow LocalSubnet rule allowing the old subnet (broader than written) and a Block LocalSubnet rule missing
   the new one. So the policy is pushed again when what the keywords resolve from changes. NotifyAddrChange wakes the
   service for IPv4 changes; the signature below (the same fields the resolution reads) is also checked every
   ADDR_POLL_TICKS poll ticks, which covers IPv6 (no notification there) and a failed notification request, and a
   push happens only when the signature differs from the one of the last push. A change must stay quiet for
   ADDR_QUIET_MS before it is pushed (debounce: DHCP and SLAAC set several addresses), but never longer than
   ADDR_MAX_MS after the first change (an interface that keeps flapping must not postpone the push for ever). */

#define ADDR_POLL_TICKS    5
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

static ULONG SigAdd(ULONG h, const void *p, SIZE_T n)
{
    const BYTE *b = p;
    while (n--) { h ^= *b++; h *= 16777619u; }
    return h;
}

static ULONG AddrSignature(VOID)
{
    ULONG h = 2166136261u, len = 0, tries; DWORD rc = ERROR_BUFFER_OVERFLOW;
    IP_ADAPTER_INFO *ai = NULL, *a; IP_ADAPTER_ADDRESSES *aa = NULL, *w;
    for (tries = 0; tries < 3 && rc == ERROR_BUFFER_OVERFLOW; tries++)
    {
        if (ai) HeapFree(GetProcessHeap(), 0, ai);
        ai = len ? HeapAlloc(GetProcessHeap(), 0, len) : NULL;
        rc = GetAdaptersInfo(ai, &len);
    }
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
        if (!aa) break;
        rc = GetAdaptersAddresses(AF_INET6, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, NULL, aa, &len);
    }
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
    return h;
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

/* the signature differs from the last push's: (re)start the quiet period */
static VOID AddrCheck(VOID)
{
    ULONG sig = AddrSignature();
    if (sig == g_LastSig && !g_SigDirty) return;
    if (sig == g_LastSig) { g_SigDirty = FALSE; return; }      /* changed and changed back before the push */
    if (!g_SigDirty || sig != g_PendingSig)
    {
        DWORD now = GetTickCount();
        if (!g_SigDirty) g_SigFirst = now;
        g_SigDirty = TRUE; g_PendingSig = sig;
        g_SigDue = now + ADDR_QUIET_MS;
        if ((LONG)(g_SigDue - (g_SigFirst + ADDR_MAX_MS)) > 0) g_SigDue = g_SigFirst + ADDR_MAX_MS;   /* upper bound */
    }
}

static VOID Push(VOID)
{
    BOOL present; DWORD err;
    g_LastSig = AddrSignature();    /* taken before the push reads the addresses: a later change is seen as a difference */
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
    HKEY hKey = NULL; HANDLE hChange = NULL, hs[3]; DWORD wait, nWait; ULONG retryTicks = 0, addrTicks = 0;
    FILETIME ft;

    g_hStatus = RegisterServiceCtrlHandlerExW(g_Name, CtrlHandler, NULL);
    if (!g_hStatus) return;
    SetState(SERVICE_START_PENDING);
    g_hStop = CreateEventW(NULL, TRUE, FALSE, NULL);
    hChange = CreateEventW(NULL, FALSE, FALSE, NULL);
    /* a boot-time base keeps generations increasing across service restarts (the device outlives us) */
    GetSystemTimeAsFileTime(&ft);
    g_Generation = (((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime) / 10000000ULL;
    if (!g_hStop || !hChange || FwWatchOpen(&hKey)) goto done;
    RegNotifyChangeKeyValue(hKey, TRUE, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, hChange, TRUE);
    SetState(SERVICE_RUNNING);
    g_hAddr = CreateEventW(NULL, TRUE, FALSE, NULL);
    ArmAddrNotify();
    Push();
    hs[0] = g_hStop; hs[1] = hChange; hs[2] = g_hAddr;
    PromptInit(g_hStop);
    for (;;)
    {
        /* wake every POLL_MS for the block prompt; when the device is absent retry every NITROFW_RETRY_SECONDS;
           netsh/COM changes arrive through the key notification */
        nWait = g_AddrArmed ? 3 : 2;
        wait = WaitForMultipleObjects(nWait, hs, FALSE, POLL_MS);
        if (wait == WAIT_OBJECT_0) break;
        if (wait == WAIT_OBJECT_0 + 2) { ArmAddrNotify(); AddrCheck(); }
        else if (wait == WAIT_TIMEOUT && ++addrTicks >= ADDR_POLL_TICKS)
        {
            addrTicks = 0;
            if (g_AddrStuck) ArmAddrNotify();    /* the request of an earlier run may have completed since: notify again */
            AddrCheck();
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
            PromptPoll();
            if (++retryTicks < NITROFW_RETRY_SECONDS * 1000 / POLL_MS) continue;
            retryTicks = 0;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\ReactOS\\Nitro\\Firewall", 0, KEY_READ, &hk) == 0)
            { RegQueryValueExW(hk, L"KernelFilterPresent", NULL, &t, (BYTE *)&present, &cb); RegCloseKey(hk); }
            if (!present) Push();   /* device may have appeared */
        }
    }
    PromptStop();
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
