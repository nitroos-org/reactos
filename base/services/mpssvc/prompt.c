/*
 * PROJECT:     NitroOS basic firewall
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The block prompt: "NitroOS Firewall has blocked some features of this app".
 *
 * How it works. The kernel filter reports the local endpoints that accept traffic (IOCTL_NITROFW_GET_LISTENERS: TCP
 * listeners, UDP sockets bound to an explicit port, with the creator's process id). Once a second, while the filter
 * enforces, mpssvc looks at the endpoints it has not handled yet and for each one decides, in user mode where the
 * rules and settings are:
 *   - the program (full image path of the process) is shown to the user once per profile: the first time it listens
 *     while no inbound rule of that profile (allow or block, for the program or for the port) covers it;
 *   - only profiles that are active, enabled, have notifications on (DisableNotifications = 0, the setting
 *     firewall.cpl writes), have no "block all incoming" and whose default inbound action is block are asked about;
 *   - loopback-only listeners are not asked about (loopback always passes the filter), nor are services (a
 *     service has nobody to answer).
 * The dialog (fwalert.exe) is started by mpssvc in the SESSION OF THE LISTENING PROCESS, with that session's user
 * token: WTSQueryUserToken when it returns a real user token, otherwise the token of the shell (explorer.exe) of
 * that session. Nothing here assumes session 0: when the interactive desktop moves to session 1 the listener's
 * session id is 1, the shell is looked up there, and the dialog appears on that desktop (winsta0\default).
 * The dialog only returns an answer (its exit code); mpssvc validates it and writes the rule itself:
 *   Allow access -> an inbound allow rule for TCP and one for UDP, program = the listener's path, for the checked
 *                   profiles (as the Windows prompt does);
 *   Cancel / closed -> inbound block rules, so the question is not asked again.
 * Only administrators are asked (there is no elevation prompt here): a standard user's listener stays blocked.
 */
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <winnls.h>
#include <winuser.h>
#include <winsvc.h>
#include <winioctl.h>
#include <tlhelp32.h>
#include <reactos/nitrofw.h>
#include <fwstore.h>

#define PROMPT_POLL_MS       1000
#define PROMPT_RETRY_MS      5000      /* no shell to show the dialog on yet */
#define PROMPT_MIN_GAP_MS    2000      /* between two dialogs */
#define FWALERT_ALLOW        0x100

#define MAX_SEEN     512
#define MAX_HANDLED  1024

typedef struct { WCHAR Path[MAX_PATH]; ULONG Bit; BOOL Answered; } SEEN;   /* Answered: the answer is stored as rules */
typedef struct { ULONG Pid; LONGLONG Created; USHORT Port; UCHAR Proto; } HANDLED;

typedef struct _REQ
{
    WCHAR Path[MAX_PATH];
    ULONG Session;
    ULONG Bits;         /* profiles this prompt stands for (marked seen) */
    ULONG Preselect;    /* checkboxes that start checked */
    NITROFW_LISTENER Key;   /* the endpoint that caused it (forgotten again if the question could not be asked) */
} REQ;

static CRITICAL_SECTION g_Lock;
static BOOL g_Init;
static SEEN g_Seen[MAX_SEEN];
static ULONG g_NSeen, g_SeenRing;
static HANDLED g_Handled[MAX_HANDLED];
static ULONG g_HandledNext;
static HANDLE g_hStop, g_hWorker;
static volatile LONG g_Busy;
static DWORD g_NextTry, g_LastDialog;   /* GetTickCount values; 0 = unset */

VOID PromptInit(HANDLE hStop)
{
    HANDLE tok; ULONG i;
    static const WCHAR *privs[] = { L"SeAssignPrimaryTokenPrivilege", L"SeIncreaseQuotaPrivilege", L"SeTcbPrivilege" };
    InitializeCriticalSection(&g_Lock);
    g_hStop = hStop; g_Init = TRUE;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
    {
        for (i = 0; i < ARRAYSIZE(privs); i++)
        {
            TOKEN_PRIVILEGES tp;
            tp.PrivilegeCount = 1; tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            if (LookupPrivilegeValueW(NULL, privs[i], &tp.Privileges[0].Luid))
                AdjustTokenPrivileges(tok, FALSE, &tp, 0, NULL, NULL);
        }
        CloseHandle(tok);
    }
}

VOID PromptStop(VOID)
{
    if (!g_Init) return;
    if (g_hWorker)
    {
        /* g_hStop is set by the caller: the worker's waits return */
        WaitForSingleObject(g_hWorker, 5000);
        CloseHandle(g_hWorker); g_hWorker = NULL;
    }
    DeleteCriticalSection(&g_Lock);
    g_Init = FALSE;
}

/* ---- seen set and handled-endpoint cache (under g_Lock) ---- */

static BOOL SeenHas(PCWSTR path, ULONG bit)
{
    ULONG i; BOOL f = FALSE;
    EnterCriticalSection(&g_Lock);
    for (i = 0; i < g_NSeen; i++)
        if (g_Seen[i].Bit == bit && !_wcsicmp(g_Seen[i].Path, path)) { f = TRUE; break; }
    LeaveCriticalSection(&g_Lock);
    return f;
}

static VOID SeenAdd(PCWSTR path, ULONG bit)
{
    EnterCriticalSection(&g_Lock);
    {
        /* full: the oldest entry goes (a program asked about long ago may be asked again; never a repeated prompt for a recent one) */
        SEEN *e = (g_NSeen < MAX_SEEN) ? &g_Seen[g_NSeen++] : &g_Seen[g_SeenRing++ % MAX_SEEN];
        lstrcpynW(e->Path, path, MAX_PATH);
        e->Bit = bit;
        e->Answered = FALSE;
    }
    LeaveCriticalSection(&g_Lock);
}

/* the answer for (path, profile) is stored as rules: deleting those rules makes the program ask again */
static VOID SeenAnswered(PCWSTR path, ULONG bit)
{
    ULONG i;
    if (!SeenHas(path, bit)) SeenAdd(path, bit);
    EnterCriticalSection(&g_Lock);
    for (i = 0; i < g_NSeen; i++)
        if (g_Seen[i].Bit == bit && !_wcsicmp(g_Seen[i].Path, path)) { g_Seen[i].Answered = TRUE; break; }
    LeaveCriticalSection(&g_Lock);
}

static VOID SeenRemove(PCWSTR path, ULONG bit)
{
    ULONG i;
    EnterCriticalSection(&g_Lock);
    for (i = 0; i < g_NSeen; i++)
        if (g_Seen[i].Bit == bit && !_wcsicmp(g_Seen[i].Path, path)) { g_Seen[i] = g_Seen[--g_NSeen]; break; }
    LeaveCriticalSection(&g_Lock);
}

static BOOL SameKey(const HANDLED *h, const NITROFW_LISTENER *l)
{
    return h->Pid == l->ProcessId && h->Created == l->CreationTime && h->Port == l->Port && h->Proto == l->Protocol;
}

static BOOL HandledHas(const NITROFW_LISTENER *l)
{
    ULONG i; BOOL f = FALSE;
    EnterCriticalSection(&g_Lock);
    for (i = 0; i < MAX_HANDLED; i++)
        if (g_Handled[i].Pid && SameKey(&g_Handled[i], l)) { f = TRUE; break; }
    LeaveCriticalSection(&g_Lock);
    return f;
}

static VOID HandledAdd(const NITROFW_LISTENER *l)
{
    HANDLED *h;
    EnterCriticalSection(&g_Lock);
    h = &g_Handled[g_HandledNext++ % MAX_HANDLED];
    h->Pid = l->ProcessId; h->Created = l->CreationTime; h->Port = l->Port; h->Proto = l->Protocol;
    LeaveCriticalSection(&g_Lock);
}

static VOID HandledRemove(const NITROFW_LISTENER *l)
{
    ULONG i;
    EnterCriticalSection(&g_Lock);
    for (i = 0; i < MAX_HANDLED; i++)
        if (g_Handled[i].Pid && SameKey(&g_Handled[i], l)) g_Handled[i].Pid = 0;
    LeaveCriticalSection(&g_Lock);
}

/* ---- the process behind a listener ---- */

typedef BOOL (WINAPI *PFN_QFPIN)(HANDLE, DWORD, LPWSTR, PDWORD);

static BOOL ProcessPath(ULONG pid, PWSTR path, DWORD cch)
{
    HANDLE h; BOOL ok = FALSE; PFN_QFPIN fn;
    fn = (PFN_QFPIN)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "QueryFullProcessImageNameW");
    if (!fn) return FALSE;
    h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!h) return FALSE;
    ok = fn(h, 0, path, &cch);
    CloseHandle(h);
    return ok;
}

static PCWSTR BaseName(PCWSTR p) { PCWSTR b = wcsrchr(p, L'\\'); return b ? b + 1 : p; }

/* a process running as LocalSystem, LocalService or NetworkService is not a user's program (installers, setup steps,
   services): nobody to ask, and Windows never asks about them either */
static BOOL IsSystemIdentity(ULONG pid)
{
    HANDLE hp, tok; BYTE buf[256]; DWORD cb; BOOL r = FALSE; ULONG i;
    static const WELL_KNOWN_SID_TYPE types[] = { WinLocalSystemSid, WinLocalServiceSid, WinNetworkServiceSid };
    hp = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hp) return FALSE;
    if (OpenProcessToken(hp, TOKEN_QUERY, &tok))
    {
        if (GetTokenInformation(tok, TokenUser, buf, sizeof(buf), &cb))
            for (i = 0; i < ARRAYSIZE(types) && !r; i++)
            {
                BYTE sid[SECURITY_MAX_SID_SIZE]; DWORD sz = sizeof(sid);
                if (CreateWellKnownSid(types[i], NULL, sid, &sz) && EqualSid(((TOKEN_USER *)buf)->User.Sid, sid)) r = TRUE;
            }
        CloseHandle(tok);
    }
    CloseHandle(hp);
    return r;
}

/* services have nobody to answer: skip the service control manager's children and the usual system processes */
static BOOL IsServiceProcess(ULONG pid, PCWSTR path)
{
    if (IsSystemIdentity(pid)) return TRUE;

    static const WCHAR *sys[] = { L"services.exe", L"lsass.exe", L"svchost.exe", L"smss.exe", L"csrss.exe", L"wininit.exe", L"winlogon.exe" };
    PROCESSENTRY32W pe; HANDLE snap; ULONG i, parent = 0; BOOL svc = FALSE;
    PCWSTR base = BaseName(path);
    for (i = 0; i < ARRAYSIZE(sys); i++)
        if (!_wcsicmp(base, sys[i])) return TRUE;
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return FALSE;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe))
        do { if (pe.th32ProcessID == pid) { parent = pe.th32ParentProcessID; break; } } while (Process32NextW(snap, &pe));
    if (parent && Process32FirstW(snap, &pe))
        do { if (pe.th32ProcessID == parent) { svc = !_wcsicmp(pe.szExeFile, L"services.exe"); break; } } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    return svc;
}

/* ---- the user's token in a session ---- */

typedef BOOL (WINAPI *PFN_WTSQUT)(ULONG, PHANDLE);

static BOOL TokenIsSystem(HANDLE tok)
{
    BYTE buf[256]; DWORD cb; BYTE sid[SECURITY_MAX_SID_SIZE]; DWORD sz = sizeof(sid); BOOL r = FALSE;
    if (GetTokenInformation(tok, TokenUser, buf, sizeof(buf), &cb) && CreateWellKnownSid(WinLocalSystemSid, NULL, sid, &sz))
        r = EqualSid(((TOKEN_USER *)buf)->User.Sid, sid);
    return r;
}

/* primary token of the logged-on user of a session, or NULL (nobody logged on there yet) */
static HANDLE SessionUserToken(ULONG session)
{
    HANDLE tok = NULL, snap, dup = NULL;
    HMODULE wts = LoadLibraryW(L"wtsapi32.dll");
    PFN_WTSQUT q = wts ? (PFN_WTSQUT)GetProcAddress(wts, "WTSQueryUserToken") : NULL;
    PROCESSENTRY32W pe;

    /* the real thing; ReactOS's wtsapi32 may still return the caller's own (SYSTEM) token: not a user */
    if (q && q(session, &tok) && tok)
    {
        if (!TokenIsSystem(tok))
        {
            if (DuplicateTokenEx(tok, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &dup)) { CloseHandle(tok); FreeLibrary(wts); return dup; }
        }
        CloseHandle(tok); tok = NULL;
    }
    if (wts) FreeLibrary(wts);

    /* the shell of that session */
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return NULL;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe))
    {
        do
        {
            DWORD sid = 0; HANDLE hp;
            if (_wcsicmp(pe.szExeFile, L"explorer.exe") || !ProcessIdToSessionId(pe.th32ProcessID, &sid) || sid != session)
                continue;
            hp = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
            if (!hp) continue;
            if (OpenProcessToken(hp, TOKEN_DUPLICATE | TOKEN_QUERY, &tok))
            {
                if (!TokenIsSystem(tok) &&
                    DuplicateTokenEx(tok, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &dup))
                { CloseHandle(tok); CloseHandle(hp); break; }
                CloseHandle(tok); tok = NULL;
            }
            CloseHandle(hp);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return dup;
}

static BOOL TokenIsAdmin(HANDLE primary)
{
    HANDLE imp = NULL; PSID admins = NULL; BOOL member = FALSE;
    SID_IDENTIFIER_AUTHORITY nt = { SECURITY_NT_AUTHORITY };
    if (!DuplicateTokenEx(primary, TOKEN_QUERY, NULL, SecurityIdentification, TokenImpersonation, &imp)) return FALSE;
    if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admins))
    {
        if (!CheckTokenMembership(imp, admins, &member)) member = FALSE;
        FreeSid(admins);
    }
    CloseHandle(imp);
    return member;
}

/* ---- rules ---- */

static PCWSTR ShortName(PCWSTR path, PWSTR out, ULONG cch)
{
    PWSTR dot;
    lstrcpynW(out, BaseName(path), cch);
    dot = wcsrchr(out, L'.');
    if (dot && dot != out) *dot = 0;
    return out;
}

static BOOL PortListHas(PCWSTR s, ULONG port)
{
    ULONG n = 0; PCWSTR p = s;
    if (!s || !*s || !wcscmp(s, L"*")) return TRUE;
    while (*p)
    {
        ULONG lo, hi; WCHAR *e;
        while (*p == L',' || *p == L' ') p++;
        if (!*p) break;
        if (*p >= L'0' && *p <= L'9')
        {
            lo = hi = wcstoul(p, &e, 10);
            if (*e == L'-') hi = wcstoul(e + 1, &e, 10);
            n++;
            if (port >= lo && port <= hi) return TRUE;
            p = e;
        }
        else if (!_wcsnicmp(p, L"RPC-EPMap", 9)) { n++; if (port == 135) return TRUE; p += 9; }
        else if (!_wcsnicmp(p, L"RPC", 3)) { n++; if (port >= 49152) return TRUE; p += 3; }
        else { while (*p && *p != L',') p++; }   /* other keywords: the kernel filter cannot resolve them either */
    }
    return n == 0;   /* nothing the filter understands: it treats the rule as "any port" */
}

/* an inbound rule (allow or block) of the profile that speaks to this program/protocol/port: asking would be pointless */
static BOOL RuleCovers(const FW_RULE *r, PCWSTR path, ULONG proto, ULONG port, ULONG bit)
{
    if (!r->Enabled || r->Dir != 1) return FALSE;
    if (r->Profiles != FWP_ANY_COM && !(r->Profiles & bit)) return FALSE;
    if (r->Protocol != 256 && (ULONG)r->Protocol != proto) return FALSE;
    if (r->App && *r->App && wcscmp(r->App, L"*"))
    {
        WCHAR exp[MAX_PATH];
        DWORD n = ExpandEnvironmentStringsW(r->App, exp, MAX_PATH);
        if (!n || n > MAX_PATH || _wcsicmp(exp, path)) return FALSE;
    }
    return PortListHas(r->LPorts, port);
}

/* an inbound rule of the profile that names this program (the rules the prompt wrote, or the user's own) */
static BOOL RuleNamesProgram(const FW_RULE *r, PCWSTR path, ULONG bit)
{
    WCHAR exp[MAX_PATH]; DWORD n;
    if (r->Dir != 1 || !r->App || !*r->App || !wcscmp(r->App, L"*")) return FALSE;
    if (r->Profiles != FWP_ANY_COM && !(r->Profiles & bit)) return FALSE;
    n = ExpandEnvironmentStringsW(r->App, exp, MAX_PATH);
    return n && n <= MAX_PATH && !_wcsicmp(exp, path);
}

static BOOL AnyRuleCovers(const FW_RULESET *rs, PCWSTR path, ULONG proto, ULONG port, ULONG bit)
{
    ULONG i;
    for (i = 0; i < rs->N; i++)
        if (RuleCovers(&rs->R[i], path, proto, port, bit)) return TRUE;
    return FALSE;
}

/* The rules changed (called by the service after the store was written): a program whose answer was stored as rules
 * and that has none left for a profile is asked again the next time it listens, as if it was new */
VOID PromptRulesChanged(VOID)
{
    FW_RULESET rs; ULONG i, j, n = 0;
    if (!g_Init) return;
    EnterCriticalSection(&g_Lock);
    for (i = 0; i < g_NSeen; i++) if (g_Seen[i].Answered) n++;
    LeaveCriticalSection(&g_Lock);
    if (!n || FwStoreLoad(&rs)) return;
    EnterCriticalSection(&g_Lock);
    for (i = 0; i < g_NSeen; )
    {
        BOOL named = FALSE;
        if (g_Seen[i].Answered)
            for (j = 0; j < rs.N && !named; j++)
                named = RuleNamesProgram(&rs.R[j], g_Seen[i].Path, g_Seen[i].Bit);
        if (g_Seen[i].Answered && !named) g_Seen[i] = g_Seen[--g_NSeen]; else i++;
    }
    LeaveCriticalSection(&g_Lock);
    FwRuleSetFree(&rs);
}

static DWORD AddProgramRules(PCWSTR path, ULONG mask, BOOL allow)
{
    static const ULONG protos[2] = { 6, 17 };
    WCHAR nm[MAX_PATH]; DWORD err = 0; ULONG i;
    ShortName(path, nm, MAX_PATH);
    for (i = 0; i < 2 && !err; i++)
    {
        FW_RULE r;
        FwRuleInit(&r);
        FwRuleSetStr(&r.Name, nm);
        FwRuleSetStr(&r.App, path);
        r.Enabled = TRUE; r.Dir = 1; r.Action = allow ? 1 : 0; r.Protocol = protos[i];
        r.Profiles = (mask == FWP_ALL) ? FWP_ANY_COM : (LONG)mask;
        err = FwStoreAdd(&r);
        FwRuleFree(&r);
    }
    return err;
}

/* ---- the dialog ---- */

static DWORD WINAPI Worker(LPVOID param)
{
    REQ *rq = param; HANDLE tok, hs[2]; STARTUPINFOW si; PROCESS_INFORMATION pi;
    WCHAR sys[MAX_PATH], exe[MAX_PATH], cmd[2 * MAX_PATH + 64], desk[] = L"winsta0\\default";
    DWORD code = 0, wait; BOOL started; ULONG b;

    tok = SessionUserToken(rq->Session);
    if (!tok)
    {
        /* nobody to ask yet: forget the marks, ask again later */
        for (b = 1; b <= 4; b <<= 1) if (rq->Bits & b) SeenRemove(rq->Path, b);
        HandledRemove(&rq->Key);
        g_NextTry = GetTickCount() + PROMPT_RETRY_MS;
        goto out;
    }
    if (!TokenIsAdmin(tok)) goto closetok;      /* no elevation prompt here: a standard user cannot change the firewall */

    GetSystemDirectoryW(sys, MAX_PATH);
    _snwprintf(exe, MAX_PATH, L"%s\\fwalert.exe", sys);
    _snwprintf(cmd, ARRAYSIZE(cmd), L"\"%s\" /prompt %lu \"%s\"", exe, rq->Preselect, rq->Path);
    memset(&si, 0, sizeof(si)); si.cb = sizeof(si); si.lpDesktop = desk;
    started = CreateProcessAsUserW(tok, exe, cmd, NULL, NULL, FALSE, 0, NULL, sys, &si, &pi);
    if (!started)
    {
        /* keep the marks (no spam); the administrator can add the rule in firewall.cpl */
        goto closetok;
    }
    CloseHandle(pi.hThread);
    hs[0] = pi.hProcess; hs[1] = g_hStop;
    wait = WaitForMultipleObjects(2, hs, FALSE, INFINITE);
    if (wait == WAIT_OBJECT_0 && GetExitCodeProcess(pi.hProcess, &code))
    {
        if (code & FWALERT_ALLOW)
        {
            ULONG mask = code & FWP_ALL;
            if (mask && !AddProgramRules(rq->Path, mask, TRUE))
                for (b = 1; b <= 4; b <<= 1) if (mask & b) SeenAnswered(rq->Path, b);
        }
        else if (code == 0)
        {
            /* Cancel: block, as Windows does */
            if (!AddProgramRules(rq->Path, rq->Bits, FALSE))
                for (b = 1; b <= 4; b <<= 1) if (rq->Bits & b) SeenAnswered(rq->Path, b);
        }
        /* anything else: the dialog crashed; no rule, the marks stay */
    }
    else
        TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);
closetok:
    CloseHandle(tok);
out:
    g_LastDialog = GetTickCount();
    HeapFree(GetProcessHeap(), 0, rq);
    InterlockedExchange(&g_Busy, 0);
    return 0;
}

/* ---- the poll ---- */

VOID PromptPoll(VOID)
{
    HANDLE h; NITROFW_STATUS st; DWORD ret; BYTE *buf; NITROFW_LISTENERS *hdr; NITROFW_LISTENER *l;
    ULONG active, cand = 0, i, b; FW_RULESET rs; BOOL haveRules = FALSE;
    DWORD now = GetTickCount();

    if (!g_Init || g_Busy || (g_NextTry && (LONG)(now - g_NextTry) < 0) || (g_LastDialog && now - g_LastDialog < PROMPT_MIN_GAP_MS)) return;
    h = CreateFileW(NITROFW_USER_PATH, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    memset(&st, 0, sizeof(st));
    if (!DeviceIoControl(h, IOCTL_NITROFW_GET_STATUS, NULL, 0, &st, sizeof(st), &ret, NULL) || !(st.KernelState & NITROFW_KSTATE_ENFORCING))
        goto done;
    active = FwCurrentProfiles();
    for (b = 1; b <= 4; b <<= 1)
    {
        FW_PROFILE p;
        if (!(active & b) || FwProfileLoad(b, &p)) continue;
        if (p.Enable && !p.DoNotAllowExceptions && !p.DisableNotifications && p.DefaultInbound) cand |= b;
    }
    if (!cand) goto done;

    buf = HeapAlloc(GetProcessHeap(), 0, sizeof(*hdr) + NITROFW_MAX_LISTENERS * sizeof(*l));
    if (!buf) goto done;
    hdr = (NITROFW_LISTENERS *)buf; l = (NITROFW_LISTENER *)(hdr + 1);
    if (!DeviceIoControl(h, IOCTL_NITROFW_GET_LISTENERS, NULL, 0, buf, sizeof(*hdr) + NITROFW_MAX_LISTENERS * sizeof(*l), &ret, NULL))
    { HeapFree(GetProcessHeap(), 0, buf); goto done; }

    for (i = 0; i < hdr->Count && !g_Busy; i++)
    {
        WCHAR path[MAX_PATH]; DWORD sess = 0; ULONG need = 0; REQ *rq;
        if (HandledHas(&l[i])) continue;
        if ((l[i].Addr >> 24) == 127) { HandledAdd(&l[i]); continue; }      /* loopback only: never filtered */
        if (!ProcessPath(l[i].ProcessId, path, MAX_PATH) || !ProcessIdToSessionId(l[i].ProcessId, &sess))
        { HandledAdd(&l[i]); continue; }                                     /* gone, or not ours to look at */
        if (IsServiceProcess(l[i].ProcessId, path)) { HandledAdd(&l[i]); continue; }
        if (!haveRules) { if (FwStoreLoad(&rs)) break; haveRules = TRUE; }
        for (b = 1; b <= 4; b <<= 1)
            if ((cand & b) && !SeenHas(path, b) && !AnyRuleCovers(&rs, path, l[i].Protocol, l[i].Port, b)) need |= b;
        if (!need)
        {
            /* covered by a rule, or already asked: remember the endpoint, and the program for the profiles it was covered in */
            HandledAdd(&l[i]);
            continue;
        }
        rq = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*rq));
        if (!rq) break;
        lstrcpynW(rq->Path, path, MAX_PATH);
        rq->Key = l[i]; rq->Session = sess; rq->Bits = need; rq->Preselect = active & FWP_ALL;
        for (b = 1; b <= 4; b <<= 1) if (need & b) SeenAdd(path, b);
        HandledAdd(&l[i]);
        InterlockedExchange(&g_Busy, 1);
        if (g_hWorker) { CloseHandle(g_hWorker); g_hWorker = NULL; }
        g_hWorker = CreateThread(NULL, 0, Worker, rq, 0, NULL);
        if (!g_hWorker)
        {
            for (b = 1; b <= 4; b <<= 1) if (need & b) SeenRemove(path, b);
            HandledRemove(&l[i]);
            HeapFree(GetProcessHeap(), 0, rq);
            InterlockedExchange(&g_Busy, 0);
        }
    }
    if (haveRules) FwRuleSetFree(&rs);
    HeapFree(GetProcessHeap(), 0, buf);
done:
    CloseHandle(h);
}
