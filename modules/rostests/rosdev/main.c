/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     main
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * PROJECT:     ReactOS test infrastructure
 * PURPOSE:     rosdev: guest agent entry point, safety guards, host handshake and the poll loop
 *
 * TEST VMS ONLY (see rosdev.h). Guards, all checked before any network traffic:
 *   1. the command line carries /testvm;
 *   2. HKLM\SOFTWARE\ReactOS\ReactOS\RosDevTestVm is the marker string the injector writes;
 *   3. only one instance runs.
 * The only peer is 10.0.2.2 (the QEMU user-network host). After connect() the agent's own
 * address must lie in 10.0.2.0/24, so a bridged network that happens to route 10.0.2.2
 * elsewhere is refused. The host proves it knows the per-VM token before any job is accepted.
 * The agent never listens.
 */
#include "rosdev.h"

static BOOL ReadRegString(const WCHAR *name, WCHAR *out, DWORD cch)
{
    HKEY k;
    DWORD type, cb = (cch - 1) * sizeof(WCHAR);
    BOOL ok = FALSE;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, ROSDEV_KEY, 0, KEY_READ, &k) != ERROR_SUCCESS) return FALSE;
    if (RegQueryValueExW(k, name, NULL, &type, (BYTE *)out, &cb) == ERROR_SUCCESS && type == REG_SZ)
    {
        out[cb / sizeof(WCHAR)] = 0;
        out[cch - 1] = 0;
        ok = TRUE;
    }
    RegCloseKey(k);
    return ok;
}

static DWORD ReadRegDword(const WCHAR *name, DWORD def)
{
    HKEY k;
    DWORD type, v = def, cb = sizeof(v);

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, ROSDEV_KEY, 0, KEY_READ, &k) != ERROR_SUCCESS) return def;
    if (RegQueryValueExW(k, name, NULL, &type, (BYTE *)&v, &cb) != ERROR_SUCCESS || type != REG_DWORD) v = def;
    RegCloseKey(k);
    return v;
}

static void Random16(BYTE out[16])
{
    SHA256_STATE s;
    BYTE d[32];
    LARGE_INTEGER q;
    DWORD v[6];
    static LONG ctr;

    QueryPerformanceCounter(&q);
    v[0] = q.LowPart; v[1] = q.HighPart; v[2] = GetTickCount();
    v[3] = GetCurrentProcessId() ^ (GetCurrentThreadId() << 16); v[4] = (DWORD)(ULONG_PTR)&q;
    v[5] = (DWORD)InterlockedIncrement(&ctr);
    Sha256Init(&s);
    Sha256Update(&s, v, sizeof(v));
    Sha256Final(&s, d);
    memcpy(out, d, 16);
}

static BOOL ConstEq(const BYTE *a, const BYTE *b, int n)
{
    int i;
    BYTE x = 0;
    for (i = 0; i < n; i++) x |= a[i] ^ b[i];
    return x == 0;
}

static void Mac(const char *token, char role, const BYTE *snonce, const BYTE *gnonce, BYTE out[32])
{
    BYTE m[33];
    m[0] = (BYTE)role;
    memcpy(m + 1, snonce, 16);
    memcpy(m + 17, gnonce, 16);
    HmacSha256((const BYTE *)token, strlen(token), m, sizeof(m), out);
}

static BOOL Handshake(CONN *c, const char *token)
{
    RMSG m;
    BYTE sn[16], gn[16], mac[32], theirs[32];
    char gnh[40], mach[70], info[300];
    REPLY r;
    const char *v;
    WCHAR comp[64] = L"";
    DWORD n = 64;
    OSVERSIONINFOW vi;

    if (!RecvMsg(c, &m, 10000) || strcmp(m.verb, "CHALLENGE")) return FALSE;
    v = MsgGet(&m, "nonce");
    if (!v || HexDecode(v, sn, 16) != 16) return FALSE;
    Random16(gn);
    Mac(token, 'G', sn, gn, mac);
    HexEncode(gn, 16, gnh);
    HexEncode(mac, 32, mach);
    ZeroMemory(&vi, sizeof(vi));
    vi.dwOSVersionInfoSize = sizeof(vi);
    GetVersionExW(&vi);
    GetComputerNameW(comp, &n);
    _snprintf(info, sizeof(info), "%lu.%lu.%lu", vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);
    info[sizeof(info) - 1] = 0;
    ReplyInit(&r, "HELLO");
    ReplyStr(&r, "v", "1");
    ReplyStr(&r, "gnonce", gnh);
    ReplyStr(&r, "mac", mach);
    ReplyStr(&r, "agent", ROSDEV_VERSION);
#ifdef _WIN64
    ReplyStr(&r, "arch", "x64");
#else
    ReplyStr(&r, "arch", "x86");
#endif
    ReplyStr(&r, "os", info);
    ReplyWide(&r, "computer", comp);
    ReplyU64(&r, "pid", GetCurrentProcessId());
    if (!ReplySend(c, &r)) return FALSE;
    if (!RecvMsg(c, &m, 10000) || strcmp(m.verb, "WELCOME")) return FALSE;
    v = MsgGet(&m, "mac");
    if (!v || HexDecode(v, theirs, 32) != 32) return FALSE;
    Mac(token, 'H', sn, gn, mac);
    return ConstEq(mac, theirs, 32);
}

static BOOL LocalAddressAllowed(SOCKET s)
{
    struct sockaddr_in a;
    int len = sizeof(a);

    if (getsockname(s, (struct sockaddr *)&a, &len) != 0 || a.sin_family != AF_INET) return FALSE;
    return (ntohl(a.sin_addr.s_addr) & 0xFFFFFF00UL) == ROSDEV_NET_PREFIX;
}

static BOOL ConnectHost(CONN *c, USHORT port)
{
    struct sockaddr_in a;

    ZeroMemory(c, sizeof(*c));
    c->s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (c->s == INVALID_SOCKET) return FALSE;
    /* jobs start child processes with inherited handles; they must not inherit the host connection */
    SetHandleInformation((HANDLE)c->s, HANDLE_FLAG_INHERIT, 0);
    ZeroMemory(&a, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = inet_addr(ROSDEV_HOST_ADDR);
    if (connect(c->s, (struct sockaddr *)&a, sizeof(a)) != 0 || !LocalAddressAllowed(c->s))
    {
        closesocket(c->s);
        c->s = INVALID_SOCKET;
        return FALSE;
    }
    return TRUE;
}

static BOOL HasArg(const WCHAR *cmd, const WCHAR *arg, WCHAR *value, int cch)
{
    size_t al = wcslen(arg);
    const WCHAR *p = cmd;

    while (*p)
    {
        const WCHAR *e;
        while (*p == L' ') p++;
        e = p;
        while (*e && *e != L' ') e++;
        if ((size_t)(e - p) >= al && !_wcsnicmp(p, arg, al) && (!value ? (size_t)(e - p) == al : (e - p > (int)al)))
        {
            if (value)
            {
                int n = (int)(e - p - al);
                if (n >= cch) n = cch - 1;
                memcpy(value, p + al, n * sizeof(WCHAR));
                value[n] = 0;
            }
            return TRUE;
        }
        p = e;
    }
    return FALSE;
}

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE prev, LPWSTR cmd, int show)
{
    WCHAR marker[64] = L"", wtoken[136] = L"", wport[16] = L"";
    char token[4 * 128 + 1];
    DWORD port;
    WSADATA wsa;
    CONN c;
    HANDLE mutex;
    int tries;

    wcsncpy(g_Args, cmd, 511);
    g_Args[511] = 0;
    if (!HasArg(cmd, L"/testvm", NULL, 0) || !ReadRegString(L"RosDevTestVm", marker, 64) || wcscmp(marker, ROSDEV_MARKER))
    {
        LogLine("refusing to run: needs /testvm and the TestVm marker (test VMs only)");
        return 2;
    }
    for (tries = 0;; tries++)
    {
        mutex = CreateMutexW(NULL, FALSE, L"Global\\RosDevAgent");
        if (mutex && GetLastError() != ERROR_ALREADY_EXISTS) break;
        if (mutex) CloseHandle(mutex);
        /* /wait: a restart in progress, the old agent is still exiting */
        if (!HasArg(cmd, L"/wait", NULL, 0) || tries > 150) return 3;
        Sleep(200);
    }

    port = ReadRegDword(L"RosDevPort", ROSDEV_DEFAULT_PORT);
    if (HasArg(cmd, L"/port:", wport, 16)) port = (DWORD)_wtoi(wport);
    if (!ReadRegString(L"RosDevToken", wtoken, 136)) wtoken[0] = 0;
    HasArg(cmd, L"/token:", wtoken, 136);
    if (!wtoken[0] || port == 0 || port > 65535)
    {
        LogLine("refusing to run: no token or bad port");
        return 4;
    }
    if (!WideCharToMultiByte(CP_UTF8, 0, wtoken, -1, token, sizeof(token), NULL, NULL))
    {
        LogLine("refusing to run: token does not convert");
        return 4;
    }
    if (WSAStartup(MAKEWORD(2, 2), &wsa)) return 5;
    LogLine("rosdev %s started, host %s:%lu", ROSDEV_VERSION, ROSDEV_HOST_ADDR, port);

    while (!g_Quit)
    {
        static RMSG msg;     /* large, keep it off the stack */

        if (!ConnectHost(&c, (USHORT)port)) { Sleep(2000); continue; }
        if (!Handshake(&c, token))
        {
            LogLine("handshake failed");
            closesocket(c.s);
            Sleep(2000);
            continue;
        }
        LogLine("connected");
        for (;;)
        {
            if (!ConnWrite(&c, "POLL\n", 5)) break;
            if (!RecvMsg(&c, &msg, POLL_WAIT)) break;
            if (!strcmp(msg.verb, "NOP")) continue;
            if (strcmp(msg.verb, "JOB")) break;
            if (!RunJob(&c, &msg)) break;
            if (g_Quit || g_PowerPending) break;
        }
        closesocket(c.s);
        LogLine("disconnected");
        if (g_PowerPending)
        {
            Sleep(120000);      /* the shutdown ends this process; if it does not, resume */
            g_PowerPending = FALSE;
            LogLine("power request did not end the session; resuming");
        }
        else if (!g_Quit) Sleep(1000);
    }
    WSACleanup();
    return 0;
}
