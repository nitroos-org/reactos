/*
 * PROJECT:     ReactOS IP Helper Service
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Port proxy: relays IPv4 TCP connections as configured under
 *              HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp
 *              (value name "listenaddress/listenport", data "connectaddress/connectport").
 *              Accepts on one thread per listener, connects on a pool thread, then relays both
 *              directions with overlapped WSARecv/WSASend completed through one I/O completion port.
 */

#include "precomp.h"

#define BUFSZ           16384
#define NUM_WORKERS     4
#define RELOAD_POLL_MS  10000
#define MAX_VALUE_CHARS 280

typedef struct _CONN CONN;

typedef struct _IOP
{
    OVERLAPPED ov;
    CONN *c;
    int dir;            /* reads s[dir], writes s[1 - dir] */
    int isSend;
    DWORD len;
    DWORD sent;
    CHAR buf[BUFSZ];
} IOP;

struct _CONN
{
    LIST_ENTRY Entry;
    SOCKET s[2];
    LONG pending;
    LONG aborted;
    LONG closed;
    LONG doneMask;
    IOP op[2];
};

typedef struct _LISTENER
{
    LIST_ENTRY Entry;
    WCHAR Name[MAX_VALUE_CHARS];
    WCHAR Data[MAX_VALUE_CHARS];
    WCHAR ConnHost[MAX_VALUE_CHARS];
    USHORT ConnPort;
    SOCKET Sock;
    HANDLE Thread;
    LONG Closing;
    BOOL Seen;
} LISTENER;

static CRITICAL_SECTION g_Lock;
static LIST_ENTRY g_Listeners;
static LIST_ENTRY g_Conns;
static LONG g_ConnCount;
static HANDLE g_hIocp;
static HANDLE g_hStop;
static HANDLE g_hCfgThread;
static HANDLE g_Workers[NUM_WORKERS];
static BOOL g_WsaStarted;

/* ---- connections ---------------------------------------------------------------- */

static
VOID
CloseConnSockets(CONN *c, BOOL bAbortive)
{
    int i;

    if (InterlockedExchange(&c->closed, 1))
        return;

    for (i = 0; i < 2; i++)
    {
        if (bAbortive)
        {
            struct linger l = {1, 0};
            setsockopt(c->s[i], SOL_SOCKET, SO_LINGER, (const char *)&l, sizeof(l));
        }
        closesocket(c->s[i]);
    }
}

static
VOID
AbortConn(CONN *c)
{
    InterlockedExchange(&c->aborted, 1);
    CloseConnSockets(c, TRUE);
}

static
VOID
FreeConn(CONN *c)
{
    CloseConnSockets(c, FALSE);
    EnterCriticalSection(&g_Lock);
    RemoveEntryList(&c->Entry);
    InterlockedDecrement(&g_ConnCount);
    LeaveCriticalSection(&g_Lock);
    HeapFree(GetProcessHeap(), 0, c);
}

static
VOID
ReleaseConn(CONN *c)
{
    if (InterlockedDecrement(&c->pending) == 0)
    {
        if (c->aborted || c->doneMask == 3)
            FreeConn(c);
    }
}

static
VOID
StartRecv(IOP *op)
{
    CONN *c = op->c;
    WSABUF wb;
    DWORD flags = 0;

    if (c->aborted)
        return;

    op->isSend = 0;
    ZeroMemory(&op->ov, sizeof(op->ov));
    wb.buf = op->buf;
    wb.len = BUFSZ;
    InterlockedIncrement(&c->pending);
    if (WSARecv(c->s[op->dir], &wb, 1, NULL, &flags, &op->ov, NULL) == SOCKET_ERROR &&
        WSAGetLastError() != WSA_IO_PENDING)
    {
        InterlockedDecrement(&c->pending);   /* the caller still holds a reference */
        AbortConn(c);
    }
}

static
VOID
StartSend(IOP *op)
{
    CONN *c = op->c;
    WSABUF wb;

    if (c->aborted)
        return;

    op->isSend = 1;
    ZeroMemory(&op->ov, sizeof(op->ov));
    wb.buf = op->buf + op->sent;
    wb.len = op->len - op->sent;
    InterlockedIncrement(&c->pending);
    if (WSASend(c->s[1 - op->dir], &wb, 1, NULL, 0, &op->ov, NULL) == SOCKET_ERROR &&
        WSAGetLastError() != WSA_IO_PENDING)
    {
        InterlockedDecrement(&c->pending);
        AbortConn(c);
    }
}

static
VOID
HandleCompletion(IOP *op, DWORD cb, BOOL bOk)
{
    CONN *c = op->c;

    if (!bOk)
    {
        AbortConn(c);
    }
    else if (!op->isSend)
    {
        if (cb == 0)
        {
            /* EOF from the sender: propagate the half-close, keep the other direction going */
            shutdown(c->s[1 - op->dir], SD_SEND);
            InterlockedExchangeAdd(&c->doneMask, 1 << op->dir);
        }
        else
        {
            op->len = cb;
            op->sent = 0;
            StartSend(op);
        }
    }
    else
    {
        op->sent += cb;
        if (cb == 0)
            AbortConn(c);
        else if (op->sent < op->len)
            StartSend(op);
        else
            StartRecv(op);
    }

    ReleaseConn(c);
}

static
DWORD
WINAPI
WorkerThread(LPVOID lpParam)
{
    for (;;)
    {
        DWORD cb = 0;
        ULONG_PTR key = 0;
        LPOVERLAPPED pov = NULL;
        BOOL ok = GetQueuedCompletionStatus(g_hIocp, &cb, &key, &pov, INFINITE);

        if (pov == NULL)
        {
            if (key == 1)
                break;      /* stop packet */
            continue;
        }

        HandleCompletion(CONTAINING_RECORD(pov, IOP, ov), cb, ok);
    }
    return 0;
}

/* ---- accept / connect ----------------------------------------------------------- */

typedef struct _CONNREQ
{
    SOCKET Client;
    WCHAR Host[MAX_VALUE_CHARS];
    USHORT Port;
} CONNREQ;

static
BOOL
ResolveHost(PCWSTR pszHost, ULONG *pAddr)
{
    CHAR szHost[MAX_VALUE_CHARS];
    ULONG addr;
    struct hostent *he;

    if (!WideCharToMultiByte(CP_ACP, 0, pszHost, -1, szHost, sizeof(szHost), NULL, NULL))
        return FALSE;

    addr = inet_addr(szHost);
    if (addr != INADDR_NONE || strcmp(szHost, "255.255.255.255") == 0)
    {
        *pAddr = addr;
        return TRUE;
    }

    he = gethostbyname(szHost);
    if (!he || he->h_addrtype != AF_INET || !he->h_addr_list[0])
        return FALSE;
    memcpy(pAddr, he->h_addr_list[0], sizeof(*pAddr));
    return TRUE;
}

static
DWORD
WINAPI
ConnectWork(LPVOID lpParam)
{
    CONNREQ *req = lpParam;
    struct sockaddr_in sa;
    SOCKET out = INVALID_SOCKET;
    CONN *c = NULL;
    ULONG addr;
    int i;

    if (!ResolveHost(req->Host, &addr))
        goto fail;

    out = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (out == INVALID_SOCKET)
        goto fail;

    ZeroMemory(&sa, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(req->Port);
    sa.sin_addr.s_addr = addr;
    if (connect(out, (struct sockaddr *)&sa, sizeof(sa)) == SOCKET_ERROR)
        goto fail;

    c = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*c));
    if (!c)
        goto fail;

    c->s[0] = req->Client;
    c->s[1] = out;
    c->pending = 1;     /* setup reference */
    for (i = 0; i < 2; i++)
    {
        c->op[i].c = c;
        c->op[i].dir = i;
    }

    for (i = 0; i < 2; i++)
    {
        if (!CreateIoCompletionPort((HANDLE)c->s[i], g_hIocp, 0, 0))
        {
            HeapFree(GetProcessHeap(), 0, c);
            c = NULL;
            goto fail;
        }
    }

    EnterCriticalSection(&g_Lock);
    InsertTailList(&g_Conns, &c->Entry);
    InterlockedIncrement(&g_ConnCount);
    LeaveCriticalSection(&g_Lock);

    StartRecv(&c->op[0]);
    StartRecv(&c->op[1]);
    ReleaseConn(c);
    HeapFree(GetProcessHeap(), 0, req);
    return 0;

fail:
    if (out != INVALID_SOCKET)
        closesocket(out);
    closesocket(req->Client);
    HeapFree(GetProcessHeap(), 0, req);
    return 0;
}

static
DWORD
WINAPI
AcceptThread(LPVOID lpParam)
{
    LISTENER *l = lpParam;

    for (;;)
    {
        SOCKET s = accept(l->Sock, NULL, NULL);
        CONNREQ *req;

        if (s == INVALID_SOCKET)
        {
            if (l->Closing)
                break;
            Sleep(50);
            continue;
        }

        req = HeapAlloc(GetProcessHeap(), 0, sizeof(*req));
        if (!req)
        {
            closesocket(s);
            continue;
        }
        req->Client = s;
        EnterCriticalSection(&g_Lock);
        wcscpy(req->Host, l->ConnHost);
        req->Port = l->ConnPort;
        LeaveCriticalSection(&g_Lock);

        if (!QueueUserWorkItem(ConnectWork, req, WT_EXECUTELONGFUNCTION))
        {
            closesocket(s);
            HeapFree(GetProcessHeap(), 0, req);
        }
    }
    return 0;
}

/* ---- configuration -------------------------------------------------------------- */

/* A port is a number or a service name, as entered by netsh */
static
BOOL
ParsePort(PCWSTR psz, USHORT *pPort)
{
    CHAR szName[64];
    struct servent *se;
    PWSTR end;
    long v;

    if (*psz >= L'0' && *psz <= L'9')
    {
        v = wcstol(psz, &end, 10);
        if (*end != 0 || v <= 0 || v > 65535)
            return FALSE;
        *pPort = (USHORT)v;
        return TRUE;
    }

    if (!WideCharToMultiByte(CP_ACP, 0, psz, -1, szName, sizeof(szName), NULL, NULL))
        return FALSE;
    se = getservbyname(szName, "tcp");
    if (!se)
        return FALSE;
    *pPort = ntohs((USHORT)se->s_port);
    return TRUE;
}

/* "addr/port" -> host string and port. The split is at the last '/'. */
static
BOOL
SplitEntry(PCWSTR psz, PWSTR pszHost, USHORT *pPort)
{
    PCWSTR p = wcsrchr(psz, L'/');
    SIZE_T n;

    if (!p || p == psz)
        return FALSE;
    n = p - psz;
    if (n >= MAX_VALUE_CHARS)
        return FALSE;
    memcpy(pszHost, psz, n * sizeof(WCHAR));
    pszHost[n] = 0;
    return ParsePort(p + 1, pPort);
}

static
VOID
SetListenerTarget(LISTENER *l, PCWSTR pszData)
{
    WCHAR host[MAX_VALUE_CHARS];
    USHORT port;

    EnterCriticalSection(&g_Lock);
    wcscpy(l->Data, pszData);
    if (SplitEntry(pszData, host, &port))
    {
        wcscpy(l->ConnHost, host);
        l->ConnPort = port;
    }
    else
    {
        l->ConnHost[0] = 0;
        l->ConnPort = 0;
    }
    LeaveCriticalSection(&g_Lock);
}

static
LISTENER *
StartListener(PCWSTR pszName, PCWSTR pszData)
{
    WCHAR host[MAX_VALUE_CHARS];
    USHORT port;
    ULONG addr;
    struct sockaddr_in sa;
    LISTENER *l;
    BOOL one = TRUE;

    if (!SplitEntry(pszName, host, &port))
        return NULL;
    if (wcscmp(host, L"*") == 0)
        addr = INADDR_ANY;
    else if (!ResolveHost(host, &addr))
        return NULL;

    l = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*l));
    if (!l)
        return NULL;
    wcscpy(l->Name, pszName);
    SetListenerTarget(l, pszData);

    l->Sock = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (l->Sock == INVALID_SOCKET)
        goto fail;

    setsockopt(l->Sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof(one));

    ZeroMemory(&sa, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = addr;
    if (bind(l->Sock, (struct sockaddr *)&sa, sizeof(sa)) == SOCKET_ERROR ||
        listen(l->Sock, SOMAXCONN) == SOCKET_ERROR)
        goto fail;

    l->Thread = CreateThread(NULL, 0, AcceptThread, l, 0, NULL);
    if (!l->Thread)
        goto fail;
    return l;

fail:
    if (l->Sock != INVALID_SOCKET)
        closesocket(l->Sock);
    HeapFree(GetProcessHeap(), 0, l);
    return NULL;
}

static
VOID
StopListener(LISTENER *l)
{
    InterlockedExchange(&l->Closing, 1);
    closesocket(l->Sock);
    WaitForSingleObject(l->Thread, 5000);
    CloseHandle(l->Thread);
    HeapFree(GetProcessHeap(), 0, l);
}

static
LISTENER *
FindListener(PCWSTR pszName)
{
    PLIST_ENTRY e;
    for (e = g_Listeners.Flink; e != &g_Listeners; e = e->Flink)
    {
        LISTENER *l = CONTAINING_RECORD(e, LISTENER, Entry);
        if (_wcsicmp(l->Name, pszName) == 0)
            return l;
    }
    return NULL;
}

static
VOID
ReloadConfig(VOID)
{
    HKEY hKey;
    DWORD i, cchName, cbData, dwType;
    WCHAR name[MAX_VALUE_CHARS], data[MAX_VALUE_CHARS];
    PLIST_ENTRY e, next;
    LISTENER *l;
    LIST_ENTRY dead;

    InitializeListHead(&dead);

    for (e = g_Listeners.Flink; e != &g_Listeners; e = e->Flink)
        CONTAINING_RECORD(e, LISTENER, Entry)->Seen = FALSE;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, PORTPROXY_KEY_V4TOV4, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        for (i = 0;; i++)
        {
            cchName = MAX_VALUE_CHARS - 1;
            cbData = (MAX_VALUE_CHARS - 1) * sizeof(WCHAR);
            if (RegEnumValueW(hKey, i, name, &cchName, NULL, &dwType, (LPBYTE)data, &cbData) != ERROR_SUCCESS)
                break;
            if (dwType != REG_SZ)
                continue;
            name[cchName] = 0;
            data[cbData / sizeof(WCHAR)] = 0;

            l = FindListener(name);
            if (l)
            {
                if (wcscmp(l->Data, data) != 0)
                    SetListenerTarget(l, data);
                l->Seen = TRUE;
            }
            else
            {
                l = StartListener(name, data);
                if (l)
                {
                    l->Seen = TRUE;
                    InsertTailList(&g_Listeners, &l->Entry);
                }
            }
        }
        RegCloseKey(hKey);
    }

    for (e = g_Listeners.Flink; e != &g_Listeners; e = next)
    {
        next = e->Flink;
        l = CONTAINING_RECORD(e, LISTENER, Entry);
        if (!l->Seen)
        {
            RemoveEntryList(&l->Entry);
            StopListener(l);
        }
    }
}

static
DWORD
WINAPI
ConfigThread(LPVOID lpParam)
{
    HKEY hKey = NULL;
    HANDLE hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    HANDLE h[2];
    BOOL bArmed = FALSE;
    DWORD dwWait;

    h[0] = g_hStop;
    h[1] = hEvent;

    RegCreateKeyExW(HKEY_LOCAL_MACHINE, PORTPROXY_KEY_V4TOV4, 0, NULL, 0,
                    KEY_READ | KEY_NOTIFY, NULL, &hKey, NULL);
    /* watch the whole PortProxy tree */
    if (hKey)
    {
        RegCloseKey(hKey);
        hKey = NULL;
    }
    RegOpenKeyExW(HKEY_LOCAL_MACHINE, PORTPROXY_KEY_ROOT, 0, KEY_READ | KEY_NOTIFY, &hKey);

    for (;;)
    {
        /* arm first, then read, so a change during the read is not lost.
         * A request stays pending until the key changes, so arm again only
         * after the event fired: every request armed on a poll timeout would
         * stay queued on the handle (one more every RELOAD_POLL_MS). */
        if (!bArmed && hKey && hEvent)
            bArmed = RegNotifyChangeKeyValue(hKey, TRUE,
                                             REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                                             hEvent, TRUE) == ERROR_SUCCESS;

        ReloadConfig();

        dwWait = WaitForMultipleObjects(bArmed ? 2 : 1, h, FALSE, RELOAD_POLL_MS);
        if (dwWait == WAIT_OBJECT_0)
            break;
        if (dwWait == WAIT_OBJECT_0 + 1)
            bArmed = FALSE;     /* the request completed */
    }

    if (hKey)
        RegCloseKey(hKey);
    if (hEvent)
        CloseHandle(hEvent);
    return 0;
}

/* ---- start / stop --------------------------------------------------------------- */

DWORD
PortProxyStart(VOID)
{
    WSADATA wsa;
    int i;
    DWORD err;

    InitializeCriticalSection(&g_Lock);
    InitializeListHead(&g_Listeners);
    InitializeListHead(&g_Conns);

    err = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (err)
        return err;
    g_WsaStarted = TRUE;

    g_hIocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, NUM_WORKERS);
    g_hStop = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_hIocp || !g_hStop)
    {
        err = GetLastError();
        PortProxyStop();
        return err ? err : ERROR_OUTOFMEMORY;
    }

    for (i = 0; i < NUM_WORKERS; i++)
        g_Workers[i] = CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);

    g_hCfgThread = CreateThread(NULL, 0, ConfigThread, NULL, 0, NULL);
    return NO_ERROR;
}

VOID
PortProxyStop(VOID)
{
    PLIST_ENTRY e;
    int i, tries;

    if (g_hStop)
        SetEvent(g_hStop);
    if (g_hCfgThread)
    {
        WaitForSingleObject(g_hCfgThread, 10000);
        CloseHandle(g_hCfgThread);
        g_hCfgThread = NULL;
    }

    /* the config thread is gone: no more listeners are created */
    while (!IsListEmpty(&g_Listeners))
    {
        LISTENER *l = CONTAINING_RECORD(RemoveHeadList(&g_Listeners), LISTENER, Entry);
        StopListener(l);
    }

    /* abort live relays and let the workers drain the cancelled I/O */
    EnterCriticalSection(&g_Lock);
    for (e = g_Conns.Flink; e != &g_Conns; e = e->Flink)
        AbortConn(CONTAINING_RECORD(e, CONN, Entry));
    LeaveCriticalSection(&g_Lock);
    for (tries = 0; g_ConnCount != 0 && tries < 100; tries++)
        Sleep(50);

    if (g_hIocp)
    {
        for (i = 0; i < NUM_WORKERS; i++)
            if (g_Workers[i])
                PostQueuedCompletionStatus(g_hIocp, 0, 1, NULL);
        for (i = 0; i < NUM_WORKERS; i++)
            if (g_Workers[i])
            {
                WaitForSingleObject(g_Workers[i], 5000);
                CloseHandle(g_Workers[i]);
                g_Workers[i] = NULL;
            }
        CloseHandle(g_hIocp);
        g_hIocp = NULL;
    }
    if (g_hStop)
    {
        CloseHandle(g_hStop);
        g_hStop = NULL;
    }
    if (g_WsaStarted)
    {
        WSACleanup();
        g_WsaStarted = FALSE;
    }
    DeleteCriticalSection(&g_Lock);
}
