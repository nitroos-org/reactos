/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Which requests go through the proxy: the names of the machine itself are never proxied, a name
 *              with a dot is, and the tunnel request for an https target is HTTP/1.0
 *
 * The rows are what WinINet of Windows Server 2022 does (a proxy listener and an origin listener in this process,
 * InternetOpen with INTERNET_OPEN_TYPE_PROXY): "localhost" in any case and "127.0.0.1" go direct with any bypass list
 * or none, "localhost." and "127.0.0.2" go through the proxy, "<local>" adds the names without a dot.
 *
 * Neither wininet nor Winsock are imported: InternetOpen.c of this program tests that they are not loaded at start.
 */

#include <apitest.h>

#define WIN32_NO_STATUS
#define _INC_WINDOWS
#define COM_NO_WINDOWS_H
#include <windef.h>
#include <winnls.h>
#include <winsock2.h>
#include <wininet.h>
#include <stdio.h>
#include <string.h>

#define PROXY_PORT   18980
#define ORIGIN_PORT  18981

static HINTERNET (WINAPI *pInternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
static BOOL (WINAPI *pInternetSetOptionW)(HINTERNET, DWORD, LPVOID, DWORD);
static HINTERNET (WINAPI *pInternetOpenUrlW)(HINTERNET, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);
static BOOL (WINAPI *pInternetCloseHandle)(HINTERNET);

static int (WSAAPI *pWSAStartup)(WORD, LPWSADATA);
static int (WSAAPI *pWSACleanup)(void);
static SOCKET (WSAAPI *psocket)(int, int, int);
static int (WSAAPI *pbind)(SOCKET, const struct sockaddr *, int);
static int (WSAAPI *plisten)(SOCKET, int);
static SOCKET (WSAAPI *paccept)(SOCKET, struct sockaddr *, int *);
static int (WSAAPI *precv)(SOCKET, char *, int, int);
static int (WSAAPI *psend)(SOCKET, const char *, int, int);
static int (WSAAPI *pclosesocket)(SOCKET);
static int (WSAAPI *pioctlsocket)(SOCKET, long, u_long *);

static BOOL LoadFunctions(void)
{
    HMODULE hWininet = LoadLibraryA("wininet.dll"), hWs2 = LoadLibraryA("ws2_32.dll");

    if (!hWininet || !hWs2)
        return FALSE;
#define GET_INET(name) if (!(p##name = (void *)GetProcAddress(hWininet, #name))) return FALSE
    GET_INET(InternetOpenA); GET_INET(InternetSetOptionW); GET_INET(InternetOpenUrlW); GET_INET(InternetCloseHandle);
#undef GET_INET
#define GET_WS(name) if (!(p##name = (void *)GetProcAddress(hWs2, #name))) return FALSE
    GET_WS(WSAStartup); GET_WS(WSACleanup); GET_WS(socket); GET_WS(bind); GET_WS(listen); GET_WS(accept);
    GET_WS(recv); GET_WS(send); GET_WS(closesocket); GET_WS(ioctlsocket);
#undef GET_WS
    return TRUE;
}

static volatile LONG s_stop;
static CRITICAL_SECTION s_cs;
static char s_seen[256];

typedef struct { const char *who; USHORT port; const char *answer; HANDLE ready; } LISTENER;

static DWORD WINAPI Serve(LPVOID arg)
{
    LISTENER *l = arg;
    SOCKET s = psocket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    u_long nb = 1;

    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = (USHORT)((l->port >> 8) | (l->port << 8));
    a.sin_addr.s_addr = 0x0100007F; /* 127.0.0.1 */
    if (pbind(s, (struct sockaddr *)&a, sizeof(a)) || plisten(s, 8))
    {
        pclosesocket(s);
        SetEvent(l->ready);
        return 1;
    }
    pioctlsocket(s, FIONBIO, &nb);
    SetEvent(l->ready);
    while (!s_stop)
    {
        SOCKET c = paccept(s, NULL, NULL);
        char buf[512], resp[256];
        int n, i, k;

        if (c == INVALID_SOCKET)
        {
            Sleep(10);
            continue;
        }
        nb = 0;
        pioctlsocket(c, FIONBIO, &nb);
        n = precv(c, buf, sizeof(buf) - 1, 0);
        EnterCriticalSection(&s_cs);
        k = (int)strlen(s_seen);
        k += sprintf(s_seen + k, "%s:", l->who);
        for (i = 0; i < n && i < 60 && buf[i] != '\r' && buf[i] != '\n'; i++)
            s_seen[k++] = buf[i];
        s_seen[k] = 0;
        LeaveCriticalSection(&s_cs);
        if (n > 0 && !strncmp(buf, "CONNECT", 7))
            strcpy(resp, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        else
            sprintf(resp, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", (int)strlen(l->answer),
                    l->answer);
        psend(c, resp, (int)strlen(resp), 0);
        pclosesocket(c);
    }
    pclosesocket(s);
    return 0;
}

/* The name of the listener that saw the request ("proxy:..." or "origin:...") */
static const char *Try(HINTERNET in, const char *url)
{
    HINTERNET u;
    static char got[256];
    WCHAR wurl[256];

    EnterCriticalSection(&s_cs);
    s_seen[0] = 0;
    LeaveCriticalSection(&s_cs);
    MultiByteToWideChar(CP_ACP, 0, url, -1, wurl, ARRAYSIZE(wurl));
    u = pInternetOpenUrlW(in, wurl, NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (u)
        pInternetCloseHandle(u);
    Sleep(200);
    EnterCriticalSection(&s_cs);
    strcpy(got, s_seen);
    LeaveCriticalSection(&s_cs);
    return got;
}

static void Check(const char *bypass, const char *url, const char *want)
{
    HINTERNET in;
    DWORD to = 5000;
    char proxy[64];
    const char *got;

    sprintf(proxy, "127.0.0.1:%u", PROXY_PORT);
    in = pInternetOpenA("rostest", INTERNET_OPEN_TYPE_PROXY, proxy, bypass, 0);
    ok(in != NULL, "InternetOpen failed: %lu\n", GetLastError());
    if (!in)
        return;
    pInternetSetOptionW(in, INTERNET_OPTION_CONNECT_TIMEOUT, &to, sizeof(to));
    pInternetSetOptionW(in, INTERNET_OPTION_RECEIVE_TIMEOUT, &to, sizeof(to));
    got = Try(in, url);
    ok(strstr(got, want) == got, "bypass '%s', %s: saw '%s', expected '%s'\n", bypass ? bypass : "(none)", url, got, want);
    pInternetCloseHandle(in);
}

START_TEST(ProxyBypass)
{
    WSADATA wsa;
    LISTENER lp = { "proxy", PROXY_PORT, "PROXY", NULL }, lo = { "origin", ORIGIN_PORT, "ORIGIN", NULL };
    HANDLE th[2];
    char url[128];
    UINT i, h;
    static const char *const lists[] = { NULL, "", "<local>", "other.example" };
    static const struct { const char *host; BOOL direct; } hosts[] =
    {
        { "localhost", TRUE }, { "LOCALHOST", TRUE }, { "127.0.0.1", TRUE },
        { "localhost.", FALSE }, { "127.0.0.2", FALSE }, { "kb37name.invalid", FALSE },
    };

    if (!LoadFunctions() || pWSAStartup(MAKEWORD(2, 2), &wsa))
    {
        skip("wininet or Winsock is not available\n");
        return;
    }
    InitializeCriticalSection(&s_cs);
    lp.ready = CreateEventW(NULL, FALSE, FALSE, NULL);
    lo.ready = CreateEventW(NULL, FALSE, FALSE, NULL);
    th[0] = CreateThread(NULL, 0, Serve, &lp, 0, NULL);
    th[1] = CreateThread(NULL, 0, Serve, &lo, 0, NULL);
    WaitForSingleObject(lp.ready, 5000);
    WaitForSingleObject(lo.ready, 5000);

    for (i = 0; i < ARRAYSIZE(lists); i++)
    {
        for (h = 0; h < ARRAYSIZE(hosts); h++)
        {
            sprintf(url, "http://%s:%u/", hosts[h].host, ORIGIN_PORT);
            Check(lists[i], url, hosts[h].direct ? "origin:GET /" : "proxy:GET http://");
        }
    }

    /* a name without a dot is direct with "<local>" only (it does not resolve: no listener sees it) */
    Check("<local>", "http://nodots:18981/", "");
    Check(NULL, "http://nodots:18981/", "proxy:GET http://nodots");

    /* the tunnel request of an https target through the proxy */
    Check(NULL, "https://kb37name.invalid:18981/", "proxy:CONNECT kb37name.invalid:18981 HTTP/1.0");

    s_stop = 1;
    WaitForMultipleObjects(2, th, TRUE, 3000);
    CloseHandle(th[0]);
    CloseHandle(th[1]);
    CloseHandle(lp.ready);
    CloseHandle(lo.ready);
    DeleteCriticalSection(&s_cs);
    pWSACleanup();
}
