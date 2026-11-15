/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The IP Helper service relays TCP for all four netsh interface portproxy kinds
 *              (v4tov4, v4tov6, v6tov4, v6tov6), takes a changed or removed entry at run time,
 *              and an IPv6 listener does not take IPv4
 *
 * The test writes entries under HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\<kind>\tcp as
 * "netsh interface portproxy add" does and removes them again. A local echo server is the target.
 */

#include <apitest.h>

#define WIN32_NO_STATUS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#define KEY_FMT   L"SYSTEM\\CurrentControlSet\\Services\\PortProxy\\%ls\\tcp"
#define WAIT_MS   40000

typedef struct _ECHO
{
    SOCKET Listener;
    HANDLE Thread;
    CHAR Tag;
    USHORT Port;
} ECHO;

typedef struct _KIND
{
    PCWSTR Name;
    BOOL ListenV6;
    BOOL TargetV6;
} KIND;

static const KIND g_Kinds[] =
{
    {L"v4tov4", FALSE, FALSE},
    {L"v4tov6", FALSE, TRUE},
    {L"v6tov4", TRUE,  FALSE},
    {L"v6tov6", TRUE,  TRUE},
};

static void SetLoopback(SOCKADDR_IN6 *Sa6, SOCKADDR_IN *Sa4, BOOL V6, USHORT Port)
{
    ZeroMemory(Sa6, sizeof(*Sa6));
    ZeroMemory(Sa4, sizeof(*Sa4));
    if (V6)
    {
        Sa6->sin6_family = AF_INET6;
        Sa6->sin6_addr.u.Byte[15] = 1;
        Sa6->sin6_port = htons(Port);
    }
    else
    {
        Sa4->sin_family = AF_INET;
        Sa4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        Sa4->sin_port = htons(Port);
    }
}

static int Connect(SOCKET s, BOOL V6, USHORT Port)
{
    SOCKADDR_IN6 Sa6;
    SOCKADDR_IN Sa4;

    SetLoopback(&Sa6, &Sa4, V6, Port);
    return V6 ? connect(s, (SOCKADDR *)&Sa6, sizeof(Sa6)) : connect(s, (SOCKADDR *)&Sa4, sizeof(Sa4));
}

/* A bound but not listening socket on the loopback gives a free port */
static USHORT FreePort(BOOL V6)
{
    SOCKADDR_IN6 Sa6;
    SOCKADDR_IN Sa4;
    SOCKET s = socket(V6 ? AF_INET6 : AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int Len = V6 ? sizeof(Sa6) : sizeof(Sa4);
    USHORT Port = 0;

    SetLoopback(&Sa6, &Sa4, V6, 0);
    if (s == INVALID_SOCKET)
        return 0;
    if ((V6 ? bind(s, (SOCKADDR *)&Sa6, sizeof(Sa6)) : bind(s, (SOCKADDR *)&Sa4, sizeof(Sa4))) == 0 &&
        (V6 ? getsockname(s, (SOCKADDR *)&Sa6, &Len) : getsockname(s, (SOCKADDR *)&Sa4, &Len)) == 0)
        Port = ntohs(V6 ? Sa6.sin6_port : Sa4.sin_port);
    closesocket(s);
    return Port;
}

/* Reads one request, answers Tag and the request, closes */
static DWORD WINAPI EchoThread(LPVOID Param)
{
    ECHO *e = Param;

    for (;;)
    {
        SOCKET c = accept(e->Listener, NULL, NULL);
        CHAR Buf[64];
        int n;

        if (c == INVALID_SOCKET)
            break;
        Buf[0] = e->Tag;
        n = recv(c, Buf + 1, sizeof(Buf) - 1, 0);
        if (n > 0)
            send(c, Buf, n + 1, 0);
        shutdown(c, SD_SEND);
        closesocket(c);
    }
    return 0;
}

static BOOL StartEcho(ECHO *e, BOOL V6, CHAR Tag)
{
    SOCKADDR_IN6 Sa6;
    SOCKADDR_IN Sa4;
    int Len = V6 ? sizeof(Sa6) : sizeof(Sa4);
    int Ret;

    ZeroMemory(e, sizeof(*e));
    e->Tag = Tag;
    e->Listener = socket(V6 ? AF_INET6 : AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (e->Listener == INVALID_SOCKET)
        return FALSE;
    SetLoopback(&Sa6, &Sa4, V6, 0);
    Ret = V6 ? bind(e->Listener, (SOCKADDR *)&Sa6, sizeof(Sa6)) : bind(e->Listener, (SOCKADDR *)&Sa4, sizeof(Sa4));
    if (Ret != 0 || listen(e->Listener, 5) != 0 ||
        (V6 ? getsockname(e->Listener, (SOCKADDR *)&Sa6, &Len) : getsockname(e->Listener, (SOCKADDR *)&Sa4, &Len)) != 0)
    {
        closesocket(e->Listener);
        return FALSE;
    }
    e->Port = ntohs(V6 ? Sa6.sin6_port : Sa4.sin_port);
    e->Thread = CreateThread(NULL, 0, EchoThread, e, 0, NULL);
    return e->Thread != NULL;
}

static void StopEcho(ECHO *e)
{
    closesocket(e->Listener);
    WaitForSingleObject(e->Thread, 5000);
    CloseHandle(e->Thread);
}

/* One request through the proxy: TRUE and the reply when the connection was made */
static BOOL Request(BOOL V6, USHORT Port, CHAR *Reply, int ReplySize, int *pLen)
{
    SOCKET s = socket(V6 ? AF_INET6 : AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int n, total = 0;
    DWORD Timeout = 5000;

    *pLen = 0;
    if (s == INVALID_SOCKET)
        return FALSE;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&Timeout, sizeof(Timeout));
    if (Connect(s, V6, Port) != 0)
    {
        closesocket(s);
        return FALSE;
    }
    if (send(s, "ping", 4, 0) != 4)
    {
        closesocket(s);
        return FALSE;
    }
    while (total < ReplySize && (n = recv(s, Reply + total, ReplySize - total, 0)) > 0)
        total += n;
    closesocket(s);
    *pLen = total;
    return TRUE;
}

/* Waits until a connection to the proxy port is made (Up) or refused (!Up) */
static BOOL WaitListener(BOOL V6, USHORT Port, BOOL Up)
{
    DWORD Start = GetTickCount();

    while (GetTickCount() - Start < WAIT_MS)
    {
        SOCKET s = socket(V6 ? AF_INET6 : AF_INET, SOCK_STREAM, IPPROTO_TCP);
        BOOL Connected;

        if (s == INVALID_SOCKET)
            return FALSE;
        Connected = Connect(s, V6, Port) == 0;
        closesocket(s);
        if (Connected == Up)
            return TRUE;
        Sleep(250);
    }
    return FALSE;
}

static LONG SetEntry(PCWSTR Kind, USHORT ListenPort, PCWSTR ListenAddr, PCWSTR TargetAddr, USHORT TargetPort)
{
    WCHAR Key[128], Name[64], Data[128];
    HKEY hKey;
    LONG Err;

    _snwprintf(Key, _countof(Key), KEY_FMT, Kind);
    _snwprintf(Name, _countof(Name), L"%ls/%u", ListenAddr, ListenPort);
    _snwprintf(Data, _countof(Data), L"%ls/%u", TargetAddr, TargetPort);
    Key[_countof(Key) - 1] = Name[_countof(Name) - 1] = Data[_countof(Data) - 1] = 0;
    Err = RegCreateKeyExW(HKEY_LOCAL_MACHINE, Key, 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL);
    if (Err != ERROR_SUCCESS)
        return Err;
    Err = RegSetValueExW(hKey, Name, 0, REG_SZ, (const BYTE *)Data, (DWORD)((wcslen(Data) + 1) * sizeof(WCHAR)));
    RegCloseKey(hKey);
    return Err;
}

static void DelEntry(PCWSTR Kind, USHORT ListenPort, PCWSTR ListenAddr)
{
    WCHAR Key[128], Name[64];
    HKEY hKey;

    _snwprintf(Key, _countof(Key), KEY_FMT, Kind);
    _snwprintf(Name, _countof(Name), L"%ls/%u", ListenAddr, ListenPort);
    Key[_countof(Key) - 1] = Name[_countof(Name) - 1] = 0;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, Key, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS)
    {
        RegDeleteValueW(hKey, Name);
        RegCloseKey(hKey);
    }
}

static void CheckReply(const char *What, BOOL Got, const CHAR *Reply, int Len, CHAR Tag)
{
    ok(Got, "%s: no connection through the proxy\n", What);
    ok(Len == 5 && Reply[0] == Tag && memcmp(Reply + 1, "ping", 4) == 0,
       "%s: reply of %d bytes '%.*s', expected '%cping'\n", What, Len, Len, Reply, Tag);
}

static void TestKind(const KIND *k)
{
    ECHO Echo;
    CHAR Reply[32];
    int Len;
    BOOL Got;
    USHORT ListenPort;
    LONG Err;
    PCWSTR ListenAddr = k->ListenV6 ? L"::1" : L"127.0.0.1";
    PCWSTR TargetAddr = k->TargetV6 ? L"::1" : L"127.0.0.1";
    char What[32];

    sprintf(What, "%ls", k->Name);
    if (!StartEcho(&Echo, k->TargetV6, 'A'))
    {
        skip("%s: no echo server (%d)\n", What, WSAGetLastError());
        return;
    }
    ListenPort = FreePort(k->ListenV6);
    ok(ListenPort != 0, "%s: no free port\n", What);

    Err = SetEntry(k->Name, ListenPort, ListenAddr, TargetAddr, Echo.Port);
    if (Err != ERROR_SUCCESS)
    {
        skip("%s: cannot write the PortProxy key (error %ld, not elevated?)\n", What, Err);
        StopEcho(&Echo);
        return;
    }

    ok(WaitListener(k->ListenV6, ListenPort, TRUE), "%s: the service did not listen on %ls/%u\n", What, ListenAddr, ListenPort);
    Got = Request(k->ListenV6, ListenPort, Reply, sizeof(Reply), &Len);
    CheckReply(What, Got, Reply, Len, 'A');

    /* an IPv6 listener on the loopback does not take IPv4 and the other way round */
    {
        SOCKET s = socket(k->ListenV6 ? AF_INET : AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        int Ret = Connect(s, !k->ListenV6, ListenPort);

        ok(Ret != 0, "%s: the listener also takes the other family\n", What);
        closesocket(s);
    }

    /* a second target takes over without a restart */
    {
        ECHO Echo2;

        if (StartEcho(&Echo2, k->TargetV6, 'B'))
        {
            DWORD Start = GetTickCount();

            ok(SetEntry(k->Name, ListenPort, ListenAddr, TargetAddr, Echo2.Port) == ERROR_SUCCESS, "%s: set\n", What);
            do
            {
                Got = Request(k->ListenV6, ListenPort, Reply, sizeof(Reply), &Len);
                if (Got && Len == 5 && Reply[0] == 'B')
                    break;
                Sleep(250);
            } while (GetTickCount() - Start < WAIT_MS);
            CheckReply(What, Got, Reply, Len, 'B');
            StopEcho(&Echo2);
        }
    }

    DelEntry(k->Name, ListenPort, ListenAddr);
    ok(WaitListener(k->ListenV6, ListenPort, FALSE), "%s: the listener is still there after the delete\n", What);
    StopEcho(&Echo);
}

/* "*" as the listen address and a host name as the target, each resolved for its family */
static void TestWildcardAndName(void)
{
    ECHO Echo;
    CHAR Reply[32];
    int Len;
    USHORT ListenPort = FreePort(TRUE);
    BOOL Got;

    if (!StartEcho(&Echo, TRUE, 'C'))
    {
        skip("no IPv6 echo server (%d)\n", WSAGetLastError());
        return;
    }
    /* v4tov6 on "*" towards "localhost": the IPv6 address of the name is used */
    if (SetEntry(L"v4tov6", ListenPort, L"*", L"localhost", Echo.Port) != ERROR_SUCCESS)
    {
        skip("cannot write the PortProxy key\n");
        StopEcho(&Echo);
        return;
    }
    ok(WaitListener(FALSE, ListenPort, TRUE), "v4tov6 */%u: no listener\n", ListenPort);
    Got = Request(FALSE, ListenPort, Reply, sizeof(Reply), &Len);
    CheckReply("v4tov6 * to localhost", Got, Reply, Len, 'C');
    DelEntry(L"v4tov6", ListenPort, L"*");
    ok(WaitListener(FALSE, ListenPort, FALSE), "v4tov6 */%u: still listening after the delete\n", ListenPort);

    /* the same port on the IPv4 and the IPv6 wildcard are two listeners */
    SetEntry(L"v6tov6", ListenPort, L"*", L"::1", Echo.Port);
    ok(WaitListener(TRUE, ListenPort, TRUE), "v6tov6 */%u: no listener\n", ListenPort);
    Got = Request(TRUE, ListenPort, Reply, sizeof(Reply), &Len);
    CheckReply("v6tov6 *", Got, Reply, Len, 'C');
    DelEntry(L"v6tov6", ListenPort, L"*");
    ok(WaitListener(TRUE, ListenPort, FALSE), "v6tov6 */%u: still listening after the delete\n", ListenPort);

    StopEcho(&Echo);
}

START_TEST(PortProxy)
{
    WSADATA wsa;
    SOCKET s;
    int i;

    ok(WSAStartup(MAKEWORD(2, 2), &wsa) == 0, "WSAStartup\n");

    s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET)
    {
        skip("no IPv6 sockets (IPv6 is off)\n");
        WSACleanup();
        return;
    }
    closesocket(s);

    for (i = 0; i < (int)_countof(g_Kinds); i++)
        TestKind(&g_Kinds[i]);
    TestWildcardAndName();

    WSACleanup();
}
