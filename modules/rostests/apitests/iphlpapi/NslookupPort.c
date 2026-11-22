/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The ports nslookup.exe uses: the source port of its queries is chosen by the stack (not 53), and the
 *              option -port= is taken but the server is still asked on port 53
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Windows Server 2022 (measured with a DNS server that logs the source address and port of every query): every query,
 * PTR of the server, A and AAAA, comes from its own ephemeral source port (60289, 60290, ...), never from 53. "set port=5353"
 * and "-port=5353" are accepted and "set all" shows port=5353, but the queries still go to port 53 and nothing arrives on 5353.
 * A server on 127.0.0.1:53 therefore works (nslookup used to bind its own socket to port 53 and answered itself).
 */

#include <apitest.h>

#define WIN32_NO_STATUS
#include <winsock2.h>
#include <strsafe.h>

#define MAX_SEEN 64

static SOCKET g_Sock[3] = { INVALID_SOCKET, INVALID_SOCKET, INVALID_SOCKET };    /* 127.0.0.2:53, 127.0.0.1:53, 127.0.0.2:5353 */
static volatile LONG g_Stop;
static CRITICAL_SECTION g_Lock;
static USHORT g_SeenPort[MAX_SEEN];
static int g_SeenSock[MAX_SEEN];
static int g_SeenCount;

/* A reply with one A record to every query; AAAA gets an empty answer */
static int BuildReply(const UCHAR *q, int qlen, UCHAR *r)
{
    int i = 12, len;
    USHORT type;

    if (qlen < 17)
        return 0;
    while (i < qlen && q[i])
        i += 1 + q[i];
    if (i + 5 > qlen)
        return 0;
    type = (USHORT)((q[i + 1] << 8) | q[i + 2]);
    len = i + 5;
    memcpy(r, q, len);
    r[2] = 0x85;
    r[3] = 0x80;
    r[6] = r[7] = r[8] = r[9] = r[10] = r[11] = 0;
    if (type == 1)
    {
        static const UCHAR rec[] = { 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 9 };

        r[7] = 1;
        memcpy(r + len, rec, sizeof(rec));
        len += sizeof(rec);
    }
    return len;
}

static DWORD WINAPI ServerThread(PVOID Context)
{
    UCHAR q[512], r[512];
    SOCKADDR_IN from;
    int fromlen, got, len, i;
    fd_set fds;
    struct timeval tv;

    while (!g_Stop)
    {
        FD_ZERO(&fds);
        for (i = 0; i < 3; i++)
            FD_SET(g_Sock[i], &fds);
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        if (select(0, &fds, NULL, NULL, &tv) <= 0)
            continue;
        for (i = 0; i < 3; i++)
        {
            if (!FD_ISSET(g_Sock[i], &fds))
                continue;
            fromlen = sizeof(from);
            got = recvfrom(g_Sock[i], (char *)q, sizeof(q), 0, (SOCKADDR *)&from, &fromlen);
            if (got <= 0)
                continue;
            EnterCriticalSection(&g_Lock);
            if (g_SeenCount < MAX_SEEN)
            {
                g_SeenPort[g_SeenCount] = ntohs(from.sin_port);
                g_SeenSock[g_SeenCount++] = i;
            }
            LeaveCriticalSection(&g_Lock);
            len = BuildReply(q, got, r);
            if (len && i != 2)
                sendto(g_Sock[i], (char *)r, len, 0, (SOCKADDR *)&from, fromlen);
        }
    }
    return 0;
}

static void RunCapture(PCWSTR pszCommand, PSTR pszOut, DWORD cbOut)
{
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    HANDLE hRead, hWrite;
    WCHAR szCmd[MAX_PATH * 2];
    DWORD cb, total = 0;

    pszOut[0] = 0;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0))
        return;
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    StringCchCopyW(szCmd, ARRAYSIZE(szCmd), pszCommand);
    if (!CreateProcessW(NULL, szCmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        CloseHandle(hWrite);
        CloseHandle(hRead);
        ok(FALSE, "could not run %ls\n", pszCommand);
        return;
    }
    CloseHandle(hWrite);
    while (total < cbOut - 1 && ReadFile(hRead, pszOut + total, cbOut - 1 - total, &cb, NULL) && cb)
        total += cb;
    pszOut[total] = 0;
    WaitForSingleObject(pi.hProcess, 60000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hRead);

    /* no carriage returns */
    for (cb = total = 0; pszOut[cb]; cb++)
        if (pszOut[cb] != '\r')
            pszOut[total++] = pszOut[cb];
    pszOut[total] = 0;
}

static void Reset(void)
{
    EnterCriticalSection(&g_Lock);
    g_SeenCount = 0;
    LeaveCriticalSection(&g_Lock);
}

/* Counts the queries that came to socket Sock from a source port that is (Port == 53) or is not 53 */
static int Count(int Sock, BOOL Port53)
{
    int i, n = 0;

    EnterCriticalSection(&g_Lock);
    for (i = 0; i < g_SeenCount; i++)
        if (g_SeenSock[i] == Sock && (g_SeenPort[i] == 53) == Port53)
            n++;
    LeaveCriticalSection(&g_Lock);
    return n;
}

START_TEST(NslookupPort)
{
    static char szOut[8192];
    static const struct { ULONG Addr; USHORT Port; } Bind[3] =
    {
        { 0x7F000002, 53 }, { 0x7F000001, 53 }, { 0x7F000002, 5353 },
    };
    WCHAR szExe[MAX_PATH], szCmd[MAX_PATH * 2];
    WSADATA wsaData;
    SOCKADDR_IN addr;
    HANDLE hThread;
    int i;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        skip("Failed to init WS2\n");
        return;
    }

    GetSystemDirectoryW(szExe, ARRAYSIZE(szExe));
    StringCchCatW(szExe, ARRAYSIZE(szExe), L"\\nslookup.exe");
    if (GetFileAttributesW(szExe) == INVALID_FILE_ATTRIBUTES)
    {
        skip("No nslookup.exe\n");
        WSACleanup();
        return;
    }

    for (i = 0; i < 3; i++)
    {
        g_Sock[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        addr.sin_family = AF_INET;
        addr.sin_port = htons(Bind[i].Port);
        addr.sin_addr.s_addr = htonl(Bind[i].Addr);
        if (g_Sock[i] == INVALID_SOCKET || bind(g_Sock[i], (SOCKADDR *)&addr, sizeof(addr)) != 0)
        {
            skip("Cannot bind port %u (error %d)\n", Bind[i].Port, WSAGetLastError());
            for (i = 0; i < 3; i++)
                if (g_Sock[i] != INVALID_SOCKET)
                    closesocket(g_Sock[i]);
            WSACleanup();
            return;
        }
    }
    InitializeCriticalSection(&g_Lock);
    hThread = CreateThread(NULL, 0, ServerThread, NULL, 0, NULL);

    /* a server on 127.0.0.2:53: the queries come from a source port that is not 53 */
    Reset();
    StringCchPrintfW(szCmd, ARRAYSIZE(szCmd), L"\"%s\" name.test 127.0.0.2", szExe);
    RunCapture(szCmd, szOut, sizeof(szOut));
    ok(Count(0, FALSE) >= 2, "queries from a source port other than 53: %d\n", Count(0, FALSE));
    ok(Count(0, TRUE) == 0, "%d queries came from source port 53\n", Count(0, TRUE));
    ok(strstr(szOut, "Address:  192.0.2.9\n") != NULL, "answer not printed: '%s'\n", szOut);

    /* the same for a server on 127.0.0.1:53, which used to be answered by nslookup's own socket */
    Reset();
    StringCchPrintfW(szCmd, ARRAYSIZE(szCmd), L"\"%s\" -timeout=1 -retry=0 name.test 127.0.0.1", szExe);
    RunCapture(szCmd, szOut, sizeof(szOut));
    ok(Count(1, TRUE) == 0, "%d queries to 127.0.0.1 came from source port 53\n", Count(1, TRUE));
    ok(strstr(szOut, "Address:  192.0.2.9\n") != NULL, "answer of 127.0.0.1 not printed: '%s'\n", szOut);

    /* -port= is taken, the server is still asked on port 53 and nothing arrives on 5353 */
    Reset();
    StringCchPrintfW(szCmd, ARRAYSIZE(szCmd), L"\"%s\" -port=5353 name.test 127.0.0.2", szExe);
    RunCapture(szCmd, szOut, sizeof(szOut));
    ok(Count(0, FALSE) >= 1, "no query on port 53 with -port=5353\n");
    ok(Count(2, FALSE) + Count(2, TRUE) == 0, "queries arrived on port 5353\n");
    ok(strstr(szOut, "Address:  192.0.2.9\n") != NULL, "answer not printed with -port=5353: '%s'\n", szOut);
    ok(strstr(szOut, "nknown") == NULL && strstr(szOut, "nvalid") == NULL, "-port=5353 not taken: '%s'\n", szOut);

    g_Stop = 1;
    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    for (i = 0; i < 3; i++)
        closesocket(g_Sock[i]);
    DeleteCriticalSection(&g_Lock);
    WSACleanup();
}
