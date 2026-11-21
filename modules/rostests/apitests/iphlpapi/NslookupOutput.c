/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test what nslookup.exe asks for and prints for a name that has an IPv4 and an IPv6 address
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Windows Server 2022 (measured against a DNS server that logs its queries): "nslookup NAME SERVER" sends a PTR query for
 * the server, then BOTH an A and an AAAA query for the name, and prints all addresses, the IPv6 one first:
 *
 *   Name:    dual.kb.test
 *   Addresses:  fd00:88::51
 *             10.88.0.51
 *
 * "-type=A" sends only the A query and "-type=AAAA" only the AAAA query.
 * The test runs a DNS server on 127.0.0.2:53 (the port nslookup uses) and runs nslookup.exe against it.
 */

#include <apitest.h>

#define WIN32_NO_STATUS
#include <winsock2.h>
#include <strsafe.h>

#define MAX_SEEN 32

static SOCKET g_Server = INVALID_SOCKET;
static volatile LONG g_Stop;
static CRITICAL_SECTION g_Lock;
static char g_SeenName[MAX_SEEN][64];
static USHORT g_SeenType[MAX_SEEN];
static int g_SeenCount;

/* Answers: dual.test has A 10.1.2.3 and AAAA fd00:88::51, a4only.test has A 10.1.2.4 and an empty answer to AAAA;
   everything else (the PTR query for the server too) does not exist */
static int BuildReply(const UCHAR *q, int qlen, UCHAR *r, char *name, USHORT *type)
{
    int i = 12, n = 0, len;
    static const UCHAR aaaa[16] = { 0xfd, 0x00, 0x00, 0x88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x51 };
    const UCHAR *data = NULL;
    int datalen = 0;
    UCHAR a4[4];
    BOOL dual, a4only;

    if (qlen < 17)
        return 0;
    while (i < qlen && q[i])
    {
        int l = q[i];
        if (i + 1 + l >= qlen || n + l + 2 >= 64)
            return 0;
        if (n)
            name[n++] = '.';
        memcpy(name + n, q + i + 1, l);
        n += l;
        i += 1 + l;
    }
    name[n] = 0;
    if (i + 5 > qlen)
        return 0;
    i += 1;
    *type = (USHORT)((q[i] << 8) | q[i + 1]);
    i += 4;
    len = i;

    memcpy(r, q, len);
    r[2] = 0x81;
    r[3] = 0x80;
    r[6] = r[7] = r[8] = r[9] = r[10] = r[11] = 0;

    dual = !_stricmp(name, "dual.test");
    a4only = !_stricmp(name, "a4only.test");
    if (!dual && !a4only)
    {
        r[3] = 0x83; /* NXDOMAIN */
        return len;
    }
    if (*type == 1)
    {
        a4[0] = 10; a4[1] = 1; a4[2] = 2; a4[3] = dual ? 3 : 4;
        data = a4;
        datalen = 4;
    }
    else if (*type == 28 && dual)
    {
        data = aaaa;
        datalen = 16;
    }
    if (data)
    {
        r[7] = 1;
        r[len++] = 0xC0; r[len++] = 0x0C;
        r[len++] = 0; r[len++] = *type & 0xFF;
        r[len++] = 0; r[len++] = 1;
        r[len++] = 0; r[len++] = 0; r[len++] = 0; r[len++] = 60;
        r[len++] = 0; r[len++] = (UCHAR)datalen;
        memcpy(r + len, data, datalen);
        len += datalen;
    }
    return len;
}

static DWORD WINAPI ServerThread(PVOID Context)
{
    UCHAR q[512], r[512];
    SOCKADDR_IN from;
    int fromlen, got, len;
    char name[64];
    USHORT type;

    while (!g_Stop)
    {
        fromlen = sizeof(from);
        got = recvfrom(g_Server, (char *)q, sizeof(q), 0, (SOCKADDR *)&from, &fromlen);
        if (got <= 0)
        {
            if (WSAGetLastError() != WSAETIMEDOUT)
                Sleep(10);
            continue;
        }
        name[0] = 0;
        type = 0;
        len = BuildReply(q, got, r, name, &type);
        if (!len)
            continue;
        EnterCriticalSection(&g_Lock);
        if (g_SeenCount < MAX_SEEN)
        {
            StringCchCopyA(g_SeenName[g_SeenCount], sizeof(g_SeenName[0]), name);
            g_SeenType[g_SeenCount++] = type;
        }
        LeaveCriticalSection(&g_Lock);
        sendto(g_Server, (char *)r, len, 0, (SOCKADDR *)&from, fromlen);
    }
    return 0;
}

/* The output of a command line, without carriage returns */
static BOOL RunCapture(PCWSTR pszCommand, PSTR pszOut, DWORD cbOut)
{
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    HANDLE hRead, hWrite;
    WCHAR szCmd[MAX_PATH * 2];
    DWORD cb, total = 0, i, j;
    BOOL ok_;

    if (!CreatePipe(&hRead, &hWrite, &sa, 0))
        return FALSE;
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    StringCchCopyW(szCmd, ARRAYSIZE(szCmd), pszCommand);
    ok_ = CreateProcessW(NULL, szCmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(hWrite);
    if (!ok_)
    {
        CloseHandle(hRead);
        return FALSE;
    }
    while (total < cbOut - 1 && ReadFile(hRead, pszOut + total, cbOut - 1 - total, &cb, NULL) && cb)
        total += cb;
    pszOut[total] = 0;
    WaitForSingleObject(pi.hProcess, 60000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hRead);
    for (i = j = 0; pszOut[i]; i++)
        if (pszOut[i] != '\r')
            pszOut[j++] = pszOut[i];
    pszOut[j] = 0;
    return TRUE;
}

static int CountQueries(PCSTR pszName, USHORT Type)
{
    int i, n = 0;

    EnterCriticalSection(&g_Lock);
    for (i = 0; i < g_SeenCount; i++)
        if (g_SeenType[i] == Type && !_stricmp(g_SeenName[i], pszName))
            n++;
    LeaveCriticalSection(&g_Lock);
    return n;
}

static void Run(PCWSTR pszExe, PCWSTR pszArgs, PSTR pszOut, DWORD cbOut)
{
    WCHAR szCmd[MAX_PATH * 2];

    EnterCriticalSection(&g_Lock);
    g_SeenCount = 0;
    LeaveCriticalSection(&g_Lock);
    StringCchPrintfW(szCmd, ARRAYSIZE(szCmd), L"\"%s\" %s", pszExe, pszArgs);
    ok(RunCapture(szCmd, pszOut, cbOut), "could not run %ls\n", szCmd);
}

START_TEST(NslookupOutput)
{
    static char szOut[8192];
    WCHAR szExe[MAX_PATH];
    WSADATA wsaData;
    SOCKADDR_IN addr;
    DWORD timeout = 200;
    HANDLE hThread;
    PCSTR p;

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

    g_Server = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ok(g_Server != INVALID_SOCKET, "socket failed: %d\n", WSAGetLastError());
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK + 1);  /* 127.0.0.2: nslookup binds its own socket to port 53, and a
                                                           server on 127.0.0.1:53 would get its own replies */
    if (g_Server == INVALID_SOCKET || bind(g_Server, (SOCKADDR *)&addr, sizeof(addr)) != 0)
    {
        skip("Cannot bind 127.0.0.2:53 (error %d)\n", WSAGetLastError());
        if (g_Server != INVALID_SOCKET)
            closesocket(g_Server);
        WSACleanup();
        return;
    }
    setsockopt(g_Server, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    InitializeCriticalSection(&g_Lock);
    hThread = CreateThread(NULL, 0, ServerThread, NULL, 0, NULL);

    /* a name with both address types: A and AAAA are asked, both are printed, IPv6 first */
    Run(szExe, L"dual.test 127.0.0.2", szOut, sizeof(szOut));
    ok(CountQueries("dual.test", 1) >= 1, "no A query for dual.test\n");
    ok(CountQueries("dual.test", 28) >= 1, "no AAAA query for dual.test\n");
    p = strstr(szOut, "Addresses:  fd00:88::51\n          10.1.2.3\n");
    ok(p != NULL, "both addresses not printed, IPv6 first: '%s'\n", szOut);

    /* a name with an A record only: the AAAA answer is empty */
    Run(szExe, L"a4only.test 127.0.0.2", szOut, sizeof(szOut));
    ok(CountQueries("a4only.test", 1) >= 1, "no A query for a4only.test\n");
    ok(CountQueries("a4only.test", 28) >= 1, "no AAAA query for a4only.test\n");
    ok(strstr(szOut, "Address:  10.1.2.4\n") != NULL, "address not printed: '%s'\n", szOut);
    ok(strstr(szOut, "Addresses") == NULL, "'Addresses' printed for one address: '%s'\n", szOut);

    /* -type=A asks only for A, -type=AAAA only for AAAA */
    Run(szExe, L"-type=A dual.test 127.0.0.2", szOut, sizeof(szOut));
    ok(CountQueries("dual.test", 1) >= 1, "no A query with -type=A\n");
    ok(CountQueries("dual.test", 28) == 0, "AAAA query with -type=A\n");
    ok(strstr(szOut, "10.1.2.3") != NULL && strstr(szOut, "fd00:88::51") == NULL, "-type=A output: '%s'\n", szOut);

    Run(szExe, L"-type=AAAA dual.test 127.0.0.2", szOut, sizeof(szOut));
    ok(CountQueries("dual.test", 28) >= 1, "no AAAA query with -type=AAAA\n");
    ok(CountQueries("dual.test", 1) == 0, "A query with -type=AAAA\n");
    ok(strstr(szOut, "fd00:88::51") != NULL && strstr(szOut, "10.1.2.3") == NULL, "-type=AAAA output: '%s'\n", szOut);

    g_Stop = 1;
    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    closesocket(g_Server);
    DeleteCriticalSection(&g_Lock);
    WSACleanup();
}
