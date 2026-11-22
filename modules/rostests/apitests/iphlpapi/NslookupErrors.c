/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     What nslookup.exe prints when the answer to the A query is an error and the AAAA answer is not (and the
 *              other way round), for an empty answer to both, and for an error code of the server
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Windows Server 2022 (measured against a DNS server that logs its queries, 64 and 32 bit): the plain "nslookup NAME SERVER"
 * sends A and AAAA whatever the A answer is and prints the addresses that came. When no address came, the A query says why:
 *   its RCODE as "*** SERVER can't find NAME: <text>" (1 Format error, 2 Server failed, 3 Non-existent domain,
 *   4 Not implemented, 5 Query refused, others BAD ERROR VALUE), or, for an empty reply,
 *   "*** No internal type for both IPv4 and IPv6 Addresses (A+AAAA) records available for NAME".
 * -type=A / -type=AAAA with an empty reply: "*** No address (A) records available for NAME" /
 *   "*** No IPv6 address (AAAA) records available for NAME".
 * "Non-authoritative answer:" is printed when the A reply holds the answer and its AA bit is clear.
 * The server answers by the name: <A>-<AAAA>[-na].test with each of ok nx refused servfail formerr notimp yx nodata;
 * "na" clears the AA bit.
 */

#include <apitest.h>

#define WIN32_NO_STATUS
#include <winsock2.h>
#include <strsafe.h>

#define MAX_SEEN 32

static SOCKET g_Server = INVALID_SOCKET;
static volatile LONG g_Stop;
static CRITICAL_SECTION g_Lock;
static USHORT g_SeenType[MAX_SEEN];
static int g_SeenCount;

static int RcodeOf(PCSTR pszBehaviour)
{
    if (!_stricmp(pszBehaviour, "nx")) return 3;
    if (!_stricmp(pszBehaviour, "refused")) return 5;
    if (!_stricmp(pszBehaviour, "servfail")) return 2;
    if (!_stricmp(pszBehaviour, "formerr")) return 1;
    if (!_stricmp(pszBehaviour, "notimp")) return 4;
    if (!_stricmp(pszBehaviour, "yx")) return 6;
    return 0;
}

/* The reply to one query, 0 when it is not one for the names of this test */
static int BuildReply(const UCHAR *q, int qlen, UCHAR *r, USHORT *type)
{
    char name[64], beh[3][16];
    int i = 12, n = 0, len, nparts = 0, rcode;
    PSTR s, e;
    BOOL ok_ = FALSE, aa;

    if (qlen < 17)
        return 0;
    while (i < qlen && q[i])
    {
        int l = q[i];
        if (i + 1 + l >= qlen || n + l + 2 >= (int)sizeof(name))
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

    /* <a>-<aaaa>[-na].test */
    s = strstr(name, ".test");
    if (!s || s[5])
    {
        r[3] = 0x83;
        return len;
    }
    *s = 0;
    for (s = name; nparts < 3; nparts++)
    {
        e = strchr(s, '-');
        if (e) *e = 0;
        StringCchCopyA(beh[nparts], sizeof(beh[0]), s);
        if (!e) { nparts++; break; }
        s = e + 1;
    }
    if (nparts < 2)
    {
        r[3] = 0x83;
        return len;
    }
    aa = !(nparts > 2 && !_stricmp(beh[2], "na"));
    if (aa)
        r[2] |= 0x04;
    s = beh[*type == 28 ? 1 : 0];
    rcode = RcodeOf(s);
    r[3] = (UCHAR)(0x80 | rcode);
    ok_ = !_stricmp(s, "ok");
    if (ok_ && (*type == 1 || *type == 28))
    {
        static const UCHAR a4[4] = { 192, 0, 2, 7 };
        static const UCHAR a6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7 };
        int datalen = *type == 1 ? 4 : 16;

        r[7] = 1;
        r[len++] = 0xC0; r[len++] = 0x0C;
        r[len++] = 0; r[len++] = (UCHAR)*type;
        r[len++] = 0; r[len++] = 1;
        r[len++] = 0; r[len++] = 0; r[len++] = 0; r[len++] = 60;
        r[len++] = 0; r[len++] = (UCHAR)datalen;
        memcpy(r + len, *type == 1 ? a4 : a6, datalen);
        len += datalen;
    }
    return len;
}

static DWORD WINAPI ServerThread(PVOID Context)
{
    UCHAR q[512], r[512];
    SOCKADDR_IN from;
    int fromlen, got, len;
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
        type = 0;
        len = BuildReply(q, got, r, &type);
        if (!len)
            continue;
        EnterCriticalSection(&g_Lock);
        if (g_SeenCount < MAX_SEEN)
            g_SeenType[g_SeenCount++] = type;
        LeaveCriticalSection(&g_Lock);
        sendto(g_Server, (char *)r, len, 0, (SOCKADDR *)&from, fromlen);
    }
    return 0;
}

/* The output of a command line (standard output and error), without carriage returns */
static void RunCapture(PCWSTR pszCommand, PSTR pszOut, DWORD cbOut)
{
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    HANDLE hRead, hWrite;
    WCHAR szCmd[MAX_PATH * 2];
    DWORD cb, total = 0, i, j;

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
    for (i = j = 0; pszOut[i]; i++)
        if (pszOut[i] != '\r')
            pszOut[j++] = pszOut[i];
    pszOut[j] = 0;
}

static int CountQueries(USHORT Type)
{
    int i, n = 0;

    EnterCriticalSection(&g_Lock);
    for (i = 0; i < g_SeenCount; i++)
        if (g_SeenType[i] == Type)
            n++;
    LeaveCriticalSection(&g_Lock);
    return n;
}

typedef struct
{
    PCWSTR Args;        /* after the program name */
    PCSTR Contains;     /* text that must be in the output */
    PCSTR Absent;       /* text that must not be in the output, or NULL */
} ROW;

START_TEST(NslookupErrors)
{
    static const ROW Rows[] =
    {
        /* an error or an empty answer to A does not hide the AAAA answer, and the other way round */
        { L"refused-ok.test", "Address:  2001:db8::7\n", "can't find" },
        { L"nx-ok.test", "Address:  2001:db8::7\n", "can't find" },
        { L"servfail-ok.test", "Address:  2001:db8::7\n", "can't find" },
        { L"formerr-ok.test", "Address:  2001:db8::7\n", "can't find" },
        { L"nodata-ok.test", "Address:  2001:db8::7\n", "No internal type" },
        { L"ok-refused.test", "Address:  192.0.2.7\n", "can't find" },
        { L"ok-nx.test", "Address:  192.0.2.7\n", "can't find" },
        { L"ok-servfail.test", "Address:  192.0.2.7\n", "can't find" },
        { L"ok-nodata.test", "Address:  192.0.2.7\n", "No internal type" },
        { L"ok-ok.test", "Addresses:  2001:db8::7\n          192.0.2.7\n", "can't find" },
        /* no address: the A query says why */
        { L"nx-nx.test", "can't find nx-nx.test: Non-existent domain\n", NULL },
        { L"refused-refused.test", "can't find refused-refused.test: Query refused\n", NULL },
        { L"servfail-servfail.test", "can't find servfail-servfail.test: Server failed\n", NULL },
        { L"formerr-formerr.test", "can't find formerr-formerr.test: Format error\n", NULL },
        { L"notimp-notimp.test", "can't find notimp-notimp.test: Not implemented\n", NULL },
        { L"yx-yx.test", "can't find yx-yx.test: BAD ERROR VALUE\n", NULL },
        { L"nx-refused.test", "can't find nx-refused.test: Non-existent domain\n", "Query refused" },
        { L"refused-nx.test", "can't find refused-nx.test: Query refused\n", "Non-existent" },
        { L"servfail-nx.test", "can't find servfail-nx.test: Server failed\n", "Non-existent" },
        { L"nx-nodata.test", "can't find nx-nodata.test: Non-existent domain\n", "No internal type" },
        { L"nodata-nx.test", "*** No internal type for both IPv4 and IPv6 Addresses (A+AAAA) records available for nodata-nx.test\n", "Non-existent" },
        { L"nodata-nodata.test", "*** No internal type for both IPv4 and IPv6 Addresses (A+AAAA) records available for nodata-nodata.test\n", NULL },
        /* one type only */
        { L"-type=A nodata-nodata.test", "*** No address (A) records available for nodata-nodata.test\n", NULL },
        { L"-type=AAAA nodata-nodata.test", "*** No IPv6 address (AAAA) records available for nodata-nodata.test\n", NULL },
        { L"-type=A nx-nx.test", "can't find nx-nx.test: Non-existent domain\n", NULL },
        { L"-type=AAAA servfail-servfail.test", "can't find servfail-servfail.test: Server failed\n", NULL },
        /* "Non-authoritative answer:" follows the AA bit of the A reply that holds the answer */
        { L"ok-ok-na.test", "Non-authoritative answer:\n", NULL },
        { L"ok-ok.test", "Name:    ok-ok.test\n", "Non-authoritative" },
        { L"ok-nodata-na.test", "Non-authoritative answer:\n", NULL },
        { L"nodata-ok-na.test", "Address:  2001:db8::7\n", "Non-authoritative" },
        { L"-type=A ok-ok-na.test", "Non-authoritative answer:\n", NULL },
        { L"-type=AAAA ok-ok.test", "Address:  2001:db8::7\n", "Non-authoritative" },
    };
    static char szOut[8192];
    WCHAR szExe[MAX_PATH], szCmd[MAX_PATH * 2];
    WSADATA wsaData;
    SOCKADDR_IN addr;
    DWORD timeout = 200;
    HANDLE hThread;
    ULONG i;

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
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK + 1);
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

    for (i = 0; i < ARRAYSIZE(Rows); i++)
    {
        EnterCriticalSection(&g_Lock);
        g_SeenCount = 0;
        LeaveCriticalSection(&g_Lock);
        StringCchPrintfW(szCmd, ARRAYSIZE(szCmd), L"\"%s\" %s 127.0.0.2", szExe, Rows[i].Args);
        RunCapture(szCmd, szOut, sizeof(szOut));
        ok(strstr(szOut, Rows[i].Contains) != NULL, "%ls: '%s' not in the output: '%s'\n", Rows[i].Args, Rows[i].Contains, szOut);
        if (Rows[i].Absent)
            ok(strstr(szOut, Rows[i].Absent) == NULL, "%ls: '%s' is in the output: '%s'\n", Rows[i].Args, Rows[i].Absent, szOut);
    }

    /* both queries are sent although the A answer is an error */
    EnterCriticalSection(&g_Lock);
    g_SeenCount = 0;
    LeaveCriticalSection(&g_Lock);
    StringCchPrintfW(szCmd, ARRAYSIZE(szCmd), L"\"%s\" refused-ok.test 127.0.0.2", szExe);
    RunCapture(szCmd, szOut, sizeof(szOut));
    ok(CountQueries(1) >= 1, "no A query\n");
    ok(CountQueries(28) >= 1, "no AAAA query after an A answer that is an error\n");

    g_Stop = 1;
    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    closesocket(g_Server);
    DeleteCriticalSection(&g_Lock);
    WSACleanup();
}
