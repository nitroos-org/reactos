/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test the line format of netstat.exe for a listening TCP socket and a bound UDP socket
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Windows 10 22H2 (measured, netstat -an and netstat -ano, a listener on 0.0.0.0, one on 127.0.0.1 and a bound UDP socket):
 *
 *   "  TCP    0.0.0.0:5599           0.0.0.0:0              LISTENING"          (no padding after the state)
 *   "  TCP    0.0.0.0:5599           0.0.0.0:0              LISTENING       3828"
 *   "  UDP    0.0.0.0:5597           *:*                    "                   (*:* padded to 23, no PID)
 *   "  UDP    0.0.0.0:5597           *:*                                    3828"
 *
 * The protocol starts in column 2, the local address in 9, the foreign address in 32, the state in 55 and the PID in 71.
 * Installers such as Oracle XE's find a port by the text ":<port> " in these lines.
 */

#include <apitest.h>

#define WIN32_NO_STATUS
#include <winsock2.h>
#include <strsafe.h>

#define TCP_PORT 9878
#define UDP_PORT 9879

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
    WaitForSingleObject(pi.hProcess, 30000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hRead);
    for (i = j = 0; pszOut[i]; i++)
        if (pszOut[i] != '\r')
            pszOut[j++] = pszOut[i];
    pszOut[j] = 0;
    return TRUE;
}

/* The line of the output that has the text pszNeedle, copied to pszLine; FALSE if there is none */
static BOOL FindLine(PCSTR pszOut, PCSTR pszNeedle, PSTR pszLine, SIZE_T cchLine)
{
    PCSTR p = pszOut, eol;

    while (*p)
    {
        SIZE_T len;

        eol = strchr(p, '\n');
        len = eol ? (SIZE_T)(eol - p) : strlen(p);
        if (len < cchLine)
        {
            memcpy(pszLine, p, len);
            pszLine[len] = 0;
            if (strstr(pszLine, pszNeedle))
                return TRUE;
        }
        if (!eol)
            break;
        p = eol + 1;
    }
    return FALSE;
}

static void CheckColumn(PCSTR pszLine, SIZE_T Column, PCSTR pszText, PCSTR pszWhat)
{
    ok(strlen(pszLine) >= Column + strlen(pszText) && !strncmp(pszLine + Column, pszText, strlen(pszText)),
       "%s: '%s' not at column %lu of '%s'\n", pszWhat, pszText, (ULONG)Column, pszLine);
}

START_TEST(NetstatOutput)
{
    static char szOut[65536];
    char szLine[512], szPid[32], szNeedle[32];
    WCHAR szNetstat[MAX_PATH], szCmd[MAX_PATH * 2];
    WSADATA wsaData;
    SOCKET tcp = INVALID_SOCKET, udp = INVALID_SOCKET;
    SOCKADDR_IN addr;
    SIZE_T len;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        skip("Failed to init WS2\n");
        return;
    }

    GetSystemDirectoryW(szNetstat, ARRAYSIZE(szNetstat));
    StringCchCatW(szNetstat, ARRAYSIZE(szNetstat), L"\\netstat.exe");
    if (GetFileAttributesW(szNetstat) == INVALID_FILE_ATTRIBUTES)
    {
        skip("No netstat.exe\n");
        goto quit;
    }

    ZeroMemory(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    tcp = socket(AF_INET, SOCK_STREAM, 0);
    udp = socket(AF_INET, SOCK_DGRAM, 0);
    addr.sin_port = htons(TCP_PORT);
    if (tcp == INVALID_SOCKET || bind(tcp, (SOCKADDR *)&addr, sizeof(addr)) || listen(tcp, 5))
    {
        skip("Cannot listen on port %d\n", TCP_PORT);
        goto quit;
    }
    addr.sin_port = htons(UDP_PORT);
    if (udp == INVALID_SOCKET || bind(udp, (SOCKADDR *)&addr, sizeof(addr)))
    {
        skip("Cannot bind port %d\n", UDP_PORT);
        goto quit;
    }

    StringCchPrintfA(szPid, ARRAYSIZE(szPid), "%lu", GetCurrentProcessId());

    /* netstat -an */
    StringCchPrintfW(szCmd, ARRAYSIZE(szCmd), L"\"%s\" -an", szNetstat);
    if (!RunCapture(szCmd, szOut, sizeof(szOut)))
    {
        skip("Cannot run netstat\n");
        goto quit;
    }
    StringCchPrintfA(szNeedle, ARRAYSIZE(szNeedle), ":%d ", TCP_PORT);
    ok(FindLine(szOut, szNeedle, szLine, sizeof(szLine)), "No line with '%s' in the output of netstat -an\n", szNeedle);
    if (FindLine(szOut, szNeedle, szLine, sizeof(szLine)))
    {
        CheckColumn(szLine, 2, "TCP", "netstat -an");
        CheckColumn(szLine, 9, "0.0.0.0:9878", "netstat -an");
        CheckColumn(szLine, 32, "0.0.0.0:0", "netstat -an");
        CheckColumn(szLine, 55, "LISTENING", "netstat -an");
        len = strlen(szLine);
        ok(len == 55 + 9, "netstat -an: the line has trailing text or padding: '%s'\n", szLine);
    }
    StringCchPrintfA(szNeedle, ARRAYSIZE(szNeedle), ":%d ", UDP_PORT);
    ok(FindLine(szOut, szNeedle, szLine, sizeof(szLine)), "No line with '%s' in the output of netstat -an\n", szNeedle);
    if (FindLine(szOut, szNeedle, szLine, sizeof(szLine)))
    {
        CheckColumn(szLine, 2, "UDP", "netstat -an");
        CheckColumn(szLine, 9, "0.0.0.0:9879", "netstat -an");
        CheckColumn(szLine, 32, "*:*", "netstat -an");
    }
    ok(!FindLine(szOut, ":9880 ", szLine, sizeof(szLine)), "A line for a port nobody uses: '%s'\n", szLine);

    /* netstat -ano */
    StringCchPrintfW(szCmd, ARRAYSIZE(szCmd), L"\"%s\" -ano", szNetstat);
    if (!RunCapture(szCmd, szOut, sizeof(szOut)))
    {
        skip("Cannot run netstat -ano\n");
        goto quit;
    }
    StringCchPrintfA(szNeedle, ARRAYSIZE(szNeedle), ":%d ", TCP_PORT);
    if (FindLine(szOut, szNeedle, szLine, sizeof(szLine)))
    {
        CheckColumn(szLine, 55, "LISTENING", "netstat -ano");
        CheckColumn(szLine, 71, szPid, "netstat -ano");
        ok(strlen(szLine) == 71 + strlen(szPid), "netstat -ano: trailing text after the PID: '%s'\n", szLine);
    }
    else
    {
        ok(0, "No line with '%s' in the output of netstat -ano\n", szNeedle);
    }
    StringCchPrintfA(szNeedle, ARRAYSIZE(szNeedle), ":%d ", UDP_PORT);
    if (FindLine(szOut, szNeedle, szLine, sizeof(szLine)))
    {
        CheckColumn(szLine, 32, "*:*", "netstat -ano");
        CheckColumn(szLine, 71, szPid, "netstat -ano");
    }
    else
    {
        ok(0, "No line with '%s' in the output of netstat -ano\n", szNeedle);
    }

quit:
    if (tcp != INVALID_SOCKET)
        closesocket(tcp);
    if (udp != INVALID_SOCKET)
        closesocket(udp);
    WSACleanup();
}
