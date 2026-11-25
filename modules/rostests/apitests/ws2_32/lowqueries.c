/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later
 * PURPOSE:     The interface and address queries of Winsock work for a thread of Low integrity
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The queries of the stack (WSAIoctl SIO_GET_INTERFACE_LIST and SIO_ADDRESS_LIST_QUERY) opened \Device\Tcp for read and
 * write data. A Low integrity token cannot write an object that has no label (no-write-up), so the interface list failed
 * for a sandboxed process (and the failure path closed an invalid handle: a Debug assertion). Every request they send is
 * FILE_ANY_ACCESS: the helper opens the device for FILE_READ_ATTRIBUTES, which Windows grants to Everyone.
 */

#include "ws2_32.h"

static HANDLE MakeLowToken(void)
{
    HANDLE Process, Low = NULL;
    TOKEN_MANDATORY_LABEL Label;
    BYTE Sid[SECURITY_MAX_SID_SIZE];
    DWORD SidSize = sizeof(Sid);

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &Process))
        return NULL;
    if (!DuplicateTokenEx(Process, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &Low))
        Low = NULL;
    CloseHandle(Process);
    if (!Low)
        return NULL;

    CreateWellKnownSid(WinLowLabelSid, NULL, Sid, &SidSize);
    Label.Label.Sid = Sid;
    Label.Label.Attributes = SE_GROUP_INTEGRITY;
    if (!SetTokenInformation(Low, TokenIntegrityLevel, &Label, sizeof(Label) + SidSize))
    {
        CloseHandle(Low);
        return NULL;
    }
    return Low;
}

static void Queries(const char *Who)
{
    SOCKET s;
    char Buffer[4096];
    DWORD Bytes;
    int Result;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    ok(s != INVALID_SOCKET, "%s: socket failed %d\n", Who, WSAGetLastError());
    if (s == INVALID_SOCKET)
        return;

    Bytes = 0;
    Result = WSAIoctl(s, SIO_GET_INTERFACE_LIST, NULL, 0, Buffer, sizeof(Buffer), &Bytes, NULL, NULL);
    ok(Result == 0, "%s: SIO_GET_INTERFACE_LIST failed %d (%d)\n", Who, Result, WSAGetLastError());
    ok(Bytes >= sizeof(INTERFACE_INFO), "%s: SIO_GET_INTERFACE_LIST returned %lu bytes\n", Who, Bytes);

    Bytes = 0;
    Result = WSAIoctl(s, SIO_ADDRESS_LIST_QUERY, NULL, 0, Buffer, sizeof(Buffer), &Bytes, NULL, NULL);
    ok(Result == 0, "%s: SIO_ADDRESS_LIST_QUERY failed %d (%d)\n", Who, Result, WSAGetLastError());

    closesocket(s);
}

START_TEST(lowqueries)
{
    WSADATA Data;
    HANDLE Low;

    ok(WSAStartup(MAKEWORD(2, 2), &Data) == 0, "WSAStartup failed\n");

    Queries("caller");

    Low = MakeLowToken();
    ok(Low != NULL, "no Low token: %lu\n", GetLastError());
    if (Low)
    {
        ok(SetThreadToken(NULL, Low), "SetThreadToken failed %lu\n", GetLastError());
        Queries("Low");
        RevertToSelf();
        CloseHandle(Low);
    }

    WSACleanup();
}
