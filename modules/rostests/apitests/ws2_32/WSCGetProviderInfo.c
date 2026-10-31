/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for WSCGetProviderInfo
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows 10 22H2 (x64 and x86), default catalog: Firefox imports it (the Mozilla network code asks
 * for the LSP categories of the providers).
 */

#include "ws2_32.h"
#include <ws2spi.h>

typedef int (WSAAPI *WSCGetProviderInfo_t)(LPGUID, int, PBYTE, size_t *, DWORD, LPINT);

START_TEST(WSCGetProviderInfo)
{
    WSCGetProviderInfo_t pWSCGetProviderInfo;
    WSAPROTOCOL_INFOW *protocols;
    GUID unknown = { 1, 2, 3, { 4, 5, 6, 7, 8, 9, 10, 11 } };
    DWORD size = 0;
    BYTE buffer[64];
    size_t info_size;
    INT error, count, ret, i;
    WSADATA data;

    pWSCGetProviderInfo = (WSCGetProviderInfo_t)GetProcAddress(GetModuleHandleW(L"ws2_32.dll"), "WSCGetProviderInfo");
    ok(pWSCGetProviderInfo != NULL, "WSCGetProviderInfo is not exported\n");
    if (!pWSCGetProviderInfo)
        return;

    ok(WSAStartup(MAKEWORD(2, 2), &data) == 0, "WSAStartup failed\n");

    WSCEnumProtocols(NULL, NULL, &size, &error);
    protocols = malloc(size);
    count = WSCEnumProtocols(NULL, protocols, &size, &error);
    ok(count > 0, "WSCEnumProtocols returned %d\n", count);

    for (i = 0; i < count; i++)
    {
        /* the categories of the providers of the catalog cannot be read (nothing records them) */
        info_size = sizeof(DWORD);
        error = 0x1234;
        ret = pWSCGetProviderInfo(&protocols[i].ProviderId, 0, buffer, &info_size, 0, &error);
        ok(ret == SOCKET_ERROR, "%d: returned %d\n", i, ret);
        ok(error == WSAEINVALIDPROVIDER, "%d: error %d\n", i, error);
        ok(info_size == sizeof(DWORD), "%d: size %u\n", i, (unsigned)info_size);

        /* the flags do not matter */
        error = 0x1234;
        ret = pWSCGetProviderInfo(&protocols[i].ProviderId, 0, buffer, &info_size, 1, &error);
        ok(ret == SOCKET_ERROR && error == WSAEINVALIDPROVIDER, "%d: flags: %d %d\n", i, ret, error);
    }

    if (count > 0)
    {
        GUID *id = &protocols[0].ProviderId;

        /* the buffer has to be one DWORD */
        for (info_size = 0; info_size <= 64; info_size += 2)
        {
            if (info_size == sizeof(DWORD))
                continue;
            error = 0x1234;
            ret = pWSCGetProviderInfo(id, 0, buffer, &info_size, 0, &error);
            ok(ret == SOCKET_ERROR && error == WSAEINVAL, "size %u: %d %d\n", (unsigned)info_size, ret, error);
        }
        info_size = sizeof(DWORD);
        error = 0x1234;
        ret = pWSCGetProviderInfo(id, 0, NULL, &info_size, 0, &error);
        ok(ret == SOCKET_ERROR && error == WSAEINVAL, "no buffer: %d %d\n", ret, error);

        /* the audit information is not implemented, other types are not known */
        info_size = sizeof(DWORD);
        error = 0x1234;
        ret = pWSCGetProviderInfo(id, 1, buffer, &info_size, 0, &error);
        ok(ret == SOCKET_ERROR && error == ERROR_CALL_NOT_IMPLEMENTED, "audit: %d %d\n", ret, error);
        error = 0x1234;
        ret = pWSCGetProviderInfo(id, 2, buffer, &info_size, 0, &error);
        ok(ret == SOCKET_ERROR && error == WSANO_RECOVERY, "type 2: %d %d\n", ret, error);
        error = 0x1234;
        ret = pWSCGetProviderInfo(id, -1, buffer, &info_size, 0, &error);
        ok(ret == SOCKET_ERROR && error == WSANO_RECOVERY, "type -1: %d %d\n", ret, error);
    }

    /* a provider that is not in the catalog */
    info_size = sizeof(DWORD);
    error = 0x1234;
    ret = pWSCGetProviderInfo(&unknown, 0, buffer, &info_size, 0, &error);
    ok(ret == SOCKET_ERROR && error == WSANO_RECOVERY, "unknown provider: %d %d\n", ret, error);
    error = 0x1234;
    ret = pWSCGetProviderInfo(NULL, 0, buffer, &info_size, 0, &error);
    ok(ret == SOCKET_ERROR && error == WSAEFAULT, "no provider: %d %d\n", ret, error);

    free(protocols);
    WSACleanup();
}
