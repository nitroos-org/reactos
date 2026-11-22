/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     RpcBindingSetAuthInfo of bindings of ncalrpc and ncacn_np: the status for authentication services and levels
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expected statuses are those of Windows Server 2022 (x64 and x86), probe rpcauth: no server is needed, the
 * status is given when the authentication is set. Not asserted: the services Negotiate, Kerberos and schannel on
 * ncalrpc (Windows answers 1747; the ReactOS code accepts them on purpose, see the ticket).
 */

#include <apitest.h>

#include <windows.h>
#include <rpc.h>

#define L_NONE    RPC_C_AUTHN_LEVEL_NONE
#define L_CONNECT RPC_C_AUTHN_LEVEL_CONNECT
#define L_PRIV    RPC_C_AUTHN_LEVEL_PKT_PRIVACY

static RPC_STATUS SetAuth(PCWSTR Protseq, PCWSTR Endpoint, ULONG Service, ULONG Level)
{
    RPC_WSTR String = NULL;
    RPC_BINDING_HANDLE Binding = NULL;
    RPC_STATUS Status;

    Status = RpcStringBindingComposeW(NULL, (RPC_WSTR)Protseq, (RPC_WSTR)(wcscmp(Protseq, L"ncalrpc") ? L"127.0.0.1" : L""),
                                      (RPC_WSTR)Endpoint, NULL, &String);
    if (Status != RPC_S_OK)
        return Status;
    Status = RpcBindingFromStringBindingW(String, &Binding);
    RpcStringFreeW(&String);
    if (Status != RPC_S_OK)
        return Status;
    Status = RpcBindingSetAuthInfoW(Binding, NULL, Level, Service, NULL, RPC_C_AUTHZ_NONE);
    RpcBindingFree(&Binding);
    return Status;
}

static void CheckRow(PCWSTR Protseq, PCWSTR Endpoint, ULONG Service, ULONG L1, ULONG L2, ULONG L6, ULONG L7, ULONG L99)
{
    static const ULONG Levels[] = { L_NONE, L_CONNECT, L_PRIV, 7, 99 };
    ULONG Expected[5];
    RPC_STATUS Status;
    int i;

    Expected[0] = L1; Expected[1] = L2; Expected[2] = L6; Expected[3] = L7; Expected[4] = L99;
    for (i = 0; i < 5; i++)
    {
        Status = SetAuth(Protseq, Endpoint, Service, Levels[i]);
        ok(Status == Expected[i], "%ls service 0x%lx level %lu: %lu, expected %lu\n",
           Protseq, Service, Levels[i], (ULONG)Status, Expected[i]);
    }
}

START_TEST(SetAuthInfoRows)
{
    PCWSTR Seqs[] = { L"ncalrpc", L"ncacn_np" };
    PCWSTR Endpoints[] = { L"kbauthep", L"\\pipe\\kbauthep" };
    int s;

    for (s = 0; s < 2; s++)
    {
        /* no service: only the level none, every other level is unknown */
        CheckRow(Seqs[s], Endpoints[s], RPC_C_AUTHN_NONE, 0, 1748, 1748, 1748, 1748);
        /* NTLM and the default service */
        CheckRow(Seqs[s], Endpoints[s], RPC_C_AUTHN_WINNT, 0, 0, 0, 1748, 1748);
        CheckRow(Seqs[s], Endpoints[s], RPC_C_AUTHN_DEFAULT, 0, 0, 0, 1748, 1748);
        /* numbers that are no authentication service: refused at every level (also none), unknown level first */
        CheckRow(Seqs[s], Endpoints[s], 0x99, 1747, 1747, 1747, 1748, 1748);
        CheckRow(Seqs[s], Endpoints[s], 0x44, 1747, 1747, 1747, 1748, 1748);
        CheckRow(Seqs[s], Endpoints[s], 0x64, 1747, 1747, 1747, 1748, 1748);
    }

    /* over the network: Negotiate and schannel are accepted, Kerberos needs a principal name or an identity (1749) */
    CheckRow(L"ncacn_np", L"\\pipe\\kbauthep", RPC_C_AUTHN_GSS_NEGOTIATE, 0, 0, 0, 1748, 1748);
    CheckRow(L"ncacn_np", L"\\pipe\\kbauthep", RPC_C_AUTHN_GSS_SCHANNEL, 0, 0, 0, 1748, 1748);
    CheckRow(L"ncacn_np", L"\\pipe\\kbauthep", RPC_C_AUTHN_GSS_KERBEROS, 1749, 1749, 1749, 1748, 1748);
}
