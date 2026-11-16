/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The server side of the generic_handle test (in a file of its own: the server and client headers of one
 *              interface cannot be included together)
 */

#include <windows.h>
#include <rpc.h>

#include "generic_handle_s.h"

int __cdecl s_gen_add(GEN_HANDLE name, int a, int b)
{
    return a + b;
}

int __cdecl s_gen_fault(GEN_HANDLE name, int code)
{
    RpcRaiseException(code);
    return 0;
}

int __cdecl s_gen_ref(GEN_HANDLE name, int *value)
{
    return *value;
}

RPC_STATUS gen_handle_server_start(const char *endpoint)
{
    RPC_STATUS status;

    status = RpcServerUseProtseqEpA((RPC_CSTR)"ncalrpc", RPC_C_PROTSEQ_MAX_REQS_DEFAULT, (RPC_CSTR)endpoint, NULL);
    if (status != RPC_S_OK)
        return status;
    status = RpcServerRegisterIf(s_gen_handle_v1_0_s_ifspec, NULL, NULL);
    if (status != RPC_S_OK)
        return status;
    status = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, TRUE);
    if (status == RPC_S_ALREADY_LISTENING)
        status = RPC_S_OK;
    return status;
}

void gen_handle_server_stop(void)
{
    RpcServerUnregisterIf(s_gen_handle_v1_0_s_ifspec, NULL, FALSE);
}
