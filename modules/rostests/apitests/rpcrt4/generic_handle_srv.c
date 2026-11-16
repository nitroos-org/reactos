/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The server side of the generic_handle test (in a file of its own: the server and client headers of one
 *              interface cannot be included together)
 */

#include <string.h>
#include <windows.h>
#include <rpc.h>

#include "generic_handle_s.h"

/* what the server routine got as its generic handle object: the string the client passed, never the binding of
 * the call (the stub once put the binding into that argument and unmarshalled the string into the binding) */
LONG g_srv_calls, g_srv_name_is_binding, g_srv_bad_names;
WCHAR g_srv_expected[16];

int __cdecl s_gen_add(GEN_HANDLE name, int a, int b)
{
    InterlockedIncrement(&g_srv_calls);
    if ((handle_t)name == I_RpcGetCurrentCallHandle())
        InterlockedIncrement(&g_srv_name_is_binding);
    if (g_srv_expected[0] && (!name || wcscmp(name, g_srv_expected)))
        InterlockedIncrement(&g_srv_bad_names);
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
