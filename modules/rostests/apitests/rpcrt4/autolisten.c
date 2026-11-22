/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     RPC_IF_AUTOLISTEN interfaces, as the services that share a host process use them:
 *              - an auto-listen interface alone is served (no RpcServerListen), and again after it was unregistered and
 *                registered once more (a service that stops and starts); a change of RpcServerUnregisterIf that stops
 *                the listening of the process with the last auto-listen interface must keep this working: the server
 *                thread of a stopped listening is only taken away by RpcMgmtWaitServerListen, a listening that is
 *                started again before that gets no thread and the calls hang,
 *              - the listener count of the registration of an auto-listen interface is taken back when the
 *                interface is unregistered, so with a manual listener in the same process RpcMgmtStopServerListening
 *                ends the listening (Windows Server 2022: RpcMgmtIsServerListening is RPC_S_NOT_LISTENING then).
 *
 * The interface is the one of primitive_handle.c, the server lives in this process, over ncalrpc.
 */

#include <apitest.h>

#include <stdio.h>
#include <windows.h>
#include <rpc.h>

#include "primitive_handle_c.h"

RPC_IF_HANDLE prim_handle_server_ifspec(void);

static DWORD call_val(handle_t binding, int a, int b, int *result)
{
    DWORD code = 0;

    *result = -1;
    RpcTryExcept
    {
        *result = prim_val(binding, a, b);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        code = RpcExceptionCode();
    }
    RpcEndExcept
    return code;
}

START_TEST(autolisten)
{
    char endpoint[64], binding_string[128];
    RPC_IF_HANDLE ifspec = prim_handle_server_ifspec();
    handle_t binding = NULL;
    RPC_STATUS status;
    DWORD code;
    int result, i;

    sprintf(endpoint, "autolisten_test_%lu", GetCurrentProcessId());
    status = RpcServerUseProtseqEpA((RPC_CSTR)"ncalrpc", RPC_C_PROTSEQ_MAX_REQS_DEFAULT, (RPC_CSTR)endpoint, NULL);
    ok(status == RPC_S_OK, "RpcServerUseProtseqEp: %ld\n", status);
    if (status != RPC_S_OK)
        return;

    sprintf(binding_string, "ncalrpc:[%s]", endpoint);

    /* an auto-listen interface alone is served */
    status = RpcServerRegisterIf2(ifspec, NULL, NULL, RPC_IF_AUTOLISTEN, RPC_C_LISTEN_MAX_CALLS_DEFAULT, (UINT)-1, NULL);
    ok(status == RPC_S_OK, "RpcServerRegisterIf2: %ld\n", status);
    if (status != RPC_S_OK)
        return;
    status = RpcBindingFromStringBindingA((RPC_CSTR)binding_string, &binding);
    ok(status == RPC_S_OK, "RpcBindingFromStringBinding: %ld\n", status);
    code = call_val(binding, 1, 2, &result);
    ok(code == 0 && result == 3, "call of the auto-listen interface: exception %lu, result %d\n", code, result);
    RpcBindingFree(&binding);

    /* it stops and starts again, a few times */
    for (i = 0; i < 3; i++)
    {
        status = RpcServerUnregisterIf(ifspec, NULL, TRUE);
        ok(status == RPC_S_OK, "round %d: RpcServerUnregisterIf: %ld\n", i, status);
        status = RpcServerRegisterIf2(ifspec, NULL, NULL, RPC_IF_AUTOLISTEN, RPC_C_LISTEN_MAX_CALLS_DEFAULT, (UINT)-1, NULL);
        ok(status == RPC_S_OK, "round %d: RpcServerRegisterIf2: %ld\n", i, status);
        status = RpcBindingFromStringBindingA((RPC_CSTR)binding_string, &binding);
        ok(status == RPC_S_OK, "round %d: RpcBindingFromStringBinding: %ld\n", i, status);
        code = call_val(binding, 10 + i, 2, &result);
        ok(code == 0 && result == 12 + i, "round %d: exception %lu, result %d\n", i, code, result);
        RpcBindingFree(&binding);
    }

    /* a manual listener beside it: the auto-listen interface goes, the manual listener stays, its stop should end listening */
    status = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, TRUE);
    ok(status == RPC_S_OK, "RpcServerListen: %ld\n", status);
    ok(RpcMgmtIsServerListening(NULL) == RPC_S_OK, "not listening after RpcServerListen\n");
    status = RpcServerUnregisterIf(ifspec, NULL, TRUE);
    ok(status == RPC_S_OK, "RpcServerUnregisterIf: %ld\n", status);
    status = RpcMgmtIsServerListening(NULL);
    ok(status == RPC_S_OK, "not listening after the auto-listen interface went: %ld\n", status);
    status = RpcMgmtStopServerListening(NULL);
    ok(status == RPC_S_OK, "RpcMgmtStopServerListening: %ld\n", status);
    status = RpcMgmtIsServerListening(NULL);
    ok(status == RPC_S_NOT_LISTENING, "still listening after the manual stop (a count of the unregistered interface is left): %ld\n", status);
    status = RpcMgmtWaitServerListen();
    ok(status == RPC_S_OK, "RpcMgmtWaitServerListen: %ld\n", status);
}
