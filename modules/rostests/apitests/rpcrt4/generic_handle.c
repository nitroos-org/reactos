/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The client stub (NdrClientCall2) calls the unbind routine of an explicit generic handle once per call,
 *              with the binding handle the bind routine returned and the same handle object:
 *              - a call that returns,
 *              - a call the server faults (the fault is raised in the client),
 *              - a call that raises in the client before anything is sent (a NULL [ref] pointer),
 *              - a call to a server that is not there,
 *              and a run of calls does not make the heaps or the handles of the process grow (every binding is freed,
 *              the pooled connection is reused).
 *              A bind routine that returns NULL makes the call fail.
 *              The server routine gets the generic handle object the client passed (the string), not the binding of the
 *              call.
 *
 * The server lives in this process (generic_handle_srv.c), over ncalrpc.
 */

#include <apitest.h>
#include <pseh/pseh2.h>

#include <stdio.h>
#include <windows.h>
#include <rpc.h>

#include "generic_handle_c.h"

RPC_STATUS gen_handle_server_start(const char *endpoint);
void gen_handle_server_stop(void);
extern LONG g_srv_calls, g_srv_name_is_binding, g_srv_bad_names;
extern WCHAR g_srv_expected[16];

static char g_endpoint[64];
static LONG g_binds, g_unbinds;
static LONG g_bad_unbinds;          /* unbinds with another handle or object than the bind of the call */
static GEN_HANDLE g_bound_name;     /* the handle object of the last bind */
static handle_t g_bound;            /* what the last bind returned */

handle_t __RPC_USER GEN_HANDLE_bind(GEN_HANDLE name)
{
    char binding_string[128];
    const char *endpoint = g_endpoint;
    handle_t binding = NULL;

    g_binds++;
    g_bound_name = name;
    g_bound = NULL;
    if (!wcscmp(name, L"nullbind"))
        return NULL;
    if (!wcscmp(name, L"down"))
        endpoint = "gen_handle_nobody_listens";
    sprintf(binding_string, "ncalrpc:[%s]", endpoint);
    if (RpcBindingFromStringBindingA((RPC_CSTR)binding_string, &binding) != RPC_S_OK)
        return NULL;
    g_bound = binding;
    return binding;
}

void __RPC_USER GEN_HANDLE_unbind(GEN_HANDLE name, handle_t binding)
{
    g_unbinds++;
    if (binding != g_bound || name != g_bound_name || !binding)
    {
        g_bad_unbinds++;
        return;
    }
    RpcBindingFree(&binding);
}

static void reset_counts(void)
{
    g_binds = g_unbinds = g_bad_unbinds = 0;
}

/* the busy bytes of all heaps of the process */
static SIZE_T heap_busy(void)
{
    HANDLE heaps[64];
    PROCESS_HEAP_ENTRY entry;
    DWORD count, i;
    SIZE_T total = 0;

    count = GetProcessHeaps(ARRAYSIZE(heaps), heaps);
    if (count > ARRAYSIZE(heaps))
        count = ARRAYSIZE(heaps);
    for (i = 0; i < count; i++)
    {
        if (!HeapLock(heaps[i]))
            continue;
        entry.lpData = NULL;
        while (HeapWalk(heaps[i], &entry))
            if (entry.wFlags & PROCESS_HEAP_ENTRY_BUSY)
                total += entry.cbData;
        HeapUnlock(heaps[i]);
    }
    return total;
}

/* a call through GEN_HANDLE name; returns the exception it raised (0 if none) */
static DWORD call(int which, const WCHAR *name, int arg, int *result)
{
    DWORD code = 0;
    int ret = -1;

    RpcTryExcept
    {
        switch (which)
        {
        case 0: ret = gen_add((GEN_HANDLE)name, arg, 1); break;
        case 1: ret = gen_fault((GEN_HANDLE)name, arg); break;
        case 2: ret = gen_ref((GEN_HANDLE)name, NULL); break;
        }
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        code = RpcExceptionCode();
    }
    RpcEndExcept
    if (result)
        *result = ret;
    return code;
}

START_TEST(generic_handle)
{
    RPC_STATUS status;
    SIZE_T before, after;
    DWORD code, handles_before = 0, handles_after = 0;
    int result, i;
    const int calls = 5000;

    sprintf(g_endpoint, "gen_handle_test_%lu", GetCurrentProcessId());
    status = gen_handle_server_start(g_endpoint);
    ok(status == RPC_S_OK, "server start: %ld\n", status);
    if (status != RPC_S_OK)
        return;

    /* a call that returns; the server routine gets the string */
    reset_counts();
    wcscpy(g_srv_expected, L"plain");
    code = call(0, L"plain", 41, &result);
    ok(code == 0, "gen_add raised %lu\n", code);
    ok(result == 42, "gen_add returned %d\n", result);
    ok(g_srv_calls == 1, "server calls %ld\n", g_srv_calls);
    ok(g_srv_name_is_binding == 0, "the server routine got the binding of the call as its generic handle\n");
    ok(g_srv_bad_names == 0, "the server routine got another string than the client passed\n");
    g_srv_expected[0] = 0;
    ok(g_binds == 1, "binds %ld\n", g_binds);
    ok(g_unbinds == 1, "unbinds %ld, expected 1\n", g_unbinds);
    ok(g_bad_unbinds == 0, "unbinds with another handle or object: %ld\n", g_bad_unbinds);

    /* the server faults: the fault is raised in the client, the binding is still unbound */
    reset_counts();
    code = call(1, L"fault", 0x1234, NULL);
    ok(code == 0x1234, "gen_fault raised %lu\n", code);
    ok(g_binds == 1, "binds %ld\n", g_binds);
    ok(g_unbinds == 1, "unbinds %ld, expected 1\n", g_unbinds);
    ok(g_bad_unbinds == 0, "unbinds with another handle or object: %ld\n", g_bad_unbinds);

    /* the client stub raises before sending (NULL [ref] pointer) */
    reset_counts();
    code = call(2, L"nullref", 0, NULL);
    ok(code == RPC_X_NULL_REF_POINTER, "gen_ref raised %lu\n", code);
    ok(g_binds == 1, "binds %ld\n", g_binds);
    ok(g_unbinds == 1, "unbinds %ld, expected 1\n", g_unbinds);
    ok(g_bad_unbinds == 0, "unbinds with another handle or object: %ld\n", g_bad_unbinds);

    /* nobody listens at the endpoint */
    reset_counts();
    code = call(0, L"down", 1, NULL);
    ok(code != 0, "gen_add to an endpoint nobody listens at did not raise\n");
    trace("call to an absent server raised %lu\n", code);
    ok(g_binds == 1, "binds %ld\n", g_binds);
    ok(g_unbinds == 1, "unbinds %ld, expected 1\n", g_unbinds);
    ok(g_bad_unbinds == 0, "unbinds with another handle or object: %ld\n", g_bad_unbinds);

    /* the bind routine returns NULL: the call fails (whether the unbind routine is called with NULL is not
     * checked; the stubs MIDL generates inline skip it) */
    reset_counts();
    code = call(0, L"nullbind", 1, NULL);
    ok(code != 0, "gen_add with a NULL binding did not raise\n");
    trace("call with a NULL binding raised %lu, unbinds %ld\n", code, g_unbinds);
    ok(g_binds == 1, "binds %ld\n", g_binds);

    /* many calls: every binding is freed, the pooled connection is reused, the heaps and handles do not grow */
    for (i = 0; i < 100; i++)
        call(0, L"warm", i, NULL);
    reset_counts();
    wcscpy(g_srv_expected, L"loop");
    g_srv_calls = g_srv_name_is_binding = g_srv_bad_names = 0;
    GetProcessHandleCount(GetCurrentProcess(), &handles_before);
    before = heap_busy();
    code = 0;
    for (i = 0; i < calls; i++)
    {
        code = call(0, L"loop", i, &result);
        if (result != i + 1)
            break;
    }
    after = heap_busy();
    GetProcessHandleCount(GetCurrentProcess(), &handles_after);
    g_srv_expected[0] = 0;
    ok(i == calls, "call %d returned %d (exception %lu)\n", i, result, code);
    ok(g_srv_calls == calls, "server calls %ld\n", g_srv_calls);
    ok(g_srv_name_is_binding == 0, "the server routine got the binding of the call as its generic handle %ld times\n",
       g_srv_name_is_binding);
    ok(g_srv_bad_names == 0, "the server routine got another string than the client passed %ld times\n", g_srv_bad_names);
    ok(g_binds == calls, "binds %ld\n", g_binds);
    ok(g_unbinds == calls, "unbinds %ld, expected %d\n", g_unbinds, calls);
    ok(g_bad_unbinds == 0, "unbinds with another handle or object: %ld\n", g_bad_unbinds);
    trace("heap growth over %d calls: %ld bytes, handles %lu -> %lu\n", calls, (long)(after - before),
          handles_before, handles_after);
    ok((LONG_PTR)(after - before) < calls * 8, "heap grew by %ld bytes over %d calls\n", (long)(after - before), calls);
    /* a few for the thread pool and the connections that come and go */
    ok(handles_after <= handles_before + 8, "handles %lu -> %lu over %d calls\n", handles_before, handles_after, calls);

    gen_handle_server_stop();
}
