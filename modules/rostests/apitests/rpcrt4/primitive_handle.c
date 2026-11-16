/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The server stub (NdrStubCall2) gives a server routine whose interface has an explicit primitive
 *              handle_t the binding of the call:
 *              - a handle_t passed by value is the binding of the call (the thread's call handle),
 *              - a handle_t passed by pointer points to it,
 *              and the binding is usable: the object UUID the client set on its binding is the one the server
 *              side binding reports (RpcBindingInqObject), RpcBindingToStringBinding works on it.
 *              The generic and context handle slots must not get it (see generic_handle).
 *
 * The widl generated server stubs only make the by-value form of the handle, so the server interface of this test is
 * built by hand (the procedure format string of a procedure with an explicit primitive handle_t, flag byte 0 or 1).
 * The server lives in this process, over ncalrpc.
 */

#include <apitest.h>

#include <stdio.h>
#include <windows.h>
#include <rpc.h>
#include <rpcdce.h>
#include <rpcndr.h>

#include "primitive_handle_c.h"

#define PS ((unsigned)sizeof(void *))
#define FCSHORT(s) (unsigned char)(s), (unsigned char)((s) >> 8)

/* the procedure format string of "int proc([in] handle_t h, [in] int a, [in] int b)", the handle taking the
 * binding of the call by value (flag 0) or by pointer (flag 1); the stack is the handle, a, b and the return value,
 * a slot of a pointer each */
#define PROC(num, flag) \
    0x00, 0x48, 0, 0, 0, 0, FCSHORT(num), FCSHORT(4 * PS), \
    0x32 /* FC_BIND_PRIMITIVE */, (flag), FCSHORT(0), \
    FCSHORT(0x10), FCSHORT(0x8), 0x44, 0x03, \
    0x0a, 0x01, FCSHORT(0), FCSHORT(0), FCSHORT(0), FCSHORT(0), \
    FCSHORT(0x48), FCSHORT(PS), 0x08 /* FC_LONG */, 0, \
    FCSHORT(0x48), FCSHORT(2 * PS), 0x08, 0, \
    FCSHORT(0x70), FCSHORT(3 * PS), 0x08, 0

static const unsigned char g_proc_fmt[] =
{
    PROC(0, 0),
    PROC(1, 1),
    0
};
#define PROC_LEN ((sizeof(g_proc_fmt) - 1) / 2)

static const unsigned char g_type_fmt[] = { 0, 0, 0, 0 };

static const unsigned short g_fmt_offsets[] = { 0, (unsigned short)PROC_LEN };

static int __cdecl srv_prim_val(handle_t h, int a, int b);
static int __cdecl srv_prim_ptr(handle_t *ph, int a, int b);

static const SERVER_ROUTINE g_routines[] = { (SERVER_ROUTINE)srv_prim_val, (SERVER_ROUTINE)srv_prim_ptr };

static RPC_DISPATCH_FUNCTION g_dispatch_funcs[] = { NdrServerCall2, NdrServerCall2 };
static RPC_DISPATCH_TABLE g_dispatch_table = { 2, g_dispatch_funcs };

static const MIDL_SERVER_INFO g_server_info;
static const MIDL_STUB_DESC g_stub_desc;

static const RPC_SERVER_INTERFACE g_server_if =
{
    sizeof(RPC_SERVER_INTERFACE),
    {{0x5ec0ac10, 0x4321, 0x1234, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11}}, {1, 0}},
    {{0x8a885d04, 0x1ceb, 0x11c9, {0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60}}, {2, 0}},
    &g_dispatch_table,
    0,
    0,
    0,
    (void *)&g_server_info,
    0
};

static const MIDL_STUB_DESC g_stub_desc =
{
    (void *)&g_server_if,
    MIDL_user_allocate,
    MIDL_user_free,
    { 0 },
    0, 0, 0, 0,
    g_type_fmt + 2,
    1,
    0x50002,
    0,
    0x50200ca,
    0, 0, 0,
    1,
    0, 0, 0
};

static const MIDL_SERVER_INFO g_server_info =
{
    &g_stub_desc,
    g_routines,
    g_proc_fmt,
    g_fmt_offsets,
    0, 0, 0, 0
};

static UUID g_object = {0x5ec0ac10, 0x4321, 0x1234, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x77}};

static LONG g_val_calls, g_ptr_calls;
static LONG g_val_not_call_handle, g_ptr_not_call_handle, g_ptr_null;
static LONG g_val_bad_object, g_ptr_bad_object;
static LONG g_val_no_string, g_ptr_no_string;

/* what the binding the server routine got says: the object UUID of the call and a binding string */
static BOOL binding_ok(handle_t h, BOOL *object_ok)
{
    UUID object;
    RPC_CSTR string = NULL;
    RPC_STATUS status;
    BOOL string_ok;

    *object_ok = FALSE;
    memset(&object, 0, sizeof(object));
    if (RpcBindingInqObject(h, &object) == RPC_S_OK)
        *object_ok = !memcmp(&object, &g_object, sizeof(object));
    status = RpcBindingToStringBindingA(h, &string);
    string_ok = (status == RPC_S_OK);
    if (string)
        RpcStringFreeA(&string);
    return string_ok;
}

static int __cdecl srv_prim_val(handle_t h, int a, int b)
{
    BOOL object_ok;

    InterlockedIncrement(&g_val_calls);
    if (h != I_RpcGetCurrentCallHandle())
        InterlockedIncrement(&g_val_not_call_handle);
    if (!binding_ok(h, &object_ok))
        InterlockedIncrement(&g_val_no_string);
    if (!object_ok)
        InterlockedIncrement(&g_val_bad_object);
    return a + b;
}

static int __cdecl srv_prim_ptr(handle_t *ph, int a, int b)
{
    BOOL object_ok;

    InterlockedIncrement(&g_ptr_calls);
    if (!ph)
    {
        InterlockedIncrement(&g_ptr_null);
        return -1;
    }
    if (*ph != I_RpcGetCurrentCallHandle())
        InterlockedIncrement(&g_ptr_not_call_handle);
    if (!binding_ok(*ph, &object_ok))
        InterlockedIncrement(&g_ptr_no_string);
    if (!object_ok)
        InterlockedIncrement(&g_ptr_bad_object);
    return a + b;
}

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

static DWORD call_ptr(handle_t binding, int a, int b, int *result)
{
    DWORD code = 0;

    *result = -1;
    RpcTryExcept
    {
        *result = prim_ptr(binding, a, b);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        code = RpcExceptionCode();
    }
    RpcEndExcept
    return code;
}

START_TEST(primitive_handle)
{
    char endpoint[64], binding_string[128];
    handle_t binding = NULL;
    RPC_STATUS status;
    DWORD code;
    int result, i;
    const int calls = 200;

    sprintf(endpoint, "prim_handle_test_%lu", GetCurrentProcessId());
    status = RpcServerUseProtseqEpA((RPC_CSTR)"ncalrpc", RPC_C_PROTSEQ_MAX_REQS_DEFAULT, (RPC_CSTR)endpoint, NULL);
    ok(status == RPC_S_OK, "RpcServerUseProtseqEp: %ld\n", status);
    if (status != RPC_S_OK)
        return;
    status = RpcServerRegisterIf((RPC_IF_HANDLE)&g_server_if, NULL, NULL);
    ok(status == RPC_S_OK, "RpcServerRegisterIf: %ld\n", status);
    if (status != RPC_S_OK)
        return;
    status = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, TRUE);
    ok(status == RPC_S_OK || status == RPC_S_ALREADY_LISTENING, "RpcServerListen: %ld\n", status);

    sprintf(binding_string, "ncalrpc:[%s]", endpoint);
    status = RpcBindingFromStringBindingA((RPC_CSTR)binding_string, &binding);
    ok(status == RPC_S_OK, "RpcBindingFromStringBinding: %ld\n", status);
    status = RpcBindingSetObject(binding, &g_object);
    ok(status == RPC_S_OK, "RpcBindingSetObject: %ld\n", status);

    /* the handle by value */
    code = call_val(binding, 40, 2, &result);
    ok(code == 0, "prim_val raised %lu\n", code);
    ok(result == 42, "prim_val returned %d\n", result);
    ok(g_val_calls == 1, "prim_val server calls %ld\n", g_val_calls);
    ok(g_val_not_call_handle == 0, "the handle_t of prim_val is not the binding of the call\n");
    ok(g_val_bad_object == 0, "the binding of prim_val does not report the object UUID of the call\n");
    ok(g_val_no_string == 0, "RpcBindingToStringBinding failed on the binding of prim_val\n");

    /* the handle by pointer */
    code = call_ptr(binding, 40, 2, &result);
    ok(code == 0, "prim_ptr raised %lu\n", code);
    ok(result == 42, "prim_ptr returned %d\n", result);
    ok(g_ptr_calls == 1, "prim_ptr server calls %ld\n", g_ptr_calls);
    ok(g_ptr_null == 0, "the handle_t * of prim_ptr is NULL\n");
    ok(g_ptr_not_call_handle == 0, "the handle_t * of prim_ptr does not point to the binding of the call\n");
    ok(g_ptr_bad_object == 0, "the binding of prim_ptr does not report the object UUID of the call\n");
    ok(g_ptr_no_string == 0, "RpcBindingToStringBinding failed on the binding of prim_ptr\n");

    /* every call gets it */
    for (i = 0; i < calls; i++)
    {
        code = call_val(binding, i, 1, &result);
        if (code || result != i + 1)
            break;
        code = call_ptr(binding, i, 2, &result);
        if (code || result != i + 2)
            break;
    }
    ok(i == calls, "call %d: result %d, exception %lu\n", i, result, code);
    ok(g_val_calls == calls + 1, "prim_val server calls %ld\n", g_val_calls);
    ok(g_ptr_calls == calls + 1, "prim_ptr server calls %ld\n", g_ptr_calls);
    ok(g_val_not_call_handle == 0 && g_val_bad_object == 0 && g_val_no_string == 0,
       "prim_val: %ld / %ld / %ld calls without the binding of the call\n",
       g_val_not_call_handle, g_val_bad_object, g_val_no_string);
    ok(g_ptr_null == 0 && g_ptr_not_call_handle == 0 && g_ptr_bad_object == 0 && g_ptr_no_string == 0,
       "prim_ptr: %ld / %ld / %ld / %ld calls without the binding of the call\n",
       g_ptr_null, g_ptr_not_call_handle, g_ptr_bad_object, g_ptr_no_string);

    RpcBindingFree(&binding);
    RpcServerUnregisterIf((RPC_IF_HANDLE)&g_server_if, NULL, FALSE);
}
