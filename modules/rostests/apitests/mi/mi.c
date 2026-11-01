/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for the MI client API (mi.dll)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Every expectation here was checked against Windows 10 22H2 (19045).
 */

#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#define COBJMACROS
#include <objbase.h>
#include <initguid.h>
#include <wbemcli.h>

#define mi_clientFT_V1 mi_clientFT_V1_import
#include <mi.h>
#undef mi_clientFT_V1

#ifndef MI_DLL_NAME
#define MI_DLL_NAME L"mi.dll"
#endif

typedef MI_Result (MI_MAIN_CALL *PFN_INIT)(MI_Uint32, const MI_Char *, MI_Instance **, MI_Application *);

static HMODULE hmi;
static PFN_INIT pMI_Application_InitializeV1;
static const MI_ClientFT_V1 **pmi_clientFT_V1;

/* pull every instance of an operation; returns the final result, the count and a clone of the first instance */
static MI_Result pull_all(MI_Operation *op, UINT *count, MI_Instance **first, const MI_Char **message_out)
{
    const MI_Instance *inst;
    MI_Boolean more = MI_TRUE;
    MI_Result result = MI_RESULT_FAILED, res;
    const MI_Char *message;
    const MI_Instance *details;
    UINT guard = 0;

    *count = 0;
    if (first) *first = NULL;
    while (more && guard++ < 100000)
    {
        inst = NULL;
        message = NULL;
        details = NULL;
        res = op->ft->GetInstance(op, &inst, &more, &result, &message, &details);
        ok(res == MI_RESULT_OK, "GetInstance returned %d\n", res);
        if (res != MI_RESULT_OK) break;
        if (inst)
        {
            if (!*count && first) inst->ft->Clone(inst, first);
            (*count)++;
        }
        if (!more && message_out) *message_out = message;
        if (!more && result != MI_RESULT_OK)
            ok(details != NULL, "no error details for result %d\n", result);
    }
    return result;
}

static void test_exports(void)
{
    ok(pMI_Application_InitializeV1 != NULL, "MI_Application_InitializeV1 not exported\n");
    ok(pmi_clientFT_V1 != NULL, "mi_clientFT_V1 not exported\n");
    if (pmi_clientFT_V1)
    {
        const MI_ClientFT_V1 *ft = *pmi_clientFT_V1;
        ok(ft != NULL, "mi_clientFT_V1 is NULL\n");
        if (ft)
        {
            ok(ft->applicationFT != NULL, "no applicationFT\n");
            ok(ft->sessionFT != NULL, "no sessionFT\n");
            ok(ft->operationFT != NULL, "no operationFT\n");
            ok(ft->destinationOptionsFT != NULL, "no destinationOptionsFT\n");
            ok(ft->operationOptionsFT != NULL, "no operationOptionsFT\n");
            ok(ft->utilitiesFT != NULL, "no utilitiesFT\n");
            ok(ft->serializerFT != NULL, "no serializerFT\n");
            ok(ft->deserializerFT != NULL, "no deserializerFT\n");
        }
    }
}

static void test_utilities(void)
{
    const MI_ClientFT_V1 *ft = *pmi_clientFT_V1;
    MI_Instance *err = NULL;
    MI_Value v;
    MI_Type type;
    MI_Result res;

    res = ft->utilitiesFT->CimErrorFromErrorCode(ERROR_FILE_NOT_FOUND, L"Win32", L"file is missing", &err);
    ok(res == MI_RESULT_OK, "CimErrorFromErrorCode returned %d\n", res);
    ok(err != NULL, "no error instance\n");
    if (!err) return;
    res = err->ft->GetElement(err, L"Message", &v, &type, NULL, NULL);
    ok(res == MI_RESULT_OK, "GetElement(Message) returned %d\n", res);
    ok(res || type == MI_STRING, "Message type %d\n", type);
    if (!res && type == MI_STRING) ok(v.string && wcsstr(v.string, L"file is missing"), "Message %ls\n", v.string);
    res = err->ft->GetElement(err, L"error_Code", &v, &type, NULL, NULL);
    ok(res == MI_RESULT_OK, "GetElement(error_Code) returned %d\n", res);
    ok(res || (type == MI_UINT32 && v.uint32 == ERROR_FILE_NOT_FOUND), "error_Code type %d value %u\n", type, v.uint32);
    err->ft->Delete(err);
}

static void test_instance(MI_Application *app)
{
    MI_Instance *inst = NULL, *copy = NULL;
    const MI_Char *name;
    MI_Value v;
    MI_Type type;
    MI_Uint32 count, flags, index;
    MI_Result res;

    res = app->ft->NewInstance(app, L"MI_Test", NULL, &inst);
    ok(res == MI_RESULT_OK, "NewInstance returned %d\n", res);
    if (!inst) return;
    res = inst->ft->GetClassName(inst, &name);
    ok(res == MI_RESULT_OK && name && !wcscmp(name, L"MI_Test"), "GetClassName %d %ls\n", res, name);
    v.uint32 = 42;
    res = inst->ft->AddElement(inst, L"Answer", &v, MI_UINT32, 0);
    ok(res == MI_RESULT_OK, "AddElement returned %d\n", res);
    res = inst->ft->AddElement(inst, L"Answer", &v, MI_UINT32, 0);
    ok(res == MI_RESULT_ALREADY_EXISTS, "AddElement duplicate returned %d\n", res);
    v.string = L"hello";
    res = inst->ft->AddElement(inst, L"Text", &v, MI_STRING, 0);
    ok(res == MI_RESULT_OK, "AddElement string returned %d\n", res);
    res = inst->ft->AddElement(inst, L"Nothing", NULL, MI_STRING, 0);
    ok(res == MI_RESULT_OK, "AddElement NULL returned %d\n", res);
    res = inst->ft->GetElementCount(inst, &count);
    ok(res == MI_RESULT_OK && count == 3, "GetElementCount %d %u\n", res, count);

    memset(&v, 0, sizeof(v));
    res = inst->ft->GetElement(inst, L"answer", &v, &type, &flags, &index);
    ok(res == MI_RESULT_OK, "GetElement (case-insensitive) returned %d\n", res);
    ok(type == MI_UINT32 && v.uint32 == 42 && index == 0, "got type %d value %u index %u\n", type, v.uint32, index);
    res = inst->ft->GetElement(inst, L"Nothing", &v, &type, &flags, NULL);
    ok(res == MI_RESULT_OK && (flags & MI_FLAG_NULL), "NULL element: %d flags %#x\n", res, flags);
    res = inst->ft->GetElement(inst, L"Missing", &v, &type, &flags, NULL);
    ok(res == MI_RESULT_NO_SUCH_PROPERTY, "GetElement missing returned %d\n", res);
    res = inst->ft->GetElementAt(inst, 7, &name, &v, &type, &flags);
    ok(res == MI_RESULT_INVALID_PARAMETER, "GetElementAt out of range returned %d\n", res);

    v.uint32 = 7;
    res = inst->ft->SetElement(inst, L"Answer", &v, MI_UINT32, 0);
    ok(res == MI_RESULT_OK, "SetElement returned %d\n", res);
    res = inst->ft->SetElement(inst, L"Missing", &v, MI_UINT32, 0);
    ok(res == MI_RESULT_NO_SUCH_PROPERTY, "SetElement missing returned %d\n", res);

    res = inst->ft->Clone(inst, &copy);
    ok(res == MI_RESULT_OK && copy, "Clone returned %d\n", res);
    if (copy)
    {
        res = copy->ft->GetElement(copy, L"Text", &v, &type, &flags, NULL);
        ok(res == MI_RESULT_OK && type == MI_STRING && v.string && !wcscmp(v.string, L"hello"), "clone Text %d\n", res);
        res = copy->ft->GetElement(copy, L"Answer", &v, &type, &flags, NULL);
        ok(res == MI_RESULT_OK && v.uint32 == 7, "clone Answer %d %u\n", res, v.uint32);
        copy->ft->Delete(copy);
    }
    res = inst->ft->ClearElement(inst, L"Text");
    ok(res == MI_RESULT_OK, "ClearElement returned %d\n", res);
    res = inst->ft->GetElement(inst, L"Text", &v, &type, &flags, NULL);
    ok(res == MI_RESULT_OK && (flags & MI_FLAG_NULL), "cleared element flags %#x\n", flags);
    inst->ft->Delete(inst);
}

static void test_options(MI_Application *app)
{
    MI_OperationOptions oo = MI_OPERATIONOPTIONS_NULL;
    MI_DestinationOptions dopt = MI_DESTINATIONOPTIONS_NULL;
    MI_Interval in, out;
    MI_Result res;

    res = app->ft->NewOperationOptions(app, MI_FALSE, &oo);
    ok(res == MI_RESULT_OK && oo.ft, "NewOperationOptions returned %d\n", res);
    if (oo.ft)
    {
        memset(&in, 0, sizeof(in));
        in.seconds = 30;
        res = oo.ft->SetInterval(&oo, L"__MI_OPERATIONOPTIONS_TIMEOUT", &in, 0);
        ok(res == MI_RESULT_OK, "SetInterval returned %d\n", res);
        memset(&out, 0xcc, sizeof(out));
        res = oo.ft->GetInterval(&oo, L"__MI_OPERATIONOPTIONS_TIMEOUT", &out, NULL, NULL);
        ok(res == MI_RESULT_OK && out.seconds == 30 && out.minutes == 0, "GetInterval %d %u\n", res, out.seconds);
        oo.ft->Delete(&oo);
    }
    res = app->ft->NewDestinationOptions(app, &dopt);
    ok(res == MI_RESULT_OK && dopt.ft, "NewDestinationOptions returned %d\n", res);
    if (dopt.ft)
    {
        const MI_Char *s = NULL;
        res = dopt.ft->SetString(&dopt, L"__MI_DESTINATIONOPTIONS_DATA_LOCALE", L"en-US", 0);
        ok(res == MI_RESULT_OK, "SetString returned %d\n", res);
        res = dopt.ft->GetString(&dopt, L"__MI_DESTINATIONOPTIONS_DATA_LOCALE", &s, NULL, NULL);
        ok(res == MI_RESULT_OK && s && !wcscmp(s, L"en-US"), "GetString %d %ls\n", res, s);
        dopt.ft->Delete(&dopt);
    }
}

static void check_os_instance(const MI_Instance *inst)
{
    const MI_Char *name = NULL, *ns = NULL;
    MI_Value v;
    MI_Type type;
    MI_Uint32 flags, count;
    MI_Result res;
    MI_Class *cls = NULL;

    res = inst->ft->GetClassName(inst, &name);
    ok(res == MI_RESULT_OK && name && !_wcsicmp(name, L"Win32_OperatingSystem"), "class name %ls\n", name);
    res = inst->ft->GetNameSpace(inst, &ns);
    ok(res == MI_RESULT_OK && ns && !_wcsicmp(ns, L"root/cimv2"), "namespace %ls\n", ns);
    res = inst->ft->GetElementCount(inst, &count);
    ok(res == MI_RESULT_OK && count >= 25, "element count %u\n", count);

    res = inst->ft->GetElement(inst, L"Caption", &v, &type, &flags, NULL);
    ok(res == MI_RESULT_OK && type == MI_STRING && !(flags & MI_FLAG_NULL) && v.string && v.string[0],
       "Caption: res %d type %d flags %#x\n", res, type, flags);
    if (!res && type == MI_STRING && v.string) trace("Caption: %ls\n", v.string);

    res = inst->ft->GetElement(inst, L"BuildNumber", &v, &type, &flags, NULL);
    ok(res == MI_RESULT_OK && type == MI_STRING && v.string && v.string[0] >= '0' && v.string[0] <= '9',
       "BuildNumber: res %d type %d\n", res, type);

    res = inst->ft->GetElement(inst, L"TotalVisibleMemorySize", &v, &type, &flags, NULL);
    ok(res == MI_RESULT_OK && type == MI_UINT64 && v.uint64 > 65536, "TotalVisibleMemorySize: res %d type %d value %I64u\n",
       res, type, (res || type != MI_UINT64) ? 0 : v.uint64);

    res = inst->ft->GetElement(inst, L"NumberOfProcesses", &v, &type, &flags, NULL);
    ok(res == MI_RESULT_OK && type == MI_UINT32 && v.uint32 > 3, "NumberOfProcesses: res %d type %d value %u\n",
       res, type, v.uint32);

    res = inst->ft->GetElement(inst, L"OSType", &v, &type, &flags, NULL);
    ok(res == MI_RESULT_OK && type == MI_UINT16 && v.uint16 == 18, "OSType: res %d type %d value %u\n", res, type, v.uint16);

    res = inst->ft->GetElement(inst, L"Primary", &v, &type, &flags, NULL);
    ok(res == MI_RESULT_OK && type == MI_BOOLEAN && v.boolean == MI_TRUE, "Primary: res %d type %d value %u\n",
       res, type, v.boolean);

    res = inst->ft->GetElement(inst, L"LastBootUpTime", &v, &type, &flags, NULL);
    ok(res == MI_RESULT_OK && type == MI_DATETIME, "LastBootUpTime: res %d type %d\n", res, type);
    if (!res && type == MI_DATETIME)
        ok(v.datetime.isTimestamp && v.datetime.u.timestamp.year >= 2000 && v.datetime.u.timestamp.month >= 1 &&
           v.datetime.u.timestamp.month <= 12, "LastBootUpTime %u-%u\n",
           v.datetime.u.timestamp.year, v.datetime.u.timestamp.month);

    res = inst->ft->GetElement(inst, L"Name", &v, &type, &flags, NULL);
    ok(res == MI_RESULT_OK && type == MI_STRING && (flags & MI_FLAG_PROPERTY), "Name: res %d type %d flags %#x\n",
       res, type, flags);

    res = inst->ft->GetClass(inst, &cls);
    ok(res == MI_RESULT_OK && cls, "GetClass returned %d\n", res);
    if (cls)
    {
        const MI_Char *cname = NULL;
        res = cls->ft->GetClassName(cls, &cname);
        ok(res == MI_RESULT_OK && cname && !_wcsicmp(cname, L"Win32_OperatingSystem"), "class %ls\n", cname);
        cls->ft->Delete(cls);
    }
}

struct push_ctx
{
    HANDLE done;
    LONG instances;
    LONG finals;
    MI_Result result;
    BOOL bad_order;
};

static void MI_CALL push_instance(MI_Operation *op, void *context, const MI_Instance *inst, MI_Boolean more,
                                  MI_Result result, const MI_Char *message, const MI_Instance *details,
                                  MI_Result (MI_CALL *ack)(MI_Operation *))
{
    struct push_ctx *ctx = context;
    if (ctx->finals) ctx->bad_order = TRUE;
    if (inst) InterlockedIncrement(&ctx->instances);
    if (!more)
    {
        ctx->finals++;
        ctx->result = result;
    }
    if (ack) ack(op);
    if (!more) SetEvent(ctx->done);
}

static void test_session(MI_Application *app, const MI_Char *protocol)
{
    MI_Session session = MI_SESSION_NULL;
    MI_Operation op = MI_OPERATION_NULL;
    MI_Instance *ext = NULL, *first = NULL;
    MI_OperationCallbacks cb = MI_OPERATIONCALLBACKS_NULL;
    struct push_ctx ctx;
    const MI_Char *message;
    WCHAR query[128];
    UINT count, pull_count;
    MI_Result res;

    res = app->ft->NewSession(app, protocol, NULL, NULL, NULL, &ext, &session);
    ok(res == MI_RESULT_OK, "NewSession(%ls) returned %d\n", protocol ? protocol : L"NULL", res);
    if (res) return;
    ok(session.ft != NULL, "no session ft\n");

    /* pull: enumerate Win32_OperatingSystem */
    session.ft->EnumerateInstances(&session, 0, NULL, L"root\\cimv2", L"Win32_OperatingSystem", MI_FALSE, NULL, &op);
    ok(op.ft != NULL, "no operation ft\n");
    res = pull_all(&op, &count, &first, NULL);
    ok(res == MI_RESULT_OK, "enumerate result %d\n", res);
    ok(count == 1, "got %u Win32_OperatingSystem instances\n", count);
    op.ft->Close(&op);
    if (first)
    {
        check_os_instance(first);
        first->ft->Delete(first);
    }

    /* pull: WQL query for our own process */
    _snwprintf(query, ARRAYSIZE(query) - 1, L"SELECT * FROM Win32_Process WHERE ProcessId = %lu", GetCurrentProcessId());
    query[ARRAYSIZE(query) - 1] = 0;
    memset(&op, 0, sizeof(op));
    session.ft->QueryInstances(&session, 0, NULL, L"root/cimv2", L"WQL", query, NULL, &op);
    res = pull_all(&op, &count, &first, NULL);
    ok(res == MI_RESULT_OK, "query result %d\n", res);
    ok(count == 1, "got %u processes\n", count);
    op.ft->Close(&op);
    if (first)
    {
        MI_Value v;
        MI_Type type;
        res = first->ft->GetElement(first, L"ProcessId", &v, &type, NULL, NULL);
        ok(res == MI_RESULT_OK && type == MI_UINT32 && v.uint32 == GetCurrentProcessId(), "ProcessId %d %d %u\n",
           res, type, v.uint32);
        res = first->ft->GetElement(first, L"Name", &v, &type, NULL, NULL);
        ok(res == MI_RESULT_OK && type == MI_STRING && v.string && wcsstr(v.string, L".exe"), "Name %d\n", res);
        first->ft->Delete(first);
    }

    /* push: the same enumeration through callbacks */
    memset(&ctx, 0, sizeof(ctx));
    ctx.done = CreateEventW(NULL, TRUE, FALSE, NULL);
    ctx.result = MI_RESULT_FAILED;
    cb.callbackContext = &ctx;
    cb.instanceResult = push_instance;
    memset(&op, 0, sizeof(op));
    session.ft->EnumerateInstances(&session, 0, NULL, L"root/cimv2", L"Win32_Process", MI_FALSE, &cb, &op);
    ok(WaitForSingleObject(ctx.done, 60000) == WAIT_OBJECT_0, "push enumeration timed out\n");
    ok(ctx.result == MI_RESULT_OK, "push result %d\n", ctx.result);
    ok(ctx.finals == 1 && !ctx.bad_order, "finals %ld bad order %d\n", ctx.finals, ctx.bad_order);
    ok(ctx.instances > 3, "push got %ld processes\n", ctx.instances);
    op.ft->Close(&op);
    CloseHandle(ctx.done);

    /* pull: GetClass Win32_BIOS */
    memset(&op, 0, sizeof(op));
    session.ft->GetClass(&session, 0, NULL, L"root\\cimv2", L"Win32_BIOS", NULL, &op);
    {
        const MI_Class *cls = NULL;
        MI_Boolean more = MI_TRUE;
        MI_Result result = MI_RESULT_FAILED;
        const MI_Instance *details;
        MI_Uint32 n = 0;
        BOOL got = FALSE;

        while (more)
        {
            res = op.ft->GetClass(&op, &cls, &more, &result, &message, &details);
            ok(res == MI_RESULT_OK, "Operation GetClass returned %d\n", res);
            if (res) break;
            if (cls && !got)
            {
                const MI_Char *cname = NULL;
                MI_Type type;
                MI_Uint32 flags;
                MI_Value v;
                MI_Boolean exists;
                got = TRUE;
                ok(cls->ft->GetClassName(cls, &cname) == MI_RESULT_OK && cname && !_wcsicmp(cname, L"Win32_BIOS"),
                   "class %ls\n", cname);
                ok(cls->ft->GetElementCount(cls, &n) == MI_RESULT_OK && n >= 8, "Win32_BIOS has %u properties\n", n);
                res = cls->ft->GetElement(cls, L"Manufacturer", &v, &exists, &type, NULL, NULL, &flags, NULL);
                ok(res == MI_RESULT_OK && type == MI_STRING, "Manufacturer: %d type %d\n", res, type);
                res = cls->ft->GetElement(cls, L"NoSuchProperty", &v, &exists, &type, NULL, NULL, &flags, NULL);
                ok(res == MI_RESULT_NO_SUCH_PROPERTY, "missing class property returned %d\n", res);
            }
        }
        ok(got, "no class returned\n");
        ok(result == MI_RESULT_OK, "GetClass result %d\n", result);
    }
    op.ft->Close(&op);

    /* errors */
    memset(&op, 0, sizeof(op));
    session.ft->EnumerateInstances(&session, 0, NULL, L"root\\cimv2", L"Win32_NoSuchClassAtAll", MI_FALSE, NULL, &op);
    res = pull_all(&op, &count, NULL, NULL);
    ok(res == MI_RESULT_INVALID_CLASS, "unknown class result %d\n", res);
    ok(count == 0, "unknown class returned %u instances\n", count);
    op.ft->Close(&op);

    memset(&op, 0, sizeof(op));
    session.ft->EnumerateInstances(&session, 0, NULL, L"root\\nosuchnamespace", L"Win32_OperatingSystem", MI_FALSE, NULL, &op);
    res = pull_all(&op, &count, NULL, NULL);
    ok(res == MI_RESULT_INVALID_NAMESPACE, "unknown namespace result %d\n", res);
    op.ft->Close(&op);

    memset(&op, 0, sizeof(op));
    session.ft->QueryInstances(&session, 0, NULL, L"root\\cimv2", L"WQL", L"SELEC * FRO Win32_Process", NULL, &op);
    res = pull_all(&op, &count, NULL, NULL);
    ok(res == MI_RESULT_INVALID_QUERY, "bad query result %d\n", res);
    op.ft->Close(&op);

    memset(&op, 0, sizeof(op));
    session.ft->GetClass(&session, 0, NULL, L"root\\cimv2", L"Win32_NoSuchClassAtAll", NULL, &op);
    {
        const MI_Class *cls = NULL;
        MI_Boolean more = MI_TRUE;
        MI_Result result = MI_RESULT_OK;
        const MI_Instance *details;
        while (more && op.ft->GetClass(&op, &cls, &more, &result, &message, &details) == MI_RESULT_OK) ;
        ok(result == MI_RESULT_NOT_FOUND || result == MI_RESULT_INVALID_CLASS, "unknown GetClass result %d\n", result);
    }
    op.ft->Close(&op);

    pull_count = 0;
    (void)pull_count;
    res = session.ft->Close(&session, NULL, NULL);
    ok(res == MI_RESULT_OK, "Session Close returned %d\n", res);
}

/* ---- filtered enumeration, concurrency and callback lifetime (review fixes) ---- */

/* pull a WQL query on a session and check that every instance has property `prop` equal to `expect`.
 * Returns the final result; *bad counts instances that do not match (wrong rows). */
static MI_Result query_checked(MI_Session *session, const WCHAR *query, const WCHAR *prop, const WCHAR *expect,
                               UINT *count, UINT *bad)
{
    MI_Operation op = MI_OPERATION_NULL;
    MI_Boolean more = MI_TRUE;
    MI_Result result = MI_RESULT_FAILED, res;
    UINT guard = 0;

    *count = *bad = 0;
    session->ft->QueryInstances(session, 0, NULL, L"root/cimv2", L"WQL", query, NULL, &op);
    if (!op.ft) return MI_RESULT_FAILED;
    while (more && guard++ < 100000)
    {
        const MI_Instance *inst = NULL, *details = NULL;
        const MI_Char *message = NULL;

        res = op.ft->GetInstance(&op, &inst, &more, &result, &message, &details);
        if (res != MI_RESULT_OK) { result = res; break; }
        if (!inst) continue;
        (*count)++;
        {
            MI_Value v;
            MI_Type type;
            MI_Uint32 flags;
            if (inst->ft->GetElement(inst, prop, &v, &type, &flags, NULL) != MI_RESULT_OK || type != MI_STRING ||
                (flags & MI_FLAG_NULL) || !v.string || _wcsicmp(v.string, expect))
                (*bad)++;
        }
    }
    op.ft->Close(&op);
    return result;
}

/* pull every class of an operation; returns the final result, the count and whether `want` was seen */
static MI_Result pull_classes(MI_Operation *op, UINT *count, const MI_Char *want, BOOL *seen,
                              const MI_Instance **details_out, MI_Class **want_copy)
{
    const MI_Class *cls;
    MI_Boolean more = MI_TRUE;
    MI_Result result = MI_RESULT_FAILED, res;
    const MI_Char *message, *name;
    const MI_Instance *details;
    UINT guard = 0;

    *count = 0;
    if (seen) *seen = FALSE;
    if (want_copy) *want_copy = NULL;
    while (more && guard++ < 100000)
    {
        cls = NULL;
        details = NULL;
        res = op->ft->GetClass(op, &cls, &more, &result, &message, &details);
        ok(res == MI_RESULT_OK, "GetClass returned %d\n", res);
        if (res != MI_RESULT_OK) break;
        if (cls)
        {
            (*count)++;
            name = NULL;
            if (want && cls->ft->GetClassName(cls, &name) == MI_RESULT_OK && name && !_wcsicmp(name, want))
            {
                if (seen) *seen = TRUE;
                if (want_copy && !*want_copy) cls->ft->Clone(cls, want_copy);
            }
        }
        if (!more && details_out) *details_out = details;
    }
    return result;
}

static BOOL has_qualifier(const MI_QualifierSet *qs, const MI_Char *name)
{
    MI_Type type = 0;
    MI_Uint32 flags = 0, index = 0;
    MI_Value value;
    /* Windows insists on the index output */
    return qs->ft && qs->ft->GetQualifier(qs, name, &type, &flags, &value, &index) == MI_RESULT_OK &&
           type == MI_BOOLEAN && value.boolean;
}

/* class hierarchy, class enumeration, namespaces, method and parameter qualifiers, error ids */
static void test_schema(MI_Application *app)
{
    MI_Session session = MI_SESSION_NULL;
    MI_Operation op = MI_OPERATION_NULL;
    MI_Instance *ext = NULL, *first = NULL;
    MI_Class *cls = NULL, *parent = NULL, *grand = NULL;
    const MI_Instance *details = NULL;
    const MI_Char *name;
    MI_QualifierSet qs;
    MI_ParameterSet ps;
    MI_Value v;
    MI_Type type;
    MI_Boolean more;
    MI_Result res, result;
    const MI_Char *message;
    const MI_Class *c;
    UINT count, i;
    BOOL seen;

    res = app->ft->NewSession(app, NULL, NULL, NULL, NULL, &ext, &session);
    ok(res == MI_RESULT_OK, "NewSession returned %d\n", res);
    if (res) return;

    /* every class of root/cimv2, names only. On Windows a session keeps these name-only classes and
     * serves them to later operations, so this runs in a session of its own. */
    {
        MI_Session names_session = MI_SESSION_NULL;
        res = app->ft->NewSession(app, NULL, NULL, NULL, NULL, &ext, &names_session);
        ok(res == MI_RESULT_OK, "NewSession returned %d\n", res);
        if (!res)
        {
            names_session.ft->EnumerateClasses(&names_session, 0, NULL, L"root/cimv2", NULL, MI_TRUE, NULL, &op);
            res = pull_classes(&op, &count, L"Win32_Process", &seen, NULL, NULL);
            ok(res == MI_RESULT_OK, "EnumerateClasses result %d\n", res);
            ok(count > 20, "got %u classes\n", count);
            ok(seen, "no Win32_Process\n");
            op.ft->Close(&op);
            names_session.ft->Close(&names_session, NULL, NULL);
        }
    }

    /* the subclasses of CIM_Process, full classes */
    memset(&op, 0, sizeof(op));
    session.ft->EnumerateClasses(&session, 0, NULL, L"root/cimv2", L"CIM_Process", MI_FALSE, NULL, &op);
    res = pull_classes(&op, &count, L"Win32_Process", &seen, NULL, NULL);
    ok(res == MI_RESULT_OK, "EnumerateClasses(CIM_Process) result %d\n", res);
    ok(count >= 1 && seen, "got %u subclasses of CIM_Process, Win32_Process %d\n", count, seen);
    op.ft->Close(&op);

    /* the superclass chain Win32_Process > CIM_Process > CIM_LogicalElement */
    memset(&op, 0, sizeof(op));
    session.ft->GetClass(&session, 0, NULL, L"root/cimv2", L"Win32_Process", NULL, &op);
    res = pull_classes(&op, &count, L"Win32_Process", &seen, NULL, &cls);
    ok(res == MI_RESULT_OK && cls, "GetClass(Win32_Process) result %d\n", res);
    op.ft->Close(&op);
    if (cls)
    {
        /* every output of GetElementAt is optional (MI.NET reads one attribute at a time) */
        type = 0;
        res = cls->ft->GetElementAt(cls, 0, NULL, NULL, NULL, &type, NULL, NULL, NULL);
        ok(res == MI_RESULT_OK, "GetElementAt(NULL name) returned %d\n", res);
        ok(type == MI_STRING, "first property type %d\n", type);
        name = NULL;
        res = cls->ft->GetElementAt(cls, 0, &name, NULL, NULL, NULL, NULL, NULL, NULL);
        ok(res == MI_RESULT_OK && name && !wcscmp(name, L"Caption"), "first property %d %ls\n", res, name);

        /* Create is static, its CommandLine an In parameter */
        memset(&qs, 0, sizeof(qs));
        memset(&ps, 0, sizeof(ps));
        res = cls->ft->GetMethod(cls, L"Create", &qs, &ps, &i);
        ok(res == MI_RESULT_OK, "GetMethod(Create) returned %d\n", res);
        if (!res)
        {
            ok(has_qualifier(&qs, L"Static"), "Create is not Static\n");
            memset(&qs, 0, sizeof(qs));
            res = ps.ft->GetParameter(&ps, L"CommandLine", &type, NULL, &qs, &i);
            ok(res == MI_RESULT_OK && type == MI_STRING, "GetParameter(CommandLine) %d type %d\n", res, type);
            if (!res) ok(has_qualifier(&qs, L"In"), "CommandLine is not In\n");
        }
        memset(&qs, 0, sizeof(qs));
        res = cls->ft->GetMethod(cls, L"Terminate", &qs, &ps, &i);
        ok(res == MI_RESULT_OK, "GetMethod(Terminate) returned %d\n", res);
        if (!res) ok(!has_qualifier(&qs, L"Static"), "Terminate is Static\n");
        name = NULL;
        res = cls->ft->GetParentClassName(cls, &name);
        ok(res == MI_RESULT_OK && name && !wcscmp(name, L"CIM_Process"), "GetParentClassName %d %ls\n", res, name);
        res = cls->ft->GetParentClass(cls, &parent);
        ok(res == MI_RESULT_OK && parent, "GetParentClass returned %d\n", res);
        if (parent)
        {
            name = NULL;
            parent->ft->GetClassName(parent, &name);
            ok(name && !wcscmp(name, L"CIM_Process"), "parent %ls\n", name);
            res = parent->ft->GetParentClass(parent, &grand);
            ok(res == MI_RESULT_OK && grand, "GetParentClass(CIM_Process) returned %d\n", res);
            if (grand)
            {
                name = NULL;
                grand->ft->GetClassName(grand, &name);
                ok(name && !wcscmp(name, L"CIM_LogicalElement"), "grandparent %ls\n", name);
                grand->ft->Delete(grand);
            }
            parent->ft->Delete(parent);
        }

        cls->ft->Delete(cls);
    }

    /* an unknown class: Not found, error id "HRESULT 0x80041002" */
    memset(&op, 0, sizeof(op));
    session.ft->GetClass(&session, 0, NULL, L"root/cimv2", L"NoSuchClass_pswmi", NULL, &op);
    res = pull_classes(&op, &count, NULL, NULL, &details, NULL);
    ok(res == MI_RESULT_NOT_FOUND, "GetClass(unknown) result %d\n", res);
    ok(details != NULL, "no error details\n");
    if (details)
    {
        res = details->ft->GetElement(details, L"MessageID", &v, &type, NULL, NULL);
        ok(res == MI_RESULT_OK && type == MI_STRING && v.string && !wcscmp(v.string, L"HRESULT 0x80041002"),
           "MessageID %d %ls\n", res, res ? L"" : v.string);
        res = details->ft->GetElement(details, L"error_Code", &v, &type, NULL, NULL);
        ok(res == MI_RESULT_OK && type == MI_UINT32 && v.uint32 == 0x80041002, "error_Code %d %#x\n", res, v.uint32);
    }
    op.ft->Close(&op);

    /* an unknown namespace */
    memset(&op, 0, sizeof(op));
    session.ft->GetClass(&session, 0, NULL, L"pswmi_badnamespace", L"Win32_Process", NULL, &op);
    res = pull_classes(&op, &count, NULL, NULL, &details, NULL);
    ok(res == MI_RESULT_INVALID_NAMESPACE, "GetClass(bad namespace) result %d\n", res);
    if (details)
    {
        res = details->ft->GetElement(details, L"MessageID", &v, &type, NULL, NULL);
        ok(res == MI_RESULT_OK && type == MI_STRING && v.string && !wcscmp(v.string, L"HRESULT 0x8004100e"),
           "MessageID %d %ls\n", res, res ? L"" : v.string);
    }
    op.ft->Close(&op);

    /* deep enumeration of a base class returns the instances of its subclasses */
    memset(&op, 0, sizeof(op));
    session.ft->EnumerateInstances(&session, 0, NULL, L"root/cimv2", L"CIM_ComputerSystem", MI_FALSE, NULL, &op);
    res = pull_all(&op, &count, &first, NULL);
    ok(res == MI_RESULT_OK, "EnumerateInstances(CIM_ComputerSystem) result %d\n", res);
    ok(count == 1, "got %u computer systems\n", count);
    op.ft->Close(&op);
    if (first)
    {
        name = NULL;
        first->ft->GetClassName(first, &name);
        ok(name && !wcscmp(name, L"Win32_ComputerSystem"), "class %ls\n", name);
        first->ft->Delete(first);
    }

    /* namespaces: root has CIMV2 and Interop, root/Interop has ms_409 */
    for (i = 0; i < 2; i++)
    {
        static const MI_Char *const ns[] = { L"root", L"root/Interop" };
        static const MI_Char *const child[] = { L"CIMV2", L"ms_409" };
        const MI_Instance *inst;
        BOOL found = FALSE, found2 = FALSE;

        memset(&op, 0, sizeof(op));
        session.ft->EnumerateInstances(&session, 0, NULL, ns[i], L"__NAMESPACE", MI_FALSE, NULL, &op);
        more = MI_TRUE;
        count = 0;
        while (more && count < 1000)
        {
            inst = NULL;
            res = op.ft->GetInstance(&op, &inst, &more, &result, &message, &details);
            if (res) break;
            if (!inst) continue;
            count++;
            if (inst->ft->GetElement(inst, L"Name", &v, &type, NULL, NULL) == MI_RESULT_OK && type == MI_STRING &&
                v.string)
            {
                if (!_wcsicmp(v.string, child[i])) found = TRUE;
                if (!i && !_wcsicmp(v.string, L"Interop")) found2 = TRUE;
            }
        }
        ok(res == MI_RESULT_OK && result == MI_RESULT_OK, "__NAMESPACE in %ls: %d %d\n", ns[i], res, result);
        ok(found, "no %ls namespace in %ls (%u)\n", child[i], ns[i], count);
        if (!i) ok(found2, "no Interop namespace in root\n");
        op.ft->Close(&op);
    }

    /* a class of root/Interop, with its superclass */
    memset(&op, 0, sizeof(op));
    session.ft->GetClass(&session, 0, NULL, L"root/Interop", L"Win32_PowerSupplyProfile", NULL, &op);
    more = MI_TRUE;
    c = NULL;
    res = op.ft->GetClass(&op, &c, &more, &result, &message, &details);
    ok(res == MI_RESULT_OK && c, "GetClass(Win32_PowerSupplyProfile) %d %d\n", res, result);
    if (c)
    {
        name = NULL;
        c->ft->GetParentClassName(c, &name);
        ok(name && !wcscmp(name, L"CIM_RegisteredProfile"), "parent %ls\n", name);
    }
    op.ft->Close(&op);

    session.ft->Close(&session, NULL, NULL);
}

/* a method of the instances does not run on "the first instance of the class"; a class a namespace does not
 * have is an invalid class */
static void test_method_scope(MI_Application *app)
{
    MI_Session session = MI_SESSION_NULL;
    MI_Operation op = MI_OPERATION_NULL;
    MI_Instance *ext = NULL;
    MI_Result res, result;
    const MI_Char *message = NULL;
    UINT count;

    res = app->ft->NewSession(app, NULL, NULL, NULL, NULL, &ext, &session);
    ok(res == MI_RESULT_OK, "NewSession returned %d\n", res);
    if (res) return;

    memset(&op, 0, sizeof(op));
    session.ft->Invoke(&session, 0, NULL, L"root/cimv2", L"Win32_Service", L"ChangeStartMode", NULL, NULL, NULL, &op);
    result = pull_all(&op, &count, NULL, &message);
    trace("Invoke ChangeStartMode on the class: %d (%ls)\n", result, message);
    ok(result == MI_RESULT_FAILED, "ChangeStartMode on the class: %d\n", result);
    op.ft->Close(&op);

    memset(&op, 0, sizeof(op));
    session.ft->Invoke(&session, 0, NULL, L"root/cimv2", L"Win32_Process", L"GetOwnerSid", NULL, NULL, NULL, &op);
    result = pull_all(&op, &count, NULL, &message);
    ok(result == MI_RESULT_FAILED, "GetOwnerSid on the class: %d\n", result);
    op.ft->Close(&op);

    /* a static method returns its out-parameters */
    {
        MI_Instance *out = NULL;
        MI_Value v;
        MI_Type type;
        MI_Uint32 flags;
        memset(&op, 0, sizeof(op));
        session.ft->Invoke(&session, 0, NULL, L"root/cimv2", L"Win32_Process", L"Create", NULL, NULL, NULL, &op);
        result = pull_all(&op, &count, &out, &message);
        trace("Invoke Create: result %d count %u out %p\n", result, count, out);
        ok(result == MI_RESULT_OK, "Create: %d\n", result);
        ok(count == 1 && out, "Create returned %u instances\n", count);
        if (out)
        {
            UINT n = 0;
            MI_Uint32 ec = 0;
            out->ft->GetElementCount(out, &ec);
            trace("out params: %u elements\n", ec);
            ok(ec > 0, "no out-parameters\n");
            ok(out->ft->GetElement(out, L"ReturnValue", &v, &type, &flags, NULL) == MI_RESULT_OK, "no ReturnValue\n");
            (void)n;
            out->ft->Delete(out);
        }
        op.ft->Close(&op);
    }

    memset(&op, 0, sizeof(op));
    session.ft->EnumerateInstances(&session, 0, NULL, L"root/Interop", L"Win32_Process", MI_FALSE, NULL, &op);
    result = pull_all(&op, &count, NULL, &message);
    trace("Win32_Process in root/Interop: %d (%ls)\n", result, message);
    ok(result == MI_RESULT_INVALID_CLASS, "Win32_Process in root/Interop: %d\n", result);
    ok(!count, "%u instances\n", count);
    op.ft->Close(&op);

    session.ft->Close(&session, NULL, NULL);
}

static void own_exe_name(WCHAR *name, DWORD size)
{
    WCHAR path[MAX_PATH], *p;
    GetModuleFileNameW(NULL, path, ARRAYSIZE(path));
    p = wcsrchr(path, '\\');
    wcsncpy(name, p ? p + 1 : path, size - 1);
    name[size - 1] = 0;
}

struct verify_ctx
{
    HANDLE done;
    const WCHAR *prop, *expect;
    LONG count, bad, finals;
    MI_Result result;
};

static void MI_CALL verify_instance(MI_Operation *op, void *context, const MI_Instance *inst, MI_Boolean more,
                                    MI_Result result, const MI_Char *message, const MI_Instance *details,
                                    MI_Result (MI_CALL *ack)(MI_Operation *))
{
    struct verify_ctx *ctx = context;
    if (inst)
    {
        MI_Value v;
        MI_Type type;
        MI_Uint32 flags;
        InterlockedIncrement(&ctx->count);
        if (inst->ft->GetElement(inst, ctx->prop, &v, &type, &flags, NULL) != MI_RESULT_OK || type != MI_STRING ||
            (flags & MI_FLAG_NULL) || !v.string || _wcsicmp(v.string, ctx->expect))
            InterlockedIncrement(&ctx->bad);
    }
    if (!more)
    {
        ctx->result = result;
        ctx->finals++;
    }
    if (ack) ack(op);
    if (!more) SetEvent(ctx->done);
}

/* pull every instance; count them and those of a class */
static MI_Result pull_instance_classes(MI_Operation *op, const MI_Char *class_name, UINT *count, UINT *matches)
{
    const MI_Instance *inst, *details;
    const MI_Char *message, *name;
    MI_Boolean more = MI_TRUE;
    MI_Result result = MI_RESULT_FAILED;
    UINT guard = 0;

    *count = *matches = 0;
    while (more && guard++ < 100000)
    {
        inst = NULL;
        if (op->ft->GetInstance(op, &inst, &more, &result, &message, &details) != MI_RESULT_OK) break;
        if (!inst) continue;
        (*count)++;
        name = NULL;
        if (inst->ft->GetClassName(inst, &name) == MI_RESULT_OK && name && !_wcsicmp(name, class_name)) (*matches)++;
    }
    return result;
}

static void test_associations(MI_Application *app)
{
    MI_Session session = MI_SESSION_NULL;
    MI_Operation op = MI_OPERATION_NULL;
    MI_Instance *proc = NULL, *first = NULL, *keys = NULL;
    const MI_Char *name;
    WCHAR query[128], pid[16];
    UINT count, matches, n;
    MI_Result res;
    MI_Value v;
    MI_Type type;
    MI_Uint32 flags;

    res = app->ft->NewSession(app, NULL, NULL, NULL, NULL, NULL, &session);
    ok(res == MI_RESULT_OK, "NewSession returned %d\n", res);
    if (res) return;

    _snwprintf(query, ARRAYSIZE(query) - 1, L"SELECT * FROM Win32_Process WHERE ProcessId = %lu", GetCurrentProcessId());
    query[ARRAYSIZE(query) - 1] = 0;
    _snwprintf(pid, ARRAYSIZE(pid) - 1, L"%lu", GetCurrentProcessId());
    pid[ARRAYSIZE(pid) - 1] = 0;
    session.ft->QueryInstances(&session, 0, NULL, L"root\\cimv2", L"WQL", query, NULL, &op);
    res = pull_all(&op, &count, &proc, NULL);
    ok(res == MI_RESULT_OK && count == 1 && proc, "own process: result %d count %u\n", res, count);
    op.ft->Close(&op);
    if (!proc) goto done;

    /* Get-CimAssociatedInstance -ResultClassName Win32_ComputerSystem */
    memset(&op, 0, sizeof(op));
    session.ft->AssociatorInstances(&session, 0, NULL, L"root\\cimv2", proc, NULL, L"Win32_ComputerSystem", NULL, NULL,
                                    MI_FALSE, NULL, &op);
    ok(op.ft != NULL, "no operation ft\n");
    res = pull_all(&op, &count, &first, NULL);
    ok(res == MI_RESULT_OK, "associators result %d\n", res);
    ok(count == 1, "got %u computer systems\n", count);
    op.ft->Close(&op);
    if (first)
    {
        name = NULL;
        ok(first->ft->GetClassName(first, &name) == MI_RESULT_OK && name && !_wcsicmp(name, L"Win32_ComputerSystem"),
           "class %ls\n", name);
        res = first->ft->GetElement(first, L"Name", &v, &type, &flags, NULL);
        ok(res == MI_RESULT_OK && type == MI_STRING && v.string && v.string[0], "Name: %d type %d\n", res, type);
        ok(res == MI_RESULT_OK && (flags & MI_FLAG_KEY), "Name flags %#x\n", flags);
        res = first->ft->GetElement(first, L"NumberOfLogicalProcessors", &v, &type, NULL, NULL);
        ok(res == MI_RESULT_OK && type == MI_UINT32 && v.uint32 >= 1, "NumberOfLogicalProcessors: %d type %d\n", res, type);
        first->ft->Delete(first);
        first = NULL;
    }

    /* the association class and both roles */
    memset(&op, 0, sizeof(op));
    session.ft->AssociatorInstances(&session, 0, NULL, L"root\\cimv2", proc, L"Win32_SystemProcesses", NULL,
                                    L"PartComponent", L"GroupComponent", MI_FALSE, NULL, &op);
    res = pull_instance_classes(&op, L"Win32_ComputerSystem", &count, &matches);
    ok(res == MI_RESULT_OK && count == 1 && matches == 1, "by association: result %d count %u matches %u\n", res, count, matches);
    op.ft->Close(&op);

    /* an abstract association class covers its subclasses */
    memset(&op, 0, sizeof(op));
    session.ft->AssociatorInstances(&session, 0, NULL, L"root\\cimv2", proc, L"CIM_Component", L"CIM_System", NULL, NULL,
                                    MI_FALSE, NULL, &op);
    res = pull_instance_classes(&op, L"Win32_ComputerSystem", &count, &matches);
    ok(res == MI_RESULT_OK && count == 1 && matches == 1, "by base classes: result %d count %u matches %u\n", res, count, matches);
    op.ft->Close(&op);

    /* the process is the part, never the group */
    memset(&op, 0, sizeof(op));
    session.ft->AssociatorInstances(&session, 0, NULL, L"root\\cimv2", proc, NULL, NULL, L"GroupComponent", NULL,
                                    MI_FALSE, NULL, &op);
    res = pull_all(&op, &count, NULL, NULL);
    ok(res == MI_RESULT_OK && count == 0, "wrong role: result %d count %u\n", res, count);
    op.ft->Close(&op);

    /* an unknown result class is no error */
    memset(&op, 0, sizeof(op));
    session.ft->AssociatorInstances(&session, 0, NULL, L"root\\cimv2", proc, NULL, L"Win32_NoSuchClassAtAll", NULL, NULL,
                                    MI_FALSE, NULL, &op);
    res = pull_all(&op, &count, NULL, NULL);
    ok(res == MI_RESULT_OK && count == 0, "unknown result class: result %d count %u\n", res, count);
    op.ft->Close(&op);

    /* keys only */
    memset(&op, 0, sizeof(op));
    session.ft->AssociatorInstances(&session, 0, NULL, L"root\\cimv2", proc, NULL, L"Win32_ComputerSystem", NULL, NULL,
                                    MI_TRUE, NULL, &op);
    res = pull_all(&op, &count, &first, NULL);
    ok(res == MI_RESULT_OK && count == 1, "keys only: result %d count %u\n", res, count);
    op.ft->Close(&op);
    if (first)
    {
        MI_Result count_res;
        n = 0;
        count_res = first->ft->GetElementCount(first, &n);
        res = first->ft->GetElement(first, L"Name", &v, &type, NULL, NULL);
        ok(res == MI_RESULT_OK && type == MI_STRING, "keys only Name: %d type %d\n", res, type);
        /* Windows keeps the other properties, NULL; without them is as good for a client */
        flags = 0;
        res = first->ft->GetElement(first, L"NumberOfLogicalProcessors", &v, &type, &flags, NULL);
        ok(count_res == MI_RESULT_OK && n >= 1, "keys only: GetElementCount %d, %u properties\n", count_res, n);
        ok(res == MI_RESULT_NO_SUCH_PROPERTY || (res == MI_RESULT_OK && (flags & MI_FLAG_NULL)),
           "keys only: NumberOfLogicalProcessors %d flags %#x\n", res, flags);
        first->ft->Delete(first);
        first = NULL;
    }

    /* the association instance */
    memset(&op, 0, sizeof(op));
    session.ft->ReferenceInstances(&session, 0, NULL, L"root\\cimv2", proc, L"Win32_SystemProcesses", NULL, MI_FALSE,
                                   NULL, &op);
    ok(op.ft != NULL, "no operation ft\n");
    res = pull_all(&op, &count, &first, NULL);
    ok(res == MI_RESULT_OK && count == 1, "references: result %d count %u\n", res, count);
    op.ft->Close(&op);
    if (first)
    {
        name = NULL;
        ok(first->ft->GetClassName(first, &name) == MI_RESULT_OK && name && !_wcsicmp(name, L"Win32_SystemProcesses"),
           "class %ls\n", name);
        res = first->ft->GetElement(first, L"PartComponent", &v, &type, NULL, NULL);
        ok(res == MI_RESULT_OK && type == MI_REFERENCE && v.reference, "PartComponent: %d type %d\n", res, type);
        if (res == MI_RESULT_OK && type == MI_REFERENCE && v.reference)
        {
            MI_Value h;
            MI_Type htype;
            name = NULL;
            ok(v.reference->ft->GetClassName(v.reference, &name) == MI_RESULT_OK && name &&
               !_wcsicmp(name, L"Win32_Process"), "PartComponent class %ls\n", name);
            res = v.reference->ft->GetElement(v.reference, L"Handle", &h, &htype, NULL, NULL);
            ok(res == MI_RESULT_OK && htype == MI_STRING && h.string && !wcscmp(h.string, pid),
               "PartComponent Handle %d %ls\n", res, res == MI_RESULT_OK && htype == MI_STRING ? h.string : L"");
        }
        res = first->ft->GetElement(first, L"GroupComponent", &v, &type, NULL, NULL);
        ok(res == MI_RESULT_OK && type == MI_REFERENCE && v.reference, "GroupComponent: %d type %d\n", res, type);
        if (res == MI_RESULT_OK && type == MI_REFERENCE && v.reference)
        {
            name = NULL;
            ok(v.reference->ft->GetClassName(v.reference, &name) == MI_RESULT_OK && name &&
               !_wcsicmp(name, L"Win32_ComputerSystem"), "GroupComponent class %ls\n", name);
        }
        first->ft->Delete(first);
        first = NULL;
    }

    memset(&op, 0, sizeof(op));
    session.ft->ReferenceInstances(&session, 0, NULL, L"root\\cimv2", proc, NULL, L"GroupComponent", MI_FALSE, NULL, &op);
    res = pull_all(&op, &count, NULL, NULL);
    ok(res == MI_RESULT_OK && count == 0, "references by the wrong role: result %d count %u\n", res, count);
    op.ft->Close(&op);

    /* an instance that does not exist */
    res = app->ft->NewInstance(app, L"Win32_Process", NULL, &keys);
    ok(res == MI_RESULT_OK, "NewInstance returned %d\n", res);
    if (keys)
    {
        v.string = (MI_Char *)L"4294967290";
        res = keys->ft->AddElement(keys, L"Handle", &v, MI_STRING, MI_FLAG_KEY);
        ok(res == MI_RESULT_OK, "AddElement returned %d\n", res);
        memset(&op, 0, sizeof(op));
        session.ft->AssociatorInstances(&session, 0, NULL, L"root\\cimv2", keys, NULL, NULL, NULL, NULL, MI_FALSE, NULL, &op);
        res = pull_all(&op, &count, NULL, NULL);
        ok(res == MI_RESULT_NOT_FOUND && count == 0, "missing instance: result %d count %u\n", res, count);
        op.ft->Close(&op);
        memset(&op, 0, sizeof(op));
        session.ft->ReferenceInstances(&session, 0, NULL, L"root\\cimv2", keys, NULL, NULL, MI_FALSE, NULL, &op);
        res = pull_all(&op, &count, NULL, NULL);
        ok(res == MI_RESULT_NOT_FOUND && count == 0, "missing instance references: result %d count %u\n", res, count);
        op.ft->Close(&op);
        keys->ft->Delete(keys);
    }

    /* a key name that is not a property name: Windows refuses to add the element, mi.dll then must not paste it into WQL */
    res = app->ft->NewInstance(app, L"Win32_Process", NULL, &keys);
    ok(res == MI_RESULT_OK, "NewInstance returned %d\n", res);
    if (keys)
    {
        v.string = (MI_Char *)L"1";
        res = keys->ft->AddElement(keys, L"Handle=\"1\"} WHERE ResultClass=Win32_ComputerSystem, X", &v, MI_STRING, MI_FLAG_KEY);
        if (res == MI_RESULT_OK)
        {
            memset(&op, 0, sizeof(op));
            session.ft->AssociatorInstances(&session, 0, NULL, L"root\\cimv2", keys, NULL, NULL, NULL, NULL, MI_FALSE, NULL, &op);
            res = pull_all(&op, &count, NULL, NULL);
            ok(count == 0, "odd key name: result %d count %u\n", res, count);
            op.ft->Close(&op);
        }
        keys->ft->Delete(keys);
    }

    /* no instance */
    memset(&op, 0, sizeof(op));
    session.ft->AssociatorInstances(&session, 0, NULL, L"root\\cimv2", NULL, NULL, NULL, NULL, NULL, MI_FALSE, NULL, &op);
    ok(op.ft != NULL, "no operation ft for a NULL instance\n");
    if (op.ft)
    {
        const MI_Instance *inst = NULL, *details = NULL;
        const MI_Char *message = NULL;
        MI_Boolean more = MI_TRUE;
        MI_Result result = MI_RESULT_OK;

        res = op.ft->GetInstance(&op, &inst, &more, &result, &message, &details);
        ok(res == MI_RESULT_OK && !inst && !more, "NULL instance: GetInstance %d inst %p more %d\n", res, inst, more);
        ok(result == MI_RESULT_INVALID_PARAMETER, "NULL instance: result %d\n", result);
        op.ft->Close(&op);
    }

    /* what the PowerShell completer asks for Get-CimAssociatedInstance -ResultClassName */
    memset(&op, 0, sizeof(op));
    session.ft->QueryInstances(&session, 0, NULL, L"root\\cimv2", L"WQL", L"associators of {Win32_Process} WHERE SchemaOnly",
                               NULL, &op);
    res = pull_instance_classes(&op, L"Win32_ComputerSystem", &count, &matches);
    ok(res == MI_RESULT_OK && count >= 1 && matches == 1, "schema: result %d count %u matches %u\n", res, count, matches);
    op.ft->Close(&op);

    memset(&op, 0, sizeof(op));
    session.ft->QueryInstances(&session, 0, NULL, L"root\\cimv2", L"WQL", L"references of {Win32_Process} WHERE SchemaOnly",
                               NULL, &op);
    res = pull_instance_classes(&op, L"Win32_SystemProcesses", &count, &matches);
    ok(res == MI_RESULT_OK && count >= 1 && matches == 1, "reference schema: result %d count %u matches %u\n", res, count, matches);
    op.ft->Close(&op);

done:
    if (proc) proc->ft->Delete(proc);
    session.ft->Close(&session, NULL, NULL);
}

static void test_filtered_enumeration(MI_Application *app)
{
    MI_Session session = MI_SESSION_NULL;
    MI_Operation op = MI_OPERATION_NULL;
    MI_OperationCallbacks cb = MI_OPERATIONCALLBACKS_NULL;
    struct verify_ctx ctx;
    WCHAR exe[MAX_PATH], query[MAX_PATH + 64];
    UINT count, bad, total, i;
    MI_Result res;

    res = app->ft->NewSession(app, NULL, NULL, NULL, NULL, NULL, &session);
    ok(res == MI_RESULT_OK, "NewSession returned %d\n", res);
    if (res) return;

    /* a filtered enumeration must return exactly the rows that match the filter */
    res = query_checked(&session, L"SELECT * FROM Win32_Service WHERE State = 'Running'", L"State", L"Running", &count, &bad);
    ok(res == MI_RESULT_OK, "running services result %d\n", res);
    ok(count > 0, "no running service returned\n");
    ok(bad == 0, "%u of %u 'Running' services do not match the filter\n", bad, count);

    res = query_checked(&session, L"SELECT * FROM Win32_Service WHERE State = 'Stopped'", L"State", L"Stopped", &count, &bad);
    ok(res == MI_RESULT_OK, "stopped services result %d\n", res);
    ok(bad == 0, "%u of %u 'Stopped' services do not match the filter\n", bad, count);

    own_exe_name(exe, ARRAYSIZE(exe));
    _snwprintf(query, ARRAYSIZE(query) - 1, L"SELECT * FROM Win32_Process WHERE Name = '%s'", exe);
    query[ARRAYSIZE(query) - 1] = 0;
    res = query_checked(&session, query, L"Name", exe, &count, &bad);
    ok(res == MI_RESULT_OK, "process by name result %d\n", res);
    ok(count >= 1, "own process %ls not returned\n", exe);
    ok(bad == 0, "%u of %u processes do not match Name = '%ls'\n", bad, count, exe);

    /* unfiltered: every process must have a name, and the total is at least the filtered count */
    res = query_checked(&session, L"SELECT * FROM Win32_Process", L"Name", L"", &total, &bad);
    ok(res == MI_RESULT_OK, "all processes result %d\n", res);
    ok(total >= count && total > 3, "total %u filtered %u\n", total, count);

    /* the same filter through push callbacks */
    for (i = 0; i < 2; i++)
    {
        memset(&ctx, 0, sizeof(ctx));
        ctx.done = CreateEventW(NULL, TRUE, FALSE, NULL);
        ctx.prop = L"State";
        ctx.expect = i ? L"Stopped" : L"Running";
        ctx.result = MI_RESULT_FAILED;
        cb.callbackContext = &ctx;
        cb.instanceResult = verify_instance;
        memset(&op, 0, sizeof(op));
        _snwprintf(query, ARRAYSIZE(query) - 1, L"SELECT * FROM Win32_Service WHERE State = '%s'", ctx.expect);
        query[ARRAYSIZE(query) - 1] = 0;
        session.ft->QueryInstances(&session, 0, NULL, L"root/cimv2", L"WQL", query, &cb, &op);
        ok(WaitForSingleObject(ctx.done, 60000) == WAIT_OBJECT_0, "push query timed out\n");
        ok(ctx.result == MI_RESULT_OK && ctx.finals == 1, "push result %d finals %ld\n", ctx.result, ctx.finals);
        ok(ctx.bad == 0, "push: %ld of %ld services do not match State = %ls\n", ctx.bad, ctx.count, ctx.expect);
        if (op.ft) op.ft->Close(&op);
        CloseHandle(ctx.done);
    }
    session.ft->Close(&session, NULL, NULL);
}

struct thread_ctx
{
    MI_Application *app;
    int id;
    LONG failures;
    UINT enumerations;
};

#define CONCURRENT_ROUNDS 15

static DWORD WINAPI concurrent_thread(void *arg)
{
    struct thread_ctx *t = arg;
    MI_Session session = MI_SESSION_NULL;
    WCHAR exe[MAX_PATH], query[MAX_PATH + 64];
    UINT i, count, bad;
    MI_Result res;

    if (t->app->ft->NewSession(t->app, NULL, NULL, NULL, NULL, NULL, &session) != MI_RESULT_OK)
    {
        t->failures++;
        return 0;
    }
    own_exe_name(exe, ARRAYSIZE(exe));
    for (i = 0; i < CONCURRENT_ROUNDS; i++)
    {
        /* every thread uses the same two classes, so they share wbemprox's tables */
        res = query_checked(&session, L"SELECT * FROM Win32_Service WHERE State = 'Running'", L"State", L"Running",
                            &count, &bad);
        if (res != MI_RESULT_OK || !count || bad) t->failures++;
        _snwprintf(query, ARRAYSIZE(query) - 1, L"SELECT * FROM Win32_Process WHERE Name = '%s'", exe);
        query[ARRAYSIZE(query) - 1] = 0;
        res = query_checked(&session, query, L"Name", exe, &count, &bad);
        if (res != MI_RESULT_OK || !count || bad) t->failures++;
        res = query_checked(&session, L"SELECT * FROM Win32_Process", L"Name", L"", &count, &bad);
        if (res != MI_RESULT_OK || count < 4) t->failures++;
        t->enumerations += 3;
    }
    session.ft->Close(&session, NULL, NULL);
    return 0;
}

static void test_concurrent_enumeration(MI_Application *app)
{
    struct thread_ctx ctx[4];
    HANDLE threads[4];
    int i;

    for (i = 0; i < 4; i++)
    {
        memset(&ctx[i], 0, sizeof(ctx[i]));
        ctx[i].app = app;
        ctx[i].id = i;
        threads[i] = CreateThread(NULL, 0, concurrent_thread, &ctx[i], 0, NULL);
        ok(threads[i] != NULL, "CreateThread failed\n");
    }
    for (i = 0; i < 4; i++)
    {
        if (!threads[i]) continue;
        ok(WaitForSingleObject(threads[i], 240000) == WAIT_OBJECT_0, "thread %d did not finish\n", i);
        CloseHandle(threads[i]);
        ok(ctx[i].failures == 0, "thread %d: %ld wrong or failed enumerations of %u\n", i, ctx[i].failures,
           ctx[i].enumerations);
    }
}

struct life_ctx
{
    HANDLE in_final, done;
    LONG final_returned;
    LONG callbacks;
    BOOL close_inside;
    MI_Result close_result;
    MI_Result (MI_CALL *first_ack)(MI_Operation *);
    MI_Operation *first_op;
    HANDLE first_seen;
    BOOL manual;
};

static void MI_CALL life_callback(MI_Operation *op, void *context, const MI_Instance *inst, MI_Boolean more,
                                  MI_Result result, const MI_Char *message, const MI_Instance *details,
                                  MI_Result (MI_CALL *ack)(MI_Operation *))
{
    struct life_ctx *ctx = context;
    LONG n = InterlockedIncrement(&ctx->callbacks);

    if (ctx->manual)
    {
        /* hold the first result un-acked; every later one is acked at once */
        if (n == 1)
        {
            ctx->first_ack = ack;
            ctx->first_op = op;
            SetEvent(ctx->first_seen);
            return;
        }
    }
    if (more) { if (ack) ack(op); return; }
    SetEvent(ctx->in_final);
    if (ctx->close_inside) ctx->close_result = op->ft->Close(op);
    else Sleep(400); /* the client is still using its context while the final callback runs */
    InterlockedExchange(&ctx->final_returned, 1);
    SetEvent(ctx->done);
}

static void init_life(struct life_ctx *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->in_final = CreateEventW(NULL, TRUE, FALSE, NULL);
    ctx->done = CreateEventW(NULL, TRUE, FALSE, NULL);
    ctx->first_seen = CreateEventW(NULL, TRUE, FALSE, NULL);
}

static void free_life(struct life_ctx *ctx)
{
    CloseHandle(ctx->in_final);
    CloseHandle(ctx->done);
    CloseHandle(ctx->first_seen);
}

static BOOL running_on_reactos(void)
{
    WCHAR root[MAX_PATH];
    HKEY key;
    if (GetEnvironmentVariableW(L"MI_TEST_STRICT_CLOSE", root, ARRAYSIZE(root))) return TRUE;
    /* Not the system directory's name: new installs go to \Windows */
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\ReactOS", 0, KEY_READ, &key) != ERROR_SUCCESS) return FALSE;
    RegCloseKey(key);
    return TRUE;
}

static void test_callback_lifetime(MI_Application *app)
{
    MI_Session session = MI_SESSION_NULL;
    MI_Operation op = MI_OPERATION_NULL;
    MI_OperationCallbacks cb = MI_OPERATIONCALLBACKS_NULL;
    struct life_ctx ctx;
    MI_Result res;

    res = app->ft->NewSession(app, NULL, NULL, NULL, NULL, NULL, &session);
    ok(res == MI_RESULT_OK, "NewSession returned %d\n", res);
    if (res) return;

    /* Close from another thread while the final callback is still running must wait for it. Windows'
     * mi.dll does not wait and then crashes in its own worker (checked on the 22H2 oracle), so this and the
     * next case only run on ReactOS. */
    if (running_on_reactos())
    {
        trace("callback lifetime: Close during the final callback\n");
        init_life(&ctx);
        cb.callbackContext = &ctx;
        cb.instanceResult = life_callback;
        session.ft->EnumerateInstances(&session, 0, NULL, L"root/cimv2", L"Win32_OperatingSystem", MI_FALSE, &cb, &op);
        ok(op.ft != NULL, "no operation\n");
        if (op.ft)
        {
            ok(WaitForSingleObject(ctx.in_final, 60000) == WAIT_OBJECT_0, "final callback never started\n");
            res = op.ft->Close(&op);
            ok(res == MI_RESULT_OK, "Close returned %d\n", res);
            ok(ctx.final_returned, "Close returned while the final callback was still running\n");
            WaitForSingleObject(ctx.done, 5000);
        }
        free_life(&ctx);
    }
    cb.callbackContext = &ctx;
    cb.instanceResult = life_callback;

    /* Close from inside the final callback must not deadlock. */
    if (running_on_reactos())
    {
        trace("callback lifetime: Close inside the final callback\n");
        init_life(&ctx);
        ctx.close_inside = TRUE;
        ctx.close_result = MI_RESULT_FAILED;
        memset(&op, 0, sizeof(op));
        session.ft->EnumerateInstances(&session, 0, NULL, L"root/cimv2", L"Win32_OperatingSystem", MI_FALSE, &cb, &op);
        ok(WaitForSingleObject(ctx.done, 20000) == WAIT_OBJECT_0, "Close inside the callback deadlocked\n");
        ok(ctx.close_result == MI_RESULT_OK, "Close inside the callback returned %d\n", ctx.close_result);
        free_life(&ctx);
    }

    /* manual-ack pacing: Cancel does not acknowledge the result the client still holds.
     * The 22H2 oracle behaves the same way up to the ack (no further callback after Cancel while the result
     * is un-acked), but its mi.dll then hangs in the session/application teardown, so only ReactOS runs it. */
    if (running_on_reactos())
    {
        init_life(&ctx);
        ctx.manual = TRUE;
        memset(&op, 0, sizeof(op));
        session.ft->EnumerateInstances(&session, MI_OPERATIONFLAGS_MANUAL_ACK_RESULTS, NULL, L"root/cimv2", L"Win32_Process",
                                       MI_FALSE, &cb, &op);
        if (op.ft && WaitForSingleObject(ctx.first_seen, 60000) == WAIT_OBJECT_0)
        {
            op.ft->Cancel(&op, MI_REASON_NONE);
            Sleep(400);
            ok(ctx.callbacks == 1, "%ld callbacks arrived after Cancel without an ack\n", ctx.callbacks);
            if (ctx.first_ack) ctx.first_ack(&op);
            ok(WaitForSingleObject(ctx.done, 30000) == WAIT_OBJECT_0, "no final callback after the ack\n");
        }
        else ok(0, "manual-ack enumeration did not start\n");
        if (op.ft) op.ft->Close(&op);
        free_life(&ctx);
    }

    session.ft->Close(&session, NULL, NULL);
}

static void test_remote(MI_Application *app)
{
    MI_Session session = MI_SESSION_NULL;
    MI_Instance *ext = NULL;
    MI_Result res;

    res = app->ft->NewSession(app, L"NoSuchProtocol", NULL, NULL, NULL, &ext, &session);
    ok(res != MI_RESULT_OK, "unknown protocol accepted\n");
    if (ext) ext->ft->Delete(ext);
    if (res == MI_RESULT_OK) session.ft->Close(&session, NULL, NULL);
}

/* ---- review round 2: stale application handle, stale wbemprox view, DLL pinned by a worker ---- */

#define STALE_CHILDREN 12
#define STALE_CHILD_ARG L"mi_stale_child"

/* MI_Application is passed by value: a copy kept across MI_Application_Close must be rejected, even once
 * the memory behind it has been handed to a newer application. What Windows mi.dll does with a stale
 * copy is undefined (it frees the block), so this only runs on ReactOS. */
static void test_app_stale_copy(void)
{
    MI_Application app = MI_APPLICATION_NULL, copy, later = MI_APPLICATION_NULL, later_copy;
    MI_Instance *ext = NULL, *inst = NULL;
    MI_Result res;
    UINT i;

    if (!running_on_reactos()) return;

    res = pMI_Application_InitializeV1(0, L"mi_apitest_stale", &ext, &app);
    ok(res == MI_RESULT_OK, "Initialize returned %d\n", res);
    if (res) return;
    copy = app;
    res = app.ft->Close(&app);
    ok(res == MI_RESULT_OK, "Close returned %d\n", res);
    ok(app.ft == NULL, "Close left ft set\n");

    /* the stale by-value copy: no crash, no success */
    res = copy.ft->Close(&copy);
    ok(res != MI_RESULT_OK, "Close through a stale copy succeeded\n");
    res = copy.ft->NewInstance(&copy, L"MI_Test", NULL, &inst);
    ok(res != MI_RESULT_OK, "NewInstance through a stale copy succeeded\n");
    if (res == MI_RESULT_OK && inst) inst->ft->Delete(inst);

    /* a newer application may reuse the block: the stale copy must not reach it, nor close it */
    for (i = 0; i < 4; i++)
    {
        res = pMI_Application_InitializeV1(0, L"mi_apitest_later", &ext, &later);
        ok(res == MI_RESULT_OK, "second Initialize returned %d\n", res);
        if (res) return;
        res = copy.ft->Close(&copy);
        ok(res != MI_RESULT_OK, "stale Close succeeded while a newer application is live\n");
        inst = NULL;
        res = later.ft->NewInstance(&later, L"MI_Test", NULL, &inst);
        ok(res == MI_RESULT_OK, "the newer application was closed by a stale copy (%d)\n", res);
        if (inst) inst->ft->Delete(inst);
        later_copy = later;
        res = later.ft->Close(&later);
        ok(res == MI_RESULT_OK, "Close of the newer application returned %d\n", res);
        ok(later.ft == NULL, "Close left ft set\n");
        res = later_copy.ft->Close(&later_copy);
        ok(res != MI_RESULT_OK, "double Close through a copy succeeded\n");
    }
}

/* wbemprox keeps one table per class and refills it for every query. An object kept from an earlier
 * query names a row of the old fill: once the table has shrunk, its properties (the system ones that read
 * the key columns included) must fail instead of reading past the rows. */
static void test_stale_view(void)
{
    static const WCHAR *prop_names[] = { L"__RELPATH", L"__PATH", L"Name", L"Handle", L"ProcessId" };
    IWbemLocator *locator = NULL;
    IWbemServices *services = NULL;
    IEnumWbemClassObject *first = NULL, *second = NULL;
    IWbemClassObject *objs[512], *obj;
    BSTR ns, lang, query;
    PROCESS_INFORMATION pi[STALE_CHILDREN];
    STARTUPINFOW si;
    WCHAR exe[MAX_PATH], cmd[MAX_PATH + 32];
    ULONG got, count1 = 0, count2 = 0, i, p;
    HRESULT hr;
    VARIANT v;
    UINT started = 0;

    if (!running_on_reactos()) return;

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ok(SUCCEEDED(hr), "CoInitializeEx returned %08lx\n", hr);
    hr = CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (void **)&locator);
    ok(hr == S_OK, "no locator: %08lx\n", hr);
    if (hr != S_OK) goto done;
    ns = SysAllocString(L"root\\cimv2");
    hr = IWbemLocator_ConnectServer(locator, ns, NULL, NULL, NULL, 0, NULL, NULL, &services);
    SysFreeString(ns);
    ok(hr == S_OK, "ConnectServer returned %08lx\n", hr);
    if (hr != S_OK) goto done;

    GetModuleFileNameW(NULL, exe, ARRAYSIZE(exe));
    _snwprintf(cmd, ARRAYSIZE(cmd) - 1, L"\"%s\" mi %s", exe, STALE_CHILD_ARG);
    cmd[ARRAYSIZE(cmd) - 1] = 0;
    memset(pi, 0, sizeof(pi));
    for (i = 0; i < STALE_CHILDREN; i++)
    {
        memset(&si, 0, sizeof(si));
        si.cb = sizeof(si);
        if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi[started])) started++;
    }
    ok(started == STALE_CHILDREN, "only %u children started\n", started);
    Sleep(500);

    lang = SysAllocString(L"WQL");
    query = SysAllocString(L"SELECT * FROM Win32_Process");
    hr = IWbemServices_ExecQuery(services, lang, query, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                 NULL, &first);
    ok(hr == S_OK, "ExecQuery returned %08lx\n", hr);
    if (hr == S_OK)
    {
        for (;;)
        {
            got = 0;
            hr = IEnumWbemClassObject_Next(first, WBEM_INFINITE, 1, &obj, &got);
            if (hr != S_OK || !got) break;
            if (count1 < ARRAYSIZE(objs)) objs[count1++] = obj;
            else IWbemClassObject_Release(obj);
        }
    }
    ok(count1 > started, "first fill has %lu rows\n", count1);

    /* the children go away and a second query shrinks the table */
    for (i = 0; i < started; i++)
    {
        TerminateProcess(pi[i].hProcess, 0);
        WaitForSingleObject(pi[i].hProcess, 10000);
        CloseHandle(pi[i].hProcess);
        CloseHandle(pi[i].hThread);
    }
    Sleep(500);
    hr = IWbemServices_ExecQuery(services, lang, query, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                 NULL, &second);
    ok(hr == S_OK, "second ExecQuery returned %08lx\n", hr);
    if (hr == S_OK)
    {
        for (;;)
        {
            got = 0;
            hr = IEnumWbemClassObject_Next(second, WBEM_INFINITE, 1, &obj, &got);
            if (hr != S_OK || !got) break;
            count2++;
            IWbemClassObject_Release(obj);
        }
    }
    trace("stale view: first fill %lu rows, second fill %lu rows\n", count1, count2);

    if (count1 && count2 < count1)
    {
        /* every kept object with a row index past the new fill is stale */
        for (i = count2; i < count1; i++)
        {
            for (p = 0; p < ARRAYSIZE(prop_names); p++)
            {
                VariantInit(&v);
                hr = IWbemClassObject_Get(objs[i], prop_names[p], 0, &v, NULL, NULL);
                ok(hr == WBEM_E_NOT_FOUND, "row %lu of %lu, property %lu: Get returned %08lx\n", i, count2, p, hr);
                VariantClear(&v);
            }
            /* the properties that name no row still answer */
            VariantInit(&v);
            hr = IWbemClassObject_Get(objs[i], L"__CLASS", 0, &v, NULL, NULL);
            ok(hr == S_OK && V_VT(&v) == VT_BSTR, "__CLASS of a stale object returned %08lx\n", hr);
            VariantClear(&v);
        }
        /* and a row inside the new fill is still readable */
        VariantInit(&v);
        hr = IWbemClassObject_Get(objs[0], L"__RELPATH", 0, &v, NULL, NULL);
        ok(hr == S_OK, "__RELPATH of a row inside the table returned %08lx\n", hr);
        VariantClear(&v);
    }
    else skip("the process table did not shrink (%lu -> %lu)\n", count1, count2);

    for (i = 0; i < count1; i++) IWbemClassObject_Release(objs[i]);
    if (first) IEnumWbemClassObject_Release(first);
    if (second) IEnumWbemClassObject_Release(second);
    SysFreeString(lang);
    SysFreeString(query);
done:
    if (services) IWbemServices_Release(services);
    if (locator) IWbemLocator_Release(locator);
    CoUninitialize();
}

static LONG pin_callbacks;
static HANDLE pin_seen;

static void MI_CALL pin_callback(MI_Operation *op, void *context, const MI_Instance *inst, MI_Boolean more,
                                 MI_Result result, const MI_Char *message, const MI_Instance *details,
                                 MI_Result (MI_CALL *ack)(MI_Operation *))
{
    if (InterlockedIncrement(&pin_callbacks) == 1) SetEvent(pin_seen);
    /* never acked: the worker stays parked in mi.dll */
}

/* A worker that is still inside mi.dll keeps the module loaded: the client's last FreeLibrary must not run
 * DllMain (and delete the locks) under it. The worker is parked on an ack that never comes, so this runs
 * last and leaves it behind. */
static void test_unload_pin(MI_Application *app)
{
    static MI_OperationCallbacks cb;
    static MI_Operation op;
    MI_Session session = MI_SESSION_NULL;

    if (app->ft->NewSession(app, NULL, NULL, NULL, NULL, NULL, &session) != MI_RESULT_OK) return;
    pin_seen = CreateEventW(NULL, TRUE, FALSE, NULL);
    memset(&cb, 0, sizeof(cb));
    memset(&op, 0, sizeof(op));
    cb.instanceResult = pin_callback;
    session.ft->EnumerateInstances(&session, MI_OPERATIONFLAGS_MANUAL_ACK_RESULTS, NULL, L"root/cimv2",
                                   L"Win32_Process", MI_FALSE, &cb, &op);
    ok(WaitForSingleObject(pin_seen, 60000) == WAIT_OBJECT_0, "no result delivered\n");
    session.ft->Close(&session, NULL, NULL);
    app->ft->Close(app);
    FreeLibrary(hmi);
    ok(GetModuleHandleW(MI_DLL_NAME) != NULL, "mi.dll was unloaded under a live worker\n");
    hmi = NULL;
}

START_TEST(mi)
{
    MI_Application app = MI_APPLICATION_NULL;
    MI_Instance *ext = NULL;
    MI_Result res;

    if (wcsstr(GetCommandLineW(), STALE_CHILD_ARG))
    {
        Sleep(120000); /* helper process for test_stale_view */
        return;
    }
    hmi = LoadLibraryW(MI_DLL_NAME);
    ok(hmi != NULL, "mi.dll not loaded, error %lu\n", GetLastError());
    if (!hmi) return;
    pMI_Application_InitializeV1 = (PFN_INIT)GetProcAddress(hmi, "MI_Application_InitializeV1");
    pmi_clientFT_V1 = (const MI_ClientFT_V1 **)GetProcAddress(hmi, "mi_clientFT_V1");
    test_exports();
    if (!pMI_Application_InitializeV1 || !pmi_clientFT_V1 || !*pmi_clientFT_V1) return;

    res = pMI_Application_InitializeV1(0, L"mi_apitest", &ext, &app);
    ok(res == MI_RESULT_OK, "MI_Application_InitializeV1 returned %d\n", res);
    ok(ext == NULL, "unexpected extended error\n");
    ok(app.ft != NULL, "no application ft\n");
    if (res || !app.ft) return;

    test_utilities();
    test_instance(&app);
    test_options(&app);
    test_session(&app, NULL);
    test_session(&app, L"WMIDCOM");
    test_filtered_enumeration(&app);
    test_associations(&app);
    test_schema(&app);
    test_method_scope(&app);
    test_concurrent_enumeration(&app);
    test_callback_lifetime(&app);
    test_remote(&app);
    test_app_stale_copy();
    test_stale_view();

    if (running_on_reactos())
    {
        test_unload_pin(&app);
        return;
    }
    res = app.ft->Close(&app);
    ok(res == MI_RESULT_OK, "Application Close returned %d\n", res);
    FreeLibrary(hmi);
}
