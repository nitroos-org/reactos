/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Task Scheduler 2.0: late-bound (IDispatch) access to the scheduler objects
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>

#define COBJMACROS
#include <windef.h>
#include <winbase.h>
#include <objbase.h>
#include <oleauto.h>
#include <initguid.h>
#include <taskschd.h>

#define TASK_NAME L"ReactOS ApiTest Dispatch"

static const WCHAR task_xml[] =
    L"<?xml version=\"1.0\" encoding=\"UTF-16\"?>"
    L"<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">"
    L"<RegistrationInfo><Description>IDispatch test</Description></RegistrationInfo>"
    L"<Settings><Enabled>true</Enabled></Settings>"
    L"<Actions Context=\"Author\"><Exec><Command>cmd.exe</Command><Arguments>/c exit 0</Arguments></Exec></Actions>"
    L"</Task>";

static DISPID get_id(IDispatch *disp, const WCHAR *name)
{
    DISPID id = DISPID_UNKNOWN;
    LPOLESTR names[1];
    HRESULT hr;

    names[0] = (LPOLESTR)name;
    hr = IDispatch_GetIDsOfNames(disp, &IID_NULL, names, 1, LOCALE_USER_DEFAULT, &id);
    ok(hr == S_OK, "GetIDsOfNames(%ls) failed: 0x%lx\n", name, hr);
    return id;
}

static HRESULT invoke(IDispatch *disp, const WCHAR *name, WORD flags, VARIANT *args, UINT nargs, VARIANT *res)
{
    DISPPARAMS params = { args, NULL, nargs, 0 };
    DISPID put = DISPID_PROPERTYPUT;
    EXCEPINFO ei;
    UINT argerr = 0xdeadbeef;
    DISPID id = get_id(disp, name);
    HRESULT hr;

    if (flags & DISPATCH_PROPERTYPUT)
    {
        params.rgdispidNamedArgs = &put;
        params.cNamedArgs = 1;
    }
    memset(&ei, 0, sizeof(ei));
    if (res) VariantInit(res);
    hr = IDispatch_Invoke(disp, id, &IID_NULL, LOCALE_USER_DEFAULT, flags, &params, res, &ei, &argerr);
    if (hr == DISP_E_EXCEPTION)
    {
        SysFreeString(ei.bstrSource);
        SysFreeString(ei.bstrDescription);
        SysFreeString(ei.bstrHelpFile);
    }
    return hr;
}

static void test_typeinfo(IDispatch *disp, const IID *iid, const char *name)
{
    ITypeInfo *ti = NULL, *ti2 = NULL;
    TYPEATTR *attr;
    UINT count = 0;
    HRESULT hr;

    hr = IDispatch_GetTypeInfoCount(disp, &count);
    ok(hr == S_OK, "%s: GetTypeInfoCount failed: 0x%lx\n", name, hr);
    ok(count == 1, "%s: GetTypeInfoCount returned %u\n", name, count);

    hr = IDispatch_GetTypeInfo(disp, 0, LOCALE_USER_DEFAULT, &ti);
    ok(hr == S_OK, "%s: GetTypeInfo failed: 0x%lx\n", name, hr);
    if (hr == S_OK)
    {
        hr = ITypeInfo_GetTypeAttr(ti, &attr);
        ok(hr == S_OK, "%s: GetTypeAttr failed: 0x%lx\n", name, hr);
        if (hr == S_OK)
        {
            ok(IsEqualGUID(&attr->guid, iid), "%s: unexpected typeinfo guid\n", name);
            ITypeInfo_ReleaseTypeAttr(ti, attr);
        }
        ITypeInfo_Release(ti);
    }

    hr = IDispatch_GetTypeInfo(disp, 1, LOCALE_USER_DEFAULT, &ti2);
    ok(hr == DISP_E_BADINDEX, "%s: GetTypeInfo(1) returned 0x%lx\n", name, hr);
    ok(ti2 == NULL, "%s: GetTypeInfo(1) returned a typeinfo\n", name);
}

static void test_names(IDispatch *disp, const char *name)
{
    DISPID ids[2];
    LPOLESTR names[2];
    HRESULT hr;

    names[0] = (LPOLESTR)L"NoSuchMemberAnywhere";
    ids[0] = 0x1234;
    hr = IDispatch_GetIDsOfNames(disp, &IID_NULL, names, 1, LOCALE_USER_DEFAULT, ids);
    ok(hr == DISP_E_UNKNOWNNAME, "%s: unknown name: 0x%lx\n", name, hr);
    ok(ids[0] == DISPID_UNKNOWN, "%s: unknown name id %ld\n", name, ids[0]);

    names[0] = (LPOLESTR)L"Name";
    hr = IDispatch_GetIDsOfNames(disp, (REFIID)&IID_IUnknown, names, 1, LOCALE_USER_DEFAULT, ids);
    ok(hr == DISP_E_UNKNOWNINTERFACE, "%s: non-NULL riid: 0x%lx\n", name, hr);
}

static void test_service(IDispatch *disp)
{
    static const struct { const WCHAR *name; DISPID id; } members[] =
    {
        { L"GetFolder", 1 }, { L"GetRunningTasks", 2 }, { L"NewTask", 3 }, { L"Connect", 4 },
        { L"Connected", 5 }, { L"TargetServer", 6 }, { L"ConnectedUser", 7 }, { L"ConnectedDomain", 8 },
        { L"HighestVersion", 9 },
    };
    LPOLESTR names[2];
    DISPID ids[2];
    VARIANT arg, res;
    unsigned i;
    HRESULT hr;

    test_typeinfo(disp, &IID_ITaskService, "ITaskService");
    test_names(disp, "ITaskService");

    for (i = 0; i < ARRAYSIZE(members); i++)
        ok(get_id(disp, members[i].name) == members[i].id, "%ls: unexpected DISPID\n", members[i].name);
    ok(get_id(disp, L"connect") == 4, "GetIDsOfNames is case sensitive\n");

    /* method name followed by a parameter name */
    names[0] = (LPOLESTR)L"GetFolder";
    names[1] = (LPOLESTR)L"Path";
    hr = IDispatch_GetIDsOfNames(disp, &IID_NULL, names, 2, LOCALE_USER_DEFAULT, ids);
    ok(hr == S_OK, "GetIDsOfNames(GetFolder, Path) failed: 0x%lx\n", hr);
    if (hr == S_OK)
    {
        ok(ids[0] == 1, "GetFolder id %ld\n", ids[0]);
        ok(ids[1] == 0, "Path parameter id %ld\n", ids[1]);
    }

    /* method call with all the optional arguments omitted */
    hr = invoke(disp, L"Connect", DISPATCH_METHOD, NULL, 0, NULL);
    ok(hr == S_OK, "Invoke(Connect) failed: 0x%lx\n", hr);

    hr = invoke(disp, L"Connected", DISPATCH_PROPERTYGET, NULL, 0, &res);
    ok(hr == S_OK, "Invoke(Connected) failed: 0x%lx\n", hr);
    if (hr == S_OK)
    {
        ok(V_VT(&res) == VT_BOOL, "Connected: vt %d\n", V_VT(&res));
        ok(V_BOOL(&res) == VARIANT_TRUE, "Connected is %d\n", V_BOOL(&res));
        VariantClear(&res);
    }

    hr = invoke(disp, L"HighestVersion", DISPATCH_PROPERTYGET, NULL, 0, &res);
    ok(hr == S_OK, "Invoke(HighestVersion) failed: 0x%lx\n", hr);
    if (hr == S_OK)
    {
        ok(V_VT(&res) == VT_I4 || V_VT(&res) == VT_UI4, "HighestVersion: vt %d\n", V_VT(&res));
        ok(V_UI4(&res) >= 0x10001, "HighestVersion is 0x%lx\n", V_UI4(&res));
        VariantClear(&res);
    }

    hr = invoke(disp, L"ConnectedUser", DISPATCH_PROPERTYGET, NULL, 0, &res);
    ok(hr == S_OK, "Invoke(ConnectedUser) failed: 0x%lx\n", hr);
    if (hr == S_OK)
    {
        ok(V_VT(&res) == VT_BSTR && V_BSTR(&res) && V_BSTR(&res)[0], "ConnectedUser: vt %d\n", V_VT(&res));
        VariantClear(&res);
    }

    /* wrong argument count and type */
    hr = invoke(disp, L"GetFolder", DISPATCH_METHOD, NULL, 0, &res);
    ok(hr == DISP_E_BADPARAMCOUNT, "GetFolder without arguments: 0x%lx\n", hr);
    VariantInit(&arg);
    V_VT(&arg) = VT_DISPATCH;
    V_DISPATCH(&arg) = disp;
    hr = invoke(disp, L"GetFolder", DISPATCH_METHOD, &arg, 1, &res);
    ok(hr == DISP_E_TYPEMISMATCH, "GetFolder(IDispatch): 0x%lx\n", hr);
}

static IDispatch *get_dispatch_result(HRESULT hr, VARIANT *res, const char *what)
{
    IDispatch *disp = NULL;

    ok(hr == S_OK, "%s failed: 0x%lx\n", what, hr);
    if (hr != S_OK) return NULL;
    ok(V_VT(res) == VT_DISPATCH, "%s: vt %d\n", what, V_VT(res));
    if (V_VT(res) == VT_DISPATCH && V_DISPATCH(res))
    {
        disp = V_DISPATCH(res);
        IDispatch_AddRef(disp);
    }
    VariantClear(res);
    return disp;
}

static void test_collection(IDispatch *coll, const WCHAR *expect_name)
{
    VARIANT res, arg;
    IEnumVARIANT *enumvar = NULL;
    IUnknown *unk;
    BOOL found = FALSE;
    LONG count = -1;
    ULONG fetched;
    HRESULT hr;

    test_typeinfo(coll, &IID_IRegisteredTaskCollection, "IRegisteredTaskCollection");

    ok(get_id(coll, L"Count") == 1, "Count: unexpected DISPID\n");
    ok(get_id(coll, L"Item") == DISPID_VALUE, "Item: unexpected DISPID\n");
    ok(get_id(coll, L"_NewEnum") == DISPID_NEWENUM, "_NewEnum: unexpected DISPID\n");

    hr = invoke(coll, L"Count", DISPATCH_PROPERTYGET, NULL, 0, &res);
    ok(hr == S_OK, "Invoke(Count) failed: 0x%lx\n", hr);
    if (hr == S_OK)
    {
        ok(V_VT(&res) == VT_I4, "Count: vt %d\n", V_VT(&res));
        count = V_I4(&res);
    }
    ok(count >= 1, "Count is %ld\n", count);

    /* the default member is Item(index) */
    VariantInit(&arg);
    V_VT(&arg) = VT_I4;
    V_I4(&arg) = 1;
    VariantInit(&res);
    {
        DISPPARAMS params = { &arg, NULL, 1, 0 };
        hr = IDispatch_Invoke(coll, DISPID_VALUE, &IID_NULL, LOCALE_USER_DEFAULT,
                              DISPATCH_METHOD | DISPATCH_PROPERTYGET, &params, &res, NULL, NULL);
    }
    ok(hr == S_OK, "Invoke(DISPID_VALUE, 1) failed: 0x%lx\n", hr);
    if (hr == S_OK) VariantClear(&res);

    /* For Each */
    hr = invoke(coll, L"_NewEnum", DISPATCH_PROPERTYGET, NULL, 0, &res);
    ok(hr == S_OK, "Invoke(_NewEnum) failed: 0x%lx\n", hr);
    if (hr != S_OK) return;
    ok(V_VT(&res) == VT_UNKNOWN || V_VT(&res) == VT_DISPATCH, "_NewEnum: vt %d\n", V_VT(&res));
    unk = V_UNKNOWN(&res);
    hr = unk ? IUnknown_QueryInterface(unk, &IID_IEnumVARIANT, (void **)&enumvar) : E_FAIL;
    ok(hr == S_OK, "QueryInterface(IEnumVARIANT) failed: 0x%lx\n", hr);
    VariantClear(&res);
    if (!enumvar) return;
    for (;;)
    {
        VARIANT item;

        VariantInit(&item);
        fetched = 0;
        hr = IEnumVARIANT_Next(enumvar, 1, &item, &fetched);
        if (hr != S_OK || !fetched) break;
        if (V_VT(&item) == VT_DISPATCH)
        {
            hr = invoke(V_DISPATCH(&item), L"Name", DISPATCH_PROPERTYGET, NULL, 0, &res);
            if (hr == S_OK)
            {
                if (V_VT(&res) == VT_BSTR && !wcscmp(V_BSTR(&res), expect_name)) found = TRUE;
                VariantClear(&res);
            }
        }
        VariantClear(&item);
    }
    ok(found, "task %ls not enumerated by _NewEnum\n", expect_name);
    IEnumVARIANT_Release(enumvar);
}

static void test_task(IDispatch *task)
{
    VARIANT res, arg;
    HRESULT hr;

    test_typeinfo(task, &IID_IRegisteredTask, "IRegisteredTask");
    test_names(task, "IRegisteredTask");

    ok(get_id(task, L"Name") == 1, "Name: unexpected DISPID\n");
    ok(get_id(task, L"State") == 3, "State: unexpected DISPID\n");
    ok(get_id(task, L"Enabled") == 4, "Enabled: unexpected DISPID\n");
    ok(get_id(task, L"Run") == 5, "Run: unexpected DISPID\n");
    ok(get_id(task, L"LastTaskResult") == 9, "LastTaskResult: unexpected DISPID\n");

    hr = invoke(task, L"Name", DISPATCH_PROPERTYGET, NULL, 0, &res);
    ok(hr == S_OK, "Invoke(Name) failed: 0x%lx\n", hr);
    if (hr == S_OK)
    {
        ok(V_VT(&res) == VT_BSTR && !wcscmp(V_BSTR(&res), TASK_NAME), "Name: vt %d\n", V_VT(&res));
        VariantClear(&res);
    }

    hr = invoke(task, L"Xml", DISPATCH_PROPERTYGET, NULL, 0, &res);
    ok(hr == S_OK, "Invoke(Xml) failed: 0x%lx\n", hr);
    if (hr == S_OK)
    {
        ok(V_VT(&res) == VT_BSTR && wcsstr(V_BSTR(&res), L"cmd.exe"), "Xml: vt %d\n", V_VT(&res));
        VariantClear(&res);
    }

    hr = invoke(task, L"State", DISPATCH_PROPERTYGET, NULL, 0, &res);
    ok(hr == S_OK, "Invoke(State) failed: 0x%lx\n", hr);
    if (hr == S_OK)
    {
        ok(V_VT(&res) == VT_I4, "State: vt %d\n", V_VT(&res));
        ok(V_I4(&res) == TASK_STATE_READY, "State is %ld\n", V_I4(&res));
    }

    /* property put */
    VariantInit(&arg);
    V_VT(&arg) = VT_BOOL;
    V_BOOL(&arg) = VARIANT_FALSE;
    hr = invoke(task, L"Enabled", DISPATCH_PROPERTYPUT, &arg, 1, NULL);
    ok(hr == S_OK, "Invoke(Enabled = False) failed: 0x%lx\n", hr);
    hr = invoke(task, L"Enabled", DISPATCH_PROPERTYGET, NULL, 0, &res);
    ok(hr == S_OK, "Invoke(Enabled) failed: 0x%lx\n", hr);
    if (hr == S_OK)
    {
        ok(V_VT(&res) == VT_BOOL && V_BOOL(&res) == VARIANT_FALSE, "Enabled: vt %d value %d\n", V_VT(&res), V_BOOL(&res));
        VariantClear(&res);
    }
    hr = invoke(task, L"State", DISPATCH_PROPERTYGET, NULL, 0, &res);
    ok(hr == S_OK && V_I4(&res) == TASK_STATE_DISABLED, "State after disable: 0x%lx %ld\n", hr, V_I4(&res));
    V_BOOL(&arg) = VARIANT_TRUE;
    hr = invoke(task, L"Enabled", DISPATCH_PROPERTYPUT, &arg, 1, NULL);
    ok(hr == S_OK, "Invoke(Enabled = True) failed: 0x%lx\n", hr);

    /* method call with a VARIANT argument */
    VariantInit(&arg);
    hr = invoke(task, L"Run", DISPATCH_METHOD, &arg, 1, &res);
    ok(hr == S_OK, "Invoke(Run) failed: 0x%lx\n", hr);
    if (hr == S_OK) VariantClear(&res);

    hr = invoke(task, L"LastTaskResult", DISPATCH_PROPERTYGET, NULL, 0, &res);
    ok(hr == S_OK, "Invoke(LastTaskResult) failed: 0x%lx\n", hr);
    if (hr == S_OK)
    {
        ok(V_VT(&res) == VT_I4, "LastTaskResult: vt %d\n", V_VT(&res));
        VariantClear(&res);
    }
}

static void test_folder(IDispatch *folder)
{
    VARIANT args[7], res;
    IDispatch *task, *coll;
    HRESULT hr;

    test_typeinfo(folder, &IID_ITaskFolder, "ITaskFolder");
    test_names(folder, "ITaskFolder");

    ok(get_id(folder, L"Name") == 1, "Name: unexpected DISPID\n");
    ok(get_id(folder, L"Path") == 2, "Path: unexpected DISPID\n");
    ok(get_id(folder, L"GetTask") == 7, "GetTask: unexpected DISPID\n");
    ok(get_id(folder, L"GetTasks") == 8, "GetTasks: unexpected DISPID\n");
    ok(get_id(folder, L"DeleteTask") == 9, "DeleteTask: unexpected DISPID\n");
    ok(get_id(folder, L"RegisterTask") == 10, "RegisterTask: unexpected DISPID\n");

    hr = invoke(folder, L"Path", DISPATCH_PROPERTYGET, NULL, 0, &res);
    ok(hr == S_OK, "Invoke(Path) failed: 0x%lx\n", hr);
    if (hr == S_OK)
    {
        ok(V_VT(&res) == VT_BSTR && !wcscmp(V_BSTR(&res), L"\\"), "Path: vt %d\n", V_VT(&res));
        VariantClear(&res);
    }
    hr = invoke(folder, L"Name", DISPATCH_PROPERTYGET, NULL, 0, &res);
    ok(hr == S_OK, "Invoke(Name) failed: 0x%lx\n", hr);
    if (hr == S_OK)
    {
        ok(V_VT(&res) == VT_BSTR, "Name: vt %d\n", V_VT(&res));
        VariantClear(&res);
    }

    /* a leftover of an aborted run */
    VariantInit(&args[1]);
    V_VT(&args[1]) = VT_BSTR;
    V_BSTR(&args[1]) = SysAllocString(TASK_NAME);
    VariantInit(&args[0]);
    V_VT(&args[0]) = VT_I4;
    V_I4(&args[0]) = 0;
    invoke(folder, L"DeleteTask", DISPATCH_METHOD, args, 2, NULL);
    /* arguments are passed last to first: RegisterTask(path, xml, flags, userId, password, logonType, sddl) */
    memset(args, 0, sizeof(args));
    V_VT(&args[6]) = VT_BSTR;  V_BSTR(&args[6]) = SysAllocString(TASK_NAME);
    V_VT(&args[5]) = VT_BSTR;  V_BSTR(&args[5]) = SysAllocString(task_xml);
    V_VT(&args[4]) = VT_I4;    V_I4(&args[4]) = TASK_CREATE;
    V_VT(&args[3]) = VT_EMPTY;
    V_VT(&args[2]) = VT_EMPTY;
    V_VT(&args[1]) = VT_I4;    V_I4(&args[1]) = TASK_LOGON_INTERACTIVE_TOKEN;
    V_VT(&args[0]) = VT_EMPTY;
    hr = invoke(folder, L"RegisterTask", DISPATCH_METHOD, args, 7, &res);
    task = get_dispatch_result(hr, &res, "Invoke(RegisterTask)");
    SysFreeString(V_BSTR(&args[6]));
    SysFreeString(V_BSTR(&args[5]));
    if (!task) return;

    test_task(task);
    IDispatch_Release(task);

    /* GetTask(name) returns the same task */
    VariantInit(&args[0]);
    V_VT(&args[0]) = VT_BSTR;
    V_BSTR(&args[0]) = SysAllocString(TASK_NAME);
    hr = invoke(folder, L"GetTask", DISPATCH_METHOD, args, 1, &res);
    task = get_dispatch_result(hr, &res, "Invoke(GetTask)");
    if (task) IDispatch_Release(task);

    /* an HRESULT error of the method comes back to the caller */
    SysFreeString(V_BSTR(&args[0]));
    V_BSTR(&args[0]) = SysAllocString(L"No Such Task ReactOS");
    hr = invoke(folder, L"GetTask", DISPATCH_METHOD, args, 1, &res);
    ok(hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) || hr == DISP_E_EXCEPTION, "GetTask(missing): 0x%lx\n", hr);
    SysFreeString(V_BSTR(&args[0]));

    VariantInit(&args[0]);
    V_VT(&args[0]) = VT_I4;
    V_I4(&args[0]) = 0;
    hr = invoke(folder, L"GetTasks", DISPATCH_METHOD, args, 1, &res);
    coll = get_dispatch_result(hr, &res, "Invoke(GetTasks)");
    if (coll)
    {
        test_collection(coll, TASK_NAME);
        IDispatch_Release(coll);
    }

    V_VT(&args[1]) = VT_BSTR;
    V_BSTR(&args[1]) = SysAllocString(TASK_NAME);
    V_VT(&args[0]) = VT_I4;
    V_I4(&args[0]) = 0;
    hr = invoke(folder, L"DeleteTask", DISPATCH_METHOD, args, 2, NULL);
    ok(hr == S_OK, "Invoke(DeleteTask) failed: 0x%lx\n", hr);
    SysFreeString(V_BSTR(&args[1]));
}

START_TEST(TaskSchedulerDispatch)
{
    IDispatch *service = NULL, *folder = NULL;
    VARIANT arg, res;
    HRESULT hr;

    hr = CoInitialize(NULL);
    ok(hr == S_OK, "CoInitialize failed: 0x%lx\n", hr);

    hr = CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, &IID_IDispatch, (void **)&service);
    if (hr != S_OK)
    {
        skip("Task Scheduler is not available (0x%lx)\n", hr);
        goto out;
    }

    test_service(service);

    VariantInit(&arg);
    V_VT(&arg) = VT_BSTR;
    V_BSTR(&arg) = SysAllocString(L"\\");
    hr = invoke(service, L"GetFolder", DISPATCH_METHOD, &arg, 1, &res);
    folder = get_dispatch_result(hr, &res, "Invoke(GetFolder)");
    SysFreeString(V_BSTR(&arg));
    if (folder)
    {
        test_folder(folder);
        IDispatch_Release(folder);
    }

    IDispatch_Release(service);
out:
    CoUninitialize();
}
