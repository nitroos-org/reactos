/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test that a client of a local (EXE) COM server is given the class soon after the server registers it
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Edge Update (Omaha) starts its update service and then activates a class that the service serves. COM
 * starts the server, finds the class missing and asks again: a fixed pause of one second between the asks,
 * during which the update worker that the service started had taken the install lock the handoff needed,
 * so every install of the WebView2 runtime failed with "another application is being installed". The
 * activation is complete as soon as the server has registered its class object: the test registers one at
 * once after the server starts and measures how long the client takes after that.
 */

#define COBJMACROS
#include <apitest.h>
#include <stdio.h>
#include <string.h>
#include <windef.h>
#include <winbase.h>
#include <objbase.h>

static const GUID CLSID_LocalServerStartup =
    { 0x6b2d1a40, 0x7f19, 0x4a35, { 0x8c, 0x0d, 0x4c, 0x6f, 0x63, 0x61, 0x6c, 0x01 } };

#define EVENT_REGISTERED "ReactOS_combase_apitest_LocalServerStartup_registered"
#define EVENT_DONE       "ReactOS_combase_apitest_LocalServerStartup_done"

/* The server: a factory that makes nothing, registered as soon as the process runs */
static HRESULT WINAPI Factory_QueryInterface(IClassFactory *iface, REFIID riid, void **ppv)
{
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IClassFactory))
    {
        *ppv = iface;
        return S_OK;
    }
    *ppv = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI Factory_AddRef(IClassFactory *iface)
{
    return 2;
}

static ULONG WINAPI Factory_Release(IClassFactory *iface)
{
    return 1;
}

static HRESULT WINAPI Factory_CreateInstance(IClassFactory *iface, IUnknown *outer, REFIID riid, void **ppv)
{
    *ppv = NULL;
    return E_NOTIMPL;
}

static HRESULT WINAPI Factory_LockServer(IClassFactory *iface, BOOL lock)
{
    return S_OK;
}

static IClassFactoryVtbl FactoryVtbl =
{
    Factory_QueryInterface,
    Factory_AddRef,
    Factory_Release,
    Factory_CreateInstance,
    Factory_LockServer
};

static IClassFactory g_factory = { &FactoryVtbl };

static void run_server(void)
{
    HANDLE registered, done;
    DWORD cookie;
    HRESULT hr;

    CoInitializeEx(NULL, COINIT_MULTITHREADED);
    registered = OpenEventA(EVENT_MODIFY_STATE, FALSE, EVENT_REGISTERED);
    done = OpenEventA(SYNCHRONIZE, FALSE, EVENT_DONE);
    if (registered && done)
    {
        SetEvent(registered);
        hr = CoRegisterClassObject(&CLSID_LocalServerStartup, (IUnknown *)&g_factory, CLSCTX_LOCAL_SERVER,
                                   REGCLS_MULTIPLEUSE, &cookie);
        if (SUCCEEDED(hr))
        {
            WaitForSingleObject(done, 30000);
            CoRevokeClassObject(cookie);
        }
    }
    if (registered) CloseHandle(registered);
    if (done) CloseHandle(done);
    CoUninitialize();
}

static BOOL set_registry(BOOL create)
{
    char guid[64], key[200], path[MAX_PATH], command[MAX_PATH + 64];
    LPOLESTR wide;
    HKEY hkey;
    LONG ret;

    StringFromCLSID(&CLSID_LocalServerStartup, &wide);
    WideCharToMultiByte(CP_ACP, 0, wide, -1, guid, sizeof(guid), NULL, NULL);
    CoTaskMemFree(wide);
    sprintf(key, "SOFTWARE\\Classes\\CLSID\\%s\\LocalServer32", guid);

    if (!create)
    {
        RegDeleteKeyA(HKEY_LOCAL_MACHINE, key);
        sprintf(key, "SOFTWARE\\Classes\\CLSID\\%s", guid);
        RegDeleteKeyA(HKEY_LOCAL_MACHINE, key);
        return TRUE;
    }

    GetModuleFileNameA(NULL, path, sizeof(path));
    sprintf(command, "\"%s\" LocalServerStartup server", path);
    ret = RegCreateKeyExA(HKEY_LOCAL_MACHINE, key, 0, NULL, 0, KEY_WRITE, NULL, &hkey, NULL);
    if (ret)
        return FALSE;
    ret = RegSetValueExA(hkey, NULL, 0, REG_SZ, (const BYTE *)command, strlen(command) + 1);
    RegCloseKey(hkey);
    return ret == 0;
}

static DWORD g_registered_ticks;

static DWORD WINAPI wait_registered(void *param)
{
    if (WaitForSingleObject((HANDLE)param, 30000) == WAIT_OBJECT_0)
        g_registered_ticks = GetTickCount();
    return 0;
}

static void test_client(void)
{
    HANDLE registered, done, thread;
    IClassFactory *factory = NULL;
    DWORD returned_ticks;
    LONG latency;
    HRESULT hr;

    registered = CreateEventA(NULL, TRUE, FALSE, EVENT_REGISTERED);
    done = CreateEventA(NULL, TRUE, FALSE, EVENT_DONE);
    if (!registered || !done || !set_registry(TRUE))
    {
        skip("cannot register the test server (%lu)\n", GetLastError());
        goto cleanup;
    }

    thread = CreateThread(NULL, 0, wait_registered, registered, 0, NULL);
    hr = CoGetClassObject(&CLSID_LocalServerStartup, CLSCTX_LOCAL_SERVER, NULL, &IID_IClassFactory, (void **)&factory);
    returned_ticks = GetTickCount();
    ok(hr == S_OK, "CoGetClassObject returned %#lx\n", hr);
    if (hr == S_OK)
        IClassFactory_Release(factory);

    WaitForSingleObject(thread, 5000);
    CloseHandle(thread);
    latency = (LONG)(returned_ticks - g_registered_ticks);
    trace("the class was returned %ld ms after the server registered it\n", latency);
    ok(g_registered_ticks != 0, "the server did not start\n");
    /* the server is up some hundreds of milliseconds after the start: a client that polls once a second
     * gets the class 700 ms or more after that, one that polls every 100 ms or less within 150 ms */
    ok(latency < 400, "CoGetClassObject returned %ld ms after the server registered its class\n", latency);

cleanup:
    if (done) SetEvent(done);
    Sleep(500);
    set_registry(FALSE);
    if (registered) CloseHandle(registered);
    if (done) CloseHandle(done);
}

START_TEST(LocalServerStartup)
{
    if (strstr(GetCommandLineA(), " server"))
    {
        run_server();
        return;
    }

    CoInitializeEx(NULL, COINIT_MULTITHREADED);
    test_client();
    CoUninitialize();
}
