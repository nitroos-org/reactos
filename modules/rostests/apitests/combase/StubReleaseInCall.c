/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test that a call returns when its last reference to the stub of the object is released by the call
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * When the last external reference of an exported object goes away while a call into the object is
 * running (the Click-To-Run client releases the BITS callback while BITS is still inside
 * IBackgroundCopyCallback::JobTransferred), the stub is deleted by the thread that dispatches that
 * call, when the call returns. Deleting the stub unregisters the RPC interface of the call. Waiting for
 * the running calls of the interface there made the dispatching thread wait for itself, with the lock
 * of the registered interfaces held: the call never returned and every other marshal of the process
 * blocked. Windows does not wait.
 */

#define COBJMACROS
#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#include <objbase.h>

#define CALL_TIMEOUT 20000

static IStream *g_stream;
static HRESULT g_release_hr = E_FAIL, g_unmarshal_hr = E_FAIL, g_call_hr = E_FAIL;

/* An IPersist (a simple interface that has a proxy and a stub in ole32) */
static HRESULT WINAPI Persist_QueryInterface(IPersist *iface, REFIID riid, void **ppv)
{
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IPersist))
    {
        *ppv = iface;
        return S_OK;
    }
    *ppv = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI Persist_AddRef(IPersist *iface)
{
    return 2;
}

static ULONG WINAPI Persist_Release(IPersist *iface)
{
    return 1;
}

/* The call: it gives back the references that the marshaled pointer holds (what BITS does with
 * RemRelease when it drops the callback), so the stub goes away as soon as this call returns */
static HRESULT WINAPI Persist_GetClassID(IPersist *iface, CLSID *clsid)
{
    LARGE_INTEGER zero = { { 0 } };

    IStream_Seek(g_stream, zero, STREAM_SEEK_SET, NULL);
    g_release_hr = CoReleaseMarshalData(g_stream);
    *clsid = CLSID_NULL;
    return S_OK;
}

static IPersistVtbl Persist_Vtbl =
{
    Persist_QueryInterface,
    Persist_AddRef,
    Persist_Release,
    Persist_GetClassID,
};

static DWORD WINAPI client_thread(LPVOID param)
{
    LARGE_INTEGER zero = { { 0 } };
    IPersist *proxy = NULL;
    HRESULT hr;

    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr))
        return hr;

    IStream_Seek(g_stream, zero, STREAM_SEEK_SET, NULL);
    hr = g_unmarshal_hr = CoUnmarshalInterface(g_stream, &IID_IPersist, (void **)&proxy);
    if (SUCCEEDED(hr))
    {
        CLSID clsid;

        hr = g_call_hr = IPersist_GetClassID(proxy, &clsid);
        IPersist_Release(proxy);
    }
    CoUninitialize();
    return hr;
}

START_TEST(StubReleaseInCall)
{
    IPersist object = { &Persist_Vtbl };
    HANDLE thread;
    DWORD wait, exit_code;
    HRESULT hr;

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ok(hr == S_OK, "CoInitializeEx returned %08lx\n", hr);

    hr = CreateStreamOnHGlobal(NULL, TRUE, &g_stream);
    ok(hr == S_OK, "CreateStreamOnHGlobal returned %08lx\n", hr);
    hr = CoMarshalInterface(g_stream, &IID_IPersist, (IUnknown *)&object, MSHCTX_LOCAL, NULL,
                            MSHLFLAGS_NORMAL);
    ok(hr == S_OK, "CoMarshalInterface returned %08lx\n", hr);
    if (hr != S_OK)
        return;

    thread = CreateThread(NULL, 0, client_thread, NULL, 0, NULL);
    ok(thread != NULL, "CreateThread failed: %lu\n", GetLastError());
    if (!thread)
        return;

    wait = WaitForSingleObject(thread, CALL_TIMEOUT);
    ok(wait == WAIT_OBJECT_0, "the call into the object did not return (wait result %lu)\n", wait);
    if (wait == WAIT_OBJECT_0)
    {
        GetExitCodeThread(thread, &exit_code);
        ok(g_unmarshal_hr == S_OK, "CoUnmarshalInterface returned %08lx\n", g_unmarshal_hr);
        ok(g_call_hr == S_OK, "GetClassID returned %08lx\n", g_call_hr);
        ok(exit_code == S_OK, "the client returned %08lx\n", exit_code);
        ok(g_release_hr == S_OK, "CoReleaseMarshalData returned %08lx\n", g_release_hr);
        CloseHandle(thread);
        IStream_Release(g_stream);
        CoUninitialize();
    }
    /* else: the dispatching thread still holds the lock of the registered interfaces, ending COM would hang */
}
