/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test that a COM apartment that is made remotable leaves no handles behind when it ends
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Every single-threaded apartment that exports an object is reachable from other apartments. Windows
 * serves all apartments of a process through one endpoint, so apartments that are called from another
 * apartment and then end do not raise the process handle count (measured on Windows 10 22H2, x64 and x86).
 * The shell runs each folder window in such an apartment.
 */

#define COBJMACROS
#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#include <objbase.h>

#define THREADS 50

/* A plain object without IMarshal, so that it is marshaled by the standard marshaler */
static HRESULT WINAPI Test_QueryInterface(IUnknown *iface, REFIID riid, void **ppv)
{
    if (IsEqualIID(riid, &IID_IUnknown))
    {
        *ppv = iface;
        return S_OK;
    }
    *ppv = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI Test_AddRef(IUnknown *iface)
{
    return 2;
}

static ULONG WINAPI Test_Release(IUnknown *iface)
{
    return 1;
}

static IUnknownVtbl Test_Vtbl = { Test_QueryInterface, Test_AddRef, Test_Release };

struct apartment_params
{
    HANDLE ready, done;
    IStream *marshaled;
    HRESULT hr;
};

/* A single-threaded apartment that exports an object and serves calls until it is told to end */
static DWORD WINAPI apartment_thread(LPVOID param)
{
    struct apartment_params *params = param;
    IUnknown object = { &Test_Vtbl };
    MSG msg;

    params->hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (SUCCEEDED(params->hr))
        params->hr = CoMarshalInterThreadInterfaceInStream(&IID_IUnknown, &object, &params->marshaled);
    SetEvent(params->ready);
    if (SUCCEEDED(params->hr))
    {
        while (MsgWaitForMultipleObjects(1, &params->done, FALSE, 30000, QS_ALLINPUT) == WAIT_OBJECT_0 + 1)
        {
            while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
                DispatchMessageW(&msg);
        }
    }
    CoUninitialize();
    return 0;
}

/* Starts count apartments at once (so that each has its own thread id), calls into each from this one,
 * then lets them all end; returns the number of apartments that could not be called */
static int run_apartments(int count)
{
    struct apartment_params params[THREADS];
    HANDLE threads[THREADS];
    IUnknown *proxy, *unk;
    int i, failed = 0;
    HRESULT hr;

    for (i = 0; i < count; i++)
    {
        params[i].ready = CreateEventW(NULL, FALSE, FALSE, NULL);
        params[i].done = CreateEventW(NULL, TRUE, FALSE, NULL);
        params[i].marshaled = NULL;
        params[i].hr = E_FAIL;
        threads[i] = CreateThread(NULL, 0, apartment_thread, &params[i], 0, NULL);
        if (threads[i])
            WaitForSingleObject(params[i].ready, 30000);
    }

    for (i = 0; i < count; i++)
    {
        proxy = NULL;
        hr = threads[i] ? params[i].hr : E_FAIL;
        if (SUCCEEDED(hr))
            hr = CoGetInterfaceAndReleaseStream(params[i].marshaled, &IID_IUnknown, (void **)&proxy);
        if (SUCCEEDED(hr))
        {
            /* A remote QueryInterface: a call over the apartment's endpoint */
            hr = IUnknown_QueryInterface(proxy, &IID_IStream, (void **)&unk);
            if (SUCCEEDED(hr))
                IUnknown_Release(unk);
            IUnknown_Release(proxy);
        }
        if (hr != E_NOINTERFACE)
            failed++;
    }

    for (i = 0; i < count; i++)
    {
        SetEvent(params[i].done);
        if (threads[i])
        {
            WaitForSingleObject(threads[i], 30000);
            CloseHandle(threads[i]);
        }
        CloseHandle(params[i].ready);
        CloseHandle(params[i].done);
    }
    return failed;
}

START_TEST(ApartmentEndpoint)
{
    IUnknown object = { &Test_Vtbl };
    IStream *exported = NULL;
    DWORD before = 0, after = 0;
    int failed;
    HRESULT hr;

    /* Keep one object exported for the whole test, as a long-running process does: the RPC runtime then
     * keeps listening, so the endpoints of the apartments below stay open as long as they are registered */
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ok(hr == S_OK, "CoInitializeEx failed: 0x%08lx\n", hr);
    hr = CreateStreamOnHGlobal(NULL, TRUE, &exported);
    ok(hr == S_OK, "CreateStreamOnHGlobal failed: 0x%08lx\n", hr);
    if (FAILED(hr))
    {
        CoUninitialize();
        return;
    }
    hr = CoMarshalInterface(exported, &IID_IUnknown, &object, MSHCTX_INPROC, NULL, MSHLFLAGS_TABLESTRONG);
    ok(hr == S_OK, "CoMarshalInterface failed: 0x%08lx\n", hr);

    /* The process-wide parts (RPC runtime, the first endpoint) are made by the first apartments */
    ok(run_apartments(3) == 0, "warm-up apartments failed\n");

    ok(GetProcessHandleCount(GetCurrentProcess(), &before), "GetProcessHandleCount failed: %lu\n", GetLastError());
    failed = run_apartments(THREADS);
    ok(GetProcessHandleCount(GetCurrentProcess(), &after), "GetProcessHandleCount failed: %lu\n", GetLastError());

    ok(failed == 0, "%d of %d calls into another apartment failed\n", failed, THREADS);
    ok((LONG)(after - before) <= 4, "%d remotable apartments changed the handle count from %lu to %lu\n",
       THREADS, before, after);

    if (SUCCEEDED(hr))
    {
        LARGE_INTEGER zero = {{0, 0}};
        IStream_Seek(exported, zero, STREAM_SEEK_SET, NULL);
        CoReleaseMarshalData(exported);
    }
    IStream_Release(exported);
    CoUninitialize();
}
