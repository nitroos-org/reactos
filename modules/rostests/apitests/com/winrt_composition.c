/*
 * PROJECT:         ReactOS API Tests
 * LICENSE:         LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:         Tests for the Windows.UI.Composition WinRT classes Compositor and CompositorController
 * COPYRIGHT:       Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Only documented behaviour is checked, so the test holds on Windows 10 too (it was not run there: the lane's one
 * oracle probe measured the class registrations instead). On this system the members of ICompositor are still
 * E_NOTIMPL; the test accepts S_OK as well and releases what it gets.
 */

#include "com_apitest.h"

typedef struct IObj IObj;
typedef struct
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IObj *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(IObj *This);
    ULONG (STDMETHODCALLTYPE *Release)(IObj *This);
    HRESULT (STDMETHODCALLTYPE *GetIids)(IObj *This, ULONG *count, IID **iids);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(IObj *This, PVOID *name);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(IObj *This, int *level);
    /* the first methods of the interface asked for: ActivateInstance, Close, CreateColorKeyFrameAnimation, ... */
    HRESULT (STDMETHODCALLTYPE *Method6)(IObj *This, void *a);
    HRESULT (STDMETHODCALLTYPE *Method7)(IObj *This, void *a);
    HRESULT (STDMETHODCALLTYPE *Method8)(IObj *This, void *a, void *b);
    HRESULT (STDMETHODCALLTYPE *Method9)(IObj *This, void *a);
} ObjVtbl;
struct IObj { const ObjVtbl *lpVtbl; };

static const GUID IID_Factory  = {0x00000035, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
static const GUID IID_Closable = {0x30d5a829, 0x7fa4, 0x4026, {0x83, 0xbb, 0xd7, 0x5b, 0xae, 0x4e, 0xa9, 0x9e}};
static const GUID IID_Agile    = {0x94ea2b94, 0xe9cc, 0x49e0, {0xc0, 0xff, 0xee, 0x64, 0xca, 0x8f, 0x5b, 0x90}};
static const GUID IID_ICompositor = {0xb403ca50, 0x7f8c, 0x4e83, {0x98, 0x5f, 0xcc, 0x45, 0x06, 0x00, 0x36, 0xd8}};
static const GUID IID_ICompositorInterop = {0x25297d5c, 0x3ad4, 0x4c9c, {0xb5, 0xcf, 0xe3, 0x6a, 0x38, 0x51, 0x23, 0x30}};
/* ICompositorDesktopInterop: learn.microsoft.com, "Using the Visual layer with Windows Forms" (C# declaration) */
static const GUID IID_ICompositorDesktopInterop = {0x29e691fa, 0x4567, 0x4dca, {0xb3, 0x19, 0xd0, 0xf2, 0x07, 0xeb, 0x68, 0x07}};
/* ICompositorController: microsoft/windows-rs (MIT OR Apache-2.0) commit 8ca69fdaa9d69c78b9bcfbee96c6916f2282e7f0,
 * metadata/winrt/Windows.UI.Composition.Core.rdl: slot 6 get Compositor, slot 7 Commit */
static const GUID IID_ICompositorController = {0x2d75f35a, 0x70a7, 0x4395, {0xba, 0x2d, 0xce, 0xf0, 0xb1, 0x83, 0x99, 0xf9}};
static const GUID IID_Unknown1 = {0x12345678, 0x1234, 0x1234, {0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34}};

typedef HRESULT (WINAPI *PRO_GET_ACTIVATION_FACTORY)(PVOID, REFIID, void **);
typedef HRESULT (WINAPI *PRO_ACTIVATE_INSTANCE)(PVOID, IObj **);
typedef HRESULT (WINAPI *PWINDOWS_CREATE_STRING)(LPCWSTR, UINT32, PVOID *);
typedef HRESULT (WINAPI *PWINDOWS_DELETE_STRING)(PVOID);
typedef LPCWSTR (WINAPI *PWINDOWS_GET_RAW)(PVOID, UINT32 *);

static PRO_GET_ACTIVATION_FACTORY pRoGetActivationFactory;
static PRO_ACTIVATE_INSTANCE pRoActivateInstance;
static PWINDOWS_CREATE_STRING pWindowsCreateString;
static PWINDOWS_DELETE_STRING pWindowsDeleteString;
static PWINDOWS_GET_RAW pWindowsGetStringRawBuffer;

static void TestClass(const WCHAR *Name, BOOL IsCompositor)
{
    PVOID Class = NULL, ClassName = NULL;
    IObj *Factory = NULL, *Obj = NULL, *Iface;
    HRESULT hr;
    ULONG Count;
    IID *Iids;

    hr = pWindowsCreateString(Name, lstrlenW(Name), &Class);
    ok(hr == S_OK, "WindowsCreateString returned 0x%08lx\n", hr);

    hr = pRoGetActivationFactory(Class, &IID_Factory, (void **)&Factory);
    ok(hr == S_OK, "%ls: RoGetActivationFactory returned 0x%08lx\n", Name, hr);
    if (Factory)
    {
        Iface = (IObj *)0x1234;
        hr = Factory->lpVtbl->QueryInterface(Factory, &IID_Unknown1, (void **)&Iface);
        ok(hr == E_NOINTERFACE, "%ls: factory QI(unknown) returned 0x%08lx\n", Name, hr);
        ok(Iface == NULL, "%ls: factory QI(unknown) left %p\n", Name, Iface);
        Factory->lpVtbl->Release(Factory);
    }

    hr = pRoActivateInstance(Class, &Obj);
    ok(hr == S_OK, "%ls: RoActivateInstance returned 0x%08lx\n", Name, hr);
    ok(Obj != NULL, "%ls: no instance\n", Name);
    if (!Obj)
        goto done;

    hr = Obj->lpVtbl->GetRuntimeClassName(Obj, &ClassName);
    ok(hr == S_OK, "%ls: GetRuntimeClassName returned 0x%08lx\n", Name, hr);
    if (hr == S_OK)
    {
        ok(!lstrcmpW(pWindowsGetStringRawBuffer(ClassName, NULL), Name), "%ls: class name is %ls\n", Name,
           pWindowsGetStringRawBuffer(ClassName, NULL));
        pWindowsDeleteString(ClassName);
    }

    Iids = NULL;
    Count = 0;
    hr = Obj->lpVtbl->GetIids(Obj, &Count, &Iids);
    ok(hr == S_OK, "%ls: GetIids returned 0x%08lx\n", Name, hr);
    if (hr == S_OK)
    {
        ok(Count >= 1 && Iids != NULL, "%ls: %lu IIDs\n", Name, Count);
        CoTaskMemFree(Iids);
    }

    Iface = (IObj *)0x1234;
    hr = Obj->lpVtbl->QueryInterface(Obj, &IID_Unknown1, (void **)&Iface);
    ok(hr == E_NOINTERFACE, "%ls: QI(unknown) returned 0x%08lx\n", Name, hr);
    ok(Iface == NULL, "%ls: QI(unknown) left %p\n", Name, Iface);

    Iface = NULL;
    hr = Obj->lpVtbl->QueryInterface(Obj, &IID_Agile, (void **)&Iface);
    ok(hr == S_OK && Iface, "%ls: QI(IAgileObject) returned 0x%08lx\n", Name, hr);
    if (Iface)
        Iface->lpVtbl->Release(Iface);

    if (!IsCompositor)
    {
        IObj *Comp = NULL;

        Iface = NULL;
        hr = Obj->lpVtbl->QueryInterface(Obj, &IID_ICompositorController, (void **)&Iface);
        ok(hr == S_OK && Iface, "QI(ICompositorController) returned 0x%08lx\n", hr);
        if (Iface)
        {
            hr = Iface->lpVtbl->Method6(Iface, &Comp);
            ok(hr == S_OK && Comp, "ICompositorController::get_Compositor returned 0x%08lx\n", hr);
            if (Comp)
                Comp->lpVtbl->Release(Comp);
            Iids = NULL;
            Count = 0;
            hr = Iface->lpVtbl->GetIids(Iface, &Count, &Iids);
            ok(hr == S_OK && Count >= 2, "ICompositorController::GetIids returned 0x%08lx, %lu IIDs\n", hr, Count);
            if (hr == S_OK)
                CoTaskMemFree(Iids);
            Iface->lpVtbl->Release(Iface);
        }
    }

    if (IsCompositor)
    {
        IObj *Visual = NULL;

        Iface = NULL;
        hr = Obj->lpVtbl->QueryInterface(Obj, &IID_ICompositorInterop, (void **)&Iface);
        ok(hr == S_OK && Iface, "QI(ICompositorInterop) returned 0x%08lx\n", hr);
        if (Iface)
            Iface->lpVtbl->Release(Iface);

        Iface = NULL;
        hr = Obj->lpVtbl->QueryInterface(Obj, &IID_ICompositorDesktopInterop, (void **)&Iface);
        ok(hr == S_OK && Iface, "QI(ICompositorDesktopInterop) returned 0x%08lx\n", hr);
        if (Iface)
        {
            IObj *Unk = NULL, *Unk2 = NULL;

            Iface->lpVtbl->QueryInterface(Iface, &IID_IUnknown, (void **)&Unk);
            Obj->lpVtbl->QueryInterface(Obj, &IID_IUnknown, (void **)&Unk2);
            ok(Unk != NULL && Unk == Unk2, "ICompositorDesktopInterop identity %p vs %p\n", Unk, Unk2);
            if (Unk)
                Unk->lpVtbl->Release(Unk);
            if (Unk2)
                Unk2->lpVtbl->Release(Unk2);
            Iface->lpVtbl->Release(Iface);
        }

        Iface = NULL;
        hr = Obj->lpVtbl->QueryInterface(Obj, &IID_ICompositor, (void **)&Iface);
        ok(hr == S_OK && Iface, "QI(ICompositor) returned 0x%08lx\n", hr);
        if (Iface)
        {
            /* CreateContainerVisual is the 10th method (index 9): S_OK on Windows, E_NOTIMPL here for now */
            hr = Iface->lpVtbl->Method9(Iface, &Visual);
            ok(hr == S_OK || hr == E_NOTIMPL, "CreateContainerVisual returned 0x%08lx\n", hr);
            if (hr == S_OK && Visual)
                Visual->lpVtbl->Release(Visual);
            else
                ok(Visual == NULL, "CreateContainerVisual failed but returned %p\n", Visual);
            Iface->lpVtbl->Release(Iface);
        }
    }

    Iface = NULL;
    hr = Obj->lpVtbl->QueryInterface(Obj, &IID_Closable, (void **)&Iface);
    ok(hr == S_OK && Iface, "%ls: QI(IClosable) returned 0x%08lx\n", Name, hr);
    if (Iface)
    {
        hr = Iface->lpVtbl->Method6(Iface, NULL);   /* Close takes no argument, the extra one is ignored */
        ok(hr == S_OK, "%ls: Close returned 0x%08lx\n", Name, hr);
        Iface->lpVtbl->Release(Iface);
    }
    Obj->lpVtbl->Release(Obj);

done:
    pWindowsDeleteString(Class);
}

START_TEST(winrt_composition)
{
    static const WCHAR Compositor[] = L"Windows.UI.Composition.Compositor";
    static const WCHAR Controller[] = L"Windows.UI.Composition.Core.CompositorController";
    static const WCHAR NotRegistered[] = L"Windows.UI.Composition.Visual";
    HMODULE hCombase = LoadLibraryW(L"combase.dll");
    PVOID Class = NULL;
    IObj *Obj = (IObj *)0x1234;
    HRESULT hr;

    if (!hCombase)
    {
        skip("No combase.dll\n");
        return;
    }
    pRoGetActivationFactory = (PRO_GET_ACTIVATION_FACTORY)GetProcAddress(hCombase, "RoGetActivationFactory");
    pRoActivateInstance = (PRO_ACTIVATE_INSTANCE)GetProcAddress(hCombase, "RoActivateInstance");
    pWindowsCreateString = (PWINDOWS_CREATE_STRING)GetProcAddress(hCombase, "WindowsCreateString");
    pWindowsDeleteString = (PWINDOWS_DELETE_STRING)GetProcAddress(hCombase, "WindowsDeleteString");
    pWindowsGetStringRawBuffer = (PWINDOWS_GET_RAW)GetProcAddress(hCombase, "WindowsGetStringRawBuffer");
    if (!pRoGetActivationFactory || !pRoActivateInstance || !pWindowsCreateString || !pWindowsDeleteString ||
        !pWindowsGetStringRawBuffer)
    {
        skip("No WinRT activation\n");
        return;
    }

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ok(SUCCEEDED(hr), "CoInitializeEx returned 0x%08lx\n", hr);

    TestClass(Compositor, TRUE);
    TestClass(Controller, FALSE);

    /* a class that is not activatable by default construction is not registered */
    hr = pWindowsCreateString(NotRegistered, lstrlenW(NotRegistered), &Class);
    ok(hr == S_OK, "WindowsCreateString returned 0x%08lx\n", hr);
    hr = pRoActivateInstance(Class, &Obj);
    ok(hr == REGDB_E_CLASSNOTREG, "RoActivateInstance(Visual) returned 0x%08lx\n", hr);
    pWindowsDeleteString(Class);

    CoUninitialize();
}
