/*
 * PROJECT:         ReactOS API Tests
 * LICENSE:         LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:         Tests for the Windows.UI.ViewManagement.UISettings WinRT class
 * COPYRIGHT:       Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Qt 6.8 creates a UISettings with C++/WinRT and asks it for colours; without the class it dies with an
 * unhandled hresult_class_not_registered.
 */

#include "com_apitest.h"

typedef struct { UINT8 A, R, G, B; } UiColor;

typedef struct IUi IUi;
typedef struct
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IUi *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(IUi *This);
    ULONG (STDMETHODCALLTYPE *Release)(IUi *This);
    HRESULT (STDMETHODCALLTYPE *GetIids)(IUi *This, ULONG *count, IID **iids);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(IUi *This, PVOID *name);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(IUi *This, int *level);
    /* the first method of every UISettings interface */
    HRESULT (STDMETHODCALLTYPE *Method6)(IUi *This, void *a, void *b);
    HRESULT (STDMETHODCALLTYPE *Method7)(IUi *This, void *a, void *b);
} UiVtbl;
struct IUi { const UiVtbl *lpVtbl; };

static const GUID IID_UISettings  = {0x85361600, 0x1c63, 0x4627, {0xbc, 0xb1, 0x3a, 0x89, 0xe0, 0xbc, 0x9c, 0x55}};
static const GUID IID_UISettings2 = {0xbad82401, 0x2721, 0x44f9, {0xbb, 0x91, 0x2b, 0xb2, 0x28, 0xbe, 0x44, 0x2f}};
static const GUID IID_UISettings3 = {0x03021be4, 0x5254, 0x4781, {0x81, 0x94, 0x51, 0x68, 0xf7, 0xd0, 0x6d, 0x7b}};
static const GUID IID_UISettings4 = {0x52bb3002, 0x919b, 0x4d6b, {0x9b, 0x78, 0x8d, 0xd6, 0x6f, 0xf4, 0xb9, 0x3b}};
static const GUID IID_UISettings5 = {0x5349d588, 0x0cb5, 0x5f05, {0xbd, 0x34, 0x70, 0x6b, 0x32, 0x31, 0xf0, 0xbd}};
static const GUID IID_UISettings6 = {0xaef19bd7, 0xfe31, 0x5a04, {0xad, 0xa4, 0x46, 0x9a, 0xae, 0xc6, 0xdf, 0xa9}};
static const GUID IID_ActivationFactoryTest = {0x00000035, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};

typedef HRESULT (WINAPI *PRO_GET_ACTIVATION_FACTORY)(PVOID, REFIID, void **);
typedef HRESULT (WINAPI *PWINDOWS_CREATE_STRING)(LPCWSTR, UINT32, PVOID *);
typedef HRESULT (WINAPI *PWINDOWS_DELETE_STRING)(PVOID);

START_TEST(winrt_ui)
{
    static const WCHAR ClassName[] = L"Windows.UI.ViewManagement.UISettings";
    HMODULE hCombase = LoadLibraryW(L"combase.dll");
    PRO_GET_ACTIVATION_FACTORY pRoGetActivationFactory;
    PWINDOWS_CREATE_STRING pWindowsCreateString;
    PWINDOWS_DELETE_STRING pWindowsDeleteString;
    PVOID Class = NULL;
    IUnknown *Factory = NULL;
    IUi *Settings = NULL, *Iface;
    HRESULT (STDMETHODCALLTYPE *ActivateInstance)(IUnknown *, IUi **);
    UiColor Back, Fore, Accent, Dark3, Light3;
    INT64 Token;
    double Scale;
    BOOLEAN Flag;
    HRESULT hr;
    int i;
    const GUID *Iids[] = { &IID_UISettings, &IID_UISettings2, &IID_UISettings3,
                           &IID_UISettings4, &IID_UISettings5, &IID_UISettings6 };

    if (!hCombase)
    {
        skip("No combase.dll\n");
        return;
    }
    pRoGetActivationFactory = (PRO_GET_ACTIVATION_FACTORY)GetProcAddress(hCombase, "RoGetActivationFactory");
    pWindowsCreateString = (PWINDOWS_CREATE_STRING)GetProcAddress(hCombase, "WindowsCreateString");
    pWindowsDeleteString = (PWINDOWS_DELETE_STRING)GetProcAddress(hCombase, "WindowsDeleteString");
    if (!pRoGetActivationFactory || !pWindowsCreateString || !pWindowsDeleteString)
    {
        skip("No WinRT activation\n");
        return;
    }

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ok(SUCCEEDED(hr), "CoInitializeEx returned 0x%08lx\n", hr);
    hr = pWindowsCreateString(ClassName, ARRAYSIZE(ClassName) - 1, &Class);
    ok(hr == S_OK, "WindowsCreateString returned 0x%08lx\n", hr);

    hr = pRoGetActivationFactory(Class, &IID_ActivationFactoryTest, (void **)&Factory);
    ok(hr == S_OK, "RoGetActivationFactory returned 0x%08lx\n", hr);
    if (hr != S_OK || !Factory)
        goto done;

    /* ActivateInstance is the seventh method of IActivationFactory */
    ActivateInstance = ((HRESULT (STDMETHODCALLTYPE **)(IUnknown *, IUi **))*(void ***)Factory)[6];
    hr = ActivateInstance(Factory, &Settings);
    ok(hr == S_OK, "ActivateInstance returned 0x%08lx\n", hr);
    ok(Settings != NULL, "No instance\n");
    if (hr != S_OK || !Settings)
    {
        Factory->lpVtbl->Release(Factory);
        goto done;
    }

    for (i = 0; i < ARRAYSIZE(Iids); i++)
    {
        Iface = NULL;
        hr = Settings->lpVtbl->QueryInterface(Settings, Iids[i], (void **)&Iface);
        ok(hr == S_OK && Iface, "QueryInterface(IUISettings%d) returned 0x%08lx\n", i + 1, hr);
        if (Iface)
            Iface->lpVtbl->Release(Iface);
    }
    Iface = (IUi *)0x1234;
    hr = Settings->lpVtbl->QueryInterface(Settings, &IID_ActivationFactoryTest, (void **)&Iface);
    ok(hr == E_NOINTERFACE, "QueryInterface(IActivationFactory) returned 0x%08lx\n", hr);
    ok(Iface == NULL, "Interface is %p\n", Iface);

    /* IUISettings3::GetColorValue: Background 0, Foreground 1, AccentDark3 2 .. AccentLight3 8 */
    Iface = NULL;
    hr = Settings->lpVtbl->QueryInterface(Settings, &IID_UISettings3, (void **)&Iface);
    if (Iface)
    {
        HRESULT (STDMETHODCALLTYPE *GetColorValue)(IUi *, INT32, UiColor *) = (void *)Iface->lpVtbl->Method6;
        HRESULT (STDMETHODCALLTYPE *Add)(IUi *, void *, INT64 *) = (void *)Iface->lpVtbl->Method7;

        hr = GetColorValue(Iface, 0, &Back);
        ok(hr == S_OK, "GetColorValue(Background) returned 0x%08lx\n", hr);
        hr = GetColorValue(Iface, 1, &Fore);
        ok(hr == S_OK, "GetColorValue(Foreground) returned 0x%08lx\n", hr);
        hr = GetColorValue(Iface, 5, &Accent);
        ok(hr == S_OK, "GetColorValue(Accent) returned 0x%08lx\n", hr);
        hr = GetColorValue(Iface, 2, &Dark3);
        ok(hr == S_OK, "GetColorValue(AccentDark3) returned 0x%08lx\n", hr);
        hr = GetColorValue(Iface, 8, &Light3);
        ok(hr == S_OK, "GetColorValue(AccentLight3) returned 0x%08lx\n", hr);
        ok(Back.A == 255 && Fore.A == 255 && Accent.A == 255, "Colours are not opaque\n");
        /* Qt tells a dark scheme from a light one by comparing these two */
        ok(Back.R + Back.G + Back.B != Fore.R + Fore.G + Fore.B, "Background and foreground are the same\n");
        ok(Dark3.R + Dark3.G + Dark3.B <= Accent.R + Accent.G + Accent.B, "AccentDark3 is lighter than the accent\n");
        ok(Light3.R + Light3.G + Light3.B >= Accent.R + Accent.G + Accent.B, "AccentLight3 is darker than the accent\n");

        hr = GetColorValue(Iface, 10, &Back);
        ok(hr == E_INVALIDARG, "GetColorValue(10) returned 0x%08lx\n", hr);

        Token = 0;
        hr = Add(Iface, NULL, &Token);
        ok(hr == E_INVALIDARG, "add_ColorValuesChanged(NULL) returned 0x%08lx\n", hr);
        Iface->lpVtbl->Release(Iface);
    }

    Iface = NULL;
    Settings->lpVtbl->QueryInterface(Settings, &IID_UISettings2, (void **)&Iface);
    if (Iface)
    {
        HRESULT (STDMETHODCALLTYPE *GetScale)(IUi *, double *, void *) = (void *)Iface->lpVtbl->Method6;
        Scale = 0;
        hr = GetScale(Iface, &Scale, NULL);
        ok(hr == S_OK && Scale == 1.0, "TextScaleFactor returned 0x%08lx, %f\n", hr, Scale);
        Iface->lpVtbl->Release(Iface);
    }

    Iface = NULL;
    Settings->lpVtbl->QueryInterface(Settings, &IID_UISettings5, (void **)&Iface);
    if (Iface)
    {
        HRESULT (STDMETHODCALLTYPE *GetFlag)(IUi *, BOOLEAN *, void *) = (void *)Iface->lpVtbl->Method6;
        Flag = 0x55;
        hr = GetFlag(Iface, &Flag, NULL);
        ok(hr == S_OK && (Flag == TRUE || Flag == FALSE), "AutoHideScrollBars returned 0x%08lx, %d\n", hr, Flag);
        Iface->lpVtbl->Release(Iface);
    }

    Settings->lpVtbl->Release(Settings);
    Factory->lpVtbl->Release(Factory);

done:
    if (Class)
        pWindowsDeleteString(Class);
    CoUninitialize();
}
