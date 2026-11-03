/*
 * PROJECT:         ReactOS API Tests
 * LICENSE:         LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:         Tests for the Windows.Management.Deployment.PackageManager WinRT class
 * COPYRIGHT:       Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Read-only: only package queries are made. The Office Deployment Tool setup.exe asks for
 * FindPackages(L"Microsoft.Office.Desktop", L"_8wekyb3d8bbwe"); on a system without that package
 * Windows 10 returns an empty collection.
 */

#include "com_apitest.h"
#include <winreg.h>

typedef struct IObj IObj;
struct IObj
{
    void **lpVtbl;
};

#define METHOD(obj, index, type) ((type)((obj)->lpVtbl[index]))
typedef HRESULT (STDMETHODCALLTYPE *PQUERYINTERFACE)(IObj *, REFIID, void **);
typedef ULONG (STDMETHODCALLTYPE *PRELEASE)(IObj *);
typedef HRESULT (STDMETHODCALLTYPE *PGETRUNTIMECLASSNAME)(IObj *, PVOID *);
typedef HRESULT (STDMETHODCALLTYPE *PGETTRUSTLEVEL)(IObj *, int *);
typedef HRESULT (STDMETHODCALLTYPE *PACTIVATEINSTANCE)(IObj *, IObj **);
typedef HRESULT (STDMETHODCALLTYPE *PFINDBYNAMEPUBLISHER)(IObj *, PVOID, PVOID, IObj **);
typedef HRESULT (STDMETHODCALLTYPE *PFINDBYSTRING)(IObj *, PVOID, IObj **);
typedef HRESULT (STDMETHODCALLTYPE *PFIRST)(IObj *, IObj **);
typedef HRESULT (STDMETHODCALLTYPE *PGETBOOLEAN)(IObj *, BOOLEAN *);

static const GUID IID_IActivationFactoryTest = {0x00000035, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
static const GUID IID_IAgileObjectTest = {0x94ea2b94, 0xe9cc, 0x49e0, {0xc0, 0xff, 0xee, 0x64, 0xca, 0x8f, 0x5b, 0x90}};
static const GUID IID_IPackageManagerTest = {0x9a7d4b65, 0x5e8f, 0x4fc7, {0xa2, 0xe5, 0x7f, 0x69, 0x25, 0xcb, 0x8b, 0x53}};
static const GUID IID_IPackageManager2Test = {0xf7aad08d, 0x0840, 0x46f2, {0xb5, 0xd8, 0xca, 0xd4, 0x76, 0x93, 0xa0, 0x95}};
/* IIterable<Windows.ApplicationModel.Package> and IIterator<Windows.ApplicationModel.Package> */
static const GUID IID_IIterablePackageTest = {0x69ad6aa7, 0x0c49, 0x5f27, {0xa5, 0xeb, 0xef, 0x4d, 0x59, 0x46, 0x7b, 0x6d}};
static const GUID IID_IIteratorPackageTest = {0x0217f069, 0x025c, 0x5ee6, {0xa8, 0x7f, 0xe7, 0x82, 0xe3, 0xb6, 0x23, 0xae}};

typedef HRESULT (WINAPI *PRO_GET_ACTIVATION_FACTORY)(PVOID, REFIID, void **);
typedef HRESULT (WINAPI *PWINDOWS_CREATE_STRING)(LPCWSTR, UINT32, PVOID *);
typedef HRESULT (WINAPI *PWINDOWS_DELETE_STRING)(PVOID);
typedef LPCWSTR (WINAPI *PWINDOWS_GET_STRING_RAW_BUFFER)(PVOID, UINT32 *);

static PWINDOWS_CREATE_STRING pWindowsCreateString;
static PWINDOWS_DELETE_STRING pWindowsDeleteString;
static PWINDOWS_GET_STRING_RAW_BUFFER pWindowsGetStringRawBuffer;

static PVOID make_string(LPCWSTR str)
{
    PVOID h = NULL;
    HRESULT hr = pWindowsCreateString(str, lstrlenW(str), &h);
    ok(hr == S_OK, "WindowsCreateString returned 0x%08lx\n", hr);
    return h;
}

static void test_class_name(IObj *obj, LPCWSTR expected)
{
    PVOID name = NULL;
    HRESULT hr = METHOD(obj, 4, PGETRUNTIMECLASSNAME)(obj, &name);
    ok(hr == S_OK, "GetRuntimeClassName returned 0x%08lx\n", hr);
    if (hr == S_OK)
    {
        LPCWSTR raw = pWindowsGetStringRawBuffer(name, NULL);
        ok(raw && !wcscmp(raw, expected), "class name %ls\n", raw ? raw : L"(null)");
        pWindowsDeleteString(name);
    }
}

/* An empty collection: QI for IIterable<Package>, First gives an iterator that has no current item */
static void test_empty_collection(IObj *packages)
{
    IObj *iterable = NULL, *iterator = NULL, *agile = NULL;
    BOOLEAN has = 0x55;
    HRESULT hr;

    test_class_name(packages, L"Windows.Foundation.Collections.IVector`1<Windows.ApplicationModel.Package>");
    hr = METHOD(packages, 0, PQUERYINTERFACE)(packages, &IID_IAgileObjectTest, (void **)&agile);
    ok(hr == S_OK, "collection QI(IAgileObject) returned 0x%08lx\n", hr);
    if (agile)
        METHOD(agile, 2, PRELEASE)(agile);
    hr = METHOD(packages, 0, PQUERYINTERFACE)(packages, &IID_IIterablePackageTest, (void **)&iterable);
    ok(hr == S_OK, "collection QI(IIterable<Package>) returned 0x%08lx\n", hr);
    if (iterable)
        METHOD(iterable, 2, PRELEASE)(iterable);

    hr = METHOD(packages, 6, PFIRST)(packages, &iterator);
    ok(hr == S_OK, "First returned 0x%08lx\n", hr);
    if (hr != S_OK || !iterator)
        return;
    hr = METHOD(iterator, 0, PQUERYINTERFACE)(iterator, &IID_IIteratorPackageTest, (void **)&iterable);
    ok(hr == S_OK, "iterator QI(IIterator<Package>) returned 0x%08lx\n", hr);
    if (iterable)
        METHOD(iterable, 2, PRELEASE)(iterable);
    hr = METHOD(iterator, 7, PGETBOOLEAN)(iterator, &has);
    ok(hr == S_OK, "get_HasCurrent returned 0x%08lx\n", hr);
    ok(has == FALSE, "HasCurrent is %d\n", has);
    METHOD(iterator, 2, PRELEASE)(iterator);
}

static const GUID IID_IAsyncInfoTest = {0x00000036, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
/* IPackageManager3 .. IPackageManager9 (Windows.Management.winmd of Windows 10 22H2) */
static const GUID IID_IPackageManagerN[] =
{
    {0xdaad9948, 0x36f1, 0x41a7, {0x91, 0x88, 0xbc, 0x26, 0x3e, 0x0d, 0xcb, 0x72}},
    {0x3c719963, 0xbab6, 0x46bf, {0x8f, 0xf7, 0xda, 0x47, 0x19, 0x23, 0x0a, 0xe6}},
    {0x711f3117, 0x1afd, 0x4313, {0x97, 0x8c, 0x9b, 0xb6, 0xe1, 0xb8, 0x64, 0xa7}},
    {0x0847e909, 0x53cd, 0x4e4f, {0x83, 0x2e, 0x57, 0xd1, 0x80, 0xf6, 0xe4, 0x47}},
    {0xf28654f4, 0x2ba7, 0x4b80, {0x88, 0xd6, 0xbe, 0x15, 0xf9, 0xa2, 0x3f, 0xba}},
    {0xb8575330, 0x1298, 0x4ee2, {0x80, 0xee, 0x7f, 0x65, 0x9c, 0x5d, 0x27, 0x82}},
    {0x1aa79035, 0xcc71, 0x4b2e, {0x80, 0xa6, 0xc7, 0x04, 0x1d, 0x85, 0x79, 0xa7}},
};
typedef HRESULT (STDMETHODCALLTYPE *PPROVISION)(IObj *, PVOID, IObj **);
typedef HRESULT (STDMETHODCALLTYPE *PPUTHANDLER)(IObj *, void *);
typedef HRESULT (STDMETHODCALLTYPE *PGETRESULTS)(IObj *, void **);
typedef HRESULT (STDMETHODCALLTYPE *PGETINT)(IObj *, int *);

static LONG g_completed_calls;
static int g_completed_status;

static HRESULT STDMETHODCALLTYPE handler_QI(void *This, REFIID riid, void **out) { *out = This; return S_OK; }
static ULONG STDMETHODCALLTYPE handler_AddRef(void *This) { return 2; }
static ULONG STDMETHODCALLTYPE handler_Release(void *This) { return 1; }
static HRESULT STDMETHODCALLTYPE handler_Invoke(void *This, IObj *op, int status)
{
    InterlockedIncrement(&g_completed_calls);
    g_completed_status = status;
    return S_OK;
}
static void *handler_vtbl[] = { handler_QI, handler_AddRef, handler_Release, handler_Invoke };

/* A deployment operation on this system's PackageManager completes with an error: the call succeeds, the
 * operation is a completed IAsyncOperationWithProgress with IAsyncInfo, and its Completed handler is called.
 * Only run on ReactOS: on Windows this is a provisioning call. */
static void test_deployment_operation(IObj *Manager6, PVOID Family)
{
    IObj *Op = NULL, *Info = NULL;
    void *handler = handler_vtbl, *result = (void *)1;
    void **handler_ptr = &handler_vtbl[0];
    HRESULT hr, code = 0;
    int status = -1;

    (void)handler;
    hr = METHOD(Manager6, 6, PPROVISION)(Manager6, Family, &Op);
    ok(hr == S_OK, "ProvisionPackageForAllUsersAsync returned 0x%08lx\n", hr);
    if (hr != S_OK || !Op)
        return;
    hr = METHOD(Op, 0, PQUERYINTERFACE)(Op, &IID_IAsyncInfoTest, (void **)&Info);
    ok(hr == S_OK, "QueryInterface(IAsyncInfo) returned 0x%08lx\n", hr);
    if (hr == S_OK)
    {
        hr = METHOD(Info, 7, PGETINT)(Info, &status);
        ok(hr == S_OK && status == 3, "get_Status returned 0x%08lx, status %d\n", hr, status);
        hr = METHOD(Info, 8, PGETINT)(Info, (int *)&code);
        ok(hr == S_OK && code == (HRESULT)0x80073CF1, "get_ErrorCode returned 0x%08lx, code 0x%08lx\n", hr, code);
        METHOD(Info, 2, PRELEASE)(Info);
    }
    g_completed_calls = 0;
    hr = METHOD(Op, 8, PPUTHANDLER)(Op, &handler_ptr);
    ok(hr == S_OK, "put_Completed returned 0x%08lx\n", hr);
    ok(g_completed_calls == 1 && g_completed_status == 3, "Completed handler called %ld times, status %d\n",
       g_completed_calls, g_completed_status);
    hr = METHOD(Op, 10, PGETRESULTS)(Op, &result);
    ok(hr == (HRESULT)0x80073CF1, "GetResults returned 0x%08lx\n", hr);
    METHOD(Op, 2, PRELEASE)(Op);
}

static BOOL running_on_reactos(void)
{
    HKEY key;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\ReactOS", 0, KEY_READ, &key) != ERROR_SUCCESS)
        return FALSE;
    RegCloseKey(key);
    return TRUE;
}

static void test_extra_interfaces(IObj *Manager, PVOID Family)
{
    IObj *Iface;
    HRESULT hr;
    int i;

    for (i = 0; i < ARRAYSIZE(IID_IPackageManagerN); i++)
    {
        Iface = NULL;
        hr = METHOD(Manager, 0, PQUERYINTERFACE)(Manager, &IID_IPackageManagerN[i], (void **)&Iface);
        ok(hr == S_OK, "QueryInterface(IPackageManager%d) returned 0x%08lx\n", i + 3, hr);
        if (hr != S_OK || !Iface)
            continue;
        if (i == 3 && running_on_reactos())
            test_deployment_operation(Iface, Family);
        METHOD(Iface, 2, PRELEASE)(Iface);
    }
}

START_TEST(winrt_packagemanager)
{
    static const WCHAR ClassName[] = L"Windows.Management.Deployment.PackageManager";
    HMODULE hCombase = LoadLibraryW(L"combase.dll");
    PRO_GET_ACTIVATION_FACTORY pRoGetActivationFactory;
    IObj *Factory = NULL, *Instance = NULL, *Manager = NULL, *Other = NULL, *Packages = NULL, *Package;
    PVOID Class = NULL, Name, Publisher, Empty, Family, FullName;
    int Trust = -1;
    HRESULT hr;

    if (!hCombase)
    {
        skip("No combase.dll\n");
        return;
    }
    pRoGetActivationFactory = (PRO_GET_ACTIVATION_FACTORY)GetProcAddress(hCombase, "RoGetActivationFactory");
    pWindowsCreateString = (PWINDOWS_CREATE_STRING)GetProcAddress(hCombase, "WindowsCreateString");
    pWindowsDeleteString = (PWINDOWS_DELETE_STRING)GetProcAddress(hCombase, "WindowsDeleteString");
    pWindowsGetStringRawBuffer = (PWINDOWS_GET_STRING_RAW_BUFFER)GetProcAddress(hCombase, "WindowsGetStringRawBuffer");
    if (!pRoGetActivationFactory || !pWindowsCreateString || !pWindowsDeleteString || !pWindowsGetStringRawBuffer)
    {
        skip("No WinRT activation\n");
        return;
    }

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ok(SUCCEEDED(hr), "CoInitializeEx returned 0x%08lx\n", hr);
    Class = make_string(ClassName);

    hr = pRoGetActivationFactory(Class, &IID_IActivationFactoryTest, (void **)&Factory);
    ok(hr == S_OK, "RoGetActivationFactory returned 0x%08lx\n", hr);
    if (hr != S_OK || !Factory)
        goto done;

    /* The factory is not agile; the instance is */
    hr = METHOD(Factory, 0, PQUERYINTERFACE)(Factory, &IID_IAgileObjectTest, (void **)&Other);
    ok(hr == E_NOINTERFACE, "factory QI(IAgileObject) returned 0x%08lx\n", hr);
    if (Other)
        METHOD(Other, 2, PRELEASE)(Other), Other = NULL;

    hr = METHOD(Factory, 6, PACTIVATEINSTANCE)(Factory, &Instance);
    ok(hr == S_OK, "ActivateInstance returned 0x%08lx\n", hr);
    METHOD(Factory, 2, PRELEASE)(Factory);
    if (hr != S_OK || !Instance)
        goto done;

    test_class_name(Instance, ClassName);
    hr = METHOD(Instance, 5, PGETTRUSTLEVEL)(Instance, &Trust);
    ok(hr == S_OK, "GetTrustLevel returned 0x%08lx\n", hr);
    ok(Trust == 1, "trust level %d\n", Trust);
    hr = METHOD(Instance, 0, PQUERYINTERFACE)(Instance, &IID_IAgileObjectTest, (void **)&Other);
    ok(hr == S_OK, "instance QI(IAgileObject) returned 0x%08lx\n", hr);
    if (Other)
        METHOD(Other, 2, PRELEASE)(Other), Other = NULL;
    hr = METHOD(Instance, 0, PQUERYINTERFACE)(Instance, &IID_IPackageManager2Test, (void **)&Other);
    ok(hr == S_OK, "instance QI(IPackageManager2) returned 0x%08lx\n", hr);
    if (Other)
        METHOD(Other, 2, PRELEASE)(Other), Other = NULL;
    hr = METHOD(Instance, 0, PQUERYINTERFACE)(Instance, &IID_IPackageManagerTest, (void **)&Manager);
    ok(hr == S_OK, "instance QI(IPackageManager) returned 0x%08lx\n", hr);
    METHOD(Instance, 2, PRELEASE)(Instance);
    if (hr != S_OK || !Manager)
        goto done;

    Name = make_string(L"Microsoft.Office.Desktop");
    Publisher = make_string(L"_8wekyb3d8bbwe");
    Empty = NULL;
    Family = make_string(L"Microsoft.Office.Desktop_8wekyb3d8bbwe");
    FullName = make_string(L"Microsoft.Office.Desktop_16.0.0.0_x64__8wekyb3d8bbwe");

    /* IPackageManager::FindPackages(name, publisher) is the 14th method */
    hr = METHOD(Manager, 13, PFINDBYNAMEPUBLISHER)(Manager, Name, Publisher, &Packages);
    ok(hr == S_OK, "FindPackages(name, publisher) returned 0x%08lx\n", hr);
    if (hr == S_OK && Packages)
    {
        test_empty_collection(Packages);
        METHOD(Packages, 2, PRELEASE)(Packages), Packages = NULL;
    }
    hr = METHOD(Manager, 13, PFINDBYNAMEPUBLISHER)(Manager, Empty, Empty, &Packages);
    ok(hr == E_INVALIDARG, "FindPackages(NULL, NULL) returned 0x%08lx\n", hr);
    if (Packages)
        METHOD(Packages, 2, PRELEASE)(Packages), Packages = NULL;
    hr = METHOD(Manager, 13, PFINDBYNAMEPUBLISHER)(Manager, Name, Publisher, NULL);
    ok(hr == E_POINTER, "FindPackages(name, publisher, NULL) returned 0x%08lx\n", hr);

    /* FindPackages(packageFamilyName), the 20th method */
    hr = METHOD(Manager, 19, PFINDBYSTRING)(Manager, Family, &Packages);
    ok(hr == S_OK, "FindPackages(family) returned 0x%08lx\n", hr);
    if (hr == S_OK && Packages)
    {
        test_empty_collection(Packages);
        METHOD(Packages, 2, PRELEASE)(Packages), Packages = NULL;
    }

    /* FindPackage(packageFullName), the 18th method: S_OK and no package when it is not installed */
    Package = (IObj *)(ULONG_PTR)0x1234;
    hr = METHOD(Manager, 17, PFINDBYSTRING)(Manager, FullName, &Package);
    ok(hr == S_OK, "FindPackage(full name) returned 0x%08lx\n", hr);
    ok(Package == NULL, "package %p\n", Package);

    test_extra_interfaces(Manager, Family);

    METHOD(Manager, 2, PRELEASE)(Manager);
    pWindowsDeleteString(Name);
    pWindowsDeleteString(Publisher);
    pWindowsDeleteString(Family);
    pWindowsDeleteString(FullName);

done:
    if (Class)
        pWindowsDeleteString(Class);
    CoUninitialize();
}
