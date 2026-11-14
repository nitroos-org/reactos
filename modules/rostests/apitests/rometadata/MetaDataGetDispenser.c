/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     rometadata.dll loads and exports MetaDataGetDispenser
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Microsoft.WindowsAppRuntime.dll imports MetaDataGetDispenser from rometadata.dll. With the library missing,
 * its LoadLibrary fails with ERROR_MOD_NOT_FOUND and a WinUI 3 application stops in its own failure path.
 * The metadata reader is not implemented, so the call must fail cleanly and leave the output pointer NULL.
 */

#include <apitest.h>
#include <objbase.h>

START_TEST(MetaDataGetDispenser)
{
    /* CLSID_CorMetaDataDispenser, IID_IUnknown */
    static const GUID Clsid = { 0xe5cb7a31, 0x7512, 0x11d2, { 0x89, 0xce, 0x00, 0x80, 0xc7, 0x92, 0xe5, 0xd8 } };
    static const GUID IidUnknown = { 0x00000000, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
    HMODULE hMod = LoadLibraryA("rometadata.dll");
    HRESULT (WINAPI *pMetaDataGetDispenser)(REFCLSID, REFIID, LPVOID *);
    LPVOID pv;
    HRESULT hr;

    ok(hMod != NULL, "rometadata.dll does not load: %lu\n", GetLastError());
    if (!hMod)
        return;

    pMetaDataGetDispenser = (void *)GetProcAddress(hMod, "MetaDataGetDispenser");
    ok(pMetaDataGetDispenser != NULL, "MetaDataGetDispenser is not exported\n");
    if (!pMetaDataGetDispenser)
        return;

    pv = (LPVOID)(ULONG_PTR)0x1234;
    hr = pMetaDataGetDispenser(&Clsid, &IidUnknown, &pv);
    if (FAILED(hr))
        ok(pv == NULL, "failure left the output pointer %p\n", pv);
    else
        ok(pv != NULL, "success without an interface\n");
    if (SUCCEEDED(hr) && pv)
        ((IUnknown *)pv)->lpVtbl->Release((IUnknown *)pv);

    hr = pMetaDataGetDispenser(&Clsid, &IidUnknown, NULL);
    ok(FAILED(hr), "a NULL output pointer gave %08lx\n", hr);
}
