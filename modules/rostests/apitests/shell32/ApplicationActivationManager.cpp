/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for IApplicationActivationManager
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Only what does not start another program: the class, and the answer for an app that is not
 * installed (measured on Windows 10 22H2).
 */

#include "shelltest.h"
#include <shellutils.h>

START_TEST(ApplicationActivationManager)
{
    CComPtr<IApplicationActivationManager> pAAM;
    DWORD dwPid;
    HRESULT hrInit = CoInitialize(NULL);
    HRESULT hr = CoCreateInstance(CLSID_ApplicationActivationManager, NULL, CLSCTX_ALL,
                                  IID_PPV_ARG(IApplicationActivationManager, &pAAM));
    if (FAILED(hr))
    {
        skip("IApplicationActivationManager is not available (0x%lx)\n", hr);
        goto Quit;
    }

    dwPid = 0x1234;
    hr = pAAM->ActivateApplication(L"Contoso.NoSuchApp_8wekyb3d8bbwe!App", NULL, AO_NONE, &dwPid);
    ok(hr == (HRESULT)0x80073CF1L, "got 0x%lx\n", hr);
    ok(dwPid == 0, "got %lu\n", dwPid);

Quit:
    pAAM.Release();
    if (SUCCEEDED(hrInit))
        CoUninitialize();
}
