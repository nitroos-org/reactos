/*
 * PROJECT:     shell32
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     IApplicationActivationManager implementation
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#ifndef _CAPPLICATIONACTIVATIONMANAGER_H_
#define _CAPPLICATIONACTIVATIONMANAGER_H_

class CApplicationActivationManager :
    public CComCoClass<CApplicationActivationManager, &CLSID_ApplicationActivationManager>,
    public CComObjectRootEx<CComMultiThreadModelNoCS>,
    public IApplicationActivationManager
{
public:
    CApplicationActivationManager();
    ~CApplicationActivationManager();

    // *** IApplicationActivationManager methods ***
    STDMETHOD(ActivateApplication)(LPCWSTR pszAppUserModelId, LPCWSTR pszArguments,
                                   ACTIVATEOPTIONS options, DWORD *pdwProcessId) override;
    STDMETHOD(ActivateForFile)(LPCWSTR pszAppUserModelId, IShellItemArray *pItemArray,
                               LPCWSTR pszVerb, DWORD *pdwProcessId) override;
    STDMETHOD(ActivateForProtocol)(LPCWSTR pszAppUserModelId, IShellItemArray *pItemArray,
                                   DWORD *pdwProcessId) override;

DECLARE_REGISTRY_RESOURCEID(IDR_APPACTIVATIONMANAGER)
DECLARE_NOT_AGGREGATABLE(CApplicationActivationManager)
DECLARE_PROTECT_FINAL_CONSTRUCT()

BEGIN_COM_MAP(CApplicationActivationManager)
    COM_INTERFACE_ENTRY_IID(IID_IApplicationActivationManager, IApplicationActivationManager)
END_COM_MAP()
};

#endif // _CAPPLICATIONACTIVATIONMANAGER_H_
