/*
 * PROJECT:     ReactOS shdocvw
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     IAttachmentExecute (CLSID_AttachmentServices): Mark-of-the-Web
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#pragma once

#ifdef __cplusplus

#include <atlstr.h>

// Not in the ShellObjects typelib: a coclass entry would register IAttachmentExecute in HKCR\Interface
// (Windows does not), so the CLSID is defined here
DEFINE_GUID(CLSID_AttachmentServices, 0x4125dd96, 0xe03a, 0x4103, 0x8f, 0x70, 0xe0, 0x59, 0x7d, 0x80, 0x3b, 0x9c);

class CAttachmentServices
    : public CComCoClass<CAttachmentServices, &CLSID_AttachmentServices>
    , public CComObjectRootEx<CComMultiThreadModelNoCS>
    , public IAttachmentExecute
{
    CStringW m_strTitle;
    CStringW m_strLocalPath;
    CStringW m_strFileName;
    CStringW m_strSource;
    CStringW m_strReferrer;
    CStringW m_strMarkHost; // HostUrl of the stream of the local file
    GUID m_guid = GUID_NULL;
    bool m_bGuidSet = false;

    HRESULT GetZone(DWORD *pdwZone, BOOL bSaving);
    PCWSTR GetExtension(CStringW &strExt);
    bool IsHighRisk();
    HRESULT RunPromptDialog(HWND hwnd, bool bExec, ATTACHMENT_ACTION *pAction);

public:
    CAttachmentServices();
    virtual ~CAttachmentServices();

    DECLARE_REGISTRY_RESOURCEID(IDR_ATTACHMENTSERVICES)
    DECLARE_NOT_AGGREGATABLE(CAttachmentServices)
    DECLARE_PROTECT_FINAL_CONSTRUCT()

    BEGIN_COM_MAP(CAttachmentServices)
        COM_INTERFACE_ENTRY_IID(IID_IAttachmentExecute, IAttachmentExecute)
    END_COM_MAP()

    // IAttachmentExecute
    STDMETHODIMP SetClientTitle(LPCWSTR pszTitle) override;
    STDMETHODIMP SetClientGuid(REFGUID guid) override;
    STDMETHODIMP SetLocalPath(LPCWSTR pszLocalPath) override;
    STDMETHODIMP SetFileName(LPCWSTR pszFileName) override;
    STDMETHODIMP SetSource(LPCWSTR pszSource) override;
    STDMETHODIMP SetReferrer(LPCWSTR pszReferrer) override;
    STDMETHODIMP CheckPolicy() override;
    STDMETHODIMP Prompt(HWND hwnd, ATTACHMENT_PROMPT prompt, ATTACHMENT_ACTION *paction) override;
    STDMETHODIMP Save() override;
    STDMETHODIMP Execute(HWND hwnd, LPCWSTR pszVerb, HANDLE *phProcess) override;
    STDMETHODIMP SaveWithUI(HWND hwnd) override;
    STDMETHODIMP ClearClientState() override;
};

#endif /* __cplusplus */
