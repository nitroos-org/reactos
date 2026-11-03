/*
 * PROJECT:     ReactOS shdocvw
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     IAttachmentExecute (CLSID_AttachmentServices): Mark-of-the-Web
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Behaviour measured on Windows 10 22H2 (see the apitest for the cases):
 *  - Save() writes the "Zone.Identifier" alternate data stream of the local
 *    file as "[ZoneTransfer]\r\nZoneId=N\r\n[ReferrerUrl=..\r\n]HostUrl=..\r\n"
 *    when the zone of the source is Internet (3) or Untrusted (4); for the
 *    local, intranet and trusted zones it writes nothing and returns S_OK.
 *    The URLs are stored as given (no stripping of credentials or queries).
 *  - Save() without a local path is E_UNEXPECTED, for a missing file
 *    HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), without a source
 *    INET_E_SECURITY_PROBLEM. The client GUID is not required.
 *  - CheckPolicy() is S_FALSE (prompt) for the Internet zone, S_OK otherwise,
 *    INET_E_SECURITY_PROBLEM without a source; Set*(NULL) is E_INVALIDARG.
 */

#include "objects.h"

#include <urlmon.h>
#include <strsafe.h>
#include <wine/debug.h>
WINE_DEFAULT_DEBUG_CHANNEL(shdocvw);

EXTERN_C const GUID CLSID_AttachmentServices =
    { 0x4125dd96, 0xe03a, 0x4103, { 0x8f, 0x70, 0xe0, 0x59, 0x7d, 0x80, 0x3b, 0x9c } };

#define ATT_ZONE_STREAM L":Zone.Identifier"
#define ATT_MAX_URL 2084
#define ATT_MAX_HOST 256

CAttachmentServices::CAttachmentServices()
{
}

CAttachmentServices::~CAttachmentServices()
{
}

STDMETHODIMP CAttachmentServices::SetClientTitle(LPCWSTR pszTitle)
{
    if (!pszTitle)
        return E_INVALIDARG;
    m_strTitle = pszTitle;
    return S_OK;
}

STDMETHODIMP CAttachmentServices::SetClientGuid(REFGUID guid)
{
    m_guid = guid;
    m_bGuidSet = true;
    return S_OK;
}

STDMETHODIMP CAttachmentServices::SetLocalPath(LPCWSTR pszLocalPath)
{
    if (!pszLocalPath)
        return E_INVALIDARG;
    m_strLocalPath = pszLocalPath;
    return S_OK;
}

STDMETHODIMP CAttachmentServices::SetFileName(LPCWSTR pszFileName)
{
    if (!pszFileName)
        return E_INVALIDARG;
    m_strFileName = pszFileName;
    return S_OK;
}

STDMETHODIMP CAttachmentServices::SetSource(LPCWSTR pszSource)
{
    if (!pszSource)
        return E_INVALIDARG;
    m_strSource = pszSource;
    return S_OK;
}

STDMETHODIMP CAttachmentServices::SetReferrer(LPCWSTR pszReferrer)
{
    if (!pszReferrer)
        return E_INVALIDARG;
    m_strReferrer = pszReferrer;
    return S_OK;
}

// The zone of the source URL (or path). A source urlmon cannot classify
// ("about:internet", unknown schemes) is the Internet zone, like Windows.
//
// Without a source (Explorer and ShellExecute open a file by its path only)
// the mark of the file decides: its Zone.Identifier stream, none = local.
HRESULT CAttachmentServices::GetZone(DWORD *pdwZone, BOOL bSaving)
{
    *pdwZone = URLZONE_INTERNET;
    if (m_strSource.IsEmpty())
    {
        if (bSaving || m_strLocalPath.IsEmpty() ||
            GetFileAttributesW(m_strLocalPath) == INVALID_FILE_ATTRIBUTES)
            return INET_E_SECURITY_PROBLEM;
        *pdwZone = URLZONE_LOCAL_MACHINE;
        HANDLE hFile = CreateFileW(m_strLocalPath + ATT_ZONE_STREAM, GENERIC_READ,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
            return S_OK;
        char sz[1024];
        DWORD cb = 0;
        ReadFile(hFile, sz, sizeof(sz) - 1, &cb, NULL);
        CloseHandle(hFile);
        sz[cb] = 0;
        PCSTR pszZone = strstr(sz, "ZoneId=");
        if (pszZone)
            *pdwZone = (DWORD)atoi(pszZone + 7);
        PCSTR pszHost = strstr(sz, "HostUrl=");
        if (pszHost)
        {
            CStringA strHost(pszHost + 8);
            int ich = strHost.FindOneOf("\r\n");
            if (ich >= 0)
                strHost = strHost.Left(ich);
            int cch = MultiByteToWideChar(CP_UTF8, 0, strHost, -1, NULL, 0);
            if (cch > 0)
            {
                MultiByteToWideChar(CP_UTF8, 0, strHost, -1, m_strMarkHost.GetBuffer(cch), cch);
                m_strMarkHost.ReleaseBuffer(cch - 1);
            }
        }
        return S_OK;
    }

    CStringW strUrl = m_strSource;
    PCWSTR pszSource = strUrl;
    // A path (C:\x or \\server\share\x) is mapped through its file: URL
    if ((pszSource[0] && pszSource[1] == L':' && pszSource[2] == L'\\') ||
        (pszSource[0] == L'\\' && pszSource[1] == L'\\'))
    {
        WCHAR szUrl[ATT_MAX_URL];
        DWORD cch = _countof(szUrl);
        if (SUCCEEDED(UrlCreateFromPathW(pszSource, szUrl, &cch, 0)))
            strUrl = szUrl;
    }

    CComPtr<IInternetSecurityManager> pSecMgr;
    HRESULT hr = CoInternetCreateSecurityManager(NULL, &pSecMgr, 0);
    if (FAILED(hr))
        return S_OK; // Internet zone
    DWORD dwZone;
    hr = pSecMgr->MapUrlToZone(strUrl, &dwZone, 0);
    if (SUCCEEDED(hr) && dwZone != (DWORD)URLZONE_INVALID)
        *pdwZone = dwZone;

    // urlmon knows no "local intranet" defaults: a host without a dot (an
    // intranet name, a UNC server) and the loopback names are not the Internet
    if (*pdwZone == URLZONE_INTERNET)
    {
        WCHAR szHost[ATT_MAX_HOST];
        DWORD cchHost = _countof(szHost);
        if (SUCCEEDED(UrlGetPartW(strUrl, szHost, &cchHost, URL_PART_HOSTNAME, 0)) && szHost[0])
        {
            bool bLoopback = !_wcsicmp(szHost, L"localhost") || !wcscmp(szHost, L"[::1]") ||
                             !wcsncmp(szHost, L"127.", 4);
            if (bLoopback || (!wcschr(szHost, L'.') && !wcschr(szHost, L':')))
                *pdwZone = URLZONE_INTRANET;
        }
    }
    return S_OK;
}

// The extension of the file name (SetFileName wins over the local path)
PCWSTR CAttachmentServices::GetExtension(CStringW &strExt)
{
    PCWSTR pszName = m_strFileName.IsEmpty() ? (PCWSTR)m_strLocalPath : (PCWSTR)m_strFileName;
    PCWSTR pszExt = PathFindExtensionW(pszName);
    strExt = pszExt;
    return strExt;
}

static const WCHAR s_HighRiskTypes[] =
    L".ade.adp.app.application.appref-ms.asp.bas.bat.cer.chm.cmd.cnt.com.cpl.crt.csh.der.diagcab.exe.fxp."
    L"gadget.grp.hlp.hpj.hta.inf.ins.isp.its.jar.jnlp.js.jse.ksh.lnk.mad.maf.mag.mam.maq.mar.mas.mat.mau."
    L"mav.maw.mcf.mda.mdb.mde.mdt.mdw.mdz.msc.msh.msh1.msh2.mshxml.msh1xml.msh2xml.msi.msp.mst.ops.osd."
    L"pcd.pif.plg.prf.prg.printerexport.ps1.ps1xml.ps2.ps2xml.psc1.psc2.psd1.psdm1.pst.reg.scf.scr.sct."
    L"shb.shs.theme.tmp.url.vb.vbe.vbp.vbs.vsmacros.vss.vst.vsw.webpnp.website.ws.wsc.wsf.wsh.xbap.xll.xnk.";

bool CAttachmentServices::IsHighRisk()
{
    CStringW strExt;
    GetExtension(strExt);
    if (strExt.GetLength() < 2 || strExt.GetLength() > 24)
        return false;
    strExt.MakeLower();
    strExt += L'.';
    return wcsstr(s_HighRiskTypes, strExt) != NULL;
}

STDMETHODIMP CAttachmentServices::CheckPolicy()
{
    DWORD dwZone;
    HRESULT hr = GetZone(&dwZone, FALSE);
    if (FAILED(hr))
        return hr;
    return (dwZone >= URLZONE_INTERNET) ? S_FALSE : S_OK;
}

static BOOL IsSaveZoneInfoDisabled()
{
    static const WCHAR szKey[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments";
    HKEY hRoots[] = { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE };
    for (UINT i = 0; i < _countof(hRoots); ++i)
    {
        DWORD dwValue = 0, cb = sizeof(dwValue), dwType;
        if (SHGetValueW(hRoots[i], szKey, L"SaveZoneInformation", &dwType, &dwValue, &cb) == ERROR_SUCCESS &&
            dwType == REG_DWORD && dwValue == 1)
            return TRUE;
    }
    return FALSE;
}

static HRESULT WriteAnsiLine(HANDLE hFile, PCSTR psz)
{
    DWORD cb = (DWORD)strlen(psz), cbWritten;
    if (!WriteFile(hFile, psz, cb, &cbWritten, NULL) || cbWritten != cb)
        return HRESULT_FROM_WIN32(GetLastError());
    return S_OK;
}

static HRESULT WriteUrlLine(HANDLE hFile, PCSTR pszKey, PCWSTR pszUrl)
{
    CStringA str(pszKey);
    int cb = WideCharToMultiByte(CP_UTF8, 0, pszUrl, -1, NULL, 0, NULL, NULL);
    if (cb > 1)
    {
        CStringA strUrl;
        WideCharToMultiByte(CP_UTF8, 0, pszUrl, -1, strUrl.GetBuffer(cb), cb, NULL, NULL);
        strUrl.ReleaseBuffer(cb - 1);
        str += strUrl;
    }
    str += "\r\n";
    return WriteAnsiLine(hFile, str);
}

STDMETHODIMP CAttachmentServices::Save()
{
    if (m_strLocalPath.IsEmpty())
        return E_UNEXPECTED;

    DWORD dwAttrs = GetFileAttributesW(m_strLocalPath);
    if (dwAttrs == INVALID_FILE_ATTRIBUTES)
        return HRESULT_FROM_WIN32(GetLastError());

    DWORD dwZone;
    HRESULT hr = GetZone(&dwZone, TRUE);
    if (FAILED(hr))
        return hr;

    if (dwZone < URLZONE_INTERNET || IsSaveZoneInfoDisabled())
        return S_OK; // nothing to mark

    CStringW strStream = m_strLocalPath + ATT_ZONE_STREAM;
    HANDLE hFile = CreateFileW(strStream, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        DWORD dwError = GetLastError();
        // A file system without streams (FAT) cannot carry the mark
        if (dwError == ERROR_INVALID_NAME || dwError == ERROR_NOT_SUPPORTED)
            return S_OK;
        return HRESULT_FROM_WIN32(dwError);
    }

    CStringA strZone;
    strZone.Format("[ZoneTransfer]\r\nZoneId=%lu\r\n", dwZone);
    hr = WriteAnsiLine(hFile, strZone);
    if (SUCCEEDED(hr) && !m_strReferrer.IsEmpty())
        hr = WriteUrlLine(hFile, "ReferrerUrl=", m_strReferrer);
    if (SUCCEEDED(hr))
        hr = WriteUrlLine(hFile, "HostUrl=", m_strSource);
    CloseHandle(hFile);
    return hr;
}

STDMETHODIMP CAttachmentServices::ClearClientState()
{
    // The state (the "don't ask again" memory) is kept in the stream only
    return S_OK;
}

struct ATTDLG
{
    CAttachmentServices *pThis;
    PCWSTR pszName;
    PCWSTR pszType;
    PCWSTR pszFrom;
    bool bExec;
    bool bAlways;
};

static INT_PTR CALLBACK AttachmentDlgProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
        case WM_INITDIALOG:
        {
            ATTDLG *pDlg = (ATTDLG *)lParam;
            WCHAR sz[256];
            LoadStringW(instance, pDlg->bExec ? IDS_ATT_TITLE_EXEC : IDS_ATT_TITLE_SAVE, sz, _countof(sz));
            SetWindowTextW(hwnd, sz);
            LoadStringW(instance, pDlg->bExec ? IDS_ATT_QUESTION_EXEC : IDS_ATT_QUESTION_SAVE, sz, _countof(sz));
            SetDlgItemTextW(hwnd, IDC_ATT_QUESTION, sz);
            LoadStringW(instance, pDlg->bExec ? IDS_ATT_RUN : IDS_ATT_SAVE, sz, _countof(sz));
            SetDlgItemTextW(hwnd, IDOK, sz);
            SetDlgItemTextW(hwnd, IDC_ATT_NAME, pDlg->pszName);
            SetDlgItemTextW(hwnd, IDC_ATT_TYPE, pDlg->pszType);
            SetDlgItemTextW(hwnd, IDC_ATT_FROM, pDlg->pszFrom);
            CheckDlgButton(hwnd, IDC_ATT_ALWAYS, BST_CHECKED);
            SendDlgItemMessageW(hwnd, IDC_ATT_ICON, STM_SETICON, (WPARAM)LoadIconW(NULL, (PCWSTR)IDI_WARNING), 0);
            SetWindowLongPtrW(hwnd, DWLP_USER, (LONG_PTR)pDlg);
            return TRUE;
        }
        case WM_COMMAND:
        {
            switch (LOWORD(wParam))
            {
                case IDOK:
                case IDCANCEL:
                {
                    ATTDLG *pDlg = (ATTDLG *)GetWindowLongPtrW(hwnd, DWLP_USER);
                    pDlg->bAlways = (IsDlgButtonChecked(hwnd, IDC_ATT_ALWAYS) == BST_CHECKED);
                    EndDialog(hwnd, LOWORD(wParam));
                    return TRUE;
                }
            }
            break;
        }
    }
    return FALSE;
}

// The "Open File - Security Warning" dialog (SmartScreen and the publisher
// check are out of scope). Unchecking "Always ask" removes the mark.
HRESULT CAttachmentServices::RunPromptDialog(HWND hwnd, bool bExec, ATTACHMENT_ACTION *pAction)
{
    CStringW strName = m_strFileName.IsEmpty() ? (PCWSTR)PathFindFileNameW(m_strLocalPath) : (PCWSTR)m_strFileName;

    SHFILEINFOW sfi = {};
    WCHAR szType[80] = L"";
    if (SHGetFileInfoW(strName, FILE_ATTRIBUTE_NORMAL, &sfi, sizeof(sfi),
                       SHGFI_TYPENAME | SHGFI_USEFILEATTRIBUTES))
        StringCchCopyW(szType, _countof(szType), sfi.szTypeName);

    // From: the host of the source
    CStringW strFrom = m_strSource.IsEmpty() ? m_strMarkHost : m_strSource;
    WCHAR szHost[ATT_MAX_HOST + 1];
    DWORD cchHost = _countof(szHost);
    if (SUCCEEDED(UrlGetPartW(strFrom, szHost, &cchHost, URL_PART_HOSTNAME, 0)) && szHost[0])
        strFrom = szHost;

    ATTDLG dlg = { this, strName, szType, strFrom, bExec, true };
    INT_PTR ret = DialogBoxParamW(instance, MAKEINTRESOURCEW(IDD_ATTACHMENT_PROMPT), hwnd,
                                  AttachmentDlgProc, (LPARAM)&dlg);
    if (ret != IDOK)
    {
        *pAction = ATTACHMENT_ACTION_CANCEL;
        return S_OK;
    }

    *pAction = bExec ? ATTACHMENT_ACTION_EXEC : ATTACHMENT_ACTION_SAVE;
    if (!dlg.bAlways && !m_strLocalPath.IsEmpty())
        DeleteFileW(m_strLocalPath + ATT_ZONE_STREAM);
    return S_OK;
}

STDMETHODIMP CAttachmentServices::Prompt(HWND hwnd, ATTACHMENT_PROMPT prompt, ATTACHMENT_ACTION *paction)
{
    if (!paction)
        return E_POINTER;
    *paction = ATTACHMENT_ACTION_CANCEL;

    bool bExec = (prompt == ATTACHMENT_PROMPT_EXEC || prompt == ATTACHMENT_PROMPT_EXEC_OR_SAVE);
    ATTACHMENT_ACTION defAction = bExec ? ATTACHMENT_ACTION_EXEC : ATTACHMENT_ACTION_SAVE;
    if (prompt == ATTACHMENT_PROMPT_NONE)
        defAction = ATTACHMENT_ACTION_SAVE;

    HRESULT hr = CheckPolicy();
    if (FAILED(hr))
        return hr;
    // Only the high-risk file types of the Internet zone ask
    if (hr == S_OK || prompt == ATTACHMENT_PROMPT_NONE || !IsHighRisk())
    {
        *paction = defAction;
        return S_OK;
    }
    return RunPromptDialog(hwnd, bExec, paction);
}

STDMETHODIMP CAttachmentServices::Execute(HWND hwnd, LPCWSTR pszVerb, HANDLE *phProcess)
{
    if (phProcess)
        *phProcess = NULL;
    if (m_strLocalPath.IsEmpty())
        return E_UNEXPECTED;

    ATTACHMENT_ACTION action;
    HRESULT hr = Prompt(hwnd, ATTACHMENT_PROMPT_EXEC, &action);
    if (FAILED(hr))
        return hr;
    if (action != ATTACHMENT_ACTION_EXEC)
        return HRESULT_FROM_WIN32(ERROR_CANCELLED);

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOZONECHECKS | SEE_MASK_FLAG_NO_UI;
    sei.hwnd = hwnd;
    sei.lpVerb = pszVerb;
    sei.lpFile = m_strLocalPath;
    sei.nShow = SW_SHOWNORMAL;
    if (!ShellExecuteExW(&sei))
        return HRESULT_FROM_WIN32(GetLastError());
    if (phProcess)
        *phProcess = sei.hProcess;
    else if (sei.hProcess)
        CloseHandle(sei.hProcess);
    return S_OK;
}

STDMETHODIMP CAttachmentServices::SaveWithUI(HWND hwnd)
{
    ATTACHMENT_ACTION action;
    HRESULT hr = Prompt(hwnd, ATTACHMENT_PROMPT_SAVE, &action);
    if (FAILED(hr))
        return hr;
    if (action != ATTACHMENT_ACTION_SAVE)
        return HRESULT_FROM_WIN32(ERROR_CANCELLED);
    return Save();
}
