/*
 * PROJECT:     shell32
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     IApplicationActivationManager implementation
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * There are no packaged (UWP) apps here. The one app that callers activate is the Windows
 * Settings app: a browser's "Make default" button asks it for its "Default apps" page
 * (Chrome: windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel,
 * arguments "page=SettingsPageAppsDefaults..."). That page is the browser chooser, which is
 * what an ms-settings:defaultapps link opens as well.
 */

#include "precomp.h"

WINE_DEFAULT_DEBUG_CHANNEL(shell);

// Windows 10 22H2's answer for the AppUserModelID of a packaged app that is not installed
// (measured: "Contoso.NoSuchApp_8wekyb3d8bbwe!App" -> 0x80073cf1)
#define ACTIVATION_ERR_NOT_REGISTERED   ((HRESULT)0x80073CF1L)

static const WCHAR s_szSettingsAumid[] =
    L"windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel";

CApplicationActivationManager::CApplicationActivationManager()
{
}

CApplicationActivationManager::~CApplicationActivationManager()
{
}

STDMETHODIMP
CApplicationActivationManager::ActivateApplication(LPCWSTR pszAppUserModelId, LPCWSTR pszArguments,
                                                   ACTIVATEOPTIONS options, DWORD *pdwProcessId)
{
    TRACE("(%p)->(%s, %s, %x, %p)\n", this, debugstr_w(pszAppUserModelId), debugstr_w(pszArguments),
          options, pdwProcessId);

    if (!pszAppUserModelId || !pdwProcessId)
        return E_INVALIDARG;
    *pdwProcessId = 0;

    if (lstrcmpiW(pszAppUserModelId, s_szSettingsAumid))
        return ACTIVATION_ERR_NOT_REGISTERED;

    // Only the "Default apps" pages have something behind them (the browser chooser).
    LPCWSTR pszUri = L"ms-settings:";
    if (pszArguments && !StrCmpNIW(pszArguments, L"page=SettingsPageAppsDefaults", 29))
        pszUri = L"ms-settings:defaultapps";

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    sei.lpFile = pszUri;
    sei.nShow = SW_SHOWNORMAL;
    if (!ShellExecuteExW(&sei))
    {
        DWORD dwError = GetLastError();
        ERR("ShellExecuteEx(%s) failed %lu\n", debugstr_w(pszUri), dwError);
        return HRESULT_FROM_WIN32(dwError ? dwError : ERROR_GEN_FAILURE);
    }
    if (sei.hProcess)
    {
        *pdwProcessId = GetProcessId(sei.hProcess);
        CloseHandle(sei.hProcess);
    }
    return S_OK;
}

STDMETHODIMP
CApplicationActivationManager::ActivateForFile(LPCWSTR pszAppUserModelId, IShellItemArray *pItemArray,
                                               LPCWSTR pszVerb, DWORD *pdwProcessId)
{
    FIXME("(%p)->(%s, %p, %s, %p) stub\n", this, debugstr_w(pszAppUserModelId), pItemArray,
          debugstr_w(pszVerb), pdwProcessId);
    if (pdwProcessId)
        *pdwProcessId = 0;
    return ACTIVATION_ERR_NOT_REGISTERED;
}

STDMETHODIMP
CApplicationActivationManager::ActivateForProtocol(LPCWSTR pszAppUserModelId, IShellItemArray *pItemArray,
                                                   DWORD *pdwProcessId)
{
    FIXME("(%p)->(%s, %p, %p) stub\n", this, debugstr_w(pszAppUserModelId), pItemArray, pdwProcessId);
    if (pdwProcessId)
        *pdwProcessId = 0;
    return ACTIVATION_ERR_NOT_REGISTERED;
}
