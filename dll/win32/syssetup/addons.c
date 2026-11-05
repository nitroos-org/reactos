/*
 * PROJECT:     ReactOS System Setup
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 *              or GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Addon installation management
 * COPYRIGHT:   Copyright 2026 Carl Bialorucki <carl.bialorucki@reactos.org>
 */

#include "precomp.h"
#include <strsafe.h>

#define NDEBUG
#include <debug.h>

typedef enum _AddonConsent {
    NOT_ASKED,
    APPROVED,
    DENIED
} AddonConsent;

typedef struct _ADDON_INSTALL_DATA
{
    PCWSTR Title;
    PCWSTR AddonPath;
    PCWSTR CreateProcessFormatString;
    PCWSTR FeatmgrPkg;     /* RAPPS catalog package the feature manager installs when the local file is missing or failed */
    DWORD Flags;
} ADDON_INSTALL_DATA, *PADDON_INSTALL_DATA;
typedef const ADDON_INSTALL_DATA* PCADDON_INSTALL_DATA;

/* The installer file stays on disk after a successful install (the optional feature manager reuses it)
 * and a failure is only logged: setup shows no message box and goes on with the next addon. */
#define ADDON_KEEP_FILE_QUIET   0x1

/* TODO: Move this out of code and into an .inf or something. */
static const ADDON_INSTALL_DATA Addons[] = {
#ifdef _M_IX86
    /* Wine Gecko is not installed by setup: it is offered on demand by the feature manager (wine-gecko)
     * and by the add-on prompt of appwiz.cpl on first use of the mshtml engine. */
    {L"WineVDM", L"%SystemRoot%\\winevdm_setup.exe", L"\"%s\" /VERYSILENT", L"winevdm"},
#elif defined(_M_AMD64)
    /* PowerShell 7: the image carries the official MSI (staged at build time) in the feature manager's payload
     * folder. The feature manager installs it silently, local-first, with the properties of its catalog entry
     * (powershell-7.txt), and records the install so that it shows as installed and can be repaired or removed.
     * The format string has no %s: the path is only the "is the MSI in this image" test. */
    {L"PowerShell 7", L"%SystemRoot%\\Featmgr\\Payload\\powershell-7\\PowerShell-x64.msi",
     L"featmgr.exe /enable powershell-7", NULL, ADDON_KEEP_FILE_QUIET},
#endif
    {NULL, NULL, NULL, NULL, 0}
};

HRESULT
RunCommandAndWait(
    _In_ PWCHAR Command)
{
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    DWORD ExitCode = 0;

    if (CreateProcessW(NULL, Command, NULL, NULL, FALSE,
                       0, NULL, NULL, &si, &pi))
    {
        WaitForSingleObject(pi.hProcess, INFINITE);
        GetExitCodeProcess(pi.hProcess, &ExitCode);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        if (ExitCode == 0)
            return S_OK;

        /* The process ran and failed: the last error says nothing about it */
        return HRESULT_FROM_WIN32(ExitCode);
    }

    return HRESULT_FROM_WIN32(GetLastError());
}

BOOL DoesFileExist(
    _In_ PCWSTR path)
{
    DWORD attr = GetFileAttributesW(path);
    return (attr != INVALID_FILE_ATTRIBUTES &&
            !(attr & FILE_ATTRIBUTE_DIRECTORY));
}

HRESULT
InstallAddon(
    _In_    PCADDON_INSTALL_DATA pInstallData,
    _Inout_ AddonConsent* Consent,
    _In_    PITEMSDATA pItemsData,
    _Inout_ PREGISTRATIONNOTIFY pNotify)
{
    HRESULT hr;
    WCHAR Command[MAX_PATH], ExpandedAddonPath[MAX_PATH];

    pNotify->Progress++;
    pNotify->CurrentItem = pInstallData->Title;
    SendMessage(pItemsData->hwndDlg, PM_STEP_START, 3, (LPARAM)pNotify);

    ExpandEnvironmentStringsW(pInstallData->AddonPath,
                              ExpandedAddonPath,
                              ARRAYSIZE(ExpandedAddonPath));

    /* Attempt to install addon from local installer. */
    if (!DoesFileExist(ExpandedAddonPath))
    {
        if (pInstallData->FeatmgrPkg == NULL)
        {
            hr = S_OK;
            goto done;
        }
        goto featmgr_install;
    }

    hr = StringCchPrintfW(Command, ARRAYSIZE(Command),
                          pInstallData->CreateProcessFormatString, ExpandedAddonPath);
    if (!SUCCEEDED(hr))
        goto done;

    hr = RunCommandAndWait(Command);
    if (SUCCEEDED(hr))
    {
        /* We successfully installed the addon locally! Try removing it from disk and finish. */
        if (!(pInstallData->Flags & ADDON_KEEP_FILE_QUIET))
            DeleteFileW(ExpandedAddonPath);
        goto done;
    }

    if (pInstallData->FeatmgrPkg == NULL)
        goto done;

featmgr_install:
    /* Local installer doesn't exist or failed. Try installing through the feature manager (it fetches the
     * RAPPS catalog itself, checks the package's hash and runs the installer silently). */
    if (*Consent == NOT_ASKED)
    {
        WCHAR szMessage[256], szCaption[64];
        LoadStringW(hDllInstance, IDS_INSTALLADDONSMESSAGE, szMessage, ARRAYSIZE(szMessage));
        LoadStringW(hDllInstance, IDS_INSTALLADDONSCAPTION, szCaption, ARRAYSIZE(szCaption));
        int MsgBox = MessageBoxW(NULL, szMessage, szCaption,
                                 MB_YESNO | MB_ICONINFORMATION);
        *Consent = (MsgBox == IDYES) ? APPROVED : DENIED;
    }

    if (*Consent == DENIED)
    {
        hr = HRESULT_FROM_WIN32(ERROR_CANCELLED);
        goto done;
    }

    hr = StringCchPrintfW(Command, ARRAYSIZE(Command), L"featmgr.exe /install %s", pInstallData->FeatmgrPkg);
    if (!SUCCEEDED(hr))
        goto done;

    hr = RunCommandAndWait(Command);

done:
    if ((pInstallData->Flags & ADDON_KEEP_FILE_QUIET) && FAILED(hr))
    {
        /* Log it and let setup continue: nothing here may block or fail the installation. */
        DPRINT1("Addon '%S' failed: 0x%08lx\n", pInstallData->Title, hr);
        LogItem(NULL, L"An optional component could not be installed; setup continues");
        hr = S_OK;
    }
    /* We don't set an error in pNotify because the user chose to cancel the download.
     * Showing an error may make the user think the installation of the operating system failed. */
    if (!SUCCEEDED(hr) && hr != HRESULT_FROM_WIN32(ERROR_CANCELLED))
        pNotify->LastError = HRESULT_CODE(hr);
    SendMessage(pItemsData->hwndDlg, PM_STEP_END, 3, (LPARAM)pNotify);
    return hr;
}

HRESULT
InstallOptionalComponents(
    _In_ PITEMSDATA pItemsData)
{
    HRESULT hr = S_OK;
    PSETUPDATA pSetupData;
    REGISTRATIONNOTIFY Notify = { 0 };
    AddonConsent Consent = NOT_ASKED;

    /* The last element in Addons is null, don't count it as a step. */
    SendMessage(pItemsData->hwndDlg, PM_ITEM_START, 3, (LPARAM)(ARRAYSIZE(Addons) - 1));
    pSetupData = (PSETUPDATA)GetWindowLongPtr(pItemsData->hwndDlg, DWLP_USER);

    if (pSetupData->UnattendSetup)
        Consent = pSetupData->RappsDownload ? APPROVED : DENIED;

    for (DWORD i = 0; i < ARRAYSIZE(Addons); i++)
    {
        if (Addons[i].AddonPath == NULL
            || Addons[i].CreateProcessFormatString == NULL)
            continue;

        hr = InstallAddon(&Addons[i], &Consent, pItemsData, &Notify);

        /* Declining the download is not an error. Reset hr to S_OK. */
        if (hr == HRESULT_FROM_WIN32(ERROR_CANCELLED))
            hr = S_OK;

        if (!SUCCEEDED(hr))
        {
            WCHAR szMessage[256], szCaption[64];
            LoadStringW(hDllInstance, IDS_INSTALLADDONSFAILEDMESSAGE, szMessage, ARRAYSIZE(szMessage));
            LoadStringW(hDllInstance, IDS_INSTALLADDONSCAPTION, szCaption, ARRAYSIZE(szCaption));
            MessageBoxW(NULL, szMessage, szCaption,
                        MB_OK | MB_ICONWARNING | MB_TOPMOST);
            break;
        }
    }

    SendMessage(pItemsData->hwndDlg, PM_ITEM_END, 3, HRESULT_CODE(hr));
    return hr;
}
