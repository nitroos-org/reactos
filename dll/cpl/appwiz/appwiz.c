/*
 * PROJECT:                 ReactOS Software Control Panel
 * FILE:                    dll/cpl/appwiz/appwiz.c
 * PURPOSE:                 ReactOS Software Control Panel
 * PROGRAMMERS:             Gero Kuehn (reactos.filter@gkware.com)
 *                          Dmitry Chapyshev (dmitry@reactos.org)
 */

#include "appwiz.h"

#include <shellapi.h>
#include <cpl.h>
#include <wine/unicode.h>

HINSTANCE hApplet = NULL;

static LONG start_params(const WCHAR *params, HWND hwnd_parent)
{
    if (!params)
        return FALSE;

    if (!strcmpW(params, L"install_gecko"))
    {
        install_addon(ADDON_GECKO, hwnd_parent);
        return TRUE;
    }

    if (!strcmpW(params, L"install_mono"))
    {
        install_addon(ADDON_MONO, hwnd_parent);
        return TRUE;
    }

    WARN("unknown param %s\n", debugstr_w(params));
    return FALSE;
}

/* Applets exposed by this .cpl: the classic software list, plus the Windows-
 * native "Turn Windows features on or off" entry that hosts the two-tier
 * optional-feature manager (optfeatures.exe, base/applications/featmgr).
 * This is the ONLY Control Panel item for the feature manager; optionalfeatures.exe
 * and the Programs and Features task link reach it without a second icon. */
#define APPWIZ_APPLET_PROGRAMS  0
#define APPWIZ_APPLET_FEATURES  1
#define APPWIZ_APPLET_COUNT     2

/* Control Panel Callback */
LONG CALLBACK
CPlApplet(HWND hwndCPl, UINT uMsg, LPARAM lParam1, LPARAM lParam2)
{
    CPLINFO *CPlInfo;

    switch (uMsg)
    {
        case CPL_INIT:
            return TRUE;

        case CPL_GETCOUNT:
            return APPWIZ_APPLET_COUNT;

        case CPL_STARTWPARMSW:
            return start_params((const WCHAR *)lParam2, hwndCPl);

        case CPL_INQUIRE:
            CPlInfo = (CPLINFO*)lParam2;
            CPlInfo->lData = 0;
            if (lParam1 == APPWIZ_APPLET_FEATURES)
            {
                CPlInfo->idIcon = IDI_CPLFEATURES;
                CPlInfo->idName = IDS_FEATURESNAME;
                CPlInfo->idInfo = IDS_FEATURESDESCRIPTION;
            }
            else
            {
                CPlInfo->idIcon = IDI_CPLSYSTEM;
                CPlInfo->idName = IDS_CPLSYSTEMNAME;
                CPlInfo->idInfo = IDS_CPLSYSTEMDESCRIPTION;
            }
            break;

        case CPL_DBLCLK:
            if (lParam1 == APPWIZ_APPLET_FEATURES)
            {
                /* "Turn Windows features on or off" -> hosted feature manager */
                ShellExecuteW(NULL,
                              L"open",
                              L"optfeatures.exe",
                              NULL,
                              NULL,
                              SW_SHOWNORMAL);
            }
            else
            {
                ShellExecuteW(NULL,
                              NULL,
                              L"rapps.exe",
                              L"/appwiz",
                              NULL,
                              SW_SHOWNORMAL);
            }
            break;
    }

    return FALSE;
}

BOOL WINAPI
DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpvReserved)
{
    UNREFERENCED_PARAMETER(lpvReserved);

    switch (dwReason)
    {
        case DLL_PROCESS_ATTACH:
        case DLL_THREAD_ATTACH:
            CoInitialize(NULL);
            hApplet = hinstDLL;
            break;
    }

    return TRUE;
}
