/*
 * PROJECT:     ReactOS-Nitro Optional Features launcher
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     optionalfeatures.exe, the Windows name of "Turn Windows features on or
 *              off". It has no Control Panel icon of its own (appwiz.cpl hosts the one
 *              entry); it starts the manager (optfeatures.exe) and passes the command
 *              line through, so it works from Run, scripts and the Programs and
 *              Features task link.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#include <windef.h>
#include <winbase.h>
#include <winuser.h>
#include <shellapi.h>

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, LPWSTR lpCmd, int nShow)
{
    HINSTANCE hRet;

    UNREFERENCED_PARAMETER(hInst);
    UNREFERENCED_PARAMETER(hPrev);

    hRet = ShellExecuteW(NULL, L"open", L"optfeatures.exe",
                         (lpCmd && lpCmd[0]) ? lpCmd : NULL, NULL, nShow);
    if ((INT_PTR)hRet <= 32)
    {
        MessageBoxW(NULL, L"Could not start the Optional Features manager (optfeatures.exe).",
                    L"Optional Features", MB_OK | MB_ICONERROR);
        return 1;
    }
    return 0;
}
