/*
 * PROJECT:     ReactOS Secondary Logon Service
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     The service's helper in another session: gives and takes back the window station and desktop entries
 *              of a secondary logon there (see SeclHelperMain in desktop.c)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Started by the Secondary Logon service as SYSTEM, on the Winlogon desktop of the session. It makes no window and
 * runs no message loop. Its exit code is the result.
 */

#include <stdarg.h>
#include <windef.h>
#include <winbase.h>

DWORD WINAPI SeclHelperMain(PCWSTR CommandLine);

int
WINAPI
wWinMain(
    _In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ PWSTR lpCmdLine,
    _In_ int nShowCmd)
{
    UNREFERENCED_PARAMETER(hInstance);
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(nShowCmd);

    return (int)SeclHelperMain(lpCmdLine);
}
