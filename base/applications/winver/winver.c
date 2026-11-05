/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Version Program
 * FILE:            base/applications/winver/winver.c
 */

#include "winver_p.h"
#include <reactos/buildno.h>

HINSTANCE Winver_hInstance;

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow)
{
    INITCOMMONCONTROLSEX iccx;
    WINVER_OS_INFO OSInfo;

    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);

    Winver_hInstance = hInstance;

    /* Initialize common controls */
    iccx.dwSize = sizeof(iccx);
    iccx.dwICC = ICC_STANDARD_CLASSES | ICC_WIN95_CLASSES;
    InitCommonControlsEx(&iccx);

    if (!Winver_GetOSInfo(&OSInfo))
    {
        /* OS info is not available, display the default contents */
        OSInfo.szCompatInfo[0] = UNICODE_NULL;
    }

    /* The product name; the registry ProductName stays as programs expect it */
    StringCchCopyW(OSInfo.szName, _countof(OSInfo.szName), BRAND_PRODUCT_NAME_W);

    return ShellAboutW(NULL, OSInfo.szName, OSInfo.szCompatInfo, NULL);
}
