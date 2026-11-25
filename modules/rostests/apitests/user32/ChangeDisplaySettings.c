/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1+ (https://spdx.org/licenses/LGPL-2.1+)
 * PURPOSE:     Tests for ChangeDisplaySettings with CDS_TEST
 */

#include "precomp.h"

static BOOL
IsListed(DWORD Width, DWORD Height, DWORD Bpp)
{
    DEVMODEW dm;
    DWORD i;

    for (i = 0; ; i++)
    {
        ZeroMemory(&dm, sizeof(dm));
        dm.dmSize = sizeof(dm);
        if (!EnumDisplaySettingsW(NULL, i, &dm))
            break;
        if (dm.dmPelsWidth == Width && dm.dmPelsHeight == Height && dm.dmBitsPerPel == Bpp)
            return TRUE;
    }
    return FALSE;
}

START_TEST(ChangeDisplaySettings)
{
    DEVMODEW Current, Request;
    LONG Result;

    ZeroMemory(&Current, sizeof(Current));
    Current.dmSize = sizeof(Current);
    if (!EnumDisplaySettingsW(NULL, ENUM_CURRENT_SETTINGS, &Current))
    {
        skip("No current display settings\n");
        return;
    }

    /* The current mode can be set */
    Request = Current;
    Request.dmFields = DM_PELSWIDTH | DM_PELSHEIGHT | DM_BITSPERPEL;
    Result = ChangeDisplaySettingsW(&Request, CDS_TEST);
    ok(Result == DISP_CHANGE_SUCCESSFUL, "Current mode: %ld\n", Result);

    /* A resolution the display does not list is not supported (nothing is changed with CDS_TEST) */
    Request.dmPelsWidth = Current.dmPelsWidth + 3;
    Request.dmPelsHeight = Current.dmPelsHeight + 1;
    if (IsListed(Request.dmPelsWidth, Request.dmPelsHeight, Request.dmBitsPerPel))
    {
        skip("The odd resolution is listed\n");
    }
    else
    {
        Result = ChangeDisplaySettingsW(&Request, CDS_TEST);
        ok(Result == DISP_CHANGE_BADMODE, "Unlisted resolution: %ld\n", Result);
    }

    /* The same for a color depth the display does not list */
    Request = Current;
    Request.dmFields = DM_PELSWIDTH | DM_PELSHEIGHT | DM_BITSPERPEL;
    Request.dmBitsPerPel = 7;
    Result = ChangeDisplaySettingsW(&Request, CDS_TEST);
    ok(Result == DISP_CHANGE_BADMODE, "Unlisted depth: %ld\n", Result);

    /* The test did not change the mode */
    ZeroMemory(&Request, sizeof(Request));
    Request.dmSize = sizeof(Request);
    ok(EnumDisplaySettingsW(NULL, ENUM_CURRENT_SETTINGS, &Request), "\n");
    ok(Request.dmPelsWidth == Current.dmPelsWidth && Request.dmPelsHeight == Current.dmPelsHeight,
       "Mode changed to %lux%lu\n", Request.dmPelsWidth, Request.dmPelsHeight);
}
