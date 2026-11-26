/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1+ (https://spdx.org/licenses/LGPL-2.1+)
 * PURPOSE:     Tests for ChangeDisplaySettingsEx with CDS_TEST, and the refusals of a real change
 *
 * The expectations were measured on Windows Server 2022 (QEMU standard VGA, every mode listed at one rate, 32 bits):
 * a listed mode is supported with or without a color depth or refresh rate in dmFields; a refresh rate of 0 or 1
 * means the adapter's default; any other rate the mode is not listed at, any resolution that is not listed, a color
 * depth that is not listed and a color depth of 0 named in dmFields give DISP_CHANGE_BADMODE. A change without
 * CDS_TEST, with or without CDS_FULLSCREEN, answers the same and keeps the mode when it refuses.
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

static LONG
Change(DWORD Flags, DWORD Width, DWORD Height, DWORD UseBpp, DWORD Bpp, DWORD UseFreq, DWORD Freq)
{
    DEVMODEW dm;

    ZeroMemory(&dm, sizeof(dm));
    dm.dmSize = sizeof(dm);
    dm.dmFields = DM_PELSWIDTH | DM_PELSHEIGHT;
    dm.dmPelsWidth = Width;
    dm.dmPelsHeight = Height;
    if (UseBpp)
    {
        dm.dmFields |= DM_BITSPERPEL;
        dm.dmBitsPerPel = Bpp;
    }
    if (UseFreq)
    {
        dm.dmFields |= DM_DISPLAYFREQUENCY;
        dm.dmDisplayFrequency = Freq;
    }
    return ChangeDisplaySettingsExW(NULL, &dm, NULL, Flags, NULL);
}

static LONG
Test(DWORD Width, DWORD Height, DWORD UseBpp, DWORD Bpp, DWORD UseFreq, DWORD Freq)
{
    return Change(CDS_TEST, Width, Height, UseBpp, Bpp, UseFreq, Freq);
}

START_TEST(ChangeDisplaySettings)
{
    DEVMODEW Current, After;
    DWORD W, H, B, F, Flags;

    ZeroMemory(&Current, sizeof(Current));
    Current.dmSize = sizeof(Current);
    if (!EnumDisplaySettingsW(NULL, ENUM_CURRENT_SETTINGS, &Current))
    {
        skip("No current display settings\n");
        return;
    }
    W = Current.dmPelsWidth;
    H = Current.dmPelsHeight;
    B = Current.dmBitsPerPel;
    F = Current.dmDisplayFrequency;

    /* The current mode, with and without a depth and a rate */
    ok_long(Test(W, H, 0, 0, 0, 0), DISP_CHANGE_SUCCESSFUL);
    ok_long(Test(W, H, 1, B, 0, 0), DISP_CHANGE_SUCCESSFUL);
    ok_long(Test(W, H, 1, B, 1, F), DISP_CHANGE_SUCCESSFUL);
    ok_long(Test(W, H, 0, 0, 1, F), DISP_CHANGE_SUCCESSFUL);

    /* A rate of 0 or 1 is the adapter's default */
    ok_long(Test(W, H, 1, B, 1, 0), DISP_CHANGE_SUCCESSFUL);
    ok_long(Test(W, H, 1, B, 1, 1), DISP_CHANGE_SUCCESSFUL);
    ok_long(Test(W, H, 0, 0, 1, 0), DISP_CHANGE_SUCCESSFUL);
    ok_long(Test(W, H, 0, 0, 1, 1), DISP_CHANGE_SUCCESSFUL);

    /* A rate the mode is not listed at (a mode listed at 0 or 1 is available at any rate) */
    if (F > 1)
    {
        ok_long(Test(W, H, 1, B, 1, 97), DISP_CHANGE_BADMODE);
        ok_long(Test(W, H, 0, 0, 1, 97), DISP_CHANGE_BADMODE);
    }
    else
    {
        ok_long(Test(W, H, 1, B, 1, 97), DISP_CHANGE_SUCCESSFUL);
    }

    /* A resolution the display does not list, whatever else is named */
    if (IsListed(W + 3, H + 1, B))
    {
        skip("The odd resolution is listed\n");
    }
    else
    {
        ok_long(Test(W + 3, H + 1, 0, 0, 0, 0), DISP_CHANGE_BADMODE);
        ok_long(Test(W + 3, H + 1, 1, B, 0, 0), DISP_CHANGE_BADMODE);
        ok_long(Test(W + 3, H + 1, 1, B, 1, F), DISP_CHANGE_BADMODE);
        ok_long(Test(W + 3, H + 1, 1, B, 1, 0), DISP_CHANGE_BADMODE);
        ok_long(Test(W + 3, H + 1, 1, B, 1, 1), DISP_CHANGE_BADMODE);
    }
    ok_long(Test(1, 1, 1, B, 0, 0), DISP_CHANGE_BADMODE);

    /* A color depth the display does not list, and a depth of 0 that is named */
    ok_long(Test(W, H, 1, 7, 0, 0), DISP_CHANGE_BADMODE);
    ok_long(Test(W, H, 1, 0, 0, 0), DISP_CHANGE_BADMODE);

    /* Windows lists 8 and 16 bit modes to a 32 bit program (it emulates them) and accepts them; a 64 bit program is
     * refused a depth the display does not list */
    ok_long(Test(W, H, 1, 16, 0, 0), (IsListed(W, H, 16) || sizeof(void *) == 4) ? DISP_CHANGE_SUCCESSFUL : DISP_CHANGE_BADMODE);
    ok_long(Test(W, H, 1, 8, 0, 0), (IsListed(W, H, 8) || sizeof(void *) == 4) ? DISP_CHANGE_SUCCESSFUL : DISP_CHANGE_BADMODE);
    if (sizeof(void *) == 4 && IsListed(W + 3, H + 1, 16) == FALSE && !IsListed(W + 3, H + 1, B))
        ok_long(Test(W + 3, H + 1, 1, 16, 0, 0), DISP_CHANGE_BADMODE);

    /* The tests did not change the mode */
    ZeroMemory(&After, sizeof(After));
    After.dmSize = sizeof(After);
    ok(EnumDisplaySettingsW(NULL, ENUM_CURRENT_SETTINGS, &After), "\n");
    ok(After.dmPelsWidth == W && After.dmPelsHeight == H && After.dmBitsPerPel == B,
       "Mode changed to %lux%lu\n", After.dmPelsWidth, After.dmPelsHeight);

    /* The same requests without CDS_TEST, with and without CDS_FULLSCREEN (measured on Windows Server 2022: the
     * answer is the one of the test and a refused change leaves the mode as it was). Only refusals and the change
     * to the current mode are made here: a change to another mode would be seen by whatever else runs */
    for (Flags = 0; Flags < 2; Flags++)
    {
        DWORD Fl = Flags ? CDS_FULLSCREEN : 0;

        ok_long(Change(Fl, W, H, 1, B, 1, 0), DISP_CHANGE_SUCCESSFUL);
        ok_long(Change(Fl, W, H, 1, B, 1, 1), DISP_CHANGE_SUCCESSFUL);
        ok_long(Change(Fl, W, H, 0, 0, 0, 0), DISP_CHANGE_SUCCESSFUL);
        if (F > 1)
            ok_long(Change(Fl, W, H, 1, B, 1, 97), DISP_CHANGE_BADMODE);
        if (!IsListed(W + 3, H + 1, B))
        {
            ok_long(Change(Fl, W + 3, H + 1, 0, 0, 0, 0), DISP_CHANGE_BADMODE);
            ok_long(Change(Fl, W + 3, H + 1, 1, B, 1, F), DISP_CHANGE_BADMODE);
        }
        ok_long(Change(Fl, 1, 1, 1, B, 0, 0), DISP_CHANGE_BADMODE);
        ok_long(Change(Fl, W, H, 1, 7, 0, 0), DISP_CHANGE_BADMODE);
        ok_long(Change(Fl, W, H, 1, 0, 0, 0), DISP_CHANGE_BADMODE);

        ZeroMemory(&After, sizeof(After));
        After.dmSize = sizeof(After);
        ok(EnumDisplaySettingsW(NULL, ENUM_CURRENT_SETTINGS, &After), "\n");
        ok(After.dmPelsWidth == W && After.dmPelsHeight == H && After.dmBitsPerPel == B,
           "Mode changed to %lux%lu\n", After.dmPelsWidth, After.dmPelsHeight);
    }
    /* A test never changes the mode or the registry, also for a depth that is found another way (a 32 bit program that
     * asks for 8 or 16 bits). Another listed resolution, so that a change would show */
    {
        DEVMODEW dm;
        DWORD i, OtherW = 0, OtherH = 0, Depths[2] = { 8, 16 }, d;

        for (i = 0; ; i++)
        {
            ZeroMemory(&dm, sizeof(dm));
            dm.dmSize = sizeof(dm);
            if (!EnumDisplaySettingsW(NULL, i, &dm))
                break;
            if (dm.dmBitsPerPel == B && (dm.dmPelsWidth != W || dm.dmPelsHeight != H))
            {
                OtherW = dm.dmPelsWidth;
                OtherH = dm.dmPelsHeight;
                break;
            }
        }

        if (!OtherW)
        {
            skip("No other listed resolution\n");
        }
        else
        {
            DWORD TestFlags[2] = { CDS_TEST, CDS_TEST | CDS_UPDATEREGISTRY };

            for (i = 0; i < 2; i++)
            {
                /* The listed depth first, then 8 and 16 bits (the answer for those depends on the process, see above) */
                for (d = 0; d < 3; d++)
                {
                    DWORD Bpp = d == 0 ? B : Depths[d - 1];
                    LONG Want = DISP_CHANGE_SUCCESSFUL;

                    if (d != 0 && !IsListed(OtherW, OtherH, Bpp) && sizeof(void *) == 8)
                        Want = DISP_CHANGE_BADMODE;
                    ok_long(Change(TestFlags[i], OtherW, OtherH, 1, Bpp, 0, 0), Want);

                    ZeroMemory(&After, sizeof(After));
                    After.dmSize = sizeof(After);
                    ok(EnumDisplaySettingsW(NULL, ENUM_CURRENT_SETTINGS, &After), "\n");
                    ok(After.dmPelsWidth == W && After.dmPelsHeight == H && After.dmBitsPerPel == B,
                       "Flags %lx, %lux%lux%lu: mode changed to %lux%lux%lu\n", TestFlags[i], OtherW, OtherH, Bpp,
                       After.dmPelsWidth, After.dmPelsHeight, After.dmBitsPerPel);
                    if (After.dmPelsWidth != W || After.dmPelsHeight != H || After.dmBitsPerPel != B)
                    {
                        /* Put it back, whatever the registry says now */
                        ZeroMemory(&dm, sizeof(dm));
                        dm.dmSize = sizeof(dm);
                        dm.dmFields = DM_PELSWIDTH | DM_PELSHEIGHT | DM_BITSPERPEL;
                        dm.dmPelsWidth = W;
                        dm.dmPelsHeight = H;
                        dm.dmBitsPerPel = B;
                        ChangeDisplaySettingsExW(NULL, &dm, NULL, CDS_UPDATEREGISTRY, NULL);
                    }
                }

                /* What the registry holds is what a change without a mode applies: it is still the current mode */
                ChangeDisplaySettingsExW(NULL, NULL, NULL, 0, NULL);
                ZeroMemory(&After, sizeof(After));
                After.dmSize = sizeof(After);
                ok(EnumDisplaySettingsW(NULL, ENUM_CURRENT_SETTINGS, &After), "\n");
                ok(After.dmPelsWidth == W && After.dmPelsHeight == H && After.dmBitsPerPel == B,
                   "Flags %lx: the registry mode is %lux%lux%lu\n", TestFlags[i],
                   After.dmPelsWidth, After.dmPelsHeight, After.dmBitsPerPel);
            }
        }
    }
    ChangeDisplaySettingsExW(NULL, NULL, NULL, 0, NULL);
}
