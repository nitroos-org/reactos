/*
 * PROJECT:     ReactOS common controls
 * LICENSE:     LGPL-2.1-or-later (see COPYING.LIB in the top level directory)
 * PURPOSE:     The helpers of commctrl.c as the v5 (5.82) controls need them: no themes, v5 version rules
 *              (the v6 flavour of the same functions is in commctrl.c, the names carry _v5, see comctl32.h)
 */

#define __WINE_COMCTL32_VERSION 5
#include "../comctl32.h"

void COMCTL32_OpenThemeForWindow(HWND hwnd, const WCHAR *theme_class)
{
}

void COMCTL32_CloseThemeForWindow(HWND hwnd)
{
}

/* A helper to handle CCM_SETVERSION messages */
LRESULT COMCTL32_SetVersion(INT *current_version, INT new_version)
{
    INT old_version;

    if (new_version > 5)
        return -1;

    old_version = *current_version;
    *current_version = new_version;
    return old_version;
}

/* A helper to handle WM_THEMECHANGED messages */
LRESULT COMCTL32_ThemeChanged(HWND hwnd, const WCHAR *theme_class, BOOL invalidate, BOOL erase)
{
    return DefWindowProcW(hwnd, WM_THEMECHANGED, 0, 0);
}

/* A helper to handle WM_NCPAINT messages */
LRESULT COMCTL32_NCPaint(HWND hwnd, WPARAM wp, LPARAM lp, const WCHAR *theme_class)
{
    return DefWindowProcW(hwnd, WM_NCPAINT, wp, lp);
}

BOOL COMCTL32_IsThemed(HWND hwnd)
{
    return FALSE;
}
