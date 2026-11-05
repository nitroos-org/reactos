/*
 * Dwmapi
 *
 * Copyright 2007 Andras Kovacs
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 */

#include <stdarg.h>

#ifdef __REACTOS__
#include <rtlfuncs.h>
#else
#include "winternl.h"
#endif

#define COBJMACROS
#include "windef.h"
#include "winbase.h"
#include "wingdi.h"
#include "winuser.h"
#include "dwmapi.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(dwmapi);


/**********************************************************************
 *           DwmIsCompositionEnabled         (DWMAPI.@)
 */
HRESULT WINAPI DwmIsCompositionEnabled(BOOL *enabled)
{

#ifdef __REACTOS__
    RTL_OSVERSIONINFOW version;
#else
    RTL_OSVERSIONINFOEXW version;
#endif

    TRACE("%p\n", enabled);

    if (!enabled)
        return E_INVALIDARG;

    *enabled = FALSE;
    version.dwOSVersionInfoSize = sizeof(version);
    if (!RtlGetVersion(&version))
        *enabled = (version.dwMajorVersion > 6 || (version.dwMajorVersion == 6 && version.dwMinorVersion >= 3));

    return S_OK;
}

/**********************************************************************
 *           DwmEnableComposition         (DWMAPI.102)
 */
HRESULT WINAPI DwmEnableComposition(UINT uCompositionAction)
{
    FIXME("(%d) stub\n", uCompositionAction);

    return S_OK;
}

/**********************************************************************
 *           DwmExtendFrameIntoClientArea    (DWMAPI.@)
 */
HRESULT WINAPI DwmExtendFrameIntoClientArea(HWND hwnd, const MARGINS* margins)
{
    typedef BOOL (WINAPI *PFN_SETGLASS)(HWND, BOOL);
    static PFN_SETGLASS pfnSetGlass;
    static BOOL once;
    BOOL glass;

    TRACE("(%p, %p)\n", hwnd, margins);

    if (!margins)
        return E_POINTER;
    if (!IsWindow(hwnd))
        return E_HANDLE;

    /*
     * There is no compositor to blend a "sheet of glass" window with what lies below it. Programs that
     * use one for a shaped or translucent popup (Firefox, Chromium) draw premultiplied ARGB into it:
     * mark the window, and win32k blends their copies of a 32 bpp DIB with alpha over what is below.
     */
    if (!once)
    {
        HMODULE hUser = GetModuleHandleW(L"user32.dll");
        if (hUser)
            pfnSetGlass = (PFN_SETGLASS)GetProcAddress(hUser, "NitroSetWindowGlass");
        once = TRUE;
    }
    glass = margins->cxLeftWidth == -1 && margins->cxRightWidth == -1 &&
            margins->cyTopHeight == -1 && margins->cyBottomHeight == -1;
    /*
     * win32k only marks a window of the calling process. The answer for a window of another process is
     * S_OK all the same, with the window left as it was: what Windows answers for one was not observed.
     */
    if (pfnSetGlass)
        pfnSetGlass(hwnd, glass);

    return S_OK;
}

/**********************************************************************
 *           DwmGetColorizationColor      (DWMAPI.@)
 */
HRESULT WINAPI DwmGetColorizationColor(DWORD *colorization, BOOL *opaque_blend)
{
#ifdef __REACTOS__
    /* Windows 10 22H2 in an interactive session: S_OK, ARGB 0xe3006fc7 and opaque TRUE (the default accent) */
    TRACE("(%p, %p)\n", colorization, opaque_blend);

    if (!colorization || !opaque_blend)
        return E_INVALIDARG;
    *colorization = 0xe3006fc7;
    *opaque_blend = TRUE;
    return S_OK;
#else
    FIXME("(%p, %p) stub\n", colorization, opaque_blend);

    return E_NOTIMPL;
#endif
}

#ifdef __REACTOS__
static int get_display_frequency(void);
#endif

/**********************************************************************
 *                  DwmFlush              (DWMAPI.@)
 */
HRESULT WINAPI DwmFlush(void)
{
#ifdef __REACTOS__
    /* DwmFlush blocks until the next composition pass, at most one refresh
     * period. Applications pace their vsync threads with it (Firefox ESR 128
     * D3DVsyncSource: NotifyVsync, DwmFlush, repeat): an immediate return
     * turns that thread into a busy loop that floods the refresh driver and
     * the content processes. Wait for the next vblank boundary on the grid
     * DwmGetCompositionTimingInfo reports (qpcVBlank + qpcRefreshPeriod). */
    LARGE_INTEGER frequency, qpc;
    LONGLONG period, next;
    DWORD ms;
    int hz;

    TRACE("()\n");

    /* 0 and 1 mean "hardware default"; never wait a second or spin */
    hz = get_display_frequency();
    if (hz < 2 || hz > 1000)
        hz = 60;

    QueryPerformanceFrequency(&frequency);
    period = frequency.QuadPart / hz;
    if (period <= 0)
        period = 1;

    QueryPerformanceCounter(&qpc);
    next = (qpc.QuadPart / period + 1) * period;
    ms = (DWORD)(((next - qpc.QuadPart) * 1000 + frequency.QuadPart - 1) / frequency.QuadPart);
    Sleep(ms ? ms : 1);

    return S_OK;
#else
    static BOOL once;

    if (!once++) FIXME("() stub\n");

    return S_OK;
#endif
}

/**********************************************************************
 *        DwmInvalidateIconicBitmaps      (DWMAPI.@)
 */
HRESULT WINAPI DwmInvalidateIconicBitmaps(HWND hwnd)
{
    static BOOL once;

    if (!once++) FIXME("(%p) stub\n", hwnd);

    return E_NOTIMPL;
}

/**********************************************************************
 *           DwmSetWindowAttribute         (DWMAPI.@)
 */
#ifdef __REACTOS__
/*
 * DWMWA_NCRENDERING_POLICY (2), measured on Windows 10 22H2: a DWORD, S_OK for any value (also 3), E_INVALIDARG
 * for a size other than 4 or a NULL pointer. DWMNCRP_DISABLED (1) turns the non-client rendering off for the
 * window, DWMNCRP_ENABLED (2) on even for a window without a caption, DWMNCRP_USEWINDOWSTYLE (0) leaves it to
 * the window style; DWMWA_NCRENDERING_ENABLED and the caption button bounds follow it, also for a hidden window.
 * The policy is kept in the window property NitroDwmNc, which win32k reads. What happens when it changes (the
 * frame change and WM_DWMNCRENDERINGCHANGED) is decided by win32k when the window's thread takes the message
 * posted here, see IntDwmNcResolve: Windows too does it a moment after the call has returned.
 */
#define NITRO_NC_POLICY_MASK 3
#define NITRO_NC_POLICY_POSTED_LPARAM 0x4E4D5745 /* DWMNC_POLICY of win32k */

/* The property is an integer atom: RegisterWindowMessage gives the atom of win32k's table that win32k reads it with */
static LPCWSTR nitro_nc_prop(void)
{
    static UINT atom;

    if (!atom)
        atom = RegisterWindowMessageW(L"NitroDwmNc");
    return (LPCWSTR)(ULONG_PTR)atom;
}

static ULONG_PTR get_nc_data(HWND hwnd)
{
    return (ULONG_PTR)GetPropW(hwnd, nitro_nc_prop());
}

/* The state of the non-client rendering of a window for the policy in the low bits of data */
static BOOL nc_rendering_enabled(HWND hwnd, ULONG_PTR data)
{
    switch (data & NITRO_NC_POLICY_MASK)
    {
        case 1: return FALSE;
        case 2: return TRUE;
        default: return (GetWindowLongW(hwnd, GWL_STYLE) & WS_CAPTION) == WS_CAPTION;
    }
}

static HRESULT set_ncrendering_policy(HWND hwnd, DWORD policy)
{
    SetPropW(hwnd, nitro_nc_prop(), (HANDLE)(ULONG_PTR)(policy == 1 || policy == 2 ? policy : 0));
    PostMessageW(hwnd, WM_DWMNCRENDERINGCHANGED, 0, NITRO_NC_POLICY_POSTED_LPARAM);
    return S_OK;
}
#endif

HRESULT WINAPI DwmSetWindowAttribute(HWND hwnd, DWORD attributenum, LPCVOID attribute, DWORD size)
{
#ifdef __REACTOS__
    TRACE("(%p, %lx, %p, %lx)\n", hwnd, attributenum, attribute, size);

    if (attributenum == 2 /* DWMWA_NCRENDERING_POLICY */)
    {
        if (!IsWindow(hwnd))
            return HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE);
        if (!attribute || size != sizeof(DWORD))
            return E_INVALIDARG;
        return set_ncrendering_policy(hwnd, *(const DWORD *)attribute);
    }
#endif
    {
        static BOOL once;

        if (!once++) FIXME("(%p, %lx, %p, %lx) stub\n", hwnd, attributenum, attribute, size);
    }

    return S_OK;
}

/**********************************************************************
 *           DwmGetGraphicsStreamClient         (DWMAPI.@)
 */
HRESULT WINAPI DwmGetGraphicsStreamClient(UINT uIndex, UUID *pClientUuid)
{
    FIXME("(%d, %p) stub\n", uIndex, pClientUuid);

    return E_NOTIMPL;
}

/**********************************************************************
 *           DwmGetTransportAttributes         (DWMAPI.@)
 */
HRESULT WINAPI DwmGetTransportAttributes(BOOL *pfIsRemoting, BOOL *pfIsConnected, DWORD *pDwGeneration)
{
#ifdef __REACTOS__
    /* Windows 10 22H2 in an interactive session: S_OK, not remoting, connected, generation 1 (a session
     * without a desktop answers DWM_E_COMPOSITIONDISABLED) */
    TRACE("(%p, %p, %p)\n", pfIsRemoting, pfIsConnected, pDwGeneration);

    if (!pfIsRemoting || !pfIsConnected || !pDwGeneration)
        return E_INVALIDARG;
    *pfIsRemoting = FALSE;
    *pfIsConnected = TRUE;
    *pDwGeneration = 1;
    return S_OK;
#else
    FIXME("(%p, %p, %p) stub\n", pfIsRemoting, pfIsConnected, pDwGeneration);

    return DWM_E_COMPOSITIONDISABLED;
#endif
}

/**********************************************************************
 *           DwmUnregisterThumbnail         (DWMAPI.@)
 */
HRESULT WINAPI DwmUnregisterThumbnail(HTHUMBNAIL thumbnail)
{
    FIXME("(%p) stub\n", thumbnail);

    return E_NOTIMPL;
}

/**********************************************************************
 *           DwmEnableMMCSS         (DWMAPI.@)
 */
HRESULT WINAPI DwmEnableMMCSS(BOOL enableMMCSS)
{
    FIXME("(%d) stub\n", enableMMCSS);

    return S_OK;
}

/**********************************************************************
 *           DwmGetGraphicsStreamTransformHint         (DWMAPI.@)
 */
HRESULT WINAPI DwmGetGraphicsStreamTransformHint(UINT uIndex, MilMatrix3x2D *pTransform)
{
    FIXME("(%d, %p) stub\n", uIndex, pTransform);

    return E_NOTIMPL;
}

/**********************************************************************
 *           DwmEnableBlurBehindWindow         (DWMAPI.@)
 */
HRESULT WINAPI DwmEnableBlurBehindWindow(HWND hWnd, const DWM_BLURBEHIND *pBlurBuf)
{
    FIXME("%p %p\n", hWnd, pBlurBuf);

    return E_NOTIMPL;
}

/**********************************************************************
 *           DwmDefWindowProc         (DWMAPI.@)
 */
BOOL WINAPI DwmDefWindowProc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam, LRESULT *plResult)
{
    static int i;

    if (!i++) FIXME("stub\n");

    return FALSE;
}

#ifdef __REACTOS__
/*
 * DwmGetWindowAttribute. The answers below were measured on Windows 10 22H2 (interactive session, 96 DPI)
 * for attributes 0..40 with buffer sizes 0, 1, 4, 8 and 16, on an overlapped, a maximized, a minimized,
 * a hidden, a layered, a tool, a popup-with-caption, a dialog-modal-frame and a caption-less popup window,
 * and on the shell's windows:
 *   - an invalid or NULL window is E_HANDLE, a NULL buffer E_INVALIDARG;
 *   - NCRENDERING_ENABLED (1), CLOAKED (14), FREEZE_REPRESENTATION (15), PASSIVE_UPDATE_MODE (16) and
 *     USE_IMMERSIVE_DARK_MODE (20) are DWORDs: S_OK with any size from 4 up, E_INVALIDARG below. Every
 *     window answers 0 for the last four; NCRENDERING_ENABLED is 1 for a window with a caption and 0 for
 *     one without (a caption-less popup, the taskbar, the desktop);
 *   - CAPTION_BUTTON_BOUNDS (5) and EXTENDED_FRAME_BOUNDS (9) are RECTs: S_OK with 16 bytes,
 *     HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) with 4 or 8, E_INVALIDARG with 0 or 1;
 *   - every other attribute 0..40 (2, 3, 4, 6, 7, 8, 10, 11, 12, 13, 17..19, 21..40) is E_INVALIDARG.
 * Sizes 2, 3, 5..15 and above 16 were not measured: below 4 is taken as invalid, 4..15 as too small for a
 * RECT, above 16 as enough.
 *
 * CAPTION_BUTTON_BOUNDS is the rectangle of the system caption buttons, in window coordinates. Measured
 * (frame fw = 8 for a sizing frame, 3 for a fixed one, SM_CYCAPTION 23, 96 DPI): top 0, bottom fw + 23 - 1
 * (30 / 25); right = the right edge of EXTENDED_FRAME_BOUNDS (width - 7 with the 7 invisible pixels of a
 * sizing frame, width - 2 for a fixed frame), and width - fw - 1 for a maximized window; left = right - 146
 * for the three buttons of a window with a system menu and a minimize or maximize box, right - 49 for the
 * close button alone (no such box, or a tool window). A window without a caption, and one whose non-client
 * rendering is disabled by DwmSetWindowAttribute(DWMWA_NCRENDERING_POLICY, DWMNCRP_DISABLED), has an all-zero RECT. It is
 * the same for a hidden and for a minimized window (the right edge follows the minimized rectangle).
 *
 * EXTENDED_FRAME_BOUNDS is the window rectangle in screen coordinates without the invisible resize border
 * of Windows 10 and, for a maximized window, without its off-screen overhang (the work area). ReactOS draws
 * no invisible border, so its frame bounds are the window rectangle, except for a maximized window.
 * Not measured here: a window with another DPI than the system's (button width and caption scale with
 * the DPI as on Windows is assumed), WS_EX_CONTEXTHELP's third button, a window without WS_SYSMENU (zero
 * RECT assumed), a window with only WS_DLGFRAME.
 */
#define NITRO_CAPTION_BUTTON_CX 46
#ifndef SM_CXPADDEDBORDER
#define SM_CXPADDEDBORDER 92
#endif

static UINT get_window_dpi(HWND hwnd)
{
    typedef UINT (WINAPI *PFN_GETDPIFORWINDOW)(HWND);
    static PFN_GETDPIFORWINDOW pGetDpiForWindow;
    static BOOL once;
    UINT dpi = 0;

    if (!once)
    {
        HMODULE hUser = GetModuleHandleW(L"user32.dll");
        if (hUser)
            pGetDpiForWindow = (PFN_GETDPIFORWINDOW)GetProcAddress(hUser, "GetDpiForWindow");
        once = TRUE;
    }
    if (pGetDpiForWindow)
        dpi = pGetDpiForWindow(hwnd);
    return dpi ? dpi : 96;
}

static BOOL window_has_caption(HWND hwnd)
{
    return (GetWindowLongW(hwnd, GWL_STYLE) & WS_CAPTION) != 0;
}

static LONG window_frame_width(HWND hwnd)
{
    if (GetWindowLongW(hwnd, GWL_STYLE) & WS_THICKFRAME)
        return GetSystemMetrics(SM_CXSIZEFRAME) + GetSystemMetrics(SM_CXPADDEDBORDER);
    return GetSystemMetrics(SM_CXFIXEDFRAME);
}

static void get_extended_frame_bounds(HWND hwnd, RECT *bounds)
{
    GetWindowRect(hwnd, bounds);
    if (IsZoomed(hwnd) && IsWindowVisible(hwnd) && window_has_caption(hwnd))
    {
        LONG fw = window_frame_width(hwnd);
        InflateRect(bounds, -fw, -fw);
    }
}

static void get_caption_button_bounds(HWND hwnd, RECT *rect)
{
    LONG style = GetWindowLongW(hwnd, GWL_STYLE), ex = GetWindowLongW(hwnd, GWL_EXSTYLE);
    UINT dpi = get_window_dpi(hwnd);
    LONG fw, width, count, right;
    RECT wr, bounds;

    SetRectEmpty(rect);
    if (!(style & WS_CAPTION) || !(style & WS_SYSMENU))
        return;
    /* No non-client rendering, no system buttons: all zero (Windows 10, also for a hidden window) */
    if ((get_nc_data(hwnd) & NITRO_NC_POLICY_MASK) == 1)
        return;

    GetWindowRect(hwnd, &wr);
    get_extended_frame_bounds(hwnd, &bounds);
    fw = window_frame_width(hwnd);
    count = (!(ex & WS_EX_TOOLWINDOW) && (style & (WS_MINIMIZEBOX | WS_MAXIMIZEBOX))) ? 3 : 1;
    width = MulDiv(count * NITRO_CAPTION_BUTTON_CX, dpi, 96) + fw;

    right = bounds.right - wr.left;
    if (IsZoomed(hwnd))
        right--;
    rect->right = right;
    rect->left = right - width;
    rect->top = 0;
    rect->bottom = fw + GetSystemMetrics(SM_CYCAPTION) - 1;
}
#endif

/**********************************************************************
 *           DwmGetWindowAttribute         (DWMAPI.@)
 */
HRESULT WINAPI DwmGetWindowAttribute(HWND hwnd, DWORD attribute, PVOID pv_attribute, DWORD size)
{
#ifdef __REACTOS__
    RECT rect;

    TRACE("(%p %ld %p %ld)\n", hwnd, attribute, pv_attribute, size);

    if (!IsWindow(hwnd))
        return HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE);
    if (!pv_attribute)
        return E_INVALIDARG;

    switch (attribute)
    {
        case 1: /* DWMWA_NCRENDERING_ENABLED */
        case 14: /* DWMWA_CLOAKED */
        case 15: /* DWMWA_FREEZE_REPRESENTATION */
        case 16: /* DWMWA_PASSIVE_UPDATE_MODE */
        case 20: /* DWMWA_USE_IMMERSIVE_DARK_MODE */
            if (size < sizeof(DWORD))
                return E_INVALIDARG;
            *(DWORD *)pv_attribute = (attribute == 1) ? nc_rendering_enabled(hwnd, get_nc_data(hwnd)) : 0;
            return S_OK;

        case 5: /* DWMWA_CAPTION_BUTTON_BOUNDS */
        case 9: /* DWMWA_EXTENDED_FRAME_BOUNDS */
            if (size < sizeof(DWORD))
                return E_INVALIDARG;
            if (size < sizeof(RECT))
                return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
            if (attribute == 5)
                get_caption_button_bounds(hwnd, &rect);
            else
                get_extended_frame_bounds(hwnd, &rect);
            *(RECT *)pv_attribute = rect;
            return S_OK;

        default:
            return E_INVALIDARG;
    }
#else
    FIXME("(%p %ld %p %ld) stub\n", hwnd, attribute, pv_attribute, size);

    return E_NOTIMPL;
#endif
}

/**********************************************************************
 *           DwmRegisterThumbnail         (DWMAPI.@)
 */
HRESULT WINAPI DwmRegisterThumbnail(HWND dest, HWND src, PHTHUMBNAIL thumbnail_id)
{
    FIXME("(%p %p %p) stub\n", dest, src, thumbnail_id);

    return E_NOTIMPL;
}

static int get_display_frequency(void)
{
    DEVMODEW mode;
    BOOL ret;

    memset(&mode, 0, sizeof(mode));
    mode.dmSize = sizeof(mode);
    ret = EnumDisplaySettingsExW(NULL, ENUM_CURRENT_SETTINGS, &mode, 0);
    if (ret && mode.dmFields & DM_DISPLAYFREQUENCY && mode.dmDisplayFrequency)
    {
        return mode.dmDisplayFrequency;
    }
    else
    {
        WARN("Failed to query display frequency, returning a fallback value.\n");
        return 60;
    }
}

/**********************************************************************
 *           DwmGetCompositionTimingInfo         (DWMAPI.@)
 */
HRESULT WINAPI DwmGetCompositionTimingInfo(HWND hwnd, DWM_TIMING_INFO *info)
{
    LARGE_INTEGER performance_frequency, qpc;
    static int i, display_frequency;

    if (!info)
        return E_INVALIDARG;

    if (info->cbSize != sizeof(DWM_TIMING_INFO))
        return MILERR_MISMATCHED_SIZE;

    if(!i++) FIXME("(%p %p)\n", hwnd, info);

    memset(info, 0, info->cbSize);
    info->cbSize = sizeof(DWM_TIMING_INFO);

    display_frequency = get_display_frequency();
    info->rateRefresh.uiNumerator = display_frequency;
    info->rateRefresh.uiDenominator = 1;
    info->rateCompose.uiNumerator = display_frequency;
    info->rateCompose.uiDenominator = 1;

    QueryPerformanceFrequency(&performance_frequency);
    info->qpcRefreshPeriod = performance_frequency.QuadPart / display_frequency;

    QueryPerformanceCounter(&qpc);
    info->qpcVBlank = (qpc.QuadPart / info->qpcRefreshPeriod) * info->qpcRefreshPeriod;

    return S_OK;
}

/**********************************************************************
 *           DwmAttachMilContent         (DWMAPI.@)
 */
HRESULT WINAPI DwmAttachMilContent(HWND hwnd)
{
    FIXME("(%p) stub\n", hwnd);
    return E_NOTIMPL;
}

/**********************************************************************
 *           DwmDetachMilContent         (DWMAPI.@)
 */
HRESULT WINAPI DwmDetachMilContent(HWND hwnd)
{
    FIXME("(%p) stub\n", hwnd);
    return E_NOTIMPL;
}

/**********************************************************************
 *           DwmUpdateThumbnailProperties         (DWMAPI.@)
 */
HRESULT WINAPI DwmUpdateThumbnailProperties(HTHUMBNAIL thumbnail, const DWM_THUMBNAIL_PROPERTIES *props)
{
    FIXME("(%p, %p) stub\n", thumbnail, props);
    return E_NOTIMPL;
}

/**********************************************************************
 *           DwmSetPresentParameters         (DWMAPI.@)
 */
HRESULT WINAPI DwmSetPresentParameters(HWND hwnd, DWM_PRESENT_PARAMETERS *params)
{
    FIXME("(%p %p) stub\n", hwnd, params);
    return S_OK;
};

/**********************************************************************
 *           DwmSetIconicLivePreviewBitmap         (DWMAPI.@)
 */
HRESULT WINAPI DwmSetIconicLivePreviewBitmap(HWND hwnd, HBITMAP hbmp, POINT *pos, DWORD flags)
{
    FIXME("(%p %p %p %lx) stub\n", hwnd, hbmp, pos, flags);
    return S_OK;
};

/**********************************************************************
 *           DwmSetIconicThumbnail         (DWMAPI.@)
 */
HRESULT WINAPI DwmSetIconicThumbnail(HWND hwnd, HBITMAP hbmp, DWORD flags)
{
    FIXME("(%p %p %lx) stub\n", hwnd, hbmp, flags);
    return S_OK;
};

/**********************************************************************
 *           DwmpGetColorizationParameters         (DWMAPI.@)
 */
HRESULT WINAPI DwmpGetColorizationParameters(void *params)
{
    FIXME("(%p) stub\n", params);
    return E_NOTIMPL;
}
