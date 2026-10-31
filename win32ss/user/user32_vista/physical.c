/*
 * PROJECT:     ReactOS user32 - physical coordinates and top-level window queries
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     GetPhysicalCursorPos, SetPhysicalCursorPos, LogicalToPhysicalPoint,
 *              PhysicalToLogicalPoint, WindowFromPhysicalPoint, GetUnpredictedMessagePos,
 *              IsTopLevelWindow and GetTopLevelWindow
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * This system has one DPI for every window and does not scale for a process, so a physical
 * coordinate is the logical one, which is what Windows 10 answers at 100 percent scaling. What
 * is left of these functions is what Windows checks around the conversion. Error codes and the
 * rules below were measured on Windows 10 22H2 (build 19045), x64 and x86:
 *  - the point conversions need a valid window (NULL is not one: ERROR_INVALID_WINDOW_HANDLE),
 *    a readable and writable point (ERROR_NOACCESS), and fail without an error for a point
 *    outside the window rectangle in screen coordinates (right and bottom edges included). A
 *    child window is no exception, and the desktop window has the screen for its rectangle.
 *  - the cursor functions are GetCursorPos and SetCursorPos; a call on a desktop that the
 *    process may not use fails the same way for both, before the pointer is looked at.
 *  - the position of the last pointer message that was not predicted stays 0 as long as no
 *    pointer message was ever sent, and this system sends none.
 */

#define WIN32_NO_STATUS
#define _INC_WINDOWS
#define COM_NO_WINDOWS_H
#include <windef.h>
#include <winbase.h>
#include <wingdi.h>
#include <winuser.h>

#define NDEBUG
#include <debug.h>

/* A window whose parent is the desktop (an owned window is one too); the desktop itself is not */
static BOOL
HasDesktopParent(HWND hwnd)
{
    HWND hDesktop = GetDesktopWindow();

    return hwnd != hDesktop && GetAncestor(hwnd, GA_PARENT) == hDesktop;
}

BOOL
WINAPI
IsTopLevelWindow(
    _In_ HWND hwnd)
{
    DWORD Error;
    BOOL Ret;

    if (!IsWindow(hwnd))
    {
        SetLastError(ERROR_INVALID_WINDOW_HANDLE);
        return FALSE;
    }

    Error = GetLastError();
    Ret = HasDesktopParent(hwnd);
    SetLastError(Error);
    return Ret;
}

HWND
WINAPI
GetTopLevelWindow(
    _In_ HWND hwnd)
{
    DWORD Error;
    HWND hRoot;

    if (!IsWindow(hwnd))
    {
        SetLastError(ERROR_INVALID_WINDOW_HANDLE);
        return NULL;
    }

    Error = GetLastError();
    /* The window below the desktop that holds this one; a message-only window and the desktop have none */
    hRoot = GetAncestor(hwnd, GA_ROOT);
    if (hRoot && !HasDesktopParent(hRoot))
        hRoot = NULL;
    SetLastError(Error);
    return hRoot;
}

static BOOL
MapPhysicalPoint(HWND hwnd, POINT *point)
{
    DWORD Error;
    RECT Rect;

    if (!IsWindow(hwnd))
    {
        SetLastError(ERROR_INVALID_WINDOW_HANDLE);
        return FALSE;
    }

    if (!point || IsBadWritePtr(point, sizeof(*point)))
    {
        SetLastError(ERROR_NOACCESS);
        return FALSE;
    }

    Error = GetLastError();
    if (!GetWindowRect(hwnd, &Rect))
        return FALSE;
    SetLastError(Error);
    if (point->x < Rect.left || point->x > Rect.right || point->y < Rect.top || point->y > Rect.bottom)
        return FALSE;
    return TRUE;
}

BOOL
WINAPI
LogicalToPhysicalPoint(
    _In_ HWND hwnd,
    _Inout_ POINT *point)
{
    return MapPhysicalPoint(hwnd, point);
}

BOOL
WINAPI
PhysicalToLogicalPoint(
    _In_ HWND hwnd,
    _Inout_ POINT *point)
{
    return MapPhysicalPoint(hwnd, point);
}

BOOL
WINAPI
GetPhysicalCursorPos(
    _Out_ POINT *point)
{
    POINT Pos;

    if (!GetCursorPos(&Pos))
        return FALSE;
    if (!point || IsBadWritePtr(point, sizeof(*point)))
    {
        SetLastError(ERROR_NOACCESS);
        return FALSE;
    }
    *point = Pos;
    return TRUE;
}

BOOL
WINAPI
SetPhysicalCursorPos(
    _In_ int x,
    _In_ int y)
{
    return SetCursorPos(x, y);
}

HWND
WINAPI
WindowFromPhysicalPoint(
    _In_ POINT point)
{
    return WindowFromPoint(point);
}

DWORD
WINAPI
GetUnpredictedMessagePos(VOID)
{
    return 0;
}
