/*
 * PROJECT:     ReactOS user32 - dialog DPI change behaviour
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     GetDialogDpiChangeBehavior, SetDialogDpiChangeBehavior,
 *              GetDialogControlDpiChangeBehavior and SetDialogControlDpiChangeBehavior
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Nothing here changes the DPI of a window, so the behaviours are only state, kept in a window
 * property (which goes away with the window). Everything else was measured on Windows 10 22H2
 * (build 19045), x64 and x86:
 *  - an invalid window is ERROR_INVALID_WINDOW_HANDLE for all four functions.
 *  - the dialog functions accept a window whose class reserves at least DLGWINDOWEXTRA bytes
 *    (every dialog does, and so does any class that is meant to use DefDlgProc, whatever its
 *    window procedure does), also a child or a message-only window, and report
 *    ERROR_WINDOW_NOT_DIALOG (1420) for any other window; the control functions take any window.
 *  - the setters fail with ERROR_ACCESS_DENIED for a window of another process (before the class
 *    is looked at), and accept a window of another thread of the process.
 *  - a setter changes the bits that are in the mask to the value that the same bits have in the
 *    new value, returns TRUE without any error for a mask or value with other bits, and the
 *    bits that are not defined are not kept: three bits for a dialog (DDC_DISABLE_ALL,
 *    DDC_DISABLE_RESIZE, DDC_DISABLE_CONTROL_RELAYOUT), two for a control
 *    (DCDC_DISABLE_FONT_UPDATE, DCDC_DISABLE_RELAYOUT). The two behaviours do not affect each
 *    other, and the awareness of the thread does not matter.
 *  - the getters return 0, and set no error, for a window that has none set. On Windows the
 *    dialog getter faults when the window is a dialog of another process; here it answers.
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

#ifndef ERROR_WINDOW_NOT_DIALOG
#define ERROR_WINDOW_NOT_DIALOG 1420
#endif

#define DIALOG_BEHAVIOR_MASK    0x7
#define CONTROL_BEHAVIOR_MASK   0x3

static const WCHAR s_DialogPropName[] = L"User32DialogDpiChange";
static const WCHAR s_ControlPropName[] = L"User32ControlDpiChange";

static BOOL
IsDialogClassWindow(HWND hwnd)
{
    return GetClassLongW(hwnd, GCL_CBWNDEXTRA) >= DLGWINDOWEXTRA;
}

static LONG
GetBehavior(HWND hwnd, LPCWSTR PropName, BOOL DialogOnly, LONG Mask)
{
    DWORD Error;
    LONG Value;

    if (!IsWindow(hwnd))
    {
        SetLastError(ERROR_INVALID_WINDOW_HANDLE);
        return 0;
    }

    Error = GetLastError();
    if (DialogOnly && !IsDialogClassWindow(hwnd))
    {
        SetLastError(ERROR_WINDOW_NOT_DIALOG);
        return 0;
    }

    Value = (LONG)(ULONG_PTR)GetPropW(hwnd, PropName) & Mask;
    SetLastError(Error);
    return Value;
}

static BOOL
SetBehavior(HWND hwnd, LPCWSTR PropName, BOOL DialogOnly, LONG Mask, LONG NewMask, LONG NewValue)
{
    DWORD Error, Pid;
    LONG Value;

    if (!IsWindow(hwnd))
    {
        SetLastError(ERROR_INVALID_WINDOW_HANDLE);
        return FALSE;
    }

    GetWindowThreadProcessId(hwnd, &Pid);
    if (Pid != GetCurrentProcessId())
    {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }

    Error = GetLastError();
    if (DialogOnly && !IsDialogClassWindow(hwnd))
    {
        SetLastError(ERROR_WINDOW_NOT_DIALOG);
        return FALSE;
    }

    NewMask &= Mask;
    Value = ((LONG)(ULONG_PTR)GetPropW(hwnd, PropName) & Mask & ~NewMask) | (NewValue & NewMask);
    if (!SetPropW(hwnd, PropName, (HANDLE)(ULONG_PTR)Value))
        return FALSE;
    SetLastError(Error);
    return TRUE;
}

int
WINAPI
GetDialogDpiChangeBehavior(
    _In_ HWND hDlg)
{
    return GetBehavior(hDlg, s_DialogPropName, TRUE, DIALOG_BEHAVIOR_MASK);
}

BOOL
WINAPI
SetDialogDpiChangeBehavior(
    _In_ HWND hDlg,
    _In_ int mask,
    _In_ int values)
{
    return SetBehavior(hDlg, s_DialogPropName, TRUE, DIALOG_BEHAVIOR_MASK, mask, values);
}

int
WINAPI
GetDialogControlDpiChangeBehavior(
    _In_ HWND hWnd)
{
    return GetBehavior(hWnd, s_ControlPropName, FALSE, CONTROL_BEHAVIOR_MASK);
}

BOOL
WINAPI
SetDialogControlDpiChangeBehavior(
    _In_ HWND hWnd,
    _In_ int mask,
    _In_ int values)
{
    return SetBehavior(hWnd, s_ControlPropName, FALSE, CONTROL_BEHAVIOR_MASK, mask, values);
}
