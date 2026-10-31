/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for GetDialogDpiChangeBehavior, SetDialogDpiChangeBehavior,
 *              GetDialogControlDpiChangeBehavior and SetDialogControlDpiChangeBehavior
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The results were measured on Windows 10 22H2 (x64 and x86). A dialog here is a window whose class
 * reserves DLGWINDOWEXTRA bytes; the setters change the bits of the mask only, keep three bits (dialog)
 * or two bits (control), and refuse a window of another process.
 */

#include "precomp.h"

typedef int (WINAPI *PFN_Get)(HWND);
typedef BOOL (WINAPI *PFN_Set)(HWND, int, int);

#define PENDING_ERROR 0xdeadbeef
#ifndef ERROR_WINDOW_NOT_DIALOG
#define ERROR_WINDOW_NOT_DIALOG 1420
#endif

static PFN_Get pGetDialog, pGetControl;
static PFN_Set pSetDialog, pSetControl;

static LRESULT CALLBACK PlainProc(HWND Wnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProcW(Wnd, Msg, wParam, lParam);
}

static INT_PTR CALLBACK DialogFunc(HWND Wnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    return 0;
}

static HWND MakeDialog(void)
{
    struct { DLGTEMPLATE Template; WORD Menu, Class, Title; } Data;

    ZeroMemory(&Data, sizeof(Data));
    Data.Template.style = WS_POPUP | WS_CAPTION | DS_MODALFRAME;
    Data.Template.cx = 100;
    Data.Template.cy = 100;
    return CreateDialogIndirectParamW(NULL, &Data.Template, NULL, DialogFunc, 0);
}

static HANDLE g_ThreadReady;
static HANDLE g_ThreadStop;
static HWND g_ThreadWindow;

static DWORD WINAPI ThreadProc(PVOID Param)
{
    g_ThreadWindow = CreateWindowExW(0, L"#32770", L"thread dialog", WS_OVERLAPPEDWINDOW, 0, 0, 10, 10, NULL, NULL, NULL, NULL);
    SetEvent(g_ThreadReady);
    WaitForSingleObject(g_ThreadStop, 20000);
    DestroyWindow(g_ThreadWindow);
    return 0;
}

#define EXPECT_GET(Fn, Wnd, Expected, ExpError, Label) \
    do { \
        int Value_; \
        DWORD Err_; \
        SetLastError(PENDING_ERROR); \
        Value_ = Fn(Wnd); \
        Err_ = GetLastError(); \
        ok(Value_ == (Expected), "%s: %s returned %d, expected %d\n", Label, #Fn, Value_, (int)(Expected)); \
        ok(Err_ == (ExpError), "%s: %s: last error %lu, expected %lu\n", Label, #Fn, Err_, (DWORD)(ExpError)); \
    } while (0)

#define EXPECT_SET(Fn, Wnd, Mask, Value, ExpResult, ExpError, Label) \
    do { \
        BOOL Res_; \
        DWORD Err_; \
        SetLastError(PENDING_ERROR); \
        Res_ = Fn(Wnd, Mask, Value); \
        Err_ = GetLastError(); \
        ok(Res_ == (ExpResult), "%s: %s(0x%x, 0x%x) returned %d\n", Label, #Fn, (unsigned)(Mask), (unsigned)(Value), Res_); \
        ok(Err_ == (ExpError), "%s: %s(0x%x, 0x%x): last error %lu, expected %lu\n", Label, #Fn, (unsigned)(Mask), (unsigned)(Value), Err_, (DWORD)(ExpError)); \
    } while (0)

START_TEST(DialogDpiBehavior)
{
    HMODULE User32 = GetModuleHandleW(L"user32.dll");
    static const struct { int Mask, Value, Result; } DialogSteps[] =
    {
        { 7, 2, 2 }, { 0, 0, 2 }, { 1, 1, 3 }, { 1, 0, 2 }, { 2, 2, 2 }, { 4, 4, 6 }, { 7, 7, 7 }, { 7, 0, 0 },
        { 8, 8, 0 }, { 0x10, 0x10, 0 }, { -1, -1, 7 }, { 3, 1, 5 }, { 3, 7, 7 }, { 0, 7, 7 }, { 2, 1, 5 }, { 4, 3, 1 },
    };
    static const struct { int Mask, Value, Result; } ControlSteps[] =
    {
        { 0, 0, 0 }, { 1, 1, 1 }, { 1, 0, 0 }, { 2, 2, 2 }, { 3, 3, 3 }, { 3, 0, 0 }, { 4, 4, 0 }, { 7, 7, 3 },
        { -1, -1, 3 }, { 1, 3, 3 }, { 2, 1, 1 },
    };
    HWND Top, Dialog, Class32770, Child, Message, Desktop, ThreadWnd, Destroyed, Custom30, Custom29;
    WNDCLASSW Class;
    HANDLE Thread;
    WCHAR Name[32];
    ULONG i;

    pGetDialog = (PFN_Get)GetProcAddress(User32, "GetDialogDpiChangeBehavior");
    pSetDialog = (PFN_Set)GetProcAddress(User32, "SetDialogDpiChangeBehavior");
    pGetControl = (PFN_Get)GetProcAddress(User32, "GetDialogControlDpiChangeBehavior");
    pSetControl = (PFN_Set)GetProcAddress(User32, "SetDialogControlDpiChangeBehavior");
    if (!pGetDialog || !pSetDialog || !pGetControl || !pSetControl)
    {
        skip("the dialog DPI change behaviour functions are not exported\n");
        return;
    }

    GetSystemMetrics(SM_CXSCREEN);

    Top = CreateWindowExW(0, L"STATIC", L"static", WS_OVERLAPPEDWINDOW, 0, 0, 100, 100, NULL, NULL, NULL, NULL);
    Class32770 = CreateWindowExW(0, L"#32770", L"dialog class", WS_OVERLAPPEDWINDOW, 0, 0, 100, 100, NULL, NULL, NULL, NULL);
    Dialog = MakeDialog();
    Child = CreateWindowExW(0, L"BUTTON", L"button", WS_CHILD, 10, 10, 50, 50, Top, NULL, NULL, NULL);
    Message = CreateWindowExW(0, L"#32770", L"message", WS_OVERLAPPEDWINDOW, 0, 0, 10, 10, HWND_MESSAGE, NULL, NULL, NULL);
    Desktop = GetDesktopWindow();
    ok(Top && Class32770 && Dialog && Child && Message, "the windows were not created\n");

    /* classes that reserve fewer or at least DLGWINDOWEXTRA window bytes */
    ZeroMemory(&Class, sizeof(Class));
    Class.lpfnWndProc = PlainProc;
    Class.lpszClassName = L"DialogDpiBehavior29";
    Class.cbWndExtra = DLGWINDOWEXTRA - 1;
    RegisterClassW(&Class);
    Class.lpszClassName = L"DialogDpiBehavior30";
    Class.cbWndExtra = DLGWINDOWEXTRA;
    RegisterClassW(&Class);
    Custom29 = CreateWindowExW(0, L"DialogDpiBehavior29", L"29", WS_OVERLAPPEDWINDOW, 0, 0, 10, 10, NULL, NULL, NULL, NULL);
    Custom30 = CreateWindowExW(0, L"DialogDpiBehavior30", L"30", WS_OVERLAPPEDWINDOW, 0, 0, 10, 10, NULL, NULL, NULL, NULL);

    /* nothing is set yet */
    EXPECT_GET(pGetDialog, NULL, 0, ERROR_INVALID_WINDOW_HANDLE, "NULL");
    EXPECT_GET(pGetControl, NULL, 0, ERROR_INVALID_WINDOW_HANDLE, "NULL");
    EXPECT_GET(pGetDialog, (HWND)(ULONG_PTR)0x12345, 0, ERROR_INVALID_WINDOW_HANDLE, "bad window");
    EXPECT_GET(pGetControl, (HWND)(ULONG_PTR)0x12345, 0, ERROR_INVALID_WINDOW_HANDLE, "bad window");
    EXPECT_GET(pGetDialog, Top, 0, ERROR_WINDOW_NOT_DIALOG, "static");
    EXPECT_GET(pGetControl, Top, 0, PENDING_ERROR, "static");
    EXPECT_GET(pGetDialog, Class32770, 0, PENDING_ERROR, "dialog class");
    EXPECT_GET(pGetDialog, Dialog, 0, PENDING_ERROR, "dialog");
    EXPECT_GET(pGetControl, Dialog, 0, PENDING_ERROR, "dialog");
    EXPECT_GET(pGetDialog, Child, 0, ERROR_WINDOW_NOT_DIALOG, "button");
    EXPECT_GET(pGetControl, Child, 0, PENDING_ERROR, "button");
    EXPECT_GET(pGetDialog, Desktop, 0, ERROR_WINDOW_NOT_DIALOG, "desktop");

    /* the windows that take the dialog behaviour */
    EXPECT_SET(pSetDialog, NULL, 7, 2, FALSE, ERROR_INVALID_WINDOW_HANDLE, "NULL");
    EXPECT_SET(pSetDialog, (HWND)(ULONG_PTR)0x12345, 7, 2, FALSE, ERROR_INVALID_WINDOW_HANDLE, "bad window");
    EXPECT_SET(pSetDialog, Top, 7, 2, FALSE, ERROR_WINDOW_NOT_DIALOG, "static");
    EXPECT_GET(pGetDialog, Top, 0, ERROR_WINDOW_NOT_DIALOG, "static after");
    EXPECT_SET(pSetDialog, Child, 7, 2, FALSE, ERROR_WINDOW_NOT_DIALOG, "button");
    EXPECT_SET(pSetDialog, Desktop, 7, 2, FALSE, ERROR_ACCESS_DENIED, "desktop");
    EXPECT_SET(pSetControl, Desktop, 3, 1, FALSE, ERROR_ACCESS_DENIED, "desktop");
    if (Custom29)
        EXPECT_SET(pSetDialog, Custom29, 7, 1, FALSE, ERROR_WINDOW_NOT_DIALOG, "class with 29 window bytes");
    if (Custom30)
    {
        EXPECT_SET(pSetDialog, Custom30, 7, 1, TRUE, PENDING_ERROR, "class with 30 window bytes");
        EXPECT_GET(pGetDialog, Custom30, 1, PENDING_ERROR, "class with 30 window bytes");
    }
    if (Message)
    {
        EXPECT_SET(pSetDialog, Message, 7, 4, TRUE, PENDING_ERROR, "message-only dialog class");
        EXPECT_GET(pGetDialog, Message, 4, PENDING_ERROR, "message-only dialog class");
    }
    EXPECT_SET(pSetDialog, Class32770, 7, 2, TRUE, PENDING_ERROR, "dialog class");
    EXPECT_GET(pGetDialog, Class32770, 2, PENDING_ERROR, "dialog class");

    /* the bits of the mask change, three bits are kept */
    for (i = 0; i < sizeof(DialogSteps) / sizeof(DialogSteps[0]); i++)
    {
        EXPECT_SET(pSetDialog, Dialog, DialogSteps[i].Mask, DialogSteps[i].Value, TRUE, PENDING_ERROR, "dialog step");
        EXPECT_GET(pGetDialog, Dialog, DialogSteps[i].Result, PENDING_ERROR, "dialog step");
    }
    EXPECT_SET(pSetDialog, Dialog, 7, 0, TRUE, PENDING_ERROR, "dialog reset");

    /* the control behaviour takes every window of the process, two bits are kept, and is not the dialog one */
    EXPECT_SET(pSetControl, NULL, 3, 1, FALSE, ERROR_INVALID_WINDOW_HANDLE, "NULL");
    EXPECT_SET(pSetControl, (HWND)(ULONG_PTR)0x12345, 3, 1, FALSE, ERROR_INVALID_WINDOW_HANDLE, "bad window");
    EXPECT_SET(pSetControl, Top, 3, 1, TRUE, PENDING_ERROR, "static");
    EXPECT_GET(pGetControl, Top, 1, PENDING_ERROR, "static");
    EXPECT_SET(pSetControl, Dialog, 3, 2, TRUE, PENDING_ERROR, "dialog");
    EXPECT_GET(pGetControl, Dialog, 2, PENDING_ERROR, "dialog");
    EXPECT_GET(pGetDialog, Dialog, 0, PENDING_ERROR, "dialog (not changed by the control one)");
    EXPECT_SET(pSetDialog, Dialog, 7, 7, TRUE, PENDING_ERROR, "dialog");
    EXPECT_GET(pGetControl, Dialog, 2, PENDING_ERROR, "dialog (not changed by the dialog one)");
    for (i = 0; i < sizeof(ControlSteps) / sizeof(ControlSteps[0]); i++)
    {
        EXPECT_SET(pSetControl, Child, ControlSteps[i].Mask, ControlSteps[i].Value, TRUE, PENDING_ERROR, "control step");
        EXPECT_GET(pGetControl, Child, ControlSteps[i].Result, PENDING_ERROR, "control step");
    }

    /* a window of another thread of the process */
    g_ThreadReady = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_ThreadStop = CreateEventW(NULL, TRUE, FALSE, NULL);
    Thread = CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL);
    if (Thread && WaitForSingleObject(g_ThreadReady, 10000) == WAIT_OBJECT_0)
    {
        ThreadWnd = g_ThreadWindow;
        EXPECT_SET(pSetDialog, ThreadWnd, 7, 2, TRUE, PENDING_ERROR, "dialog of another thread");
        EXPECT_GET(pGetDialog, ThreadWnd, 2, PENDING_ERROR, "dialog of another thread");
        EXPECT_SET(pSetControl, ThreadWnd, 3, 1, TRUE, PENDING_ERROR, "dialog of another thread");
        EXPECT_GET(pGetControl, ThreadWnd, 1, PENDING_ERROR, "dialog of another thread");
        SetEvent(g_ThreadStop);
        WaitForSingleObject(Thread, 10000);
    }
    else
    {
        skip("the thread did not start\n");
        SetEvent(g_ThreadStop);
    }
    if (Thread)
        CloseHandle(Thread);
    CloseHandle(g_ThreadReady);
    CloseHandle(g_ThreadStop);

    /* a destroyed window, and a new one that has its handle slot, start again */
    Destroyed = MakeDialog();
    if (Destroyed)
    {
        EXPECT_SET(pSetDialog, Destroyed, 7, 7, TRUE, PENDING_ERROR, "to be destroyed");
        EXPECT_SET(pSetControl, Destroyed, 3, 3, TRUE, PENDING_ERROR, "to be destroyed");
        DestroyWindow(Destroyed);
        EXPECT_GET(pGetDialog, Destroyed, 0, ERROR_INVALID_WINDOW_HANDLE, "destroyed");
        EXPECT_GET(pGetControl, Destroyed, 0, ERROR_INVALID_WINDOW_HANDLE, "destroyed");
        EXPECT_SET(pSetDialog, Destroyed, 7, 7, FALSE, ERROR_INVALID_WINDOW_HANDLE, "destroyed");
        for (i = 0; i < 40; i++)
        {
            HWND Fresh = MakeDialog();

            EXPECT_GET(pGetDialog, Fresh, 0, PENDING_ERROR, "fresh dialog");
            EXPECT_GET(pGetControl, Fresh, 0, PENDING_ERROR, "fresh dialog");
            DestroyWindow(Fresh);
        }
    }

    (void)Name;
    DestroyWindow(Dialog);
    DestroyWindow(Class32770);
    DestroyWindow(Top);
}
