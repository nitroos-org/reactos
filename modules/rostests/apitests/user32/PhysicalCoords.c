/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for GetPhysicalCursorPos, SetPhysicalCursorPos, LogicalToPhysicalPoint,
 *              PhysicalToLogicalPoint, WindowFromPhysicalPoint, GetUnpredictedMessagePos,
 *              GetSystemDpiForProcess, IsTopLevelWindow and GetTopLevelWindow
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The results were measured on Windows 10 22H2 (x64 and x86) at 100 percent scaling, in the
 * interactive session, for every DPI awareness of the thread. Where a window of another
 * process or an unreachable desktop would change the answer, the cases use only what exists in
 * every session.
 */

#include "precomp.h"

typedef BOOL (WINAPI *PFN_GetPhysicalCursorPos)(LPPOINT);
typedef BOOL (WINAPI *PFN_SetPhysicalCursorPos)(int, int);
typedef BOOL (WINAPI *PFN_PointForWindow)(HWND, LPPOINT);
typedef HWND (WINAPI *PFN_WindowFromPhysicalPoint)(POINT);
typedef DWORD (WINAPI *PFN_GetUnpredictedMessagePos)(VOID);
typedef UINT (WINAPI *PFN_GetSystemDpiForProcess)(HANDLE);
typedef BOOL (WINAPI *PFN_IsTopLevelWindow)(HWND);
typedef HWND (WINAPI *PFN_GetTopLevelWindow)(HWND);

#define PENDING_ERROR 0xdeadbeef

#define CHECK_POINT_RESULT(Fn, Wnd, X, Y, Expected, Label) \
    do { \
        POINT Pt_ = { (X), (Y) }; \
        BOOL Res_; \
        DWORD Err_; \
        SetLastError(PENDING_ERROR); \
        Res_ = Fn(Wnd, &Pt_); \
        Err_ = GetLastError(); \
        ok(Res_ == (Expected), "%s (%d,%d): returned %d\n", Label, (int)(X), (int)(Y), Res_); \
        ok(Err_ == PENDING_ERROR, "%s (%d,%d): the last error became %lu\n", Label, (int)(X), (int)(Y), Err_); \
        ok(Pt_.x == (X) && Pt_.y == (Y), "%s (%d,%d): the point became %ld,%ld\n", Label, (int)(X), (int)(Y), Pt_.x, Pt_.y); \
    } while (0)

static void
TestPointConversion(PFN_PointForWindow Fn, const char *Name, HWND Top, HWND Child, HWND Owned)
{
    POINT Pt = { 150, 150 };
    RECT Rect;
    BOOL Result;
    DWORD Error;
    char Label[32];

    /* NULL is not a window here */
    SetLastError(PENDING_ERROR);
    Result = Fn(NULL, &Pt);
    Error = GetLastError();
    ok(Result == FALSE, "%s(NULL) returned %d\n", Name, Result);
    ok(Error == ERROR_INVALID_WINDOW_HANDLE, "%s(NULL): last error %lu\n", Name, Error);

    SetLastError(PENDING_ERROR);
    Result = Fn((HWND)(ULONG_PTR)0x12345, &Pt);
    Error = GetLastError();
    ok(Result == FALSE, "%s(bad window) returned %d\n", Name, Result);
    ok(Error == ERROR_INVALID_WINDOW_HANDLE, "%s(bad window): last error %lu\n", Name, Error);

    SetLastError(PENDING_ERROR);
    Result = Fn(Top, NULL);
    Error = GetLastError();
    ok(Result == FALSE, "%s(NULL point) returned %d\n", Name, Result);
    ok(Error == ERROR_NOACCESS, "%s(NULL point): last error %lu\n", Name, Error);

    SetLastError(PENDING_ERROR);
    Result = Fn(Top, (LPPOINT)(ULONG_PTR)8);
    Error = GetLastError();
    ok(Result == FALSE, "%s(bad point) returned %d\n", Name, Result);
    ok(Error == ERROR_NOACCESS, "%s(bad point): last error %lu\n", Name, Error);

    /* the point has to be in the window, the right and bottom edges are in */
    GetWindowRect(Top, &Rect);
    sprintf(Label, "%s top", Name);
    CHECK_POINT_RESULT(Fn, Top, (Rect.left + Rect.right) / 2, (Rect.top + Rect.bottom) / 2, TRUE, Label);
    CHECK_POINT_RESULT(Fn, Top, Rect.left, Rect.top, TRUE, Label);
    CHECK_POINT_RESULT(Fn, Top, Rect.right, Rect.bottom, TRUE, Label);
    CHECK_POINT_RESULT(Fn, Top, Rect.left - 1, Rect.top, FALSE, Label);
    CHECK_POINT_RESULT(Fn, Top, Rect.left, Rect.top - 1, FALSE, Label);
    CHECK_POINT_RESULT(Fn, Top, Rect.right + 1, Rect.bottom, FALSE, Label);
    CHECK_POINT_RESULT(Fn, Top, Rect.right, Rect.bottom + 1, FALSE, Label);

    /* an owned window and a child window work the same, with their own rectangles */
    GetWindowRect(Owned, &Rect);
    sprintf(Label, "%s owned", Name);
    CHECK_POINT_RESULT(Fn, Owned, Rect.left, Rect.top, TRUE, Label);
    CHECK_POINT_RESULT(Fn, Owned, Rect.left - 1, Rect.top, FALSE, Label);
    GetWindowRect(Child, &Rect);
    sprintf(Label, "%s child", Name);
    CHECK_POINT_RESULT(Fn, Child, Rect.left, Rect.top, TRUE, Label);
    CHECK_POINT_RESULT(Fn, Child, (Rect.left + Rect.right) / 2, (Rect.top + Rect.bottom) / 2, TRUE, Label);
    CHECK_POINT_RESULT(Fn, Child, Rect.right + 1, Rect.bottom, FALSE, Label);
    CHECK_POINT_RESULT(Fn, Child, Rect.left, Rect.top - 1, FALSE, Label);

    /* the desktop window is top-level and has the screen for its rectangle */
    sprintf(Label, "%s desktop", Name);
    CHECK_POINT_RESULT(Fn, GetDesktopWindow(), 0, 0, TRUE, Label);
    CHECK_POINT_RESULT(Fn, GetDesktopWindow(), -100, -100, FALSE, Label);
    CHECK_POINT_RESULT(Fn, GetDesktopWindow(), 100000, 100000, FALSE, Label);
}

START_TEST(PhysicalCoords)
{
    HMODULE User32 = GetModuleHandleW(L"user32.dll");
    PFN_GetPhysicalCursorPos pGetPhysicalCursorPos;
    PFN_SetPhysicalCursorPos pSetPhysicalCursorPos;
    PFN_PointForWindow pLogicalToPhysicalPoint, pPhysicalToLogicalPoint;
    PFN_WindowFromPhysicalPoint pWindowFromPhysicalPoint;
    PFN_GetUnpredictedMessagePos pGetUnpredictedMessagePos;
    PFN_GetSystemDpiForProcess pGetSystemDpiForProcess;
    PFN_IsTopLevelWindow pIsTopLevelWindow;
    PFN_GetTopLevelWindow pGetTopLevelWindow;
    PFN_GetSystemDpiForProcess pGetDpiForSystem;
    HWND Top, Child, GrandChild, Owned, Owner2, MsgOnly, Desktop;
    POINT Saved, Pos, Expected;
    BOOL Interactive, Result;
    DWORD Error;
    HANDLE Process;
    UINT Dpi;
    int i;

    pGetPhysicalCursorPos = (PFN_GetPhysicalCursorPos)GetProcAddress(User32, "GetPhysicalCursorPos");
    pSetPhysicalCursorPos = (PFN_SetPhysicalCursorPos)GetProcAddress(User32, "SetPhysicalCursorPos");
    pLogicalToPhysicalPoint = (PFN_PointForWindow)GetProcAddress(User32, "LogicalToPhysicalPoint");
    pPhysicalToLogicalPoint = (PFN_PointForWindow)GetProcAddress(User32, "PhysicalToLogicalPoint");
    pWindowFromPhysicalPoint = (PFN_WindowFromPhysicalPoint)GetProcAddress(User32, "WindowFromPhysicalPoint");
    pGetUnpredictedMessagePos = (PFN_GetUnpredictedMessagePos)GetProcAddress(User32, "GetUnpredictedMessagePos");
    pGetSystemDpiForProcess = (PFN_GetSystemDpiForProcess)GetProcAddress(User32, "GetSystemDpiForProcess");
    pGetDpiForSystem = (PFN_GetSystemDpiForProcess)GetProcAddress(User32, "GetDpiForSystem");
    pIsTopLevelWindow = (PFN_IsTopLevelWindow)GetProcAddress(User32, "IsTopLevelWindow");
    pGetTopLevelWindow = (PFN_GetTopLevelWindow)GetProcAddress(User32, "GetTopLevelWindow");

    if (!pGetPhysicalCursorPos || !pSetPhysicalCursorPos || !pLogicalToPhysicalPoint || !pPhysicalToLogicalPoint ||
        !pWindowFromPhysicalPoint || !pGetUnpredictedMessagePos || !pGetSystemDpiForProcess ||
        !pIsTopLevelWindow || !pGetTopLevelWindow)
    {
        skip("the physical coordinate functions are not exported\n");
        return;
    }

    /* the user32 of a thread has to be initialized before any of the functions is used */
    GetSystemMetrics(SM_CXSCREEN);

    Top = CreateWindowExW(0, L"STATIC", L"top", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 120, 300, 200, NULL, NULL, NULL, NULL);
    Child = CreateWindowExW(0, L"STATIC", L"child", WS_CHILD | WS_VISIBLE, 10, 10, 50, 50, Top, NULL, NULL, NULL);
    GrandChild = CreateWindowExW(0, L"STATIC", L"grandchild", WS_CHILD | WS_VISIBLE, 1, 1, 5, 5, Child, NULL, NULL, NULL);
    Owned = CreateWindowExW(0, L"STATIC", L"owned", WS_POPUP | WS_VISIBLE, 600, 120, 100, 100, Top, NULL, NULL, NULL);
    Owner2 = CreateWindowExW(0, L"STATIC", L"owned2", WS_OVERLAPPEDWINDOW, 0, 0, 10, 10, Owned, NULL, NULL, NULL);
    MsgOnly = CreateWindowExW(0, L"STATIC", L"message", WS_OVERLAPPEDWINDOW, 0, 0, 10, 10, HWND_MESSAGE, NULL, NULL, NULL);
    Desktop = GetDesktopWindow();
    ok(Top && Child && GrandChild && Owned && Owner2, "the windows were not created\n");

    /* the cursor functions are GetCursorPos and SetCursorPos; outside the interactive session they fail alike */
    Interactive = GetCursorPos(&Saved);
    if (!Interactive)
    {
        Error = GetLastError();
        SetLastError(PENDING_ERROR);
        Result = pGetPhysicalCursorPos(&Pos);
        ok(Result == FALSE, "GetPhysicalCursorPos succeeded where GetCursorPos failed\n");
        ok(GetLastError() == Error, "GetPhysicalCursorPos: last error %lu, GetCursorPos had %lu\n", GetLastError(), Error);
        SetLastError(PENDING_ERROR);
        Result = pSetPhysicalCursorPos(10, 10);
        ok(Result == FALSE, "SetPhysicalCursorPos succeeded where GetCursorPos failed\n");
        ok(GetLastError() == Error, "SetPhysicalCursorPos: last error %lu, GetCursorPos had %lu\n", GetLastError(), Error);
        skip("no interactive window station: cursor and window position cases\n");
    }
    else
    {
        SetLastError(PENDING_ERROR);
        Result = pGetPhysicalCursorPos(NULL);
        Error = GetLastError();
        ok(Result == FALSE, "GetPhysicalCursorPos(NULL) returned %d\n", Result);
        ok(Error == ERROR_NOACCESS, "GetPhysicalCursorPos(NULL): last error %lu\n", Error);
        SetLastError(PENDING_ERROR);
        Result = pGetPhysicalCursorPos((LPPOINT)(ULONG_PTR)1);
        Error = GetLastError();
        ok(Result == FALSE, "GetPhysicalCursorPos(bad pointer) returned %d\n", Result);
        ok(Error == ERROR_NOACCESS, "GetPhysicalCursorPos(bad pointer): last error %lu\n", Error);

        Pos.x = Pos.y = -77;
        SetLastError(PENDING_ERROR);
        Result = pGetPhysicalCursorPos(&Pos);
        Error = GetLastError();
        ok(Result == TRUE, "GetPhysicalCursorPos returned %d\n", Result);
        ok(Error == PENDING_ERROR, "GetPhysicalCursorPos: last error %lu\n", Error);
        GetCursorPos(&Expected);
        ok(Pos.x == Expected.x && Pos.y == Expected.y, "GetPhysicalCursorPos gave %ld,%ld, GetCursorPos %ld,%ld\n",
           Pos.x, Pos.y, Expected.x, Expected.y);

        SetLastError(PENDING_ERROR);
        Result = pSetPhysicalCursorPos(50, 60);
        Error = GetLastError();
        ok(Result == TRUE, "SetPhysicalCursorPos returned %d\n", Result);
        ok(Error == PENDING_ERROR, "SetPhysicalCursorPos: last error %lu\n", Error);
        GetCursorPos(&Pos);
        ok(Pos.x == 50 && Pos.y == 60, "the cursor is at %ld,%ld\n", Pos.x, Pos.y);

        /* a position outside the screen is treated as SetCursorPos treats it */
        SetCursorPos(-30000, -30000);
        GetCursorPos(&Expected);
        SetCursorPos(50, 60);
        Result = pSetPhysicalCursorPos(-30000, -30000);
        ok(Result == TRUE, "SetPhysicalCursorPos(-30000,-30000) returned %d\n", Result);
        GetCursorPos(&Pos);
        ok(Pos.x == Expected.x && Pos.y == Expected.y, "the cursor is at %ld,%ld, SetCursorPos left it at %ld,%ld\n",
           Pos.x, Pos.y, Expected.x, Expected.y);
        SetCursorPos(Saved.x, Saved.y);
    }

    /* the point conversions (identical at 100 percent scaling) */
    if (pGetDpiForSystem && pGetDpiForSystem(NULL) != 96)
    {
        skip("the system DPI is not 96\n");
    }
    else
    {
        TestPointConversion(pPhysicalToLogicalPoint, "PhysicalToLogicalPoint", Top, Child, Owned);
        TestPointConversion(pLogicalToPhysicalPoint, "LogicalToPhysicalPoint", Top, Child, Owned);
    }

    /* the window under a point */
    if (Interactive)
    {
        static const POINT Points[] = { { 150, 150 }, { 0, 0 }, { 110, 130 }, { -5, -5 }, { 30000, 30000 }, { 650, 150 } };

        for (i = 0; i < (int)(sizeof(Points) / sizeof(Points[0])); i++)
        {
            HWND Physical = pWindowFromPhysicalPoint(Points[i]);
            HWND Logical = WindowFromPoint(Points[i]);

            ok(Physical == Logical, "(%ld,%ld): WindowFromPhysicalPoint gave %p, WindowFromPoint %p\n",
               Points[i].x, Points[i].y, Physical, Logical);
        }
    }

    /* no pointer message was ever sent, so there is no position of one */
    ok(pGetUnpredictedMessagePos() == 0, "GetUnpredictedMessagePos returned 0x%08lx\n", pGetUnpredictedMessagePos());

    /* the system DPI of a process */
    Dpi = pGetDpiForSystem ? pGetDpiForSystem(NULL) : 96;
    SetLastError(PENDING_ERROR);
    ok(pGetSystemDpiForProcess(GetCurrentProcess()) == Dpi, "the system DPI of this process is not %u\n", Dpi);
    ok(GetLastError() == PENDING_ERROR, "the last error became %lu\n", GetLastError());
    ok(pGetSystemDpiForProcess(NULL) == Dpi, "the system DPI of NULL is not %u\n", Dpi);
    SetLastError(PENDING_ERROR);
    ok(pGetSystemDpiForProcess((HANDLE)(ULONG_PTR)0x1234) == 0, "a bad handle has a DPI\n");
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "bad handle: last error %lu\n", GetLastError());
    Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
    if (Process)
    {
        ok(pGetSystemDpiForProcess(Process) == Dpi, "the system DPI of a limited handle is not %u\n", Dpi);
        CloseHandle(Process);
    }
    Process = OpenProcess(SYNCHRONIZE, FALSE, GetCurrentProcessId());
    if (Process)
    {
        SetLastError(PENDING_ERROR);
        ok(pGetSystemDpiForProcess(Process) == 0, "a handle without query access has a DPI\n");
        ok(GetLastError() == ERROR_INVALID_PARAMETER, "synchronize handle: last error %lu\n", GetLastError());
        CloseHandle(Process);
    }

    /* top-level windows: the ones below the desktop, not the desktop and not message-only windows */
    {
        struct { HWND Wnd; BOOL IsTop; HWND Top; const char *Name; } Cases[] =
        {
            { Desktop, FALSE, NULL, "desktop" },
            { Top, TRUE, Top, "top" },
            { Child, FALSE, Top, "child" },
            { GrandChild, FALSE, Top, "grandchild" },
            { Owned, TRUE, Owned, "owned popup" },
            { Owner2, TRUE, Owner2, "owned overlapped" },
            { MsgOnly, FALSE, NULL, "message-only" },
        };
        HWND Found;

        for (i = 0; i < (int)(sizeof(Cases) / sizeof(Cases[0])); i++)
        {
            if (!Cases[i].Wnd)
                continue;
            SetLastError(PENDING_ERROR);
            Result = pIsTopLevelWindow(Cases[i].Wnd);
            Error = GetLastError();
            ok(Result == Cases[i].IsTop, "IsTopLevelWindow(%s) returned %d\n", Cases[i].Name, Result);
            ok(Error == PENDING_ERROR, "IsTopLevelWindow(%s): last error %lu\n", Cases[i].Name, Error);
            SetLastError(PENDING_ERROR);
            Found = pGetTopLevelWindow(Cases[i].Wnd);
            Error = GetLastError();
            ok(Found == Cases[i].Top, "GetTopLevelWindow(%s) returned %p, expected %p\n", Cases[i].Name, Found, Cases[i].Top);
            ok(Error == PENDING_ERROR, "GetTopLevelWindow(%s): last error %lu\n", Cases[i].Name, Error);
        }

        SetLastError(PENDING_ERROR);
        ok(pIsTopLevelWindow(NULL) == FALSE, "IsTopLevelWindow(NULL) succeeded\n");
        ok(GetLastError() == ERROR_INVALID_WINDOW_HANDLE, "IsTopLevelWindow(NULL): last error %lu\n", GetLastError());
        SetLastError(PENDING_ERROR);
        ok(pIsTopLevelWindow((HWND)(ULONG_PTR)0x12345) == FALSE, "IsTopLevelWindow(bad) succeeded\n");
        ok(GetLastError() == ERROR_INVALID_WINDOW_HANDLE, "IsTopLevelWindow(bad): last error %lu\n", GetLastError());
        SetLastError(PENDING_ERROR);
        ok(pGetTopLevelWindow(NULL) == NULL, "GetTopLevelWindow(NULL) returned a window\n");
        ok(GetLastError() == ERROR_INVALID_WINDOW_HANDLE, "GetTopLevelWindow(NULL): last error %lu\n", GetLastError());
        SetLastError(PENDING_ERROR);
        ok(pGetTopLevelWindow((HWND)(ULONG_PTR)0x12345) == NULL, "GetTopLevelWindow(bad) returned a window\n");
        ok(GetLastError() == ERROR_INVALID_WINDOW_HANDLE, "GetTopLevelWindow(bad): last error %lu\n", GetLastError());
    }

    if (MsgOnly)
        DestroyWindow(MsgOnly);
    DestroyWindow(Owner2);
    DestroyWindow(Owned);
    DestroyWindow(Top);
}
