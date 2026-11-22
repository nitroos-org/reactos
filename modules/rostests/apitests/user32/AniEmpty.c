/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     An animated cursor object without frames (as user32 creates it before it
 *              sends the data): used as the pointer, drawn, queried, destroyed
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <winreg.h>

/* ReactOS' own simple call routine index (the Windows XP SP2 table, 0x21) */
#define ROUTINE_CREATEEMPTYCUROBJECT 0x21

HCURSOR WINAPI GetCursorFrameInfo(HCURSOR, DWORD, DWORD, PINT, DWORD *);

typedef ULONG_PTR (WINAPI *PCALL1)(ULONG_PTR, DWORD);
typedef BOOL (WINAPI *PSETDATA)(HCURSOR, PVOID, PVOID, const VOID *);

static BOOL running_on_reactos(void)
{
    HKEY key;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\ReactOS\\ReactOS", 0, KEY_READ, &key) != ERROR_SUCCESS)
        return FALSE;
    RegCloseKey(key);
    return TRUE;
}

/* The fields of the kernel's CURSORDATA that the test fills (win32ss/include/ntuser.h) */
typedef struct
{
    LPWSTR lpName;
    LPWSTR lpModName;
    USHORT rt;
    USHORT dummy;
    ULONG CURSORF_flags;
    SHORT xHotspot;
    SHORT yHotspot;
    HBITMAP hbmMask;
    HBITMAP hbmColor;
    HBITMAP hbmAlpha;
    RECT rcBounds;
    HBITMAP hbmUserAlpha;
    ULONG bpp;
    ULONG cx;
    ULONG cy;
    UINT cpcur;
    UINT cicur;
    PVOID aspcur;
    DWORD *aicur;
    INT *ajifRate;
    UINT iicur;
} CURSORDATA_T;

#define T_CURSORF_ACON 0x0008

static void MoveInto(HWND hwnd, int dx)
{
    RECT rc;
    INPUT in = { INPUT_MOUSE };
    MSG msg;
    int i;

    GetWindowRect(hwnd, &rc);
    for (i = 0; i < 3; i++)
    {
        in.mi.dx = ((rc.left + 20 + dx + i * 3) * 65536) / GetSystemMetrics(SM_CXSCREEN);
        in.mi.dy = ((rc.top + 20 + i * 3) * 65536) / GetSystemMetrics(SM_CYSCREEN);
        in.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE;
        SendInput(1, &in, sizeof(in));
        Sleep(20);
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
            DispatchMessageW(&msg);
    }
}

static void ExerciseEmpty(PCALL1 pCall, PSETDATA pSetData, BOOL animated, BOOL refuse)
{
    HWND hwnd;
    HDC hdc;
    HCURSOR hcur, hold, hnow;
    ICONINFO ii;
    DWORD steps;
    INT rate;
    UINT step;
    BOOL ret;

    hwnd = CreateWindowExW(0, L"STATIC", L"AniEmpty", WS_POPUP | WS_VISIBLE, 40, 40, 200, 200,
                           NULL, NULL, GetModuleHandleW(NULL), NULL);
    ok(hwnd != NULL, "CreateWindowEx failed %lu\n", GetLastError());
    if (!hwnd)
        return;
    hdc = GetDC(hwnd);

    hcur = (HCURSOR)pCall(animated, ROUTINE_CREATEEMPTYCUROBJECT);
    ok(hcur != NULL, "no object\n");
    if (!hcur)
        goto done;

    if (refuse)
    {
        /* Data that is refused: a step naming a frame that does not exist */
        CURSORDATA_T cd, frame;
        DWORD seq[1] = { 5 };
        INT jif[1] = { 1 };

        ZeroMemory(&cd, sizeof(cd));
        ZeroMemory(&frame, sizeof(frame));
        cd.CURSORF_flags = T_CURSORF_ACON;
        cd.cpcur = 1;
        cd.cicur = 1;
        cd.aspcur = &frame;
        cd.aicur = seq;
        cd.ajifRate = jif;
        ret = pSetData(hcur, NULL, NULL, &cd);
        ok(!ret, "refused data accepted\n");
    }

    hold = SetCursor(hcur);
    ok(hold != hcur, "old cursor is the new one\n");
    hnow = GetCursor();
    ok(hnow == hcur, "GetCursor returned %p, expected %p\n", hnow, hcur);
    /* the window's own cursor takes over at the first mouse move: the object is only drawn from */
    MoveInto(hwnd, 0);

    /* The class cursor of a window that has the object: the first mouse move over it uses it */
    SetClassLongPtrW(hwnd, GCLP_HCURSOR, (LONG_PTR)hcur);
    MoveInto(hwnd, 30);

    for (step = 0; step < 6; step++)
    {
        SetLastError(0xdeadbeef);
        ret = DrawIconEx(hdc, 0, 0, hcur, 16, 16, step, NULL, DI_NORMAL);
        if (animated)
            ok(!ret, "DrawIconEx step %u returned TRUE\n", step);
    }
    ret = DrawIconEx(hdc, 0, 0, hcur, 16, 16, 0xFFFFFFFF, NULL, DI_NORMAL);
    ok(!ret || !animated, "DrawIconEx step -1 returned TRUE\n");

    for (step = 0; step < 3; step++)
    {
        steps = 0x1234;
        rate = 0x1234;
        SetLastError(0xdeadbeef);
        ret = GetCursorFrameInfo(hcur, 0, step, &rate, &steps) != NULL;
        if (animated)
            ok(!ret, "GetCursorFrameInfo step %u succeeded\n", step);
    }

    ZeroMemory(&ii, sizeof(ii));
    SetLastError(0xdeadbeef);
    ret = GetIconInfo(hcur, &ii);
    if (animated)
        ok(!ret, "GetIconInfo succeeded\n");
    if (ret)
    {
        if (ii.hbmMask) DeleteObject(ii.hbmMask);
        if (ii.hbmColor) DeleteObject(ii.hbmColor);
    }

    /* The object is the pointer now: take it away, then destroy it */
    SetCursor(hold);
    MoveInto(hwnd, 0);
    SetCursor(hcur);
    MoveInto(hwnd, 30);
    ret = DestroyCursor(hcur);
    trace("DestroyCursor while current: %d\n", ret);
    SetCursor(hold);
    MoveInto(hwnd, 0);
    SetClassLongPtrW(hwnd, GCLP_HCURSOR, (LONG_PTR)hold);
    DestroyCursor(hcur);

done:
    ReleaseDC(hwnd, hdc);
    DestroyWindow(hwnd);
}

/* A cursor that was the pointer and has been replaced by the cursor of the window under the pointer
   can be destroyed (it stayed "current" and its handle was never released) */
static void DestroyAfterReplaced(PCALL1 pCall)
{
    HWND hwnd;
    HCURSOR hcur;
    DWORD before, after;
    int i;

    hwnd = CreateWindowExW(0, L"STATIC", L"AniEmpty", WS_POPUP | WS_VISIBLE, 40, 40, 200, 200,
                           NULL, NULL, GetModuleHandleW(NULL), NULL);
    if (!hwnd)
        return;
    MoveInto(hwnd, 0);
    before = GetGuiResources(GetCurrentProcess(), GR_USEROBJECTS);
    for (i = 0; i < 20; i++)
    {
        hcur = (HCURSOR)pCall(FALSE, ROUTINE_CREATEEMPTYCUROBJECT);
        SetCursor(hcur);
        MoveInto(hwnd, i);
        ok(DestroyCursor(hcur), "DestroyCursor of the replaced cursor failed, error %lu\n", GetLastError());
    }
    after = GetGuiResources(GetCurrentProcess(), GR_USEROBJECTS);
    ok(after == before, "%lu USER objects before, %lu after\n", before, after);

    /* A cursor destroyed while the pointer, then replaced: the object is freed (its reference was kept) */
    for (i = 0; i < 20; i++)
    {
        hcur = (HCURSOR)pCall(FALSE, ROUTINE_CREATEEMPTYCUROBJECT);
        SetCursor(hcur);
        SetCursor(hcur);
        DestroyCursor(hcur);
        MoveInto(hwnd, i);
    }
    after = GetGuiResources(GetCurrentProcess(), GR_USEROBJECTS);
    ok(after == before, "destroyed while current: %lu USER objects before, %lu after\n", before, after);
    DestroyWindow(hwnd);
}

START_TEST(AniEmpty)
{
    HMODULE hwin32u;
    PCALL1 pCall;
    PSETDATA pSetData;

    if (!running_on_reactos())
    {
        skip("ReactOS' simple call numbers\n");
        return;
    }
    hwin32u = LoadLibraryW(L"win32u.dll");
    pCall = hwin32u ? (PCALL1)GetProcAddress(hwin32u, "NtUserCallOneParam") : NULL;
    pSetData = hwin32u ? (PSETDATA)GetProcAddress(hwin32u, "NtUserSetCursorIconData") : NULL;
    if (!pCall || !pSetData)
    {
        skip("no win32u\n");
        return;
    }

    DestroyAfterReplaced(pCall);
    ExerciseEmpty(pCall, pSetData, FALSE, FALSE);
    ExerciseEmpty(pCall, pSetData, TRUE, FALSE);
    ExerciseEmpty(pCall, pSetData, TRUE, TRUE);
}
