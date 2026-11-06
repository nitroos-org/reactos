/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     SetClipboardData with GDI handles that are not what the format carries
 *
 * Windows takes any handle for the GDI formats and only drops what the clipboard really owns:
 * a DC or a pen given as a bitmap, or a bitmap given as a palette, is still the application's
 * after EmptyClipboard. The expected results are the ones Windows 10 gives.
 */

#include "precomp.h"

static HWND hwnd;

static void test_foreign_gdi_objects(void)
{
    HBITMAP hbm;
    HDC hdc;
    HPEN hpen;
    HANDLE h;

    ok(OpenClipboard(hwnd), "OpenClipboard failed, error %lu\n", GetLastError());
    ok(EmptyClipboard(), "EmptyClipboard failed, error %lu\n", GetLastError());

    /* a bitmap is the clipboard's from SetClipboardData on */
    hbm = CreateBitmap(4, 4, 1, 32, NULL);
    h = SetClipboardData(CF_BITMAP, hbm);
    ok(h == hbm, "SetClipboardData(CF_BITMAP, bitmap) returned %p\n", h);
    ok(EmptyClipboard(), "EmptyClipboard failed\n");
    ok(GetObjectType(hbm) == 0, "the bitmap the clipboard dropped is still there\n");

    /* a DC is not a bitmap: the clipboard must not delete it */
    hdc = CreateCompatibleDC(NULL);
    h = SetClipboardData(CF_BITMAP, hdc);
    ok(h == hdc, "SetClipboardData(CF_BITMAP, DC) returned %p\n", h);
    ok(EmptyClipboard(), "EmptyClipboard failed\n");
    ok(GetObjectType(hdc) == OBJ_MEMDC, "the DC given as a bitmap was deleted: type %lu\n", GetObjectType(hdc));
    DeleteDC(hdc);

    hpen = CreatePen(PS_SOLID, 1, RGB(1, 2, 3));
    h = SetClipboardData(CF_BITMAP, hpen);
    ok(h == hpen, "SetClipboardData(CF_BITMAP, pen) returned %p\n", h);
    ok(EmptyClipboard(), "EmptyClipboard failed\n");
    ok(GetObjectType(hpen) == OBJ_PEN, "the pen given as a bitmap was deleted: type %lu\n", GetObjectType(hpen));
    DeleteObject(hpen);

    /* a bitmap is not a palette either */
    hbm = CreateBitmap(4, 4, 1, 32, NULL);
    h = SetClipboardData(CF_PALETTE, hbm);
    ok(h == hbm, "SetClipboardData(CF_PALETTE, bitmap) returned %p\n", h);
    ok(EmptyClipboard(), "EmptyClipboard failed\n");
    ok(GetObjectType(hbm) == OBJ_BITMAP, "the bitmap given as a palette was deleted: type %lu\n", GetObjectType(hbm));
    DeleteObject(hbm);

    /* a handle that is nothing at all is kept as it is and dropped without harm */
    h = SetClipboardData(CF_BITMAP, (HANDLE)(ULONG_PTR)0x12345678);
    ok(h == (HANDLE)(ULONG_PTR)0x12345678, "SetClipboardData(CF_BITMAP, number) returned %p\n", h);
    ok(EmptyClipboard(), "EmptyClipboard failed\n");

    /* the same bitmap again: the clipboard still has it */
    hbm = CreateBitmap(4, 4, 1, 32, NULL);
    ok(SetClipboardData(CF_BITMAP, hbm) == hbm, "first SetClipboardData failed\n");
    ok(SetClipboardData(CF_BITMAP, hbm) == hbm, "second SetClipboardData failed\n");
    ok(GetObjectType(hbm) == OBJ_BITMAP, "the bitmap was deleted by setting it again\n");
    h = GetClipboardData(CF_BITMAP);
    ok(h == hbm, "GetClipboardData(CF_BITMAP) returned %p, expected %p\n", h, hbm);
    ok(EmptyClipboard(), "EmptyClipboard failed\n");
    ok(CloseClipboard(), "CloseClipboard failed\n");
}

START_TEST(ClipboardSetData)
{
    hwnd = CreateWindowExA(0, "STATIC", "clip", 0, 0, 0, 1, 1, HWND_MESSAGE, NULL, GetModuleHandleA(NULL), NULL);
    ok(hwnd != NULL, "CreateWindowEx failed\n");
    if (!hwnd)
        return;

    test_foreign_gdi_objects();

    DestroyWindow(hwnd);
}
