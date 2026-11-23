/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     SetSystemCursor of a system cursor that exists
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/* Windows Server 2022 (10.0.20348.587, probe on the reference, the cursor of a standard user at the console):
 * SetSystemCursor(h, OCR_NORMAL) returns TRUE and leaves the last error alone. The system cursor keeps its handle
 * (LoadCursor(NULL, IDC_ARROW) gives the same HCURSOR) and has the data of h (hot spot, size); h is destroyed:
 * GetIconInfo and DestroyCursor of it fail (ERROR_INVALID_CURSOR_HANDLE), so does a second SetSystemCursor with it.
 * A cursor created with CreateCursor and one made with CopyCursor behave alike. NULL fails with
 * ERROR_RESOURCE_NAME_NOT_FOUND; an id that is no system cursor fails with the last error left alone and the
 * cursor stays valid. No USER object is left behind. */

#define OCR_NORMAL_ID   32512
#define OCR_IBEAM_ID    32513

static HCURSOR MakeCursor(int HotX, int HotY)
{
    BYTE And[128], Xor[128];

    memset(And, 0xFF, sizeof(And));
    memset(Xor, 0, sizeof(Xor));
    return CreateCursor(GetModuleHandleW(NULL), HotX, HotY, 32, 32, And, Xor);
}

static BOOL Hotspot(HCURSOR Cursor, int *X, int *Y)
{
    ICONINFO Info;

    if (!GetIconInfo(Cursor, &Info))
        return FALSE;
    *X = Info.xHotspot;
    *Y = Info.yHotspot;
    if (Info.hbmMask)
        DeleteObject(Info.hbmMask);
    if (Info.hbmColor)
        DeleteObject(Info.hbmColor);
    return TRUE;
}

/* Puts a system cursor back as it was: a cursor with the saved data is made and handed over. */
static void Restore(DWORD Id, HCURSOR System, ICONINFO *Saved)
{
    HCURSOR Copy;

    Saved->fIcon = FALSE;
    Copy = CreateIconIndirect(Saved);
    if (Copy)
        SetSystemCursor(Copy, Id);
    if (Saved->hbmMask)
        DeleteObject(Saved->hbmMask);
    if (Saved->hbmColor)
        DeleteObject(Saved->hbmColor);
}

START_TEST(SetSystemCursor)
{
    HCURSOR Arrow, Ibeam, Cursor, Copy, Again;
    ICONINFO SavedArrow, SavedIbeam;
    DWORD Objects, After;
    int X, Y;
    BOOL Ret;

    Arrow = LoadCursorW(NULL, MAKEINTRESOURCEW(OCR_NORMAL_ID));
    Ibeam = LoadCursorW(NULL, MAKEINTRESOURCEW(OCR_IBEAM_ID));
    ok(Arrow != NULL && Ibeam != NULL, "LoadCursor failed %lu\n", GetLastError());
    if (!Arrow || !Ibeam || !GetIconInfo(Arrow, &SavedArrow))
        return;
    if (!GetIconInfo(Ibeam, &SavedIbeam))
    {
        DeleteObject(SavedArrow.hbmMask);
        if (SavedArrow.hbmColor)
            DeleteObject(SavedArrow.hbmColor);
        return;
    }
    Objects = GetGuiResources(GetCurrentProcess(), GR_USEROBJECTS);

    /* A created cursor with the hot spot (5, 5) */
    Cursor = MakeCursor(5, 5);
    ok(Cursor != NULL, "CreateCursor failed %lu\n", GetLastError());
    SetLastError(0xDEADBEEF);
    Ret = SetSystemCursor(Cursor, OCR_NORMAL_ID);
    ok(Ret == TRUE, "SetSystemCursor returned %d, error %lu\n", Ret, GetLastError());
    ok(GetLastError() == 0xDEADBEEF, "last error %lu\n", GetLastError());
    ok(!Hotspot(Cursor, &X, &Y), "the handle given to SetSystemCursor is still valid\n");
    SetLastError(0xDEADBEEF);
    Ret = DestroyCursor(Cursor);
    ok(Ret == FALSE && GetLastError() == ERROR_INVALID_CURSOR_HANDLE, "DestroyCursor returned %d, error %lu\n", Ret, GetLastError());
    Again = LoadCursorW(NULL, MAKEINTRESOURCEW(OCR_NORMAL_ID));
    ok(Again == Arrow, "The system cursor has the handle %p, was %p\n", Again, Arrow);
    ok(Hotspot(Again, &X, &Y) && X == 5 && Y == 5, "The system cursor has the hot spot (%d, %d), expected (5, 5)\n", X, Y);

    /* A copy of the system cursor, the case of the ticket */
    Copy = CopyCursor(Again);
    ok(Copy != NULL, "CopyCursor failed %lu\n", GetLastError());
    SetLastError(0xDEADBEEF);
    Ret = SetSystemCursor(Copy, OCR_NORMAL_ID);
    ok(Ret == TRUE, "SetSystemCursor of a copy returned %d, error %lu\n", Ret, GetLastError());
    ok(!Hotspot(Copy, &X, &Y), "the copy is still valid\n");
    SetLastError(0xDEADBEEF);
    Ret = DestroyCursor(Copy);
    ok(Ret == FALSE && GetLastError() == ERROR_INVALID_CURSOR_HANDLE, "DestroyCursor of the copy returned %d, error %lu\n", Ret, GetLastError());

    /* The handle a second time */
    Cursor = MakeCursor(7, 7);
    ok(SetSystemCursor(Cursor, OCR_NORMAL_ID) == TRUE, "SetSystemCursor failed %lu\n", GetLastError());
    SetLastError(0xDEADBEEF);
    Ret = SetSystemCursor(Cursor, OCR_NORMAL_ID);
    ok(Ret == FALSE && GetLastError() == ERROR_INVALID_CURSOR_HANDLE, "second SetSystemCursor returned %d, error %lu\n", Ret, GetLastError());
    ok(Hotspot(LoadCursorW(NULL, MAKEINTRESOURCEW(OCR_NORMAL_ID)), &X, &Y) && X == 7 && Y == 7, "hot spot (%d, %d), expected (7, 7)\n", X, Y);

    /* Another system cursor */
    Cursor = MakeCursor(9, 9);
    ok(SetSystemCursor(Cursor, OCR_IBEAM_ID) == TRUE, "SetSystemCursor(OCR_IBEAM) failed %lu\n", GetLastError());
    ok(LoadCursorW(NULL, MAKEINTRESOURCEW(OCR_IBEAM_ID)) == Ibeam, "the I-beam has another handle\n");
    ok(Hotspot(Ibeam, &X, &Y) && X == 9 && Y == 9, "I-beam hot spot (%d, %d), expected (9, 9)\n", X, Y);

    /* Arguments that fail: NULL, and an id of no system cursor (the cursor is not destroyed) */
    SetLastError(0xDEADBEEF);
    Ret = SetSystemCursor(NULL, OCR_NORMAL_ID);
    ok(Ret == FALSE && GetLastError() == ERROR_RESOURCE_NAME_NOT_FOUND, "SetSystemCursor(NULL) returned %d, error %lu\n", Ret, GetLastError());
    Cursor = MakeCursor(1, 1);
    SetLastError(0xDEADBEEF);
    Ret = SetSystemCursor(Cursor, 12345);
    ok(Ret == FALSE && GetLastError() == 0xDEADBEEF, "SetSystemCursor(12345) returned %d, error %lu\n", Ret, GetLastError());
    ok(Hotspot(Cursor, &X, &Y) && X == 1 && Y == 1, "the cursor of the failed call is not valid\n");
    ok(DestroyCursor(Cursor), "DestroyCursor failed %lu\n", GetLastError());

    /* The session's cursors as they were */
    Restore(OCR_NORMAL_ID, Arrow, &SavedArrow);
    Restore(OCR_IBEAM_ID, Ibeam, &SavedIbeam);
    ok(Hotspot(LoadCursorW(NULL, MAKEINTRESOURCEW(OCR_NORMAL_ID)), &X, &Y), "no arrow after the restore\n");

    After = GetGuiResources(GetCurrentProcess(), GR_USEROBJECTS);
    ok(After == Objects, "USER objects before %lu, after %lu\n", Objects, After);
}
