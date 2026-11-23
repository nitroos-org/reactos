/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     DestroyCursor of the cursor that is the pointer of the thread
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/* Windows Server 2022 (10.0.20348.587, probe on the reference): DestroyCursor of the cursor that SetCursor made
 * the pointer returns FALSE with the last error left alone, and the handle is gone all the same: SetCursor and
 * DestroyCursor of it fail with ERROR_INVALID_CURSOR_HANDLE, and SetCursor of another cursor afterwards returns
 * NULL as the old cursor. A cursor that another one replaced is destroyed normally (TRUE). SetCursor twice with
 * the same cursor leaves it the pointer. */

static HCURSOR MakeCursor(void)
{
    BYTE And[128], Xor[128];

    memset(And, 0xFF, sizeof(And));
    memset(Xor, 0, sizeof(Xor));
    return CreateCursor(GetModuleHandleW(NULL), 1, 1, 32, 32, And, Xor);
}

static void Test_CurrentCursor(HCURSOR Arrow)
{
    HCURSOR Cursor, Old;
    BOOL Ret;

    Cursor = MakeCursor();
    ok(Cursor != NULL, "CreateCursor failed: %lu\n", GetLastError());
    if (!Cursor)
        return;

    Old = SetCursor(Cursor);
    ok(Old == Arrow, "SetCursor returned %p, expected %p\n", Old, Arrow);

    SetLastError(0xDEADBEEF);
    Ret = DestroyCursor(Cursor);
    ok(Ret == FALSE, "DestroyCursor of the current cursor returned %d\n", Ret);
    ok(GetLastError() == 0xDEADBEEF, "last error %lu\n", GetLastError());

    /* the handle is gone */
    SetLastError(0xDEADBEEF);
    Old = SetCursor(Cursor);
    ok(Old == NULL, "SetCursor of the destroyed cursor returned %p\n", Old);
    ok(GetLastError() == ERROR_INVALID_CURSOR_HANDLE, "last error %lu\n", GetLastError());
    SetLastError(0xDEADBEEF);
    Ret = DestroyCursor(Cursor);
    ok(Ret == FALSE, "second DestroyCursor returned %d\n", Ret);
    ok(GetLastError() == ERROR_INVALID_CURSOR_HANDLE, "last error %lu\n", GetLastError());

    /* the destroyed cursor is not given back as the old one */
    SetLastError(0xDEADBEEF);
    Old = SetCursor(Arrow);
    ok(Old == NULL, "SetCursor(arrow) returned %p, expected NULL\n", Old);
    ok(GetLastError() == 0xDEADBEEF, "last error %lu\n", GetLastError());
}

static void Test_SetTwice(HCURSOR Arrow)
{
    HCURSOR Cursor, Old;
    BOOL Ret;

    Cursor = MakeCursor();
    ok(Cursor != NULL, "CreateCursor failed: %lu\n", GetLastError());
    if (!Cursor)
        return;

    SetCursor(Cursor);
    Old = SetCursor(Cursor);
    ok(Old == Cursor, "second SetCursor returned %p, expected %p\n", Old, Cursor);

    /* still the pointer: refused (and destroyed) */
    Ret = DestroyCursor(Cursor);
    ok(Ret == FALSE, "DestroyCursor after SetCursor twice returned %d\n", Ret);
    SetLastError(0xDEADBEEF);
    Old = SetCursor(Cursor);
    ok(Old == NULL && GetLastError() == ERROR_INVALID_CURSOR_HANDLE, "SetCursor returned %p, error %lu\n", Old, GetLastError());

    SetCursor(Arrow);
}

static void Test_Replaced(HCURSOR Arrow)
{
    HCURSOR First, Second, Old;
    BOOL Ret;

    First = MakeCursor();
    Second = MakeCursor();
    ok(First != NULL && Second != NULL, "CreateCursor failed: %lu\n", GetLastError());
    if (!First || !Second)
        return;

    SetCursor(First);
    SetCursor(Second);
    Ret = DestroyCursor(First);
    ok(Ret == TRUE, "DestroyCursor of a replaced cursor returned %d\n", Ret);

    /* no pointer at all: the cursor that was the pointer can be destroyed */
    Old = SetCursor(NULL);
    ok(Old == Second, "SetCursor(NULL) returned %p, expected %p\n", Old, Second);
    Ret = DestroyCursor(Second);
    ok(Ret == TRUE, "DestroyCursor after SetCursor(NULL) returned %d\n", Ret);

    SetCursor(Arrow);
}

/* destroying the pointer cursor, again and again, leaves no USER object behind */
static void Test_NoLeak(HCURSOR Arrow)
{
    DWORD Before, After;
    int i;

    Before = GetGuiResources(GetCurrentProcess(), GR_USEROBJECTS);
    for (i = 0; i < 50; i++)
    {
        HCURSOR Cursor = MakeCursor();

        if (!Cursor)
            break;
        SetCursor(Cursor);
        DestroyCursor(Cursor);
        SetCursor(Arrow);
    }
    After = GetGuiResources(GetCurrentProcess(), GR_USEROBJECTS);
    ok(After == Before, "USER objects: %lu before, %lu after\n", Before, After);
}

/* SetSystemCursor takes the cursor (Windows destroys it); one that it does not keep must not stay referenced
 * after the program destroys it */
static void Test_SetSystemCursorNoLeak(void)
{
    DWORD Before, After;
    int i;

    Before = GetGuiResources(GetCurrentProcess(), GR_USEROBJECTS);
    for (i = 0; i < 50; i++)
    {
        HCURSOR Cursor = MakeCursor();

        if (!Cursor)
            break;
        SetSystemCursor(Cursor, OCR_NORMAL);
        DestroyCursor(Cursor);
    }
    SystemParametersInfoW(SPI_SETCURSORS, 0, NULL, 0);
    After = GetGuiResources(GetCurrentProcess(), GR_USEROBJECTS);
    ok(After == Before, "USER objects: %lu before, %lu after\n", Before, After);
}

START_TEST(DestroyCurrentCursor)
{
    HCURSOR Arrow = LoadCursorW(NULL, MAKEINTRESOURCEW(OCR_NORMAL));

    ok(Arrow != NULL, "LoadCursor failed\n");
    SetCursor(Arrow);

    Test_CurrentCursor(Arrow);
    Test_SetTwice(Arrow);
    Test_Replaced(Arrow);
    Test_NoLeak(Arrow);
    Test_SetSystemCursorNoLeak();
}
