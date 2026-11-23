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
#define SETTER_PROCESS_ROUNDS   300
#define SETTER_INPROCESS_ROUNDS 1000

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

/* A cursor of a pattern a drawing can tell from every system arrow: opaque white all over (AND 0, XOR 1) */
static HCURSOR MakeWhiteCursor(int HotX, int HotY)
{
    BYTE And[128], Xor[128];

    memset(And, 0, sizeof(And));
    memset(Xor, 0xFF, sizeof(Xor));
    return CreateCursor(GetModuleHandleW(NULL), HotX, HotY, 32, 32, And, Xor);
}

/* Entries of the GDI handle table that are in use, every owner and the public ones included: what a bitmap that
 * nobody deletes leaves behind. -1 where the table is not mapped in this layout (a 32-bit process under WoW64). */
typedef struct _GDI_ENTRY_VIEW
{
    PVOID pobj;
    ULONG ulObj;
    USHORT FullUnique;
    UCHAR Objt;
    UCHAR Flags;
    PVOID pUser;
} GDI_ENTRY_VIEW;

static LONG GdiEntriesInUse(void)
{
    /* PEB at TEB+0x60 (0x30 on x86), GdiSharedHandleTable at PEB+0xF8 (0x94 on x86) */
    PUCHAR Peb = *(PUCHAR *)((PUCHAR)NtCurrentTeb() + (sizeof(PVOID) == 8 ? 0x60 : 0x30));
    GDI_ENTRY_VIEW *Table = *(GDI_ENTRY_VIEW **)(Peb + (sizeof(PVOID) == 8 ? 0xF8 : 0x94));
    BOOL Wow64 = FALSE;
    LONG Count = 0;
    ULONG i;

    if (!Table)
        return -1;
    IsWow64Process(GetCurrentProcess(), &Wow64);
    if (Wow64)
        return -1;
    for (i = 0; i < 0x10000; i++)
    {
        if ((LONG_PTR)Table[i].pobj < 0 && Table[i].Objt != 0)
            Count++;
    }
    return Count;
}

/* The process that sets a system cursor from a cursor of its own and exits (the test's second process) */
static void ChildSetsAndExits(void)
{
    HCURSOR Cursor;

    GetSystemMetrics(SM_CXSCREEN);  /* a GUI process */
    Cursor = MakeWhiteCursor(11, 13);
    if (!Cursor || !SetSystemCursor(Cursor, OCR_NORMAL_ID))
        ExitProcess(2);
    ExitProcess(0);
}

static BOOL RunChild(void)
{
    WCHAR Path[MAX_PATH + 64];
    STARTUPINFOW Si = { sizeof(Si) };
    PROCESS_INFORMATION Pi;
    DWORD Code = 99;
    size_t Len;

    Len = GetModuleFileNameW(NULL, Path, MAX_PATH);
    if (!Len || Len >= MAX_PATH)
        return FALSE;
    wcscpy(Path + Len, L" SetSystemCursor child");
    if (!CreateProcessW(NULL, Path, NULL, NULL, FALSE, 0, NULL, NULL, &Si, &Pi))
        return FALSE;
    WaitForSingleObject(Pi.hProcess, 60000);
    GetExitCodeProcess(Pi.hProcess, &Code);
    CloseHandle(Pi.hProcess);
    CloseHandle(Pi.hThread);
    return Code == 0;
}

/* What the system cursor is when drawn: 1 where the center pixel of a 32x32 draw is white */
static int DrawsWhite(HCURSOR Cursor)
{
    HDC Screen = GetDC(NULL), Mem = CreateCompatibleDC(Screen);
    HBITMAP Bmp = CreateCompatibleBitmap(Screen, 32, 32), Old = SelectObject(Mem, Bmp);
    COLORREF Px;
    BOOL Ret;

    PatBlt(Mem, 0, 0, 32, 32, BLACKNESS);
    Ret = DrawIconEx(Mem, 0, 0, Cursor, 32, 32, 0, NULL, DI_NORMAL);
    Px = GetPixel(Mem, 16, 16);
    SelectObject(Mem, Old);
    DeleteObject(Bmp);
    DeleteDC(Mem);
    ReleaseDC(NULL, Screen);
    if (!Ret)
        return -1;
    return Px == RGB(255, 255, 255);
}

/* Process A sets a system cursor from its own cursor and exits; process B (this one) then uses the system cursor.
 * The bitmaps that A created must not die with A: the system cursor keeps them for every process. */
static void TestSetterExit(HCURSOR Arrow, ICONINFO *SavedArrow)
{
    HCURSOR Now, Copy;
    ICONINFO Info;
    CURSORINFO Ci = { sizeof(Ci) };
    BITMAP Bm;
    WNDCLASSW Wc = { 0 };
    HWND Wnd;
    HCURSOR Previous;
    LONG GdiBefore, GdiAfter;
    DWORD UserBefore, UserAfter, GdiOwn;
    int i;

    ok(RunChild(), "the setter process did not finish with 0\n");

    Now = LoadCursorW(NULL, MAKEINTRESOURCEW(OCR_NORMAL_ID));
    ok(Now == Arrow, "the system cursor has the handle %p after the setter exited, was %p\n", Now, Arrow);
    ZeroMemory(&Info, sizeof(Info));
    ok(GetIconInfo(Now, &Info), "GetIconInfo of the system cursor failed %lu after the setter exited\n", GetLastError());
    ok(Info.xHotspot == 11 && Info.yHotspot == 13, "hot spot (%lu, %lu) after the setter exited, expected (11, 13)\n",
       Info.xHotspot, Info.yHotspot);
    ok(Info.hbmMask != NULL, "no mask bitmap after the setter exited\n");
    if (Info.hbmMask)
    {
        ZeroMemory(&Bm, sizeof(Bm));
        ok(GetObjectW(Info.hbmMask, sizeof(Bm), &Bm) == sizeof(Bm) && Bm.bmWidth == 32,
           "mask bitmap of the system cursor: width %ld\n", Bm.bmWidth);
        DeleteObject(Info.hbmMask);
    }
    if (Info.hbmColor)
        DeleteObject(Info.hbmColor);
    ok(DrawsWhite(Now) == 1, "the system cursor does not draw the setter's pattern after the setter exited\n");
    Copy = CopyCursor(Now);
    ok(Copy != NULL, "CopyCursor of the system cursor failed %lu\n", GetLastError());
    if (Copy)
    {
        ok(DrawsWhite(Copy) == 1, "the copy does not draw the setter's pattern\n");
        DestroyCursor(Copy);
    }

    /* The pointer over a window of this process */
    Wc.lpfnWndProc = DefWindowProcW;
    Wc.hInstance = GetModuleHandleW(NULL);
    Wc.hCursor = Now;
    Wc.lpszClassName = L"SetSystemCursorWnd";
    RegisterClassW(&Wc);
    Wnd = CreateWindowExW(0, Wc.lpszClassName, L"x", WS_POPUP | WS_VISIBLE, 0, 0, 64, 64, NULL, NULL, Wc.hInstance, NULL);
    ok(Wnd != NULL, "CreateWindowEx failed %lu\n", GetLastError());
    if (Wnd)
    {
        SetCursorPos(10, 10);
        Previous = SetCursor(Now);
        (void)Previous;
        ok(GetCursorInfo(&Ci), "GetCursorInfo failed %lu\n", GetLastError());
        ok(Ci.hCursor == Now || Ci.hCursor == NULL, "the cursor on screen is %p, the system cursor %p\n", Ci.hCursor, Now);
        ok(DrawsWhite(Ci.hCursor ? Ci.hCursor : Now) == 1, "the cursor of GetCursorInfo does not draw the pattern\n");
        DestroyWindow(Wnd);
    }
    UnregisterClassW(Wc.lpszClassName, Wc.hInstance);

    /* Rounds: A sets and exits (processes), and one process sets from its own cursors many times; nothing may be left,
     * in this process's USER and GDI objects and in the shared GDI table (the public bitmaps of the cursors) */
    GdiBefore = GdiEntriesInUse();
    UserBefore = GetGuiResources(GetCurrentProcess(), GR_USEROBJECTS);
    GdiOwn = GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS);
    for (i = 0; i < SETTER_PROCESS_ROUNDS; i++)
    {
        if (!RunChild())
        {
            ok(0, "round %d: the setter process failed\n", i);
            break;
        }
    }
    for (i = 0; i < SETTER_INPROCESS_ROUNDS; i++)
    {
        HCURSOR Own = MakeWhiteCursor(i % 32, i % 32);

        if (!Own || !SetSystemCursor(Own, OCR_NORMAL_ID))
        {
            ok(0, "round %d: SetSystemCursor failed %lu\n", i, GetLastError());
            break;
        }
    }
    GdiAfter = GdiEntriesInUse();
    UserAfter = GetGuiResources(GetCurrentProcess(), GR_USEROBJECTS);
    ok(UserAfter <= UserBefore, "USER objects of this process before %lu, after %lu\n", UserBefore, UserAfter);
    ok(GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS) == GdiOwn, "GDI objects of this process before %lu, after %lu\n",
       GdiOwn, GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS));
    if (GdiBefore >= 0)
        ok(GdiAfter <= GdiBefore + 8, "GDI table entries in use before %ld, after %ld (%d + %d rounds)\n",
           GdiBefore, GdiAfter, SETTER_PROCESS_ROUNDS, SETTER_INPROCESS_ROUNDS);
    ok(DrawsWhite(LoadCursorW(NULL, MAKEINTRESOURCEW(OCR_NORMAL_ID))) == 1, "the system cursor does not draw after the rounds\n");
    (void)SavedArrow;
}

START_TEST(SetSystemCursor)
{
    HCURSOR Arrow, Ibeam, Cursor, Copy, Again;
    ICONINFO SavedArrow, SavedIbeam;
    DWORD Objects, After;
    int X, Y;
    BOOL Ret;
    char **argv;

    if (winetest_get_mainargs(&argv) >= 3 && !strcmp(argv[2], "child"))
    {
        ChildSetsAndExits();
        return;
    }

    Arrow =LoadCursorW(NULL, MAKEINTRESOURCEW(OCR_NORMAL_ID));
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

    TestSetterExit(Arrow, &SavedArrow);

    /* The session's cursors as they were */
    Restore(OCR_NORMAL_ID, Arrow, &SavedArrow);
    Restore(OCR_IBEAM_ID, Ibeam, &SavedIbeam);
    ok(Hotspot(LoadCursorW(NULL, MAKEINTRESOURCEW(OCR_NORMAL_ID)), &X, &Y), "no arrow after the restore\n");

    After = GetGuiResources(GetCurrentProcess(), GR_USEROBJECTS);
    ok(After == Objects, "USER objects before %lu, after %lu\n", Objects, After);
}
