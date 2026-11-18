/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     WM_CHAR through the ANSI and the Unicode message functions, and SendInput(KEYEVENTF_UNICODE) into windows of both kinds
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The rows of the posted messages were measured on Windows Server 2022 (x64 and WOW64, code page 1252) with a program that
 * posts WM_CHAR to its own windows and retrieves it with PeekMessageA and PeekMessageW. The SendInput rows could not be
 * measured there (the peer has no interactive session); they follow the documentation: the system generates VK_PACKET key
 * events and TranslateMessage turns them into WM_CHAR with the UTF-16 unit, which an ANSI retrieval converts like any other
 * WM_CHAR. Windows 10 was not measured.
 */

#include "precomp.h"

#include <winnls.h>

#define TEST_ACP 1252

static WCHAR g_UnitLog[32];
static int g_UnitCount;

static LRESULT CALLBACK WndProcW(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_CHAR && g_UnitCount < 32)
        g_UnitLog[g_UnitCount++] = (WCHAR)wParam;
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static LRESULT CALLBACK WndProcA(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_CHAR && g_UnitCount < 32)
        g_UnitLog[g_UnitCount++] = (WCHAR)wParam;
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

static WPARAM Retrieve(HWND hwnd, BOOL Ansi)
{
    MSG Msg;
    int Tries;

    for (Tries = 0; Tries < 100; Tries++)
    {
        BOOL Ret = Ansi ? PeekMessageA(&Msg, hwnd, WM_CHAR, WM_CHAR, PM_REMOVE) : PeekMessageW(&Msg, hwnd, WM_CHAR, WM_CHAR, PM_REMOVE);

        if (Ret)
            return Msg.wParam;
        Sleep(5);
    }
    return (WPARAM)-1;
}

/* post as Unicode (PostMessageW) or ANSI, retrieve with PeekMessageA/W */
static void Row(HWND hwnd, BOOL PostAnsi, BOOL PeekAnsi, WPARAM Posted, WPARAM Expected)
{
    WPARAM Got;

    if (PostAnsi)
        PostMessageA(hwnd, WM_CHAR, Posted, 1);
    else
        PostMessageW(hwnd, WM_CHAR, Posted, 1);
    Got = Retrieve(hwnd, PeekAnsi);
    ok(Got == Expected, "post%c %04Ix, peek%c: got %Ix, expected %Ix\n", PostAnsi ? 'A' : 'W', Posted, PeekAnsi ? 'A' : 'W', Got, Expected);
}

static void TestRetrieval(HWND Wide, HWND Ansi)
{
    static const struct { WPARAM Posted, ToAnsi; } WRows[] =
    {
        { 0x0041, 0x41 }, { 0x00E9, 0xE9 }, { 0x0080, 0x3F }, { 0x00FF, 0xFF }, { 0x20AC, 0x80 }, { 0x0416, 0x3F },
        { 0x4E2D, 0x3F }, { 0xD83D, 0x3F }, { 0xFFFF, 0x3F }, { 0x0001, 0x01 }, { 0x003F, 0x3F },
    };
    static const struct { WPARAM Posted, ToUnicode; } ARows[] =
    {
        { 0x41, 0x41 }, { 0xE9, 0xE9 }, { 0x80, 0x20AC }, { 0xFF, 0xFF }, { 0x01, 0x01 }, { 0x3F, 0x3F },
    };
    UINT i;

    /* a Unicode WM_CHAR retrieved with the ANSI function is the character of the code page (no sign extension: 0xE9, not 0xFFE9),
       and unchanged with the Unicode function */
    for (i = 0; i < ARRAYSIZE(WRows); i++)
    {
        Row(Wide, FALSE, FALSE, WRows[i].Posted, WRows[i].Posted);
        Row(Wide, FALSE, TRUE, WRows[i].Posted, WRows[i].ToAnsi);
        Row(Ansi, FALSE, TRUE, WRows[i].Posted, WRows[i].ToAnsi);
    }
    /* an ANSI WM_CHAR is unchanged with the ANSI function and converted with the Unicode function */
    for (i = 0; i < ARRAYSIZE(ARows); i++)
    {
        /* NitroOS converts the ANSI characters 0x80..0x9F of a posted WM_CHAR with a table that is not the code page's (0x80 comes out as
           U+0080, then as 0x3F in the ANSI retrieval): not part of the sign extension fixed here */
        BOOL Todo = is_reactos() && ARows[i].Posted == 0x80;

        todo_if(Todo)
        Row(Wide, TRUE, TRUE, ARows[i].Posted, ARows[i].Posted);
        todo_if(Todo)
        Row(Wide, TRUE, FALSE, ARows[i].Posted, ARows[i].ToUnicode);
    }
}

/* ANSI retrieval and DispatchMessageA: the window procedure of either kind of window gets its own kind of character */
static void TestDispatch(HWND Wide, HWND Ansi)
{
    static const struct { WPARAM Posted, ToWide, ToAnsi; } Rows[] =
    {
        { 0x0041, 0x41, 0x41 }, { 0x00E9, 0xE9, 0xE9 }, { 0x0080, 0x3F, 0x3F }, { 0x00FF, 0xFF, 0xFF }, { 0x20AC, 0x20AC, 0x80 },
        { 0x0416, 0x3F, 0x3F }, { 0xD83D, 0x3F, 0x3F },
    };
    UINT i;

    for (i = 0; i < ARRAYSIZE(Rows); i++)
    {
        MSG Msg;
        int Tries;

        g_UnitCount = 0;
        PostMessageW(Wide, WM_CHAR, Rows[i].Posted, 1);
        for (Tries = 0; Tries < 100 && !PeekMessageA(&Msg, Wide, WM_CHAR, WM_CHAR, PM_REMOVE); Tries++)
            Sleep(5);
        DispatchMessageA(&Msg);
        ok(g_UnitCount == 1 && g_UnitLog[0] == Rows[i].ToWide, "wide window, %04Ix: %d messages, got %x, expected %Ix\n", Rows[i].Posted, g_UnitCount, g_UnitLog[0], Rows[i].ToWide);

        g_UnitCount = 0;
        PostMessageW(Ansi, WM_CHAR, Rows[i].Posted, 1);
        for (Tries = 0; Tries < 100 && !PeekMessageA(&Msg, Ansi, WM_CHAR, WM_CHAR, PM_REMOVE); Tries++)
            Sleep(5);
        DispatchMessageA(&Msg);
        ok(g_UnitCount == 1 && g_UnitLog[0] == Rows[i].ToAnsi, "ansi window, %04Ix: %d messages, got %x, expected %Ix\n", Rows[i].Posted, g_UnitCount, g_UnitLog[0], Rows[i].ToAnsi);
    }
}

static void PumpAll(HWND hwnd, BOOL Ansi, int Ms)
{
    DWORD End = GetTickCount() + Ms;
    MSG Msg;

    while ((int)(End - GetTickCount()) > 0)
    {
        while (Ansi ? PeekMessageA(&Msg, NULL, 0, 0, PM_REMOVE) : PeekMessageW(&Msg, NULL, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&Msg);
            if (Ansi)
                DispatchMessageA(&Msg);
            else
                DispatchMessageW(&Msg);
        }
        Sleep(5);
    }
}

static BOOL TypeUnits(HWND hwnd, BOOL Ansi, const WCHAR *Units)
{
    INPUT In[16];
    UINT n = 0;

    for (; *Units; Units++)
    {
        ZeroMemory(&In[n], sizeof(In[n]));
        In[n].type = INPUT_KEYBOARD;
        In[n].ki.wScan = *Units;
        In[n].ki.dwFlags = KEYEVENTF_UNICODE;
        In[n + 1] = In[n];
        In[n + 1].ki.dwFlags |= KEYEVENTF_KEYUP;
        n += 2;
    }
    g_UnitCount = 0;
    if (SendInput(n, In, sizeof(INPUT)) != n)
        return FALSE;
    PumpAll(hwnd, Ansi, 300);
    return TRUE;
}

/* KEYEVENTF_UNICODE: one WM_CHAR with the UTF-16 unit per unit; a surrogate pair is two; the retrieval kind decides the conversion */
static void TestSendInput(HWND Wide, HWND Ansi)
{
    static const struct { const WCHAR *Units; WCHAR Wide[4]; WCHAR Ansi[4]; PCSTR Name; } Rows[] =
    {
        { L"\x0068", { 0x68 }, { 0x68 }, "U+0068" },
        { L"\x00E9", { 0xE9 }, { 0xE9 }, "U+00E9" },
        { L"\x0416", { 0x416 }, { 0x3F }, "U+0416" },
        { L"\x4E2D", { 0x4E2D }, { 0x3F }, "U+4E2D" },
        { L"\x20AC", { 0x20AC }, { 0x80 }, "U+20AC" },
        { L"\xD83D\xDE00", { 0xD83D, 0xDE00 }, { 0x3F, 0x3F }, "U+1F600 as a surrogate pair" },
    };
    HWND Windows[2] = { Wide, Ansi };
    UINT i, k, j;

    for (k = 0; k < 2; k++)
    {
        SetForegroundWindow(Windows[k]);
        SetFocus(Windows[k]);
        PumpAll(Windows[k], k == 1, 200);
        if (GetFocus() != Windows[k])
        {
            skip("no focus on the %s window\n", k ? "ANSI" : "Unicode");
            continue;
        }
        /* a session that takes SendInput but delivers nothing (no interactive desktop) is not a failure of the rows */
        if (!TypeUnits(Windows[k], k == 1, L"h") || g_UnitCount == 0)
        {
            skip("SendInput does not reach the %s window (no interactive desktop?)\n", k ? "ANSI" : "Unicode");
            continue;
        }
        for (i = 0; i < ARRAYSIZE(Rows); i++)
        {
            const WCHAR *Expected = k ? Rows[i].Ansi : Rows[i].Wide;
            int Count = (int)wcslen(Rows[i].Units);

            /* the Unicode window is served with the Unicode function, the ANSI window with the ANSI one */
            if (!TypeUnits(Windows[k], k == 1, Rows[i].Units))
            {
                skip("SendInput failed, error %lu\n", GetLastError());
                return;
            }
            ok(g_UnitCount == Count, "%s, %s window: %d messages, expected %d\n", Rows[i].Name, k ? "ANSI" : "Unicode", g_UnitCount, Count);
            for (j = 0; j < (UINT)Count && j < (UINT)g_UnitCount; j++)
                ok(g_UnitLog[j] == Expected[j], "%s, %s window, unit %u: got %x, expected %x\n", Rows[i].Name, k ? "ANSI" : "Unicode", j, g_UnitLog[j], Expected[j]);
        }
    }
}

START_TEST(WmCharAnsi)
{
    WNDCLASSW ClassW;
    WNDCLASSA ClassA;
    HWND Wide, Ansi;
    HINSTANCE Instance = GetModuleHandleW(NULL);

    if (GetACP() != TEST_ACP)
    {
        skip("the rows are for code page %d, the process uses %u\n", TEST_ACP, GetACP());
        return;
    }

    ZeroMemory(&ClassW, sizeof(ClassW));
    ClassW.lpfnWndProc = WndProcW;
    ClassW.hInstance = Instance;
    ClassW.lpszClassName = L"WmCharAnsiW";
    ZeroMemory(&ClassA, sizeof(ClassA));
    ClassA.lpfnWndProc = WndProcA;
    ClassA.hInstance = Instance;
    ClassA.lpszClassName = "WmCharAnsiA";
    ok(RegisterClassW(&ClassW) != 0, "RegisterClassW: %lu\n", GetLastError());
    ok(RegisterClassA(&ClassA) != 0, "RegisterClassA: %lu\n", GetLastError());
    Wide = CreateWindowW(L"WmCharAnsiW", L"w", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 10, 10, 200, 100, NULL, NULL, Instance, NULL);
    Ansi = CreateWindowA("WmCharAnsiA", "a", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 230, 10, 200, 100, NULL, NULL, Instance, NULL);
    ok(Wide && Ansi, "windows %p %p\n", Wide, Ansi);
    if (Wide && Ansi)
    {
        ok(IsWindowUnicode(Wide) && !IsWindowUnicode(Ansi), "window kinds\n");
        TestRetrieval(Wide, Ansi);
        TestDispatch(Wide, Ansi);
        TestSendInput(Wide, Ansi);
    }
    if (Wide)
        DestroyWindow(Wide);
    if (Ansi)
        DestroyWindow(Ansi);
    UnregisterClassW(L"WmCharAnsiW", Instance);
    UnregisterClassA("WmCharAnsiA", Instance);
}
