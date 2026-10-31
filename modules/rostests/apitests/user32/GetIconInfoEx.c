/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for GetIconInfoExA and GetIconInfoExW
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The results were measured on Windows 10 22H2 (x64 and x86). On x64 the ANSI version cuts the module
 * name after its first character (a defect that x86 does not have); only the first character and what follows
 * the second are compared here.
 */

#include "precomp.h"
#include <winnls.h>

typedef struct
{
    DWORD cbSize;
    BOOL fIcon;
    DWORD xHotspot;
    DWORD yHotspot;
    HBITMAP hbmMask;
    HBITMAP hbmColor;
    WORD wResID;
    WCHAR szModName[MAX_PATH];
    WCHAR szResName[MAX_PATH];
} ICONINFOEX_W;

typedef struct
{
    DWORD cbSize;
    BOOL fIcon;
    DWORD xHotspot;
    DWORD yHotspot;
    HBITMAP hbmMask;
    HBITMAP hbmColor;
    WORD wResID;
    CHAR szModName[MAX_PATH];
    CHAR szResName[MAX_PATH];
} ICONINFOEX_A;

typedef BOOL (WINAPI *PFN_GetIconInfoExW)(HICON, ICONINFOEX_W *);
typedef BOOL (WINAPI *PFN_GetIconInfoExA)(HICON, ICONINFOEX_A *);

#define PENDING_ERROR 0xdeadbeef
#ifndef ERROR_INVALID_CURSOR_HANDLE
#define ERROR_INVALID_CURSOR_HANDLE 1402
#endif

static PFN_GetIconInfoExW pGetIconInfoExW;
static PFN_GetIconInfoExA pGetIconInfoExA;
/* the system cursors of ReactOS are monochrome */
static BOOL g_RequireColor = TRUE;

static void
CheckInfo(const char *Label, HICON Icon, BOOL IsIcon, WORD ResId, PCWSTR ResName, PCWSTR ModName)
{
    ICONINFOEX_W Info;
    ICONINFOEX_A InfoA;
    ICONINFO Plain;
    CHAR Expected[MAX_PATH];
    BOOL Result;
    DWORD Error;

    ok(Icon != NULL, "%s: no icon\n", Label);
    if (!Icon)
        return;

    FillMemory(&Info, sizeof(Info), 0xAA);
    Info.cbSize = sizeof(Info);
    SetLastError(PENDING_ERROR);
    Result = pGetIconInfoExW(Icon, &Info);
    Error = GetLastError();
    ok(Result == TRUE, "%s: GetIconInfoExW failed, error %lu\n", Label, Error);
    ok(Error == PENDING_ERROR, "%s: last error became %lu\n", Label, Error);
    if (!Result)
        return;

    ok(Info.cbSize == sizeof(Info), "%s: cbSize became %lu\n", Label, Info.cbSize);
    ok(Info.fIcon == IsIcon, "%s: fIcon is %d\n", Label, Info.fIcon);
    ok(Info.hbmMask != NULL, "%s: no mask\n", Label);
    ok(Info.hbmColor != NULL || !g_RequireColor, "%s: no color bitmap\n", Label);
    ok(Info.wResID == ResId, "%s: wResID is %u, expected %u\n", Label, Info.wResID, ResId);
    ok(wcscmp(Info.szResName, ResName) == 0, "%s: szResName is '%ls', expected '%ls'\n", Label, Info.szResName, ResName);
    ok(wcscmp(Info.szModName, ModName) == 0, "%s: szModName is '%ls', expected '%ls'\n", Label, Info.szModName, ModName);

    /* the same icon through GetIconInfo */
    ZeroMemory(&Plain, sizeof(Plain));
    ok(GetIconInfo(Icon, &Plain), "%s: GetIconInfo failed\n", Label);
    ok(Plain.xHotspot == Info.xHotspot && Plain.yHotspot == Info.yHotspot,
       "%s: hotspot %lu,%lu, GetIconInfo %lu,%lu\n", Label, Info.xHotspot, Info.yHotspot, Plain.xHotspot, Plain.yHotspot);
    if (Plain.hbmMask)
        DeleteObject(Plain.hbmMask);
    if (Plain.hbmColor)
        DeleteObject(Plain.hbmColor);
    if (Info.hbmMask)
        DeleteObject(Info.hbmMask);
    if (Info.hbmColor)
        DeleteObject(Info.hbmColor);

    /* the ANSI version */
    FillMemory(&InfoA, sizeof(InfoA), 0xAA);
    InfoA.cbSize = sizeof(InfoA);
    SetLastError(PENDING_ERROR);
    Result = pGetIconInfoExA(Icon, &InfoA);
    ok(Result == TRUE, "%s: GetIconInfoExA failed, error %lu\n", Label, GetLastError());
    if (!Result)
        return;
    ok(GetLastError() == PENDING_ERROR, "%s: ANSI last error became %lu\n", Label, GetLastError());
    ok(InfoA.fIcon == IsIcon && InfoA.wResID == ResId, "%s: ANSI fIcon %d, wResID %u\n", Label, InfoA.fIcon, InfoA.wResID);
    WideCharToMultiByte(CP_ACP, 0, ResName, -1, Expected, sizeof(Expected), NULL, NULL);
    ok(strcmp(InfoA.szResName, Expected) == 0, "%s: ANSI szResName is '%s', expected '%s'\n", Label, InfoA.szResName, Expected);
    WideCharToMultiByte(CP_ACP, 0, ModName, -1, Expected, sizeof(Expected), NULL, NULL);
    ok(InfoA.szModName[0] == Expected[0], "%s: ANSI szModName starts with '%c', expected '%c'\n", Label, InfoA.szModName[0], Expected[0]);
    if (Expected[0] && Expected[1])
        ok(strcmp(InfoA.szModName + 2, Expected + 2) == 0, "%s: ANSI szModName is '%s', expected '%s'\n", Label, InfoA.szModName, Expected);
    if (InfoA.hbmMask)
        DeleteObject(InfoA.hbmMask);
    if (InfoA.hbmColor)
        DeleteObject(InfoA.hbmColor);
}

START_TEST(GetIconInfoEx)
{
    HMODULE User32 = GetModuleHandleW(L"user32.dll");
    HINSTANCE Instance = GetModuleHandleW(NULL);
    WCHAR Exe[MAX_PATH];
    ICONINFOEX_W Info;
    ICONINFO Plain;
    HICON Icon, Copy;
    HBITMAP Mask;
    BOOL Result;
    DWORD Error;
    ULONG i;
    static const DWORD BadSizes[] = { 0, sizeof(Info) - 1, sizeof(Info) + 1, sizeof(ICONINFO), sizeof(Info) + 8 };

    pGetIconInfoExW = (PFN_GetIconInfoExW)GetProcAddress(User32, "GetIconInfoExW");
    pGetIconInfoExA = (PFN_GetIconInfoExA)GetProcAddress(User32, "GetIconInfoExA");
    if (!pGetIconInfoExW || !pGetIconInfoExA)
    {
        skip("GetIconInfoEx is not exported\n");
        return;
    }

    GetSystemMetrics(SM_CXSCREEN);
    GetModuleFileNameW(NULL, Exe, MAX_PATH);

    /* handle and size checks */
    FillMemory(&Info, sizeof(Info), 0xAA);
    Info.cbSize = sizeof(Info);
    SetLastError(PENDING_ERROR);
    Result = pGetIconInfoExW(NULL, &Info);
    Error = GetLastError();
    ok(Result == FALSE, "GetIconInfoExW(NULL) succeeded\n");
    ok(Error == ERROR_INVALID_CURSOR_HANDLE, "GetIconInfoExW(NULL): last error %lu\n", Error);
    SetLastError(PENDING_ERROR);
    Result = pGetIconInfoExW((HICON)(ULONG_PTR)0x1234, &Info);
    Error = GetLastError();
    ok(Result == FALSE, "GetIconInfoExW(bad handle) succeeded\n");
    ok(Error == ERROR_INVALID_CURSOR_HANDLE, "GetIconInfoExW(bad handle): last error %lu\n", Error);

    Icon = LoadIconW(Instance, MAKEINTRESOURCEW(IDI_TEST));
    ok(Icon != NULL, "LoadIcon failed\n");
    for (i = 0; Icon && i < sizeof(BadSizes) / sizeof(BadSizes[0]); i++)
    {
        FillMemory(&Info, sizeof(Info), 0xAA);
        Info.cbSize = BadSizes[i];
        SetLastError(PENDING_ERROR);
        Result = pGetIconInfoExW(Icon, &Info);
        Error = GetLastError();
        ok(Result == FALSE, "GetIconInfoExW with cbSize %lu succeeded\n", BadSizes[i]);
        ok(Error == ERROR_INVALID_PARAMETER, "GetIconInfoExW with cbSize %lu: last error %lu\n", BadSizes[i], Error);
        ok(Info.hbmMask == (HBITMAP)(ULONG_PTR)(sizeof(void *) == 8 ? 0xAAAAAAAAAAAAAAAAULL : 0xAAAAAAAAUL),
           "cbSize %lu: the structure was written\n", BadSizes[i]);
    }

    /* icons and cursors that come from a resource of this module */
    CheckInfo("icon by id", Icon, TRUE, IDI_TEST, L"", Exe);
    CheckInfo("icon by name", LoadIconW(Instance, L"TESTICON"), TRUE, 0, L"TESTICON", Exe);
    CheckInfo("16x16 icon by id", LoadImageW(Instance, MAKEINTRESOURCEW(IDI_TEST), IMAGE_ICON, 16, 16, 0), TRUE, IDI_TEST, L"", Exe);
    CheckInfo("shared icon by id", LoadImageW(Instance, MAKEINTRESOURCEW(IDI_TEST), IMAGE_ICON, 0, 0, LR_SHARED | LR_DEFAULTSIZE),
              TRUE, IDI_TEST, L"", Exe);
    CheckInfo("cursor by name", LoadCursorW(Instance, L"TESTCURSOR"), FALSE, 0, L"TESTCURSOR", Exe);
    CheckInfo("cursor by id", LoadCursorW(Instance, MAKEINTRESOURCEW(IDC_TEST)), FALSE, IDC_TEST, L"", Exe);

    /* icons and cursors of the system belong to user32 */
    g_RequireColor = !is_reactos();
    CheckInfo("system cursor", LoadCursorW(NULL, MAKEINTRESOURCEW(OCR_NORMAL)), FALSE, OCR_NORMAL, L"", L"USER32");
    g_RequireColor = TRUE;
    CheckInfo("system icon", LoadIconW(NULL, MAKEINTRESOURCEW(OIC_ERROR)), TRUE, OIC_ERROR, L"", L"USER32");

    /* icons that have no resource: nothing to report */
    Mask = CreateBitmap(16, 16, 1, 1, NULL);
    ZeroMemory(&Plain, sizeof(Plain));
    Plain.fIcon = TRUE;
    Plain.xHotspot = 3;
    Plain.yHotspot = 4;
    Plain.hbmMask = Mask;
    Copy = CreateIconIndirect(&Plain);
    ok(Copy != NULL, "CreateIconIndirect failed\n");
    if (Copy)
    {
        FillMemory(&Info, sizeof(Info), 0xAA);
        Info.cbSize = sizeof(Info);
        Result = pGetIconInfoExW(Copy, &Info);
        ok(Result == TRUE, "GetIconInfoExW of a made icon failed\n");
        if (Result)
        {
            ok(Info.fIcon == TRUE, "fIcon is %d\n", Info.fIcon);
            ok(Info.hbmMask != NULL, "no mask\n");
            ok(Info.hbmColor == NULL, "a monochrome icon has a color bitmap\n");
            ok(Info.wResID == 0, "wResID is %u\n", Info.wResID);
            ok(Info.szModName[0] == 0, "szModName is '%ls'\n", Info.szModName);
            ok(Info.szResName[0] == 0, "szResName is '%ls'\n", Info.szResName);
            if (Info.hbmMask)
                DeleteObject(Info.hbmMask);
        }
        DestroyIcon(Copy);
    }
    DeleteObject(Mask);

    if (Icon)
    {
        Copy = CopyIcon(Icon);
        ok(Copy != NULL, "CopyIcon failed\n");
        if (Copy)
        {
            FillMemory(&Info, sizeof(Info), 0xAA);
            Info.cbSize = sizeof(Info);
            Result = pGetIconInfoExW(Copy, &Info);
            ok(Result == TRUE, "GetIconInfoExW of a copied icon failed\n");
            if (Result)
            {
                ok(Info.wResID == 0, "copied: wResID is %u\n", Info.wResID);
                ok(Info.szModName[0] == 0, "copied: szModName is '%ls'\n", Info.szModName);
                ok(Info.szResName[0] == 0, "copied: szResName is '%ls'\n", Info.szResName);
                if (Info.hbmMask)
                    DeleteObject(Info.hbmMask);
                if (Info.hbmColor)
                    DeleteObject(Info.hbmColor);
            }
            DestroyIcon(Copy);
        }
    }
}
