/*
 * PROJECT:         ReactOS api tests
 * LICENSE:         LGPL-2.1+ (https://spdx.org/licenses/LGPL-2.1+)
 * PURPOSE:         Tests for visual style enumeration and activation
 */

#include <apitest.h>
#include <stdio.h>
#include <windows.h>
#include <uxtheme.h>
#include <uxundoc.h>
#include <shlwapi.h>

typedef struct _ENUM_CTX
{
    INT Count;
    INT BadName;
    INT MissingFile;
    WCHAR FirstFile[MAX_PATH];
} ENUM_CTX;

static BOOL CALLBACK
EnumProc(LPVOID Reserved, LPCWSTR pszFile, LPCWSTR pszName, LPCWSTR pszTip, LPVOID Reserved2, LPVOID Data)
{
    ENUM_CTX *ctx = Data;

    if (!pszName || !*pszName)
        ctx->BadName++;
    if (!pszFile || GetFileAttributesW(pszFile) == INVALID_FILE_ATTRIBUTES)
        ctx->MissingFile++;
    if (!ctx->Count && pszFile)
        lstrcpynW(ctx->FirstFile, pszFile, MAX_PATH);
    ctx->Count++;
    return TRUE;
}

START_TEST(VisualStyles)
{
    WCHAR szThemes[MAX_PATH], szLautus[MAX_PATH];
    WCHAR szOldFile[MAX_PATH], szOldColor[MAX_PATH], szOldSize[MAX_PATH];
    WCHAR szFile[MAX_PATH], szColor[MAX_PATH], szSize[MAX_PATH];
    ENUM_CTX ctx = { 0 };
    HRESULT hr;
    BOOL wasActive;
    HWND hwnd;
    MSG msg;
    INT i;

    GetWindowsDirectoryW(szThemes, _countof(szThemes));
    PathAppendW(szThemes, L"Resources\\Themes");
    lstrcpyW(szLautus, szThemes);
    PathAppendW(szLautus, L"Lautus\\lautus.msstyles");

    if (GetFileAttributesW(szLautus) == INVALID_FILE_ATTRIBUTES)
    {
        skip("%S is not installed\n", szLautus);
        return;
    }

    /* The theme hooks reach a process through its first window: create one and
       let the message loop run before the theme functions are used */
    hwnd = CreateWindowExA(0, "static", "", WS_POPUP, 0, 0, 10, 10, NULL, NULL, NULL, NULL);
    ok(hwnd != NULL, "CreateWindowEx failed\n");
    for (i = 0; i < 100; i++)
    {
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        Sleep(20);
    }

    /* The visual styles installed under Resources\Themes are enumerable */
    hr = EnumThemes(szThemes, EnumProc, &ctx);
    ok(hr == S_OK, "EnumThemes returned 0x%lx\n", hr);
    ok(ctx.Count >= 1, "EnumThemes found %d styles\n", ctx.Count);
    ok(ctx.BadName == 0, "%d styles without a display name\n", ctx.BadName);
    ok(ctx.MissingFile == 0, "%d styles reported with a missing file\n", ctx.MissingFile);

    /* A style file can be opened (the process has the theme hooks) */
    {
        HTHEMEFILE hFile = NULL;
        hr = OpenThemeFile(szLautus, NULL, NULL, &hFile, 0);
        ok(hr == S_OK, "OpenThemeFile returned 0x%lx\n", hr);
        if (hr == S_OK)
            CloseThemeFile(hFile);
    }

    /* Remember the current state to restore it at the end */
    wasActive = IsThemeActive();
    szOldFile[0] = szOldColor[0] = szOldSize[0] = 0;
    if (wasActive)
        GetCurrentThemeName(szOldFile, _countof(szOldFile), szOldColor, _countof(szOldColor),
                            szOldSize, _countof(szOldSize));

    /* Activate Lautus */
    hr = SetSystemVisualStyle(szLautus, NULL, NULL, 0);
    ok(hr == S_OK, "SetSystemVisualStyle(lautus) returned 0x%lx\n", hr);
    if (hr == S_OK)
    {
        ok(IsThemeActive(), "IsThemeActive is FALSE after activating a style\n");
        szFile[0] = 0;
        hr = GetCurrentThemeName(szFile, _countof(szFile), szColor, _countof(szColor), szSize, _countof(szSize));
        ok(hr == S_OK, "GetCurrentThemeName returned 0x%lx\n", hr);
        ok(!lstrcmpiW(szFile, szLautus), "Current theme is %S, expected %S\n", szFile, szLautus);
    }

    /* Back to the classic theme */
    hr = SetSystemVisualStyle(NULL, NULL, NULL, 0);
    ok(hr == S_OK, "SetSystemVisualStyle(NULL) returned 0x%lx\n", hr);
    ok(!IsThemeActive(), "IsThemeActive is TRUE after returning to the classic theme\n");

    /* Restore */
    if (wasActive && szOldFile[0])
        SetSystemVisualStyle(szOldFile, szOldColor, szOldSize, 0);

    if (hwnd)
        DestroyWindow(hwnd);
}
