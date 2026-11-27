/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The wallpaper bitmaps are freed when the wallpaper changes and when the per-user values are reloaded
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <winreg.h>

/* SystemPoolTagInformation (22): one entry per pool tag */
typedef struct
{
    ULONG Tag;
    ULONG PagedAllocs;
    ULONG PagedFrees;
    SIZE_T PagedUsed;
    ULONG NonPagedAllocs;
    ULONG NonPagedFrees;
    SIZE_T NonPagedUsed;
} WPT_POOLTAG;

typedef LONG (NTAPI *PNTQSI)(ULONG, PVOID, ULONG, PULONG);
typedef BOOL (WINAPI *PUPDATEPERUSER)(DWORD, BOOL);

/* Bytes of the surfaces (pool tag Gh05) in use, -1 if the pool tags cannot be read */
static LONGLONG SurfaceBytes(PNTQSI pNtQuerySystemInformation)
{
    ULONG size = 1 << 20, ret = 0, n, i;
    BYTE *buf = HeapAlloc(GetProcessHeap(), 0, size);
    LONGLONG bytes = -1;

    if (!buf)
        return -1;
    if (pNtQuerySystemInformation(22, buf, size, &ret) >= 0)
    {
        WPT_POOLTAG *t = (WPT_POOLTAG *)(buf + sizeof(ULONG_PTR));
        n = *(ULONG *)buf;
        for (i = 0; i < n; i++)
        {
            if (t[i].Tag == '50hG')
            {
                bytes = (LONGLONG)t[i].PagedUsed + (LONGLONG)t[i].NonPagedUsed;
                break;
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, buf);
    return bytes;
}

/* A 24 bpp picture of cx x cy, 1 MB or more as a surface of the screen's format */
static BOOL MakeBmp(const WCHAR *path, LONG cx, LONG cy)
{
    BITMAPFILEHEADER bf = { 0x4D42 };
    BITMAPINFOHEADER bi = { sizeof(bi), cx, cy, 1, 24, BI_RGB };
    DWORD stride = ((cx * 3) + 3) & ~3, n;
    BYTE *row;
    HANDLE h;
    LONG y;

    row = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, stride);
    if (!row)
        return FALSE;
    h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
    {
        HeapFree(GetProcessHeap(), 0, row);
        return FALSE;
    }
    bf.bfOffBits = sizeof(bf) + sizeof(bi);
    bf.bfSize = bf.bfOffBits + stride * cy;
    WriteFile(h, &bf, sizeof(bf), &n, NULL);
    WriteFile(h, &bi, sizeof(bi), &n, NULL);
    for (y = 0; y < cy; y++)
    {
        memset(row, (BYTE)y, stride);
        WriteFile(h, row, stride, &n, NULL);
    }
    CloseHandle(h);
    HeapFree(GetProcessHeap(), 0, row);
    return TRUE;
}

static BOOL ReadDesktopValue(HKEY key, const WCHAR *name, WCHAR *value, DWORD cb, BOOL *present)
{
    DWORD type;
    *present = (RegQueryValueExW(key, name, NULL, &type, (BYTE *)value, &cb) == ERROR_SUCCESS && type == REG_SZ);
    return TRUE;
}

static void RestoreDesktopValue(HKEY key, const WCHAR *name, const WCHAR *value, BOOL present)
{
    if (present)
        RegSetValueExW(key, name, 0, REG_SZ, (const BYTE *)value, (DWORD)(wcslen(value) + 1) * sizeof(WCHAR));
    else
        RegDeleteValueW(key, name);
}

START_TEST(WallpaperBitmaps)
{
    WCHAR file[MAX_PATH], old[MAX_PATH] = L"", oldStyle[16] = L"", oldTile[16] = L"";
    BOOL hadStyle, hadTile;
    PNTQSI pNtQuerySystemInformation;
    PUPDATEPERUSER pUpdatePerUserSystemParameters;
    LONGLONG start, after, cost;
    HKEY key;
    int i;

    pNtQuerySystemInformation = (PNTQSI)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    pUpdatePerUserSystemParameters = (PUPDATEPERUSER)GetProcAddress(GetModuleHandleW(L"user32.dll"), "UpdatePerUserSystemParameters");
    if (!pNtQuerySystemInformation || SurfaceBytes(pNtQuerySystemInformation) < 0)
    {
        skip("the pool tags cannot be read\n");
        return;
    }
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Control Panel\\Desktop", 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &key))
    {
        skip("cannot open the desktop settings\n");
        return;
    }

    GetTempPathW(MAX_PATH, file);
    wcscat(file, L"wpbitmaps.bmp");
    if (!MakeBmp(file, 640, 480))
    {
        skip("cannot make the picture, error %lu\n", GetLastError());
        RegCloseKey(key);
        return;
    }

    SystemParametersInfoW(SPI_GETDESKWALLPAPER, MAX_PATH, old, 0);
    ReadDesktopValue(key, L"WallpaperStyle", oldStyle, sizeof(oldStyle), &hadStyle);
    ReadDesktopValue(key, L"TileWallpaper", oldTile, sizeof(oldTile), &hadTile);

    /* Stretched: the picture is loaded, then copied at the size of the screen */
    RegSetValueExW(key, L"WallpaperStyle", 0, REG_SZ, (const BYTE *)L"2", 2 * sizeof(WCHAR));
    RegSetValueExW(key, L"TileWallpaper", 0, REG_SZ, (const BYTE *)L"0", 2 * sizeof(WCHAR));

    ok(SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, file, 0), "SPI_SETDESKWALLPAPER failed, error %lu\n", GetLastError());
    Sleep(200);
    start = SurfaceBytes(pNtQuerySystemInformation);

    /* Each change frees the picture it loaded and the copy of the previous wallpaper */
    for (i = 0; i < 10; i++)
        SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, file, 0);
    Sleep(200);
    after = SurfaceBytes(pNtQuerySystemInformation);
    cost = after - start;
    ok(cost < 1024 * 1024, "10 wallpaper changes left %I64d bytes of surfaces\n", cost);

    /* Reloading the per-user values (at every logon and logoff) drops the wallpaper: its bitmap goes with it */
    if (pUpdatePerUserSystemParameters)
    {
        start = after;
        for (i = 0; i < 5; i++)
        {
            pUpdatePerUserSystemParameters(0, TRUE);
            SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, file, 0);
        }
        Sleep(200);
        after = SurfaceBytes(pNtQuerySystemInformation);
        cost = after - start;
        ok(cost < 1024 * 1024, "5 reloads of the per-user values left %I64d bytes of surfaces\n", cost);
    }
    else
    {
        skip("no UpdatePerUserSystemParameters\n");
    }

    RestoreDesktopValue(key, L"WallpaperStyle", oldStyle, hadStyle);
    RestoreDesktopValue(key, L"TileWallpaper", oldTile, hadTile);
    RegCloseKey(key);
    SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, old, 0);
    DeleteFileW(file);
}
