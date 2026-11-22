/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     SPI_SETDESKWALLPAPER opens the file with the caller's rights
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <sddl.h>

static BOOL MakeBmp(const WCHAR *path)
{
    BITMAPFILEHEADER bf = { 0x4D42 };
    BITMAPINFOHEADER bi = { sizeof(bi), 8, 8, 1, 24, BI_RGB };
    BYTE row[24] = { 0 };
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD n;
    int y;

    if (h == INVALID_HANDLE_VALUE)
        return FALSE;
    bf.bfOffBits = sizeof(bf) + sizeof(bi);
    bf.bfSize = bf.bfOffBits + sizeof(row) * 8;
    WriteFile(h, &bf, sizeof(bf), &n, NULL);
    WriteFile(h, &bi, sizeof(bi), &n, NULL);
    for (y = 0; y < 8; y++)
        WriteFile(h, row, sizeof(row), &n, NULL);
    CloseHandle(h);
    return TRUE;
}

/* A token of the caller with Administrators deny-only, impersonated by this thread */
static BOOL ImpersonateWithoutAdmins(void)
{
    HANDLE token, restricted;
    BYTE sid[SECURITY_MAX_SID_SIZE];
    DWORD size = sizeof(sid);
    SID_AND_ATTRIBUTES sa;
    BOOL ret;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &token))
        return FALSE;
    CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, sid, &size);
    sa.Sid = sid;
    sa.Attributes = 0;
    ret = CreateRestrictedToken(token, 0, 1, &sa, 0, NULL, 0, NULL, &restricted);
    CloseHandle(token);
    if (!ret)
        return FALSE;
    ret = ImpersonateLoggedOnUser(restricted);
    CloseHandle(restricted);
    return ret;
}

START_TEST(WallpaperAccess)
{
    WCHAR dir[MAX_PATH], file[MAX_PATH], old[MAX_PATH] = L"";
    PSECURITY_DESCRIPTOR sd;
    HANDLE h;
    BOOL ret, canRead;

    GetTempPathW(MAX_PATH, dir);
    wcscat(dir, L"wpaccess");
    CreateDirectoryW(dir, NULL);
    wcscpy(file, dir);
    wcscat(file, L"\\secret.bmp");
    if (!MakeBmp(file))
    {
        skip("cannot make the file, error %lu\n", GetLastError());
        goto done;
    }

    /* Only SYSTEM and Administrators may read it (needs a file system with access lists) */
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;FA;;;SY)(A;;FA;;;BA)", SDDL_REVISION_1, &sd, NULL) ||
        !SetFileSecurityW(file, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, sd))
    {
        skip("no access list on this file system (error %lu)\n", GetLastError());
        goto done;
    }
    LocalFree(sd);

    SystemParametersInfoW(SPI_GETDESKWALLPAPER, MAX_PATH, old, 0);

    if (!ImpersonateWithoutAdmins())
    {
        skip("cannot impersonate a restricted token, error %lu\n", GetLastError());
        goto done;
    }
    h = CreateFileW(file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    canRead = (h != INVALID_HANDLE_VALUE);
    if (canRead)
        CloseHandle(h);
    if (canRead)
    {
        RevertToSelf();
        skip("the file is readable without Administrators\n");
        goto done;
    }

    /* Without Administrators in effect the file cannot be read, so it cannot be the wallpaper */
    SetLastError(0xdeadbeef);
    ret = SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, file, 0);
    ok(!ret, "SPI_SETDESKWALLPAPER of a file the caller cannot read succeeded\n");
    RevertToSelf();

    /* The same call with the rights restored works */
    ret = SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, file, 0);
    ok(ret, "SPI_SETDESKWALLPAPER of a readable file failed, error %lu\n", GetLastError());

    SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, old, 0);
done:
    SetFileAttributesW(file, FILE_ATTRIBUTE_NORMAL);
    DeleteFileW(file);
    RemoveDirectoryW(dir);
}
