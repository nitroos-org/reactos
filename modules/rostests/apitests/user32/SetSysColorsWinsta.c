/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     SetSysColors needs WINSTA_WRITEATTRIBUTES on the window station of the process
 *              (Windows: ERROR_ACCESS_DENIED for a handle without it; measured on Windows Server 2022)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

static BOOL SetCurrentColor(DWORD *pError)
{
    INT Index = COLOR_BACKGROUND;
    COLORREF Color = GetSysColor(COLOR_BACKGROUND); /* the value it has: nothing changes */
    BOOL Ret;

    SetLastError(0xDEADBEEF);
    Ret = SetSysColors(1, &Index, &Color);
    *pError = GetLastError();
    return Ret;
}

START_TEST(SetSysColorsWinsta)
{
    static const struct { DWORD Access; BOOL Allowed; } Rows[] =
    {
        { WINSTA_WRITEATTRIBUTES, TRUE },
        { WINSTA_READATTRIBUTES | WINSTA_WRITEATTRIBUTES, TRUE },
        { WINSTA_READATTRIBUTES, FALSE },
        { WINSTA_ENUMDESKTOPS, FALSE },
        { WINSTA_ACCESSCLIPBOARD, FALSE },
        { WINSTA_EXITWINDOWS, FALSE },
        { WINSTA_ENUMERATE, FALSE },
    };
    HWINSTA hOld = GetProcessWindowStation();
    WCHAR Name[64];
    DWORD Len, Error;
    BOOL Ret;
    size_t i;

    Name[0] = 0;
    if (!GetUserObjectInformationW(hOld, UOI_NAME, Name, sizeof(Name), &Len) || _wcsicmp(Name, L"WinSta0"))
    {
        skip("not running on the interactive window station (%ls)\n", Name);
        return;
    }

    Ret = SetCurrentColor(&Error);
    ok(Ret, "SetSysColors with the process window station failed, error %lu\n", Error);

    for (i = 0; i < ARRAYSIZE(Rows); i++)
    {
        HWINSTA hWinSta = OpenWindowStationW(L"WinSta0", FALSE, Rows[i].Access);

        if (!hWinSta)
        {
            skip("OpenWindowStation(0x%lx) failed, error %lu\n", Rows[i].Access, GetLastError());
            continue;
        }
        if (!SetProcessWindowStation(hWinSta))
        {
            skip("SetProcessWindowStation(0x%lx) failed, error %lu\n", Rows[i].Access, GetLastError());
            CloseWindowStation(hWinSta);
            continue;
        }

        Ret = SetCurrentColor(&Error);
        ok(Ret == Rows[i].Allowed, "access 0x%lx: SetSysColors returned %d, expected %d\n", Rows[i].Access, Ret, Rows[i].Allowed);
        if (!Rows[i].Allowed)
            ok(Error == ERROR_ACCESS_DENIED, "access 0x%lx: error %lu, expected %d\n", Rows[i].Access, Error, ERROR_ACCESS_DENIED);

        SetProcessWindowStation(hOld);
        CloseWindowStation(hWinSta);
    }
}
