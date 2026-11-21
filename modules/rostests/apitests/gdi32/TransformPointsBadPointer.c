/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     LPtoDP / DPtoLP with a pointer that is NULL or cannot be read or written: a DC whose
 *              transform is the identity answers TRUE without looking at the pointer, every other DC
 *              fails the call (FALSE, no last error); results measured on Windows Server 2022
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#define BAD_POINTER ((POINT *)(ULONG_PTR)1)

typedef struct
{
    int State;
    BOOL Expected; /* result with a pointer that cannot be used (Windows) */
} ROW;

static HDC MakeDC(int State)
{
    HDC hDC = CreateCompatibleDC(NULL);
    XFORM Xform = { 1, 0, 0, 1, 5, 0 }, Identity = { 1, 0, 0, 1, 0, 0 };

    switch (State)
    {
        case 0: break;                                                      /* MM_TEXT, nothing set */
        case 1: SetViewportOrgEx(hDC, 7, 9, NULL); break;
        case 2: SetWindowOrgEx(hDC, 7, 9, NULL); break;
        case 3: SetMapMode(hDC, MM_ANISOTROPIC); SetWindowExtEx(hDC, 100, 100, NULL); SetViewportExtEx(hDC, 100, 100, NULL); break;
        case 4: SetMapMode(hDC, MM_LOMETRIC); break;
        case 5: SetGraphicsMode(hDC, GM_ADVANCED); ModifyWorldTransform(hDC, NULL, MWT_IDENTITY); break;
        case 6: SetGraphicsMode(hDC, GM_ADVANCED); SetWorldTransform(hDC, &Xform); break;
        case 7: SetMapMode(hDC, MM_ANISOTROPIC); SetWindowExtEx(hDC, 100, 100, NULL); SetViewportExtEx(hDC, 200, 300, NULL); SetViewportOrgEx(hDC, 7, 9, NULL); break;
        case 8: SetMapMode(hDC, MM_ISOTROPIC); break;
        case 9: SetMapMode(hDC, MM_ANISOTROPIC); break;
        case 10: SetGraphicsMode(hDC, GM_ADVANCED); break;
        case 11: SetMapMode(hDC, MM_ANISOTROPIC); SetWindowExtEx(hDC, 1, 1, NULL); SetViewportExtEx(hDC, 1, 1, NULL); break;
        case 12: SetViewportOrgEx(hDC, 0, 0, NULL); break;
        case 14: SetGraphicsMode(hDC, GM_ADVANCED); SetWorldTransform(hDC, &Identity); break;
        case 15: SetWindowOrgEx(hDC, 0, 0, NULL); break;
        case 16: SetMapMode(hDC, MM_ANISOTROPIC); SetWindowExtEx(hDC, 1, 1, NULL); break;
        case 17: SetMapMode(hDC, MM_ISOTROPIC); SetWindowExtEx(hDC, 1, 1, NULL); SetViewportExtEx(hDC, 1, 1, NULL); break;
        case 18: SetWindowExtEx(hDC, 1, 1, NULL); SetViewportExtEx(hDC, 1, 1, NULL); break;
    }
    return hDC;
}

START_TEST(TransformPointsBadPointer)
{
    /* States 13 (MM_ANISOTROPIC, then MM_TEXT again) and 19 (as 11, then MM_TEXT) are FALSE on Windows although the
     * transform is the identity again: they depend on history that is not modelled here and are left out. */
    static const ROW Rows[] =
    {
        { 0, TRUE }, { 1, FALSE }, { 2, FALSE }, { 3, FALSE }, { 4, FALSE }, { 5, TRUE }, { 6, FALSE }, { 7, FALSE },
        { 8, FALSE }, { 9, TRUE }, { 10, TRUE }, { 11, TRUE }, { 12, TRUE }, { 14, TRUE }, { 15, TRUE }, { 16, TRUE },
        { 17, FALSE }, { 18, TRUE },
    };
    SYSTEM_INFO si;
    POINT *Page;
    DWORD OldProt;
    size_t i;

    GetSystemInfo(&si);

    for (i = 0; i < _countof(Rows); i++)
    {
        HDC hDC = MakeDC(Rows[i].State);
        BOOL Ret;

        SetLastError(0xDEADBEEF);
        Ret = LPtoDP(hDC, BAD_POINTER, 2);
        ok(Ret == Rows[i].Expected, "state %d: LPtoDP(bad pointer) = %d, expected %d\n", Rows[i].State, Ret, Rows[i].Expected);
        ok_err(0xDEADBEEF);

        SetLastError(0xDEADBEEF);
        Ret = DPtoLP(hDC, BAD_POINTER, 2);
        ok(Ret == Rows[i].Expected, "state %d: DPtoLP(bad pointer) = %d, expected %d\n", Rows[i].State, Ret, Rows[i].Expected);
        ok_err(0xDEADBEEF);

        SetLastError(0xDEADBEEF);
        Ret = LPtoDP(hDC, NULL, 2);
        ok(Ret == Rows[i].Expected, "state %d: LPtoDP(NULL, 2) = %d, expected %d\n", Rows[i].State, Ret, Rows[i].Expected);

        SetLastError(0xDEADBEEF);
        Ret = DPtoLP(hDC, NULL, 2);
        ok(Ret == Rows[i].Expected, "state %d: DPtoLP(NULL, 2) = %d, expected %d\n", Rows[i].State, Ret, Rows[i].Expected);

        /* a count that is not positive succeeds whatever the pointer is */
        ok_int(LPtoDP(hDC, NULL, 0), TRUE);
        ok_int(LPtoDP(hDC, BAD_POINTER, -1), TRUE);
        ok_int(DPtoLP(hDC, NULL, 0), TRUE);
        ok_int(DPtoLP(hDC, BAD_POINTER, -1), TRUE);

        /* a page that is read only, and a buffer that runs into a page that is not committed */
        Page = VirtualAlloc(NULL, 2 * si.dwPageSize, MEM_RESERVE, PAGE_NOACCESS);
        if (Page && VirtualAlloc(Page, si.dwPageSize, MEM_COMMIT, PAGE_READWRITE))
        {
            POINT *Last = (POINT *)((BYTE *)Page + si.dwPageSize - sizeof(POINT));

            Last->x = 10;
            Last->y = 20;
            Ret = LPtoDP(hDC, Last, 2);
            ok(Ret == Rows[i].Expected, "state %d: LPtoDP(buffer into a reserved page) = %d, expected %d\n", Rows[i].State, Ret, Rows[i].Expected);
            ok((Last->x == 10 && Last->y == 20) || Rows[i].Expected, "state %d: first point was written (%ld,%ld)\n", Rows[i].State, Last->x, Last->y);

            VirtualProtect(Page, si.dwPageSize, PAGE_READONLY, &OldProt);
            Ret = LPtoDP(hDC, Page, 2);
            ok(Ret == Rows[i].Expected, "state %d: LPtoDP(read only page) = %d, expected %d\n", Rows[i].State, Ret, Rows[i].Expected);
        }
        if (Page)
            VirtualFree(Page, 0, MEM_RELEASE);

        DeleteDC(hDC);
    }
}
