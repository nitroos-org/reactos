/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for D3DKMTCheckOcclusion without a display miniport (basic render)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Expected answers were measured on Windows 10 22H2 in an interactive session: the result depends only
 * on whether the handle names a window. The same executable runs on Windows and on ReactOS.
 */

#include "precomp.h"

#include <ntstatus.h>
#include <d3dkmthk.h>

typedef NTSTATUS (APIENTRY *PFN_CHECKOCCLUSION)(const D3DKMT_CHECKOCCLUSION *);

static PFN_CHECKOCCLUSION pCheckOcclusion;

static NTSTATUS Check(HWND hWnd)
{
    D3DKMT_CHECKOCCLUSION Desc;

    Desc.hWindow = hWnd;
    return pCheckOcclusion(&Desc);
}

START_TEST(D3DKMTCheckOcclusion)
{
    HMODULE hMod = GetModuleHandleW(L"gdi32.dll");
    HWND hWnd, hCover, hChild;
    D3DKMT_CHECKOCCLUSION Desc;
    NTSTATUS Status;

    pCheckOcclusion = (PFN_CHECKOCCLUSION)GetProcAddress(hMod, "D3DKMTCheckOcclusion");
    if (!pCheckOcclusion)
    {
        /* ReactOS NT 5.x builds export it from gdi32_vista */
        hMod = LoadLibraryW(L"gdi32_vista.dll");
        if (hMod)
            pCheckOcclusion = (PFN_CHECKOCCLUSION)GetProcAddress(hMod, "D3DKMTCheckOcclusion");
    }
    if (!pCheckOcclusion)
    {
        skip("D3DKMTCheckOcclusion is not available\n");
        return;
    }

    /* Null structure and null handle */
    Status = pCheckOcclusion(NULL);
    ok(Status == STATUS_INVALID_PARAMETER, "NULL structure: got 0x%lx\n", Status);
    Status = Check(NULL);
    ok(Status == STATUS_INVALID_PARAMETER, "NULL handle: got 0x%lx\n", Status);

    /* A handle that names no window is reported as occluded */
    Status = Check((HWND)(ULONG_PTR)0x12345);
    ok(Status == STATUS_GRAPHICS_PRESENT_OCCLUDED, "Bogus handle: got 0x%lx\n", Status);

    Status = Check(GetDesktopWindow());
    ok(Status == STATUS_SUCCESS, "Desktop window: got 0x%lx\n", Status);

    hWnd = CreateWindowA("static", "occ1", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 0, 0, 200, 200, NULL, NULL, NULL, NULL);
    if (!hWnd)
    {
        skip("Could not create a window\n");
        return;
    }

    Status = Check(hWnd);
    ok(Status == STATUS_SUCCESS, "Visible window: got 0x%lx\n", Status);

    /* The structure is input only */
    memset(&Desc, 0xCC, sizeof(Desc));
    Desc.hWindow = hWnd;
    Status = pCheckOcclusion(&Desc);
    ok(Status == STATUS_SUCCESS, "Visible window: got 0x%lx\n", Status);
    ok(Desc.hWindow == hWnd, "hWindow changed to %p\n", Desc.hWindow);

    /* A minimized window is not reported as occluded */
    ShowWindow(hWnd, SW_MINIMIZE);
    Status = Check(hWnd);
    ok(Status == STATUS_SUCCESS, "Minimized window: got 0x%lx\n", Status);
    Sleep(500);
    Status = Check(hWnd);
    ok(Status == STATUS_SUCCESS, "Minimized window, later: got 0x%lx\n", Status);
    ShowWindow(hWnd, SW_SHOWNORMAL);
    Status = Check(hWnd);
    ok(Status == STATUS_SUCCESS, "Restored window: got 0x%lx\n", Status);

    /* Neither is a hidden one */
    ShowWindow(hWnd, SW_HIDE);
    Status = Check(hWnd);
    ok(Status == STATUS_SUCCESS, "Hidden window: got 0x%lx\n", Status);
    ShowWindow(hWnd, SW_SHOW);

    /* Nor one that another window covers */
    hCover = CreateWindowA("static", "occ2", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 50, 50, 400, 400, NULL, NULL, NULL, NULL);
    if (hCover)
    {
        Status = Check(hWnd);
        ok(Status == STATUS_SUCCESS, "Covered window: got 0x%lx\n", Status);
        Status = Check(hCover);
        ok(Status == STATUS_SUCCESS, "Covering window: got 0x%lx\n", Status);
    }

    hChild = CreateWindowA("static", "occ3", WS_CHILD | WS_VISIBLE, 0, 0, 50, 50, hWnd, NULL, NULL, NULL);
    if (hChild)
    {
        Status = Check(hChild);
        ok(Status == STATUS_SUCCESS, "Child window: got 0x%lx\n", Status);
    }

    /* A destroyed window is gone */
    if (hCover)
    {
        DestroyWindow(hCover);
        Status = Check(hCover);
        ok(Status == STATUS_GRAPHICS_PRESENT_OCCLUDED, "Destroyed window: got 0x%lx\n", Status);
    }

    DestroyWindow(hWnd);
}
