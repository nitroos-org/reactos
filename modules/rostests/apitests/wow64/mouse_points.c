/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     mouse_points
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/* GetMouseMovePointsEx must neither read nor write the guest entries the
 * kernel did not fill. Run the same i386 executable as "mouse_points native"
 * on native i386 (the oracle) and as "mouse_points wow64" under WoW64. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

static unsigned Checks, Failures;
#define CHECK(x) do { ++Checks; if (!(x)) { ++Failures; printf("FAIL line %u: %s error=%lu\n", __LINE__, #x, GetLastError()); } } while (0)

#define POINTS 4
#define PATTERN 0xA5

static BOOL Untouched(const BYTE *Data, SIZE_T Size)
{
    SIZE_T i;
    for (i = 0; i < Size; ++i)
        if (Data[i] != PATTERN) return FALSE;
    return TRUE;
}

/* The first two entries end the first page; the rest start the second page,
 * which has the given protection during the call. */
static VOID Run(BYTE *Pages, SIZE_T Page, DWORD Protect, DWORD Resolution)
{
    MOUSEMOVEPOINT In = {0}, *Out = (MOUSEMOVEPOINT *)(Pages + Page - 2 * sizeof(MOUSEMOVEPOINT));
    MEMORY_BASIC_INFORMATION Tail;
    DWORD Old;
    int Ret;
    memset(Pages, PATTERN, 2 * Page);
    if (Protect != PAGE_READWRITE) CHECK(VirtualProtect(Pages + Page, Page, Protect, &Old));
    SetLastError(0xdeadbeef);
    Ret = GetMouseMovePointsEx(sizeof(MOUSEMOVEPOINT), &In, Out, POINTS, Resolution);
    /* Native probes only the first entry, so an access to the tail page shows
     * as a consumed guard before the protection is restored. */
    CHECK(VirtualQuery(Pages + Page, &Tail, sizeof(Tail)) == sizeof(Tail));
    CHECK(Tail.Protect == Protect);
    if (Protect != PAGE_READWRITE) CHECK(VirtualProtect(Pages + Page, Page, PAGE_READWRITE, &Old));
    printf("protect=%#lx resolution=%lu ret=%d error=%lu\n", Protect, Resolution, Ret, GetLastError());
    /* The in-tree win32k fills no points: display mode reports the buffer size,
     * high-resolution mode a history position. Neither writes the buffer. */
    if (Resolution == GMMP_USE_DISPLAY_POINTS) CHECK(Ret == POINTS);
    else CHECK(Ret >= 0);
    CHECK(Untouched(Pages, 2 * Page));
}

/* Display mode probes the first entry for write; high-resolution mode does not touch it. */
static VOID RunFirst(BYTE *Pages, SIZE_T Page)
{
    MOUSEMOVEPOINT In = {0};
    DWORD Old;
    int Ret;
    CHECK(VirtualProtect(Pages + Page, Page, PAGE_NOACCESS, &Old));
    SetLastError(0xdeadbeef);
    Ret = GetMouseMovePointsEx(sizeof(MOUSEMOVEPOINT), &In, (MOUSEMOVEPOINT *)(Pages + Page), POINTS, GMMP_USE_DISPLAY_POINTS);
    CHECK(Ret == -1 && GetLastError() == ERROR_NOACCESS);
    Ret = GetMouseMovePointsEx(sizeof(MOUSEMOVEPOINT), &In, (MOUSEMOVEPOINT *)(Pages + Page), POINTS, GMMP_USE_HIGH_RESOLUTION_POINTS);
    CHECK(Ret >= 0);
    CHECK(VirtualProtect(Pages + Page, Page, PAGE_READWRITE, &Old));
}

int main(int argc, char **argv)
{
    SYSTEM_INFO Info;
    BYTE *Pages;
    BOOL Wow = FALSE;
    if (sizeof(PVOID) != 4 || argc != 2 || (strcmp(argv[1], "native") && strcmp(argv[1], "wow64")))
    {
        printf("usage: i386 mouse_points native|wow64\n");
        return 1;
    }
    GetSystemInfo(&Info);
    CHECK(IsWow64Process(GetCurrentProcess(), &Wow));
    CHECK(Wow == !strcmp(argv[1], "wow64"));
    printf("wow64=%d\n", Wow);
    Pages = VirtualAlloc(NULL, 2 * Info.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    CHECK(Pages != NULL);
    if (Pages)
    {
        Run(Pages, Info.dwPageSize, PAGE_READWRITE, GMMP_USE_DISPLAY_POINTS);
        Run(Pages, Info.dwPageSize, PAGE_READWRITE, GMMP_USE_HIGH_RESOLUTION_POINTS);
        /* A guard fires once on the first access and then leaves the tail
         * writable, so a read or a write-back of the unfilled entries shows. */
        Run(Pages, Info.dwPageSize, PAGE_READWRITE | PAGE_GUARD, GMMP_USE_DISPLAY_POINTS);
        Run(Pages, Info.dwPageSize, PAGE_READWRITE | PAGE_GUARD, GMMP_USE_HIGH_RESOLUTION_POINTS);
        /* An unreadable tail must not turn a native success into a fault. */
        Run(Pages, Info.dwPageSize, PAGE_NOACCESS, GMMP_USE_DISPLAY_POINTS);
        Run(Pages, Info.dwPageSize, PAGE_NOACCESS, GMMP_USE_HIGH_RESOLUTION_POINTS);
        RunFirst(Pages, Info.dwPageSize);
        CHECK(VirtualFree(Pages, 0, MEM_RELEASE));
    }
    printf("mouse_points: %u checks, %u failures\n", Checks, Failures);
    return Failures ? 1 : 0;
}
