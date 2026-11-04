/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for CreateFileMappingFromApp, MapViewOfFileFromApp, CreateFileMappingNumaW/A and
 *              MapViewOfFileExNuma
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Chrome, Firefox and Visual Code look the FromApp pair up with GetProcAddress.
 *
 * MapViewOfFile3, MapViewOfFileNuma2 and UnmapViewOfFile2 are tested with placeholders in Placeholder.c.
 */

#include "precomp.h"

#define NO_PREFERRED_NODE 0xFFFFFFFF
#define GRANULE           0x10000

typedef HANDLE (WINAPI *PFN_CreateFileMappingFromApp)(HANDLE, PSECURITY_ATTRIBUTES, ULONG, ULONG64, PCWSTR);
typedef PVOID (WINAPI *PFN_MapViewOfFileFromApp)(HANDLE, ULONG, ULONG64, SIZE_T);
typedef HANDLE (WINAPI *PFN_CreateFileMappingNumaW)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR, DWORD);
typedef HANDLE (WINAPI *PFN_CreateFileMappingNumaA)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR, DWORD);
typedef PVOID (WINAPI *PFN_MapViewOfFileExNuma)(HANDLE, DWORD, DWORD, DWORD, SIZE_T, PVOID, DWORD);

static PFN_CreateFileMappingFromApp pCreateFileMappingFromApp;
static PFN_MapViewOfFileFromApp pMapViewOfFileFromApp;
static PFN_CreateFileMappingNumaW pCreateFileMappingNumaW;
static PFN_CreateFileMappingNumaA pCreateFileMappingNumaA;
static PFN_MapViewOfFileExNuma pMapViewOfFileExNuma;

static void
TestFromApp(void)
{
    HANDLE Mapping;
    PVOID View, View2;

    SetLastError(0xdeadbeef);
    Mapping = pCreateFileMappingFromApp(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0x20000, NULL);
    ok(Mapping != NULL, "CreateFileMappingFromApp failed with %lu\n", GetLastError());
    if (!Mapping)
        return;

    View = pMapViewOfFileFromApp(Mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0);
    ok(View != NULL, "MapViewOfFileFromApp failed with %lu\n", GetLastError());
    if (View)
    {
        MEMORY_BASIC_INFORMATION Info;

        /* the whole mapping, offset 64 KB */
        ok(VirtualQuery(View, &Info, sizeof(Info)) == sizeof(Info), "VirtualQuery failed\n");
        ok(Info.RegionSize == 0x20000, "view size %Ix\n", Info.RegionSize);
        *(volatile DWORD *)View = 0x12345678;

        /* a second view with an offset of 64 KB sees what the first one wrote there */
        *((volatile DWORD *)((PBYTE)View + GRANULE)) = 0xCAFEBABE;
        View2 = pMapViewOfFileFromApp(Mapping, FILE_MAP_READ, GRANULE, 0x10000);
        ok(View2 != NULL, "MapViewOfFileFromApp with an offset failed with %lu\n", GetLastError());
        if (View2)
        {
            ok(*(volatile DWORD *)View2 == 0xCAFEBABE, "offset view reads %lx\n", *(volatile DWORD *)View2);
            ok(UnmapViewOfFile(View2), "UnmapViewOfFile failed with %lu\n", GetLastError());
        }

        /* an offset far beyond the mapping: the 64 bit offset is not truncated to 32 bits */
        SetLastError(0xdeadbeef);
        View2 = pMapViewOfFileFromApp(Mapping, FILE_MAP_READ, 0x100000000ULL * 4, 0x1000);
        ok(View2 == NULL, "a view beyond the mapping\n");
        if (View2)
            UnmapViewOfFile(View2);

        ok(UnmapViewOfFile(View), "UnmapViewOfFile failed with %lu\n", GetLastError());
        SetLastError(0xdeadbeef);
        ok(!UnmapViewOfFile(View), "UnmapViewOfFile of an unmapped view succeeded\n");
        ok(GetLastError() == ERROR_INVALID_ADDRESS, "error %lu\n", GetLastError());
    }

    CloseHandle(Mapping);
}

static void
TestNuma(void)
{
    HANDLE Mapping;
    PVOID View;

    SetLastError(0xdeadbeef);
    Mapping = pCreateFileMappingNumaW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x10000, NULL, NO_PREFERRED_NODE);
    ok(Mapping != NULL, "CreateFileMappingNumaW failed with %lu\n", GetLastError());
    if (Mapping)
    {
        View = pMapViewOfFileExNuma(Mapping, FILE_MAP_WRITE, 0, 0, 0, NULL, NO_PREFERRED_NODE);
        ok(View != NULL, "MapViewOfFileExNuma failed with %lu\n", GetLastError());
        if (View)
        {
            *(volatile DWORD *)View = 1;
            ok(UnmapViewOfFile(View), "UnmapViewOfFile failed with %lu\n", GetLastError());
        }

        View = pMapViewOfFileExNuma(Mapping, FILE_MAP_WRITE, 0, 0, 0, NULL, 0);
        ok(View != NULL, "MapViewOfFileExNuma with node 0 failed with %lu\n", GetLastError());
        if (View)
            UnmapViewOfFile(View);

        SetLastError(0xdeadbeef);
        View = pMapViewOfFileExNuma(Mapping, FILE_MAP_WRITE, 0, 0, 0, NULL, 63);
        if (is_reactos())
            ok(View == NULL && GetLastError() == ERROR_INVALID_PARAMETER, "node 63: %p, error %lu\n", View, GetLastError());
        if (View)
            UnmapViewOfFile(View);
        CloseHandle(Mapping);
    }

    SetLastError(0xdeadbeef);
    Mapping = pCreateFileMappingNumaW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x10000, NULL, 63);
    if (is_reactos())
        ok(Mapping == NULL && GetLastError() == ERROR_INVALID_PARAMETER, "node 63: %p, error %lu\n", Mapping, GetLastError());
    if (Mapping)
        CloseHandle(Mapping);

    /* the A version, and a named mapping that is found again by name */
    Mapping = pCreateFileMappingNumaA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x10000, "MapViewOfFile3ApiTest", 0);
    ok(Mapping != NULL, "CreateFileMappingNumaA failed with %lu\n", GetLastError());
    if (Mapping)
    {
        HANDLE Second = OpenFileMappingA(FILE_MAP_READ, FALSE, "MapViewOfFile3ApiTest");

        ok(Second != NULL, "OpenFileMappingA failed with %lu\n", GetLastError());
        if (Second)
            CloseHandle(Second);
        CloseHandle(Mapping);
    }
}

START_TEST(FileMappingFromApp)
{
    HMODULE Kernel32 = GetModuleHandleW(L"kernel32.dll");

    pCreateFileMappingFromApp = (PFN_CreateFileMappingFromApp)GetProcAddress(Kernel32, "CreateFileMappingFromApp");
    pMapViewOfFileFromApp = (PFN_MapViewOfFileFromApp)GetProcAddress(Kernel32, "MapViewOfFileFromApp");
    pCreateFileMappingNumaW = (PFN_CreateFileMappingNumaW)GetProcAddress(Kernel32, "CreateFileMappingNumaW");
    pCreateFileMappingNumaA = (PFN_CreateFileMappingNumaA)GetProcAddress(Kernel32, "CreateFileMappingNumaA");
    pMapViewOfFileExNuma = (PFN_MapViewOfFileExNuma)GetProcAddress(Kernel32, "MapViewOfFileExNuma");

    if (pCreateFileMappingFromApp && pMapViewOfFileFromApp)
    {
        TestFromApp();
    }
    else
    {
        ok(!is_reactos(), "CreateFileMappingFromApp or MapViewOfFileFromApp is not exported by kernel32\n");
        skip("the FromApp functions are not available\n");
    }

    if (pCreateFileMappingNumaW && pCreateFileMappingNumaA && pMapViewOfFileExNuma)
    {
        TestNuma();
    }
    else
    {
        ok(!is_reactos(), "the Numa mapping functions are not exported by kernel32\n");
        skip("the Numa mapping functions are not available\n");
    }
}
